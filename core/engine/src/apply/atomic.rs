//! Atomic apply (spec/commits.md §4): one store transaction joins every valid delta of a commit
//! after its role records reach perm, records deaths, expiry and purges, and
//! re-judges held deltas when the held set changed; events go out after it is durable.

use super::{Parts, Streamed, copies, validity};
use crate::engine::{Core, Meta, Owned, Tx, records};
use crate::error::{Error, Result};
use crate::events::{Cause, Event, Origin};
use osis_commit::{CommitBlob, Decoded, Header};
use osis_base::{Ak, CommitId, CreationRecord, Tid, Value, WallMs};
use osis_crdt::{Changes, Fragment};
use osis_store::Shred;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::engine::Gives;

/// Notes a held compaction snapshot of `(tid, ak)` with its frontiers and `Absorbed`.
pub(crate) fn note_snapshot(core: &mut Core, tid: &Tid, ak: &Ak, ts: osis_base::Ts, id: &CommitId, (fr, abs): Gives) {
    // kept in (`ts`, ID) order, so arrival order (a rebuild's is the store's) does not show
    let v = core.ix.snapshots.entry_or_default((*tid, ak.clone()));
    if !v.iter().any(|x| x.1 == *id) {
        let at = v.partition_point(|x| (x.0, x.1) < (ts, *id));
        v.insert(at, (ts, *id, fr, abs));
    }
}

/// Indexes the dropped parts of `id` that still stand in (`Dropped::stands_in`).
pub(crate) fn note_stands_in(core: &mut Core, id: &CommitId) {
    let Some(m) = core.ix.commits.get(id) else { return };
    let ks: Vec<(Tid, Ak)> = m.dropped.iter().filter(|x| x.1.stands_in).filter_map(|x| m.view.aspects.get(*x.0)).map(|a| (a.tid, a.ak.clone())).collect();
    for k in ks {
        core.ix.dropped_snapshots.insert(k, *id);
    }
}

/// Forgets snapshot `id` of `(tid, ak)` when its body drops: its carried writes are index
/// entries derived from the body (spec/commits.md §5), which a rebuild cannot read.
pub(crate) fn forget_snapshot(core: &mut Core, tid: &Tid, ak: &Ak, id: &CommitId) {
    let k = (*tid, ak.clone());
    if let Some(mut v) = core.ix.snapshots.get(&k).cloned()
        && v.iter().any(|x| x.1 == *id)
    {
        v.retain(|x| x.1 != *id);
        if v.is_empty() {
            core.ix.snapshots.remove(&k);
        } else {
            core.ix.snapshots.insert(k.clone(), v);
        }
    }
    if let Some(mut v) = core.ix.carried.get(&k).cloned()
        && v.iter().any(|c| c.snap == *id)
    {
        v.retain(|c| c.snap != *id);
        if v.is_empty() {
            core.ix.carried.remove(&k);
        } else {
            core.ix.carried.insert(k, v);
        }
    }
}

/// A compaction snapshot's held parts may count a waiting commit's missing delta of their
/// aspects as dropped (`receipt::listed`): those waits are judged again.
fn wake_listed(core: &mut Core, h: &Header, held: &BTreeSet<usize>) {
    if h.kind.is_compaction() {
        for a in held.iter().filter_map(|ai| h.aspects.get(*ai)) {
            core.waits.wake(&a.tid, &a.ak);
        }
    }
}

/// Adds a commit to the per-aspect and session range indexes.
pub(crate) fn index_commit(core: &mut Core, id: &CommitId, h: &crate::engine::View) {
    for a in &h.aspects {
        core.ix.by_aspect.insert((a.tid, a.ak.clone()), (h.ts, *id));
        // a delta wait on the aspect reads it (`at_most_bound`), its part here or not
        core.waits.wake(&a.tid, &a.ak);
        if a.ak.as_str() == "label.0" {
            core.ix.labeled.insert(a.tid);
        }
        if a.ak.as_str() == crate::flows::LINK_SEED {
            core.links = None;
        }
        core.ix.by_thing.insert((a.tid, h.author), *id);
        if h.form.counted() && h.kind.has_own_writes() && a.lo < a.hi {
            core.ix.ranges.insert((a.tid, a.ak.clone(), h.form.own_source(h.author, *id)), a.lo, (a.hi, *id));
        }
    }
    if h.actor != h.author {
        core.ix.by_actor.insert((h.actor, h.author), *id);
    }
    for b in &h.chunks {
        core.ix.by_chunk.insert(*b, *id);
    }
    if let Some(t) = h.undoes {
        core.ix.undone_by.insert(t, *id);
    }
}

/// Commits of the same session whose counter ranges on one aspect overlap this one's
/// (spec/commits.md §4: all are invalid).
fn overlaps(core: &Core, id: &CommitId, h: &Header) -> BTreeSet<CommitId> {
    let mut out = BTreeSet::new();
    if !h.form.counted() || !h.kind.has_own_writes() {
        return out;
    }
    let src = h.form.own_source(h.author, *id);
    for a in &h.aspects {
        if let Some(m) = core.ix.ranges.get(&(a.tid, a.ak.clone(), src.clone())) {
            for (lo, (hi, c)) in m.range(..a.hi) {
                if *hi > a.lo && *lo < a.hi && c != id {
                    out.insert(*c);
                }
            }
        }
    }
    out
}

/// Joins `delta` (a whole delta, or one piece of one: spec/crdt.md §8) into the state of
/// `(tid, ak)`, holding value-less what must be. The writes of deltas invalid here go first;
/// `snap`: a valid snapshot's part, whose own copies of them all join (spec/permissions.md
/// §5.2).
/// `held_only`: only the deaths of writes the state held before, as loaded for the join (the
/// pages it touches hold every write it supersedes): a snapshot's copies dying on arrival die
/// for it alone (`retention::note_copies`), not again for the other bodies carrying them. A
/// paged state loads only the pages the join touches, or where it resets or re-encodes a paged
/// collection joins it a page at a time (`Tx::join_reset`).
pub(crate) fn join_into_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, mut delta: Fragment, snap: bool, held_only: bool) -> Result<Changes> {
    let _s = crate::costs::span("apply: join");
    tx.load_lazy(tid, ak)?;
    // writes owned by deltas invalid here go from every body before it joins (un-merge is a
    // function of the held set: another's nested write under an invalid creation goes too),
    // except a valid snapshot's own copies of them
    let un = Unmerge::probe(tx, tid, ak, &delta)?;
    if !un.is_empty() {
        if snap {
            let mine = delta.copy_index();
            delta.remove_dots(&|d| un.bad(d) && !mine.holds(d));
        } else {
            un.strip(&mut delta);
        }
        // the writes stripped (others' nested under an invalid creation) still die at a valid
        // superseder (spec/crdt.md §4.8), which this join cannot meet: dated from the bodies
        crate::retention::mark_if_bounded(tx, tid, ak)?;
    }
    // the state is held stripped and stripping commutes with join (spec/crdt.md §4.7)
    strip_valueless(tx.core, tid, ak, &mut delta);
    // a paged state loads only the pages the join touches
    let touch = crate::engine::pages::touch_of(&delta, tx.core.pages.get(&(*tid, ak.clone())));
    if touch.is_none()
        && let Some(ch) = tx.join_reset(tid, ak, &delta, held_only)?
    {
        return Ok(ch);
    }
    tx.ensure_touch(tid, ak, &touch)?;
    // joined in place (evicted on rollback), so a join costs O(delta), not a copy of the state
    let k = (*tid, ak.clone());
    tx.core.touch();
    // `secrets.0` read before: this join's entries read again from the pages it touched
    let secrets = (ak.as_str() == "secrets.0").then(|| tx.core.secrets_read.get(tid).cloned().map(|s| (s, delta.clone()))).flatten();
    tx.core.wrote(k.clone());
    let mut st = tx.core.states.get_mut(&k).and_then(Option::take).unwrap_or_default();
    let before = held_only.then(|| st.stamps());
    let mut ch = st.join(delta);
    if let Some(b) = before {
        ch.retain_deaths(|d| b.holds(&d.stamp));
    }
    let secrets = secrets.and_then(|(mut read, d)| super::keys::secrets_patch(std::sync::Arc::make_mut(&mut read), &d, &st).then_some(read));
    let st = tx.kept(tid, ak, st)?;
    if ch.is_changed() || !ch.deaths().is_empty() {
        tx.set_state_touched(tid, ak, st, &touch, Shred::No)?;
    } else {
        tx.core.states.insert(k, st);
    }
    if let Some(read) = secrets {
        tx.core.secrets_read.insert(*tid, read);
    }
    Ok(ch)
}

/// One examined part (`Parts`): decoded whole, or streamed again at apply.
#[derive(Clone, Copy)]
pub(super) enum PartRef<'p> {
    Whole(&'p Decoded),
    Streamed(&'p Streamed),
}

impl PartRef<'_> {
    /// A snapshot's frontiers and `Absorbed`.
    fn gives(&self) -> Option<Gives> {
        match self {
            PartRef::Whole(Decoded::Snapshot(x)) => Some((x.frontiers.clone(), x.absorbed.clone().into_iter().collect())),
            PartRef::Whole(Decoded::Delta(_)) => None,
            PartRef::Streamed(s) => s.gives.clone(),
        }
    }
}

/// The parts by aspect, in the commit's part order.
pub(super) fn in_order(parts: &Parts) -> Vec<(usize, PartRef<'_>)> {
    let mut v: Vec<(usize, usize, PartRef<'_>)> = parts.whole.iter().map(|(ai, di, d)| (*ai, *di, PartRef::Whole(d))).collect();
    v.extend(parts.streamed.iter().map(|s| (s.ai, s.di, PartRef::Streamed(s))));
    v.sort_by_key(|x| (x.0, x.1));
    v.into_iter().map(|x| (x.0, x.2)).collect()
}

/// A streamed delta's pages, read through the transaction the code joining its pieces holds too
/// (`each_piece`): each borrows it in turn.
struct SharedPages<'c, 't, 'a> {
    tx: &'c RefCell<&'t mut Tx<'a>>,
    dedup: &'c osis_crypto::Secret32,
}

impl osis_crdt::PageSource for SharedPages<'_, '_, '_> {
    fn get(&mut self, link: &osis_base::Link) -> std::result::Result<Vec<u8>, osis_crdt::PageError> {
        let mut tx = self.tx.try_borrow_mut().map_err(|_| osis_crdt::PageError::Storage)?;
        let mut blobs = crate::engine::blobs::TxBlobs::new(&mut tx.txn);
        osis_label::BlobReader::new(self.dedup, &mut blobs).get(link)
    }
}

/// Stops a stream whose piece failed to join (the error is the join's).
const STOPPED: osis_crdt::Error = osis_crdt::Error::Malformed("stopped");

/// Hands `f` a part's delta: a whole one at once, a streamed one a piece at a time as it decodes
/// again (`stream_stored`). A streamed part failing now, after `examine` accepted it, means its
/// bytes or pages changed since: a local error.
pub(super) fn each_piece(tx: &mut Tx<'_>, h: &Header, id: &CommitId, blob: &CommitBlob, part: PartRef<'_>, f: &mut dyn FnMut(&mut Tx<'_>, Fragment) -> Result<()>) -> Result<()> {
    let s = match part {
        PartRef::Whole(d) => return f(tx, d.fragment().clone()),
        PartRef::Streamed(s) => s,
    };
    let p = blob.parts.iter().find(|p| p.ai == s.ai && p.di == s.di).ok_or(Error::Corrupt("streamed part"))?;
    stream_stored(tx, h, id, p, &s.dedup, f).map(|_| ())
}

/// Decodes a verified part `p` of commit `id` (header `h`, its thing's `dedup` secret) again and
/// hands `f` its pieces, the skeleton first, then its pages in wire order
/// (`osis_commit::stream_part`; joining the pieces is joining the whole, spec/crdt.md §8): the
/// transaction is shared between the page source and `f`. A snapshot's frontiers and `Absorbed`.
pub(super) fn stream_stored(tx: &mut Tx<'_>, h: &Header, id: &CommitId, p: &osis_commit::Part, dedup: &osis_crypto::Secret32, f: &mut dyn FnMut(&mut Tx<'_>, Fragment) -> Result<()>) -> Result<Option<Gives>> {
    let cell = RefCell::new(tx);
    let mut failed = None;
    let mut pages = SharedPages { tx: &cell, dedup };
    // a memory commit's parts hold everything inline (spec/crdt.md §8)
    let mut unpaged = osis_crdt::Unpaged;
    let source: &mut dyn osis_crdt::PageSource = if h.ephemeral.is_some() { &mut unpaged } else { &mut pages };
    let mut interner = osis_crdt::Interner::new();
    let r = osis_commit::stream_part(h, id, p, dedup, &mut interner, Some(source), &mut |piece| {
        // counted: tests read how many pieces streamed
        let _s = crate::costs::span("apply: piece");
        let mut tx = cell.try_borrow_mut().map_err(|_| STOPPED)?;
        #[cfg(test)]
        if let Some(n) = tx.core.piece_fault.as_mut() {
            if *n == 0 {
                failed = Some(Error::Corrupt("test: piece fault"));
                return Err(STOPPED);
            }
            *n -= 1;
        }
        f(&mut tx, piece).map_err(|e| {
            failed = Some(e);
            STOPPED
        })
    });
    if let Some(e) = failed {
        return Err(e);
    }
    let head = r.map_err(|_| Error::Corrupt("a verified delta failed to decode again"))?;
    Ok(head.map(|x| (x.frontiers, x.absorbed.into_iter().collect())))
}

/// What the joins of a commit's parts, and the rebuilds after them, leave for the rest of apply.
#[derive(Default)]
pub(super) struct Joins {
    pub changed: BTreeSet<(Tid, Ak)>,
    pub touched: Touched,
    /// Aspects a valid snapshot joined into that are rebuilt once the commit is stored.
    pub vouching: BTreeSet<(Tid, Ak)>,
    /// Per valid part joined, its deaths: noted after the commit's record, as they may drop its
    /// own body (dead on arrival).
    pub joined: Vec<(Tid, Ak, bool, Vec<osis_crdt::Death>)>,
}

/// Joins every part of commit `id` (`valid`: per aspect; `void`: a void import's body joins
/// nothing), in part order, a piece at a time (tests under `Core::whole_apply`: `oracle::joins`).
///
/// Invariant (the differential `tests_paged` checks it against `oracle::joins`, which decodes
/// and joins every part whole): joining a delta a piece at a time, each piece's state pages
/// written to the store and dropped from the cache before the next, leaves exactly the state,
/// deaths, snapshot records, carried writes and outcomes that joining it whole does. Pieces
/// split a delta by element (§8), and what is judged of a whole delta is judged of its pieces:
/// carried writes, un-merging and holding value-less per write, misstatements per write against
/// the state before the part (`copies_before`), deaths per join.
fn joins(tx: &mut Tx<'_>, h: &Header, id: &CommitId, blob: &CommitBlob, parts: &Parts, valid: &[bool], void: bool) -> Result<Joins> {
    let mut j = Joins::default();
    #[cfg(test)]
    if tx.core.whole_apply {
        super::oracle::joins(tx, h, id, parts, valid, void, &mut j)?;
        return Ok(j);
    }
    for (ai, part) in in_order(parts) {
        join_part(tx, h, id, blob, ai, part, valid.get(ai).copied().unwrap_or(false), void, &mut j)?;
    }
    Ok(j)
}

/// Joins one part (`joins`): every held snapshot notes its frontiers and carried writes,
/// whatever its validity; a valid part joins; an invalid delta joins and un-merges (its sequence
/// records stay as hidden anchors, spec/crdt.md §4.6); an invalid snapshot gives nothing (its
/// copies never join, spec/permissions.md §5.2), nor does a void import's body (its copies may
/// sit under an origin's own dots).
#[allow(clippy::too_many_arguments)]
fn join_part(tx: &mut Tx<'_>, h: &Header, id: &CommitId, blob: &CommitBlob, ai: usize, part: PartRef<'_>, v: bool, void: bool, j: &mut Joins) -> Result<()> {
    let Some(a) = h.aspects.get(ai) else { return Ok(()) };
    let (tid, ak) = (a.tid, a.ak.clone());
    let gives = part.gives();
    let snap = gives.is_some();
    // edge and creation aspects reach perm instead
    let perm = validity::perm_ak(ak.as_str());
    if !v && !snap && (void || perm) {
        return if perm { Ok(()) } else { arrived_invalid(tx, &tid, &ak, j) };
    }
    if let Some(fr) = gives {
        note_snapshot(tx.core, &tid, &ak, h.ts, id, fr);
    }
    // a valid snapshot carrying writes of deltas invalid here makes them count again, and
    // others' writes nested under them come back only from their bodies: the aspect is rebuilt
    // (spec/crdt.md §4.6), as when it may copy a held delta's write otherwise than the state
    // holds it (the rebuild judges per delta)
    let owned = if snap && v { invalid_of(tx.core, &tid, &ak) } else { Vec::new() };
    let mut vouch = false;
    let copies = if snap && v { copies_before(tx, h, id, blob, part, &tid, &ak, &owned, &mut vouch)? } else { None };
    // deaths count only for bodies with a relative bound
    let bounded = v && crate::retention::any_bounded(tx.core, &tid, &ak);
    let mut carried: BTreeMap<osis_crdt::Source, BTreeSet<u64>> = BTreeMap::new();
    let mut ch = Changes::new();
    // an invalid delta: a piece at a time in place, or (a valid snapshot carries one of its
    // writes) rebuilt once after its pieces
    let un = if !v && !snap { Some(Unmerge::of(tx, &tid, &ak)?) } else { None };
    each_piece(tx, h, id, blob, part, &mut |tx, f| {
        if snap {
            for (src, ctrs) in copies::carried_of(tx.core, &tid, &ak, &f) {
                carried.entry(src).or_default().extend(ctrs);
            }
            vouch |= !owned.is_empty() && f.holds_dots(&|d| owned.iter().any(|o| o.owns(d)));
            if !vouch && let Some(cs) = &copies {
                let core = &*tx.core;
                vouch = !f.misstated_in(cs, &|d| copies::owner_held(core, &tid, &ak, d), &|d| copies::owner_expires(core, &tid, &ak, d)).is_empty();
            }
        }
        if !v {
            if let Some(un) = &un {
                join_into_state(tx, &tid, &ak, f.clone(), false, false)?;
                if un.in_place() {
                    unmerge_part(tx, &tid, &ak, un, Some(f))?;
                }
                tx.evict_pages(&tid, &ak);
            }
            return Ok(());
        }
        j.touched.note(&tid, &ak, &f);
        ch.merge(join_into_state(tx, &tid, &ak, f, snap, snap && bounded)?);
        tx.evict_pages(&tid, &ak);
        Ok(())
    })?;
    if snap {
        copies::note_carried_of(tx.core, &tid, &ak, id, carried);
    }
    if vouch {
        j.vouching.insert((tid, ak.clone()));
    }
    if !v {
        if let Some(un) = &un {
            if !un.in_place() {
                rebuild(tx, &tid, &ak)?;
            }
            unmerged_as_rebuilt(tx, &tid, &ak)?;
            unmerged(tx, &tid, &ak, j)?;
        }
        return Ok(());
    }
    if ch.is_changed() {
        j.changed.insert((tid, ak.clone()));
    }
    // a death the state cannot date: the bodies can (spec/commits.md §5)
    if ch.undated() {
        crate::retention::mark_if_bounded(tx, &tid, &ak)?;
    }
    j.joined.push((tid, ak, snap, if bounded { ch.into_deaths() } else { Vec::new() }));
    Ok(())
}

/// Before a valid snapshot's pieces join a state that holds something: whether a piece holds a
/// write of a delta invalid here (`vouch`), else, when one may copy a held delta's write
/// (`Fragment::holds_owned`), the state's copies to judge its pieces against
/// (`Fragment::misstated_in`: the snapshot is judged against the state before it, read before
/// any piece joins). Reads the snapshot once more; the state whole only to judge.
#[allow(clippy::too_many_arguments)]
fn copies_before(tx: &mut Tx<'_>, h: &Header, id: &CommitId, blob: &CommitBlob, part: PartRef<'_>, tid: &Tid, ak: &Ak, owned: &[Owned], vouch: &mut bool) -> Result<Option<osis_crdt::CopySet>> {
    tx.load_lazy(tid, ak)?;
    if tx.cached(tid, ak).is_none() {
        return Ok(None);
    }
    let mut holds = false;
    each_piece(tx, h, id, blob, part, &mut |tx, f| {
        *vouch |= !owned.is_empty() && f.holds_dots(&|d| owned.iter().any(|o| o.owns(d)));
        holds |= f.holds_owned(&|src, lo, hi| core_holds_owner(tx.core, tid, ak, src, lo, hi));
        Ok(())
    })?;
    if *vouch || !holds {
        return Ok(None);
    }
    tx.load(tid, ak)?;
    Ok(tx.cached(tid, ak).map(|st| osis_crdt::CopySet::of(&[st])))
}

/// What un-merging removes on `(tid, ak)` (spec/crdt.md §4.6, spec/permissions.md §5.2): from
/// every delta body, the state and the residues the writes of the held deltas invalid here,
/// with the records they created and others' writes nested in them (`bad`); from a held valid
/// snapshot's body only what it holds under such a dot without a write of its own there
/// (`unvouched`): its copies stay, its writer vouched for them. Where a snapshot vouches for a
/// write (`vouched`) the state holds its copy joined with the delta's, so only a rebuild gives
/// the snapshot's copy alone.
pub(crate) struct Unmerge {
    owned: OwnedSet,
    vouched: copies::Records,
    /// The dots whose map record a held valid snapshot holds key-erased (spec/crdt.md §4.7).
    erased: BTreeSet<osis_crdt::Dot>,
}

/// A list of `Owned` for a lookup per dot in O(log its length): a fall lists every fallen delta,
/// and asks about every dot it reads.
#[derive(Default)]
struct OwnedSet {
    commits: BTreeSet<CommitId>,
    /// Per source, the counters owned as inclusive ranges, sorted and disjoint.
    ranges: BTreeMap<osis_crdt::Source, Vec<(u64, u64)>>,
}

impl OwnedSet {
    fn of(owned: &[Owned]) -> OwnedSet {
        let mut set = OwnedSet::default();
        for o in owned {
            match o {
                Owned::Range { src, lo, hi } => set.ranges.entry(src.clone()).or_default().extend((lo < hi).then(|| (*lo, hi - 1))),
                Owned::Commit(c) => {
                    set.commits.insert(*c);
                }
                Owned::Dots { src, ctrs } => set.ranges.entry(src.clone()).or_default().extend(ctrs.iter().map(|c| (*c, *c))),
            }
        }
        for v in set.ranges.values_mut() {
            v.sort_unstable();
            v.dedup_by(|b, a| {
                let over = b.0 <= a.1;
                if over {
                    a.1 = a.1.max(b.1);
                }
                over
            });
        }
        set
    }
    fn is_empty(&self) -> bool {
        self.commits.is_empty() && self.ranges.is_empty()
    }
    /// `Owned::owns` of any of them.
    fn owns(&self, d: &osis_crdt::Dot) -> bool {
        if let osis_crdt::SourceKind::Commit(c) = d.src.kind()
            && self.commits.contains(c)
        {
            return true;
        }
        self.ranges.get(&d.src).is_some_and(|v| {
            let i = v.partition_point(|r| r.1 < d.ctr);
            v.get(i).is_some_and(|r| r.0 <= d.ctr)
        })
    }
}

impl Unmerge {
    /// From the held set, reading the valid snapshots' writes when a delta is invalid.
    pub(crate) fn of(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Unmerge> {
        let owned = invalid_of(tx.core, tid, ak);
        let (vouched, erased) = copies::vouched(tx, tid, ak, &owned)?;
        Ok(Unmerge { owned: OwnedSet::of(&owned), vouched, erased })
    }
    /// `of` for removing from `f` alone: snapshots are read only when `f` holds a write of an
    /// invalid delta.
    pub(crate) fn probe(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, f: &Fragment) -> Result<Unmerge> {
        let owned = invalid_of(tx.core, tid, ak);
        if owned.is_empty() || !f.holds_dots(&|d| owned.iter().any(|o| o.owns(d))) {
            return Ok(Unmerge { owned: OwnedSet::default(), vouched: BTreeSet::new(), erased: BTreeSet::new() });
        }
        Unmerge::of(tx, tid, ak)
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.owned.is_empty()
    }
    /// Whether what a delta body, the state or a residue holds under owner dot `d` goes.
    pub(crate) fn bad(&self, d: &osis_crdt::Dot) -> bool {
        self.owned.owns(d)
    }
    /// Whether a held valid snapshot holds a write in the record of dot `d` and key `key`: of
    /// a keyed map entry, its creation's copy under that key or the record itself (its
    /// creation pruned by a reset, alive by a later nested write); else any write under `d`.
    /// A key-erased record (its writer held the dot value-less, spec/crdt.md §4.7) keeps every
    /// record of its dot, whether or not this node holds it value-less yet (seed 7340007): the
    /// answer must not change when the dot goes value-less here, since no rebuild runs then.
    /// Limit: with the dot value-less here, the state's key-erased record is asked with no
    /// key, so a misstated copy under another key keeps it there but not in a body.
    fn vouches(&self, d: &osis_crdt::Dot, key: Option<&osis_base::Value>) -> bool {
        match key {
            Some(k) => self.erased.contains(d) || self.vouched.contains(&(d.clone(), Some(k.clone()))),
            None => self.vouched.range((d.clone(), None)..).next().is_some_and(|x| x.0 == *d),
        }
    }
    /// Whether what a valid snapshot's body holds under owner dot `d` goes.
    pub(crate) fn unvouched(&self, d: &osis_crdt::Dot) -> bool {
        self.bad(d) && !self.vouches(d, None)
    }
    /// Removes from a delta body, the state or a residue what un-merging removes (spec/crdt.md
    /// §4.6): the invalid deltas' writes, the records they created and others' writes nested in
    /// them, except in a record a held valid snapshot's copy keeps (`vouches`): the record
    /// stays in the state, so others' valid writes in it stay too. A copy of a map entry's
    /// creation under another key (misstated) keeps its own record, not the delta's; a
    /// key-erased one keeps them all.
    pub(crate) fn strip(&self, f: &mut Fragment) {
        if !self.is_empty() {
            f.remove_dots_keeping(&|d| self.bad(d), &|d, k| self.vouches(d, k));
        }
    }
    /// Whether removing in place from the state can give the join (spec/crdt.md §4.6): no held
    /// valid snapshot vouches for a write of an invalid delta.
    pub(crate) fn in_place(&self) -> bool {
        self.vouched.is_empty() && self.erased.is_empty()
    }
}

/// The owners of writes of the held deltas on `(tid, ak)` that are invalid here.
pub(crate) fn invalid_of(core: &Core, tid: &Tid, ak: &Ak) -> Vec<Owned> {
    let mut out = Vec::new();
    for c in core.ix.invalid.get(&(*tid, ak.clone())).into_iter().flatten() {
        let Some(m) = core.ix.commits.get(c) else { continue };
        let Some(ai) = m.aspect(tid, ak) else { continue };
        if m.valid_at(ai) {
            continue;
        }
        out.extend(crate::retention::writes_of(core, &m.header, c, ai));
    }
    out
}

pub(crate) fn strip_valueless(core: &Core, tid: &Tid, ak: &Ak, st: &mut Fragment) {
    if let Some(v) = core.ix.valueless.get(&(*tid, ak.clone()))
        && !v.is_empty()
    {
        st.strip(&|d| v.iter().any(|o| o.owns(d)));
    }
}

/// Records the creation records commit `blob` carries that are not held yet (a durable
/// commit's `created.0` parts, durable; an ephemeral one's beside its deltas, memory class);
/// whether any was new. A durable record of a thing held as memory class persists it: its row
/// moves to the store (rows stay in the class they were written in).
fn note_created(tx: &mut Tx<'_>, h: &Header, blob: &CommitBlob, parts: &[(usize, usize, Decoded)]) -> Result<bool> {
    let mut any = false;
    if h.ephemeral.is_some() {
        let received = tx.now();
        for r in blob.parts.iter().flat_map(|p| &p.records) {
            let t = r.tid();
            if tx.core.created(&t).is_none() {
                tx.in_class(true, |tx| Ok(tx.txn.put_local(&[records::CREATED, t.as_bytes()].concat(), &osis_base::encode(&r.to_value()), Shred::No)?))?;
                tx.core.ix.held.create_memory(r.clone());
                tx.core.memory.things.insert(t, crate::engine::MemoryThing { ts: h.ts, node: h.author, actor: h.actor, received, made_here: false });
                any = true;
            }
        }
        return Ok(any);
    }
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() != osis_commit::retention::CREATED || tx.core.durable_created(&a.tid).is_some() {
            continue;
        }
        let rec = d.fragment().read().as_ref().and_then(CreationRecord::from_value).ok_or(Error::BadInput("created.0"))?;
        if rec.tid() == a.tid {
            let key = [records::CREATED, a.tid.as_bytes()].concat();
            let persisting = tx.core.ix.held.is_memory(&a.tid);
            if persisting {
                // a row stays in its class: the memory one goes first
                tx.txn.remove_local(&key, Shred::No)?;
            }
            tx.txn.put_local(&key, &osis_base::encode(&rec.to_value()), Shred::No)?;
            tx.core.ix.held.create(rec);
            tx.core.inbox_moved(&a.tid);
            if persisting {
                continue;
            }
            // the reader actor of the thing's deltas is known now
            let touching: Vec<CommitId> = tx.core.aspects_of(&a.tid).flat_map(|(_, s)| s.iter().map(|x| x.1)).collect();
            for c in touching {
                tx.core.bodies.remove(&c);
                tx.core.mark_changed(c);
            }
            any = true;
        }
    }
    Ok(any)
}

/// Applies a verified commit (`parts` examined) in this transaction.
pub(crate) fn apply_verified(tx: &mut Tx<'_>, blob: &CommitBlob, parts: Parts, origin: Origin, received: WallMs) -> Result<()> {
    let _s = crate::costs::span("apply");
    tx.core.touch();
    let id = blob.id();
    let h = Arc::new(blob.header.clone());
    tx.core.hlc.observe(h.ts);
    // a memory-class application writes nothing durable (the next durable commit persists the
    // clock)
    if !tx.txn.is_memory() {
        tx.txn.put_local(records::HLC, &tx.core.hlc.last().to_u64().to_be_bytes(), Shred::No)?;
    }

    // creation records first: perm and dedup secrets need them
    let mut held_changed = note_created(tx, &h, blob, &parts.whole)?;
    copies::note_imports(tx.core, &id, &h);
    let view = Arc::new(crate::engine::View::of(&h));
    if h.kind.is_role() {
        validity::note_required(tx.core, &h, &id, &parts.whole);
        let mut all = parts.whole.clone();
        all.extend(away_of(tx, &h, &id, &parts));
        validity::add_role_commit(tx, &view, Some(&h), &id, &validity::EdgeParts::of(&h, &all))?;
        held_changed = true;
    }
    if held_changed {
        tx.core.update_timelines();
    }

    // overlapping session-form counters void both commits
    let ov = overlaps(tx.core, &id, &h);
    if !ov.is_empty() {
        held_changed = true;
        for c in ov.iter().chain(std::iter::once(&id)) {
            tx.core.ix.void.insert(*c);
            tx.core.stale_commits.insert(*c);
            tx.txn.put_local(&[records::VOID, &c.0[..]].concat(), &[], Shred::No)?;
        }
        let now = tx.now();
        tx.core.events.diagnostic(
            crate::events::Diagnostic { kind: crate::events::DiagnosticKind::OverlappingCounters, tids: vec![h.author], commit: Some(id), peer: Some(h.author), detail: String::new() },
            now,
        );
    }
    // an import naming an origin on its own thing is void, judged once both are held
    // (spec/permissions.md §7): this one, or held ones naming this commit
    let voided = copies::self_origin_imports(tx.core, &id, &h);
    let void_self = voided.contains(&id);
    for c in &voided {
        held_changed = true;
        tx.core.ix.void.insert(*c);
        tx.core.stale_commits.insert(*c);
        tx.txn.put_local(&[records::VOID, &c.0[..]].concat(), &[], Shred::No)?;
    }
    crate::retention::origin_arrived(tx, &id, &h)?;
    index_commit(tx.core, &id, &view);
    // copies snapshots held here took of its writes: compared with its deltas once stored
    let uncarried = copies::uncarry(tx.core, &id, &h, &|ai| parts.has(ai));
    let valid: Vec<bool> = (0..h.aspects.len()).map(|ai| validity::part_valid(tx.core, &h, &id, ai)).collect();
    let missing: BTreeSet<usize> = (0..h.aspects.len()).filter(|ai| !parts.has(*ai)).collect();
    let meta = Meta { view, header: crate::engine::LazyHeader::ready(h.clone()), received, origin, valid: valid.clone(), dropped: BTreeMap::new(), missing };
    tx.core.put_meta(id, meta.clone());
    tx.core.index_validity(&id);

    wake_listed(tx.core, &h, &parts.ais());

    if origin == Origin::Local && h.kind == osis_commit::Kind::Content {
        let order = in_order(&parts);
        for (ai, a) in h.aspects.iter().enumerate() {
            // one delta: keep only what undoing it reads
            let pre = match order.iter().filter(|p| p.0 == ai).collect::<Vec<_>>().as_slice() {
                [(_, p)] => {
                    let mut acc = None;
                    each_piece(tx, &h, &id, blob, *p, &mut |tx, f| crate::undo::footprint(tx, &a.tid, &a.ak, &f, &mut acc))?;
                    Some(acc)
                }
                _ => None,
            };
            crate::undo::remember(tx, &id, &a.tid, &a.ak, pre)?;
        }
    }
    let pend = super::keys::before_join(tx, &h, &parts.whole, &valid)?;
    let mut j = joins(tx, &h, &id, blob, &parts, &valid, void_self)?;
    // an invalid aspect whose part is not held: others' writes under its creations go too (the
    // part may never come, or come late)
    for (ai, a) in h.aspects.iter().enumerate() {
        if !valid.get(ai).copied().unwrap_or(false) && !parts.has(ai) {
            arrived_invalid(tx, &a.tid, &a.ak, &mut j)?;
        }
    }
    {
        let _s = crate::costs::span("apply: put_commit");
        tx.put_commit(&id, blob, &meta, Shred::No, None)?;
    }
    note_held_rules(tx, &h, &id, &parts)?;
    after_store(tx, &h, &id, &uncarried, &voided, &mut j)?;
    {
        let _s = crate::costs::span("apply: retention");
        crate::retention::stripped_joined(tx, &id, &parts.stripped_joined(), &mut j.changed)?;
        crate::retention::on_apply(tx, &id, &mut j.changed)?;
    }
    {
        let _s = crate::costs::span("apply: observe");
        observe_all(tx, &j)?;
    }
    super::keys::after_join(tx, &h, &parts.whole, &valid, pend)?;
    let flipped = rejudged(tx, held_changed)?;
    let changed = j.changed;
    let rosters: BTreeSet<Tid> = if h.kind.is_role() { h.aspects.iter().filter(|a| validity::edge_ak(a.ak.as_str())).map(|a| a.tid).collect() } else { BTreeSet::new() };
    // a received roster change may end this node's read access (spec/permissions.md §3); its own
    // self-removals drop what they lost once placed (node-sync `drop_left`)
    if origin != Origin::Local {
        crate::rotation::mark_lost_due(tx, rosters.iter().copied())?;
        // a rotation from before the removal, arriving after it, must not give a kept copy a secret
        let copies: Vec<Tid> = h.aspects.iter().filter(|a| a.ak.as_str() == "secrets.0" && tx.core.ix.kept.contains_key(&a.tid)).map(|a| a.tid).collect();
        crate::rotation::mark_lost_due(tx, copies)?;
    }
    // a memory commit is ephemeral state to watchers (a local one's batch queues its own event,
    // `Engine::write`) and to the ephemeral lane (`MemorySync`), nothing to the durable sync path
    if h.ephemeral.is_some() {
        tx.core.memory.applied.push(id);
        if origin == Origin::Local && h.author == tx.core.id.tid() {
            tx.core.memory.unsent.push(id);
        }
        tx.core.memory.dirty.extend(h.aspects.iter().map(|a| (a.tid, a.ak.clone())));
        if origin != Origin::Local {
            tx.core.events.queue(Event::Ephemeral { id: id.into(), origin, author: h.author, actor: h.actor, ts: h.ts, received, changed: changed.into_iter().collect(), signals: Vec::new() });
        }
    } else {
        tx.core.events.queue(Event::Applied { id, origin, author: h.author, actor: h.actor, ts: h.ts, received, changed: changed.into_iter().collect() });
    }
    if !flipped.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Validity, changed: flipped });
    }
    for thing in rosters {
        tx.core.events.queue(Event::Roster { thing });
    }
    // a memory commit expired or superseded on arrival is not kept
    crate::retention::memory::forget_if_spent(tx, &id)
}

/// Notes the `required.0^` deltas among `parts`, once stored (`validity::note_required_rules`).
fn note_held_rules(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &Parts) -> Result<()> {
    for ai in parts.ais() {
        if h.aspects.get(ai).is_some_and(|a| a.ak.as_str() == osis_commit::retention::REQUIRED) {
            let held: Vec<(usize, usize, osis_commit::Decoded)> = super::held_parts(tx, id, ai)?.into_iter().map(|d| (ai, 0, d)).collect();
            validity::note_required_rules(tx.core, h, id, &held);
        }
    }
    Ok(())
}

/// A delta invalid on arrival whose part is not held (it may never come, or come late), on
/// apply or late: others' writes already joined may sit under its creations, so the aspect
/// un-merges as on a flip; a held one joins and un-merges a piece at a time (`join_part`).
/// Edge and creation aspects reach perm instead.
fn arrived_invalid(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, j: &mut Joins) -> Result<()> {
    if validity::perm_ak(ak.as_str()) {
        return Ok(());
    }
    if unmerge_fell(tx, tid, ak, None)? {
        unmerged(tx, tid, ak, j)?;
    }
    Ok(())
}

/// After an invalid delta's writes went from `(tid, ak)`.
fn unmerged(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, j: &mut Joins) -> Result<()> {
    // the writes it un-merged may have superseded others (spec/crdt.md §4.8)
    crate::retention::mark_if_bounded(tx, tid, ak)?;
    // others' writes went: what waits on the aspect's state is judged again
    tx.core.mark_aspect_changed(tid, ak);
    j.changed.insert((*tid, ak.clone()));
    j.touched.whole(tid, ak);
    Ok(())
}

/// Whether a dot of `src` with a counter in `lo..hi` may have a received owner (a cheap filter
/// before `strip_copies`: a session range overlapping a held one, any commit source).
pub(super) fn core_holds_owner(core: &Core, tid: &Tid, ak: &Ak, src: &osis_crdt::Source, lo: u64, hi: u64) -> bool {
    match src.kind() {
        osis_crdt::SourceKind::Session(_) => core.ix.ranges.get(&(*tid, ak.clone(), src.clone())).is_some_and(|m| m.range(..hi).next_back().is_some_and(|(_, (h, _))| *h > lo)),
        osis_crdt::SourceKind::Commit(_) => true,
        osis_crdt::SourceKind::Derived(_) => false,
    }
}

/// Once commit `id` (header `h`) is stored, so its own bodies join too: the rebuilds its joins
/// call for (`vouching`, `refill`, `unjoin_void`), then the deaths its valid parts reported.
fn after_store(tx: &mut Tx<'_>, h: &Header, id: &CommitId, uncarried: &[(Tid, Ak, BTreeSet<CommitId>)], voided: &BTreeSet<CommitId>, j: &mut Joins) -> Result<()> {
    for (tid, ak) in std::mem::take(&mut j.vouching) {
        // counted: tests read whether a snapshot vouched
        let _s = crate::costs::span("apply: vouched rebuild");
        rebuild_changed(tx, &tid, &ak, &[], j)?;
    }
    refill(tx, h, id, uncarried, j)?;
    unjoin_void(tx, h, id, voided, j)?;
    for (tid, ak, snap, deaths) in &j.joined {
        crate::retention::note_deaths(tx, tid, ak, deaths)?;
        if *snap {
            crate::retention::note_copies(tx, id, tid, ak)?;
        }
    }
    Ok(())
}

/// Rebuilds `(tid, ak)` without `gone` (`rebuild_without`): its deaths recomputed, what waits on
/// its state judged again.
fn rebuild_changed(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, gone: &[Owned], j: &mut Joins) -> Result<()> {
    rebuild_without(tx, tid, ak, gone)?;
    crate::retention::mark_deaths_due(tx, tid, ak)?;
    tx.core.mark_aspect_changed(tid, ak);
    j.changed.insert((*tid, ak.clone()));
    j.touched.whole(tid, ak);
    Ok(())
}

/// Rebuilds the aspects of commit `id` (header `h`) whose writes valid snapshots held before it
/// copied otherwise than its deltas hold them (`uncarried`, `copies::differing_copies`): the
/// snapshots' copies govern (spec/permissions.md §5.2), so the delta's writes under those dots go.
/// Invariant: every held delta a held valid snapshot misstates has been compared with it, on
/// whichever arrived second (`copies_before` for the snapshot), so the state is `rebuilt`'s. A
/// carried entry names only the first owner of a dot to arrive: an import's dots may be received
/// already through another import of its origin (spec/permissions.md §7), so an import's held
/// parts are compared with every held valid snapshot of the aspect.
fn refill(tx: &mut Tx<'_>, h: &Header, id: &CommitId, uncarried: &[(Tid, Ak, BTreeSet<CommitId>)], j: &mut Joins) -> Result<()> {
    let mut per: BTreeMap<(Tid, Ak), BTreeSet<CommitId>> = uncarried.iter().map(|(t, a, s)| ((*t, a.clone()), s.clone())).collect();
    if h.kind == osis_commit::Kind::Import
        && let Some(m) = tx.core.ix.commits.get(id)
    {
        for a in h.aspects.iter().enumerate().filter(|(ai, _)| m.holds(*ai)).map(|x| x.1) {
            let k = (a.tid, a.ak.clone());
            per.entry(k.clone()).or_default().extend(tx.core.ix.snapshots.get(&k).into_iter().flatten().map(|s| s.1));
        }
    }
    for ((tid, ak), snaps) in per {
        let Some(ai) = h.aspects.iter().position(|a| a.tid == tid && a.ak == ak) else { continue };
        // an invalid snapshot's copies never joined
        let snaps: BTreeSet<CommitId> = snaps.into_iter().filter(|s| copies::snapshot_valid(tx.core, s, &tid, &ak)).collect();
        if snaps.is_empty() {
            continue;
        }
        if copies::differing_copies(tx, h, id, ai, &snaps)?.is_empty() {
            continue;
        }
        rebuild_changed(tx, &tid, &ak, &[], j)?;
    }
    Ok(())
}

/// Rebuilds the aspects where held imports turned void by commit `id` (header `h`), an origin
/// on their own thing, joined copies under `id`'s own dots: those go from the state and `id`'s
/// deltas give the writes again (spec/permissions.md §7).
fn unjoin_void(tx: &mut Tx<'_>, h: &Header, id: &CommitId, voided: &BTreeSet<CommitId>, j: &mut Joins) -> Result<()> {
    let mut aspects: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    for c in voided.iter().filter(|c| *c != id) {
        let Some(m) = tx.core.ix.commits.get(c) else { continue };
        aspects.extend(m.header.aspects.iter().filter(|a| h.aspects.iter().any(|x| x.tid == a.tid && x.ak == a.ak)).map(|a| (a.tid, a.ak.clone())));
    }
    for (tid, ak) in aspects {
        if copies::owns_commit_dots(tx.core, id, &tid, &ak) {
            rebuild_changed(tx, &tid, &ak, &[Owned::Commit(*id)], j)?;
        }
    }
    Ok(())
}

/// The derived indexes of every aspect the joins changed (`observe_touched`).
fn observe_all(tx: &mut Tx<'_>, j: &Joins) -> Result<()> {
    for (tid, ak) in &j.changed {
        observe_touched(tx, tid, ak, &j.touched)?;
    }
    Ok(())
}

/// Re-judges held deltas when the held set changed or something is stale
/// (`validity::rejudge_all`), and observes the aspects that flipped; returns them.
fn rejudged(tx: &mut Tx<'_>, held_changed: bool) -> Result<Vec<(Tid, Ak)>> {
    if !held_changed && !tx.core.stale() {
        return Ok(Vec::new());
    }
    let flipped = validity::rejudge_all(tx, true)?;
    for (tid, ak) in &flipped {
        observe_state(tx, tid, ak)?;
    }
    Ok(flipped)
}

/// The parts of `parts.waiting` that keep snapshot `id` out of the walk (`validity::away_parts`).
fn away_of(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &Parts) -> Vec<(usize, usize, osis_commit::Decoded)> {
    parts.waiting.as_ref().map(|w| validity::away_parts(tx, h, id, &w.parts)).unwrap_or_default()
}

/// Joins deltas of an applied commit that arrived later (spec/commits.md §4). Late creation
/// records and edge writes reach perm as on apply (a certificate copy may bring a commit's
/// `roles.0` delta after its `created.0` one), and held deltas are re-judged.
pub(crate) fn join_late(tx: &mut Tx<'_>, id: &CommitId, merged: &CommitBlob, parts: Parts) -> Result<()> {
    tx.core.touch();
    let mut meta = tx.core.ix.commits.get(id).cloned().ok_or(Error::Corrupt("commit index"))?;
    let h = meta.header.clone();
    meta.missing.retain(|ai| !parts.has(*ai));
    tx.core.put_meta(*id, meta.clone());
    let uncarried = copies::uncarry(tx.core, id, &h, &|ai| parts.has(ai));
    let late = parts.ais();
    wake_listed(tx.core, &h, &late);
    let mut held_changed = note_created(tx, &h, merged, &parts.whole)?;
    copies::note_imports(tx.core, id, &h);
    let away = away_of(tx, &h, id, &parts);
    let edges = h.kind.is_role() && (!away.is_empty() || late.iter().any(|ai| h.aspects.get(*ai).is_some_and(|a| validity::edge_ak(a.ak.as_str()))));
    if h.kind.is_role() {
        held_changed |= judge_late(tx, &h, id, &parts, &mut meta)?;
    }
    let with_keys = with_keys(tx, &h, id, &parts)?;
    let pend = super::keys::before_join(tx, &h, &with_keys, &meta.valid)?;
    let void_import = h.kind == osis_commit::Kind::Import && tx.core.ix.void.contains(id);
    let mut j = joins(tx, &h, id, merged, &parts, &meta.valid, void_import)?;
    // the record's `node/edges` row, read once: it is also the commit's edge writes again
    let all = if h.kind.is_role() { Some(super::edge_parts_of(tx, id, &h, merged.clone())?) } else { None };
    tx.put_commit(id, merged, &meta, Shred::No, all.as_ref())?;
    note_held_rules(tx, &h, id, &parts)?;
    after_store(tx, &h, id, &uncarried, &BTreeSet::new(), &mut j)?;
    // expiry and purges for the late parts (a late snapshot part carrying purged values too)
    crate::retention::stripped_joined(tx, id, &parts.stripped_joined(), &mut j.changed)?;
    crate::retention::on_late(tx, id, &late, &mut j.changed)?;
    if edges && let Some(all) = &all {
        tx.core.ix.held.remove(id);
        let mut walked = all.clone();
        walked.0.extend(validity::EdgeParts::of(&h, &away).0);
        validity::add_role_commit(tx, &meta.view, Some(&h), id, &walked)?;
        held_changed = true;
    }
    if held_changed {
        tx.core.update_timelines();
    }
    observe_all(tx, &j)?;
    super::keys::after_join(tx, &h, &with_keys, &meta.valid, pend)?;
    let flipped = rejudged(tx, held_changed)?;
    if edges {
        let rosters: Vec<Tid> = h.aspects.iter().filter(|a| validity::edge_ak(a.ak.as_str())).map(|a| a.tid).collect();
        if meta.origin != Origin::Local {
            crate::rotation::mark_lost_due(tx, rosters.iter().copied())?;
        }
        for thing in rosters.into_iter().collect::<BTreeSet<_>>() {
            tx.core.events.queue(Event::Roster { thing });
        }
    }
    tx.core.events.queue(Event::Joined { id: *id });
    let changed = j.changed;
    for (t, a) in &changed {
        tx.core.mark_aspect_changed(t, a);
    }
    if !changed.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::LateDelta, changed: changed.into_iter().collect() });
    }
    if !flipped.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Validity, changed: flipped });
    }
    // a memory commit whose late parts went at once (expired, superseded)
    crate::retention::memory::forget_if_spent(tx, id)
}

/// Takes applied snapshot `id` out of the walk on a thing where a part of `waiting` is held with a
/// linked frontier away, if it is still in. Nothing joins: `rejudged` and its events as a late part's.
pub(crate) fn leave_walk(tx: &mut Tx<'_>, id: &CommitId, waiting: &[osis_commit::Part]) -> Result<()> {
    let meta = tx.core.ix.commits.get(id).cloned().ok_or(Error::Corrupt("commit index"))?;
    let h = meta.header.clone();
    let away = validity::away_parts(tx, &h, id, waiting);
    let out: BTreeSet<Tid> = away.iter().filter_map(|(ai, _, _)| h.aspects.get(*ai)).map(|a| a.tid).filter(|t| tx.core.ix.held.walks(id, t)).collect();
    if out.is_empty() {
        return Ok(());
    }
    tx.core.touch();
    let mut all = super::edge_parts(tx, id)?;
    all.0.extend(validity::EdgeParts::of(&h, &away).0);
    tx.core.ix.held.remove(id);
    validity::add_role_commit(tx, &meta.view, Some(&h), id, &all)?;
    tx.core.update_timelines();
    let flipped = rejudged(tx, true)?;
    if meta.origin != Origin::Local {
        crate::rotation::mark_lost_due(tx, out.iter().copied())?;
    }
    for thing in out {
        tx.core.events.queue(Event::Roster { thing });
    }
    if !flipped.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Validity, changed: flipped });
    }
    Ok(())
}

/// The late parts of role commit `id` judged with the parts held before (a grant's `roles.0`
/// part names what its `secrets.0` part may box): what that judged (an overreaching late
/// `secrets.0` part) holds for their join; other aspects' flips go through the re-judge
/// (`invalidated`, `revalidated`). Whether a late part's validity changed (`meta` updated).
fn judge_late(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &Parts, meta: &mut Meta) -> Result<bool> {
    let mut all = parts.whole.clone();
    all.extend(super::held_parts_at(tx, id, &|ai| !parts.has(ai))?);
    validity::note_required(tx.core, h, id, &all);
    let mut flipped = false;
    for ai in parts.ais() {
        let v = validity::part_valid(tx.core, h, id, ai);
        if let Some(x) = meta.valid.get_mut(ai)
            && *x != v
        {
            *x = v;
            flipped = true;
        }
    }
    if flipped {
        if let Some(m) = tx.core.ix.commits.get_mut(id) {
            m.valid = meta.valid.clone();
        }
        tx.core.index_validity(id);
    }
    Ok(flipped)
}

/// The late parts of commit `id` with, for a role commit, the held `keys.0` parts of the things
/// of its late `secrets.0` parts and the held `secrets.0` parts of those of its late `keys.0`
/// parts: late `secrets.0` parts establish epochs like the first ones, with the commit's
/// `keys.0`. The keysets "before" are the current `keys.0` state, which already holds this
/// commit's `keys.0` when that part joined earlier: an approximation like `revalidated`'s (a
/// keyset the commit replaced is no longer known; its removed keys come from the index of held
/// keyed entries, and a write whose removed keys are unknown waits as usual). A late `keys.0`
/// part likewise applies the held `secrets.0` of its thing again: applied without the keyset (a
/// role commit applies from any held part), they made no rotation.
fn with_keys(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &Parts) -> Result<Vec<(usize, usize, Decoded)>> {
    let mut out = parts.whole.clone();
    if h.kind != osis_commit::Kind::Role {
        return Ok(out);
    }
    let late = parts.ais();
    let late_on = |ak: &str| -> BTreeSet<Tid> { late.iter().filter_map(|ai| h.aspects.get(*ai)).filter(|a| a.ak.as_str() == ak).map(|a| a.tid).collect() };
    let (late_secrets, late_keys) = (late_on("secrets.0"), late_on("keys.0"));
    for (ai, a) in h.aspects.iter().enumerate() {
        let want = match a.ak.as_str() {
            "keys.0" => late_secrets.contains(&a.tid),
            "secrets.0" => late_keys.contains(&a.tid),
            _ => false,
        };
        if want && !parts.has(ai) {
            out.extend(super::held_parts(tx, id, ai)?.into_iter().map(|d| (ai, 0, d)));
        }
    }
    Ok(out)
}

/// The `secrets.0` entries a commit's joins touched, per aspect (`None`: anything may have
/// changed, read the whole state).
#[derive(Default)]
pub(super) struct Touched(std::collections::BTreeMap<(Tid, Ak), Option<SecretsKeys>>);

/// Keys of the box and history-box entries a change touched.
type SecretsKeys = (Vec<Value>, Vec<Value>);

impl Touched {
    pub(super) fn note(&mut self, tid: &Tid, ak: &Ak, f: &Fragment) {
        if ak.as_str() != "secrets.0" {
            return;
        }
        let keys = crate::engine::secrets::touched_keys(f);
        match (self.0.entry((*tid, ak.clone())).or_insert_with(|| Some((Vec::new(), Vec::new()))), keys) {
            (Some(acc), Some((b, h))) => {
                acc.0.extend(b);
                acc.1.extend(h);
            }
            (slot, _) => *slot = None,
        }
    }
    pub(super) fn whole(&mut self, tid: &Tid, ak: &Ak) {
        self.0.insert((*tid, ak.clone()), None);
    }
}

/// `observe_state`, reading only the touched `secrets.0` entries where known.
fn observe_touched(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, touched: &Touched) -> Result<()> {
    match touched.0.get(&(*tid, ak.clone())) {
        Some(Some((boxes, history))) => observe_secrets_keys(tx, tid, boxes, history),
        _ => observe_state(tx, tid, ak),
    }
}

/// What the `secrets.0` entries keyed `boxes` and `history` of `actor` hold (and the history chain
/// they reach) teaches this node: O(those entries), not O(boxes). Whether anything was learned.
pub(crate) fn ingest_secrets_keys(tx: &mut Tx<'_>, actor: &Tid, boxes: &[Value], history: &[Value]) -> Result<bool> {
    let ak = Ak::new("secrets.0").map_err(|_| Error::Misuse("ak"))?;
    // the boxes keyed so, and the history boxes (their chain is followed in memory)
    use osis_crdt::PathSeg;
    let mut paths: Vec<Vec<PathSeg>> = boxes.iter().map(|k| vec![PathSeg::Field(0), PathSeg::Key(k.clone())]).collect();
    paths.push(vec![PathSeg::Field(1)]);
    tx.ensure_paths(actor, &ak, &paths)?;
    let k = (*actor, ak);
    // taken out of the cache while the core learns from it, then put back
    let Some(st) = tx.core.states.get_mut(&k).and_then(Option::take) else { return Ok(false) };
    tx.core.touch();
    let learned = tx.core.ingest_keyed(actor, &st, boxes, history);
    tx.core.states.insert(k, Some(st));
    Ok(learned)
}

/// `ingest_secrets_keys`, persisting what was learned and reopening the boxes sealed to `actor`.
fn observe_secrets_keys(tx: &mut Tx<'_>, actor: &Tid, boxes: &[Value], history: &[Value]) -> Result<()> {
    if ingest_secrets_keys(tx, actor, boxes, history)? && let Some(e) = tx.core.ix.secrets.get(actor) {
        let b = crate::engine::secrets::encode_epochs(e);
        tx.txn.put_local(&[b"k/".as_slice(), actor.as_bytes()].concat(), &b, Shred::Yes)?;
        tx.core.waits.secrets_changed(actor);
        // boxes sealed to this actor elsewhere open now (role flows hook)
        crate::flows::reopen_dependents(tx, *actor)?;
    }
    #[cfg(test)]
    if tx.core.check_ingest {
        // the whole state's ingestion learns nothing the entries' did not
        let ak = Ak::new("secrets.0").map_err(|_| Error::Misuse("ak"))?;
        let before = tx.core.ix.secrets.get(actor).cloned();
        let st = tx.state(actor, &ak)?.cloned();
        let alts = st.as_ref().map(crate::engine::secrets::history_alts).unwrap_or_default();
        if let Some(s) = st.as_ref().and_then(Fragment::read).as_ref().and_then(crate::engine::secrets::secrets_value)
            && tx.core.ingest_secrets(actor, &s, None, &alts)
        {
            match before {
                Some(b) => tx.core.ix.secrets.insert(*actor, b),
                None => tx.core.ix.secrets.remove(actor),
            };
            return Err(Error::Misuse("per-entry secrets.0 ingestion missed what the whole state holds"));
        }
    }
    Ok(())
}

/// Keeps the indexes derived from states current: secrets opened from `secrets.0`, delete keys
/// and keyset epochs from `keys.0`, the `was.0` and `moved.0` indexes, group definitions.
pub(crate) fn observe_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if !matches!(ak.as_str(), "secrets.0" | "keys.0" | "was.0" | "moved.0" | "group.0" | "placed.0~") {
        return Ok(());
    }
    // `placed.0~` follows every state write (`Tx::placed_from`)
    if ak.as_str() == "placed.0~" {
        return Ok(());
    }
    let v = tx.state(tid, ak)?.and_then(Fragment::read);
    match ak.as_str() {
        "secrets.0" => {
            let alts = tx.state(tid, ak)?.map(crate::engine::secrets::history_alts).unwrap_or_default();
            if let Some(s) = v.as_ref().and_then(crate::engine::secrets::secrets_value)
                && tx.core.ingest_secrets(tid, &s, None, &alts)
                && let Some(e) = tx.core.ix.secrets.get(tid)
            {
                let b = crate::engine::secrets::encode_epochs(e);
                tx.txn.put_local(&[b"k/".as_slice(), tid.as_bytes()].concat(), &b, Shred::Yes)?;
                tx.core.waits.secrets_changed(tid);
                // boxes sealed to this actor elsewhere open now (role flows hook)
                crate::flows::reopen_dependents(tx, *tid)?;
            }
        }
        "keys.0" => {
            if let Some(k) = v.as_ref().and_then(crate::engine::secrets::keys_value) {
                // the keysets' epochs and suites it records are persisted with the epochs
                let before = tx.core.ix.secrets.get(tid).cloned();
                tx.core.observe_keys(tid, &k);
                if let Some(e) = tx.core.ix.secrets.get(tid)
                    && before.as_ref() != Some(e)
                {
                    let b = crate::engine::secrets::encode_epochs(e);
                    tx.txn.put_local(&[b"k/".as_slice(), tid.as_bytes()].concat(), &b, Shred::Yes)?;
                    tx.core.waits.secrets_changed(tid);
                }
            }
        }
        "was.0" => {
            if let Some(old) = tx.core.ix.was_of.remove(tid) {
                tx.core.ix.was.remove(&old, tid);
            }
            if let Some(Value::Tid(t)) = v {
                tx.core.ix.was.insert(t, *tid);
                tx.core.ix.was_of.insert(*tid, t);
            }
        }
        "moved.0" => match v {
            Some(Value::Tid(t)) => {
                tx.core.ix.moved.insert(*tid, t);
            }
            _ => {
                tx.core.ix.moved.remove(tid);
            }
        },
        // every path that changes a `group.0` (late deltas, re-judging) updates `groups.0`
        // (what a thing's groups are decides what the node syncs: its waits are examined again)
        "group.0" => {
            for t in tx.core.ix.groups.set(*tid, group_def(v)) {
                tx.core.waits.wake_thing(&t);
            }
        }
        _ => {}
    }
    Ok(())
}

/// A `group.0` value's (items, subgroups).
pub(crate) fn group_def(v: Option<Value>) -> Option<(BTreeSet<Tid>, BTreeSet<Tid>)> {
    v.and_then(|v| osis_schema::AspectKey::decode(&osis_schema::core_types::GROUP, &v).ok()).map(|g| (g.items, g.subgroups))
}

/// Un-merges `(tid, ak)` after validity only fell (deltas or carried writes newly invalid, none
/// valid again): the state without the writes of every delta invalid here, in place, when that
/// is what `rebuild` gives (none of them supersedes a write in the state, spec/crdt.md §4.6);
/// else `rebuild`. `fell`: the bodies of what fell, when known: a paged state then loads and
/// rewrites only the pages holding their dots (else the whole state). No other body is read.
/// Whether the state may have changed.
pub(crate) fn unmerge_fell(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, fell: Option<Fragment>) -> Result<bool> {
    let un = Unmerge::of(tx, tid, ak)?;
    let changed = unmerge_part(tx, tid, ak, &un, fell)?;
    unmerged_as_rebuilt(tx, tid, ak)?;
    Ok(changed)
}

/// `unmerge_fell` of the held deltas `parts` that turned invalid on `(tid, ak)`: a paged state a
/// piece of their bodies at a time (the pages holding its dots, then dropped), the whole state
/// in one pass when it is not paged, one is not held whole (dropped, partly received) or a
/// valid snapshot carries their writes.
pub(crate) fn unmerge_fallen(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, parts: &[(CommitId, usize)]) -> Result<()> {
    let un = Unmerge::of(tx, tid, ak)?;
    tx.load_lazy(tid, ak)?;
    let mut whole = parts.is_empty() || !un.in_place() || !tx.core.pages.contains_key(&(*tid, ak.clone()));
    if !whole {
        for (id, ai) in parts {
            let n = tx.core.ix.commits.get(id).filter(|m| !m.dropped.contains_key(ai)).and_then(|m| m.header.aspects.get(*ai)).map(|a| a.hashes.len());
            let got = super::each_held_piece(tx, id, *ai, &mut |tx, f| {
                unmerge_part(tx, tid, ak, &un, Some(f))?;
                tx.evict_pages(tid, ak);
                Ok(())
            })?;
            whole |= got.is_empty() || n != Some(got.len());
        }
    }
    if whole {
        unmerge_part(tx, tid, ak, &un, None)?;
    }
    unmerged_as_rebuilt(tx, tid, ak)
}

/// `unmerge_fell` without its check: an invalid delta streamed a piece at a time un-merges after
/// each piece's join, and only once its last piece joined is the state what a rebuild gives
/// (the rebuild drops at once every write under the delta's creations, those in pages a later
/// piece loads too). Rebuilds where removing in place cannot give the join (`Unmerge::in_place`,
/// or one of the writes superseded another in the state).
fn unmerge_part(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, un: &Unmerge, fell: Option<Fragment>) -> Result<bool> {
    let _s = crate::costs::span("unmerge: pass");
    if !un.in_place() {
        return rebuild(tx, tid, ak).map(|()| true);
    }
    let bad = |d: &osis_crdt::Dot| un.bad(d);
    tx.load_lazy(tid, ak)?;
    let k = (*tid, ak.clone());
    // a paged collection below an entry an invalid delta created goes whole with it, pages not
    // holding the fallen dots too (others' writes nested there): loaded and written whole
    let touch = fell.as_ref().and_then(|f| crate::engine::pages::touch_of(f, tx.core.pages.get(&k))).filter(|_| !tx.core.pages.get(&k).is_some_and(|i| i.below_entry_of(&bad)));
    tx.ensure_touch(tid, ak, &touch)?;
    let in_place = match tx.core.states.get(&k).and_then(Option::as_ref) {
        None => None,
        Some(cur) if cur.dots_supersede(&bad) => return rebuild(tx, tid, ak).map(|()| true),
        Some(cur) => Some(cur.holds_dots(&bad)),
    };
    if in_place == Some(true) {
        let mut st = tx.core.states.get_mut(&k).and_then(Option::take).unwrap_or_default();
        st.remove_dots(&bad);
        st.prune(None, &mut Changes::new());
        let st = tx.kept(tid, ak, st)?;
        tx.core.touch();
        tx.core.wrote(k);
        tx.set_state_touched(tid, ak, st, &touch, Shred::Yes)?;
    }
    Ok(in_place == Some(true))
}

/// Debug builds: the state of `(tid, ak)` after an un-merge in place is what rebuilding gives,
/// as stored: a reopen forgets a deleted text element's char (spec/crdt.md §5.7, its creation's
/// body gives it back on a rebuild, and only a fallen delete needs it: that rebuilds), so a state
/// reopened and one kept in memory differ there and read alike.
fn unmerged_as_rebuilt(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    #[cfg(debug_assertions)]
    {
        use crate::engine::state::encode;
        let want = rebuilt(tx, tid, ak, &[], &BTreeSet::new())?.0;
        let got = tx.state(tid, ak)?;
        debug_assert!(got.map(encode).transpose()? == want.as_ref().map(encode).transpose()?, "in-place un-merge of {tid:?} {ak:?} differs from a rebuild:\n  in place {got:?}\n  rebuilt  {want:?}");
    }
    #[cfg(not(debug_assertions))]
    let _ = (tx, tid, ak);
    Ok(())
}

/// Rebuilds `(tid, ak)` after validity changed (spec/crdt.md §4.6, spec/permissions.md §5.2):
/// the join of the current state (a snapshot this node holds), the residues and every held
/// body, the state, residues and delta bodies first stripped of the writes of the deltas now
/// invalid here (by counter range or commit ID, so the author's valid deltas, dropped bodies
/// included, keep theirs) and of the writes valid snapshots misstate; a valid snapshot's copies
/// of those writes all join (`Unmerge::unvouched`), so it gives its copy alone.
pub(crate) fn rebuild(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    rebuild_without(tx, tid, ak, &[])
}

/// `rebuild`, the writes `gone` matches first removed from the current state, exactly (others'
/// writes nested under them stay): what a snapshot turned invalid gave
/// (`copies::given_by`). Reports each valid snapshot misstating a held delta.
pub(crate) fn rebuild_without(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, gone: &[Owned]) -> Result<()> {
    let (st, misstating) = rebuilt(tx, tid, ak, gone, &BTreeSet::new())?;
    let now = tx.now();
    for s in misstating {
        let peer = tx.core.ix.commits.get(&s).map(|m| m.view.author);
        let d = crate::events::Diagnostic { kind: crate::events::DiagnosticKind::Misstated, tids: vec![*tid], commit: Some(s), peer, detail: format!("{ak}: a snapshot copies a held write otherwise") };
        tx.core.events.diagnostic(d, now);
    }
    tx.set_state(tid, ak, st, Shred::Yes, false)
}

/// The residues of `(tid, ak)` (`records::RESIDUE`), not a void import's (its body joins
/// nothing either). Invariant: every non-value write and value-less stamp of a delta held
/// value-less is in a body or a residue the node holds, never in the state alone, so a rebuild
/// (an un-merge) gives it back after a later write that superseded it in the state goes: the
/// state stays the join of what is held, whatever the order the expiry, that write and its
/// revocation came in. Held: a body dropped as covered gives its residue from its coverers'
/// copies (`retention::make_valueless`) while one carries it (`retention::uncover` drops it); a part missing at expiry or purge gives none and joins
/// when a late copy comes (`retention::takes_late`), as does one dropped for its keep bounds
/// before it went value-less (it counts as never received, spec/commits.md §5).
fn residues(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Vec<Fragment>> {
    let mut rows = Vec::new();
    tx.scan(&records::aspect_key(records::RESIDUE, tid, ak), |k, v| {
        let mut r = records::Rd::new(k);
        let c = CommitId(r.arr()?);
        let ai = u32::from_be_bytes(r.arr()?) as usize;
        rows.push((c, ai, v));
        Ok(())
    })?;
    let mut out = Vec::new();
    for (c, ai, v) in rows {
        if !tx.core.ix.void.contains(&c) && crate::retention::valueless(tx.core, &c, ai) {
            out.push(crate::engine::state::decode(&v)?);
        }
    }
    Ok(out)
}

/// What `rebuild_without` writes, and the valid snapshots misstating a held delta other than by
/// value-less copies. A held
/// delta's writes under a dot a held valid snapshot misstates (`copies::misstated_in`) count
/// for nothing: the snapshots' copies govern, joined by the copy order (spec/permissions.md
/// §5.2). Under a dot any held snapshot misstates the current state's writes go first, so the
/// held bodies give them again. The held bodies of `skip` are left out (their writes must be in
/// `gone`).
pub(crate) fn rebuilt(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, gone: &[Owned], skip: &BTreeSet<CommitId>) -> Result<(Option<Fragment>, BTreeSet<CommitId>)> {
    // newest first (a join does not depend on the order), for `Fragment::settled_above`
    let held: Vec<(osis_base::Ts, CommitId)> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).map(|s| s.iter().rev().copied().collect()).unwrap_or_default();
    // snapshots or imports held: their copies are judged against the deltas, read whole below
    let copies = tx.core.ix.snapshots.get(&(*tid, ak.clone())).is_some_and(|v| !v.is_empty()) || tx.core.ix.imports.range((*tid, CommitId([0; 32]))..).next().is_some_and(|((t, _), _)| t == tid);
    // the part of `c` that may join, with whether it is a snapshot's and valid
    let joining = |tx: &mut Tx<'_>, c: &CommitId| -> Result<Option<(usize, bool, bool)>> {
        if skip.contains(c) {
            return Ok(None);
        }
        let Some(ai) = tx.core.ix.commits.get(c).and_then(|m| m.aspect(tid, ak)) else { return Ok(None) };
        // stored: a commit being applied joins once stored
        if !super::stores_part(tx, c, ai)? {
            return Ok(None);
        }
        let Some(m) = tx.core.ix.commits.get(c) else { return Ok(None) };
        // nor does a void import's (spec/permissions.md §7)
        if m.header.kind == osis_commit::Kind::Import && tx.core.ix.void.contains(c) {
            return Ok(None);
        }
        Ok(Some((ai, m.header.kind.is_compaction(), m.valid_at(ai))))
    };
    // the held snapshots (valid or not: an invalid one joins nothing, spec/permissions.md §5.2)
    // and the held deltas
    let mut snaps: Vec<(CommitId, bool)> = Vec::new();
    let mut deltas: Vec<(CommitId, usize, Header)> = Vec::new();
    if copies {
        for (_, c) in &held {
            let Some((ai, snap, valid)) = joining(tx, c)? else { continue };
            if snap {
                snaps.push((*c, valid));
            } else if let Some(m) = tx.core.ix.commits.get(c) {
                deltas.push((*c, ai, (*m.header).clone()));
            }
        }
    }
    let un = Unmerge::of(tx, tid, ak)?;
    // misstated writes: per held delta, against every held snapshot
    let mut strip_state: BTreeSet<osis_crdt::Dot> = BTreeSet::new();
    let mut strip_own: BTreeMap<CommitId, BTreeSet<osis_crdt::Dot>> = BTreeMap::new();
    let mut misstating = BTreeSet::new();
    if !deltas.is_empty() {
        let mut ixs = Vec::new();
        for (s, valid) in snaps {
            if let Some(ix) = copies::copy_index(tx, &s, tid, ak)? {
                ixs.push((s, valid, ix));
            }
        }
        for (c, ai, h) in &deltas {
            // the delta's writes, indexed once it is compared
            let mut own = None;
            for (s, valid, ix) in &ixs {
                let dots = copies::misstated_in(tx, ix, h, c, *ai, &mut own)?;
                if dots.is_empty() {
                    continue;
                }
                strip_state.extend(dots.iter().cloned());
                if *valid {
                    // reported unless only value-less: an honest snapshot taken after a purge
                    // this node has not seen yet (its copy governs all the same)
                    if !ix.misstated(&copies::owned_ranges(h, c, *ai), copies::held_copies(tx, c, *ai, &mut own)?, true).is_empty() {
                        misstating.insert(*s);
                    }
                    strip_own.entry(*c).or_default().extend(dots);
                }
            }
        }
    }
    let current = tx.state(tid, ak)?.cloned();
    // the state and the residues of bodies dropped value-less: what the node holds beyond its
    // bodies (spec/crdt.md §4.6 Un-merge)
    let mut kept: Vec<Fragment> = current.into_iter().chain(residues(tx, tid, ak)?).collect();
    for c in kept.iter_mut() {
        if !strip_state.is_empty() {
            c.strip_forged(&|d| strip_state.contains(d));
        }
        if !gone.is_empty() {
            c.strip_copies(&|d| gone.iter().any(|o| o.owns(d)));
        }
    }
    let mut st = Fragment::default();
    let mut ch = Changes::new();
    for mut b in kept {
        un.strip(&mut b);
        st.join_into(b, None, &mut ch);
    }
    // the bodies a piece at a time, until none can change a settled state (debug builds: all of
    // them, checking that)
    let mut settled = None;
    for (ts, c) in &held {
        if !copies && settled.is_none() && st.settled_above(*ts) {
            if !cfg!(debug_assertions) {
                break;
            }
            settled = Some(st.clone());
        }
        let _s = settled.is_none().then(|| crate::costs::span("rebuild: body"));
        let Some((ai, snap, valid)) = joining(tx, c)? else { continue };
        debug_assert!(copies || !snap, "snapshot {c:?} of {tid:?} {ak:?} held and stored, not in `ix.snapshots`");
        if snap && !valid {
            continue;
        }
        let own = strip_own.get(c);
        super::each_held_piece(tx, c, ai, &mut |_, mut f| {
            if let Some(dots) = own {
                f.strip_forged(&|d| dots.contains(d));
            }
            if snap {
                f.remove_dots(&|d| un.unvouched(d));
            } else {
                un.strip(&mut f);
            }
            st.join_into(f, None, &mut ch);
            Ok(())
        })?;
    }
    debug_assert!(settled.as_ref().is_none_or(|x| *x == st), "a rebuild of {tid:?} {ak:?} stopped early: {settled:?}, all bodies {st:?}");
    strip_valueless(tx.core, tid, ak, &mut st);
    Ok(((!st.is_empty()).then_some(st), misstating))
}

#[cfg(test)]
mod tests {
    use super::{Owned, OwnedSet};
    use osis_crdt::{Dot, Source};

    // `OwnedSet::owns` is `Owned::owns` of any of them, counters at both ends of the range too.
    #[test]
    fn owned_set_matches_owned_spec_crdt_4_6() {
        let srcs = [Source::session(osis_crdt::Session { node: osis_base::Tid::from_bytes([1; 15]), nonce: [0; osis_crdt::SESSION_NONCE_LEN] }), Source::session(osis_crdt::Session { node: osis_base::Tid::from_bytes([2; 15]), nonce: [0; osis_crdt::SESSION_NONCE_LEN] }), Source::commit(osis_base::CommitId([3; 32])), Source::commit(osis_base::CommitId([4; 32]))];
        let ctrs: Vec<u64> = (1..14).chain([u64::MAX - 1, u64::MAX]).collect();
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = |n: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as usize % n
        };
        for _ in 0..3000 {
            let owned: Vec<Owned> = (0..next(6))
                .map(|_| {
                    let src = srcs[next(srcs.len())].clone();
                    match next(3) {
                        0 => {
                            let (a, b) = (ctrs[next(ctrs.len())], ctrs[next(ctrs.len())]);
                            Owned::Range { src, lo: a.min(b), hi: a.max(b) }
                        }
                        1 => Owned::Commit(osis_base::CommitId([3 + next(2) as u8; 32])),
                        _ => {
                            let mut c: Vec<u64> = (0..next(4)).map(|_| ctrs[next(ctrs.len())]).collect();
                            c.sort_unstable();
                            c.dedup();
                            Owned::Dots { src, ctrs: c }
                        }
                    }
                })
                .collect();
            let set = OwnedSet::of(&owned);
            assert_eq!(set.is_empty(), owned.is_empty());
            for src in &srcs {
                for ctr in &ctrs {
                    let d = Dot { src: src.clone(), ctr: *ctr };
                    assert_eq!(set.owns(&d), owned.iter().any(|o| o.owns(&d)), "{owned:?} {d:?}");
                }
            }
        }
    }
}

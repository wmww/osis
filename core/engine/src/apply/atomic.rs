//! Applying a commit (spec/commits.md §4): one store transaction joins every valid delta of a commit
//! after its role records reach perm, marks the bodies its joins may have replaced, applies expiry and purges, and
//! re-judges held deltas when the held set changed; events go out after it is durable.

use super::{Parts, Streamed, copies, validity};
use crate::engine::{Core, Meta, Owned, Tx, records};
use crate::error::{Error, Result};
use crate::events::{Cause, Event, Origin};
use crate::retention::Killed;
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

/// Forgets snapshot `id` of `(tid, ak)` when its body drops: its index entry is derived from
/// the body (spec/commits.md §5), which a rebuild cannot read.
pub(crate) fn forget_snapshot(core: &mut Core, tid: &Tid, ak: &Ak, id: &CommitId) {
    let k = (*tid, ak.clone());
    if let Some(mut v) = core.ix.snapshots.get(&k).cloned()
        && v.iter().any(|x| x.1 == *id)
    {
        v.retain(|x| x.1 != *id);
        if v.is_empty() {
            core.ix.snapshots.remove(&k);
        } else {
            core.ix.snapshots.insert(k, v);
        }
    }
}

/// Adds a commit to the per-aspect and session range indexes.
pub(crate) fn index_commit(core: &mut Core, id: &CommitId, h: &crate::engine::View) {
    for a in &h.aspects {
        core.ix.by_aspect.insert((a.tid, a.ak.clone()), (h.ts, *id));
        if a.ak.as_str() == crate::flows::LINK_SEED {
            core.links = None;
        }
        core.ix.by_thing.insert((a.tid, h.author), *id);
        if h.form.counted() && h.kind.has_own_writes() && a.lo < a.hi {
            core.ix.ranges.insert((a.tid, a.ak.clone(), h.form.own_source(h.author, *id)), (a.lo, *id), a.hi);
        }
    }
    if h.actor != h.author {
        core.ix.by_actor.insert((h.actor, h.author), *id);
    }
    for b in &h.chunks {
        core.ix.by_chunk.insert(*b, *id);
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
            for ((lo, c), hi) in m.range(..(a.hi, CommitId([0; 32]))) {
                if *hi > a.lo && *lo < a.hi && c != id {
                    out.insert(*c);
                }
            }
        }
    }
    out
}

/// Joins `delta` (a whole delta, or one piece of one: spec/crdt.md §8) into the state of
/// `(tid, ak)`: the ordinary valid join. The writes of deltas invalid here go first; `snap`: a
/// valid snapshot's part, whose own copies of them all join (spec/permissions.md §5.2). Then the
/// value-less list (`strip_valueless`): the one join-time predicate, so no value a delta held
/// value-less here reaches the state from any body (an undelete's copy of a char, a stale
/// copy, a snapshot's); the same predicate ends every rebuild.
/// A paged state loads only the pages the join touches, or where it resets or re-encodes a
/// paged collection joins it a page at a time (`Tx::join_reset`).
pub(crate) fn join_into_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, mut delta: Fragment, snap: bool, dead: Option<&mut Killed>) -> Result<Changes> {
    let _s = crate::costs::span("apply: join");
    tx.load_lazy(tid, ak)?;
    // writes carried by deltas invalid here go from every body before it joins (un-merge is a
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
        // superseder (spec/crdt.md §4.8), which this join cannot meet: judged again from the bodies
        crate::retention::mark_bounded(tx, tid, ak);
    }
    // the state is held stripped and stripping commutes with join (spec/crdt.md §4.7): the
    // one predicate, applied to what joins and to what a rebuild gives
    strip_valueless(tx.core, tid, ak, &mut delta);
    // a paged state loads only the pages the join touches
    let touch = crate::engine::pages::touch_of(&delta, tx.core.pages.get(&(*tid, ak.clone())));
    if touch.is_none()
        && let Some(ch) = tx.join_reset(tid, ak, &delta)?
    {
        if let Some(dead) = dead {
            dead.all = true;
        }
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
    let before = dead.as_ref().map(|_| (Killed::before(&st, &delta), delta.clone()));
    let ch = st.join(delta);
    if let (Some(dead), Some((w, d))) = (dead, before) {
        dead.note(&w, &st, &d);
    }
    let secrets = secrets.and_then(|(mut read, d)| super::keys::secrets_patch(std::sync::Arc::make_mut(&mut read), &d, &st).then_some(read));
    let st = tx.kept(tid, ak, st)?;
    if ch.is_changed() {
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
    let mut v: Vec<(usize, PartRef<'_>)> = parts.whole.iter().map(|(ai, d)| (*ai, PartRef::Whole(d))).collect();
    v.extend(parts.streamed.iter().map(|s| (s.ai, PartRef::Streamed(s))));
    v.sort_by_key(|x| x.0);
    v
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
    let p = blob.parts.iter().find(|p| p.ai == s.ai).ok_or(Error::Corrupt("streamed part"))?;
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
    /// Aspects rebuilt once the commit is stored (its own bodies join too): one a valid
    /// snapshot vouching for invalid writes joined into, or one an invalid delta arrived on.
    pub rebuild: BTreeSet<(Tid, Ak)>,
    /// Per valid part joined on an aspect holding a body with a relative bound, the writes its
    /// joins superseded: the bodies they replaced are judged again (`retention::mark_killed`),
    /// after the commit's record.
    pub joined: Vec<(Tid, Ak, Killed)>,
}

/// Joins every part of commit `id` (`valid`: per aspect), in part order, a piece at a time (tests under `Core::whole_apply`: `oracle::joins`).
///
/// Invariant (the differential `tests_paged` checks it against `oracle::joins`, which decodes
/// and joins every part whole): joining a delta a piece at a time, each piece's state pages
/// written to the store and dropped from the cache before the next, leaves exactly the state,
/// snapshot records and outcomes that joining it whole does. Pieces split a delta by
/// element (§8), and what is judged of a whole delta is judged of its pieces: un-merging,
/// vouching and holding value-less per write, superseded writes per join.
fn joins(tx: &mut Tx<'_>, h: &Header, id: &CommitId, blob: &CommitBlob, parts: &Parts, valid: &[bool]) -> Result<Joins> {
    let mut j = Joins::default();
    #[cfg(test)]
    if tx.core.whole_apply {
        super::oracle::joins(tx, h, id, parts, valid, &mut j)?;
        return Ok(j);
    }
    for (ai, part) in in_order(parts) {
        join_part(tx, h, id, blob, ai, part, valid.get(ai).copied().unwrap_or(false), &mut j)?;
    }
    Ok(j)
}

/// Joins one part (`joins`): every held snapshot notes its frontiers, whatever its validity; a
/// valid part joins (a valid snapshot's writes like any write, spec/crdt.md §4.1: they are
/// never compared with their own delta's); an invalid delta does not join: the aspect is
/// rebuilt once it is stored (`after_store`: its writes and others' writes nested under its
/// creations go, spec/crdt.md §4.6); an invalid snapshot gives
/// nothing (its copies never join, spec/permissions.md §5.2).
#[allow(clippy::too_many_arguments)]
fn join_part(tx: &mut Tx<'_>, h: &Header, id: &CommitId, blob: &CommitBlob, ai: usize, part: PartRef<'_>, v: bool, j: &mut Joins) -> Result<()> {
    let Some(a) = h.aspects.get(ai) else { return Ok(()) };
    let (tid, ak) = (a.tid, a.ak.clone());
    // a signal joins no state (spec/data-model.md §2): its body is held as history, heard
    // through `Event::Commits` (spec/commits.md §5 Signals)
    if ak.signal() {
        return Ok(());
    }
    let gives = part.gives();
    let snap = gives.is_some();
    // edge and creation aspects reach perm instead
    let perm = validity::perm_ak(ak.as_str());
    if !v && !snap && perm {
        return Ok(());
    }
    if let Some(fr) = gives {
        note_snapshot(tx.core, &tid, &ak, h.ts, id, fr);
    }
    // a valid snapshot carrying writes of deltas invalid here makes them count again, and
    // others' writes nested under them come back only from their bodies: the aspect is rebuilt
    // (spec/crdt.md §4.6)
    let owned = if snap && v { invalid_of(tx.core, &tid, &ak) } else { Vec::new() };
    let mut vouch = false;
    // superseded writes matter only for bodies with a relative bound
    let bounded = v && (crate::retention::any_bounded(tx.core, &tid, &ak) || crate::engine::listing::listened(tx.core, &tid, &ak));
    let mut ch = Changes::new();
    let mut dead = Killed::default();
    // an invalid delta (the one path, issues/drop-rejoin-robust.md item 1): nothing of it
    // joins; the aspect is rebuilt from the held bodies once it is stored
    if !v && !snap {
        j.rebuild.insert((tid, ak.clone()));
        return Ok(());
    }
    each_piece(tx, h, id, blob, part, &mut |tx, f| {
        if snap {
            vouch |= copies::vouches_any(&f, &owned);
        }
        if !v {
            return Ok(());
        }
        j.touched.note(&tid, &ak, &f);
        ch.merge(join_into_state(tx, &tid, &ak, f, snap, bounded.then_some(&mut dead))?);
        tx.evict_pages(&tid, &ak);
        Ok(())
    })?;
    if vouch {
        j.rebuild.insert((tid, ak.clone()));
    }
    if !v {
        return Ok(());
    }
    if ch.is_changed() {
        j.changed.insert((tid, ak.clone()));
    }
    j.joined.push((tid, ak, dead));
    Ok(())
}

/// What un-merging removes on `(tid, ak)` (spec/crdt.md §4.6, spec/permissions.md §5.2): from
/// every delta body (leftovers included) and the state the writes of the held deltas invalid here,
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
    /// Whether `f` carries a value of a write of theirs (`Fragment::strip` would change it).
    fn valued_in(&self, f: &Fragment) -> bool {
        let mut g = f.clone();
        g.strip(&|d| self.owns(d));
        g != *f
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
    /// Whether what a delta body or the state holds under origin dot `d` goes.
    pub(crate) fn bad(&self, d: &osis_crdt::Dot) -> bool {
        self.owned.owns(d)
    }
    /// Whether a held valid snapshot holds a write in the record of dot `d` and key `key`: of
    /// a keyed map entry, its creation's copy under that key or the record itself (its
    /// creation pruned by a reset, alive by a later nested write); else any write under `d`.
    /// A key-erased record (its writer held the dot value-less, spec/crdt.md §4.7) keeps every
    /// record of its dot, the state's own key-erased record (asked with no key) included:
    /// nested writes of other deltas live there, and the answer must not
    /// change when the dot goes value-less here, since no rebuild runs then.
    /// Limit: with the dot value-less here, the state's key-erased record is asked with no
    /// key, so a copy under another key keeps it there but not in a body.
    fn vouches(&self, d: &osis_crdt::Dot, key: Option<&osis_base::Value>) -> bool {
        if self.erased.contains(d) {
            return true;
        }
        match key {
            Some(k) => self.vouched.contains(&(d.clone(), Some(k.clone()))),
            None => self.vouched.range((d.clone(), None)..).next().is_some_and(|x| x.0 == *d),
        }
    }
    /// Whether what a valid snapshot's body holds under origin dot `d` goes.
    pub(crate) fn unvouched(&self, d: &osis_crdt::Dot) -> bool {
        self.bad(d) && !self.vouches(d, None)
    }
    /// Removes from a delta body or the state what un-merging removes (spec/crdt.md
    /// §4.6): the invalid deltas' writes, the records they created and others' writes nested in
    /// them, except in a record a held valid snapshot's copy keeps (`vouches`): the record
    /// stays in the state, so others' valid writes in it stay too. A copy of a map entry's
    /// creation under another key keeps its own record, not the delta's; a key-erased one
    /// keeps them all.
    pub(crate) fn strip(&self, f: &mut Fragment) {
        if !self.is_empty() {
            f.remove_dots_keeping(&|d| self.bad(d), &|d, k| self.vouches(d, k));
        }
    }
}

/// Whether held part `ai` of `c` carries a value of a write of `owned` (`rebuild`'s invariant).
pub(crate) fn carries_any(tx: &mut Tx<'_>, c: &CommitId, ai: usize, owned: &[Owned]) -> Result<bool> {
    let set = OwnedSet::of(owned);
    let mut carries = false;
    super::each_held_piece(tx, c, ai, &mut |_, f| {
        carries = carries || set.valued_in(&f);
        Ok(())
    })?;
    Ok(carries)
}

/// The writes of the held deltas on `(tid, ak)` that are invalid here.
pub(crate) fn invalid_of(core: &Core, tid: &Tid, ak: &Ak) -> Vec<Owned> {
    let mut out = Vec::new();
    for c in core.ix.invalid.get(&(*tid, ak.clone())).into_iter().flatten() {
        let Some(m) = core.ix.commits.get(c) else { continue };
        let Some(ai) = m.aspect(tid, ak) else { continue };
        if m.valid_at(ai) {
            continue;
        }
        out.extend(crate::retention::writes_of(&m.header, c, ai));
    }
    out
}

pub(crate) fn strip_valueless(core: &Core, tid: &Tid, ak: &Ak, st: &mut Fragment) {
    if let Some(v) = core.ix.valueless.get(&(*tid, ak.clone()))
        && !v.is_empty()
    {
        st.strip(&|d| crate::retention::sorted_owns(v, d));
    }
}

/// Records the creation records durable commit `h` carries on `created.0` that are not held
/// yet; whether any was new.
fn note_created(tx: &mut Tx<'_>, h: &Header, parts: &[(usize, Decoded)]) -> Result<bool> {
    let mut any = false;
    if h.ephemeral.is_some() {
        return Ok(false);
    }
    for (ai, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() != osis_commit::retention::CREATED || tx.core.created(&a.tid).is_some() {
            continue;
        }
        let rec = d.fragment().read().as_ref().and_then(CreationRecord::from_value).ok_or(Error::BadInput("created.0"))?;
        if rec.tid() == a.tid {
            let key = [records::CREATED, a.tid.as_bytes()].concat();
            tx.txn.put_local(&key, &osis_base::encode(&rec.to_value()), Shred::No)?;
            tx.core.ix.held.create(rec);
            tx.core.inbox_actors = None;
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

/// Role commit `id` (with a frontier) is due an answer by this node's addenda, kept across
/// restarts (`records::ADDENDA_DUE`).
fn note_addenda_due(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    if tx.core.ix.addenda_due.insert(*id) {
        tx.txn.put_local(&[records::ADDENDA_DUE, &id.0[..]].concat(), &[], Shred::No)?;
    }
    Ok(())
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
    let mut held_changed = note_created(tx, &h, &parts.whole)?;
    let view = Arc::new(crate::engine::View::of(&h));
    if h.kind.is_role() {
        validity::note_required(tx.core, &h, &id, &parts.whole);
        validity::add_role_commit(tx.core, &view, &id, &validity::EdgeParts::of(&h, &parts.whole));
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
    index_commit(tx.core, &id, &view);
    validity::note_addenda(tx.core, &h, &id, &parts.whole);
    // an explicit demotion: this node answers it with its addenda (`Engine::answer_removals`)
    if h.kind.is_role() && view.frontier.is_some() {
        note_addenda_due(tx, &id)?;
    }
    let valid: Vec<bool> = (0..h.aspects.len()).map(|ai| validity::part_valid(tx.core, &h, &id, ai)).collect();
    let missing: BTreeSet<usize> = (0..h.aspects.len()).filter(|ai| !parts.has(*ai)).collect();
    let meta = Meta { view, header: crate::engine::LazyHeader::ready(h.clone()), received, origin, valid: valid.clone(), dropped: BTreeMap::new(), stripped: BTreeSet::new(), valued: BTreeSet::new(), missing };
    crate::retention::fetch_fallen(tx, &h, &id, &meta.missing)?;
    tx.core.put_meta(id, meta.clone());
    tx.core.index_validity(&id);
    crate::retention::note_requests(tx, &id, &h)?;

    let pend = super::keys::before_join(tx, &h, &parts.whole, &valid)?;
    let mut j = joins(tx, &h, &id, blob, &parts, &valid)?;
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
    after_store(tx, &mut j)?;
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
    } else {
        // an own edge with an `until` (a self-demotion): judged when it passes
        crate::rotation::arm_untils(tx, rosters.iter().copied())?;
    }
    // a memory commit is ephemeral state to watchers (a local one's batch queues its own event,
    // `Engine::write`); node-sync carries its bodies as any commit's (`mark_changed`)
    if h.ephemeral.is_some() {
        tx.core.memory.dirty.extend(h.aspects.iter().map(|a| (a.tid, a.ak.clone())));
        if origin != Origin::Local {
            tx.core.events.queue(Event::Ephemeral { id, origin, author: h.author, actor: h.actor, ts: h.ts, received, changed: changed.into_iter().collect() });
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
    for a in h.aspects.iter().filter(|a| a.ak.as_str() == "created.0") {
        tx.core.events.queue(Event::Created { thing: a.tid });
    }
    // a memory commit expired or superseded on arrival is not kept
    crate::retention::memory::forget_if_spent(tx, &id)
}

/// Notes the `required^.0` deltas among `parts`, once stored (`validity::note_required_rules`).
fn note_held_rules(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &Parts) -> Result<()> {
    for ai in parts.ais() {
        if h.aspects.get(ai).is_some_and(|a| a.ak.as_str() == osis_commit::retention::REQUIRED) {
            let held: Vec<(usize, osis_commit::Decoded)> = super::held_part(tx, id, ai)?.into_iter().map(|d| (ai, d)).collect();
            validity::note_required_rules(tx.core, h, id, &held);
        }
    }
    Ok(())
}

/// A delta invalid on arrival whose part is not held (it may never come, or come late), on
/// apply or late: others' writes already joined may sit under its creations, so the aspect is
/// rebuilt as on a flip (a held one once stored, `join_part`). Edge and creation aspects reach
/// perm instead.
fn arrived_invalid(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, j: &mut Joins) -> Result<()> {
    if validity::perm_ak(ak.as_str()) || ak.signal() {
        return Ok(());
    }
    if invalid_of(tx.core, tid, ak).is_empty() {
        return Ok(());
    }
    rebuild_changed(tx, tid, ak, j)
}

/// Once commit `id` is stored, so its own bodies join too: the rebuilds its joins call for
/// (`Joins::rebuild`), then the bodies its valid parts' joins replaced are marked.
fn after_store(tx: &mut Tx<'_>, j: &mut Joins) -> Result<()> {
    for (tid, ak) in std::mem::take(&mut j.rebuild) {
        // counted: tests read whether a snapshot vouched
        let _s = crate::costs::span("apply: vouched rebuild");
        rebuild_changed(tx, &tid, &ak, j)?;
    }
    for (tid, ak, dead) in &j.joined {
        crate::retention::mark_killed(tx, tid, ak, dead);
    }
    Ok(())
}

/// `rebuild` of `(tid, ak)` in an apply: noted for its events and indexes.
fn rebuild_changed(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, j: &mut Joins) -> Result<()> {
    rebuild(tx, tid, ak)?;
    j.changed.insert((*tid, ak.clone()));
    j.touched.whole(tid, ak);
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
pub(crate) fn rejudged(tx: &mut Tx<'_>, held_changed: bool) -> Result<Vec<(Tid, Ak)>> {
    if !held_changed && !tx.core.stale() {
        return Ok(Vec::new());
    }
    let flipped = validity::rejudge_all(tx, true)?;
    for (tid, ak) in &flipped {
        observe_state(tx, tid, ak)?;
    }
    Ok(flipped)
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
    let late = parts.ais();
    let mut held_changed = note_created(tx, &h, &parts.whole)?;
    let edges = h.kind.is_role() && late.iter().any(|ai| h.aspects.get(*ai).is_some_and(|a| validity::edge_ak(a.ak.as_str())));
    validity::note_addenda(tx.core, &h, id, &parts.whole);
    if edges && meta.view.frontier.is_some() {
        note_addenda_due(tx, id)?;
    }
    if h.kind.is_role() {
        held_changed |= judge_late(tx, &h, id, &parts, &mut meta)?;
    }
    let with_keys = with_keys(tx, &h, id, &parts)?;
    let pend = super::keys::before_join(tx, &h, &with_keys, &meta.valid)?;
    let mut j = joins(tx, &h, id, merged, &parts, &meta.valid)?;
    // the record's `node/edges` row, read once: it is also the commit's edge writes again
    let all = if h.kind.is_role() { Some(super::edge_parts_of(tx, id, &h, merged.clone())?) } else { None };
    tx.put_commit(id, merged, &meta, Shred::No, all.as_ref())?;
    // a leftover set aside at a purge's fall is stale once a copy joined whole
    crate::retention::forget_joined_leftovers(tx, &h, id, &late)?;
    note_held_rules(tx, &h, id, &parts)?;
    after_store(tx, &mut j)?;
    // a snapshot back and judged invalid carries nothing: the parts dropped under its cover
    // alone are missing again, as when a held one turns invalid (spec/permissions.md §5.2)
    let fell: Vec<usize> = if h.kind.is_compaction() { late.iter().copied().filter(|ai| tx.core.ix.commits.get(id).is_some_and(|m| !m.valid_at(*ai))).collect() } else { Vec::new() };
    for ai in fell {
        let Some(a) = h.aspects.get(ai) else { continue };
        crate::retention::uncover(tx, &a.tid, &a.ak)?;
        rebuild_changed(tx, &a.tid, &a.ak, &mut j)?;
    }
    // expiry and purges for the late parts (a late snapshot part carrying purged values too)
    crate::retention::stripped_joined(tx, id, &parts.stripped_joined(), &mut j.changed)?;
    crate::retention::on_late(tx, id, &late, &mut j.changed)?;
    if edges && let Some(all) = &all {
        tx.core.ix.held.remove(id);
        validity::add_role_commit(tx.core, &meta.view, id, all);
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
        } else {
            crate::rotation::arm_untils(tx, rosters.iter().copied())?;
        }
        for thing in rosters.into_iter().collect::<BTreeSet<_>>() {
            tx.core.events.queue(Event::Roster { thing });
        }
    }
    tx.core.events.queue(Event::Joined { id: *id, origin: meta.origin, author: h.author, actor: h.actor, ts: h.ts, received: meta.received });
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
fn with_keys(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &Parts) -> Result<Vec<(usize, Decoded)>> {
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
            out.extend(super::held_part(tx, id, ai)?.map(|d| (ai, d)));
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

/// Keeps the indexes derived from states current: secrets opened from `secrets.0`, inbox
/// delete-key hints `keys.0` replaces, group definitions.
pub(crate) fn observe_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if !matches!(ak.as_str(), "secrets.0" | "keys.0" | "group.0") {
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
                // boxes sealed to this actor elsewhere open now (role flows hook)
                crate::flows::reopen_dependents(tx, *tid)?;
            }
        }
        "keys.0" => {
            if let Some(k) = v.as_ref().and_then(crate::engine::secrets::keys_value) {
                tx.core.observe_keys(tid, &k);
            }
        }
        // every path that changes a `group.0` (late deltas, re-judging) updates `groups.0`
        "group.0" => tx.core.ix.groups.set(*tid, group_def(v)),
        _ => {}
    }
    Ok(())
}

/// A `group.0` value's (items, subgroups).
pub(crate) fn group_def(v: Option<Value>) -> Option<(BTreeSet<Tid>, BTreeSet<Tid>)> {
    v.and_then(|v| osis_schema::RawKey::decode(&osis_schema::core_types::GROUP, &v).ok()).map(|g| (g.items, g.subgroups))
}

/// What a transaction changed (`check_rebuilt`).
#[cfg(debug_assertions)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TxChange {
    None,
    /// Valid joins of new commits only.
    Joins,
    /// Something else: a part's status, a state written otherwise.
    More,
}

/// Debug builds, at the end of every transaction (issues/drop-rejoin-robust.md, item 5): each
/// aspect it touched (below) holds exactly the join of its held bodies (`rebuilt`: spec/crdt.md
/// §4.6 Un-merge), as stored, but for the text chars §5.7 leaves to the node. Panics with the
/// difference. Every change but a valid join is a rebuild, so for those aspects this checks
/// that a rebuild is a fixpoint; for the ordinary joins, that the incremental state is the
/// rebuild. Returns what the transaction changed.
#[cfg(debug_assertions)]
pub(crate) fn check_rebuilt(tx: &mut Tx<'_>) -> Result<TxChange> {
    use crate::engine::state::encode;
    // per aspect, the new commits joining it whole and valid (`fresh`: sampled below), and
    // whether some other change touched it (a part's status, valid, dropped or missing, changed
    // or arrived otherwise; a state written otherwise: always checked)
    let mut fresh: BTreeMap<(Tid, Ak), usize> = BTreeMap::new();
    let mut always: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    let status = |m: &Meta, ai: usize| (m.valid_at(ai), m.dropped.contains_key(&ai), m.missing.contains(&ai), m.stripped.contains(&ai));
    for (id, old) in tx.core.ix.commits.before() {
        let new = tx.core.ix.commits.get(id);
        let Some(m) = new.or(old) else { continue };
        for (ai, a) in m.view.aspects.iter().enumerate() {
            let k = (a.tid, a.ak.clone());
            match (old, new) {
                (None, Some(n)) if status(n, ai) == (true, false, false, false) => *fresh.entry(k).or_default() += 1,
                (Some(o), Some(n)) if status(n, ai) == status(o, ai) => {}
                _ => {
                    always.insert(k);
                }
            }
        }
    }
    // a wrong state stays wrong, so a later sample still sees it: an aspect only new commits
    // joined is checked when its held commits passed a power of four (O(1) bodies read per
    // commit; at every commit the check cost about 40% more tier-1 CPU, at powers of two 20%)
    let core = &*tx.core;
    let quarters = |n: usize| if n == 0 { 0 } else { n.ilog2() / 2 + 1 };
    let sampled = |k: &(Tid, Ak)| match fresh.get(k) {
        Some(added) if !always.contains(k) => {
            let n = core.ix.by_aspect.get(k).map_or(0, |s| s.len());
            quarters(n) != quarters(n.saturating_sub(*added))
        }
        _ => true,
    };
    let change = if !always.is_empty() {
        TxChange::More
    } else if !fresh.is_empty() || !core.written.is_empty() {
        TxChange::Joins
    } else {
        TxChange::None
    };
    let touched: BTreeSet<(Tid, Ak)> = core.written.iter().chain(fresh.keys()).chain(&always).filter(|k| sampled(k)).cloned().collect();
    for (tid, ak) in touched {
        // unseen: the cached state as it was, and no cost recorded
        let k = (tid, ak.clone());
        // the value-less list is a cache of the parts' statuses: a part held as a bare leftover
        // has its own writes on it, one held whole or as a leftover holding values none
        let list = tx.core.ix.valueless.get(&k).cloned().unwrap_or_default();
        for c in tx.core.ix.by_aspect.get(&k).map(|s| s.iter().map(|(_, c)| *c).collect::<Vec<_>>()).unwrap_or_default() {
            let Some(m) = tx.core.ix.commits.get(&c) else { continue };
            let Some(ai) = m.aspect(&tid, &ak) else { continue };
            let own = crate::retention::writes_of(&m.header, &c, ai);
            let on = own.iter().filter(|o| list.binary_search(o).is_ok()).count();
            if m.bare(ai) {
                debug_assert_eq!(on, own.len(), "{c:?} on {tid:?} {ak:?}: held as a bare leftover, its writes not all value-less");
            } else if m.holds(ai) {
                debug_assert_eq!(on, 0, "{c:?} on {tid:?} {ak:?}: held with values, its writes value-less");
            }
        }
        let cached = (tx.core.states.get(&k).cloned(), tx.core.pages.get(&k).cloned());
        let (want, got) = crate::costs::paused(|| -> Result<_> { Ok((rebuilt(tx, &tid, &ak, None)?, tx.state(&tid, &ak)?.cloned())) })?;
        match cached.0 {
            Some(s) => tx.core.states.insert(k.clone(), s),
            None => tx.core.states.remove(&k),
        };
        match cached.1 {
            Some(p) => tx.core.pages.insert(k, p),
            None => tx.core.pages.remove(&k),
        };
        // a creation's char a node may hold or not (spec/crdt.md §5.7) aside
        let plain = |f: Option<Fragment>| f.map(|mut f| {
            f.drop_local_chars();
            f
        });
        let (got, want) = (plain(got), plain(want));
        let same = got.as_ref().map(encode).transpose()? == want.as_ref().map(encode).transpose()?;
        debug_assert!(same, "state of {tid:?} {ak:?} differs from a rebuild from held bodies:\n{}", text_diff(&format!("{got:#?}"), &format!("{want:#?}")));
        // and the group index, derived from it
        if ak.as_str() == "group.0" {
            let def = group_def(got.as_ref().and_then(Fragment::read));
            debug_assert_eq!(tx.core.ix.groups.defs.get(&tid), def.as_ref(), "the group index of {tid:?} differs from its state");
        }
    }
    Ok(change)
}

/// The lines of `kept` and `rebuilt` the other lacks, `-` kept and `+` rebuilt, each with its
/// line number.
#[cfg(debug_assertions)]
fn text_diff(kept: &str, rebuilt: &str) -> String {
    let (a, b): (Vec<&str>, Vec<&str>) = (kept.lines().collect(), rebuilt.lines().collect());
    let (sa, sb): (BTreeSet<&str>, BTreeSet<&str>) = (a.iter().copied().collect(), b.iter().copied().collect());
    let mut out = String::new();
    for (i, l) in a.iter().enumerate().filter(|(_, l)| !sb.contains(*l)) {
        out.push_str(&format!("  - kept {i}: {l}\n"));
    }
    for (i, l) in b.iter().enumerate().filter(|(_, l)| !sa.contains(*l)) {
        out.push_str(&format!("  + rebuilt {i}: {l}\n"));
    }
    if out.is_empty() {
        out = format!("  (same lines, other order or count)\n  kept {kept}\n  rebuilt {rebuilt}\n");
    }
    out
}

/// The one path after anything but a valid join changes what `(tid, ak)` holds
/// (issues/drop-rejoin-robust.md item 1): a validity flip, a drop, a part held as its leftover,
/// a re-arrival. The state is `rebuilt` (spec/crdt.md §4.6, spec/permissions.md §5.2): the join
/// of every held body, leftovers included, each first stripped of the writes of the deltas now
/// invalid here (by counter range or commit ID, so the author's valid deltas keep theirs; a
/// valid snapshot keeps its own copies of them, `Unmerge::unvouched`), then of the values held
/// value-less here. Written shredded (spec/commits.md §5: a body went, so every local copy of it
/// goes). What waits on its state, and its bodies with a relative bound, are
/// judged again.
///
/// Invariant (spec/crdt.md §4.7, spec/commits.md §5; `retention::strip_leftover`): no held body
/// carries the value of a write this node holds value-less (expired, purged), its own or a copy
/// under the original's dot (a snapshot's),
/// and none loses a value of a write not so held. Kept where it can break: while the aspect's
/// value-less list changed in this transaction, this walk reads every held body and holds each
/// snapshot carrying a listed value as its leftover (`retention::strip_carried`, which lists nothing);
/// a body arriving later is judged on its join (`retention::drop_gone`).
pub(crate) fn rebuild(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    // a signal has no state: a validity change or a drop only changes which bodies count
    // (spec/commits.md §5 Signals)
    if ak.signal() {
        tx.core.mark_aspect_changed(tid, ak);
        return Ok(());
    }
    tx.core.rebuilds += 1;
    let k = (*tid, ak.clone());
    // the state changes: held purge-on-replace bodies are judged again (`retention::settle_none`)
    if tx.core.ix.none_held.get(&k).is_some_and(|s| !s.is_empty()) {
        tx.core.none_due.insert(k.clone());
    }
    let memory = tx.core.memory_tx;
    if let Some(b) = &mut tx.core.batched {
        let e = b.entry(k).or_default();
        e.memory |= memory;
        return Ok(());
    }
    let _s = crate::costs::span("rebuild");
    crate::engine::listing::before_rebuild(tx, tid, ak)?;
    let listed = tx.core.valueless_dirty.contains(&k).then(|| tx.core.ix.valueless.get(&k).cloned()).flatten().filter(|l| !l.is_empty());
    let mut carriers = Vec::new();
    let st = rebuilt(tx, tid, ak, listed.as_deref().map(|l| (l, &mut carriers)))?;
    for (c, ai) in &carriers {
        crate::retention::strip_carried(tx, c, *ai)?;
    }
    tx.set_state(tid, ak, st, Shred::Yes)?;
    // members gone by expiry, purge, a keep bound or validity leave the group index with them
    if ak.as_str() == "group.0" {
        observe_state(tx, tid, ak)?;
    }
    crate::retention::mark_bounded(tx, tid, ak);
    tx.core.mark_aspect_changed(tid, ak);
    Ok(())
}

/// Runs `f` with the rebuilds it asks batched (`Core::batched`): each aspect rebuilt once at the
/// end (a rebuild reads the held bodies, so one per
/// aspect instead of one per change keeps a round of `n` expiries on an aspect linear in `n`).
/// `f` must read no state it changed: its bodies and indexes are current, the states not. Within
/// an outer batch, `f` joins it.
pub(crate) fn run_batched<T>(tx: &mut Tx<'_>, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T> {
    if tx.core.batched.is_some() {
        return f(tx);
    }
    tx.core.batched = Some(BTreeMap::new());
    let r = f(tx);
    let asked = tx.core.batched.take().unwrap_or_default();
    let r = r?;
    for ((tid, ak), b) in asked {
        tx.in_class(b.memory, |tx| {
            rebuild(tx, &tid, &ak)?;
            crate::retention::off_valueless(tx, &tid, &ak, &b.unlist);
            Ok(())
        })?;
    }
    Ok(r)
}

/// `rebuilt`'s request for the held parts carrying a value of a write the list names, and where
/// they go.
pub(crate) type Carrying<'a> = (&'a [Owned], &'a mut Vec<(CommitId, usize)>);

/// What `rebuild` writes: the plain join of the held bodies (a valid snapshot's copies like
/// any write, spec/crdt.md §4.1 copy order). `carrying`: every held body is read, and those
/// carrying a value of a write the list given names go in the vector, invalid ones included
/// (`rebuild`'s invariant).
pub(crate) fn rebuilt(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, mut carrying: Option<Carrying<'_>>) -> Result<Option<Fragment>> {
    if ak.signal() {
        return Ok(None);
    }
    // newest first (a join does not depend on the order), for `Fragment::settled_above`
    let held: Vec<(osis_base::Ts, CommitId)> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).map(|s| s.iter().rev().copied().collect()).unwrap_or_default();
    let snapshots = tx.core.ix.snapshots.get(&(*tid, ak.clone())).is_some_and(|v| !v.is_empty());
    // the part of `c` that may join, with whether it is a snapshot's and valid
    let joining = |tx: &mut Tx<'_>, c: &CommitId| -> Result<Option<(usize, bool, bool)>> {
        let Some(ai) = tx.core.ix.commits.get(c).and_then(|m| m.aspect(tid, ak)) else { return Ok(None) };
        // stored: a commit being applied joins once stored
        if !super::stores_part(tx, c, ai)? {
            return Ok(None);
        }
        let Some(m) = tx.core.ix.commits.get(c) else { return Ok(None) };
        Ok(Some((ai, m.header.kind.is_compaction(), m.valid_at(ai))))
    };
    let un = Unmerge::of(tx, tid, ak)?;
    let mut st = Fragment::default();
    let mut ch = Changes::new();
    // the bodies a piece at a time; once the state is settled above the next one, none older
    // can change it (debug builds: all of them, the state they would skip beside, checking that)
    let mut settled = false;
    let mut fast: Option<Fragment> = None;
    let listed = carrying.as_ref().map(|(l, _)| OwnedSet::of(l));
    for (ts, c) in &held {
        // a body stamped `ts` carries nothing stamped later (a snapshot's writes included,
        // spec/crdt.md §8)
        if listed.is_none() && !settled && st.settled_above(*ts) {
            settled = true;
            if cfg!(debug_assertions) {
                fast = Some(st.clone());
            }
        }
        if settled && !cfg!(debug_assertions) {
            break;
        }
        let Some((ai, snap, valid)) = joining(tx, c)? else { continue };
        let _s = (!settled).then(|| crate::costs::span("rebuild: body"));
        debug_assert!(snapshots || !snap, "snapshot {c:?} of {tid:?} {ak:?} held and stored, not in `ix.snapshots`");
        // an invalid snapshot joins nothing, but its body is held
        let joins = !snap || valid;
        if !joins && listed.is_none() {
            continue;
        }
        let mut carries = false;
        super::each_held_piece(tx, c, ai, &mut |_, mut f| {
            if let Some(l) = &listed
                && !carries
            {
                carries = l.valued_in(&f);
                debug_assert!(snap || !carries, "content body {c:?} of {tid:?} {ak:?} holds a listed value: its own go at `make_leftover`, and only a snapshot copies another's");
            }
            if !joins {
                return Ok(());
            }
            if snap {
                f.remove_dots(&|d| un.unvouched(d));
            } else {
                un.strip(&mut f);
            }
            if let Some(x) = fast.as_mut().filter(|_| !settled) {
                x.join_into(f.clone(), None, &mut Changes::new());
            }
            st.join_into(f, None, &mut ch);
            Ok(())
        })?;
        if carries && let Some((_, out)) = &mut carrying {
            out.push((*c, ai));
        }
    }
    debug_assert!(fast.as_ref().is_none_or(|x| *x == st), "a rebuild of {tid:?} {ak:?} stopped early: {fast:?}, all bodies {st:?}");
    strip_valueless(tx.core, tid, ak, &mut st);
    Ok((!st.is_empty()).then_some(st))
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

//! Atomic apply (spec/commits.md §4): one store transaction joins every valid delta of a commit
//! after its role records reach perm, records deaths, receipts, expiry and purges, and
//! re-judges held deltas when the held set changed; events go out after it is durable.

use super::{Parts, Streamed, validity};
use crate::engine::{Core, Meta, Owned, Tx, records};
use std::cell::RefCell;
use crate::error::{Error, Result};
use crate::events::{Cause, Event, Origin};
use osis_commit::{CommitBlob, Decoded, Header};
use osis_base::{Ak, CommitId, CreationRecord, Tid, Value, WallMs};
use osis_crdt::{Changes, Fragment};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::engine::Gives;

fn fragment(d: Decoded) -> (Fragment, Option<Gives>) {
    match d {
        Decoded::Delta(x) => (x.fragment, None),
        Decoded::Snapshot(x) => (x.fragment, Some((x.frontiers, x.absorbed.into_iter().collect()))),
    }
}

/// Notes a held compaction snapshot of `(tid, ak)` with its frontiers and `Absorbed`.
pub(crate) fn note_snapshot(core: &mut Core, tid: &Tid, ak: &Ak, ts: osis_base::Ts, id: &CommitId, (fr, abs): Gives) {
    // kept in (`ts`, ID) order, so arrival order (a rebuild's is the store's) does not show
    let v = core.ix.snapshots.entry_or_default((*tid, ak.clone()));
    if !v.iter().any(|x| x.1 == *id) {
        let at = v.partition_point(|x| (x.0, x.1) < (ts, *id));
        v.insert(at, (ts, *id, fr, abs));
    }
}

/// Indexes the dropped parts of `id` that kept their frontiers (`Dropped::gives`).
pub(crate) fn note_gives(core: &mut Core, id: &CommitId) {
    let Some(m) = core.ix.commits.get(id) else { return };
    let ks: Vec<(Tid, Ak)> = m.dropped.iter().filter(|x| x.1.gives.is_some()).filter_map(|x| m.view.aspects.get(*x.0)).map(|a| (a.tid, a.ak.clone())).collect();
    for k in ks {
        core.ix.dropped_snapshots.insert(k, *id);
    }
}

/// Forgets snapshot `id` of `(tid, ak)` when its body drops: its carried writes are index
/// entries derived from the body (spec/commits.md §5), which a rebuild cannot read; its
/// frontiers and `Absorbed` stay in its record when kept (`Dropped::gives`, `retention::drop_part`).
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

/// Adds a commit to the per-aspect and node-form range indexes.
pub(crate) fn index_commit(core: &mut Core, id: &CommitId, h: &crate::engine::View) {
    for a in &h.aspects {
        core.ix.by_aspect.insert((a.tid, a.ak.clone()), (h.ts, *id));
        if a.ak.as_str() == "label.0" {
            core.ix.labeled.insert(a.tid);
        }
        if a.ak.as_str() == crate::flows::LINK_SEED {
            core.links = None;
        }
        core.ix.by_thing.insert(a.tid, *id);
        if h.form.counted() && h.kind.has_own_writes() && a.lo < a.hi {
            core.ix.ranges.insert((a.tid, a.ak.clone(), h.form.own_source(h.author, *id)), a.lo, (a.hi, *id));
        }
    }
    for b in &h.chunks {
        core.ix.by_chunk.insert(*b, *id);
    }
}

/// Commits by the same node (session) whose node-form (session-form) ranges on one aspect
/// overlap this one's (spec/commits.md §4: all are invalid).
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
/// `(tid, ak)`, holding value-less what must be. `held_only`: only the deaths of writes the state
/// held before, as loaded for the join (the pages it touches hold every write it supersedes): a
/// snapshot's copies dying on arrival die for it alone (`retention::note_copies`), not again for
/// the other bodies carrying them. A paged state loads only the pages the join touches, or
/// where it resets or re-encodes a paged collection joins it a page at a time
/// (`Tx::join_reset`).
pub(crate) fn join_into_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, mut delta: Fragment, held_only: bool) -> Result<Changes> {
    let _s = crate::costs::span("apply: join");
    tx.load_lazy(tid, ak)?;
    // writes owned by deltas invalid here go from every body before it joins (un-merge is a
    // function of the held set: another's nested write under an invalid creation goes too)
    let un = Unmerge::probe(tx, tid, ak, &delta)?;
    if !un.is_empty() {
        delta.remove_dots(&|d| un.bad(d));
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
    tx.core.wrote(k.clone());
    let mut st = tx.core.states.get_mut(&k).and_then(Option::take).unwrap_or_default();
    let before = held_only.then(|| st.stamps());
    let mut ch = st.join(delta);
    if let Some(b) = before {
        ch.retain_deaths(|d| b.holds(&d.stamp));
    }
    let st = tx.kept(tid, ak, st);
    if ch.is_changed() || !ch.deaths().is_empty() {
        tx.set_state_touched(tid, ak, st, &touch, Shred::No)?;
    } else {
        tx.core.states.insert(k, st);
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
/// again, the skeleton first, then its pages in wire order (`osis_commit::stream_part`; joining
/// the pieces is joining the whole, spec/crdt.md §8). A streamed part failing now, after
/// `examine` accepted it, means its bytes or pages changed since: a local error.
pub(super) fn each_piece(tx: &mut Tx<'_>, h: &Header, id: &CommitId, blob: &CommitBlob, part: PartRef<'_>, f: &mut dyn FnMut(&mut Tx<'_>, Fragment) -> Result<()>) -> Result<()> {
    let s = match part {
        PartRef::Whole(d) => return f(tx, d.fragment().clone()),
        PartRef::Streamed(s) => s,
    };
    let p = blob.parts.iter().find(|p| p.ai == s.ai && p.di == s.di).ok_or(Error::Corrupt("streamed part"))?;
    let cell = RefCell::new(tx);
    let mut failed = None;
    let mut pages = SharedPages { tx: &cell, dedup: &s.dedup };
    let mut interner = osis_crdt::Interner::new();
    let r = osis_commit::stream_part(h, id, p, &s.dedup, &mut interner, Some(&mut pages), &mut |piece| {
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
    r.map(|_| ()).map_err(|_| Error::Corrupt("a delta examined failed to decode again"))
}

/// What the joins of a commit's parts leave for the rest of apply.
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
/// nothing), in part order, a piece at a time.
///
/// Invariant (the differential `tests_paged` checks it against `oracle::joins`, which decodes
/// and joins every part whole): joining a delta a piece at a time, each piece's state pages
/// written to the store and dropped from the cache before the next, leaves exactly the state,
/// deaths, snapshot records, carried writes and outcomes that joining it whole does. Pieces
/// split a delta by element (§8), and what is judged of a whole delta is judged of its pieces:
/// carried writes, un-merging and holding value-less per write, misstatements per write against
/// the state before the part (`copies_before`), deaths per join.
#[allow(clippy::too_many_arguments)]
pub(super) fn joins(tx: &mut Tx<'_>, h: &Header, id: &CommitId, blob: &CommitBlob, parts: &Parts, valid: &[bool], void: bool, j: &mut Joins) -> Result<()> {
    for (ai, part) in in_order(parts) {
        join_part(tx, h, id, blob, ai, part, valid.get(ai).copied().unwrap_or(false), void, j)?;
    }
    Ok(())
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
    let perm = matches!(ak.as_str(), "roles.0" | "tenures.0" | "created.0");
    if !v && !snap && (void || perm) {
        return if perm { Ok(()) } else { arrived_invalid(tx, &tid, &ak, &mut j.changed, &mut j.touched) };
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
    each_piece(tx, h, id, blob, part, &mut |tx, f| {
        if snap {
            for (src, ctrs) in validity::carried_of(tx.core, &tid, &ak, &f) {
                carried.entry(src).or_default().extend(ctrs);
            }
            vouch |= !owned.is_empty() && f.holds_dots(&|d| owned.iter().any(|o| o.owns(d)));
            if !vouch && let Some(cs) = &copies {
                let core = &*tx.core;
                vouch = !f.misstated_in(cs, &|d| validity::owner_held(core, &tid, &ak, d), &|d| validity::owner_expires(core, &tid, &ak, d)).is_empty();
            }
        }
        if !v {
            if !snap {
                join_into_state(tx, &tid, &ak, f.clone(), false)?;
                unmerge_fell(tx, &tid, &ak, Some(f))?;
                tx.evict_pages(&tid, &ak);
            }
            return Ok(());
        }
        j.touched.note(&tid, &ak, &f);
        ch.merge(join_into_state(tx, &tid, &ak, f, snap && bounded)?);
        tx.evict_pages(&tid, &ak);
        Ok(())
    })?;
    if snap {
        validity::note_carried_of(tx.core, &tid, &ak, id, carried);
    }
    if vouch {
        j.vouching.insert((tid, ak.clone()));
    }
    if !v {
        if !snap {
            unmerged(tx, &tid, &ak, &mut j.changed, &mut j.touched)?;
        }
        return Ok(());
    }
    if ch.is_changed() {
        j.changed.insert((tid, ak.clone()));
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

/// What un-merging removes from every body of `(tid, ak)` (spec/crdt.md §4.6, spec/permissions.md
/// §5.2): the writes of the held deltas invalid here, except those a held valid snapshot carries
/// (its writer vouched for them).
pub(crate) struct Unmerge {
    owned: Vec<Owned>,
    vouched: BTreeSet<osis_crdt::Dot>,
}

impl Unmerge {
    /// From the held set, reading the valid snapshots' writes (`have`: fragments of some of them
    /// already read, by commit) when a delta is invalid.
    pub(crate) fn of(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, have: &BTreeMap<CommitId, &Fragment>) -> Result<Unmerge> {
        let owned = invalid_of(tx.core, tid, ak);
        let vouched = validity::vouched(tx, tid, ak, &owned, have)?;
        Ok(Unmerge { owned, vouched })
    }
    /// `of` for removing from `f` alone: snapshots are read only when `f` holds a write of an
    /// invalid delta.
    pub(crate) fn probe(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, f: &Fragment) -> Result<Unmerge> {
        let owned = invalid_of(tx.core, tid, ak);
        if owned.is_empty() || !f.holds_dots(&|d| owned.iter().any(|o| o.owns(d))) {
            return Ok(Unmerge { owned: Vec::new(), vouched: BTreeSet::new() });
        }
        Unmerge::of(tx, tid, ak, &BTreeMap::new())
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.owned.is_empty()
    }
    /// Whether the write under owner dot `d` goes.
    pub(crate) fn bad(&self, d: &osis_crdt::Dot) -> bool {
        self.owned.iter().any(|o| o.owns(d)) && !self.vouched.contains(d)
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
        if m.header.kind.has_own_writes() {
            out.extend(Owned::of(&m.header, c, ai));
        } else if m.header.kind == osis_commit::Kind::Import {
            // an origin owning its dots here (a commit-form commit on this aspect: the import is
            // void, spec/permissions.md §7) keeps its writes
            out.extend(m.header.origins.iter().filter(|o| !validity::owns_commit_dots(core, &o.commit, tid, ak)).map(|o| Owned::Commit(o.commit)));
        }
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
        for r in blob.parts.iter().flat_map(|p| &p.records) {
            let t = r.tid();
            if tx.core.created(&t).is_none() {
                tx.in_class(true, |tx| Ok(tx.txn.put_local(&[records::CREATED, t.as_bytes()].concat(), &osis_base::encode(&r.to_value()), Shred::No)?))?;
                tx.core.ix.held.create_memory(r.clone());
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
    validity::note_imports(tx.core, &id, &h);
    let view = Arc::new(crate::engine::View::of(&h));
    if h.kind.is_role() {
        validity::note_required(tx.core, &h, &id, &parts.whole);
        validity::add_role_commit(tx, &view, Some(&h), &id, &validity::EdgeParts::of(&h, &parts.whole))?;
        held_changed = true;
    }
    if held_changed {
        tx.core.update_timelines();
    }

    // overlapping node-form counters void both commits
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
    let voided = validity::self_origin_imports(tx.core, &id, &h);
    let void_self = voided.contains(&id);
    for c in &voided {
        held_changed = true;
        tx.core.ix.void.insert(*c);
        tx.core.stale_commits.insert(*c);
        tx.txn.put_local(&[records::VOID, &c.0[..]].concat(), &[], Shred::No)?;
    }
    index_commit(tx.core, &id, &view);
    // copies snapshots held here took of its writes: compared with its deltas once stored
    let uncarried = validity::uncarry(tx.core, &id, &h, &|ai| parts.has(ai));
    let valid: Vec<bool> = (0..h.aspects.len()).map(|ai| validity::part_valid(tx.core, &h, &id, ai)).collect();
    let missing: BTreeSet<usize> = (0..h.aspects.len()).filter(|ai| !parts.has(*ai)).collect();
    let meta = Meta { view, header: crate::engine::LazyHeader::ready(h.clone()), received, origin, valid: valid.clone(), dropped: BTreeMap::new(), missing };
    tx.core.ix.commits.insert(id, meta.clone());
    tx.core.index_validity(&id);

    // receipt record (spec/permissions.md §5.1; spec/crdt.md §8)
    {
        let _s = crate::costs::span("apply: receipt");
        super::receipt::record(tx, &h, &id, &parts.ais(), received)?;
    }

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
    let mut j = Joins::default();
    #[cfg(test)]
    if tx.core.whole_apply {
        super::oracle::joins(tx, &h, &id, &parts, &valid, void_self, &mut j)?;
    } else {
        joins(tx, &h, &id, blob, &parts, &valid, void_self, &mut j)?;
    }
    #[cfg(not(test))]
    joins(tx, &h, &id, blob, &parts, &valid, void_self, &mut j)?;
    let Joins { mut changed, mut touched, vouching, joined } = j;
    // an invalid aspect whose part is not held: others' writes under its creations go too (the
    // part may never come, or come late)
    for (ai, a) in h.aspects.iter().enumerate() {
        if !valid.get(ai).copied().unwrap_or(false) && !parts.has(ai) {
            arrived_invalid(tx, &a.tid, &a.ak, &mut changed, &mut touched)?;
        }
    }
    {
        let _s = crate::costs::span("apply: put_commit");
        tx.put_commit(&id, blob, &meta, Shred::No, None)?;
    }
    rebuild_all(tx, &vouching, &mut changed, &mut touched)?;
    refill(tx, &h, &id, &uncarried, &mut changed, &mut touched)?;
    unjoin_void(tx, &h, &id, &voided, &mut changed, &mut touched)?;
    for (tid, ak, snap, deaths) in &joined {
        crate::retention::note_deaths(tx, tid, ak, deaths)?;
        if *snap {
            crate::retention::note_copies(tx, &id, tid, ak)?;
        }
    }
    {
        let _s = crate::costs::span("apply: retention");
        crate::retention::on_apply(tx, &id, &mut changed)?;
    }

    {
        let _s = crate::costs::span("apply: observe");
        for (tid, ak) in &changed {
            observe_touched(tx, tid, ak, &touched)?;
        }
    }
    super::keys::after_join(tx, &h, &parts.whole, &valid, pend)?;
    let mut flipped = Vec::new();
    if held_changed || tx.core.stale() {
        flipped = validity::rejudge_all(tx, true)?;
        for (tid, ak) in &flipped {
            observe_state(tx, tid, ak)?;
        }
    }
    let rosters: BTreeSet<Tid> = if h.kind.is_role() { h.aspects.iter().filter(|a| a.ak.as_str() == "roles.0" || a.ak.as_str() == "tenures.0").map(|a| a.tid).collect() } else { BTreeSet::new() };
    // a received roster change may end this node's read access (spec/permissions.md §3); its own
    // self-removals drop what they lost once uploaded (`Done::drop_lost`)
    if origin != Origin::Local {
        crate::rotation::mark_lost_due(tx, rosters.iter().copied())?;
    }
    // a memory commit is ephemeral state to watchers and nothing to node-sync
    if h.ephemeral.is_some() {
        tx.core.events.queue(Event::Ephemeral { id: id.into(), origin, author: h.author, actor: h.actor, ts: h.ts, received, changed: changed.into_iter().collect(), signals: Vec::new() });
    } else {
        tx.core.events.queue(Event::Applied { id, origin, author: h.author, actor: h.actor, ts: h.ts, received, changed: changed.into_iter().collect() });
    }
    if !flipped.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Validity, changed: flipped });
    }
    for thing in rosters {
        tx.core.events.queue(Event::Roster { thing });
    }
    Ok(())
}

/// A delta invalid on arrival whose part is not held (it may never come, or come late), on
/// apply or late: others' writes already joined may sit under its creations, so the aspect
/// un-merges as on a flip; a held one joins and un-merges a piece at a time (`join_part`).
/// Edge and creation aspects reach perm instead.
fn arrived_invalid(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, changed: &mut BTreeSet<(Tid, Ak)>, touched: &mut Touched) -> Result<()> {
    if matches!(ak.as_str(), "roles.0" | "tenures.0" | "created.0") {
        return Ok(());
    }
    if unmerge_fell(tx, tid, ak, None)? {
        unmerged(tx, tid, ak, changed, touched)?;
    }
    Ok(())
}

/// After an invalid delta's writes went from `(tid, ak)`.
fn unmerged(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, changed: &mut BTreeSet<(Tid, Ak)>, touched: &mut Touched) -> Result<()> {
    // the writes it un-merged may have superseded others (spec/crdt.md §4.8)
    crate::retention::mark_if_bounded(tx, tid, ak)?;
    // others' writes went: what waits on the aspect's state is judged again
    tx.core.mark_aspect_changed(tid, ak);
    changed.insert((*tid, ak.clone()));
    touched.whole(tid, ak);
    Ok(())
}

/// Whether a dot of `src` with a counter in `lo..hi` may have a received owner (a cheap filter
/// before `strip_copies`: a node-form range overlapping a held one, any commit source).
pub(super) fn core_holds_owner(core: &Core, tid: &Tid, ak: &Ak, src: &osis_crdt::Source, lo: u64, hi: u64) -> bool {
    match src.kind() {
        osis_crdt::SourceKind::Node(_) | osis_crdt::SourceKind::Session(_) => core.ix.ranges.get(&(*tid, ak.clone(), src.clone())).is_some_and(|m| m.range(..hi).next_back().is_some_and(|(_, (h, _))| *h > lo)),
        osis_crdt::SourceKind::Commit(_) => true,
        osis_crdt::SourceKind::Derived(_) => false,
    }
}

/// Rebuilds the aspects of commit `id` (header `h`) whose writes valid snapshots held before it
/// copied otherwise than its deltas hold them (`uncarried`, `validity::differing_copies`): the
/// snapshots' copies govern (spec/permissions.md §5.2), so the delta's writes under those dots go.
fn refill(tx: &mut Tx<'_>, h: &Header, id: &CommitId, uncarried: &[(Tid, Ak, BTreeSet<CommitId>)], changed: &mut BTreeSet<(Tid, Ak)>, touched: &mut Touched) -> Result<()> {
    for (tid, ak, snaps) in uncarried {
        let Some(ai) = h.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak) else { continue };
        // an invalid snapshot's copies never joined
        let snaps: BTreeSet<CommitId> = snaps.iter().copied().filter(|s| validity::snapshot_valid(tx.core, s, tid, ak)).collect();
        if snaps.is_empty() {
            continue;
        }
        if validity::differing_copies(tx, h, id, ai, &snaps)?.is_empty() {
            continue;
        }
        rebuild(tx, tid, ak)?;
        crate::retention::mark_deaths_due(tx, tid, ak)?;
        tx.core.mark_aspect_changed(tid, ak);
        changed.insert((*tid, ak.clone()));
        touched.whole(tid, ak);
    }
    Ok(())
}

/// Rebuilds the aspects where held imports turned void by commit `id` (header `h`), an origin
/// on their own thing, joined copies under `id`'s own dots: those go from the state and `id`'s
/// deltas give the writes again (spec/permissions.md §7).
fn unjoin_void(tx: &mut Tx<'_>, h: &Header, id: &CommitId, voided: &BTreeSet<CommitId>, changed: &mut BTreeSet<(Tid, Ak)>, touched: &mut Touched) -> Result<()> {
    let mut aspects: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    for c in voided.iter().filter(|c| *c != id) {
        let Some(m) = tx.core.ix.commits.get(c) else { continue };
        aspects.extend(m.header.aspects.iter().filter(|a| h.aspects.iter().any(|x| x.tid == a.tid && x.ak == a.ak)).map(|a| (a.tid, a.ak.clone())));
    }
    for (tid, ak) in aspects {
        if !validity::owns_commit_dots(tx.core, id, &tid, &ak) {
            continue;
        }
        rebuild_without(tx, &tid, &ak, &[Owned::Commit(*id)])?;
        crate::retention::mark_deaths_due(tx, &tid, &ak)?;
        tx.core.mark_aspect_changed(&tid, &ak);
        changed.insert((tid, ak.clone()));
        touched.whole(&tid, &ak);
    }
    Ok(())
}

/// Rebuilds `aspects` once the commit is stored, so its own body joins too (`vouching`).
fn rebuild_all(tx: &mut Tx<'_>, aspects: &BTreeSet<(Tid, Ak)>, changed: &mut BTreeSet<(Tid, Ak)>, touched: &mut Touched) -> Result<()> {
    for (tid, ak) in aspects {
        // counted: tests read whether a snapshot vouched
        let _s = crate::costs::span("apply: vouched rebuild");
        rebuild(tx, tid, ak)?;
        crate::retention::mark_deaths_due(tx, tid, ak)?;
        tx.core.mark_aspect_changed(tid, ak);
        changed.insert((*tid, ak.clone()));
        touched.whole(tid, ak);
    }
    Ok(())
}

/// Joins deltas of an applied commit that arrived later (spec/commits.md §4). Late creation
/// records and edge writes reach perm as on apply (a certificate copy may bring a commit's
/// `roles.0` delta after its `created.0` one), and held deltas are re-judged.
pub(crate) fn join_late(tx: &mut Tx<'_>, id: &CommitId, merged: &CommitBlob, parts: Parts) -> Result<()> {
    tx.core.touch();
    let mut meta = tx.core.ix.commits.get(id).cloned().ok_or(Error::Corrupt("commit index"))?;
    let h = meta.header.clone();
    meta.missing.retain(|ai| !parts.has(*ai));
    tx.core.ix.commits.insert(*id, meta.clone());
    let uncarried = validity::uncarry(tx.core, id, &h, &|ai| parts.has(ai));
    let received = tx.now();
    let late = parts.ais();
    super::receipt::record(tx, &h, id, &late, received)?;
    let mut held_changed = note_created(tx, &h, merged, &parts.whole)?;
    validity::note_imports(tx.core, id, &h);
    let edges = h.kind.is_role() && late.iter().any(|ai| h.aspects.get(*ai).is_some_and(|a| matches!(a.ak.as_str(), "roles.0" | "tenures.0")));
    if h.kind.is_role() {
        // judged with the parts held before (a grant's `roles.0` part names what its
        // `secrets.0` part may box)
        let mut all = parts.whole.clone();
        all.extend(super::held_parts_at(tx, id, &|ai| !parts.has(ai))?);
        validity::note_required(tx.core, &h, id, &all);
        // what that judged (an overreaching late `secrets.0` part) holds for the late parts'
        // join below; other aspects' flips go through the re-judge (`invalidated`, `revalidated`)
        let mut flipped = false;
        for ai in late.iter().copied() {
            let v = validity::part_valid(tx.core, &h, id, ai);
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
            held_changed = true;
        }
    }
    // late `secrets.0` parts establish epochs like the first ones, with the commit's `keys.0`
    // (held parts). The keysets "before" are the current `keys.0` state, which already holds this
    // commit's `keys.0` when that part joined earlier: an approximation like `revalidated`'s (a
    // keyset the commit replaced is no longer known; its removed keys come from the index of
    // held keyed entries, and a write whose removed keys are unknown waits as usual). A late
    // `keys.0` part likewise applies the held `secrets.0` of its thing again: applied without
    // the keyset (a role commit applies from any held part), they made no rotation.
    let mut with_keys = parts.whole.clone();
    if h.kind == osis_commit::Kind::Role {
        let late_on = |ak: &str| -> BTreeSet<Tid> { late.iter().filter_map(|ai| h.aspects.get(*ai)).filter(|a| a.ak.as_str() == ak).map(|a| a.tid).collect() };
        let (late_secrets, late_keys) = (late_on("secrets.0"), late_on("keys.0"));
        for (ai, a) in h.aspects.iter().enumerate() {
            let want = match a.ak.as_str() {
                "keys.0" => late_secrets.contains(&a.tid),
                "secrets.0" => late_keys.contains(&a.tid),
                _ => false,
            };
            if want && !parts.has(ai) {
                with_keys.extend(super::held_parts(tx, id, ai)?.into_iter().map(|d| (ai, 0, d)));
            }
        }
    }
    let pend = super::keys::before_join(tx, &h, &with_keys, &meta.valid)?;
    let void_import = h.kind == osis_commit::Kind::Import && tx.core.ix.void.contains(id);
    let mut j = Joins::default();
    #[cfg(test)]
    if tx.core.whole_apply {
        super::oracle::joins(tx, &h, id, &parts, &meta.valid, void_import, &mut j)?;
    } else {
        joins(tx, &h, id, merged, &parts, &meta.valid, void_import, &mut j)?;
    }
    #[cfg(not(test))]
    joins(tx, &h, id, merged, &parts, &meta.valid, void_import, &mut j)?;
    let Joins { mut changed, mut touched, vouching, joined } = j;
    // the record's `node/edges` row, read once: it is also the commit's edge writes again
    let all = if h.kind.is_role() { Some(super::edge_parts_of(tx, id, &h, merged.clone())?) } else { None };
    tx.put_commit(id, merged, &meta, Shred::No, all.as_ref())?;
    rebuild_all(tx, &vouching, &mut changed, &mut touched)?;
    refill(tx, &h, id, &uncarried, &mut changed, &mut touched)?;
    for (tid, ak, snap, deaths) in &joined {
        crate::retention::note_deaths(tx, tid, ak, deaths)?;
        if *snap {
            crate::retention::note_copies(tx, id, tid, ak)?;
        }
    }
    // expiry and purges for the late parts (a late snapshot part carrying purged values too)
    crate::retention::on_late(tx, id, &late, &mut changed)?;
    if edges && let Some(all) = &all {
        tx.core.ix.held.remove(id);
        validity::add_role_commit(tx, &meta.view, Some(&h), id, all)?;
        held_changed = true;
    }
    if held_changed {
        tx.core.update_timelines();
    }
    for (tid, ak) in &changed {
        observe_touched(tx, tid, ak, &touched)?;
    }
    super::keys::after_join(tx, &h, &with_keys, &meta.valid, pend)?;
    let mut flipped = Vec::new();
    if held_changed || tx.core.stale() {
        flipped = validity::rejudge_all(tx, true)?;
        for (tid, ak) in &flipped {
            observe_state(tx, tid, ak)?;
        }
    }
    if edges && meta.origin != Origin::Local {
        crate::rotation::mark_lost_due(tx, h.aspects.iter().filter(|a| matches!(a.ak.as_str(), "roles.0" | "tenures.0")).map(|a| a.tid))?;
    }
    if edges {
        for thing in h.aspects.iter().filter(|a| matches!(a.ak.as_str(), "roles.0" | "tenures.0")).map(|a| a.tid).collect::<BTreeSet<_>>() {
            tx.core.events.queue(Event::Roster { thing });
        }
    }
    tx.core.events.queue(Event::Joined { id: *id });
    for (t, a) in &changed {
        tx.core.mark_aspect_changed(t, a);
    }
    if !changed.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::LateDelta, changed: changed.into_iter().collect() });
    }
    if !flipped.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Validity, changed: flipped });
    }
    Ok(())
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

/// Keeps the indexes derived from states current: secrets opened from `secrets.0`, delete keys
/// and keyset epochs from `keys.0`, the `was.0` and `moved.0` indexes, group definitions.
pub(crate) fn observe_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if !matches!(ak.as_str(), "secrets.0" | "keys.0" | "was.0" | "moved.0" | "group.0") {
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
                // the keysets' epochs and suites it records are persisted with the epochs
                let before = tx.core.ix.secrets.get(tid).cloned();
                tx.core.observe_keys(tid, &k);
                if let Some(e) = tx.core.ix.secrets.get(tid)
                    && before.as_ref() != Some(e)
                {
                    let b = crate::engine::secrets::encode_epochs(e);
                    tx.txn.put_local(&[b"k/".as_slice(), tid.as_bytes()].concat(), &b, Shred::Yes)?;
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
        "group.0" => tx.core.ix.groups.set(*tid, group_def(v)),
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
    let un = Unmerge::of(tx, tid, ak, &BTreeMap::new())?;
    let bad = |d: &osis_crdt::Dot| un.bad(d);
    tx.load_lazy(tid, ak)?;
    let k = (*tid, ak.clone());
    let touch = fell.as_ref().and_then(|f| crate::engine::pages::touch_of(f, tx.core.pages.get(&k)));
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
        let st = tx.kept(tid, ak, st);
        tx.core.touch();
        tx.core.wrote(k);
        tx.set_state_touched(tid, ak, st, &touch, Shred::Yes)?;
    }
    // in place is what rebuilding gives
    #[cfg(debug_assertions)]
    {
        let want = rebuilt(tx, tid, ak, &[])?.0;
        debug_assert!(tx.state(tid, ak)? == want.as_ref(), "in-place un-merge of {tid:?} {ak:?} differs from a rebuild");
    }
    Ok(in_place == Some(true))
}

/// Rebuilds `(tid, ak)` after validity changed (spec/crdt.md §4.6, spec/permissions.md §5.2):
/// the join of the current state (a snapshot this node holds) and every held body, each first
/// stripped of the writes of the deltas now invalid here (by counter range or commit ID, so the
/// author's valid deltas, dropped bodies included, keep theirs) that no valid snapshot carries,
/// and of the writes valid snapshots misstate.
pub(crate) fn rebuild(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    rebuild_without(tx, tid, ak, &[])
}

/// `rebuild`, the writes `gone` matches first removed from the current state, exactly (others'
/// writes nested under them stay): what a snapshot turned invalid gave
/// (`validity::given_by`). Reports each valid snapshot misstating a held delta.
pub(crate) fn rebuild_without(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, gone: &[Owned]) -> Result<()> {
    let (st, misstating) = rebuilt(tx, tid, ak, gone)?;
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
/// when a late copy comes (`retention::takes_late`). Known gap (a keep-at-most drop before
/// the delta went value-less): issues/valueless-gaps.md.
fn residues(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Vec<Fragment>> {
    let mut rows = Vec::new();
    tx.scan(&records::aspect_key(records::RESIDUE, tid, ak), |k, v| {
        let mut r = records::Rd::new(k);
        let c = CommitId(r.arr()?);
        rows.push((c, v));
        Ok(())
    })?;
    let mut out = Vec::new();
    for (c, v) in rows {
        if !tx.core.ix.void.contains(&c) {
            out.push(crate::engine::state::decode(&v)?);
        }
    }
    Ok(out)
}

/// What `rebuild_without` writes, and the valid snapshots misstating a held delta other than by
/// value-less copies. A held
/// delta's writes under a dot a held valid snapshot misstates (`validity::misstated_in`) count
/// for nothing: the snapshots' copies govern, joined by the copy order (spec/permissions.md
/// §5.2). Under a dot any held snapshot misstates the current state's writes go first, so the
/// held bodies give them again.
fn rebuilt(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, gone: &[Owned]) -> Result<(Option<Fragment>, BTreeSet<CommitId>)> {
    let held: Vec<(osis_base::Ts, CommitId)> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).map(|s| s.iter().copied().collect()).unwrap_or_default();
    // bodies (with the delta owning each, by commit and aspect), and of each valid snapshot its
    // fragment (what it vouches for); invalid snapshots apart (they join nothing)
    let mut bodies: Vec<(Fragment, Option<CommitId>, Option<CommitId>)> = Vec::new();
    let mut invalid: Vec<(CommitId, Fragment)> = Vec::new();
    let mut deltas: Vec<(CommitId, usize, Header)> = Vec::new();
    for (_, c) in held {
        let Some(m) = tx.core.ix.commits.get(&c).cloned() else { continue };
        let Some(ai) = m.aspect(tid, ak) else { continue };
        // an invalid snapshot's body joins nothing (spec/permissions.md §5.2)
        let snap_invalid = m.header.kind.is_compaction() && !m.valid_at(ai);
        // nor does a void import's (spec/permissions.md §7)
        if m.header.kind == osis_commit::Kind::Import && tx.core.ix.void.contains(&c) {
            continue;
        }
        let mut any = false;
        for d in super::held_parts(tx, &c, ai)? {
            let (f, fr) = fragment(d);
            if fr.is_some() && snap_invalid {
                invalid.push((c, f));
                continue;
            }
            any |= fr.is_none();
            bodies.push((f, fr.is_some().then_some(c), fr.is_none().then_some(c)));
        }
        if any {
            deltas.push((c, ai, (*m.header).clone()));
        }
    }
    let un = {
        let have: BTreeMap<CommitId, &Fragment> = bodies.iter().filter_map(|(f, s, _)| s.map(|s| (s, f))).collect();
        Unmerge::of(tx, tid, ak, &have)?
    };
    // misstated writes: per held delta, against every held snapshot
    let mut strip_state: BTreeSet<osis_crdt::Dot> = BTreeSet::new();
    let mut strip_own: BTreeMap<CommitId, BTreeSet<osis_crdt::Dot>> = BTreeMap::new();
    let mut misstating = BTreeSet::new();
    if !deltas.is_empty() {
        let mut snaps: Vec<(CommitId, bool)> = bodies.iter().filter_map(|(_, s, _)| s.map(|s| (s, true))).collect();
        snaps.extend(invalid.iter().map(|(s, _)| (*s, false)));
        for (s, valid) in snaps {
            let f = bodies.iter().find(|b| b.1 == Some(s)).map(|b| &b.0).or_else(|| invalid.iter().find(|x| x.0 == s).map(|x| &x.1));
            let Some(ix) = validity::copy_index(tx, &s, tid, ak, f)? else { continue };
            for (c, ai, h) in &deltas {
                let own: Vec<&Fragment> = bodies.iter().filter(|b| b.2 == Some(*c)).map(|b| &b.0).collect();
                let dots = validity::misstated_in(&ix, h, c, *ai, &own);
                if dots.is_empty() {
                    continue;
                }
                strip_state.extend(dots.iter().cloned());
                if valid {
                    // reported unless only value-less: an honest snapshot taken after a purge
                    // this node has not seen yet (its copy governs all the same)
                    if !ix.misstated(&validity::owned_ranges(h, c, *ai), &own, true).is_empty() {
                        misstating.insert(s);
                    }
                    strip_own.entry(*c).or_default().extend(dots);
                }
            }
        }
    }
    tx.load(tid, ak)?;
    let current = tx.core.states.get(&(*tid, ak.clone())).cloned().flatten();
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
    for (f, _, c) in bodies.iter_mut() {
        if let Some(dots) = c.and_then(|c| strip_own.get(&c)) {
            f.strip_forged(&|d| dots.contains(d));
        }
    }
    let mut st = Fragment::default();
    let mut ch = Changes::new();
    for mut b in kept.into_iter().chain(bodies.into_iter().map(|b| b.0)) {
        b.remove_dots(&|d| un.bad(d));
        st.join_into(b, None, &mut ch);
    }
    strip_valueless(tx.core, tid, ak, &mut st);
    Ok(((!st.is_empty()).then_some(st), misstating))
}

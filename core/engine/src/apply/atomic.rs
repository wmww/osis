//! Applying a commit (spec/commits.md §4): one store transaction joins every valid delta of a commit
//! after its role records reach perm, marks the bodies its joins may have replaced, applies expiry and purges, and
//! re-judges held deltas when the held set changed; events go out after it is durable.

use super::{Parts, Streamed, validity};
use crate::engine::{Core, Hold, Meta, Missing, Owned, Tx, records};
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
use crate::retention::snapshot::Carried;

/// Notes a held compaction snapshot of `(tid, ak)` with its frontiers and `Absorbed`; what its
/// body carries is noted once read (`note_carried`).
pub(crate) fn note_snapshot(core: &mut Core, tid: &Tid, ak: &Ak, ts: osis_base::Ts, id: &CommitId, (fr, abs, _): Gives) {
    // kept in (`ts`, ID) order, so arrival order (a rebuild's is the store's) does not show
    let v = core.ix.snapshots.entry_or_default((*tid, ak.clone()));
    if !v.iter().any(|x| x.1 == *id) {
        let at = v.partition_point(|x| (x.0, x.1) < (ts, *id));
        v.insert(at, (ts, *id, fr, abs, Carried::default()));
    }
}

/// Notes `c`, what held snapshot `id` of `(tid, ak)` carries, from its body as held (joined, or
/// its leftover): `retention::snapshot::Carried`. Where the writes it holds moved, so did the
/// commits it carries: the walk reads it again (`validity::reading`).
pub(crate) fn note_carried(core: &mut Core, tid: &Tid, ak: &Ak, id: &CommitId, c: Carried) {
    let k = (*tid, ak.clone());
    if !core.ix.snapshots.get(&k).is_some_and(|v| v.iter().any(|x| x.1 == *id && x.4 != c)) {
        return;
    }
    if let Some(x) = core.ix.snapshots.get_mut(&k).and_then(|v| v.iter_mut().find(|x| x.1 == *id)) {
        x.4 = c;
    }
    core.ix.held.touch_commit(*id);
    core.update_timelines();
}

/// Indexes the dropped parts of `id` that still stand in (`Dropped::stands_in`).
pub(crate) fn note_stands_in(core: &mut Core, id: &CommitId) {
    let Some(m) = core.ix.commits.get(id) else { return };
    let ks: Vec<(Tid, Ak)> = m.dropped_parts().filter(|x| x.1.stands_in).filter_map(|x| m.view.aspects.get(x.0)).map(|a| (a.tid, a.ak.clone())).collect();
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
        // it carries nothing from here on (`retention::snapshot::carried`)
        core.ix.held.touch_commit(*id);
        core.update_timelines();
        crate::retention::names::snapshots_moved(core, tid, ak);
    }
}

/// A role commit's inner and merge signatures (`Indexes::role_sigs`), as held facts: every role
/// commit at an epoch, whatever is known of its author or the things it is on when it applies.
/// The signing chain decides which are an account's on its account root when it reads them
/// (`Core::devices_read`), so the order commits arrive in records nothing differently.
pub(crate) fn note_role_sigs(core: &mut Core, kind: osis_commit::Kind, at_epoch: bool, id: &CommitId, sigs: &osis_commit::Sigs) {
    // a rotation is a role commit at an epoch (`osis_commit::validate`): what an open reads back
    // from the records' signature items (`index::load`)
    if kind == osis_commit::Kind::Role && at_epoch && (sigs.inner.is_some() || !sigs.merge.is_empty()) {
        core.ix.role_sigs.insert(*id, Arc::new(crate::engine::RoleSigs { inner: sigs.inner, more: sigs.more.clone(), merge: sigs.merge.clone() }));
    }
}

/// Adds a commit whose purge author is not its signer to the indexes of that thing, a member of
/// its path (`Indexes::acting_on`, `chains_on`, `by_actor`: its record and its signer's chain to
/// it go with the commit), and a split commit with a path undecided here
/// to `Indexes::paths_unknown`.
fn index_acting(core: &mut Core, id: &CommitId, h: &crate::engine::View) {
    // Interim (issues/stated-path-certificates.md): every listed thing of each stated path, its record needed and chain certified
    if let Some(x) = h.other_purge_author() {
        for a in &h.aspects {
            core.ix.acting_on.insert((a.tid, h.signer, x), *id);
            core.ix.chains_on.insert(a.tid, (h.signer, x));
        }
        core.ix.by_actor.insert((x, h.signer), *id);
    }
    if h.paths.as_ref().is_some_and(|p| h.aspects.iter().any(|a| !p.contains_key(&a.tid))) {
        core.ix.paths_unknown.insert(*id);
    }
}

/// Adds a commit to the per-aspect and session range indexes.
pub(crate) fn index_commit(core: &mut Core, id: &CommitId, h: &crate::engine::View) {
    crate::retention::names::held_again(core, id, &h.aspects);
    for a in &h.aspects {
        core.ix.by_aspect.insert((a.tid, a.ak.clone()), (h.ts, *id));
        core.ix.aspect_things.insert(a.ak.clone(), a.tid);
        core.ix.by_thing.insert((a.tid, h.signer), *id);
        if h.kind.is_role() {
            core.ix.role_on.insert((a.tid, h.signer), *id);
        }
        if h.purges {
            core.ix.purges_on.insert(a.tid, *id);
        }
        core.ix.chains_on.insert(a.tid, (h.signer, a.tid));
        if h.form.counted() && h.kind.has_own_writes() && a.lo < a.hi {
            core.ix.ranges.insert((a.tid, a.ak.clone(), h.form.own_source(h.signer, *id)), (a.lo, *id), a.hi);
        }
    }
    index_acting(core, id, h);
    if let Some(e) = h.epoch {
        core.ix.by_epoch.insert((h.signer, e), *id);
        // at an epoch not open, a held word may name it (`refresh_epochs`)
        if core.ix.epochs.get(&h.signer).is_some_and(|j| j.unnamed_at(&e) != osis_perm::EpochStanding::Counts) {
            core.ix.names_due.insert(*id);
            core.ix.epochs_due.insert(h.signer);
        }
    }
    crate::engine::edits::index_commit(core, id, h);
}

/// Commits of the same session whose counter ranges on one aspect overlap this one's
/// (spec/commits.md §4: all are invalid).
fn overlaps(core: &Core, id: &CommitId, h: &Header) -> BTreeSet<CommitId> {
    let mut out = BTreeSet::new();
    if !h.form.counted() || !h.kind.has_own_writes() {
        return out;
    }
    let src = h.form.own_source(h.signer, *id);
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
/// `(tid, ak)`: the ordinary valid join (a valid delta holds no write of an invalid one, and a
/// valid snapshot's copies all join, spec/permissions.md §5.2), after the
/// gone list (`remove_gone_writes`): the one join-time predicate, so no value a delta held
/// gone here reaches the state from any body (an undelete's copy of a char, a stale
/// copy, a snapshot's); the same predicate ends every rebuild.
/// A paged state loads only the pages the join touches, or where it resets or re-encodes a
/// paged collection joins it a page at a time (`Tx::join_reset`).
pub(crate) fn join_into_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, mut delta: Fragment, mut dead: Option<&mut Killed>) -> Result<Changes> {
    let _s = osis_base::costs::span("apply: join");
    tx.load_lazy(tid, ak)?;
    // the state is the join of the held bodies without the gone writes (spec/crdt.md §4.7): the
    // one predicate, applied to each body as it joins here and in a rebuild
    remove_gone_writes(tx.core, tid, ak, &mut delta);
    // a paged state loads only the pages the join touches
    let touch = crate::engine::pages::touch_of(&delta, tx.core.pages.get(&(*tid, ak.clone())));
    if touch.is_none()
        && let Some(ch) = tx.join_reset(tid, ak, &delta, dead.as_deref_mut())?
    {
        return Ok(ch);
    }
    tx.ensure_touch(tid, ak, &touch)?;
    // joined in place (evicted on rollback), so a join costs O(delta), not a copy of the state
    let k = (*tid, ak.clone());
    tx.core.touch();
    // `secrets.0` read before: this join's keys read again, with every page holding an entry
    // of one loaded (a key's other live entries, concurrent puts, sit on pages the join's own
    // dots do not touch)
    // (an empty kept decode may be a state that does not decode at all: never patched)
    let secrets = (ak.as_str() == "secrets.0").then(|| tx.core.secrets_read.held(tid).filter(|s| **s != Default::default()).map(|s| (s, delta.clone()))).flatten();
    if secrets.is_some() {
        tx.ensure_paths(tid, ak, &super::keys::secrets_paths(&delta))?;
    }
    tx.core.wrote(k.clone());
    let mut st = tx.core.states.get_mut(&k).and_then(Option::take).unwrap_or_default();
    // the reference index: the tids at the join's reach, before and after
    let refs = crate::engine::refs::indexed(ak).then(|| (crate::engine::refs::Delta::reach(&st, &delta), delta.clone()));
    let before = dead.as_ref().map(|_| (Killed::before(&st, &delta), delta.clone()));
    // the large values at the join's reach, before and after (the compaction trigger's estimate)
    let roots = Some(crate::retention::compact::roots(ak, &st, &delta)).filter(|b| !b.is_empty()).map(|b| (b, delta.clone()));
    let ch = st.join(delta);
    let refs = refs.filter(|_| ch.is_changed()).map(|((mut d, at), x)| {
        d.after(&st, &x, &at);
        d
    });
    if let (Some(dead), Some((w, d))) = (dead, before) {
        dead.note(&w, &st, &d);
    }
    let roots = roots.map(|(b, d)| (b, crate::retention::compact::roots(ak, &st, &d)));
    let secrets = secrets.and_then(|(mut read, d)| super::keys::secrets_patch(std::sync::Arc::make_mut(&mut read), &d, &st).then_some(read));
    let st = tx.kept(tid, ak, st)?;
    if ch.is_changed() {
        tx.set_state_touched(tid, ak, st, &touch, Shred::No)?;
        crate::engine::refs::note(tx, tid, ak, refs.unwrap_or_default())?;
    } else {
        tx.core.states.insert(k, st);
    }
    if let Some(read) = secrets {
        tx.core.secrets_read.amend(tid, read);
    }
    if let Some((b, a)) = roots {
        crate::retention::compact::Trigger::unlinked(tx, tid, ak, &b, &a)?;
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
            PartRef::Whole(Decoded::Snapshot(x)) => Some((x.frontiers.clone(), x.absorbed.clone().into_iter().collect(), x.facts.clone())),
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
        let tx = &mut **tx;
        let mut blobs = crate::engine::blobs::TxBlobs::new(&mut tx.blobs, tx.txn.is_memory());
        let page = osis_blob::BlobReader::new(self.dedup, &mut blobs).get(link)?;
        // counted: tests read how many stored bytes a stream decoded
        osis_base::costs::count("stream: bytes", page.len() as u64);
        Ok(page)
    }
}

/// A streamed piece's fragment.
pub(super) fn piece_fragment(p: osis_crdt::Piece) -> Fragment {
    match p {
        osis_crdt::Piece::Skeleton(f) | osis_crdt::Piece::Page { fragment: f, .. } => f,
    }
}

/// Stops a stream whose piece failed to join (the error is the join's).
const STOPPED: osis_crdt::Error = osis_crdt::Error::Malformed("stopped");

/// Hands `f` a part's delta: a whole one at once, a streamed one a piece at a time as it decodes
/// again (`stream_stored`: `examine` checked it in full, `PartRef::Streamed`). A streamed part
/// failing now means its bytes or pages changed since: a local error.
pub(super) fn each_piece(tx: &mut Tx<'_>, h: &Header, id: &CommitId, blob: &CommitBlob, part: PartRef<'_>, f: &mut dyn FnMut(&mut Tx<'_>, Fragment) -> Result<()>) -> Result<()> {
    let s = match part {
        PartRef::Whole(d) => return f(tx, d.fragment().clone()),
        PartRef::Streamed(s) => s,
    };
    let p = blob.part(s.ai).ok_or(Error::Corrupt("streamed part"))?;
    // its page index is kept from this first stream of it (`held_part_at`)
    let mut index = osis_crdt::PageIndex::default();
    stream_stored(tx, h, id, s.ai, super::checked(&p.delta), &s.dedup, None, &mut |tx, p| {
        index.add(&p);
        f(tx, piece_fragment(p))
    })?;
    if !index.unpaged() {
        super::put_page_index(tx, id, s.ai, &index)?;
    }
    Ok(())
}

/// Decodes the checked delta of commit `id`'s part on aspect `ai` (header `h`, its thing's
/// `dedup` secret) again, decode-only, and hands `f` its pieces, the skeleton first, then its
/// pages in wire order (`osis_commit::read_part`; joining the pieces is joining the whole,
/// spec/crdt.md §8): the transaction is shared between the page source and `f`. A snapshot's
/// frontiers and `Absorbed`. `want`: only the pages it names (the skeleton always).
#[allow(clippy::too_many_arguments)]
pub(super) fn stream_stored(tx: &mut Tx<'_>, h: &Header, id: &CommitId, ai: usize, delta: osis_crdt::Checked<'_>, dedup: &osis_crypto::Secret32, want: Option<osis_crdt::Want<'_>>, f: &mut dyn FnMut(&mut Tx<'_>, osis_crdt::Piece) -> Result<()>) -> Result<Option<Gives>> {
    let cell = RefCell::new(tx);
    let mut failed = None;
    let mut pages = SharedPages { tx: &cell, dedup };
    let source: &mut dyn osis_crdt::PageSource = &mut pages;
    let mut interner = osis_crdt::Interner::new();
    let r = osis_commit::read_part(h, id, ai, delta, &mut interner, Some(source), want, &mut |piece| {
        // counted: tests read how many pieces streamed
        let _s = osis_base::costs::span("apply: piece");
        let mut tx = cell.try_borrow_mut().map_err(|_| STOPPED)?;
        #[cfg(test)]
        if let Some(n) = tx.core.piece_fault.as_mut() {
            if *n == 0 {
                // a store failure: the transaction fails (a fault would set the commit aside)
                failed = Some(Error::Store(osis_store::Error::Misuse("test: piece fault")));
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
    Ok(head.map(|x| (x.frontiers, x.absorbed.into_iter().collect(), x.facts)))
}

/// What the joins of a commit's parts leave for the rest of apply.
#[derive(Default)]
struct Joins {
    pub changed: BTreeSet<(Tid, Ak)>,
    pub touched: Touched,
    /// Per valid part joined on an aspect holding a body with a relative bound, the writes its
    /// joins superseded: the bodies they replaced are judged again (`retention::mark_killed`),
    /// after the commit's record.
    pub joined: Vec<(Tid, Ak, Killed)>,
    /// The parts found to be whole replaces (`Hold::Body::whole`), marked at once after the
    /// joins: one `put_meta` per commit, not per part.
    pub whole: Vec<usize>,
}

/// Joins every part of commit `id` (`valid`: per aspect), in part order, a piece at a time.
///
/// Invariant (the differential `tests_paged` checks it against `Core::whole_apply`, where every
/// part decodes whole and joins by `oracle::join_into_state`, all else of `join_part` the same):
/// joining a delta a piece at a time, each piece's state pages written to the store and dropped
/// from the cache before the next, leaves exactly the state,
/// snapshot records and outcomes that joining it whole does. Pieces split a delta by
/// element (§8), and what is judged of a whole delta is judged of its pieces: un-merging,
/// vouching and gone writes per write, superseded writes per join.
fn joins(tx: &mut Tx<'_>, h: &Header, id: &CommitId, blob: &CommitBlob, parts: &Parts, valid: &[bool]) -> Result<Joins> {
    let mut j = Joins::default();
    for (ai, part) in in_order(parts) {
        join_part(tx, h, id, blob, ai, part, valid.get(ai).copied().unwrap_or(false), &mut j)?;
    }
    note_whole(tx, id, &j.whole);
    Ok(j)
}

/// Joins one part (`joins`): every held snapshot notes its frontiers, whatever its validity; a
/// valid part joins (a valid snapshot's writes like any write, spec/crdt.md §4.1: they are
/// never compared with their own delta's, and those of a delta invalid here count through it);
/// an invalid part joins nothing and changes nothing: un-merge takes exactly an invalid delta's
/// own writes (spec/crdt.md §4.6), which no other delta carries (§3.3: no foreign stamps outside
/// snapshots), and an invalid snapshot gives nothing (spec/permissions.md §5.2).
#[allow(clippy::too_many_arguments)]
fn join_part(tx: &mut Tx<'_>, h: &Header, id: &CommitId, blob: &CommitBlob, ai: usize, part: PartRef<'_>, v: bool, j: &mut Joins) -> Result<()> {
    let Some(a) = h.aspects.get(ai) else { return Ok(()) };
    let (tid, ak) = (a.tid, a.ak.clone());
    // a signal joins no state (spec/data-model.md §2): its body is held as history, heard
    // through `Event::Commits` (spec/commits.md §5 Signals); a valid fire's references are
    // known references (spec/data-model.md §8)
    if ak.signal() {
        if v && crate::engine::refs::indexed(&ak) {
            let mut d = crate::engine::refs::Delta::default();
            each_piece(tx, h, id, blob, part, &mut |_, f| {
                d.add(&f, 1);
                Ok(())
            })?;
            crate::engine::refs::note(tx, &tid, &ak, d)?;
        }
        return Ok(());
    }
    let gives = part.gives();
    let snap = gives.is_some();
    // what stands as an own replace: a plain durable commit's whole delta (`Indexes::own_replaces`)
    let own = !snap && h.ephemeral.is_none() && h.kind == osis_commit::Kind::Content && crate::retention::snapshot::own_aspect(&ak);
    let mut whole = false;
    // edge and creation aspects reach perm instead
    let perm = validity::perm_ak(ak.as_str());
    if !v && !snap && perm {
        return Ok(());
    }
    if let Some(fr) = gives {
        note_snapshot(tx.core, &tid, &ak, h.ts, id, fr);
    }
    // superseded writes date bodies with a relative bound, and make a durable body kept while
    // live one a cover may drop (`retention::bounds::live_keep`)
    let bounded = v && (!tx.is_memory_commit(id) || crate::retention::bounded(tx.core, &tid, &ak) || crate::engine::listing::listened(tx.core, &tid, &ak));
    let mut ch = Changes::new();
    let mut dead = Killed::default();
    if !v && !snap {
        if own {
            each_piece(tx, h, id, blob, part, &mut |_, f| {
                whole |= crate::retention::snapshot::replaces(&f);
                Ok(())
            })?;
            if whole {
                j.whole.push(ai);
            }
        }
        return Ok(());
    }
    let mut carried = Carried::default();
    each_piece(tx, h, id, blob, part, &mut |tx, f| {
        whole |= own && crate::retention::snapshot::replaces(&f);
        if snap {
            carried.add(&f);
        }
        if !v {
            return Ok(());
        }
        j.touched.note(&tid, &ak, &f);
        // the oracle world joins whole (`tests_paged`): only the join differs
        #[cfg(test)]
        if tx.core.whole_apply {
            ch.merge(super::oracle::join_into_state(tx, &tid, &ak, f, bounded.then_some(&mut dead))?);
            return Ok(());
        }
        ch.merge(join_into_state(tx, &tid, &ak, f, bounded.then_some(&mut dead))?);
        tx.evict_pages(&tid, &ak);
        Ok(())
    })?;
    if whole {
        j.whole.push(ai);
    }
    if snap {
        note_carried(tx.core, &tid, &ak, id, carried);
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

/// A list of `Owned` for a lookup per dot in O(log its length).
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
    /// Whether `f` holds a write of theirs (`Fragment::remove_gone` changes it; a record of
    /// another's writes keyed by their dot is none).
    fn held_in(&self, f: &Fragment) -> bool {
        let mut g = f.clone();
        g.remove_gone(&|d| self.owns(d));
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

/// Whether held part `ai` of `c` holds a write of `owned` (`rebuild`'s invariant).
pub(crate) fn carries_any(tx: &mut Tx<'_>, c: &CommitId, ai: usize, owned: &[Owned]) -> Result<bool> {
    let set = OwnedSet::of(owned);
    let mut carries = false;
    super::each_held_piece(tx, c, ai, &mut |_, f| {
        carries = carries || set.held_in(&f);
        Ok(())
    })?;
    Ok(carries)
}

/// Removes from body `f` of `(tid, ak)` the writes gone here (expired, purged: the gone
/// list, spec/crdt.md §4.7): applied to each body before it joins, never to a state (removal does
/// not commute with join).
pub(crate) fn remove_gone_writes(core: &Core, tid: &Tid, ak: &Ak, f: &mut Fragment) {
    if let Some(v) = core.ix.gone.get(&(*tid, ak.clone()))
        && !v.is_empty()
    {
        f.remove_gone(&|d| crate::retention::sorted_owns(v, d));
    }
}

/// Records the creation records durable commit `h` carries on `created.0` that are not held
/// yet; whether any was new. `first`: the node held nothing of `h`, so a strong newly reaching
/// a thing whose record it brings pulls nothing anew (`learn_record`): content on a thing is
/// dropped as not carried only while a commit minting it is held, and forgetting keeps that
/// commit known while a part of it may still bring the thing in. A late part of a commit
/// already held (a released thing's record among them, forgotten with its content) is no
/// exemption, and what was forgotten is fetched again (spec/sync-judgement.md §3 Dropped
/// bodies).
fn note_created(tx: &mut Tx<'_>, h: &Header, parts: &[(usize, Decoded)], first: bool) -> Result<bool> {
    let mut any = false;
    if h.ephemeral.is_some() {
        return Ok(false);
    }
    for (ai, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() != osis_commit::retention::CREATED {
            continue;
        }
        if tx.core.created(&a.tid).is_some() {
            // the commit minting it: what waits on it is judged once the pass ends
            // (`retention::needed::uncarried`)
            if tx.core.ix.pend_on.contains_key(&super::Wake::Enters(a.tid)) {
                tx.core.note_pass_due(a.tid);
            }
            continue;
        }
        let rec = d.fragment().read().as_ref().and_then(CreationRecord::from_value).ok_or(Error::BadInput("created.0"))?;
        if rec.tid() == a.tid {
            any |= if first { learn_record(tx, rec)? } else { hold_record(tx, rec)? };
        }
    }
    Ok(any)
}

/// Holds creation record `rec` (from a `created.0` delta or a record blob: a record proves itself
/// by its hash, spec/permissions.md §1), learned in this transaction (`Core::learned`); whether
/// it was new.
pub(crate) fn learn_record(tx: &mut Tx<'_>, rec: CreationRecord) -> Result<bool> {
    let t = rec.tid();
    let new = hold_record(tx, rec)?;
    if new {
        tx.core.learned.insert(t);
    }
    Ok(new)
}

/// `learn_record`, not counted learned: a record in a late part of a commit already held.
fn hold_record(tx: &mut Tx<'_>, rec: CreationRecord) -> Result<bool> {
    let t = rec.tid();
    if tx.core.created(&t).is_some() {
        return Ok(false);
    }
    let key = [records::CREATED, t.as_bytes()].concat();
    tx.txn.put_local(&key, &osis_base::encode(&rec.to_value()), Shred::No)?;
    tx.core.ix.held.create(rec);
    tx.core.update_timelines();
    // judged once the pass that brought it ends (`Engine::settle_needs`)
    tx.core.note_pass_due(t);
    Ok(true)
}

/// Pending commit `h` applied: received before (it waited), the account's rotations closing its
/// epoch answer again, their listings or addenda naming it by its receipt (spec/permissions.md
/// §5.1 Received, §5.5 Listings).
pub(crate) fn applied_late(tx: &mut Tx<'_>, h: &osis_commit::Header) -> Result<()> {
    if let Some(e) = h.epoch
        && let Some(v) = tx.core.account_view(&h.signer)
    {
        for r in v.closers(&e) {
            crate::flows::signing::note_rotation_due(tx, &r)?;
        }
    }
    Ok(())
}

/// Applies a verified commit (`parts` examined) in this transaction.
pub(crate) fn apply_verified(tx: &mut Tx<'_>, blob: &CommitBlob, parts: Parts, origin: Origin, received: WallMs) -> Result<()> {
    let _s = osis_base::costs::span("apply");
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
    let mut held_changed = note_created(tx, &h, &parts.whole, true)?;
    let view = Arc::new(crate::engine::View::of(&h, super::paths::decided(tx.core, &h, &blob.keys)));
    let read = super::PartsRead::of(&h, &parts.whole);
    tx.core.note_keys_of(&id, &h);
    if h.kind.is_role() {
        validity::note_required(tx.core, &h, &id, &read);
        validity::add_role_commit(tx.core, &view, &h.path, &id, read.perm());
        held_changed = true;
    }

    // overlapping session-form counters void both commits
    let ov = overlaps(tx.core, &id, &h);
    if !ov.is_empty() {
        held_changed = true;
        // the walk reads nothing of a void commit (`validity::reading`)
        for c in ov.iter().chain(std::iter::once(&id)) {
            tx.core.ix.void.insert(*c);
            tx.core.ix.held.touch_commit(*c);
            tx.core.stale_commits.insert(*c);
            tx.txn.put_local(&[records::VOID, &c.0[..]].concat(), &[], Shred::No)?;
        }
        tx.core.update_timelines();
        tx.core.events.diagnostic(
            crate::events::Diagnostic { kind: crate::events::DiagnosticKind::OverlappingCounters, tids: vec![h.signer], commit: Some(id), peer: Some(h.signer), detail: String::new() },
            tx.core.hlc.mono(),
        );
    }
    index_commit(tx.core, &id, &view);
    note_role_sigs(tx.core, blob.header.kind, blob.header.epoch.is_some(), &id, &blob.sigs);
    validity::note_addenda(tx.core, &h, &id, &parts.whole);
    if tx.core.accounts.contains_key(&h.signer) && origin == Origin::Remote {
        tx.core.signing_due = true;
    }
    // an account's rotation: this node answers it with its listing or addenda
    crate::flows::custody::take_boxes(tx, &h)?;
    // (a merge certificate is answered as its epoch: `signing::answer_rotation`)
    if h.rotation.is_some() {
        crate::flows::signing::note_rotation_due(tx, &id)?;
    }
    // an explicit demotion: this node judges what addenda it owes (`flows::addenda`)
    if h.kind.is_role() && view.frontier.is_some() {
        crate::flows::addenda::note_due(tx.core, &id);
    }
    let valid = validity::parts_valid(tx.core, &h, &view, &id);
    let missing: BTreeSet<usize> = (0..h.aspects.len()).filter(|ai| !parts.has(*ai)).collect();
    let hold = (0..h.aspects.len()).map(|ai| if missing.contains(&ai) { Hold::Missing(Missing::Plain) } else { Hold::Body { whole: false } }).collect();
    let meta = Meta::of(view.clone(), crate::engine::LazyHeader::ready(h.clone()), received, origin, None, parts.signed, valid.clone(), hold);
    tx.core.put_meta(id, meta.clone());
    tx.core.index_validity(&id);
    validity::note_grant_fire(tx.core, &id, &h, &valid);
    // held now: what it names is judged (`lists::put_names`)
    crate::flows::lists::note_listing(tx, &h, &id, &parts.whole)?;
    crate::retention::note_requests(tx, &id, &h)?;

    let pend = super::keys::before_join(tx, &h, &id, &read, &valid)?;
    let mut j = joins(tx, &h, &id, blob, &parts, &valid)?;
    {
        let _s = osis_base::costs::span("apply: put_commit");
        // role-class parts join whole: the record holds the parts read
        tx.put_commit(&id, blob, &meta, Shred::No, h.kind.is_role().then(|| read.perm()))?;
    }
    note_held_rules(tx, &h, &id, &parts)?;
    after_store(tx, &j);
    {
        let _s = osis_base::costs::span("apply: retention");
        crate::retention::stripped_joined(tx, &id, &parts.stripped_joined(), &mut j.changed)?;
        crate::retention::on_late(tx, &id, None, &mut j.changed)?;
    }
    {
        let _s = osis_base::costs::span("apply: observe");
        observe_all(tx, &j)?;
    }
    super::keys::after_join(tx, &h, &parts.whole, &valid, pend)?;
    let flipped = rejudged(tx, held_changed)?;
    let changed = j.changed;
    let rosters: BTreeSet<Tid> = if h.kind.is_role() { h.aspects.iter().filter(|a| validity::edge_ak(a.ak.as_str())).map(|a| a.tid).collect() } else { BTreeSet::new() };
    // a roster change may end this node's read access (spec/permissions.md §3): the drop is a
    // value of the state (`Engine::lost_due`); an own self-removal, made here or at a sibling,
    // drops what it lost once sync is done waiting
    crate::sync::held::wait_if_own(tx, &id, &rosters)?;
    if origin == Origin::Remote && h.kind.is_role() {
        crate::sync::held::note_arrival(tx, &h)?;
    }
    // a memory commit is ephemeral state to watchers; sync carries its bodies as any
    // commit's
    crate::retention::compact::Trigger::applied(tx, &id, &h, blob)?;
    if h.ephemeral.is_some() {
        tx.core.events.queue(Event::Ephemeral { id, origin, signer: h.signer, purge_author: view.purge_author, ts: h.ts, received, changed: changed.into_iter().collect() });
    } else {
        tx.core.events.queue(Event::Applied { id, origin, signer: h.signer, purge_author: view.purge_author, ts: h.ts, received, changed: changed.into_iter().collect() });
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

/// Notes the `retention^.0` deltas among `parts`, once stored (`validity::note_settings`).
fn note_held_rules(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &Parts) -> Result<()> {
    for ai in parts.ais() {
        if h.aspects.get(ai).is_some_and(|a| a.ak.as_str() == osis_commit::retention::RETENTION) {
            let held: Vec<(usize, osis_commit::Decoded)> = super::held_part(tx, id, ai)?.into_iter().map(|d| (ai, d)).collect();
            validity::note_settings(tx.core, h, id, &held);
        }
    }
    Ok(())
}

/// Marks parts `whole` of commit `id` as whole replaces (`Hold::Body::whole`), so they stand in
/// the own indexes (`Core::put_meta`).
fn note_whole(tx: &mut Tx<'_>, id: &CommitId, whole: &[usize]) {
    if whole.is_empty() {
        return;
    }
    if let Some(mut m) = tx.core.ix.commits.get(id).cloned() {
        for ai in whole {
            m.set_whole(*ai);
        }
        tx.core.put_meta(*id, m);
    }
}

/// Once commit `id` is stored: the bodies its valid parts' joins replaced are marked.
fn after_store(tx: &mut Tx<'_>, j: &Joins) {
    for (tid, ak, dead) in &j.joined {
        crate::retention::mark_killed(tx, tid, ak, dead);
    }
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
/// (`validity::rejudge_all`), and observes the aspects that flipped; returns them. Until nothing
/// is stale: observing may make more so (secrets opened move what is judged).
pub(crate) fn rejudged(tx: &mut Tx<'_>, held_changed: bool) -> Result<Vec<(Tid, Ak)>> {
    let mut all = Vec::new();
    let mut first = held_changed;
    while first || tx.core.stale() {
        first = false;
        let flipped = validity::rejudge_all(tx, true)?;
        for (tid, ak) in &flipped {
            observe_state(tx, tid, ak)?;
        }
        // roles may have grown: boxes kept out for want of them open now
        crate::flows::retake(tx)?;
        // and so may the secrets opening split commits' paths (`paths::refresh`)
        super::paths::refresh(tx);
        all.extend(flipped);
    }
    Ok(all)
}

/// Joins deltas of an applied commit that arrived later (spec/commits.md §4). Late creation
/// records and edge writes reach perm as on apply (a certificate copy may bring a commit's
/// `roles.0` delta after its `created.0` one), and held deltas are re-judged.
pub(crate) fn join_late(tx: &mut Tx<'_>, id: &CommitId, merged: &CommitBlob, parts: Parts) -> Result<()> {
    tx.core.touch();
    let mut meta = tx.core.ix.commits.get(id).cloned().ok_or(Error::Corrupt("commit index"))?;
    let h = meta.header.clone();
    // a late encryption carries the path keys of its things (spec/wire.md §4 `Split`): a split
    // commit's paths decided here again, its parts judged again where more are known
    let paths = super::paths::decided(tx.core, &h, &merged.keys);
    let learned = paths != meta.view.paths;
    if learned {
        meta.view = Arc::new(crate::engine::View { paths, ..(*meta.view).clone() });
        index_acting(tx.core, id, &meta.view);
        if !super::paths::undecided(&h, meta.view.paths.as_deref()) {
            tx.core.ix.paths_unknown.remove(id);
        }
        let v = validity::parts_valid(tx.core, &h, &meta.view, id);
        meta.set_valid(v);
        tx.core.stale_commits.insert(*id);
    }
    for ai in parts.ais() {
        if meta.missing(ai) {
            meta.set_hold(ai, Hold::Body { whole: false });
        }
    }
    tx.core.put_meta(*id, meta.clone());
    if learned {
        tx.core.index_validity(id);
    }
    let late = parts.ais();
    let mut held_changed = note_created(tx, &h, &parts.whole, false)?;
    let edges = h.kind.is_role() && late.iter().any(|ai| h.aspects.get(*ai).is_some_and(|a| validity::edge_ak(a.ak.as_str())));
    // a late role-class part may change what perm reads of the commit: its edge writes or the
    // role another part needs (`validity::add_role_commit`)
    let perm = h.kind.is_role() && late.iter().any(|ai| h.aspects.get(*ai).is_some_and(|a| osis_schema::core_types::is_role_class(a.ak.as_str())));
    validity::note_addenda(tx.core, &h, id, &parts.whole);
    crate::flows::lists::note_listing(tx, &h, id, &parts.whole)?;
    if edges && meta.view.frontier.is_some() {
        crate::flows::addenda::note_due(tx.core, id);
    }
    let (held, n) = with_held(tx, &h, id, &parts)?;
    let read = super::PartsRead::of(&h, &held);
    if h.kind.is_role() {
        held_changed |= judge_late(tx, &h, id, &parts, &read, &mut meta);
    }
    let with_keys = read.first(n);
    let pend = super::keys::before_join(tx, &h, id, &with_keys, meta.valid())?;
    let mut j = joins(tx, &h, id, merged, &parts, meta.valid())?;
    // the record's `node/perm` row: the commit's held parts read, also its edge writes again
    let perm_parts = h.kind.is_role().then(|| read.perm());
    tx.put_commit(id, merged, &meta, Shred::No, perm_parts)?;
    // a leftover set aside at a purge's fall is stale once a copy joined whole
    crate::retention::forget_joined_leftovers(tx, &h, id, &late)?;
    note_held_rules(tx, &h, id, &parts)?;
    after_store(tx, &j);
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
    crate::retention::on_late(tx, id, Some(&late), &mut j.changed)?;
    if perm && let Some(all) = perm_parts {
        validity::add_role_commit(tx.core, &meta.view, &meta.header.path, id, all);
        held_changed = true;
    }
    observe_all(tx, &j)?;
    super::keys::after_join(tx, &h, with_keys.all(), meta.valid(), pend)?;
    let flipped = rejudged(tx, held_changed)?;
    // late role parts pass_due: a pass after them is one after the commit (spec/permissions.md §3)
    if meta.origin == Origin::Remote && h.kind.is_role() {
        crate::sync::held::note_arrival(tx, &h)?;
    }
    if edges {
        let rosters: BTreeSet<Tid> = h.aspects.iter().filter(|a| validity::edge_ak(a.ak.as_str())).map(|a| a.tid).collect();
        crate::sync::held::wait_if_own(tx, id, &rosters)?;
        for thing in rosters {
            tx.core.events.queue(Event::Roster { thing });
        }
    }
    tx.core.events.queue(Event::Joined { id: *id, origin: meta.origin, signer: h.signer, purge_author: meta.view.purge_author, ts: h.ts, received: meta.received });
    let changed = j.changed;
    if !changed.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::LateDelta, changed: changed.into_iter().collect() });
    }
    if !flipped.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Validity, changed: flipped });
    }
    // the late parts count for the compaction trigger as an applied commit's do
    for ai in &late {
        crate::retention::compact::Trigger::part_held(tx, id, &h, merged, *ai)?;
    }
    // a memory commit whose late parts went at once (expired, superseded)
    crate::retention::memory::forget_if_spent(tx, id)
}

/// The late parts of role commit `id` judged with the parts held before (a grant's `roles.0`
/// part names what its `secrets.0` part may box): what that judged (an overreaching late
/// `secrets.0` part) holds for their join; other aspects' flips go through the re-judge
/// (`invalidated`, `revalidated`). Whether a late part's validity changed (`meta` updated).
fn judge_late(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &Parts, all: &super::PartsRead<'_>, meta: &mut Meta) -> bool {
    validity::note_required(tx.core, h, id, all);
    tx.core.update_timelines();
    let mut flipped = false;
    for ai in parts.ais() {
        let v = validity::part_valid(tx.core, h, &meta.view, id, ai);
        if let Some(x) = meta.valid_mut().get_mut(ai)
            && *x != v
        {
            *x = v;
            flipped = true;
        }
    }
    if flipped {
        let v = meta.valid().to_vec();
        tx.core.ix.commits.update(id, |m| m.set_valid(v));
        tx.core.index_validity(id);
    }
    flipped
}

/// The late parts of commit `id` and, for a role commit, its other held parts (`judge_late`
/// judges with them), with the count of those its join applies with (`before_join`, first): the
/// late parts and, for a plain role commit, the held `keys.0` parts of the things of its late
/// `secrets.0` parts and the held `secrets.0` parts of those of its late `keys.0` parts: late
/// `secrets.0` parts establish epochs like the first ones, with the commit's `keys.0`. The
/// keysets "before" are the current `keys.0` state, which already holds this commit's `keys.0`
/// when that part joined earlier: an approximation like `revalidated`'s (a keyset the commit
/// replaced is no longer known; its removed keys come from the index of held keyed entries, and
/// a write whose removed keys are unknown waits as usual). A late `keys.0` part likewise applies
/// the held `secrets.0` of its thing again: applied without the keyset (a role commit applies
/// from any held part), they made no rotation.
fn with_held(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &Parts) -> Result<(Vec<(usize, Decoded)>, usize)> {
    let mut out = parts.whole.clone();
    if !h.kind.is_role() {
        let n = out.len();
        return Ok((out, n));
    }
    let late = parts.ais();
    let late_on = |ak: &str| -> BTreeSet<Tid> { late.iter().filter_map(|ai| h.aspects.get(*ai)).filter(|a| a.ak.as_str() == ak).map(|a| a.tid).collect() };
    let (late_secrets, late_keys) = (late_on("secrets.0"), late_on("keys.0"));
    let want = |ai: usize| {
        h.kind == osis_commit::Kind::Role
            && h.aspects.get(ai).is_some_and(|a| match a.ak.as_str() {
                "keys.0" => late_secrets.contains(&a.tid),
                "secrets.0" => late_keys.contains(&a.tid),
                _ => false,
            })
    };
    let (with, rest): (Vec<_>, Vec<_>) = super::held_parts_at(tx, id, &|ai| !parts.has(ai))?.into_iter().partition(|(ai, _)| want(*ai));
    out.extend(with);
    let n = out.len();
    out.extend(rest);
    Ok((out, n))
}

/// What a commit's joins touched, per aspect: the `secrets.0` entries (`None`: anything may have
/// changed, read the whole state).
#[derive(Default)]
pub(super) struct Touched(std::collections::BTreeMap<(Tid, Ak), Option<Seen>>);

enum Seen {
    /// Keys of the box and history-box entries.
    Secrets(Vec<Value>, Vec<Value>),
}

impl Touched {
    pub(super) fn note(&mut self, tid: &Tid, ak: &Ak, f: &Fragment) {
        if ak.as_str() != "secrets.0" {
            return;
        }
        let keys = crate::engine::secrets::touched_keys(f);
        match (self.0.entry((*tid, ak.clone())).or_insert_with(|| Some(Seen::Secrets(Vec::new(), Vec::new()))), keys) {
            (Some(Seen::Secrets(b0, h0)), Some((b, h))) => {
                b0.extend(b);
                h0.extend(h);
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
        Some(Some(Seen::Secrets(boxes, history))) => observe_secrets_keys(tx, tid, boxes, history),
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

/// `ingest_secrets_keys`, reopening the boxes sealed to `actor`.
fn observe_secrets_keys(tx: &mut Tx<'_>, actor: &Tid, boxes: &[Value], history: &[Value]) -> Result<()> {
    if ingest_secrets_keys(tx, actor, boxes, history)? {
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
            && tx.core.ingest_secrets(actor, &s, crate::engine::secrets::SecretsRead::State, &alts)
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

/// Keeps the indexes derived from states current: secrets opened from `secrets.0`.
pub(crate) fn observe_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if ak.as_str() != "secrets.0" {
        return Ok(());
    }
    let v = tx.state(tid, ak)?.and_then(Fragment::read);
    let alts = tx.state(tid, ak)?.map(crate::engine::secrets::history_alts).unwrap_or_default();
    // no state (every delta stripped) holds no live entry
    let s = v.as_ref().and_then(crate::engine::secrets::secrets_value).unwrap_or_default();
    if tx.core.ingest_secrets(tid, &s, crate::engine::secrets::SecretsRead::State, &alts) {
        // boxes sealed to this actor elsewhere open now (role flows hook)
        crate::flows::reopen_dependents(tx, *tid)?;
    }
    Ok(())
}

/// Debug builds, at the end of every transaction (issues/drop-rejoin-robust.md, item 5): each
/// aspect it touched holds exactly the join of its held bodies (`check_states`). An aspect where
/// a held part's status changed, a part arrived not valid and whole, or the state was written
/// with no new commit naming it is checked now: every such change is a rebuild, so this checks
/// that a rebuild is a fixpoint, and for an invalid part that it changes nothing. An aspect only
/// valid whole joins or drops as covered (`shred_covered`, the state left as it was) touched
/// joins `Core::unchecked_states`, checked at the end of the engine's history
/// (`Engine::checked_states`): a check per change would cost O(the aspect) per commit, and a
/// wrong state stays wrong until a rebuild of the aspect rewrites it (checked then). A
/// transaction a test hook marks (`Core::unchecked_tx`) checks none of what it touched. Whether
/// the transaction changed a state or a part.
#[cfg(debug_assertions)]
pub(crate) fn check_rebuilt(tx: &mut Tx<'_>) -> Result<bool> {
    // per aspect, whether only new commits joining it whole and valid or bodies dropped as
    // covered touched it (`later`), or some other change did (a part's status, valid, dropped or
    // missing, changed or arrived otherwise; a state written otherwise: `now`)
    let mut later: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    let mut now: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    let status = |m: &Meta, ai: usize| (m.valid_at(ai), m.is_dropped(ai), m.missing(ai), m.stripped(ai));
    for (id, old) in tx.core.ix.commits.before() {
        let new = tx.core.ix.commits.get(id);
        let Some(m) = new.or(old) else { continue };
        for (ai, a) in m.view.aspects.iter().enumerate() {
            let k = (a.tid, a.ak.clone());
            match (old, new) {
                (None, Some(n)) if status(n, ai) == (true, false, false, false) => {
                    later.insert(k);
                }
                (Some(o), Some(n)) if status(n, ai) == status(o, ai) => {}
                (Some(o), Some(n)) if !o.is_dropped(ai) && n.dropped(ai).is_some_and(|d| d.why == crate::engine::DropFor::Cover) => {
                    later.insert(k);
                }
                _ => {
                    now.insert(k);
                }
            }
        }
    }
    now.extend(tx.core.written.iter().filter(|k| !later.contains(*k)).cloned());
    later.retain(|k| !now.contains(k));
    let changed = !now.is_empty() || !later.is_empty();
    // a test hook wrote states no body gives (`Core::unchecked_tx`): no check reads them
    if tx.core.unchecked_tx {
        for k in now.iter().chain(&later) {
            tx.core.unchecked_states.remove(k);
        }
        return Ok(changed);
    }
    for k in &now {
        tx.core.unchecked_states.remove(k);
    }
    tx.core.unchecked_states.extend(later);
    check_states(tx, now)?;
    Ok(changed)
}

/// Debug builds: each of `aspects` holds exactly the join of its held bodies (`rebuilt`: spec/crdt.md
/// §4.6 Un-merge), as stored, but for the text chars §5.7 leaves to the node, and the caches
/// derived from them agree (gone lists, snapshot bounds, references). Panics with the
/// difference. Changes nothing.
#[cfg(debug_assertions)]
pub(crate) fn check_states(tx: &mut Tx<'_>, aspects: BTreeSet<(Tid, Ak)>) -> Result<()> {
    use crate::engine::state::encode;
    for (tid, ak) in aspects {
        // unseen: the cached state as it was, and no cost recorded
        let k = (tid, ak.clone());
        // the gone list is a cache of the parts' statuses: a part held as a bare leftover
        // has its own writes on it, one held whole or as a leftover with its own writes live none
        let list = tx.core.ix.gone.get(&k).cloned().unwrap_or_default();
        for c in tx.core.ix.by_aspect.get(&k).map(|s| s.iter().map(|(_, c)| *c).collect::<Vec<_>>()).unwrap_or_default() {
            let Some(m) = tx.core.ix.commits.get(&c) else { continue };
            let Some(ai) = m.aspect(&tid, &ak) else { continue };
            let own = crate::retention::writes_of(&m.header, &c, ai);
            let on = own.iter().filter(|o| list.binary_search(o).is_ok()).count();
            if m.own_gone(ai) {
                debug_assert_eq!(on, own.len(), "{c:?} on {tid:?} {ak:?}: held as an own-gone leftover, its writes not all gone");
            } else if m.holds(ai) {
                debug_assert_eq!(on, 0, "{c:?} on {tid:?} {ak:?}: held with its own writes live, its writes gone");
            }
        }
        // every held snapshot is indexed with bounds holding each write its body holds
        // (`retention::snapshot::Carried`): a write missed would expire in place past its copy
        for c in tx.core.ix.by_aspect.get(&k).map(|s| s.iter().map(|(_, c)| *c).collect::<Vec<_>>()).unwrap_or_default() {
            let Some(ai) = tx.core.ix.commits.get(&c).filter(|m| !m.header.kind.has_own_writes()).and_then(|m| m.aspect(&tid, &ak)) else { continue };
            let mut held = Carried::default();
            let gives = osis_base::costs::paused(|| super::each_held_piece(tx, &c, ai, &mut |_, f| {
                held.add(&f);
                Ok(())
            }))?;
            if !matches!(gives, Some(Some(_))) {
                continue;
            }
            let bound = tx.core.ix.snapshots.get(&k).and_then(|v| v.iter().find(|x| x.1 == c)).map(|x| x.4.clone());
            debug_assert!(bound.is_some_and(|b| b.holds(&held)), "held snapshot {c:?} on {tid:?} {ak:?}: its carried bounds miss a write it holds");
        }
        // the state as stored, through the one reader (`Tx::load_lazy`), not the cache
        let cached = (tx.core.states.remove(&k), tx.core.pages.remove(&k));
        let (want, got) = osis_base::costs::paused(|| -> Result<_> { Ok((rebuilt(tx, &tid, &ak, None)?, tx.state(&tid, &ak)?.cloned())) })?;
        // and the reference index, derived from it (a signal's from its held fires)
        osis_base::costs::paused(|| if ak.signal() { crate::engine::refs::check_fires(tx, &tid, &ak) } else { crate::engine::refs::check(tx, &tid, &ak, got.as_ref()) })?;
        // and the strongs its held bodies hold where its history holds them (`refs::kept`)
        osis_base::costs::paused(|| crate::engine::refs::kept::check(tx, &tid, &ak))?;
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
    }
    Ok(())
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
/// of every held valid body, leftovers included (an invalid delta's body carries only its own
/// writes, which un-merge takes; an invalid snapshot gives nothing), stripped of the values held
/// gone here. Written shredded (spec/commits.md §5: a body went, so every local copy of it
/// goes). What waits on its state, and its bodies with a relative bound, are
/// judged again.
///
/// Invariant (spec/crdt.md §4.7, spec/commits.md §5; `retention::strip_leftover`): no held body
/// carries the value of a write gone at this node (expired, purged), its own or a copy
/// under the original's dot (a snapshot's), and none loses a value of a write not so held. Kept
/// where it can break: while the aspect's gone list changed in this transaction, this walk
/// reads every held body and holds each snapshot carrying a listed value as its leftover
/// (`retention::strip_carried`, which lists nothing); a body arriving later joins stripped and is
/// stored as its leftover (`retention::drop_gone`, no rebuild).
pub(crate) fn rebuild(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    // a signal has no state: a validity change or a drop only changes which bodies count
    // (spec/commits.md §5 Signals), and so which fires' references are known
    if ak.signal() {
        let memory = tx.core.memory_tx;
        if let Some(b) = &mut tx.core.batched {
            b.entry((*tid, ak.clone())).or_default().memory |= memory;
            return Ok(());
        }
        return crate::engine::refs::resync_fires(tx, tid, ak);
    }
    tx.core.rebuilds += 1;
    let k = (*tid, ak.clone());
    // the state changes: held purge-on-replace bodies are judged again (`retention::settle_none`)
    if crate::retention::history::of(tx.core, tid, ak).purges() {
        tx.core.none_due.insert(k.clone());
    }
    let memory = tx.core.memory_tx;
    if let Some(b) = &mut tx.core.batched {
        let e = b.entry(k).or_default();
        e.memory |= memory;
        return Ok(());
    }
    let _s = osis_base::costs::span("rebuild");
    crate::engine::listing::before_rebuild(tx, tid, ak)?;
    let listed = tx.core.gone_dirty.contains(&k).then(|| tx.core.ix.gone.get(&k).cloned()).flatten().filter(|l| !l.is_empty());
    let mut carriers = Vec::new();
    let st = rebuilt(tx, tid, ak, listed.as_deref().map(|l| (l, &mut carriers)))?;
    for (c, ai) in &carriers {
        crate::retention::strip_carried(tx, c, *ai)?;
    }
    tx.set_state(tid, ak, st, Shred::Yes)?;
    crate::retention::mark_bounded(tx, tid, ak);
    Ok(())
}

/// A gone delta's change to `(tid, ak)` in place (spec/crdt.md §4.7): the state without the
/// writes `own` owns, `rebuild`'s result at O(the delta) where the held set changed only by those
/// writes leaving and none of them superseded a write still held (no held write revived:
/// `retention::make_leftover` asks the held writes). `at`, the delta's body before the removal,
/// says where its writes sit (a paged state loads those pages). A rebuild asked in this batch
/// already reads the bodies without them.
pub(crate) fn remove_in_place(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, at: &Fragment, own: &[Owned]) -> Result<()> {
    let k = (*tid, ak.clone());
    if ak.signal() || tx.core.batched.as_ref().is_some_and(|b| b.contains_key(&k)) {
        return Ok(());
    }
    let _s = osis_base::costs::span("gone: in place");
    // the state changes: held purge-on-replace bodies are judged again (`retention::settle_none`)
    if crate::retention::history::of(tx.core, tid, ak).purges() {
        tx.core.none_due.insert(k.clone());
    }
    tx.load_lazy(tid, ak)?;
    let touch = crate::engine::pages::touch_of(at, tx.core.pages.get(&k));
    tx.ensure_touch(tid, ak, &touch)?;
    let Some(mut st) = tx.core.states.get_mut(&k).and_then(Option::take) else { return Ok(()) };
    tx.core.touch();
    tx.core.wrote(k.clone());
    let refs = crate::engine::refs::indexed(ak).then(|| crate::engine::refs::Delta::reach(&st, at));
    let roots = crate::retention::compact::roots(ak, &st, at);
    let set = OwnedSet::of(own);
    st.remove_gone(&|d| set.owns(d));
    let refs = refs.map(|(mut d, before)| {
        d.after(&st, at, &before);
        d
    });
    let after = crate::retention::compact::roots(ak, &st, at);
    let st = tx.kept(tid, ak, st)?;
    tx.set_state_touched(tid, ak, st, &touch, Shred::Yes)?;
    crate::engine::refs::note(tx, tid, ak, refs.unwrap_or_default())?;
    crate::retention::compact::Trigger::unlinked(tx, tid, ak, &roots, &after)?;
    Ok(())
}

/// A covered drop's change to `(tid, ak)` (spec/commits.md §5 Covered): its coverer carries the
/// writes of part `ai` of `c`, so the state keeps its value, and every local copy of the body
/// goes. So the rows that held its writes are written again shredded, which makes their earlier
/// versions unrecoverable: the pages its positions reach (`pages::touch_of`, piece by piece: a
/// page whose element moved went shredded then, `pages::rewrite_set`), and the skeleton where it
/// reaches outside them; an unpaged state, one unit, or a body reaching above a paged collection
/// is written whole. `rebuild`'s result, at O(pages holding the body). Called while the part is
/// still held. A rebuild asked in this batch already writes the aspect whole.
pub(crate) fn shred_covered(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<()> {
    let k = (*tid, ak.clone());
    if tx.core.batched.as_ref().is_some_and(|b| b.contains_key(&k)) {
        return Ok(());
    }
    let _s = osis_base::costs::span("covered drop: shred");
    tx.load_lazy(tid, ak)?;
    tx.core.touch();
    tx.core.wrote(k.clone());
    let mut whole = !tx.core.pages.contains_key(&k);
    if !whole {
        super::each_held_piece(tx, c, ai, &mut |tx, piece| {
            if whole {
                return Ok(());
            }
            let touch = crate::engine::pages::touch_of(&piece, tx.core.pages.get(&k));
            if touch.is_none() {
                whole = true;
                return Ok(());
            }
            tx.ensure_touch(tid, ak, &touch)?;
            let st = match tx.core.states.get_mut(&k).and_then(Option::take) {
                Some(st) => tx.kept(tid, ak, st)?,
                None => None,
            };
            tx.set_state_touched(tid, ak, st, &touch, Shred::Yes)?;
            tx.evict_pages(tid, ak);
            Ok(())
        })?;
    }
    if whole {
        let st = tx.core.states.get_mut(&k).and_then(Option::take);
        tx.set_state_touched(tid, ak, st, &None, Shred::Yes)?;
    }
    // the part leaves its listing (`listing::listed`: a dropped part is listed nowhere); the
    // state, so every other commit's listing, stays
    if crate::engine::listing::listened(tx.core, tid, ak) {
        tx.core.commits_named(*tid, ak.clone(), *c);
    }
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
            crate::retention::off_gone(tx, &tid, &ak, &b.unlist);
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
    let mut st = Fragment::default();
    let mut ch = Changes::new();
    // the bodies a piece at a time; once the state is settled above the next one, none older
    // can change it (debug builds: all of them, the state they would skip beside, checking that)
    let mut settled = false;
    let mut fast: Option<Fragment> = None;
    let listed = carrying.as_ref().map(|(l, _)| OwnedSet::of(l));
    // each body without the writes gone here, before it joins (spec/crdt.md §4.7)
    let gone = tx.core.ix.gone.get(&(*tid, ak.clone())).filter(|v| !v.is_empty()).cloned();
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
        let _s = (!settled).then(|| osis_base::costs::span("rebuild: body"));
        debug_assert!(snapshots || !snap, "snapshot {c:?} of {tid:?} {ak:?} held and stored, not in `ix.snapshots`");
        // an invalid part joins nothing, but its body is held: un-merge takes exactly an invalid
        // delta's own writes, all its body carries (spec/crdt.md §3.3, §4.6), and an invalid
        // snapshot gives nothing (spec/permissions.md §5.2)
        if !valid && listed.is_none() {
            continue;
        }
        let mut carries = false;
        super::each_held_piece(tx, c, ai, &mut |_, mut f| {
            if let Some(l) = &listed
                && !carries
            {
                carries = l.held_in(&f);
                debug_assert!(snap || !carries, "content body {c:?} of {tid:?} {ak:?} holds a listed value: its own go at `make_leftover`, and only a snapshot copies another's");
            }
            if !valid {
                return Ok(());
            }
            if let Some(v) = &gone {
                f.remove_gone(&|d| crate::retention::sorted_owns(v, d));
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
    // written whole: its dead sequence records a few bytes each
    st.compact();
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
            for src in &srcs {
                for ctr in &ctrs {
                    let d = Dot { src: src.clone(), ctr: *ctr };
                    assert_eq!(set.owns(&d), owned.iter().any(|o| o.owns(&d)), "{owned:?} {d:?}");
                }
            }
        }
    }
}

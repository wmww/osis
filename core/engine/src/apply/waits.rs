//! What brings back what the node could not judge (notes/expiry-creation-design.md §3). Nothing
//! is kept of an unjudgeable part or commit but the reading-only secrets its boxes open; sync
//! fetches it again when what it awaits arrives. This module holds what names those fetches:
//! `Wakes` and the applied commits with a slot
//! waiting (`Awaiting`, derived from held headers).

use super::Reason;
use crate::engine::Core;
use osis_base::{BlobId, CommitId, CreationRecord, Tid};
use std::collections::{BTreeMap, BTreeSet};

/// What a pending commit awaits: its one parking place, keyed by the missing thing
/// (`Indexes::pend_on`, notes/sync-facade.md Pending). An arrival examines only the commits
/// parked under what it brought (`wake`), never every pending commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Wake {
    /// Examined once after an open (`Reason::Unexamined`, `Parked`: an upgrade may read it).
    Open,
    /// A record not known here (`atomic::learn_record`).
    Record(Tid),
    /// The role inputs held moving (an edge write, a record, a rotation): a reach or an epoch.
    Moved,
    /// The wall clock reaching this time (a `ts` ahead, `Reason::Drift`).
    At(u64),
    /// A blob stored (a page, a header list's tree: `Reason::WaitBlobs`).
    Blobs,
    /// A commit held here (the rotation minting an epoch, `Reason::Epoch`).
    Commit(CommitId),
    /// What is value-less on this thing changing (a purge request, an expiry): what reaches a
    /// stored copy writing on it (`retention::pending_drops`).
    Thing(Tid),
}

/// Where pending commit `id` waiting for `r` parks (`h`: its header, where it decoded): what it
/// awaits, its expiry, and the things it writes on (a purge or expiry changing what is value-less
/// there reaches its stored copy, `retention::pending_drops`).
pub(crate) fn wakes_of(core: &Core, id: &CommitId, r: &Reason, h: Option<&osis_commit::Header>) -> Vec<Wake> {
    let mut out = match r {
        Reason::Parked | Reason::Unexamined => vec![Wake::Open],
        Reason::MissingChain(t) | Reason::UnknownCreated(t) => {
            // every record a part of it awaits (`awaits_records`): any arriving may let a part apply;
            // one held: a reach, which role commits bring (whichever part `t` names)
            let recs: BTreeSet<Tid> = std::iter::once(*t).chain(core.waits.records_of(id).iter().copied()).collect();
            let (held, unknown): (Vec<Tid>, Vec<Tid>) = recs.into_iter().partition(|x| core.created(x).is_some());
            let mut out: Vec<Wake> = unknown.into_iter().map(Wake::Record).collect();
            if !held.is_empty() {
                out.push(Wake::Moved);
            }
            out
        }
        Reason::Drift => match h {
            Some(h) => vec![Wake::At(h.ts.wall_ms().0.saturating_sub(osis_base::format::MAX_DRIFT_MS))],
            None => vec![Wake::Moved],
        },
        Reason::WaitBlobs => vec![Wake::Blobs],
        Reason::Epoch(e) => vec![Wake::Commit(*e), Wake::Moved],
    };
    if let Some(h) = h {
        // an expiry already passed was run (`expire_stored`): no wake, or the clock is due for good
        if let Some(t) = h.expires.filter(|t| *t > core.now().0) {
            out.push(Wake::At(t));
        }
        out.extend(h.aspects.iter().map(|a| Wake::Thing(a.tid)));
    }
    out.sort();
    out.dedup();
    out
}

/// Commit `id` pends for `r` (`None`: no more), parked under what it awaits (`wakes_of`). The one
/// door to `Indexes::pending`, so `pend_on` follows it in every transaction and rollback.
pub(crate) fn set_pending(core: &mut Core, id: &CommitId, r: Option<(Reason, Option<&osis_commit::Header>)>) {
    let wakes = r.as_ref().map(|(r, h)| wakes_of(core, id, r, *h)).unwrap_or_default();
    if core.ix.pend_keys.get(id).map(|w| w.as_slice()) != Some(wakes.as_slice()) {
        for w in core.ix.pend_keys.get(id).cloned().unwrap_or_default().iter() {
            core.ix.pend_on.remove(w, id);
        }
        for w in &wakes {
            core.ix.pend_on.insert(*w, *id);
            match w {
                Wake::Record(t) => core.waits.loose.want(t),
                // a tick is due then (`Engine::next_timer`)
                Wake::At(t) => core.timer_floor = core.timer_floor.min(*t),
                _ => {}
            }
        }
        match wakes.is_empty() {
            true => core.ix.pend_keys.remove(id),
            false => core.ix.pend_keys.insert(*id, std::sync::Arc::new(wakes)),
        };
    }
    match r {
        Some((r, _)) => {
            if core.ix.pending.get(id) != Some(&r) {
                core.ix.pending.insert(*id, r);
            }
        }
        None => {
            core.ix.pending.remove(id);
        }
    }
}

/// Whether a commit here awaits record `t`: one pending, thrown out whole, or an applied commit's
/// slot (what names a loose record, so it is learned).
pub(crate) fn awaits_record(core: &Core, t: &Tid) -> bool {
    core.ix.pend_on.contains_key(&Wake::Record(*t)) || core.waits.awaiting.by_record.contains_key(t) || core.waits.on_record.contains_key(t)
}

/// The first time a pending commit's `ts` comes within reach (`Wake::At`).
pub(crate) fn next_at(core: &Core) -> Option<u64> {
    core.ix.pend_on.range(Wake::At(0)..=Wake::At(u64::MAX)).next().and_then(|(w, _)| match w {
        Wake::At(t) => Some(*t),
        _ => None,
    })
}

/// Records known here only from record blobs no awaiting commit named yet (spec/commits.md §4
/// Pending storage): each kept only while a store entry of a blob carrying it is (its carrier,
/// charged to the peer that brought it), learned for good once something here awaits it
/// (`Engine::promote_loose`). In memory: a start opens the carriers again (store `Follow`).
#[derive(Clone, Default)]
pub(crate) struct Loose {
    recs: BTreeMap<Tid, (CreationRecord, BTreeSet<BlobId>)>,
    by_blob: BTreeMap<BlobId, BTreeSet<Tid>>,
    /// Records an awaiting commit or slot named while loose: learned at the next `reexamine`.
    due: BTreeSet<Tid>,
}

impl Loose {
    /// `r`, carried by `b`, awaited by nothing here yet.
    pub fn keep(&mut self, b: BlobId, r: CreationRecord) {
        let t = r.tid();
        self.recs.entry(t).or_insert_with(|| (r, BTreeSet::new())).1.insert(b);
        self.by_blob.entry(b).or_default().insert(t);
    }

    /// Something here awaits `t`: learned if loose.
    pub fn want(&mut self, t: &Tid) {
        if self.recs.contains_key(t) {
            self.due.insert(*t);
        }
    }

    pub fn get(&self, t: &Tid) -> Option<&CreationRecord> {
        self.recs.get(t).map(|x| &x.0)
    }

    /// Whether a loose record was named awaited since `take_due`.
    pub fn has_due(&self) -> bool {
        !self.due.is_empty()
    }

    /// The loose records named awaited since the last call.
    pub fn take_due(&mut self) -> BTreeSet<Tid> {
        std::mem::take(&mut self.due)
    }

    /// `t` is learned (or known): loose no more. The blobs it left carrying nothing.
    pub fn learned(&mut self, t: &Tid) -> Vec<BlobId> {
        let mut out = Vec::new();
        for b in self.recs.remove(t).map(|x| x.1).unwrap_or_default() {
            if let Some(s) = self.by_blob.get_mut(&b) {
                s.remove(t);
                if s.is_empty() {
                    self.by_blob.remove(&b);
                    out.push(b);
                }
            }
        }
        out
    }

    /// Whether `b` carries a loose record.
    pub fn carries(&self, b: &BlobId) -> bool {
        self.by_blob.contains_key(b)
    }

    /// No entry carries `b` any more: the records only it carried go.
    pub fn forget(&mut self, b: &BlobId) {
        for t in self.by_blob.remove(b).unwrap_or_default() {
            if let Some(x) = self.recs.get_mut(&t) {
                x.1.remove(b);
                if x.1.is_empty() {
                    self.recs.remove(&t);
                    self.due.remove(&t);
                }
            }
        }
    }

    /// Loose records held (scale checks).
    pub fn len(&self) -> usize {
        self.recs.len()
    }
}

/// Headers of unjudgeable commits remembered in memory (`Waits`): a page of a very large backlog is
/// the most a peer's input can keep; a restart loses them all and fetches again.
const MAX_REMEMBERED: usize = 4096;

/// Applied commits with a slot `thing_wait` holds back (`m.missing`), derived from held headers:
/// not journaled, a wake a rollback undoes only costs a fetch. A slot no entry opened costs nothing:
/// node-sync finds no entry for it.
#[derive(Clone, Default)]
pub(crate) struct Awaiting {
    by_record: BTreeMap<Tid, BTreeSet<CommitId>>,
    reach: BTreeSet<CommitId>,
}

/// The budget's refused commits, and what reading-only secrets were read from: not journaled, and
/// rebuilt at load (`load_reading`).
#[derive(Clone, Default)]
pub(crate) struct Waits {
    /// Commits read again by `reexamine` so far (scale checks).
    pub examined: u64,
    /// Commits whose boxes the reading-only budget refused (`box_refused`).
    refused: BTreeSet<CommitId>,
    /// Commits reading-only secrets came from.
    reading: BTreeSet<CommitId>,
    pub awaiting: Awaiting,
    /// Unapplied commits an awaiting entry holds, by the things their headers touch
    /// (`Engine::awaits_on`). From headers seen, in memory: a restart fetches them again.
    on_thing: BTreeMap<Tid, BTreeSet<CommitId>>,
    things_of: BTreeMap<CommitId, Vec<Tid>>,
    /// Commits thrown out whole by the records they await (every part's, not only the one the entry
    /// names: any arriving may let a part apply), by record; in memory, with `things_of`.
    on_record: BTreeMap<Tid, BTreeSet<CommitId>>,
    records_of: BTreeMap<CommitId, Vec<Tid>>,
    /// Records from record blobs nothing awaits yet (`Loose`).
    pub loose: Loose,
    /// Stamps a carrier of loose records whose every record was learned (`Engine::loose_feed`).
    pub carried: osis_base::memo::Stamps,
    /// Stamps a waiting memory commit woken by what it awaited (`Engine::memory_woken_feed`):
    /// node-sync applies it within its sync ID's room (`apply_waiting_memory`).
    pub memory_woken: osis_base::memo::Stamps,
    /// The next `reexamine` wakes `Wake::Open` (an open loaded the pending commits).
    pub open_due: bool,
    /// A blob was stored since the last `wake`: `Wake::Blobs` is due.
    pub blobs_due: bool,
    /// Things whose value-less lists or purge requests moved since the last `wake`: `Wake::Thing`.
    pub lists_moved: BTreeSet<Tid>,
    /// The commits held since the last `wake` (`Wake::Commit`); started at the first, and again
    /// after a load (whose `Wake::Open` examines every pending commit).
    pub held_feed: Option<osis_base::memo::Feed<CommitId>>,
    /// Tests: the next `wake` examines every pending commit, as a full scan (`Engine::lost_wakes`).
    pub every_due: bool,
    /// Commits whose copy's parts on things this node cannot read were not taken
    /// (`Engine::copy_stale`), by those things' secret actor: fetched again once the node holds
    /// secrets of it (`read_again`). In memory: a restart fetches every missing part again.
    unread: BTreeMap<Tid, BTreeSet<CommitId>>,
    /// Actors whose applied boxes gave secrets the node's roles did not give then
    /// (`rotation::may_take`): taken again once they do (`flows::retake`). In memory: the open's
    /// `reopen_all` (`take_account`) refuses and lists them again.
    untaken: BTreeSet<Tid>,
    /// Entries `retaken` took off `untaken` in the transaction running: a rollback lists them
    /// again (`Core::rollback_to`; the secrets they gave are rolled back), a commit forgets them.
    retaking: Vec<Tid>,
}

impl Waits {
    /// A commit's boxes had no room in the reading-only budget (`read_pending_boxes`).
    pub fn box_refused(&mut self, id: CommitId) {
        self.refused.insert(id);
    }

    /// Reading-only secrets came from `id`.
    pub fn read_from(&mut self, id: CommitId) {
        self.reading.insert(id);
    }

    /// Whether `id` gave reading-only secrets (`keys::forget_unchecked`).
    pub fn read_any(&self, id: &CommitId) -> bool {
        self.reading.contains(id)
    }

    /// The commits reading-only secrets came from.
    pub fn sources(&self) -> &BTreeSet<CommitId> {
        &self.reading
    }

    /// `id` cannot be judged; `things`: its header's.
    pub fn awaits(&mut self, id: CommitId, things: Vec<Tid>) {
        self.make_room(&id);
        for t in &things {
            self.on_thing.entry(*t).or_default().insert(id);
        }
        self.things_of.insert(id, things);
    }

    /// `id`, thrown out whole, awaits each of `records`.
    pub fn awaits_records(&mut self, id: CommitId, records: impl Iterator<Item = Tid>) {
        self.make_room(&id);
        let records: Vec<Tid> = records.collect::<BTreeSet<_>>().into_iter().collect();
        for t in &records {
            self.on_record.entry(*t).or_default().insert(id);
            self.loose.want(t);
        }
        self.records_of.insert(id, records);
    }

    /// Remembered commits stay under `MAX_REMEMBERED`, the headers of commits given directly (a peer,
    /// an inbox chain) having no entry to go with: past it the smallest ID is forgotten (it waits on no
    /// wake, and `awaits_on` stops naming it; a restart forgets them all alike).
    fn make_room(&mut self, id: &CommitId) {
        while !self.things_of.contains_key(id) && !self.records_of.contains_key(id) && self.things_of.len().max(self.records_of.len()) >= MAX_REMEMBERED {
            let Some(first) = self.things_of.keys().chain(self.records_of.keys()).min().copied() else { return };
            self.unawaits(&first);
        }
    }

    /// `id` applied, or its last entry left.
    pub fn unawaits(&mut self, id: &CommitId) {
        for t in self.things_of.remove(id).into_iter().flatten() {
            if let Some(s) = self.on_thing.get_mut(&t) {
                s.remove(id);
                if s.is_empty() {
                    self.on_thing.remove(&t);
                }
            }
        }
        for t in self.records_of.remove(id).into_iter().flatten() {
            if let Some(s) = self.on_record.get_mut(&t) {
                s.remove(id);
                if s.is_empty() {
                    self.on_record.remove(&t);
                }
            }
        }
    }

    /// The records something here awaits: an applied commit's slot, a commit thrown out whole.
    pub fn records_awaited(&self) -> impl Iterator<Item = &Tid> {
        self.awaiting.by_record.keys().chain(self.on_record.keys())
    }

    /// The records `id`, thrown out whole, awaits (`awaits_records`).
    pub fn records_of(&self, id: &CommitId) -> &[Tid] {
        self.records_of.get(id).map_or(&[], |v| v.as_slice())
    }

    /// Whether a commit touching `t` cannot be judged here (`Engine::awaits_on`).
    pub fn awaits_on(&self, t: &Tid) -> bool {
        self.on_thing.contains_key(t)
    }

    /// Commit `id` has parts not taken on content under `actor`, which the node cannot read.
    pub fn awaits_reading(&mut self, actor: Tid, id: CommitId) {
        self.unread.entry(actor).or_default().insert(id);
    }

    /// An applied box of `actor` gave secrets the node's roles did not give.
    pub fn untaken(&mut self, actor: Tid) {
        self.untaken.insert(actor);
    }

    /// The untaken actors `may` allows.
    pub fn untaken_due(&self, may: impl Fn(&Tid) -> bool) -> Vec<Tid> {
        self.untaken.iter().filter(|a| may(a)).copied().collect()
    }

    /// `actor`, taken off the untaken list (opened again).
    pub fn retaken(&mut self, actor: &Tid) {
        if self.untaken.remove(actor) {
            self.retaking.push(*actor);
        }
    }

    /// The transaction committed: what `retaken` took stays taken.
    pub fn retake_committed(&mut self) {
        self.retaking.clear();
    }

    /// The transaction (or a step of it) rolled back: what `retaken` took is listed again (a
    /// superset is harmless: `flows::retake` judges each entry again).
    pub fn retake_rolled_back(&mut self) {
        self.untaken.extend(self.retaking.drain(..));
    }

    /// The commits waiting for the node to read `actor` (`awaits_reading`), taken.
    pub fn read_again(&mut self, actor: &Tid) -> BTreeSet<CommitId> {
        self.unread.remove(actor).unwrap_or_default()
    }

    /// `id`'s reading-only secrets went, or it no longer awaits.
    pub fn forgot(&mut self, id: &CommitId) {
        self.reading.remove(id);
        self.refused.remove(id);
    }

    /// Slot of applied commit `id` waits for `r`: reach waits (`MissingChain` of a held record) by
    /// `reach`, the others by the record.
    pub fn slot_waits(&mut self, core_created: bool, id: CommitId, r: &Reason) {
        match r {
            Reason::UnknownCreated(t) | Reason::MissingChain(t) if !core_created => {
                self.awaiting.by_record.entry(*t).or_default().insert(id);
                self.loose.want(t);
            }
            _ => {
                self.awaiting.reach.insert(id);
            }
        }
    }
}

/// Names what the budget, new records and other arrivals free: `Wakes`, and the pending
/// commits to examine again, those parked under what arrived (`Wake`). The start of
/// `Engine::reexamine`: costs what arrived and the commits parked under it.
pub(crate) fn wake(core: &mut Core) -> BTreeSet<CommitId> {
    let records = core.ix.held.take_records();
    let moved = core.ix.held.take_moved();
    // learned, by whatever path: loose no more; a carrier left carrying nothing gives something held
    for t in &records {
        for b in core.waits.loose.learned(t) {
            core.waits.carried.wrote_added(&b, true, true);
        }
    }
    let room = core.reading_room();
    let mut reread = Vec::new();
    for _ in 0..room {
        let Some(id) = core.waits.refused.pop_first() else { break };
        reread.push(id);
    }
    let mut undropped: BTreeSet<CommitId> = BTreeSet::new();
    for t in &records {
        if let Some(cs) = core.waits.awaiting.by_record.remove(t) {
            undropped.extend(cs);
        }
    }
    // a commit awaiting this record among others (the entry names only the first): a pending one
    // keeps every part (`throw_out_parts`), so it is examined again (`reread`), never fetched
    for t in &records {
        for c in core.waits.on_record.get(t).into_iter().flatten() {
            if core.ix.commits.contains_key(c) {
                undropped.insert(*c);
            } else {
                reread.push(*c);
            }
        }
    }
    // a pending one awaiting a reach among records is parked under `Wake::Moved` too (`wakes_of`)
    if !moved.is_empty() {
        undropped.append(&mut core.waits.awaiting.reach);
    }
    let mut out: BTreeSet<CommitId> = reread.iter().copied().collect();
    // the pending commits parked under what arrived (`Wake`)
    let pend_on = &core.ix.pend_on;
    let mut keys: Vec<Wake> = records.iter().map(|t| Wake::Record(*t)).collect();
    if !moved.is_empty() || !records.is_empty() {
        keys.push(Wake::Moved);
    }
    if std::mem::take(&mut core.waits.blobs_due) {
        keys.push(Wake::Blobs);
    }
    if std::mem::take(&mut core.waits.open_due) {
        keys.push(Wake::Open);
    }
    keys.extend(std::mem::take(&mut core.waits.lists_moved).into_iter().map(Wake::Thing));
    match core.waits.held_feed.as_mut() {
        Some(f) => keys.extend(f.added().into_iter().map(Wake::Commit)),
        None => core.waits.held_feed = Some(core.ix.commits.feed()),
    }
    let now = core.now().0;
    keys.extend(pend_on.range(Wake::At(0)..=Wake::At(now)).map(|(w, _)| *w));
    if std::mem::take(&mut core.waits.every_due) {
        out.extend(core.ix.pending.keys().copied());
    }
    for w in &keys {
        out.extend(pend_on.get(w).into_iter().flatten().copied());
    }
    out.retain(|c| core.ix.pending.contains_key(c));
    if let Some(ch) = &mut core.wakes {
        ch.woken.extend(undropped);
        ch.records.extend(records);
        ch.moved |= !moved.is_empty();
        ch.reread.extend(reread);
    }
    out
}

/// The commits reading-only secrets came from, after a load.
pub(crate) fn load_reading(core: &mut Core) {
    let ids: BTreeSet<CommitId> = core.ix.secrets.values().flat_map(|e| osis_keys::ROLES.iter().flat_map(|r| e.role(*r).epochs().flat_map(|(_, i)| i.reading.iter().map(|u| u.commit)).collect::<Vec<_>>()).collect::<Vec<_>>()).collect();
    core.waits.reading = ids;
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/requirements.md (no unbounded storage from peer input), spec/commits.md §4: what is remembered of unjudgeable
    // headers stays under its bound however many come.
    #[test]
    fn remembered_headers_are_bounded_spec_commits_4() {
        let mut w = Waits::default();
        for i in 0..MAX_REMEMBERED + 10 {
            let mut c = [0u8; 32];
            c[..8].copy_from_slice(&(i as u64).to_be_bytes());
            w.awaits(CommitId(c), vec![Tid::from_bytes([1; 15])]);
            w.awaits_records(CommitId(c), [Tid::from_bytes([2; 15])].into_iter());
        }
        assert!(w.things_of.len() <= MAX_REMEMBERED && w.records_of.len() <= MAX_REMEMBERED);
        assert_eq!(w.on_thing[&Tid::from_bytes([1; 15])].len(), w.things_of.len(), "the index follows");
    }
}

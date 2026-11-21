//! What brings back what waits (spec/commits.md §4): the one parking place of pending commits and
//! of the waiting parts of applied ones (`Wake`, `Indexes::pend_on`), the records their parts
//! await, loose records, and the reading-only budget's refusals.

use super::Reason;
use crate::engine::Core;
use osis_base::{BlobId, CommitId, CreationRecord, Role, Tid};
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
    /// A thing entering the node closure (`Reason::Outside`): its content parts may apply
    /// (`atomic::wake_entered`, in the transaction it enters).
    Enters(Tid),
    /// The role inputs held moving (an edge write, a record, a rotation): a reach or an epoch.
    Moved,
    /// The wall clock reaching this time (a `ts` ahead, `Reason::Drift`).
    At(u64),
    /// An epoch an account's chain came to hold (the rotation minting it held with its chain, a
    /// merge's tips and a certificate: `Reason::Epoch`). Holding the rotation alone opens nothing:
    /// its key is known once the chain holds its epoch.
    Epoch(CommitId),
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
        Reason::MissingChain(_) | Reason::UnknownCreated(_) => Vec::new(),
        Reason::Outside(t) => vec![Wake::Enters(*t)],
        Reason::Drift => match h {
            Some(h) => vec![Wake::At(h.ts.wall_ms().0.saturating_sub(osis_base::format::MAX_DRIFT_MS))],
            None => vec![Wake::Moved],
        },
        // keyed by the blobs its walks lack (`reach::Walks`)
        Reason::WaitBlobs => Vec::new(),
        Reason::Epoch(e) => vec![Wake::Epoch(*e), Wake::Moved],
    };
    // every record a part of it awaits (`parts_await`), whatever its first reason: any arriving
    // may let a part apply; one held: a reach, which role commits bring (whichever part `t` names)
    let first = match r {
        Reason::MissingChain(t) | Reason::UnknownCreated(t) => Some(*t),
        _ => None,
    };
    let recs: BTreeSet<Tid> = first.into_iter().chain(core.waits.records_of(id).iter().copied()).collect();
    let (held, unknown): (Vec<Tid>, Vec<Tid>) = recs.into_iter().partition(|x| core.created(x).is_some());
    out.extend(unknown.into_iter().map(Wake::Record));
    if !held.is_empty() {
        out.push(Wake::Moved);
    }
    // every thing a content part of it waits to see enter the node closure
    out.extend(core.waits.entries_of(id).iter().map(|t| Wake::Enters(*t)));
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
    // pending no more: the blob waits of its pending copy go at the transaction's end, unless
    // it pends again in it (`reach::settle`)
    if r.is_none() {
        core.walks.unpended(id);
    }
    if core.ix.pend_keys.get(id).map(|w| w.as_slice()) != Some(wakes.as_slice()) {
        for w in core.ix.pend_keys.get(id).cloned().unwrap_or_default().iter() {
            core.ix.pend_on.remove(w, id);
            // held for itself while awaited (`retention::needed::Root::Awaited`): judged again
            if let Wake::Enters(t) = w
                && !wakes.contains(w)
            {
                core.note_lost(*t);
            }
        }
        for w in &wakes {
            core.ix.pend_on.insert(*w, *id);
            match w {
                Wake::Record(t) => {
                    core.waits.loose.want(t);
                    // judged once the pass ends: a record nothing needs is not awaited (`retention::needed`)
                    core.note_pass_due(*t);
                }
                // judged once the pass ends: what no synced sync ID carries goes (`needed::uncarried`)
                Wake::Enters(t) => core.note_pass_due(*t),
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
    // what it needs while it pends (`retention::needed`): its signers, as a held commit's, and the
    // thing whose record or chain it awaits; those of one leaving unapplied are judged again
    // where it leaves (`pending_left`)
    let awaits = match &r {
        Some((Reason::MissingChain(t) | Reason::UnknownCreated(t), _)) => Some(*t),
        _ => None,
    };
    let needs: Vec<Tid> = match &r {
        Some((_, Some(h))) => {
            // Interim (notes/a1-spec/README.md step 3): the one purge author it acts for
            let mut v = vec![h.signer, h.purge_author()];
            v.extend(awaits);
            v.sort();
            v.dedup();
            v
        }
        // pending still, its header not read this time: as it was
        Some((_, None)) => core.ix.pend_needs.get(id).map(|v| v.to_vec()).unwrap_or_default(),
        None => Vec::new(),
    };
    if core.ix.pend_needs.get(id).map(|w| w.as_slice()) != Some(needs.as_slice()) {
        for k in core.ix.pend_needs.get(id).cloned().unwrap_or_default().iter() {
            core.ix.pend_by.remove(k, id);
        }
        for k in &needs {
            core.ix.pend_by.insert(*k, *id);
        }
        match needs.is_empty() {
            true => core.ix.pend_needs.remove(id),
            false => core.ix.pend_needs.insert(*id, std::sync::Arc::new(needs)),
        };
    }
    match r {
        Some((r, _)) => {
            if core.ix.pending.get(id) != Some(&r) {
                core.ix.pending.insert(*id, r);
            }
        }
        None => {
            if core.ix.pending.remove(id).is_some() {
                // its carriers go with it unless it pends again in this transaction (`carriers::settle`)
                core.carriers_due.insert(*id);
                if core.ix.commits.contains_key(id) {
                    core.waits.unpended.wrote_added(id, true, true);
                }
            }
        }
    }
}

/// Pending commit `id` leaves unapplied (its last carrier gone, its things forgotten): a need of
/// what it needed goes, so each is judged again (`retention::needed`). Call before it unpends.
pub(crate) fn pending_left(core: &mut Core, id: &CommitId) {
    let signers = core.ix.pend_needs.get(id).cloned().unwrap_or_default();
    for k in signers.iter() {
        core.note_lost(*k);
    }
}

/// Whether something here awaits a part of whose thing waits for what it needs there: its record
/// or its entry into the node closure (`retention::needed::Root::Awaited`).
pub(crate) fn awaited(core: &Core, t: &Tid) -> bool {
    core.ix.pend_on.contains_key(&Wake::Record(*t)) || core.ix.pend_on.contains_key(&Wake::Enters(*t))
}

/// Whether something here awaits record `t`: a pending commit, a waiting part of one, or a held
/// strong to it (`Closure::awaits_record`): what names a loose record, so it is learned.
pub(crate) fn awaits_record(core: &Core, t: &Tid) -> bool {
    core.ix.pend_on.contains_key(&Wake::Record(*t)) || core.waits.on_record.contains_key(t) || core.ix.closure.awaits_record(t)
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
    /// List blobs whose rotation is not held here (spec/sync-judgement.md §1 List blobs): each
    /// one's thing lists, unverified, held as the rotation arrives (`lists_for`, verified then
    /// against its list root), by carrier.
    lists: BTreeMap<BlobId, (CommitId, Vec<osis_commit::thing_list::ThingCert>)>,
    lists_by_rotation: BTreeMap<CommitId, BTreeSet<BlobId>>,
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

    /// Thing lists of rotation `r`, not held here, carried by `b`.
    pub fn keep_lists(&mut self, b: BlobId, r: CommitId, certs: Vec<osis_commit::thing_list::ThingCert>) {
        self.lists.insert(b, (r, certs));
        self.lists_by_rotation.entry(r).or_default().insert(b);
    }

    /// The loose thing lists of rotation `r` (as its commit arrives).
    pub fn lists_for(&self, r: &CommitId) -> Vec<osis_commit::thing_list::ThingCert> {
        self.lists_by_rotation.get(r).into_iter().flatten().filter_map(|b| self.lists.get(b)).flat_map(|x| x.1.iter().cloned()).collect()
    }

    /// Rotation `r` arrived and its loose lists were held: loose no more. Their carriers.
    pub fn lists_held(&mut self, r: &CommitId) -> Vec<BlobId> {
        let out: Vec<BlobId> = self.lists_by_rotation.remove(r).into_iter().flatten().collect();
        for b in &out {
            self.lists.remove(b);
        }
        out
    }

    /// Whether `b` carries a loose record or loose thing lists.
    pub fn carries(&self, b: &BlobId) -> bool {
        self.by_blob.contains_key(b) || self.lists.contains_key(b)
    }

    /// No entry carries `b` any more: the records and lists only it carried go.
    pub fn forget(&mut self, b: &BlobId) {
        if let Some((r, _)) = self.lists.remove(b)
            && let Some(x) = self.lists_by_rotation.get_mut(&r)
        {
            x.remove(b);
            if x.is_empty() {
                self.lists_by_rotation.remove(&r);
            }
        }
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

    /// Loose records and list blobs held (scale checks).
    pub fn len(&self) -> usize {
        self.recs.len() + self.lists.len()
    }
}

/// Headers of unjudgeable commits remembered in memory (`Waits`): a page of a very large backlog is
/// the most a peer's input can keep; a restart loses them all and fetches again.
const MAX_REMEMBERED: usize = 4096;

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
    /// Pending commits, and applied ones with parts waiting, by the records their parts await
    /// (every part's, not only the one their reason names: any arriving may let a part apply); in
    /// memory (a restart fetches them again), noted at each examination that pends them.
    on_record: BTreeMap<Tid, BTreeSet<CommitId>>,
    records_of: BTreeMap<CommitId, Vec<Tid>>,
    /// Pending commits, and applied ones with parts waiting, by the things outside the node
    /// closure their content parts wait to see enter (`Reason::Outside`), noted as `records_of`.
    entries_of: BTreeMap<CommitId, Vec<Tid>>,
    /// Records from record blobs nothing awaits yet (`Loose`).
    pub loose: Loose,
    /// Stamps a carrier of loose records whose every record was learned (`Engine::loose_feed`).
    pub carried: osis_base::memo::Stamps,
    /// Stamps a waiting memory commit woken by what it awaited (`Engine::memory_woken_feed`):
    /// node-sync applies it within its sync ID's room (`apply_waiting_memory`).
    pub memory_woken: osis_base::memo::Stamps,
    /// Stamps a held commit whose waiting parts all joined or went: it pends no more
    /// (`Engine::unpended_feed`). Not journaled: a reader judges each again.
    pub unpended: osis_base::memo::Stamps,
    /// The next `reexamine` wakes `Wake::Open` (an open loaded the pending commits).
    pub open_due: bool,
    /// Things whose value-less lists or purge requests moved since the last `wake`: `Wake::Thing`.
    pub lists_moved: BTreeSet<Tid>,
    /// Epochs an account's chain came to hold since the last `wake` (`account::refresh_epochs`):
    /// `Wake::Epoch` of each.
    pub epochs_held: BTreeSet<CommitId>,
    /// Tests: the next `wake` examines every pending commit, as a full scan (`Engine::lost_wakes`).
    pub every_due: bool,
    /// Actors whose applied boxes gave secrets the node's roles did not give then
    /// (`rotation::may_take_role`), with the roles kept out: taken again once they do
    /// (`flows::retake`). In memory: the open's `reopen_all` (`take_account`) refuses and lists
    /// them again.
    untaken: BTreeMap<Tid, BTreeSet<Role>>,
    /// Entries `retaken` took off `untaken` in the transaction running: a rollback lists them
    /// again (`Core::rollback_to`; the secrets they gave are rolled back), a commit forgets them.
    retaking: Vec<(Tid, BTreeSet<Role>)>,
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

    /// Parts of pending `id` wait for `reasons` (and nothing else noted before): the records
    /// they await, and the things whose entry into the node closure they await.
    pub fn parts_await<'a>(&mut self, id: CommitId, reasons: impl Iterator<Item = &'a Reason>) {
        self.unawaits(&id);
        let mut records = BTreeSet::new();
        let mut entries = BTreeSet::new();
        for r in reasons {
            match r {
                Reason::MissingChain(t) | Reason::UnknownCreated(t) => drop(records.insert(*t)),
                Reason::Outside(t) => drop(entries.insert(*t)),
                _ => {}
            }
        }
        if records.is_empty() && entries.is_empty() {
            return;
        }
        self.make_room(&id);
        for t in &records {
            self.on_record.entry(*t).or_default().insert(id);
            self.loose.want(t);
        }
        if !records.is_empty() {
            self.records_of.insert(id, records.into_iter().collect());
        }
        if !entries.is_empty() {
            self.entries_of.insert(id, entries.into_iter().collect());
        }
    }

    /// Remembered commits stay under `MAX_REMEMBERED`, the headers of commits given directly (a peer,
    /// an inbox chain) having no entry to go with: past it the smallest ID is forgotten (it waits on no
    /// wake; a restart forgets them all alike).
    fn make_room(&mut self, id: &CommitId) {
        while !self.records_of.contains_key(id) && !self.entries_of.contains_key(id) && self.records_of.len().max(self.entries_of.len()) >= MAX_REMEMBERED {
            let Some(first) = self.records_of.keys().chain(self.entries_of.keys()).min().copied() else { return };
            self.unawaits(&first);
        }
    }

    /// `id` applied, or its last entry left.
    pub fn unawaits(&mut self, id: &CommitId) {
        self.entries_of.remove(id);
        for t in self.records_of.remove(id).into_iter().flatten() {
            if let Some(s) = self.on_record.get_mut(&t) {
                s.remove(id);
                if s.is_empty() {
                    self.on_record.remove(&t);
                }
            }
        }
    }

    /// The records the parts of `id` await (`parts_await`).
    pub fn records_of(&self, id: &CommitId) -> &[Tid] {
        self.records_of.get(id).map_or(&[], |v| v.as_slice())
    }

    /// The things whose entry into the node closure the parts of `id` await (`parts_await`).
    pub fn entries_of(&self, id: &CommitId) -> &[Tid] {
        self.entries_of.get(id).map_or(&[], |v| v.as_slice())
    }


    /// Reading `actor`'s `secrets.0` gave `roles` otherwise than the node holds them, which its
    /// roles kept as they were (`Core::ingest_view`).
    pub fn untaken(&mut self, actor: Tid, roles: BTreeSet<Role>) {
        self.untaken.entry(actor).or_default().extend(roles);
    }

    /// The untaken actors where `may` allows a role kept out.
    pub fn untaken_due(&self, may: impl Fn(&Tid, Role) -> bool) -> Vec<Tid> {
        self.untaken.iter().filter(|(a, rs)| rs.iter().any(|r| may(a, *r))).map(|(a, _)| *a).collect()
    }

    /// `actor`, taken off the untaken list (opened again).
    pub fn retaken(&mut self, actor: &Tid) {
        if let Some(rs) = self.untaken.remove(actor) {
            self.retaking.push((*actor, rs));
        }
    }

    /// The transaction committed: what `retaken` took stays taken.
    pub fn retake_committed(&mut self) {
        self.retaking.clear();
    }

    /// The transaction (or a step of it) rolled back: what `retaken` took is listed again (a
    /// superset is harmless: `flows::retake` judges each entry again).
    pub fn retake_rolled_back(&mut self) {
        for (a, rs) in self.retaking.drain(..) {
            self.untaken.entry(a).or_default().extend(rs);
        }
    }


    /// `id`'s reading-only secrets went, or it no longer awaits.
    pub fn forgot(&mut self, id: &CommitId) {
        self.reading.remove(id);
        self.refused.remove(id);
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
    let mut out: BTreeSet<CommitId> = reread.iter().copied().collect();
    // the pending commits parked under what arrived (`Wake`)
    let pend_on = &core.ix.pend_on;
    let mut keys: Vec<Wake> = records.iter().map(|t| Wake::Record(*t)).collect();
    if !moved.is_empty() || !records.is_empty() {
        keys.push(Wake::Moved);
    }
    if std::mem::take(&mut core.waits.open_due) {
        keys.push(Wake::Open);
    }
    keys.extend(std::mem::take(&mut core.waits.lists_moved).into_iter().map(Wake::Thing));
    keys.extend(std::mem::take(&mut core.waits.epochs_held).into_iter().map(Wake::Epoch));
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
        ch.reread.extend(reread);
    }
    out
}

/// The commits reading-only secrets came from, after a load.
pub(crate) fn load_reading(core: &mut Core) {
    let ids: BTreeSet<CommitId> = core.ix.secrets.values().flat_map(|e| osis_keys::ROLES.iter().flat_map(|r| e.role(*r).epochs().flat_map(|(_, i)| i.sources().map(|u| u.commit)).collect::<Vec<_>>()).collect::<Vec<_>>()).collect();
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
            w.parts_await(CommitId(c), [Reason::UnknownCreated(Tid::from_bytes([2; 15]))].iter());
        }
        assert!(w.records_of.len() <= MAX_REMEMBERED);
        assert_eq!(w.on_record[&Tid::from_bytes([2; 15])].len(), w.records_of.len(), "the index follows");
    }
}

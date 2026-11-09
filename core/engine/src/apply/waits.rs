//! What brings back what the node could not judge (notes/expiry-creation-design.md §3). Nothing
//! is kept of an unjudgeable part or commit but the reading-only secrets its boxes open; node-sync
//! fetches it again when what it awaits arrives. This module holds what names those fetches:
//! `Changed::wakes` and the applied commits with a slot
//! waiting (`Awaiting`, derived from held headers).

use super::Reason;
use crate::engine::Core;
use osis_base::{CommitId, Tid};
use std::collections::{BTreeMap, BTreeSet};

/// Applied commits with a slot `thing_wait` holds back (`m.missing`), derived from held headers:
/// not journaled, a wake a rollback undoes only costs a fetch. A slot no entry opened costs nothing:
/// node-sync finds no entry for it.
#[derive(Default)]
pub(crate) struct Awaiting {
    by_record: BTreeMap<Tid, BTreeSet<CommitId>>,
    reach: BTreeSet<CommitId>,
}

/// The budget's refused commits, and what reading-only secrets were read from: not journaled, and
/// rebuilt at load (`load_reading`).
#[derive(Default)]
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
        for t in &things {
            self.on_thing.entry(*t).or_default().insert(id);
        }
        self.things_of.insert(id, things);
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
    }

    /// The commits `awaits` holds things of.
    pub fn awaiting_ids(&self) -> Vec<CommitId> {
        self.things_of.keys().copied().collect()
    }

    /// Whether a commit touching `t` cannot be judged here (`Engine::awaits_on`).
    pub fn awaits_on(&self, t: &Tid) -> bool {
        self.on_thing.contains_key(t)
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
            }
            _ => {
                self.awaiting.reach.insert(id);
            }
        }
    }
}

/// Names what the budget and new records free: `Changed::wakes`. The start of
/// `Engine::reexamine`.
pub(crate) fn wake(core: &mut Core) {
    let records = core.ix.held.take_records();
    let moved = core.ix.held.take_moved();
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
    if !moved.is_empty() {
        undropped.append(&mut core.waits.awaiting.reach);
    }
    if let Some(ch) = &mut core.changed {
        ch.wakes.woken.extend(undropped);
        ch.wakes.records.extend(records);
        ch.wakes.moved |= !moved.is_empty();
        ch.wakes.reread.extend(reread);
    }
}

/// The commits reading-only secrets came from, after a load.
pub(crate) fn load_reading(core: &mut Core) {
    let ids: BTreeSet<CommitId> = core.ix.secrets.values().flat_map(|e| osis_keys::ROLES.iter().flat_map(|r| e.role(*r).epochs().flat_map(|(_, i)| i.reading.iter().map(|u| u.commit)).collect::<Vec<_>>()).collect::<Vec<_>>()).collect();
    core.waits.reading = ids;
}

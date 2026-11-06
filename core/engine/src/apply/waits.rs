//! What examining a pending commit read (spec/commits.md §4), so `Engine::reexamine` reads,
//! decodes and verifies again only the commits whose inputs may have changed: re-examining
//! every pending commit after every applied one made a first sync O(commits × pending).
//!
//! A record wait (`UnknownCreated`, `MissingChain`) is kept: its examination read the commit
//! (fixed), the held set and the corrected clock (drift). Kept only for commits whose header is
//! inline (no header-list blobs), within byte bounds (its things and records); the others are
//! examined at every `reexamine`, as all were.
//!
//! An examination also reads the commit's `secrets.0` boxes (`keys::read_pending_boxes`). That
//! reads the epochs of the actors they are on and of the holders they box to (`Wait::openers`;
//! no record chain: pending boxes adopt no derived establishment, `Core::ingest_view`), the key
//! actors held (taking one up drops every wait), the reading-only budget and whether the author's
//! record is held (whose budget the boxes take, kept among the wait's records): a change of any
//! drops the wait (`Waits::secrets_changed`, `Waits::wake_refused`). `Engine::check_unchanged` checks it. A chat's
//! joiner holds one such commit per member, waiting for that member's records.
//!
//! - A record wait stands while each record it names (several: parts on things waiting for
//!   different ones) is still held or not as before; records held only accumulate, so every lookup
//!   that found one finds the same. If it waits for its author's certificates (`MissingChain` of
//!   the author), also while `validity::reaches` reads the same: the edges and record links of the
//!   things its backward search reaches (`reach_watch`, `Held::take_moved`). Any of them wakes it.
//!   The other record waits read no edge: the reason that comes first stands until its record
//!   comes. So a joiner's waits on members' records and certificates, one per member, are not all
//!   judged again after each role commit it applies.
//! - A wait on a thing a purge request names is dropped (examined in full: its part is held
//!   value-less, `retention::pending_drops`); every pending commit is examined once the clock is
//!   below the latest one a wait was judged at (drift), and after a clock offset change, a
//!   rollback that changed anything (the cache is dropped) or a reload.
//!
//! `reexamine` takes only what may have changed since it last looked (`candidates`):
//! pending commits without a wait, woken ones and record waits on records added.

use super::Reason;
use crate::engine::Core;
use osis_commit::Header;
use osis_base::{CommitId, Tid};
use std::collections::{BTreeMap, BTreeSet};

/// Bytes one wait may keep (`Wait::bytes`), and all of them: past these a pending commit is
/// examined at every `reexamine`, as all were (peer input never causes unbounded allocation).
const MAX_WAIT_BYTES: usize = 64 * 1024;
const MAX_WAITS_BYTES: usize = 16 << 20;

pub(crate) struct Wait {
    /// The things the commit has deltas on.
    things: BTreeSet<Tid>,
    reason: Reason,
    /// Creation records: each held (`true`) or not when examined (several: parts on things that
    /// wait for different ones).
    records: Vec<(Tid, bool)>,
    /// The waiting commit is memory class (it sees memory records too).
    memory: bool,
    /// When it waits for its author's certificates, the things whose edges may end that
    /// (`reach_watch`).
    reach: BTreeSet<Tid>,
    /// The corrected clock when examined.
    now: u64,
    /// Actors whose held epochs its boxes read (module doc).
    openers: BTreeSet<Tid>,
    /// About what it keeps in memory.
    bytes: usize,
}

impl Wait {
    fn new(h: &Header, reason: Reason, records: Vec<(Tid, bool)>, memory: bool, reach: BTreeSet<Tid>, now: u64, openers: BTreeSet<Tid>) -> Wait {
        let things: BTreeSet<Tid> = h.aspects.iter().map(|a| a.tid).collect();
        let bytes = 160 + 48 * (things.len() + openers.len() + records.len() + reach.len());
        Wait { things, reason, records, memory, reach, now, openers, bytes }
    }
}

#[derive(Default)]
pub(crate) struct Waits {
    by_id: BTreeMap<CommitId, Wait>,
    /// Waits by the things their commits have deltas on.
    by_thing: BTreeMap<Tid, BTreeSet<CommitId>>,
    /// Record waits by the record's thing.
    by_record: BTreeMap<Tid, BTreeSet<CommitId>>,
    /// Record waits by the things of their `reach`.
    by_reach: BTreeMap<Tid, BTreeSet<CommitId>>,
    /// Waits by `Wait::openers`.
    by_opener: BTreeMap<Tid, BTreeSet<CommitId>>,
    /// Waits whose inputs changed since examined (`reach`).
    woken: BTreeSet<CommitId>,
    /// Pending commits set since `reexamine` last looked, and pending commits without a wait.
    cold: BTreeSet<CommitId>,
    /// Pending commits read again by `reexamine` so far (scale checks).
    pub examined: u64,
    /// Commits whose boxes the reading-only budget refused (`box_refused`).
    refused: BTreeSet<CommitId>,
    /// The corrected clock when `reexamine` last looked; `None`: look at every pending commit.
    seen: Option<u64>,
    /// The latest corrected clock a wait was judged at: below it, the clock went back.
    max_now: u64,
    /// The sum of `Wait::bytes`.
    bytes: usize,
}

impl Waits {
    /// About the bytes the waits keep in memory.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn remove(&mut self, id: &CommitId) {
        if let Some(w) = self.by_id.remove(id) {
            self.bytes = self.bytes.saturating_sub(w.bytes);
            for (t, _) in &w.records {
                unindex(&mut self.by_record, t, id);
            }
            for t in &w.reach {
                unindex(&mut self.by_reach, t, id);
            }
            for t in &w.things {
                unindex(&mut self.by_thing, t, id);
            }
            for t in &w.openers {
                unindex(&mut self.by_opener, t, id);
            }
        }
        self.woken.remove(id);
    }

    /// Drops every wait: the next `reexamine` examines every pending commit.
    pub fn clear(&mut self) {
        *self = Waits::default();
    }

    /// A purge request naming a delta on `tid` applied: the waits of commits with deltas on it
    /// are examined in full.
    pub fn wake_thing(&mut self, tid: &Tid) {
        let ids: Vec<CommitId> = self.by_thing.get(tid).into_iter().flatten().copied().collect();
        for id in ids {
            self.remove(&id);
            self.cold.insert(id);
        }
    }

    /// This node's epochs of `a` changed: pending boxes reading them are read again, in full.
    pub fn secrets_changed(&mut self, a: &Tid) {
        let ids: Vec<CommitId> = self.by_opener.get(a).into_iter().flatten().copied().collect();
        for id in ids {
            self.remove(&id);
            self.cold.insert(id);
        }
    }

    /// A pending commit's boxes had no room in the reading-only budget (`read_pending_boxes`).
    pub fn box_refused(&mut self, id: CommitId) {
        self.refused.insert(id);
    }

    /// The budget has room for `room` actors: that many refused commits read their boxes again,
    /// or their grants wait for good on what those secrets would open. Not all of them: past the
    /// room each is only refused again, and a burst of grants would cost its square.
    fn wake_refused(&mut self, room: usize) {
        for _ in 0..room {
            let Some(id) = self.refused.pop_first() else { break };
            self.remove(&id);
            self.cold.insert(id);
        }
    }

    /// Whether `id`'s boxes wait for room in the budget, so their turn comes (`wake_refused`).
    #[cfg(debug_assertions)]
    pub fn is_refused(&self, id: &CommitId) -> bool {
        self.refused.contains(id)
    }

    /// `id` was set pending (or its pending reason changed): examined at the next `reexamine`
    /// unless `note` keeps what it read.
    pub fn pended(&mut self, id: &CommitId) {
        self.remove(id);
        self.cold.insert(*id);
    }

    /// `id` is no longer pending.
    pub fn unpended(&mut self, id: &CommitId) {
        self.remove(id);
        self.cold.remove(id);
    }

    /// Keeps `w` for pending commit `id`, unless past the byte bounds: then `id` is examined
    /// at every `reexamine`.
    fn insert(&mut self, id: CommitId, w: Wait) {
        self.remove(&id);
        if w.bytes > MAX_WAIT_BYTES || self.bytes.saturating_add(w.bytes) > MAX_WAITS_BYTES {
            self.cold.insert(id);
            return;
        }
        self.cold.remove(&id);
        self.bytes += w.bytes;
        self.max_now = self.max_now.max(w.now);
        for (t, _) in &w.records {
            self.by_record.entry(*t).or_default().insert(id);
        }
        for t in &w.reach {
            self.by_reach.entry(*t).or_default().insert(id);
        }
        for t in &w.things {
            self.by_thing.entry(*t).or_default().insert(id);
        }
        for t in &w.openers {
            self.by_opener.entry(*t).or_default().insert(id);
        }
        self.by_id.insert(id, w);
    }
}

fn unindex<K: Ord>(m: &mut BTreeMap<K, BTreeSet<CommitId>>, k: &K, id: &CommitId) {
    if let Some(s) = m.get_mut(k) {
        s.remove(id);
        if s.is_empty() {
            m.remove(k);
        }
    }
}

/// Notes what examining pending commit `id` (`blob`, after `examine`) read, if it can be judged
/// again from that alone: a record wait. `others`: its other reasons, when parts wait alone for
/// different things.
pub(crate) fn note(core: &mut Core, id: CommitId, blob: &osis_commit::CommitBlob, inline: bool, reason: &Reason, others: &[Reason], now: u64) {
    if !inline || blob.parts.iter().any(|p| blob.header.aspects.get(p.ai).is_none()) {
        return;
    }
    let h = &blob.header;
    let memory = h.ephemeral.is_some();
    let mut records = Vec::new();
    for r in std::iter::once(reason).chain(others) {
        let (Reason::UnknownCreated(t) | Reason::MissingChain(t)) = r else { return };
        records.push((*t, core.created_for(t, memory).is_some()));
    }
    let openers = openers(blob, &id);
    // boxes read under their author's reading-only budget once its record is held (`keys::pending_boxes`)
    if !openers.is_empty() && !records.iter().any(|(t, _)| *t == h.author) {
        records.push((h.author, core.created_for(&h.author, memory).is_some()));
    }
    let needs_chain = std::iter::once(reason).chain(others).any(|r| *r == Reason::MissingChain(h.author));
    let reach = if needs_chain { reach_watch(core, blob, &id) } else { BTreeSet::new() };
    let w = Wait::new(h, reason.clone(), records, memory, reach, now, openers);
    core.waits.insert(id, w);
}

/// What decides whether pending commit `id`'s author reaches its things (`apply::thing_wait`,
/// `validity::reaches`): every thing its search backward from them can come to, by first admin or
/// holder. A path can appear only by an edge or a record on one of these.
fn reach_watch(core: &Core, blob: &osis_commit::CommitBlob, id: &CommitId) -> BTreeSet<Tid> {
    let carried = super::carried_records(&blob.header, blob, id);
    let mut stack: Vec<Tid> = blob.header.aspects.iter().map(|a| a.tid).collect();
    let mut seen: BTreeSet<Tid> = stack.iter().copied().collect();
    while let Some(t) = stack.pop() {
        let above = match core.ix.held.created(&t).or_else(|| carried.get(&t)) {
            Some(osis_base::CreationRecord::Thing { admin, .. }) => Some(*admin),
            _ => None,
        };
        for y in above.into_iter().chain(core.ix.held.holders_of(&t).copied()) {
            if seen.insert(y) {
                stack.push(y);
            }
        }
    }
    seen
}

/// `Wait::openers` of pending commit `id`.
fn openers(blob: &osis_commit::CommitBlob, id: &CommitId) -> BTreeSet<Tid> {
    let mut out = BTreeSet::new();
    for (a, w) in super::keys::pending_secrets_writes(blob, id) {
        out.insert(a);
        out.extend(w.boxes.keys().map(|k| k.holder));
    }
    out
}

/// The pending commits that may not wait as when last examined, in `CommitId` order; the rest
/// are left out of `reexamine`. Woken waits stay woken until examined.
pub(crate) fn candidates(core: &mut Core, now: u64) -> Vec<CommitId> {
    let records = core.ix.held.take_records();
    let moved = core.ix.held.take_moved();
    if !core.waits.refused.is_empty() {
        let pending = &core.ix.pending;
        core.waits.refused.retain(|id| pending.contains_key(id));
        let room = core.reading_room();
        core.waits.wake_refused(room);
    }
    let w = &mut core.waits;
    let by_reach: Vec<CommitId> = moved.iter().flat_map(|t| w.by_reach.get(t).into_iter().flatten()).copied().collect();
    w.woken.extend(by_reach);
    let all = now < core.waits.max_now || core.waits.seen.is_none_or(|s| now < s);
    core.waits.seen = Some(now);
    if all {
        return core.ix.pending.keys().filter(|id| !unchanged(core, id, now)).copied().collect();
    }
    let w = &mut core.waits;
    let wake: Vec<CommitId> = records.iter().flat_map(|t| w.by_record.get(t).into_iter().flatten()).copied().collect();
    w.woken.extend(wake);
    let out: BTreeSet<CommitId> = w.cold.iter().chain(&w.woken).copied().collect();
    out.into_iter().filter(|id| core.ix.pending.contains_key(id) && !unchanged(core, id, now)).collect()
}

/// Whether pending commit `id` certainly still waits as when last examined (memory only).
pub(crate) fn unchanged(core: &Core, id: &CommitId, now: u64) -> bool {
    let Some(w) = core.waits.by_id.get(id) else { return false };
    if core.ix.pending.get(id) != Some(&w.reason) || core.waits.woken.contains(id) || now < w.now {
        return false;
    }
    w.records.iter().all(|(t, had)| core.created_for(t, w.memory).is_some() == *had)
}

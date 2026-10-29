//! Engine events (notes/architecture.md §2): typed, sent on subscriber channels after the store
//! transaction is durable. The `osis` API builds watches on them; node-sync consumes local
//! commits from them. Diagnostics are structured, deduped and rate-limited per peer (local
//! ones per kind).

use osis_base::{Ak, CommitId, Tid, Ts, WallMs};
use std::collections::{BTreeMap, VecDeque};
use std::sync::mpsc::{Receiver, Sender, channel};

/// Where an applied commit came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Local,
    Remote,
}

/// Why aspects changed without a commit being applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// Validity changed (un-merge or re-merge, spec/permissions.md §5.2).
    Validity,
    /// A delta reached its expiry (spec/commits.md §6).
    Expiry,
    /// A purge request applied (spec/commits.md §5).
    Purge,
    /// A late delta of an applied commit joined (spec/commits.md §4).
    LateDelta,
    /// This node lost read access and forgot the aspects (spec/permissions.md §3).
    LostAccess,
}

/// An ephemeral batch of this node (notes/ephemeral.md): its session and its number there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EphemeralId {
    pub session: [u8; 32],
    pub n: u64,
}

/// What made a change: a commit, or an ephemeral batch with no durable half.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangeId {
    Commit(CommitId),
    Ephemeral(EphemeralId),
}

impl From<CommitId> for ChangeId {
    fn from(c: CommitId) -> ChangeId {
        ChangeId::Commit(c)
    }
}

impl ChangeId {
    /// The commit, unless the change was ephemeral only.
    pub fn commit(&self) -> Option<CommitId> {
        match self {
            ChangeId::Commit(c) => Some(*c),
            ChangeId::Ephemeral(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A commit applied. `changed`: every `(tid, ak)` whose read may have changed.
    Applied { id: CommitId, origin: Origin, author: Tid, actor: Tid, ts: Ts, received: WallMs, changed: Vec<(Tid, Ak)> },
    /// Late deltas of applied commit `id` joined (reads they changed come as `Changed`).
    Joined { id: CommitId },
    /// Aspects changed outside a commit's application.
    Changed { cause: Cause, changed: Vec<(Tid, Ak)> },
    /// The membership timeline's roster of `thing` may have changed.
    Roster { thing: Tid },
    /// Ephemeral state changed in memory, or signal aspects fired (notes/ephemeral.md). `id` is
    /// the batch's commit when it had a durable half (one change, one `ts`); for a remote change,
    /// the ephemeral commit that carried it.
    Ephemeral { id: ChangeId, origin: Origin, author: Tid, actor: Tid, ts: Ts, received: WallMs, changed: Vec<(Tid, Ak)>, signals: Vec<(Tid, Ak, osis_base::Value)> },
    /// Sync status changed (node-sync fills it).
    SyncStatus { label: osis_base::LabelId, detail: String },
    Diagnostic(Diagnostic),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiagnosticKind {
    /// A received commit or delta was bad input and was dropped.
    BadInput,
    /// A creation record collided with a held one for the same tid (spec/data-model.md §1).
    CollidingRecord,
    /// A commit was parked (spec/versioning.md §2).
    Parked,
    /// A commit is pending (spec/commits.md §4).
    Pending,
    /// Two commits by one node overlap on node-form counters (spec/commits.md §4).
    OverlappingCounters,
    /// This node lost read access to an actor and dropped its secrets (spec/permissions.md §3).
    Removed,
    /// An app callback panicked (the `osis` dispatcher reports it and lives on).
    Callback,
    /// A thing was placed only in groups whose closure no synced group holds (the `osis` API,
    /// spec/requirements.md Offline and network).
    NotSynced,
    /// A persisted thing's ephemeral placement stayed ephemeral: this node may not write the
    /// group (notes/ephemeral.md Ephemeral placements; `tids`: item, group).
    PlacementNotPersisted,
    /// A demotion was stamped without its pre-sync (spec/permissions.md §5.3).
    Unsynced,
    /// This node cannot open a label it should read: it waits for a re-seal
    /// (spec/permissions.md §3).
    Stranded,
    /// A text session could not commit its edits (the `osis` API: lost write access, storage);
    /// they stay in its buffer.
    Uncommitted,
    /// Ephemeral data was not synced or not applied: a server's or this node's ephemeral cap
    /// was reached, or an ephemeral commit could not be built (notes/ephemeral.md Bounds).
    EphemeralRefused,
    /// A typed read found a stored value that does not match the reader's type (another
    /// writer's data, a newer schema revision's enum case); it read as absent (the `osis` API,
    /// spec/versioning.md §5; `tids`: the thing).
    Mismatch,
    /// A local storage condition: a store file or directory readable by others whose mode
    /// could not be tightened (the `osis` file store).
    Storage,
}

/// A structured diagnostic: kind, the things and commit it names, the peer it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub kind: DiagnosticKind,
    pub tids: Vec<Tid>,
    pub commit: Option<CommitId>,
    pub peer: Option<Tid>,
    pub detail: String,
}

/// Diagnostics at most this many per peer, and local ones per kind, per window (local policy).
const PER_PEER: usize = 64;
const WINDOW_MS: u64 = 60_000;
/// Distinct diagnostics remembered for dedup.
const DEDUP: usize = 1024;

/// Subscribers and the queue of events awaiting durability.
#[derive(Default)]
pub struct Events {
    /// Subscribers; `false`: not sent `Event::Ephemeral` (`subscribe_durable`).
    subs: Vec<(Sender<Event>, bool)>,
    queued: Vec<Event>,
    seen: VecDeque<(DiagnosticKind, Option<CommitId>, Vec<Tid>)>,
    /// Window start and count per bucket: a peer, or a kind of local diagnostic (a flood of
    /// one, e.g. `Mismatch` from a screen of mistyped things, hid `Callback` or `Stranded`).
    per_peer: BTreeMap<(Option<Tid>, Option<DiagnosticKind>), (u64, usize)>,
}

impl Events {
    pub fn subscribe(&mut self) -> Receiver<Event> {
        let (tx, rx) = channel();
        self.subs.push((tx, true));
        rx
    }

    /// `subscribe` without `Event::Ephemeral` (node-sync: nothing to sync for them yet).
    pub fn subscribe_durable(&mut self) -> Receiver<Event> {
        let (tx, rx) = channel();
        self.subs.push((tx, false));
        rx
    }

    /// Queues an event; sent by `flush` once the transaction is durable.
    pub fn queue(&mut self, e: Event) {
        self.queued.push(e);
    }

    /// Drops queued events (the transaction aborted).
    pub(crate) fn discard(&mut self) {
        self.queued.clear();
    }

    /// Sends every queued event, in order; drops subscribers that hung up.
    pub fn flush(&mut self) {
        for e in std::mem::take(&mut self.queued) {
            let eph = matches!(e, Event::Ephemeral { .. });
            self.subs.retain(|(s, all)| (eph && !*all) || s.send(e.clone()).is_ok());
        }
    }

    /// A diagnostic, deduped and rate-limited per peer (local ones per kind); sent immediately
    /// (no durability).
    pub fn diagnostic(&mut self, d: Diagnostic, now: WallMs) {
        let key = (d.kind, d.commit, d.tids.clone());
        if self.seen.contains(&key) {
            return;
        }
        let bucket = (d.peer, d.peer.is_none().then_some(d.kind));
        let slot = self.per_peer.entry(bucket).or_insert((now.0, 0));
        if now.0.saturating_sub(slot.0) >= WINDOW_MS {
            *slot = (now.0, 0);
        }
        if slot.1 >= PER_PEER {
            return;
        }
        slot.1 += 1;
        if self.seen.len() >= DEDUP {
            self.seen.pop_front();
        }
        self.seen.push_back(key);
        let e = Event::Diagnostic(d);
        self.subs.retain(|(s, _)| s.send(e.clone()).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diag(kind: DiagnosticKind, n: u8, peer: Option<Tid>) -> Diagnostic {
        Diagnostic { kind, tids: vec![Tid::from_bytes([n; 15])], commit: None, peer, detail: String::new() }
    }

    // a flood of one local kind leaves the others reported; a peer's flood is capped across kinds
    #[test]
    fn local_rate_limit_per_kind() {
        let mut ev = Events::default();
        let rx = ev.subscribe();
        let now = WallMs(1);
        for n in 0..=PER_PEER as u8 {
            ev.diagnostic(diag(DiagnosticKind::Mismatch, n, None), now);
        }
        ev.diagnostic(diag(DiagnosticKind::Callback, 0, None), now);
        let got: Vec<DiagnosticKind> = rx.try_iter().filter_map(|e| if let Event::Diagnostic(d) = e { Some(d.kind) } else { None }).collect();
        assert_eq!(got.iter().filter(|k| **k == DiagnosticKind::Mismatch).count(), PER_PEER);
        assert!(got.contains(&DiagnosticKind::Callback), "not hidden by the Mismatch flood");
        let peer = Some(Tid::from_bytes([255; 15]));
        for n in 0..PER_PEER as u8 {
            ev.diagnostic(diag(DiagnosticKind::BadInput, n, peer), now);
        }
        ev.diagnostic(diag(DiagnosticKind::Pending, 0, peer), now);
        assert!(!rx.try_iter().any(|e| matches!(e, Event::Diagnostic(d) if d.kind == DiagnosticKind::Pending)), "a peer has one bucket");
        ev.diagnostic(diag(DiagnosticKind::Pending, 0, peer), WallMs(1 + WINDOW_MS));
        assert!(rx.try_iter().any(|e| matches!(e, Event::Diagnostic(d) if d.kind == DiagnosticKind::Pending)), "the next window");
    }
}

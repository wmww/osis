//! Engine events (notes/architecture.md §2): typed, sent on subscriber channels after the store
//! transaction is durable. The `osis` API builds watches on them; node-sync consumes local
//! commits from them. Diagnostics are structured, deduped and rate-limited per peer (local
//! ones per kind).

use osis_base::{Ak, CommitId, Tid, Ts, WallMs};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
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
    /// A blob arrived that a read of these aspects had missed (spec/data-model.md §6).
    Fetched,
}

/// A commit whose listed form at one aspect may read otherwise (`Event::Commits`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitChange {
    pub tid: Tid,
    pub ak: Ak,
    pub id: CommitId,
    /// The commit as it arrived, for one nobody holds (an ephemeral signal fired here or
    /// received, spec/sync.md §9): no read finds it, so it is told once, here.
    pub fired: Option<crate::engine::listing::CommitRow>,
}

impl CommitChange {
    /// A held commit: read when told (`Engine::commit_row`).
    pub fn held(tid: Tid, ak: Ak, id: CommitId) -> CommitChange {
        CommitChange { tid, ak, id, fired: None }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A commit applied. `changed`: every `(tid, ak)` whose read may have changed.
    Applied { id: CommitId, origin: Origin, author: Tid, actor: Tid, ts: Ts, received: WallMs, changed: Vec<(Tid, Ak)> },
    /// Late deltas of applied commit `id` joined (reads they changed come as `Changed`).
    Joined { id: CommitId, origin: Origin, author: Tid, actor: Tid, ts: Ts, received: WallMs },
    /// Aspects changed outside a commit's application.
    Changed { cause: Cause, changed: Vec<(Tid, Ak)> },
    /// The role timeline's roster of `thing` may have changed.
    Roster { thing: Tid },
    /// Ephemeral state changed in memory (notes/ephemeral.md). `id` is the ephemeral commit that
    /// carried the change, or the durable commit (a delete, an undone creation) that dropped its
    /// things' ephemeral state.
    Ephemeral { id: CommitId, origin: Origin, author: Tid, actor: Tid, ts: Ts, received: WallMs, changed: Vec<(Tid, Ak)> },
    /// What these commits' parts on these aspects hold or are judged changed: new, turned valid or
    /// invalid, body arrived, dropped, purged (`Engine::commit_row` reads them), and ephemeral
    /// signals fired. One per transaction, or per fire; only once a commit watch was asked for
    /// (`Engine::watch_commits`).
    Commits(Arc<Vec<CommitChange>>),
    /// Sync status changed (node-sync fills it).
    SyncStatus { label: osis_base::LabelId, detail: String },
    /// An admin dispute was detected and a side taken by default (`crate::sides`): `author`'s
    /// edge write `op` of `commit` lowering `holder` on `target`, `trust`: this node sides with it.
    DisputeDetected { commit: CommitId, op: u32, holder: Tid, target: Tid, author: Tid, trust: bool },
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
    /// Two commits of one session overlap on counters (spec/commits.md §4).
    OverlappingCounters,
    /// This node lost read access to an actor and dropped its secrets (spec/permissions.md §3).
    Removed,
    /// An app callback panicked (the `osis` dispatcher reports it and lives on).
    Callback,
    /// A thing was placed only in groups whose closure no synced group holds (the `osis` API,
    /// spec/requirements.md Offline and network).
    NotSynced,
    /// This node cannot open a label it should read: it waits for a re-seal
    /// (spec/permissions.md §3).
    Stranded,
    /// A text session could not commit its edits (the `osis` API: lost write access, storage);
    /// they stay in its buffer.
    Uncommitted,
    /// Ephemeral data was not synced or not applied: a host's or this node's ephemeral cap
    /// was reached, or an ephemeral commit could not be built.
    EphemeralRefused,
    /// A typed read found a stored value that does not match the reader's type (another
    /// writer's data, a newer schema version's enum case); it read as absent (the `osis` API,
    /// spec/versioning.md §5; `tids`: the thing).
    Mismatch,
    /// A local storage condition: a store file or directory readable by others whose mode
    /// could not be tightened (the `osis` file store).
    Storage,
    /// A heartbeat reported an aspect suspect (spec/permissions.md §4): this node re-snapshotted
    /// it, or holds the same state (`tids`: the reporting node, the thing; `commit`: the
    /// snapshot written).
    Repair,
    /// A commit of this node's turned invalid after it was written: a required retention it had
    /// not seen (spec/commits.md §5), a demotion. Its writes no longer read, and nothing re-sends
    /// them (`commit`: it, `tids`: its things).
    OwnWriteInvalid,
    /// A read found a link whose value it cannot read: a blob of its tree not held (not fetched
    /// yet, or named by no blob) or failing verification. That position read as absent
    /// (spec/data-model.md §6; `tids`: the thing).
    Unreadable,
    /// Contestable role writes arrived or stopped applying beyond what one update examines
    /// (`osis_perm::DETECT_MAX`): those that stopped applying keep their side (trusted, listed
    /// as disputes), the newly held ones get the walk's.
    DisputesUnexamined,
    /// This node could not write its addenda to a removal (spec/permissions.md §5.2): nothing of
    /// the attempt was kept, and the removal stays due, tried again with the next transaction
    /// (`commit`: the removal, `detail`: why).
    AddendaFailed,
    /// The `osis` sync driver died (a panic, or its runtime shut down with the store open):
    /// nothing syncs until the store is opened again; waits fail `Network` (`detail`: why).
    SyncStopped,
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

    /// The number of events queued (`truncate`).
    pub(crate) fn queued(&self) -> usize {
        self.queued.len()
    }

    /// Drops the events queued after the first `n` (the transaction or step that queued them
    /// failed).
    pub(crate) fn truncate(&mut self, n: usize) {
        self.queued.truncate(n);
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

    // spec/versioning.md §5 (a mismatched typed read reports a diagnostic): a flood of one local
    // kind leaves the others reported; a peer's flood is capped across kinds
    #[test]
    fn local_rate_limit_per_kind_spec_versioning_5() {
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

//! Engine events (notes/architecture.md §2): typed, sent on subscriber channels after the store
//! transaction is durable. The `osis` API builds watches on them; node-sync consumes local
//! commits from them. Diagnostics are structured, deduped and rate-limited per peer (local
//! ones per kind).

use osis_base::{Ak, CommitId, Mono, Tid, Ts, WallMs};
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
    /// This node forgot its local copy of a released thing (spec/sync-set.md §3).
    Released,
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
    /// received, spec/sync-compaction.md §2): no read finds it, so it is told once, here.
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
    /// A commit applied. `changed`: every `(tid, ak)` whose read may have changed. `purge_author`:
    /// its one purge author (`View::purge_author`).
    Applied { id: CommitId, origin: Origin, signer: Tid, purge_author: Tid, ts: Ts, received: WallMs, changed: Vec<(Tid, Ak)> },
    /// Late deltas of applied commit `id` joined (reads they changed come as `Changed`).
    Joined { id: CommitId, origin: Origin, signer: Tid, purge_author: Tid, ts: Ts, received: WallMs },
    /// Aspects changed outside a commit's application.
    Changed { cause: Cause, changed: Vec<(Tid, Ak)> },
    /// The role timeline's roster of `thing` may have changed.
    Roster { thing: Tid },
    /// A creation record arrived: `thing`'s mint-admin edge, the start of its roster.
    Created { thing: Tid },
    /// A reference index row naming each of these targets on that aspect appeared or went
    /// (`refs`): their backlinks changed. Only once a backlinks watch was asked for
    /// (`Engine::watch_references`).
    References(Arc<Vec<(Tid, Ak)>>),
    /// Ephemeral state changed in memory (notes/ephemeral.md): `id` is the ephemeral commit that
    /// carried the change.
    Ephemeral { id: CommitId, origin: Origin, signer: Tid, purge_author: Tid, ts: Ts, received: WallMs, changed: Vec<(Tid, Ak)> },
    /// What these commits' parts on these aspects hold or are judged changed: new, turned valid or
    /// invalid, body arrived, dropped, purged (`Engine::commit_row` reads them), and ephemeral
    /// signals fired. One per transaction, or per fire; only once a commit watch was asked for
    /// (`Engine::watch_commits`).
    Commits(Arc<Vec<CommitChange>>),
    /// The store was read whole again in place (`Engine::run`, after a write whose outcome was
    /// unknown): a commit answered `Err` may have landed, so any read may answer otherwise.
    Reloaded,
    /// Sync status changed (node-sync fills it).
    SyncStatus { sync_id: osis_base::SyncId, detail: String },
    /// An admin dispute was detected and a side taken by default (`crate::sides`): `author`'s
    /// edge write `op` of `commit` lowering `holder` on `target`, `trust`: this node sides with it.
    DisputeDetected { commit: CommitId, op: u32, holder: osis_base::Holder, target: Tid, author: Tid, trust: bool },
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
    /// A strong in the node closure whose target is neither in the sync unit it is in nor held
    /// otherwise (spec/sync-set.md §2 Not carried): reported at the write adding it, as a warning.
    NotCarried,
    /// This node cannot open a sync ID it should read: it waits for a re-seal
    /// (spec/permissions.md §3).
    Stranded,
    /// A text session could not commit its edits (the `osis` API: lost write access, storage);
    /// they stay in its buffer.
    Uncommitted,
    /// Ephemeral data was not synced or not applied: a peer's or this node's ephemeral cap
    /// was reached, or an ephemeral commit could not be built.
    EphemeralRefused,
    /// A typed read found a stored value that does not match the reader's type (another
    /// writer's data, a newer schema version's enum case); it read as absent (the `osis` API,
    /// spec/versioning.md §5; `tids`: the thing).
    Mismatch,
    /// A local storage condition: a store file or directory readable by others whose mode
    /// could not be tightened (the `osis` file store).
    Storage,
    /// A commit of this node's turned invalid after it was written: a required retention it had
    /// not seen (spec/commits.md §5), a demotion. Its writes no longer read, and nothing re-sends
    /// them (`commit`: it, `tids`: its things).
    OwnWriteInvalid,
    /// A read found a link whose value it cannot read: a blob of its tree not held (not fetched
    /// yet, or named by no blob) or failing verification. That position read as absent
    /// (spec/data-model.md §6; `tids`: the thing).
    Unreadable,
    /// This node could not make a write it makes on its own (its answer to a removal,
    /// spec/permissions.md §5.2; a purge-on-replace cover, spec/commits.md
    /// §5; a compaction snapshot, spec/sync-compaction.md §1): nothing of the attempt was kept; an
    /// answer stays due, tried again with the next transaction, a cover or compaction snapshot
    /// with the next change to its aspect (`commit`: the removal or rotation answered, `tids`: the
    /// thing covered or compacted, `detail`: why).
    OwnWriteFailed,
    /// The `osis` sync driver died (a panic, or its runtime shut down with the store open):
    /// nothing syncs until the store is opened again; waits fail `Network` (`detail`: why).
    SyncStopped,
    /// A dialed peer's clock differs from this node's by more than `OFFSET_DIAGNOSTIC_MS`
    /// (spec/sync-streams.md §1): one of the two is wrong (`detail`: the peer and the offset).
    ClockSkew,
    /// A bound on unverified input from other nodes (peers' unvouched entries, peers' entries)
    /// was reached under a sync ID: what came past it was not kept, and a real entry among it
    /// arrives again from its holders (`detail`: the sync ID and the bound).
    InputCapped,
    /// A connection to another node came up or ended, or a dial failed (osis-sync's driver;
    /// `detail`: the connection, the address dialed, why it ended).
    Connection,
    /// Applying a received commit failed for a fault of this node (a broken invariant of this
    /// build, or damaged storage read back as one), never a judgment of the commit: it is set aside,
    /// pending, and tried again at the next open (spec/commits.md §4; `commit`: it, none for a
    /// trial of several, `tids`: its things, `detail`: the error).
    Fault,
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

/// A diagnostics rate bucket: the peer, or the local kind and the remote it is about.
type Bucket = (Option<Tid>, Option<DiagnosticKind>, Vec<u8>);

/// Subscribers and the queue of events awaiting durability.
#[derive(Default)]
pub struct Events {
    subs: Vec<Sender<Event>>,
    queued: Vec<Event>,
    seen: VecDeque<(DiagnosticKind, Option<CommitId>, Vec<Tid>, String)>,
    /// Window start and count per bucket: a peer, or a kind of local diagnostic and the remote it
    /// is about (a flood of one, e.g. `Mismatch` from a screen of mistyped things, hid `Callback`
    /// or `Stranded`; one remote's connections hid this node's own dial failures). A bucket
    /// whose window passed goes as a new one comes, so the map holds the buckets of one window.
    per_peer: BTreeMap<Bucket, (u64, usize)>,
}

/// A world copy's (notes/test-harnesses.md, Copied worlds): the queue and the diagnostics' dedup and
/// windows as they are, no subscriber (a copy's owner subscribes again).
impl Clone for Events {
    fn clone(&self) -> Events {
        Events { subs: Vec::new(), queued: self.queued.clone(), seen: self.seen.clone(), per_peer: self.per_peer.clone() }
    }
}

impl Events {
    pub fn subscribe(&mut self) -> Receiver<Event> {
        let (tx, rx) = channel();
        self.subs.push(tx);
        rx
    }

    /// Tests only (world copies): `subscribe` whose receiver holds `pending` first, the events a
    /// copied receiver had not read.
    #[doc(hidden)]
    pub fn test_subscribe_with(&mut self, pending: Vec<Event>) -> Receiver<Event> {
        let (tx, rx) = channel();
        for e in pending {
            let _ = tx.send(e);
        }
        self.subs.push(tx);
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
            self.subs.retain(|s| s.send(e.clone()).is_ok());
        }
    }

    /// A diagnostic, deduped (the same report again: kind, commit, things and detail) and
    /// rate-limited per peer (local ones per kind); sent immediately (no durability). `now`: the
    /// monotonic clock (the rate window is a wait, spec/sync-streams.md §1 Waits).
    pub fn diagnostic(&mut self, d: Diagnostic, now: Mono) {
        self.diagnostic_from(d, Vec::new(), now);
    }

    /// `diagnostic`, a local one rate-limited per `remote` it is about (the remote's flood
    /// leaves other remotes' reports of its kind).
    pub fn diagnostic_from(&mut self, d: Diagnostic, remote: Vec<u8>, now: Mono) {
        let key = (d.kind, d.commit, d.tids.clone(), d.detail.clone());
        if self.seen.contains(&key) {
            return;
        }
        let bucket = (d.peer, d.peer.is_none().then_some(d.kind), if d.peer.is_none() { remote } else { Vec::new() });
        if !self.per_peer.contains_key(&bucket) {
            self.per_peer.retain(|_, (start, _)| now.0.saturating_sub(*start) < WINDOW_MS);
        }
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
        self.subs.retain(|s| s.send(e.clone()).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diag(kind: DiagnosticKind, n: u8, peer: Option<Tid>) -> Diagnostic {
        Diagnostic { kind, tids: vec![Tid::from_bytes([n; 15])], commit: None, peer, detail: String::new() }
    }

    // spec/versioning.md §5 (reports the path as a diagnostic): a flood of one local
    // kind leaves the others reported; a peer's flood is capped across kinds
    #[test]
    fn local_rate_limit_per_kind_spec_versioning_5() {
        let mut ev = Events::default();
        let rx = ev.subscribe();
        let now = Mono(1);
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
        ev.diagnostic(diag(DiagnosticKind::Pending, 0, peer), Mono(1 + WINDOW_MS));
        assert!(rx.try_iter().any(|e| matches!(e, Event::Diagnostic(d) if d.kind == DiagnosticKind::Pending)), "the next window");
    }
}

//! Engine events (notes/architecture.md §2): typed, sent on subscriber channels after the store
//! transaction is durable. The `osis` API builds watches on them; node-sync consumes local
//! commits from them. Diagnostics are structured, deduped and rate-limited per peer.

use osis_core::{Ak, CommitId, Tid, Ts, WallMs};
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A commit applied. `changed`: every `(tid, ak)` whose read may have changed.
    Applied { id: CommitId, origin: Origin, author: Tid, actor: Tid, ts: Ts, received: WallMs, changed: Vec<(Tid, Ak)> },
    /// Aspects changed outside a commit's application.
    Changed { cause: Cause, changed: Vec<(Tid, Ak)> },
    /// The membership timeline's roster of `thing` may have changed.
    Roster { thing: Tid },
    /// A signal received (node-sync fills it).
    Signal { kind: Ak, from: Tid, value: osis_core::Value },
    /// Sync status changed (node-sync fills it).
    SyncStatus { label: osis_core::LabelId, detail: String },
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

/// Diagnostics at most this many per peer per window (local policy).
const PER_PEER: usize = 64;
const WINDOW_MS: u64 = 60_000;
/// Distinct diagnostics remembered for dedup.
const DEDUP: usize = 1024;

/// Subscribers and the queue of events awaiting durability.
#[derive(Default)]
pub struct Events {
    subs: Vec<Sender<Event>>,
    queued: Vec<Event>,
    seen: VecDeque<(DiagnosticKind, Option<CommitId>, Vec<Tid>)>,
    per_peer: BTreeMap<Option<Tid>, (u64, usize)>,
}

impl Events {
    pub fn subscribe(&mut self) -> Receiver<Event> {
        let (tx, rx) = channel();
        self.subs.push(tx);
        rx
    }

    /// Queues an event; sent by `flush` once the transaction is durable.
    pub(crate) fn queue(&mut self, e: Event) {
        self.queued.push(e);
    }

    /// Drops queued events (the transaction aborted).
    pub(crate) fn discard(&mut self) {
        self.queued.clear();
    }

    /// Sends every queued event, in order; drops subscribers that hung up.
    pub(crate) fn flush(&mut self) {
        for e in std::mem::take(&mut self.queued) {
            self.subs.retain(|s| s.send(e.clone()).is_ok());
        }
    }

    /// A diagnostic, deduped and rate-limited per peer; sent immediately (no durability).
    pub(crate) fn diagnostic(&mut self, d: Diagnostic, now: WallMs) {
        let key = (d.kind, d.commit, d.tids.clone());
        if self.seen.contains(&key) {
            return;
        }
        let slot = self.per_peer.entry(d.peer).or_insert((now.0, 0));
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

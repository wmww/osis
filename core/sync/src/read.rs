//! Judgement for read sync IDs (spec/sync-judgement.md §1-§5, spec/sync-compaction.md §1).
//!
//! State: the `osis_base::memo::Effects` over `sync_bodies` per commit and the verdict per
//! (S, commit); the stand of "logged again once", the deletes seen and the deletes owed per
//! source, in that source's record. Acts on a verdict's change: logs its own must-hold bodies
//! (`Engine::seal`), drops own entries must-not-hold or covered and dropped, and at each store
//! source stamps for its head, relays or deposits, deletes, and logs again once; destruction's
//! telling and emptying. Depends on engine, store, opens (members, records), streams (`known`).
//! Not built: every call below.

use crate::opens::Opens;
use crate::session::{Incoming, Sessions};
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Result};
use osis_base::{CommitId, SyncId, WallMs};

/// A body's verdict at S (spec/sync-judgement.md §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Must,
    May,
    MustNot(Why),
    Unjudged,
}

/// Why a body is must-not-hold (spec/sync-judgement.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    Purged,
    Expired,
    OutsideRequired,
    StrictSubset,
    CardSuperseded,
    CardEnded,
    Emptied,
}

#[derive(Clone, Debug, Default)]
pub struct Read {}

impl Read {
    /// Whether anything acted.
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams) -> Result<bool> {
        let _ = (cx, sessions, opens, streams);
        Ok(false)
    }

    /// Answers to its own requests (Delete, deposits, stamps).
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, conn: ConnId, m: Incoming) {
        let _ = (cx, sessions, conn, m);
    }

    /// For status and inbox.
    pub fn verdict(&self, s: &SyncId, c: &CommitId) -> Option<Verdict> {
        let _ = (s, c);
        None
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        None
    }
}

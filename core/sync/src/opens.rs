//! Records, agreement and the shared set (spec/sync-opens.md §2-§6, spec/sync-ids.md §6 Walk).
//!
//! State: records (durable, in the store's record rows, `RECORD_BUDGET` LRU); per connection the
//! members, filter generations sent and received, Offer in flight, walk state; `changed_at` per S
//! (durable, its row keeping the digest of the value it was advanced for). Settle: per S,
//! `admissible(s)` is an effect over the engine's `read_credentials(s)` or unread's
//! `credentials(s)`; a moved value advances `changed_at(s)`, re-judges S's members on every
//! connection, and makes filter additions and tests due. Depends on session, store, unread,
//! engine (J, credentials, known actors). Not built: every call below.

use crate::session::{Incoming, Session};
use crate::types::{ConnId, Credential, Cx, Position, RecordId, Result, SourceClass};
use crate::unread::Unread;
use osis_base::{SyncId, WallMs};
use osis_label::StepId;
use std::collections::BTreeMap;

/// A member of a connection's shared set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub class: SourceClass,
    pub by: Credential,
    /// Being ended: served up to this position.
    pub until: Option<Position>,
    /// The source's step for S.
    pub step: Option<StepId>,
}

#[derive(Clone, Debug, Default)]
pub struct Opens {
    members: BTreeMap<ConnId, BTreeMap<SyncId, Member>>,
}

static NO_MEMBERS: BTreeMap<SyncId, Member> = BTreeMap::new();

impl Opens {
    /// The peer proved itself: Resume or NoRecord, then Digest.
    pub fn on_proved(&mut self, cx: &mut Cx, conn: ConnId, s: &mut Session) {
        let _ = (cx, conn, s);
    }

    /// Resume, Digest, Members, Beacons, Offer, Shared, Lost.
    pub fn on_message(&mut self, cx: &mut Cx, conn: ConnId, s: &mut Session, m: Incoming) {
        let _ = (cx, conn, s, m);
    }

    /// A connection ended.
    pub fn on_closed(&mut self, cx: &mut Cx, conn: ConnId) {
        let _ = cx;
        self.members.remove(&conn);
    }

    pub fn members(&self, conn: ConnId) -> &BTreeMap<SyncId, Member> {
        self.members.get(&conn).unwrap_or(&NO_MEMBERS)
    }

    /// The peer's record: where streams, read and store keep their per-peer rows.
    pub fn record(&mut self, conn: ConnId) -> Option<RecordId> {
        let _ = conn;
        None
    }

    /// Whether anything acted.
    pub fn settle(&mut self, cx: &mut Cx, unread: &Unread) -> Result<bool> {
        let _ = (cx, unread);
        Ok(false)
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        None
    }
}

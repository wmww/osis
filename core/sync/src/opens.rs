//! Records, agreement and the shared set (spec/sync-opens.md §2-§6, spec/sync-ids.md §6 Walk).
//!
//! State: records (durable, in the store's record rows, `RECORD_BUDGET` LRU); per connection the
//! members, filter generations sent and received, Offer in flight, walk state; `changed_at` per S
//! (durable, its row keeping the digest of the value it was advanced for). Settle: per S,
//! `admissible(s)` is an effect over the engine's `read_credentials(s)` or unread's
//! `credentials(s)`; a moved value advances `changed_at(s)`, re-judges S's members on every
//! connection, and makes filter additions and tests due. Every member that joins or leaves a
//! connection's shared set is reported as a `Moved`, which the driver hands to streams. Depends
//! on session, store, unread, engine (J, credentials, known actors). Not built: every call below.

use crate::session::{Incoming, Sessions};
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

/// A change of a connection's shared set: the driver hands each to `Streams::moved`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Moved {
    /// S became a member on `conn` (newly open, or open again).
    Joined(ConnId, SyncId),
    /// S stopped being a member on `conn` (ended to its `until`, closed, or the connection ended).
    Left(ConnId, SyncId),
}

#[derive(Clone, Debug, Default)]
pub struct Opens {
    members: BTreeMap<ConnId, BTreeMap<SyncId, Member>>,
}

static NO_MEMBERS: BTreeMap<SyncId, Member> = BTreeMap::new();

impl Opens {
    /// `Proved` (Resume or NoRecord, then Digest); Resume, Digest, Members, Beacons, Offer,
    /// Shared, Lost.
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, conn: ConnId, m: Incoming, moved: &mut Vec<Moved>) {
        let _ = (cx, sessions, conn, m, moved);
    }

    /// A connection ended: each of its members left.
    pub fn on_closed(&mut self, cx: &mut Cx, conn: ConnId, moved: &mut Vec<Moved>) {
        let _ = cx;
        if let Some(members) = self.members.remove(&conn) {
            moved.extend(members.into_keys().map(|s| Moved::Left(conn, s)));
        }
    }

    pub fn members(&self, conn: ConnId) -> &BTreeMap<SyncId, Member> {
        self.members.get(&conn).unwrap_or(&NO_MEMBERS)
    }

    /// The peer's record: where streams, read and store keep their per-peer rows.
    pub fn record(&self, conn: ConnId) -> Option<RecordId> {
        let _ = conn;
        None
    }

    /// Whether anything acted (a member that moved is in `moved`).
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, unread: &Unread, moved: &mut Vec<Moved>) -> Result<bool> {
        let _ = (cx, sessions, unread, moved);
        Ok(false)
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        None
    }
}

//! Reported positions (spec/sync-opens.md §6 Lost) and where a member rejoins: the shapes opens
//! and streams share. Streams, serving, says what the peer stored of this node's log (`Reported`);
//! opens folds it into `Positions` per connection and names a member's rejoin (`Rejoin`) in
//! `Moved::Joined`.

use crate::types::{ConnId, Cursor, Position};
use osis_base::SyncId;
use std::collections::BTreeMap;

/// Where a member that joins a connection's stream reads the peer's log from (opens decides: it
/// saw the peer's Lost and the digest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejoin {
    /// From where this side's stream held it when it left (or the record holds it).
    Held,
    /// From a Lost's cursor (`Some`), or from the start (a digest difference: no position).
    From(Option<Cursor>),
}

/// A reported position: what the peer stored of this node's log, as streams serving it learns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reported {
    /// The peer's stream stands at this position: every member at the stream stands there.
    Stream(ConnId, Position, Cursor),
    /// A member joining stands at its own position (none: from the start, or not named yet).
    Member(ConnId, SyncId, Option<(Position, Cursor)>),
    /// The member's join merged into the stream and the peer stored it: it follows `Stream`.
    Merged(ConnId, SyncId),
}

impl Reported {
    pub fn conn(&self) -> ConnId {
        match self {
            Reported::Stream(c, ..) | Reported::Member(c, ..) | Reported::Merged(c, _) => *c,
        }
    }
}

/// One connection's reported positions, compact so a report costs O(1) whatever the members: the
/// stream's, and each member's own while it joins. A member's position is its own if it has one,
/// else the stream's; a sync ID that is no member has none.
#[derive(Clone, Debug, Default)]
pub struct Positions {
    stream: Option<(Position, Cursor)>,
    own: BTreeMap<SyncId, Option<(Position, Cursor)>>,
}

impl Positions {
    /// Takes a report; the sync ID whose position it moved (none: the stream's).
    pub fn take(&mut self, r: Reported) -> Option<SyncId> {
        match r {
            Reported::Stream(_, p, c) => {
                if self.stream.as_ref().is_none_or(|(q, _)| *q < p) {
                    self.stream = Some((p, c));
                }
                None
            }
            Reported::Member(_, s, at) => {
                self.own.insert(s, at);
                Some(s)
            }
            Reported::Merged(_, s) => {
                self.own.remove(&s);
                Some(s)
            }
        }
    }

    /// The member S left: a later join reports afresh.
    pub fn forget(&mut self, s: &SyncId) {
        self.own.remove(s);
    }

    /// Member S's reported position.
    pub fn get(&self, s: &SyncId) -> Option<&(Position, Cursor)> {
        match self.own.get(s) {
            Some(at) => at.as_ref(),
            None => self.stream.as_ref(),
        }
    }
}

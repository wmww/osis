//! Streams and flow control (spec/sync-streams.md §3-§6).
//!
//! State: per connection and member the cursor, joins, `seq`, owed bodies, fetches in flight,
//! reports; `known` per source and S (durable in the record for a peer with one). Depends on
//! session, store, opens (members), engine (`open_entry`, `wants`). Not built: every call below.

use crate::opens::{Moved, Opens};
use crate::session::{Incoming, Sessions};
use crate::types::{ConnId, Cx, Error, Result};
use osis_base::{BlobId, SyncId, WallMs};
use std::collections::BTreeSet;

/// What a source's stream showed of S (spec/sync-judgement.md §3 `known`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Known {
    pub present: BTreeSet<BlobId>,
}

static NOTHING_KNOWN: Known = Known { present: BTreeSet::new() };

#[derive(Clone, Debug, Default)]
pub struct Streams {}

impl Streams {
    /// A member joined (its join is due) or left (its stream stops where it stands) a
    /// connection's shared set; the connection may be gone already.
    pub fn moved(&mut self, cx: &mut Cx, sessions: &mut Sessions, m: Moved) {
        let _ = (cx, sessions, m);
    }

    /// Pull, PullReply, Stream, Applied, Fetch.
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, conn: ConnId, m: Incoming) {
        let _ = (cx, sessions, opens, conn, m);
    }

    /// What that source's stream showed.
    pub fn known(&self, conn: ConnId, s: &SyncId) -> &Known {
        let _ = (conn, s);
        &NOTHING_KNOWN
    }

    pub fn caught_up(&self, conn: ConnId, s: &SyncId) -> bool {
        let _ = (conn, s);
        false
    }

    /// A source with no cursor: a bundle (spec/sync-streams.md §6).
    pub fn import(&mut self, cx: &mut Cx, bundle: &mut dyn std::io::Read) -> Result<()> {
        let _ = (cx, bundle);
        Err(Error::NotBuilt("streams::import"))
    }

    /// Whether anything acted.
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens) -> Result<bool> {
        let _ = (cx, sessions, opens);
        Ok(false)
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        None
    }
}

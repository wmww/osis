//! Inbox, deposits, steps and Register (spec/sync-inbox.md, spec/sync-ids.md §6 Steps).
//!
//! State: per delivery its re-sends; Deposit items in flight and back-offs; Register attempts per
//! (source, S); stranded notices sent. Depends on engine (deliveries, inbox blobs, taking,
//! promotion, keys), store, opens, streams. Not built: every call below.

use crate::opens::Opens;
use crate::session::{Incoming, Sessions};
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Result, Waiting};
use osis_base::{BlobId, SyncId, WallMs};
use osis_label::ShareLink;
use osis_proto::Code;

/// A peer's answer to one Deposit or Register item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemAnswer {
    pub s: SyncId,
    pub blob: Option<BlobId>,
    pub code: Code,
}

#[derive(Clone, Debug, Default)]
pub struct Inbox {}

impl Inbox {
    /// Whether anything acted.
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams) -> Result<bool> {
        let _ = (cx, sessions, opens, streams);
        Ok(false)
    }

    /// Deposit and Register answers (`ItemAnswer` each).
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, conn: ConnId, m: Incoming) {
        let _ = (cx, sessions, conn, m);
    }

    /// First contact through a link.
    pub fn redeem(&mut self, cx: &mut Cx, link: &ShareLink) -> Waiting {
        let _ = (cx, link);
        Waiting::Never("inbox::redeem not built")
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        None
    }
}

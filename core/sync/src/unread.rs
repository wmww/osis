//! Judgement for kept-unread sync IDs (spec/sync-judgement.md §6).
//!
//! State: per S stranded or not; nothing durable of its own (the sync record is the engine's,
//! the head the store's). Settle: stop on a verified removal, strand on a head move, leave when
//! unlisted. Depends on engine (`sync_records`, `sync_set`, `removal_notices`,
//! `drop_sync_record`) and store; nothing else. Reads nothing of what S carries. Not built: every
//! call below.

use crate::types::{Cx, Result};
use osis_base::{SyncId, WallMs};
use osis_crypto::{Secret32, SigningSecret};
use osis_label::ClaimSet;
use std::sync::Arc;

/// What a node keeping S unread opens and acts with, from its sync record and its store's head.
#[derive(Clone)]
pub struct UnreadCredentials {
    /// The head's sync key.
    pub sync: SigningSecret,
    /// Its sync proof (spec/sync-ids.md §2).
    pub proof: Secret32,
    pub deposit: Option<SigningSecret>,
    /// The head's claim set.
    pub claims: Option<ClaimSet>,
}

#[derive(Clone, Debug, Default)]
pub struct Unread {}

impl Unread {
    pub fn credentials(&self, cx: &mut Cx, s: &SyncId) -> Option<Arc<UnreadCredentials>> {
        let _ = (cx, s);
        None
    }

    pub fn stranded(&self, s: &SyncId) -> bool {
        let _ = s;
        false
    }

    /// Whether anything acted.
    pub fn settle(&mut self, cx: &mut Cx) -> Result<bool> {
        let _ = cx;
        Ok(false)
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        None
    }
}

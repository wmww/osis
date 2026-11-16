//! `changed_at` (spec/sync-opens.md §3): per sync ID a position of its own sequence
//! that moves when the sync ID's fingerprint (its credentials and who reaches it) changes.
//! Only the per-peer records' `acked_pos` (record.rs, the same store) compares
//! with it; it shares no positions with the node log, which may live in another store.
//!
//! Rows, catalog rows under `kind::CHANGED`: `n` the sequence's end; `c sync_id` a sync ID's
//! `changed_at` and the fingerprint it was computed from. A fingerprint is a keyed hash: it shows nothing to whoever lacks the node's
//! credentials, so overwrites shred nothing.

use crate::codec::{R, W};
use crate::store::{Shred, Transaction, kind};
use crate::Error;
use osis_base::SyncId;

const END: &[u8] = &[kind::CHANGED, b'n'];
const SLOT: &[u8] = &[kind::CHANGED, b'c'];

fn slot_pos(v: &[u8]) -> Result<u64, Error> {
    R::new(v.get(..8).ok_or(Error::Corrupt("changed_at slot"))?).u64()
}

impl Transaction<'_> {
    /// A sync ID's current fingerprint: `changed_at` advances if it is new or differs. The new
    /// position, or `None` when nothing changed. One row per sync ID.
    pub fn changed_note(&mut self, l: SyncId, fingerprint: &[u8; 32]) -> Result<Option<u64>, Error> {
        let slot = [SLOT, &l.0].concat();
        let old = self.cat_get(&slot)?;
        if old.as_ref().is_some_and(|v| v.get(8..) == Some(fingerprint.as_slice())) {
            return Ok(None);
        }
        let pos = self.changed_end()? + 1;
        self.cat_put_to(END, W::new().u64(pos).take(), Shred::No, false)?;
        self.cat_put_to(&slot, W::new().u64(pos).raw(fingerprint).take(), Shred::No, false)?;
        Ok(Some(pos))
    }

    /// The sequence's end: the position `changed_note` last gave, 0 before any.
    pub fn changed_end(&mut self) -> Result<u64, Error> {
        self.cat_get(END)?.map_or(Ok(0), |v| R::new(&v).u64())
    }

    /// `changed_at` of `l`, `None` for a sync ID not held.
    pub fn changed_at(&mut self, l: &SyncId) -> Result<Option<u64>, Error> {
        let Some(v) = self.cat_get(&[SLOT, &l.0].concat())? else { return Ok(None) };
        Ok(Some(slot_pos(&v)?))
    }

    /// `l` left this node's sync IDs: its `changed_at` goes, and it leaves every record's S.
    pub fn changed_forget(&mut self, l: &SyncId) -> Result<(), Error> {
        let slot = [SLOT, &l.0].concat();
        self.cat_remove(&slot, Shred::No)?;
        self.records_forget_sync_id(l)
    }
}

//! `changed_at` (issues/net-reconnect.md, Changes): per sync ID a position of its own sequence
//! that moves when the sync ID's fingerprint (its credentials and who reaches it) changes.
//! Only the per-peer records' `acked_pos` and `judged_pos` (record.rs, the same store) compare
//! with it; it shares no positions with the node log, which may live in another store.
//!
//! Rows, catalog rows under `kind::CHANGED`: `n` the sequence's end; `c label` a sync ID's
//! `changed_at` and the fingerprint it was computed from; `C pos label` the sync IDs by
//! `changed_at`. A fingerprint is a keyed hash: it shows nothing to whoever lacks the node's
//! credentials, so overwrites shred nothing.

use crate::codec::{R, W};
use crate::store::{Shred, Transaction, kind};
use crate::Error;
use osis_base::LabelId;

/// Rows a page of `changed_labels` reads.
const PAGE: usize = 256;

const END: &[u8] = &[kind::CHANGED, b'n'];
const SLOT: &[u8] = &[kind::CHANGED, b'c'];
const ORDER: &[u8] = &[kind::CHANGED, b'C'];

fn order_key(pos: u64, l: &LabelId) -> Vec<u8> {
    [ORDER, &pos.to_be_bytes(), &l.0].concat()
}

fn slot_pos(v: &[u8]) -> Result<u64, Error> {
    R::new(v.get(..8).ok_or(Error::Corrupt("changed_at slot"))?).u64()
}

impl Transaction<'_> {
    /// A sync ID's current fingerprint: `changed_at` advances if it is new or differs. The new
    /// position, or `None` when nothing changed. One row per sync ID.
    pub fn changed_note(&mut self, l: LabelId, fingerprint: &[u8; 32]) -> Result<Option<u64>, Error> {
        let slot = [SLOT, &l.0].concat();
        let old = self.cat_get(&slot)?;
        if old.as_ref().is_some_and(|v| v.get(8..) == Some(fingerprint.as_slice())) {
            return Ok(None);
        }
        if let Some(v) = &old {
            self.cat_remove(&order_key(slot_pos(v)?, &l), Shred::No)?;
        }
        let pos = self.changed_end()? + 1;
        self.cat_put_to(END, W::new().u64(pos).take(), Shred::No, false)?;
        self.cat_put_to(&slot, W::new().u64(pos).raw(fingerprint).take(), Shred::No, false)?;
        self.cat_put_to(&order_key(pos, &l), Vec::new(), Shred::No, false)?;
        Ok(Some(pos))
    }

    /// The sequence's end: the position `changed_note` last gave, 0 before any.
    pub fn changed_end(&mut self) -> Result<u64, Error> {
        self.cat_get(END)?.map_or(Ok(0), |v| R::new(&v).u64())
    }

    /// `changed_at` of `l`, `None` for a sync ID not held.
    pub fn changed_at(&mut self, l: &LabelId) -> Result<Option<u64>, Error> {
        let Some(v) = self.cat_get(&[SLOT, &l.0].concat())? else { return Ok(None) };
        Ok(Some(slot_pos(&v)?))
    }

    /// Up to `limit` sync IDs with `changed_at` above `after`, in order. Costs what it returns.
    pub fn changed_after(&mut self, after: u64, limit: usize) -> Result<Vec<(u64, LabelId)>, Error> {
        let rows = self.cat_scan(ORDER, &after.saturating_add(1).to_be_bytes(), limit)?;
        let mut out = Vec::with_capacity(rows.len());
        for (k, _) in rows {
            let mut r = R::new(k.get(2..).ok_or(Error::Corrupt("changed_at index"))?);
            out.push((r.u64()?, LabelId(r.array()?)));
        }
        Ok(out)
    }

    /// Every sync ID with a `changed_at`.
    pub fn changed_labels(&mut self) -> Result<Vec<LabelId>, Error> {
        let mut out = Vec::new();
        let mut from = Vec::new();
        loop {
            let rows = self.cat_scan(SLOT, &from, PAGE)?;
            let n = rows.len();
            for (k, _) in rows {
                let l: [u8; 16] = k.get(2..18).and_then(|x| x.try_into().ok()).ok_or(Error::Corrupt("changed_at slot"))?;
                from = [l.as_slice(), &[0]].concat();
                out.push(LabelId(l));
            }
            if n < PAGE {
                return Ok(out);
            }
        }
    }

    /// `l` left this node's sync IDs: its `changed_at` goes, and it leaves every record's S.
    pub fn changed_forget(&mut self, l: &LabelId) -> Result<(), Error> {
        let slot = [SLOT, &l.0].concat();
        if let Some(v) = self.cat_get(&slot)? {
            self.cat_remove(&order_key(slot_pos(&v)?, l), Shred::No)?;
            self.cat_remove(&slot, Shred::No)?;
        }
        self.records_forget_label(l)
    }
}

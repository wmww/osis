//! The node log (issues/net-reconnect.md, One node log): one durable sequence of events over
//! every sync ID a store holds, written in the transaction that makes each event true.
//!
//! The rule: a cursor names a position of this store's own history, and what it covers is
//! everything at or below that position. So:
//! - Every event gets the next position; a position is never reused by this history.
//! - Retention is compaction, never trimming by position: a slot holds a subject's one latest
//!   event (an entry's add or stamp, its deletion, a sync ID's head), so an earlier event of
//!   the subject goes when a later one is logged; a deletion event goes `TOMBSTONE_LIFETIME`
//!   after it was logged. A listing from the start is then the live set plus recent deletions.
//! - An incarnation is a run of positions of one store history. The first log append after a
//!   store start draws a new one and records the end of the one before; a start that appends
//!   nothing costs nothing. A store restored from a backup, or a copy running beside the
//!   original, is told apart by exactly this: its next append ends the old incarnation at the
//!   position it holds, so a cursor past that from the lost store, or naming a sibling's
//!   incarnation, is on no history this store has (`Valid` of core/test/tla/net/NetStream.tla).
//!
//! Rows, all catalog rows under `kind::LOG`:
//! `m` meta (cursor key, log ID, current incarnation, end position); `n` the ended incarnations;
//! `s` a memory-only marker that this store start has drawn; `e pos` an event; `i label blob` an
//! entry's slot; `h label` a head's slot; `d at pos` the deletion events by when they were
//! logged, for the sweep.

use crate::codec::{R, W};
use crate::store::{Shred, Transaction, kind};
use crate::Error;
use osis_base::format::TOMBSTONE_LIFETIME_MS;
use osis_base::{BlobId, LabelId};
use osis_crypto::aead::{self, NONCE_LEN, TAG_LEN};

/// Ended incarnations kept, oldest evicted (issues/net-reconnect.md, Picked values). Resource
/// bound: 0 makes every cursor from before an appending start no cursor (correct, one listing
/// per peer), infinity is disk growing with appending starts. 24 bytes each, one per start that
/// appends: at 50 such starts a day the cap is 82 days and 98 KB.
pub const INCARNATIONS_KEPT: usize = 4096;

const PLAIN_LEN: usize = 16 + 16 + 8;
/// The bytes of a cursor: opaque to whoever holds one.
pub const CURSOR_LEN: usize = NONCE_LEN + PLAIN_LEN + TAG_LEN;

/// Rows of the sweep's and forget's scans handled in one page.
const PAGE: usize = 256;

const META: &[u8] = &[kind::LOG, b'm'];
const ENDED: &[u8] = &[kind::LOG, b'n'];
const STARTED: &[u8] = &[kind::LOG, b's'];
const EVENT: &[u8] = &[kind::LOG, b'e'];
const ENTRY_SLOT: &[u8] = &[kind::LOG, b'i'];
const HEAD_SLOT: &[u8] = &[kind::LOG, b'h'];
const DELETED: &[u8] = &[kind::LOG, b'd'];

/// What a node log event says of its sync ID. The entry's wrap and stamp, or the head's step,
/// are read from what the node holds when the event is served.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeEvent {
    /// An entry became servable here (its row and its bytes both held), or the wrap or stamp of
    /// one that is changed. An entry whose bytes have not arrived has no event: nothing serves it.
    Added(LabelId, BlobId),
    /// An entry left the node. `at` (corrected wall ms) only ages the event.
    Deleted { label: LabelId, blob: BlobId, at: u64 },
    /// The sync ID's head moved.
    Head(LabelId),
}

/// An event and its position, which stays in this store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoggedEvent {
    pub pos: u64,
    pub event: NodeEvent,
}

/// A page of the log (`Transaction::log_read`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogRead {
    pub events: Vec<LoggedEvent>,
    /// Where the next read goes on from. `None` only for a log with nothing ever appended.
    pub cursor: Option<Vec<u8>>,
    /// The cursor given was no cursor: these are events from the start.
    pub whole: bool,
    pub more: bool,
}

struct Meta {
    key: [u8; 32],
    log_id: [u8; 16],
    incarnation: [u8; 16],
    end: u64,
}

impl Meta {
    fn encode(&self) -> Vec<u8> {
        W::new().raw(&self.key).raw(&self.log_id).raw(&self.incarnation).u64(self.end).take()
    }

    fn decode(b: &[u8]) -> Result<Meta, Error> {
        let mut r = R::new(b);
        let m = Meta { key: r.array()?, log_id: r.array()?, incarnation: r.array()?, end: r.u64()? };
        r.end()?;
        Ok(m)
    }
}

fn pos_key(prefix: &[u8], pos: u64) -> Vec<u8> {
    [prefix, &pos.to_be_bytes()].concat()
}

fn entry_slot(l: &LabelId, b: &BlobId) -> Vec<u8> {
    [ENTRY_SLOT, &l.0, &b.0].concat()
}

fn head_slot(l: &LabelId) -> Vec<u8> {
    [HEAD_SLOT, &l.0].concat()
}

fn deleted_key(at: u64, pos: u64) -> Vec<u8> {
    [DELETED, &at.to_be_bytes(), &pos.to_be_bytes()].concat()
}

fn pos_value(v: &[u8]) -> Result<u64, Error> {
    let mut r = R::new(v);
    let p = r.u64()?;
    r.end()?;
    Ok(p)
}

fn encode_event(e: &NodeEvent) -> Vec<u8> {
    match e {
        NodeEvent::Added(l, b) => W::new().u8(0).raw(&l.0).raw(&b.0).take(),
        NodeEvent::Deleted { label, blob, at } => W::new().u8(1).raw(&label.0).raw(&blob.0).u64(*at).take(),
        NodeEvent::Head(l) => W::new().u8(2).raw(&l.0).take(),
    }
}

fn decode_event(v: &[u8]) -> Result<NodeEvent, Error> {
    let mut r = R::new(v);
    let e = match r.u8()? {
        0 => NodeEvent::Added(LabelId(r.array()?), BlobId(r.array()?)),
        1 => NodeEvent::Deleted { label: LabelId(r.array()?), blob: BlobId(r.array()?), at: r.u64()? },
        2 => NodeEvent::Head(LabelId(r.array()?)),
        _ => return Err(Error::Corrupt("node log event")),
    };
    r.end()?;
    Ok(e)
}

fn decode_ended(v: &[u8]) -> Result<Vec<([u8; 16], u64)>, Error> {
    let mut r = R::new(v);
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push((r.array()?, r.u64()?));
    }
    Ok(out)
}

impl Transaction<'_> {
    fn log_meta(&mut self) -> Result<Option<Meta>, Error> {
        self.cat_get(META)?.map(|b| Meta::decode(&b)).transpose()
    }

    fn log_put_meta(&mut self, m: &Meta) -> Result<(), Error> {
        self.cat_put_to(META, m.encode(), Shred::No, false)
    }

    /// The meta row, this start's incarnation drawn: the first durable advance of a start.
    fn log_started(&mut self) -> Result<Meta, Error> {
        let drawn = self.cat_get(STARTED)?.is_some();
        let m = match self.log_meta()? {
            Some(mut m) => {
                if !drawn {
                    let mut ended = match self.cat_get(ENDED)? {
                        Some(v) => decode_ended(&v)?,
                        None => Vec::new(),
                    };
                    ended.push((m.incarnation, m.end));
                    let extra = ended.len().saturating_sub(INCARNATIONS_KEPT);
                    ended.drain(..extra);
                    let mut w = W::new();
                    for (id, end) in &ended {
                        w.raw(id).u64(*end);
                    }
                    self.cat_put_to(ENDED, w.take(), Shred::No, false)?;
                    self.rng().fill_bytes(&mut m.incarnation);
                }
                m
            }
            None => {
                let mut m = Meta { key: [0; 32], log_id: [0; 16], incarnation: [0; 16], end: 0 };
                self.rng().fill_bytes(&mut m.key);
                self.rng().fill_bytes(&mut m.log_id);
                self.rng().fill_bytes(&mut m.incarnation);
                m
            }
        };
        if !drawn {
            // a memory row: gone with this store start, by a reopen or a crash alike
            self.cat_put_to(STARTED, Vec::new(), Shred::No, true)?;
        }
        Ok(m)
    }

    /// The next position, with no event at it: a position for a value that must sort among
    /// this log's positions (a sync ID's `changed_at`, issues/net-reconnect.md Changes). It
    /// counts as an append for the incarnation rule.
    pub fn log_advance(&mut self) -> Result<u64, Error> {
        let mut m = self.log_started()?;
        m.end += 1;
        self.log_put_meta(&m)?;
        Ok(m.end)
    }

    /// The log's end: the position `log_advance` or an append last gave, 0 before any.
    pub fn log_end(&mut self) -> Result<u64, Error> {
        Ok(self.log_meta()?.map_or(0, |m| m.end))
    }

    /// Removes the event at `pos` with what ages it. The caller handles the slot.
    fn log_drop_event(&mut self, pos: u64) -> Result<(), Error> {
        let key = pos_key(EVENT, pos);
        if let Some(v) = self.cat_get(&key)? {
            if let NodeEvent::Deleted { at, .. } = decode_event(&v)? {
                self.cat_remove(&deleted_key(at, pos), Shred::Yes)?;
            }
            self.cat_remove(&key, Shred::Yes)?;
        }
        Ok(())
    }

    /// Places an event at the next position, its subject's earlier event going; `extra` follows
    /// the position in the slot. It joins this transaction, so it is durable exactly when the
    /// effect written beside it is.
    fn log_place(&mut self, slot: Vec<u8>, e: NodeEvent, extra: &[u8]) -> Result<u64, Error> {
        let pos = self.log_advance()?;
        if let Some(v) = self.cat_get(&slot)? {
            let old = pos_value(v.get(..8).ok_or(Error::Corrupt("node log slot"))?)?;
            self.log_drop_event(old)?;
        }
        self.cat_put_to(&slot, W::new().u64(pos).raw(extra).take(), Shred::Yes, false)?;
        self.cat_put_to(&pos_key(EVENT, pos), encode_event(&e), Shred::No, false)?;
        if let NodeEvent::Deleted { at, .. } = e {
            self.cat_put_to(&deleted_key(at, pos), Vec::new(), Shred::No, false)?;
        }
        Ok(pos)
    }

    /// Logs that an entry became servable or its wrap or stamp changed. Returns its position.
    pub fn log_added(&mut self, l: LabelId, b: BlobId) -> Result<u64, Error> {
        self.log_place(entry_slot(&l, &b), NodeEvent::Added(l, b), &[])
    }

    /// Logs that an entry left the node at `at` (corrected wall ms). Returns its position.
    pub fn log_deleted(&mut self, label: LabelId, blob: BlobId, at: u64) -> Result<u64, Error> {
        self.log_place(entry_slot(&label, &blob), NodeEvent::Deleted { label, blob, at }, &[])
    }

    /// Logs a head event only if `head` is not the head last logged for `l`. Whether it did.
    pub fn log_head(&mut self, l: LabelId, head: &[u8; 32]) -> Result<bool, Error> {
        let slot = head_slot(&l);
        if self.cat_get(&slot)?.is_some_and(|v| v.get(8..) == Some(head.as_slice())) {
            return Ok(false);
        }
        self.log_place(slot, NodeEvent::Head(l), head)?;
        Ok(true)
    }

    /// Every sync ID's last logged head.
    pub fn log_heads(&mut self) -> Result<Vec<(LabelId, [u8; 32])>, Error> {
        let mut out = Vec::new();
        let mut from = Vec::new();
        loop {
            let rows = self.cat_scan(HEAD_SLOT, &from, PAGE)?;
            let n = rows.len();
            for (k, v) in rows {
                let label: [u8; 16] = k.get(2..18).and_then(|x| x.try_into().ok()).ok_or(Error::Corrupt("node log slot"))?;
                let head: [u8; 32] = v.get(8..).and_then(|x| x.try_into().ok()).ok_or(Error::Corrupt("node log slot"))?;
                out.push((LabelId(label), head));
                from = [label.as_slice(), &[0]].concat();
            }
            if n < PAGE {
                return Ok(out);
            }
        }
    }

    /// Drops a sync ID's every event and slot, with no deletion event: the node stopped holding
    /// it, which says nothing of the entries.
    pub fn log_forget(&mut self, l: LabelId) -> Result<(), Error> {
        let prefix = [ENTRY_SLOT, &l.0].concat();
        loop {
            let rows = self.cat_scan(&prefix, b"", PAGE)?;
            let n = rows.len();
            for (k, v) in rows {
                self.log_drop_event(pos_value(&v)?)?;
                self.cat_remove(&k, Shred::Yes)?;
            }
            if n < PAGE {
                break;
            }
        }
        let slot = head_slot(&l);
        if let Some(v) = self.cat_get(&slot)? {
            self.log_drop_event(pos_value(v.get(..8).ok_or(Error::Corrupt("node log slot"))?)?)?;
            self.cat_remove(&slot, Shred::Yes)?;
        }
        Ok(())
    }

    /// Drops deletion events past `TOMBSTONE_LIFETIME` at `now` (at most `PAGE` a call).
    /// Whether more remain to look at.
    pub fn log_sweep(&mut self, now: u64) -> Result<bool, Error> {
        let rows = self.cat_scan(DELETED, b"", PAGE)?;
        let full = rows.len() == PAGE;
        for (k, _) in rows {
            let mut r = R::new(k.get(2..).ok_or(Error::Corrupt("node log"))?);
            let (at, pos) = (r.u64()?, r.u64()?);
            if at.saturating_add(TOMBSTONE_LIFETIME_MS) > now {
                return Ok(false);
            }
            let Some(v) = self.cat_get(&pos_key(EVENT, pos))? else {
                self.cat_remove(&k, Shred::Yes)?;
                continue;
            };
            if let NodeEvent::Deleted { label, blob, .. } = decode_event(&v)? {
                self.cat_remove(&entry_slot(&label, &blob), Shred::Yes)?;
            }
            self.log_drop_event(pos)?;
        }
        Ok(full)
    }

    fn seal_cursor(&mut self, m: &Meta, pos: u64) -> Result<Vec<u8>, Error> {
        let mut nonce = [0u8; NONCE_LEN];
        self.rng().fill_bytes(&mut nonce);
        let plain = W::new().raw(&m.log_id).raw(&m.incarnation).u64(pos).take();
        let sealed = aead::seal(&m.key, &nonce, &[], &plain).map_err(|_| Error::Corrupt("node log cursor"))?;
        Ok([nonce.as_slice(), &sealed].concat())
    }

    /// A cursor for position `pos` of this store's history, naming the current incarnation.
    /// `None` past the end, and for a log with nothing ever appended.
    pub fn log_cursor(&mut self, pos: u64) -> Result<Option<Vec<u8>>, Error> {
        let Some(m) = self.log_meta()? else { return Ok(None) };
        if pos > m.end {
            return Ok(None);
        }
        self.seal_cursor(&m, pos).map(Some)
    }

    /// The position a cursor names on this store's history. `None` is no cursor: it does not
    /// open, is past the log's end, or names an incarnation this store's history does not hold
    /// at that position.
    pub fn log_position(&mut self, cursor: &[u8]) -> Result<Option<u64>, Error> {
        let Some(m) = self.log_meta()? else { return Ok(None) };
        if cursor.len() != CURSOR_LEN {
            return Ok(None);
        }
        let Some((nonce, sealed)) = cursor.split_at_checked(NONCE_LEN) else { return Ok(None) };
        let Ok(nonce) = <[u8; NONCE_LEN]>::try_from(nonce) else { return Ok(None) };
        let Ok(plain) = aead::open(&m.key, &nonce, &[], sealed) else { return Ok(None) };
        let mut r = R::new(&plain);
        let (log_id, incarnation, pos): ([u8; 16], [u8; 16], u64) = (r.array()?, r.array()?, r.u64()?);
        r.end()?;
        if log_id != m.log_id || pos > m.end {
            return Ok(None);
        }
        if incarnation == m.incarnation {
            return Ok(Some(pos));
        }
        let ended = match self.cat_get(ENDED)? {
            Some(v) => decode_ended(&v)?,
            None => Vec::new(),
        };
        Ok(ended.iter().find(|(id, _)| *id == incarnation).filter(|(_, end)| pos <= *end).map(|_| pos))
    }

    /// Up to `limit` events after `cursor` in log order, or from the start with no cursor or one
    /// that is no cursor (`whole`). Costs what it returns, however large the log.
    pub fn log_read(&mut self, cursor: Option<&[u8]>, limit: usize) -> Result<LogRead, Error> {
        let Some(m) = self.log_meta()? else {
            return Ok(LogRead { whole: true, ..LogRead::default() });
        };
        let after = match cursor {
            Some(c) => self.log_position(c)?,
            None => None,
        };
        let whole = after.is_none();
        let from = after.unwrap_or(0).saturating_add(1);
        let rows = self.cat_scan(EVENT, &from.to_be_bytes(), limit.saturating_add(1))?;
        let more = rows.len() > limit;
        let mut events = Vec::with_capacity(rows.len().min(limit));
        for (k, v) in rows.into_iter().take(limit) {
            let pos = R::new(k.get(2..).ok_or(Error::Corrupt("node log"))?).u64()?;
            events.push(LoggedEvent { pos, event: decode_event(&v)? });
        }
        // a page's end is its last event, so nothing past it is claimed; the log's end otherwise
        let at = if more { events.last().map_or(from.saturating_sub(1), |e| e.pos) } else { m.end };
        let cursor = Some(self.seal_cursor(&m, at)?);
        Ok(LogRead { events, cursor, whole, more })
    }
}

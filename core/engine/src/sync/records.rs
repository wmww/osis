//! Sync records and removal notices (spec/sync-judgement.md §6, spec/sync.md §3 Kept unread): what
//! a node keeping a thing unread holds of it, each taken from a box sealed to its own key, in the
//! transaction where the box opened; and the removal signatures inbox blobs to this node carried,
//! kept while their blob is unexpired. No other engine state of a kept-unread thing exists.

use super::{DialHint, RemovalNotice, SyncRecord};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, SyncId, Tid, Value, WallMs};
use osis_crypto::{Epoch, Secret32, Signature};
use osis_store::Shred;
use std::collections::BTreeMap;
use std::sync::Arc;

/// `sy/` + tid: a sync record (`SyncRecord`).
pub(crate) const SYNC_RECORDS: &[u8] = b"sy/";
/// `rn/` + blob ID + sync ID: a removal notice an inbox blob carried, with its blob's expiry.
pub(crate) const REMOVAL_NOTICES: &[u8] = b"rn/";

/// A removal notice as kept: the notice and its blob's prefix expiry (it is held while unexpired).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldNotice {
    pub notice: RemovalNotice,
    pub expires: WallMs,
    /// It stopped this node keeping S (`Engine::stop_sync_record`): while held, no box of a sync
    /// epoch at or below its epoch makes a record of S's thing again.
    pub counted: bool,
}

fn record_value(r: &SyncRecord) -> Value {
    Value::List(vec![
        Value::List(r.sync_ids.iter().map(|s| Value::Bytes(s.0.to_vec())).collect()),
        Value::List(r.secrets.iter().map(|(e, s)| Value::List(vec![e.to_wire(), Value::Bytes(s.expose().to_vec())])).collect()),
        Value::List(r.dial.iter().map(|d| Value::List(vec![Value::Bytes(d.dialable.to_vec()), Value::List(d.urls.iter().cloned().map(Value::Str).collect())])).collect()),
    ])
}

fn record_of(b: &[u8]) -> Result<SyncRecord> {
    let bad = || Error::Corrupt("sync record");
    let v = osis_base::decode(b, &osis_base::Limits { max_depth: 8, max_bytes: b.len() }).map_err(|_| bad())?;
    let Value::List(f) = v else { return Err(bad()) };
    let [Value::List(ids), Value::List(secrets), Value::List(dial)] = f.as_slice() else { return Err(bad()) };
    let mut r = SyncRecord::default();
    for id in ids {
        let Value::Bytes(b) = id else { return Err(bad()) };
        r.sync_ids.push(SyncId(b.as_slice().try_into().map_err(|_| bad())?));
    }
    for s in secrets {
        let Value::List(p) = s else { return Err(bad()) };
        let [e, Value::Bytes(k)] = p.as_slice() else { return Err(bad()) };
        let e = Epoch::from_wire(e).map_err(|_| bad())?;
        r.secrets.insert(e, Secret32::from_bytes(k.as_slice().try_into().map_err(|_| bad())?));
    }
    if let Some(d) = dial.first() {
        let Value::List(p) = d else { return Err(bad()) };
        let [Value::Bytes(k), Value::List(urls)] = p.as_slice() else { return Err(bad()) };
        let urls = urls.iter().map(|u| if let Value::Str(u) = u { Ok(u.clone()) } else { Err(bad()) }).collect::<Result<_>>()?;
        r.dial = Some(DialHint { dialable: k.as_slice().try_into().map_err(|_| bad())?, urls });
    }
    Ok(r)
}

fn notice_value(n: &HeldNotice) -> Value {
    Value::List(vec![n.notice.sig.to_value(), Value::Tid(n.notice.recipient), Value::Bytes(n.notice.commit.0.to_vec()), Value::Int(n.expires.0 as i64), Value::Int(n.notice.epoch as i64), Value::Bool(n.counted)])
}

fn notice_of(k: &[u8], b: &[u8]) -> Result<(BlobId, HeldNotice)> {
    let bad = || Error::Corrupt("removal notice");
    let (blob, sync_id) = (k.get(..32).ok_or_else(bad)?, k.get(32..).ok_or_else(bad)?);
    let v = osis_base::decode(b, &osis_base::Limits { max_depth: 4, max_bytes: b.len() }).map_err(|_| bad())?;
    let Value::List(f) = v else { return Err(bad()) };
    let [sig, Value::Tid(recipient), Value::Bytes(commit), Value::Int(expires), Value::Int(epoch), Value::Bool(counted)] = f.as_slice() else { return Err(bad()) };
    let notice = RemovalNotice {
        sync_id: SyncId(sync_id.try_into().map_err(|_| bad())?),
        epoch: u64::try_from(*epoch).map_err(|_| bad())?,
        sig: Signature::from_value(sig).map_err(|_| bad())?,
        recipient: *recipient,
        commit: CommitId(commit.as_slice().try_into().map_err(|_| bad())?),
    };
    Ok((BlobId(blob.try_into().map_err(|_| bad())?), HeldNotice { notice, expires: WallMs(u64::try_from(*expires).map_err(|_| bad())?), counted: *counted }))
}

/// Loads the sync records and removal notices into the indexes (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let mut records = Vec::new();
    tx.scan(SYNC_RECORDS, |k, v| {
        records.push((Tid::from_bytes(k.try_into().map_err(|_| Error::Corrupt("sync record"))?), record_of(&v)?));
        Ok(())
    })?;
    for (t, r) in records {
        for s in &r.sync_ids {
            tx.core.ix.record_ids.insert(*s, t);
        }
        tx.core.ix.sync_records.insert(t, Arc::new(r));
    }
    let mut notices = Vec::new();
    tx.scan(REMOVAL_NOTICES, |k, v| {
        notices.push(notice_of(k, &v)?);
        Ok(())
    })?;
    for (b, n) in notices {
        let mut m = tx.core.ix.removal_notices.get(&n.notice.sync_id).map(|m| (**m).clone()).unwrap_or_default();
        let s = n.notice.sync_id;
        m.insert(b, n);
        tx.core.ix.removal_notices.insert(s, Arc::new(m));
    }
    Ok(())
}

/// Adds `sync_ids` and the sync `secrets` (each checked to name its epoch of `thing`'s sync role,
/// spec/crypto.md §4: a box's secret establishes nothing, it is held as that epoch's) to `thing`'s
/// sync record, with the granting node's `dial` hint in place of the one before, written in the
/// running transaction: the one where the box sealed to this node's own key opened
/// (spec/sync-judgement.md §6). Returns whether the record changed.
pub(crate) fn note_sync_secrets(tx: &mut Tx<'_>, thing: &Tid, sync_ids: &[SyncId], secrets: impl IntoIterator<Item = (Epoch, Secret32)>, dial: Option<&DialHint>) -> Result<bool> {
    let mut r = tx.core.ix.sync_records.get(thing).map(|r| (**r).clone()).unwrap_or_default();
    let before = r.clone();
    if let Some(d) = dial {
        r.dial = Some(d.clone());
    }
    for s in sync_ids {
        if !r.sync_ids.contains(s) {
            r.sync_ids.push(*s);
        }
    }
    // a removal that stopped this node outranks the boxes it covers: an older grant taken again
    // makes no record (spec/sync-judgement.md §6 Stops)
    let stopped = r.sync_ids.iter().filter_map(|s| tx.core.ix.removal_notices.get(s)).flat_map(|m| m.values().filter(|n| n.counted).map(|n| n.notice.epoch)).max();
    for (e, s) in secrets {
        if stopped.is_some_and(|n| e.n() <= n) {
            continue;
        }
        if e.names(thing, osis_base::Role::Sync, &s) {
            r.secrets.insert(e, s);
        }
    }
    // a record holds a sync secret: sync IDs alone name nothing this node can open
    if r == before || r.secrets.is_empty() {
        return Ok(false);
    }
    tx.txn.put_local(&[SYNC_RECORDS, thing.as_bytes()].concat(), &osis_base::encode(&record_value(&r)), Shred::Yes)?;
    for s in &r.sync_ids {
        tx.core.ix.record_ids.insert(*s, *thing);
    }
    tx.core.ix.sync_records.insert(*thing, Arc::new(r));
    Ok(true)
}

/// Drops `thing`'s sync record (`Engine::stop_sync_record`).
pub(crate) fn drop_record(tx: &mut Tx<'_>, thing: &Tid) -> Result<()> {
    if let Some(r) = tx.core.ix.sync_records.remove(thing) {
        for s in &r.sync_ids {
            tx.core.ix.record_ids.remove(s, thing);
        }
        tx.txn.remove_local(&[SYNC_RECORDS, thing.as_bytes()].concat(), Shred::Yes)?;
    }
    Ok(())
}

/// Marks the held notice `n` as having stopped this node keeping its sync ID (`HeldNotice::counted`).
pub(crate) fn count_notice(tx: &mut Tx<'_>, n: &RemovalNotice) -> Result<()> {
    let s = n.sync_id;
    let Some(mut m) = tx.core.ix.removal_notices.get(&s).map(|m| (**m).clone()) else { return Ok(()) };
    let mut moved = false;
    for (b, h) in m.iter_mut().filter(|(_, h)| h.notice == *n && !h.counted) {
        h.counted = true;
        tx.txn.put_local(&[REMOVAL_NOTICES, &b.0, &s.0].concat(), &osis_base::encode(&notice_value(h)), Shred::No)?;
        moved = true;
    }
    if moved {
        tx.core.ix.removal_notices.insert(s, Arc::new(m));
    }
    Ok(())
}

/// Keeps the removal notices inbox blob `blob` (expiring at `expires`) carried, for `unread` to
/// verify (spec/wire.md §9 position 5; spec/sync-judgement.md §6 Stops).
pub(crate) fn note_removals(tx: &mut Tx<'_>, blob: &BlobId, expires: WallMs, notices: Vec<RemovalNotice>) -> Result<()> {
    for notice in notices {
        let s = notice.sync_id;
        let mut m = tx.core.ix.removal_notices.get(&s).map(|m| (**m).clone()).unwrap_or_default();
        if m.contains_key(blob) {
            continue;
        }
        let n = HeldNotice { notice, expires, counted: false };
        tx.txn.put_local(&[REMOVAL_NOTICES, &blob.0, &s.0].concat(), &osis_base::encode(&notice_value(&n)), Shred::No)?;
        m.insert(*blob, n);
        tx.core.ix.removal_notices.insert(s, Arc::new(m));
    }
    Ok(())
}

/// Drops the notices whose blob expired by `now` (`retention::tick`).
pub(crate) fn expire_notices(tx: &mut Tx<'_>, now: WallMs) -> Result<()> {
    let gone: Vec<(SyncId, BlobId)> = tx.core.ix.removal_notices.iter().flat_map(|(s, m)| m.iter().filter(|(_, n)| n.expires <= now).map(|(b, _)| (*s, *b))).collect();
    for (s, b) in gone {
        let mut m = tx.core.ix.removal_notices.get(&s).map(|m| (**m).clone()).unwrap_or_default();
        m.remove(&b);
        match m.is_empty() {
            true => tx.core.ix.removal_notices.remove(&s),
            false => tx.core.ix.removal_notices.insert(s, Arc::new(m)),
        };
        tx.txn.remove_local(&[REMOVAL_NOTICES, &b.0, &s.0].concat(), Shred::No)?;
    }
    Ok(())
}

impl Engine {
    /// `thing`'s sync record (spec/sync-judgement.md §6): reads only its key.
    pub(crate) fn sync_record_now(&self, thing: &Tid) -> Option<Arc<SyncRecord>> {
        self.core.ix.sync_records.get(thing).cloned()
    }

    /// Every sync record, whole: for a start's listing (`sync_record_feed` follows additions).
    pub(crate) fn sync_records_now(&self) -> Arc<BTreeMap<Tid, SyncRecord>> {
        Arc::new(self.core.ix.sync_records.iter().map(|(t, r)| (*t, (**r).clone())).collect())
    }

    /// The removal notices to this node for `s`, their blobs unexpired at the memo clock (valid
    /// until the earliest expiry). Reads only `s`'s key.
    pub(crate) fn removal_notices_now(&self, s: &SyncId) -> Arc<Vec<RemovalNotice>> {
        let now = self.core.time.get();
        let Some(m) = self.core.ix.removal_notices.get(s) else { return Arc::new(Vec::new()) };
        self.core.time.until(m.values().map(|n| n.expires.0).filter(|e| *e > now).min());
        Arc::new(m.values().filter(|n| n.expires.0 > now).map(|n| n.notice.clone()).collect())
    }
}

//! Sync records (spec/sync-judgement.md §6, spec/sync.md §3 Kept unread): what a node keeping a
//! thing unread holds of it, each taken from a box sealed to its own key, in the transaction
//! where the box opened. No other engine state of a kept-unread thing exists.

use super::{DialHint, SyncRecord};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{SyncId, Tid, Value};
use osis_crypto::{Epoch, Secret32};
use osis_store::Shred;
use std::collections::BTreeMap;
use std::sync::Arc;

/// `sy/` + tid: a sync record (`SyncRecord`).
pub(crate) const SYNC_RECORDS: &[u8] = b"sy/";

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

/// Loads the sync records into the indexes (an open or reload).
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
    for (e, s) in secrets {
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

impl Engine {
    /// `thing`'s sync record (spec/sync-judgement.md §6): reads only its key.
    pub(crate) fn sync_record_now(&self, thing: &Tid) -> Option<Arc<SyncRecord>> {
        self.core.ix.sync_records.get(thing).cloned()
    }

    /// Every sync record, whole: for a start's listing (`sync_record_feed` follows additions).
    pub(crate) fn sync_records_now(&self) -> Arc<BTreeMap<Tid, SyncRecord>> {
        Arc::new(self.core.ix.sync_records.iter().map(|(t, r)| (*t, (**r).clone())).collect())
    }
}

//! Record blobs under a sync ID (spec/wire.md §3, spec/permissions.md §4): the raw creation
//! records a sync ID's chain certificates name that no closure body there carries, sealed as one
//! record blob of the records missing, and taken when one opens. Each record blob sealed here is
//! kept per sync ID with its records (`RECORD_BLOBS` rows: one per blob this node logged), so read
//! knows what its own store carries across a restart.

use super::Wrap;
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CreationRecord, SyncId, Tid};
use osis_crypto::NodeRng;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `rb/` + sync ID + blob ID: the tids of the records the record blob carries, 15 bytes each.
pub(crate) const RECORD_BLOBS: &[u8] = b"rb/";

/// Loads the record blobs kept (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("record blob row");
    let mut rows: BTreeMap<SyncId, BTreeMap<BlobId, BTreeSet<Tid>>> = BTreeMap::new();
    tx.scan(RECORD_BLOBS, |k, v| {
        let s = SyncId(k.get(..16).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let b = BlobId(k.get(16..48).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let tids = v.chunks(15).map(|x| x.try_into().map(Tid::from_bytes).map_err(|_| bad())).collect::<Result<BTreeSet<Tid>>>()?;
        rows.entry(s).or_default().insert(b, tids);
        Ok(())
    })?;
    for (s, m) in rows {
        tx.core.ix.record_blobs.insert(s, Arc::new(m));
    }
    Ok(())
}

fn note(tx: &mut Tx<'_>, s: &SyncId, b: &BlobId, tids: &BTreeSet<Tid>) -> Result<()> {
    let mut m = tx.core.ix.record_blobs.get(s).map(|x| (**x).clone()).unwrap_or_default();
    if m.get(b) == Some(tids) {
        return Ok(());
    }
    m.insert(*b, tids.clone());
    let v: Vec<u8> = tids.iter().flat_map(|t| *t.as_bytes()).collect();
    tx.txn.put_local(&[RECORD_BLOBS, &s.0, &b.0].concat(), &v, Shred::No)?;
    tx.core.ix.record_blobs.insert(*s, Arc::new(m));
    Ok(())
}

/// The rows of every record blob sealed under `s` go (`s` is read here no more).
pub(crate) fn forget(tx: &mut Tx<'_>, s: &SyncId) -> Result<()> {
    let Some(m) = tx.core.ix.record_blobs.get(s).cloned() else { return Ok(()) };
    for b in m.keys() {
        tx.txn.remove_local(&[RECORD_BLOBS, &s.0, &b.0].concat(), Shred::No)?;
    }
    tx.core.ix.record_blobs.remove(s);
    Ok(())
}

/// The row of record blob `b` under `s` goes (no own entry holds it any more).
pub(crate) fn forget_blob(tx: &mut Tx<'_>, s: &SyncId, b: &BlobId) -> Result<()> {
    let Some(m) = tx.core.ix.record_blobs.get(s).cloned() else { return Ok(()) };
    if !m.contains_key(b) {
        return Ok(());
    }
    let mut m = (*m).clone();
    m.remove(b);
    tx.txn.remove_local(&[RECORD_BLOBS, &s.0, &b.0].concat(), Shred::No)?;
    match m.is_empty() {
        true => tx.core.ix.record_blobs.remove(s),
        false => tx.core.ix.record_blobs.insert(*s, Arc::new(m)),
    };
    Ok(())
}

impl Engine {
    /// The records sync ID `s` carries as certificates (spec/permissions.md §4): those its
    /// certificates name (`certified_records`) whose `created.0` no closure body there carries
    /// (a thing of the closure its actor reads), held here.
    pub(crate) fn certificate_records_now(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<Tid>>> {
        let Some(t) = self.read_thing(s)? else { return Ok(Arc::default()) };
        let records = self.certified_records(&t)?;
        let ctx = self.body_ctx(&t);
        let out = records.iter().filter(|x| !(ctx.closure.contains(x) && self.reads(&ctx, x)) && self.core.created(x).is_some()).copied().collect();
        Ok(Arc::new(out))
    }

    /// The record blobs sealed here under `s`, each with its records.
    pub(crate) fn record_blobs_now(&self, s: &SyncId) -> Arc<BTreeMap<BlobId, BTreeSet<Tid>>> {
        self.core.ix.record_blobs.get(s).cloned().unwrap_or_default()
    }

    /// One record blob of `records` (those held here) under `s` and its wrap (spec/wire.md §3: no
    /// commitments, no expiry, durable; a fresh encryption per sync ID), wrapped under `s`'s
    /// thing's current read epoch (`wrap_secret`). `None` when none is held or no epoch is.
    pub(crate) fn seal_records_now(&mut self, s: &SyncId, records: &BTreeSet<Tid>, rng: &mut dyn NodeRng) -> Result<Option<(BlobId, Vec<u8>, Wrap)>> {
        let Some(t) = self.read_thing(s)? else { return Ok(None) };
        let recs: Vec<osis_base::CreationRecord> = records.iter().filter_map(|x| self.core.created(x).cloned()).collect();
        if recs.is_empty() {
            return Ok(None);
        }
        let Some(w) = self.wrap_secret(&t, None)? else { return Ok(None) };
        let plain = osis_commit::record_blob::encode_record_blob(&recs);
        let mut blind = [0u8; 16];
        rng.fill_bytes(&mut blind);
        let prefix = osis_label::Prefix::for_groups(osis_label::Prefix::random_salt(rng), &blind, None, &[])?.with_class(osis_label::Class::Durable);
        let (key, blob) = osis_label::frame(&prefix, &plain, rng)?;
        let id = osis_label::blob_id(&blob);
        let wrap = osis_crypto::wrap(&w, &id, &key, 0)?;
        let tids: BTreeSet<Tid> = records.iter().filter(|x| self.core.created(x).is_some()).copied().collect();
        let s = *s;
        self.run(|tx| note(tx, &s, &id, &tids))?;
        Ok(Some((id, blob, wrap)))
    }

    /// Takes a record blob's plaintext `plain`, the plaintext of blob `b` (a record proves itself
    /// by its hash): the records something here awaits are learned, with those on their record
    /// chains; the rest are kept loose, carried by `b` (spec/commits.md §4 Pending storage), and
    /// learned once something awaits them (`Engine::promote_loose`). Nothing of the blob is kept
    /// here: a peer's record blob is not kept in the own store, so it leaves no row
    /// (`record_blobs` holds what this node sealed). `None` when `plain` is no record blob.
    pub(crate) fn take_record_blob(&mut self, b: &BlobId, plain: &[u8]) -> Result<Option<BTreeSet<Tid>>> {
        let Ok(recs) = osis_commit::record_blob::decode_record_blob(plain) else { return Ok(None) };
        let tids: BTreeSet<Tid> = recs.iter().map(|r| r.tid()).collect();
        let batch: BTreeMap<Tid, CreationRecord> = recs.into_iter().map(|r| (r.tid(), r)).filter(|(t, _)| self.core.created(t).is_none()).collect();
        let seeds: Vec<Tid> = batch.keys().filter(|t| crate::apply::awaits_record(&self.core, t)).copied().collect();
        let learn = with_chains(&self.core, seeds, &batch);
        let learned: BTreeSet<Tid> = learn.iter().map(|r| r.tid()).collect();
        for (t, r) in batch {
            if !learned.contains(&t) {
                self.core.waits.loose.keep(*b, r);
            }
        }
        self.learn_records(learn)?;
        Ok(Some(tids))
    }

    /// Whether blob `b` carries a record kept loose here (its entry is kept as its carrier).
    pub fn carries_loose(&self, b: &BlobId) -> bool {
        self.core.waits.loose.carries(b)
    }

    /// A cursor over the carriers of loose records whose every record was learned since: each
    /// gives something held now (`memo::Feed`).
    pub fn loose_feed(&self) -> osis_base::memo::Feed<BlobId> {
        self.core.waits.carried.feed()
    }

    /// No entry in the store carries blob `b` any more: the loose records only it carried go.
    pub fn forget_carrier(&mut self, b: &BlobId) {
        self.core.waits.loose.forget(b);
    }

    /// Loose records kept (scale checks).
    pub fn loose_records(&self) -> usize {
        self.core.waits.loose.len()
    }
}

/// The records named by `seeds` not known here, with those on their record chains (each
/// `Thing`'s first admin), from `batch` or the loose records.
pub(crate) fn with_chains(core: &crate::engine::Core, seeds: Vec<Tid>, batch: &BTreeMap<Tid, CreationRecord>) -> Vec<CreationRecord> {
    let mut out: BTreeMap<Tid, CreationRecord> = BTreeMap::new();
    let mut stack = seeds;
    while let Some(t) = stack.pop() {
        if out.contains_key(&t) || core.created(&t).is_some() {
            continue;
        }
        let Some(r) = batch.get(&t).or_else(|| core.waits.loose.get(&t)) else { continue };
        if let CreationRecord::Thing { admin, .. } = r {
            stack.push(*admin);
        }
        out.insert(t, r.clone());
    }
    out.into_values().collect()
}

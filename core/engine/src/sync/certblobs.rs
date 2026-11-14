//! Certificate blobs of this node's own under a sync ID (spec/sync-judgement.md §1): record
//! blobs (spec/wire.md §3), the raw creation records a sync ID's chain certificates name that no
//! closure body there carries, and list blobs (spec/wire.md §4, List tree), the thing lists of
//! one rotation for the things the sync ID carries lists of; each sealed as one blob of what is
//! missing, and taken when one opens. Each one sealed here is kept per sync ID with what it
//! carries (`CERT_BLOBS` rows: one per blob this node logged), so read knows what its own store
//! carries across a restart.

use super::Wrap;
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, CreationRecord, SyncId, Tid};
use osis_crypto::NodeRng;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `cb/` + sync ID + blob ID: what the certificate blob carries (`Carried::encode`).
pub(crate) const CERT_BLOBS: &[u8] = b"cb/";

/// What a certificate blob sealed here carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Carried {
    /// A record blob: these records.
    Records(BTreeSet<Tid>),
    /// A list blob: the thing lists of this rotation for these things.
    Lists(CommitId, BTreeSet<Tid>),
}

impl Carried {
    /// Row bytes: 0 + tids, or 1 + rotation + tids (15 bytes each).
    fn encode(&self) -> Vec<u8> {
        let (head, tids): (Vec<u8>, _) = match self {
            Carried::Records(t) => (vec![0], t),
            Carried::Lists(r, t) => ([&[1u8][..], &r.0[..]].concat(), t),
        };
        [head, tids.iter().flat_map(|t| *t.as_bytes()).collect()].concat()
    }

    fn decode(v: &[u8]) -> Option<Carried> {
        let tids = |b: &[u8]| b.len().is_multiple_of(15).then(|| b.chunks(15).filter_map(|x| x.try_into().ok().map(Tid::from_bytes)).collect::<BTreeSet<Tid>>());
        match v.split_first()? {
            (0, rest) => Some(Carried::Records(tids(rest)?)),
            (1, rest) => {
                let (r, t) = rest.split_at_checked(32)?;
                Some(Carried::Lists(CommitId(r.try_into().ok()?), tids(t)?))
            }
            _ => None,
        }
    }
}

/// Loads the certificate blobs kept (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("certificate blob row");
    let mut rows: BTreeMap<SyncId, BTreeMap<BlobId, Carried>> = BTreeMap::new();
    tx.scan(CERT_BLOBS, |k, v| {
        let s = SyncId(k.get(..16).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let b = BlobId(k.get(16..48).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        rows.entry(s).or_default().insert(b, Carried::decode(&v).ok_or_else(bad)?);
        Ok(())
    })?;
    for (s, m) in rows {
        tx.core.ix.cert_blobs.insert(s, Arc::new(m));
    }
    Ok(())
}

fn note(tx: &mut Tx<'_>, s: &SyncId, b: &BlobId, carried: Carried) -> Result<()> {
    let mut m = tx.core.ix.cert_blobs.get(s).map(|x| (**x).clone()).unwrap_or_default();
    if m.get(b) == Some(&carried) {
        return Ok(());
    }
    tx.txn.put_local(&[CERT_BLOBS, &s.0, &b.0].concat(), &carried.encode(), Shred::No)?;
    m.insert(*b, carried);
    tx.core.ix.cert_blobs.insert(*s, Arc::new(m));
    Ok(())
}

/// The rows of every certificate blob sealed under `s` go (`s` is read here no more).
pub(crate) fn forget(tx: &mut Tx<'_>, s: &SyncId) -> Result<()> {
    let Some(m) = tx.core.ix.cert_blobs.get(s).cloned() else { return Ok(()) };
    for b in m.keys() {
        tx.txn.remove_local(&[CERT_BLOBS, &s.0, &b.0].concat(), Shred::No)?;
    }
    tx.core.ix.cert_blobs.remove(s);
    Ok(())
}

/// The row of certificate blob `b` under `s` goes (no own entry holds it any more).
pub(crate) fn forget_blob(tx: &mut Tx<'_>, s: &SyncId, b: &BlobId) -> Result<()> {
    let Some(m) = tx.core.ix.cert_blobs.get(s).cloned() else { return Ok(()) };
    if !m.contains_key(b) {
        return Ok(());
    }
    let mut m = (*m).clone();
    m.remove(b);
    tx.txn.remove_local(&[CERT_BLOBS, &s.0, &b.0].concat(), Shred::No)?;
    match m.is_empty() {
        true => tx.core.ix.cert_blobs.remove(s),
        false => tx.core.ix.cert_blobs.insert(*s, Arc::new(m)),
    };
    Ok(())
}

/// A fresh durable blob of `plain` and its wrap under read secret `w` (spec/wire.md §3, §4: no
/// commitments, no expiry, order 0; a fresh encryption per sync ID).
fn seal_cert_blob(w: &osis_crypto::Secret32, plain: &[u8], rng: &mut dyn NodeRng) -> Result<(BlobId, Vec<u8>, Wrap)> {
    let mut blind = [0u8; 16];
    rng.fill_bytes(&mut blind);
    let prefix = osis_label::Prefix::for_groups(osis_label::Prefix::random_salt(rng), &blind, None, &[])?.with_class(osis_label::Class::Durable);
    let (key, blob) = osis_label::frame(&prefix, plain, rng)?;
    let id = osis_label::blob_id(&blob);
    let wrap = osis_crypto::wrap(w, &id, &key, 0)?;
    Ok((id, blob, wrap))
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

    /// The thing lists sync ID `s` carries (spec/sync-judgement.md §1 List blobs; spec/permissions.md
    /// §5.5: a thing list is a chain certificate of its thing), per rotation the things whose held
    /// list it carries: the things of its closure its actor reads, and those whose records its
    /// certificates name (`certified_records`: the things its certificate commits are about).
    /// Reads each such thing's lists (`Indexes::lists_on`) alone.
    pub(crate) fn certificate_lists_now(&mut self, s: &SyncId) -> Result<Arc<BTreeMap<CommitId, BTreeSet<Tid>>>> {
        let Some(t) = self.read_thing(s)? else { return Ok(Arc::default()) };
        let records = self.certified_records(&t)?;
        let ctx = self.body_ctx(&t);
        let things: BTreeSet<Tid> = ctx.closure.iter().filter(|x| self.reads(&ctx, x)).chain(records.iter()).copied().collect();
        let mut out: BTreeMap<CommitId, BTreeSet<Tid>> = BTreeMap::new();
        for x in things {
            for r in self.core.ix.lists_on.get(&x).into_iter().flatten() {
                out.entry(*r).or_default().insert(x);
            }
        }
        Ok(Arc::new(out))
    }

    /// Whether a record blob can be sealed under `s` now (a current read epoch of its thing to
    /// wrap under; none while, say, a rotation is owed before encrypting), and a list blob of
    /// rotation `r` (`r`: `list_wrap_secret`).
    pub(crate) fn cert_wrap_now(&mut self, s: &SyncId, r: Option<&CommitId>) -> Result<bool> {
        let Some(t) = self.read_thing(s)? else { return Ok(false) };
        Ok(match r {
            Some(r) => self.list_wrap_secret(&t, r).is_some(),
            None => self.wrap_secret(&t, None)?.is_some(),
        })
    }

    /// The certificate blobs sealed here under `s`, each with what it carries.
    pub(crate) fn cert_blobs_now(&self, s: &SyncId) -> Arc<BTreeMap<BlobId, Carried>> {
        self.core.ix.cert_blobs.get(s).cloned().unwrap_or_default()
    }

    /// One record blob of `records` (those held here) under `s` and its wrap (`seal_cert_blob`).
    /// `None` when none is held or no epoch is.
    pub(crate) fn seal_records_now(&mut self, s: &SyncId, records: &BTreeSet<Tid>, rng: &mut dyn NodeRng) -> Result<Option<(BlobId, Vec<u8>, Wrap)>> {
        let Some(t) = self.read_thing(s)? else { return Ok(None) };
        let recs: Vec<osis_base::CreationRecord> = records.iter().filter_map(|x| self.core.created(x).cloned()).collect();
        if recs.is_empty() {
            return Ok(None);
        }
        let plain = osis_commit::record_blob::encode_record_blob(&recs);
        // under `t`'s current read epoch (`wrap_secret`)
        let Some(w) = self.wrap_secret(&t, None)? else { return Ok(None) };
        let (id, blob, wrap) = seal_cert_blob(&w, &plain, rng)?;
        let tids: BTreeSet<Tid> = recs.iter().map(CreationRecord::tid).collect();
        let s = *s;
        self.run(|tx| note(tx, &s, &id, Carried::Records(tids)))?;
        Ok(Some((id, blob, wrap)))
    }

    /// One list blob of rotation `r`'s thing lists held here for `things` under `s` and its wrap
    /// (`seal_cert_blob`). `None` when none is held or no epoch is.
    pub(crate) fn seal_lists_now(&mut self, s: &SyncId, r: &CommitId, things: &BTreeSet<Tid>, rng: &mut dyn NodeRng) -> Result<Option<(BlobId, Vec<u8>, Wrap)>> {
        let Some(t) = self.read_thing(s)? else { return Ok(None) };
        let r = *r;
        let wanted = things.clone();
        let certs = self.read(|tx| crate::flows::lists::certs_of(tx, &r, Some(&wanted)))?;
        if certs.is_empty() {
            return Ok(None);
        }
        let plain = osis_commit::thing_list::encode_list_blob(&certs);
        // as the rotation wraps (`list_wrap_secret`)
        let Some(w) = self.list_wrap_secret(&t, &r) else { return Ok(None) };
        let (id, blob, wrap) = seal_cert_blob(&w, &plain, rng)?;
        let tids: BTreeSet<Tid> = certs.iter().map(|c| c.list.thing).collect();
        let s = *s;
        self.run(|tx| note(tx, &s, &id, Carried::Lists(r, tids)))?;
        Ok(Some((id, blob, wrap)))
    }

    /// Takes a list blob's plaintext `plain`, the plaintext of blob `b`: its thing lists held
    /// (`hold_lists`), or, while their rotation is not held here, kept loose, carried by `b`, and
    /// held as the rotation arrives (`Loose::lists_for`). `None` when `plain` is no list blob or
    /// a list in it does not verify; else its rotation.
    pub(crate) fn take_list_blob(&mut self, b: &BlobId, plain: &[u8]) -> Result<Option<CommitId>> {
        use crate::flows::lists::ListsHeld;
        Ok(match self.hold_lists(plain)? {
            ListsHeld::Held | ListsHeld::Known => osis_commit::thing_list::decode_list_blob(plain).ok().and_then(|c| c.first().map(|c| c.rotation)),
            ListsHeld::Awaits(r) => {
                let certs = osis_commit::thing_list::decode_list_blob(plain).unwrap_or_default();
                self.core.waits.loose.keep_lists(*b, r, certs);
                Some(r)
            }
            ListsHeld::Bad => None,
        })
    }

    /// Takes a record blob's plaintext `plain`, the plaintext of blob `b` (a record proves itself
    /// by its hash): the records something here awaits are learned, with those on their record
    /// chains; the rest are kept loose, carried by `b` (spec/commits.md §4 Pending storage), and
    /// learned once something awaits them (`Engine::promote_loose`). Nothing of the blob is kept
    /// here: a peer's record blob is not kept in the own store, so it leaves no row
    /// (`cert_blobs` holds what this node sealed). `None` when `plain` is no record blob.
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

    /// Whether blob `b` carries a record or thing lists kept loose here (its entry is kept as
    /// its carrier).
    pub fn carries_loose(&self, b: &BlobId) -> bool {
        self.core.waits.loose.carries(b)
    }

    /// A cursor over the carriers of loose records or lists whose every one was learned or held
    /// since: each gives something held now (`memo::Feed`).
    pub fn loose_feed(&self) -> osis_base::memo::Feed<BlobId> {
        self.core.waits.carried.feed()
    }

    /// No entry in the store carries blob `b` any more: the loose records and lists only it
    /// carried go.
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

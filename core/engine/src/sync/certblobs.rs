//! Certificate blobs of this node's own under a sync ID (spec/sync-judgement.md §1): record
//! blobs (spec/wire.md §3), the raw creation records a sync ID's chain certificates name that no
//! closure body there carries, and list blobs (spec/wire.md §4, List tree), the thing lists of
//! one rotation for the things the sync ID carries lists of (`sync::listed`); each sealed as one
//! blob of what is missing, and taken when one opens. Each one sealed here is kept per (sync ID,
//! kind: records or a rotation's lists) with what it carries (`CERT_BLOBS` rows: one per blob
//! this node logged), so read knows what its own store carries across a restart, and a reader of
//! one rotation's list blobs reads that key alone.

use super::Wrap;
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, CreationRecord, SyncId, Tid};
use osis_crypto::NodeRng;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `cb/` + sync ID + blob ID: what the certificate blob carries (`encode`).
pub(crate) const CERT_BLOBS: &[u8] = b"cb/";

/// What a certificate blob sealed here carries: a record blob (`None`) these records, a list
/// blob of rotation `r` (`Some(r)`) the thing lists of these things.
pub type CertKind = Option<CommitId>;

/// Row bytes: 0 + tids, or 1 + rotation + tids (15 bytes each).
fn encode(r: &CertKind, tids: &BTreeSet<Tid>) -> Vec<u8> {
    let head: Vec<u8> = match r {
        None => vec![0],
        Some(r) => [&[1u8][..], &r.0[..]].concat(),
    };
    [head, tids.iter().flat_map(|t| *t.as_bytes()).collect()].concat()
}

fn decode(v: &[u8]) -> Option<(CertKind, BTreeSet<Tid>)> {
    let tids = |b: &[u8]| b.len().is_multiple_of(15).then(|| b.chunks(15).filter_map(|x| x.try_into().ok().map(Tid::from_bytes)).collect::<BTreeSet<Tid>>());
    match v.split_first()? {
        (0, rest) => Some((None, tids(rest)?)),
        (1, rest) => {
            let (r, t) = rest.split_at_checked(32)?;
            Some((Some(CommitId(r.try_into().ok()?)), tids(t)?))
        }
        _ => None,
    }
}

/// The certificate blobs sealed here under one sync ID of one kind, each with what it carries.
pub type CertBlobs = BTreeMap<BlobId, BTreeSet<Tid>>;

/// Loads the certificate blobs kept (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("certificate blob row");
    let mut rows: BTreeMap<(SyncId, CertKind), CertBlobs> = BTreeMap::new();
    tx.scan(CERT_BLOBS, |k, v| {
        let s = SyncId(k.get(..16).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let b = BlobId(k.get(16..48).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let (r, tids) = decode(&v).ok_or_else(bad)?;
        rows.entry((s, r)).or_default().insert(b, tids);
        Ok(())
    })?;
    for (k, m) in rows {
        tx.core.ix.cert_blobs.insert(k, Arc::new(m));
    }
    Ok(())
}

fn note(tx: &mut Tx<'_>, s: &SyncId, r: CertKind, b: &BlobId, tids: BTreeSet<Tid>) -> Result<()> {
    let k = (*s, r);
    let mut m = tx.core.ix.cert_blobs.get(&k).map(|x| (**x).clone()).unwrap_or_default();
    if m.get(b) == Some(&tids) {
        return Ok(());
    }
    tx.txn.put_local(&[CERT_BLOBS, &s.0, &b.0].concat(), &encode(&r, &tids), Shred::No)?;
    m.insert(*b, tids);
    tx.core.ix.cert_blobs.insert(k, Arc::new(m));
    Ok(())
}

/// The keys of `s` in `Indexes::cert_blobs`.
fn under(s: &SyncId) -> std::ops::RangeInclusive<(SyncId, CertKind)> {
    (*s, None)..=(*s, Some(CommitId([0xff; 32])))
}

/// Whether a certificate blob sealed under `s` is kept.
pub(crate) fn any(core: &crate::engine::Core, s: &SyncId) -> bool {
    core.ix.cert_blobs.range(under(s)).next().is_some()
}

/// The rows of every certificate blob sealed under `s` go (`s` is read here no more).
pub(crate) fn forget(tx: &mut Tx<'_>, s: &SyncId) -> Result<()> {
    let keys: Vec<(SyncId, CertKind)> = tx.core.ix.cert_blobs.range(under(s)).map(|(k, _)| *k).collect();
    for k in keys {
        let Some(m) = tx.core.ix.cert_blobs.get(&k).cloned() else { continue };
        for b in m.keys() {
            tx.txn.remove_local(&[CERT_BLOBS, &s.0, &b.0].concat(), Shred::No)?;
        }
        tx.core.ix.cert_blobs.remove(&k);
    }
    Ok(())
}

/// The row of certificate blob `b` of kind `r` under `s` goes (no own entry holds it any more).
pub(crate) fn forget_blob(tx: &mut Tx<'_>, s: &SyncId, r: CertKind, b: &BlobId) -> Result<()> {
    let k = (*s, r);
    let Some(m) = tx.core.ix.cert_blobs.get(&k).cloned() else { return Ok(()) };
    if !m.contains_key(b) {
        return Ok(());
    }
    let mut m = (*m).clone();
    m.remove(b);
    tx.txn.remove_local(&[CERT_BLOBS, &s.0, &b.0].concat(), Shred::No)?;
    match m.is_empty() {
        true => tx.core.ix.cert_blobs.remove(&k),
        false => tx.core.ix.cert_blobs.insert(k, Arc::new(m)),
    };
    Ok(())
}

/// A fresh durable blob of `plain` and its wrap under read secret `w` (spec/wire.md §3, §4: no
/// commitments, no expiry, order 0; a fresh encryption per sync ID).
fn seal_cert_blob(w: &osis_crypto::Secret32, plain: &[u8], rng: &mut dyn NodeRng) -> Result<(BlobId, Vec<u8>, Wrap)> {
    let mut blind = [0u8; 16];
    rng.fill_bytes(&mut blind);
    let prefix = osis_blob::Prefix::for_groups(osis_blob::Prefix::random_salt(rng), &blind, None, &[])?.with_class(osis_blob::Class::Durable);
    let (key, blob) = osis_blob::frame(&prefix, plain, rng)?;
    let id = osis_blob::blob_id(&blob);
    let wrap = osis_crypto::wrap(w, &id, &key, 0)?;
    Ok((id, blob, wrap))
}

impl Engine {
    /// The records sync ID `s` carries as certificates (spec/permissions.md §4): those its
    /// certificates name (`certified_records`) whose `created.0` no closure body there carries
    /// (a thing of the closure its actor reads, minted by no commit giving it epochs:
    /// `minted_plainly`), held here.
    pub fn certificate_records(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<Tid>>> {
        let mut out = BTreeSet::new();
        for t in self.read_things_of(s)? {
            out.extend(self.records_of(&t)?);
        }
        Ok(Arc::new(out))
    }

    /// The records read thing `t`'s sync IDs carry as certificates (`certificate_records`).
    fn records_of(&mut self, t: &Tid) -> Result<BTreeSet<Tid>> {
        let records = self.certified_records(t)?;
        let ctx = self.body_ctx(t);
        Ok(records.iter().filter(|x| !(ctx.holds(&self.core, x) && self.reads(&ctx, x) && self.minted_plainly(x)) && self.core.created(x).is_some()).copied().collect())
    }

    /// Whether no held minting of `x` gives it epochs: its own-keys rotation carrying its record
    /// (spec/permissions.md §3) is wrapped under the derived epoch it supersedes (spec/crypto.md
    /// §5), so it carries the record to that epoch's holders alone and counts as no carrier
    /// (spec/permissions.md §4 Logging certificates).
    fn minted_plainly(&self, x: &Tid) -> bool {
        let Ok(secrets) = osis_base::Ak::new("secrets.0") else { return true };
        !self.core.mintings(x).any(|(c, _)| self.core.ix.commits.get(&c).is_some_and(|m| m.aspect(x, &secrets).is_some()))
    }

    /// Whether a record blob can be sealed under `s` now (a current read epoch of its thing to
    /// wrap under; none while, say, a rotation is owed before encrypting), and a list blob of
    /// rotation `r` (`r`: `list_wrap_secret`).
    pub fn cert_wrap(&mut self, s: &SyncId, r: Option<&CommitId>) -> Result<bool> {
        for t in self.read_things_of(s)? {
            let ok = match r {
                Some(r) => self.list_wrap_secret(&t, r)?.is_some(),
                None => self.wrap_secret(&t, None)?.is_some(),
            };
            if ok {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The certificate blobs of kind `r` sealed here under `s`, each with what it carries.
    pub fn cert_blobs(&self, s: &SyncId, r: CertKind) -> Arc<CertBlobs> {
        self.core.ix.cert_blobs.get(&(*s, r)).cloned().unwrap_or_default()
    }

    /// One record blob of `records` (those held here) under `s` and its wrap (`seal_cert_blob`).
    /// `None` when none is held or no epoch is.
    pub fn seal_records(&mut self, s: &SyncId, records: &BTreeSet<Tid>, rng: &mut dyn NodeRng) -> Result<Option<(BlobId, Vec<u8>, Wrap)>> {
        // under the thing reading `s` whose certificates these are, else any reading it (a
        // record proves itself by its hash)
        let things = self.read_things_of(s)?;
        let mut thing = None;
        for t in &things {
            if self.records_of(t)?.is_superset(records) {
                thing = Some(*t);
                break;
            }
        }
        let Some(t) = thing.or_else(|| things.first().copied()) else { return Ok(None) };
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
        self.run(|tx| note(tx, &s, None, &id, tids))?;
        Ok(Some((id, blob, wrap)))
    }

    /// One list blob of rotation `r`'s thing lists held here for `things` under `s` and its wrap
    /// (`seal_cert_blob`). `None` when none is held or no epoch is.
    pub fn seal_lists(&mut self, s: &SyncId, r: &CommitId, things: &BTreeSet<Tid>, rng: &mut dyn NodeRng) -> Result<Option<(BlobId, Vec<u8>, Wrap)>> {
        // under the thing reading `s` whose rotation `r`'s lists these are, else any reading it
        let readers = self.read_things_of(s)?;
        let Some(t) = readers.iter().copied().find(|t| self.thing_lists(t, r).is_superset(things)).or_else(|| readers.first().copied()) else { return Ok(None) };
        let r = *r;
        let wanted = things.clone();
        let certs = self.read(|tx| crate::flows::lists::certs_of(tx, &r, Some(&wanted)))?;
        if certs.is_empty() {
            return Ok(None);
        }
        let plain = osis_commit::thing_list::encode_list_blob(&certs);
        // as the rotation wraps (`list_wrap_secret`)
        let Some(w) = self.list_wrap_secret(&t, &r)? else { return Ok(None) };
        let (id, blob, wrap) = seal_cert_blob(&w, &plain, rng)?;
        let tids: BTreeSet<Tid> = certs.iter().map(|c| c.list.thing).collect();
        let s = *s;
        self.run(|tx| note(tx, &s, Some(r), &id, tids))?;
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

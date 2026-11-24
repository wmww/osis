//! Certificate blobs under a sync ID (spec/sync-judgement.md §1): record blobs (spec/wire.md
//! §3), the raw creation records a sync ID's certificates name that no closure body there
//! carries, each sealed as one blob of all the sync ID carries, committing to a writer delete key
//! of the sync ID's thing (spec/crypto.md §7), and taken when one opens. Each one sealed here or
//! opened from a peer is kept per sync ID with what it carries and what a Delete of it signs for
//! (`CERT_BLOBS` rows: one per blob), so read knows what its own store and its sources carry across
//! a restart, whoever logged it (spec/permissions.md §4: a record blob logged by any node counts).

use super::Wrap;
use crate::engine::secrets::DeleteSource;
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::memo::{Effects, Feed, Quiet, Stamped, Unrecorded};
use osis_base::format::DELETE_WRITER;
use osis_base::{BlobId, CreationRecord, SyncId, Tid};
use osis_crypto::NodeRng;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `cb/` + sync ID + blob ID: what the certificate blob carries (`encode`).
pub(crate) const CERT_BLOBS: &[u8] = b"cb/";

/// One certificate blob: what it carries, and its prefix and blind (its blob key's link blind,
/// spec/crypto.md §7), what a Delete of it by levels signs for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertBlob {
    pub tids: BTreeSet<Tid>,
    pub(crate) prefix: osis_blob::Prefix,
    pub(crate) blind: [u8; 16],
}

impl CertBlob {
    /// What blob `bytes` opened under `key` carries: `tids`. `None`: its prefix is not a
    /// certificate blob's (spec/wire.md §3: no expiry, durable, one group of one level-3
    /// commitment), so it is bad input.
    pub(crate) fn of(bytes: &[u8], key: &osis_crypto::Secret32, tids: BTreeSet<Tid>) -> Option<CertBlob> {
        let prefix = osis_blob::Prefix::parse(bytes).ok()?;
        let shape = matches!(prefix.groups(), [g] if g.len() == 1 && prefix.key_at(0, DELETE_WRITER).is_some());
        (shape && prefix.expiry().is_none() && prefix.class() == osis_blob::Class::Durable).then(|| CertBlob { tids, prefix, blind: osis_crypto::link_blind(key.expose()) })
    }
}

/// Row bytes: the blind; the prefix's length (a byte) and bytes; tids (15 bytes each).
fn encode(c: &CertBlob) -> Vec<u8> {
    let prefix = c.prefix.to_bytes();
    // one group of one commitment: far below 256 bytes
    let len = u8::try_from(prefix.len()).unwrap_or(u8::MAX);
    [c.blind.to_vec(), vec![len], prefix, c.tids.iter().flat_map(|t| *t.as_bytes()).collect()].concat()
}

fn decode(v: &[u8]) -> Option<CertBlob> {
    let (blind, rest) = v.split_at_checked(16)?;
    let (len, rest) = rest.split_first()?;
    let (prefix, tids) = rest.split_at_checked(usize::from(*len))?;
    let prefix = osis_blob::Prefix::parse(prefix).ok()?;
    let tids = tids.len().is_multiple_of(15).then(|| tids.chunks(15).filter_map(|x| x.try_into().ok().map(Tid::from_bytes)).collect::<BTreeSet<Tid>>())?;
    Some(CertBlob { tids, prefix, blind: blind.try_into().ok()? })
}

/// The certificate blobs noted here under one sync ID.
pub type CertBlobs = BTreeMap<BlobId, CertBlob>;

/// Loads the certificate blobs kept (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("certificate blob row");
    let mut rows: BTreeMap<SyncId, CertBlobs> = BTreeMap::new();
    tx.scan(CERT_BLOBS, |k, v| {
        let s = SyncId(k.get(..16).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let b = BlobId(k.get(16..48).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let c = decode(&v).ok_or_else(bad)?;
        rows.entry(s).or_default().insert(b, c);
        Ok(())
    })?;
    for (k, m) in rows {
        tx.core.ix.cert_blobs.insert(k, Arc::new(m));
    }
    Ok(())
}

fn note(tx: &mut Tx<'_>, s: &SyncId, b: &BlobId, c: CertBlob) -> Result<()> {
    let mut m = tx.core.ix.cert_blobs.get(s).map(|x| (**x).clone()).unwrap_or_default();
    if m.get(b) == Some(&c) {
        return Ok(());
    }
    tx.txn.put_local(&[CERT_BLOBS, &s.0, &b.0].concat(), &encode(&c), Shred::No)?;
    m.insert(*b, c);
    tx.core.ix.cert_blobs.insert(*s, Arc::new(m));
    Ok(())
}

impl Engine {
    /// Certificate blob `b`, opened under `s`, is `c` (`certblobs`).
    pub(crate) fn note_cert_blob(&mut self, s: &SyncId, b: &BlobId, c: CertBlob) -> Result<()> {
        if self.core.ix.cert_blobs.get(s).is_some_and(|m| m.get(b) == Some(&c)) {
            return Ok(());
        }
        let (s, b) = (*s, *b);
        self.run(|tx| note(tx, &s, &b, c))
    }

    /// What a Delete by levels of certificate blob `b` noted under `s` signs for (`DeleteBasis`):
    /// its one level-3 commitment, tried against every writer delete secret held along the
    /// record chains of `s`'s things (spec/crypto.md §7). `None`: `b` is no certificate blob
    /// noted under `s`.
    pub fn cert_delete_basis(&mut self, s: &SyncId, b: &BlobId) -> Result<Option<crate::sync::DeleteBasis>> {
        let Some(c) = self.core.ix.cert_blobs.get(s).and_then(|m| m.get(b).cloned()) else { return Ok(None) };
        let mut held = Vec::new();
        for t in self.read_things_of(s)? {
            for src in self.core.delete_chain(&t) {
                match src {
                    DeleteSource::Epochs(e) => held.extend(osis_keys::delete_candidates(DELETE_WRITER, &e, Some(&e)).into_iter().map(|(_, x)| (DELETE_WRITER, osis_crypto::DeleteSecret::write(x)))),
                    DeleteSource::KeyActor { seed, .. } => held.push((DELETE_WRITER, osis_crypto::DeleteSecret::from_seed(seed))),
                }
            }
        }
        Ok(Some(crate::sync::DeleteBasis { prefix: c.prefix, blind: c.blind, held }))
    }
}

/// Whether a certificate blob sealed under `s` is kept.
pub(crate) fn any(core: &crate::engine::Core, s: &SyncId) -> bool {
    core.ix.cert_blobs.get(s).is_some()
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

/// The row of certificate blob `b` under `s` goes (neither the own store nor a source holds it
/// any more).
pub(crate) fn forget_blob(tx: &mut Tx<'_>, s: &SyncId, b: &BlobId) -> Result<()> {
    let k = *s;
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

/// A fresh durable blob of `plain` committing to writer delete key `dk`, and its wrap under read
/// secret `w` (spec/wire.md §3: no expiry, order 0; a fresh encryption per sync ID; its blind
/// its key's link blind, spec/crypto.md §7).
fn seal_cert_blob(w: &osis_crypto::Secret32, dk: &osis_crypto::VerifyingKey, plain: &[u8], tids: BTreeSet<Tid>, rng: &mut dyn NodeRng) -> Result<(BlobId, Vec<u8>, Wrap, CertBlob)> {
    let (salt, key, blind) = osis_blob::linked_prefix_inputs(rng);
    let prefix = osis_blob::Prefix::for_keys(salt, &blind, None, &[(DELETE_WRITER, *dk)])?.with_class(osis_blob::Class::Durable);
    let (key, blob) = osis_blob::frame_under(key, &prefix, plain)?;
    let id = osis_blob::blob_id(&blob);
    let wrap = osis_crypto::wrap(w, &id, &key, 0)?;
    Ok((id, blob, wrap, CertBlob { tids, prefix, blind }))
}

/// The keys followed, taken out of `CertRecords` while they settle (their function reads the
/// engine whole).
#[derive(Clone)]
struct Followers {
    /// Per record named (`Certified::namers`), the read things naming it whose sync IDs carry it
    /// as a certificate (`Engine::cert_carriers`).
    carriers: Effects<Tid, Arc<BTreeSet<Tid>>>,
    /// The records named from the first follow on.
    named: Option<Feed<Tid>>,
    /// The follow's fixed point (`certified`'s inside it).
    quiet: Quiet,
}

impl Default for Followers {
    fn default() -> Self {
        Followers { carriers: Effects::new("sync: certificate record carriers"), named: None, quiet: Quiet::default() }
    }
}

/// Per read thing, the records its sync IDs carry as certificates (`Engine::certificate_records`),
/// followed per record: a record named, held or minted anew judges itself alone, never the other
/// records its namers name. Bounded by what is held: a row per read thing naming a record its
/// closure does not carry.
#[derive(Clone, Default)]
pub(crate) struct CertRecords {
    followers: Followers,
    /// Per record, the read things carrying it, as placed.
    carriers: BTreeMap<Tid, Arc<BTreeSet<Tid>>>,
    pub(crate) rows: Stamped<Tid, Arc<BTreeSet<Tid>>>,
    /// Whether a row moved since the running follow began.
    wrote: bool,
}

impl CertRecords {
    /// Record `x`'s carriers are `now`: the rows of the read things it came to or left.
    fn place(&mut self, x: Tid, now: Arc<BTreeSet<Tid>>) {
        let was = match now.is_empty() {
            true => self.carriers.remove(&x),
            false => self.carriers.insert(x, now.clone()),
        }
        .unwrap_or_default();
        for (t, add) in was.difference(&now).map(|t| (*t, false)).chain(now.difference(&was).map(|t| (*t, true))) {
            self.wrote = true;
            self.rows.update(t, |row| {
                let mut row = row.unwrap_or_default();
                let edit = Arc::make_mut(&mut row);
                match add {
                    true => edit.insert(x),
                    false => edit.remove(&x),
                };
                (!edit.is_empty()).then_some(row)
            });
        }
    }
}

impl Engine {
    /// The records sync ID `s` carries as certificates (spec/permissions.md §4): those its
    /// certificates name (`certified_records`) whose `created.0` no closure body there carries
    /// (a thing of the closure its actor reads, minted by no commit giving it epochs:
    /// `minted_dependent`), held here. A read of the rows of `s`'s read things alone.
    pub fn certificate_records(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<Tid>>> {
        self.follow_cert_records()?;
        let mut out = BTreeSet::new();
        for t in self.read_things_of(s)? {
            out.extend(self.core.cert_records.rows.get(&t).into_iter().flat_map(|x| x.iter().copied()));
        }
        Ok(Arc::new(out))
    }

    /// The read things naming record `x` (`Certified::namers`) whose sync IDs carry it as a
    /// certificate: held here, and no closure body of the thing carries it (`certificate_records`).
    /// Reads per (namer, `x`).
    fn cert_carriers(&mut self, x: &Tid) -> Arc<BTreeSet<Tid>> {
        // counted: tests read that a make judges the records it moved, not every record named
        osis_base::costs::count("certificate records: judged", 1);
        let namers: Vec<Tid> = self.core.certified.namers.get(x).into_iter().flat_map(|n| n.iter().copied()).collect();
        if namers.is_empty() || self.core.created(x).is_none() {
            return Arc::default();
        }
        let plain = self.minted_dependent(x);
        let mut out = BTreeSet::new();
        for t in namers {
            let ctx = self.body_ctx(&t);
            if !(plain && ctx.holds(&self.core, x) && self.reads(&ctx, x) && self.minting_opens(x, &ctx) && self.minted_above_floor(x, &t)) {
                out.insert(t);
            }
        }
        Arc::new(out)
    }

    /// Brings `Certified` and then `CertRecords` up to date with what moved since the last call:
    /// the records whose carriers' reads moved, and those named since. Whether a row of either
    /// moved.
    pub(crate) fn follow_cert_records(&mut self) -> Result<bool> {
        let f = &self.core.cert_records.followers;
        if f.quiet.holds(f.carriers.idle()) && self.certificates_quiet()? {
            return Ok(false);
        }
        let _u = Unrecorded::start();
        let from = Quiet::begin();
        let moved = self.follow_certificates()?;
        self.core.cert_records.wrote = false;
        let mut f = std::mem::take(&mut self.core.cert_records.followers);
        let came: Vec<Tid> = match f.named.as_mut() {
            Some(feed) => feed.added(),
            None => {
                f.named = Some(self.core.certified.namers.feed());
                self.core.certified.namers.keys().copied().collect()
            }
        };
        for x in came {
            f.carriers.want(x);
        }
        // followed while named; once not, again as the feed gives it
        for x in f.carriers.due() {
            let Some((_, now)) = f.carriers.settle(&x, || self.cert_carriers(&x)) else { continue };
            if now.is_empty() && self.core.certified.namers.get(&x).is_none() {
                f.carriers.unwant(&x);
            }
            self.core.cert_records.place(x, now);
        }
        f.quiet.ended(from, true);
        self.core.cert_records.followers = f;
        Ok(self.core.cert_records.wrote | moved)
    }

    /// The records read thing `t`'s sync IDs carry as certificates, derived whole
    /// (`cert_carriers` the other way): for tests.
    #[cfg(test)]
    pub(crate) fn cert_records_whole(&mut self, t: &Tid) -> Result<BTreeSet<Tid>> {
        let records = self.certified_records(t)?;
        let ctx = self.body_ctx(t);
        let mut out = BTreeSet::new();
        for x in records.iter() {
            if self.core.created(x).is_some() && !(ctx.holds(&self.core, x) && self.reads(&ctx, x) && self.minted_dependent(x) && self.minting_opens(x, &ctx) && self.minted_above_floor(x, t)) {
                out.insert(*x);
            }
        }
        Ok(out)
    }

    /// Whether a held minting of `x` lies at or above the floor of the epoch this node seals read
    /// thing `t`'s content under (spec/crypto.md §4 State at a cut): always where that floor is 0
    /// (`t` never cut). A minting below it rides only in bodies a holder granted without history
    /// never opens, so it counts as no carrier and `x`'s record goes as a certificate, beside the
    /// snapshots carrying `x`'s state. A minting of unknown floor (read in no section) counts as
    /// below.
    fn minted_above_floor(&mut self, x: &Tid, t: &Tid) -> bool {
        let Some((_, f)) = self.core.seal_epoch(t).filter(|(_, f)| *f > 0) else { return true };
        let mints: Vec<(osis_base::CommitId, usize)> = self.core.mintings(x).collect();
        let x = *x;
        self.read(|tx| {
            for (c, ai) in &mints {
                if crate::sync_ids::opened::part_floor(tx, c, *ai, &x)?.is_some_and(|p| p >= f) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .unwrap_or(false)
    }

    /// Whether the readers of `ctx`'s sync unit open the section `x` was minted in: sealed under
    /// the secret `x` derived when minted, it lists `x`'s record chain up to the actor that
    /// secret derives from, and opens from a member they hold epochs of (spec/sync-judgement.md
    /// §1): the unit's actor, or an independent thing of the unit. A thing with another record
    /// chain, reached by a strong or a grant (an account's profile reached through a contact), is minted
    /// where they open nothing, so its record goes as a certificate.
    fn minting_opens(&self, x: &Tid, ctx: &crate::sync_ids::BodyCtx) -> bool {
        let core = &self.core;
        for step in core.record_chain(x) {
            let osis_base::ChainStep::Up { admin, .. } = step else { return false };
            if admin == ctx.actor || (core.is_independent(&admin) && ctx.holds(core, &admin) && !core.destroyed(&admin)) {
                return true;
            }
            if core.is_independent(&admin) || core.is_key_actor(&admin) {
                return false;
            }
        }
        false
    }

    /// Whether no held minting of `x` gives it epochs: its own-secrets rotation carrying its record
    /// (spec/permissions.md §3) is wrapped under the derived epoch it supersedes (spec/crypto.md
    /// §5), so it carries the record to that epoch's holders alone and counts as no carrier
    /// (spec/permissions.md §4 Logging certificates).
    fn minted_dependent(&self, x: &Tid) -> bool {
        let Ok(secrets) = osis_base::Ak::new("secrets.0") else { return true };
        !self.core.mintings(x).any(|(c, _)| self.core.ix.commits.get(&c).is_some_and(|m| m.aspect(x, &secrets).is_some()))
    }

    /// Whether a record blob can be sealed under `s` now (a current read epoch of its thing to
    /// wrap under; none while, say, a rotation is owed before encrypting).
    pub fn cert_wrap(&mut self, s: &SyncId) -> Result<bool> {
        for t in self.read_things_of(s)? {
            if self.wrap_secret(&t, None)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The certificate blobs noted under `s` (sealed here or opened), each with what it carries.
    pub fn cert_blobs(&self, s: &SyncId) -> Arc<CertBlobs> {
        self.core.ix.cert_blobs.get(s).cloned().unwrap_or_default()
    }

    /// Whether `b` is a certificate blob noted under `s`: what it carries is known here, held in
    /// the own store or shown at a source (spec/permissions.md §4: it counts).
    pub fn cert_blob_noted(&self, s: &SyncId, b: &BlobId) -> bool {
        self.core.ix.cert_blobs.get(s).is_some_and(|m| m.contains_key(b))
    }

    /// One record blob of `records` (those held here) under `s` and its wrap (`seal_cert_blob`).
    /// `None` when none is held or no epoch is.
    pub fn seal_records(&mut self, s: &SyncId, records: &BTreeSet<Tid>, rng: &mut dyn NodeRng) -> Result<Option<(BlobId, Vec<u8>, Wrap)>> {
        // under the thing reading `s` whose certificates these are, else any reading it (a
        // record proves itself by its hash)
        let things = self.read_things_of(s)?;
        self.follow_cert_records()?;
        let thing = things.iter().find(|t| self.core.cert_records.rows.get(*t).is_some_and(|row| row.is_superset(records))).copied();
        let Some(t) = thing.or_else(|| things.first().copied()) else { return Ok(None) };
        let recs: Vec<osis_base::CreationRecord> = records.iter().filter_map(|x| self.core.created(x).cloned()).collect();
        if recs.is_empty() {
            return Ok(None);
        }
        let plain = osis_commit::record_blob::encode_record_blob(&recs);
        // under `t`'s current read epoch (`wrap_secret`)
        let Some(w) = self.wrap_secret(&t, None)? else { return Ok(None) };
        let Some(dk) = self.read(|tx| crate::engine::secrets::writer_delete_key_in(tx, &t))? else { return Ok(None) };
        let tids: BTreeSet<Tid> = recs.iter().map(CreationRecord::tid).collect();
        let (id, blob, wrap, c) = seal_cert_blob(&w, &dk, &plain, tids, rng)?;
        let s = *s;
        self.run(|tx| note(tx, &s, &id, c))?;
        Ok(Some((id, blob, wrap)))
    }

    /// Takes a record blob's plaintext `plain`, the plaintext of blob `b` (a record proves itself
    /// by its hash): the records something here awaits are learned, with those on their record
    /// chains; the rest are kept loose, carried by `b` (spec/commits.md §4 Pending storage), and
    /// learned once something awaits them (`Engine::promote_loose`). `None` when `plain` is no
    /// record blob.
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
/// `Thing`'s mint admin), from `batch` or the loose records.
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

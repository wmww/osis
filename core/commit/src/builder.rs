//! The commit builder (spec/commits.md §1, spec/wire.md §4).

use crate::blob::{CommitBlob, Part, Sigs};
use crate::header::{AspectEntry, DeleteKey, Form, Header, Kind, Links, ListField, PurgeItem, aspect_order, purge_bytes};
use crate::groups::{COMMIT_PAST_BLOB, blob_bound};
use crate::keys::{Prefix, Secrets, delete_keys};
use crate::lists::{BlobSink, write_list};
use crate::Error;
use osis_base::format::{CHUNK_THRESHOLD, MAX_BLOB, MAX_LIST_BYTES};
use osis_base::{Ak, BlobId, CommitId, Tid, Ts};
use osis_crypto::{CryptoRngCore, Secret32, SigningSecret, delta_hash};
use osis_schema::PurgeBy;
use crate::path::{Path, Paths, Split};
use std::collections::{BTreeMap, BTreeSet};

/// The writes of one `(tid, ak)` in a commit: one part, or one piece of a `secrets.0` written in
/// pieces (spec/wire.md §4 Pieces: several writes of it, sharing every field but the delta).
#[derive(Clone, Debug)]
pub struct AspectWrite {
    pub tid: Tid,
    pub ak: Ak,
    /// Counter range `[lo, hi)` of own writes; ignored for kinds without own writes.
    pub lo: u64,
    pub hi: u64,
    /// Canonical delta (or snapshot) bytes, encoded against [`crate::writer_ctx`].
    pub delta: Vec<u8>,
    /// Resolved purge-by ([`crate::retention`] helpers: fixed, override, schema default,
    /// untyped default; snapshot).
    pub purge_by: PurgeBy,
    /// The fire this delta claims to replace (spec/commits.md §5 Signals).
    pub replaces: Option<CommitId>,
    /// That fire's floor as the writer read it (`AspectEntry::original_floor`).
    pub original_floor: u64,
}

impl AspectWrite {
    /// One delta with untyped defaults; set the other fields as needed.
    pub fn new(tid: Tid, ak: Ak, lo: u64, hi: u64, delta: Vec<u8>) -> AspectWrite {
        AspectWrite { tid, ak, lo, hi, delta, purge_by: PurgeBy::default(), replaces: None, original_floor: 0 }
    }
}

/// Builds and signs one commit.
#[derive(Clone, Debug)]
pub struct CommitBuilder {
    pub kind: Kind,
    pub ts: Ts,
    /// The thing it is signed as (spec/wire.md §4 field 1).
    pub signer: Tid,
    /// The one path it states in the clear (spec/wire.md §4 field 2), where `split` is `None`.
    pub path: Path,
    /// The split form it states instead, where the things' own paths are not one `Path`.
    pub split: Option<SplitWrite>,
    pub form: Form,
    /// Expiry T, wall ms, of every delta ([`crate::retention::write_expires`]).
    pub expires: Option<u64>,
    pub aspects: Vec<AspectWrite>,
    pub purge: Vec<PurgeItem>,
    pub undoes: Option<CommitId>,
    /// The frontier of an explicit demotion, its commit IDs ascending and distinct (spec/permissions.md §5).
    pub frontier: Option<std::sync::Arc<[CommitId]>>,
    /// The header's blind (spec/crypto.md §7): given when taken before the build (a rotation's
    /// departs mark names it), else drawn at build.
    pub blind: Option<[u8; 16]>,
    /// The ephemeral marker (an ephemeral commit, spec/commits.md §2).
    pub ephemeral: Option<crate::header::EphClass>,
    /// The own-cover marker (spec/wire.md §4 field 14).
    pub own_cover: bool,
    /// The adminless mark (`Header::adminless`).
    pub adminless: bool,
    /// The header names the signing key (`Signer`'s second form): set where the key is not the
    /// one `signer`'s record holds.
    pub name_key: bool,
    /// The blob bound the commit is checked against: `MAX_BLOB` (tests shrink it).
    pub(crate) max_blob: usize,
}

/// The split form a commit states (spec/wire.md §4 `Split`): its purge author (`None`: the
/// signer) and, per thing it writes, the things its path lists with the hops it marks direct, and
/// the read roles secret of the thing's independent at the epoch its sections are sealed under
/// (spec/crypto.md §5 Path entry).
#[derive(Clone, Debug)]
pub struct SplitWrite {
    pub author: Option<Tid>,
    pub things: BTreeMap<Tid, ((Vec<Tid>, crate::Marks), Secret32)>,
}

/// A built commit: the blob holding every delta.
#[derive(Debug)]
pub struct Built {
    pub commit: CommitBlob,
    /// Blobs written for linked header lists; they go wherever the commit's blob goes.
    pub list_blobs: Vec<BlobId>,
    /// Its signature, by the key it was built with: verified by construction.
    pub signed: crate::Signed,
}

fn build_err(e: Error) -> Error {
    match e {
        Error::Malformed(m) | Error::Invalid(m) => Error::Build(m),
        e => e,
    }
}

impl CommitBuilder {
    pub fn new(kind: Kind, ts: Ts, signer: Tid, path: Path, form: Form) -> CommitBuilder {
        CommitBuilder { kind, ts, signer, path, split: None, form, expires: None, aspects: Vec::new(), purge: Vec::new(), undoes: None, frontier: None, blind: None, ephemeral: None, own_cover: false, adminless: false, name_key: false, max_blob: MAX_BLOB }
    }

    /// Builds the header (lists above `CHUNK_THRESHOLD` go by link through `sink`), signs it,
    /// and checks the result against every header rule and that the commit fits one blob.
    pub fn build(mut self, key: &SigningSecret, secrets: &dyn Secrets, sink: &mut dyn BlobSink, rng: &mut dyn CryptoRngCore) -> Result<Built, Error> {
        let kind = self.kind;
        let blind = self.blind.unwrap_or_else(|| {
            let mut b = [0u8; 16];
            rng.fill_bytes(&mut b);
            b
        });

        // parts in canonical order (an aspect's pieces by hash), with their delete keys and
        // delta hashes
        let mut hashed = Vec::with_capacity(self.aspects.len());
        for a in std::mem::take(&mut self.aspects) {
            let dedup = secrets.dedup(&a.tid).ok_or(Error::Build("dedup secret not supplied"))?;
            hashed.push((delta_hash(&dedup, &a.delta), a));
        }
        hashed.sort_by(|(h, a), (g, b)| (aspect_order(&a.tid, a.ak.as_str()), h).cmp(&(aspect_order(&b.tid, b.ak.as_str()), g)));
        let mut aspect_keys = Vec::with_capacity(hashed.len());
        let mut entries = Vec::with_capacity(hashed.len());
        let mut deltas = Vec::with_capacity(hashed.len());
        for (hash, a) in hashed {
            let (lo, hi) = if kind.has_own_writes() { (a.lo, a.hi) } else { (0, 0) };
            aspect_keys.push(delete_keys(secrets, &a.tid, &a.purge_by)?);
            entries.push(AspectEntry {
                tid: a.tid,
                ak: a.ak,
                lo,
                hi,
                purge_by: a.purge_by,
                keys: Vec::new(),
                hash,
                replaces: a.replaces,
                original_floor: if a.replaces.is_some() { a.original_floor } else { 0 },
            });
            deltas.push(a.delta);
        }

        // delete keys: one per distinct (level, key), in their order; an aspect's ascend with
        // its levels
        let keys: Vec<DeleteKey> = aspect_keys.iter().flatten().copied().collect::<BTreeSet<_>>().into_iter().collect();
        for (entry, ks) in entries.iter_mut().zip(&aspect_keys) {
            entry.keys = ks.iter().map(|k| keys.binary_search(k).map_err(|_| Error::Build("delete key table"))).collect::<Result<_, _>>()?;
        }
        let mut purge = std::mem::take(&mut self.purge);
        purge.sort_by_cached_key(purge_bytes);

        // one path in the clear, or the split form: an entry per thing, in aspect order, sealed
        // under the thing's path key, which the writer keeps for its encryptions
        // (spec/wire.md §4 field 2)
        let mut things: Vec<Tid> = entries.iter().map(|e| e.tid).collect();
        things.dedup();
        let mut path_keys = BTreeMap::new();
        let path = match &self.split {
            None => {
                self.path.check(&self.signer).map_err(build_err)?;
                Paths::One(self.path.clone())
            }
            Some(sw) => {
                if sw.things.len() != things.len() || things.iter().any(|t| !sw.things.contains_key(t)) {
                    return Err(Error::Build("a split path other than one per thing written"));
                }
                let mut es = Vec::with_capacity(things.len());
                for (i, t) in things.iter().enumerate() {
                    let (listed, roles) = sw.things.get(t).ok_or(Error::Build("a split path other than one per thing written"))?;
                    let key = crate::path::path_key(roles, &blind, t);
                    es.push(Split::seal(&key, &listed.0, listed.1)?);
                    path_keys.insert(i, key);
                }
                Paths::Split(Split { author: sw.author.filter(|a| *a != self.signer), entries: es })
            }
        };

        let mut header = Header {
            signer: self.signer,
            // the key named is the one that signs: a writer never names another
            key: self.name_key.then(|| osis_base::SignKey(key.verifying_key().to_bytes())),
            path,
            kind,
            ts: self.ts,
            form: self.form,
            expires: self.expires,
            aspects: entries,
            purge,
            undoes: self.undoes,
            blind,
            keys,
            frontier: self.frontier,
            links: Links::default(),
            ephemeral: self.ephemeral,
            own_cover: self.own_cover,
            adminless: self.adminless,
        };
        header.validate().map_err(build_err)?;

        // lists above the threshold go by link
        let mut list_blobs = Vec::new();
        let lists: Vec<(ListField, Vec<u8>)> = ListField::ALL.into_iter().filter_map(|f| header.list_bytes(f).map(|b| (f, b))).filter(|(_, b)| b.len() > CHUNK_THRESHOLD).collect();
        // keyed to this header alone, before any is linked (`Header::list_secret`)
        let list_key = if lists.is_empty() {
            None
        } else {
            let dedup = secrets.dedup(&self.signer).ok_or(Error::Build("dedup secret of the signer not supplied"))?;
            Some(header.list_secret_for(&dedup, &|f| lists.iter().any(|(g, _)| *g == f)))
        };
        for (f, bytes) in lists {
            // its signer's record is what a reader needs to resolve the list by: the aspect list
            // of a commit carrying it must be inline (spec/commits.md §2)
            if f == ListField::Aspects && header.aspects.iter().any(|a| a.tid == header.signer && a.ak.as_str() == crate::retention::CREATED) {
                return Err(Error::TooLarge("the aspect list of a commit carrying its signer's creation"));
            }
            // no receiver would resolve it (`Header::resolve`)
            if bytes.len() > MAX_LIST_BYTES {
                return Err(Error::TooLarge("header list"));
            }
            let Some(dedup) = &list_key else { continue };
            let mut written = Vec::new();
            let mut prefix = || {
                let mut salt = [0u8; 16];
                rng.fill_bytes(&mut salt);
                // header-list chunks and tree nodes commit to no delete key (spec/wire.md §5)
                Prefix { salt, thing: self.signer, expiry: header.expires, keys: Vec::new() }
            };
            let mut rec = Recording { sink: &mut *sink, written: &mut written };
            let link = write_list(&bytes, dedup, &mut rec, &mut prefix)?;
            list_blobs.extend(written);
            header.links.set(f, Some(link));
        }

        let id = header.id();
        let sigs = Sigs::signed(&id, key);
        let parts = deltas.into_iter().enumerate().map(|(ai, delta)| Part { ai, delta }).collect();
        let commit = CommitBlob { header, sigs, parts, keys: path_keys };
        commit.check_paths().map_err(build_err)?;
        // paging keeps deltas far below a blob; a commit whose paged roots still pass it is
        // refused here (spec/commits.md §1)
        if blob_bound(&commit) > self.max_blob {
            return Err(Error::Build(COMMIT_PAST_BLOB));
        }
        // the writer checks its own signature once before anything leaves it (outside the counted
        // costs): a signing bug or a fault in signing fails here, and a faulty Ed25519 signature
        // is never published (it can leak the key)
        let signed = osis_base::costs::paused(|| crate::verify_signature(&id, &commit.sigs, &key.verifying_key()).ok());
        let Some(signed) = signed else { return Err(Error::Build("a commit signature that does not verify")) };
        Ok(Built { commit, list_blobs, signed })
    }
}

/// Records the blobs a tree write puts.
struct Recording<'a> {
    sink: &'a mut dyn BlobSink,
    written: &'a mut Vec<BlobId>,
}

impl BlobSink for Recording<'_> {
    fn put(&mut self, prefix: &Prefix, plaintext: &[u8]) -> Result<(BlobId, [u8; 32]), Error> {
        let r = self.sink.put(prefix, plaintext)?;
        self.written.push(r.0);
        Ok(r)
    }
}

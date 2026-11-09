//! The commit builder (spec/commits.md §1, spec/wire.md §4).

use crate::blob::{CommitBlob, Part, Sigs};
use crate::header::{AspectEntry, ChunkEntry, DeleteKey, Form, Header, Kind, Links, ListField, PurgeItem, RotationHeader, aspect_key, key_value, purge_value};
use crate::groups::check_fits;
use crate::keys::{Prefix, Secrets, delete_keys};
use crate::lists::{BlobSink, write_list};
use osis_base::format::MAX_LIST_BYTES;
use crate::Error;
use osis_base::format::{CHUNK_THRESHOLD, DELETE_AUTHOR, FORMAT_VERSION, MAX_BLOB};
use osis_base::{Ak, BlobId, CommitId, Tid, Ts, Value};
use osis_crypto::{CryptoRngCore, Domain, Secret32, SigningSecret, delta_hash, seal_inner};
use osis_schema::Retention;
use std::collections::BTreeMap;

/// The writes of one `(tid, ak)` in a commit.
#[derive(Clone, Debug)]
pub struct AspectWrite {
    pub tid: Tid,
    pub ak: Ak,
    /// Counter range `[lo, hi)` of own writes; ignored for kinds without own writes.
    pub lo: u64,
    pub hi: u64,
    /// Canonical delta (or snapshot) bytes, encoded against [`crate::writer_ctx`].
    pub delta: Vec<u8>,
    /// Resolved retention ([`crate::retention`] helpers: fixed, override, schema default,
    /// untyped default; snapshot).
    pub retention: Retention,
    /// Chunk, tree-node and page blobs the deltas introduce (framed with this aspect's delete
    /// keys, [`delete_keys`]).
    pub chunks: Vec<BlobId>,
}

impl AspectWrite {
    /// One delta with untyped defaults; set the other fields as needed.
    pub fn new(tid: Tid, ak: Ak, lo: u64, hi: u64, delta: Vec<u8>) -> AspectWrite {
        AspectWrite { tid, ak, lo, hi, delta, retention: Retention::default(), chunks: Vec::new() }
    }
}

/// Builds and signs one commit.
#[derive(Clone, Debug)]
pub struct CommitBuilder {
    pub kind: Kind,
    pub ts: Ts,
    /// The signing key actor: an account, or a key actor other than an account signing as
    /// itself.
    pub author: Tid,
    /// The actor it acts for.
    pub actor: Tid,
    pub form: Form,
    /// Expiry T, wall ms, of every delta ([`crate::retention::write_expires`]).
    pub expires: Option<u64>,
    pub aspects: Vec<AspectWrite>,
    pub purge: Vec<PurgeItem>,
    pub undoes: Option<CommitId>,
    /// The frontier value of an explicit demotion (spec/permissions.md §5).
    pub frontier: Option<Value>,
    /// The header's blind (spec/crypto.md §7): given when chunks were framed under it, else
    /// drawn at build.
    pub blind: Option<[u8; 16]>,
    /// The ephemeral marker (an ephemeral commit, spec/commits.md §2).
    pub ephemeral: Option<crate::header::EphClass>,
    /// An account author's epoch and inner signer (spec/wire.md §4): `build`'s key is then the
    /// epoch's signing key.
    pub account: Option<AccountSigner>,
    /// A rotation of the account's signing chain, with a key per fork it names (in that
    /// order) signing the merge at that fork's epoch.
    pub rotation: Option<(RotationHeader, Vec<SigningSecret>)>,
    /// The blob bound each delta is checked against: `MAX_BLOB` (tests shrink it).
    pub(crate) max_blob: usize,
}

/// What an account's commit carries besides its epoch's signature (spec/wire.md §4): the epoch,
/// and the node signing it with that epoch's inner secret.
#[derive(Clone, Debug)]
pub struct AccountSigner {
    pub epoch: CommitId,
    pub inner: Secret32,
    pub node: Tid,
    pub node_key: SigningSecret,
}

/// A built commit: the blob holding every delta.
#[derive(Debug)]
pub struct Built {
    pub commit: CommitBlob,
    /// Blobs written for linked header lists; they go wherever the commit's blob goes.
    pub list_blobs: Vec<BlobId>,
}

fn build_err(e: Error) -> Error {
    match e {
        Error::Malformed(m) | Error::Invalid(m) => Error::Build(m),
        e => e,
    }
}

impl CommitBuilder {
    pub fn new(kind: Kind, ts: Ts, author: Tid, actor: Tid, form: Form) -> CommitBuilder {
        CommitBuilder { kind, ts, author, actor, form, expires: None, aspects: Vec::new(), purge: Vec::new(), undoes: None, frontier: None, blind: None, ephemeral: None, account: None, rotation: None, max_blob: MAX_BLOB }
    }

    /// Builds the header (lists above `CHUNK_THRESHOLD` go by link through `sink`), signs it,
    /// and checks the result against every header rule and that each delta fits a blob.
    pub fn build(mut self, key: &SigningSecret, secrets: &dyn Secrets, sink: &mut dyn BlobSink, rng: &mut dyn CryptoRngCore) -> Result<Built, Error> {
        let kind = self.kind;
        let blind = self.blind.unwrap_or_else(|| {
            let mut b = [0u8; 16];
            rng.fill_bytes(&mut b);
            b
        });

        // aspects in canonical order, with their delete keys and delta hashes
        self.aspects.sort_by_cached_key(|a| aspect_key(&a.tid, &a.ak));
        let mut aspect_keys = Vec::with_capacity(self.aspects.len());
        let mut entries = Vec::with_capacity(self.aspects.len());
        let mut deltas = Vec::with_capacity(self.aspects.len());
        for a in std::mem::take(&mut self.aspects) {
            let dedup = secrets.dedup(&a.tid).ok_or(Error::Build("dedup secret not supplied"))?;
            let hash = delta_hash(&dedup, &a.delta);
            let (lo, hi) = if kind.has_own_writes() { (a.lo, a.hi) } else { (0, 0) };
            aspect_keys.push(delete_keys(secrets, &a.tid, &a.retention)?);
            entries.push((
                AspectEntry {
                    tid: a.tid,
                    ak: a.ak,
                    lo,
                    hi,
                    retention: a.retention,
                    keys: Vec::new(),
                    hash,
                },
                a.chunks,
            ));
            deltas.push(a.delta);
        }

        // delete keys: one per distinct (level, key), sorted by canonical bytes
        let mut table: BTreeMap<Vec<u8>, DeleteKey> = BTreeMap::new();
        for k in aspect_keys.iter().flatten() {
            table.insert(osis_base::encode(&key_value(k)), *k);
        }
        let keys: Vec<DeleteKey> = table.into_values().collect();
        let positions: BTreeMap<DeleteKey, usize> = keys.iter().enumerate().map(|(i, t)| (*t, i)).collect();
        let mut chunks = Vec::new();
        for ((entry, cs), ks) in entries.iter_mut().zip(&aspect_keys) {
            let mut idx = ks.iter().map(|k| positions.get(k).copied().ok_or(Error::Build("delete key table"))).collect::<Result<Vec<_>, _>>()?;
            idx.sort_unstable();
            for blob in cs.iter() {
                chunks.push(ChunkEntry { blob: *blob, keys: idx.clone() });
            }
            entry.keys = idx;
        }
        chunks.sort_by_key(|c| c.blob);
        let mut purge = std::mem::take(&mut self.purge);
        purge.sort_by_cached_key(|p| osis_base::encode(&purge_value(p)));

        let mut header = Header {
            version: FORMAT_VERSION,
            author: self.author,
            actor: self.actor,
            kind,
            ts: self.ts,
            form: self.form,
            expires: self.expires,
            aspects: entries.into_iter().map(|e| e.0).collect(),
            chunks,
            purge,
            undoes: self.undoes,
            blind,
            keys,
            frontier: self.frontier,
            links: Links::default(),
            ephemeral: self.ephemeral,
            epoch: self.account.as_ref().map(|a| a.epoch),
            rotation: self.rotation.as_ref().map(|r| r.0.clone()),
        };
        if self.rotation.as_ref().is_some_and(|(r, keys)| r.names.len() != keys.len()) {
            return Err(Error::Build("a merge signature per named fork"));
        }
        header.validate().map_err(build_err)?;

        // lists above the threshold go by link
        let mut list_blobs = Vec::new();
        // header-list chunks and tree nodes: the commit's level-2 key only (spec/wire.md §5)
        let list_keys: Vec<DeleteKey> = header.keys.iter().filter(|k| k.level == DELETE_AUTHOR).copied().collect();
        for f in ListField::ALL {
            let Some(v) = header.list_value(f) else { continue };
            let bytes = osis_base::encode(&v);
            if bytes.len() <= CHUNK_THRESHOLD {
                continue;
            }
            // its author's record is what a reader needs to resolve the list by: the aspect list
            // of a commit carrying it must be inline (spec/commits.md §2)
            if f == ListField::Aspects && header.aspects.iter().any(|a| a.tid == header.author && a.ak.as_str() == crate::retention::CREATED) {
                return Err(Error::TooLarge("the aspect list of a commit carrying its author's creation"));
            }
            // no receiver would resolve it (`Header::resolve`)
            if bytes.len() > MAX_LIST_BYTES {
                return Err(Error::TooLarge("header list"));
            }
            let dedup = secrets.dedup(&self.actor).ok_or(Error::Build("dedup secret of the actor not supplied"))?;
            let mut written = Vec::new();
            let mut prefix = || {
                let mut salt = [0u8; 16];
                rng.fill_bytes(&mut salt);
                Prefix { salt, blind, expiry: header.expires, keys: list_keys.clone() }
            };
            let mut rec = Recording { sink: &mut *sink, written: &mut written };
            let link = write_list(&bytes, &dedup, &mut rec, &mut prefix)?;
            list_blobs.extend(written);
            header.links.set(f, Some(link));
        }

        let id = header.id();
        let inner = self.account.as_ref().map(|a| seal_inner(&a.inner, &id.0, &a.node, &a.node_key));
        let merge = self.rotation.iter().flat_map(|(_, keys)| keys.iter().map(|k| k.sign(Domain::Merge, &id.0))).collect();
        let sigs = Sigs::signed(&id, key, inner, merge);
        let parts = deltas.into_iter().enumerate().map(|(ai, delta)| Part { ai, delta }).collect();
        let commit = CommitBlob { header, sigs, parts };
        check_fits(&commit, self.max_blob)?;
        Ok(Built { commit, list_blobs })
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

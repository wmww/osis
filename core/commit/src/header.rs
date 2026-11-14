//! Commit header: types, canonical encoding, commit ID, signature (spec/wire.md §4,
//! spec/commits.md §1, spec/crypto.md §2).

use crate::Error;
use crate::cbor::item;
use osis_base::cbor::{Item, encode_into, put_array, put_bytes, put_link, put_text, put_uint};
use osis_base::format::{CHUNK_THRESHOLD, DELETE_ADMIN, DELETE_WRITER, FORMAT_VERSION, MAX_BLOB, MAX_OBJECT_DEPTH, TAG_SET, TID_LEN};
use osis_base::{Ak, CommitId, Limits, Link, Reader, Tid, Ts, Value};
use osis_crdt::DeltaKind;
use osis_base::SIGNING_KEY_ED25519;
use osis_crypto::{Domain, KemPublicKey, Signature, VerifyingKey};
use osis_schema::{PurgeBy, Retention};

/// Decoder limits of commit structures (spec/wire.md §13).
pub(crate) const LIMITS: Limits = Limits { max_depth: MAX_OBJECT_DEPTH, max_bytes: MAX_BLOB };
// `until` meaning forever (spec/wire.md §4).
pub const FOREVER: u64 = osis_schema::FOREVER;

/// Header `kind` (spec/wire.md §4, spec/commits.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Content = 0,
    Role = 1,
    ContentSnapshot = 2,
    RoleSnapshot = 3,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::Content, Kind::Role, Kind::ContentSnapshot, Kind::RoleSnapshot];
    pub fn id(self) -> u64 {
        self as u64
    }
    pub fn from_id(id: u64) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.id() == id)
    }
    /// Deltas only on role-class aspects.
    pub fn is_role(self) -> bool {
        matches!(self, Kind::Role | Kind::RoleSnapshot)
    }
    /// Carries own writes (a counter range); compaction snapshots do not.
    pub fn has_own_writes(self) -> bool {
        !self.is_compaction()
    }
    /// Compaction snapshot.
    pub fn is_compaction(self) -> bool {
        matches!(self, Kind::ContentSnapshot | Kind::RoleSnapshot)
    }
    /// How osis-crdt reads this kind's deltas (spec/crdt.md §2.4).
    pub fn delta_kind(self) -> DeltaKind {
        if self.is_compaction() { DeltaKind::Snapshot } else { DeltaKind::Writer }
    }
}

/// The header's ephemeral marker (spec/commits.md §1, §2; spec/wire.md §4): an ephemeral
/// commit holding state (`Plain`) or a relay-only one carrying ephemeral signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EphClass {
    Plain = 0,
    Relay = 1,
}

impl EphClass {
    pub fn from_id(id: u64) -> Option<EphClass> {
        [EphClass::Plain, EphClass::Relay].into_iter().find(|c| *c as u64 == id)
    }
}

/// Dot form (spec/commits.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Form {
    Commit,
    /// Session form: dots `(Session(author, nonce), counter)`, counters per (aspect, session);
    /// every content commit with own writes, durable or memory.
    Session([u8; osis_crdt::SESSION_NONCE_LEN]),
}

impl Form {
    /// The own source of a commit of this form by `author` (`commit` for commit form).
    pub fn own_source(&self, author: Tid, commit: CommitId) -> osis_crdt::Source {
        match self {
            Form::Commit => osis_crdt::Source::commit(commit),
            Form::Session(nonce) => osis_crdt::Source::session(osis_crdt::Session { node: author, nonce: *nonce }),
        }
    }

    /// Counters per (aspect, source), contiguous: session form.
    pub fn counted(&self) -> bool {
        !matches!(self, Form::Commit)
    }

    fn put(&self, out: &mut Vec<u8>) {
        match self {
            Form::Commit => put_uint(out, 0),
            Form::Session(n) => {
                put_array(out, 2);
                put_uint(out, 1);
                put_bytes(out, n);
            }
        }
    }

    fn read(v: Item) -> Result<Form, Error> {
        if let Some(l) = v.as_list() {
            return match l.tuple() {
                Some([k, n]) if item::uint(k)? == 1 => Ok(Form::Session(item::bytes(n)?)),
                _ => Err(Error::Malformed("dot form")),
            };
        }
        match item::uint(v)? {
            0 => Ok(Form::Commit),
            _ => Err(Error::Malformed("dot form")),
        }
    }
}

/// One touched `(tid, ak)` (spec/wire.md §4 `Aspect`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AspectEntry {
    pub tid: Tid,
    pub ak: Ak,
    /// Counter range `[lo, hi)`; `0, 0` for kinds without own writes.
    pub lo: u64,
    pub hi: u64,
    pub retention: Retention,
    /// Ascending indices into the header's delete keys.
    pub keys: Vec<usize>,
    /// The delta hash of the aspect's one delta.
    pub hash: [u8; 32],
    /// The fire this delta claims to replace (a durable signal's, spec/commits.md §5 Signals).
    pub replaces: Option<CommitId>,
    /// The floor of that fire as its writer read it (spec/commits.md §5 Signals): a node whose
    /// own floor on the thing's actor is above it lists the delta nowhere. 0 without `replaces`.
    pub original_floor: u64,
}

/// A delete key with its level (spec/crypto.md §7); a valid Ed25519 key once decoded. Its order
/// (level, then key) is that of its canonical bytes, the header's key order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeleteKey {
    pub level: u8,
    pub key: [u8; 32],
}

impl DeleteKey {
    pub fn new(level: u8, key: &VerifyingKey) -> DeleteKey {
        DeleteKey { level, key: key.to_bytes() }
    }
    pub fn verifying_key(&self) -> Result<VerifyingKey, Error> {
        VerifyingKey::from_bytes(&self.key).map_err(|_| Error::Malformed("delete key"))
    }
}

/// A purge request item (spec/wire.md §4).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PurgeItem {
    /// The delta on that aspect of the commit stamped `ts` whose own writes are `src`'s (its session,
    /// or a commit-form commit's ID): one commit per stamp and source on an aspect, so it names
    /// that commit's delta where its header is not held too (spec/commits.md §5 Purge).
    Commit { tid: Tid, ak: Ak, ts: Ts, src: osis_crdt::Source },
    /// Every delta on that aspect of every commit with a smaller `ts`.
    Aspect { tid: Tid, ak: Ak },
    /// Every delta on that aspect of every commit with a smaller `ts` whose header actor is
    /// `actor`.
    Author { tid: Tid, ak: Ak, actor: Tid },
}

/// The index of the entry on `(tid, ak)` in `items`, sorted and distinct as a header's aspects
/// are (spec/wire.md §4: by the canonical bytes of `[tid, ak]`, which order by tid, then by the
/// key's length, then its bytes): a search.
pub fn aspect_position<T>(items: &[T], tid: &Tid, ak: &str, key: impl Fn(&T) -> (&Tid, &str)) -> Option<usize> {
    let want = aspect_order(tid, ak);
    items
        .binary_search_by(|x| {
            let (t, a) = key(x);
            aspect_order(t, a).cmp(&want)
        })
        .ok()
}

/// The aspect sort key: orders as the canonical bytes of `[tid, ak]` do.
pub(crate) fn aspect_order<'a>(tid: &'a Tid, ak: &'a str) -> (&'a Tid, usize, &'a [u8]) {
    (tid, ak.len(), ak.as_bytes())
}

/// The indexes of the entries on `tid` in `items`, sorted as `aspect_position` reads them.
pub fn aspects_on<T>(items: &[T], tid: &Tid, key: impl Fn(&T) -> &Tid) -> std::ops::Range<usize> {
    items.partition_point(|x| key(x) < tid)..items.partition_point(|x| key(x) <= tid)
}

impl Header {
    /// The index of its aspect `(tid, ak)` (`aspect_position`).
    pub fn aspect_index(&self, tid: &Tid, ak: &str) -> Option<usize> {
        aspect_position(&self.aspects, tid, ak, |a| (&a.tid, a.ak.as_str()))
    }

    /// The indexes of its aspects on `tid` (`aspects_on`).
    pub fn aspects_on(&self, tid: &Tid) -> std::ops::Range<usize> {
        aspects_on(&self.aspects, tid, |a| &a.tid)
    }

    /// Whether this commit is a release request: it carries `released.0` deltas (`validate`: those
    /// alone; spec/commits.md §5 Destruction).
    pub fn is_release(&self) -> bool {
        self.aspects.iter().any(|a| a.ak.as_str() == crate::retention::RELEASED)
    }

    /// The items of the commit's request (spec/commits.md §5): its purge field, or for a release
    /// an item on `created.0` of each thing it has a `released.0` delta on, which destroys the thing
    /// as a purge of its creation does.
    pub fn requests(&self) -> std::borrow::Cow<'_, [PurgeItem]> {
        if !self.is_release() {
            return std::borrow::Cow::Borrowed(&self.purge);
        }
        let Ok(created) = Ak::new(crate::retention::CREATED) else { return std::borrow::Cow::Borrowed(&[]) };
        std::borrow::Cow::Owned(self.aspects.iter().map(|a| PurgeItem::Aspect { tid: a.tid, ak: created.clone() }).collect())
    }

    /// Whether the commit carries a request (`requests`).
    pub fn has_request(&self) -> bool {
        !self.purge.is_empty() || self.is_release()
    }
}

impl PurgeItem {
    pub fn tid(&self) -> &Tid {
        match self {
            PurgeItem::Commit { tid, .. } | PurgeItem::Aspect { tid, .. } | PurgeItem::Author { tid, .. } => tid,
        }
    }
    pub fn ak(&self) -> &Ak {
        match self {
            PurgeItem::Commit { ak, .. } | PurgeItem::Aspect { ak, .. } | PurgeItem::Author { ak, .. } => ak,
        }
    }
}

/// The header lists that may go by link (spec/wire.md §4, "Inline or link").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListField {
    Aspects,
    Purge,
    Keys,
    Frontier,
}

impl ListField {
    pub const ALL: [ListField; 4] = [ListField::Aspects, ListField::Purge, ListField::Keys, ListField::Frontier];
}

/// Root links of the lists that go by link; `None` = inline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Links {
    pub aspects: Option<Link>,
    pub purge: Option<Link>,
    pub keys: Option<Link>,
    pub frontier: Option<Link>,
}

impl Links {
    pub fn get(&self, f: ListField) -> Option<&Link> {
        match f {
            ListField::Aspects => self.aspects.as_ref(),
            ListField::Purge => self.purge.as_ref(),
            ListField::Keys => self.keys.as_ref(),
            ListField::Frontier => self.frontier.as_ref(),
        }
    }
    pub fn set(&mut self, f: ListField, l: Option<Link>) {
        let slot = match f {
            ListField::Aspects => &mut self.aspects,
            ListField::Purge => &mut self.purge,
            ListField::Keys => &mut self.keys,
            ListField::Frontier => &mut self.frontier,
        };
        *slot = l;
    }
}

/// A commit header (spec/wire.md §4 `Header`). A list that goes by link is empty until
/// [`Header::resolve`](crate::Header::resolve) fills it; its link stays in `links`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub author: Tid,
    pub actor: Tid,
    pub kind: Kind,
    pub ts: Ts,
    pub form: Form,
    /// The commit's expiry T, wall ms (spec/commits.md §6): every delta of it expires then.
    pub expires: Option<u64>,
    pub aspects: Vec<AspectEntry>,
    pub purge: Vec<PurgeItem>,
    pub undoes: Option<CommitId>,
    /// 16 random bytes blinding the commitments of every blob of the commit (spec/crypto.md §7).
    pub blind: [u8; 16],
    pub keys: Vec<DeleteKey>,
    /// The frontier value (spec/data-model.md §9), typed by osis-perm.
    pub frontier: Option<Value>,
    pub links: Links,
    /// Set on an ephemeral commit (kept in memory by every node, never stored).
    pub ephemeral: Option<EphClass>,
    /// The epoch an account author signs at (spec/crypto.md §9): its minting rotation's commit
    /// ID, `FIRST_EPOCH` for the first. Present iff the author is an account (judged by the
    /// author's creation record).
    pub epoch: Option<CommitId>,
    /// A rotation of the account's signing chain (spec/wire.md §4): only on an account's role
    /// commit. Its commit ID names the epoch it mints.
    pub rotation: Option<RotationHeader>,
}

/// The first epoch of every account's signing chain, named by 32 zero bytes (spec/crypto.md §9).
pub const FIRST_EPOCH: CommitId = CommitId([0; 32]);

/// A header's `rotation` (spec/wire.md §4 `Rotation`): the new epoch's public keys, the epochs it
/// supersedes (the header's `epoch` among them), the fork rotations it names (a merge), and the
/// root of its list tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationHeader {
    pub signing_key: VerifyingKey,
    pub kem_key: KemPublicKey,
    /// Ascending, distinct.
    pub supersedes: Vec<CommitId>,
    /// Ascending, distinct.
    pub names: Vec<CommitId>,
    pub list_root: [u8; 32],
}

impl RotationHeader {
    fn put(&self, out: &mut Vec<u8>) {
        let ids = |out: &mut Vec<u8>, v: &[CommitId]| {
            put_array(out, v.len());
            v.iter().for_each(|c| put_bytes(out, &c.0));
        };
        put_array(out, 5);
        encode_into(&Value::Enum(SIGNING_KEY_ED25519, Some(Box::new(Value::bytes(&self.signing_key.to_bytes())))), out);
        encode_into(&self.kem_key.to_value(), out);
        ids(out, &self.supersedes);
        ids(out, &self.names);
        put_bytes(out, &self.list_root);
    }

    fn read(v: Item) -> Result<RotationHeader, Error> {
        let Some([sk, kem, sup, names, root]) = item::list(v)?.tuple() else { return Err(Error::Malformed("rotation arity")) };
        let signing_key = match sk.to_value()? {
            Value::Enum(SIGNING_KEY_ED25519, Some(b)) => match b.as_ref() {
                Value::Bytes(k) => VerifyingKey::from_slice(k).map_err(|_| Error::Malformed("rotation signing key"))?,
                _ => return Err(Error::Malformed("rotation signing key")),
            },
            _ => return Err(Error::Malformed("rotation signing key")),
        };
        let kem_key = KemPublicKey::from_value(&kem.to_value()?).map_err(|_| Error::Malformed("rotation kem key"))?;
        let ids = |v: Item| -> Result<Vec<CommitId>, Error> { item::list(v)?.iter().map(|c| item::bytes(c).map(CommitId)).collect() };
        Ok(RotationHeader { signing_key, kem_key, supersedes: ids(sup)?, names: ids(names)?, list_root: item::bytes(root)? })
    }
}

// ---- encode

fn put_tid_bytes(out: &mut Vec<u8>, t: &Tid) {
    put_bytes(out, t.as_bytes());
}

fn put_idxs(out: &mut Vec<u8>, v: &[usize]) {
    put_array(out, v.len());
    v.iter().for_each(|i| put_uint(out, *i as u64));
}

fn put_aspect(out: &mut Vec<u8>, a: &AspectEntry) {
    put_array(out, 8);
    put_tid_bytes(out, &a.tid);
    put_text(out, a.ak.as_str());
    put_uint(out, a.lo);
    put_uint(out, a.hi);
    put_uint(out, a.retention.by as u64);
    put_idxs(out, &a.keys);
    put_bytes(out, &a.hash);
    // `[]`, `[id]`, or `[id, floor]` with the floor above 0 (spec/wire.md §4)
    match a.replaces {
        None => put_array(out, 0),
        Some(c) => {
            put_array(out, if a.original_floor > 0 { 2 } else { 1 });
            put_bytes(out, &c.0);
            if a.original_floor > 0 {
                put_uint(out, a.original_floor);
            }
        }
    }
}

fn put_key(out: &mut Vec<u8>, t: &DeleteKey) {
    put_array(out, 2);
    put_uint(out, u64::from(t.level));
    put_bytes(out, &t.key);
}

fn put_purge(out: &mut Vec<u8>, p: &PurgeItem) {
    match p {
        PurgeItem::Commit { tid, ak, ts, src } => {
            put_array(out, 4);
            put_tid_bytes(out, tid);
            put_text(out, ak.as_str());
            put_uint(out, ts.to_u64());
            match src.kind() {
                osis_crdt::SourceKind::Session(s) => put_bytes(out, &s.to_bytes()),
                osis_crdt::SourceKind::Commit(c) => put_bytes(out, &c.0),
                osis_crdt::SourceKind::Derived(_) => put_bytes(out, &[]),
            }
        }
        PurgeItem::Aspect { tid, ak } => {
            put_array(out, 2);
            put_tid_bytes(out, tid);
            put_text(out, ak.as_str());
        }
        PurgeItem::Author { tid, ak, actor } => {
            put_array(out, 3);
            put_tid_bytes(out, tid);
            put_text(out, ak.as_str());
            put_tid_bytes(out, actor);
        }
    }
}

/// Canonical bytes of a purge item, its sort key.
pub(crate) fn purge_bytes(p: &PurgeItem) -> Vec<u8> {
    let mut out = Vec::new();
    put_purge(&mut out, p);
    out
}

/// `Opt(X)` of `x`, written by `put`.
fn put_opt<T>(out: &mut Vec<u8>, x: Option<T>, put: impl FnOnce(&mut Vec<u8>, T)) {
    put_array(out, usize::from(x.is_some()));
    if let Some(x) = x {
        put(out, x);
    }
}

impl Header {
    /// Appends list `f` (or the frontier's value) as it would sit inline; false for an absent
    /// frontier.
    fn put_list(&self, out: &mut Vec<u8>, f: ListField) -> bool {
        match f {
            ListField::Aspects => {
                put_array(out, self.aspects.len());
                self.aspects.iter().for_each(|a| put_aspect(out, a));
            }
            ListField::Purge => {
                put_array(out, self.purge.len());
                self.purge.iter().for_each(|p| put_purge(out, p));
            }
            ListField::Keys => {
                put_array(out, self.keys.len());
                self.keys.iter().for_each(|k| put_key(out, k));
            }
            ListField::Frontier => match &self.frontier {
                Some(v) => encode_into(v, out),
                None => return false,
            },
        }
        true
    }

    /// The canonical bytes of list `f` (or the frontier's value) as it would sit inline; `None`
    /// for an absent frontier.
    pub fn list_bytes(&self, f: ListField) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        self.put_list(&mut out, f).then_some(out)
    }

    fn put_position(&self, out: &mut Vec<u8>, f: ListField) {
        match (f, self.links.get(f)) {
            (ListField::Frontier, Some(l)) => {
                put_array(out, 1);
                put_link(out, l);
            }
            (ListField::Frontier, None) => put_opt(out, self.frontier.as_ref(), |out, v| encode_into(v, out)),
            (_, Some(l)) => put_link(out, l),
            (_, None) => {
                self.put_list(out, f);
            }
        }
    }

    /// Canonical bytes of the header.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        put_array(out, 16);
        put_uint(out, FORMAT_VERSION);
        put_tid_bytes(out, &self.author);
        put_tid_bytes(out, &self.actor);
        put_uint(out, self.kind.id());
        put_uint(out, self.ts.to_u64());
        self.form.put(out);
        put_opt(out, self.expires, put_uint);
        self.put_position(out, ListField::Aspects);
        self.put_position(out, ListField::Purge);
        put_opt(out, self.undoes, |out, c| put_bytes(out, &c.0));
        put_bytes(out, &self.blind);
        self.put_position(out, ListField::Keys);
        self.put_position(out, ListField::Frontier);
        put_opt(out, self.ephemeral, |out, c| put_uint(out, c as u64));
        put_opt(out, self.epoch, |out, c| put_bytes(out, &c.0));
        put_opt(out, self.rotation.as_ref(), |out, r| r.put(out));
    }

    /// Commit ID = BLAKE3(canonical header bytes).
    pub fn id(&self) -> CommitId {
        CommitId(osis_base::hash::hash(&self.encode()))
    }

    /// Whether every linked list has been resolved.
    pub fn is_resolved(&self) -> bool {
        ListField::ALL.into_iter().all(|f| self.links.get(f).is_none() || !self.list_is_empty(f))
    }

    pub(crate) fn list_is_empty(&self, f: ListField) -> bool {
        match f {
            ListField::Aspects => self.aspects.is_empty(),
            ListField::Purge => self.purge.is_empty(),
            ListField::Keys => self.keys.is_empty(),
            ListField::Frontier => self.frontier.is_none(),
        }
    }
}

/// Verifies the author's signature of `sigs` for commit `id` (spec/crypto.md §2): what it
/// vouches for, kept with the commit so the same bytes are never checked again.
pub fn verify_signature(id: &CommitId, sigs: &crate::Sigs, key: &VerifyingKey) -> Result<Signed, Error> {
    key.verify(Domain::Commit, &sigs.digest(id), &sigs.signature).map_err(|_| Error::BadSignature)?;
    Ok(Signed::of(id, sigs, key))
}

/// A commit signature that verified: the hash of the key, the digest it signs (the commit ID,
/// with an account's inner and merge signatures) and the signature bytes. It vouches only for
/// those exact bytes under that exact key (`vouches`): a copy of the commit with other signature
/// bytes, or the same bytes judged under another key, is not covered. Made only by
/// `verify_signature`, by the signer (`Built::signed`), or read back from where one was kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Signed([u8; 32]);

impl Signed {
    pub(crate) fn of(id: &CommitId, sigs: &crate::Sigs, key: &VerifyingKey) -> Signed {
        let mut b = Vec::with_capacity(32 + 32 + 64);
        b.extend_from_slice(key.as_bytes());
        b.extend_from_slice(&sigs.digest(id));
        b.extend_from_slice(&sigs.signature.0);
        Signed(osis_base::hash::hash(&b))
    }

    /// Whether this is the verdict on `sigs` of commit `id` under `key`.
    pub fn vouches(&self, id: &CommitId, sigs: &crate::Sigs, key: &VerifyingKey) -> bool {
        *self == Signed::of(id, sigs, key)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// One kept by this node (`to_bytes`): never bytes a peer sent.
    pub fn from_kept(b: [u8; 32]) -> Signed {
        Signed(b)
    }
}

/// Verifies a merge's signature at a fork's epoch, by the key that fork mints (spec/crypto.md §9).
pub fn verify_merge(id: &CommitId, sig: &Signature, fork_key: &VerifyingKey) -> bool {
    fork_key.verify(Domain::Merge, &id.0, sig).is_ok()
}

// ---- decode

// Lists are read by shape, nothing built that the bytes do not pay for. `decode` of hostile bytes
// costs about 56 B per byte, too much at `MAX_LIST_BYTES` (`Header::resolve`).

// About the fewest bytes an item takes: what a list reserves for by its count, so a count the bytes
// cannot pay for reserves nothing. A wrong value only costs a reallocation.
const MIN_ASPECT: usize = 58;
const MIN_PURGE: usize = 20;
const MIN_KEY: usize = 35;
const MIN_ID: usize = 33;

/// An array of items in strictly ascending bytes, a rule every list of a header keeps. So a repeated
/// chunk of a list ends the read where it starts, and `Vec<usize>` indices cost at most what their
/// bytes do, whatever the count.
fn read_items<'a, T>(r: &mut Reader<'a>, min_item: usize, mut item: impl FnMut(&mut Reader<'a>) -> Result<T, Error>) -> Result<Vec<T>, Error> {
    let n = r.array()?;
    let mut out = Vec::with_capacity(n.min(r.remaining() / min_item));
    let mut prev: &[u8] = &[];
    for _ in 0..n {
        let start = r.pos();
        out.push(item(r)?);
        let raw = r.since(start);
        if raw <= prev {
            return Err(Error::Malformed("list items not sorted and distinct"));
        }
        prev = raw;
    }
    Ok(out)
}

fn read_tid(r: &mut Reader<'_>) -> Result<Tid, Error> {
    Ok(Tid::from_bytes(r.fixed::<TID_LEN>()?))
}

fn read_ak(r: &mut Reader<'_>) -> Result<Ak, Error> {
    Ak::new(r.text()?).map_err(|_| Error::Malformed("aspect key"))
}

fn read_idxs(r: &mut Reader<'_>) -> Result<Vec<usize>, Error> {
    read_items(r, 1, |r| usize::try_from(r.uint()?).map_err(|_| Error::Malformed("index too large")))
}

fn read_retention(r: &mut Reader<'_>) -> Result<Retention, Error> {
    let by = PurgeBy::from_id(r.uint()?).ok_or(Error::Malformed("purgeable-by class"))?;
    Ok(Retention { by })
}

fn read_aspect(r: &mut Reader<'_>) -> Result<AspectEntry, Error> {
    if r.array()? != 8 {
        return Err(Error::Malformed("aspect arity"));
    }
    let (tid, ak, lo, hi) = (read_tid(r)?, read_ak(r)?, r.uint()?, r.uint()?);
    let (retention, keys) = (read_retention(r)?, read_idxs(r)?);
    let hash = r.fixed::<32>()?;
    let (replaces, original_floor) = match r.array()? {
        0 => (None, 0),
        1 => (Some(CommitId(r.fixed::<32>()?)), 0),
        2 => {
            let c = CommitId(r.fixed::<32>()?);
            match r.uint()? {
                0 => return Err(Error::Malformed("aspect replaces floor 0")),
                f => (Some(c), f),
            }
        }
        _ => return Err(Error::Malformed("aspect replaces arity")),
    };
    Ok(AspectEntry { tid, ak, lo, hi, retention, keys, hash, replaces, original_floor })
}

fn read_key(r: &mut Reader<'_>, check: bool) -> Result<DeleteKey, Error> {
    if r.array()? != 2 {
        return Err(Error::Malformed("delete key arity"));
    }
    let level = u8::try_from(r.uint()?).ok().filter(|l| (DELETE_ADMIN..=DELETE_WRITER).contains(l)).ok_or(Error::Malformed("delete level"))?;
    let key = DeleteKey { level, key: r.fixed().map_err(|_| Error::Malformed("delete key"))? };
    if check {
        key.verifying_key()?;
    }
    Ok(key)
}

fn read_purge(r: &mut Reader<'_>) -> Result<PurgeItem, Error> {
    match r.array()? {
        2 => Ok(PurgeItem::Aspect { tid: read_tid(r)?, ak: read_ak(r)? }),
        3 => Ok(PurgeItem::Author { tid: read_tid(r)?, ak: read_ak(r)?, actor: read_tid(r)? }),
        4 => {
            let (tid, ak) = (read_tid(r)?, read_ak(r)?);
            let ts = Ts::from_u64(r.uint()?).ok_or(Error::Malformed("purge ts"))?;
            let b = r.bytes()?;
            let src = match b.len() {
                31 => osis_crdt::Source::session(osis_crdt::Session::from_bytes(b.try_into().map_err(|_| Error::Malformed("purge source"))?)),
                32 => osis_crdt::Source::commit(CommitId(b.try_into().map_err(|_| Error::Malformed("purge source"))?)),
                _ => return Err(Error::Malformed("purge source")),
            };
            Ok(PurgeItem::Commit { tid, ak, ts, src })
        }
        _ => Err(Error::Malformed("purge item arity")),
    }
}

/// The value of a linked frontier's bytes: exactly `{0: set<32-byte ID>}` (spec/wire.md §4).
fn frontier_value(bytes: &[u8]) -> Result<Value, Error> {
    let mut r = Reader::new(bytes);
    if r.map()? != 1 || r.uint()? != 0 {
        return Err(Error::Malformed("linked frontier"));
    }
    r.tag(TAG_SET)?;
    let ids = read_items(&mut r, MIN_ID, |r| Ok(Value::bytes(&r.fixed::<32>()?)))?;
    r.end()?;
    Ok(Value::Map([(Value::Int(0), Value::Set(ids.into_iter().collect()))].into_iter().collect()))
}

impl Header {
    /// Fills list `f` from its canonical bytes; `check`: delete keys' points too (not a stored
    /// header, checked when it arrived).
    pub(crate) fn read_list(&mut self, f: ListField, bytes: &[u8], check: bool) -> Result<(), Error> {
        if f == ListField::Frontier {
            self.frontier = Some(frontier_value(bytes)?);
            return Ok(());
        }
        let r = &mut Reader::new(bytes);
        match f {
            ListField::Aspects => self.aspects = read_items(r, MIN_ASPECT, read_aspect)?,
            ListField::Purge => self.purge = read_items(r, MIN_PURGE, read_purge)?,
            ListField::Keys => self.keys = read_items(r, MIN_KEY, |r| read_key(r, check))?,
            ListField::Frontier => {}
        }
        Ok(r.end()?)
    }

    fn take_position(&mut self, f: ListField, v: Item, stored: bool) -> Result<(), Error> {
        let inner = if f == ListField::Frontier {
            match item::opt(v)? {
                None => return Ok(()),
                Some(x) => x,
            }
        } else {
            v
        };
        if let Some(l) = inner.as_link() {
            self.links.set(f, Some(l));
            return Ok(());
        }
        let bytes = inner.bytes();
        if !stored && bytes.len() > CHUNK_THRESHOLD {
            return Err(Error::Malformed("inline list above CHUNK_THRESHOLD"));
        }
        // an inline frontier is judged whole, by its type (`validity::header_frontier`)
        if f == ListField::Frontier {
            self.frontier = Some(inner.to_value()?);
            return Ok(());
        }
        self.read_list(f, bytes, !stored)
    }

    /// Reads a header from its value. Linked lists stay unresolved. `stored`: one this node
    /// verified when it arrived (a stored commit record), read without the checks that cost
    /// (delete keys' points, inline list sizes); the same header.
    pub(crate) fn read(v: Item, stored: bool) -> Result<Header, Error> {
        let items = item::list(v)?;
        let version = item::uint(items.first().ok_or(Error::Malformed("empty header"))?)?;
        if version > FORMAT_VERSION {
            return Err(Error::UnknownVersion(version));
        }
        if version != FORMAT_VERSION {
            return Err(Error::Malformed("format version"));
        }
        let Some([_, author, actor, kind, ts, form, expires, aspects, purge, undoes, blind, keys, frontier, ephemeral, epoch, rotation]) = items.tuple() else {
            return Err(Error::Malformed("header arity"));
        };
        let mut h = Header {
            author: item::tid(author)?,
            actor: item::tid(actor)?,
            kind: Kind::from_id(item::uint(kind)?).ok_or(Error::Malformed("kind"))?,
            ts: Ts::from_u64(item::uint(ts)?).ok_or(Error::Malformed("ts out of range"))?,
            form: Form::read(form)?,
            expires: item::opt(expires)?.map(item::uint).transpose()?,
            aspects: Vec::new(),
            purge: Vec::new(),
            undoes: item::opt(undoes)?.map(|c| item::bytes(c).map(CommitId)).transpose()?,
            blind: item::bytes(blind)?,
            keys: Vec::new(),
            frontier: None,
            links: Links::default(),
            ephemeral: item::opt(ephemeral)?.map(|c| EphClass::from_id(item::uint(c)?).ok_or(Error::Malformed("ephemeral marker"))).transpose()?,
            epoch: item::opt(epoch)?.map(|c| item::bytes(c).map(CommitId)).transpose()?,
            rotation: item::opt(rotation)?.map(RotationHeader::read).transpose()?,
        };
        h.take_position(ListField::Aspects, aspects, stored)?;
        h.take_position(ListField::Purge, purge, stored)?;
        h.take_position(ListField::Keys, keys, stored)?;
        h.take_position(ListField::Frontier, frontier, stored)?;
        Ok(h)
    }

    /// Decodes canonical header bytes (structure only: [`Header::validate`] checks the rules
    /// once linked lists are resolved).
    pub fn decode(b: &[u8]) -> Result<Header, Error> {
        let h = Header::read(Item::parse(b, &LIMITS)?, false)?;
        if h.encode() != b {
            return Err(Error::Malformed("not canonical"));
        }
        Ok(h)
    }

    /// `decode` of a header this node verified when it arrived (`read`'s `stored`): no canonical
    /// re-encode.
    pub fn decode_stored(b: &[u8]) -> Result<Header, Error> {
        Header::read(Item::parse(b, &LIMITS)?, true)
    }
}

//! Commit header: types, canonical encoding, commit ID, signature (spec/wire.md §4,
//! spec/commits.md §1, spec/crypto.md §2).

use crate::Error;
use crate::cbor::{ak, as_bytes, as_list, as_opt, as_tid, as_uint, tid, uidx, uint};
use osis_base::cbor::MAJOR_BYTES;
use osis_base::format::{CHUNK_THRESHOLD, DELETE_ADMIN, DELETE_WRITER, FORMAT_VERSION, MAX_BLOB, MAX_OBJECT_DEPTH, TAG_SET, TID_LEN};
use osis_base::{Ak, BlobId, CommitId, Limits, Link, Reader, Tid, Ts, Value};
use osis_crdt::DeltaKind;
use osis_crypto::{Domain, Signature, SigningSecret, VerifyingKey};
use osis_schema::{Bound, PurgeBy, Retention};

/// Decoder limits of commit structures (spec/wire.md §13).
pub(crate) const LIMITS: Limits = Limits { max_depth: MAX_OBJECT_DEPTH, max_bytes: MAX_BLOB };
/// `abs` bound meaning forever (spec/wire.md §4).
pub const FOREVER: u64 = i64::MAX as u64;

/// Header `kind` (spec/wire.md §4, spec/commits.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Content = 0,
    Role = 1,
    ContentSnapshot = 2,
    RoleSnapshot = 3,
    Import = 4,
    RosterSnapshot = 5,
}

impl Kind {
    pub const ALL: [Kind; 6] = [Kind::Content, Kind::Role, Kind::ContentSnapshot, Kind::RoleSnapshot, Kind::Import, Kind::RosterSnapshot];
    pub fn id(self) -> u64 {
        self as u64
    }
    pub fn from_id(id: u64) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.id() == id)
    }
    /// Deltas only on role-class aspects.
    pub fn is_role(self) -> bool {
        matches!(self, Kind::Role | Kind::RoleSnapshot | Kind::RosterSnapshot)
    }
    /// Carries own writes (a counter range); snapshots and imports do not.
    pub fn has_own_writes(self) -> bool {
        !matches!(self, Kind::ContentSnapshot | Kind::RoleSnapshot | Kind::Import)
    }
    /// May carry several deltas per aspect.
    pub fn several_deltas(self) -> bool {
        matches!(self, Kind::Role | Kind::RosterSnapshot)
    }
    /// Compaction snapshot.
    pub fn is_compaction(self) -> bool {
        matches!(self, Kind::ContentSnapshot | Kind::RoleSnapshot)
    }
    /// How osis-crdt reads this kind's deltas (spec/crdt.md §2.4).
    pub fn delta_kind(self) -> DeltaKind {
        match self {
            Kind::ContentSnapshot | Kind::RoleSnapshot => DeltaKind::Snapshot,
            Kind::Import => DeltaKind::Import,
            Kind::Content | Kind::Role | Kind::RosterSnapshot => DeltaKind::Writer,
        }
    }
}

/// The header's ephemeral marker (spec/commits.md §1, §2; spec/wire.md §4): an ephemeral
/// commit holding state (`Plain`) or a relay-only one carrying signals.
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

    fn value(&self) -> Value {
        match self {
            Form::Commit => uint(0),
            Form::Session(n) => Value::List(vec![uint(1), Value::bytes(n)]),
        }
    }

    fn from_value(v: &Value) -> Result<Form, Error> {
        if let Value::List(l) = v {
            return match l.as_slice() {
                [k, n] if as_uint(k)? == 1 => Ok(Form::Session(as_bytes(n)?)),
                _ => Err(Error::Malformed("dot form")),
            };
        }
        match as_uint(v)? {
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
    pub hashes: Vec<[u8; 32]>,
}

/// A delete key with its level (spec/crypto.md §7); a valid Ed25519 key once decoded.
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

/// A chunk, tree-node or page blob the deltas introduce, with the delete keys its prefix commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkEntry {
    pub blob: BlobId,
    /// Ascending indices into the header's delete keys.
    pub keys: Vec<usize>,
}

/// A purge request item (spec/wire.md §4).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PurgeItem {
    /// That commit's deltas on that aspect.
    Commit { commit: CommitId, tid: Tid, ak: Ak },
    /// Every delta on that aspect of every commit with a smaller `ts`.
    Aspect { tid: Tid, ak: Ak },
    /// Every delta on that aspect of every commit with a smaller `ts` whose purge actor
    /// (`Header::purge_actor`) is `actor`.
    Author { tid: Tid, ak: Ak, actor: Tid },
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

/// An origin commit of an import (spec/permissions.md §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    pub commit: CommitId,
    pub author: Tid,
    pub actor: Tid,
    pub ts: Ts,
}

/// The header lists that may go by link (spec/wire.md §4, "Inline or link").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListField {
    Aspects,
    Chunks,
    Purge,
    Keys,
    Frontier,
    Origins,
}

impl ListField {
    pub const ALL: [ListField; 6] = [ListField::Aspects, ListField::Chunks, ListField::Purge, ListField::Keys, ListField::Frontier, ListField::Origins];
}

/// Root links of the lists that go by link; `None` = inline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Links {
    pub aspects: Option<Link>,
    pub chunks: Option<Link>,
    pub purge: Option<Link>,
    pub keys: Option<Link>,
    pub frontier: Option<Link>,
    pub origins: Option<Link>,
}

impl Links {
    pub fn get(&self, f: ListField) -> Option<&Link> {
        match f {
            ListField::Aspects => self.aspects.as_ref(),
            ListField::Chunks => self.chunks.as_ref(),
            ListField::Purge => self.purge.as_ref(),
            ListField::Keys => self.keys.as_ref(),
            ListField::Frontier => self.frontier.as_ref(),
            ListField::Origins => self.origins.as_ref(),
        }
    }
    pub fn set(&mut self, f: ListField, l: Option<Link>) {
        let slot = match f {
            ListField::Aspects => &mut self.aspects,
            ListField::Chunks => &mut self.chunks,
            ListField::Purge => &mut self.purge,
            ListField::Keys => &mut self.keys,
            ListField::Frontier => &mut self.frontier,
            ListField::Origins => &mut self.origins,
        };
        *slot = l;
    }
}

/// A commit header (spec/wire.md §4 `Header`). A list that goes by link is empty until
/// [`Header::resolve`](crate::Header::resolve) fills it; its link stays in `links`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u64,
    pub author: Tid,
    pub actor: Tid,
    pub kind: Kind,
    pub ts: Ts,
    pub form: Form,
    /// The commit's expiry T, wall ms (spec/commits.md §6): every delta of it expires then.
    pub expires: Option<u64>,
    pub aspects: Vec<AspectEntry>,
    pub chunks: Vec<ChunkEntry>,
    pub purge: Vec<PurgeItem>,
    pub undoes: Option<CommitId>,
    /// 16 random bytes blinding the commitments of every blob of the commit (spec/crypto.md §7).
    pub blind: [u8; 16],
    pub keys: Vec<DeleteKey>,
    /// The frontier value (spec/data-model.md §9), typed by osis-perm.
    pub frontier: Option<Value>,
    pub origins: Vec<Origin>,
    pub links: Links,
    /// Set on an ephemeral commit (kept in memory by every node, never stored).
    pub ephemeral: Option<EphClass>,
}

// ---- encode

fn bound_value(b: &Bound) -> Value {
    let mut m = osis_base::ValueMap::new();
    if let Some(a) = b.abs {
        m.insert(uint(0), uint(a));
    }
    if let Some(r) = b.rel {
        m.insert(uint(1), uint(r));
    }
    Value::Map(m)
}

pub(crate) fn retention_value(r: &Retention) -> Value {
    Value::List(vec![uint(r.by as u64), bound_value(&r.at_least), bound_value(&r.at_most)])
}

fn aspect_value(a: &AspectEntry) -> Value {
    Value::List(vec![
        tid(&a.tid),
        ak(&a.ak),
        uint(a.lo),
        uint(a.hi),
        retention_value(&a.retention),
        Value::List(a.keys.iter().map(|i| uidx(*i)).collect()),
        Value::List(a.hashes.iter().map(|h| Value::bytes(h)).collect()),
    ])
}

pub(crate) fn key_value(t: &DeleteKey) -> Value {
    Value::List(vec![uint(u64::from(t.level)), Value::bytes(&t.key)])
}

fn chunk_value(c: &ChunkEntry) -> Value {
    Value::List(vec![Value::bytes(&c.blob.0), Value::List(c.keys.iter().map(|i| uidx(*i)).collect())])
}

pub(crate) fn purge_value(p: &PurgeItem) -> Value {
    match p {
        PurgeItem::Commit { commit, tid: t, ak: a } => Value::List(vec![Value::bytes(&commit.0), tid(t), ak(a)]),
        PurgeItem::Aspect { tid: t, ak: a } => Value::List(vec![tid(t), ak(a)]),
        PurgeItem::Author { tid: t, ak: a, actor } => Value::List(vec![tid(t), ak(a), tid(actor)]),
    }
}

fn origin_value(o: &Origin) -> Value {
    Value::List(vec![Value::bytes(&o.commit.0), tid(&o.author), tid(&o.actor), uint(o.ts.to_u64())])
}

/// Canonical bytes of `[tid, ak]`, the aspect sort key.
pub(crate) fn aspect_key(t: &Tid, a: &Ak) -> Vec<u8> {
    osis_base::encode(&Value::List(vec![tid(t), ak(a)]))
}

impl Header {
    /// Whether aspect `a` of this header is a permanent delta (spec/commits.md §5): keep at least
    /// forever, no keep at most, no expiry, on an aspect with no fixed retention, in a durable
    /// commit. It leaves by purge request, and leaves its header behind for good.
    pub fn permanent(&self, a: &AspectEntry) -> bool {
        self.ephemeral.is_none() && self.expires.is_none() && a.retention.at_least.abs == Some(FOREVER) && a.retention.at_most == osis_schema::Bound::default() && crate::retention::fixed_retention(a.ak.as_str()).is_none()
    }

    /// The actor holding the author right over this commit's deltas (spec/permissions.md §7,
    /// §8): the actor it acted for; an import's: its first origin commit's.
    pub fn purge_actor(&self) -> Tid {
        match self.kind {
            Kind::Import => self.origins.first().map_or(self.actor, |o| o.actor),
            _ => self.actor,
        }
    }

    /// The list's (or frontier's) value as it would sit inline; `None` for an absent frontier.
    pub fn list_value(&self, f: ListField) -> Option<Value> {
        Some(match f {
            ListField::Aspects => Value::List(self.aspects.iter().map(aspect_value).collect()),
            ListField::Chunks => Value::List(self.chunks.iter().map(chunk_value).collect()),
            ListField::Purge => Value::List(self.purge.iter().map(purge_value).collect()),
            ListField::Keys => Value::List(self.keys.iter().map(key_value).collect()),
            ListField::Frontier => return self.frontier.clone(),
            ListField::Origins => Value::List(self.origins.iter().map(origin_value).collect()),
        })
    }

    fn position(&self, f: ListField) -> Value {
        match (f, self.links.get(f)) {
            (ListField::Frontier, Some(l)) => Value::opt(Some(Value::link(*l))),
            (ListField::Frontier, None) => Value::opt(self.frontier.clone()),
            (_, Some(l)) => Value::link(*l),
            (_, None) => self.list_value(f).unwrap_or(Value::List(Vec::new())),
        }
    }

    pub fn to_value(&self) -> Value {
        Value::List(vec![
            uint(self.version),
            tid(&self.author),
            tid(&self.actor),
            uint(self.kind.id()),
            uint(self.ts.to_u64()),
            self.form.value(),
            Value::opt(self.expires.map(uint)),
            self.position(ListField::Aspects),
            self.position(ListField::Chunks),
            self.position(ListField::Purge),
            Value::opt(self.undoes.map(|c| Value::bytes(&c.0))),
            Value::bytes(&self.blind),
            self.position(ListField::Keys),
            self.position(ListField::Frontier),
            self.position(ListField::Origins),
            Value::opt(self.ephemeral.map(|c| uint(c as u64))),
        ])
    }

    /// Canonical bytes of the header.
    pub fn encode(&self) -> Vec<u8> {
        osis_base::encode(&self.to_value())
    }

    /// Commit ID = BLAKE3(canonical header bytes).
    pub fn id(&self) -> CommitId {
        CommitId(osis_base::hash::hash(&self.encode()))
    }

    /// The author's signature over the commit ID.
    pub fn sign(&self, key: &SigningSecret) -> Signature {
        key.sign(Domain::Commit, &self.id().0)
    }

    /// Whether every linked list has been resolved.
    pub fn is_resolved(&self) -> bool {
        ListField::ALL.into_iter().all(|f| self.links.get(f).is_none() || !self.list_is_empty(f))
    }

    pub(crate) fn list_is_empty(&self, f: ListField) -> bool {
        match f {
            ListField::Aspects => self.aspects.is_empty(),
            ListField::Chunks => self.chunks.is_empty(),
            ListField::Purge => self.purge.is_empty(),
            ListField::Keys => self.keys.is_empty(),
            ListField::Frontier => self.frontier.is_none(),
            ListField::Origins => self.origins.is_empty(),
        }
    }
}

/// Verifies the author's signature over a commit ID (spec/crypto.md §2).
pub fn verify_signature(id: &CommitId, sig: &Signature, key: &VerifyingKey) -> Result<(), Error> {
    key.verify(Domain::Commit, &id.0, sig).map_err(|_| Error::BadSignature)
}

// ---- decode

// Lists are read by shape, nothing built that the bytes do not pay for. `decode` of hostile bytes
// costs about 56 B per byte, too much at `MAX_LIST_BYTES` (`Header::resolve`).

// About the fewest bytes an item takes: what a list reserves for by its count, so a count the bytes
// cannot pay for reserves nothing. A wrong value only costs a reallocation.
const MIN_ASPECT: usize = 59;
const MIN_CHUNK: usize = 35;
const MIN_PURGE: usize = 20;
const MIN_KEY: usize = 35;
const MIN_ORIGIN: usize = 2 + 32 + 2 * (1 + TID_LEN) + 2;
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

fn read_bound(r: &mut Reader<'_>) -> Result<Bound, Error> {
    let mut b = Bound::default();
    let mut next = 0;
    for _ in 0..r.map()? {
        let k = r.uint()?;
        let n = r.uint()?;
        match k {
            0 if next == 0 => b.abs = Some(n),
            1 if next <= 1 => b.rel = Some(n),
            _ => return Err(Error::Malformed("bound key")),
        }
        next = k + 1;
    }
    Ok(b)
}

fn read_retention(r: &mut Reader<'_>) -> Result<Retention, Error> {
    if r.array()? != 3 {
        return Err(Error::Malformed("retention arity"));
    }
    let by = PurgeBy::from_id(r.uint()?).ok_or(Error::Malformed("purgeable-by class"))?;
    Ok(Retention { by, at_least: read_bound(r)?, at_most: read_bound(r)? })
}

fn read_aspect(r: &mut Reader<'_>) -> Result<AspectEntry, Error> {
    if r.array()? != 7 {
        return Err(Error::Malformed("aspect arity"));
    }
    let (tid, ak, lo, hi) = (read_tid(r)?, read_ak(r)?, r.uint()?, r.uint()?);
    let (retention, keys) = (read_retention(r)?, read_idxs(r)?);
    let hashes = read_items(r, MIN_ID, |r| Ok(r.fixed::<32>()?))?;
    if hashes.is_empty() {
        return Err(Error::Malformed("aspect without delta hashes"));
    }
    Ok(AspectEntry { tid, ak, lo, hi, retention, keys, hashes })
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

fn read_chunk(r: &mut Reader<'_>) -> Result<ChunkEntry, Error> {
    if r.array()? != 2 {
        return Err(Error::Malformed("chunk arity"));
    }
    Ok(ChunkEntry { blob: BlobId(r.fixed()?), keys: read_idxs(r)? })
}

fn read_purge(r: &mut Reader<'_>) -> Result<PurgeItem, Error> {
    match r.array()? {
        2 => Ok(PurgeItem::Aspect { tid: read_tid(r)?, ak: read_ak(r)? }),
        3 => {
            let first = r.bytes()?;
            // the second place tells them apart: a tid, or an aspect key's text
            if r.peek_major() == Some(MAJOR_BYTES) {
                let commit = first.try_into().map(CommitId).map_err(|_| Error::Malformed("purge commit"))?;
                Ok(PurgeItem::Commit { commit, tid: read_tid(r)?, ak: read_ak(r)? })
            } else {
                let tid = first.try_into().map(Tid::from_bytes).map_err(|_| Error::Malformed("purge tid"))?;
                Ok(PurgeItem::Author { tid, ak: read_ak(r)?, actor: read_tid(r)? })
            }
        }
        _ => Err(Error::Malformed("purge item arity")),
    }
}

fn read_origin(r: &mut Reader<'_>) -> Result<Origin, Error> {
    if r.array()? != 4 {
        return Err(Error::Malformed("origin arity"));
    }
    Ok(Origin { commit: CommitId(r.fixed()?), author: read_tid(r)?, actor: read_tid(r)?, ts: Ts::from_u64(r.uint()?).ok_or(Error::Malformed("ts out of range"))? })
}

fn as_ts(v: &Value) -> Result<Ts, Error> {
    Ts::from_u64(as_uint(v)?).ok_or(Error::Malformed("ts out of range"))
}

/// The value of a linked frontier's bytes: exactly `{0: set<32-byte ID>}` (spec/wire.md §4).
pub fn frontier_value(bytes: &[u8]) -> Result<Value, Error> {
    let mut r = Reader::new(bytes);
    if r.map()? != 1 || r.uint()? != 0 {
        return Err(Error::Malformed("linked frontier"));
    }
    r.tag(TAG_SET)?;
    let ids = read_items(&mut r, MIN_ID, |r| Ok(Value::bytes(&r.fixed::<32>()?)))?;
    r.end()?;
    Ok(Value::Map([(uint(0), Value::Set(ids.into_iter().collect()))].into_iter().collect()))
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
            ListField::Chunks => self.chunks = read_items(r, MIN_CHUNK, read_chunk)?,
            ListField::Purge => self.purge = read_items(r, MIN_PURGE, read_purge)?,
            ListField::Keys => self.keys = read_items(r, MIN_KEY, |r| read_key(r, check))?,
            ListField::Origins => self.origins = read_items(r, MIN_ORIGIN, read_origin)?,
            ListField::Frontier => {}
        }
        Ok(r.end()?)
    }

    fn take_position(&mut self, f: ListField, v: &Value, stored: bool) -> Result<(), Error> {
        let inner = if f == ListField::Frontier {
            match as_opt(v)? {
                None => return Ok(()),
                Some(x) => x,
            }
        } else {
            v
        };
        if let Value::Link(l) = inner {
            self.links.set(f, Some(**l));
            return Ok(());
        }
        let bytes = osis_base::encode(inner);
        if !stored && bytes.len() > CHUNK_THRESHOLD {
            return Err(Error::Malformed("inline list above CHUNK_THRESHOLD"));
        }
        // an inline frontier is judged whole, by its type (`validity::header_frontier`)
        if f == ListField::Frontier {
            self.frontier = Some(inner.clone());
            return Ok(());
        }
        self.read_list(f, &bytes, !stored)
    }

    /// Reads a header from its value. Linked lists stay unresolved.
    pub fn from_value(v: &Value) -> Result<Header, Error> {
        Header::from_value_as(v, false)
    }

    /// `from_value` of a header this node verified when it arrived (a stored commit record):
    /// without the checks that cost (delete keys' points, inline list sizes); the same header.
    pub fn from_stored_value(v: &Value) -> Result<Header, Error> {
        Header::from_value_as(v, true)
    }

    fn from_value_as(v: &Value, stored: bool) -> Result<Header, Error> {
        let items = as_list(v)?;
        let version = as_uint(items.first().ok_or(Error::Malformed("empty header"))?)?;
        if version > FORMAT_VERSION {
            return Err(Error::UnknownVersion(version));
        }
        if version != FORMAT_VERSION {
            return Err(Error::Malformed("format version"));
        }
        let [_, author, actor, kind, ts, form, expires, aspects, chunks, purge, undoes, blind, keys, frontier, origins, ephemeral] = items else {
            return Err(Error::Malformed("header arity"));
        };
        let mut h = Header {
            version,
            author: as_tid(author)?,
            actor: as_tid(actor)?,
            kind: Kind::from_id(as_uint(kind)?).ok_or(Error::Malformed("kind"))?,
            ts: as_ts(ts)?,
            form: Form::from_value(form)?,
            expires: as_opt(expires)?.map(as_uint).transpose()?,
            aspects: Vec::new(),
            chunks: Vec::new(),
            purge: Vec::new(),
            undoes: as_opt(undoes)?.map(|c| as_bytes(c).map(CommitId)).transpose()?,
            blind: as_bytes(blind)?,
            keys: Vec::new(),
            frontier: None,
            origins: Vec::new(),
            links: Links::default(),
            ephemeral: as_opt(ephemeral)?.map(|c| EphClass::from_id(as_uint(c)?).ok_or(Error::Malformed("ephemeral marker"))).transpose()?,
        };
        h.take_position(ListField::Aspects, aspects, stored)?;
        h.take_position(ListField::Chunks, chunks, stored)?;
        h.take_position(ListField::Purge, purge, stored)?;
        h.take_position(ListField::Keys, keys, stored)?;
        h.take_position(ListField::Frontier, frontier, stored)?;
        h.take_position(ListField::Origins, origins, stored)?;
        Ok(h)
    }

    /// Decodes canonical header bytes (structure only: [`Header::validate`] checks the rules
    /// once linked lists are resolved).
    pub fn decode(b: &[u8]) -> Result<Header, Error> {
        let v = osis_base::decode(b, &LIMITS)?;
        let h = Header::from_value(&v)?;
        if h.encode() != b {
            return Err(Error::Malformed("not canonical"));
        }
        Ok(h)
    }
}

//! Commit header: types, canonical encoding, commit ID, signature (spec/wire.md §4,
//! spec/commits.md §1, spec/crypto.md §2).

use crate::Error;
use crate::cbor::{ak, as_ak, as_bytes, as_idx, as_list, as_opt, as_tid, as_uint, tid, uidx, uint};
use osis_base::format::{CHUNK_THRESHOLD, DELETE_ADMIN, DELETE_WRITER, FORMAT_VERSION, MAX_BLOB, MAX_OBJECT_DEPTH};
use osis_base::{Ak, BlobId, CommitId, Limits, Link, SchemaId, Tid, Ts, Value};
use osis_crdt::DeltaKind;
use osis_crypto::{Domain, Signature, SigningSecret, VerifyingKey};
use osis_schema::{Bound, PurgeBy, Retention};
use std::collections::BTreeMap;

/// Decoder limits of commit structures (spec/wire.md §13).
pub(crate) const LIMITS: Limits = Limits { max_depth: MAX_OBJECT_DEPTH, max_bytes: MAX_BLOB };
/// Schema table entries at most (spec/wire.md §13).
pub const MAX_SCHEMAS: usize = 256;
/// `abs` bound meaning forever (spec/wire.md §4).
pub const FOREVER: u64 = i64::MAX as u64;

/// Header `kind` (spec/wire.md §4, spec/commits.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Content = 0,
    Membership = 1,
    ContentSnapshot = 2,
    MembershipSnapshot = 3,
    Import = 4,
    RosterSnapshot = 5,
}

impl Kind {
    pub const ALL: [Kind; 6] = [Kind::Content, Kind::Membership, Kind::ContentSnapshot, Kind::MembershipSnapshot, Kind::Import, Kind::RosterSnapshot];
    pub fn id(self) -> u64 {
        self as u64
    }
    pub fn from_id(id: u64) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.id() == id)
    }
    /// Deltas only on membership-class aspects.
    pub fn is_membership(self) -> bool {
        matches!(self, Kind::Membership | Kind::MembershipSnapshot | Kind::RosterSnapshot)
    }
    /// Carries own writes (a counter range); snapshots and imports do not.
    pub fn has_own_writes(self) -> bool {
        !matches!(self, Kind::ContentSnapshot | Kind::MembershipSnapshot | Kind::Import)
    }
    /// May carry several deltas per aspect.
    pub fn several_deltas(self) -> bool {
        matches!(self, Kind::Membership | Kind::RosterSnapshot)
    }
    /// Compaction snapshot.
    pub fn is_compaction(self) -> bool {
        matches!(self, Kind::ContentSnapshot | Kind::MembershipSnapshot)
    }
    /// How osis-crdt reads this kind's deltas (spec/crdt.md §2.4).
    pub fn delta_kind(self) -> DeltaKind {
        match self {
            Kind::ContentSnapshot | Kind::MembershipSnapshot => DeltaKind::Snapshot,
            Kind::Import => DeltaKind::Import,
            Kind::Content | Kind::Membership | Kind::RosterSnapshot => DeltaKind::Writer,
        }
    }
}

/// The header's ephemeral marker (spec/commits.md §1, §2; spec/wire.md §4): an ephemeral
/// commit holding state (`Plain`), a relay-only one carrying signals, or a presence one (state
/// tied to its author's connection, uploaded by its author only, leased).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EphClass {
    Plain = 0,
    Relay = 1,
    Presence = 2,
}

impl EphClass {
    pub fn from_id(id: u64) -> Option<EphClass> {
        [EphClass::Plain, EphClass::Relay, EphClass::Presence].into_iter().find(|c| *c as u64 == id)
    }
}

/// Dot form (spec/commits.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Form {
    Node = 0,
    Commit = 1,
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
    /// Expiry, wall ms.
    pub expires: Option<u64>,
    /// Index into the schema table; `None` for an untyped write.
    pub schema: Option<usize>,
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
}

impl PurgeItem {
    pub fn tid(&self) -> &Tid {
        match self {
            PurgeItem::Commit { tid, .. } | PurgeItem::Aspect { tid, .. } => tid,
        }
    }
    pub fn ak(&self) -> &Ak {
        match self {
            PurgeItem::Commit { ak, .. } | PurgeItem::Aspect { ak, .. } => ak,
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
    pub schemas: Vec<(SchemaId, u64)>,
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
    let mut m = BTreeMap::new();
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
        Value::opt(a.expires.map(uint)),
        Value::opt(a.schema.map(uidx)),
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
            (ListField::Frontier, Some(l)) => Value::opt(Some(Value::Link(*l))),
            (ListField::Frontier, None) => Value::opt(self.frontier.clone()),
            (_, Some(l)) => Value::Link(*l),
            (_, None) => self.list_value(f).unwrap_or(Value::List(Vec::new())),
        }
    }

    pub fn to_value(&self) -> Value {
        let schemas = self.schemas.iter().map(|(id, rev)| Value::List(vec![Value::bytes(&id.0), uint(*rev)])).collect();
        Value::List(vec![
            uint(self.version),
            tid(&self.author),
            tid(&self.actor),
            uint(self.kind.id()),
            uint(self.ts.to_u64()),
            uint(self.form as u64),
            Value::List(schemas),
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

fn as_bound(v: &Value) -> Result<Bound, Error> {
    let Value::Map(m) = v else { return Err(Error::Malformed("bound")) };
    let mut b = Bound::default();
    for (k, x) in m {
        match as_uint(k)? {
            0 => b.abs = Some(as_uint(x)?),
            1 => b.rel = Some(as_uint(x)?),
            _ => return Err(Error::Malformed("bound key")),
        }
    }
    Ok(b)
}

pub(crate) fn as_retention(v: &Value) -> Result<Retention, Error> {
    let [by, least, most] = as_list(v)? else { return Err(Error::Malformed("retention arity")) };
    let by = PurgeBy::from_id(as_uint(by)?).ok_or(Error::Malformed("purgeable-by class"))?;
    Ok(Retention { by, at_least: as_bound(least)?, at_most: as_bound(most)? })
}

fn as_aspect(v: &Value) -> Result<AspectEntry, Error> {
    let [t, a, lo, hi, r, exp, schema, toks, hashes] = as_list(v)? else { return Err(Error::Malformed("aspect arity")) };
    let hashes = as_list(hashes)?.iter().map(as_bytes::<32>).collect::<Result<Vec<_>, _>>()?;
    if hashes.is_empty() {
        return Err(Error::Malformed("aspect without delta hashes"));
    }
    Ok(AspectEntry {
        tid: as_tid(t)?,
        ak: as_ak(a)?,
        lo: as_uint(lo)?,
        hi: as_uint(hi)?,
        retention: as_retention(r)?,
        expires: as_opt(exp)?.map(as_uint).transpose()?,
        schema: as_opt(schema)?.map(as_idx).transpose()?,
        keys: as_list(toks)?.iter().map(as_idx).collect::<Result<_, _>>()?,
        hashes,
    })
}

pub(crate) fn as_key(v: &Value) -> Result<DeleteKey, Error> {
    let key = as_key_unchecked(v)?;
    key.verifying_key()?;
    Ok(key)
}

/// `as_key` without the point check (a stored header, checked when it arrived).
fn as_key_unchecked(v: &Value) -> Result<DeleteKey, Error> {
    let [l, k] = as_list(v)? else { return Err(Error::Malformed("delete key arity")) };
    let level = u8::try_from(as_uint(l)?).ok().filter(|l| (DELETE_ADMIN..=DELETE_WRITER).contains(l)).ok_or(Error::Malformed("delete level"))?;
    Ok(DeleteKey { level, key: as_bytes(k)? })
}

fn as_chunk(v: &Value) -> Result<ChunkEntry, Error> {
    let [b, keys] = as_list(v)? else { return Err(Error::Malformed("chunk arity")) };
    Ok(ChunkEntry { blob: BlobId(as_bytes(b)?), keys: as_list(keys)?.iter().map(as_idx).collect::<Result<_, _>>()? })
}

fn as_purge(v: &Value) -> Result<PurgeItem, Error> {
    match as_list(v)? {
        [c, t, a] => Ok(PurgeItem::Commit { commit: CommitId(as_bytes(c)?), tid: as_tid(t)?, ak: as_ak(a)? }),
        [t, a] => Ok(PurgeItem::Aspect { tid: as_tid(t)?, ak: as_ak(a)? }),
        _ => Err(Error::Malformed("purge item arity")),
    }
}

fn as_ts(v: &Value) -> Result<Ts, Error> {
    Ts::from_u64(as_uint(v)?).ok_or(Error::Malformed("ts out of range"))
}

fn as_origin(v: &Value) -> Result<Origin, Error> {
    let [c, au, ac, ts] = as_list(v)? else { return Err(Error::Malformed("origin arity")) };
    Ok(Origin { commit: CommitId(as_bytes(c)?), author: as_tid(au)?, actor: as_tid(ac)?, ts: as_ts(ts)? })
}

fn items<T>(v: &Value, f: impl Fn(&Value) -> Result<T, Error>) -> Result<Vec<T>, Error> {
    as_list(v)?.iter().map(f).collect()
}

impl Header {
    /// Fills list `f` from its inline value (also used for a resolved link).
    pub(crate) fn set_list(&mut self, f: ListField, v: &Value) -> Result<(), Error> {
        match f {
            ListField::Aspects => self.aspects = items(v, as_aspect)?,
            ListField::Chunks => self.chunks = items(v, as_chunk)?,
            ListField::Purge => self.purge = items(v, as_purge)?,
            ListField::Keys => self.keys = items(v, as_key)?,
            ListField::Frontier => self.frontier = Some(v.clone()),
            ListField::Origins => self.origins = items(v, as_origin)?,
        }
        Ok(())
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
            self.links.set(f, Some(*l));
            return Ok(());
        }
        if stored {
            if f == ListField::Keys {
                self.keys = items(inner, as_key_unchecked)?;
                return Ok(());
            }
        } else if osis_base::encode(inner).len() > CHUNK_THRESHOLD {
            return Err(Error::Malformed("inline list above CHUNK_THRESHOLD"));
        }
        self.set_list(f, inner)
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
        let [_, author, actor, kind, ts, form, schemas, aspects, chunks, purge, undoes, blind, keys, frontier, origins, ephemeral] = items else {
            return Err(Error::Malformed("header arity"));
        };
        let schemas = as_list(schemas)?;
        if schemas.len() > MAX_SCHEMAS {
            return Err(Error::Malformed("too many schemas"));
        }
        let schemas = schemas
            .iter()
            .map(|s| match as_list(s)? {
                [id, rev] => Ok((SchemaId(as_bytes(id)?), as_uint(rev)?)),
                _ => Err(Error::Malformed("schema entry arity")),
            })
            .collect::<Result<_, Error>>()?;
        let mut h = Header {
            version,
            author: as_tid(author)?,
            actor: as_tid(actor)?,
            kind: Kind::from_id(as_uint(kind)?).ok_or(Error::Malformed("kind"))?,
            ts: as_ts(ts)?,
            form: match as_uint(form)? {
                0 => Form::Node,
                1 => Form::Commit,
                _ => return Err(Error::Malformed("dot form")),
            },
            schemas,
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

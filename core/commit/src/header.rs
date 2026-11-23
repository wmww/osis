//! Commit header: types, canonical encoding, commit ID, signature (spec/wire.md §4,
//! spec/commits.md §1, spec/crypto.md §2).

use crate::Error;
use crate::cbor::item;
use crate::path::{Paths, Split, ThingPath};
use osis_base::cbor::{Item, MAJOR_TAG, encode_into, head, put_array, put_bytes, put_link, put_map, put_text, put_uint};
use osis_base::format::{CHUNK_THRESHOLD, DELETE_ADMIN, DELETE_WRITER, FORMAT_VERSION, MAX_BLOB, MAX_OBJECT_DEPTH, TAG_SET, TID_LEN};
use osis_base::{Ak, CommitId, Limits, Link, Reader, Tid, Ts, Value};
use std::sync::Arc;
use osis_crdt::DeltaKind;
use osis_base::SIGNING_KEY_ED25519;
use osis_crypto::{Domain, KemPublicKey, Secret32, Signature, VerifyingKey};
use osis_schema::{PurgeBy};

/// Decoder limits of commit structures (spec/wire.md §12).
pub(crate) const LIMITS: Limits = Limits::new(MAX_OBJECT_DEPTH, MAX_BLOB);
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
    /// Session form: dots `(Session(signer, nonce), counter)`, counters per (aspect, session);
    /// every content commit with own writes, durable or memory.
    Session([u8; osis_crdt::SESSION_NONCE_LEN]),
}

impl Form {
    /// The own source of a commit of this form signed by `signer` (`commit` for commit form).
    pub fn own_source(&self, signer: Tid, commit: CommitId) -> osis_crdt::Source {
        match self {
            Form::Commit => osis_crdt::Source::commit(commit),
            Form::Session(nonce) => osis_crdt::Source::session(osis_crdt::Session { node: signer, nonce: *nonce }),
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
    pub purge_by: PurgeBy,
    /// Ascending indices into the header's delete keys.
    pub keys: Vec<usize>,
    /// The delta hash of the aspect's one delta.
    pub hash: [u8; 32],
    /// The fire this delta claims to replace (a durable signal's, spec/commits.md §5 Signals).
    pub replaces: Option<CommitId>,
    /// The floor of that fire as its writer read it (spec/commits.md §5 Signals): a node whose
    /// own floor on the thing is above it lists the delta nowhere. 0 without `replaces`.
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
    /// Every delta on that aspect of every commit with a smaller `ts` whose purge author is
    /// `author` (spec/permissions.md §6).
    Author { tid: Tid, ak: Ak, author: Tid },
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

    /// The things it writes, distinct, in the order of its aspects (that of a split path's
    /// entries).
    pub fn things(&self) -> Vec<Tid> {
        let mut out: Vec<Tid> = self.aspects.iter().map(|a| a.tid).collect();
        out.dedup();
        out
    }

    /// Its one purge author (spec/permissions.md §6), in the clear in either form: a member of
    /// the path it states for every thing it writes.
    pub fn purge_author(&self) -> Tid {
        self.path.purge_author(self.signer)
    }

    /// The path a split commit states for the thing at `i` among those it writes, opened under
    /// path key `key`: `None` where it is no split commit or the key does not open that entry.
    pub fn open_path(&self, i: usize, key: &[u8; 32]) -> Option<ThingPath> {
        let Paths::Split(s) = &self.path else { return None };
        let listed = Split::open(key, s.entries.get(i)?)?;
        let t = self.things().get(i).copied()?;
        Some(crate::path::thing_path(listed, &self.signer, &self.purge_author(), &t))
    }

    /// Whether it states the split form.
    pub fn is_split(&self) -> bool {
        matches!(self.path, Paths::Split(_))
    }

    /// The things a request destroying a thing names (`[tid, created.0]`, spec/commits.md §5
    /// Destruction): a header-only copy of a split commit carries their path keys.
    pub fn destroyed(&self) -> impl Iterator<Item = &Tid> {
        self.purge.iter().filter(|p| matches!(p, PurgeItem::Aspect { ak, .. } if ak.as_str() == crate::retention::CREATED)).map(|p| p.tid())
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
    /// The key actor whose key signs the commit (spec/wire.md §4 field 1): the commit is by it.
    pub signer: Tid,
    /// The paths it states, one per thing it writes (spec/wire.md §4 field 2).
    pub path: Paths,
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
    /// The frontier's commit IDs, ascending and distinct (spec/data-model.md §9 `frontier`,
    /// exactly `{0: set<32-byte ID>}` on the wire, inline or linked): read straight from its
    /// bytes, shared with what judges it (osis-perm's `Frontier`).
    pub frontier: Option<Arc<[CommitId]>>,
    pub links: Links,
    /// Set on an ephemeral commit (kept in memory by every node, never stored).
    pub ephemeral: Option<EphClass>,
    /// The epoch an account signer signs at (spec/crypto.md §9): its minting rotation's commit
    /// ID, `FIRST_EPOCH` for the first. Present iff the signer is an account (judged by the
    /// signer's creation record).
    pub epoch: Option<CommitId>,
    /// A rotation of the account's signing chain (spec/wire.md §4): only on an account's role
    /// commit. Its commit ID names the epoch it mints.
    pub rotation: Option<RotationHeader>,
    /// A content snapshot that is its writer's own cover at a removal (spec/permissions.md §5.1,
    /// Own cover; spec/wire.md §4 field 17): only its writer drops a body under it.
    pub own_cover: bool,
    /// A role commit its signer means to leave a thing with no standing admin (spec/wire.md §4
    /// field 17, bit 1; spec/permissions.md §2 Adminless mark): read only by the writer's check.
    pub adminless: bool,
    /// A seed re-seal (spec/wire.md §4): seed boxes of an existing epoch of the account's chain,
    /// only on an account's role commit that is no rotation.
    pub reseal: Option<SeedReseal>,
}

/// A header's `reseal` (spec/wire.md §4 `Reseal`, spec/crypto.md §9 Custody): the signing key of
/// the epoch whose seed it boxes and its seed boxes, ascending by tag, distinct, at least one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedReseal {
    pub signing_key: VerifyingKey,
    pub seeds: Vec<SeedBox>,
}

impl SeedReseal {
    fn put(&self, out: &mut Vec<u8>) {
        put_array(out, 2);
        put_signing_key(out, &self.signing_key);
        put_seed_boxes(out, &self.seeds);
    }

    fn read(v: Item) -> Result<SeedReseal, Error> {
        let Some([sk, seeds]) = item::list(v)?.tuple() else { return Err(Error::Malformed("reseal arity")) };
        let seeds = read_seed_boxes(seeds)?;
        if seeds.is_empty() {
            return Err(Error::Malformed("reseal without a seed box"));
        }
        Ok(SeedReseal { signing_key: read_signing_key(sk)?, seeds })
    }
}

fn put_signing_key(out: &mut Vec<u8>, k: &VerifyingKey) {
    encode_into(&Value::Enum(SIGNING_KEY_ED25519, Some(Box::new(Value::bytes(&k.to_bytes())))), out);
}

fn read_signing_key(v: Item) -> Result<VerifyingKey, Error> {
    match v.to_value()? {
        Value::Enum(SIGNING_KEY_ED25519, Some(b)) => match b.as_ref() {
            Value::Bytes(k) => VerifyingKey::from_slice(k).map_err(|_| Error::Malformed("signing key")),
            _ => Err(Error::Malformed("signing key")),
        },
        _ => Err(Error::Malformed("signing key")),
    }
}

fn put_seed_boxes(out: &mut Vec<u8>, seeds: &[SeedBox]) {
    put_array(out, seeds.len());
    for b in seeds {
        put_array(out, 2);
        put_bytes(out, &b.tag);
        put_bytes(out, &b.sealed);
    }
}

/// Seed boxes, ascending by tag and distinct (else malformed).
fn read_seed_boxes(v: Item) -> Result<Vec<SeedBox>, Error> {
    let seeds = item::list(v)?.iter().map(|b| {
        let Some([tag, sealed]) = item::list(b)?.tuple() else { return Err(Error::Malformed("seed box arity")) };
        let sealed: Vec<u8> = sealed.as_bytes().ok_or(Error::Malformed("seed box"))?.to_vec();
        if sealed.len() < osis_crypto::SEALED_OVERHEAD + 32 {
            return Err(Error::Malformed("seed box length"));
        }
        Ok(SeedBox { tag: item::bytes(tag)?, sealed })
    }).collect::<Result<Vec<SeedBox>, Error>>()?;
    if !crate::cbor::strictly_ascending(&seeds, |b| b.tag) {
        return Err(Error::Malformed("seed boxes not ascending by tag"));
    }
    Ok(seeds)
}

/// The first epoch of every account's signing chain, named by 32 zero bytes (spec/crypto.md §9).
pub const FIRST_EPOCH: CommitId = CommitId([0; 32]);

/// A header's `rotation` (spec/wire.md §4 `Rotation`): the new epoch's public keys, the epochs it
/// supersedes (the header's `epoch` among them), the fork rotations it names (a merge), the
/// revocations its maker took off its line, and the root of its list tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationHeader {
    pub signing_key: VerifyingKey,
    pub kem_key: KemPublicKey,
    /// Ascending, distinct.
    pub supersedes: Vec<CommitId>,
    /// Ascending, distinct.
    pub names: Vec<CommitId>,
    /// The rotations carrying removals from D its maker took that are not on its line
    /// (spec/permissions.md §5.4): ascending, distinct.
    pub takes: Vec<CommitId>,
    /// Whether it removes a device from D (spec/permissions.md §5.5 Revoked): what readers
    /// outside the account read of its membership changes.
    pub revokes: bool,
    /// Its membership changes of D, sealed (`osis_crypto::seal_devices`) under the epoch it is
    /// signed at; empty when it carries none (spec/crypto.md §9, Roster).
    pub devices: Vec<u8>,
    pub list_root: [u8; 32],
    /// The new epoch's seed boxed to each device on its maker's roster (spec/crypto.md §9,
    /// Custody): ascending by tag, distinct.
    pub seeds: Vec<SeedBox>,
}

/// One seed box of a rotation (spec/wire.md §4): its tag and the sealed box to a device's KEM
/// key (`osis_crypto::seal_seeds`).
#[derive(Clone, PartialEq, Eq)]
pub struct SeedBox {
    pub tag: [u8; osis_crypto::SEED_TAG_LEN],
    pub sealed: Vec<u8>,
}

impl std::fmt::Debug for SeedBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SeedBox({:02x?}, {} bytes)", &self.tag[..4], self.sealed.len())
    }
}

impl RotationHeader {
    /// Whether it is a merge certificate: it names the tips it joins besides the one it is
    /// signed at (spec/crypto.md §9, Merges).
    pub fn is_merge(&self) -> bool {
        !self.names.is_empty()
    }

    /// The ID of the epoch it mints (spec/crypto.md §9): a plain rotation's is its commit ID
    /// `id`; a merge's `BLAKE3("osis v1 merge epoch" || signing key || its tips ascending)`, alike
    /// in every certificate of it.
    pub fn mints(&self, id: &CommitId) -> CommitId {
        if !self.is_merge() {
            return *id;
        }
        merge_epoch(&self.signing_key, &self.supersedes)
    }

    fn put(&self, out: &mut Vec<u8>) {
        let ids = |out: &mut Vec<u8>, v: &[CommitId]| {
            put_array(out, v.len());
            v.iter().for_each(|c| put_bytes(out, &c.0));
        };
        put_array(out, 9);
        put_signing_key(out, &self.signing_key);
        encode_into(&self.kem_key.to_value(), out);
        ids(out, &self.supersedes);
        ids(out, &self.names);
        ids(out, &self.takes);
        osis_base::cbor::put_bool(out, self.revokes);
        put_bytes(out, &self.devices);
        put_bytes(out, &self.list_root);
        put_seed_boxes(out, &self.seeds);
    }

    fn read(v: Item) -> Result<RotationHeader, Error> {
        let Some([sk, kem, sup, names, takes, revokes, devices, root, seeds]) = item::list(v)?.tuple() else { return Err(Error::Malformed("rotation arity")) };
        let signing_key = read_signing_key(sk)?;
        let kem_key = KemPublicKey::from_value(&kem.to_value()?).map_err(|_| Error::Malformed("rotation kem key"))?;
        let ids = |v: Item| -> Result<Vec<CommitId>, Error> { item::list(v)?.iter().map(|c| item::bytes(c).map(CommitId)).collect() };
        let seeds = read_seed_boxes(seeds)?;
        let Ok(Value::Bool(revokes)) = revokes.to_value() else { return Err(Error::Malformed("rotation revokes")) };
        let devices: Vec<u8> = devices.as_bytes().ok_or(Error::Malformed("rotation devices"))?.to_vec();
        Ok(RotationHeader { signing_key, kem_key, supersedes: ids(sup)?, names: ids(names)?, takes: ids(takes)?, revokes, devices, list_root: item::bytes(root)?, seeds })
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
    put_uint(out, a.purge_by as u64);
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
        PurgeItem::Author { tid, ak, author } => {
            put_array(out, 3);
            put_tid_bytes(out, tid);
            put_text(out, ak.as_str());
            put_tid_bytes(out, author);
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
                Some(ids) => put_frontier(out, ids),
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
            (ListField::Frontier, None) => put_opt(out, self.frontier.as_deref(), put_frontier),
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
        self.encode_with(out, &|h, out, f| h.put_position(out, f));
    }

    /// The header's canonical bytes with each list `linked` names written empty and every other
    /// as it sits inline: what the lists that go by link are keyed by (`list_secret`), the same
    /// before they are written and once they are linked.
    fn skeleton(&self, linked: &dyn Fn(ListField) -> bool) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_with(&mut out, &|h, out, f| if linked(f) { put_array(out, 0) } else { h.put_position(out, f) });
        out
    }

    /// The key of this header's linked lists' content hashes (spec/wire.md §4 Inline or link):
    /// `kdf("header list", signer dedup secret, skeleton)`. Two commits differing anywhere outside
    /// their linked lists key them apart, so a list's blobs serve one commit only and what its
    /// header costs a node to hold is what its signer delivered for it (notes/decode-bounds.md).
    pub fn list_secret(&self, signer_dedup: &Secret32) -> Secret32 {
        self.list_secret_for(signer_dedup, &|f| self.links.get(f).is_some())
    }

    pub(crate) fn list_secret_for(&self, signer_dedup: &Secret32, linked: &dyn Fn(ListField) -> bool) -> Secret32 {
        osis_crypto::kdf::kdf("header list", signer_dedup.expose(), &self.skeleton(linked))
    }

    fn encode_with(&self, out: &mut Vec<u8>, position: &dyn Fn(&Header, &mut Vec<u8>, ListField)) {
        // the flags are trailing, absent when none is set
        let flags = self.flags();
        put_array(out, if flags != 0 { 18 } else { 17 });
        put_uint(out, FORMAT_VERSION);
        put_tid_bytes(out, &self.signer);
        self.path.put(out);
        put_uint(out, self.kind.id());
        put_uint(out, self.ts.to_u64());
        self.form.put(out);
        put_opt(out, self.expires, put_uint);
        position(self, out, ListField::Aspects);
        position(self, out, ListField::Purge);
        put_opt(out, self.undoes, |out, c| put_bytes(out, &c.0));
        put_bytes(out, &self.blind);
        position(self, out, ListField::Keys);
        position(self, out, ListField::Frontier);
        put_opt(out, self.ephemeral, |out, c| put_uint(out, c as u64));
        put_opt(out, self.epoch, |out, c| put_bytes(out, &c.0));
        put_opt(out, self.rotation.as_ref(), |out, r| r.put(out));
        put_opt(out, self.reseal.as_ref(), |out, r| r.put(out));
        if flags != 0 {
            put_uint(out, flags);
        }
    }

    /// The header's `flags` (spec/wire.md §4 field 17): bit 0 own cover, bit 1 adminless.
    fn flags(&self) -> u64 {
        u64::from(self.own_cover) | u64::from(self.adminless) << 1
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

/// Verifies the signer's signature of `sigs` for commit `id` (spec/crypto.md §2): what it
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

/// How many more times an account commit carrying `rotation` seals its inner signature
/// (`Sigs::more`, spec/wire.md §4): a plain rotation's once more (the epoch it mints), a merge
/// certificate's once per named tip and once for the merge epoch, any other commit's never.
pub fn inner_seals(rotation: Option<&RotationHeader>) -> usize {
    rotation.map_or(0, |r| r.names.len() + 1)
}

/// A merge epoch's ID from its signing key and its tips, ascending (spec/crypto.md §9).
pub fn merge_epoch(signing_key: &VerifyingKey, tips: &[CommitId]) -> CommitId {
    let mut h = osis_base::hash::Hasher::new();
    h.update(osis_crypto::kdf::MERGE_EPOCH.as_bytes()).update(&signing_key.to_bytes());
    for t in tips {
        h.update(&t.0);
    }
    CommitId(h.finalize())
}

/// Verifies a merge certificate's signature by a tip's key over the merge epoch's ID `epoch`
/// (spec/crypto.md §9).
pub fn verify_merge(epoch: &CommitId, sig: &Signature, tip_key: &VerifyingKey) -> bool {
    tip_key.verify(Domain::Merge, &epoch.0, sig).is_ok()
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

fn read_purge_by(r: &mut Reader<'_>) -> Result<PurgeBy, Error> {
    let by = PurgeBy::from_id(r.uint()?).ok_or(Error::Malformed("purge-by class"))?;
    Ok(by)
}

fn read_aspect(r: &mut Reader<'_>) -> Result<AspectEntry, Error> {
    if r.array()? != 8 {
        return Err(Error::Malformed("aspect arity"));
    }
    let (tid, ak, lo, hi) = (read_tid(r)?, read_ak(r)?, r.uint()?, r.uint()?);
    let (purge_by, keys) = (read_purge_by(r)?, read_idxs(r)?);
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
    Ok(AspectEntry { tid, ak, lo, hi, purge_by, keys, hash, replaces, original_floor })
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
        3 => Ok(PurgeItem::Author { tid: read_tid(r)?, ak: read_ak(r)?, author: read_tid(r)? }),
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

/// The commit IDs of a frontier's bytes: exactly `{0: set<32-byte ID>}` (spec/wire.md §4), read
/// as they come (32 B an ID held, against 34 sent).
pub fn frontier_ids(bytes: &[u8]) -> Result<Arc<[CommitId]>, Error> {
    let mut r = Reader::new(bytes);
    if r.map()? != 1 || r.uint()? != 0 {
        return Err(Error::Malformed("frontier"));
    }
    r.tag(TAG_SET)?;
    let ids = read_items(&mut r, MIN_ID, |r| Ok(CommitId(r.fixed::<32>()?)))?;
    r.end()?;
    Ok(ids.into())
}

/// Appends the frontier of `ids` (ascending, distinct): `{0: set<32-byte ID>}`, canonical.
pub fn put_frontier(out: &mut Vec<u8>, ids: &[CommitId]) {
    debug_assert!(ids.is_sorted_by(|a, b| a < b), "frontier IDs ascending and distinct");
    put_map(out, 1);
    put_uint(out, 0);
    head(out, MAJOR_TAG, TAG_SET);
    put_array(out, ids.len());
    for c in ids {
        put_bytes(out, &c.0);
    }
}

impl Header {
    /// Fills list `f` from its canonical bytes; `check`: delete keys' points too (not a stored
    /// header, checked when it arrived).
    pub(crate) fn read_list(&mut self, f: ListField, bytes: &[u8], check: bool) -> Result<(), Error> {
        if f == ListField::Frontier {
            self.frontier = Some(frontier_ids(bytes)?);
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
        let all: Vec<Item> = items.into_iter().collect();
        let flags = match all.get(17) {
            None => 0,
            Some(m) if all.len() == 18 => match item::uint(*m)? {
                f @ 1..=3 => f,
                _ => return Err(Error::Malformed("header flags")),
            },
            Some(_) => return Err(Error::Malformed("header arity")),
        };
        let Some([_, signer, path, kind, ts, form, expires, aspects, purge, undoes, blind, keys, frontier, ephemeral, epoch, rotation, reseal]) = all.get(..17).and_then(|x| <[Item; 17]>::try_from(x).ok()) else {
            return Err(Error::Malformed("header arity"));
        };
        let signer = item::tid(signer)?;
        let mut h = Header {
            signer,
            path: Paths::read(path, &signer)?,
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
            reseal: item::opt(reseal)?.map(SeedReseal::read).transpose()?,
            own_cover: flags & 1 != 0,
            adminless: flags & 2 != 0,
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

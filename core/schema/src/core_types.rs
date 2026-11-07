//! Rust types of the core aspects (spec/data-model.md §9; agility enums and the creation record:
//! spec/wire.md §3) and their typed keys. Byte lengths the spec fixes are enforced here (a wrong
//! length is a type mismatch); unknown agility cases are `UnknownCase` (parked).

use crate::codec::{Codec, rt};
use crate::{codec_enum, codec_struct};
use crate::keys::Aspect;
use crate::path::{Path, PathError, PathErrorKind};
use crate::statics::CORE;
use osis_base::{CommitId, CreationRecord, LabelId, Role, Tid, Ts, Value, WallMs};
use std::collections::{BTreeMap, BTreeSet};

/// Role-class aspects (spec/data-model.md §9): fixed retention, spec/commits.md §2.
pub const ROLE_CLASS: [&str; 4] = ["roles.0", "secrets.0", "keys.0", "label.0"];

pub fn is_role_class(ak: &str) -> bool {
    ROLE_CLASS.contains(&ak)
}

/// The addenda aspect (spec/permissions.md §5.2, Addenda).
pub const ADDENDA_AK: &str = "addenda.0";

/// Whether `ak` is the addenda aspect.
pub fn is_addenda(ak: &str) -> bool {
    ak == ADDENDA_AK
}

/// Whether `ak` is a thing's content: what a delete removes, an undone creation resets and a read
/// of the thing counts: no creation record, no rights, no retention rule (spec/commits.md §5)
/// and no addenda.
pub fn is_content(ak: &str) -> bool {
    !is_role_class(ak) && !is_addenda(ak) && ak != "created.0" && ak != "required.0^"
}

/// Whether `ak` is a core schema key by its form: one name segment, no tid (spec/data-model.md
/// §2), declared there or not.
pub fn is_core_key(ak: &str) -> bool {
    osis_base::Ak::new(ak).is_ok_and(|a| a.tid().is_none() && a.segments().count() == 1)
}

fn mismatch(expected: &'static str) -> PathError {
    PathError::new(Path::root(), PathErrorKind::Mismatch { expected })
}

/// One-case agility enum over a blob with an optional fixed length.
macro_rules! agility {
    ($(#[$m:meta])* $name:ident, $variant:ident, $len:expr) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $variant(Vec<u8>),
        }
        #[doc(hidden)]
        impl Codec for $name {
            fn to_value(&self) -> Value {
                match self {
                    $name::$variant(b) => rt::enum_value(1, Some(Value::Bytes(b.clone()))),
                }
            }
            fn from_value(v: &Value) -> Result<$name, PathError> {
                match v {
                    Value::Enum(1, p) => {
                        let b: Vec<u8> = rt::payload(1, p)?;
                        let len: Option<usize> = $len;
                        if len.is_some_and(|n| n != b.len()) {
                            return Err(mismatch(concat!(stringify!($name), " of its fixed length")).within(crate::Step::Case(1)));
                        }
                        Ok($name::$variant(b))
                    }
                    _ => Err(rt::unknown_case(v)),
                }
            }
        }
    };
}

agility!(
    /// `signing_key = enum { 1 ed25519(blob) }`, 32 bytes.
    SigningKey, Ed25519, Some(32)
);
agility!(
    /// `signature = enum { 1 ed25519(blob) }`, 64 bytes.
    Signature, Ed25519, Some(64)
);
agility!(
    /// `kem_key = enum { 1 x25519_mlkem768(blob) }`, `pk_x || pk_m`, 1216 bytes.
    KemKey, X25519MlKem768, Some(1216)
);
agility!(
    /// `sealed = enum { 1 x25519_mlkem768(blob) }`, `ct_x || ct_m || AEAD`.
    Sealed, X25519MlKem768, None
);

/// `created.0`: the creation record (spec/wire.md §3).
#[doc(hidden)]
impl Codec for CreationRecord {
    const CHECKS_ITSELF: bool = true;
    fn to_value(&self) -> Value {
        CreationRecord::to_value(self)
    }
    fn from_value(v: &Value) -> Result<CreationRecord, PathError> {
        // An unknown signing_key case (ed25519 is 1) parks the thing (spec/wire.md §3).
        if let Value::Map(m) = v
            && let Some(Value::Enum(c, _)) = m.get(&Value::Int(1))
            && *c != 1
        {
            return Err(PathError::new(Path::root().push(crate::Step::Field(1)), PathErrorKind::UnknownCase(*c)));
        }
        CreationRecord::from_value(v).ok_or_else(|| mismatch("creation record"))
    }
}

codec_struct! {
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Epoch { 0 n: u64, 1 nonce: [u8; 32] }
}
codec_struct! {
    /// Transport URL and 32-byte host static key.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Address { 0 url: String, 1 key: [u8; 32] }
}
codec_enum! {
    /// A dot's source (spec/crdt.md §2.1); a session as `Sources` encodes it (spec/crdt.md
    /// §3.2): the node's tid, then its 16-byte nonce.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Source { 0 Commit(c: CommitId), 1 Session(s: [u8; 31]) }
}
codec_struct! {
    /// The `group.0` element a tied edge names: its creation stamp and whether it is a subgroup
    /// (spec/permissions.md §2).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Tie { 0 ts: Ts, 1 source: Source, 2 ctr: u64, 3 subgroup: bool }
}
codec_struct! {
    /// A role edge; `tied`: the membership of the target in its holder, a group, the edge goes
    /// with (spec/permissions.md §2).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Edge { 0 role: Role, 1 until: Option<WallMs>, 2 invite: Option<Role>, 3 tied: Option<Tie> }
}
codec_struct! {
    /// A keyset: epoch, KEM key, suite ID of the epoch, delete key, the epochs its rotation
    /// supersedes, and possession key (spec/crypto.md §3, §4, §7, §8).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Keyset { 0 epoch: Epoch, 1 kem_key: KemKey, 2 suite: u64, 3 delete_key: SigningKey, 4 supersedes: BTreeSet<Epoch>, 5 possession_key: SigningKey, 6 names: [u8; 32] }
}
codec_struct! {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Inbox { 0 label: LabelId, 1 hosts: Vec<Address> }
}
codec_struct! {
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct BoxKey { 0 holder: Tid, 1 role: Role, 2 epoch: Epoch }
}
codec_struct! {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SealedBox { 0 keyset: Option<Epoch>, 1 suite: u64, 2 sealed: Sealed }
}
codec_struct! {
    /// `epoch` of s; `wrap`; `possession`: the possession signature, iff the holder is not a
    /// key actor (spec/wire.md §7, spec/crypto.md §4).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SymmetricBox { 0 epoch: Epoch, 1 wrap: Vec<u8>, 2 possession: Option<Signature> }
}

codec_enum! {
    /// `box = enum { 0 sealed(..), 1 symmetric(..) }` (spec/crypto.md §4).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum SecretBox { 0 Sealed(b: SealedBox), 1 Symmetric(b: SymmetricBox) }
}
codec_struct! {
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct HistoryKey { 0 role: Role, 1 epoch: Epoch }
}
codec_struct! {
    /// Revoke frontier: the commit IDs the demoter received (spec/permissions.md §5.1).
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Frontier { 0 commits: BTreeSet<CommitId> }
}
codec_struct! {
    /// Step and claim-set bytes (spec/wire.md §8).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct StepRecord { 0 step: Vec<u8>, 1 claims: Option<Vec<u8>> }
}
codec_struct! {
    /// A label of a synced group; steps by step ID.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Label { 0 index: u64, 1 steps: BTreeMap<[u8; 32], StepRecord>, 2 hosts: Vec<Address>, 3 replaced: bool }
}
codec_struct! {
    /// `keys.0`: keysets per role (actors other than key actors), a key actor's KEM key, inbox,
    /// 32-byte deposit seed.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Keys {
        0 read: Option<Keyset>, 1 write: Option<Keyset>, 2 admin: Option<Keyset>,
        3 key: Option<KemKey>, 4 inbox: Option<Inbox>, 5 deposit_seed: Option<[u8; 32]>,
    }
}
codec_struct! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Secrets { 0 boxes: BTreeMap<BoxKey, SecretBox>, 1 history: BTreeMap<HistoryKey, Vec<u8>> }
}
codec_struct! {
    /// `node.0`: software version.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct NodeInfo { 0 software: String }
}
codec_struct! {
    /// `reach.0`: 32-byte P2P key, `peer://` items (direct addresses, relays), 32-byte LAN secret.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Reach { 0 dialable: [u8; 32], 1 items: Vec<String>, 2 lan_secret: [u8; 32] }
}
codec_struct! {
    /// `seen.0`: heartbeat (wall ms of the commit's ts), the aspects its node reports suspect.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Seen { 0 ts: WallMs, 1 stranded: bool, 2 suspect: BTreeSet<Suspect> }
}
codec_struct! {
    /// A suspect aspect in a heartbeat: thing, AK, keyed state digest (spec/permissions.md §4).
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Suspect { 0 thing: Tid, 1 ak: String, 2 digest: [u8; 16] }
}
codec_enum! {
    /// Which groups a serving node takes: `Own`, groups whose record chain reaches the node or its
    /// account and that name its serving address (a group it only reads or administers by a grant is
    /// not one); `Open`, any group within the caps.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub enum Admit { #[default] 0 Own, 1 Open }
}
codec_struct! {
    /// One group's limits at a serving node, in place of its policy's.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct HostCaps { 0 entries: u64, 1 bytes: u64 }
}
codec_struct! {
    /// `host.0^`: this node hosts (spec/data-model.md §9).
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Host {
        0 listen: Vec<String>, 1 admit: Admit, 2 labels: BTreeSet<LabelId>, 3 replicate: Vec<Address>,
        4 policy: BTreeMap<String, u64>, 5 caps: BTreeMap<LabelId, HostCaps>,
    }
}
codec_struct! {
    /// One entry of `clients.0^` (spec/data-model.md §9): a thin client's secret hash and end.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Client { 0 secret_hash: [u8; 32], 1 until: Option<WallMs> }
}
#[doc(hidden)]
impl Codec for osis_base::PurgeBy {
    fn to_value(&self) -> Value {
        rt::enum_value(*self as u64, None)
    }
    fn from_value(v: &Value) -> Result<osis_base::PurgeBy, PathError> {
        match v {
            Value::Enum(c, None) => usize::try_from(*c).ok().and_then(|c| [Self::Nobody, Self::Admin, Self::AuthorOrAdmin, Self::Writer, Self::Author].get(c).copied()).ok_or_else(|| rt::unknown_case(v)),
            _ => Err(rt::unknown_case(v)),
        }
    }
}
codec_struct! {
    /// A retention bound of `Required`, as `Bound` is of `Retention`.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct RequiredBound { 0 abs: Option<u64>, 1 rel: Option<u64> }
}
codec_struct! {
    /// The retention and expiry a write under an aspect name prefix must carry; `expires` as a
    /// duration from the write, none: no expiry.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Required { 0 by: osis_base::PurgeBy, 1 at_least: RequiredBound, 2 at_most: RequiredBound, 3 expires: Option<u64> }
}
impl Required {
    pub fn new(r: crate::Retention, expires: Option<u64>) -> Required {
        let b = |x: crate::Bound| RequiredBound { abs: x.abs, rel: x.rel };
        Required { by: r.by, at_least: b(r.at_least), at_most: b(r.at_most), expires }
    }
    pub fn retention(&self) -> crate::Retention {
        let b = |x: RequiredBound| crate::Bound { abs: x.abs, rel: x.rel };
        crate::Retention { by: self.by, at_least: b(self.at_least), at_most: b(self.at_most) }
    }
    /// The expiry a write stamped at `wall` ms must carry (`None` when out of range: no write
    /// meets it).
    pub fn expires_at(&self, wall: u64) -> Option<Option<u64>> {
        match self.expires {
            None => Some(None),
            Some(d) => wall.checked_add(d).map(Some),
        }
    }
}

codec_struct! {
    /// The retention required by aspect name prefix; `retain`: a removal from the thing retains a
    /// read-only copy unless its remover says otherwise.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct RequiredRules { 0 rules: BTreeMap<String, Required>, 1 retain: bool }
}

impl RequiredRules {
    pub fn new() -> RequiredRules {
        RequiredRules::default()
    }
}

impl From<BTreeMap<String, Required>> for RequiredRules {
    fn from(rules: BTreeMap<String, Required>) -> RequiredRules {
        RequiredRules { rules, retain: false }
    }
}

impl FromIterator<(String, Required)> for RequiredRules {
    fn from_iter<I: IntoIterator<Item = (String, Required)>>(i: I) -> RequiredRules {
        BTreeMap::from_iter(i).into()
    }
}

/// What `required.0^` value `v` requires (spec/commits.md §5): nothing, if it does not read as the
/// type or is over the bounds.
pub fn required_rules(v: &Value) -> RequiredRules {
    RequiredRules::from_value(v).ok().filter(required_fits).unwrap_or_default()
}

/// Whether `rules` is within the bounds of one `required.0^` delta.
pub fn required_fits(rules: &RequiredRules) -> bool {
    rules.rules.len() <= osis_base::format::MAX_REQUIRED_ENTRIES && rules.rules.keys().all(|p| p.len() <= osis_base::format::MAX_AK_BYTES)
}

/// The entry of `rules` governing `ak`: its longest prefix.
pub fn required_for<'a>(rules: &'a RequiredRules, ak: &str) -> Option<&'a Required> {
    (0..=ak.len()).rev().filter(|n| ak.is_char_boundary(*n)).find_map(|n| ak.get(..n).and_then(|p| rules.rules.get(p)))
}

/// `group.0`: a field never written reads empty, its default in the
/// schema. A first member so needs no write of the other field, which beside a concurrent add
/// would risk it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Group {
    pub items: BTreeSet<Tid>,
    pub subgroups: BTreeSet<Tid>,
}

#[doc(hidden)]
impl Codec for Group {
    fn to_value(&self) -> Value {
        rt::struct_value(vec![(0, self.items.to_value()), (1, self.subgroups.to_value())])
    }
    fn from_value(v: &Value) -> Result<Self, PathError> {
        let m = rt::struct_map(v)?;
        let set = |id: u64| if m.contains_key(&id.to_value()) { rt::field(m, id) } else { Ok(BTreeSet::new()) };
        Ok(Group { items: set(0)?, subgroups: set(1)? })
    }
}
codec_struct! {
    /// A tag's own settings.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Tag { 0 color: Option<String> }
}

pub type Holders = BTreeMap<Tid, Edge>;
pub type Labels = BTreeMap<LabelId, Label>;

pub const TID: Aspect<Tid> = Aspect::new("tid.0", &CORE);
pub const ASPECTS: Aspect<BTreeSet<String>> = Aspect::new("aspects.0", &CORE);
pub const CREATED: Aspect<CreationRecord> = Aspect::new("created.0", &CORE);
pub const ROLES: Aspect<Holders> = Aspect::new("roles.0", &CORE);
/// Removal commit ID -> what the author vouches for (spec/permissions.md §5.2, Addenda).
pub type Addenda = BTreeMap<Vec<u8>, Frontier>;
pub const ADDENDA: Aspect<Addenda> = Aspect::new(ADDENDA_AK, &CORE);
pub const KEYS: Aspect<Keys> = Aspect::new("keys.0", &CORE);
pub const SECRETS: Aspect<Secrets> = Aspect::new("secrets.0", &CORE);
pub const LABEL: Aspect<Labels> = Aspect::new("label.0", &CORE);
pub const NODE: Aspect<NodeInfo> = Aspect::new("node.0", &CORE);
pub const REACH: Aspect<Reach> = Aspect::new("reach.0", &CORE);
pub const SEEN: Aspect<Seen> = Aspect::new("seen.0", &CORE);
pub const HOST: Aspect<Host> = Aspect::new("host.0^", &CORE);
/// `clients.0^`: by client actor.
pub const CLIENTS: Aspect<BTreeMap<Tid, Client>> = Aspect::new("clients.0^", &CORE);
pub const REQUIRED: Aspect<RequiredRules> = Aspect::new("required.0^", &CORE);
/// `purge.0`: the delta of a purge request naming no aspect to reset; fixed retention (spec/commits.md §5).
pub const PURGE: Aspect<WallMs> = Aspect::new("purge.0", &CORE);
pub const GROUP: Aspect<Group> = Aspect::new("group.0", &CORE);
pub const GROUPS: Aspect<BTreeSet<Tid>> = Aspect::new("groups.0", &CORE);
pub const NAME: Aspect<String> = Aspect::new("name.0", &CORE);
pub const BODY: Aspect<String> = Aspect::new("body.0", &CORE);
pub const TAG: Aspect<Tag> = Aspect::new("tag.0", &CORE);

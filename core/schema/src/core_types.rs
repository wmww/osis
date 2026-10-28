//! Rust types of the core aspects (spec/data-model.md §9; agility enums and the creation record:
//! spec/wire.md §3) and their typed keys. Byte lengths the spec fixes are enforced here (a wrong
//! length is a type mismatch); unknown agility cases are `UnknownCase` (parked).

use crate::codec::{Chunked, Codec, rt};
use crate::codec_struct;
use crate::keys::Aspect;
use crate::path::{Path, PathError, PathErrorKind};
use crate::statics::CORE;
use osis_core::{CommitId, CreationRecord, LabelId, Role, SchemaId, Tid, Ts, Value, WallMs};
use std::collections::{BTreeMap, BTreeSet};

/// Membership-class aspects (spec/data-model.md §9): fixed retention, spec/commits.md §2.
pub const MEMBERSHIP_CLASS: [&str; 7] = ["/members", "/secrets", "/keys", "/label", "/tenures", "/moved", "/was"];

pub fn is_membership_class(ak: &str) -> bool {
    MEMBERSHIP_CLASS.contains(&ak)
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
    /// `kem_key = enum { 1 x25519_mlkem768(blob) }`, `pk_x || pk_m`, 1216 bytes.
    KemKey, X25519MlKem768, Some(1216)
);
agility!(
    /// `sealed = enum { 1 x25519_mlkem768(blob) }`, `ct_x || ct_m || AEAD`.
    Sealed, X25519MlKem768, None
);

/// `/created`: the creation record (spec/wire.md §3).
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
    pub struct Epoch { 0 n: u64, 1 nonce: [u8; 16] }
}
codec_struct! {
    /// Transport URL and 32-byte server static key.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Address { 0 url: String, 1 key: [u8; 32] }
}
codec_struct! {
    /// (ts, author node, commit ID) of a write.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct EdgeKey { 0 ts: Ts, 1 node: Tid, 2 commit: CommitId }
}
codec_struct! {
    /// A membership edge; `since` only in roster snapshots (spec/permissions.md §6).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Edge { 0 role: Role, 1 until: Option<WallMs>, 2 invite: Option<Role>, 3 since: Option<EdgeKey> }
}
codec_struct! {
    /// A keyset: epoch, KEM key, suite ID of the epoch, delete key (spec/crypto.md §3, §4, §7, §8).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Keyset { 0 epoch: Epoch, 1 kem_key: KemKey, 2 suite: u64, 3 delete_key: SigningKey }
}
codec_struct! {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Inbox { 0 label: LabelId, 1 servers: Vec<Address> }
}
codec_struct! {
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct BoxKey { 0 member: Tid, 1 role: Role, 2 epoch: Epoch }
}
codec_struct! {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SealedBox { 0 keyset: Option<Epoch>, 1 suite: u64, 2 sealed: Sealed }
}
codec_struct! {
    /// `epoch` of s; `wrap`: spec/wire.md §7.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SymmetricBox { 0 epoch: Epoch, 1 wrap: Vec<u8> }
}

/// `box = enum { 0 sealed(..), 1 symmetric(..) }` (spec/crypto.md §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretBox {
    Sealed(SealedBox),
    Symmetric(SymmetricBox),
}

impl Codec for SecretBox {
    fn to_value(&self) -> Value {
        match self {
            SecretBox::Sealed(b) => rt::enum_value(0, Some(b.to_value())),
            SecretBox::Symmetric(b) => rt::enum_value(1, Some(b.to_value())),
        }
    }
    fn from_value(v: &Value) -> Result<SecretBox, PathError> {
        match v {
            Value::Enum(0, p) => rt::payload(0, p).map(SecretBox::Sealed),
            Value::Enum(1, p) => rt::payload(1, p).map(SecretBox::Symmetric),
            _ => Err(rt::unknown_case(v)),
        }
    }
}

codec_struct! {
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct HistoryKey { 0 role: Role, 1 epoch: Epoch }
}
codec_struct! {
    /// Revoke frontier: tid -> AK -> author node -> counter; commit IDs of commit-form writes.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Frontier { 0 writes: BTreeMap<Tid, BTreeMap<String, BTreeMap<Tid, u64>>>, 1 commits: BTreeSet<CommitId> }
}
codec_struct! {
    /// A tenure ledger entry; a large frontier is a link.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Tenure { 0 member: Tid, 1 role: Role, 2 since: Option<EdgeKey>, 3 until: EdgeKey, 4 frontier: Option<Chunked<Frontier>> }
}
codec_struct! {
    /// Step and claim-set bytes (spec/wire.md §8).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct StepRecord { 0 step: Vec<u8>, 1 claims: Option<Vec<u8>> }
}
codec_struct! {
    /// A label of a synced group; steps by step ID.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Label { 0 index: u64, 1 steps: BTreeMap<[u8; 32], StepRecord>, 2 servers: Vec<Address>, 3 replaced: bool }
}
codec_struct! {
    /// `/keys`: keysets per role (actors other than key actors), a key actor's KEM key, inbox,
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
    /// `/node`: software revision, schema ID -> revision.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct NodeInfo { 0 software: String, 1 schemas: BTreeMap<SchemaId, u64> }
}
codec_struct! {
    /// `/reach`: 32-byte P2P key, relay URLs, 32-byte LAN secret.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Reach { 0 dialable: [u8; 32], 1 relays: Vec<String>, 2 lan_secret: [u8; 32] }
}
codec_struct! {
    /// `/seen`: heartbeat (wall ms of the commit's ts).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Seen { 0 ts: WallMs, 1 stranded: bool }
}
codec_struct! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Group { 0 items: BTreeSet<Tid>, 1 subgroups: BTreeSet<Tid> }
}
codec_struct! {
    /// `/tag`: marks a group as a user-facing tag (notes/tags.md).
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Tag { 0 color: Option<String> }
}

/// `/tenures`: a set of tenures (kept as a list in canonical order: `Link` has no `Ord`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tenures(pub Vec<Tenure>);

impl Codec for Tenures {
    fn to_value(&self) -> Value {
        Value::Set(self.0.iter().map(Codec::to_value).collect())
    }
    fn from_value(v: &Value) -> Result<Tenures, PathError> {
        match v {
            Value::Set(s) => s.iter().map(|x| Tenure::from_value(x).map_err(|e| e.within(crate::Step::Elem(x.clone())))).collect::<Result<_, _>>().map(Tenures),
            _ => Err(mismatch("set")),
        }
    }
}

pub type Members = BTreeMap<Tid, Edge>;
pub type Labels = BTreeMap<LabelId, Label>;

pub const TID: Aspect<Tid> = Aspect::new("/tid", &CORE);
pub const ASPECTS: Aspect<BTreeSet<String>> = Aspect::new("/aspects", &CORE);
pub const CREATED: Aspect<CreationRecord> = Aspect::new("/created", &CORE);
pub const MEMBERS: Aspect<Members> = Aspect::new("/members", &CORE);
pub const KEYS: Aspect<Keys> = Aspect::new("/keys", &CORE);
pub const SECRETS: Aspect<Secrets> = Aspect::new("/secrets", &CORE);
pub const TENURES: Aspect<Tenures> = Aspect::new("/tenures", &CORE);
pub const LABEL: Aspect<Labels> = Aspect::new("/label", &CORE);
pub const MOVED: Aspect<Tid> = Aspect::new("/moved", &CORE);
pub const WAS: Aspect<Tid> = Aspect::new("/was", &CORE);
pub const NODE: Aspect<NodeInfo> = Aspect::new("/node", &CORE);
pub const REACH: Aspect<Reach> = Aspect::new("/reach", &CORE);
pub const SEEN: Aspect<Seen> = Aspect::new("/seen", &CORE);
pub const GROUP: Aspect<Group> = Aspect::new("/group", &CORE);
pub const GROUPS: Aspect<BTreeSet<Tid>> = Aspect::new("/groups", &CORE);
pub const NAME: Aspect<String> = Aspect::new("/name", &CORE);
pub const BODY: Aspect<String> = Aspect::new("/body", &CORE);
pub const TAG: Aspect<Tag> = Aspect::new("/tag", &CORE);

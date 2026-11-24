//! Rust types of the core aspects (spec/data-model.md §9; agility enums and the creation record:
//! spec/wire.md §3) and their typed keys. Byte lengths the spec fixes are enforced here (a wrong
//! length is a type mismatch); unknown agility cases are `UnknownCase` (parked).

use crate::codec::{Codec, mismatch, rt};
use crate::{codec_enum, codec_struct};
use crate::keys::Aspect;
use crate::path::{Path, PathError, PathErrorKind};
use crate::statics::CORE;
use osis_base::{Ak, CommitId, CreationRecord, Ref, Role, SyncId, Ts, Value, WallMs, Weak};
use std::collections::{BTreeMap, BTreeSet};

/// Role-class aspects (spec/data-model.md §9): fixed retention, spec/commits.md §2.
pub const ROLE_CLASS: [&str; 5] = ["roles.0", "signers.0", "secrets.0", "keys.0", "sync.0"];

pub fn is_role_class(ak: &str) -> bool {
    ROLE_CLASS.contains(&ak)
}

/// Whether `ak` is never compaction-snapshotted (spec/commits.md §2): the role timeline walks
/// every edge write.
pub fn never_compacted(ak: &str) -> bool {
    ak == "roles.0" || ak == "signers.0"
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
    !is_role_class(ak) && !is_addenda(ak) && ak != "created.0" && ak != "retention^.0"
}

/// Whether `has_content` reads `ak`: content, but `purge.0`, which only places a purge request
/// (spec/commits.md §5 Purge).
pub fn counts_as_content(ak: &str) -> bool {
    is_content(ak) && ak != "purge.0"
}

/// Whether `ak` is a core schema key by its form: one name segment, no tid (spec/data-model.md
/// §2), declared there or not.
pub fn is_core_key(ak: &str) -> bool {
    osis_base::Ak::new(ak).is_ok_and(|a| a.tid().is_none() && a.segments().count() == 1)
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
    /// `signing_key = enum { ed25519 1 (blob) }`, 32 bytes.
    SigningKey, Ed25519, Some(32)
);
agility!(
    /// `kem_key = enum { x25519_mlkem768 1 (blob) }`, `pk_x || pk_m`, 1216 bytes.
    KemKey, X25519MlKem768, Some(1216)
);
agility!(
    /// `sealed = enum { x25519_mlkem768 1 (blob) }`, `ct_x || ct_m || AEAD`.
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
pub use osis_base::Address;

impl Codec for Address {
    fn to_value(&self) -> Value {
        rt::struct_value(vec![(0, self.url.to_value()), (1, self.key.to_value())])
    }
    fn from_value(v: &Value) -> Result<Address, PathError> {
        let m = rt::struct_map(v)?;
        Ok(Address { url: rt::field(m, 0)?, key: rt::field(m, 1)? })
    }
}
codec_enum! {
    /// A dot's source (spec/crdt.md §2.1); a session as `Sources` encodes it (spec/crdt.md
    /// §3.2): the node's tid, then its 16-byte nonce.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Source { 0 Commit(c: CommitId), 1 Session(s: [u8; 31]) }
}
codec_struct! {
    /// A role edge; `retain`: with `until`, its passing says retain (spec/permissions.md §3,
    /// Retain); `floor`: the read n its holder reads from, granted without history
    /// (spec/crypto.md §4, Floors).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Edge { 0 role: Role, 1 until: Option<WallMs>, 2 may_grant: bool, 3 retain: bool, 4 floor: Option<u64> }
}
codec_struct! {
    /// A keyset: epoch, KEM key, suite ID of the epoch, delete key, the epochs its rotation
    /// supersedes, names digest, the keysets of each holder actor its rotation left out at, and
    /// the demotions it carries: other commits', and whether its own commit is one
    /// (spec/crypto.md §3, §4, §7, §8).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Keyset { 0 epoch: Epoch, 1 kem_key: KemKey, 2 suite: u64, 3 delete_key: SigningKey, 4 supersedes: BTreeSet<Epoch>, 5 names: [u8; 32], 6 left_out: BTreeMap<Weak, BTreeSet<Epoch>>, 7 demotions: BTreeSet<CommitId>, 8 demotes: bool }
}
codec_struct! {
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct BoxKey { 0 holder: Weak, 1 role: Role, 2 epoch: Epoch }
}
codec_struct! {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SealedBox { 0 keyset: Option<Epoch>, 1 suite: u64, 2 sealed: Sealed }
}
codec_struct! {
    /// `epoch` of s; `wrap` (spec/wire.md §7).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SymmetricBox { 0 epoch: Epoch, 1 wrap: Vec<u8> }
}
codec_struct! {
    /// `keysets`: the holder's keysets it is sealed to, nested in turn (spec/crypto.md §4, Seal).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct JointBox { 0 keysets: BTreeSet<Epoch>, 1 suite: u64, 2 sealed: Sealed }
}

codec_enum! {
    /// `box = enum { sealed 0 (..), symmetric 1 (..), joint 2 (..) }` (spec/crypto.md §4).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum SecretBox { 0 Sealed(b: SealedBox), 1 Symmetric(b: SymmetricBox), 2 Joint(b: JointBox) }
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
    /// Step and claim-set bytes (spec/wire.md §8), and the step's endorsements by delete key
    /// (spec/sync-ids.md §4).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct StepRecord { 0 step: Vec<u8>, 1 claims: Option<Vec<u8>>, 2 endorsements: BTreeMap<[u8; 32], [u8; 64]> }
}
codec_struct! {
    /// One sync ID of a thing (`sync.0`, spec/sync-ids.md §4); steps by step ID.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SyncEntry { 0 steps: BTreeMap<[u8; 32], StepRecord> }
}
codec_struct! {
    /// `keys.0`: keysets per role (actors other than key actors), a key actor's KEM key, the
    /// thing's inbox, 32-byte deposit seed, an actor's sync ID, and
    /// per box to a holder actor, keyed as that box, the holder's keysets it names (spec/crypto.md
    /// §4, Stale).
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Keys {
        0 read: Option<Keyset>, 1 write: Option<Keyset>, 2 admin: Option<Keyset>,
        3 key: Option<KemKey>, 4 inbox: Option<Weak>, 5 deposit_seed: Option<[u8; 32]>,
        7 sync: Option<Keyset>, 8 sealed: BTreeMap<BoxKey, BTreeSet<Epoch>>, 9 sync_id: Option<SyncId>,
    }
}
codec_struct! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Secrets { 0 boxes: BTreeMap<BoxKey, SecretBox>, 1 history: BTreeMap<HistoryKey, Vec<u8>> }
}
codec_struct! {
    /// One thing's limits at a node keeping it unread, in place of the policy's.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ThingCaps { 0 entries: u64, 1 bytes: u64 }
}
codec_struct! {
    /// `caps^.0` (spec/data-model.md §9): what peers may make this node store of the sync IDs it
    /// keeps unread; per-thing limits apply to each sync ID the thing owns.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Caps { 0 policy: BTreeMap<String, u64>, 1 things: BTreeMap<Weak, ThingCaps> }
}
codec_struct! {
    /// One entry of `clients^.0` (spec/data-model.md §9): a thin client's secret hash and end.
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
            Value::Enum(c, None) => Self::from_id(*c).ok_or_else(|| rt::unknown_case(v)),
            _ => Err(rt::unknown_case(v)),
        }
    }
}
#[doc(hidden)]
impl Codec for crate::History {
    fn to_value(&self) -> Value {
        match self {
            crate::History::Keep { until, after } => rt::enum_value(0, Some(rt::struct_value(vec![(0, until.to_value()), (1, after.to_value())]))),
            crate::History::PurgeOnReplace => rt::enum_value(1, None),
        }
    }
    fn from_value(v: &Value) -> Result<crate::History, PathError> {
        match v {
            Value::Enum(0, p) => {
                let m: &Value = p.as_deref().ok_or_else(|| PathError::new(Path::root(), PathErrorKind::MissingPayload(0)))?;
                let m = rt::struct_map(m).map_err(|e| e.within(crate::Step::Case(0)))?;
                let f = |id| rt::field::<Option<u64>>(m, id).map_err(|e| e.within(crate::Step::Case(0)));
                Ok(crate::History::Keep { until: f(0)?, after: f(1)? })
            }
            Value::Enum(1, None) => Ok(crate::History::PurgeOnReplace),
            _ => Err(rt::unknown_case(v)),
        }
    }
}
codec_struct! {
    /// What a thing promises for replaced content of an aspect (`history`, absent: none
    /// promised), the expiry a writer gives its writes there as a duration from the write (none:
    /// no expiry), `final`: a writer refuses to replace a fire there, and `purge_before`: a body
    /// holding a dead write whose `ts` is before this one is under purge on replace, whatever
    /// `history` says (spec/commits.md §5 One way).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct RetentionEntry { 0 history: Option<crate::History>, 1 expires: Option<u64>, 2 r#final: bool, 3 purge_before: Option<Ts> }
}

impl RetentionEntry {
    /// The expiry a write stamped at `wall` ms gets (`None` when out of range).
    pub fn expires_at(&self, wall: u64) -> Option<Option<u64>> {
        match self.expires {
            None => Some(None),
            Some(d) => wall.checked_add(d).map(Some),
        }
    }
}

codec_struct! {
    /// A thing's `retention^.0` setting: an entry by AK, `default` for every AK with no entry but
    /// an external signal's;
    /// `retain`: a removal from the thing retains a read-only copy unless its remover says
    /// otherwise; `history_holds_targets`: a strong in a held body of the thing's history holds
    /// its target, as a current one does.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct RetentionSetting { 0 rules: BTreeMap<Ak, RetentionEntry>, 1 retain: bool, 2 default: Option<RetentionEntry>, 3 history_holds_targets: bool }
}

impl RetentionSetting {
    /// A setting of one entry: `history` for `ak`.
    pub fn of(ak: Ak, history: crate::History) -> RetentionSetting {
        BTreeMap::from([(ak, RetentionEntry { history: Some(history), ..RetentionEntry::default() })]).into()
    }

    /// The entry governing `ak`: its own, else the default; an external signal's own only, since anyone
    /// may fire one (spec/commits.md §5 The setting).
    pub fn entry(&self, ak: &Ak) -> Option<&RetentionEntry> {
        self.rules.get(ak).or(self.default.as_ref().filter(|_| !ak.external()))
    }

    /// Whether this setting enables external signal `ak`: an entry of its own names it, never the
    /// default (spec/commits.md §5 The setting). While the current setting does, a party holding no
    /// write fires it validly (spec/permissions.md §5.2 External fires).
    pub fn enables(&self, ak: &Ak) -> bool {
        ak.external() && self.rules.contains_key(ak)
    }

    /// Enables the external signals an inbox takes (`INBOX_SIGNALS`, spec/sync-inbox.md §1) as
    /// an account's creation sets its inbox's: each kept `INBOX_LIFETIME` after it is fired (a
    /// grant's fire is an offer, spec/sync-inbox.md §5); an entry this setting has already stays
    /// as it is.
    pub fn take_inbox_signals(&mut self) {
        let lifetime = crate::History::Keep { until: None, after: Some(osis_base::format::INBOX_LIFETIME_MS) };
        // each a valid AK, checked at build time
        for (k, history) in INBOX_SIGNALS.map(|k| (k, lifetime)) {
            if let Ok(k) = Ak::new(k) {
                self.rules.entry(k).or_insert(RetentionEntry { history: Some(history), ..RetentionEntry::default() });
            }
        }
    }
}

/// The external signals an inbox takes (spec/sync-inbox.md §1): grants from outside and stranded
/// notices.
pub const INBOX_SIGNALS: [&str; 2] = [Ak::check("grant@~0", true), Ak::check("stranded@~0", true)];

impl From<BTreeMap<Ak, RetentionEntry>> for RetentionSetting {
    fn from(rules: BTreeMap<Ak, RetentionEntry>) -> RetentionSetting {
        RetentionSetting { rules, ..RetentionSetting::default() }
    }
}

impl FromIterator<(Ak, RetentionEntry)> for RetentionSetting {
    fn from_iter<I: IntoIterator<Item = (Ak, RetentionEntry)>>(i: I) -> RetentionSetting {
        BTreeMap::from_iter(i).into()
    }
}

/// What `retention^.0` value `v` sets (spec/commits.md §5): `None` (no setting) if it does not
/// read as the type (a key that is no AK among them) or is over the bounds.
pub fn retention_setting(v: &Value) -> Option<RetentionSetting> {
    RetentionSetting::from_value(v).ok().filter(setting_fits)
}

/// Whether `s` is within the bounds of one `retention^.0` delta.
pub fn setting_fits(s: &RetentionSetting) -> bool {
    s.rules.len() <= osis_base::format::MAX_RETENTION_ENTRIES
}

codec_struct! {
    /// A tag's own settings.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Tag { 0 color: Option<String> }
}

pub type Holders = BTreeMap<Weak, Edge>;
pub type SyncIds = BTreeMap<SyncId, SyncEntry>;

pub const CREATED: Aspect<CreationRecord> = Aspect::new("created.0", &CORE);
pub const ROLES: Aspect<Holders> = Aspect::new("roles.0", &CORE);
/// Key grants by key (spec/data-model.md §9 `signers.0`).
pub type KeyGrants = BTreeMap<SigningKey, Edge>;
pub const SIGNERS: Aspect<KeyGrants> = Aspect::new("signers.0", &CORE);
/// Removal commit ID -> what the author vouches for (spec/permissions.md §5.2, Addenda).
pub type Addenda = BTreeMap<Vec<u8>, Frontier>;
pub const ADDENDA: Aspect<Addenda> = Aspect::new(ADDENDA_AK, &CORE);
pub const KEYS: Aspect<Keys> = Aspect::new("keys.0", &CORE);
pub const SECRETS: Aspect<Secrets> = Aspect::new("secrets.0", &CORE);
pub const SYNC: Aspect<SyncIds> = Aspect::new("sync.0", &CORE);
/// `dial.0` on any thing: each node's 32-byte dialable key to its URLs (spec/sync-set.md §1).
pub type DialList = BTreeMap<Vec<u8>, Vec<String>>;
pub const DIAL: Aspect<DialList> = Aspect::new("dial.0", &CORE);
pub const CAPS: Aspect<Caps> = Aspect::new("caps^.0", &CORE);
/// `clients^.0`: by client actor, a strong (the node root holds each client's actor).
pub const CLIENTS: Aspect<BTreeMap<Weak, Client>> = Aspect::new("clients^.0", &CORE);
/// `retention^.0`: what the thing keeps of replaced content (spec/commits.md §5); fixed retention.
pub const RETENTION: Aspect<RetentionSetting> = Aspect::new("retention^.0", &CORE);
/// `purge.0`: the delta of a purge request naming no aspect to reset; fixed retention (spec/commits.md §5).
pub const PURGE: Aspect<WallMs> = Aspect::new("purge.0", &CORE);
pub const NAME: Aspect<String> = Aspect::new("name.0", &CORE);
pub const BODY: Aspect<String> = Aspect::new("body.0", &CORE);
pub const TAG: Aspect<Tag> = Aspect::new("tag.0", &CORE);
/// `holds.0`: a plain set of strongs and weaks (spec/data-model.md §8).
pub const HOLDS: Aspect<BTreeSet<Ref>> = Aspect::new("holds.0", &CORE);

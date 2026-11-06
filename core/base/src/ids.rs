//! Tids, AKs, links and fixed-size ids (spec/data-model.md §1, §2, §6, §7; spec/sync.md §2).

use crate::cbor::encode;
use crate::format::{MAX_AK_BYTES, TID_LEN, TID_TEXT_LEN};
use crate::value::Value;
use crate::{ErrorClass, hash};
use std::fmt;

/// A thing's identity: 120 bits, minted offline when it is created. `Display` and `parse` give its
/// text form.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tid([u8; TID_LEN]);

impl Tid {
    /// From its 15 bytes. Any bytes are a valid reference, perhaps to nothing.
    pub const fn from_bytes(b: [u8; TID_LEN]) -> Tid {
        Tid(b)
    }
    pub const fn as_bytes(&self) -> &[u8; TID_LEN] {
        &self.0
    }
    /// The tid of a creation record (spec/wire.md §3).
    #[doc(hidden)]
    pub fn of_record(record: &CreationRecord) -> Tid {
        let h = hash::hash(&encode(&record.to_value()));
        let mut b = [0u8; TID_LEN];
        for (d, s) in b.iter_mut().zip(h) {
            *d = s;
        }
        Tid(b)
    }
    /// `osis://` plus the text form.
    pub fn to_uri(&self) -> String {
        format!("osis://{self}")
    }
    /// Parses the 20-character text form, with or without `osis://`.
    pub fn parse(s: &str) -> Result<Tid, TidParseError> {
        let s = s.strip_prefix("osis://").unwrap_or(s);
        if s.len() != TID_TEXT_LEN {
            return Err(TidParseError);
        }
        let out: [u8; TID_LEN] = crate::base64url::decode(s).and_then(|b| b.try_into().ok()).ok_or(TidParseError)?;
        Ok(Tid(out))
    }
}

/// Unpadded base64url; 15 bytes give exactly 20 characters.
impl fmt::Display for Tid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::base64url::encode(&self.0))
    }
}

impl fmt::Debug for Tid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tid({self})")
    }
}

impl std::str::FromStr for Tid {
    type Err = TidParseError;
    fn from_str(s: &str) -> Result<Tid, TidParseError> {
        Tid::parse(s)
    }
}

/// Text that is no tid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TidParseError;
crate::impl_error!(TidParseError, "invalid tid text form");
impl crate::Classified for TidParseError {
    fn class(&self) -> ErrorClass {
        ErrorClass::BadInput
    }
}

/// A thing's creation record (spec/wire.md §3): the `creation` struct of the core schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreationRecord {
    /// Ordinary thing: owner actor and a 32-byte random nonce.
    Thing { owner: Tid, nonce: [u8; 32] },
    /// Key actor (owns itself): `signing_key` enum case and key bytes, and a 32-byte nonce. Only
    /// `alg` 1 (ed25519, 32 bytes) is readable in this build; other cases can be built (a later
    /// suite) but `from_value` refuses them.
    KeyActor { alg: u64, public_key: Vec<u8>, nonce: [u8; 32] },
    /// Ownerless thing (spec/permissions.md §1): no owner, no key; `admin` holds the first
    /// admin edge on it, fixed by the tid (no write grants it).
    Ownerless { admin: Tid, nonce: [u8; 32] },
}

// spec/wire.md §3: `creation = struct { 0 owner: tid, 1 key: signing_key, 2 nonce: blob, 3 admin: tid }`.
const REC_OWNER: i64 = 0;
const REC_KEY: i64 = 1;
const REC_NONCE: i64 = 2;
const REC_ADMIN: i64 = 3;
/// `signing_key` case ed25519 (spec/wire.md §3).
pub const SIGNING_KEY_ED25519: u64 = 1;

impl CreationRecord {
    /// The record's value; its canonical encoding is what the tid hashes.
    pub fn to_value(&self) -> Value {
        let mut m = crate::ValueMap::new();
        match self {
            CreationRecord::Thing { owner, nonce } => {
                m.insert(Value::Int(REC_OWNER), Value::Tid(*owner));
                m.insert(Value::Int(REC_NONCE), Value::Bytes(nonce.to_vec()));
            }
            CreationRecord::KeyActor { alg, public_key, nonce } => {
                let key = Value::Enum(*alg, Some(Box::new(Value::Bytes(public_key.clone()))));
                m.insert(Value::Int(REC_KEY), key);
                m.insert(Value::Int(REC_NONCE), Value::Bytes(nonce.to_vec()));
            }
            CreationRecord::Ownerless { admin, nonce } => {
                m.insert(Value::Int(REC_NONCE), Value::Bytes(nonce.to_vec()));
                m.insert(Value::Int(REC_ADMIN), Value::Tid(*admin));
            }
        }
        Value::Map(m)
    }
    /// Reads a record: exactly one of owner, key and admin, a 32-byte nonce, no other field, key an ed25519 `signing_key` of 32 bytes. `None` is bad input
    /// (an unknown key case included: callers that must park it check the enum case themselves).
    pub fn from_value(v: &Value) -> Option<CreationRecord> {
        let Value::Map(m) = v else { return None };
        let nonce: [u8; 32] = match m.get(&Value::Int(REC_NONCE)) {
            Some(Value::Bytes(b)) => b.as_slice().try_into().ok()?,
            _ => return None,
        };
        match (m.get(&Value::Int(REC_OWNER)), m.get(&Value::Int(REC_KEY)), m.get(&Value::Int(REC_ADMIN)), m.len()) {
            (Some(Value::Tid(owner)), None, None, 2) => Some(CreationRecord::Thing { owner: *owner, nonce }),
            (None, None, Some(Value::Tid(admin)), 2) => Some(CreationRecord::Ownerless { admin: *admin, nonce }),
            (None, Some(Value::Enum(SIGNING_KEY_ED25519, Some(p))), None, 2) => match p.as_ref() {
                Value::Bytes(pk) if pk.len() == 32 => {
                    Some(CreationRecord::KeyActor { alg: SIGNING_KEY_ED25519, public_key: pk.clone(), nonce })
                }
                _ => None,
            },
            _ => None,
        }
    }
    pub fn nonce(&self) -> &[u8; 32] {
        match self {
            CreationRecord::Thing { nonce, .. } | CreationRecord::KeyActor { nonce, .. } | CreationRecord::Ownerless { nonce, .. } => nonce,
        }
    }
    pub fn tid(&self) -> Tid {
        Tid::of_record(self)
    }
    /// The owner actor of an ordinary thing (none for a key actor or an ownerless thing).
    pub fn owner(&self) -> Option<Tid> {
        match self {
            CreationRecord::Thing { owner, .. } => Some(*owner),
            CreationRecord::KeyActor { .. } | CreationRecord::Ownerless { .. } => None,
        }
    }
    /// The next actor up the record chain (spec/permissions.md §1): the owner, or an ownerless
    /// thing's first admin (none for a key actor).
    pub fn up(&self) -> Option<Tid> {
        match self {
            CreationRecord::Thing { owner: a, .. } | CreationRecord::Ownerless { admin: a, .. } => Some(*a),
            CreationRecord::KeyActor { .. } => None,
        }
    }
}

/// Where an aspect's writes live: durable commits, or in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Lifetime {
    #[default]
    Durable,
    /// A value held in memory.
    Ephemeral,
    /// A write with no lasting value: delivered to callbacks, never in state.
    Signal,
}

impl Lifetime {
    pub fn is_durable(self) -> bool {
        self == Lifetime::Durable
    }
}

/// An aspect key: name segments `[a-z_][a-z0-9_]*` joined by `:`, after an
/// optional leading `:<tid>` segment; then `.N`, the aspect version; then the markers `^`
/// (admin-only) and at most one of `~` (ephemeral) or `*` (signal): `name.0`,
/// `contact:names.0`, `:<tid>:foo.1^~`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Ak(String);

/// Byte offsets and fields of a valid AK.
#[derive(Clone, Copy)]
struct Parsed {
    /// Start of the name segments: 0, or after the tid segment.
    names: usize,
    /// The `.` before the version.
    dot: usize,
    version: u64,
    admin: bool,
    lifetime: Lifetime,
}

const fn name_start(c: u8) -> bool {
    c.is_ascii_lowercase() || c == b'_'
}

/// The grammar of [`Ak`]; `const` so key constants are checked at build time ([`Ak::check`]).
const fn parse(s: &[u8]) -> Option<Parsed> {
    if s.len() > MAX_AK_BYTES {
        return None;
    }
    let mut rest = s;
    let mut names = 0;
    if let [b':', tail @ ..] = rest {
        let mut t = tail;
        let mut n = 0;
        while n < TID_TEXT_LEN {
            match t {
                [c, r @ ..] if c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_' => t = r,
                _ => return None,
            }
            n += 1;
        }
        let [b':', r @ ..] = t else { return None };
        rest = r;
        names = TID_TEXT_LEN + 2;
    }
    loop {
        match rest {
            [c, r @ ..] if name_start(*c) => rest = r,
            _ => return None,
        }
        while let [c, r @ ..] = rest {
            if !(name_start(*c) || c.is_ascii_digit()) {
                break;
            }
            rest = r;
        }
        match rest {
            [b':', r @ ..] => rest = r,
            _ => break,
        }
    }
    let [b'.', r @ ..] = rest else { return None };
    let dot = s.len() - rest.len();
    rest = r;
    // the version: decimal, no leading zero
    let mut version: u64 = 0;
    let mut digits = 0;
    while let [c, r @ ..] = rest {
        if !c.is_ascii_digit() || (digits == 1 && version == 0) {
            break;
        }
        version = match version.checked_mul(10) {
            Some(v) => match v.checked_add((*c - b'0') as u64) {
                Some(v) => v,
                None => return None,
            },
            None => return None,
        };
        digits += 1;
        rest = r;
    }
    if digits == 0 {
        return None;
    }
    let mut admin = false;
    if let [b'^', r @ ..] = rest {
        admin = true;
        rest = r;
    }
    let lifetime = match rest {
        [] => Lifetime::Durable,
        [b'~'] => Lifetime::Ephemeral,
        [b'*'] => Lifetime::Signal,
        _ => return None,
    };
    Some(Parsed { names, dot, version, admin, lifetime })
}

impl Ak {
    pub fn new(s: impl Into<String>) -> Result<Ak, AkError> {
        let s = s.into();
        match parse(s.as_bytes()) {
            Some(_) => Ok(Ak(s)),
            None => Err(AkError),
        }
    }
    #[doc(hidden)]
    /// `s` if it is a valid AK, else a panic: at build time in a `const` (key constants).
    pub const fn check(s: &'static str) -> &'static str {
        assert!(parse(s.as_bytes()).is_some(), "invalid aspect key");
        s
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    fn parsed(&self) -> Parsed {
        // only `MIN` fails to parse: it reads as no segments, version 0, no markers
        parse(self.0.as_bytes()).unwrap_or(Parsed { names: 0, dot: 0, version: 0, admin: false, lifetime: Lifetime::Durable })
    }
    /// The name segments (the tid segment is [`Ak::tid`]).
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        let p = self.parsed();
        self.0.get(p.names..p.dot).unwrap_or("").split(':').filter(|s| !s.is_empty())
    }
    /// The aspect version, `N` of `.N`.
    pub fn version(&self) -> u64 {
        self.parsed().version
    }
    /// The leading tid segment, if any.
    pub fn tid(&self) -> Option<Tid> {
        if self.parsed().names == 0 {
            return None;
        }
        self.0.get(1..=TID_TEXT_LEN).and_then(|t| Tid::parse(t).ok())
    }
    /// The `^` marker: admin-only.
    pub fn admin(&self) -> bool {
        self.parsed().admin
    }
    /// The lifetime marker: none durable, `~` ephemeral, `*` signal.
    pub fn lifetime(&self) -> Lifetime {
        self.parsed().lifetime
    }
    #[doc(hidden)]
    /// The markers of a valid AK's text, read from its tail (`^`, `~` and `*` occur nowhere else
    /// in one): admin-only, lifetime. For keys held as text (`RawKey::ak`).
    pub fn markers_of(s: &str) -> (bool, Lifetime) {
        let (lifetime, rest) = match s.as_bytes() {
            [r @ .., b'~'] => (Lifetime::Ephemeral, r),
            [r @ .., b'*'] => (Lifetime::Signal, r),
            r => (Lifetime::Durable, r),
        };
        (matches!(rest, [.., b'^']), lifetime)
    }
    /// Whether this key is a later version of `other`: the same tid and name segments, a higher
    /// version, any markers.
    pub fn successor_of(&self, other: &Ak) -> bool {
        let (p, q) = (self.parsed(), other.parsed());
        self.0.get(..p.dot) == other.0.get(..q.dot) && p.version > q.version
    }
    /// Sorts before every key, valid none: the start of a range over one thing's aspects.
    #[doc(hidden)]
    pub const MIN: Ak = Ak(String::new());
}

impl fmt::Display for Ak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Text that is no aspect key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkError;
crate::impl_error!(AkError, "invalid aspect key");
impl crate::Classified for AkError {
    fn class(&self) -> ErrorClass {
        ErrorClass::BadInput
    }
}

macro_rules! byte_id {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; $len]);
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "("))?;
                for b in self.0.iter().take(8) {
                    write!(f, "{b:02x}")?;
                }
                write!(f, "..)")
            }
        }
    };
}

byte_id!(
    /// BLAKE3 of a whole blob (spec/crypto.md §5).
    BlobId, 32
);
byte_id!(
    /// BLAKE3 of a commit header (spec/commits.md §1).
    CommitId, 32
);
byte_id!(
    /// First 16 bytes of BLAKE3 over the label's genesis delete key (spec/sync.md §2).
    LabelId, 16
);

/// Link to a chunk-tree node or page (spec/data-model.md §6, spec/crypto.md §6): 97 bytes of
/// payload. `Debug` hides the blob key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Link {
    /// Keyed content hash of the canonical value the subtree encodes.
    pub hash: [u8; 32],
    pub blob: BlobId,
    pub suite: u8,
    pub key: [u8; 32],
}

impl fmt::Debug for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Link({:?}, suite {}, key ..)", self.blob, self.suite)
    }
}

/// Who may purge a write. Named sets, not a scale: `Author` excludes admins, `Admin` the author.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum PurgeBy {
    Nobody = 0,
    Admin = 1,
    #[default]
    AuthorOrAdmin = 2,
    Writer = 3,
    Author = 4,
}

impl PurgeBy {
    #[doc(hidden)]
    pub const ALL: [PurgeBy; 5] = [PurgeBy::Nobody, PurgeBy::Admin, PurgeBy::AuthorOrAdmin, PurgeBy::Writer, PurgeBy::Author];
    pub fn name(self) -> &'static str {
        match self {
            PurgeBy::Nobody => "nobody",
            PurgeBy::Admin => "admin",
            PurgeBy::AuthorOrAdmin => "author_or_admin",
            PurgeBy::Writer => "writer",
            PurgeBy::Author => "author",
        }
    }
    #[doc(hidden)]
    pub fn from_id(id: u64) -> Option<PurgeBy> {
        PurgeBy::ALL.into_iter().find(|p| *p as u64 == id)
    }
    /// The set holds the thing's admins.
    pub fn admin(self) -> bool {
        matches!(self, PurgeBy::Admin | PurgeBy::AuthorOrAdmin | PurgeBy::Writer)
    }
    /// The set holds the author.
    pub fn author(self) -> bool {
        matches!(self, PurgeBy::Author | PurgeBy::AuthorOrAdmin | PurgeBy::Writer)
    }
    /// The set holds every writer.
    pub fn writer(self) -> bool {
        self == PurgeBy::Writer
    }
}


/// A role, ordered read < write < admin.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Role {
    Read,
    Write,
    Admin,
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/data-model.md §1: text form is 20 chars of unpadded base64url, `osis://` optional.
    #[test]
    fn tid_text_round_trip() {
        let t = Tid::from_bytes(*b"\x00\x10\x83\x10Q\x87 \x92\x8b0\xd3\x8f\x41\x14\x93");
        let s = t.to_string();
        assert_eq!(s.len(), 20);
        assert_eq!(s, "ABCDEFGHIJKLMNOPQRST");
        assert_eq!(Tid::parse(&s), Ok(t));
        assert_eq!(Tid::parse(&t.to_uri()), Ok(t));
        let all = Tid::from_bytes([0xff; 15]);
        assert_eq!(all.to_string(), "____________________");
        assert_eq!(Tid::parse("____________________"), Ok(all));
    }

    // spec/data-model.md §1: anything but 20 base64url chars is rejected.
    #[test]
    fn tid_parse_rejects() {
        for s in ["", "ABCDEFGHIJKLMNOPQRS", "ABCDEFGHIJKLMNOPQRSTU", "ABCDEFGHIJKLMNOPQRS=", "ABCDEFGHIJKLMNOPQRS+", "osis:/ABCDEFGHIJKLMNOPQRST"] {
            assert_eq!(Tid::parse(s), Err(TidParseError), "{s}");
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        crate::hex::decode(s).unwrap()
    }

    // spec/wire.md §3: frozen layout of the record forms; tid = first 15 bytes of BLAKE3 of
    // exactly these bytes.
    #[test]
    fn creation_record_bytes() {
        let r = CreationRecord::Thing { owner: Tid::from_bytes([7; 15]), nonce: [1; 32] };
        let rb = hex(&format!("a2 00 d90650 4f{} 02 5820{}", "07".repeat(15), "01".repeat(32)));
        let o = CreationRecord::Ownerless { admin: Tid::from_bytes([8; 15]), nonce: [1; 32] };
        let ob = hex(&format!("a2 02 5820{} 03 d90650 4f{}", "01".repeat(32), "08".repeat(15)));
        let k = CreationRecord::KeyActor { alg: 1, public_key: vec![9; 32], nonce: [1; 32] };
        let kb = hex(&format!("a2 01 d90651 82 01 5820{} 02 5820{}", "09".repeat(32), "01".repeat(32)));
        for (rec, bytes) in [(r, rb), (o, ob), (k, kb)] {
            assert_eq!(encode(&rec.to_value()), bytes);
            assert_eq!(rec.tid().as_bytes()[..], blake3::hash(&bytes).as_bytes()[..15]);
            assert_eq!(CreationRecord::from_value(&rec.to_value()), Some(rec));
        }
    }

    // spec/wire.md §3: exactly one of owner and key, a 32-byte nonce, ed25519 keys of 32 bytes,
    // no other field.
    #[test]
    fn creation_record_rejects() {
        let owner = Tid::from_bytes([7; 15]);
        let r = CreationRecord::Thing { owner, nonce: [1; 32] };
        assert_ne!(r.tid(), CreationRecord::Thing { owner, nonce: [2; 32] }.tid());
        assert_eq!(CreationRecord::from_value(&Value::Int(0)), None);
        let Value::Map(m) = r.to_value() else { unreachable!() };
        let key = |alg, len| Value::Enum(alg, Some(Box::new(Value::Bytes(vec![9; len]))));
        let with = |f: &dyn Fn(&mut crate::ValueMap)| {
            let mut m = m.clone();
            f(&mut m);
            CreationRecord::from_value(&Value::Map(m))
        };
        assert_eq!(with(&|m| { m.insert(Value::Int(1), key(1, 32)); }), None); // both
        assert_eq!(with(&|m| { m.remove(&Value::Int(0)); }), None); // neither
        assert_eq!(with(&|m| { m.insert(Value::Int(2), Value::Bytes(vec![1; 31])); }), None);
        assert_eq!(with(&|m| { m.insert(Value::Int(3), Value::Int(0)); }), None);
        for (alg, len) in [(1, 31), (1, 33), (0, 32), (2, 32)] {
            assert_eq!(with(&|m| { m.remove(&Value::Int(0)); m.insert(Value::Int(1), key(alg, len)); }), None, "{alg} {len}");
        }
        assert!(with(&|m| { m.remove(&Value::Int(0)); m.insert(Value::Int(1), key(1, 32)); }).is_some());
        assert_eq!(with(&|m| { m.insert(Value::Int(3), Value::Tid(owner)); }), None); // both owner and admin
        assert_eq!(with(&|m| { m.insert(Value::Int(4), Value::Int(0)); }), None);
    }

    // spec/data-model.md §2: the AK grammar and its accessors.
    #[test]
    fn ak_rules() {
        let a = Ak::new("note:body.0").unwrap();
        assert_eq!(a.segments().collect::<Vec<_>>(), ["note", "body"]);
        assert_eq!((a.version(), a.tid(), a.admin(), a.lifetime()), (0, None, false, Lifetime::Durable));
        let t = Tid::from_bytes([7; 15]);
        let b = Ak::new(format!(":{t}:a_1:b.12^~")).unwrap();
        assert_eq!(b.segments().collect::<Vec<_>>(), ["a_1", "b"]);
        assert_eq!((b.version(), b.tid(), b.admin(), b.lifetime()), (12, Some(t), true, Lifetime::Ephemeral));
        assert_eq!(Ak::new("roles.0").unwrap().segments().count(), 1);
        assert_eq!(Ak::new("x.3*").unwrap().lifetime(), Lifetime::Signal);
        let admin = Ak::new("x.0^").unwrap();
        assert_eq!((admin.admin(), admin.lifetime()), (true, Lifetime::Durable));
        for k in ["x.0", "x.3*", "x.0^", "x:y.1^~", ":AAAAAAAAAAAAAAAAAAAA:a.12^*"] {
            let a = Ak::new(k).unwrap();
            assert_eq!(Ak::markers_of(k), (a.admin(), a.lifetime()), "{k}");
        }
        assert!(Ak::new("note:body.1").unwrap().successor_of(&a));
        assert!(Ak::new("note:body.1~").unwrap().successor_of(&a));
        assert!(!a.successor_of(&a) && !Ak::new("note:bod.1").unwrap().successor_of(&a) && !Ak::new(format!(":{t}:note:body.1")).unwrap().successor_of(&a));
        let max = format!("x.{}", u64::MAX);
        assert_eq!(Ak::new(max).unwrap().version(), u64::MAX);
        for bad in [
            "", "x", "x.", ".0", "/x.0", "x.00", "x.01", "x.-1", "X.0", "1x.0", "x:.0", ":x.0", "x::y.0", "x-y.0", "x.0~^", "x.0~*", "x.0*~", "x.0~~", "x.0^^", "x^.0", "x.^", "x.0^0",
            "x.0 ", "x.0.0", "x.18446744073709551616", "x:Y.0", ":AAAAAAAAAAAAAAAAAAAA.0", ":AAAAAAAAAAAAAAAAAAA:x.0", ":AAAAAAAAAAAAAAAAAAA=:x.0",
        ] {
            assert_eq!(Ak::new(bad), Err(AkError), "{bad}");
        }
        assert!(Ak::new(":AAAAAAAAAAAAAAAAAAAA:x.0").is_ok());
        assert!(Ak::new(format!("{}.0", "a".repeat(MAX_AK_BYTES - 2))).is_ok());
        assert!(Ak::new(format!("{}.0", "a".repeat(MAX_AK_BYTES - 1))).is_err());
        assert_eq!(Ak::MIN.segments().count(), 0);
    }

    // A key constant is checked at build time: `Ak::check` is a `const fn` panicking on a
    // non-AK, and every `Aspect::new` constant evaluates it.
    const CHECKED: &str = Ak::check("note:body.0^~");
    #[test]
    #[should_panic(expected = "invalid aspect key")]
    fn ak_check_rejects() {
        assert_eq!(CHECKED, "note:body.0^~");
        let _ = Ak::check(std::hint::black_box("/note/body"));
    }

    #[test]
    fn role_order() {
        assert!(Role::Read < Role::Write && Role::Write < Role::Admin);
    }

    #[test]
    fn link_debug_hides_key() {
        let l = Link { hash: [1; 32], blob: BlobId([2; 32]), suite: 1, key: [0xab; 32] };
        assert!(!format!("{l:?}").contains("abab"));
    }
}

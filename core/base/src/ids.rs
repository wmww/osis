//! Tids, AKs, links and fixed-size ids (spec/data-model.md §1, §2, §6, §7; spec/sync.md §2).

use crate::cbor::encode;
use crate::format::{MAX_AK_BYTES, TID_LEN, TID_TEXT_LEN};
use crate::value::Value;
use crate::{ErrorClass, hash};
use std::collections::BTreeMap;
use std::fmt;

/// 120-bit thing id: first 15 bytes of BLAKE3 over the canonical creation record.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tid([u8; TID_LEN]);

impl Tid {
    /// Wraps 15 bytes received on the wire. Any bytes are a valid (possibly dangling) reference.
    pub const fn from_bytes(b: [u8; TID_LEN]) -> Tid {
        Tid(b)
    }
    pub const fn as_bytes(&self) -> &[u8; TID_LEN] {
        &self.0
    }
    /// The tid of a creation record (spec/wire.md §3).
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
}

// spec/wire.md §3: `creation = struct { 0 owner: tid, 1 key: signing_key, 2 nonce: blob }`.
const REC_OWNER: i64 = 0;
const REC_KEY: i64 = 1;
const REC_NONCE: i64 = 2;
/// `signing_key` case ed25519 (spec/wire.md §3).
pub const SIGNING_KEY_ED25519: u64 = 1;

impl CreationRecord {
    /// The record's value; its canonical encoding is what the tid hashes.
    pub fn to_value(&self) -> Value {
        let mut m = BTreeMap::new();
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
        }
        Value::Map(m)
    }
    /// Reads a record: exactly one of owner and key, a 32-byte nonce, no other field, key an
    /// ed25519 `signing_key` of 32 bytes. `None` is bad input (an unknown key case included:
    /// callers that must park it check the enum case themselves).
    pub fn from_value(v: &Value) -> Option<CreationRecord> {
        let Value::Map(m) = v else { return None };
        let nonce: [u8; 32] = match m.get(&Value::Int(REC_NONCE)) {
            Some(Value::Bytes(b)) => b.as_slice().try_into().ok()?,
            _ => return None,
        };
        match (m.get(&Value::Int(REC_OWNER)), m.get(&Value::Int(REC_KEY)), m.len()) {
            (Some(Value::Tid(owner)), None, 2) => Some(CreationRecord::Thing { owner: *owner, nonce }),
            (None, Some(Value::Enum(SIGNING_KEY_ED25519, Some(p))), 2) => match p.as_ref() {
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
            CreationRecord::Thing { nonce, .. } | CreationRecord::KeyActor { nonce, .. } => nonce,
        }
    }
    pub fn tid(&self) -> Tid {
        Tid::of_record(self)
    }
}

/// Aspect key: `/seg/seg...`, non-empty segments; one segment is a core aspect (spec/data-model.md §2).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Ak(String);

impl Ak {
    pub fn new(s: impl Into<String>) -> Result<Ak, AkError> {
        let s = s.into();
        let rest = s.strip_prefix('/').ok_or(AkError)?;
        if s.len() > MAX_AK_BYTES || rest.split('/').any(str::is_empty) {
            return Err(AkError);
        }
        Ok(Ak(s))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// One segment: belongs to the core schema.
    pub fn is_core(&self) -> bool {
        !self.0.get(1..).unwrap_or("").contains('/')
    }
    /// First segment (the schema maintainer's namespace for app AKs).
    pub fn namespace(&self) -> &str {
        self.0.get(1..).unwrap_or("").split('/').next().unwrap_or("")
    }
}

impl fmt::Display for Ak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

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
byte_id!(
    /// 128 random bits, minted once per schema (spec/data-model.md §10).
    SchemaId, 16
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

/// Membership role, ordered read < write < admin.
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

    // spec/wire.md §3: frozen layout of both record forms; tid = first 15 bytes of BLAKE3 of
    // exactly these bytes.
    #[test]
    fn creation_record_bytes() {
        let r = CreationRecord::Thing { owner: Tid::from_bytes([7; 15]), nonce: [1; 32] };
        let rb = hex(&format!("a2 00 d90650 4f{} 02 5820{}", "07".repeat(15), "01".repeat(32)));
        let k = CreationRecord::KeyActor { alg: 1, public_key: vec![9; 32], nonce: [1; 32] };
        let kb = hex(&format!("a2 01 d90651 82 01 5820{} 02 5820{}", "09".repeat(32), "01".repeat(32)));
        for (rec, bytes) in [(r, rb), (k, kb)] {
            assert_eq!(encode(&rec.to_value()), bytes);
            assert_eq!(rec.tid().as_bytes()[..], blake3::hash(&bytes).as_bytes()[..15]);
            assert_eq!(CreationRecord::from_value(&rec.to_value()), Some(rec));
        }
    }

    // spec/wire.md §3: exactly one of owner and key, a 32-byte nonce, ed25519 keys of 32 bytes.
    #[test]
    fn creation_record_rejects() {
        let owner = Tid::from_bytes([7; 15]);
        let r = CreationRecord::Thing { owner, nonce: [1; 32] };
        assert_ne!(r.tid(), CreationRecord::Thing { owner, nonce: [2; 32] }.tid());
        assert_eq!(CreationRecord::from_value(&Value::Int(0)), None);
        let Value::Map(m) = r.to_value() else { unreachable!() };
        let key = |alg, len| Value::Enum(alg, Some(Box::new(Value::Bytes(vec![9; len]))));
        let with = |f: &dyn Fn(&mut BTreeMap<Value, Value>)| {
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
    }

    // spec/data-model.md §2: AKs are slash-prefixed, slash-separated; one segment = core.
    #[test]
    fn ak_rules() {
        let a = Ak::new("/note/body").unwrap();
        assert!(!a.is_core());
        assert_eq!(a.namespace(), "note");
        assert!(Ak::new("/members").unwrap().is_core());
        for bad in ["", "/", "note", "/note/", "//x", "/a//b"] {
            assert_eq!(Ak::new(bad), Err(AkError), "{bad}");
        }
        assert!(Ak::new(format!("/{}", "a".repeat(MAX_AK_BYTES))).is_err());
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

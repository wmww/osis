//! Tids, AKs, links and fixed-size ids (spec/data-model.md §1, §2, §6, §7; spec/sync.md §2).

use crate::cbor::encode;
use crate::format::{TID_LEN, TID_TEXT_LEN};
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
    /// The tid of a creation record (spec/data-model.md §1).
    pub fn of_record(record: &CreationRecord) -> Tid {
        let h = hash::hash(&encode(&record.to_value()));
        let mut b = [0u8; TID_LEN];
        b.copy_from_slice(h.get(..TID_LEN).unwrap_or(&[0; TID_LEN]));
        Tid(b)
    }
    /// `osis://` plus the text form.
    pub fn to_uri(&self) -> String {
        format!("osis://{self}")
    }
    /// Parses the 20-character text form, with or without `osis://`.
    pub fn parse(s: &str) -> Result<Tid, TidParseError> {
        let s = s.strip_prefix("osis://").unwrap_or(s);
        let s = s.as_bytes();
        if s.len() != TID_TEXT_LEN {
            return Err(TidParseError);
        }
        let mut out = [0u8; TID_LEN];
        for (quad, dst) in s.as_chunks::<4>().0.iter().zip(out.as_chunks_mut::<3>().0) {
            let mut n: u32 = 0;
            for &c in quad.iter() {
                n = (n << 6) | u32::from(b64_value(c).ok_or(TidParseError)?);
            }
            let [_, a, b, c] = n.to_be_bytes();
            *dst = [a, b, c];
        }
        Ok(Tid(out))
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Unpadded base64url; 15 bytes give exactly 20 characters.
impl fmt::Display for Tid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::with_capacity(TID_TEXT_LEN);
        for &[a, b, c] in self.0.as_chunks::<3>().0 {
            let n = u32::from_be_bytes([0, a, b, c]);
            for shift in [18, 12, 6, 0] {
                #[allow(clippy::indexing_slicing)] // 6-bit index into 64 entries
                s.push(char::from(B64[((n >> shift) & 63) as usize]));
            }
        }
        f.write_str(&s)
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

/// A thing's creation record (spec/data-model.md §1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreationRecord {
    /// Ordinary thing: owner actor and a 32-byte random nonce.
    Thing { owner: Tid, nonce: [u8; 32] },
    /// Key actor (owns itself): algorithm-tagged signing public key and a 32-byte nonce.
    KeyActor { alg: u64, public_key: Vec<u8>, nonce: [u8; 32] },
}

// provisional layout (plans/protocol-spec.md item 2): a struct, field 0 owner tid, 1 nonce,
// 2 signing key as enum (alg case, key bytes); exactly one of 0 and 2.
const REC_OWNER: i64 = 0;
const REC_NONCE: i64 = 1;
const REC_KEY: i64 = 2;

impl CreationRecord {
    /// Canonical value of the record (provisional layout).
    pub fn to_value(&self) -> Value {
        let mut m = BTreeMap::new();
        match self {
            CreationRecord::Thing { owner, nonce } => {
                m.insert(Value::Int(REC_OWNER), Value::Tid(*owner));
                m.insert(Value::Int(REC_NONCE), Value::Bytes(nonce.to_vec()));
            }
            CreationRecord::KeyActor { alg, public_key, nonce } => {
                m.insert(Value::Int(REC_NONCE), Value::Bytes(nonce.to_vec()));
                let key = Value::Enum(*alg, Some(Box::new(Value::Bytes(public_key.clone()))));
                m.insert(Value::Int(REC_KEY), key);
            }
        }
        Value::Map(m)
    }
    /// Reads a record; anything else is bad input.
    pub fn from_value(v: &Value) -> Option<CreationRecord> {
        let Value::Map(m) = v else { return None };
        let nonce: [u8; 32] = match m.get(&Value::Int(REC_NONCE)) {
            Some(Value::Bytes(b)) => b.as_slice().try_into().ok()?,
            _ => return None,
        };
        match (m.get(&Value::Int(REC_OWNER)), m.get(&Value::Int(REC_KEY)), m.len()) {
            (Some(Value::Tid(owner)), None, 2) => Some(CreationRecord::Thing { owner: *owner, nonce }),
            (None, Some(Value::Enum(alg, Some(p))), 2) => match p.as_ref() {
                Value::Bytes(pk) => Some(CreationRecord::KeyActor { alg: *alg, public_key: pk.clone(), nonce }),
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

/// Longest AK accepted. provisional (spec sets none; a decoder needs one).
pub const MAX_AK_BYTES: usize = 1024;

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

    // spec/data-model.md §1: tid = first 120 bits of BLAKE3 over the canonical creation record;
    // the record round-trips through its value.
    #[test]
    fn tid_of_record() {
        let owner = Tid::from_bytes([7; 15]);
        let r = CreationRecord::Thing { owner, nonce: [1; 32] };
        let h = blake3::hash(&encode(&r.to_value()));
        assert_eq!(r.tid().as_bytes()[..], h.as_bytes()[..15]);
        assert_eq!(CreationRecord::from_value(&r.to_value()), Some(r.clone()));
        let k = CreationRecord::KeyActor { alg: 0, public_key: vec![9; 32], nonce: [1; 32] };
        assert_eq!(CreationRecord::from_value(&k.to_value()), Some(k.clone()));
        assert_ne!(k.tid(), r.tid());
        let r2 = CreationRecord::Thing { owner, nonce: [2; 32] };
        assert_ne!(r.tid(), r2.tid());
        assert_eq!(CreationRecord::from_value(&Value::Int(0)), None);
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

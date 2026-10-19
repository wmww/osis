//! Values (spec/data-model.md §4, §5). `Eq` and `Ord` are those of the canonical encoding: `Ord`
//! is computed structurally and equals bytewise comparison of `cbor::encode` (tested), so maps and
//! sets (`BTreeMap`, `BTreeSet`) iterate in canonical order with unique keys by construction.
//! Exception: a link compares by its keyed content hash alone (spec/data-model.md §4, §6), so two
//! writes of one large value are equal; canonical order is unchanged (the hash leads the link).

use crate::cbor::CanonicalBytes;
use crate::format::{TAG_ENUM, TAG_LINK, TAG_SET, TAG_TID};
use crate::ids::{Link, Tid};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub enum Value {
    Int(i64),
    Float(Float),
    Bool(bool),
    Str(String),
    Bytes(Vec<u8>),
    Tid(Tid),
    /// Case ID (a CBOR uint, so up to u64; schema case IDs are small) and optional payload.
    Enum(u64, Option<Box<Value>>),
    /// Also the struct representation (int keys).
    Map(BTreeMap<Value, Value>),
    List(Vec<Value>),
    Set(BTreeSet<Value>),
    Link(Link),
    /// A tag this build does not know, with its content as received.
    Unknown(Unknown),
}

/// An f64 by bit pattern; NaN is always the canonical positive quiet NaN.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Float(u64);

impl Float {
    pub const CANONICAL_NAN: u64 = 0x7ff8_0000_0000_0000;
    /// Normalizes NaN (spec/data-model.md §5).
    pub fn new(f: f64) -> Float {
        if f.is_nan() { Float(Self::CANONICAL_NAN) } else { Float(f.to_bits()) }
    }
    /// From received bits: `None` for a non-canonical NaN.
    pub fn from_bits(bits: u64) -> Option<Float> {
        if f64::from_bits(bits).is_nan() && bits != Self::CANONICAL_NAN { None } else { Some(Float(bits)) }
    }
    pub fn to_bits(self) -> u64 {
        self.0
    }
    pub fn get(self) -> f64 {
        f64::from_bits(self.0)
    }
}

/// Tag numbers with a meaning in this build; never held by `Unknown`. The reserved STRUCT tag
/// is not one: a later version may define it, so it is preserved like any unknown tag.
pub fn is_known_tag(tag: u64) -> bool {
    matches!(tag, TAG_SET | TAG_TID | TAG_ENUM | TAG_LINK)
}

/// Unknown tag with its canonical content bytes (spec/data-model.md §5): merges as an opaque
/// value, fails only a typed read.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Unknown {
    tag: u64,
    content: CanonicalBytes,
}

impl Unknown {
    /// `None` if this build knows the tag.
    pub fn new(tag: u64, content: CanonicalBytes) -> Option<Unknown> {
        if is_known_tag(tag) { None } else { Some(Unknown { tag, content }) }
    }
    pub fn tag(&self) -> u64 {
        self.tag
    }
    pub fn content(&self) -> &CanonicalBytes {
        &self.content
    }
}

impl Value {
    pub fn float(f: f64) -> Value {
        Value::Float(Float::new(f))
    }
    /// Nesting depth as the decoder counts it: arrays, maps and tags on the deepest path.
    pub fn depth(&self) -> usize {
        fn max(it: impl Iterator<Item = usize>) -> usize {
            it.max().unwrap_or(0)
        }
        match self {
            Value::Int(_) | Value::Float(_) | Value::Bool(_) | Value::Str(_) | Value::Bytes(_) => 0,
            Value::Tid(_) => 1,
            Value::Enum(_, None) | Value::Link(_) => 2,
            Value::Enum(_, Some(p)) => 2 + p.depth(),
            Value::List(l) => 1 + max(l.iter().map(Value::depth)),
            Value::Map(m) => 1 + max(m.iter().map(|(k, v)| k.depth().max(v.depth()))),
            Value::Set(s) => 2 + max(s.iter().map(Value::depth)),
            Value::Unknown(u) => 1 + u.content.depth(),
        }
    }
}

/// Position of a value's first encoded byte group, for ordering across kinds: major type, then
/// (for tags) the tag number, then (for major 7) false < true < float.
fn kind_key(v: &Value) -> (u8, u64) {
    match v {
        Value::Int(i) if *i >= 0 => (0, 0),
        Value::Int(_) => (1, 0),
        Value::Bytes(_) => (2, 0),
        Value::Str(_) => (3, 0),
        Value::List(_) => (4, 0),
        Value::Map(_) => (5, 0),
        Value::Set(_) => (6, TAG_SET),
        Value::Tid(_) => (6, TAG_TID),
        Value::Enum(..) => (6, TAG_ENUM),
        Value::Link(_) => (6, TAG_LINK),
        Value::Unknown(u) => (6, u.tag),
        Value::Bool(false) => (7, 20),
        Value::Bool(true) => (7, 21),
        Value::Float(_) => (7, 27),
    }
}

impl Ord for Value {
    /// Bytewise order of canonical encodings. Canonical heads compare like their arguments,
    /// and no canonical item is a prefix of another, so arrays compare element by element.
    fn cmp(&self, other: &Value) -> Ordering {
        use Value::*;
        let k = kind_key(self).cmp(&kind_key(other));
        if k != Ordering::Equal {
            return k;
        }
        match (self, other) {
            // Major 1 argument is -1-n: larger magnitude sorts later.
            (Int(a), Int(b)) => if *a >= 0 { a.cmp(b) } else { b.cmp(a) },
            (Float(a), Float(b)) => a.0.cmp(&b.0),
            (Bool(_), Bool(_)) => Ordering::Equal,
            (Str(a), Str(b)) => cmp_bytes(a.as_bytes(), b.as_bytes()),
            (Bytes(a), Bytes(b)) => cmp_bytes(a, b),
            (Tid(a), Tid(b)) => a.cmp(b),
            (Enum(ca, pa), Enum(cb, pb)) => {
                // `[case]` (array of 1) sorts before `[case, payload]` (array of 2).
                pa.is_some().cmp(&pb.is_some()).then(ca.cmp(cb)).then_with(|| pa.cmp(pb))
            }
            (List(a), List(b)) => a.len().cmp(&b.len()).then_with(|| a.iter().cmp(b.iter())),
            (Set(a), Set(b)) => a.len().cmp(&b.len()).then_with(|| a.iter().cmp(b.iter())),
            (Map(a), Map(b)) => a.len().cmp(&b.len()).then_with(|| a.iter().cmp(b.iter())),
            (Link(a), Link(b)) => a.hash.cmp(&b.hash),
            (Unknown(a), Unknown(b)) => a.content.as_bytes().cmp(b.content.as_bytes()),
            _ => Ordering::Equal, // unreachable: equal kind keys mean equal variants
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Value {}

impl std::hash::Hash for Value {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        use Value::*;
        kind_key(self).hash(h);
        match self {
            Int(i) => i.hash(h),
            Float(f) => f.hash(h),
            Bool(_) => {}
            Str(s) => s.hash(h),
            Bytes(b) => b.hash(h),
            Tid(t) => t.hash(h),
            Enum(c, p) => (c, p).hash(h),
            Map(m) => m.iter().for_each(|kv| kv.hash(h)),
            List(l) => l.iter().for_each(|v| v.hash(h)),
            Set(s) => s.iter().for_each(|v| v.hash(h)),
            Link(l) => l.hash.hash(h),
            Unknown(u) => u.content.as_bytes().hash(h),
        }
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Value) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Byte and text strings: length head first, then content.
fn cmp_bytes(a: &[u8], b: &[u8]) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

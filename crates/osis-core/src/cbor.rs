//! Canonical encoder and strict decoder for the osis CBOR profile (spec/data-model.md §5).
//! Accepted bytes are canonical, so they are hashed and stored as received, never re-encoded.

use crate::format::{MAX_VALUE_BYTES, MAX_VALUE_DEPTH, TAG_ENUM, TAG_LINK, TAG_SET, TAG_TID, TID_LEN};
use crate::ids::{BlobId, Link, Tid};
use crate::value::{Float, Unknown, Value};
use crate::{Classified, ErrorClass};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const MAJOR_UINT: u8 = 0;
const MAJOR_NINT: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const FALSE: u8 = 0xf4;
const TRUE: u8 = 0xf5;
const FLOAT64: u8 = 0xfb;

/// Decoder limits; every decode takes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Deepest nesting: arrays, maps and tags on the deepest path (a scalar is 0).
    pub max_depth: usize,
    /// Most bytes one value may span.
    pub max_bytes: usize,
}

impl Limits {
    pub const DEFAULT: Limits = Limits { max_depth: MAX_VALUE_DEPTH, max_bytes: MAX_VALUE_BYTES };
}

impl Default for Limits {
    fn default() -> Limits {
        Limits::DEFAULT
    }
}

/// Why bytes are outside the profile. Always `BadInput`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    TooLarge,
    TooDeep,
    Trailing,
    NonShortestHead,
    Indefinite,
    ReservedInfo,
    IntOutOfRange,
    InvalidUtf8,
    /// Map keys not strictly increasing by canonical bytes (unsorted or duplicate).
    MapKeyOrder,
    /// Set elements not strictly increasing by canonical bytes (unsorted or duplicate).
    SetOrder,
    /// null, undefined, half or single floats, other simple values.
    BadSimple,
    NonCanonicalNan,
    /// A known tag around content of the wrong shape.
    TagContent(u64),
}

crate::impl_error!(DecodeError {
    Truncated => ("cbor: truncated"),
    TooLarge => ("cbor: value exceeds size limit"),
    TooDeep => ("cbor: nesting exceeds depth limit"),
    Trailing => ("cbor: trailing bytes"),
    NonShortestHead => ("cbor: non-shortest head"),
    Indefinite => ("cbor: indefinite length"),
    ReservedInfo => ("cbor: reserved additional info"),
    IntOutOfRange => ("cbor: integer outside i64"),
    InvalidUtf8 => ("cbor: invalid utf-8"),
    MapKeyOrder => ("cbor: map keys unsorted or duplicate"),
    SetOrder => ("cbor: set elements unsorted or duplicate"),
    BadSimple => ("cbor: simple value or float width outside the profile"),
    NonCanonicalNan => ("cbor: non-canonical NaN"),
    TagContent(t) => ("cbor: bad content for tag {t}"),
});

impl Classified for DecodeError {
    fn class(&self) -> ErrorClass {
        ErrorClass::BadInput
    }
}

/// Bytes known to be one canonical value.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CanonicalBytes {
    bytes: Vec<u8>,
    depth: usize,
}

impl CanonicalBytes {
    /// Checks that `bytes` is exactly one value in the profile.
    pub fn parse(bytes: Vec<u8>, limits: &Limits) -> Result<CanonicalBytes, DecodeError> {
        let mut d = Decoder::new(&bytes, limits);
        d.item(0)?;
        if d.pos != bytes.len() {
            return Err(DecodeError::Trailing);
        }
        let depth = d.deepest;
        Ok(CanonicalBytes { bytes, depth })
    }
    pub fn from_value(v: &Value) -> CanonicalBytes {
        CanonicalBytes { bytes: encode(v), depth: v.depth() }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
    pub fn depth(&self) -> usize {
        self.depth
    }
    pub fn to_value(&self) -> Result<Value, DecodeError> {
        decode(&self.bytes, &Limits { max_depth: self.depth, max_bytes: self.bytes.len() })
    }
}

impl fmt::Debug for CanonicalBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CanonicalBytes(")?;
        for b in self.bytes.iter().take(32) {
            write!(f, "{b:02x}")?;
        }
        if self.bytes.len() > 32 {
            write!(f, "..; {} bytes", self.bytes.len())?;
        }
        write!(f, ")")
    }
}

/// Canonical encoding of a value.
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    // Shortest form (RFC 8949 §4.2.1). Truncating casts are guarded by the ranges.
    match arg {
        0..=23 => out.push(m | arg as u8),
        24..=0xff => out.extend([m | 24, arg as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend((arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend((arg as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend(arg.to_be_bytes());
        }
    }
}

fn len_head(out: &mut Vec<u8>, major: u8, len: usize) {
    head(out, major, len as u64);
}

fn bytes(out: &mut Vec<u8>, b: &[u8]) {
    len_head(out, MAJOR_BYTES, b.len());
    out.extend_from_slice(b);
}

pub fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Int(i) if *i >= 0 => head(out, MAJOR_UINT, *i as u64),
        // -1 - i == !i for negative i.
        Value::Int(i) => head(out, MAJOR_NINT, !*i as u64),
        Value::Float(f) => {
            out.push(FLOAT64);
            out.extend(f.to_bits().to_be_bytes());
        }
        Value::Bool(b) => out.push(if *b { TRUE } else { FALSE }),
        Value::Str(s) => {
            len_head(out, MAJOR_TEXT, s.len());
            out.extend_from_slice(s.as_bytes());
        }
        Value::Bytes(b) => bytes(out, b),
        Value::Tid(t) => {
            head(out, MAJOR_TAG, TAG_TID);
            bytes(out, t.as_bytes());
        }
        Value::Enum(case, payload) => {
            head(out, MAJOR_TAG, TAG_ENUM);
            head(out, MAJOR_ARRAY, if payload.is_some() { 2 } else { 1 });
            head(out, MAJOR_UINT, *case);
            if let Some(p) = payload {
                encode_into(p, out);
            }
        }
        Value::Map(m) => {
            len_head(out, MAJOR_MAP, m.len());
            for (k, v) in m {
                encode_into(k, out);
                encode_into(v, out);
            }
        }
        Value::List(l) => {
            len_head(out, MAJOR_ARRAY, l.len());
            l.iter().for_each(|e| encode_into(e, out));
        }
        Value::Set(s) => {
            head(out, MAJOR_TAG, TAG_SET);
            len_head(out, MAJOR_ARRAY, s.len());
            s.iter().for_each(|e| encode_into(e, out));
        }
        Value::Link(l) => {
            head(out, MAJOR_TAG, TAG_LINK);
            head(out, MAJOR_ARRAY, 3);
            bytes(out, &l.hash);
            bytes(out, &l.blob.0);
            len_head(out, MAJOR_BYTES, 33);
            out.push(l.suite);
            out.extend_from_slice(&l.key);
        }
        Value::Unknown(u) => {
            head(out, MAJOR_TAG, u.tag());
            out.extend_from_slice(u.content().as_bytes());
        }
    }
}

/// Decodes exactly one value spanning all of `input`.
pub fn decode(input: &[u8], limits: &Limits) -> Result<Value, DecodeError> {
    let (v, used) = decode_prefix(input, limits)?;
    if used.len() != input.len() {
        return Err(DecodeError::Trailing);
    }
    Ok(v)
}

/// Decodes one value from the start of `input`; returns it with the bytes it spans.
pub fn decode_prefix<'a>(input: &'a [u8], limits: &Limits) -> Result<(Value, &'a [u8]), DecodeError> {
    let mut d = Decoder::new(input, limits);
    let v = d.item(0)?;
    Ok((v, input.get(..d.pos).unwrap_or(input)))
}

struct Decoder<'a> {
    /// Input cut at `max_bytes`.
    buf: &'a [u8],
    /// Whether the input continues past the cut.
    cut: bool,
    pos: usize,
    max_depth: usize,
    deepest: usize,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8], limits: &Limits) -> Decoder<'a> {
        let cut = input.len() > limits.max_bytes;
        let buf = input.get(..limits.max_bytes).unwrap_or(input);
        Decoder { buf, cut, pos: 0, max_depth: limits.max_depth, deepest: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn short(&self) -> DecodeError {
        if self.cut { DecodeError::TooLarge } else { DecodeError::Truncated }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or_else(|| self.short())?;
        self.pos = end;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        let b = *self.buf.get(self.pos).ok_or_else(|| self.short())?;
        self.pos += 1;
        Ok(b)
    }

    fn be(&mut self, n: usize) -> Result<u64, DecodeError> {
        Ok(self.take(n)?.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b)))
    }

    /// Argument of a non-major-7 head with initial byte `ib`, shortest form enforced.
    fn arg(&mut self, ib: u8) -> Result<u64, DecodeError> {
        let (v, min) = match ib & 31 {
            ai @ 0..=23 => return Ok(u64::from(ai)),
            24 => (self.be(1)?, 24),
            25 => (self.be(2)?, 0x100),
            26 => (self.be(4)?, 0x1_0000),
            27 => (self.be(8)?, 0x1_0000_0000),
            31 => return Err(DecodeError::Indefinite),
            _ => return Err(DecodeError::ReservedInfo),
        };
        if v < min { Err(DecodeError::NonShortestHead) } else { Ok(v) }
    }

    /// A length that must fit in the remaining input at `per` bytes per unit at least.
    fn len(&mut self, ib: u8, per: usize) -> Result<usize, DecodeError> {
        let n = self.arg(ib)?;
        match usize::try_from(n).ok().and_then(|n| n.checked_mul(per)) {
            Some(need) if need <= self.remaining() => Ok(n as usize),
            _ => Err(self.short()),
        }
    }

    /// Expects a head of `major` and returns its argument.
    fn expect(&mut self, major: u8, tag: u64) -> Result<u64, DecodeError> {
        let ib = self.byte()?;
        if ib >> 5 != major {
            return Err(DecodeError::TagContent(tag));
        }
        self.arg(ib)
    }

    fn fixed_bytes<const N: usize>(&mut self, tag: u64) -> Result<[u8; N], DecodeError> {
        if self.expect(MAJOR_BYTES, tag)? != N as u64 {
            return Err(DecodeError::TagContent(tag));
        }
        let mut b = [0u8; N];
        b.copy_from_slice(self.take(N)?);
        Ok(b)
    }

    /// Opens an array, map or tag at nesting `level`.
    fn enter(&mut self, level: usize) -> Result<(), DecodeError> {
        if level > self.max_depth {
            return Err(DecodeError::TooDeep);
        }
        self.deepest = self.deepest.max(level);
        Ok(())
    }

    /// One item inside `depth` arrays, maps and tags.
    fn item(&mut self, depth: usize) -> Result<Value, DecodeError> {
        let ib = self.byte()?;
        match ib >> 5 {
            MAJOR_UINT => {
                let n = self.arg(ib)?;
                i64::try_from(n).map(Value::Int).map_err(|_| DecodeError::IntOutOfRange)
            }
            MAJOR_NINT => {
                let n = self.arg(ib)?;
                // -1 - n == !n, in range iff n <= i64::MAX.
                i64::try_from(n).map(|n| Value::Int(!n)).map_err(|_| DecodeError::IntOutOfRange)
            }
            MAJOR_BYTES => {
                let n = self.len(ib, 1)?;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            MAJOR_TEXT => {
                let n = self.len(ib, 1)?;
                let s = std::str::from_utf8(self.take(n)?).map_err(|_| DecodeError::InvalidUtf8)?;
                Ok(Value::Str(s.to_owned()))
            }
            MAJOR_ARRAY => {
                self.enter(depth + 1)?;
                let n = self.len(ib, 1)?;
                let mut l = Vec::new();
                for _ in 0..n {
                    l.push(self.item(depth + 1)?);
                }
                Ok(Value::List(l))
            }
            MAJOR_MAP => {
                self.enter(depth + 1)?;
                let n = self.len(ib, 2)?;
                let mut m = BTreeMap::new();
                let mut prev: &[u8] = &[];
                for _ in 0..n {
                    let start = self.pos;
                    let k = self.item(depth + 1)?;
                    let raw = self.buf.get(start..self.pos).unwrap_or(&[]);
                    // Empty `prev` only before the first key; every item is at least one byte.
                    if !prev.is_empty() && raw <= prev {
                        return Err(DecodeError::MapKeyOrder);
                    }
                    prev = raw;
                    let v = self.item(depth + 1)?;
                    // Distinct bytes, one value: links with one content hash.
                    if m.insert(k, v).is_some() {
                        return Err(DecodeError::MapKeyOrder);
                    }
                }
                Ok(Value::Map(m))
            }
            MAJOR_TAG => {
                let tag = self.arg(ib)?;
                self.tagged(tag, depth)
            }
            _ => match ib {
                // Major 7.
                FALSE => Ok(Value::Bool(false)),
                TRUE => Ok(Value::Bool(true)),
                FLOAT64 => {
                    let bits = self.be(8)?;
                    Float::from_bits(bits).map(Value::Float).ok_or(DecodeError::NonCanonicalNan)
                }
                _ => Err(DecodeError::BadSimple),
            },
        }
    }

    fn tagged(&mut self, tag: u64, depth: usize) -> Result<Value, DecodeError> {
        let inner = depth + 1;
        self.enter(inner)?;
        match tag {
            TAG_SET => {
                self.enter(inner + 1)?;
                let ib = self.byte()?;
                if ib >> 5 != MAJOR_ARRAY {
                    return Err(DecodeError::TagContent(tag));
                }
                let n = self.len(ib, 1)?;
                let mut s = BTreeSet::new();
                let mut prev: &[u8] = &[];
                for _ in 0..n {
                    let start = self.pos;
                    let e = self.item(inner + 1)?;
                    let raw = self.buf.get(start..self.pos).unwrap_or(&[]);
                    if !prev.is_empty() && raw <= prev {
                        return Err(DecodeError::SetOrder);
                    }
                    prev = raw;
                    if !s.insert(e) {
                        return Err(DecodeError::SetOrder);
                    }
                }
                Ok(Value::Set(s))
            }
            TAG_TID => Ok(Value::Tid(Tid::from_bytes(self.fixed_bytes::<TID_LEN>(tag)?))),
            TAG_ENUM => {
                self.enter(inner + 1)?;
                let n = self.expect(MAJOR_ARRAY, tag)?;
                if n != 1 && n != 2 {
                    return Err(DecodeError::TagContent(tag));
                }
                let case = self.expect(MAJOR_UINT, tag)?;
                let payload = if n == 2 { Some(Box::new(self.item(inner + 1)?)) } else { None };
                Ok(Value::Enum(case, payload))
            }
            TAG_LINK => {
                self.enter(inner + 1)?;
                if self.expect(MAJOR_ARRAY, tag)? != 3 {
                    return Err(DecodeError::TagContent(tag));
                }
                let hash = self.fixed_bytes::<32>(tag)?;
                let blob = BlobId(self.fixed_bytes::<32>(tag)?);
                let [suite, key @ ..] = self.fixed_bytes::<33>(tag)?;
                Ok(Value::Link(Link { hash, blob, suite, key }))
            }
            _ => {
                let start = self.pos;
                let saved = std::mem::take(&mut self.deepest);
                self.item(inner)?;
                let content_depth = self.deepest.saturating_sub(inner);
                self.deepest = self.deepest.max(saved);
                let bytes = self.buf.get(start..self.pos).unwrap_or(&[]).to_vec();
                let content = CanonicalBytes { bytes, depth: content_depth };
                Unknown::new(tag, content).map(Value::Unknown).ok_or(DecodeError::TagContent(tag))
            }
        }
    }
}

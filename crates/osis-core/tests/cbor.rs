//! Canonical CBOR profile tests (spec/data-model.md §5).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)] // test code

use osis_core::format::{TAG_ENUM, TAG_LINK, TAG_SET, TAG_STRUCT_RESERVED, TAG_TID};
use osis_core::{BlobId, CanonicalBytes, DecodeError, Float, Limits, Link, Tid, Unknown, Value, decode, decode_prefix, encode};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

fn d(b: &[u8]) -> Result<Value, DecodeError> {
    decode(b, &Limits::DEFAULT)
}

fn floats() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<f64>().prop_map(Value::float),
        Just(Value::float(0.0)),
        Just(Value::float(-0.0)),
        Just(Value::float(f64::NAN)),
        Just(Value::float(f64::INFINITY)),
        any::<u64>().prop_map(|b| Value::float(f64::from_bits(b))),
    ]
}

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<i64>().prop_map(Value::Int),
        (-30i64..300).prop_map(Value::Int),
        prop_oneof![Just(i64::MIN), Just(i64::MAX), Just(-1), Just(23), Just(24), Just(-25), Just(65536)].prop_map(Value::Int),
        floats(),
        any::<bool>().prop_map(Value::Bool),
        prop::collection::vec(any::<char>(), 0..6).prop_map(|c| Value::Str(c.into_iter().collect())),
        prop::collection::vec(any::<u8>(), 0..30).prop_map(Value::Bytes),
        any::<[u8; 15]>().prop_map(|b| Value::Tid(Tid::from_bytes(b))),
        (any::<[u8; 32]>(), any::<[u8; 32]>(), any::<u8>(), any::<[u8; 32]>())
            .prop_map(|(hash, blob, suite, key)| Value::Link(Link { hash, blob: BlobId(blob), suite, key })),
        prop_oneof![Just(0u64), Just(23), Just(300), Just(u64::MAX)].prop_map(|c| Value::Enum(c, None)),
    ]
}

fn value() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::List),
            prop::collection::vec((inner.clone(), inner.clone()), 0..6).prop_map(|e| Value::Map(e.into_iter().collect())),
            prop::collection::vec(inner.clone(), 0..6).prop_map(|e| Value::Set(e.into_iter().collect())),
            (any::<u64>(), inner.clone()).prop_map(|(c, p)| Value::Enum(c, Some(Box::new(p)))),
            (prop_oneof![Just(0u64), Just(2), Just(255), Just(259), Just(TAG_STRUCT_RESERVED), Just(70_000), Just(u64::MAX)], inner)
                .prop_map(|(t, c)| Value::Unknown(Unknown::new(t, CanonicalBytes::from_value(&c)).unwrap())),
        ]
    })
}

/// Random edits of a byte string: flip, insert, delete, truncate.
fn mutate(mut b: Vec<u8>, ops: &[(u8, usize, u8)]) -> Vec<u8> {
    for &(op, at, x) in ops {
        let at = if b.is_empty() { 0 } else { at % (b.len() + 1) };
        match op % 4 {
            0 if at < b.len() => b[at] ^= x | 1,
            1 => b.insert(at, x),
            2 if at < b.len() => {
                b.remove(at);
            }
            _ => b.truncate(at),
        }
    }
    b
}

fn check_ord(a: &Value, b: &Value) -> Result<(), TestCaseError> {
    prop_assert_eq!(a.cmp(b), encode(a).cmp(&encode(b)));
    prop_assert_eq!(a == b, encode(a) == encode(b));
    Ok(())
}

fn check_mutation(v: &Value, ops: &[(u8, usize, u8)]) -> Result<(), TestCaseError> {
    let b = mutate(encode(v), ops);
    if let Ok(w) = d(&b) {
        prop_assert_eq!(&encode(&w), &b);
    }
    if let Ok((w, used)) = decode_prefix(&b, &Limits::DEFAULT) {
        prop_assert_eq!(encode(&w), used.to_vec());
    }
    Ok(())
}

/// Slow tier (notes/architecture.md §4): 20000 cases whatever `PROPTEST_CASES` says.
fn slow_runner() -> proptest::test_runner::TestRunner {
    proptest::test_runner::TestRunner::new(ProptestConfig { cases: 20_000, ..ProptestConfig::default() })
}

// §5, slow tier: `ord_is_byte_order` at size.
#[test]
#[ignore]
fn slow_ord_is_byte_order() {
    slow_runner().run(&(value(), value()), |(a, b)| check_ord(&a, &b)).unwrap();
}

// §5, slow tier: `mutation` at size.
#[test]
#[ignore]
fn slow_mutation() {
    let ops = prop::collection::vec((any::<u8>(), any::<usize>(), any::<u8>()), 1..6);
    slow_runner().run(&(value(), ops), |(v, ops)| check_mutation(&v, &ops)).unwrap();
}

proptest! {
    // §5: round trip.
    #[test]
    fn round_trip(v in value()) {
        let b = encode(&v);
        prop_assert_eq!(d(&b), Ok(v.clone()));
        let c = CanonicalBytes::parse(b.clone(), &Limits::DEFAULT).unwrap();
        prop_assert_eq!(c.depth(), v.depth());
        prop_assert_eq!(c.to_value(), Ok(v.clone()));
        prop_assert_eq!(CanonicalBytes::from_value(&v), c);
    }

    // §5: map keys and set elements sort by canonical bytes; Value's Ord is that order.
    #[test]
    fn ord_is_byte_order(a in value(), b in value()) {
        check_ord(&a, &b)?;
    }

    // §5: strict decoding: any accepted input re-encodes to itself (no non-canonical form is
    // accepted), and nothing panics on mutated input.
    #[test]
    fn mutation(v in value(), ops in prop::collection::vec((any::<u8>(), any::<usize>(), any::<u8>()), 1..6)) {
        check_mutation(&v, &ops)?;
    }

    // §5: random bytes never panic; accepted ones are canonical.
    #[test]
    fn random_bytes(b in prop::collection::vec(any::<u8>(), 0..64)) {
        if let Ok(w) = d(&b) {
            prop_assert_eq!(encode(&w), b);
        }
    }

    // Decoder limits: a value at the depth limit decodes, one level less rejects.
    #[test]
    fn depth_limit(v in value()) {
        let b = encode(&v);
        let lim = |max_depth| Limits { max_depth, max_bytes: usize::MAX };
        prop_assert!(decode(&b, &lim(v.depth())).is_ok());
        if v.depth() > 0 {
            prop_assert_eq!(decode(&b, &lim(v.depth() - 1)), Err(DecodeError::TooDeep));
        }
    }
}

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn tag_head(t: u64) -> String {
    let mut out = Vec::new();
    // Tag numbers here are all 256..65535: 3-byte head.
    assert!((256..65536).contains(&t));
    out.push(0xd9);
    out.extend((t as u16).to_be_bytes());
    out.iter().map(|b| format!("{b:02x}")).collect()
}

// §5: known encodings of each kind.
#[test]
fn known_encodings() {
    let cases: Vec<(Value, &str)> = vec![
        (Value::Int(0), "00"),
        (Value::Int(23), "17"),
        (Value::Int(24), "1818"),
        (Value::Int(-1), "20"),
        (Value::Int(-25), "3818"),
        (Value::Int(256), "190100"),
        (Value::Int(i64::MAX), "1b7fffffffffffffff"),
        (Value::Int(i64::MIN), "3b7fffffffffffffff"),
        (Value::float(1.0), "fb3ff0000000000000"),
        (Value::float(-0.0), "fb8000000000000000"),
        (Value::float(f64::NAN), "fb7ff8000000000000"),
        (Value::Bool(false), "f4"),
        (Value::Bool(true), "f5"),
        (Value::Str("a".into()), "6161"),
        (Value::Bytes(vec![1, 2]), "420102"),
        (Value::List(vec![]), "80"),
        (Value::Map(BTreeMap::from([(Value::Int(1), Value::Int(2)), (Value::Int(-1), Value::Int(0)), (Value::Str("a".into()), Value::Int(0))])), "a3 0102 2000 616100"),
        (Value::Set(BTreeSet::from([Value::Int(10), Value::Int(1)])), "d90102 82 01 0a"),
    ];
    for (v, h) in cases {
        assert_eq!(encode(&v), hex(h), "{v:?}");
        assert_eq!(d(&hex(h)), Ok(v));
    }
    let t = Value::Tid(Tid::from_bytes([0xab; 15]));
    assert_eq!(encode(&t), hex(&format!("{} 4f {}", tag_head(TAG_TID), "ab".repeat(15))));
    let e = Value::Enum(3, Some(Box::new(Value::Bool(true))));
    assert_eq!(encode(&e), hex(&format!("{} 82 03 f5", tag_head(TAG_ENUM))));
    assert_eq!(encode(&Value::Enum(0, None)), hex(&format!("{} 81 00", tag_head(TAG_ENUM))));
    let l = Value::Link(Link { hash: [1; 32], blob: BlobId([2; 32]), suite: 1, key: [3; 32] });
    let lh = format!("{} 83 5820{} 5820{} 5821 01{}", tag_head(TAG_LINK), "01".repeat(32), "02".repeat(32), "03".repeat(32));
    assert_eq!(encode(&l), hex(&lh));
    assert!(matches!(d(&hex(&lh)), Ok(Value::Link(x)) if Value::Link(x) == l && x.blob == BlobId([2; 32]) && x.key == [3; 32]));
    // §5: unknown tags keep tag and content.
    let u = hex("c2 4101");
    let v = d(&u).unwrap();
    assert!(matches!(&v, Value::Unknown(x) if x.tag() == 2 && x.content().as_bytes() == [0x41, 0x01]));
    assert_eq!(encode(&v), u);
    // The reserved STRUCT tag is preserved like any unknown tag.
    let s = hex(&format!("{} a0", tag_head(TAG_STRUCT_RESERVED)));
    assert!(matches!(d(&s), Ok(Value::Unknown(_))));
}

// §4, §6: a link compares by content hash alone (two writes of one large value are equal);
// a set or map holding two links with one hash is not canonical.
#[test]
fn links_equal_by_hash() {
    use std::hash::{BuildHasher, RandomState};
    let a = Value::Link(Link { hash: [1; 32], blob: BlobId([2; 32]), suite: 1, key: [3; 32] });
    let b = Value::Link(Link { hash: [1; 32], blob: BlobId([4; 32]), suite: 1, key: [5; 32] });
    let c = Value::Link(Link { hash: [6; 32], blob: BlobId([2; 32]), suite: 1, key: [3; 32] });
    assert_eq!(a, b);
    assert_ne!(a, c);
    let rs = RandomState::new();
    assert_eq!(rs.hash_one(&a), rs.hash_one(&b));
    assert_eq!(Value::Set([a.clone(), b.clone(), c.clone()].into_iter().collect()), Value::Set([a.clone(), c].into_iter().collect()));
    let mut set = encode(&Value::List(vec![a.clone(), b.clone()]));
    set.splice(0..0, hex(&tag_head(TAG_SET)));
    assert_eq!(d(&set), Err(DecodeError::SetOrder));
    let mut map = vec![0xa2];
    for (k, v) in [(&a, 0u8), (&b, 1)] {
        map.extend(encode(k));
        map.push(v);
    }
    assert_eq!(d(&map), Err(DecodeError::MapKeyOrder));
}

// §5: every rejection rule.
#[test]
fn rejections() {
    use DecodeError::*;
    let tid = tag_head(TAG_TID);
    let en = tag_head(TAG_ENUM);
    let ln = tag_head(TAG_LINK);
    let set = tag_head(TAG_SET);
    let cases: Vec<(String, DecodeError)> = vec![
        // Shortest heads (ints, lengths, tags).
        ("1817".into(), NonShortestHead),
        ("190017".into(), NonShortestHead),
        ("1a0000ffff".into(), NonShortestHead),
        ("1b00000000ffffffff".into(), NonShortestHead),
        ("3817".into(), NonShortestHead),
        ("5801ff".into(), NonShortestHead),
        ("780161".into(), NonShortestHead),
        ("9800".into(), NonShortestHead),
        ("b800".into(), NonShortestHead),
        ("d802 01".into(), NonShortestHead),
        ("c2 01 00".into(), Trailing),
        ("d90002 00".into(), NonShortestHead),
        // Definite lengths only; reserved additional info.
        ("5f41ff".into(), Indefinite),
        ("7f ff".into(), Indefinite),
        ("9f ff".into(), Indefinite),
        ("bf ff".into(), Indefinite),
        ("1c".into(), ReservedInfo),
        ("5d".into(), ReservedInfo),
        // Ints outside i64.
        ("1b8000000000000000".into(), IntOutOfRange),
        ("3b8000000000000000".into(), IntOutOfRange),
        // Floats: 8 bytes only, canonical NaN only. No other simple values.
        ("f97e00".into(), BadSimple),
        ("fa7fc00000".into(), BadSimple),
        ("fb7ff8000000000001".into(), NonCanonicalNan),
        ("fbfff8000000000000".into(), NonCanonicalNan),
        ("fb7ff0000000000001".into(), NonCanonicalNan),
        ("f6".into(), BadSimple),
        ("f7".into(), BadSimple),
        ("f0".into(), BadSimple),
        ("f820".into(), BadSimple),
        ("ff".into(), BadSimple),
        // Text must be UTF-8.
        ("62c328".into(), InvalidUtf8),
        // Map keys sorted, unique; sets sorted, unique.
        ("a2 0100 0000".into(), MapKeyOrder),
        ("a2 0000 0000".into(), MapKeyOrder),
        ("a2 6161 00 01 00".into(), MapKeyOrder),
        (format!("{set} 82 0a 01"), SetOrder),
        (format!("{set} 82 01 01"), SetOrder),
        (format!("{set} a0"), TagContent(TAG_SET)),
        // Known tags with the wrong content.
        (format!("{tid} 4e {}", "00".repeat(14)), TagContent(TAG_TID)),
        (format!("{tid} 6f {}", "61".repeat(15)), TagContent(TAG_TID)),
        (format!("{en} 80"), TagContent(TAG_ENUM)),
        (format!("{en} 83 00 00 00"), TagContent(TAG_ENUM)),
        (format!("{en} 81 20"), TagContent(TAG_ENUM)),
        (format!("{en} 01"), TagContent(TAG_ENUM)),
        (format!("{ln} 82 5820{} 5820{}", "00".repeat(32), "00".repeat(32)), TagContent(TAG_LINK)),
        (format!("{ln} 83 5820{} 5820{} 5820{}", "00".repeat(32), "00".repeat(32), "00".repeat(32)), TagContent(TAG_LINK)),
        // Truncation and trailing bytes.
        ("".into(), Truncated),
        ("19 01".into(), Truncated),
        ("63 6161".into(), Truncated),
        ("82 01".into(), Truncated),
        ("9b 7fffffffffffffff".into(), Truncated),
        ("0000".into(), Trailing),
    ];
    for (h, e) in cases {
        assert_eq!(d(&hex(&h)), Err(e), "{h}");
    }
}

// Decoder limits: size cap, and depth cap without recursion blowup on deep input.
#[test]
fn limits() {
    let b = encode(&Value::Bytes(vec![0; 100]));
    assert!(decode(&b, &Limits { max_depth: 4, max_bytes: 102 }).is_ok());
    assert_eq!(decode(&b, &Limits { max_depth: 4, max_bytes: 101 }), Err(DecodeError::TooLarge));
    let deep = vec![0x81u8; 1_000_000];
    assert_eq!(d(&deep), Err(DecodeError::TooDeep));
    // spec/data-model.md §5: 64 nested arrays around a scalar are allowed, 65 are not.
    let nest = |n: usize| [vec![0x81u8; n], vec![0x00]].concat();
    assert!(d(&nest(64)).is_ok());
    assert_eq!(d(&nest(65)), Err(DecodeError::TooDeep));
    // A huge claimed length is rejected before allocation.
    assert_eq!(d(&hex("9b 0000000100000000")), Err(DecodeError::Truncated));
    assert_eq!(d(&hex("bb 0000000100000000")), Err(DecodeError::Truncated));
}

// decode_prefix returns the consumed bytes as received.
#[test]
fn prefix() {
    let b = hex("8201 02 ff ee");
    let (v, used) = decode_prefix(&b, &Limits::DEFAULT).unwrap();
    assert_eq!(v, Value::List(vec![Value::Int(1), Value::Int(2)]));
    assert_eq!(used, &b[..3]);
}

// §5: NaN normalized at construction; -0.0 and 0.0 distinct.
#[test]
fn floats_identity() {
    assert_eq!(Value::float(f64::NAN), Value::float(-f64::NAN));
    assert_ne!(Value::float(0.0), Value::float(-0.0));
    assert_eq!(Float::from_bits(0x7ff8_0000_0000_0001), None);
    assert_eq!(Float::new(f64::from_bits(0xfff8_0000_0000_0001)).to_bits(), Float::CANONICAL_NAN);
}

// §5: Unknown never holds a known tag.
#[test]
fn unknown_rejects_known_tags() {
    let c = CanonicalBytes::from_value(&Value::Int(0));
    for t in [TAG_SET, TAG_TID, TAG_ENUM, TAG_LINK] {
        assert!(Unknown::new(t, c.clone()).is_none());
    }
    assert!(Unknown::new(TAG_STRUCT_RESERVED, c).is_some());
}

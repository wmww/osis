//! Canonical CBOR profile tests (spec/data-model.md §5).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)] // test code

use osis_base::format::{TAG_ENUM, TAG_LINK, TAG_SET, TAG_STRUCT_RESERVED, TAG_TID};
use osis_base::{BlobId, CanonicalBytes, DecodeError, Float, Limits, Link, Tid, Unknown, Value, decode, decode_prefix, encode, item_prefix};
use proptest::prelude::*;

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
            .prop_map(|(hash, blob, suite, key)| Value::link(Link { hash, blob: BlobId(blob), suite, key })),
        prop_oneof![Just(0u64), Just(23), Just(300), Just(i64::MAX as u64)].prop_map(|c| Value::Enum(c, None)),
    ]
}

fn value() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::List),
            prop::collection::vec((inner.clone(), inner.clone()), 0..6).prop_map(|e| Value::Map(e.into_iter().collect())),
            prop::collection::vec(inner.clone(), 0..6).prop_map(|e| Value::Set(e.into_iter().collect())),
            (0..=i64::MAX as u64, inner.clone()).prop_map(|(c, p)| Value::Enum(c, Some(Box::new(p)))),
            (prop_oneof![Just(0u64), Just(2), Just(255), Just(259), Just(TAG_STRUCT_RESERVED), Just(70_000), Just(u64::MAX)], inner)
                .prop_map(|(t, c)| Value::unknown(Unknown::new(t, CanonicalBytes::from_value(&c)).unwrap())),
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

/// The properties' size (notes/testing.md, When tests run): 20000 cases whatever `PROPTEST_CASES` says.
fn slow_runner() -> proptest::test_runner::TestRunner {
    proptest::test_runner::TestRunner::new(ProptestConfig { cases: 20_000, ..ProptestConfig::default() })
}

// §5, a property: `ord_is_byte_order` at size.
#[test]
#[ignore = "property"]
fn ord_is_byte_order_large() {
    slow_runner().run(&(value(), value()), |(a, b)| check_ord(&a, &b)).unwrap();
}

// §5, a property: `mutation` at size.
#[test]
#[ignore = "property"]
fn mutation_large() {
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

    // §5: map keys and set elements sort by canonical bytes; Value's Ord is that order for values
    // without two links of one content hash (random links never share one; see links_sort_by_bytes).
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

    // §5: an item's extent found by its heads alone is the extent decoding finds, followed by
    // anything; on random bytes it never panics and agrees wherever decoding accepts.
    #[test]
    fn item_prefix_is_decoded_extent(v in value(), tail in prop::collection::vec(any::<u8>(), 0..8), b in prop::collection::vec(any::<u8>(), 0..64)) {
        let e = encode(&v);
        let with_tail = [e.as_slice(), &tail].concat();
        prop_assert_eq!(item_prefix(&with_tail, &Limits::DEFAULT), Ok(e.as_slice()));
        if let Ok((_, used)) = decode_prefix(&b, &Limits::DEFAULT) {
            prop_assert_eq!(item_prefix(&b, &Limits::DEFAULT), Ok(used));
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
    osis_base::hex::decode(s).unwrap()
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
        (Value::Map(osis_base::ValueMap::from([(Value::Int(1), Value::Int(2)), (Value::Int(-1), Value::Int(0)), (Value::Str("a".into()), Value::Int(0))])), "a3 0102 2000 616100"),
        (Value::Set(osis_base::ValueSet::from([Value::Int(10), Value::Int(1)])), "d90102 82 01 0a"),
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
    let l = Value::link(Link { hash: [1; 32], blob: BlobId([2; 32]), suite: 1, key: [3; 32] });
    let lh = format!("{} 83 5820{} 5820{} 5821 01{}", tag_head(TAG_LINK), "01".repeat(32), "02".repeat(32), "03".repeat(32));
    assert_eq!(encode(&l), hex(&lh));
    assert!(matches!(d(&hex(&lh)), Ok(Value::Link(x)) if Value::Link(x.clone()) == l && x.blob == BlobId([2; 32]) && x.key == [3; 32]));
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
    let a = Value::link(Link { hash: [1; 32], blob: BlobId([2; 32]), suite: 1, key: [3; 32] });
    let b = Value::link(Link { hash: [1; 32], blob: BlobId([4; 32]), suite: 1, key: [5; 32] });
    let c = Value::link(Link { hash: [6; 32], blob: BlobId([2; 32]), suite: 1, key: [3; 32] });
    assert_eq!(a, b);
    assert_ne!(a, c);
    let rs = RandomState::new();
    assert_eq!(rs.hash_one(&a), rs.hash_one(&b));
    assert_eq!(Value::Set([a.clone(), b.clone(), c.clone()].into_iter().collect()), Value::Set([a.clone(), c].into_iter().collect()));
    let mut set = encode(&Value::List(vec![a.clone(), b.clone()]));
    set.splice(0..0, hex(&tag_head(TAG_SET)));
    assert_eq!(d(&set), Err(DecodeError::EqualLinks));
    let mut map = vec![0xa2];
    for (k, v) in [(&a, 0u8), (&b, 1)] {
        map.extend(encode(k));
        map.push(v);
    }
    assert_eq!(d(&map), Err(DecodeError::EqualLinks));
}

// §5: with links of one content hash, Ord and byte order differ ([LA, 3] < [LB, 5] by value while
// LA's bytes sort after LB's); sets and maps still encode sorted by bytes, round trip, and a
// byte-sorted input re-encodes to itself.
#[test]
fn links_sort_by_bytes() {
    let la = Value::link(Link { hash: [1; 32], blob: BlobId([9; 32]), suite: 1, key: [0; 32] });
    let lb = Value::link(Link { hash: [1; 32], blob: BlobId([2; 32]), suite: 1, key: [0; 32] });
    let x = Value::List(vec![la, Value::Int(3)]);
    let y = Value::List(vec![lb, Value::Int(5)]);
    assert_eq!(x.cmp(&y), std::cmp::Ordering::Less);
    assert!(encode(&x) > encode(&y));
    let s = Value::Set([x.clone(), y.clone()].into_iter().collect());
    let b = encode(&s);
    let mut want = hex(&tag_head(TAG_SET));
    want.push(0x82);
    want.extend(encode(&y));
    want.extend(encode(&x));
    assert_eq!(b, want);
    assert_eq!(d(&b).map(|v| encode(&v)), Ok(b.clone()));
    let m = Value::Map([(x.clone(), Value::Int(1)), (y.clone(), Value::Int(2))].into_iter().collect());
    let mb = encode(&m);
    let mut want = vec![0xa2];
    want.extend(encode(&y));
    want.push(0x02);
    want.extend(encode(&x));
    want.push(0x01);
    assert_eq!(mb, want);
    assert_eq!(d(&mb).map(|v| encode(&v)), Ok(mb));
    // Nested: the set inside a list still sorts by bytes.
    let l = Value::List(vec![s]);
    assert_eq!(d(&encode(&l)).map(|v| encode(&v)), Ok(encode(&l)));
}

// §5: every rejection rule.
// spec/data-model.md §5 (cbor profile)
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
// spec/data-model.md §5 (cbor profile)
#[test]
fn unknown_rejects_known_tags() {
    let c = CanonicalBytes::from_value(&Value::Int(0));
    for t in [TAG_SET, TAG_TID, TAG_ENUM, TAG_LINK] {
        assert!(Unknown::new(t, c.clone()).is_none());
    }
    assert!(Unknown::new(TAG_STRUCT_RESERVED, c).is_some());
}

// RFC 8949 §4.2.1: `head` is the shortest head at every length boundary, `head_len` its length.
#[test]
fn head_boundaries() {
    use osis_base::cbor::{head, head_len};
    let mut args = vec![0u64, u64::MAX, u64::MAX - 1];
    for b in [24u64, 0x100, 0x1_0000, 0x1_0000_0000] {
        args.extend([b - 1, b, b + 1]);
    }
    for major in 0..=7u8 {
        for &a in &args {
            let m = major << 5;
            let want: Vec<u8> = match a {
                0..24 => vec![m | a as u8],
                24..0x100 => vec![m | 24, a as u8],
                0x100..0x1_0000 => [&[m | 25][..], &(a as u16).to_be_bytes()].concat(),
                0x1_0000..0x1_0000_0000 => [&[m | 26][..], &(a as u32).to_be_bytes()].concat(),
                _ => [&[m | 27][..], &a.to_be_bytes()].concat(),
            };
            let mut got = Vec::new();
            head(&mut got, major, a);
            assert_eq!(got, want, "major {major} arg {a}");
            assert_eq!(head_len(a), want.len(), "arg {a}");
        }
    }
}

/// One hostile shape: `item` repeated in a list of `n` bytes at most.
fn repeated(n: usize, item: &[u8]) -> Vec<u8> {
    let count = (n - 9) / item.len();
    let mut out = Vec::with_capacity(n);
    osis_base::cbor::head(&mut out, osis_base::cbor::MAJOR_ARRAY, count as u64);
    for _ in 0..count {
        out.extend_from_slice(item);
    }
    out
}

/// A list holding `item` `depth` lists deep.
fn nested(depth: usize, item: &[u8]) -> Vec<u8> {
    [&vec![0x81; depth][..], item].concat()
}

/// The inputs `decode_peak_within_the_bound` measures: name, bytes. Each decodes.
fn hostile_shapes(n: usize) -> Vec<(&'static str, Vec<u8>)> {
    let tid = [&[0xd9, 0x06, 0x50, 0x4f][..], &[1; 15][..]].concat();
    vec![
        ("{0:0}", repeated(n, &[0xa1, 0, 0])),
        ("{}", repeated(n, &[0xa0])),
        ("[]", repeated(n, &[0x80])),
        ("[[]]", repeated(n, &[0x81, 0x80])),
        ("[0]", repeated(n, &[0x81, 0])),
        ("0", repeated(n, &[0])),
        ("empty str", repeated(n, &[0x60])),
        ("one-byte str", repeated(n, &[0x61, b'a'])),
        ("one-byte bytes", repeated(n, &[0x41, 1])),
        ("set of one", repeated(n, &[0xd9, 0x01, 0x02, 0x81, 0])),
        ("enum of one", repeated(n, &[0xd9, 0x06, 0x51, 0x82, 0, 0])),
        ("unknown tag", repeated(n, &[0xc0, 0])),
        ("unknown tag around a list", [&[0xc0][..], &repeated(n, &[0])].concat()),
        ("unknown tags at the depth limit", repeated(n, &[&[0xc0; 63][..], &[0]].concat())),
        ("tid", repeated(n, &tid)),
        ("lists at the depth limit", repeated(n, &nested(63, &[0]))),
        ("maps at the depth limit", repeated(n, &[&[0xa1, 0][..]; 63].concat().into_iter().chain([0]).collect::<Vec<u8>>())),
        ("big map", {
            let count = n / 10;
            let mut out = Vec::with_capacity(n);
            osis_base::cbor::head(&mut out, osis_base::cbor::MAJOR_MAP, count as u64);
            for i in 0..count as i64 {
                encode_into_int(&mut out, i);
                out.push(0);
            }
            out
        }),
    ]
}

/// Inputs that fail, after a head has claimed space their bytes never fill. A claim is space
/// allocated but untouched, until an item lands in it.
fn lying_shapes(n: usize) -> Vec<(&'static str, Vec<u8>)> {
    use osis_base::cbor::{MAJOR_ARRAY, head};
    let claim = |items: &[u8]| {
        let mut out = Vec::with_capacity(n);
        head(&mut out, MAJOR_ARRAY, (n - 9) as u64);
        while out.len() + items.len() <= n {
            out.extend_from_slice(items);
        }
        out
    };
    // each of the depth limit's lists claims its share of what is left
    let mut spine = Vec::with_capacity(n);
    for _ in 0..osis_base::format::MAX_VALUE_DEPTH {
        head(&mut spine, MAJOR_ARRAY, (n / 2) as u64);
    }
    spine.resize(n, 0);
    vec![("one claim, unknown tags", claim(&[0xc0, 0])), ("one claim, zeros", claim(&[0])), ("claims at the depth limit", spine)]
}

fn encode_into_int(out: &mut Vec<u8>, i: i64) {
    osis_base::cbor::encode_into(&Value::Int(i), out);
}

#[cfg(target_os = "linux")]
fn status_kib(field: &str) -> usize {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = s.lines().find(|l| l.starts_with(field)).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// Bytes of input a decode may spend `DECODE_PEAK_MAX` per byte on, measured.
const PEAK_INPUT: usize = 2 << 20;
/// Allowed resident growth per input byte; the bound `decode` states (`osis_base::cbor`).
const DECODE_PEAK_MAX: usize = 64;
/// Allowed address space growth per input byte, untouched claims included: 72 (`osis_base::cbor`),
/// and a test thread's malloc arena grows it in steps of 64 MiB, 32 B per byte here.
const DECODE_CLAIM_MAX: usize = 104;

// Every shape of small items, and of heads claiming what their bytes cannot fill, costs under
// `DECODE_PEAK_MAX` per byte of input in real memory and under `DECODE_CLAIM_MAX` in address space:
// each runs in its own child process, as the peaks are process-wide and this binary's tests share one.
#[cfg(target_os = "linux")]
#[test]
fn decode_peak_within_the_bound() {
    const CHILD: &str = "OSIS_DECODE_PEAK_SHAPE";
    let shapes = |n| hostile_shapes(n).into_iter().chain(lying_shapes(n)).collect::<Vec<_>>();
    if let Ok(which) = std::env::var(CHILD) {
        let (_, bytes) = shapes(PEAK_INPUT).swap_remove(which.parse().unwrap());
        let _ = std::fs::write("/proc/self/clear_refs", "5");
        let (rss0, vm0) = (status_kib("VmRSS"), status_kib("VmSize"));
        let v = decode(&bytes, &Limits::DEFAULT);
        println!("peak_kib={} {}", status_kib("VmHWM").saturating_sub(rss0), status_kib("VmPeak").saturating_sub(vm0));
        std::hint::black_box(&v);
        return;
    }
    for (name, bytes) in hostile_shapes(1 << 12) {
        decode(&bytes, &Limits::DEFAULT).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    let exe = std::env::current_exe().unwrap();
    let mut over = Vec::new();
    for (i, (name, _)) in shapes(1 << 12).iter().enumerate() {
        let out = std::process::Command::new(&exe)
            .args(["--exact", "decode_peak_within_the_bound", "--nocapture", "--test-threads=1"])
            .env(CHILD, i.to_string())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{name}: {text}");
        let line = text.lines().find_map(|l| l.split("peak_kib=").nth(1)).unwrap_or_else(|| panic!("{name}: {text}"));
        let kib: Vec<usize> = line.split_whitespace().map(|x| x.parse().unwrap()).collect();
        let [real, claimed] = kib[..] else { panic!("{name}: {line}") };
        let per_byte = |k: usize| k as f64 * 1024.0 / PEAK_INPUT as f64;
        println!("{name}: {:.1} B per byte, {:.1} claimed", per_byte(real), per_byte(claimed));
        if real * 1024 > DECODE_PEAK_MAX * PEAK_INPUT || claimed * 1024 > DECODE_CLAIM_MAX * PEAK_INPUT {
            over.push((*name, per_byte(real), per_byte(claimed)));
        }
    }
    assert!(over.is_empty(), "over {DECODE_PEAK_MAX} B per byte, or {DECODE_CLAIM_MAX} claimed: {over:?}");
}

// A valid value's heads promise at most one item per byte; heads that promise more are refused
// before their space is allocated, each on its own within the input and all together not.
#[test]
fn lying_heads_refused_before_allocating() {
    use osis_base::cbor::{MAJOR_ARRAY, MAJOR_MAP, head};
    let n: usize = 1 << 16;
    // each list claims all that is left: only the first few can be believed
    let mut nested = Vec::new();
    while nested.len() + 3 < n {
        let left = n - nested.len() - 3;
        head(&mut nested, MAJOR_ARRAY, left as u64);
    }
    nested.resize(n, 0);
    assert_eq!(decode(&nested, &Limits { max_depth: usize::MAX, max_bytes: n }), Err(DecodeError::Truncated));
    let mut maps = Vec::new();
    head(&mut maps, MAJOR_MAP, (n / 2 - 3) as u64);
    head(&mut maps, osis_base::cbor::MAJOR_UINT, 0);
    head(&mut maps, MAJOR_MAP, (n / 2 - 3) as u64);
    maps.resize(n, 0);
    assert_eq!(decode(&maps, &Limits { max_depth: usize::MAX, max_bytes: n }), Err(DecodeError::Truncated));
    // exactly as many as the bytes: every item a byte, nothing refused
    let mut exact = Vec::new();
    head(&mut exact, MAJOR_ARRAY, 1000);
    exact.resize(1000 + exact.len(), 0);
    assert!(matches!(d(&exact), Ok(Value::List(l)) if l.len() == 1000));
}

// `Value`'s size is what every item of a decode costs (`osis_base::cbor::decode`).
#[test]
fn value_stays_small() {
    assert!(size_of::<Value>() <= 32, "{}", size_of::<Value>());
}

// `ValueMap` and `ValueSet` behave as the `BTreeMap` and `BTreeSet` they replaced, equal link keys
// included: the same entries in the same order by any mix of operations.
proptest! {
    #[test]
    fn sorted_containers_match_btree(ops in proptest::collection::vec((0u8..4, 0u8..12, any::<u8>()), 0..200)) {
        use std::collections::{BTreeMap, BTreeSet};
        // a key: an int, or a link of hash `k % 3` with a blob telling equal ones apart
        let key = |k: u8, v: u8| if k < 6 { Value::Int(k.into()) } else { Value::link(Link { hash: [k % 3; 32], blob: BlobId([v; 32]), suite: 1, key: [0; 32] }) };
        let bytes = |v: &Value| encode(v);
        let (mut m, mut bm) = (osis_base::ValueMap::new(), BTreeMap::new());
        let (mut s, mut bs) = (osis_base::ValueSet::new(), BTreeSet::new());
        let mut all = Vec::new();
        for (op, k, v) in ops {
            let (k, x) = (key(k, v), Value::Int(v.into()));
            all.push((k.clone(), x.clone()));
            match op {
                0 | 1 => {
                    prop_assert_eq!(m.insert(k.clone(), x.clone()), bm.insert(k.clone(), x));
                    prop_assert_eq!(s.insert(k.clone()), bs.insert(k));
                }
                2 => {
                    prop_assert_eq!(m.remove(&k), bm.remove(&k));
                    prop_assert_eq!(s.remove(&k), bs.remove(&k));
                }
                _ => {
                    prop_assert_eq!(m.get(&k), bm.get(&k));
                    prop_assert_eq!(s.contains(&k), bs.contains(&k));
                }
            }
            prop_assert_eq!(m.iter().map(|(a, b)| (bytes(a), bytes(b))).collect::<Vec<_>>(), bm.iter().map(|(a, b)| (bytes(a), bytes(b))).collect::<Vec<_>>());
            prop_assert_eq!(s.iter().map(bytes).collect::<Vec<_>>(), bs.iter().map(bytes).collect::<Vec<_>>());
        }
        let cm: osis_base::ValueMap = all.iter().cloned().collect();
        let bcm: BTreeMap<Value, Value> = all.iter().cloned().collect();
        prop_assert_eq!(cm.iter().map(|(a, b)| (bytes(a), bytes(b))).collect::<Vec<_>>(), bcm.iter().map(|(a, b)| (bytes(a), bytes(b))).collect::<Vec<_>>());
        let cs: osis_base::ValueSet = all.iter().map(|e| e.0.clone()).collect();
        let bcs: BTreeSet<Value> = all.iter().map(|e| e.0.clone()).collect();
        prop_assert_eq!(cs.iter().map(bytes).collect::<Vec<_>>(), bcs.iter().map(bytes).collect::<Vec<_>>());
    }
}

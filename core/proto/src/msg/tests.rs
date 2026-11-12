//! spec/wire.md §11.2, §13: message layouts, caps, rejections.

use super::*;
use crate::examples::messages;
use proptest::prelude::*;

// spec/wire.md §11.2 (Resume): a tag past `MAX_RESUME_TAGS`, or of the wrong length, is refused
#[test]
fn resume_caps_spec_wire_11_2() {
    let over = Message::Resume { id: 1, nonce: [1; 32], tags: vec![[2; 32]; crate::prove::MAX_RESUME_TAGS + 1] };
    assert!(Message::decode(&over.encode()).is_err());
    let short = Value::List(vec![Value::Int(34), Value::Int(1), Value::bytes(&[1; 32]), Value::List(vec![Value::bytes(&[2; 31])])]);
    assert!(Message::decode(&osis_base::cbor::encode(&short)).is_err());
}

// spec/wire.md §11.2: every kind `Message::kind` names decodes at some arity: the per-kind field
// table in `decode_body` and its match stay in step, not only for the examples listed
#[test]
fn every_kind_is_in_the_decode_table() {
    for kind in kinds() {
        assert!(!unknown_at_every_arity(kind), "kind {kind} has no field count or decode arm");
    }
}

/// The kinds `Message::kind` names, parsed from its source.
fn kinds() -> Vec<u64> {
    let src = include_str!("../msg.rs");
    let body = src.split("pub fn kind(&self)").nth(1).expect("fn kind").split("\n    }\n").next().unwrap();
    let kinds: Vec<u64> = body.lines().filter_map(|l| l.trim().strip_suffix(',')?.rsplit("=> ").next()?.parse().ok()).collect();
    assert!(kinds.len() > 30, "kinds parsed from Message::kind: {kinds:?}");
    kinds
}

/// Whether `kind` decodes as an unknown kind with 0 to 6 fields after its head.
fn unknown_at_every_arity(kind: u64) -> bool {
    (2..=8).all(|n| {
        let mut items = vec![Value::Int(kind as i64), Value::Int(1)];
        items.resize(n, Value::Int(0));
        matches!(decode_body(kind, 1, Value::List(items)), Err(Error::UnknownKind(_)))
    })
}

/// Retired kinds (spec/wire.md §11.2): never decoded, never reused.
const RETIRED: [u64; 10] = [10, 12, 13, 15, 16, 17, 18, 21, 22, 23];

// spec/wire.md §11.2: a retired kind number is no message: it decodes as an unknown kind (a
// request of it is answered Error 11), is neither request nor reply, and names no kind again
#[test]
fn retired_kinds_are_unknown_spec_wire_11_2() {
    let kinds = kinds();
    for kind in RETIRED {
        assert!(unknown_at_every_arity(kind), "kind {kind} decodes");
        let r = rejected(Value::List(vec![Value::Int(kind as i64), Value::Int(7), Value::Int(0)]));
        assert_eq!((r.id, r.code(), r.error), (7, Code::UNSUPPORTED, Error::UnknownKind(kind)), "kind {kind}");
        assert!(!is_request_kind(kind) && !is_reply_kind(kind), "kind {kind}");
        assert!(!kinds.contains(&kind), "kind {kind} reused");
    }
}

fn enc(v: Value) -> Vec<u8> {
    cbor::encode(&v)
}

fn rejected(v: Value) -> Rejected {
    Message::decode(&enc(v)).expect_err("decoded")
}

fn with_list(m: Message, n: usize) -> Value {
    // Replaces the first list field of `m`'s encoding by `n` copies of its first element.
    let Value::List(mut items) = m.to_value() else { unreachable!() };
    for it in items.iter_mut() {
        if let Value::List(l) = it
            && let Some(first) = l.first().cloned()
        {
            *l = vec![first; n];
            break;
        }
    }
    Value::List(items)
}

// spec/wire.md §11.2: the examples name every kind but the ones listed (the vectors generator
// round-trips each example)
#[test]
fn examples_name_every_kind() {
    let ms = messages();
    let mut kinds: Vec<u64> = ms.iter().map(|(_, m)| m.kind()).collect();
    kinds.dedup();
    // retired kinds name nothing; kinds 24-29 (client port): tests/it/port.rs; 30-31 reports;
    // 32-35 elsewhere; 36-40 the shared set; 41-44 the stream; 45-46 the digest
    assert_eq!(kinds, (0..=23).filter(|k| !RETIRED.contains(k)).chain(30..=31).chain(36..=46).collect::<Vec<_>>());
}

// spec/wire.md §11.2 Pull: a Stream with a cursor and no events (an ended member reaching its
// `until`, asking a report) is a message
#[test]
fn a_stream_with_no_events_round_trips_spec_wire_11_2() {
    let m = Message::Stream(Box::new(crate::msg::Stream { events: vec![], cursor: Some(vec![0x30; 72]), report: true }));
    assert_eq!(Message::decode(&m.encode()), Ok(m));
}

// spec/wire.md §11.2: per-message caps
#[test]
fn caps() {
    let ms: std::collections::BTreeMap<_, _> = messages().into_iter().collect();
    let m = |n: &str| ms[n].clone();
    for (name, cap) in [("delete", MAX_ITEMS), ("fetch", MAX_ITEMS), ("path reply", MAX_PATH_STEPS), ("fetch reply", MAX_ITEMS)] {
        assert!(Message::decode(&enc(with_list(m(name), cap))).is_ok(), "{name} at cap");
        assert_eq!(rejected(with_list(m(name), cap + 1)).error, Error::Cap(match name {
            "delete" => "delete items",
            "fetch" => "fetch ids",
            "path reply" => "path steps",
            _ => "fetch items",
        }), "{name}");
    }
    // Delete and Fetch need at least one item
    for name in ["delete", "fetch"] {
        assert!(Message::decode(&enc(with_list(m(name), 0))).is_err(), "{name} empty");
    }
}

// spec/wire.md §11.1: [kind, id, ...] with id < 2^32; unknown kind answered by 11; Stream carries id 0
#[test]
fn heads() {
    let r = rejected(Value::List(vec![Value::Int(99), Value::Int(7)]));
    assert_eq!((r.id, r.code()), (7, Code::UNSUPPORTED));
    // kind 47 is unknown
    assert_eq!(rejected(Value::List(vec![Value::Int(47), Value::Int(0)])).code(), Code::UNSUPPORTED);
    assert_eq!(rejected(Value::List(vec![Value::Int(2), Value::Int(0), Value::Int(1)])).error, Error::Malformed("id 0"));
    assert_eq!(rejected(Value::List(vec![Value::Int(1), Value::Int(0)])).error, Error::Malformed("id 0"));
    assert!(Message::decode(&enc(Value::List(vec![Value::Int(0), Value::Int(0), Value::Int(2)]))).is_ok());
    // non-canonical head, trailing bytes, indefinite length
    assert!(Message::decode(&[0x82, 0x01, 0x18, 0x01]).is_err());
    assert!(Message::decode(&[0x82, 0x01, 0x01, 0x00]).is_err());
    assert!(Message::decode(&[0x9f, 0x01, 0x01, 0xff]).is_err());
    let r = rejected(Value::List(vec![Value::Int(2), Value::Int(1 << 32), Value::Int(0)]));
    assert_eq!((r.id, r.code()), (0, Code::MALFORMED));
    let r = rejected(Value::List(vec![Value::Int(2), Value::Int(9), Value::Int(0), Value::Int(0)]));
    assert_eq!((r.id, r.code()), (9, Code::MALFORMED));
    assert!(Message::decode(&[0xff]).is_err());
    let Value::List(mut push) = messages().into_iter().find(|(n, _)| *n == "stream").unwrap().1.to_value() else { unreachable!() };
    push[1] = Value::Int(5);
    assert!(Message::decode(&enc(Value::List(push))).is_err());
}

// spec/wire.md §11.2: wrap 57 bytes, sig 64, label 16; blob at most MAX_BLOB
// spec/sync.md §5 (deposit refusals): an oversized blob does not decode
#[test]
fn field_sizes() {
    let Value::List(offer) = messages().into_iter().find(|(n, _)| *n == "offer with a deposit").unwrap().1.to_value() else { unreachable!() };
    // the deposit item: [2, label, blob, wrap, sig]
    let with = |pos: usize, v: Value| {
        let mut o = offer.clone();
        let Value::List(items) = &mut o[2] else { unreachable!() };
        let Value::List(d) = &mut items[0] else { unreachable!() };
        d[pos] = v;
        Value::List(o)
    };
    for (pos, len) in [(1, 15), (3, 48), (4, 63)] {
        assert!(Message::decode(&enc(with(pos, Value::Bytes(vec![0; len])))).is_err(), "pos {pos}");
    }
    assert_eq!(rejected(with(2, Value::Bytes(vec![0; MAX_BLOB + 1]))).error, Error::Cap("offer item"));
    let st = |n: usize| Value::List(vec![Value::Int(6), Value::Int(1), Value::Bytes(vec![0; n])]);
    assert_eq!(rejected(st(MAX_STEP_BYTES + 1)).error, Error::Cap("step"));
    // a step must parse: 323 zero bytes do not
    assert!(matches!(rejected(st(MAX_STEP_BYTES)).error, Error::Label(_)));
}

proptest! {
    // spec/wire.md §13: decoders never panic on arbitrary or mutated bytes
    #[test]
    fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..200), which in 0usize..29, pos in any::<usize>(), byte in any::<u8>()) {
        let _ = Message::decode(&bytes);
        let ms = messages();
        let mut enc = ms[which % ms.len()].1.encode();
        let p = pos % enc.len();
        enc[p] = byte;
        if let Ok(m) = Message::decode(&enc) {
            // anything accepted re-encodes to the same canonical bytes
            prop_assert_eq!(m.encode(), enc);
        }
    }
}

// spec/wire.md §13 (message items), spec/requirements.md (peer input never causes unbounded
// allocation): a frame of one-byte items is refused before its value tree is built, while the
// densest message valid by §11.2 still decodes
#[test]
fn item_cap_spec_wire_13() {
    let n = MAX_MESSAGE - 16;
    let mut body = vec![0x83, 0x0b, 0x01, 0x9a];
    body.extend_from_slice(&(n as u32).to_be_bytes());
    body.extend(std::iter::repeat_n(0u8, n));
    let r = Message::decode(&body).expect_err("decoded");
    assert_eq!(r.error, Error::Cap("message items"));
    // Deleted events filling the frame (denser than any engine reply: those page by
    // `stream_event_size`)
    let deleted = (LabelId([0xdd; 16]), Event::Deleted(BlobId([0xee; 32])));
    let each = enc(Value::List(vec![Value::bytes(&deleted.0.0), event_value(&deleted.1)])).len();
    let k = (MAX_MESSAGE - 64) / each;
    let m = Message::PullReply(Box::new(PullReply { id: 1, events: vec![deleted; k], cursor: Some(vec![1; 72]), whole: false, trimmed: false, more: true, report: false, joins: vec![] }));
    let body = m.encode();
    assert!(body.len() <= MAX_MESSAGE && body.len() + 100 > MAX_MESSAGE, "{}", body.len());
    assert_eq!(Message::decode(&body), Ok(m));
}

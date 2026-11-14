//! spec/wire.md §11.1, §11.2, §13: message layouts, ids, caps, rejections.

use super::*;
use crate::examples::{messages, rejections};
use proptest::prelude::*;
use std::collections::BTreeSet;

/// Every kind version 1 names (spec/wire.md §11.2).
const KINDS: [u64; 32] = [0, 1, 2, 3, 7, 11, 14, 19, 20, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46];
/// Retired kinds (spec/wire.md §11.2): never decoded, never reused.
const RETIRED: [u64; 15] = [4, 5, 6, 8, 9, 10, 12, 13, 15, 16, 17, 18, 21, 22, 23];

fn enc(v: Value) -> Vec<u8> {
    cbor::encode(&v)
}

fn rejected(v: Value) -> Rejected {
    Msg::decode(&enc(v)).expect_err("decoded")
}

// spec/wire.md §11.2: one example of every kind decodes to itself and re-encodes to its bytes
#[test]
fn every_kind_round_trips_spec_wire_11_2() {
    let mut kinds = BTreeSet::new();
    for (name, m) in messages() {
        let body = m.encode();
        assert_eq!(Msg::decode(&body).as_ref(), Ok(&m), "{name}");
        assert_eq!(Msg::decode(&body).map(|m| m.encode()), Ok(body), "{name}");
        kinds.insert(m.kind());
    }
    assert_eq!(kinds, KINDS.into_iter().collect());
}

// spec/wire.md §11.2: every kind has a rejection of a canonical-form or layout rule, answered 2
// when it is a request and dropped otherwise
#[test]
fn every_kind_has_a_canonical_rejection_spec_wire_11_2() {
    let mut kinds = BTreeSet::new();
    for (name, rule, body) in rejections() {
        let r = Msg::decode(&body).expect_err(name);
        assert_eq!(r.code(), Code::MALFORMED, "{name} ({rule}): {:?}", r.error);
        assert_eq!(r.answered(), !r.read || flow(r.kind).is_none_or(|f| f == Flow::Request), "{name}");
        if let Some((kind, _)) = peek_head(&body) {
            kinds.insert(kind);
        }
    }
    assert_eq!(kinds, KINDS.into_iter().collect(), "a rejection per kind");
}

// spec/wire.md §1 (an array with exactly those positions): a message of every kind takes exactly its layout's
// fields: one more or one fewer is malformed
#[test]
fn exact_arity_spec_wire_11_2() {
    for (name, m) in messages() {
        let Value::List(items) = m.to_value() else { unreachable!() };
        let mut more = items.clone();
        more.push(Value::Int(0));
        let mut fewer = items;
        fewer.pop();
        for v in [more, fewer] {
            assert_eq!(rejected(Value::List(v)).code(), Code::MALFORMED, "{name}");
        }
    }
}

// spec/wire.md §11.1: an id is 0 in a push and nonzero in every request and reply, but an Error
// answering a frame whose id cannot be read; spec/wire.md §11.2: the shared set's and the
// stream's requests and answers (every Fetch) have the top bit set, NoRecord exactly 2^31
#[test]
fn ids_spec_wire_11_1() {
    for (name, m) in messages() {
        let (kind, id) = (m.kind(), m.id());
        match flow(kind) {
            Some(Flow::Push) => assert_eq!(id, 0, "{name}"),
            Some(_) if kind == 0 => {}
            Some(_) => assert_ne!(id, 0, "{name}"),
            None => panic!("{name}"),
        }
        assert_eq!(top_bit_kind(kind), matches!(kind, 19 | 20 | 36..=42));
        if top_bit_kind(kind) {
            assert_ne!(id & crate::limits::TOP_BIT, 0, "{name}");
        }
    }
    let r = rejected(Value::List(vec![Value::Int(2), Value::Int(0), Value::Int(1)]));
    assert_eq!((r.error.clone(), r.answered()), (Error::Malformed("id"), true), "a request is answered");
    let r = rejected(Value::List(vec![Value::Int(1), Value::Int(0)]));
    assert_eq!((r.error.clone(), r.answered()), (Error::Malformed("id"), false), "a reply is dropped");
    let r = rejected(Value::List(vec![Value::Int(2), Value::Int(1 << 32), Value::Int(0)]));
    assert_eq!((r.id, r.code(), r.answered()), (0, Code::MALFORMED, true), "an id that cannot be read: answered with 0");
    let r = Msg::decode(&[0x9f, 0x02, 0x01, 0x00, 0xff]).expect_err("indefinite");
    assert_eq!((r.id, r.answered()), (0, true), "nor can one in a body that is not canonical CBOR");
    let r = Msg::decode(&[0x83, 0x02, 0x18, 0x05, 0x00]).expect_err("non-canonical");
    assert_eq!((r.kind, r.id, r.answered()), (2, 5, true), "a request whose head reads is answered with its id");
    let r = Msg::decode(&[0x82, 0x01, 0x18, 0x05]).expect_err("non-canonical");
    assert_eq!((r.kind, r.id, r.answered()), (1, 5, false), "a reply whose head reads is dropped");
    assert!(Msg::decode(&enc(Value::List(vec![Value::Int(0), Value::Int(0), Value::Int(2)]))).is_ok());
}

// spec/wire.md §11.2: a kind version 1 does not name, a retired one included, is unknown: a
// request of it is answered Error 11 with its id
#[test]
fn unknown_and_retired_kinds_spec_wire_11_2() {
    for kind in RETIRED.into_iter().chain([47, 99, 1 << 40]) {
        for n in 2..=8 {
            let mut items = vec![Value::uint(kind), Value::Int(7)];
            items.resize(n, Value::Int(0));
            let r = rejected(Value::List(items));
            assert_eq!((r.id, r.code(), r.error.clone(), r.answered()), (7, Code::UNSUPPORTED, Error::UnknownKind(kind), true), "kind {kind}");
        }
        assert_eq!(flow(kind), None);
        assert!(!KINDS.contains(&kind));
    }
}

/// `m`'s encoding with the list at position `pos` (or at field `inner.1` of its item `inner.0`)
/// holding `n` copies of its first element.
fn grown(m: &Msg, pos: usize, inner: Option<(usize, usize)>, n: usize) -> Value {
    let Value::List(mut items) = m.to_value() else { unreachable!() };
    let mut l = &mut items[pos];
    if let Some((at, i)) = inner {
        let Value::List(outer) = l else { unreachable!() };
        let Value::List(item) = &mut outer[at] else { unreachable!() };
        l = &mut item[i];
    }
    let Value::List(l) = l else { unreachable!() };
    let first = l[0].clone();
    *l = vec![first; n];
    Value::List(items)
}

// spec/wire.md §11.2 (per-message caps): Offer, Lost, Digest, Prove, Resume: every list cap
// takes its cap and refuses one more
#[test]
fn list_caps_spec_wire_11_2() {
    use crate::limits::*;
    let ms: std::collections::BTreeMap<_, _> = messages().into_iter().collect();
    type Case<'a> = (&'a str, usize, Option<(usize, usize)>, usize);
    let cases: [Case; 11] = [
        ("delete", 3, None, MAX_DELETE_ITEMS),
        ("status", 2, None, MAX_DELETE_ITEMS),
        ("fetch", 4, None, MAX_FETCH_IDS),
        ("fetch reply", 2, None, MAX_FETCH_IDS),
        ("offer", 2, None, MAX_OFFER_ITEMS),
        ("offer", 2, Some((2, 2)), MAX_ITEM_HITS),
        ("lost", 2, None, MAX_OFFER_ITEMS),
        ("shared", 2, None, MAX_OFFER_ITEMS),
        ("members", 2, None, MAX_MEMBERS),
        ("prove", 2, None, MAX_PROOFS),
        ("resume", 3, None, MAX_RESUME_TAGS),
    ];
    for (name, pos, inner, cap) in cases {
        let m = &ms[name];
        let at = enc(grown(m, pos, inner, cap));
        assert!(at.len() <= MAX_MESSAGE, "{name}: {} bytes at its cap", at.len());
        assert!(Msg::decode(&at).is_ok(), "{name} at its cap");
        // past the cap: refused as over it, or (Resume, whose cap fills a message) as too large
        assert_eq!(rejected(grown(m, pos, inner, cap + 1)).code(), Code::MALFORMED, "{name} past its cap");
    }
}

// spec/wire.md §11.2 Prove: at most `MAX_ROTATIONS` rotations, each a header-only copy
#[test]
fn prove_rotations_cap_spec_wire_11_2() {
    let prove = |n: usize| Msg::Prove { id: 32, proofs: vec![], rotations: Some(vec![crate::examples::rotation(); n]) };
    let at = prove(crate::limits::MAX_ROTATIONS);
    assert_eq!(Msg::decode(&at.encode()), Ok(at));
    assert_eq!(rejected(prove(crate::limits::MAX_ROTATIONS + 1).to_value()).error, Error::Cap("rotations"));
}

// spec/wire.md §11.2 (Offer: a Deposit item's blob at most `MAX_BLOB`; Pull: a cursor at most
// 256 bytes); spec/wire.md §13 (blob `MAX_BLOB`)
#[test]
fn byte_caps_spec_wire_13() {
    let m = messages().into_iter().find(|(n, _)| *n == "offer with a deposit").unwrap().1;
    let Msg::Offer { id, mut items } = m else { unreachable!() };
    let OfferItem::Deposit(d) = &mut items[0] else { unreachable!() };
    d.blob = vec![0; crate::limits::MAX_BLOB];
    let at = Msg::Offer { id, items: items.clone() };
    assert!(Msg::decode(&at.encode()).is_ok());
    let OfferItem::Deposit(d) = &mut items[0] else { unreachable!() };
    d.blob.push(0);
    assert!(matches!(Msg::decode(&Msg::Offer { id, items }.encode()).unwrap_err().error, Error::Cap(_)));
    assert!(Cursor::new(vec![0; 256]).is_ok());
    assert_eq!(Cursor::new(vec![0; 257]), Err(Error::Cap("cursor")));
}

// spec/wire.md §11.2 (Pull): `stream_event_len` is the exact size of an event in a reply, so a
// server pages by it
#[test]
fn stream_event_len_is_exact_spec_wire_11_2() {
    for (name, m) in messages() {
        let events = match m {
            Msg::PullReply(r) => r.events,
            Msg::Stream(s) => s.events,
            _ => continue,
        };
        for (s, e) in events {
            let v = Value::List(vec![Value::bytes(&s.0), event_value(&e)]);
            assert_eq!(stream_event_len(&e), enc(v).len(), "{name}: {e:?}");
        }
    }
    let big = Event::Refused(BlobId([1; 32]), Code(u64::MAX));
    assert_eq!(stream_event_len(&big), enc(Value::List(vec![Value::bytes(&[0; 16]), event_value(&big)])).len());
}

// spec/wire.md §11.1: the kind and id of a frame still arriving
#[test]
fn peek_head_reads_a_partial_frame_spec_wire_11_1() {
    for (name, m) in messages() {
        let body = m.encode();
        assert_eq!(peek_head(&body[..body.len().min(12)]), Some((m.kind(), m.id())), "{name}");
    }
    assert_eq!(peek_head(&[0x83, 0x02]), None);
}

proptest! {
    // spec/wire.md §13: decoders never panic on arbitrary or mutated bytes, and whatever decodes
    // is canonical: it re-encodes to the bytes it came from
    #[test]
    fn decode_never_panics_and_accepts_only_canonical_spec_wire_13(bytes in proptest::collection::vec(any::<u8>(), 0..200), which in any::<usize>(), pos in any::<usize>(), byte in any::<u8>()) {
        if let Ok(m) = Msg::decode(&bytes) {
            prop_assert_eq!(m.encode(), bytes);
        }
        let ms = messages();
        let mut enc = ms[which % ms.len()].1.encode();
        let p = pos % enc.len();
        enc[p] = byte;
        if let Ok(m) = Msg::decode(&enc) {
            prop_assert_eq!(m.encode(), enc);
        }
    }
}

// spec/wire.md §13 (a message at most 2^20 CBOR data items): a frame of one-byte items is
// refused before its value tree is built, while a frame densely full of valid events decodes
#[test]
fn item_cap_spec_wire_13() {
    let n = MAX_MESSAGE - 16;
    let mut body = vec![0x83, 0x0b, 0x01, 0x9a];
    body.extend_from_slice(&(n as u32).to_be_bytes());
    body.extend(std::iter::repeat_n(0u8, n));
    assert_eq!(Msg::decode(&body).expect_err("decoded").error, Error::Cap("message items"));
    let deleted = (SyncId([0xdd; 16]), Event::Deleted(BlobId([0xee; 32])));
    let k = (MAX_MESSAGE - 300) / stream_event_len(&deleted.1);
    let m = Msg::PullReply(Box::new(PullReply { id: crate::limits::TOP_BIT | 1, events: vec![deleted; k], cursor: Some(Cursor::new(vec![1; 72]).unwrap()), whole: false, trimmed: false, more: true, report: false, joins: vec![] }));
    let body = m.encode();
    assert!(body.len() <= MAX_MESSAGE && body.len() + 400 > MAX_MESSAGE, "{}", body.len());
    assert_eq!(Msg::decode(&body), Ok(m));
}

// spec/wire.md §11.1 (`id` is 0 in a push): a request's or reply's id can be set; a push keeps 0
#[test]
fn set_id_spec_wire_11_1() {
    for (name, mut m) in messages() {
        m.set_id(9);
        assert_eq!(m.id(), if m.flow() == Flow::Push { 0 } else { 9 }, "{name}");
    }
}

// spec/wire.md §11.2: each request kind's answer kinds, an Error answering any
#[test]
fn answers_spec_wire_11_2() {
    let pairs = [(2, 3), (7, 1), (14, 11), (19, 20), (24, 26), (25, 26), (27, 26), (28, 1), (30, 1), (31, 1), (32, 33), (34, 35), (36, 39), (37, 39), (38, 39), (40, 39), (41, 42)];
    for req in KINDS.into_iter().filter(|k| flow(*k) == Some(Flow::Request)) {
        assert!(answers(req, 0), "{req}");
        for rep in KINDS.into_iter().filter(|k| *k != 0 && flow(*k) == Some(Flow::Reply)) {
            assert_eq!(answers(req, rep), pairs.contains(&(req, rep)), "{req} {rep}");
        }
    }
}

//! spec/wire.md §11.2, §13: message layouts, caps, rejections.

use super::*;
use crate::examples::messages;
use proptest::prelude::*;

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

// spec/wire.md §11.2: every kind round trips
#[test]
fn round_trip_every_kind() {
    let ms = messages();
    let mut kinds: Vec<u64> = ms.iter().map(|(_, m)| m.kind()).collect();
    kinds.dedup();
    // kind 24 (the old signal) is retired
    assert_eq!(kinds, (0..=23).collect::<Vec<_>>());
    for (name, m) in ms {
        assert_eq!(Message::decode(&m.encode()), Ok(m.clone()), "{name}");
    }
}

// spec/wire.md §11.2: per-message caps
#[test]
fn caps() {
    let ms: std::collections::BTreeMap<_, _> = messages().into_iter().collect();
    let m = |n: &str| ms[n].clone();
    for (name, cap) in [("upload", MAX_ITEMS), ("delete", MAX_ITEMS), ("fetch", MAX_ITEMS), ("subscribe", MAX_LABELS), ("unsubscribe", MAX_LABELS), ("path reply", MAX_PATH_STEPS), ("fetch reply", MAX_ITEMS)] {
        assert!(Message::decode(&enc(with_list(m(name), cap))).is_ok(), "{name} at cap");
        assert_eq!(rejected(with_list(m(name), cap + 1)).error, Error::Cap(match name {
            "upload" => "upload entries",
            "delete" => "delete items",
            "fetch" => "fetch ids",
            "path reply" => "path steps",
            "fetch reply" => "fetch items",
            _ => "labels",
        }), "{name}");
    }
    // gained and want: 4096
    let sync = |n: usize| Message::Sync { id: 1, label: LabelId([0; 16]), cursor: None, inline_limit: 0, entries: vec![], gained: vec![BlobId([0; 32]); n] };
    assert!(Message::decode(&sync(MAX_GAINED).encode()).is_ok());
    assert_eq!(Message::decode(&sync(MAX_GAINED + 1).encode()).unwrap_err().error, Error::Cap("gained"));
    let want = |n: usize| Message::SyncReply { id: 1, events: vec![], want: vec![BlobId([0; 32]); n], codes: vec![], cursor: Cursor { log_id: [0; 16], seq: 0 }, more: false };
    assert!(Message::decode(&want(MAX_GAINED + 1).encode()).is_err());
    // Upload, Delete, Fetch, Subscribe need at least one item
    for name in ["upload", "delete", "fetch", "subscribe", "reconcile"] {
        assert!(Message::decode(&enc(with_list(m(name), 0))).is_err(), "{name} empty");
    }
}

fn fp_range(lo: u8, hi: u8) -> Range {
    Range { lower: Bound::new(vec![lo]).unwrap(), upper: Bound::new(vec![hi]).unwrap(), mode: Mode::Fingerprint([0; 16]) }
}

// spec/wire.md §11.2, §11.3: Reconcile 256 ranges, reply 4096; sorted disjoint; mode list sizes
#[test]
fn reconcile_rules() {
    let rec = |ranges: Vec<Range>| Message::Reconcile { id: 1, label: LabelId([0; 16]), ranges }.encode();
    let reply = |ranges: Vec<Range>| Message::ReconcileReply { id: 1, ranges }.encode();
    let many = |n: usize| (0..n).map(|i| Range { lower: Bound::new((i as u16).to_be_bytes().to_vec()).unwrap(), upper: Bound::new((i as u16 + 1).to_be_bytes().to_vec()).unwrap(), mode: Mode::Fingerprint([0; 16]) }).collect::<Vec<_>>();
    assert!(Message::decode(&rec(many(256))).is_ok());
    assert_eq!(Message::decode(&rec(many(257))).unwrap_err().error, Error::Cap("ranges"));
    assert!(Message::decode(&reply(many(4096))).is_ok());
    assert!(Message::decode(&reply(many(4097))).is_err());
    // overlap, unsorted, empty range
    assert!(Message::decode(&rec(vec![fp_range(1, 3), fp_range(2, 4)])).is_err());
    assert!(Message::decode(&rec(vec![fp_range(3, 4), fp_range(1, 2)])).is_err());
    assert!(Message::decode(&rec(vec![fp_range(1, 3), fp_range(3, 4)])).is_ok());
    assert!(Message::decode(&rec(vec![fp_range(2, 2)])).is_err());
    // `[1]` and `[1, 0]` are the same bound
    let r = Range { lower: Bound::new(vec![1]).unwrap(), upper: Bound::new(vec![1, 0]).unwrap(), mode: Mode::Fingerprint([0; 16]) };
    assert!(Message::decode(&rec(vec![r])).is_err());
    // an end upper bound must be last
    let end = Range { lower: Bound::empty(), upper: Bound::empty(), mode: Mode::Fingerprint([0; 16]) };
    assert!(Message::decode(&rec(vec![end.clone()])).is_ok());
    assert!(Message::decode(&rec(vec![end, fp_range(5, 6)])).is_err());
    // bound over 32 bytes
    let Value::List(mut v) = Message::Reconcile { id: 1, label: LabelId([0; 16]), ranges: vec![fp_range(1, 2)] }.to_value() else { unreachable!() };
    v[3] = Value::List(vec![Value::List(vec![Value::Bytes(vec![0; 33]), Value::Bytes(vec![]), Value::List(vec![Value::Int(0), Value::Bytes(vec![0; 16])])])]);
    assert!(Message::decode(&enc(Value::List(v))).is_err());
    // mode 1 at most 32 IDs, sorted, inside the range; mode 2 lists 1024 and 32
    let ids = |n: usize| (0..n).map(|i| { let mut b = [0u8; 32]; b[..8].copy_from_slice(&(i as u64).to_be_bytes()); BlobId(b) }).collect::<Vec<_>>();
    let whole = |mode| Range { lower: Bound::empty(), upper: Bound::empty(), mode };
    assert!(Message::decode(&rec(vec![whole(Mode::Ids(ids(32)))])).is_ok());
    assert!(Message::decode(&rec(vec![whole(Mode::Ids(ids(33)))])).is_err());
    let mut rev = ids(3);
    rev.reverse();
    assert!(Message::decode(&rec(vec![whole(Mode::Ids(rev))])).is_err());
    assert!(Message::decode(&rec(vec![Range { lower: Bound::new(vec![1]).unwrap(), upper: Bound::empty(), mode: Mode::Ids(ids(1)) }])).is_err());
    assert!(Message::decode(&reply(vec![whole(Mode::Diff { theirs: ids(1024), lacking: ids(32) })])).is_ok());
    assert!(Message::decode(&reply(vec![whole(Mode::Diff { theirs: ids(1025), lacking: vec![] })])).is_err());
    assert!(Message::decode(&reply(vec![whole(Mode::Diff { theirs: vec![], lacking: ids(33) })])).is_err());
}

// spec/wire.md §11.1: [kind, id, ...] with id < 2^32; unknown kind answered by 11; Push carries id 0
#[test]
fn heads() {
    let r = rejected(Value::List(vec![Value::Int(99), Value::Int(7)]));
    assert_eq!((r.id, r.code()), (7, Code::UNSUPPORTED));
    // id 0 only on Error and Push; kind 24 is retired
    assert_eq!(rejected(Value::List(vec![Value::Int(24), Value::Int(0)])).code(), Code::UNSUPPORTED);
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
    let Value::List(mut push) = messages().into_iter().find(|(n, _)| *n == "push").unwrap().1.to_value() else { unreachable!() };
    push[1] = Value::Int(5);
    assert!(Message::decode(&enc(Value::List(push))).is_err());
}

// spec/wire.md §11.2: wrap 49 bytes, sig 64, label 16; blob at most MAX_BLOB
// spec/sync.md §5 (upload refusals): an oversized blob does not decode
#[test]
fn field_sizes() {
    let Value::List(dep) = messages().into_iter().find(|(n, _)| *n == "deposit").unwrap().1.to_value() else { unreachable!() };
    for (pos, len) in [(2, 15), (4, 48), (5, 63)] {
        let mut d = dep.clone();
        d[pos] = Value::Bytes(vec![0; len]);
        assert!(Message::decode(&enc(Value::List(d))).is_err(), "pos {pos}");
    }
    let mut d = dep.clone();
    d[3] = Value::Bytes(vec![0; MAX_BLOB + 1]);
    assert_eq!(rejected(Value::List(d)).error, Error::Cap("message"));
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

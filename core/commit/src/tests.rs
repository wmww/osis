//! Unit tests (spec/wire.md §4, spec/commits.md).

use crate::*;
use osis_base::{Ak, CommitId, SchemaId, Tid, Ts, Value, WallMs};
use osis_crypto::{Secret32, SigningSecret};
use osis_schema::{Bound, PurgeBy, Retention};

pub(crate) fn t(n: u8) -> Tid {
    Tid::from_bytes([n; 15])
}

pub(crate) fn ts(wall: u64) -> Ts {
    Ts::make(WallMs(wall), 0).unwrap()
}

/// A valid delete key at `level` from secret `[b; 32]`.
pub(crate) fn dkey(level: u8, b: u8) -> DeleteKey {
    DeleteKey::new(level, &osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([b; 32])).verifying_key())
}

pub(crate) fn sample_header() -> Header {
    Header {
        version: 1,
        author: t(1),
        actor: t(2),
        kind: Kind::Content,
        ts: ts(1_000_000),
        form: Form::Node,
        schemas: vec![(SchemaId([7; 16]), 3)],
        aspects: vec![AspectEntry {
            tid: t(3),
            ak: Ak::new("/app/title").unwrap(),
            lo: 1,
            hi: 2,
            retention: Retention { by: PurgeBy::Author, at_least: Bound { abs: None, rel: Some(5) }, at_most: Bound::default() },
            expires: Some(2_000_000),
            schema: Some(0),
            keys: vec![0, 1],
            hashes: vec![[9; 32]],
        }],
        chunks: vec![],
        purge: vec![],
        undoes: Some(CommitId([4; 32])),
        blind: [5; 16],
        keys: vec![dkey(1, 1), dkey(2, 2)],
        frontier: None,
        origins: vec![],
        links: Links::default(),
    }
}

// spec/wire.md §4: the header round-trips through its canonical bytes; the commit ID is
// BLAKE3 of them.
#[test]
fn header_round_trip() {
    let h = sample_header();
    let b = h.encode();
    assert_eq!(Header::decode(&b).unwrap(), h);
    assert_eq!(h.id().0, osis_base::hash::hash(&b));
}

// spec/wire.md §4: a stored header (verified on arrival) reads back as `from_value` reads it,
// without the delete keys' point checks
#[test]
fn stored_header_reads_alike_spec_wire_4() {
    let h = sample_header();
    let v = h.to_value();
    assert_eq!(Header::from_stored_value(&v).unwrap(), Header::from_value(&v).unwrap());
    assert_eq!(Header::from_stored_value(&v).unwrap(), h);
}

// spec/wire.md §4: a field change changes the commit ID.
#[test]
fn id_covers_fields() {
    let h = sample_header();
    let mut h2 = h.clone();
    h2.keys[0] = dkey(1, 3);
    assert_ne!(h.id(), h2.id());
    let mut h2 = h.clone();
    h2.blind[0] ^= 1;
    assert_ne!(h.id(), h2.id());
}

// spec/crypto.md §2: the signature is over the commit ID under the commit domain.
#[test]
fn sign_verify() {
    let h = sample_header();
    let k = SigningSecret::from_seed(&Secret32::from_bytes([3; 32]));
    let sig = h.sign(&k);
    verify_signature(&h.id(), &sig, &k.verifying_key()).unwrap();
    let mut h2 = h.clone();
    h2.ts = ts(1_000_001);
    assert!(matches!(verify_signature(&h2.id(), &sig, &k.verifying_key()), Err(Error::BadSignature)));
}

// spec/versioning.md §2: an unknown (higher) format version parks; version 0 is malformed.
// spec/versioning.md §2 (park unknown), §2 (reject malformed)
#[test]
fn version_parks() {
    use osis_base::{Classified, ErrorClass};
    let mut v = sample_header().to_value();
    if let Value::List(items) = &mut v {
        items[0] = Value::Int(2);
        items.push(Value::Int(0));
    }
    let e = Header::decode(&osis_base::encode(&v)).unwrap_err();
    assert!(matches!(e, Error::UnknownVersion(2)));
    assert_eq!(e.class(), ErrorClass::Parked);
    let mut h = sample_header();
    h.version = 0;
    assert!(matches!(Header::decode(&h.encode()), Err(Error::Malformed(_))));
}

// spec/wire.md §1, §4: wrong arity, wrong types and out-of-range items are rejected.
// spec/versioning.md §2 (reject malformed)
#[test]
fn header_rejects_malformed() {
    let good = sample_header().to_value();
    let Value::List(items) = good else { unreachable!() };
    let mutate = |i: usize, x: Value| {
        let mut it = items.clone();
        it[i] = x;
        Header::decode(&osis_base::encode(&Value::List(it))).unwrap_err()
    };
    assert!(matches!(mutate(1, Value::Bytes(vec![0; 14])), Error::Malformed(_)));
    assert!(matches!(mutate(3, Value::Int(6)), Error::Malformed(_)));
    assert!(matches!(mutate(5, Value::Int(2)), Error::Malformed(_)));
    assert!(matches!(mutate(10, Value::List(vec![Value::Int(1), Value::Int(2)])), Error::Malformed(_)));
    assert!(matches!(mutate(11, Value::Bytes(vec![0; 15])), Error::Malformed(_)));
    assert!(matches!(mutate(12, Value::List(vec![Value::List(vec![Value::Int(4), Value::Bytes(dkey(1, 1).key.to_vec())])])), Error::Malformed(_)));
    // a delete key of the wrong length, or not a valid point
    assert!(matches!(mutate(12, Value::List(vec![Value::List(vec![Value::Int(1), Value::Bytes(vec![0; 16])])])), Error::Malformed(_)));
    assert!(matches!(mutate(12, Value::List(vec![Value::List(vec![Value::Int(1), Value::Bytes(vec![0; 32])])])), Error::Malformed(_)));
    let mut short = items.clone();
    short.pop();
    assert!(Header::decode(&osis_base::encode(&Value::List(short))).is_err());
    // an aspect without hashes
    let mut h = sample_header();
    h.aspects[0].hashes.clear();
    assert!(matches!(Header::decode(&h.encode()), Err(Error::Malformed(_))));
}

//! Unit tests (spec/wire.md §4, spec/commits.md): header round trips here, one module per area.

mod build;
mod paths;
mod prop;
mod review;
mod validate;
mod verify;

use crate::*;
use osis_base::{Ak, CommitId, Tid, Ts, Value, WallMs};
use osis_crypto::{Secret32, SigningSecret};
use osis_schema::{PurgeBy};

pub(crate) fn t(n: u8) -> Tid {
    Tid::from_bytes([n; 15])
}

pub(crate) fn ts(wall: u64) -> Ts {
    Ts::make(WallMs(wall), 0).unwrap()
}

/// A valid delete key at `level` from secret `[b; 32]`.
pub(crate) fn dkey(level: u8, b: u8) -> DeleteKey {
    DeleteKey::new(level, &osis_crypto::DeleteSecret::write(&Secret32::from_bytes([b; 32])).verifying_key())
}

/// The test signer's session nonce (spec/crdt.md §2.1).
pub(crate) const NONCE: [u8; 16] = [0x5e; 16];
pub(crate) const SESSION: Form = Form::Session(NONCE);

pub(crate) fn sample_header() -> Header {
    Header {
        signer: t(1),
        key: None,
        path: Paths::One(Path::through(t(2))),
        kind: Kind::Content,
        ts: ts(1_000_000),
        form: SESSION,
        expires: Some(2_000_000),
        aspects: vec![AspectEntry {
            tid: t(3),
            ak: Ak::new("app:title.0").unwrap(),
            lo: 1,
            hi: 2,
            purge_by: PurgeBy::AuthorOrAdmin,
            keys: vec![0, 1],
            hash: [9; 32],
            replaces: Some(CommitId([8; 32])),
            original_floor: 3,
        }],
        purge: vec![],
        undoes: Some(CommitId([4; 32])),
        blind: [5; 16],
        keys: vec![dkey(1, 1), dkey(2, 2)],
        frontier: None,
        links: Links::default(),
        ephemeral: None,
        own_cover: false,
        adminless: false,
    }
}

// spec/wire.md §4: a stored header (verified on arrival) reads back as `decode` reads it,
// without the delete keys' point checks
#[test]
fn stored_header_reads_alike_spec_wire_4() {
    let h = sample_header();
    let b = h.encode();
    assert_eq!(Header::decode_stored(&b).unwrap(), Header::decode(&b).unwrap());
    assert_eq!(Header::decode_stored(&b).unwrap(), h);
}

// spec/wire.md §4 field 1: `[tid, signing_key]` names the signing key; it round-trips, is in the
// commit ID, and anything else in that place (another arity, a key of another case or length)
// is malformed
#[test]
fn second_signer_form_round_trips_spec_wire_4() {
    let h = Header { key: Some(osis_base::SignKey([7; 32])), ..sample_header() };
    let b = h.encode();
    assert_eq!(Header::decode(&b).unwrap(), h);
    assert_ne!(h.id(), sample_header().id());
    let Value::List(items) = header_value(&h) else { unreachable!() };
    let Value::List(signer) = &items[1] else { unreachable!("the second form is an array") };
    let mutate = |x: Value| {
        let mut it = items.clone();
        it[1] = x;
        Header::decode(&osis_base::encode(&Value::List(it))).unwrap_err()
    };
    let key = |case: u64, n: usize| Value::Enum(case, Some(Box::new(Value::Bytes(vec![7; n]))));
    for bad in [vec![signer[0].clone()], vec![signer[0].clone(), key(1, 32), key(1, 32)], vec![signer[0].clone(), key(2, 32)], vec![signer[0].clone(), key(1, 31)], vec![signer[0].clone(), Value::Bytes(vec![7; 32])]] {
        assert!(matches!(mutate(Value::List(bad)), Error::Malformed(_)));
    }
}

/// A header's value tree, to edit into malformed headers.
pub(crate) fn header_value(h: &Header) -> Value {
    osis_base::decode(&h.encode(), &osis_base::Limits::DEFAULT).unwrap()
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
    let sigs = crate::Sigs::signed(&h.id(), &k);
    verify_signature(&h.id(), &sigs, &k.verifying_key()).unwrap();
    let mut h2 = h.clone();
    h2.ts = ts(1_000_001);
    assert!(matches!(verify_signature(&h2.id(), &sigs, &k.verifying_key()), Err(Error::BadSignature)));
}

// spec/versioning.md §2: an unknown (higher) format version parks; version 0 is malformed.
// spec/versioning.md §2 (park unknown), §2 (reject malformed)
#[test]
fn version_parks() {
    use osis_base::{Classified, ErrorClass};
    let mut v = header_value(&sample_header());
    if let Value::List(items) = &mut v {
        items[0] = Value::Int(2);
        items.push(Value::Int(0));
    }
    let e = Header::decode(&osis_base::encode(&v)).unwrap_err();
    assert!(matches!(e, Error::UnknownVersion(2)));
    assert_eq!(e.class(), ErrorClass::Parked);
    let mut v = header_value(&sample_header());
    if let Value::List(items) = &mut v {
        items[0] = Value::Int(0);
    }
    assert!(matches!(Header::decode(&osis_base::encode(&v)), Err(Error::Malformed(_))));
}

// spec/wire.md §1, §4: wrong arity, wrong types and out-of-range items are rejected.
// spec/versioning.md §2 (reject malformed)
#[test]
fn header_rejects_malformed() {
    let good = header_value(&sample_header());
    let Value::List(items) = good else { unreachable!() };
    let mutate = |i: usize, x: Value| {
        let mut it = items.clone();
        it[i] = x;
        Header::decode(&osis_base::encode(&Value::List(it))).unwrap_err()
    };
    assert!(matches!(mutate(1, Value::Bytes(vec![0; 14])), Error::Malformed(_)));
    assert!(matches!(mutate(3, Value::Int(6)), Error::Malformed(_)));
    assert!(matches!(mutate(5, Value::Int(2)), Error::Malformed(_)));
    assert!(matches!(mutate(6, Value::List(vec![Value::Int(1), Value::Int(2)])), Error::Malformed(_)));
    assert!(matches!(mutate(9, Value::List(vec![Value::Int(1), Value::Int(2)])), Error::Malformed(_)));
    assert!(matches!(mutate(10, Value::Bytes(vec![0; 15])), Error::Malformed(_)));
    assert!(matches!(mutate(11, Value::List(vec![Value::List(vec![Value::Int(4), Value::Bytes(dkey(1, 1).key.to_vec())])])), Error::Malformed(_)));
    // a delete key of the wrong length, or not a valid point
    assert!(matches!(mutate(11, Value::List(vec![Value::List(vec![Value::Int(1), Value::Bytes(vec![0; 16])])])), Error::Malformed(_)));
    assert!(matches!(mutate(11, Value::List(vec![Value::List(vec![Value::Int(1), Value::Bytes(vec![0; 32])])])), Error::Malformed(_)));
    let mut short = items.clone();
    short.pop();
    assert!(Header::decode(&osis_base::encode(&Value::List(short))).is_err());
    // an aspect's delta hash: one 32-byte string
    let Value::List(aspects) = &items[7] else { unreachable!() };
    let Value::List(aspect) = &aspects[0] else { unreachable!() };
    let hash = aspect[6].clone();
    for bad in [Value::Bytes(vec![0; 31]), Value::List(vec![hash])] {
        let mut a = aspect.clone();
        a[6] = bad;
        assert_eq!(osis_base::Classified::class(&mutate(7, Value::List(vec![Value::List(a)]))), osis_base::ErrorClass::BadInput);
    }
}

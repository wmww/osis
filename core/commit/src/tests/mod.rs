//! Unit tests (spec/wire.md §4, spec/commits.md): header round trips here, one module per area.

mod build;
mod prop;
mod review;
mod validate;
mod verify;

use crate::*;
use osis_base::{Ak, CommitId, Tid, Ts, Value, WallMs};
use osis_crypto::{Secret32, Signature, SigningSecret};
use osis_schema::{PurgeBy, Retention};

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

/// The test author's session nonce (spec/crdt.md §2.1).
pub(crate) const NONCE: [u8; 16] = [0x5e; 16];
pub(crate) const SESSION: Form = Form::Session(NONCE);

pub(crate) fn sample_header() -> Header {
    Header {
        version: 1,
        author: t(1),
        actor: t(2),
        kind: Kind::Content,
        ts: ts(1_000_000),
        form: SESSION,
        expires: Some(2_000_000),
        aspects: vec![AspectEntry {
            tid: t(3),
            ak: Ak::new("app:title.0").unwrap(),
            lo: 1,
            hi: 2,
            retention: Retention { by: PurgeBy::AuthorOrAdmin, history: Some(osis_schema::History::Keep { until: None, after: Some(5) }) },
            keys: vec![0, 1],
            hash: [9; 32],
            replaces: Some(CommitId([8; 32])),
        }],
        chunks: vec![],
        purge: vec![],
        undoes: Some(CommitId([4; 32])),
        blind: [5; 16],
        keys: vec![dkey(1, 1), dkey(2, 2)],
        frontier: None,
        links: Links::default(),
        ephemeral: None,
        epoch: None,
        rotation: None,
    }
}

// spec/wire.md §4 fields 15, 16: an account's epoch and a rotation round-trip; a rotation sits
// only on a role commit, supersedes the epoch it is signed at, and keeps its lists ascending.
#[test]
fn rotation_header_spec_wire_4() {
    use crate::header::RotationHeader;
    let keys = osis_crypto::AccountEpochKeys::from_seed(&Secret32::from_bytes([8; 32]));
    let rot = RotationHeader { signing_key: keys.signing.verifying_key(), kem_key: keys.kem.public().clone(), supersedes: vec![crate::FIRST_EPOCH, CommitId([3; 32])], names: vec![CommitId([3; 32])], list_root: [6; 32] };
    let mut h = sample_header();
    h.epoch = Some(crate::FIRST_EPOCH);
    assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    h.rotation = Some(rot.clone());
    assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    assert!(matches!(h.validate(), Err(Error::Invalid(m)) if m.contains("rotation outside a role commit")));
    let mut r = validate::role_header("roles.0");
    r.epoch = Some(crate::FIRST_EPOCH);
    r.rotation = Some(rot.clone());
    assert!(r.validate().is_err(), "writes no keys.0");
    let mut r = validate::role_header("keys.0");
    r.aspects[0].tid = r.author;
    r.actor = r.author;
    r.epoch = Some(crate::FIRST_EPOCH);
    r.rotation = Some(rot.clone());
    r.validate().unwrap();
    let mut x = r.clone();
    x.aspects[0].tid = Tid::from_bytes([0xee; 15]);
    assert!(x.validate().is_err(), "keys.0 of another");
    r.epoch = Some(CommitId([9; 32]));
    assert!(r.validate().is_err(), "signed at an epoch it does not supersede");
    r.epoch = Some(crate::FIRST_EPOCH);
    r.rotation = Some(RotationHeader { supersedes: vec![CommitId([3; 32]), crate::FIRST_EPOCH], ..rot });
    assert!(r.validate().is_err(), "supersedes not ascending");
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
    let sigs = crate::Sigs::signed(&h.id(), &k, None, Vec::new());
    verify_signature(&h.id(), &sigs, &k.verifying_key()).unwrap();
    let mut h2 = h.clone();
    h2.ts = ts(1_000_001);
    assert!(matches!(verify_signature(&h2.id(), &sigs, &k.verifying_key()), Err(Error::BadSignature)));
}

// spec/crypto.md §2: an account's commit signature covers its inner and merge signatures, so a relay swaps neither
#[test]
fn signature_binds_inner_and_merge_spec_crypto_2() {
    let h = sample_header();
    let id = h.id();
    let k = SigningSecret::from_seed(&Secret32::from_bytes([3; 32]));
    let good = crate::Sigs::signed(&id, &k, Some([1; osis_crypto::INNER_LEN]), vec![Signature([2; 64])]);
    verify_signature(&id, &good, &k.verifying_key()).unwrap();
    let mut swapped_inner = good.clone();
    swapped_inner.inner = Some([9; osis_crypto::INNER_LEN]);
    assert!(matches!(verify_signature(&id, &swapped_inner, &k.verifying_key()), Err(Error::BadSignature)));
    let mut swapped_merge = good.clone();
    swapped_merge.merge = vec![Signature([8; 64])];
    assert!(matches!(verify_signature(&id, &swapped_merge, &k.verifying_key()), Err(Error::BadSignature)));
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
    assert!(matches!(mutate(6, Value::List(vec![Value::Int(1), Value::Int(2)])), Error::Malformed(_)));
    assert!(matches!(mutate(10, Value::List(vec![Value::Int(1), Value::Int(2)])), Error::Malformed(_)));
    assert!(matches!(mutate(11, Value::Bytes(vec![0; 15])), Error::Malformed(_)));
    assert!(matches!(mutate(12, Value::List(vec![Value::List(vec![Value::Int(4), Value::Bytes(dkey(1, 1).key.to_vec())])])), Error::Malformed(_)));
    // a delete key of the wrong length, or not a valid point
    assert!(matches!(mutate(12, Value::List(vec![Value::List(vec![Value::Int(1), Value::Bytes(vec![0; 16])])])), Error::Malformed(_)));
    assert!(matches!(mutate(12, Value::List(vec![Value::List(vec![Value::Int(1), Value::Bytes(vec![0; 32])])])), Error::Malformed(_)));
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

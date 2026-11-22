//! Unit tests (spec/wire.md §4, spec/commits.md): header round trips here, one module per area.

mod build;
mod paths;
mod prop;
mod review;
mod validate;
mod verify;

use crate::*;
use osis_base::{Ak, CommitId, Tid, Ts, Value, WallMs};
use osis_crypto::{Secret32, Signature, SigningSecret};
use osis_schema::{PurgeBy};

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

/// The test signer's session nonce (spec/crdt.md §2.1).
pub(crate) const NONCE: [u8; 16] = [0x5e; 16];
pub(crate) const SESSION: Form = Form::Session(NONCE);

pub(crate) fn sample_header() -> Header {
    Header {
        signer: t(1),
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
        epoch: None,
        rotation: None,
        reseal: None, own_cover: false, adminless: false,
    }
}

// spec/wire.md §4 fields 14, 15: an account's epoch and a rotation round-trip; a rotation sits
// only on a role commit, supersedes the epoch it is signed at, and keeps its lists ascending.
#[test]
fn rotation_header_spec_wire_4() {
    use crate::header::RotationHeader;
    let keys = osis_crypto::AccountEpochKeys::from_seed(&Secret32::from_bytes([8; 32]));
    let rot = RotationHeader { signing_key: keys.signing.verifying_key(), kem_key: keys.kem.public().clone(), supersedes: vec![crate::FIRST_EPOCH, CommitId([3; 32])], names: Vec::new(), takes: vec![CommitId([4; 32])], revokes: true, devices: vec![9; 40], list_root: [6; 32], seeds: Vec::new() };
    let mut h = sample_header();
    h.path = Paths::default();
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
    r.aspects[0].tid = r.signer;
    r.epoch = Some(crate::FIRST_EPOCH);
    r.rotation = Some(rot.clone());
    r.validate().unwrap();
    let mut x = r.clone();
    x.aspects[0].tid = Tid::from_bytes([0xee; 15]);
    assert!(x.validate().is_err(), "keys.0 of another");
    r.epoch = Some(CommitId([9; 32]));
    assert!(r.validate().is_err(), "signed at an epoch it does not supersede");
    r.epoch = Some(crate::FIRST_EPOCH);
    r.rotation = Some(RotationHeader { takes: vec![CommitId([5; 32]), CommitId([4; 32])], ..rot.clone() });
    assert!(r.validate().is_err(), "takes not ascending");
    r.rotation = Some(RotationHeader { supersedes: vec![CommitId([3; 32]), crate::FIRST_EPOCH], ..rot.clone() });
    assert!(r.validate().is_err(), "supersedes not ascending");
    // a merge certificate: exactly its tips, nothing else carried; its epoch is not its commit's
    let merge = RotationHeader { names: vec![CommitId([3; 32])], takes: Vec::new(), revokes: false, devices: Vec::new(), ..rot.clone() };
    r.rotation = Some(merge.clone());
    r.validate().unwrap();
    assert_eq!(merge.mints(&CommitId([1; 32])), merge.mints(&CommitId([2; 32])), "every certificate mints one epoch");
    assert_eq!(rot.mints(&CommitId([1; 32])), CommitId([1; 32]));
    for (bad, why) in [
        (RotationHeader { takes: vec![CommitId([4; 32])], ..merge.clone() }, "takes"),
        (RotationHeader { revokes: true, devices: vec![9; 40], ..merge.clone() }, "removes"),
        (RotationHeader { supersedes: vec![crate::FIRST_EPOCH, CommitId([3; 32]), CommitId([5; 32])], ..merge.clone() }, "answers"),
    ] {
        r.rotation = Some(bad);
        assert!(r.validate().is_err(), "a merge carrying {why}");
    }
    r.rotation = Some(rot);
    never_split(r, "a rotation");
}

// spec/wire.md §4 field 16: a seed re-seal round-trips; it sits only on an account's role
// commit that is no rotation, with at least one box, ascending by tag.
#[test]
fn reseal_header_spec_wire_4() {
    use crate::header::{RotationHeader, SeedBox, SeedReseal};
    let keys = osis_crypto::AccountEpochKeys::from_seed(&Secret32::from_bytes([8; 32]));
    let b = |t: u8| SeedBox { tag: [t; 16], sealed: vec![t; osis_crypto::SEALED_OVERHEAD + 32] };
    let rs = SeedReseal { signing_key: keys.signing.verifying_key(), seeds: vec![b(1), b(2)] };
    let mut r = validate::role_header("account.0");
    r.epoch = Some(crate::FIRST_EPOCH);
    r.reseal = Some(rs.clone());
    assert_eq!(Header::decode(&r.encode()).unwrap(), r);
    r.validate().unwrap();
    let mut x = r.clone();
    x.epoch = None;
    assert!(x.validate().is_err(), "no account's");
    let mut x = r.clone();
    x.kind = Kind::Content;
    assert!(x.validate().is_err(), "no role commit");
    let mut x = r.clone();
    x.rotation = Some(RotationHeader { signing_key: keys.signing.verifying_key(), kem_key: keys.kem.public().clone(), supersedes: vec![crate::FIRST_EPOCH], names: vec![], takes: vec![], revokes: false, devices: vec![], list_root: [6; 32], seeds: vec![b(1)] });
    assert!(x.validate().is_err(), "on a rotation");
    let mut x = r.clone();
    x.reseal = Some(SeedReseal { seeds: vec![b(2), b(1)], ..rs.clone() });
    assert!(Header::decode(&x.encode()).is_err(), "boxes not ascending");
    x.reseal = Some(SeedReseal { seeds: vec![], ..rs });
    assert!(Header::decode(&x.encode()).is_err(), "no box");
    never_split(r, "a seed re-seal");
}

/// `r`'s `path`, the one-for-all `[0]`, is never split, whatever else it writes.
fn never_split(mut r: Header, what: &str) {
    let mut other = r.aspects[0].clone();
    other.tid = Tid::from_bytes([0xee; 15]);
    r.aspects.push(other);
    r.validate().unwrap();
    r.path = Paths::Split(crate::Split { author: None, entries: vec![vec![0; crate::entry_len(0).unwrap()]; 2] });
    assert!(matches!(r.validate(), Err(Error::Invalid(m)) if m.contains("split")), "{what} stating the split form");
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
    let sigs = crate::Sigs::signed(&h.id(), &k, None, Vec::new(), Vec::new());
    verify_signature(&h.id(), &sigs, &k.verifying_key()).unwrap();
    let mut h2 = h.clone();
    h2.ts = ts(1_000_001);
    assert!(matches!(verify_signature(&h2.id(), &sigs, &k.verifying_key()), Err(Error::BadSignature)));
}

// spec/crypto.md §2: an account's commit signature covers its inner signature (every seal of it)
// and merge signatures, so a relay swaps none; the seals round-trip in the blob
#[test]
fn signature_binds_inner_and_merge_spec_crypto_2() {
    let h = sample_header();
    let id = h.id();
    let k = SigningSecret::from_seed(&Secret32::from_bytes([3; 32]));
    let good = crate::Sigs::signed(&id, &k, Some([1; osis_crypto::INNER_LEN]), vec![[4; osis_crypto::INNER_LEN]], vec![Signature([2; 64])]);
    verify_signature(&id, &good, &k.verifying_key()).unwrap();
    let mut swapped_inner = good.clone();
    swapped_inner.inner = Some([9; osis_crypto::INNER_LEN]);
    assert!(matches!(verify_signature(&id, &swapped_inner, &k.verifying_key()), Err(Error::BadSignature)));
    let mut swapped_merge = good.clone();
    swapped_merge.merge = vec![Signature([8; 64])];
    assert!(matches!(verify_signature(&id, &swapped_merge, &k.verifying_key()), Err(Error::BadSignature)));
    let mut swapped_more = good.clone();
    swapped_more.more = vec![[5; osis_crypto::INNER_LEN]];
    assert!(matches!(verify_signature(&id, &swapped_more, &k.verifying_key()), Err(Error::BadSignature)));
    let blob = crate::CommitBlob { header: h, sigs: good.clone(), parts: Vec::new(), keys: Default::default() };
    assert_eq!(crate::CommitBlob::decode(&blob.encode()).unwrap().sigs, good);
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

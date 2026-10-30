//! Delete keys, commit blobs, delta verification (spec/crypto.md §7, spec/wire.md §4, spec/commits.md §4).

use crate::tests::{sample_header, t, ts};
use crate::*;
use osis_base::{Classified, ErrorClass, Tid, Ts, Value};
use osis_crdt::{AnyView, Delta, Interner, Source, Writer, create, encode_delta};
use osis_crypto::{DeleteSecret, Secret32, SigningSecret, VerifyingKey, delta_hash};
use osis_schema::{PurgeBy, Retention};

pub(crate) struct TestSecrets {
    pub admin: bool,
}

pub(crate) fn sec(tag: u8, tid: &Tid) -> Secret32 {
    let mut b = [tag; 32];
    b[..15].copy_from_slice(tid.as_bytes());
    Secret32::from_bytes(b)
}

impl Secrets for TestSecrets {
    fn dedup(&self, tid: &Tid) -> Option<Secret32> {
        Some(sec(0xd0, tid))
    }
    fn admin_key(&self, tid: &Tid) -> Option<VerifyingKey> {
        self.admin.then(|| DeleteSecret::derive(&sec(0xa1, tid)).verifying_key())
    }
    fn chain_key(&self) -> Option<VerifyingKey> {
        Some(DeleteSecret::derive(&Secret32::from_bytes([0xc2; 32])).verifying_key())
    }
    fn write_key(&self, tid: &Tid) -> Option<VerifyingKey> {
        Some(DeleteSecret::derive(&sec(0x33, tid)).verifying_key())
    }
}

/// A one-register delta by `author` at `ts`, counter `lo`.
pub(crate) fn register_delta(author: Tid, at: Ts, lo: u64, v: &str) -> Vec<u8> {
    let mut w = Writer::new(at, Source::node(author), lo);
    let fragment = create(&mut w, &AnyView, &Value::Str(v.into())).unwrap();
    let d = Delta { nonce: [lo as u8; 16], fragment };
    encode_delta(&d, &writer_ctx(Kind::Content, at, author, lo, lo + 1), None).unwrap()
}

// spec/crypto.md §7: delete keys by retention level; level 2 omitted for imports; a missing
// key is an error, level 1 included.
#[test]
fn delete_levels_by_retention() {
    let s = TestSecrets { admin: true };
    let lv = |by, kind| delete_keys(&s, &t(3), &Retention { by, ..Default::default() }, kind).unwrap().iter().map(|x| x.level).collect::<Vec<_>>();
    assert_eq!(lv(PurgeBy::Nobody, Kind::Content), Vec::<u8>::new());
    assert_eq!(lv(PurgeBy::Admin, Kind::Content), vec![1]);
    assert_eq!(lv(PurgeBy::Author, Kind::Content), vec![1, 2]);
    assert_eq!(lv(PurgeBy::Writer, Kind::Content), vec![1, 2, 3]);
    assert_eq!(lv(PurgeBy::Writer, Kind::Import), vec![1, 3]);
    assert!(delete_keys(&TestSecrets { admin: false }, &t(3), &Retention::default(), Kind::Content).is_err());
}

/// A valid one-aspect content commit over a register delta, its blob and author key.
pub(crate) fn one_commit() -> (CommitBlob, SigningSecret) {
    let key = SigningSecret::from_seed(&Secret32::from_bytes([0x41; 32]));
    let mut h = sample_header();
    let at = h.ts;
    let delta = register_delta(h.author, at, 1, "hello");
    h.aspects[0].hashes = vec![delta_hash(&sec(0xd0, &h.aspects[0].tid), &delta)];
    let signature = h.sign(&key);
    (CommitBlob { header: h, signature, parts: vec![Part { ai: 0, di: 0, delta }] }, key)
}

// spec/wire.md §4: the commit blob plaintext round-trips; a header-only rewrite is allowed.
#[test]
fn commit_blob_round_trip() {
    let (b, _) = one_commit();
    let bytes = b.encode();
    assert_eq!(CommitBlob::decode(&bytes).unwrap(), b);
    assert!(b.missing().is_empty());
    let mut empty = b.clone();
    empty.parts.clear();
    assert_eq!(CommitBlob::decode(&empty.encode()).unwrap(), empty);
    assert_eq!(empty.missing(), vec![(0, 0)]);
    assert_eq!(empty.id(), b.id());
}

// spec/wire.md §4: parts are sorted and distinct; a non-array delta is malformed.
#[test]
fn commit_blob_rejects() {
    let (mut b, _) = one_commit();
    b.parts.push(b.parts[0].clone());
    assert!(matches!(CommitBlob::decode(&b.encode()), Err(Error::Malformed(_))));
    let (mut b, _) = one_commit();
    b.parts[0].delta = osis_base::encode(&Value::Int(3));
    assert!(matches!(CommitBlob::decode(&b.encode()), Err(Error::Malformed(_))));
}

// spec/commits.md §4: signature, delta hash under the thing's dedup secret, range check.
#[test]
fn verify_deltas() {
    let s = TestSecrets { admin: true };
    let (b, key) = one_commit();
    let dedup = |t: &Tid| s.dedup(t);
    let out = verify_blob(&b, &key.verifying_key(), &dedup, None).unwrap();
    assert!(matches!(out.as_slice(), [Decoded::Delta(_)]));
    // wrong dedup secret: hash mismatch
    let wrong = |_: &Tid| Some(Secret32::from_bytes([0; 32]));
    let e = verify_blob(&b, &key.verifying_key(), &wrong, None).unwrap_err();
    assert!(matches!(e, Error::DeltaHash { ai: 0, di: 0 }));
    // another key
    let other = SigningSecret::from_seed(&Secret32::from_bytes([0x42; 32]));
    assert!(matches!(verify_blob(&b, &other.verifying_key(), &dedup, None), Err(Error::BadSignature)));
    // range check: a delta whose own writes reach above the header range [1, 2)
    let (mut b2, _) = one_commit();
    let (author, at) = (b2.header.author, b2.header.ts);
    let mut w = Writer::new(at, Source::node(author), 1);
    let set = Value::Set([Value::Int(1), Value::Int(2)].into_iter().collect());
    let fragment = create(&mut w, &AnyView, &set).unwrap();
    let r = w.range();
    assert!(r.hi > 2);
    let delta = encode_delta(&Delta { nonce: [5; 16], fragment }, &writer_ctx(Kind::Content, at, author, r.lo, r.hi), None).unwrap();
    b2.header.aspects[0].hashes = vec![delta_hash(&sec(0xd0, &t(3)), &delta)];
    b2.parts[0].delta = delta;
    let mut i = Interner::new();
    let e = verify_part(&b2.header, &b2.id(), &b2.parts[0], &sec(0xd0, &t(3)), &mut i, None).unwrap_err();
    assert!(matches!(e, Error::Delta(_)));
    assert_eq!(e.class(), ErrorClass::BadInput);
    // part index out of range
    let mut p = b.parts[0].clone();
    p.di = 1;
    assert!(matches!(verify_part(&b.header, &b.id(), &p, &sec(0xd0, &t(3)), &mut i, None), Err(Error::Malformed(_))));
    let _ = ts(0);
}

// spec/crdt.md §5.6: a keyed map removal is malformed outside the membership-class aspects; the
// keyless form is fine anywhere
#[test]
fn keyed_map_removal_only_in_membership_aspects_spec_crdt_5_6() {
    let (mut b, _) = one_commit();
    let (author, at) = (b.header.author, b.header.ts);
    let dot = osis_crdt::Dot::new(Source::node(t(9)), 4);
    let w = Writer::new(at, Source::node(author), 1);
    let check = |b: &mut CommitBlob, keyed: bool, ak: &str| {
        let fragment = osis_crdt::reset_entries(&w.clone().keyed_removals(keyed), &[(dot.clone(), Value::Str("a key".into()))]);
        let delta = encode_delta(&Delta { nonce: [5; 16], fragment }, &writer_ctx(Kind::Content, at, author, 1, 2), None).unwrap();
        b.header.aspects[0].ak = osis_base::Ak::new(ak).unwrap();
        b.header.aspects[0].hashes = vec![delta_hash(&sec(0xd0, &t(3)), &delta)];
        b.parts[0].delta = delta;
        verify_part(&b.header, &b.id(), &b.parts[0], &sec(0xd0, &t(3)), &mut Interner::new(), None)
    };
    assert!(matches!(check(&mut b, true, "/x/map"), Err(Error::Malformed(_))));
    assert!(check(&mut b, false, "/x/map").is_ok());
    assert!(check(&mut b, true, "/secrets").is_ok());
    assert!(check(&mut b, true, "/members").is_ok());
}

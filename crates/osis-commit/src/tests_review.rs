//! Regression tests from the osis-commit review (spec/wire.md §4, §6; spec/commits.md §2, §5).

use crate::tests::{sample_header, t, ts};
use crate::tests_build::{content, key, rng};
use crate::tests_validate::membership_header;
use crate::tests_verify::{TestSecrets, register_delta, sec};
use crate::*;
use osis_core::{Ak, Link, Value};
use osis_crypto::{link_hash, link_tree_hash};
use osis_schema::{AspectDefaults, PurgeBy, Retention};

// spec/wire.md §6: repeated links are legal (identical chunks share a blob), so the reader is
// bounded instead: a non-final chunk below CHUNK_MIN is bad input and the chunks visited are
// capped by the caller's output bound.
#[test]
fn tree_reader_bounded() {
    use osis_core::format::CHUNK_MIN;
    let d = sec(0xd0, &t(2));
    let mut m = MemoryBlobs::default();
    let none = Prefix { salt: [0; 16], expiry: None, commitments: vec![] };
    let chunk = vec![0u8; CHUNK_MIN];
    let (cid, _) = m.put(&none, &chunk).unwrap();
    let cl = Link { hash: link_hash(&d, &chunk), blob: cid, suite: 1, key: [0; 32] };
    let plain = osis_core::encode(&Value::List(vec![Value::Int(1), Value::List(vec![Value::Link(cl); 4])]));
    let (nid, _) = m.put(&Prefix { salt: [1; 16], ..none.clone() }, &plain).unwrap();
    let root = Link { hash: link_tree_hash(&d, 1, &[cl.hash; 4]), blob: nid, suite: 1, key: [0; 32] };
    assert_eq!(read_tree(&root, &d, &mut m, MAX_LIST_BYTES).unwrap().len(), 4 * CHUNK_MIN);
    assert!(matches!(read_tree(&root, &d, &mut m, 3 * CHUNK_MIN), Err(Error::TooLarge(_))));
    // a level 2 node repeating that level 1 node 512 times stops at the bound
    let plain2 = osis_core::encode(&Value::List(vec![Value::Int(2), Value::List(vec![Value::Link(root); 512])]));
    let (n2, _) = m.put(&Prefix { salt: [2; 16], ..none }, &plain2).unwrap();
    let root2 = Link { hash: link_tree_hash(&d, 2, &vec![root.hash; 512]), blob: n2, suite: 1, key: [0; 32] };
    assert!(matches!(read_tree(&root2, &d, &mut m, MAX_LIST_BYTES), Err(Error::TooLarge(_))));
}

// spec/wire.md §6: a short chunk repeated (so not final) is bad input.
#[test]
fn tree_short_nonfinal_chunk_rejected() {
    let d = sec(0xd0, &t(2));
    let mut m = MemoryBlobs::default();
    let none = Prefix { salt: [0; 16], expiry: None, commitments: vec![] };
    let chunk = vec![7u8; 1024];
    let (cid, _) = m.put(&none, &chunk).unwrap();
    let cl = Link { hash: link_hash(&d, &chunk), blob: cid, suite: 1, key: [0; 32] };
    let plain = osis_core::encode(&Value::List(vec![Value::Int(1), Value::List(vec![Value::Link(cl); 512])]));
    let (nid, _) = m.put(&Prefix { salt: [1; 16], ..none.clone() }, &plain).unwrap();
    let root = Link { hash: link_tree_hash(&d, 1, &vec![cl.hash; 512]), blob: nid, suite: 1, key: [0; 32] };
    assert!(matches!(read_tree(&root, &d, &mut m, MAX_LIST_BYTES), Err(Error::Malformed(_))));
    // the local output bound
    let plain = osis_core::encode(&Value::List(vec![Value::Int(1), Value::List(vec![Value::Link(cl)])]));
    let (nid, _) = m.put(&Prefix { salt: [2; 16], ..none }, &plain).unwrap();
    let root = Link { hash: link_tree_hash(&d, 1, &[cl.hash]), blob: nid, suite: 1, key: [0; 32] };
    assert_eq!(read_tree(&root, &d, &mut m, 1024).unwrap(), chunk);
    assert!(matches!(read_tree(&root, &d, &mut m, 1023), Err(Error::TooLarge(_))));
}

// spec/commits.md §5, §6: `/created` (fixed retention) never carries `expires`.
#[test]
fn created_rejects_expires() {
    let mut h = sample_header();
    let a = &mut h.aspects[0];
    a.ak = Ak::new("/created").unwrap();
    a.retention = retention::CREATED_RETENTION;
    a.tokens.clear();
    a.schema = None;
    a.expires = None;
    h.tokens.clear();
    h.schemas.clear();
    h.validate().unwrap();
    h.aspects[0].expires = Some(h.ts.wall_ms().0 + 1);
    assert!(h.validate().unwrap_err().to_string().contains("fixed-retention"));
}

// spec/sync.md §3, spec/wire.md §4: a received blob mixing retention classes is bad input.
#[test]
fn prefix_inputs_mixed_class_bad_input() {
    use osis_core::{Classified, ErrorClass};
    let mut b = content(2);
    b.aspects[0].tid = t(3);
    b.aspects[1].tid = t(3);
    b.aspects[1].ak = Ak::new("/app/body").unwrap();
    b.aspects[0].retention = Retention { by: PurgeBy::Admin, ..Default::default() };
    let c = b.build(&key(), &TestSecrets { admin: true }, &mut MemoryBlobs::default(), &mut rng()).unwrap().commit;
    let e = prefix_inputs(&c.header, &[(0, 0), (1, 0)]).unwrap_err();
    assert_eq!(e.class(), ErrorClass::BadInput);
    assert_eq!(project(&c, |_| ()).unwrap().len(), 2);
}

// spec/crypto.md §7: token levels are exactly those the retention calls for; only level 1 may
// be missing (provisional: a writer without the admin secret, on content and membership
// commits alike, issues/token-admin-secret.md); level 2 only drops for imports.
#[test]
fn token_levels_strict() {
    let mut h = sample_header();
    h.tokens.remove(0);
    h.aspects[0].tokens = vec![0];
    h.validate().unwrap();
    let mut x = sample_header();
    x.tokens.remove(1);
    x.aspects[0].tokens = vec![0];
    assert!(x.validate().unwrap_err().to_string().contains("token levels"), "level 2 missing on a content commit");
    let mut m = membership_header("/members");
    m.tokens.clear();
    m.aspects[0].tokens.clear();
    m.validate().unwrap();
    let mut b = CommitBuilder::new(Kind::Membership, ts(1_000_000), t(1), t(2), Form::Node);
    let mut a = AspectWrite::new(t(3), Ak::new("/members").unwrap(), 1, 2, register_delta(t(1), ts(1_000_000), 1, "a"));
    a.retention = retention::MEMBERSHIP_RETENTION;
    b.aspects.push(a);
    let c = b.build(&key(), &TestSecrets { admin: false }, &mut MemoryBlobs::default(), &mut rng()).unwrap();
    assert!(c.commit.header.tokens.is_empty());
}

// spec/wire.md §4: every aspect lists at least one delta hash; the builder refuses an aspect
// without deltas.
#[test]
fn zero_deltas_refused() {
    let mut h = membership_header("/members");
    h.aspects[0].hashes.clear();
    assert!(matches!(h.validate(), Err(Error::Malformed(_))));
    let mut b = CommitBuilder::new(Kind::Membership, ts(1_000_000), t(1), t(2), Form::Node);
    let mut a = AspectWrite::new(t(3), Ak::new("/members").unwrap(), 1, 2, vec![]);
    a.deltas.clear();
    a.retention = retention::MEMBERSHIP_RETENTION;
    b.aspects.push(a);
    assert!(matches!(b.build(&key(), &TestSecrets { admin: true }, &mut MemoryBlobs::default(), &mut rng()), Err(Error::Build(_))));
}

// spec/wire.md §1: integers in structures stay below 2^63; an oversized schema default expiry
// is refused rather than clamped.
#[test]
fn expiry_range() {
    let d = AspectDefaults { retention: Retention::default(), expires: Some(u64::MAX - 5) };
    assert!(retention::write_expires("/app/x", ts(10), Some(&d), None).is_err());
    assert!(retention::write_expires("/app/x", ts(10), None, Some(FOREVER + 1)).is_err());
    let mut h = sample_header();
    h.aspects[0].expires = Some(FOREVER + 1);
    assert!(h.validate().is_err());
}

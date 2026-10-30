//! Regression tests from the osis-commit review (spec/wire.md §4, §6; spec/commits.md §2, §5).

use crate::tests::{sample_header, t, ts};
use crate::tests_build::{content, key, rng};
use crate::tests_validate::membership_header;
use crate::tests_verify::{TestSecrets, register_delta, sec};
use crate::*;
use osis_base::{Ak, Link};
use osis_crypto::{link_hash, link_tree_hash};
use osis_schema::{AspectDefaults, PurgeBy, Retention};

// spec/wire.md §6: repeated links are legal (identical chunks share a blob), so the reader is
// bounded instead: a non-final chunk below CHUNK_MIN is bad input and the chunks visited are
// capped by the caller's output bound.
#[test]
fn tree_reader_bounded() {
    use osis_base::format::CHUNK_MIN;
    let d = sec(0xd0, &t(2));
    let mut m = MemoryBlobs::default();
    let none = Prefix { salt: [0; 16], blind: [0; 16], expiry: None, keys: vec![] };
    let chunk = vec![0u8; CHUNK_MIN];
    let (cid, _) = m.put(&none, &chunk).unwrap();
    let cl = Link { hash: link_hash(&d, &chunk), blob: cid, suite: 1, key: [0; 32] };
    let plain = crate::tree::node_plaintext(1, &[(cl, CHUNK_MIN as u64); 4]).unwrap();
    let (nid, _) = m.put(&Prefix { salt: [1; 16], ..none.clone() }, &plain).unwrap();
    let root = Link { hash: link_tree_hash(&d, 1, &[(cl.hash, CHUNK_MIN as u64); 4]), blob: nid, suite: 1, key: [0; 32] };
    assert_eq!(read_list(&root, &d, &mut m, MAX_LIST_BYTES).unwrap().len(), 4 * CHUNK_MIN);
    assert!(matches!(read_list(&root, &d, &mut m, 3 * CHUNK_MIN), Err(Error::TooLarge(_))));
    // a level 2 node repeating that level 1 node 512 times stops at the bound
    let plain2 = crate::tree::node_plaintext(2, &vec![(root, 4 * CHUNK_MIN as u64); 512]).unwrap();
    let (n2, _) = m.put(&Prefix { salt: [2; 16], ..none }, &plain2).unwrap();
    let root2 = Link { hash: link_tree_hash(&d, 2, &vec![(root.hash, 4 * CHUNK_MIN as u64); 512]), blob: n2, suite: 1, key: [0; 32] };
    assert!(matches!(read_list(&root2, &d, &mut m, MAX_LIST_BYTES), Err(Error::TooLarge(_))));
}

// spec/wire.md §6: a short chunk repeated (so not final) is bad input.
#[test]
fn tree_short_nonfinal_chunk_rejected() {
    let d = sec(0xd0, &t(2));
    let mut m = MemoryBlobs::default();
    let none = Prefix { salt: [0; 16], blind: [0; 16], expiry: None, keys: vec![] };
    let chunk = vec![7u8; 1024];
    let (cid, _) = m.put(&none, &chunk).unwrap();
    let cl = Link { hash: link_hash(&d, &chunk), blob: cid, suite: 1, key: [0; 32] };
    let plain = crate::tree::node_plaintext(1, &vec![(cl, 1024); 512]).unwrap();
    let (nid, _) = m.put(&Prefix { salt: [1; 16], ..none.clone() }, &plain).unwrap();
    let root = Link { hash: link_tree_hash(&d, 1, &vec![(cl.hash, 1024); 512]), blob: nid, suite: 1, key: [0; 32] };
    assert!(matches!(read_list(&root, &d, &mut m, MAX_LIST_BYTES), Err(Error::Malformed(_))));
    // the local output bound
    let plain = crate::tree::node_plaintext(1, &[(cl, 1024)]).unwrap();
    let (nid, _) = m.put(&Prefix { salt: [2; 16], ..none }, &plain).unwrap();
    let root = Link { hash: link_tree_hash(&d, 1, &[(cl.hash, 1024)]), blob: nid, suite: 1, key: [0; 32] };
    assert_eq!(read_list(&root, &d, &mut m, 1024).unwrap(), chunk);
    assert!(matches!(read_list(&root, &d, &mut m, 1023), Err(Error::TooLarge(_))));
}

// spec/commits.md §5, §6: `/created` (fixed retention) never carries `expires`.
#[test]
fn created_rejects_expires() {
    let mut h = sample_header();
    let a = &mut h.aspects[0];
    a.ak = Ak::new("/created").unwrap();
    a.retention = retention::CREATED_RETENTION;
    a.keys.clear();
    a.schema = None;
    a.expires = None;
    h.keys.clear();
    h.schemas.clear();
    h.validate().unwrap();
    h.aspects[0].expires = Some(h.ts.wall_ms().0 + 1);
    assert!(h.validate().unwrap_err().to_string().contains("fixed-retention"));
}

// spec/commits.md §2 (created one minting): a durable snapshot or import never carries `/created`.
#[test]
fn created_only_in_commits_with_own_writes() {
    let mut h = sample_header();
    let a = &mut h.aspects[0];
    a.ak = Ak::new("/created").unwrap();
    a.retention = retention::CREATED_RETENTION;
    a.keys.clear();
    a.schema = None;
    a.expires = None;
    a.lo = 0;
    a.hi = 0;
    h.keys.clear();
    h.schemas.clear();
    for k in [Kind::ContentSnapshot, Kind::Import] {
        let mut x = h.clone();
        x.kind = k;
        assert!(x.validate().unwrap_err().to_string().contains("without own writes"), "{k:?}");
    }
}

// spec/sync.md §3, spec/wire.md §4: a received blob mixing retention classes is bad input.
#[test]
fn prefix_inputs_mixed_class_bad_input() {
    use osis_base::{Classified, ErrorClass};
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

// spec/crypto.md §7: delete levels are exactly those the retention calls for, level 1
// included, on content and membership commits alike; level 2 only drops for imports.
#[test]
fn delete_levels_strict() {
    let mut h = sample_header();
    h.keys.remove(0);
    h.aspects[0].keys = vec![0];
    assert!(h.validate().unwrap_err().to_string().contains("delete levels"), "level 1 missing");
    let mut x = sample_header();
    x.keys.remove(1);
    x.aspects[0].keys = vec![0];
    assert!(x.validate().unwrap_err().to_string().contains("delete levels"), "level 2 missing on a content commit");
    let mut m = membership_header("/members");
    m.keys.clear();
    m.aspects[0].keys.clear();
    assert!(m.validate().unwrap_err().to_string().contains("delete levels"), "membership: level 1");
    let mut b = CommitBuilder::new(Kind::Membership, ts(1_000_000), t(1), t(2), Form::Commit);
    let mut a = AspectWrite::new(t(3), Ak::new("/members").unwrap(), 1, 2, register_delta(t(1), ts(1_000_000), 1, "a"));
    a.retention = retention::MEMBERSHIP_RETENTION;
    b.aspects.push(a);
    assert!(matches!(b.clone().build(&key(), &TestSecrets { admin: false }, &mut MemoryBlobs::default(), &mut rng()), Err(Error::Build(_))));
    let c = b.build(&key(), &TestSecrets { admin: true }, &mut MemoryBlobs::default(), &mut rng()).unwrap();
    assert_eq!(c.commit.header.keys.iter().map(|k| k.level).collect::<Vec<_>>(), vec![1]);
}

// spec/wire.md §4: every aspect lists at least one delta hash; the builder refuses an aspect
// without deltas.
#[test]
fn zero_deltas_refused() {
    let mut h = membership_header("/members");
    h.aspects[0].hashes.clear();
    assert!(matches!(h.validate(), Err(Error::Malformed(_))));
    let mut b = CommitBuilder::new(Kind::Membership, ts(1_000_000), t(1), t(2), Form::Commit);
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
    let d = AspectDefaults { retention: Retention::default(), expires: Some(u64::MAX - 5), ..Default::default() };
    assert!(retention::write_expires("/app/x", ts(10), Some(&d), None).is_err());
    assert!(retention::write_expires("/app/x", ts(10), None, Some(FOREVER + 1)).is_err());
    let mut h = sample_header();
    h.aspects[0].expires = Some(FOREVER + 1);
    assert!(h.validate().is_err());
}

// spec/wire.md §4: one author chain: a header listing two level-2 delete keys is bad input.
#[test]
fn one_level_2_key() {
    let mut h = sample_header();
    h.keys.push(crate::tests::dkey(2, 9));
    h.keys.sort_by_key(|k| osis_base::encode(&crate::header::key_value(k)));
    let i = h.keys.iter().position(|k| *k == crate::tests::dkey(1, 1)).unwrap();
    let j = h.keys.iter().position(|k| *k == crate::tests::dkey(2, 2)).unwrap();
    let k = h.keys.iter().position(|k| *k == crate::tests::dkey(2, 9)).unwrap();
    h.aspects[0].keys = vec![i, j];
    let mut a2 = h.aspects[0].clone();
    a2.ak = Ak::new("/app/title2").unwrap();
    a2.keys = vec![i, k];
    h.aspects.push(a2);
    assert!(h.validate().unwrap_err().to_string().contains("level-2"));
}

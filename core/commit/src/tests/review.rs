//! Regression tests from the osis-commit review (spec/wire.md §4, §6; spec/commits.md §2, §5).

use crate::tests::{sample_header, t, ts};
use crate::tests::build::{content, key, rng};
use crate::tests::validate::role_header;
use crate::tests::verify::{TestSecrets, register_delta, sec};
use crate::*;
use osis_base::{Ak, Link};
use std::mem::size_of;
use osis_crypto::{link_hash, link_tree_hash};
use osis_schema::{AspectDefaults, PurgeBy, Retention};

// spec/wire.md §6, through `read_list` (tree.rs `reader_bounds_spec_wire_6` has the reader's
// own bounds): a short chunk repeated (so not final) is bad input, one of CHUNK_MIN is not;
// the output bound is exact.
#[test]
fn list_reader_bounds() {
    let d = sec(0xd0, &t(2));
    let mut m = MemoryBlobs::default();
    let none = Prefix { salt: [0; 16], blind: [0; 16], expiry: None, keys: vec![] };
    let chunk = vec![7u8; 1024];
    let (cid, _) = m.put(&none, &chunk).unwrap();
    let cl = Link { hash: link_hash(&d, &chunk), blob: cid, suite: 1, key: [0; 32] };
    let min = vec![0u8; osis_base::format::CHUNK_MIN];
    let (mid, _) = m.put(&Prefix { salt: [3; 16], ..none.clone() }, &min).unwrap();
    let ml = Link { hash: link_hash(&d, &min), blob: mid, suite: 1, key: [0; 32] };
    let mut root = |kids: &[(Link, u64)], salt: u8| {
        let (nid, _) = m.put(&Prefix { salt: [salt; 16], ..none.clone() }, &crate::tree::node_plaintext(1, kids).unwrap()).unwrap();
        let hashes: Vec<_> = kids.iter().map(|(l, n)| (l.hash, *n)).collect();
        Link { hash: link_tree_hash(&d, 1, &hashes), blob: nid, suite: 1, key: [0; 32] }
    };
    let repeated = root(&vec![(cl, 1024); 512], 1);
    let single = root(&[(cl, 1024)], 2);
    // repeated links are legal: a non-final chunk of exactly CHUNK_MIN passes
    let mins = root(&[(ml, min.len() as u64); 4], 4);
    assert!(matches!(read_list(&repeated, &d, &mut m, MAX_LIST_BYTES), Err(Error::Malformed(_))));
    assert_eq!(read_list(&single, &d, &mut m, 1024).unwrap(), chunk);
    assert!(matches!(read_list(&single, &d, &mut m, 1023), Err(Error::TooLarge(_))));
    assert_eq!(read_list(&mins, &d, &mut m, MAX_LIST_BYTES).unwrap().len(), 4 * min.len());
}

// spec/commits.md §5, §6: `created.0` has ordinary retention, so its commit may expire.
#[test]
fn created_may_expire_spec_commits_6() {
    let mut h = sample_header();
    h.aspects[0].ak = Ak::new("created.0").unwrap();
    h.expires = Some(h.ts.wall_ms().0 + 1);
    h.validate().unwrap();
}

// spec/commits.md §2, §5: a snapshot never carries `retention^.0`, kept forever and read
// a delta at a time; its retention is fixed.
#[test]
fn retention_setting_kinds_spec_commits_5() {
    let mut h = sample_header();
    let a = &mut h.aspects[0];
    a.ak = Ak::new("retention^.0").unwrap();
    a.retention = retention::KEPT_RETENTION;
    a.keys.clear();
    a.lo = 0;
    a.hi = 0;
    h.expires = None;
    h.keys.clear();
    h.kind = Kind::ContentSnapshot;
    h.form = crate::header::Form::Commit;
    assert!(h.validate().unwrap_err().to_string().contains("without own writes"));
    assert_eq!(retention::fixed_retention("retention^.0"), Some(retention::KEPT_RETENTION));
}

// spec/commits.md §2 (created one minting): a durable snapshot never carries `created.0`.
#[test]
fn created_only_in_commits_with_own_writes() {
    let mut h = sample_header();
    let a = &mut h.aspects[0];
    a.ak = Ak::new("created.0").unwrap();
    a.retention = retention::KEPT_RETENTION;
    a.keys.clear();
    a.lo = 0;
    a.hi = 0;
    h.expires = None;
    h.keys.clear();
    h.kind = Kind::ContentSnapshot;
    h.form = Form::Commit;
    assert!(h.validate().unwrap_err().to_string().contains("without own writes"));
}

// spec/wire.md §5: one prefix group per distinct delete-key set among the blob's aspects, in
// order of first aspect; an aspect index past the header is bad input.
#[test]
fn prefix_groups_by_key_set() {
    use osis_base::{Classified, ErrorClass};
    let mut b = content(2);
    b.aspects[0].tid = t(3);
    b.aspects[1].tid = t(3);
    b.aspects[1].ak = Ak::new("app:body.0").unwrap();
    b.aspects[0].retention = Retention { by: PurgeBy::Admin };
    let c = b.build(&key(), &TestSecrets { admin: true }, &mut MemoryBlobs::default(), &mut rng()).unwrap().commit;
    let g = prefix_groups(&c.header, [0, 1]).unwrap();
    assert_eq!(g.len(), 2);
    assert_ne!(g[0], g[1]);
    assert_eq!(prefix_groups(&c.header, [1, 1, 0]).unwrap(), g);
    assert_eq!(prefix_groups(&c.header, [2]).unwrap_err().class(), ErrorClass::BadInput);
}

// spec/crypto.md §7: delete levels are exactly those the retention calls for, level 1
// included, on content and role commits alike.
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
    let mut m = role_header("roles.0");
    m.keys.clear();
    m.aspects[0].keys.clear();
    assert!(m.validate().unwrap_err().to_string().contains("delete levels"), "role commit: level 1");
    let mut b = CommitBuilder::new(Kind::Role, ts(1_000_000), t(1), t(1), Form::Commit);
    let mut a = AspectWrite::new(t(3), Ak::new("roles.0").unwrap(), 1, 2, register_delta(t(1), ts(1_000_000), 1, "a"));
    a.retention = retention::ROLE_RETENTION;
    b.aspects.push(a);
    assert!(matches!(b.clone().build(&key(), &TestSecrets { admin: false }, &mut MemoryBlobs::default(), &mut rng()), Err(Error::Build(_))));
    let c = b.build(&key(), &TestSecrets { admin: true }, &mut MemoryBlobs::default(), &mut rng()).unwrap();
    assert_eq!(c.commit.header.keys.iter().map(|k| k.level).collect::<Vec<_>>(), vec![1]);
}

// spec/wire.md §1: integers in structures stay below 2^63; an oversized schema default expiry
// is refused rather than clamped.
#[test]
fn expiry_range() {
    let d = AspectDefaults { retention: Retention::default(), expires: Some(u64::MAX - 5) };
    assert!(retention::write_expires("app:x.0", ts(10), Some(&d), None).is_err());
    assert!(retention::write_expires("app:x.0", ts(10), None, Some(FOREVER + 1)).is_err());
    let mut h = sample_header();
    h.expires = Some(FOREVER + 1);
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
    a2.ak = Ak::new("app:title2.0").unwrap();
    a2.keys = vec![i, k];
    h.aspects.push(a2);
    assert!(h.validate().unwrap_err().to_string().contains("level-2"));
}

/// Links `bytes` as list `f` of a header holding nothing else.
fn linked_as(f: ListField, bytes: &[u8], d: &osis_crypto::Secret32, m: &mut MemoryBlobs) -> Header {
    let mut salt = 0u64;
    let link = write_list(bytes, d, m, &mut || {
        salt += 1;
        let mut s = [0; 16];
        s[..8].copy_from_slice(&salt.to_be_bytes());
        Prefix { salt: s, blind: [0; 16], expiry: None, keys: vec![] }
    })
    .unwrap();
    let mut h = sample_header();
    (h.aspects, h.chunks, h.purge, h.keys, h.frontier) = (vec![], vec![], vec![], vec![], None);
    h.links.set(f, Some(link));
    h
}

fn array(n: usize, item: impl Fn(usize) -> Vec<u8>) -> Vec<u8> {
    let mut b = Vec::new();
    osis_base::cbor::head(&mut b, 4, n as u64);
    (0..n).for_each(|i| b.extend(item(i)));
    b
}

fn peak_mib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines().find(|l| l.starts_with("VmHWM"))?.split_whitespace().nth(1)?.parse::<u64>().ok().map(|k| k / 1024)
}

// spec/requirements.md, peer input never costs unbounded memory: a list of the wrong shape is refused
// before its items are built. 8 MiB of one-entry maps peak at 6.5 GB as a whole-value decode. VmHWM
// (no counting allocator, unsafe is forbidden) is the process's, and another test beside this one could
// fail it or hide a rise, so the check runs in a process of its own.
#[test]
fn hostile_list_refused_by_shape() {
    const ALONE: &str = "OSIS_COMMIT_PEAK_ALONE";
    if std::env::var_os(ALONE).is_none() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::review::hostile_list_refused_by_shape", "--nocapture"])
            .env(ALONE, "1")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success() && text.contains("1 passed"), "{text}{}", String::from_utf8_lossy(&out.stderr));
        return;
    }
    let d = sec(0xd0, &t(2));
    let mut m = MemoryBlobs::default();
    let n = 8 << 20;
    let maps = array(n / 3, |_| vec![0xa1, 0, 0]);
    let mut in_frontier = vec![0xa1, 0];
    in_frontier.extend(&maps);
    let mut in_set = vec![0xa1, 0];
    osis_base::cbor::head(&mut in_set, 6, osis_base::format::TAG_SET);
    in_set.extend(&maps);
    let cases = [(ListField::Aspects, &maps), (ListField::Chunks, &maps), (ListField::Purge, &maps), (ListField::Keys, &maps), (ListField::Frontier, &maps), (ListField::Frontier, &in_frontier), (ListField::Frontier, &in_set)];
    let headers: Vec<_> = cases.map(|(f, bytes)| (f, linked_as(f, bytes, &d, &mut m))).into();
    let start = peak_mib();
    for (f, mut h) in headers {
        assert!(h.resolve(&mut m, &d).is_err(), "{f:?}");
        if let (Some(a), Some(b)) = (start, peak_mib()) {
            assert!(b - a < 64, "{f:?}: {a} to {b} MiB");
        }
    }
}

/// What a resolved header's lists hold on the heap.
fn held(h: &Header) -> usize {
    use std::mem::size_of_val as size;
    let ak = |a: &Ak| a.as_str().len();
    h.aspects.capacity() * size_of::<AspectEntry>() + h.aspects.iter().map(|a| ak(&a.ak) + size(a.keys.as_slice())).sum::<usize>()
        + h.chunks.capacity() * size_of::<ChunkEntry>() + h.chunks.iter().map(|c| size(c.keys.as_slice())).sum::<usize>()
        + h.purge.capacity() * size_of::<PurgeItem>() + h.purge.iter().map(|p| ak(p.ak())).sum::<usize>()
}

// The same, for lists of the right shape: what an item costs is bounded by what its bytes pay, at the
// fewest bytes an item can take.
#[test]
fn list_items_cost_at_most_their_bytes_times_six() {
    let d = sec(0xd0, &t(2));
    let mut m = MemoryBlobs::default();
    let n = 1 << 18;
    let tid = |i: usize| {
        let mut b = vec![0x4f];
        b.extend(&(i as u64).to_be_bytes());
        b.extend([0; 7]);
        b
    };
    let id = |i: usize| {
        let mut b = vec![0x58, 32];
        b.extend(&(i as u64).to_be_bytes());
        b.extend([0; 24]);
        b
    };
    let lists = [
        (ListField::Aspects, array(n / 57, |i| [&[0x88][..], &tid(i), &[0x63, b'a', b'.', b'0', 1, 2, 0, 0x80], &id(0), &[0x80]].concat())),
        (ListField::Chunks, array(n / 36, |i| [&[0x82][..], &id(i), &[0x80]].concat())),
        (ListField::Purge, array(n / 21, |i| [&[0x82][..], &tid(i), &[0x63, b'a', b'.', b'0']].concat())),
    ];
    for (f, bytes) in lists {
        let mut h = linked_as(f, &bytes, &d, &mut m);
        h.resolve(&mut m, &d).unwrap_or_else(|e| panic!("{f:?}: {e}"));
        assert!(held(&h) <= 6 * bytes.len(), "{f:?}: {} for {}", held(&h), bytes.len());
    }
}

const CHUNK_THRESHOLD_PLUS: usize = osis_base::format::CHUNK_THRESHOLD + 1;

// spec/wire.md §4: a list's items are sorted and distinct, so a chunk link repeated (a small upload
// for a list of any length) is refused at its first repeat; so is a frontier out of order or of any
// shape but `{0: set<32-byte ID>}`.
#[test]
fn list_items_ascend_and_frontier_shape() {
    let d = sec(0xd0, &t(2));
    let mut m = MemoryBlobs::default();
    let item = |i: usize| {
        let mut b = vec![0x82, 0x58, 32];
        b.extend(&(i as u64).to_be_bytes());
        b.extend([0; 24]);
        b.push(0x80);
        b
    };
    let n = (CHUNK_THRESHOLD_PLUS + 100) / 36;
    let ok = array(n, item);
    let mut h = linked_as(ListField::Chunks, &ok, &d, &mut m);
    h.resolve(&mut m, &d).unwrap();
    assert_eq!(h.chunks.len(), n);
    let again = array(n, |i| item(i.min(n - 2)));
    let mut h = linked_as(ListField::Chunks, &again, &d, &mut m);
    assert!(matches!(h.resolve(&mut m, &d), Err(Error::Malformed("list items not sorted and distinct"))));

    let frontier = |n: usize, id: &dyn Fn(usize) -> usize, extra: &[u8]| {
        let mut b = vec![0xa1 + u8::from(!extra.is_empty()), 0];
        osis_base::cbor::head(&mut b, 6, osis_base::format::TAG_SET);
        b.extend(array(n, |i| {
            let mut x = vec![0x58, 32];
            x.extend(&(id(i) as u64).to_be_bytes());
            x.extend([0; 24]);
            x
        }));
        b.extend(extra);
        b
    };
    let n = (CHUNK_THRESHOLD_PLUS + 100) / 34;
    let good = frontier(n, &|i| i, &[]);
    let mut h = linked_as(ListField::Frontier, &good, &d, &mut m);
    h.resolve(&mut m, &d).unwrap();
    assert_eq!(osis_base::encode(h.frontier.as_ref().unwrap()), good);
    for bad in [frontier(n, &|i| i.min(n - 2), &[]), frontier(n, &|i| n - i, &[]), frontier(n, &|i| i, &[1, 0])] {
        let mut h = linked_as(ListField::Frontier, &bad, &d, &mut m);
        assert!(h.resolve(&mut m, &d).is_err());
    }
}

// A read by shape takes exactly what the whole-value decode took: inline lists go by it too, so every
// list of a built commit passes both ways, and a tree node of another shape is refused.
#[test]
fn node_by_shape() {
    let d = sec(0xd0, &t(2));
    let ca = Link { hash: link_hash(&d, b"x"), blob: osis_base::BlobId([1; 32]), suite: 1, key: [2; 32] };
    let good = crate::tree::node_plaintext(1, &[(ca, 1), (ca, 1)]).unwrap();
    assert_eq!(crate::tree::parse_node(&good).unwrap(), (1, vec![(ca, 1), (ca, 1)]));
    let mut long = good.clone();
    long.push(0);
    assert!(crate::tree::parse_node(&long).is_err());
    let maps = [&[0x83, 1, 0x9a][..], &(1u32 << 20).to_be_bytes(), &[0xa1, 0, 0].repeat(1 << 20)].concat();
    assert!(crate::tree::parse_node(&maps).is_err());
}

// Forms a read by shape must refuse as `osis_base::decode` does, or the bytes would not be the header's:
// map keys out of order or repeated, heads not the shortest, indefinite or impossible lengths.
#[test]
fn list_forms_refused() {
    let aspect = |lo: &[u8], by: &[u8], ak: &[u8]| {
        let mut b = vec![0x81, 0x88, 0x4f];
        b.extend([1; 15]);
        b.extend(ak);
        b.extend(lo);
        b.push(2);
        b.extend(by);
        b.extend([0x80, 0x58, 32]);
        b.extend([3; 32]);
        b.push(0x80);
        b
    };
    let read = |f: ListField, b: &[u8]| {
        let mut h = sample_header();
        h.read_list(f, b, false)
    };
    let name: &[u8] = &[0x63, b'a', b'.', b'0'];
    for by in [&[0][..], &[1], &[2], &[3]] {
        read(ListField::Aspects, &aspect(&[1], by, name)).unwrap();
    }
    for by in [&[4][..], &[0x18, 1], &[0x20], &[0x82, 2, 0], &[0x81, 2]] {
        assert!(read(ListField::Aspects, &aspect(&[1], by, name)).is_err(), "{by:02x?}");
    }
    for lo in [&[0x18, 1][..], &[0x19, 0, 1], &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], &[0x20]] {
        assert!(read(ListField::Aspects, &aspect(lo, &[2], name)).is_err(), "{lo:02x?}");
    }
    assert!(read(ListField::Aspects, &aspect(&[1], &[2], &[0x63, 0xff, 0xff, 0xff])).is_err());
    let good = aspect(&[1], &[2], name);
    read(ListField::Aspects, &good).unwrap();
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(read(ListField::Aspects, &trailing).is_err());
    for count in [&[0x9f][..], &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], &[0x9a, 0xff, 0xff, 0xff, 0xff], &[0x98, 1]] {
        assert!(read(ListField::Aspects, &[count, &good[1..]].concat()).is_err(), "{count:02x?}");
    }

    let id = [&[0x58, 32][..], &[4; 32]].concat();
    let tag = |t: Vec<u8>| [&[0xa1, 0][..], &t, &[0x81], &id].concat();
    let shortest = |t| {
        let mut b = Vec::new();
        osis_base::cbor::head(&mut b, 6, t);
        b
    };
    read(ListField::Frontier, &tag(shortest(osis_base::format::TAG_SET))).unwrap();
    assert!(read(ListField::Frontier, &tag([&[0xdb][..], &osis_base::format::TAG_SET.to_be_bytes()].concat())).is_err());
    assert!(read(ListField::Frontier, &tag(shortest(osis_base::format::TAG_SET + 1))).is_err());
}

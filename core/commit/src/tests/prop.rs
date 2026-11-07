//! Property tests (spec/wire.md §4, spec/sync.md §3).

use crate::tests::{SESSION, dkey, t, ts};
use crate::tests::build::{key, rng};
use crate::tests::verify::{TestSecrets, register_delta};
use crate::*;
use osis_base::{Ak, BlobId, CommitId, Link, Tid, Value};
use osis_schema::{History, PurgeBy, Retention};
use osis_crypto::Secret32;
use proptest::prelude::*;

/// Every canonical history: none, purge on replace, or a keep with at least one bound, `after` above 0.
fn history() -> impl Strategy<Value = Option<History>> {
    (0u8..3, proptest::option::of(0u64..1 << 62), proptest::option::of(1u64..1 << 40)).prop_map(|(k, until, after)| match k {
        0 => None,
        1 => Some(History::PurgeOnReplace),
        _ => Some(History::Keep { until: until.or(after.is_none().then_some(5)), after }),
    })
}

fn retention() -> impl Strategy<Value = Retention> {
    (0u64..5, history()).prop_map(|(b, history)| Retention { by: PurgeBy::from_id(b).unwrap(), history })
}

fn tid() -> impl Strategy<Value = Tid> {
    any::<[u8; 15]>().prop_map(Tid::from_bytes)
}

fn aspect() -> impl Strategy<Value = AspectEntry> {
    (tid(), "[a-z]{1,8}", 0u64..100, 0u64..100, retention(), proptest::collection::vec(0usize..8, 0..3), any::<[u8; 32]>())
        .prop_map(|(tid, ak, lo, hi, retention, keys, hash)| AspectEntry { tid, ak: Ak::new(format!("{ak}.0")).unwrap(), lo, hi, retention, keys, hash })
}

fn link() -> impl Strategy<Value = Link> {
    (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(hash, b)| Link { hash, blob: BlobId(b), suite: 1, key: [7; 32] })
}

prop_compose! {
    fn header()(
        author in tid(), actor in tid(), kind in 0u64..4, wall in 0u64..1 << 46, form in any::<bool>(), expires in proptest::option::of(0u64..1 << 50),
        aspects in proptest::collection::vec(aspect(), 0..4),
        chunks in proptest::collection::vec((any::<[u8; 32]>(), proptest::collection::vec(0usize..5, 0..3)), 0..3),
        purge in proptest::collection::vec((proptest::option::of(any::<[u8; 32]>()), tid()), 0..3),
        undoes in proptest::option::of(any::<[u8; 32]>()),
        blind in any::<[u8; 16]>(),
        keys in proptest::collection::vec((1u8..4, any::<u8>()), 0..4),
        frontier in proptest::option::of(any::<i64>()),
        links in proptest::collection::vec(proptest::option::of(link()), 5),
    ) -> Header {
        let mut l = Links::default();
        for (f, x) in ListField::ALL.into_iter().zip(links) {
            l.set(f, x);
        }
        let mut h = Header {
            version: 1, author, actor, kind: Kind::from_id(kind).unwrap(), ts: ts(wall).max(ts(0)),
            form: if form { Form::Commit } else { SESSION },
            expires,
            aspects,
            chunks: chunks.into_iter().map(|(b, keys)| ChunkEntry { blob: BlobId(b), keys }).collect(),
            purge: purge.into_iter().map(|(c, tid)| match c {
                Some(c) => PurgeItem::Commit { commit: CommitId(c), tid, ak: Ak::new("p.0").unwrap() },
                None if tid.as_bytes()[0] % 2 == 0 => PurgeItem::Aspect { tid, ak: Ak::new("p.0").unwrap() },
                None => PurgeItem::Author { tid, ak: Ak::new("p.0").unwrap(), actor: tid },
            }).collect(),
            undoes: undoes.map(CommitId), blind,
            keys: keys.into_iter().map(|(level, b)| dkey(level, b)).collect(),
            frontier: frontier.map(|n| Value::Map([(Value::Int(0), Value::Int(n))].into_iter().collect())),
            links: l,
            ephemeral: None,
        };
        // the lists' rule: sorted and distinct
        let by_item = |b: Value| osis_base::encode(&b);
        for a in &mut h.aspects {
            a.keys.sort();
            a.keys.dedup();
        }
        h.aspects.sort_by_key(|a| crate::header::aspect_key(&a.tid, &a.ak));
        h.aspects.dedup_by_key(|a| crate::header::aspect_key(&a.tid, &a.ak));
        for c in &mut h.chunks {
            c.keys.sort();
            c.keys.dedup();
        }
        h.chunks.sort_by_key(|c| c.blob);
        h.chunks.dedup_by_key(|c| c.blob);
        h.purge.sort_by_key(|p| by_item(crate::header::purge_value(p)));
        h.purge.dedup();
        h.keys.sort_by_key(|k| by_item(crate::header::key_value(k)));
        h.keys.dedup();
        // a linked list's items are not in the header bytes
        for f in ListField::ALL {
            if h.links.get(f).is_some() {
                match f {
                    ListField::Aspects => h.aspects.clear(),
                    ListField::Chunks => h.chunks.clear(),
                    ListField::Purge => h.purge.clear(),
                    ListField::Keys => h.keys.clear(),
                    ListField::Frontier => h.frontier = None,
                }
            }
        }
        h
    }
}

/// A content commit over `n` aspects of three things with mixed retention (`nobody` or not
/// throughout: a commit mixes no other class with it), expiring or not.
fn commit(classes: &[(u8, u8)], exp: bool) -> CommitBlob {
    let at = ts(1_000_000);
    let mut b = CommitBuilder::new(Kind::Content, at, t(1), t(2), SESSION);
    b.expires = exp.then_some(5_000_000);
    let nobody = classes.first().is_some_and(|c| c.1 == 0);
    for (i, (thing, by)) in classes.iter().enumerate() {
        let by = if nobody { 0 } else { (*by).max(1) };
        let mut a = AspectWrite::new(t(10 + thing), Ak::new(format!("app:f{i}.0")).unwrap(), 1, 2, register_delta(t(1), at, 1, &format!("{i}")));
        let history = (by == 0).then_some(History::FOREVER);
        a.retention = Retention { by: PurgeBy::from_id(u64::from(by)).unwrap(), history };
        b.aspects.push(a);
    }
    b.build(&key(), &TestSecrets { admin: true }, &mut MemoryBlobs::default(), &mut rng()).unwrap().commit
}

/// `b` with a few small edits, seeded: bytes, or a head widened to a longer form.
fn edited(b: &[u8], mut seed: u64) -> Vec<u8> {
    const HEADS: [u8; 24] = [0, 1, 2, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1f, 0x20, 0x3f, 0x40, 0x4f, 0x58, 0x60, 0x63, 0x80, 0x81, 0x9f, 0xa0, 0xa1, 0xa2, 0xc0, 0xff];
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed as usize
    };
    let mut x = b.to_vec();
    for _ in 0..1 + next() % 3 {
        let at = next() % (x.len() + 1);
        let byte = if next() % 2 == 0 { HEADS[next() % HEADS.len()] } else { next() as u8 };
        match next() % 6 {
            0 => x.insert(at, byte),
            1 if at < x.len() => drop(x.remove(at)),
            2 => x.truncate(at),
            3 if at < x.len() && x[at] & 31 < 24 => {
                // the same argument in a head one size up
                let (ib, arg) = (x[at], x[at] & 31);
                x.splice(at..=at, [(ib & 0xe0) | 24, arg]);
            }
            _ if at < x.len() => x[at] = byte,
            _ => {}
        }
    }
    x
}

/// What `read_list` accepts, the general decoder accepts as the same canonical bytes, and the items read
/// encode back to them.
fn reader_agrees(h: &Header, f: ListField, bytes: &[u8]) -> Result<(), TestCaseError> {
    let mut x = h.clone();
    if x.read_list(f, bytes, false).is_err() {
        return Ok(());
    }
    let v = osis_base::decode(bytes, &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: bytes.len() });
    prop_assert!(v.is_ok(), "{f:?} {bytes:02x?}: {v:?}");
    prop_assert_eq!(osis_base::encode(&v.unwrap()), bytes);
    prop_assert_eq!(osis_base::encode(&x.list_value(f).unwrap()), bytes, "{:?}", f);
    Ok(())
}

proptest! {
    // Differential of `osis_base::Reader` against `osis_base::decode`: valid lists and tree nodes, and
    // edits of them.
    #[test]
    fn reader_accepts_only_what_decode_does(h in header(), ids in proptest::collection::btree_set(any::<[u8; 32]>(), 0..4), kids in proptest::collection::vec((link(), 0u64..1 << 20), 1..4), seed in 1u64..) {
        let frontier = Value::Map([(Value::Int(0), Value::Set(ids.iter().map(|i| Value::bytes(i)).collect()))].into_iter().collect());
        let lists: Vec<(ListField, Vec<u8>)> = ListField::ALL.into_iter().map(|f| {
            let v = if f == ListField::Frontier { frontier.clone() } else { h.list_value(f).unwrap() };
            (f, osis_base::encode(&v))
        }).collect();
        let node = tree::node_plaintext(3, &kids).unwrap();
        prop_assert_eq!(tree::parse_node(&node).unwrap(), (3, kids));
        for i in 0..300u64 {
            let s = seed.wrapping_add(i.wrapping_mul(0x9e37_79b9_7f4a_7c15)) | 1;
            for (f, b) in &lists {
                reader_agrees(&h, *f, b)?;
                reader_agrees(&h, *f, &edited(b, s))?;
            }
            let e = edited(&node, s);
            if let Ok((level, kids)) = tree::parse_node(&e) {
                prop_assert!(osis_base::decode(&e, &osis_base::Limits { max_depth: 4, max_bytes: e.len() }).is_ok(), "{:02x?}", e);
                prop_assert_eq!(tree::node_plaintext(level, &kids).unwrap(), e);
            }
        }
    }

    // spec/wire.md §4: any header, inline or linked lists, round-trips through its bytes.
    #[test]
    fn header_round_trip_prop(h in header()) {
        let back = Header::decode(&h.encode()).unwrap();
        prop_assert_eq!(back, h);
    }

    // spec/wire.md §4, spec/sync.md §3: sections partition the commit's deltas by reader, each
    // opens under its reader's secret alone and the opened parts verify; a non-reader's copy
    // carries the others' sections verbatim; the prefix groups are one per key set.
    #[test]
    fn sections_partition(classes in proptest::collection::vec((0u8..3, 0u8..4), 1..8), exp in any::<bool>(), split in 1usize..4) {
        let c = commit(&classes, exp);
        let secret = |r: usize| Secret32::from_bytes([r as u8 + 1; 32]);
        let mut rng = rng();
        let env = seal_commit(&c, |ai| ai % split, |r, _| Some((secret(*r), vec![])), &[], &mut rng).unwrap();
        prop_assert_eq!(Envelope::decode(&env.encode()).unwrap(), env.clone());
        let mut all: Vec<usize> = env.ais();
        all.sort();
        prop_assert_eq!(all, (0..classes.len()).collect::<Vec<_>>());
        let s = TestSecrets { admin: true };
        let dedup = |t: &Tid| s.dedup(t);
        let mut sealed_total = 0;
        for r in 0..split {
            let o = env.open(|_| vec![secret(r)]).unwrap();
            prop_assert_eq!(o.commit.id(), c.id());
            verify_blob(&o.commit, &key().verifying_key(), &dedup, None).unwrap();
            for p in &o.commit.parts {
                prop_assert_eq!(p.ai % split, r);
            }
            sealed_total += o.sealed.len();
            let again = seal_commit(&o.commit, |ai| ai % split, |x, _| Some((secret(*x), vec![])), &o.sealed, &mut rng).unwrap();
            prop_assert_eq!(again.open(|_| (0..split).map(secret).collect()).unwrap().commit, c.clone());
        }
        prop_assert_eq!(sealed_total, env.sections.len() * (split - 1));
        let groups = prefix_groups(&c.header, env.ais()).unwrap();
        let mut sets: Vec<&Vec<usize>> = Vec::new();
        for a in &c.header.aspects {
            if !sets.contains(&&a.keys) {
                sets.push(&a.keys);
            }
        }
        prop_assert_eq!(groups.len(), sets.len());
        for (g, set) in groups.iter().zip(sets) {
            prop_assert_eq!(g, &set.iter().map(|i| c.header.keys[*i]).collect::<Vec<_>>());
        }
    }
}

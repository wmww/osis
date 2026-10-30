//! Property tests (spec/wire.md §4, spec/sync.md §3).

use crate::tests::{dkey, t, ts};
use crate::tests::build::{key, rng};
use crate::tests::verify::{TestSecrets, register_delta};
use crate::*;
use osis_base::{Ak, BlobId, CommitId, Link, SchemaId, Tid, Value};
use osis_schema::{Bound, PurgeBy, Retention};
use proptest::prelude::*;

fn bound() -> impl Strategy<Value = Bound> {
    (proptest::option::of(0u64..1 << 62), proptest::option::of(0u64..1 << 40)).prop_map(|(abs, rel)| Bound { abs, rel })
}

fn retention() -> impl Strategy<Value = Retention> {
    (0u64..4, bound(), bound()).prop_map(|(b, at_least, at_most)| Retention { by: PurgeBy::from_id(b).unwrap(), at_least, at_most })
}

fn tid() -> impl Strategy<Value = Tid> {
    any::<[u8; 15]>().prop_map(Tid::from_bytes)
}

fn aspect() -> impl Strategy<Value = AspectEntry> {
    (tid(), "[a-z]{1,8}", 0u64..100, 0u64..100, retention(), proptest::option::of(0u64..1 << 50), proptest::option::of(0usize..4), proptest::collection::vec(0usize..8, 0..3), proptest::collection::vec(any::<[u8; 32]>(), 1..3))
        .prop_map(|(tid, ak, lo, hi, retention, expires, schema, keys, hashes)| AspectEntry { tid, ak: Ak::new(format!("/{ak}")).unwrap(), lo, hi, retention, expires, schema, keys, hashes })
}

fn link() -> impl Strategy<Value = Link> {
    (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(hash, b)| Link { hash, blob: BlobId(b), suite: 1, key: [7; 32] })
}

prop_compose! {
    fn header()(
        author in tid(), actor in tid(), kind in 0u64..6, wall in 0u64..1 << 46, form in any::<bool>(),
        schemas in proptest::collection::vec((any::<[u8; 16]>(), 0u64..9), 0..3),
        aspects in proptest::collection::vec(aspect(), 0..4),
        chunks in proptest::collection::vec((any::<[u8; 32]>(), proptest::collection::vec(0usize..5, 0..3)), 0..3),
        purge in proptest::collection::vec((proptest::option::of(any::<[u8; 32]>()), tid()), 0..3),
        undoes in proptest::option::of(any::<[u8; 32]>()),
        blind in any::<[u8; 16]>(),
        keys in proptest::collection::vec((1u8..4, any::<u8>()), 0..4),
        frontier in proptest::option::of(any::<i64>()),
        origins in proptest::collection::vec((any::<[u8; 32]>(), tid(), tid(), 0u64..1 << 40), 0..2),
        links in proptest::collection::vec(proptest::option::of(link()), 6),
    ) -> Header {
        let mut l = Links::default();
        for (f, x) in ListField::ALL.into_iter().zip(links) {
            l.set(f, x);
        }
        let mut h = Header {
            version: 1, author, actor, kind: Kind::from_id(kind).unwrap(), ts: ts(wall).max(ts(0)),
            form: if form { Form::Commit } else { Form::Node },
            schemas: schemas.into_iter().map(|(i, r)| (SchemaId(i), r)).collect(),
            aspects,
            chunks: chunks.into_iter().map(|(b, keys)| ChunkEntry { blob: BlobId(b), keys }).collect(),
            purge: purge.into_iter().map(|(c, tid)| match c {
                Some(c) => PurgeItem::Commit { commit: CommitId(c), tid, ak: Ak::new("/p").unwrap() },
                None => PurgeItem::Aspect { tid, ak: Ak::new("/p").unwrap() },
            }).collect(),
            undoes: undoes.map(CommitId), blind,
            keys: keys.into_iter().map(|(level, b)| dkey(level, b)).collect(),
            frontier: frontier.map(|n| Value::Map([(Value::Int(0), Value::Int(n))].into_iter().collect())),
            origins: origins.into_iter().map(|(c, author, actor, w)| Origin { commit: CommitId(c), author, actor, ts: ts(w) }).collect(),
            links: l,
            ephemeral: None,
        };
        // a linked list's items are not in the header bytes
        for f in ListField::ALL {
            if h.links.get(f).is_some() {
                match f {
                    ListField::Aspects => h.aspects.clear(),
                    ListField::Chunks => h.chunks.clear(),
                    ListField::Purge => h.purge.clear(),
                    ListField::Keys => h.keys.clear(),
                    ListField::Frontier => h.frontier = None,
                    ListField::Origins => h.origins.clear(),
                }
            }
        }
        h
    }
}

/// A content commit over `n` aspects of three things with mixed retention and expiry.
fn commit(classes: &[(u8, u8, bool)]) -> CommitBlob {
    let at = ts(1_000_000);
    let mut b = CommitBuilder::new(Kind::Content, at, t(1), t(2), Form::Node);
    for (i, (thing, by, exp)) in classes.iter().enumerate() {
        let mut a = AspectWrite::new(t(10 + thing), Ak::new(format!("/app/f{i}")).unwrap(), 1, 2, register_delta(t(1), at, 1, &format!("{i}")));
        a.retention = Retention { by: PurgeBy::from_id(u64::from(*by)).unwrap(), ..Default::default() };
        a.expires = exp.then_some(5_000_000);
        b.aspects.push(a);
    }
    b.build(&key(), &TestSecrets { admin: true }, &mut MemoryBlobs::default(), &mut rng()).unwrap().commit
}

proptest! {
    // spec/wire.md §4: any header, inline or linked lists, round-trips through its bytes.
    #[test]
    fn header_round_trip_prop(h in header()) {
        let back = Header::decode(&h.encode()).unwrap();
        prop_assert_eq!(back, h);
    }

    // spec/sync.md §3: projections partition the commit's deltas, hold one class each, and
    // every projection verifies alone.
    #[test]
    fn projections_partition(classes in proptest::collection::vec((0u8..3, 0u8..4, any::<bool>()), 1..8), split in 1usize..4) {
        let c = commit(&classes);
        let ps = project(&c, |ai| ai % split).unwrap();
        let mut all: Vec<(usize, usize)> = ps.iter().flat_map(|p| p.parts.clone()).collect();
        all.sort();
        prop_assert_eq!(all, (0..classes.len()).map(|i| (i, 0)).collect::<Vec<_>>());
        let s = TestSecrets { admin: true };
        let dedup = |t: &Tid| s.dedup(t);
        for p in &ps {
            let blob = CommitBlob::decode(&p.plaintext).unwrap();
            prop_assert_eq!(blob.id(), c.id());
            verify_blob(&blob, &key().verifying_key(), &dedup, None).unwrap();
            prop_assert_eq!(prefix_inputs(&c.header, &p.parts).unwrap(), (p.expires, p.keys.clone()));
            for (ai, _) in &p.parts {
                let a = &c.header.aspects[*ai];
                prop_assert_eq!((a.retention, a.expires, ai % split), (p.retention, p.expires, p.readers));
            }
        }
    }
}

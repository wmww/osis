//! Builder, header-list links, projection, purge rewrite (spec/commits.md §1, §5; spec/wire.md
//! §4, §6; spec/sync.md §3).

use crate::tests::{t, ts};
use crate::tests_verify::{TestSecrets, register_delta, sec};
use crate::*;
use osis_core::format::{CHUNK_THRESHOLD, MAX_BLOB};
use osis_core::{Ak, CommitId, Tid, Ts, Value};
use osis_crdt::{AnyView, Delta, Source, Writer, create, encode_delta};
use osis_crypto::{SeededRng, Secret32, SigningSecret};
use osis_schema::{PurgeBy, Retention};

pub(crate) fn key() -> SigningSecret {
    SigningSecret::from_seed(&Secret32::from_bytes([0x41; 32]))
}

pub(crate) fn rng() -> SeededRng {
    SeededRng::from_seed([0x55; 32])
}

pub(crate) fn content(n: usize) -> CommitBuilder {
    let at = ts(1_000_000);
    let mut b = CommitBuilder::new(Kind::Content, at, t(1), t(2), Form::Node);
    for i in 0..n {
        let d = register_delta(t(1), at, 1, &format!("v{i}"));
        let tid = Tid::from_bytes([(i % 251) as u8, (i / 251) as u8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]);
        b.aspects.push(AspectWrite::new(tid, Ak::new("/app/title").unwrap(), 1, 2, d));
    }
    b
}

fn dedup(t: &Tid) -> Option<Secret32> {
    TestSecrets { admin: true }.dedup(t)
}

fn build(b: CommitBuilder, sink: &mut MemoryBlobs) -> Result<Built, Error> {
    b.build(&key(), &TestSecrets { admin: true }, sink, &mut rng())
}

// spec/commits.md §1, spec/wire.md §4: a built content commit verifies; its tokens follow the
// untyped `author` retention (levels 1 and 2).
#[test]
fn build_content() {
    let mut sink = MemoryBlobs::default();
    let built = build(content(3), &mut sink).unwrap();
    let c = &built.commit;
    assert!(sink.blobs.is_empty());
    assert_eq!(c.header.aspects.len(), 3);
    assert_eq!(c.header.tokens.iter().filter(|t| t.level == 2).count(), 1);
    assert_eq!(c.header.tokens.len(), 4);
    let back = CommitBlob::decode(&c.encode()).unwrap();
    assert_eq!(&back, c);
    assert_eq!(verify_blob(&back, &key().verifying_key(), &dedup, None).unwrap().len(), 3);
}

// spec/commits.md §2, §6: a membership commit may carry several deltas on one aspect sharing
// its range, and `expires` there is refused; so is `expires` beside a purge request.
#[test]
fn build_membership_and_refusals() {
    let at = ts(1_000_000);
    let mut b = CommitBuilder::new(Kind::Membership, at, t(1), t(2), Form::Node);
    let mut a = AspectWrite::new(t(3), Ak::new("/members").unwrap(), 1, 2, register_delta(t(1), at, 1, "a"));
    a.deltas.push(register_delta(t(1), at, 1, "b"));
    a.retention = retention::MEMBERSHIP_RETENTION;
    b.aspects.push(a);
    let mut sink = MemoryBlobs::default();
    let built = build(b.clone(), &mut sink).unwrap();
    assert_eq!(built.commit.header.aspects[0].hashes.len(), 2);
    assert_eq!(built.commit.header.tokens.len(), 1);
    verify_blob(&built.commit, &key().verifying_key(), &dedup, None).unwrap();
    let mut bad = b.clone();
    bad.aspects[0].expires = Some(at.wall_ms().0 + 10);
    assert!(matches!(build(bad, &mut sink), Err(Error::Build(_))));
    let mut p = content(1);
    p.aspects[0].expires = Some(at.wall_ms().0 + 10);
    p.purge.push(PurgeItem::Aspect { tid: t(9), ak: Ak::new("/app/title").unwrap() });
    assert!(matches!(build(p.clone(), &mut sink), Err(Error::Build(_))));
    p.aspects[0].expires = None;
    let built = build(p, &mut sink).unwrap();
    assert_eq!(retention::purge_keep_until(&built.commit.header), Some(at.wall_ms().0 + osis_core::format::MEMBERSHIP_KEEP_MS));
}

// spec/wire.md §4, §6: a list above CHUNK_THRESHOLD goes by link to a chunk tree keyed by the
// actor's dedup secret; a decoder resolves it and gets the same header and commit ID.
#[test]
fn list_overflow_links() {
    let mut sink = MemoryBlobs::default();
    let built = build(content(2000), &mut sink).unwrap();
    let h = &built.commit.header;
    assert!(h.links.aspects.is_some());
    assert!(h.links.tokens.is_none());
    assert!(!built.list_blobs.is_empty());
    assert_eq!(built.list_blobs.len(), sink.blobs.len());
    assert!(h.encode().len() < CHUNK_THRESHOLD);
    // over 16 tokens: header-list blobs carry the level-2 commitment only
    for (p, _) in sink.blobs.values() {
        assert_eq!(p.commitments.len(), 1);
        assert_eq!(p.commitments[0][0], 2);
    }
    let bytes = built.commit.encode();
    let mut back = CommitBlob::decode(&bytes).unwrap();
    assert!(!back.header.is_resolved());
    assert!(matches!(back.header.validate(), Err(Error::Missing)));
    assert!(matches!(back.header.resolve(&mut MemoryBlobs::default(), &sec(0xd0, &t(2))), Err(Error::Missing)));
    assert!(matches!(back.header.resolve(&mut sink, &sec(0xd0, &t(9))), Err(Error::Corrupt)));
    back.header.resolve(&mut sink, &sec(0xd0, &t(2))).unwrap();
    assert_eq!(&back, &built.commit);
    assert_eq!(back.id(), built.commit.id());
    verify_blob(&back, &key().verifying_key(), &dedup, None).unwrap();
}

// spec/wire.md §4: a linked list at or below the threshold is rejected.
#[test]
fn small_linked_list_rejected() {
    let mut sink = MemoryBlobs::default();
    let built = build(content(2), &mut sink).unwrap();
    let mut h = built.commit.header.clone();
    let bytes = osis_core::encode(&h.list_value(ListField::Aspects).unwrap());
    let d = sec(0xd0, &t(2));
    let mut salt = 0u8;
    let link = write_tree(&bytes, &d, &mut sink, &mut || {
        salt += 1;
        Ok(Prefix { salt: [salt; 16], expiry: None, commitments: vec![] })
    })
    .unwrap();
    assert_eq!(read_tree(&link, &d, &mut sink).unwrap(), bytes);
    h.links.aspects = Some(link);
    let mut back = Header::decode(&h.encode()).unwrap();
    assert!(back.aspects.is_empty());
    assert!(matches!(back.resolve(&mut sink, &d), Err(Error::Malformed(_))));
}

fn mixed() -> CommitBlob {
    let mut b = content(6);
    for (i, a) in b.aspects.iter_mut().enumerate() {
        // one thing, so the token sets differ only by retention
        a.tid = t(3);
        a.ak = Ak::new(format!("/app/f{i}")).unwrap();
        if i % 2 == 1 {
            a.retention = Retention { by: PurgeBy::Writer, ..Default::default() };
        }
        if i == 5 {
            a.expires = Some(9_000_000_000);
        }
    }
    build(b, &mut MemoryBlobs::default()).unwrap().commit
}

// spec/sync.md §3: one blob per (readable subset, retention class); the projections partition
// the commit's deltas and each verifies alone with the prefix inputs its class calls for.
#[test]
fn projection_partitions() {
    let c = mixed();
    let readers = |ai: usize| ai.is_multiple_of(3);
    let ps = project(&c, readers).unwrap();
    let mut all: Vec<(usize, usize)> = ps.iter().flat_map(|p| p.parts.clone()).collect();
    all.sort();
    assert_eq!(all, (0..6).map(|i| (i, 0)).collect::<Vec<_>>());
    assert_eq!(ps.len(), 5);
    for p in &ps {
        let blob = CommitBlob::decode(&p.plaintext).unwrap();
        assert_eq!(blob.id(), c.id());
        verify_blob(&blob, &key().verifying_key(), &dedup, None).unwrap();
        assert_eq!(prefix_inputs(&c.header, &p.parts).unwrap(), (p.expires, p.tokens.clone()));
        let levels: Vec<u8> = p.tokens.iter().map(|t| t.level).collect();
        assert!(levels.windows(2).all(|w| w[0] < w[1]), "at most one commitment per level");
        for (ai, _) in &p.parts {
            assert_eq!(readers(*ai), p.readers);
        }
    }
    assert!(strict_subset(&ps[0].parts[..0], &ps[0].parts));
    assert!(!strict_subset(&ps[0].parts, &ps[0].parts));
}

fn big_delta(author: Tid, at: Ts, len: usize) -> Vec<u8> {
    let mut w = Writer::new(at, Source::node(author), 1);
    let fragment = create(&mut w, &AnyView, &Value::Bytes(vec![0x5a; len])).unwrap();
    encode_delta(&Delta { nonce: [1; 16], fragment }, &writer_ctx(Kind::Content, at, author, 1, 2), None).unwrap()
}

// spec/sync.md §3: a class above MAX_BLOB splits greedily in aspect-list order; spec/commits.md
// §1: one delta that cannot fit a blob is refused by the writer.
#[test]
fn projection_splits_by_size() {
    let at = ts(1_000_000);
    let mut b = CommitBuilder::new(Kind::Content, at, t(1), t(2), Form::Node);
    for i in 0..4u8 {
        b.aspects.push(AspectWrite::new(t(3), Ak::new(format!("/app/f{i}")).unwrap(), 1, 2, big_delta(t(1), at, 3 << 20)));
    }
    let c = build(b, &mut MemoryBlobs::default()).unwrap().commit;
    let ps = project(&c, |_| ()).unwrap();
    assert_eq!(ps.iter().map(|p| p.parts.clone()).collect::<Vec<_>>(), vec![vec![(0, 0), (1, 0)], vec![(2, 0), (3, 0)]]);
    for p in &ps {
        assert!(p.plaintext.len() < MAX_BLOB);
    }
    let mut huge = CommitBuilder::new(Kind::Content, at, t(1), t(2), Form::Node);
    huge.aspects.push(AspectWrite::new(t(3), Ak::new("/app/f").unwrap(), 1, 2, big_delta(t(1), at, MAX_BLOB)));
    assert!(matches!(build(huge, &mut MemoryBlobs::default()), Err(Error::Build(_))));
}

// spec/commits.md §5: a purge rewrite keeps header and commit ID, drops bodies, may be
// header-only; its prefix inputs follow the remaining parts.
#[test]
fn purge_rewrite() {
    let c = mixed();
    let r = rewrite(&c, |ai, _| ai == 5);
    assert_eq!(r.id(), c.id());
    assert_eq!(r.missing(), vec![(5, 0)]);
    let all = rewrite(&c, |_, _| true);
    assert!(all.parts.is_empty());
    let back = CommitBlob::decode(&all.encode()).unwrap();
    verify_blob(&back, &key().verifying_key(), &dedup, None).unwrap();
    assert_eq!(prefix_inputs(&c.header, &[]).unwrap(), (None, vec![]));
    assert!(matches!(prefix_inputs(&c.header, &[(4, 0), (5, 0)]), Err(Error::Build(_))));
}

// spec/permissions.md §7, spec/wire.md §4: an import carries its origins table, empty ranges,
// no level-2 token; its deltas re-source writes to `Commit(origin)`.
#[test]
fn build_import() {
    let at = ts(2_000_000);
    let origin = CommitId([0x0c; 32]);
    let ots = ts(1_000_000);
    let mut w = Writer::new(ots, Source::commit(origin), 1);
    let fragment = create(&mut w, &AnyView, &Value::Str("moved".into())).unwrap();
    let d = encode_delta(&Delta { nonce: [2; 16], fragment }, &writer_ctx(Kind::Import, at, t(1), 0, 0), None).unwrap();
    let mut b = CommitBuilder::new(Kind::Import, at, t(1), t(2), Form::Node);
    let mut a = AspectWrite::new(t(3), Ak::new("/app/title").unwrap(), 0, 0, d);
    a.retention = Retention { by: PurgeBy::Writer, ..Default::default() };
    b.aspects.push(a);
    b.origins.push(Origin { commit: origin, author: t(5), actor: t(6), ts: ots });
    let c = build(b, &mut MemoryBlobs::default()).unwrap().commit;
    assert_eq!(c.header.tokens.iter().map(|t| t.level).collect::<Vec<_>>().len(), 2);
    assert!(c.header.tokens.iter().all(|t| t.level != 2));
    assert_eq!(c.header.origins.len(), 1);
    verify_blob(&c, &key().verifying_key(), &dedup, None).unwrap();
}

// spec/wire.md §4, spec/crypto.md §7: the chunk list holds, per introduced blob, one chunk
// token hash per token secret of its delta under the chunk's own prefix salt, indexed into the
// header tokens; the chunk's prefix commitments verify those tokens.
#[test]
fn chunk_list() {
    let mut b = content(1);
    b.aspects[0].retention = Retention { by: PurgeBy::Writer, ..Default::default() };
    b.aspects[0].chunks = vec![(osis_core::BlobId([9; 32]), [1; 16]), (osis_core::BlobId([3; 32]), [2; 16])];
    let built = build(b, &mut MemoryBlobs::default()).unwrap();
    let h = &built.commit.header;
    assert_eq!(h.chunks.iter().map(|c| c.blob.0[0]).collect::<Vec<_>>(), vec![3, 9]);
    let secs = &built.aspect_tokens[0];
    assert_eq!(secs.len(), 3);
    for (c, salt) in h.chunks.iter().zip([[2u8; 16], [1; 16]]) {
        assert_eq!(c.tokens.len(), 3);
        let prefix = Prefix::for_chunk(salt, None, secs).unwrap();
        for ((ti, th), s) in c.tokens.iter().zip(secs) {
            assert_eq!(h.tokens[*ti].level, s.level);
            assert_eq!(*th, s.hash(&salt).hash);
            let token = osis_crypto::delete_token(&s.secret, &salt);
            assert!(prefix.commitments.iter().any(|x| osis_crypto::verify_presented_token(token.expose(), x, &salt)));
        }
    }
}

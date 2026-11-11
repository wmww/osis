//! Builder, header-list links, sections, purge rewrite (spec/commits.md §1, §5; spec/wire.md
//! §4, §6; spec/sync.md §3).

use crate::tests::{SESSION, t, ts};
use crate::tests::verify::{TestSecrets, register_delta, sec};
use crate::*;
use osis_base::format::{CHUNK_THRESHOLD, MAX_BLOB};
use osis_base::{Ak, CommitId, Tid, Ts, Value};
use osis_crdt::{AnyView, Delta, Writer, create, encode_delta};
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
    let mut b = CommitBuilder::new(Kind::Content, at, t(1), t(2), SESSION);
    for i in 0..n {
        let d = register_delta(t(1), at, 1, &format!("v{i}"));
        let tid = Tid::from_bytes([(i % 251) as u8, (i / 251) as u8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]);
        b.aspects.push(AspectWrite::new(tid, Ak::new("app:title.0").unwrap(), 1, 2, d));
    }
    b
}

fn dedup(t: &Tid) -> Option<Secret32> {
    TestSecrets { admin: true }.dedup(t)
}

fn build(b: CommitBuilder, sink: &mut MemoryBlobs) -> Result<Built, Error> {
    b.build(&key(), &TestSecrets { admin: true }, sink, &mut rng())
}

// spec/commits.md §1, §5, spec/wire.md §4: a built content commit verifies; its delete keys follow the
// untyped `admin` retention (level 1, one per thing).
#[test]
fn build_content() {
    let mut sink = MemoryBlobs::default();
    let built = build(content(3), &mut sink).unwrap();
    let c = &built.commit;
    assert!(sink.blobs.is_empty());
    assert_eq!(c.header.aspects.len(), 3);
    assert!(c.header.keys.iter().all(|t| t.level == 1));
    assert_eq!(c.header.keys.len(), 3);
    let back = CommitBlob::decode(&c.encode()).unwrap();
    assert_eq!(&back, c);
    assert_eq!(verify_blob(&back, &key().verifying_key(), &dedup, None).unwrap().len(), 3);
}

// spec/commits.md §2, §6: a role commit's `expires` is refused; so is `expires` beside a purge
// request.
#[test]
fn build_role_commit_and_refusals() {
    let at = ts(1_000_000);
    let mut b = CommitBuilder::new(Kind::Role, at, t(1), t(1), Form::Commit);
    // empty `roles.0` maps: a core-aspect delta must fit the core type
    let roles = |nonce: u8| {
        let mut w = Writer::new(at, Form::Commit.own_source(t(1), CommitId([0; 32])), 1);
        let fragment = create(&mut w, &AnyView, &Value::Map(Default::default())).unwrap();
        encode_delta(&Delta { nonce: [nonce; 16], fragment }, &writer_ctx(Form::Commit, Kind::Role, at, t(1), 1, 2), None).unwrap()
    };
    let mut a = AspectWrite::new(t(3), Ak::new("roles.0").unwrap(), 1, 2, roles(1));
    a.retention = retention::ROLE_RETENTION;
    b.aspects.push(a);
    let mut sink = MemoryBlobs::default();
    let built = build(b.clone(), &mut sink).unwrap();
    assert_eq!(built.commit.header.keys.len(), 1);
    verify_blob(&built.commit, &key().verifying_key(), &dedup, None).unwrap();
    let mut bad = b.clone();
    bad.expires = Some(at.wall_ms().0 + 10);
    assert!(matches!(build(bad, &mut sink), Err(Error::Build(_))));
    let mut p = content(1);
    p.expires = Some(at.wall_ms().0 + 10);
    p.purge.push(PurgeItem::Aspect { tid: t(9), ak: Ak::new("app:title.0").unwrap() });
    assert_eq!(retention::purge_keep_until(&build(p.clone(), &mut sink).unwrap().commit.header), p.expires);
    p.expires = None;
    let built = build(p, &mut sink).unwrap();
    assert_eq!(retention::purge_keep_until(&built.commit.header), Some(at.wall_ms().0 + osis_base::format::ROLE_KEEP_MS));
}

// spec/wire.md §4, §6: a list above CHUNK_THRESHOLD goes by link to a chunk tree keyed by the
// actor's dedup secret; a decoder resolves it and gets the same header and commit ID.
#[test]
fn list_overflow_links() {
    let mut sink = MemoryBlobs::default();
    let mut b = content(2000);
    // a level-2 key listed, which the list blobs commit to alone
    for a in &mut b.aspects {
        a.retention = Retention { by: PurgeBy::AuthorOrAdmin };
    }
    let built = build(b, &mut sink).unwrap();
    let h = &built.commit.header;
    assert!(h.links.aspects.is_some());
    assert!(h.links.keys.is_none());
    assert!(!built.list_blobs.is_empty());
    assert_eq!(built.list_blobs.len(), sink.blobs.len());
    assert!(h.encode().len() < CHUNK_THRESHOLD);
    // header-list blobs carry the level-2 commitment only (spec/wire.md §5), under the header's blind
    for (p, _) in sink.blobs.values() {
        assert_eq!(p.keys.iter().map(|k| k.level).collect::<Vec<_>>(), vec![2]);
        assert_eq!(p.blind, h.blind);
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

// A list no receiver would resolve (`MAX_LIST_BYTES`) fails at its author, so a demotion's frontier
// too large stamps nothing only the author could apply.
#[test]
fn list_over_the_bound_refused_at_the_author() {
    let at = ts(1_000_000);
    let mut b = CommitBuilder::new(Kind::Role, at, t(1), t(1), Form::Commit);
    let mut a = AspectWrite::new(t(3), Ak::new("roles.0").unwrap(), 1, 2, register_delta(t(1), at, 1, "a"));
    a.retention = retention::ROLE_RETENTION;
    b.aspects.push(a);
    let mut sink = MemoryBlobs::default();
    // the bound's bytes as one value, and one past it
    let of = |n: usize| Value::Bytes(vec![0; n]);
    let room = MAX_LIST_BYTES + MAX_LIST_BYTES - osis_base::encode(&of(MAX_LIST_BYTES)).len();
    let mut fits = b.clone();
    fits.frontier = Some(of(room));
    assert_eq!(osis_base::encode(fits.frontier.as_ref().unwrap()).len(), MAX_LIST_BYTES);
    let built = build(fits, &mut sink).unwrap();
    let link = built.commit.header.links.frontier.expect("linked");
    assert_eq!(read_list(&link, &sec(0xd0, &t(1)), &mut sink, MAX_LIST_BYTES).unwrap().len(), MAX_LIST_BYTES);
    let mut over = b;
    over.frontier = Some(of(room + 1));
    assert!(matches!(build(over, &mut sink), Err(Error::TooLarge("header list"))));
    // a hand-built commit past the bound is bad input at every receiver, not a local refusal
    let d = sec(0xd0, &t(1));
    let mut prefix = || crate::keys::Prefix { salt: [7; 16], blind: [0; 16], expiry: None, keys: Vec::new() };
    let big = write_list(&osis_base::encode(&of(room + 1)), &d, &mut sink, &mut prefix).unwrap();
    let mut h = built.commit.header.clone();
    h.frontier = None;
    h.links.frontier = Some(big);
    let e = h.resolve(&mut sink, &d).unwrap_err();
    assert!(matches!(e, Error::Invalid(_)), "{e:?}");
    assert_eq!(osis_base::Classified::class(&e), osis_base::ErrorClass::BadInput);
}

// spec/wire.md §4: a linked list at or below the threshold is rejected.
#[test]
fn small_linked_list_rejected() {
    let mut sink = MemoryBlobs::default();
    let built = build(content(2), &mut sink).unwrap();
    let mut h = built.commit.header.clone();
    let bytes = osis_base::encode(&h.list_value(ListField::Aspects).unwrap());
    let d = sec(0xd0, &t(2));
    let mut salt = 0u8;
    let link = write_list(&bytes, &d, &mut sink, &mut || {
        salt += 1;
        Prefix { salt: [salt; 16], blind: [0; 16], expiry: None, keys: vec![] }
    })
    .unwrap();
    assert_eq!(read_list(&link, &d, &mut sink, MAX_LIST_BYTES).unwrap(), bytes);
    h.links.aspects = Some(link);
    let mut back = Header::decode(&h.encode()).unwrap();
    assert!(back.aspects.is_empty());
    assert!(matches!(back.resolve(&mut sink, &d), Err(Error::Malformed(_))));
}

fn mixed() -> CommitBlob {
    let mut b = content(6);
    for (i, a) in b.aspects.iter_mut().enumerate() {
        // one thing, so the key sets differ only by retention
        a.tid = t(3);
        a.ak = Ak::new(format!("app:f{i}.0")).unwrap();
        if i % 2 == 1 {
            a.retention = Retention { by: PurgeBy::Writer };
        }
    }
    b.expires = Some(9_000_000_000);
    build(b, &mut MemoryBlobs::default()).unwrap().commit
}

// spec/wire.md §4, spec/sync.md §3: one blob per commit, one section per reader actor; a
// reader opens its section and nothing else (invariant: a non-reader learns only the `ai`
// list and the size), the opened parts verify alone, a sealed section is copied verbatim into
// a fresh encryption and still opens there; the prefix groups are the distinct key sets.
#[test]
fn sections_per_reader_actor() {
    let c = mixed();
    let reader = |ai: usize| u8::from(ai.is_multiple_of(3));
    let secret = |r: &u8| Secret32::from_bytes([*r + 1; 32]);
    let mut rng = SeededRng::from_u64(0);
    let env = seal_commit(&c, reader, |r, _| Some((secret(r), vec![])), &[], &mut rng).unwrap();
    assert_eq!(env.id(), c.id());
    assert_eq!(env.sections.len(), 2);
    assert_eq!(env.sections[0].ais, vec![0, 3]);
    assert_eq!(env.sections[1].ais, vec![1, 2, 4, 5]);
    let back = Envelope::decode(&env.encode()).unwrap();
    assert_eq!(back, env);
    // reader 1 opens its section alone; reader 0 (the other secret) its own; nobody neither
    let o1 = env.open(|_| vec![secret(&1)]).unwrap();
    assert_eq!(o1.commit.parts.iter().map(|p| p.ai).collect::<Vec<_>>(), vec![0, 3]);
    assert_eq!(o1.sealed.len(), 1);
    verify_blob(&o1.commit, &key().verifying_key(), &dedup, None).unwrap();
    assert_eq!(CommitBlob::decode(&o1.commit.encode()).unwrap(), o1.commit);
    let o0 = env.open(|s| if s.ais.contains(&1) { vec![Secret32::from_bytes([9; 32]), secret(&0)] } else { vec![] }).unwrap();
    assert_eq!(o0.commit.parts.iter().map(|p| p.ai).collect::<Vec<_>>(), vec![1, 2, 4, 5]);
    let none = env.open(|_| vec![Secret32::from_bytes([9; 32])]).unwrap();
    assert!(none.commit.parts.is_empty() && none.sealed.len() == 2);
    // a fresh encryption by reader 1 carries reader 0's section byte for byte
    let again = seal_commit(&o1.commit, reader, |r, _| Some((secret(r), vec![])), &o1.sealed, &mut rng).unwrap();
    assert_eq!(again.sections[1], env.sections[1]);
    assert_ne!(again.sections[0], env.sections[0], "a fresh section key and wrap");
    let o = again.open(|_| vec![secret(&0), secret(&1)]).unwrap();
    assert_eq!(o.commit, c);
    // the section key encrypts one plaintext under the commit's ID only: another commit ID or
    // a byte of the wrap or ciphertext changed opens nothing
    let mut other = env.clone();
    other.header.blind = [0xee; 16];
    assert!(other.open(|_| vec![secret(&1)]).unwrap().commit.parts.is_empty());
    let mut bent = env.clone();
    bent.sections[0].ciphertext[3] ^= 1;
    assert!(bent.open(|_| vec![secret(&1)]).is_err());
    let mut bent = env.clone();
    bent.sections[0].wrap[30] ^= 1;
    assert!(bent.open(|_| vec![secret(&1)]).unwrap().commit.parts.is_empty());
    // a section whose list disagrees with its parts is bad input
    let mut lied = env.clone();
    lied.sections[0].ais = vec![0];
    assert!(lied.open(|_| vec![secret(&1)]).is_err());
    // the prefix groups: the two key sets of `mixed` (alternating retention), by first aspect
    let groups = prefix_groups(&c.header, env.ais()).unwrap();
    assert_eq!(groups.len(), 2);
    assert_eq!(groups, prefix_groups(&c.header, [0, 1]).unwrap());
    assert_eq!(prefix_groups(&c.header, [1, 0]).unwrap(), groups);
    assert!(prefix_groups(&c.header, []).unwrap().is_empty());
    assert!(prefix_groups(&c.header, [6]).is_err());
    assert!(strict_subset(&[], &[0]));
    assert!(!strict_subset(&[0], &[0]));
}

// spec/wire.md §4: sections sorted by first aspect, no aspect twice, a wrap of its length.
#[test]
fn envelope_rejections() {
    let c = mixed();
    let mut rng = SeededRng::from_u64(0);
    let env = seal_commit(&c, |ai| ai % 2, |_, _| Some((Secret32::from_bytes([1; 32]), vec![])), &[], &mut rng).unwrap();
    let mut swapped = env.clone();
    swapped.sections.swap(0, 1);
    assert!(Envelope::decode(&swapped.encode()).is_err());
    let mut twice = env.clone();
    twice.sections[1].ais = vec![0, 1];
    assert!(Envelope::decode(&twice.encode()).is_err());
    // a derivation chain rides in the clear and round-trips; one past MAX_CHAIN_DEPTH, or listing a
    // tid twice (a reader would derive through it again and again), is bad input
    let mut chain = env.clone();
    chain.sections[0].chain = vec![t(7), t(8)];
    assert_eq!(Envelope::decode(&chain.encode()).unwrap(), chain);
    chain.sections[0].chain = (0..=osis_base::format::MAX_CHAIN_DEPTH as u8).map(t).collect();
    assert!(Envelope::decode(&chain.encode()).is_err());
    chain.sections[0].chain = vec![t(7), t(8), t(7)];
    assert!(Envelope::decode(&chain.encode()).is_err());
    let mut short = env.clone();
    short.sections[0].wrap.pop();
    assert!(Envelope::decode(&short.encode()).is_err());
    // a section whose secret is not held is left out
    assert!(seal_commit(&c, |_| (), |_, _| None::<(Secret32, Vec<osis_base::Tid>)>, &[], &mut rng).unwrap().sections.is_empty());
    assert_eq!(seal_commit(&c, |ai| ai % 2, |r, _| (*r == 0).then(|| (Secret32::from_bytes([1; 32]), vec![])), &[], &mut rng).unwrap().ais(), vec![0, 2, 4]);
    // an extra section on an aspect a sealed part is on is dropped, one clashing with another
    // extra is bad input
    let extra = env.sections[1].clone();
    let one = seal_commit(&c, |_| (), |_, _| Some((Secret32::from_bytes([2; 32]), vec![])), std::slice::from_ref(&extra), &mut rng).unwrap();
    assert_eq!(one.sections.len(), 1);
    assert!(seal_commit(&rewrite(&c, |_| true), |_| (), |_, _| Some((Secret32::from_bytes([2; 32]), vec![])), &[extra.clone(), extra], &mut rng).is_err());
}

fn big_delta(author: Tid, at: Ts, len: usize) -> Vec<u8> {
    let mut w = Writer::new(at, SESSION.own_source(author, CommitId([0; 32])), 1);
    let fragment = create(&mut w, &AnyView, &Value::Bytes(vec![0x5a; len])).unwrap();
    encode_delta(&Delta { nonce: [1; 16], fragment }, &writer_ctx(SESSION, Kind::Content, at, author, 1, 2), None).unwrap()
}

// spec/sync.md §3 (no size split), spec/commits.md §1 (commit fits a blob): the whole commit
// must fit one blob: two 3 MiB deltas do, four do not; a delta over MAX_BLOB (a caller's
// mistake: a value left unchunked) is refused.
#[test]
fn commit_fits_one_blob() {
    let at = ts(1_000_000);
    let mut b = CommitBuilder::new(Kind::Content, at, t(1), t(2), SESSION);
    for i in 0..2u8 {
        b.aspects.push(AspectWrite::new(t(3), Ak::new(format!("app:f{i}.0")).unwrap(), 1, 2, big_delta(t(1), at, 3 << 20)));
    }
    let c = build(b, &mut MemoryBlobs::default()).unwrap().commit;
    assert!(blob_bound(&c) < MAX_BLOB);
    let mut b = CommitBuilder::new(Kind::Content, at, t(1), t(2), SESSION);
    for i in 0..4u8 {
        b.aspects.push(AspectWrite::new(t(3), Ak::new(format!("app:f{i}.0")).unwrap(), 1, 2, big_delta(t(1), at, 3 << 20)));
    }
    assert!(matches!(build(b, &mut MemoryBlobs::default()), Err(Error::Build(COMMIT_PAST_BLOB))));
    let mut huge = CommitBuilder::new(Kind::Content, at, t(1), t(2), SESSION);
    huge.aspects.push(AspectWrite::new(t(3), Ak::new("app:f.0").unwrap(), 1, 2, big_delta(t(1), at, MAX_BLOB)));
    assert!(matches!(build(huge, &mut MemoryBlobs::default()), Err(Error::Build(_))));
}

/// A struct of string registers (spec/crdt.md §3.1).
struct Wide(bool);

impl osis_crdt::View for Wide {
    fn encoding(&self) -> Option<osis_crdt::Encoding> {
        Some(if self.0 { osis_crdt::Encoding::Struct } else { osis_crdt::Encoding::Register })
    }
    fn project<'a>(&self, v: &'a Value) -> Option<std::borrow::Cow<'a, Value>> {
        Some(std::borrow::Cow::Borrowed(v))
    }
    fn field(&self, _: u64) -> Option<Wide> {
        self.0.then_some(Wide(false))
    }
    fn field_default(&self, _: u64) -> Option<Value> {
        None
    }
    fn case(&self, _: u64) -> Option<Wide> {
        None
    }
    fn element(&self) -> Option<Wide> {
        None
    }
    fn key(&self) -> Option<Wide> {
        None
    }
}

// spec/commits.md §1 (delta fits a blob), spec/crdt.md §8: a struct of many registers just
// under the chunk threshold pages its field map, so its delta fits a blob; left unpaged it would
// not and is refused. A small blob bound and page parameters stand in for the format's (65
// fields, MAX_BLOB / 64 each).
#[test]
fn wide_struct_delta_fits_spec_commits_1() {
    use osis_crdt::{MemoryPages, PageParams};
    let at = ts(1_000_000);
    let max_blob = 64 << 10;
    let v = Value::Map((0..65).map(|i| (Value::Int(i), Value::Str("w".repeat(max_blob / 64 - 16)))).collect());
    let mut w = Writer::new(at, SESSION.own_source(t(1), CommitId([0; 32])), 1);
    let fragment = create(&mut w, &Wide(true), &v).unwrap();
    let hi = w.range().hi;
    let small = PageParams { target: 4096, cut: osis_base::ChunkParams { min: 1024, max: 4096, mask_bits: 8 }, fanout: 8, ..PageParams::FORMAT };
    let enc = |params: PageParams| {
        let mut pages = MemoryPages::with_params(params);
        encode_delta(&Delta { nonce: [1; 16], fragment: fragment.clone() }, &writer_ctx(SESSION, Kind::Content, at, t(1), 1, hi), Some(&mut pages)).unwrap()
    };
    let attempt = |delta: Vec<u8>| {
        let mut b = CommitBuilder::new(Kind::Content, at, t(1), t(2), SESSION);
        b.max_blob = max_blob;
        b.aspects.push(AspectWrite::new(t(3), Ak::new("app:w.0").unwrap(), 1, hi, delta));
        build(b, &mut MemoryBlobs::default())
    };
    let paged = enc(small);
    assert!(paged.len() <= small.target);
    attempt(paged).unwrap();
    assert!(matches!(attempt(enc(PageParams { target: usize::MAX, ..small })), Err(Error::Build(_))));
}

// spec/commits.md §5: a purge rewrite keeps header and commit ID, drops bodies, may be
// header-only; its prefix inputs follow the remaining parts.
#[test]
fn purge_rewrite() {
    let c = mixed();
    let r = rewrite(&c, |ai| ai == 5);
    assert_eq!(r.id(), c.id());
    assert_eq!(r.missing(), vec![5]);
    let all = rewrite(&c, |_| true);
    assert!(all.parts.is_empty());
    let back = CommitBlob::decode(&all.encode()).unwrap();
    verify_blob(&back, &key().verifying_key(), &dedup, None).unwrap();
    assert!(prefix_groups(&c.header, r.parts.iter().map(|p| p.ai)).unwrap().len() == 2);
    assert!(prefix_groups(&c.header, []).unwrap().is_empty());
}

// spec/wire.md §4, §5: the chunk list holds, per introduced blob, the indices of its delta's
// delete keys in the header.
#[test]
fn chunk_list() {
    let mut b = content(1);
    b.aspects[0].retention = Retention { by: PurgeBy::Writer };
    b.aspects[0].chunks = vec![osis_base::BlobId([9; 32]), osis_base::BlobId([3; 32])];
    let built = build(b, &mut MemoryBlobs::default()).unwrap();
    let h = &built.commit.header;
    assert_eq!(h.chunks.iter().map(|c| c.blob.0[0]).collect::<Vec<_>>(), vec![3, 9]);
    for c in &h.chunks {
        assert_eq!(c.keys, h.aspects[0].keys);
        let keys: Vec<DeleteKey> = c.keys.iter().map(|i| h.keys[*i]).collect();
        assert_eq!(keys.iter().map(|k| k.level).collect::<Vec<_>>(), vec![1, 2, 3]);
    }
}

// spec/commits.md §1 (the whole commit fits `MAX_BLOB`, or the writer refuses it): the
// writer's bound counts a section per thing and a commitment group per key set, not per
// aspect: 2500 things of three writes each build, and seal well within it.
#[test]
fn many_writes_per_thing_fit_one_blob() {
    let mut b = content(7500);
    for (i, a) in b.aspects.iter_mut().enumerate() {
        a.tid = Tid::from_bytes([(i / 3 % 251) as u8, (i / 3 / 251) as u8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8]);
        a.ak = Ak::new(format!("app:f{}.0", i % 3)).unwrap();
    }
    let c = build(b, &mut MemoryBlobs::default()).unwrap().commit;
    assert!(blob_bound(&c) <= MAX_BLOB);
    let things: Vec<Tid> = c.header.aspects.iter().map(|a| a.tid).collect();
    let mut rng = SeededRng::from_u64(0);
    let env = seal_commit(&c, |ai| things[ai], |_, _| Some((Secret32::from_bytes([1; 32]), vec![t(9); osis_base::format::MAX_CHAIN_DEPTH])), &[], &mut rng).unwrap();
    assert_eq!(env.sections.len(), 2500);
    let groups = prefix_groups(&c.header, env.ais()).unwrap();
    let prefix = osis_base::format::PREFIX_FIXED_LEN + groups.iter().map(|g| 1 + g.len() * osis_base::format::COMMITMENT_LEN).sum::<usize>();
    assert!(osis_crypto::blob_len(prefix, env.encode().len()) <= blob_bound(&c), "the bound bounds");
}

// spec: none (forensic test support): `Section::may_open_with` never rules out a section's own
// key, at part counts past one byte's CBOR head too, and rules out most other keys
#[test]
fn section_key_filter_keeps_the_key() {
    let (commit, secret) = (CommitId([4; 32]), Secret32::from_bytes([1; 32]));
    let mut rng = SeededRng::from_u64(0);
    let mut wrong = 0;
    for n in [0usize, 1, 3, 23, 24, 30] {
        let parts: Vec<Part> = (0..n).map(|ai| Part::new(ai * 30, osis_base::encode(&Value::Int(ai as i64)))).collect();
        let s = Section::seal(&commit, &parts, vec![t(1)], &secret, &mut rng).unwrap();
        let key = osis_crypto::unwrap_section(&secret, &commit, &s.wrap).unwrap();
        assert!(s.may_open_with(key.expose()), "{n} parts");
        wrong += (0..64u8).filter(|i| s.may_open_with(&[*i; 32])).count();
    }
    assert!(wrong < 64, "{wrong} of {} wrong keys pass", 6 * 64);
}

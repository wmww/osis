//! `commit/`: commit headers, commit IDs, signatures and commit blob plaintexts (spec/wire.md §4,
//! spec/commits.md). Generated.

use super::{FixedRng, case, generated_header, s32};
use crate::file::{Record, VecFile};
use crate::hex;
use osis_commit::*;
use osis_base::{Ak, CommitId, Tid, Ts, Value, WallMs};
use osis_crdt::{AnyView, Delta, Frontiers, Snapshot, Source, Writer, create, encode_delta, encode_snapshot};
use osis_crypto::{Secret32, SigningSecret};
use osis_schema::{PurgeBy, Retention};

const SPEC: &str = "spec/wire.md §4";

struct VSecrets;

impl Secrets for VSecrets {
    fn dedup(&self, _: &Tid) -> Option<Secret32> {
        Some(s32(0x30))
    }
    fn admin_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&s32(0x31)).verifying_key())
    }
    fn purge_author_key(&self) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&s32(0x32)).verifying_key())
    }
    fn write_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&s32(0x33)).verifying_key())
    }
}

const SIGNER: Tid = Tid::from_bytes([0x21; 15]);
/// The thing the content commits' paths list (spec/wire.md §4 field 2).
const LISTED: Tid = Tid::from_bytes([0x22; 15]);
const THING: Tid = Tid::from_bytes([0x23; 15]);
const BLIND: [u8; 16] = [0x34; 16];
/// The signer's session nonce (spec/crdt.md §2.1).
const NONCE: [u8; osis_crdt::SESSION_NONCE_LEN] = [0x28; osis_crdt::SESSION_NONCE_LEN];
const SESSION: Form = Form::Session(NONCE);

fn ts(wall: u64) -> Ts {
    Ts::make(WallMs(wall), 0).unwrap()
}

/// The own source of a commit of `form` by the signer (commit form: the placeholder).
fn own(form: Form) -> Source {
    form.own_source(SIGNER, CommitId([0; 32]))
}

/// A writer's delta of one register write under the own source of `form`.
fn delta(form: Form, kind: Kind, at: Ts, lo: u64, v: Value, nonce: u8) -> Vec<u8> {
    let mut w = Writer::new(at, own(form), lo);
    let fragment = create(&mut w, &AnyView, &v).unwrap();
    encode_delta(&Delta { nonce: [nonce; 16], fragment }, &writer_ctx(form, kind, at, SIGNER, lo, lo + 1), None).unwrap()
}

/// `delta` of core aspect `ak`, written through its core type (a core-aspect delta must fit it,
/// spec/crdt.md §3.3 rule 7).
fn core_delta(ak: &str, form: Form, kind: Kind, at: Ts, lo: u64, v: Value, nonce: u8) -> Vec<u8> {
    let mut w = Writer::new(at, own(form), lo);
    let fragment = create(&mut w, &osis_schema::core_schema().view(ak).unwrap(), &v).unwrap();
    encode_delta(&Delta { nonce: [nonce; 16], fragment }, &writer_ctx(form, kind, at, SIGNER, lo, lo + 1), None).unwrap()
}

/// A `roles.0` value granting `role` (an enum case id) to the tid of bytes `m`.
fn grant(m: u8, role: u64) -> Value {
    let edge = Value::Map([(Value::Int(0), Value::Enum(role, None))].into_iter().collect());
    Value::Map([(Value::Weak(Tid::from_bytes([m; 15])), edge)].into_iter().collect())
}

fn built(b: CommitBuilder) -> CommitBlob {
    let key = SigningSecret::from_seed(&s32(0x35));
    let c = b.build(&key, &VSecrets, &mut MemoryBlobs::default(), &mut FixedRng::new(&[&BLIND])).unwrap().commit;
    let dedup = |_: &Tid| Some(s32(0x30));
    verify_blob(&c, &key.verifying_key(), &dedup, None).unwrap();
    c
}

fn record(name: &str, spec: &str, c: &CommitBlob) -> Record {
    let mut r = case(name, spec)
        .with("signing-seed", hex(s32(0x35).expose()))
        .with("dedup", hex(s32(0x30).expose()))
        .with("delete-secrets", format!("1:{} 2:{} 3:{}", hex(s32(0x31).expose()), hex(s32(0x32).expose()), hex(s32(0x33).expose())))
        .with("blind", hex(&BLIND));
    for p in &c.parts {
        r = r.with(&format!("delta-{}", p.ai), hex(&p.delta));
    }
    r.with("header", hex(&c.header.encode()))
        .with("commit-id", hex(&c.id().0))
        .with("signature", hex(&c.sigs.signature.0))
        .with("blob", hex(&c.encode()))
}

fn content() -> CommitBlob {
    let at = ts(1_700_000_000_000);
    let mut b = CommitBuilder::new(Kind::Content, at, SIGNER, osis_commit::Path::through(LISTED), SESSION);
    let mut a = AspectWrite::new(THING, Ak::new("app:title.0").unwrap(), 1, 2, delta(SESSION, Kind::Content, at, 1, Value::Str("hello".into()), 1));
    // two delete keys (admin, author), so their order is a case
    a.retention = Retention { by: PurgeBy::AuthorOrAdmin };
    b.aspects.push(a);
    built(b)
}

fn role_commit() -> CommitBlob {
    built(role_builder())
}

fn role_builder() -> CommitBuilder {
    let at = ts(1_700_000_001_000);
    let mut b = CommitBuilder::new(Kind::Role, at, SIGNER, osis_commit::Path::default(), Form::Commit);
    let mut a = AspectWrite::new(THING, Ak::new("roles.0").unwrap(), 1, 2, core_delta("roles.0", Form::Commit, Kind::Role, at, 1, grant(0x41, 1), 2));
    a.retention = retention::ROLE_RETENTION;
    b.aspects.push(a);
    b
}

/// `role_commit` with header flags bit 1 set (spec/wire.md §4 field 18).
fn adminless_role_commit() -> CommitBlob {
    let mut b = role_builder();
    b.adminless = true;
    built(b)
}

/// A compaction snapshot carrying the author's session's write (spec/crdt.md §8: its frontier
/// names that session, which occurs in the fragment).
fn snapshot() -> CommitBlob {
    let at = ts(1_700_000_002_000);
    let mut w = Writer::new(ts(1_700_000_000_000), own(SESSION), 1);
    let fragment = create(&mut w, &AnyView, &Value::Str("hello".into())).unwrap();
    let frontiers = Frontiers { sessions: [(osis_crdt::Session { node: SIGNER, nonce: NONCE }, 1)].into_iter().collect() };
    let s = Snapshot { absorbed: Default::default(), facts: Default::default(), nonce: [4; 16], fragment, frontiers };
    let bytes = encode_snapshot(&s, &writer_ctx(Form::Commit, Kind::ContentSnapshot, at, SIGNER, 0, 0), None).unwrap();
    let mut b = CommitBuilder::new(Kind::ContentSnapshot, at, SIGNER, osis_commit::Path::through(LISTED), Form::Commit);
    let mut a = AspectWrite::new(THING, Ak::new("app:title.0").unwrap(), 0, 0, bytes);
    a.retention = retention::snapshot_retention("app:title.0");
    b.aspects.push(a);
    built(b)
}

/// An ephemeral commit (spec/commits.md §2): a commit-form content snapshot with the marker,
/// carrying a write under a session of its author (spec/crdt.md §2.1) and that session's frontier.
fn ephemeral(class: osis_commit::EphClass) -> CommitBlob {
    let at = ts(1_700_000_004_000);
    let session = osis_crdt::Session { node: SIGNER, nonce: [0x27; osis_crdt::SESSION_NONCE_LEN] };
    let mut w = Writer::new(ts(1_700_000_003_500), Source::session(session), 1);
    let fragment = create(&mut w, &AnyView, &Value::Str("typing".into())).unwrap();
    let frontiers = Frontiers { sessions: [(session, 1)].into_iter().collect() };
    let s = Snapshot { absorbed: Default::default(), facts: Default::default(), nonce: [6; 16], fragment, frontiers };
    let bytes = encode_snapshot(&s, &writer_ctx(Form::Commit, Kind::ContentSnapshot, at, SIGNER, 0, 0), None).unwrap();
    let mut b = CommitBuilder::new(Kind::ContentSnapshot, at, SIGNER, osis_commit::Path::through(LISTED), Form::Commit);
    let mut a = AspectWrite::new(THING, Ak::new("app:state.0").unwrap(), 0, 0, bytes);
    a.retention = Retention { by: PurgeBy::Writer };
    b.aspects.push(a);
    b.ephemeral = Some(class);
    built(b)
}

/// A session-form ephemeral content commit (spec/commits.md §2, §3): its own write under
/// `(Session(author, nonce), 1)`, the nonce in the header's form.
fn session_commit() -> CommitBlob {
    let at = ts(1_700_000_004_500);
    let bytes = delta(SESSION, Kind::Content, at, 1, Value::Str("typing".into()), 11);
    let mut b = CommitBuilder::new(Kind::Content, at, SIGNER, osis_commit::Path::through(LISTED), SESSION);
    let mut a = AspectWrite::new(THING, Ak::new("app:state.0").unwrap(), 1, 2, bytes);
    a.retention = Retention { by: PurgeBy::Writer };
    b.aspects.push(a);
    b.ephemeral = Some(osis_commit::EphClass::Plain);
    built(b)
}

fn reject(name: &str, spec: &str, h: &Header, rule: &str) -> Record {
    let bytes = h.encode();
    let ok = Header::decode(&bytes).and_then(|x| x.validate());
    assert!(ok.is_err(), "{name} must be rejected");
    case(name, spec).with("header", hex(&bytes)).with("reject", rule)
}

pub fn headers() -> VecFile {
    let mut cases = Vec::new();
    let c = content();
    cases.push(record("minimal content commit", "spec/wire.md §4; spec/commits.md §1", &c));
    cases.push(record("role commit", "spec/wire.md §4; spec/commits.md §2", &role_commit()));
    cases.push(record("role commit with the adminless mark", "spec/wire.md §4 field 18; spec/permissions.md §2", &adminless_role_commit()));
    cases.push(record("content compaction snapshot", "spec/wire.md §4; spec/commits.md §2, §5", &snapshot()));
    let e = ephemeral(osis_commit::EphClass::Plain);
    cases.push(record("ephemeral commit", "spec/wire.md §4; spec/commits.md §2", &e));
    cases.push(record("relay-only commit", "spec/wire.md §4; spec/commits.md §2", &ephemeral(osis_commit::EphClass::Relay)));
    cases.push(record("session-form ephemeral content commit", "spec/wire.md §4; spec/commits.md §2, §3", &session_commit()));
    let mut purged = c.clone();
    purged.parts.clear();
    cases.push(case("header-only purge rewrite", "spec/wire.md §4; spec/commits.md §5").with("blob", hex(&purged.encode())).with("commit-id", hex(&c.id().0)));

    let h = &c.header;
    let mut v = osis_base::decode(&h.encode(), &osis_base::Limits::DEFAULT).unwrap();
    if let Value::List(items) = &mut v {
        items[0] = Value::Int(2);
    }
    let bytes = osis_base::encode(&v);
    assert!(matches!(Header::decode(&bytes), Err(Error::UnknownVersion(2))));
    cases.push(case("unknown format version parks", "spec/versioning.md §2").with("header", hex(&bytes)).with("reject", "parked-version"));
    let mut x = h.clone();
    x.kind = Kind::Role;
    cases.push(reject("content aspect in a role commit", "spec/commits.md §2", &x, "aspect-class"));
    let mut x = role_commit().header;
    x.expires = Some(x.ts.wall_ms().0 + 1);
    cases.push(reject("expires on a role commit", "spec/commits.md §2", &x, "role-commit-expires"));
    let mut x = h.clone();
    x.expires = Some(x.ts.wall_ms().0);
    cases.push(reject("expires not after ts", "spec/commits.md §6", &x, "expires-ts"));
    let mut x = h.clone();
    x.aspects[0].lo = 0;
    cases.push(reject("empty counter range on a content commit", "spec/wire.md §4", &x, "counter-range"));
    let mut x = h.clone();
    x.keys.reverse();
    cases.push(reject("delete keys out of order", "spec/wire.md §4", &x, "order"));
    cases.extend(more_accepted());
    cases.extend(several_things());
    cases.extend(more_rejected(&c.header));
    VecFile { header: generated_header("commit", SPEC), cases }
}

/// `b` built under the rng seeded `seed`, with every byte it drew, so the vector can list them:
/// built again from just those bytes, it is the same commit.
fn build_recorded(b: CommitBuilder, key: &SigningSecret, seed: u8, sink: &mut MemoryBlobs) -> (Built, Vec<u8>) {
    let mut rec = Recording(osis_crypto::SeededRng::from_seed([seed; 32]), Vec::new());
    let first = b.clone().build(key, &VSecrets, &mut MemoryBlobs::default(), &mut rec).unwrap();
    let again = b.build(key, &VSecrets, sink, &mut FixedRng::new(&[&rec.1])).unwrap();
    assert_eq!(first.commit, again.commit);
    (again, rec.1)
}

/// Records every byte drawn from a seeded rng.
struct Recording(osis_crypto::SeededRng, Vec<u8>);

impl osis_crypto::RngCore for Recording {
    fn next_u32(&mut self) -> u32 {
        unimplemented!("vectors draw bytes only")
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!("vectors draw bytes only")
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
        self.1.extend_from_slice(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), osis_crypto::RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl osis_crypto::CryptoRng for Recording {}

fn more_accepted() -> Vec<Record> {
    let mut out = Vec::new();
    // commit form, expiring, undoes
    let at = ts(1_700_000_004_000);
    let mut b = CommitBuilder::new(Kind::Content, at, SIGNER, osis_commit::Path::through(LISTED), Form::Commit);
    let mut a = AspectWrite::new(THING, Ak::new("app:title.0").unwrap(), 1, 2, delta(Form::Commit, Kind::Content, at, 1, Value::Str("typed".into()), 6));
    b.expires = Some(at.wall_ms().0 + 86_400_000);
    a.retention = Retention { by: PurgeBy::Writer };
    b.aspects.push(a);
    b.undoes = Some(CommitId([0x2c; 32]));
    let c = built(b);
    out.push(record("commit form, expiry, undoes", "spec/wire.md §4; spec/commits.md §3, §5, §6, §7", &c));
    // purge request, with a creation
    let at = ts(1_700_000_005_000);
    let mut b = CommitBuilder::new(Kind::Content, at, SIGNER, osis_commit::Path::through(LISTED), SESSION);
    let cr = AspectWrite::new(THING, Ak::new("created.0").unwrap(), 1, 2, core_delta("created.0", SESSION, Kind::Content, at, 1, osis_base::CreationRecord::Thing { admin: LISTED, nonce: [0x2e; 32], link: None, expires: None }.to_value(), 7));
    b.aspects.push(cr);
    b.aspects.push(AspectWrite::new(THING, Ak::new("app:body.0").unwrap(), 1, 2, delta(SESSION, Kind::Content, at, 1, Value::Str("".into()), 8)));
    b.purge = vec![
        PurgeItem::Aspect { tid: THING, ak: Ak::new("app:body.0").unwrap() },
        PurgeItem::Commit { tid: THING, ak: Ak::new("app:title.0").unwrap(), ts: osis_base::Ts::from_u64(0x1234_0000).unwrap(), src: osis_crdt::Source::commit(CommitId([0x2d; 32])) },
    ];
    out.push(record("purge request beside a creation", "spec/wire.md §4; spec/commits.md §5", &built(b)));
    // a fire replacing an earlier one, expiring, with a purge request naming it
    let at = ts(1_700_000_005_500);
    let mut b = CommitBuilder::new(Kind::Content, at, SIGNER, osis_commit::Path::through(LISTED), SESSION);
    let mut a = AspectWrite::new(THING, Ak::new("app:msg~0").unwrap(), 1, 2, delta(SESSION, Kind::Content, at, 1, Value::Str("edited".into()), 9));
    a.retention = Retention { by: PurgeBy::AuthorOrAdmin };
    a.replaces = Some(CommitId([0x2f; 32]));
    b.aspects.push(a);
    b.expires = Some(at.wall_ms().0 + 86_400_000);
    b.purge = vec![PurgeItem::Commit { tid: THING, ak: Ak::new("app:msg~0").unwrap(), ts: osis_base::Ts::from_u64(0x1234_0000).unwrap(), src: osis_crdt::Source::commit(CommitId([0x2f; 32])) }];
    out.push(record("signal fire replacing another, expiring, purging it", "spec/wire.md §4; spec/commits.md §5 Signals, Purge", &built(b)));
    // role commit with a frontier
    let at = ts(1_700_000_006_000);
    let mut b = CommitBuilder::new(Kind::Role, at, SIGNER, osis_commit::Path::default(), Form::Commit);
    let mut a = AspectWrite::new(THING, Ak::new("roles.0").unwrap(), 1, 2, core_delta("roles.0", Form::Commit, Kind::Role, at, 1, grant(0x41, 0), 9));
    a.retention = retention::ROLE_RETENTION;
    b.aspects.push(a);
    b.frontier = Some(std::sync::Arc::from([CommitId([0x51; 32]), CommitId([0x52; 32])]));
    out.push(record("role demotion with a frontier", "spec/wire.md §4; spec/permissions.md §5", &built(b)));
    // a linked aspect list (above CHUNK_THRESHOLD)
    let at = ts(1_700_000_007_000);
    let mut b = CommitBuilder::new(Kind::Content, at, SIGNER, osis_commit::Path::through(LISTED), SESSION);
    let long = "x".repeat(990);
    for i in 0..140u32 {
        let mut a = AspectWrite::new(THING, Ak::new(format!("app:{long}{i:03}.0")).unwrap(), 1, 2, delta(SESSION, Kind::Content, at, 1, Value::Int(i64::from(i)), 10));
        // the commit lists a level-2 key, which its list blobs commit to alone
        a.retention = Retention { by: PurgeBy::AuthorOrAdmin };
        b.aspects.push(a);
    }
    let key = SigningSecret::from_seed(&s32(0x35));
    let mut sink = MemoryBlobs::default();
    let (bl, randomness) = build_recorded(b, &key, 0x36, &mut sink);
    let c = bl.commit;
    assert!(c.header.links.aspects.is_some());
    let mut back = CommitBlob::decode(&c.encode()).unwrap();
    back.header.resolve(&mut sink, &s32(0x30)).unwrap();
    assert_eq!(back, c);
    let mut r = case("linked aspect list", "spec/wire.md §4, §5, §6")
        .with("signing-seed", hex(s32(0x35).expose()))
        .with("dedup", hex(s32(0x30).expose()))
        .with("delete-secrets", format!("1:{} 2:{} 3:{}", hex(s32(0x31).expose()), hex(s32(0x32).expose()), hex(s32(0x33).expose())))
        .with("randomness", hex(&randomness))
        .with("aspect-list-blake3", hex(&osis_base::hash::hash(&c.header.list_bytes(ListField::Aspects).unwrap())));
    for (i, id) in bl.list_blobs.iter().enumerate() {
        let (p, plain) = &sink.blobs[id];
        // one empty group (spec/wire.md §5), under the link blind of the blob key the test sink
        // returns (zero), bound to the header's signer
        assert_eq!(p.thing, SIGNER);
        let framed = osis_blob::Prefix::for_delete_keys(p.salt, &osis_crypto::thing_blind(&osis_crypto::link_blind(&[0; 32]), p.thing.as_bytes()), p.expiry.map(WallMs), std::slice::from_ref(&p.keys)).unwrap();
        assert_eq!(framed.commitments().count(), 0);
        r = r.with(&format!("list-blob-{i}"), format!("{} {} {} {}", hex(&id.0), hex(&p.salt), hex(&framed.commitments().copied().collect::<Vec<_>>().concat()), hex(plain)));
    }
    out.push(r.with("header", hex(&c.header.encode())).with("commit-id", hex(&c.id().0)).with("signature", hex(&c.sigs.signature.0)).with("blob", hex(&c.encode())));
    out
}

/// A content commit writing two things along one listed thing: one `path` for both, in the clear
/// (spec/wire.md §4 field 2); and with the second thing's path differing (`[A, LISTED]`, purge
/// author LISTED): the split form, each entry sealed under its thing's path key from the read roles
/// secret given (`roles-i`), the second marking its hop into the thing direct (`marks`), the opened
/// form carrying each key; and one path in the clear marking the hop past LISTED direct. The
/// randomness is the header blind.
fn several_things() -> Vec<Record> {
    let at = ts(1_700_000_005_000);
    let other = Tid::from_bytes([0x24; 15]);
    let mut b = CommitBuilder::new(Kind::Content, at, SIGNER, osis_commit::Path::through(LISTED), SESSION);
    for (i, t) in [THING, other].into_iter().enumerate() {
        b.aspects.push(AspectWrite::new(t, Ak::new("app:title.0").unwrap(), 1, 2, delta(SESSION, Kind::Content, at, 1, Value::Str(format!("t{i}")), 12 + i as u8)));
    }
    let key = SigningSecret::from_seed(&s32(0x35));
    let dedup = |_: &Tid| Some(s32(0x30));
    let roles = [(THING, s32(0x3a), vec![LISTED], 0), (other, s32(0x3b), vec![Tid::from_bytes([0x26; 15]), LISTED], 0b100)];
    let mut out = Vec::new();
    for split in [false, true] {
        let mut b = b.clone();
        if split {
            b.split = Some(osis_commit::SplitWrite { author: Some(LISTED), things: roles.iter().map(|(t, s, p, m)| (*t, ((p.clone(), *m), s.clone()))).collect() });
        }
        let (bl, randomness) = build_recorded(b, &key, 0x38, &mut MemoryBlobs::default());
        let c = bl.commit;
        verify_blob(&c, &key.verifying_key(), &dedup, None).unwrap();
        if !split {
            assert_eq!(c.header.path, osis_commit::Paths::One(osis_commit::Path::through(LISTED)));
            out.push(record("several things: one path", "spec/wire.md §4 field 2", &c).with("randomness", hex(&randomness)));
            continue;
        }
        assert!(c.header.is_split());
        let mut r = record("several things: split paths", "spec/wire.md §4 field 2, spec/crypto.md §5 Path entry", &c).with("randomness", hex(&randomness));
        for (i, (t, s, ..)) in roles.iter().enumerate() {
            assert_eq!(c.keys.get(&i), Some(&osis_commit::path_key(s, &c.header.blind, t)));
            r = r.with(&format!("roles-{i}"), hex(s.expose())).with(&format!("path-key-{i}"), hex(&c.keys[&i]));
        }
        out.push(r);
        // a path key its entry does not commit to: the opened form carrying it is bad input
        let mut x = c.clone();
        x.keys.insert(0, [0x5c; 32]);
        assert!(CommitBlob::decode(&x.encode()).is_err());
        out.push(case("path key its entry does not commit to", "spec/wire.md §4 field 2, PathKey").with("blob", hex(&x.encode())).with("reject", "path-key"));
    }
    let mut b = b;
    b.path = osis_commit::Path { purge: 1, things: vec![LISTED], direct: 0b10 };
    let (bl, randomness) = build_recorded(b, &key, 0x39, &mut MemoryBlobs::default());
    verify_blob(&bl.commit, &key.verifying_key(), &dedup, None).unwrap();
    out.push(record("several things: one path marking a hop direct", "spec/wire.md §4 field 2, marks", &bl.commit).with("randomness", hex(&randomness)));
    out
}

fn more_rejected(content: &Header) -> Vec<Record> {
    let mut out = Vec::new();
    // stated paths (spec/wire.md §4 field 2)
    let with_path = |p: osis_commit::Path| Header { path: osis_commit::Paths::One(p), ..content.clone() };
    let long: Vec<Tid> = (0..=osis_base::format::MAX_PATH_THINGS).map(|i| Tid::from_bytes([0x50 + i as u8; 15])).collect();
    out.push(reject("path longer than MAX_PATH_THINGS", "spec/wire.md §4 field 2", &with_path(osis_commit::Path { purge: 0, things: long, direct: 0 }), "path"));
    out.push(reject("purge-author index past the path", "spec/wire.md §4 field 2", &with_path(osis_commit::Path { purge: 2, things: vec![LISTED], direct: 0 }), "path"));
    out.push(reject("path listing a thing twice", "spec/wire.md §4 field 2", &with_path(osis_commit::Path { purge: 0, things: vec![LISTED, LISTED], direct: 0 }), "path"));
    out.push(reject("path listing its signer", "spec/wire.md §4 field 2", &with_path(osis_commit::Path { purge: 0, things: vec![SIGNER], direct: 0 }), "path"));
    out.push(reject("path marking a hop past the hop past its end", "spec/wire.md §4 field 2, marks", &with_path(osis_commit::Path { purge: 0, things: vec![LISTED], direct: 0b100 }), "path"));
    // `marks` not canonical: the bytes of `[0, LISTED, h'03']` with that byte string rewritten
    let marked = with_path(osis_commit::Path { purge: 0, things: vec![LISTED], direct: 0b11 }).encode();
    let at = [LISTED.as_bytes(), &[0x41, 0x03][..]].concat();
    let pos = marked.windows(at.len()).position(|w| w == at).expect("the marked path's bytes") + LISTED.as_bytes().len();
    for (name, m) in [("empty", vec![0x40]), ("ending in a zero byte", vec![0x42, 0x03, 0x00]), ("of 10 bytes", [vec![0x4a, 0x03], vec![0; 8], vec![0x01]].concat())] {
        let bytes = [&marked[..pos], &m[..], &marked[pos + 2..]].concat();
        assert!(Header::decode(&bytes).and_then(|x| x.validate()).is_err(), "marks {name}");
        out.push(case(&format!("path marks {name}"), "spec/wire.md §4 field 2, marks").with("header", hex(&bytes)).with("reject", "path"));
    }
    // entry `n` listing `k` things: its key commitment's first byte `n`
    let entry = |k: usize, n: u8| [vec![n], vec![0x5d; osis_commit::entry_len(k).unwrap() - 1]].concat();
    let split = |author: Option<Tid>, entries: Vec<Vec<u8>>| osis_commit::Paths::Split(osis_commit::Split { author, entries });
    let x = Header { path: split(None, vec![entry(0, 0), entry(0, 1)]), ..content.clone() };
    out.push(reject("split path on a commit writing one thing", "spec/wire.md §4 field 2", &x, "path-form"));
    let mut x = content.clone();
    let mut a = x.aspects[0].clone();
    a.tid = Tid::from_bytes([0x24; 15]);
    x.aspects.push(a);
    x.validate().unwrap();
    x.path = split(None, vec![entry(0, 0), entry(0, 1), entry(0, 2)]);
    out.push(reject("split path of another count than the things written", "spec/wire.md §4 field 2", &x, "path-form"));
    x.path = split(None, vec![entry(0, 0), vec![0x5d; 50]]);
    out.push(reject("split path entry of no padded length", "spec/wire.md §4 field 2", &x, "path"));
    x.path = split(None, vec![entry(0, 0), vec![0x5d; osis_commit::entry_len(0).unwrap() - osis_commit::COMMITMENT_LEN]]);
    out.push(reject("split path entry without its key commitment", "spec/wire.md §4 field 2", &x, "path"));
    x.path = split(None, vec![entry(0, 0), entry(0, 0)]);
    out.push(reject("split path entries committing to one key", "spec/wire.md §4 field 2", &x, "path"));
    x.path = split(Some(SIGNER), vec![entry(0, 0), entry(0, 1)]);
    out.push(reject("split path naming its signer as purge author", "spec/wire.md §4 field 2", &x, "path"));
    let mut x = role_commit().header;
    let mut a = x.aspects[0].clone();
    a.tid = Tid::from_bytes([0x24; 15]);
    x.aspects.push(a);
    x.path = split(None, vec![entry(0, 0), entry(0, 1)]);
    out.push(reject("split path on a role commit", "spec/wire.md §4 field 2", &x, "path-form"));
    let m = role_commit().header;
    let mut x = m.clone();
    x.purge.push(PurgeItem::Aspect { tid: THING, ak: Ak::new("app:title.0").unwrap() });
    out.push(reject("purge request on a role commit", "spec/commits.md §2, §5", &x, "purge-role-class"));
    let frontier = Some(std::sync::Arc::from([]));
    let mut x = m.clone();
    x.kind = Kind::RoleSnapshot;
    x.aspects[0].ak = Ak::new("secrets.0").unwrap();
    x.aspects[0].lo = 0;
    x.aspects[0].hi = 0;
    x.validate().unwrap();
    x.frontier = frontier;
    out.push(reject("frontier on a role compaction snapshot", "spec/wire.md §4", &x, "frontier"));
    let mut x = content.clone();
    x.keys.push(DeleteKey::new(3, &osis_crypto::DeleteSecret::derive(&s32(0x37)).verifying_key()));
    out.push(reject("delete key no aspect lists", "spec/wire.md §4", &x, "unused-key"));
    // one purge author per commit: a second level-2 key, listed by a second aspect, is bad input
    let mut x = content.clone();
    let (k1, k2) = (x.keys[0], x.keys[1]);
    let other = DeleteKey::new(2, &osis_crypto::DeleteSecret::derive(&s32(0x38)).verifying_key());
    x.keys.push(other);
    x.keys.sort();
    let ix = |k: &DeleteKey| x.keys.iter().position(|y| y == k).unwrap();
    let (i1, i2, io) = (ix(&k1), ix(&k2), ix(&other));
    x.aspects[0].keys = vec![i1, i2];
    let mut a = x.aspects[0].clone();
    a.ak = Ak::new("app:title2.0").unwrap();
    a.keys = vec![i1, io];
    x.aspects.push(a);
    assert!(x.validate().is_err_and(|e| e.to_string().contains("level-2")), "the level-2 rule refuses it");
    out.push(reject("two level-2 delete keys", "spec/wire.md §4 field 11", &x, "level-2"));
    let mut x = content.clone();
    x.keys.remove(1);
    x.aspects[0].keys = vec![0];
    out.push(reject("author retention without its level-2 key", "spec/crypto.md §7", &x, "delete-levels"));
    let mut x = content.clone();
    x.keys.remove(0);
    x.aspects[0].keys = vec![0];
    out.push(reject("author retention without its level-1 key", "spec/crypto.md §7", &x, "delete-levels"));
    let mut x = m.clone();
    x.form = SESSION;
    out.push(reject("session form on a role commit", "spec/commits.md §3", &x, "form"));
    let e = ephemeral(osis_commit::EphClass::Plain).header;
    let mut x = m.clone();
    x.ephemeral = Some(osis_commit::EphClass::Plain);
    out.push(reject("ephemeral marker on a role commit", "spec/commits.md §2", &x, "ephemeral"));
    let mut x = e.clone();
    x.purge.push(PurgeItem::Aspect { tid: THING, ak: Ak::new("app:title.0").unwrap() });
    out.push(reject("ephemeral commit with a purge request", "spec/commits.md §2", &x, "ephemeral"));
    let s = session_commit().header;
    let mut x = s.clone();
    x.aspects[0].retention.by = PurgeBy::Admin;
    x.aspects[0].keys.truncate(1);
    x.keys.truncate(1);
    out.push(reject("session-form ephemeral commit not purgeable by writer", "spec/commits.md §2", &x, "ephemeral"));
    let mut v = osis_base::decode(&s.encode(), &osis_base::Limits::DEFAULT).unwrap();
    if let Value::List(items) = &mut v {
        items[5] = Value::List(vec![Value::Int(2), Value::Bytes(vec![0x28; 16])]);
    }
    let bytes = osis_base::encode(&v);
    assert!(Header::decode(&bytes).is_err());
    out.push(case("unknown dot form", "spec/wire.md §4").with("header", hex(&bytes)).with("reject", "form"));
    let mut x = ephemeral(osis_commit::EphClass::Relay).header;
    x.expires = Some(x.ts.wall_ms().0 + 1);
    out.push(reject("relay-only commit with an expiry", "spec/commits.md §2", &x, "ephemeral"));
    let mut v = osis_base::decode(&e.encode(), &osis_base::Limits::DEFAULT).unwrap();
    if let Value::List(items) = &mut v
        && let Some(m) = items.last_mut()
    {
        *m = Value::List(vec![Value::Int(2)]);
    }
    let bytes = osis_base::encode(&v);
    assert!(Header::decode(&bytes).is_err());
    out.push(case("unknown ephemeral marker", "spec/wire.md §4").with("header", hex(&bytes)).with("reject", "ephemeral"));
    // header flags (field 18): 0 is absent, bits above 1 are reserved, bit 1 is a role commit's
    let mut x = content.clone();
    x.adminless = true;
    out.push(reject("adminless mark on a content commit", "spec/wire.md §4 field 18", &x, "flags"));
    for (name, f) in [("header flags of 0", 0), ("reserved header flag", 4)] {
        let mut v = osis_base::decode(&m.encode(), &osis_base::Limits::DEFAULT).unwrap();
        if let Value::List(items) = &mut v {
            items.push(Value::Int(f));
        }
        let bytes = osis_base::encode(&v);
        assert!(Header::decode(&bytes).is_err(), "{name}");
        out.push(case(name, "spec/wire.md §4 field 18").with("header", hex(&bytes)).with("reject", "flags"));
    }
    // a delete key that is no valid Ed25519 point
    let mut x = content.clone();
    x.keys[0].key = [0; 32];
    let bytes = x.encode();
    assert!(Header::decode(&bytes).is_err());
    out.push(case("delete key not a valid point", "spec/wire.md §4").with("header", hex(&bytes)).with("reject", "delete-key"));
    out
}

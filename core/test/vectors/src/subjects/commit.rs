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
    fn chain_key(&self) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&s32(0x32)).verifying_key())
    }
    fn write_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&s32(0x33)).verifying_key())
    }
}

const AUTHOR: Tid = Tid::from_bytes([0x21; 15]);
const ACTOR: Tid = Tid::from_bytes([0x22; 15]);
const THING: Tid = Tid::from_bytes([0x23; 15]);
const BLIND: [u8; 16] = [0x34; 16];
/// The author's session nonce (spec/crdt.md §2.1).
const NONCE: [u8; osis_crdt::SESSION_NONCE_LEN] = [0x28; osis_crdt::SESSION_NONCE_LEN];
const SESSION: Form = Form::Session(NONCE);

fn ts(wall: u64) -> Ts {
    Ts::make(WallMs(wall), 0).unwrap()
}

/// The own source of a commit of `form` by the author (commit form: the placeholder).
fn own(form: Form) -> Source {
    form.own_source(AUTHOR, CommitId([0; 32]))
}

/// A writer's delta of one register write under the own source of `form`.
fn delta(form: Form, kind: Kind, at: Ts, lo: u64, v: Value, nonce: u8) -> Vec<u8> {
    let mut w = Writer::new(at, own(form), lo);
    let fragment = create(&mut w, &AnyView, &v).unwrap();
    encode_delta(&Delta { nonce: [nonce; 16], fragment }, &writer_ctx(form, kind, at, AUTHOR, lo, lo + 1), None).unwrap()
}

/// `delta` of core aspect `ak`, written through its core type (a core-aspect delta must fit it,
/// spec/crdt.md §3.3 rule 7).
fn core_delta(ak: &str, form: Form, kind: Kind, at: Ts, lo: u64, v: Value, nonce: u8) -> Vec<u8> {
    let mut w = Writer::new(at, own(form), lo);
    let fragment = create(&mut w, &osis_schema::core_schema().view(ak).unwrap(), &v).unwrap();
    encode_delta(&Delta { nonce: [nonce; 16], fragment }, &writer_ctx(form, kind, at, AUTHOR, lo, lo + 1), None).unwrap()
}

/// A `roles.0` value granting `role` (an enum case id) to the tid of bytes `m`.
fn grant(m: u8, role: u64) -> Value {
    let edge = Value::Map([(Value::Int(0), Value::Enum(role, None))].into_iter().collect());
    Value::Map([(Value::Tid(Tid::from_bytes([m; 15])), edge)].into_iter().collect())
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
        .with("signature", hex(&c.signature.0))
        .with("blob", hex(&c.encode()))
}

fn content() -> CommitBlob {
    let at = ts(1_700_000_000_000);
    let mut b = CommitBuilder::new(Kind::Content, at, AUTHOR, ACTOR, SESSION);
    b.aspects.push(AspectWrite::new(THING, Ak::new("app:title.0").unwrap(), 1, 2, delta(SESSION, Kind::Content, at, 1, Value::Str("hello".into()), 1)));
    built(b)
}

fn role_commit() -> CommitBlob {
    let at = ts(1_700_000_001_000);
    let mut b = CommitBuilder::new(Kind::Role, at, AUTHOR, AUTHOR, Form::Commit);
    let mut a = AspectWrite::new(THING, Ak::new("roles.0").unwrap(), 1, 2, core_delta("roles.0", Form::Commit, Kind::Role, at, 1, grant(0x41, 1), 2));
    a.retention = retention::ROLE_RETENTION;
    b.aspects.push(a);
    built(b)
}

/// A compaction snapshot carrying the author's session's write (spec/crdt.md §8: its frontier
/// names that session, which occurs in the fragment).
fn snapshot() -> CommitBlob {
    let at = ts(1_700_000_002_000);
    let mut w = Writer::new(ts(1_700_000_000_000), own(SESSION), 1);
    let fragment = create(&mut w, &AnyView, &Value::Str("hello".into())).unwrap();
    let frontiers = Frontiers { sessions: [(osis_crdt::Session { node: AUTHOR, nonce: NONCE }, 1)].into_iter().collect() };
    let s = Snapshot { absorbed: Default::default(), nonce: [4; 16], fragment, frontiers };
    let bytes = encode_snapshot(&s, &writer_ctx(Form::Commit, Kind::ContentSnapshot, at, AUTHOR, 0, 0), None).unwrap();
    let mut b = CommitBuilder::new(Kind::ContentSnapshot, at, AUTHOR, ACTOR, Form::Commit);
    let mut a = AspectWrite::new(THING, Ak::new("app:title.0").unwrap(), 0, 0, bytes);
    a.retention = retention::snapshot_retention("app:title.0", [], 0);
    b.aspects.push(a);
    built(b)
}

/// An ephemeral commit (spec/commits.md §2): a commit-form content snapshot with the marker,
/// carrying a write under a session of its author (spec/crdt.md §2.1) and that session's frontier.
fn ephemeral(class: osis_commit::EphClass) -> CommitBlob {
    let at = ts(1_700_000_004_000);
    let session = osis_crdt::Session { node: AUTHOR, nonce: [0x27; osis_crdt::SESSION_NONCE_LEN] };
    let mut w = Writer::new(ts(1_700_000_003_500), Source::session(session), 1);
    let fragment = create(&mut w, &AnyView, &Value::Str("typing".into())).unwrap();
    let frontiers = Frontiers { sessions: [(session, 1)].into_iter().collect() };
    let s = Snapshot { absorbed: Default::default(), nonce: [6; 16], fragment, frontiers };
    let bytes = encode_snapshot(&s, &writer_ctx(Form::Commit, Kind::ContentSnapshot, at, AUTHOR, 0, 0), None).unwrap();
    let mut b = CommitBuilder::new(Kind::ContentSnapshot, at, AUTHOR, ACTOR, Form::Commit);
    let mut a = AspectWrite::new(THING, Ak::new("app:state.0").unwrap(), 0, 0, bytes);
    a.retention = Retention { by: PurgeBy::Writer, ..Default::default() };
    b.aspects.push(a);
    b.ephemeral = Some(class);
    built(b)
}

/// A session-form ephemeral content commit (spec/commits.md §2, §3): its own write under
/// `(Session(author, nonce), 1)`, the nonce in the header's form.
fn session_commit() -> CommitBlob {
    let at = ts(1_700_000_004_500);
    let bytes = delta(SESSION, Kind::Content, at, 1, Value::Str("typing".into()), 11);
    let mut b = CommitBuilder::new(Kind::Content, at, AUTHOR, ACTOR, SESSION);
    let mut a = AspectWrite::new(THING, Ak::new("app:state.0").unwrap(), 1, 2, bytes);
    a.retention = Retention { by: PurgeBy::Writer, ..Default::default() };
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
    cases.push(record("content compaction snapshot", "spec/wire.md §4; spec/commits.md §2, §5", &snapshot()));
    let e = ephemeral(osis_commit::EphClass::Plain);
    cases.push(record("ephemeral commit", "spec/wire.md §4; spec/commits.md §2", &e));
    cases.push(record("relay-only commit", "spec/wire.md §4; spec/commits.md §2", &ephemeral(osis_commit::EphClass::Relay)));
    cases.push(record("session-form ephemeral content commit", "spec/wire.md §4; spec/commits.md §2, §3", &session_commit()));
    let mut purged = c.clone();
    purged.parts.clear();
    cases.push(case("header-only purge rewrite", "spec/wire.md §4; spec/commits.md §5").with("blob", hex(&purged.encode())).with("commit-id", hex(&c.id().0)));

    let h = &c.header;
    let mut v = h.clone();
    v.version = 2;
    let bytes = v.encode();
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
    x.expires = Some(x.ts.wall_ms().0 + 1);
    x.purge.push(PurgeItem::Aspect { tid: THING, ak: Ak::new("app:body.0").unwrap() });
    cases.push(reject("expires with a purge request", "spec/commits.md §5", &x, "purge-expires"));
    let mut x = h.clone();
    x.aspects[0].lo = 0;
    cases.push(reject("empty counter range on a content commit", "spec/wire.md §4", &x, "counter-range"));
    let mut x = h.clone();
    x.keys.reverse();
    cases.push(reject("delete keys out of order", "spec/wire.md §4", &x, "order"));
    cases.extend(more_accepted());
    cases.extend(more_rejected(&c.header));
    VecFile { header: generated_header("commit", SPEC), cases }
}

/// Records every byte drawn from a seeded rng, so the vector can list them.
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
    use osis_base::BlobId;
    use osis_schema::Bound;
    let mut out = Vec::new();
    // commit form, expiring, absolute bounds, chunks, undoes
    let at = ts(1_700_000_004_000);
    let mut b = CommitBuilder::new(Kind::Content, at, AUTHOR, ACTOR, Form::Commit);
    let mut a = AspectWrite::new(THING, Ak::new("app:title.0").unwrap(), 1, 2, delta(Form::Commit, Kind::Content, at, 1, Value::Str("typed".into()), 6));
    b.expires = Some(at.wall_ms().0 + 86_400_000);
    a.retention = Retention { by: PurgeBy::Writer, at_least: Bound { abs: Some(1_800_000_000_000), rel: None }, at_most: Bound { abs: Some(1_900_000_000_000), rel: Some(0) } };
    a.chunks = vec![BlobId([0x28; 32]), BlobId([0x2a; 32])];
    b.aspects.push(a);
    b.undoes = Some(CommitId([0x2c; 32]));
    let c = built(b);
    out.push(record("commit form, expiry, absolute bounds, chunks, undoes", "spec/wire.md §4; spec/commits.md §3, §5, §6, §7", &c));
    // purge request, created.0 kept forever
    let at = ts(1_700_000_005_000);
    let mut b = CommitBuilder::new(Kind::Content, at, AUTHOR, ACTOR, SESSION);
    let mut cr = AspectWrite::new(THING, Ak::new("created.0").unwrap(), 1, 2, core_delta("created.0", SESSION, Kind::Content, at, 1, osis_base::CreationRecord::Thing { admin: ACTOR, nonce: [0x2e; 32] }.to_value(), 7));
    cr.retention = retention::CREATED_RETENTION;
    b.aspects.push(cr);
    b.aspects.push(AspectWrite::new(THING, Ak::new("app:body.0").unwrap(), 1, 2, delta(SESSION, Kind::Content, at, 1, Value::Str("".into()), 8)));
    b.purge = vec![
        PurgeItem::Aspect { tid: THING, ak: Ak::new("app:body.0").unwrap() },
        PurgeItem::Commit { commit: CommitId([0x2d; 32]), tid: THING, ak: Ak::new("app:title.0").unwrap() },
    ];
    out.push(record("purge request; created.0 kept forever", "spec/wire.md §4; spec/commits.md §5", &built(b)));
    // role commit with a frontier
    let at = ts(1_700_000_006_000);
    let mut b = CommitBuilder::new(Kind::Role, at, AUTHOR, AUTHOR, Form::Commit);
    let mut a = AspectWrite::new(THING, Ak::new("roles.0").unwrap(), 1, 2, core_delta("roles.0", Form::Commit, Kind::Role, at, 1, grant(0x41, 0), 9));
    a.retention = retention::ROLE_RETENTION;
    b.aspects.push(a);
    b.frontier = Some(Value::Map([(Value::Int(0), Value::Map(Default::default())), (Value::Int(1), Value::Set(Default::default()))].into_iter().collect()));
    out.push(record("role demotion with a frontier", "spec/wire.md §4; spec/permissions.md §5", &built(b)));
    // a linked aspect list (above CHUNK_THRESHOLD)
    let at = ts(1_700_000_007_000);
    let mut b = CommitBuilder::new(Kind::Content, at, AUTHOR, ACTOR, SESSION);
    let long = "x".repeat(990);
    for i in 0..140u32 {
        b.aspects.push(AspectWrite::new(THING, Ak::new(format!("app:{long}{i:03}.0")).unwrap(), 1, 2, delta(SESSION, Kind::Content, at, 1, Value::Int(i64::from(i)), 10)));
    }
    let key = SigningSecret::from_seed(&s32(0x35));
    let mut rec = Recording(osis_crypto::SeededRng::from_seed([0x36; 32]), Vec::new());
    let first = b.clone().build(&key, &VSecrets, &mut MemoryBlobs::default(), &mut rec).unwrap();
    let mut sink = MemoryBlobs::default();
    let bl = b.build(&key, &VSecrets, &mut sink, &mut FixedRng::new(&[&rec.1])).unwrap();
    assert_eq!(first.commit, bl.commit);
    let c = bl.commit;
    assert!(c.header.links.aspects.is_some());
    let mut back = CommitBlob::decode(&c.encode()).unwrap();
    back.header.resolve(&mut sink, &s32(0x30)).unwrap();
    assert_eq!(back, c);
    let mut r = case("linked aspect list", "spec/wire.md §4, §5, §6")
        .with("signing-seed", hex(s32(0x35).expose()))
        .with("dedup", hex(s32(0x30).expose()))
        .with("delete-secrets", format!("1:{} 2:{} 3:{}", hex(s32(0x31).expose()), hex(s32(0x32).expose()), hex(s32(0x33).expose())))
        .with("randomness", hex(&rec.1))
        .with("aspect-list-blake3", hex(&osis_base::hash::hash(&osis_base::encode(&c.header.list_value(ListField::Aspects).unwrap()))));
    for (i, id) in bl.list_blobs.iter().enumerate() {
        let (p, plain) = &sink.blobs[id];
        // level-2 commitments only (spec/wire.md §5)
        let framed = osis_label::Prefix::for_delete_keys(p.salt, &p.blind, p.expiry.map(WallMs), std::slice::from_ref(&p.keys)).unwrap();
        assert!(framed.commitments().count() == 1 && framed.commitments().all(|x| x[0] == 2));
        r = r.with(&format!("list-blob-{i}"), format!("{} {} {} {}", hex(&id.0), hex(&p.salt), hex(&framed.commitments().copied().collect::<Vec<_>>().concat()), hex(plain)));
    }
    out.push(r.with("header", hex(&c.header.encode())).with("commit-id", hex(&c.id().0)).with("signature", hex(&c.signature.0)).with("blob", hex(&c.encode())));
    out
}

fn more_rejected(content: &Header) -> Vec<Record> {
    let mut out = Vec::new();
    let m = role_commit().header;
    let mut x = m.clone();
    x.purge.push(PurgeItem::Aspect { tid: THING, ak: Ak::new("app:title.0").unwrap() });
    out.push(reject("purge request on a role commit", "spec/commits.md §2, §5", &x, "purge-role-class"));
    let frontier = Some(Value::Map(Default::default()));
    let mut x = m.clone();
    x.kind = Kind::RoleSnapshot;
    x.aspects[0].ak = Ak::new("secrets.0").unwrap();
    x.aspects[0].lo = 0;
    x.aspects[0].hi = 0;
    x.validate().unwrap();
    x.frontier = frontier;
    out.push(reject("frontier on a role compaction snapshot", "spec/wire.md §4", &x, "frontier"));
    let mut x = content.clone();
    x.chunks.push(ChunkEntry { blob: osis_base::BlobId([1; 32]), keys: vec![1, 0] });
    out.push(reject("chunk delete keys out of order", "spec/wire.md §4", &x, "chunk-keys"));
    let mut x = content.clone();
    x.chunks.push(ChunkEntry { blob: osis_base::BlobId([1; 32]), keys: vec![9] });
    out.push(reject("chunk delete key index out of range", "spec/wire.md §4", &x, "chunk-keys"));
    let mut x = content.clone();
    x.aspects[0].ak = Ak::new("created.0").unwrap();
    out.push(reject("created.0 with other than its fixed retention", "spec/commits.md §5", &x, "fixed-retention"));
    let mut x = content.clone();
    x.aspects[0].ak = Ak::new("created.0").unwrap();
    x.aspects[0].retention = retention::CREATED_RETENTION;
    x.aspects[0].keys.clear();
    x.keys.clear();
    x.validate().unwrap();
    x.expires = Some(x.ts.wall_ms().0 + 1);
    out.push(reject("created.0 with expires", "spec/commits.md §5, §6", &x, "fixed-expires"));
    let mut x = content.clone();
    let mut n = x.aspects[0].clone();
    n.ak = Ak::new("app:n.0").unwrap();
    n.retention = Retention { by: PurgeBy::Nobody, ..Default::default() };
    n.keys.clear();
    // canonical order: the shorter AK of one thing first
    x.aspects.insert(0, n);
    out.push(reject("a nobody delta beside another class", "spec/commits.md §5", &x, "nobody-mix"));
    let mut x = content.clone();
    x.keys.push(DeleteKey::new(3, &osis_crypto::DeleteSecret::derive(&s32(0x37)).verifying_key()));
    out.push(reject("delete key no aspect lists", "spec/wire.md §4", &x, "unused-key"));
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
    let mut x = e.clone();
    x.aspects[0].retention.at_least.rel = Some(5);
    out.push(reject("ephemeral snapshot with a keep bound", "spec/commits.md §2", &x, "ephemeral"));
    let s = session_commit().header;
    let mut x = s.clone();
    x.aspects[0].retention.at_most.abs = Some(x.ts.wall_ms().0 + 5);
    out.push(reject("session-form ephemeral commit with a keep bound", "spec/commits.md §2", &x, "ephemeral"));
    let mut v = s.to_value();
    if let Value::List(items) = &mut v {
        items[5] = Value::List(vec![Value::Int(2), Value::Bytes(vec![0x28; 16])]);
    }
    let bytes = osis_base::encode(&v);
    assert!(Header::decode(&bytes).is_err());
    out.push(case("unknown dot form", "spec/wire.md §4").with("header", hex(&bytes)).with("reject", "form"));
    let mut x = ephemeral(osis_commit::EphClass::Relay).header;
    x.expires = Some(x.ts.wall_ms().0 + 1);
    out.push(reject("relay-only commit with an expiry", "spec/commits.md §2", &x, "ephemeral"));
    let mut v = e.to_value();
    if let Value::List(items) = &mut v
        && let Some(m) = items.last_mut()
    {
        *m = Value::List(vec![Value::Int(2)]);
    }
    let bytes = osis_base::encode(&v);
    assert!(Header::decode(&bytes).is_err());
    out.push(case("unknown ephemeral marker", "spec/wire.md §4").with("header", hex(&bytes)).with("reject", "ephemeral"));
    // a delete key that is no valid Ed25519 point
    let mut x = content.clone();
    x.keys[0].key = [0; 32];
    let bytes = x.encode();
    assert!(Header::decode(&bytes).is_err());
    out.push(case("delete key not a valid point", "spec/wire.md §4").with("header", hex(&bytes)).with("reject", "delete-key"));
    out
}

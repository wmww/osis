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

fn ts(wall: u64) -> Ts {
    Ts::make(WallMs(wall), 0).unwrap()
}

fn delta(kind: Kind, at: Ts, src: Source, lo: u64, v: Value, nonce: u8) -> Vec<u8> {
    let mut w = Writer::new(at, src, lo);
    let fragment = create(&mut w, &AnyView, &v).unwrap();
    encode_delta(&Delta { nonce: [nonce; 16], fragment }, &writer_ctx(kind, at, AUTHOR, lo, lo + 1), None).unwrap()
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
        r = r.with(&format!("delta-{}-{}", p.ai, p.di), hex(&p.delta));
    }
    r.with("header", hex(&c.header.encode()))
        .with("commit-id", hex(&c.id().0))
        .with("signature", hex(&c.signature.0))
        .with("blob", hex(&c.encode()))
}

fn content() -> CommitBlob {
    let at = ts(1_700_000_000_000);
    let mut b = CommitBuilder::new(Kind::Content, at, AUTHOR, ACTOR, Form::Node);
    b.aspects.push(AspectWrite::new(THING, Ak::new("/app/title").unwrap(), 1, 2, delta(Kind::Content, at, Source::node(AUTHOR), 1, Value::Str("hello".into()), 1)));
    built(b)
}

fn membership() -> CommitBlob {
    let at = ts(1_700_000_001_000);
    let mut b = CommitBuilder::new(Kind::Membership, at, AUTHOR, ACTOR, Form::Commit);
    let edge = |m: u8| Value::Map([(Value::Tid(Tid::from_bytes([m; 15])), Value::Int(1))].into_iter().collect());
    let mut a = AspectWrite::new(THING, Ak::new("/members").unwrap(), 1, 2, delta(Kind::Membership, at, Source::node(AUTHOR), 1, edge(0x41), 2));
    a.deltas.push(delta(Kind::Membership, at, Source::node(AUTHOR), 1, edge(0x42), 3));
    a.retention = retention::MEMBERSHIP_RETENTION;
    b.aspects.push(a);
    built(b)
}

fn snapshot() -> CommitBlob {
    let at = ts(1_700_000_002_000);
    let mut w = Writer::new(ts(1_700_000_000_000), Source::node(AUTHOR), 1);
    let fragment = create(&mut w, &AnyView, &Value::Str("hello".into())).unwrap();
    let s = Snapshot { absorbed: Default::default(), authors: Default::default(), nonce: [4; 16], fragment, frontiers: Frontiers([(AUTHOR, 1)].into_iter().collect()) };
    let bytes = encode_snapshot(&s, &writer_ctx(Kind::ContentSnapshot, at, AUTHOR, 0, 0), None).unwrap();
    let mut b = CommitBuilder::new(Kind::ContentSnapshot, at, AUTHOR, ACTOR, Form::Node);
    let mut a = AspectWrite::new(THING, Ak::new("/app/title").unwrap(), 0, 0, bytes);
    a.retention = retention::snapshot_retention("/app/title", None);
    b.aspects.push(a);
    built(b)
}

fn import() -> CommitBlob {
    let at = ts(1_700_000_003_000);
    let origin = CommitId([0x24; 32]);
    let ots = ts(1_600_000_000_000);
    let d = delta(Kind::Import, at, Source::commit(origin), 1, Value::Str("moved".into()), 5);
    let mut b = CommitBuilder::new(Kind::Import, at, AUTHOR, ACTOR, Form::Node);
    let mut a = AspectWrite::new(THING, Ak::new("/app/title").unwrap(), 0, 0, d);
    a.retention = Retention { by: PurgeBy::Writer, ..Default::default() };
    b.aspects.push(a);
    b.origins.push(Origin { commit: origin, author: Tid::from_bytes([0x25; 15]), actor: Tid::from_bytes([0x26; 15]), ts: ots });
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
    cases.push(record("membership commit, two deltas on one aspect", "spec/wire.md §4; spec/commits.md §2", &membership()));
    cases.push(record("content compaction snapshot", "spec/wire.md §4; spec/commits.md §2, §5", &snapshot()));
    cases.push(record("import with origins", "spec/wire.md §4; spec/permissions.md §7", &import()));
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
    x.kind = Kind::Membership;
    cases.push(reject("content aspect in a membership commit", "spec/commits.md §2", &x, "aspect-class"));
    let mut x = membership().header;
    x.aspects[0].expires = Some(x.ts.wall_ms().0 + 1);
    cases.push(reject("expires on a membership commit", "spec/commits.md §2", &x, "membership-expires"));
    let mut x = h.clone();
    x.aspects[0].expires = Some(x.ts.wall_ms().0);
    cases.push(reject("expires not after ts", "spec/commits.md §6", &x, "expires-ts"));
    let mut x = h.clone();
    x.aspects[0].expires = Some(x.ts.wall_ms().0 + 1);
    x.purge.push(PurgeItem::Aspect { tid: THING, ak: Ak::new("/app/body").unwrap() });
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
    // commit form, typed, expiring, absolute bounds, chunks, undoes
    let at = ts(1_700_000_004_000);
    let mut b = CommitBuilder::new(Kind::Content, at, AUTHOR, ACTOR, Form::Commit);
    let mut a = AspectWrite::new(THING, Ak::new("/app/title").unwrap(), 1, 2, delta(Kind::Content, at, Source::node(AUTHOR), 1, Value::Str("typed".into()), 6));
    a.schema = Some((osis_base::SchemaId([0x27; 16]), 2));
    a.expires = Some(at.wall_ms().0 + 86_400_000);
    a.retention = Retention { by: PurgeBy::Writer, at_least: Bound { abs: Some(1_800_000_000_000), rel: None }, at_most: Bound { abs: Some(1_900_000_000_000), rel: Some(1000) } };
    a.chunks = vec![BlobId([0x28; 32]), BlobId([0x2a; 32])];
    b.aspects.push(a);
    b.undoes = Some(CommitId([0x2c; 32]));
    let c = built(b);
    out.push(record("commit form, schema index, expiry, absolute bounds, chunks, undoes", "spec/wire.md §4; spec/commits.md §3, §5, §6, §7", &c));
    // purge request, /created kept forever
    let at = ts(1_700_000_005_000);
    let mut b = CommitBuilder::new(Kind::Content, at, AUTHOR, ACTOR, Form::Node);
    let mut cr = AspectWrite::new(THING, Ak::new("/created").unwrap(), 1, 2, delta(Kind::Content, at, Source::node(AUTHOR), 1, Value::Str("record".into()), 7));
    cr.retention = retention::CREATED_RETENTION;
    b.aspects.push(cr);
    b.aspects.push(AspectWrite::new(THING, Ak::new("/app/body").unwrap(), 1, 2, delta(Kind::Content, at, Source::node(AUTHOR), 1, Value::Str("".into()), 8)));
    b.purge = vec![
        PurgeItem::Aspect { tid: THING, ak: Ak::new("/app/body").unwrap() },
        PurgeItem::Commit { commit: CommitId([0x2d; 32]), tid: THING, ak: Ak::new("/app/title").unwrap() },
    ];
    out.push(record("purge request; /created kept forever", "spec/wire.md §4; spec/commits.md §5", &built(b)));
    // membership commit with a frontier
    let at = ts(1_700_000_006_000);
    let mut b = CommitBuilder::new(Kind::Membership, at, AUTHOR, ACTOR, Form::Commit);
    let mut a = AspectWrite::new(THING, Ak::new("/members").unwrap(), 1, 2, delta(Kind::Membership, at, Source::node(AUTHOR), 1, Value::Map([(Value::Tid(Tid::from_bytes([0x41; 15])), Value::Int(0))].into_iter().collect()), 9));
    a.retention = retention::MEMBERSHIP_RETENTION;
    b.aspects.push(a);
    b.frontier = Some(Value::Map([(Value::Int(0), Value::Map(Default::default())), (Value::Int(1), Value::Set(Default::default()))].into_iter().collect()));
    out.push(record("membership demotion with a frontier", "spec/wire.md §4; spec/permissions.md §5", &built(b)));
    // a linked aspect list (above CHUNK_THRESHOLD)
    let at = ts(1_700_000_007_000);
    let mut b = CommitBuilder::new(Kind::Content, at, AUTHOR, ACTOR, Form::Node);
    let long = "x".repeat(990);
    for i in 0..140u32 {
        b.aspects.push(AspectWrite::new(THING, Ak::new(format!("/app/{long}{i:03}")).unwrap(), 1, 2, delta(Kind::Content, at, Source::node(AUTHOR), 1, Value::Int(i64::from(i)), 10)));
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
    back.header.resolve(&mut sink, &s32(0x30), MAX_LIST_BYTES).unwrap();
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
        let framed = osis_label::Prefix::for_delete_keys(p.salt, &p.blind, p.expiry.map(WallMs), &p.keys).unwrap();
        assert!(framed.commitments().len() == 1 && framed.commitments().iter().all(|x| x[0] == 2));
        r = r.with(&format!("list-blob-{i}"), format!("{} {} {} {}", hex(&id.0), hex(&p.salt), hex(&framed.commitments().concat()), hex(plain)));
    }
    out.push(r.with("header", hex(&c.header.encode())).with("commit-id", hex(&c.id().0)).with("signature", hex(&c.signature.0)).with("blob", hex(&c.encode())));
    out
}

fn more_rejected(content: &Header) -> Vec<Record> {
    use osis_base::SchemaId;
    let mut out = Vec::new();
    let m = membership().header;
    let mut x = m.clone();
    x.purge.push(PurgeItem::Aspect { tid: THING, ak: Ak::new("/app/title").unwrap() });
    out.push(reject("purge request on a membership commit", "spec/commits.md §2, §5", &x, "purge-membership"));
    let mut x = content.clone();
    x.origins.push(Origin { commit: CommitId([1; 32]), author: AUTHOR, actor: ACTOR, ts: ts(5) });
    out.push(reject("origins on a non-import", "spec/wire.md §4", &x, "origins"));
    let mut x = import().header;
    let mut other = x.aspects[0].clone();
    other.tid = Tid::from_bytes([0xff; 15]);
    x.aspects.push(other);
    out.push(reject("import on several things", "spec/permissions.md §7", &x, "import-things"));
    let frontier = Some(Value::Map(Default::default()));
    let mut x = m.clone();
    x.kind = Kind::MembershipSnapshot;
    x.aspects[0].ak = Ak::new("/secrets").unwrap();
    x.aspects[0].lo = 0;
    x.aspects[0].hi = 0;
    x.aspects[0].hashes.truncate(1);
    x.validate().unwrap();
    x.frontier = frontier.clone();
    out.push(reject("frontier on a membership compaction snapshot", "spec/wire.md §4", &x, "frontier"));
    let mut x = m.clone();
    x.kind = Kind::RosterSnapshot;
    x.validate().unwrap();
    x.frontier = frontier;
    out.push(reject("frontier on a roster snapshot", "spec/wire.md §4", &x, "frontier"));
    let mut x = content.clone();
    x.schemas = vec![(SchemaId([9; 16]), 1), (SchemaId([1; 16]), 1)];
    out.push(reject("schemas out of order", "spec/wire.md §4", &x, "order"));
    let mut x = content.clone();
    x.chunks.push(ChunkEntry { blob: osis_base::BlobId([1; 32]), keys: vec![1, 0] });
    out.push(reject("chunk delete keys out of order", "spec/wire.md §4", &x, "chunk-keys"));
    let mut x = content.clone();
    x.chunks.push(ChunkEntry { blob: osis_base::BlobId([1; 32]), keys: vec![9] });
    out.push(reject("chunk delete key index out of range", "spec/wire.md §4", &x, "chunk-keys"));
    let mut x = content.clone();
    x.aspects[0].ak = Ak::new("/created").unwrap();
    out.push(reject("/created with other than its fixed retention", "spec/commits.md §5", &x, "fixed-retention"));
    let mut x = content.clone();
    x.aspects[0].ak = Ak::new("/created").unwrap();
    x.aspects[0].retention = retention::CREATED_RETENTION;
    x.aspects[0].keys.clear();
    x.keys.clear();
    x.validate().unwrap();
    x.aspects[0].expires = Some(x.ts.wall_ms().0 + 1);
    out.push(reject("/created with expires", "spec/commits.md §5, §6", &x, "fixed-expires"));
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
    // a delete key that is no valid Ed25519 point
    let mut x = content.clone();
    x.keys[0].key = [0; 32];
    let bytes = x.encode();
    assert!(Header::decode(&bytes).is_err());
    out.push(case("delete key not a valid point", "spec/wire.md §4").with("header", hex(&bytes)).with("reject", "delete-key"));
    out
}

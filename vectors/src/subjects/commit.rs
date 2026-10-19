//! `commit/`: commit headers, commit IDs, signatures and commit blob plaintexts (spec/wire.md §4,
//! spec/commits.md). Generated.

use super::{FixedRng, case, generated_header, s32};
use crate::file::{Record, VecFile};
use crate::hex;
use osis_commit::*;
use osis_core::{Ak, CommitId, Tid, Ts, Value, WallMs};
use osis_crdt::{AnyView, Delta, Frontiers, Snapshot, Source, Writer, create, encode_delta, encode_snapshot};
use osis_crypto::{Secret32, SigningSecret};
use osis_schema::{PurgeBy, Retention};

const SPEC: &str = "spec/wire.md §4";

struct VSecrets;

impl Secrets for VSecrets {
    fn dedup(&self, _: &Tid) -> Option<Secret32> {
        Some(s32(0x30))
    }
    fn admin(&self, _: &Tid) -> Option<Secret32> {
        Some(s32(0x31))
    }
    fn chain_write(&self) -> Option<Secret32> {
        Some(s32(0x32))
    }
    fn write(&self, _: &Tid) -> Option<Secret32> {
        Some(s32(0x33))
    }
}

const AUTHOR: Tid = Tid::from_bytes([0x21; 15]);
const ACTOR: Tid = Tid::from_bytes([0x22; 15]);
const THING: Tid = Tid::from_bytes([0x23; 15]);
const SALT: [u8; 16] = [0x34; 16];

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
    let c = b.build(&key, &VSecrets, &mut MemoryBlobs::default(), &mut FixedRng::new(&[&SALT])).unwrap().commit;
    let dedup = |_: &Tid| Some(s32(0x30));
    verify_blob(&c, &key.verifying_key(), &dedup, None).unwrap();
    c
}

fn record(name: &str, spec: &str, c: &CommitBlob) -> Record {
    let mut r = case(name, spec)
        .with("signing-seed", hex(s32(0x35).expose()))
        .with("dedup", hex(s32(0x30).expose()))
        .with("token-secrets", format!("1:{} 2:{} 3:{}", hex(s32(0x31).expose()), hex(s32(0x32).expose()), hex(s32(0x33).expose())))
        .with("salt", hex(&SALT));
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
    let mut b = CommitBuilder::new(Kind::Membership, at, AUTHOR, ACTOR, Form::Node);
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
    let s = Snapshot { nonce: [4; 16], fragment, frontiers: Frontiers([(AUTHOR, 1)].into_iter().collect()) };
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
    x.tokens.reverse();
    cases.push(reject("tokens out of order", "spec/wire.md §4", &x, "order"));
    VecFile { header: generated_header("commit", SPEC), cases }
}

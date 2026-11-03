#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, dead_code)]
//! Shared test helpers: a test schema with one aspect per encoding, grants, delivery.

use osis_commit::Kind;
use osis_base::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::local_peer::{LocalPeer, Package};
use osis_node::{Engine, Mutation};
use osis_schema::core_types as ct;
use osis_schema::{Aspect, Codec, StaticSchema};

pub const T0: WallMs = WallMs(1_700_000_000_000);

pub static TEST: StaticSchema = StaticSchema::new(
    "test.osis",
    r#"
version 1;
type item = struct { 0 name: string, 1 n: int };
type shape = enum { 0 dot, 1 circle(int) };
type book = struct { 0 entries: map<string, string>, 1 note: string };
aspect t:reg.0: string;
aspect t:count.0: counter<int>;
aspect t:hi.0: max<int>;
aspect t:lo.0: min<int>;
aspect t:rec.0: item;
aspect t:shape.0: shape;
aspect t:tags.0: set<string>;
aspect t:map.0: map<string, item>;
aspect t:big.0: map<string, string>;
aspect t:gone.0: string [by: writer, keep_at_most: 0s];
aspect t:gone2.0: string [by: writer, keep_at_most: 0s];
aspect t:gonemap.0: map<string, string> [by: writer, keep_at_most: 0s];
aspect t:brief.0: string [expires: 1h];
aspect t:kept.0: string [by: writer, keep_at_least: 1d];
aspect t:keptset.0: set<string> [by: writer, keep_at_least: 1d];
aspect t:short.0: string [by: writer, keep_at_most: 10m];
aspect t:short2.0: string [by: writer, keep_at_most: 10m];
aspect t:list.0: list<string>;
aspect t:text.0: text;
aspect t:blob.0: blob;
aspect t:book.0: book;
aspect t:docs.0: map<string, text>;
aspect t:shortmap.0: map<string, string> [by: writer, keep_at_most: 10m];
"#,
);

pub const REG: Aspect<Value> = Aspect::new("t:reg.0", &TEST);
pub const COUNT: Aspect<Value> = Aspect::new("t:count.0", &TEST);
pub const HI: Aspect<Value> = Aspect::new("t:hi.0", &TEST);
pub const LO: Aspect<Value> = Aspect::new("t:lo.0", &TEST);
pub const REC: Aspect<Value> = Aspect::new("t:rec.0", &TEST);
pub const SHAPE: Aspect<Value> = Aspect::new("t:shape.0", &TEST);
pub const TAGS: Aspect<Value> = Aspect::new("t:tags.0", &TEST);
pub const MAP: Aspect<Value> = Aspect::new("t:map.0", &TEST);
pub const BIG: Aspect<Value> = Aspect::new("t:big.0", &TEST);
pub const GONE: Aspect<Value> = Aspect::new("t:gone.0", &TEST);
pub const GONE2: Aspect<Value> = Aspect::new("t:gone2.0", &TEST);
pub const GONEMAP: Aspect<Value> = Aspect::new("t:gonemap.0", &TEST);
pub const BRIEF: Aspect<Value> = Aspect::new("t:brief.0", &TEST);
pub const KEPT: Aspect<Value> = Aspect::new("t:kept.0", &TEST);
pub const KEPTSET: Aspect<Value> = Aspect::new("t:keptset.0", &TEST);
pub const SHORT: Aspect<Value> = Aspect::new("t:short.0", &TEST);
pub const SHORT2: Aspect<Value> = Aspect::new("t:short2.0", &TEST);
pub const LIST: Aspect<Value> = Aspect::new("t:list.0", &TEST);
pub const TEXT: Aspect<Value> = Aspect::new("t:text.0", &TEST);
pub const BLOB: Aspect<Value> = Aspect::new("t:blob.0", &TEST);
pub const BOOK: Aspect<Value> = Aspect::new("t:book.0", &TEST);
pub const DOCS: Aspect<Value> = Aspect::new("t:docs.0", &TEST);
pub const SHORTMAP: Aspect<Value> = Aspect::new("t:shortmap.0", &TEST);

pub fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

pub fn s(x: &str) -> Value {
    Value::Str(x.into())
}

pub fn item(name: &str, n: i64) -> Value {
    Value::Map([(Value::Int(0), s(name)), (Value::Int(1), Value::Int(n))].into_iter().collect())
}

pub fn net(n: usize, seed: u64) -> LocalPeer {
    LocalPeer::new(n, seed, T0).unwrap()
}

/// A new thing owned by peer `i`'s node.
pub fn new_thing(lp: &mut LocalPeer, i: usize) -> Tid {
    let p = lp.peer(i).unwrap();
    let me = p.engine.tid();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    m.set(t, &REG, &s("new")).unwrap();
    p.commit(m).unwrap();
    t
}

pub fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, since: None, tied: None, keyset: None }
}

/// Peer `i` writes `holder`'s edge on `thing` as remove + put (`None` removes it), with an
/// optional frontier.
pub fn set_edge(e: &mut Engine, thing: Tid, holder: Tid, edge: Option<ct::Edge>, frontier: Option<Value>) -> CommitId {
    // an edge change is remove + put (spec/permissions.md §2)
    let mut m = Mutation::new();
    m.op(thing, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(holder)) }).unwrap();
    if let Some(x) = edge {
        m.op(thing, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(x.to_value()) }).unwrap();
    }
    if let Some(f) = frontier {
        m.frontier(f);
    }
    e.commit(m).unwrap().unwrap()
}

/// Delivers every commit of `from` to `to`.
pub fn sync(lp: &mut LocalPeer, from: usize, to: usize) {
    lp.sync(from, to).unwrap();
}

pub fn packages(lp: &mut LocalPeer, from: usize) -> Vec<Package> {
    lp.packages(from).unwrap()
}

pub fn is_role(e: &Engine, id: &CommitId) -> bool {
    e.header(id).is_some_and(|h| h.kind == Kind::Role)
}

/// Canonical bytes of every aspect state of `tids` (convergence check).
pub fn states(e: &mut Engine, tids: &[Tid]) -> Vec<(Tid, Ak, Option<Value>)> {
    let mut out = Vec::new();
    for (t, a) in e.all_aspects().unwrap() {
        if tids.contains(&t) {
            out.push((t, a.clone(), e.get(&t, &a).unwrap()));
        }
    }
    out.sort_by(|x, y| (x.0, x.1.as_str()).cmp(&(y.0, y.1.as_str())));
    out
}

// Forensic attack (spec/commits.md §5, spec/requirements.md Deletion: forward secure): peers
// whose backend records every row written.

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Whether an attacker holding the device recovers `marker` (`Engine::forensic`: rows, blobs,
/// wraps, every row and blob ever written).
pub fn recoverable(p: &mut osis_node::local_peer::Peer, marker: &[u8]) -> bool {
    plaintexts(p).iter().any(|x| contains(x, marker))
}

/// `recoverable` of each marker, from one attack (an attack costs seconds).
pub fn recovered<const N: usize>(p: &mut osis_node::local_peer::Peer, markers: [&[u8]; N]) -> [bool; N] {
    let found = plaintexts(p);
    markers.map(|m| found.iter().any(|x| contains(x, m)))
}

/// Every plaintext an attacker recovers.
pub fn plaintexts(p: &mut osis_node::local_peer::Peer) -> Vec<Vec<u8>> {
    p.engine.forensic(&p.backend).unwrap().into_iter().map(|r| r.plain).collect()
}

/// Where the attack on `engine` over `backend` recovers `marker` (empty: nowhere).
pub fn found_in(engine: &mut osis_node::Engine, backend: &osis_store::MemoryBackend, marker: &[u8]) -> Vec<osis_store::Source> {
    engine.forensic(backend).unwrap().into_iter().filter(|r| contains(&r.plain, marker)).map(|r| r.from).collect()
}

/// A content snapshot of `(t, a)` by peer `by` at `ts` carrying `f` (hand-built, unchecked).
pub fn forge_snapshot(lp: &mut LocalPeer, by: usize, t: Tid, a: &osis_base::Ak, ts: osis_base::Ts, f: osis_crdt::Fragment) -> Vec<u8> {
    forge_snapshot_with(lp, by, t, a, ts, f, Default::default())
}

pub fn forge_snapshot_with(lp: &mut LocalPeer, by: usize, t: Tid, a: &osis_base::Ak, ts: osis_base::Ts, f: osis_crdt::Fragment, frontiers: osis_crdt::Frontiers) -> Vec<u8> {
    forge_snapshot_absorbing(lp, by, t, a, ts, f, frontiers, Default::default())
}

/// `forge_snapshot_with` listing `absorbed` (commit ID -> author).
#[allow(clippy::too_many_arguments)]
pub fn forge_snapshot_absorbing(lp: &mut LocalPeer, by: usize, t: Tid, a: &osis_base::Ak, ts: osis_base::Ts, f: osis_crdt::Fragment, frontiers: osis_crdt::Frontiers, absorbed: std::collections::BTreeMap<osis_base::CommitId, Tid>) -> Vec<u8> {
    use osis_commit::{Form, Kind, writer_ctx};
    let author = lp.peers[by].engine.tid();
    let snap = osis_crdt::Snapshot { absorbed, nonce: [7; 16], fragment: f, frontiers };
    let bytes = osis_crdt::encode_snapshot(&snap, &writer_ctx(Form::Commit, Kind::ContentSnapshot, ts, author, 0, 0), None).unwrap();
    forge_snapshot_bytes(lp, by, t, a, ts, bytes)
}

/// A content snapshot commit of `(t, a)` by peer `by` at `ts` over snapshot delta `bytes` as
/// given (hand-built, unchecked: bad input reaches the receiver's decoder).
pub fn forge_snapshot_bytes(lp: &mut LocalPeer, by: usize, t: Tid, a: &osis_base::Ak, ts: osis_base::Ts, bytes: Vec<u8>) -> Vec<u8> {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs};
    let author = lp.peers[by].engine.tid();
    let mut aw = AspectWrite::new(t, a.clone(), 0, 0, bytes);
    aw.retention = osis_commit::retention::snapshot_retention(a.as_str(), [], 0);
    let mut cb = CommitBuilder::new(Kind::ContentSnapshot, ts, author, author, Form::Commit);
    cb.aspects.push(aw);
    let rec = lp.peers[0].engine.get_typed(&t, &osis_schema::core_types::CREATED).unwrap().unwrap();
    cb.build(&lp.peers[by].engine.identity().keys().signing, &Keys(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
}

/// Secrets for hand-built commits with `writer` retention: dedup, and made-up delete keys
/// (hosts' business).
pub struct Keys(pub osis_base::CreationRecord);
impl osis_commit::Secrets for Keys {
    fn dedup(&self, _: &Tid) -> Option<osis_crypto::Secret32> {
        Some(osis_crypto::dedup_secret(self.0.nonce()))
    }
    fn admin_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([3; 32])).verifying_key())
    }
    fn chain_key(&self) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([1; 32])).verifying_key())
    }
    fn write_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([2; 32])).verifying_key())
    }
}

/// Whether commit `id` (header `h`) owns one of `dots`, carried writes by aspect
/// (`Engine::carried_dots`): its session-form range on the aspect holds one, or a commit-form
/// dot names it.
pub fn owns_carried(h: &osis_commit::Header, id: &CommitId, dots: &std::collections::BTreeSet<(Tid, Ak, osis_crdt::Dot)>) -> bool {
    h.aspects.iter().any(|a| {
        dots.iter().filter(|(t, k, _)| *t == a.tid && *k == a.ak).any(|(_, _, d)| match d.src.kind() {
            osis_crdt::SourceKind::Session(_) => h.form.counted() && d.src == h.form.own_source(h.author, *id) && a.lo <= d.ctr && d.ctr < a.hi,
            osis_crdt::SourceKind::Commit(c) => c == id,
            osis_crdt::SourceKind::Node(_) | osis_crdt::SourceKind::Derived(_) => false,
        })
    })
}

/// A session of `node` for hand-built commits (spec/crdt.md §2.1): one of its own, apart from
/// its engine's.
pub fn forged_session(node: Tid) -> osis_commit::Form {
    let _ = node;
    osis_commit::Form::Session([0x5e; 16])
}

/// The session form of peer `i`'s engine: what its own commits write under.
pub fn session_of(lp: &LocalPeer, i: usize) -> osis_commit::Form {
    osis_commit::Form::Session(lp.peers[i].engine.ephemeral_session().nonce)
}

/// Node `e` as a reader to box a secret to.
pub fn read_recipient(e: &Engine) -> osis_keys::Recipient {
    osis_keys::Recipient { holder: e.tid(), role: Role::Read, keys: osis_keys::HolderKeys::KeyActor { kem: e.identity().keys().kem.public().clone(), seed: None } }
}

/// The stamp of a `forge_pending_grant` commit.
pub fn grant_ts(bytes: &[u8]) -> osis_base::WallMs {
    osis_commit::CommitBlob::decode(bytes).unwrap().header.ts.wall_ms()
}

/// A role commit by `by` boxing `rcpt` (`read_recipient`) a fresh read secret of `t` (a
/// re-grant the recipient judges plausible when `by` is an admin of `t`), stamped past the drift
/// bound of a node at `by`'s clock, so it pends there (hand-built): the only wait such a part has.
/// `grant_ts` gives the stamp; a node's clock there and `Engine::freeze_pending` keep it pending.
pub fn forge_pending_grant(by: &mut Engine, rcpt: osis_keys::Recipient, t: Tid, seed: u64) -> Vec<u8> {
    use osis_commit::{AspectWrite, CommitBuilder, Form, MemoryBlobs, writer_ctx};
    use osis_crdt::{Delta, Source, Writer, create, encode_delta};
    let mut held = osis_keys::ActorEpochs::default();
    held.read.set_established(osis_keys::Epoch::new(1, [0; 32]).unwrap(), osis_keys::Provenance::Fixed);
    let rot = osis_keys::rotate(&t, &[Role::Read].into(), &held, &ct::Secrets::default(), &[rcpt], &osis_keys::Names::default(), &mut osis_crypto::SeededRng::from_u64(seed)).unwrap();
    let v = ct::Secrets { boxes: rot.secrets.boxes, history: rot.secrets.history.into_iter().collect() }.to_value();
    let ak = Ak::new("secrets.0").unwrap();
    let author = by.tid();
    let ts = osis_base::Ts::make(osis_base::WallMs(by.now().0 + 2 * osis_base::format::MAX_DRIFT_MS), 0).unwrap();
    let view = osis_schema::core_schema().view(ak.as_str()).unwrap();
    let mut w = Writer::new(ts, Source::commit(CommitId([0; 32])), 1);
    let f = create(&mut w, &view, &v).unwrap();
    let r = w.range();
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(Form::Commit, Kind::Role, ts, author, r.lo, r.hi), None).unwrap();
    let mut cb = CommitBuilder::new(Kind::Role, ts, author, author, Form::Commit);
    let mut aw = AspectWrite::new(t, ak.clone(), r.lo, r.hi, bytes);
    aw.retention = osis_commit::retention::write_retention(ak.as_str(), None, None).unwrap();
    cb.aspects.push(aw);
    let rec = by.get_typed(&t, &ct::CREATED).unwrap().unwrap();
    cb.build(&by.identity().keys().signing, &Keys(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
}

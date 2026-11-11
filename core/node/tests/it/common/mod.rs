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
revision 1;
type item = struct { name 0: string, n 1: int };
type shape = enum { dot 0, circle 1 (int) };
type book = struct { entries 0: map<string, string>, note 1: string };
aspect t:reg.0: string;
aspect t:count.0: counter<int>;
aspect t:hi.0: max<int>;
aspect t:lo.0: min<int>;
aspect t:rec.0: item;
aspect t:shape.0: shape;
aspect t:tags.0: set<string>;
aspect t:map.0: map<string, item>;
aspect t:big.0: map<string, string>;
purgeable_by(writer) aspect t:gone.0: string;
purgeable_by(writer) aspect t:gone2.0: string;
purgeable_by(writer) aspect t:gonemap.0: map<string, string>;
expires(1h) aspect t:brief.0: string;
purgeable_by(writer) aspect t:kept.0: string;
purgeable_by(writer) aspect t:keptset.0: set<string>;
purgeable_by(writer) aspect t:keptmap.0: map<string, string>;
aspect t:list.0: list<string>;
ephemeral aspect t:log+.0: list<string>;
aspect t:listtext.0: list<text>;
aspect t:text.0: text;
aspect t:blob.0: blob;
aspect t:book.0: book;
aspect t:docs.0: map<string, text>;
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
pub const KEPTMAP: Aspect<Value> = Aspect::new("t:keptmap.0", &TEST);
pub const LIST: Aspect<Value> = Aspect::new("t:list.0", &TEST);
pub const LOG: Aspect<Value> = Aspect::new("t:log+.0", &TEST);
pub const TEXT: Aspect<Value> = Aspect::new("t:text.0", &TEST);
pub const BLOB: Aspect<Value> = Aspect::new("t:blob.0", &TEST);
pub const BOOK: Aspect<Value> = Aspect::new("t:book.0", &TEST);
pub const DOCS: Aspect<Value> = Aspect::new("t:docs.0", &TEST);
pub const BIGMAP: Aspect<Value> = Aspect::new("t:big.0", &TEST);
pub const LISTTEXT: Aspect<Value> = Aspect::new("t:listtext.0", &TEST);

/// Purgeable by `by`.
pub fn purgeable_by(by: osis_base::PurgeBy) -> osis_schema::Retention {
    osis_schema::Retention { by }
}

/// Kept a day after replaced: what an undo writing back replaced content needs (spec/crdt.md §4.6).
pub const DAY: osis_schema::History = osis_schema::History::Keep { until: None, after: Some(86_400_000) };

/// What `TEST`'s things keep (spec/commits.md §5 The setting): `t:gone*` purged on replace, `t:kept*`
/// a day after replaced, nothing elsewhere. Written where the helpers create a thing.
pub fn test_setting() -> ct::RetentionSetting {
    let gone = osis_schema::History::PurgeOnReplace;
    setting(&[("t:gone.0", gone), ("t:gone2.0", gone), ("t:gonemap.0", gone), ("t:kept.0", DAY), ("t:keptset.0", DAY), ("t:keptmap.0", DAY)])
}

/// A `retention^.0` setting keeping `history` for each AK named.
pub fn setting(entries: &[(&str, osis_schema::History)]) -> ct::RetentionSetting {
    entries.iter().map(|(a, h)| (ak(a), ct::RetentionEntry { history: Some(*h), ..Default::default() })).collect()
}

/// A setting keeping a day of history after replaced on every aspect (its default): what an undo
/// writing back replaced content needs (spec/crdt.md §4.6).
pub fn day_setting() -> ct::RetentionSetting {
    ct::RetentionSetting { default: Some(ct::RetentionEntry { history: Some(DAY), ..Default::default() }), ..Default::default() }
}

/// `m` also writes setting `x` on `t` (its writer must be an admin of `t`).
pub fn keep_in(m: &mut osis_node::Mutation, t: Tid, x: &ct::RetentionSetting) {
    m.set(t, &ct::RETENTION, x).unwrap();
}

/// Peer `i`, an admin of `t`, writes setting `x` on it: its commit.
pub fn set_setting(lp: &mut LocalPeer, i: usize, t: Tid, x: &ct::RetentionSetting) -> CommitId {
    let mut m = osis_node::Mutation::new();
    m.set(t, &ct::RETENTION, x).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

pub fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

/// Sets enough long-keyed aspects of `t` that the commit's aspect list passes `CHUNK_THRESHOLD`
/// and goes by link (spec/wire.md §4); few of them, as a commit's cost grows with its parts.
/// Returns the first key.
pub fn link_aspects(m: &mut osis_node::Mutation, t: Tid) -> Ak {
    let n = osis_base::format::CHUNK_THRESHOLD / 1000 + 4;
    let name = |i: usize| ak(&format!("u:{}{i:05}.0", "a".repeat(1000)));
    for i in 0..n {
        m.set(t, &name(i), &s("v")).unwrap();
    }
    name(0)
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

/// `net` whose peers join no account: the test makes or pairs them.
pub fn net_bare(n: usize, seed: u64) -> LocalPeer {
    LocalPeer::new_bare(n, seed, T0).unwrap()
}

/// `net` with every peer answering removals with no addenda (`Engine::write_addenda`): for an
/// oracle checking that what a node reads is a function of the commits it received alone.
pub fn net_off(n: usize, seed: u64) -> LocalPeer {
    let mut lp = net(n, seed);
    for p in &mut lp.peers {
        p.engine.write_addenda(false);
    }
    lp
}

/// A new thing whose first admin is peer `i`'s node.
pub fn new_thing(lp: &mut LocalPeer, i: usize) -> Tid {
    new_thing_keeping(lp, i, &[])
}

/// `new_thing` whose setting also keeps `extra` (each AK's history beside `test_setting`'s).
pub fn new_thing_keeping(lp: &mut LocalPeer, i: usize, extra: &[(&str, osis_schema::History)]) -> Tid {
    let p = lp.peer(i).unwrap();
    let me = p.engine.me();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    m.set(t, &REG, &s("new")).unwrap();
    let mut x = test_setting();
    x.rules.extend(setting(extra).rules);
    m.set(t, &ct::RETENTION, &x).unwrap();
    p.commit(m).unwrap();
    t
}

pub fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None }
}

/// Peer `i` writes `holder`'s edge on `thing` as remove + put (`None` removes it), with an
/// optional frontier: a write that needs one given none carries an empty one (an explicit
/// removal, one with no frontier being a finalize, or a write that audits, spec/permissions.md
/// §2, §5.1). A hand-built frontier says exactly what this node lists: it answers the write
/// with no addendum of its own (`Engine::write_addenda`), which would list the rest. A bare edge
/// write (no secrets): `LocalPeer` runs no sync passes, so no repair follows it here; on a
/// `Net`, set up access with `Net::grant`.
pub fn set_edge(e: &mut Engine, thing: Tid, holder: Tid, edge: Option<ct::Edge>, frontier: Option<Value>) -> CommitId {
    if frontier.is_some() || e.needs_frontier(&thing, &holder, edge.as_ref()) {
        e.write_addenda(false);
    }
    // an edge change is remove + put (spec/permissions.md §2)
    let mut m = Mutation::new();
    m.op(thing, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(holder)) }).unwrap();
    let needs = e.needs_frontier(&thing, &holder, edge.as_ref());
    if let Some(x) = edge {
        m.op(thing, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(x.to_value()) }).unwrap();
    }
    if let Some(f) = frontier.or_else(|| needs.then(|| ct::Frontier::default().to_value())) {
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
    let author = lp.peers[by].engine.me();
    let snap = osis_crdt::Snapshot { absorbed, nonce: [7; 16], fragment: f, frontiers };
    let bytes = osis_crdt::encode_snapshot(&snap, &writer_ctx(Form::Commit, Kind::ContentSnapshot, ts, author, 0, 0), None).unwrap();
    forge_snapshot_bytes(lp, by, t, a, ts, bytes)
}

/// A content snapshot commit of `(t, a)` by peer `by` at `ts` over snapshot delta `bytes` as
/// given (hand-built, unchecked: bad input reaches the receiver's decoder).
pub fn forge_snapshot_bytes(lp: &mut LocalPeer, by: usize, t: Tid, a: &osis_base::Ak, ts: osis_base::Ts, bytes: Vec<u8>) -> Vec<u8> {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs};
    let author = lp.peers[by].engine.me();
    let mut aw = AspectWrite::new(t, a.clone(), 0, 0, bytes);
    aw.retention = osis_commit::retention::snapshot_retention(a.as_str());
    let mut cb = CommitBuilder::new(Kind::ContentSnapshot, ts, author, author, Form::Commit);
    cb.aspects.push(aw);
    let rec = lp.peers[0].engine.get_typed(&t, &osis_schema::core_types::CREATED).unwrap().unwrap();
    let forge_key = lp.peers[by].engine.sign_forged(&mut cb);
    cb.build(&forge_key, &Keys(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
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

/// Whether commit `id` (header `h`) carries one of `dots`, carried writes by aspect
/// (`Engine::carried_dots`): its session-form range on the aspect holds one, or a commit-form
/// dot names it.
pub fn owns_carried(h: &osis_commit::Header, id: &CommitId, dots: &std::collections::BTreeSet<(Tid, Ak, osis_crdt::Dot)>) -> bool {
    h.aspects.iter().any(|a| {
        dots.iter().filter(|(t, k, _)| *t == a.tid && *k == a.ak).any(|(_, _, d)| match d.src.kind() {
            osis_crdt::SourceKind::Session(_) => h.form.counted() && d.src == h.form.own_source(h.author, *id) && a.lo <= d.ctr && d.ctr < a.hi,
            osis_crdt::SourceKind::Commit(c) => c == id,
            osis_crdt::SourceKind::Derived(_) => false,
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
    lp.peers[i].engine.own_session_form()
}

/// Node `e` as a reader to box a secret to.
pub fn read_recipient(e: &mut Engine) -> osis_keys::Recipient {
    let me = e.me();
    osis_keys::Recipient { holder: me, role: Role::Read, keys: e.account_holder_keys(&me).unwrap() }
}

/// The stamp of a `forge_pending_grant` commit.
pub fn grant_ts(bytes: &[u8]) -> osis_base::WallMs {
    osis_commit::CommitBlob::decode(bytes).unwrap().header.ts.wall_ms()
}

/// The keep-at-least bound of the body holding part `(t, a)` of `c` (`Engine::body_keeps`).
pub fn body_keep(e: &mut Engine, c: &CommitId, t: &Tid, a: &Ak) -> u64 {
    let ai = e.header(c).unwrap().aspects.iter().position(|x| x.tid == *t && x.ak == *a).unwrap();
    e.body_keeps(c).unwrap()[ai]
}

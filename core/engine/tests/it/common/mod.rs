#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, dead_code)]
//! Shared test helpers: a test schema with one aspect per encoding, grants, delivery.

use osis_commit::Kind;
use osis_base::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_engine::local_peer::{LocalPeer, Package};
use osis_engine::{Engine, Mutation};
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
aspect t:refs.0: set<ref>;
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
pub const REFS: Aspect<Value> = Aspect::new("t:refs.0", &TEST);
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
pub fn keep_in(m: &mut osis_engine::Mutation, t: Tid, x: &ct::RetentionSetting) {
    m.set(t, &ct::RETENTION, x).unwrap();
}

/// Peer `i`, an admin of `t`, writes setting `x` on it: its commit.
pub fn set_setting(lp: &mut LocalPeer, i: usize, t: Tid, x: &ct::RetentionSetting) -> CommitId {
    let mut m = osis_engine::Mutation::new();
    m.set(t, &ct::RETENTION, x).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

pub fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

/// Sets enough long-keyed aspects of `t` that the commit's aspect list passes `CHUNK_THRESHOLD`
/// and goes by link (spec/wire.md §4); few of them, as a commit's cost grows with its parts.
/// Returns the first key.
pub fn link_aspects(m: &mut osis_engine::Mutation, t: Tid) -> Ak {
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

/// `n` peers, each its own account (`LocalPeer::new` at `T0`), each holding the others' account
/// chains (synced once), so any may grant any: built once per `(n, seed)` (`LocalPeer::cached`; a
/// copy costs less than a build).
pub fn net(n: usize, seed: u64) -> LocalPeer {
    LocalPeer::cached(&format!("common::net/{n}/{seed}"), || {
        let mut lp = LocalPeer::new(n, seed, T0).unwrap();
        lp.sync_all().unwrap();
        (lp, ())
    })
    .0
}

/// `n` peers, each its own account, that have met no other (`LocalPeer::new` at `T0`).
pub fn net_apart(n: usize, seed: u64) -> LocalPeer {
    LocalPeer::cached(&format!("common::net_apart/{n}/{seed}"), || (LocalPeer::new_apart(n, seed, T0).unwrap(), ())).0
}

/// `n` peers, the nodes of one account (peer 0 made it, the others paired, nothing else synced):
/// each holds what another makes under the account root (`new_thing`) once it holds its record
/// and the root's strong to it. Built once per `n` (`LocalPeer::cached`).
pub fn net_one(n: usize) -> LocalPeer {
    LocalPeer::cached(&format!("common::net_one/{n}"), || {
        let mut lp = LocalPeer::new_bare(n, 0, T0).unwrap();
        lp.peers[0].engine.create_account().unwrap();
        let mut rest = lp.peers.split_off(1);
        for p in &mut rest {
            pair_into(&mut lp, 0, p);
        }
        lp.peers.extend(rest);
        (lp, ())
    })
    .0
}

/// Pairs `p`, a node that joined no account, into peer `by`'s account (as `Engine::pair` over a
/// direct connection).
pub fn pair_into(lp: &mut LocalPeer, by: usize, p: &mut osis_engine::local_peer::Peer) {
    let account = lp.peers[by].engine.me();
    for id in p.engine.commit_ids() {
        let pk = p.engine.package(&id).unwrap().unwrap();
        lp.deliver(by, &pk).unwrap();
    }
    let node = p.engine.tid();
    let (_, send) = lp.peers[by].engine.pair(&node).unwrap();
    for id in send {
        let pk = lp.peers[by].engine.package(&id).unwrap().unwrap();
        p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    p.engine.paired(&account).unwrap();
}

/// `net` whose peers join no account: the test makes or pairs them.
pub fn net_bare(n: usize, seed: u64) -> LocalPeer {
    LocalPeer::cached(&format!("common::net_bare/{n}/{seed}"), || (LocalPeer::new_bare(n, seed, T0).unwrap(), ())).0
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

/// A new plain thing of peer `i`: its mint admin `Engine::plain_admin`, held where it lives and
/// by every other peer (`LocalPeer::hold`), which keeps it once granted a role (`set_edge`).
pub fn new_thing(lp: &mut LocalPeer, i: usize) -> Tid {
    new_thing_keeping(lp, i, &[])
}

/// `new_thing` whose setting also keeps `extra` (each AK's history beside `test_setting`'s).
pub fn new_thing_keeping(lp: &mut LocalPeer, i: usize, extra: &[(&str, osis_schema::History)]) -> Tid {
    let p = lp.peer(i).unwrap();
    let admin = p.engine.plain_admin();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, admin);
    m.set(t, &REG, &s("new")).unwrap();
    let mut x = test_setting();
    x.rules.extend(setting(extra).rules);
    m.set(t, &ct::RETENTION, &x).unwrap();
    p.commit(m).unwrap();
    lp.hold(t);
    t
}

/// `new_thing` shared with the net (`share`).
pub fn new_shared(lp: &mut LocalPeer, i: usize) -> Tid {
    let t = new_thing(lp, i);
    share(lp, i, t);
    t
}

/// Every other peer holding no role on `t` is granted read on it through the flow by peer
/// `admin`, an admin of it: each keeps what it receives of `t`.
pub fn share(lp: &mut LocalPeer, admin: usize, t: Tid) {
    for j in (0..lp.peers.len()).filter(|j| *j != admin) {
        let who = lp.peers[j].engine.me();
        if lp.peers[admin].engine.key_role(&t, &who).is_none() {
            lp.peers[admin].engine.grant(&t, &who, &edge(Role::Read)).unwrap();
        }
    }
}

pub fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, retain: false, floor: None }
}

/// Writes `holder`'s edge on `thing`: a grant by the flow (`Engine::grant`: the holder's secrets
/// with it, so a holder holding the thing keeps it) when the write needs no frontier and is given
/// none, else `edge_write`. Its edge commit.
pub fn set_edge(e: &mut Engine, thing: Tid, holder: Tid, edge: Option<ct::Edge>, frontier: Option<ct::Frontier>) -> CommitId {
    match &edge {
        Some(x) if frontier.is_none() && !e.needs_frontier(&thing, &holder, edge.as_ref()) => *e.grant(&thing, &holder, x).unwrap().commits.last().unwrap(),
        _ => edge_write(e, thing, holder, edge, frontier),
    }
}

/// Writes `holder`'s edge on `thing` as a bare remove + put (`None` removes it; no secrets: for a
/// holder no peer is, or an edge between things), with an optional frontier: a write that needs
/// one given none carries an empty one (an explicit removal, one with no frontier being a
/// finalize, or a write that audits, spec/permissions.md §2, §5.1). A hand-built frontier says
/// exactly what this node lists: it answers the write with no addendum of its own
/// (`Engine::write_addenda`), which would list the rest.
pub fn edge_write(e: &mut Engine, thing: Tid, holder: Tid, edge: Option<ct::Edge>, frontier: Option<ct::Frontier>) -> CommitId {
    if frontier.is_some() || e.needs_frontier(&thing, &holder, edge.as_ref()) {
        e.write_addenda(false);
    }
    // an edge change is remove + put (spec/permissions.md §2)
    let mut m = Mutation::new();
    m.op(thing, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Weak(holder)) }).unwrap();
    let needs = e.needs_frontier(&thing, &holder, edge.as_ref());
    if let Some(x) = edge {
        m.op(thing, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Weak(holder))], op: Op::Set(x.to_value()) }).unwrap();
    }
    if let Some(f) = frontier.or_else(|| needs.then(ct::Frontier::default)) {
        m.frontier(osis_perm::Frontier::new(f.commits));
    }
    e.commit(m).unwrap().unwrap()
}

/// A fresh observer of `t`: a node of its own account (`Peer::new` at peer `admin`'s time) holding
/// `t`, granted read on it by peer `admin` through the flow, holding what peer `admin` holds then
/// (made before the history a test judges: what it holds of `t` is its base), so it opens and keeps
/// what it is given of `t`. Kept outside `lp`, a template: each copy (`fresh_copy`) is one fresh
/// node, given what the test gives it.
pub fn reader(lp: &mut LocalPeer, admin: usize, t: Tid, seed: u64) -> osis_engine::local_peer::Peer {
    let mut p = osis_engine::local_peer::Peer::new(seed, lp.peers[admin].engine.now()).unwrap();
    lp.peers[admin].know(&[p.engine.me()]).unwrap();
    for id in p.engine.commit_ids() {
        let pk = p.engine.package(&id).unwrap().unwrap();
        lp.deliver(admin, &pk).unwrap();
    }
    p.engine.hold(osis_base::Strong(t)).unwrap();
    let me = p.engine.me();
    lp.peers[admin].engine.grant(&t, &me, &edge(Role::Read)).unwrap();
    for pk in packages(lp, admin) {
        p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    p.reexamine().unwrap();
    assert!(p.engine.closure_holds(&t), "the observer holds {t:?}");
    p
}

/// A copy of observer `p` (`reader`) at wall time `at`: one fresh node.
pub fn fresh_copy(p: &mut osis_engine::local_peer::Peer, at: WallMs) -> osis_engine::local_peer::Peer {
    let q = p.copy().unwrap();
    q.clock.set(at);
    q
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
pub fn recoverable(p: &mut osis_engine::local_peer::Peer, marker: &[u8]) -> bool {
    plaintexts(p).iter().any(|x| contains(x, marker))
}

/// `recoverable` of each marker, from one attack (an attack costs seconds).
pub fn recovered<const N: usize>(p: &mut osis_engine::local_peer::Peer, markers: [&[u8]; N]) -> [bool; N] {
    let found = plaintexts(p);
    markers.map(|m| found.iter().any(|x| contains(x, m)))
}

/// Every plaintext an attacker recovers.
pub fn plaintexts(p: &mut osis_engine::local_peer::Peer) -> Vec<Vec<u8>> {
    p.engine.forensic(&p.backend, &p.blob_disk.0).unwrap().into_iter().map(|r| r.plain).collect()
}

/// Where the attack on peer `p`'s device recovers `marker` (empty: nowhere).
pub fn found_in(p: &mut osis_engine::local_peer::Peer, marker: &[u8]) -> Vec<osis_store::Source> {
    p.engine.forensic(&p.backend, &p.blob_disk.0).unwrap().into_iter().filter(|r| contains(&r.plain, marker)).map(|r| r.from).collect()
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
    let snap = osis_crdt::Snapshot { absorbed, facts: Default::default(), nonce: [7; 16], fragment: f, frontiers };
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
    cb.build(&forge_key, &Keys(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(0)).unwrap().commit.encode()
}

/// Secrets for hand-built commits with `writer` retention: dedup, and made-up delete keys
/// (peers' business).
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
    osis_keys::Recipient { holder: me, role: Role::Read, keys: e.account_holder_keys(&me).unwrap(), floor: 0 }
}

/// The keep-at-least bound of part `(t, a)` of `c` (`Engine::part_keeps`).
pub fn part_keep(e: &mut Engine, c: &CommitId, t: &Tid, a: &Ak) -> u64 {
    let ai = e.header(c).unwrap().aspects.iter().position(|x| x.tid == *t && x.ak == *a).unwrap();
    e.part_keeps(c).unwrap()[ai]
}

/// The purge item naming commit `c`'s delta on `(tid, ak)` by its stamp, from its header `h`.
pub fn stamp_item(h: &osis_commit::Header, c: CommitId, tid: Tid, ak: osis_base::Ak) -> osis_commit::PurgeItem {
    osis_commit::PurgeItem::Commit { tid, ak, ts: h.ts, src: h.form.own_source(h.author, c) }
}

/// The blobs a held commit's deltas link (their pages and their values' trees, through the node
/// and page blobs `e` holds; spec/sync-judgement.md §1), durable or in memory; none when not held.
pub fn linked_blobs(e: &mut Engine, c: &CommitId) -> Vec<osis_base::BlobId> {
    held_bytes(e, c).and_then(|bytes| e.body_links(&bytes).ok()).map(|t| t.blobs.into_iter().collect()).unwrap_or_default()
}

/// Commit `c`'s bytes as `e` holds it, stored or in memory.
pub fn held_bytes(e: &mut Engine, c: &CommitId) -> Option<Vec<u8>> {
    match e.commit_bytes(c) {
        Ok(Some(b)) => Some(b),
        _ => e.memory_blob(c).ok().flatten().map(|b| b.encode()),
    }
}

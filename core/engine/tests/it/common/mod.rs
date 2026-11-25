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
purge_by(writer) aspect t:gone.0: string;
purge_by(writer) aspect t:gone2.0: string;
purge_by(writer) aspect t:gonemap.0: map<string, string>;
expires(1h) aspect t:brief.0: string;
purge_by(writer) aspect t:kept.0: string;
purge_by(writer) aspect t:keptset.0: set<string>;
purge_by(writer) aspect t:keptmap.0: map<string, string>;
aspect t:list.0: list<string>;
ephemeral aspect t:log+.0: list<string>;
ephemeral aspect t:emap+.0: map<string, string>;
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
pub const EMAP: Aspect<Value> = Aspect::new("t:emap+.0", &TEST);
pub const TEXT: Aspect<Value> = Aspect::new("t:text.0", &TEST);
pub const BLOB: Aspect<Value> = Aspect::new("t:blob.0", &TEST);
pub const BOOK: Aspect<Value> = Aspect::new("t:book.0", &TEST);
pub const DOCS: Aspect<Value> = Aspect::new("t:docs.0", &TEST);
pub const BIGMAP: Aspect<Value> = Aspect::new("t:big.0", &TEST);
pub const LISTTEXT: Aspect<Value> = Aspect::new("t:listtext.0", &TEST);

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

/// `n` peers (`LocalPeer::new` at `T0`), each holding the others'
/// records (synced once), so any may grant any: built once per `(n, seed)` (`LocalPeer::cached`; a
/// copy costs less than a build).
pub fn net(n: usize, seed: u64) -> LocalPeer {
    LocalPeer::cached(&format!("common::net/{n}/{seed}"), || {
        let mut lp = LocalPeer::new(n, seed, T0).unwrap();
        lp.sync_all().unwrap();
        (lp, ())
    })
    .0
}

/// Every order of `0..n` (n small).
pub fn perms(n: usize) -> Vec<Vec<usize>> {
    let mut out = vec![Vec::new()];
    for i in 0..n {
        out = out.into_iter().flat_map(|p: Vec<usize>| (0..=p.len()).map(move |at| {
            let mut q = p.clone();
            q.insert(at, i);
            q
        })).collect();
    }
    out
}

/// `n` peers that have met no other (`LocalPeer::new` at `T0`).
pub fn net_apart(n: usize, seed: u64) -> LocalPeer {
    LocalPeer::cached(&format!("common::net_apart/{n}/{seed}"), || (LocalPeer::new_apart(n, seed, T0).unwrap(), ())).0
}

/// `n` peers, the nodes of one account (`LocalPeer::one_account`: peer 0 makes it, the others
/// paired in at admin): built once per `n`.
pub fn net_one(n: usize) -> LocalPeer {
    LocalPeer::cached(&format!("common::net_one/{n}"), || (LocalPeer::one_account(n, 0, T0).unwrap().0, ())).0
}

/// The account of `net_one`'s peers.
pub fn account_of(lp: &mut LocalPeer) -> Tid {
    lp.peers[0].engine.settings_thing().unwrap().unwrap()
}

/// Pairs `p` into peer `by`'s account (`LocalPeer::pair_into`).
pub fn pair_into(lp: &mut LocalPeer, by: usize, p: &mut osis_engine::local_peer::Peer) {
    lp.pair_into(by, p).unwrap();
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

/// A new dependent thing of peer `i`: its mint admin the account the peer acts for
/// (`settings_thing`: made for the account, so its other nodes read it, spec/permissions.md §8),
/// else `Engine::me`; held where it lives and by every other peer (`LocalPeer::hold`), which
/// keeps it once granted a role (`set_edge`).
pub fn new_thing(lp: &mut LocalPeer, i: usize) -> Tid {
    new_thing_keeping(lp, i, &[])
}

/// `new_thing` whose setting also keeps `extra` (each AK's history beside `test_setting`'s).
pub fn new_thing_keeping(lp: &mut LocalPeer, i: usize, extra: &[(&str, osis_schema::History)]) -> Tid {
    let p = lp.peer(i).unwrap();
    let admin = p.engine.settings_thing().unwrap().unwrap_or_else(|| p.engine.tid());
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

/// Peer `i` commits `v` to `k` on `t` alone.
pub fn put<K: osis_schema::RawKey>(lp: &mut LocalPeer, i: usize, t: Tid, k: &K, v: &K::T) -> CommitId {
    let mut m = Mutation::new();
    m.set(t, k, v).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

/// Peer `i` commits `op` on `k` of `t` alone.
pub fn put_op<K: osis_schema::RawKey>(lp: &mut LocalPeer, i: usize, t: Tid, k: &K, op: PathOp) -> CommitId {
    let mut m = Mutation::new();
    m.op(t, k, op).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

/// The tags `TAGS` holds on `t` at peer `i`.
pub fn tags(lp: &mut LocalPeer, i: usize, t: Tid) -> std::collections::BTreeSet<String> {
    match lp.peers[i].engine.get(&t, &ak("t:tags.0")).unwrap() {
        Some(Value::Set(s)) => s.into_iter().map(|v| if let Value::Str(x) = v { x } else { String::new() }).collect(),
        _ => std::collections::BTreeSet::new(),
    }
}

/// Peer `i` adds `tag` to `TAGS` on `t`.
pub fn add_tag(lp: &mut LocalPeer, i: usize, t: Tid, tag: &str) -> CommitId {
    put_op(lp, i, t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s(tag)) })
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
        let who = lp.peers[j].engine.tid();
        if lp.peers[admin].engine.key_role(&t, &who).is_none() {
            lp.peers[admin].engine.grant(&t, &who, &edge(Role::Read)).unwrap();
        }
    }
}

pub fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, may_grant: false, retain: false, floor: None }
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
    lp.peers[admin].know(&[p.engine.tid()]).unwrap();
    for id in p.engine.commit_ids() {
        let pk = p.engine.package(&id).unwrap().unwrap();
        lp.deliver(admin, &pk).unwrap();
    }
    p.engine.hold(osis_base::Strong(t)).unwrap();
    let me = p.engine.tid();
    lp.peers[admin].engine.grant(&t, &me, &edge(Role::Read)).unwrap();
    // what `admin` sends it: the grant's fire, certificates (the grant among them), then what
    // the sync IDs it then syncs carry
    lp.pass_fires_to(admin, &mut p).unwrap();
    for _ in 0..2 {
        let synced = p.engine.sync_set().unwrap().ids.keys().copied().collect();
        for pk in lp.packages_under(admin, &synced).unwrap() {
            p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
        }
    }
    p.reexamine().unwrap();
    assert!(p.engine.closure_holds(&t), "the observer holds {t:?}");
    p
}

/// A fresh node apart from `lp` (seeded `seed`) holding `t`, granted read on it by peer `admin`
/// through the flow and given nothing else (`LocalPeer::fresh_reader`), as a one-peer net: it
/// keeps what it is then handed of `t`, in any order.
pub fn fresh_net(lp: &mut LocalPeer, admin: usize, t: Tid, seed: u64) -> LocalPeer {
    LocalPeer::apart(vec![lp.fresh_reader(admin, t, seed)], seed)
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

/// What `from` sends peer `to` in a sync, `to`'s sync set as it stands (`LocalPeer::packages_for`).
pub fn packages_for(lp: &mut LocalPeer, from: usize, to: usize) -> Vec<Package> {
    lp.packages_for(from, to).unwrap()
}

/// Commit `id` as `from` sends it to peer `to` (`packages_for`); panics when no sync ID `to`
/// syncs carries it.
pub fn package_for(lp: &mut LocalPeer, from: usize, to: usize, id: CommitId) -> Package {
    packages_for(lp, from, to).into_iter().find(|p| p.id == id).unwrap_or_else(|| panic!("{from} sends {to} no {id:?}"))
}

/// What `from` sends `p`, a node apart, in a sync: `packages_under` the sync IDs `p` syncs as it
/// stands (an observer from `reader`, whose sync set its grant already moved).
pub fn packages_for_peer(lp: &mut LocalPeer, from: usize, p: &mut osis_engine::local_peer::Peer) -> Vec<Package> {
    let synced = p.engine.sync_set().unwrap().ids.keys().copied().collect();
    lp.packages_under(from, &synced).unwrap()
}

/// What `from` sends peer `to`, a reader of `t` given its grant alone (`LocalPeer::fresh_reader`):
/// `packages_under` the sync IDs `to` syncs and `t`'s (as `from` holds them), which `to` syncs
/// once it holds `t`'s record. `packages_to` without its copy of the world.
pub fn packages_reading(lp: &mut LocalPeer, from: usize, to: usize, t: Tid) -> Vec<Package> {
    let mut synced = lp.synced(to).unwrap();
    synced.extend(lp.peers[from].engine.sync_ids(&t).unwrap().iter().map(|o| o.id));
    lp.packages_under(from, &synced).unwrap()
}

/// Commit `id` as `from` sends `p`, a node apart (`packages_for_peer`).
pub fn package_for_peer(lp: &mut LocalPeer, from: usize, p: &mut osis_engine::local_peer::Peer, id: CommitId) -> Package {
    packages_for_peer(lp, from, p).into_iter().find(|x| x.id == id).unwrap_or_else(|| panic!("{from} sends no {id:?}"))
}

/// `r`, what a node under test made of hostile, partial or forged input: a refusal of the input
/// (bad input, parked) is `None`; a local error (an engine invariant broken, a store failing)
/// fails the test, as it would fail the node.
pub fn unless_refused(r: osis_engine::Result<osis_engine::Ingested>) -> Option<osis_engine::Ingested> {
    use osis_base::Classified;
    match r {
        Ok(x) => Some(x),
        Err(e) if e.class() == osis_base::ErrorClass::Local => panic!("receiving fails the node: {e}"),
        Err(_) => None,
    }
}


/// What `from` sends peer `to` once `to` syncs what a sync from `from` brings it to sync (its
/// sync set after `LocalPeer::sync`, on a copy of the world): what those sync IDs carry and every
/// certificate (`LocalPeer::packages_under`), for a test handing them over in its own order.
pub fn packages_to(lp: &mut LocalPeer, from: usize, to: usize) -> Vec<Package> {
    lp.packages_to(from, to).unwrap()
}

/// Delivers to peer `to` of `other` (a net apart) what `lp`'s peer `from` sends it in a sync
/// (`LocalPeer::packages_under` the sync IDs it syncs), but the packages `skip` names: again
/// while what it syncs grows (a grant or a rotation it takes moves its sync IDs).
pub fn give_carried(lp: &mut LocalPeer, from: usize, other: &mut LocalPeer, to: usize, skip: impl Fn(&Package) -> bool) {
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let synced = other.synced(to).unwrap();
        if !seen.is_empty() && synced.is_subset(&seen) {
            return;
        }
        seen.extend(synced.iter().copied());
        for p in lp.packages_under(from, &synced).unwrap().iter().filter(|p| !skip(p)) {
            other.deliver(to, p).unwrap();
        }
    }
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

/// `forge_snapshot_with` listing `absorbed` (commit ID -> signer).
#[allow(clippy::too_many_arguments)]
pub fn forge_snapshot_absorbing(lp: &mut LocalPeer, by: usize, t: Tid, a: &osis_base::Ak, ts: osis_base::Ts, f: osis_crdt::Fragment, frontiers: osis_crdt::Frontiers, absorbed: std::collections::BTreeMap<osis_base::CommitId, Tid>) -> Vec<u8> {
    use osis_commit::{Form, Kind, writer_ctx};
    let author = lp.peers[by].engine.tid();
    let snap = osis_crdt::Snapshot { absorbed, facts: Default::default(), nonce: [7; 16], fragment: f, frontiers };
    let bytes = osis_crdt::encode_snapshot(&snap, &writer_ctx(Form::Commit, Kind::ContentSnapshot, ts, author, 0, 0), None).unwrap();
    forge_snapshot_bytes(lp, by, t, a, ts, bytes)
}

/// A content snapshot commit of `(t, a)` by peer `by` at `ts` over snapshot delta `bytes` as
/// given (hand-built, unchecked: bad input reaches the receiver's decoder).
pub fn forge_snapshot_bytes(lp: &mut LocalPeer, by: usize, t: Tid, a: &osis_base::Ak, ts: osis_base::Ts, bytes: Vec<u8>) -> Vec<u8> {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs};
    let author = lp.peers[by].engine.tid();
    let mut aw = AspectWrite::new(t, a.clone(), 0, 0, bytes);
    aw.purge_by = osis_commit::retention::snapshot_purge_by(a.as_str());
    let mut cb = CommitBuilder::new(Kind::ContentSnapshot, ts, author, osis_commit::Path::default(), Form::Commit);
    cb.aspects.push(aw);
    let rec = lp.peers[0].engine.get_typed(&t, &osis_schema::core_types::CREATED).unwrap().unwrap();
    let forge_key = lp.peers[by].engine.identity().signing().clone();
    cb.build(&forge_key, &lp.peers[0].engine.hand_secrets(&[rec]), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(0)).unwrap().commit.encode()
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
    let me = e.tid();
    e.recipient_for(&me, Role::Read).unwrap()
}

/// The keep-at-least bound of part `(t, a)` of `c` (`Engine::part_keeps`).
pub fn part_keep(e: &mut Engine, c: &CommitId, t: &Tid, a: &Ak) -> u64 {
    let ai = e.header(c).unwrap().aspects.iter().position(|x| x.tid == *t && x.ak == *a).unwrap();
    e.part_keeps(c).unwrap()[ai]
}

/// The purge item naming commit `c`'s delta on `(tid, ak)` by its stamp, from its header `h`.
pub fn stamp_item(h: &osis_commit::Header, c: CommitId, tid: Tid, ak: osis_base::Ak) -> osis_commit::PurgeItem {
    osis_commit::PurgeItem::Commit { tid, ak, ts: h.ts, src: h.form.own_source(h.signer, c) }
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

//! Validity is a function of the held set (spec/permissions.md §5, §5.2; spec/requirements.md
//! Decentralization): random writes by a writer and demotions of it, with frontiers before,
//! inside and after its writes (backdated ones included), delivered in every arrival order to
//! fresh nodes, give one verdict per delta and one read.

use crate::local_peer::{LocalPeer, Package, Peer};
use crate::Mutation;
use osis_base::{Ak, Clock, CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_perm::DemotionScope;
use osis_schema::core_types as ct;
use osis_schema::Codec;
use std::collections::{BTreeMap, BTreeSet};

const T0: WallMs = WallMs(1_700_000_000_000);

struct Rng(u64);
impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }
}

fn reg() -> Ak {
    Ak::new("t:reg.0").unwrap()
}

fn edge(lp: &mut LocalPeer, by: usize, t: Tid, m: Tid, role: Option<Role>, frontier: Option<Value>) -> CommitId {
    let mut mu = Mutation::new();
    let op = match role {
        Some(role) => PathOp { path: vec![PathSeg::Key(Value::Tid(m))], op: Op::Set(ct::Edge { role, until: None, invite: None, tied: None }.to_value()) },
        None => PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(m)) },
    };
    mu.op(t, &ct::ROLES, op).unwrap();
    if let Some(f) = frontier {
        mu.frontier(f);
    }
    lp.peers[by].commit(mu).unwrap().unwrap()
}

fn write(p: &mut Peer, t: Tid, v: &str) -> CommitId {
    let mut m = Mutation::new();
    m.set(t, &reg(), &Value::Str(v.into())).unwrap();
    p.commit(m).unwrap().unwrap()
}

/// What a node judged and reads: every listed commit's per-delta verdict (`None`: not applied),
/// what pends, and the register of every listed thing.
type Seen = (Vec<Option<Vec<bool>>>, usize, Vec<Option<Value>>);

fn seen(p: &mut Peer, ids: &[CommitId], things: &[Tid]) -> Seen {
    let v = ids.iter().map(|id| p.engine.core.ix.commits.get(id).map(|m| m.valid.clone())).collect();
    let r = things.iter().map(|t| p.engine.get(t, &reg()).unwrap()).collect();
    (v, p.engine.pending().len(), r)
}

fn perms(n: usize) -> Vec<Vec<usize>> {
    if n == 0 {
        return vec![Vec::new()];
    }
    let mut out = Vec::new();
    for p in perms(n - 1) {
        for i in 0..=p.len() {
            let mut q = p.clone();
            q.insert(i, n - 1);
            out.push(q);
        }
    }
    out
}

/// The shape of a history: B's writes (1-2), the frontier's point (0: before B's writes,
/// backdated; 1 between them; the last: after them), the demoter (0: A, the first admin; 2: C, an
/// admin of G), the grandchild of G (0: none; 1: created in a later commit, so it can arrive
/// late under a late parent; 2: in its parent's commit), and what follows the
/// demotion (0 nothing, 1 B writes again unaware, 2 A grants B again, 3 A gives B read on the
/// item: a commit naming a former leaf).
struct Shape {
    writes: usize,
    at: usize,
    by: usize,
    sub: usize,
    tail: usize,
}

/// One history of `shape`, the rest random. Peer 0 (A) is first admin of G, gives peer 1 (B) write and
/// peer 2 (C) admin; A creates two items under G in one commit, and maybe an item under the first
/// (a grandchild of G) in that commit or the next; B writes on G or on one of them, the demoter receiving each at once or not
/// before the demotion; the demoter removes B with a frontier as of `shape.at`; then the tail.
/// Returns how many orders ran.
fn sample(shape: Shape) -> usize {
    let mut rng = Rng(1); // xorshift needs a nonzero state
    let (mut lp, (g, base)) = LocalPeer::cached("apply::tests_order::sample", || {
        let mut lp = LocalPeer::fresh(3, T0);
        lp.sync_all().unwrap();
        let (a, b, c) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let mut m = Mutation::new();
        let g = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(g, &reg(), &Value::Str("g".into())).unwrap();
        lp.peers[0].commit(m).unwrap();
        edge(&mut lp, 0, g, b, Some(Role::Write), None);
        edge(&mut lp, 0, g, c, Some(Role::Admin), None);
        lp.sync_all().unwrap();
        let base: Vec<CommitId> = lp.peers[0].engine.commit_ids();
        (lp, (g, base))
    });
    let b = lp.peers[1].engine.me();
    lp.advance(1_000);
    let mut m = Mutation::new();
    let item = lp.peers[0].engine.new_thing(&mut m, g);
    let item2 = lp.peers[0].engine.new_thing(&mut m, g);
    m.set(item, &reg(), &Value::Str("v0".into())).unwrap();
    m.set(item2, &reg(), &Value::Str("w0".into())).unwrap();
    if shape.sub == 1 {
        lp.peers[0].commit(std::mem::take(&mut m)).unwrap();
    }
    let sub = if shape.sub > 0 {
        let sub = lp.peers[0].engine.new_thing(&mut m, item);
        m.set(sub, &reg(), &Value::Str("s0".into())).unwrap();
        sub
    } else {
        item2
    };
    lp.peers[0].commit(m).unwrap();
    lp.sync_all().unwrap();
    let by = shape.by;
    let mut marks = vec![lp.peers[by].clock.now_wall_ms()];
    for k in 0..shape.writes {
        lp.advance(1_000);
        let on = [g, item, item2, sub][rng.below(4)];
        let id = write(&mut lp.peers[1], on, &format!("b{k}"));
        if rng.below(2) == 0 {
            let pk = lp.peers[1].engine.package(&id).unwrap().unwrap();
            lp.deliver(by, &pk).unwrap();
        }
        marks.push(lp.peers[1].clock.now_wall_ms());
    }
    lp.advance(1_000);
    let as_of = marks[shape.at.min(shape.writes)];
    let scope = DemotionScope { roles: BTreeMap::from([(b, BTreeSet::from([g]))]), content: BTreeMap::from([(b, BTreeSet::from([g, item, item2, sub]))]) };
    let f = lp.peers[by].engine.frontier(&scope, as_of).unwrap();
    edge(&mut lp, by, g, b, None, Some(f.to_value()));
    lp.advance(1_000);
    match shape.tail {
        1 => {
            write(&mut lp.peers[1], sub, "late");
        }
        2 => {
            lp.sync(by, 0).unwrap();
            edge(&mut lp, 0, g, b, Some(Role::Write), None);
        }
        3 => {
            edge(&mut lp, 0, item, b, Some(Role::Read), None);
        }
        _ => {}
    }
    lp.sync_all().unwrap();
    let mut packs: BTreeMap<CommitId, Package> = BTreeMap::new();
    for i in [0, 1, 2] {
        for pk in lp.packages(i).unwrap() {
            packs.entry(pk.id).or_insert(pk);
        }
    }
    let base: Vec<Package> = base.iter().filter_map(|id| packs.get(id).cloned()).collect();
    let rest: Vec<Package> = packs.values().filter(|p| !base.iter().any(|q| q.id == p.id)).cloned().collect();
    let ids: Vec<CommitId> = packs.keys().copied().collect();
    let things = [g, item, item2, sub];
    let want = seen(&mut lp.peers[0], &ids, &things);
    assert_eq!(want.1, 0, "A holds everything");
    assert_eq!(seen(&mut lp.peers[1], &ids, &things), want, "B judges as A");
    assert_eq!(seen(&mut lp.peers[2], &ids, &things), want, "C judges as A");
    // a fresh node per order: copies of one, a node apart from A, B and C
    let mut fresh = Peer::new(3, lp.peers[0].clock.now_wall_ms()).unwrap();
    let orders = perms(rest.len());
    for order in &orders {
        let mut p = fresh.copy().unwrap();
        for pk in base.iter().chain(order.iter().map(|&i| &rest[i])) {
            p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
        }
        assert_eq!(seen(&mut p, &ids, &things), want, "arrival order {order:?}");
    }
    orders.len()
}

// spec/permissions.md §5 (validity is a deterministic function of the held set), §5.2 (a write
// a demotion's frontier misses is invalid whatever order it arrives in), spec/crdt.md §4.6:
// frontiers before (backdated), inside and after the writer's writes; children of the demoted
// actor created in one commit, a grandchild in a later commit or in theirs; a demotion by an admin other than the
// first admin; a commit naming a former leaf.
#[test]
fn validity_alike_in_every_arrival_order_spec_permissions_5_2() {
    let cases = [(1, 0, 0, 1, 0), (1, 1, 2, 1, 0), (2, 1, 2, 2, 0), (2, 1, 0, 0, 0), (1, 0, 2, 0, 3)];
    for (writes, at, by, sub, tail) in cases {
        assert_eq!(sample(Shape { writes, at, by, sub, tail }), 24);
    }
}

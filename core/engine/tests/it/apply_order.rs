//! Validity is a function of the held set (spec/permissions.md §5, §5.2; spec/requirements.md
//! Decentralization): random writes by a writer and demotions of it, with frontiers before,
//! inside and after its writes (backdated ones included), delivered in every arrival order to
//! fresh nodes, give one verdict per delta and one read.

use osis_engine::local_peer::{LocalPeer, Package, Peer};
use osis_engine::Mutation;
use osis_base::{Ak, Clock, CommitId, Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_engine::DemotionScope;
use osis_schema::core_types as ct;
use osis_schema::Codec;
use std::collections::{BTreeMap, BTreeSet};
use crate::common::T0;

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

fn edge(lp: &mut LocalPeer, by: usize, t: Tid, m: Tid, role: Option<Role>, frontier: Option<osis_perm::Frontier>) -> CommitId {
    let mut mu = Mutation::new();
    let op = match role {
        Some(role) => PathOp { path: vec![PathSeg::Key(Value::Weak(m))], op: Op::Set(ct::Grant { role, until: None, may_grant: false, retain: false, floor: None }.to_value()) },
        None => PathOp { path: Vec::new(), op: Op::Remove(Value::Weak(m)) },
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

/// What a node judged and reads: every listed commit's per-delta verdict on the listed things
/// (`None`: not applied; a part on another's root, unknown to a node that does not hold it, is
/// none of its judgement), what pends, and the register of every listed thing.
type Seen = (Vec<Option<Vec<bool>>>, usize, Vec<Option<Value>>);

fn seen(p: &mut Peer, ids: &[CommitId], things: &[Tid]) -> Seen {
    let on = |m: &osis_engine::engine::Meta| m.view.aspects.iter().zip(m.valid()).filter(|(a, _)| things.contains(&a.tid)).map(|(_, v)| *v).collect();
    let v = ids.iter().map(|id| p.engine.core.ix.commits.get(id).map(on)).collect();
    let r = things.iter().map(|t| p.engine.get(t, &reg()).unwrap()).collect();
    (v, p.engine.pending().len(), r)
}

/// `check` on `p` after each arrival order of `rest` (with the order), walked as a tree: each
/// prefix is received once, by a copy (`Peer::copy`) of the node at the prefix before it. Returns
/// how many orders ran.
fn each_order(mut p: Peer, rest: &[Package], order: &mut Vec<usize>, check: &mut dyn FnMut(&[usize], &mut Peer)) -> usize {
    let left: Vec<usize> = (0..rest.len()).filter(|i| !order.contains(i)).collect();
    let Some((&last, others)) = left.split_last() else {
        check(order, &mut p);
        return 1;
    };
    let mut next = |mut q: Peer, i: usize| {
        q.receive(&rest[i].bytes, rest[i].blobs.clone()).unwrap();
        order.push(i);
        let n = each_order(q, rest, order, check);
        order.pop();
        n
    };
    let n: usize = others.iter().map(|&i| next(p.copy().unwrap(), i)).sum();
    n + next(p, last)
}

/// The shape of a history: B's writes (1-2), the frontier's point (0: before B's writes,
/// backdated; 1 between them; the last: after them), the demoter (0: A, the mint admin; 2: C, an
/// admin of G), the thing minted with admin one of G's dependents (0: none; 1: created in a later
/// commit, so it can arrive late after a late mint admin; 2: in its mint admin's commit), and what follows the
/// demotion (0 nothing, 1 B writes again unaware, 2 A grants B again, 3 A gives B read on the
/// item: a commit naming a former leaf), and whether B's last write, which the demoter then
/// has not received, carries the demotion's very `ts` (`tie`: an HLC tie, so concurrent).
struct Shape {
    writes: usize,
    at: usize,
    by: usize,
    sub: usize,
    tail: usize,
    tie: bool,
}

/// One history of `shape`, the rest random. Peer 0 (A) is mint admin of G, gives peer 1 (B) write,
/// peer 2 (C) admin and peer 3 (D, which then receives nothing more) read; A mints two things with admin G in one commit, and maybe one with admin the first
/// in that commit or the next; B writes on G or on one of them, the demoter receiving each at once or not
/// before the demotion; the demoter removes B with a frontier as of `shape.at`; then the tail.
/// Returns how many orders ran.
fn sample(shape: Shape) -> usize {
    let mut rng = Rng(1); // xorshift needs a nonzero state
    let (mut lp, (g, base)) = LocalPeer::cached("apply::tests_order::sample", || {
        let mut lp = LocalPeer::fresh(4, T0);
        lp.sync_all().unwrap();
        let (a, b, c, d) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
        let mut m = Mutation::new();
        let g = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(g, &reg(), &Value::Str("g".into())).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.hold(g);
        for (h, role) in [(b, Role::Write), (c, Role::Admin), (d, Role::Read)] {
            lp.peers[0].engine.grant(&g, &h, &ct::Grant { role, until: None, may_grant: false, retain: false, floor: None }).unwrap();
        }
        lp.sync_all().unwrap();
        // every peer's: each holds its own root's and of the others only what it needs
        let base: Vec<CommitId> = lp.peers.iter_mut().flat_map(|p| p.engine.commit_ids()).collect::<BTreeSet<_>>().into_iter().collect();
        (lp, (g, base))
    });
    // a node apart from A, B and C, a reader of G holding it, as of the base
    let mut fresh = lp.peers.pop().unwrap();
    let b = lp.peers[1].engine.tid();
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
    lp.hold(sub);
    lp.sync_all().unwrap();
    let by = shape.by;
    let mut marks = vec![lp.peers[by].clock.now_wall_ms()];
    for k in 0..shape.writes {
        lp.advance(1_000);
        let on = [g, item, item2, sub][rng.below(4)];
        let id = write(&mut lp.peers[1], on, &format!("b{k}"));
        if rng.below(2) == 0 && !(shape.tie && k + 1 == shape.writes) {
            let pk = lp.peers[1].engine.package(&id).unwrap().unwrap();
            lp.deliver(by, &pk).unwrap();
        }
        marks.push(lp.peers[1].clock.now_wall_ms());
    }
    if !shape.tie {
        lp.advance(1_000);
    }
    let as_of = marks[shape.at.min(shape.writes)];
    let scope = DemotionScope { roles: BTreeMap::from([(b, BTreeSet::from([g]))]), content: BTreeMap::from([(b, BTreeSet::from([g, item, item2, sub]))]) };
    let f = lp.peers[by].engine.frontier(&scope, as_of).unwrap();
    let rm = edge(&mut lp, by, g, b, None, Some(osis_perm::Frontier::new(f.commits)));
    if shape.tie {
        let ts = |p: &Peer, id: &CommitId| p.engine.header(id).unwrap().ts;
        let last = *lp.peers[1].engine.commit_ids().iter().max_by_key(|id| ts(&lp.peers[1], id)).unwrap();
        assert_eq!(ts(&lp.peers[1], &last), ts(&lp.peers[by], &rm), "B's last write at the demotion's ts");
    }
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
    // B's writes reach A and C before B hears of its demotion: a node that loses its role on a
    // thing drops its writes there that it has not sent (spec/sync-set.md §3 Release)
    for to in [0, 2] {
        lp.sync(1, to).unwrap();
    }
    lp.sync_all().unwrap();
    // what A, B and C send D (a reader of G: its sync set as it stands)
    let synced = fresh.engine.sync_set().unwrap().ids.keys().copied().collect();
    let mut packs: BTreeMap<CommitId, Package> = BTreeMap::new();
    for i in [0, 1, 2] {
        for pk in lp.packages_under(i, &synced).unwrap() {
            packs.entry(pk.id).or_insert(pk);
        }
    }
    let base: Vec<Package> = base.iter().filter_map(|id| packs.get(id).cloned()).collect();
    let rest: Vec<Package> = packs.values().filter(|p| !base.iter().any(|q| q.id == p.id)).cloned().collect();
    let things = [g, item, item2, sub];
    // the commits on the things (each node keeps its own roots' and the chains it needs)
    let ids: Vec<CommitId> = packs.iter().filter(|(_, p)| osis_commit::CommitBlob::decode(&p.bytes).is_ok_and(|b| b.header.aspects.iter().any(|a| things.contains(&a.tid)))).map(|(id, _)| *id).collect();
    let want = seen(&mut lp.peers[0], &ids, &things);
    assert_eq!(want.1, 0, "A holds everything");
    assert_eq!(seen(&mut lp.peers[1], &ids, &things), want, "B judges as A");
    assert_eq!(seen(&mut lp.peers[2], &ids, &things), want, "C judges as A");
    // a fresh node per order: copies of D as of the base
    fresh.clock.set(lp.peers[0].clock.now_wall_ms());
    each_order(fresh, &rest, &mut Vec::new(), &mut |order, p| assert_eq!(seen(p, &ids, &things), want, "arrival order {order:?}"))
}

// spec/permissions.md §5 (validity is a deterministic function of the commits a node holds), §5.2 (names its commit, whatever their order), spec/crdt.md §4.6:
// frontiers before (backdated), inside and after the writer's writes; children of the demoted
// actor created in one commit, a grandchild in a later commit or in theirs; a demotion by an admin other than the
// mint admin; a commit naming a former leaf; B's last write at the demotion's `ts` (§5.2, Position).
#[test]
fn validity_alike_in_every_arrival_order_spec_permissions_5_2() {
    let cases = [(1, 0, 0, 1, 0, false), (1, 1, 2, 1, 0, false), (2, 1, 2, 2, 0, false), (2, 1, 0, 0, 0, false), (1, 0, 2, 0, 3, false), (2, 2, 2, 2, 0, true)];
    for (writes, at, by, sub, tail, tie) in cases {
        assert_eq!(sample(Shape { writes, at, by, sub, tail, tie }), 24);
    }
}

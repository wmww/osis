#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Regression tests from the node-core review.

mod common;
use common::*;
use osis_commit::{CommitBlob, PurgeItem};
use osis_core::{Role, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::local_peer::Package;
use osis_node::{Ingested, Mutation, Reason};
use osis_perm::DemotionScope;
use osis_schema::Codec;

fn set(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: osis_core::Tid, k: &osis_schema::Aspect<Value>, v: &str) -> osis_core::CommitId {
    let mut m = Mutation::new();
    m.set(t, k, &s(v)).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

fn strip_parts(pk: &Package, keep: impl Fn(&str) -> bool, h: &osis_commit::Header) -> Vec<u8> {
    let mut b = CommitBlob::decode(&pk.bytes).unwrap();
    b.parts.retain(|p| keep(h.aspects[p.ai].ak.as_str()));
    b.encode()
}

// spec/crdt.md §4.6, spec/permissions.md §5.2: another writer's nested write into a map entry an
// invalid delta created goes with it, whether it arrived before or after the revoke.
#[test]
fn nested_write_under_invalid_entry_spec_crdt_4_6() {
    let mut lp = net(3, 71);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, t, c, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    // b creates key "ash" (never seen by node 0 before the revoke); c writes into it
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("ash"))], op: Op::Set(item("b", 1)) }).unwrap();
    let bid = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 2);
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("ash")), PathSeg::Field(1)], op: Op::Set(Value::Int(8)) }).unwrap();
    lp.peers[2].commit(m).unwrap().unwrap();
    let scope = DemotionScope { membership: [(b, [t].into())].into(), content: [(b, [t].into())].into() };
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&scope, now).unwrap();
    set_edge(&mut lp.peers[0].engine, t, b, None, Some(f.to_value()));
    // node 0: c's write first, then the revoke is held, then b's commit
    sync(&mut lp, 2, 0);
    let bpk = lp.peers[1].engine.package(&bid).unwrap().unwrap();
    lp.deliver(0, &bpk).unwrap();
    // node 2: had b's and c's writes joined, then receives the revoke
    sync(&mut lp, 0, 2);
    sync(&mut lp, 0, 1);
    sync(&mut lp, 1, 0);
    let want = lp.peers[0].engine.get(&t, &ak("/t/map")).unwrap();
    for i in 1..3 {
        assert_eq!(lp.peers[i].engine.get(&t, &ak("/t/map")).unwrap(), want, "node {i}");
        assert_eq!(lp.peers[i].engine.state(&t, &ak("/t/map")).unwrap(), lp.peers[0].engine.state(&t, &ak("/t/map")).unwrap());
    }
}

// spec/commits.md §4: a missing delta whose expiry has passed counts as held.
#[test]
fn expired_missing_delta_counts_as_held_spec_commits_4() {
    let mut lp = net(2, 72);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let mut m = Mutation::new();
    m.set(t, &BRIEF, &s("gone soon")).unwrap();
    m.set(t, &REG, &s("stays")).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
    let partial = strip_parts(&pk, |a| a != "/t/brief", &h);
    assert!(matches!(lp.peers[1].engine.ingest(&partial, Vec::new()).unwrap(), Ingested::Pending(_, Reason::WaitDeltas)));
    lp.advance(3_600_001);
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s("stays")));
}

// spec/commits.md §4: a part that does not hash to its header entry is dropped alone; the
// commit waits for (or applies without) that delta and takes the good copy later.
#[test]
fn bad_part_dropped_alone_spec_commits_4() {
    let mut lp = net(2, 73);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(t, &KEPT, &s("k")).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
    let mut b = CommitBlob::decode(&pk.bytes).unwrap();
    let last = b.parts.len() - 1;
    let n = b.parts[last].delta.len();
    b.parts[last].delta[n - 1] ^= 1;
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let r = lp.peers[1].engine.ingest(&b.encode(), Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::WaitDeltas)), "{r:?}");
    assert_eq!(lp.deliver(1, &pk).unwrap(), Ingested::Applied(id));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/kept")).unwrap(), Some(s("k")));
}

// spec/commits.md §5: a purge drops every body carrying the purged values, snapshots included.
#[test]
fn purge_drops_snapshots_spec_commits_5() {
    let mut lp = net(1, 74);
    let t = new_thing(&mut lp, 0);
    let secret = set(&mut lp, 0, t, &REG, "secret");
    let snap = lp.peers[0].engine.snapshot(&t, &ak("/t/reg")).unwrap().unwrap();
    assert!(lp.peers[0].engine.holds_body(&snap, &t, &ak("/t/reg")));
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("/t/reg") });
    lp.peers[0].commit(m).unwrap();
    assert!(!lp.peers[0].engine.holds_body(&secret, &t, &ak("/t/reg")));
    assert!(!lp.peers[0].engine.holds_body(&snap, &t, &ak("/t/reg")));
    // a purge never carries expires (spec/commits.md §5)
    let mut m = Mutation::new();
    m.set(t, &BRIEF, &s("x")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("/t/reg") });
    assert!(lp.peers[0].commit(m).is_err());
}

// spec/commits.md §5: a body is one projection class: its deltas share deaths and are dropped
// together; keep at most 0 drops at apply even when the killing `ts` is ahead of the clock.
#[test]
fn body_is_a_class_spec_commits_5() {
    let mut lp = net(2, 75);
    let t = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("a")).unwrap();
    m.set(t, &GONE2, &s("a2")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    // node 0's clock is ahead; its kill of /t/gone reaches node 1
    lp.peers[0].clock.advance(600_000);
    set(&mut lp, 0, t, &GONE, "b");
    sync(&mut lp, 0, 1);
    let e = &mut lp.peers[1].engine;
    assert!(!e.holds_body(&c, &t, &ak("/t/gone")));
    assert!(!e.holds_body(&c, &t, &ak("/t/gone2")));
    assert_eq!(e.get(&t, &ak("/t/gone2")).unwrap(), Some(s("a2")));
    // deaths aggregate over the class: killing one delta's write dates the other's body
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(t, &ak("/x/y"), &s("y")).unwrap();
    let c2 = lp.peers[0].commit(m).unwrap().unwrap();
    set(&mut lp, 0, t, &REG, "r2");
    let e = &mut lp.peers[0].engine;
    assert!(e.deaths(&c2, &t, &ak("/x/y")).unwrap().is_some());
    assert_eq!(e.deaths(&c2, &t, &ak("/x/y")).unwrap(), e.deaths(&c2, &t, &ak("/t/reg")).unwrap());
}

// spec/crdt.md §8: snapshot frontiers cover only writes the state reflects (valid ones).
#[test]
fn snapshot_frontier_valid_only_spec_crdt_8() {
    let mut lp = net(2, 76);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    let scope = DemotionScope { membership: [(b, [t].into())].into(), content: [(b, [t].into())].into() };
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&scope, now).unwrap();
    lp.advance(10);
    set(&mut lp, 1, t, &REG, "b's");
    lp.advance(10);
    set_edge(&mut lp.peers[0].engine, t, b, None, Some(f.to_value()));
    sync(&mut lp, 1, 0);
    let r = lp.peers[0].engine.receipt(&t, &ak("/t/reg")).unwrap();
    assert_eq!(r.contiguous(&b, u64::MAX), 1, "received, though invalid");
    let snap = lp.peers[0].engine.snapshot(&t, &ak("/t/reg")).unwrap().unwrap();
    let mut lp2 = net(1, 77);
    lp2.advance(100);
    for p in lp.packages(0).unwrap() {
        let h = lp.peers[0].engine.header(&p.id).unwrap();
        let skip = h.author == b && h.aspects.iter().any(|a| a.ak.as_str() == "/t/reg");
        if !skip {
            let _ = lp2.deliver(0, &p);
        }
    }
    assert!(lp2.peers[0].engine.commit_ids().contains(&snap));
    assert_eq!(lp2.peers[0].engine.receipt(&t, &ak("/t/reg")).unwrap().contiguous(&b, u64::MAX), 0);
    // snapshot retention takes the schema's default bounds (keep at least 1d)
    set(&mut lp, 0, t, &KEPT, "k");
    let ks = lp.peers[0].engine.snapshot(&t, &ak("/t/kept")).unwrap().unwrap();
    let sh = lp.peers[0].engine.header(&ks).unwrap();
    assert_eq!(sh.aspects[0].retention.at_least.rel, Some(86_400_000));
}

// spec/permissions.md §7: a move is one local transaction: refused as a whole.
#[test]
fn move_is_atomic_spec_perm_7() {
    let mut lp = net(2, 78);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    let before = lp.peers[1].engine.commit_ids().len();
    // node 1 may not create things owned by node 0
    let a = lp.peers[0].engine.tid();
    assert!(lp.peers[1].engine.move_thing(&t, a).is_err());
    assert_eq!(lp.peers[1].engine.commit_ids().len(), before);
    // a failed transaction rolls the caches back: the next commit takes the same counters
    let me = lp.peers[1].engine.tid();
    let mut m = Mutation::new();
    let x = lp.peers[1].engine.new_thing(&mut m, me);
    m.set(x, &REG, &s("ok")).unwrap();
    lp.peers[1].commit(m).unwrap();
    assert_eq!(lp.peers[1].engine.get(&x, &ak("/t/reg")).unwrap(), Some(s("ok")));
}

// spec/permissions.md §7: resolution follows `/moved` up to RESOLUTION_HOPS.
#[test]
fn resolution_hops_spec_perm_7() {
    let mut lp = net(1, 79);
    let t1 = new_thing(&mut lp, 0);
    let t2 = new_thing(&mut lp, 0);
    let t3 = new_thing(&mut lp, 0);
    for (a, b) in [(t1, t2), (t2, t3)] {
        let mut m = Mutation::new();
        m.set(a, &osis_schema::core_types::MOVED, &b).unwrap();
        lp.peers[0].commit(m).unwrap();
    }
    let me = lp.peers[0].engine.tid();
    assert_eq!(lp.peers[0].engine.resolve(&me, &t1), t3);
    let _ = WallMs(0);
}


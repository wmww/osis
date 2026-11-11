#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Regression tests from the node-core review.

use crate::common;
use common::*;
use osis_commit::{CommitBlob, PurgeItem};
use osis_base::{Role, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::local_peer::Package;
use osis_node::{Ingested, Mutation};
use osis_perm::DemotionScope;
use osis_schema::Codec;

fn set(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: osis_base::Tid, k: &osis_schema::Aspect<Value>, v: &str) -> osis_base::CommitId {
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
    let mut lp = net_off(3, 0);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (b, c) = (lp.peers[1].engine.me(), lp.peers[2].engine.me());
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
    let scope = DemotionScope { roles: [(b, [t].into())].into(), content: [(b, [t].into())].into() };
    lp.advance(10);
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
    let want = lp.peers[0].engine.get(&t, &ak("t:map.0")).unwrap();
    for i in 1..3 {
        assert_eq!(lp.peers[i].engine.get(&t, &ak("t:map.0")).unwrap(), want, "node {i}");
        assert_eq!(lp.peers[i].engine.state(&t, &ak("t:map.0")).unwrap(), lp.peers[0].engine.state(&t, &ak("t:map.0")).unwrap());
    }
}

// spec/commits.md §4, §6: an expiring commit with a delta missing applies what is held at once; at
// the commit's expiry its held part goes.
#[test]
fn expiring_commit_applies_without_missing_delta_spec_commits_4() {
    let mut lp = net(2, 0);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let at = osis_base::WallMs(lp.peers[0].engine.now().0 + 3_600_000);
    let mut m = Mutation::new();
    m.set(t, &BRIEF, &s("gone soon")).unwrap();
    m.set(t, &REG, &s("held")).unwrap();
    m.expires(t, &BRIEF, at).unwrap();
    m.expires(t, &REG, at).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
    let partial = strip_parts(&pk, |a| a != "t:brief.0", &h);
    assert_eq!(lp.peers[1].receive(&partial, Vec::new()).unwrap(), Ingested::Applied(id));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("held")));
    lp.advance(3_600_001);
    lp.peers[1].tick().unwrap();
    assert!(lp.peers[1].engine.pending().is_empty(), "{:?}", lp.peers[1].engine.pending());
    assert!(lp.peers[1].engine.commit_ids().contains(&id));
    // the expired write applied before T stays its value-less winner (spec/crdt.md §4.7)
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), None);
}

// spec/commits.md §4: a part that does not hash to its header entry is dropped alone; the
// commit applies without that delta and takes the good copy later.
#[test]
fn bad_part_dropped_alone_spec_commits_4() {
    let mut lp = net(2, 0);
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
    let r = lp.peers[1].receive(&b.encode(), Vec::new()).unwrap();
    assert_eq!(r, Ingested::Applied(id));
    assert_eq!(lp.deliver(1, &pk).unwrap(), Ingested::Applied(id));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:kept.0")).unwrap(), Some(s("k")));
}

// spec/commits.md §5: a purge drops every body carrying the purged values, snapshots included.
#[test]
fn purge_drops_snapshots_spec_commits_5() {
    let mut lp = net(1, 0);
    let t = new_thing(&mut lp, 0);
    let secret = set(&mut lp, 0, t, &REG, "secret");
    let snap = lp.peers[0].engine.snapshot(&t, &ak("t:reg.0")).unwrap().unwrap();
    assert!(lp.peers[0].engine.body_not_dropped(&snap, &t, &ak("t:reg.0")));
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("t:reg.0") });
    lp.peers[0].commit(m).unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&secret, &t, &ak("t:reg.0")));
    assert!(!lp.peers[0].engine.body_not_dropped(&snap, &t, &ak("t:reg.0")));
    // a purge may carry expires, reaching only deltas expiring no later (spec/commits.md §5): a
    // writer refuses one naming a delta beyond it
    let mut m = Mutation::new();
    m.set(t, &BRIEF, &s("x")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("t:reg.0") });
    assert!(matches!(lp.peers[0].commit(m), Err(osis_node::Error::Clash(_))));
}

// spec/commits.md §5: a purge drops every snapshot body carrying the purged values whatever the
// arrival order: a snapshot arriving after the request and the named delta, or the named delta
// arriving after the request and the snapshot.
#[test]
fn purge_drops_late_snapshot_spec_commits_5() {
    let mut lp = net(2, 0);
    let t = new_thing(&mut lp, 0);
    let reg = ak("t:reg.0");
    let secret = set(&mut lp, 0, t, &REG, "secret");
    let snap = lp.peers[0].engine.snapshot(&t, &reg).unwrap().unwrap();
    let spk = lp.peers[0].engine.package(&snap).unwrap().unwrap();
    let secret_pk = lp.peers[0].engine.package(&secret).unwrap().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: reg.clone() });
    lp.peers[0].commit(m).unwrap();
    let rest: Vec<Package> = packages(&mut lp, 0).into_iter().filter(|p| p.id != snap && p.id != secret).collect();
    let check = |e: &mut osis_node::Engine, why: &str| {
        assert!(!e.body_not_dropped(&snap, &t, &reg), "{why}: snapshot dropped");
        assert_eq!(e.get(&t, &reg).unwrap(), Some(s("public")), "{why}");
    };
    // the snapshot last
    for p in rest.iter().chain([&secret_pk]) {
        lp.deliver(1, p).unwrap();
    }
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    lp.peers[1].reexamine().unwrap();
    assert!(!lp.peers[1].engine.body_not_dropped(&secret, &t, &reg));
    lp.deliver(1, &spk).unwrap();
    check(&mut lp.peers[1].engine, "snapshot last");
    lp.peers[1].restart(0x5b01).unwrap();
    check(&mut lp.peers[1].engine, "snapshot last, restarted");
    // the named delta last
    let i = lp.peers.len();
    lp.peers.push(osis_node::local_peer::Peer::new(0x5b02, lp.peers[0].engine.now()).unwrap());
    for p in rest.iter().chain([&spk, &secret_pk]) {
        lp.deliver(i, p).unwrap();
    }
    lp.peers[i].engine.set_syncing(t, true).unwrap();
    lp.peers[i].reexamine().unwrap();
    check(&mut lp.peers[i].engine, "named delta last");
    // the snapshot's header (applied alone, spec/commits.md §4), then its part
    let j = lp.peers.len();
    lp.peers.push(osis_node::local_peer::Peer::new(0x5b03, lp.peers[0].engine.now()).unwrap());
    for p in rest.iter().chain([&secret_pk]) {
        lp.deliver(j, p).unwrap();
    }
    let sh = lp.peers[0].engine.header(&snap).unwrap();
    let r = lp.peers[j].receive(&strip_parts(&spk, |_| false, &sh), Vec::new()).unwrap();
    assert_eq!(r, Ingested::Applied(snap));
    lp.peers[j].engine.set_syncing(t, true).unwrap();
    assert!(!lp.peers[j].engine.body_not_dropped(&secret, &t, &reg));
    lp.deliver(j, &spk).unwrap();
    check(&mut lp.peers[j].engine, "snapshot part last");
    lp.peers[j].restart(0x5b04).unwrap();
    check(&mut lp.peers[j].engine, "snapshot part last, restarted");
}

// spec/crdt.md §8: snapshot frontiers cover only writes the state reflects (valid ones).
#[test]
fn snapshot_frontier_valid_only_spec_crdt_8() {
    let mut lp = net(2, 0);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.me();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    let scope = DemotionScope { roles: [(b, [t].into())].into(), content: [(b, [t].into())].into() };
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&scope, now).unwrap();
    lp.advance(10);
    set(&mut lp, 1, t, &REG, "b's");
    lp.advance(10);
    set_edge(&mut lp.peers[0].engine, t, b, None, Some(f.to_value()));
    sync(&mut lp, 1, 0);
    let bs = lp.peers[0].engine.commit_ids().into_iter().find(|c| lp.peers[0].engine.header(c).is_some_and(|h| h.author == b && h.aspects.iter().any(|a| a.ak.as_str() == "t:reg.0"))).unwrap();
    let now = lp.peers[0].engine.now();
    assert!(lp.peers[0].engine.frontier(&scope, now).unwrap().commits.contains(&bs), "received, though invalid");
    let snap = lp.peers[0].engine.snapshot(&t, &ak("t:reg.0")).unwrap().unwrap();
    let mut lp2 = net(1, 1); // a node apart from lp's (its own seeds)
    lp2.advance(100);
    for p in lp.packages(0).unwrap() {
        let h = lp.peers[0].engine.header(&p.id).unwrap();
        let skip = h.author == b && h.aspects.iter().any(|a| a.ak.as_str() == "t:reg.0");
        if !skip {
            let _ = lp2.deliver(0, &p);
        }
    }
    assert!(lp2.peers[0].engine.commit_ids().contains(&snap));
    // a snapshot's frontier is no receipt (spec/crdt.md §8)
    let now = lp2.peers[0].engine.now();
    assert!(!lp2.peers[0].engine.frontier(&scope, now).unwrap().commits.contains(&bs));
}

// spec/commits.md §5 (a body's live writes span every aspect of its class): a body on two
// aspects asked by one of them, then changed through the other, is judged afresh whichever
// aspect is asked (liveness is not cached per asked aspect alone: a stale answer gave a host
// delete with no carrier, or a carrier for nothing). The node keeps every body, so nothing
// covers the body away.
#[test]
fn body_live_spans_its_class_spec_commits_5() {
    let mut lp = net(1, 0);
    lp.peers[0].engine.keep_bodies(true);
    let t = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("a")).unwrap();
    m.set(t, &GONE2, &s("a2")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(10);
    set(&mut lp, 0, t, &GONE, "b");
    let (a1, a2) = (ak("t:gone.0"), ak("t:gone2.0"));
    let e = &mut lp.peers[0].engine;
    assert!(e.body_live(&c, &t, &a1).unwrap(), "its t:gone2.0 write is live");
    lp.advance(10);
    set(&mut lp, 0, t, &GONE2, "b2");
    let e = &mut lp.peers[0].engine;
    assert!(!e.body_live(&c, &t, &a2).unwrap());
    assert!(!e.body_live(&c, &t, &a1).unwrap(), "asked by the other aspect of the body");
}

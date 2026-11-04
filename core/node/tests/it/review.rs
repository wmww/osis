#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Regression tests from the node-core review.

use crate::common;
use common::*;
use osis_commit::{CommitBlob, PurgeItem};
use osis_base::{Role, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::local_peer::Package;
use osis_node::{Ingested, Mutation, Reason};
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
    let scope = DemotionScope { roles: [(b, [t].into())].into(), content: [(b, [t].into())].into() };
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
    let partial = strip_parts(&pk, |a| a != "t:brief.0", &h);
    assert!(matches!(lp.peers[1].engine.ingest(&partial, Vec::new()).unwrap(), Ingested::Pending(_, Reason::WaitDeltas)));
    lp.advance(3_600_001);
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("stays")));
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
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:kept.0")).unwrap(), Some(s("k")));
}

// spec/commits.md §5: a purge drops every body carrying the purged values, snapshots included.
#[test]
fn purge_drops_snapshots_spec_commits_5() {
    let mut lp = net(1, 74);
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
    // a purge never carries expires (spec/commits.md §5)
    let mut m = Mutation::new();
    m.set(t, &BRIEF, &s("x")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("t:reg.0") });
    assert!(lp.peers[0].commit(m).is_err());
}

// spec/commits.md §5: a purge drops every snapshot body carrying the purged values whatever the
// arrival order: a snapshot arriving after the request and the named delta, or the named delta
// arriving after the request and the snapshot.
#[test]
fn purge_drops_late_snapshot_spec_commits_5() {
    let mut lp = net(2, 0x5b00);
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
    lp.peers[1].engine.reexamine().unwrap();
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
    lp.peers[i].engine.reexamine().unwrap();
    check(&mut lp.peers[i].engine, "named delta last");
    // the snapshot's header (it waits for its part, spec/commits.md §4), then its part
    let j = lp.peers.len();
    lp.peers.push(osis_node::local_peer::Peer::new(0x5b03, lp.peers[0].engine.now()).unwrap());
    for p in rest.iter().chain([&secret_pk]) {
        lp.deliver(j, p).unwrap();
    }
    let sh = lp.peers[0].engine.header(&snap).unwrap();
    let r = lp.peers[j].engine.ingest(&strip_parts(&spk, |_| false, &sh), Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::WaitDeltas)), "{r:?}");
    lp.peers[j].engine.set_syncing(t, true).unwrap();
    lp.peers[j].engine.reexamine().unwrap();
    assert!(!lp.peers[j].engine.body_not_dropped(&secret, &t, &reg));
    // its part counted as held (a later snapshot lists it): applied, and the part comes late
    let ts = osis_base::Ts::make(lp.peers[0].engine.now(), 0).unwrap();
    let lister = forge_snapshot_absorbing(&mut lp, 0, t, &reg, ts, osis_crdt::Fragment::default(), osis_crdt::Frontiers::default(), std::collections::BTreeMap::from([(snap, sh.author)]));
    assert!(matches!(lp.peers[j].engine.ingest(&lister, Vec::new()).unwrap(), Ingested::Applied(_)));
    assert!(lp.peers[j].engine.commit_ids().contains(&snap));
    lp.deliver(j, &spk).unwrap();
    check(&mut lp.peers[j].engine, "snapshot part last");
    lp.peers[j].restart(0x5b04).unwrap();
    check(&mut lp.peers[j].engine, "snapshot part last, restarted");
}

// spec/commits.md §5: a compaction snapshot's bounds come from the retention of the writes it
// carries live, whether the writer knows the schema or not: `writer`, the longest relative keep
// at least, the strictest keep at most (an override included); a write that died stops counting (no carry-over
// through the held earlier snapshot); a write whose own delta's header is not held counts as the
// held snapshot carrying it; an untyped aspect snapshots with no bounds; an absolute keep at
// most already passed counts as 0 after replaced.
#[test]
fn snapshot_bounds_from_carried_writes_spec_commits_5() {
    use osis_schema::{Bound, PurgeBy, Retention};
    let mut lp = net(2, 0x5b10);
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    let (short, reg, doc) = (ak("t:short.0"), ak("t:reg.0"), ak("u:doc.0"));
    set(&mut lp, 0, t, &SHORT, "a");
    set(&mut lp, 0, t, &KEPT, "k");
    let mut m = Mutation::new();
    m.set(t, &doc, &s("untyped")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let most = |rel| Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs: None, rel } };
    let mut m = Mutation::new();
    m.set(t, &REG, &s("brief")).unwrap();
    m.retention(t, &REG, most(Some(5_000))).unwrap();
    let brief = lp.peers[0].commit(m).unwrap().unwrap();
    // node 1 holds every write but the override, and node 0's snapshot carrying it
    let s0 = lp.peers[0].engine.snapshot(&t, &reg).unwrap().unwrap();
    for p in packages(&mut lp, 0).into_iter().filter(|p| p.id != brief) {
        lp.deliver(1, &p).unwrap();
    }
    let e1 = &mut lp.peers[1].engine;
    e1.set_syncing(t, true).unwrap();
    e1.reexamine().unwrap();
    let ret = |e: &osis_node::Engine, c: &osis_base::CommitId| e.header(c).unwrap().aspects[0].retention;
    let snap = e1.snapshot(&t, &short).unwrap().unwrap();
    assert_eq!(ret(e1, &snap), most(Some(600_000)), "schema default, schema unknown here");
    let snap = e1.snapshot(&t, &ak("t:kept.0")).unwrap().unwrap();
    assert_eq!(ret(e1, &snap), Retention { at_least: Bound { abs: None, rel: Some(86_400_000) }, ..most(None) }, "keep at least");
    let u = e1.snapshot(&t, &doc).unwrap().unwrap();
    assert_eq!(ret(e1, &u), most(None), "untyped");
    let snap = e1.snapshot(&t, &reg).unwrap().unwrap();
    assert_eq!(ret(e1, &snap), most(Some(5_000)), "own header not held: the carrying snapshot");
    assert_eq!(ret(&lp.peers[0].engine, &s0), most(Some(5_000)), "the override");
    // a default write kills the override: neither held snapshot carries it on
    set(&mut lp, 0, t, &REG, "plain");
    sync(&mut lp, 0, 1);
    for i in 0..2 {
        let snap = lp.peers[i].engine.snapshot(&t, &reg).unwrap().unwrap();
        assert_eq!(ret(&lp.peers[i].engine, &snap), most(None), "peer {i}: the override died");
    }
    // an absolute keep at most: inherited while ahead, 0 after replaced once passed
    let now = lp.peers[0].engine.now().0;
    let mut m = Mutation::new();
    m.set(t, &REG, &s("until")).unwrap();
    m.retention(t, &REG, Retention { at_most: Bound { abs: Some(now + 10_000), rel: None }, ..most(None) }).unwrap();
    lp.peers[0].commit(m).unwrap();
    let e0 = &mut lp.peers[0].engine;
    let snap = e0.snapshot(&t, &reg).unwrap().unwrap();
    assert_eq!(ret(e0, &snap).at_most, Bound { abs: Some(now + 10_000), rel: None }, "ahead");
    lp.advance(20_000);
    let e0 = &mut lp.peers[0].engine;
    let snap = e0.snapshot(&t, &reg).unwrap().unwrap();
    assert_eq!(ret(e0, &snap).at_most, Bound { abs: None, rel: Some(0) }, "passed");
}

// spec/commits.md §5: a body is one projection class: its deltas share deaths and are dropped
// together; while one of them has a live write the class is kept (`AT_MOST_GRACE`); keep at
// most 0 drops at apply the kill that leaves it none, even when the killing `ts` is ahead of
// the clock.
#[test]
fn body_is_a_class_spec_commits_5() {
    let mut lp = net(2, 75);
    let t = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("a")).unwrap();
    m.set(t, &GONE2, &s("a2")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    // node 0's clock is ahead; its kills reach node 1
    lp.peers[0].clock.advance(600_000);
    set(&mut lp, 0, t, &GONE, "b");
    sync(&mut lp, 0, 1);
    let e = &mut lp.peers[1].engine;
    assert!(e.body_not_dropped(&c, &t, &ak("t:gone.0")) && e.body_not_dropped(&c, &t, &ak("t:gone2.0")), "t:gone2.0 is still live");
    set(&mut lp, 0, t, &GONE2, "b2");
    sync(&mut lp, 0, 1);
    let e = &mut lp.peers[1].engine;
    assert!(!e.body_not_dropped(&c, &t, &ak("t:gone.0")));
    assert!(!e.body_not_dropped(&c, &t, &ak("t:gone2.0")));
    assert_eq!(e.get(&t, &ak("t:gone2.0")).unwrap(), Some(s("b2")));
    // deaths aggregate over the class: killing one delta's write dates the other's body
    let mut m = Mutation::new();
    m.set(t, &SHORT, &s("r")).unwrap();
    m.set(t, &SHORT2, &s("y")).unwrap();
    let c2 = lp.peers[0].commit(m).unwrap().unwrap();
    set(&mut lp, 0, t, &SHORT, "r2");
    let e = &mut lp.peers[0].engine;
    assert!(e.deaths(&c2, &t, &ak("t:short2.0")).unwrap().is_some());
    assert_eq!(e.deaths(&c2, &t, &ak("t:short2.0")).unwrap(), e.deaths(&c2, &t, &ak("t:short.0")).unwrap());
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
    let mut lp2 = net(1, 77);
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
    // snapshot retention takes the carried write's relative keep at least (1d)
    set(&mut lp, 0, t, &KEPT, "k");
    let ks = lp.peers[0].engine.snapshot(&t, &ak("t:kept.0")).unwrap().unwrap();
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
    assert_eq!(lp.peers[1].engine.get(&x, &ak("t:reg.0")).unwrap(), Some(s("ok")));
}

// spec/permissions.md §7: resolution follows `moved.0` up to RESOLUTION_HOPS.
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


// spec/crdt.md §3.3 rule 7, spec/permissions.md §7 (a snapshot origin's bare anchors are
// imported): a text reset while another writer inserted at an element the reset pruned, then
// compacted (its ordinary bodies dropped), moves complete: the copy reads like the original, at
// the mover and at a node receiving the import.
#[test]
fn move_reset_compacted_text_complete_spec_perm_7() {
    let mut lp = net(2, 79);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (a, b) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    let mut m = Mutation::new();
    m.set(t, &TEXT, &s("abc")).unwrap();
    let c1 = lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.replace(t, &TEXT, &s("xyz")).unwrap();
    let c2 = lp.peers[0].commit(m).unwrap().unwrap();
    // later, b inserts after `b` without having seen the reset: `b` is a bare anchor after it
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.op(t, &TEXT, PathOp { path: Vec::new(), op: Op::Insert { at: 2, items: vec![s("q")] } }).unwrap();
    let c3 = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    let k = ak("t:text.0");
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&t, &k).unwrap(), Some(s("xyzq")));
    let snap = e.snapshot(&t, &k).unwrap().unwrap();
    for c in [c1, c2, c3] {
        assert_eq!(e.covered(&snap, &c, &t, &k).unwrap(), Some(true));
        e.drop_body(&c, &t, &k).unwrap();
    }
    let (copy, imports) = e.move_thing(&t, a).unwrap();
    assert!(imports.iter().any(|i| e.header(i).is_some_and(|h| h.origins.iter().any(|o| o.commit == snap))), "the snapshot is an origin");
    assert_eq!(e.get(&copy, &k).unwrap(), Some(s("xyzq")), "the copy is complete");
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.get(&copy, &k).unwrap(), Some(s("xyzq")), "receivers accept the import");
}

// spec/permissions.md §7 (an import carries the bare anchors its imported writes reference): a
// text reset and compacted, then an insert at an element the reset pruned arrives (beyond the
// snapshot, imported from its own commit): the snapshot's import keeps that anchor, so the copy
// places the insert.
#[test]
fn move_keeps_anchor_of_later_insert_spec_perm_7() {
    let mut lp = net(2, 80);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (a, b) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    let mut m = Mutation::new();
    m.set(t, &TEXT, &s("abc")).unwrap();
    let c1 = lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.replace(t, &TEXT, &s("xyz")).unwrap();
    let c2 = lp.peers[0].commit(m).unwrap().unwrap();
    let k = ak("t:text.0");
    let e = &mut lp.peers[0].engine;
    let snap = e.snapshot(&t, &k).unwrap().unwrap();
    for c in [c1, c2] {
        e.drop_body(&c, &t, &k).unwrap();
    }
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.op(t, &TEXT, PathOp { path: Vec::new(), op: Op::Insert { at: 2, items: vec![s("q")] } }).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&t, &k).unwrap(), Some(s("xyzq")));
    let (copy, imports) = e.move_thing(&t, a).unwrap();
    assert!(imports.iter().any(|i| e.header(i).is_some_and(|h| h.origins.iter().any(|o| o.commit == snap))));
    assert_eq!(e.get(&copy, &k).unwrap(), Some(s("xyzq")), "the copy places the insert");
}

// spec/permissions.md §7, spec/crdt.md §3.3 rule 7 (`MAX_DELTA_BARE`): a 100k-character text
// replaced three times (300k bare anchors nothing anchors at) and compacted moves: the import
// carries only the referenced bare anchors, so it stays within the bound.
#[test]
#[ignore = "tier 2"]
fn move_many_bare_anchors_spec_perm_7() {
    let mut lp = net(1, 81);
    let t = new_thing(&mut lp, 0);
    let a = lp.peers[0].engine.tid();
    let k = ak("t:text.0");
    let mut ids = Vec::new();
    for ch in ["a", "b", "c", "d"] {
        let mut m = Mutation::new();
        m.replace(t, &TEXT, &s(&ch.repeat(100_000))).unwrap();
        ids.push(lp.peers[0].commit(m).unwrap().unwrap());
        lp.advance(1_000);
    }
    let e = &mut lp.peers[0].engine;
    e.snapshot(&t, &k).unwrap().unwrap();
    for c in ids {
        e.drop_body(&c, &t, &k).unwrap();
    }
    let (copy, _) = e.move_thing(&t, a).unwrap();
    assert_eq!(e.get(&copy, &k).unwrap(), Some(s(&"d".repeat(100_000))));
}

/// Text `t` on peer 0: "headtail", then `n` characters typed between, then deleted (two
/// commits: a delete is at most `MAX_DELTA_BARE` elements), all but the last `kept` of them;
/// then "SECRETmid" typed after "head" and "SECRET" deleted (shown "mid" anchors at it);
/// compacted (the snapshot carries the deleted elements content-less, its bodies dropped) when
/// `compact`.
fn deleted_text(lp: &mut osis_node::local_peer::LocalPeer, t: osis_base::Tid, n: usize, kept: usize, compact: bool) {
    let mut m = Mutation::new();
    m.set(t, &TEXT, &s("headtail")).unwrap();
    let mut ids = vec![lp.peers[0].commit(m).unwrap().unwrap()];
    let mut m = Mutation::new();
    m.op(t, &TEXT, PathOp { path: Vec::new(), op: Op::Insert { at: 4, items: vec![s(&"x".repeat(n))] } }).unwrap();
    ids.push(lp.peers[0].commit(m).unwrap().unwrap());
    let gone = n - kept;
    for len in [gone / 2, gone - gone / 2] {
        let mut m = Mutation::new();
        m.op(t, &TEXT, PathOp { path: Vec::new(), op: Op::Delete { at: 4, len } }).unwrap();
        ids.push(lp.peers[0].commit(m).unwrap().unwrap());
    }
    for op in [Op::Insert { at: 4, items: vec![s("SECRETmid")] }, Op::Delete { at: 4, len: 6 }] {
        let mut m = Mutation::new();
        m.op(t, &TEXT, PathOp { path: Vec::new(), op }).unwrap();
        ids.push(lp.peers[0].commit(m).unwrap().unwrap());
    }
    if compact {
        let k = ak("t:text.0");
        let e = &mut lp.peers[0].engine;
        e.snapshot(&t, &k).unwrap().unwrap();
        for c in ids {
            e.drop_body(&c, &t, &k).unwrap();
        }
    }
}

// spec/permissions.md §7 (an import carries only the sequence elements the importer's state
// shows and those they anchor at, the latter without content), spec/crdt.md §3.3 rule 7
// (`MAX_DELTA_BARE`): a text with 300k characters deleted and a word erased inside shown text
// moves, from its commits or compacted: the copy reads like the original, the imports are
// small and hold no erased text, and a receiver accepts them.
#[test]
#[ignore = "tier 2"]
fn move_deleted_text_small_import_spec_perm_7() {
    for compact in [false, true] {
        let mut lp = net(2, 82);
        lp.sync_all().unwrap();
        let t = new_thing(&mut lp, 0);
        let a = lp.peers[0].engine.tid();
        deleted_text(&mut lp, t, 300_000, 0, compact);
        let k = ak("t:text.0");
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.get(&t, &k).unwrap(), Some(s("headmidtail")));
        let (copy, imports) = e.move_thing(&t, a).unwrap();
        assert_eq!(e.get(&copy, &k).unwrap(), Some(s("headmidtail")), "compact {compact}: the copy is complete");
        let mut size = 0;
        for i in &imports {
            let pk = e.package(i).unwrap().unwrap();
            size += pk.bytes.len() + pk.blobs.iter().map(|(_, b)| b.len()).sum::<usize>();
            for b in std::iter::once(&pk.bytes).chain(pk.blobs.iter().map(|(_, b)| b)) {
                assert!(!b.windows(6).any(|w| w == b"SECRET"), "compact {compact}: erased text in an import");
            }
        }
        assert!(size < 16 * 1024, "compact {compact}: imports of {size} bytes");
        sync(&mut lp, 0, 1);
        assert_eq!(lp.peers[1].engine.get(&copy, &k).unwrap(), Some(s("headmidtail")), "compact {compact}: receivers accept the import");
    }
}

// spec/permissions.md §7, spec/crdt.md §3.3 rule 7 (`MAX_DELTA_BARE`): a compacted text whose
// shown last character is typed after 400k deleted ones (its placement anchors at all of them)
// still needs an import over the bound: the move fails cleanly, creating nothing.
#[test]
#[ignore = "tier 2"]
fn move_over_max_delta_bare_fails_spec_perm_7() {
    let mut lp = net(1, 83);
    let t = new_thing(&mut lp, 0);
    let a = lp.peers[0].engine.tid();
    deleted_text(&mut lp, t, 400_000, 1, true);
    let k = ak("t:text.0");
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&t, &k).unwrap(), Some(s("headmidxtail")));
    let before = e.commit_ids().len();
    let err = e.move_thing(&t, a).unwrap_err();
    assert!(err.to_string().contains("MAX_DELTA_BARE"), "{err}");
    assert_eq!(e.commit_ids().len(), before, "nothing written");
}

// spec/commits.md §5 (a body's live writes span every aspect of its class): a body on two
// aspects asked by one of them, then changed through the other, is judged afresh whichever
// aspect is asked (liveness is not cached per asked aspect alone: a stale answer gave a timed
// delete with no carrier, or a carrier for nothing).
#[test]
fn body_live_spans_its_class_spec_commits_5() {
    let mut lp = net(1, 84);
    let t = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    m.set(t, &SHORT, &s("a")).unwrap();
    m.set(t, &SHORT2, &s("a2")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(10);
    set(&mut lp, 0, t, &SHORT, "b");
    let (a1, a2) = (ak("t:short.0"), ak("t:short2.0"));
    let e = &mut lp.peers[0].engine;
    assert!(e.body_live(&c, &t, &a1).unwrap(), "its t:short2.0 write is live");
    lp.advance(10);
    set(&mut lp, 0, t, &SHORT2, "b2");
    let e = &mut lp.peers[0].engine;
    assert!(e.body_not_dropped(&c, &t, &a1), "dead, kept to first death plus 10 min");
    assert!(!e.body_live(&c, &t, &a2).unwrap());
    assert!(!e.body_live(&c, &t, &a1).unwrap(), "asked by the other aspect of the body");
}

const MOVED_AKS: [&str; 5] = ["t:text.0", "t:list.0", "t:map.0", "t:docs.0", "t:tags.0"];

/// One edit round on `t` by `i` (each kind of value), then `j` edits inside what `i` made.
fn edit_round(lp: &mut osis_node::local_peer::LocalPeer, t: osis_base::Tid, i: usize, j: usize, n: usize) {
    let op = |lp: &mut osis_node::local_peer::LocalPeer, i: usize, k: &osis_schema::Aspect<Value>, path: Vec<PathSeg>, op: Op| {
        let mut m = Mutation::new();
        m.op(t, k, PathOp { path, op }).unwrap();
        lp.peers[i].commit(m).unwrap();
        lp.advance(100);
    };
    let key = |x: &str| vec![PathSeg::Key(s(x))];
    let v = format!("v{n}");
    op(lp, i, &TEXT, vec![], Op::Insert { at: 0, items: vec![s(&format!("ab{n}"))] });
    op(lp, i, &LIST, vec![], Op::Insert { at: 0, items: vec![s(&v), s("x")] });
    op(lp, i, &MAP, key(&v), Op::Set(item(&v, n as i64)));
    op(lp, i, &DOCS, key(&v), Op::Set(s("hello")));
    op(lp, i, &TAGS, vec![], Op::Add(s(&v)));
    if i != j {
        sync(lp, i, j);
    }
    op(lp, j, &TEXT, vec![], Op::Delete { at: 1, len: 1 });
    op(lp, j, &TEXT, vec![], Op::Move { at: 0, len: 1, to: 1 });
    op(lp, j, &LIST, vec![], Op::Delete { at: 1, len: 1 });
    op(lp, j, &LIST, vec![], Op::Insert { at: 1, items: vec![s("y")] });
    op(lp, j, &MAP, vec![PathSeg::Key(s(&v)), PathSeg::Field(1)], Op::Set(Value::Int(100 + n as i64)));
    op(lp, j, &DOCS, key(&v), Op::Insert { at: 2, items: vec![s("XY")] });
    op(lp, j, &TAGS, vec![], Op::Remove(s(&v)));
    if i != j {
        sync(lp, j, i);
    }
}

/// A thing written by two nodes into each other's elements, compacted with the bodies kept and
/// written again after: (the net, the thing, node 0's actor).
fn edited_and_compacted(seed: u64) -> (osis_node::local_peer::LocalPeer, osis_base::Tid, osis_base::Tid) {
    let mut lp = net(2, seed);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (a, b) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    for n in 0..2 {
        edit_round(&mut lp, t, n % 2, 1 - n % 2, n);
    }
    for k in MOVED_AKS {
        lp.peers[0].engine.snapshot(&t, &ak(k)).unwrap().unwrap();
    }
    sync(&mut lp, 0, 1);
    for n in 2..4 {
        edit_round(&mut lp, t, n % 2, 1 - n % 2, n);
    }
    (lp, t, a)
}

/// `to` reads as `from` at node 0, both at the mover and at a receiver.
fn reads_alike(lp: &mut osis_node::local_peer::LocalPeer, from: osis_base::Tid, to: osis_base::Tid) {
    sync(lp, 0, 1);
    for k in MOVED_AKS {
        let want = lp.peers[0].engine.get(&from, &ak(k)).unwrap();
        assert!(want.is_some(), "{k}");
        assert_eq!(lp.peers[0].engine.get(&to, &ak(k)).unwrap(), want, "{k}: the copy");
        assert_eq!(lp.peers[1].engine.get(&to, &ak(k)).unwrap(), want, "{k}: a receiver");
    }
}

// spec/permissions.md §7 (every import write under a listed origin): honest moves of maps,
// nested maps, sets, lists and text, written by two nodes into each other's elements, compacted
// with the bodies kept and written again after, then the copy moved again: each import applies
// at its importer and at a receiver, and the copies read as the source.
#[test]
fn honest_moves_after_compaction_apply_spec_perm_7() {
    let (mut lp, t, a) = edited_and_compacted(81);
    let (copy, _) = lp.peers[0].engine.move_thing(&t, a).unwrap();
    reads_alike(&mut lp, t, copy);
    // the copy compacted (its snapshots carry the imports' dots) and moved on
    for k in MOVED_AKS {
        lp.peers[0].engine.snapshot(&copy, &ak(k)).unwrap().unwrap();
    }
    let (copy2, _) = lp.peers[0].engine.move_thing(&copy, a).unwrap();
    reads_alike(&mut lp, t, copy2);
}

// spec/permissions.md §7 (an import is an origin of the writes it holds): a copy moved on before
// any snapshot of it, after native edits inside its imported elements, gives the next copy all of
// it; that copy edited, partly compacted and moved again likewise.
#[test]
fn moving_an_uncompacted_copy_keeps_its_imports_spec_perm_7() {
    let (mut lp, t, a) = edited_and_compacted(82);
    let (copy, _) = lp.peers[0].engine.move_thing(&t, a).unwrap();
    reads_alike(&mut lp, t, copy);
    edit_round(&mut lp, copy, 0, 0, 4);
    let (copy2, _) = lp.peers[0].engine.move_thing(&copy, a).unwrap();
    reads_alike(&mut lp, copy, copy2);
    edit_round(&mut lp, copy2, 0, 0, 5);
    let (copy3, _) = lp.peers[0].engine.move_thing(&copy2, a).unwrap();
    reads_alike(&mut lp, copy2, copy3);
    for k in &MOVED_AKS[..3] {
        lp.peers[0].engine.snapshot(&copy3, &ak(k)).unwrap().unwrap();
    }
    edit_round(&mut lp, copy3, 0, 0, 6);
    let (copy4, _) = lp.peers[0].engine.move_thing(&copy3, a).unwrap();
    reads_alike(&mut lp, copy3, copy4);
}

// spec/permissions.md §7 (two imports holding one write, a hostile creator's only): the copy of
// a copy so built reads as it.
#[test]
fn moving_a_copy_with_a_doubled_import_spec_perm_7() {
    let mut lp = net(2, 83);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let a = lp.peers[0].engine.tid();
    edit_round(&mut lp, t, 0, 0, 0);
    let (copy, _) = lp.peers[0].engine.move_thing(&t, a).unwrap();
    lp.peers[0].engine.reimport(&t, &copy).unwrap();
    let (copy2, _) = lp.peers[0].engine.move_thing(&copy, a).unwrap();
    for k in MOVED_AKS {
        let want = lp.peers[0].engine.get(&copy, &ak(k)).unwrap();
        assert_eq!(lp.peers[0].engine.get(&copy2, &ak(k)).unwrap(), want, "{k}");
    }
}

// spec/crdt.md §5.7 Live, spec/permissions.md §7: a delete an import leaves out (it expires) leaves
// a nested text's char-less anchor in the copy, without its flag; other chars of the commit read,
// so nothing was stripped and the element stays.
#[test]
fn move_keeps_element_of_text_with_delete_left_out_spec_perm_7() {
    let k = ak("t:listtext.0");
    for expiring in [false, true] {
        let mut lp = net(1, 0x7a06);
        let t = new_thing(&mut lp, 0);
        let a = lp.peers[0].engine.tid();
        let mut m = Mutation::new();
        m.op(t, &LISTTEXT, PathOp { path: vec![], op: Op::Insert { at: 0, items: vec![s("abc")] } }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.advance(10);
        let mut m = Mutation::new();
        if expiring {
            m.expires(t, &k, WallMs(T0.0 + 3_600_000)).unwrap();
        }
        m.op(t, &LISTTEXT, PathOp { path: vec![PathSeg::Index(0)], op: Op::Delete { at: 1, len: 1 } }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.advance(10);
        let (copy, _) = lp.peers[0].engine.move_thing(&t, a).unwrap();
        assert_eq!(lp.peers[0].engine.get(&copy, &k).unwrap(), Some(Value::List(vec![s("ac")])), "expiring {expiring}");
    }
}

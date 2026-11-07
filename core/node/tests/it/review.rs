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

// spec/commits.md §4, §6: an expiring commit with a delta missing applies what is held at once; at
// the commit's expiry its held part goes.
#[test]
fn expiring_commit_applies_without_missing_delta_spec_commits_4() {
    let mut lp = net(2, 72);
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
    assert_eq!(lp.peers[1].engine.ingest(&partial, Vec::new()).unwrap(), Ingested::Applied(id));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("held")));
    lp.advance(3_600_001);
    lp.peers[1].engine.tick().unwrap();
    assert!(lp.peers[1].engine.pending().is_empty(), "{:?}", lp.peers[1].engine.pending());
    assert!(lp.peers[1].engine.commit_ids().contains(&id));
    // the expired write applied before T stays its value-less winner (spec/crdt.md §4.7)
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), None);
}

// spec/commits.md §4: a part that does not hash to its header entry is dropped alone; the
// commit applies without that delta and takes the good copy later.
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
    assert_eq!(r, Ingested::Applied(id));
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
    // the snapshot's header (applied alone, spec/commits.md §4), then its part
    let j = lp.peers.len();
    lp.peers.push(osis_node::local_peer::Peer::new(0x5b03, lp.peers[0].engine.now()).unwrap());
    for p in rest.iter().chain([&secret_pk]) {
        lp.deliver(j, p).unwrap();
    }
    let sh = lp.peers[0].engine.header(&snap).unwrap();
    let r = lp.peers[j].engine.ingest(&strip_parts(&spk, |_| false, &sh), Vec::new()).unwrap();
    assert_eq!(r, Ingested::Applied(snap));
    lp.peers[j].engine.set_syncing(t, true).unwrap();
    assert!(!lp.peers[j].engine.body_not_dropped(&secret, &t, &reg));
    lp.deliver(j, &spk).unwrap();
    check(&mut lp.peers[j].engine, "snapshot part last");
    lp.peers[j].restart(0x5b04).unwrap();
    check(&mut lp.peers[j].engine, "snapshot part last, restarted");
}

// spec/commits.md §5: a compaction snapshot's history comes from the retention of the writes it
// carries live, whether the writer knows the schema or not: `writer`, purge on replace if any
// carried write's is (an override included), else kept for the longest `after`; a write that died stops counting (no carry-over
// through the held earlier snapshot); a write whose own delta's header is not held counts as the
// held snapshot carrying it; an untyped aspect snapshots with no history promised.
#[test]
fn snapshot_bounds_from_carried_writes_spec_commits_5() {
    use osis_schema::{History, PurgeBy, Retention};
    let mut lp = net(2, 0x5b10);
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    let (gone, reg, doc) = (ak("t:gone.0"), ak("t:reg.0"), ak("u:doc.0"));
    set(&mut lp, 0, t, &GONE, "a");
    set(&mut lp, 0, t, &KEPT, "k");
    let mut m = Mutation::new();
    m.set(t, &doc, &s("untyped")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let most = |purge: bool| Retention { by: PurgeBy::Writer, history: purge.then_some(History::PurgeOnReplace) };
    let mut m = Mutation::new();
    m.set(t, &REG, &s("brief")).unwrap();
    m.retention(t, &REG, most(true)).unwrap();
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
    let snap = e1.snapshot(&t, &gone).unwrap().unwrap();
    assert_eq!(ret(e1, &snap), most(true), "schema default, schema unknown here");
    let snap = e1.snapshot(&t, &ak("t:kept.0")).unwrap().unwrap();
    assert_eq!(ret(e1, &snap), Retention { history: Some(History::Keep { until: None, after: Some(86_400_000) }), ..most(false) }, "kept a while");
    let u = e1.snapshot(&t, &doc).unwrap().unwrap();
    assert_eq!(ret(e1, &u), most(false), "untyped");
    let snap = e1.snapshot(&t, &reg).unwrap().unwrap();
    assert_eq!(ret(e1, &snap), most(true), "own header not held: the carrying snapshot");
    assert_eq!(ret(&lp.peers[0].engine, &s0), most(true), "the override");
    // a default write kills the override: neither held snapshot carries it on
    set(&mut lp, 0, t, &REG, "plain");
    sync(&mut lp, 0, 1);
    for i in 0..2 {
        let snap = lp.peers[i].engine.snapshot(&t, &reg).unwrap().unwrap();
        assert_eq!(ret(&lp.peers[i].engine, &snap), most(false), "peer {i}: the override died");
    }
}

// spec/commits.md §5: a retention class of a body: its deltas share deaths and are dropped
// together, at the first death of any; while one of them has a live write the class goes by the
// timer (due at once, its carrier first), and the kill that leaves it none drops it in that
// transaction, even when the killing `ts` is ahead of the clock.
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
    assert!(e.body_not_dropped(&c, &t, &ak("t:gone.0")) && e.body_not_dropped(&c, &t, &ak("t:gone2.0")), "t:gone2.0 is still live: held until the timer");
    assert!(e.due_live_drops().unwrap().iter().any(|x| x.0 == c), "due at once, the killing ts ahead of the clock");
    e.tick().unwrap();
    assert!(!e.body_not_dropped(&c, &t, &ak("t:gone.0")) && !e.body_not_dropped(&c, &t, &ak("t:gone2.0")), "the class goes together");
    assert_eq!(e.get(&t, &ak("t:gone2.0")).unwrap(), Some(s("a2")), "its live write stays in the state");
    // deaths aggregate over the class: killing one delta's write dates the other's body
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("r")).unwrap();
    m.set(t, &GONE2, &s("y")).unwrap();
    let c2 = lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    set(&mut lp, 0, t, &GONE, "r2");
    let e = &mut lp.peers[0].engine;
    assert!(e.deaths(&c2, &t, &ak("t:gone2.0")).unwrap().is_some());
    assert_eq!(e.deaths(&c2, &t, &ak("t:gone2.0")).unwrap(), e.deaths(&c2, &t, &ak("t:gone.0")).unwrap());
    // the kill leaving no live write drops the class in its transaction, here and at the node
    // whose clock it is ahead of
    set(&mut lp, 0, t, &GONE2, "y2");
    let e = &mut lp.peers[0].engine;
    assert!(!e.body_not_dropped(&c2, &t, &ak("t:gone.0")) && !e.body_not_dropped(&c2, &t, &ak("t:gone2.0")));
    sync(&mut lp, 0, 1);
    let e = &mut lp.peers[1].engine;
    assert!(!e.body_not_dropped(&c2, &t, &ak("t:gone.0")) && !e.body_not_dropped(&c2, &t, &ak("t:gone2.0")));
    assert_eq!(e.get(&t, &ak("t:gone2.0")).unwrap(), Some(s("y2")));
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
    assert_eq!(sh.aspects[0].retention.history, Some(osis_schema::History::Keep { until: None, after: Some(86_400_000) }));
}

// spec/commits.md §5 (a body's live writes span every aspect of its class): a body on two
// aspects asked by one of them, then changed through the other, is judged afresh whichever
// aspect is asked (liveness is not cached per asked aspect alone: a stale answer gave a drop with
// no carrier, or a carrier for nothing).
#[test]
fn body_live_spans_its_class_spec_commits_5() {
    let mut lp = net(1, 84);
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
    assert!(e.body_not_dropped(&c, &t, &a1), "live: kept");
    lp.advance(10);
    set(&mut lp, 0, t, &GONE2, "b2");
    let e = &mut lp.peers[0].engine;
    assert!(!e.body_not_dropped(&c, &t, &a1), "dead: dropped with the kill");
    assert!(!e.body_live(&c, &t, &a2).unwrap());
    assert!(!e.body_live(&c, &t, &a1).unwrap(), "asked by the other aspect of the body");
}

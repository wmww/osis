#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Retention, expiry, purge, compaction snapshots and undo (spec/commits.md §5–§7).

use crate::common;
use common::*;
use osis_commit::{Kind, PurgeItem};
use osis_base::{Role, Value, WallMs};
use osis_crdt::{Op, PathOp};
use osis_node::{Cause, Event, Mutation};

fn set(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: osis_base::Tid, k: &osis_schema::Aspect<Value>, v: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.set(t, k, &s(v)).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

// spec/commits.md §5, spec/crdt.md §4.8: a write dies when superseded, at the superseding
// `ts`; per body the first and last death are kept; keep at least counts from the last.
#[test]
fn deaths_and_bounds_spec_commits_5() {
    let mut lp = net(1, 51);
    let t = new_thing(&mut lp, 0);
    let c1 = set(&mut lp, 0, t, &KEPT, "one");
    lp.advance(10);
    let c2 = set(&mut lp, 0, t, &KEPT, "two");
    let ts2 = lp.peers[0].engine.header(&c2).unwrap().ts;
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.deaths(&c1, &t, &ak("/t/kept")).unwrap(), Some((ts2, ts2)));
    assert_eq!(e.deaths(&c2, &t, &ak("/t/kept")).unwrap(), None);
    let k = e.body_keep(&c1, &t, &ak("/t/kept")).unwrap();
    assert_eq!(k.at_least, ts2.wall_ms().0 + 86_400_000);
    assert_eq!(k.at_most, None);
    assert!(e.holds_body(&c1, &t, &ak("/t/kept")));
}

// spec/crdt.md §4.8, spec/commits.md §5: a write dies at the earliest `ts` of its superseders,
// whatever order they arrive in: a superseder arriving after a later one pruned the write, and
// a write arriving after its earliest superseder was pruned, give the same first death (so
// every node has one keep-at-most bound).
#[test]
fn first_death_order_independent_spec_crdt_4_8() {
    let mut lp = net(3, 54);
    let t = new_thing(&mut lp, 0);
    let mut ids = Vec::new();
    for v in ["one", "two", "three"] {
        ids.push(set(&mut lp, 0, t, &SHORT, v));
        lp.advance(10);
    }
    let ts2 = lp.peers[0].engine.header(&ids[1]).unwrap().ts;
    let k = ak("/t/short");
    assert_eq!(lp.peers[0].engine.deaths(&ids[0], &t, &k).unwrap().map(|d| d.0), Some(ts2));
    let pks = packages(&mut lp, 0);
    let pk = |c: &osis_base::CommitId| pks.iter().find(|p| p.id == *c).unwrap().clone();
    let rest: Vec<_> = pks.iter().filter(|p| !ids.contains(&p.id)).cloned().collect();
    for (to, order) in [(1, [0, 2, 1]), (2, [2, 1, 0])] {
        for p in &rest {
            lp.deliver(to, p).unwrap();
        }
        for i in order {
            lp.deliver(to, &pk(&ids[i])).unwrap();
        }
        let e = &mut lp.peers[to].engine;
        assert_eq!(e.deaths(&ids[0], &t, &k).unwrap().map(|d| d.0), Some(ts2), "node {to}");
        assert_eq!(e.body_keep(&ids[0], &t, &k).unwrap().at_most, Some(ts2.wall_ms().0 + 600_000), "node {to}");
    }
}

// spec/crdt.md §4.8, spec/commits.md §5: last deaths alike too (keep at least counts from the
// last): X < Y < Z delivered Z first leaves X dead at Y's `ts`, not Z's.
#[test]
fn last_death_order_independent_spec_crdt_4_8() {
    let mut lp = net(3, 55);
    let t = new_thing(&mut lp, 0);
    let mut ids = Vec::new();
    for v in ["one", "two", "three"] {
        ids.push(set(&mut lp, 0, t, &KEPT, v));
        lp.advance(10);
    }
    let ts: Vec<_> = ids.iter().map(|c| lp.peers[0].engine.header(c).unwrap().ts).collect();
    let k = ak("/t/kept");
    let pks = packages(&mut lp, 0);
    let pk = |c: &osis_base::CommitId| pks.iter().find(|p| p.id == *c).unwrap().clone();
    let rest: Vec<_> = pks.iter().filter(|p| !ids.contains(&p.id)).cloned().collect();
    for (to, order) in [(1, [2, 1, 0]), (2, [0, 2, 1])] {
        for p in &rest {
            lp.deliver(to, p).unwrap();
        }
        for i in order {
            lp.deliver(to, &pk(&ids[i])).unwrap();
        }
    }
    for to in 0..3 {
        let e = &mut lp.peers[to].engine;
        assert_eq!(e.deaths(&ids[0], &t, &k).unwrap(), Some((ts[1], ts[1])), "node {to}");
        assert_eq!(e.deaths(&ids[1], &t, &k).unwrap(), Some((ts[2], ts[2])), "node {to}");
        assert_eq!(e.deaths(&ids[2], &t, &k).unwrap(), None, "node {to}");
    }
}

// spec/commits.md §5: keep at most 0 after replaced: the replacing node drops the body in the
// transaction that applies the kill (live state unchanged);
// a dropped body cannot be undone (§7).
// spec/commits.md §5 (keep at most)
#[test]
fn keep_at_most_zero_spec_commits_5() {
    let mut lp = net(2, 52);
    let t = new_thing(&mut lp, 0);
    let c1 = set(&mut lp, 0, t, &GONE, "draft");
    sync(&mut lp, 0, 1);
    lp.advance(5);
    set(&mut lp, 0, t, &GONE, "final");
    let e = &mut lp.peers[0].engine;
    assert!(!e.holds_body(&c1, &t, &ak("/t/gone")));
    assert_eq!(e.get(&t, &ak("/t/gone")).unwrap(), Some(s("final")));
    assert_eq!(e.revert(&c1).unwrap(), None);
    // every node drops it by the bound, here when it applies the kill
    sync(&mut lp, 0, 1);
    assert!(!lp.peers[1].engine.holds_body(&c1, &t, &ak("/t/gone")));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/gone")).unwrap(), Some(s("final")));
}

// spec/commits.md §6, spec/crdt.md §4.7: at T the delta's values go value-less everywhere and
// its body is dropped; a copy arriving after T is stripped on arrival.
#[test]
fn expiry_spec_commits_6() {
    let mut lp = net(3, 53);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let c = set(&mut lp, 0, t, &BRIEF, "soon gone");
    let h = lp.peers[0].engine.header(&c).unwrap();
    let a = h.aspects.iter().find(|a| a.ak.as_str() == "/t/brief").unwrap();
    assert_eq!(a.expires, Some(h.ts.wall_ms().0 + 3_600_000));
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/brief")).unwrap(), Some(s("soon gone")));
    lp.advance(3_600_001);
    for i in 0..2 {
        lp.peers[i].drain_events();
        lp.peers[i].engine.tick().unwrap();
        assert_eq!(lp.peers[i].engine.get(&t, &ak("/t/brief")).unwrap(), None, "node {i}");
        assert!(!lp.peers[i].engine.holds_body(&c, &t, &ak("/t/brief")));
        assert!(lp.peers[i].drain_events().iter().any(|e| matches!(e, Event::Changed { cause: Cause::Expiry, .. })));
    }
    // a late copy (from a relay that still had it) is stripped on arrival
    let pk = osis_node::local_peer::Package { id: c, bytes: lp.peers[1].engine.commit_bytes(&c).unwrap().unwrap(), blobs: Vec::new() };
    sync(&mut lp, 0, 2);
    let _ = lp.deliver(2, &pk);
    assert_eq!(lp.peers[2].engine.get(&t, &ak("/t/brief")).unwrap(), None);
    // an explicit T on any aspect
    let mut m = Mutation::new();
    let now = lp.peers[0].engine.now();
    m.set(t, &REG, &s("x")).unwrap();
    m.expires(t, &REG, WallMs(now.0 + 1000)).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.advance(1000);
    lp.peers[0].engine.tick().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("/t/reg")).unwrap(), None);
}

// spec/commits.md §5, spec/permissions.md §8: a purge request drops the named deltas its author
// may purge, everywhere it applies, and later copies arrive value-less; a writer without the
// right purges nothing.
#[test]
fn purge_spec_commits_5() {
    let mut lp = net(3, 54);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    let secret = set(&mut lp, 0, t, &REG, "secret");
    let full = lp.peers[0].engine.package(&secret).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    // b (author retention: only a's chain or an admin may purge a's delta) tries and fails
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("b's")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("/t/reg") });
    lp.peers[1].commit(m).unwrap();
    assert!(lp.peers[1].engine.holds_body(&secret, &t, &ak("/t/reg")));
    // a purges it
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("/t/reg") });
    let pc = lp.peers[0].commit(m).unwrap().unwrap();
    assert!(!lp.peers[0].engine.holds_body(&secret, &t, &ak("/t/reg")));
    sync(&mut lp, 0, 1);
    assert!(!lp.peers[1].engine.holds_body(&secret, &t, &ak("/t/reg")));
    // node 2 gets the purge before the purged delta: the delta arrives purged
    let pks = lp.packages(1).unwrap();
    let purge_pk = pks.iter().find(|p| p.id == pc).unwrap().clone();
    for p in pks.iter().filter(|p| p.id != pc && p.id != secret) {
        let _ = lp.deliver(2, p);
    }
    lp.deliver(2, &purge_pk).unwrap();
    // a relay still holding the old full blob
    lp.deliver(2, &full).unwrap();
    assert!(lp.peers[2].engine.commit_ids().contains(&secret));
    assert!(!lp.peers[2].engine.holds_body(&secret, &t, &ak("/t/reg")));
    for i in 0..3 {
        assert_eq!(lp.peers[i].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s("public")), "node {i}");
    }
}

// spec/commits.md §2, §5; spec/crdt.md §8: a compaction snapshot of a node's whole state covers
// every body it applied; a node holding only the snapshot reads the same (a kept set: deaths
// are kept under a relative bound only).
#[test]
fn compaction_snapshot_spec_commits_5() {
    let mut lp = net(2, 55);
    let t = new_thing(&mut lp, 0);
    let mut bodies = Vec::new();
    for i in 0..4 {
        let mut m = Mutation::new();
        m.op(t, &KEPTSET, PathOp { path: Vec::new(), op: Op::Add(s(&format!("t{i}"))) }).unwrap();
        bodies.push(lp.peers[0].commit(m).unwrap().unwrap());
    }
    let mut m = Mutation::new();
    m.op(t, &KEPTSET, PathOp { path: Vec::new(), op: Op::Remove(s("t0")) }).unwrap();
    bodies.push(lp.peers[0].commit(m).unwrap().unwrap());
    let snap = lp.peers[0].engine.snapshot(&t, &ak("/t/keptset")).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&snap).unwrap();
    assert_eq!(h.kind, Kind::ContentSnapshot);
    assert_eq!((h.aspects[0].lo, h.aspects[0].hi), (0, 0));
    assert_eq!(h.aspects[0].retention.by, osis_schema::PurgeBy::Writer);
    for c in &bodies {
        assert_eq!(lp.peers[0].engine.covered(&snap, c, &t, &ak("/t/keptset")).unwrap(), Some(true));
    }
    // the receiver gets the creation and the snapshot only
    let me0 = lp.peers[0].engine.tid();
    for p in lp.packages(0).unwrap() {
        let h = lp.peers[0].engine.header(&p.id).unwrap();
        let only_tags = h.aspects.iter().all(|a| a.ak.as_str() == "/t/keptset");
        if !only_tags || p.id == snap || h.author != me0 {
            lp.deliver(1, &p).unwrap();
        }
    }
    let want = lp.peers[0].engine.get(&t, &ak("/t/keptset")).unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/keptset")).unwrap(), want);
    // its frontiers count as received
    let r = lp.peers[1].engine.receipt(&t, &ak("/t/keptset")).unwrap();
    assert_eq!(r.contiguous(&me0, u64::MAX), 5);
    // spec/commits.md §5 (deaths per body): a write dying later dies in every body carrying
    // it, the snapshot's included, also where its own body was never held
    lp.advance(10);
    let mut m = Mutation::new();
    m.op(t, &KEPTSET, PathOp { path: Vec::new(), op: Op::Remove(s("t1")) }).unwrap();
    let kill = lp.peers[0].commit(m).unwrap().unwrap();
    let ts = lp.peers[0].engine.header(&kill).unwrap().ts;
    for p in lp.packages(0).unwrap() {
        if p.id == kill {
            lp.deliver(1, &p).unwrap();
        }
    }
    for i in 0..2 {
        assert_eq!(lp.peers[i].engine.deaths(&snap, &t, &ak("/t/keptset")).unwrap(), Some((ts, ts)), "node {i}");
    }
    assert_eq!(lp.peers[0].engine.deaths(&bodies[1], &t, &ak("/t/keptset")).unwrap(), Some((ts, ts)));
}

// spec/commits.md §7, spec/crdt.md §4.6: revert, redo as a revert of the revert; the held
// commits list them; an admin reverts another's change.
#[test]
fn undo_redo_spec_commits_7() {
    let mut lp = net(2, 56);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    set(&mut lp, 0, t, &REG, "a");
    let c2 = set(&mut lp, 0, t, &REG, "b");
    let mut m = Mutation::new();
    m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s("x")) }).unwrap();
    let c3 = lp.peers[0].commit(m).unwrap().unwrap();
    let scope = [(t, ak("/t/reg")), (t, ak("/t/tags"))];
    assert_eq!(lp.peers[0].engine.held_commits(Some(&scope))[0].id, c3);
    let u3 = lp.peers[0].engine.revert(&c3).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("/t/tags")).unwrap(), Some(Value::Set(Default::default())));
    let u2 = lp.peers[0].engine.revert(&c2).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s("a")));
    let held: Vec<_> = lp.peers[0].engine.held_commits(Some(&scope)).into_iter().map(|c| (c.id, c.header.undoes)).collect();
    assert_eq!(held[..2], [(u2, Some(c2)), (u3, Some(c3))]);
    // redo = undo of the undo commit
    lp.peers[0].engine.revert(&u2).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s("b")));
    // undo replicates like any commit
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s("b")));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/tags")).unwrap(), Some(Value::Set(Default::default())));
    // an admin undoes another's change
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    lp.advance(5);
    let cb = set(&mut lp, 1, t, &REG, "vandal");
    sync(&mut lp, 1, 0);
    assert!(lp.peers[0].engine.held_commits(Some(&scope)).iter().any(|c| c.id == cb && c.header.author == b));
    lp.peers[0].engine.revert(&cb).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s("b")));
}

// spec/commits.md §7, spec/crdt.md §4.6 over a paged state (notes/node.md, Paged state): in a new
// session, which loads only the pages it touches, undoing an edit of a key of a large map, an
// edit inside an entry's nested map and a removal restores what a whole state would, and a
// session loading everything reads the same.
#[test]
fn undo_in_lazily_loaded_pages_spec_commits_7() {
    let mut lp = net(1, 58);
    let t = new_thing(&mut lp, 0);
    let fill: std::collections::BTreeMap<Value, Value> = (0..300).map(|i| (s(&format!("k{i:03}")), s(&"v".repeat(300)))).collect();
    let mut m = Mutation::new();
    m.set(t, &BIG, &Value::Map(fill)).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let key = |k: &str| osis_crdt::PathSeg::Key(s(k));
    let edit = |lp: &mut osis_node::local_peer::LocalPeer, op: PathOp| {
        let mut m = Mutation::new();
        m.op(t, &BIG, op).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    lp.advance(5);
    let c1 = edit(&mut lp, PathOp { path: vec![key("k100")], op: Op::Set(s("changed")) });
    lp.advance(5);
    let c2 = edit(&mut lp, PathOp { path: Vec::new(), op: Op::Remove(s("k200")) });
    lp.advance(5);
    let c3 = edit(&mut lp, PathOp { path: vec![key("new")], op: Op::Set(s("added")) });
    let before = lp.peers[0].engine.get(&t, &ak("/t/big")).unwrap();
    for (c, k, want) in [(c3, "new", None), (c2, "k200", Some(s(&"v".repeat(300)))), (c1, "k100", Some(s(&"v".repeat(300))))] {
        lp.peers[0].restart(58).unwrap();
        lp.advance(5);
        lp.peers[0].engine.revert(&c).unwrap().unwrap();
        assert_eq!(lp.peers[0].engine.get_at(&t, &ak("/t/big"), &[key(k)]).unwrap(), want, "undo of {k}");
    }
    // a whole read after the three undos: the fill again
    lp.peers[0].restart(59).unwrap();
    let Some(Value::Map(after)) = lp.peers[0].engine.get(&t, &ak("/t/big")).unwrap() else { panic!() };
    assert_eq!(after.len(), 300);
    assert!(after.values().all(|v| *v == s(&"v".repeat(300))));
    assert_ne!(Some(Value::Map(after)), before);
}

// spec/commits.md §7, spec/crdt.md §4.6 over a paged state: node 0 edits inside key "n" of a
// large map while node 1 concurrently writes its own entry for "n", which lands on another page.
// In a new session, undoing the edit reads the join of every entry of "n" (the undo replaces
// both), exactly as with the whole state loaded.
#[test]
fn undo_nested_edit_reads_every_entry_of_its_key_spec_commits_7() {
    use std::collections::BTreeMap;
    let run = |whole: bool| {
        let mut lp = net(2, 61);
        let t = new_thing(&mut lp, 0);
        let b = lp.peers[1].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
        let big = ak("/x/big");
        let key = |k: &str| osis_crdt::PathSeg::Key(s(k));
        let put = |lp: &mut osis_node::local_peer::LocalPeer, i: usize, path: Vec<osis_crdt::PathSeg>, v: Value| {
            let mut m = Mutation::new();
            m.op(t, &big, PathOp { path, op: Op::Set(v) }).unwrap();
            lp.peers[i].commit(m).unwrap().unwrap()
        };
        let mut m = Mutation::new();
        m.set(t, &big, &Value::Map(BTreeMap::new())).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        put(&mut lp, 1, vec![key("n")], Value::Map(BTreeMap::from([(s("b"), s("1"))])));
        let fill = |lp: &mut osis_node::local_peer::LocalPeer, r: std::ops::Range<usize>| {
            let mut m = Mutation::new();
            for i in r {
                m.op(t, &big, PathOp { path: vec![key(&format!("k{i:03}"))], op: Op::Set(s(&"v".repeat(300))) }).unwrap();
            }
            lp.peers[0].commit(m).unwrap().unwrap();
        };
        fill(&mut lp, 0..150);
        put(&mut lp, 0, vec![key("n")], Value::Map(BTreeMap::from([(s("a"), s("0"))])));
        fill(&mut lp, 150..300);
        lp.advance(5);
        let e = put(&mut lp, 0, vec![key("n"), key("a")], s("5"));
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[0].engine.get_at(&t, &big, &[key("n")]).unwrap(), Some(Value::Map(BTreeMap::from([(s("a"), s("5")), (s("b"), s("1"))]))));
        lp.peers[0].restart(61).unwrap();
        if whole {
            lp.peers[0].engine.get(&t, &big).unwrap();
        }
        lp.advance(5);
        lp.peers[0].engine.revert(&e).unwrap().unwrap();
        let n = lp.peers[0].engine.get_at(&t, &big, &[key("n")]).unwrap();
        assert_eq!(n, Some(Value::Map(BTreeMap::from([(s("a"), s("0")), (s("b"), s("1"))]))));
        lp.peers[0].restart(62).unwrap();
        lp.peers[0].engine.state(&t, &big).unwrap()
    };
    assert!(run(false) == run(true), "the undo in a lazily loaded session equals the whole state's");
}

// spec/crdt.md §4.8: X < W < Y on a kept register, W's body under keep at most 0 (dropped when
// Y kills it). In order, X dies at W; a lagging writer's V (older than X) arriving last replays
// the aspect without W's body (was: X died at Y there); so does a replay of every body.
#[test]
fn deaths_alike_after_superseder_dropped_spec_crdt_4_8() {
    use osis_schema::{Bound, PurgeBy, Retention};
    let mut lp = net(4, 77);
    let t = new_thing(&mut lp, 0);
    let p1 = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    lp.advance(10);
    let v = set(&mut lp, 1, t, &KEPT, "v");
    lp.advance(10);
    let x = set(&mut lp, 0, t, &KEPT, "x");
    lp.advance(10);
    let mut m = Mutation::new();
    m.retention(t, &KEPT, Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs: None, rel: Some(0) } }).unwrap();
    m.set(t, &KEPT, &s("w")).unwrap();
    let w = lp.peers[0].commit(m).unwrap().unwrap();
    // W's body as sent before Y dropped it
    let wpk = packages(&mut lp, 0).into_iter().find(|p| p.id == w).unwrap();
    lp.advance(10);
    let y = set(&mut lp, 0, t, &KEPT, "y");
    let mut pks = packages(&mut lp, 0);
    pks.extend(packages(&mut lp, 1));
    let pk = |c: &osis_base::CommitId| if *c == w { wpk.clone() } else { pks.iter().find(|p| p.id == *c).unwrap().clone() };
    let rest: Vec<_> = pks.iter().filter(|p| ![v, x, w, y].contains(&p.id)).cloned().collect();
    let k = ak("/t/kept");
    let mut got = Vec::new();
    for (to, order) in [(2, [v, x, w, y]), (3, [x, w, y, v])] {
        for p in &rest {
            lp.deliver(to, p).unwrap();
        }
        for c in order {
            lp.deliver(to, &pk(&c)).unwrap();
        }
        assert!(!lp.peers[to].engine.holds_body(&w, &t, &k));
        got.push(lp.peers[to].engine.deaths(&x, &t, &k).unwrap());
        lp.peers[to].engine.replay_deaths(&t, &k).unwrap();
        got.push(lp.peers[to].engine.deaths(&x, &t, &k).unwrap());
    }
    let tw = lp.peers[0].engine.header(&w).unwrap().ts;
    assert_eq!(got, vec![Some((tw, tw)); 4]);
}

fn set_op(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: osis_base::Tid, op: Op) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.op(t, &KEPTSET, PathOp { path: Vec::new(), op }).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

// spec/crdt.md §4.8, uniform retention: on a kept set X adds e and W removes it; a snapshot
// covers W, whose body goes (no dead write: past its bound) while X's stays; Y, a lagging
// writer's remove of e older than the snapshot, beats W's reset in the state. A node holding
// W's body dates X at W; the compactor, which replays without it, did so at Y.
#[test]
fn deaths_alike_after_superseder_compacted_spec_crdt_4_8() {
    let mut lp = net(3, 78);
    let t = new_thing(&mut lp, 0);
    let p1 = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    lp.advance(10);
    let x = set_op(&mut lp, 0, t, Op::Add(s("e")));
    sync(&mut lp, 0, 1);
    lp.advance(10);
    let w = set_op(&mut lp, 0, t, Op::Remove(s("e")));
    lp.advance(10);
    let y = set_op(&mut lp, 1, t, Op::Remove(s("e")));
    lp.advance(10);
    let k = ak("/t/keptset");
    lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    let mut all = packages(&mut lp, 0);
    all.extend(packages(&mut lp, 1));
    let tw = lp.peers[0].engine.header(&w).unwrap().ts;
    assert_eq!(lp.peers[0].engine.deaths(&x, &t, &k).unwrap(), Some((tw, tw)));
    lp.peers[0].engine.drop_body(&w, &t, &k).unwrap();
    sync(&mut lp, 1, 0);
    assert!(lp.peers[0].engine.header(&y).is_some());
    for p in &all {
        lp.deliver(2, p).unwrap();
    }
    for i in [0, 2] {
        assert_eq!(lp.peers[i].engine.deaths(&x, &t, &k).unwrap(), Some((tw, tw)), "node {i}");
        lp.peers[i].engine.replay_deaths(&t, &k).unwrap();
        assert_eq!(lp.peers[i].engine.deaths(&x, &t, &k).unwrap(), Some((tw, tw)), "node {i} replayed");
    }
}

// spec/crdt.md §4.8: two snapshots carry K's write on a kept register; Z kills it, Z2 then Z,
// and the second snapshot, taken after Z2 by a writer that saw neither, carries it again. With
// K's body dropped (nothing older held: no residue) a replay meets the write in both snapshots;
// the second copy is not dated again at Z2 (was: the first snapshot's last death at Z2).
#[test]
fn deaths_alike_after_carried_write_dropped_spec_crdt_4_8() {
    let mut lp = net(4, 79);
    let t = new_thing(&mut lp, 0);
    for i in [1, 2] {
        let p = lp.peers[i].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, p, Some(edge(Role::Write)), None);
    }
    sync(&mut lp, 0, 1);
    sync(&mut lp, 0, 2);
    let k = ak("/t/kept");
    lp.advance(10);
    let kc = set(&mut lp, 0, t, &KEPT, "k");
    sync(&mut lp, 0, 1);
    sync(&mut lp, 0, 2);
    // peer 2's typed write registers the schema its snapshot takes bounds from
    set(&mut lp, 2, t, &REG, "r");
    lp.advance(10);
    let s1 = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    let z = set(&mut lp, 1, t, &KEPT, "z");
    sync(&mut lp, 1, 0);
    lp.advance(10);
    set(&mut lp, 0, t, &KEPT, "z2");
    lp.advance(10);
    let s2 = lp.peers[2].engine.snapshot(&t, &k).unwrap().unwrap();
    assert!(lp.peers[2].engine.header(&s2).unwrap().aspects[0].retention.at_least.rel.is_some());
    let mut all = packages(&mut lp, 0);
    all.extend(packages(&mut lp, 1));
    all.extend(packages(&mut lp, 2));
    let mut seen = std::collections::BTreeSet::new();
    all.retain(|p| seen.insert(p.id));
    all.sort_by_key(|p| lp.peers[0].engine.header(&p.id).or_else(|| lp.peers[2].engine.header(&p.id)).unwrap().ts);
    for p in &all {
        lp.deliver(3, p).unwrap();
    }
    let tz = lp.peers[0].engine.header(&z).unwrap().ts;
    let e = &mut lp.peers[3].engine;
    assert_eq!(e.deaths(&s1, &t, &k).unwrap(), Some((tz, tz)));
    e.drop_body(&kc, &t, &k).unwrap();
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(e.deaths(&s1, &t, &k).unwrap(), Some((tz, tz)));
}

fn map_op(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: osis_base::Tid, path: Vec<osis_crdt::PathSeg>, v: Value) -> osis_base::CommitId {
    use osis_schema::{Bound, PurgeBy, Retention};
    let mut m = Mutation::new();
    m.retention(t, &MAP, Retention { by: PurgeBy::Writer, at_least: Bound { abs: None, rel: Some(3_600_000) }, at_most: Bound::default() }).unwrap();
    m.op(t, &MAP, PathOp { path, op: Op::Set(v) }).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

// spec/crdt.md §4.8: on a kept map, B (another writer) and then C write inside A's entry. In
// order, A's field dies at B and B's at C; a replay of every body agrees (was: a replay
// stripped B's and C's writes as copies of A's entry, so B had no death and A's died at C).
#[test]
fn deaths_alike_nested_in_others_entry_spec_crdt_4_8() {
    use osis_crdt::PathSeg;
    let mut lp = net(2, 80);
    let t = new_thing(&mut lp, 0);
    let p1 = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    lp.advance(10);
    let a = map_op(&mut lp, 0, t, vec![PathSeg::Key(s("k"))], item("x", 1));
    sync(&mut lp, 0, 1);
    lp.advance(10);
    let b = map_op(&mut lp, 1, t, vec![PathSeg::Key(s("k")), PathSeg::Field(1)], Value::Int(2));
    sync(&mut lp, 1, 0);
    lp.advance(10);
    let c = map_op(&mut lp, 0, t, vec![PathSeg::Key(s("k")), PathSeg::Field(1)], Value::Int(3));
    let k = ak("/t/map");
    let e = &mut lp.peers[0].engine;
    let (tb, tc) = (e.header(&b).unwrap().ts, e.header(&c).unwrap().ts);
    let want = (e.deaths(&a, &t, &k).unwrap(), e.deaths(&b, &t, &k).unwrap());
    assert_eq!(want, (Some((tb, tb)), Some((tc, tc))));
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!((e.deaths(&a, &t, &k).unwrap(), e.deaths(&b, &t, &k).unwrap()), want);
}

// spec/crdt.md §4.8, spec/requirements.md Scale: a dropped snapshot's residue keeps only the
// copies a replay cannot play at their own commit (held here): not the aspect's state.
#[test]
fn snapshot_residue_skips_held_copies_spec_crdt_4_8() {
    let mut lp = net(1, 81);
    let t = new_thing(&mut lp, 0);
    let k = ak("/t/keptset");
    for i in 0..40 {
        lp.advance(10);
        set_op(&mut lp, 0, t, Op::Add(s(&format!("element {i}"))));
    }
    lp.advance(10);
    let s1 = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    set_op(&mut lp, 0, t, Op::Add(s("last")));
    lp.advance(10);
    lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    let e = &mut lp.peers[0].engine;
    e.drop_body(&s1, &t, &k).unwrap();
    let n = e.residue_bytes(&t, &k).unwrap();
    assert!(n < 100, "residue of {n} bytes");
    e.replay_deaths(&t, &k).unwrap();
}

// spec/crdt.md §4.8, spec/commits.md §5: on a kept set a lagging writer's remove of an element,
// older than a compaction snapshot the owner took after it, dates the element's death at the
// remove; with the writer's later add in the same batch the window spans the snapshot, which
// (no death of its own: nothing it carries dies after it) plays its copies there instead of a
// replay of every body.
#[test]
fn late_delta_before_snapshot_windowed_spec_crdt_4_8() {
    let mut lp = net(2, 82);
    let t = new_thing(&mut lp, 0);
    let p1 = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    let k = ak("/t/keptset");
    let mut adds = Vec::new();
    for i in 0..10 {
        lp.advance(10);
        adds.push(set_op(&mut lp, 0, t, Op::Add(s(&format!("e{i}")))));
    }
    sync(&mut lp, 0, 1);
    lp.advance(10);
    let late = set_op(&mut lp, 1, t, Op::Remove(s("e3")));
    let tl = lp.peers[1].engine.header(&late).unwrap().ts;
    for i in 10..20 {
        lp.advance(10);
        set_op(&mut lp, 0, t, Op::Add(s(&format!("e{i}"))));
    }
    lp.advance(10);
    lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    set_op(&mut lp, 1, t, Op::Add(s("x")));
    lp.advance(10);
    set_op(&mut lp, 0, t, Op::Add(s("after")));
    osis_node::costs::take();
    // the writer's chain, then its late writes in one batch
    lp.peers[0].engine.defer_deaths(true).unwrap();
    sync(&mut lp, 1, 0);
    lp.peers[0].engine.defer_deaths(false).unwrap();
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.deaths(&adds[3], &t, &k).unwrap(), Some((tl, tl)));
    let costs: Vec<&str> = osis_node::costs::take().into_iter().map(|x| x.0).collect();
    assert!(costs.contains(&"deaths: window skips copies"), "{costs:?}");
    assert!(!costs.contains(&"deaths: whole replay"), "{costs:?}");
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(e.deaths(&adds[3], &t, &k).unwrap(), Some((tl, tl)));
    assert!(e.last_deaths_stale().unwrap().is_empty());
}

// spec/crdt.md §4.8, §8: a snapshot's copy of a write nested in an entry another held commit
// created (a put into the key's live entry) supersedes that commit's write there; delivered the
// snapshot first, the late creator dies at the carried write, as in a replay of every body (was:
// the window dropped the entry's content with the creator's copies, order seed 7233).
#[test]
fn late_entry_creator_dies_at_carried_nested_write_spec_crdt_4_8() {
    let mut lp = net(2, 84);
    let t = new_thing(&mut lp, 0);
    let k = ak("/t/gonemap");
    let put = |lp: &mut osis_node::local_peer::LocalPeer, v: &str| {
        let mut m = Mutation::new();
        m.op(t, &GONEMAP, PathOp { path: vec![osis_crdt::PathSeg::Key(s("a"))], op: Op::Set(s(v)) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let a = put(&mut lp, "one");
    lp.advance(10);
    let b = put(&mut lp, "two");
    let tb = lp.peers[0].engine.header(&b).unwrap().ts;
    lp.advance(10);
    lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.deaths(&a, &t, &k).unwrap(), Some((tb, tb)));
    for p in packages(&mut lp, 0).iter().filter(|p| p.id != a && p.id != b) {
        lp.deliver(1, p).unwrap();
    }
    let pa = packages(&mut lp, 0).into_iter().find(|p| p.id == a).unwrap();
    osis_node::costs::take();
    lp.deliver(1, &pa).unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.holds_body(&a, &t, &k));
    assert_eq!(e.deaths(&a, &t, &k).unwrap(), Some((tb, tb)));
    // the snapshot carries a write never held here, stamped after the late one: it plays
    let costs: Vec<&str> = osis_node::costs::take().into_iter().map(|x| x.0).collect();
    assert!(costs.contains(&"deaths: window over copies"), "{costs:?}");
    assert!(!costs.contains(&"deaths: whole replay"), "{costs:?}");
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(e.deaths(&a, &t, &k).unwrap(), Some((tb, tb)));
}

// spec/crdt.md §4.8, §8: on a kept register A, then X (a writer's), then a compaction snapshot
// S carrying X; node 3 holds A and S but never X, so a replay dates A at S's copy of X. L, a
// third writer's write between X and S, arrives late: a replay plays L before S's copy and
// dates A at L, though A died before L's `ts`; the window judges A too (walks seed 7204: the
// window kept A at X).
#[test]
fn late_delta_preempts_carried_superseder_spec_crdt_4_8() {
    let mut lp = net(4, 85);
    let t = new_thing(&mut lp, 0);
    for i in [1, 2] {
        let p = lp.peers[i].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, p, Some(edge(Role::Write)), None);
    }
    sync(&mut lp, 0, 1);
    sync(&mut lp, 0, 2);
    let k = ak("/t/kept");
    lp.advance(10);
    let a = set(&mut lp, 0, t, &KEPT, "a");
    sync(&mut lp, 0, 2);
    lp.advance(10);
    let x = set(&mut lp, 1, t, &KEPT, "x");
    sync(&mut lp, 1, 0);
    lp.advance(10);
    let l = set(&mut lp, 2, t, &KEPT, "l");
    lp.advance(10);
    lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    let (tx, tl) = (lp.peers[0].engine.header(&x).unwrap().ts, lp.peers[2].engine.header(&l).unwrap().ts);
    for p in packages(&mut lp, 0).iter().filter(|p| p.id != x) {
        lp.deliver(3, p).unwrap();
    }
    assert_eq!(lp.peers[3].engine.deaths(&a, &t, &k).unwrap(), Some((tx, tx)));
    let (pl, rest): (Vec<_>, Vec<_>) = packages(&mut lp, 2).into_iter().partition(|p| p.id == l);
    for p in &rest {
        lp.deliver(3, p).unwrap();
    }
    osis_node::costs::take();
    lp.deliver(3, &pl[0]).unwrap();
    let e = &mut lp.peers[3].engine;
    assert_eq!(e.deaths(&a, &t, &k).unwrap(), Some((tl, tl)));
    let costs: Vec<&str> = osis_node::costs::take().into_iter().map(|x| x.0).collect();
    assert!(costs.contains(&"deaths: window over copies"), "{costs:?}");
    assert!(!costs.contains(&"deaths: whole replay"), "{costs:?}");
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(e.deaths(&a, &t, &k).unwrap(), Some((tl, tl)));
}

// notes/local-store.md (rebuildable indexes), spec/crdt.md §4.8: the last-death rows of a kept
// register follow its death records; rows that do not parse are rebuilt by the next window that
// reads them, and a rebuild of the persisted index writes them again from the records.
#[test]
fn last_death_rows_rebuilt_spec_crdt_4_8() {
    let mut lp = net(2, 83);
    let t = new_thing(&mut lp, 0);
    let p1 = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    let k = ak("/t/kept");
    for i in 0..70 {
        lp.advance(10);
        set(&mut lp, 0, t, &KEPT, &format!("a{i}"));
    }
    lp.advance(10);
    let late: Vec<_> = (0..2).map(|i| set(&mut lp, 1, t, &KEPT, &format!("b{i}"))).collect();
    lp.advance(10);
    for i in 0..3 {
        set(&mut lp, 0, t, &KEPT, &format!("c{i}"));
    }
    let pks = packages(&mut lp, 1);
    let e = &mut lp.peers[0].engine;
    assert!(e.last_deaths_stale().unwrap().is_empty());
    assert!(e.damage_last_deaths(&t, &k).unwrap() > 64);
    assert!(!e.last_deaths_stale().unwrap().is_empty());
    // the writer's chain, then its late writes
    for p in &pks {
        lp.deliver(0, p).unwrap();
    }
    let e = &mut lp.peers[0].engine;
    assert!(e.last_deaths_stale().unwrap().is_empty(), "rebuilt by the window");
    let tb = e.header(&late[1]).unwrap().ts;
    assert_eq!(e.deaths(&late[0], &t, &k).unwrap(), Some((tb, tb)));
    e.damage_last_deaths(&t, &k).unwrap();
    e.rebuild_index().unwrap();
    assert!(e.last_deaths_stale().unwrap().is_empty(), "rebuilt with the index");
}

// spec/requirements.md (Decentralization: deaths a function of the held set), spec/crdt.md
// §4.8: on a kept set the owner drops its first add (no residue: nothing older held), takes two
// snapshots carrying it, and a lagging writer's removes older than both arrive in one batch:
// the window spans both snapshots, and every body's deaths equal a whole replay and those of
// nodes taking the same commits in other orders.
#[test]
fn late_deltas_before_two_snapshots_alike_spec_crdt_4_8() {
    let mut lp = net(4, 84);
    let t = new_thing(&mut lp, 0);
    let p1 = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    let k = ak("/t/keptset");
    let mut adds = Vec::new();
    for i in 0..10 {
        lp.advance(10);
        adds.push(set_op(&mut lp, 0, t, Op::Add(s(&format!("e{i}")))));
    }
    sync(&mut lp, 0, 1);
    let early = packages(&mut lp, 0);
    lp.advance(10);
    set_op(&mut lp, 1, t, Op::Remove(s("e0")));
    lp.advance(10);
    set_op(&mut lp, 1, t, Op::Remove(s("e3")));
    for i in 10..15 {
        lp.advance(10);
        set_op(&mut lp, 0, t, Op::Add(s(&format!("e{i}"))));
    }
    lp.advance(10);
    lp.peers[0].engine.drop_body(&adds[0], &t, &k).unwrap();
    lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    set_op(&mut lp, 0, t, Op::Add(s("between")));
    lp.advance(10);
    lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    set_op(&mut lp, 1, t, Op::Add(s("x")));
    lp.advance(10);
    set_op(&mut lp, 0, t, Op::Add(s("after")));
    let own = packages(&mut lp, 0);
    let theirs: Vec<_> = packages(&mut lp, 1).into_iter().filter(|p| !own.iter().any(|q| q.id == p.id)).collect();
    osis_node::costs::take();
    lp.peers[0].engine.defer_deaths(true).unwrap();
    sync(&mut lp, 1, 0);
    lp.peers[0].engine.defer_deaths(false).unwrap();
    let e0 = &lp.peers[0].engine;
    let ids: Vec<_> = own.iter().chain(&theirs).map(|p| p.id).filter(|c| e0.header(c).is_some_and(|h| h.aspects.iter().any(|a| a.ak == k))).collect();
    let deaths = |e: &mut osis_node::Engine| ids.iter().map(|c| e.deaths(c, &t, &k).unwrap()).collect::<Vec<_>>();
    let want = deaths(&mut lp.peers[0].engine);
    let costs: Vec<&str> = osis_node::costs::take().into_iter().map(|x| x.0).collect();
    assert!(costs.contains(&"deaths: window skips copies"), "{costs:?}");
    assert!(!costs.contains(&"deaths: whole replay"), "{costs:?}");
    assert!(want.iter().any(|d| d.is_some()));
    // other orders: the late writer's commits first, or after the owner's
    let early_ids: Vec<_> = early.iter().map(|p| p.id).collect();
    // as the owner sends them now: the first add without its body
    let (early, rest): (Vec<_>, Vec<_>) = own.iter().cloned().partition(|p| early_ids.contains(&p.id));
    for (to, order) in [(2, [&early, &theirs, &rest]), (3, [&early, &rest, &theirs])] {
        for p in order.into_iter().flatten() {
            lp.deliver(to, p).unwrap();
        }
        assert_eq!(deaths(&mut lp.peers[to].engine), want, "node {to}");
    }
    lp.peers[0].engine.replay_deaths(&t, &k).unwrap();
    assert_eq!(deaths(&mut lp.peers[0].engine), want, "a whole replay");
    assert!(lp.peers[0].engine.last_deaths_stale().unwrap().is_empty());
}

// spec/crdt.md §4.8, §8: a dropped snapshot carries a write X never held here, in its residue
// (an older kept body held when it dropped) or only in the state (none held: no residue); a late
// delta older than X dies at it, in a window as in a replay of every body (was: the window
// skipped the snapshot, whose carried groups go with its body).
#[test]
fn late_delta_dies_at_dropped_snapshot_copy_spec_crdt_4_8() {
    for residue in [true, false] {
        late_delta_dies_at_dropped_snapshot_copy(residue);
    }
}

fn late_delta_dies_at_dropped_snapshot_copy(residue: bool) {
    let mut lp = net(4, 85);
    let t = new_thing(&mut lp, 0);
    for i in [1, 2] {
        let p = lp.peers[i].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, p, Some(edge(Role::Write)), None);
    }
    sync(&mut lp, 0, 1);
    sync(&mut lp, 0, 2);
    let k = ak("/t/kept");
    lp.advance(10);
    let a = set(&mut lp, 0, t, &KEPT, "a");
    sync(&mut lp, 0, 2);
    lp.advance(10);
    let l = set(&mut lp, 1, t, &KEPT, "late");
    lp.advance(10);
    let x = set(&mut lp, 2, t, &KEPT, "x");
    lp.advance(10);
    let s1 = lp.peers[2].engine.snapshot(&t, &k).unwrap().unwrap();
    let mut all = packages(&mut lp, 0);
    all.extend(packages(&mut lp, 1));
    all.extend(packages(&mut lp, 2));
    let mut seen = std::collections::BTreeSet::new();
    all.retain(|p| seen.insert(p.id) && p.id != x && (residue || p.id != a));
    let (late, rest): (Vec<_>, Vec<_>) = all.into_iter().partition(|p| p.id == l);
    for p in &rest {
        lp.deliver(3, p).unwrap();
    }
    let e = &mut lp.peers[3].engine;
    assert!(e.header(&x).is_none() && e.holds_body(&s1, &t, &k));
    e.drop_body(&s1, &t, &k).unwrap();
    assert_eq!(e.residue_bytes(&t, &k).unwrap() > 0, residue);
    lp.deliver(3, &late[0]).unwrap();
    let (tl, tx) = (lp.peers[1].engine.header(&l).unwrap().ts, lp.peers[2].engine.header(&x).unwrap().ts);
    let e = &mut lp.peers[3].engine;
    let deaths = |e: &mut osis_node::Engine| (if residue { e.deaths(&a, &t, &k).unwrap() } else { None }, e.deaths(&l, &t, &k).unwrap());
    let got = deaths(e);
    assert_eq!(got, (residue.then_some((tl, tl)), Some((tx, tx))), "residue {residue}");
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(deaths(e), got, "residue {residue}");
}

fn kept_text(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: osis_base::Tid, op: Op) -> osis_base::CommitId {
    use osis_schema::{Bound, PurgeBy, Retention};
    let mut m = Mutation::new();
    m.retention(t, &TEXT, Retention { by: PurgeBy::Author, at_least: Bound { abs: None, rel: Some(3_600_000) }, at_most: Bound::default() }).unwrap();
    m.op(t, &TEXT, PathOp { path: Vec::new(), op }).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

// spec/crdt.md §4.8: on a kept text a lagging writer's delete, older than a compaction snapshot,
// arrives late; the window skips the snapshot (every write it carries is played at its own
// commit), whose element creations stay in it as anchors, and dates as a whole replay.
#[test]
fn late_text_delete_before_snapshot_windowed_spec_crdt_4_8() {
    let mut lp = net(2, 86);
    let t = new_thing(&mut lp, 0);
    let p1 = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    let k = ak("/t/text");
    lp.advance(10);
    let i1 = kept_text(&mut lp, 0, t, Op::Insert { at: 0, items: vec![s("ab")] });
    sync(&mut lp, 0, 1);
    lp.advance(10);
    let d = kept_text(&mut lp, 1, t, Op::Delete { at: 0, len: 1 });
    lp.advance(10);
    kept_text(&mut lp, 0, t, Op::Insert { at: 0, items: vec![s("c")] });
    lp.advance(10);
    lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    kept_text(&mut lp, 0, t, Op::Insert { at: 0, items: vec![s("d")] });
    osis_node::costs::take();
    sync(&mut lp, 1, 0);
    let e = &mut lp.peers[0].engine;
    let td = e.header(&d).unwrap().ts;
    let got = e.deaths(&i1, &t, &k).unwrap();
    assert_eq!(got, Some((td, td)));
    let costs: Vec<&str> = osis_node::costs::take().into_iter().map(|x| x.0).collect();
    assert!(costs.contains(&"deaths: window skips copies") && !costs.contains(&"deaths: whole replay"), "{costs:?}");
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(e.deaths(&i1, &t, &k).unwrap(), got);
}

// spec/crdt.md §4.8, §8: on a kept map X (never held here) writes inside A's entry and a
// snapshot carries it; Y, later, writes there too. A's field dies at X in a replay of every body
// (was: the replay dropped X's copy with A's entry and dated it at Y; the state at the end no
// longer holds X's write).
#[test]
fn replay_dates_at_carried_write_in_held_entry_spec_crdt_4_8() {
    use osis_crdt::PathSeg;
    let mut lp = net(4, 87);
    let t = new_thing(&mut lp, 0);
    for i in [1, 2] {
        let p = lp.peers[i].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, p, Some(edge(Role::Write)), None);
    }
    sync(&mut lp, 0, 2);
    let k = ak("/t/map");
    lp.advance(10);
    let a = map_op(&mut lp, 0, t, vec![PathSeg::Key(s("k"))], item("a", 1));
    sync(&mut lp, 0, 2);
    lp.advance(10);
    let x = map_op(&mut lp, 2, t, vec![PathSeg::Key(s("k")), PathSeg::Field(1)], Value::Int(2));
    lp.advance(10);
    let s1 = lp.peers[2].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    let y = map_op(&mut lp, 0, t, vec![PathSeg::Key(s("k")), PathSeg::Field(1)], Value::Int(3));
    let mut all = packages(&mut lp, 0);
    all.extend(packages(&mut lp, 2));
    let mut seen = std::collections::BTreeSet::new();
    all.retain(|p| seen.insert(p.id) && p.id != x);
    for p in &all {
        lp.deliver(3, p).unwrap();
    }
    let tx = lp.peers[2].engine.header(&x).unwrap().ts;
    let e = &mut lp.peers[3].engine;
    assert!(e.header(&x).is_none() && e.holds_body(&s1, &t, &k) && e.holds_body(&y, &t, &k));
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(e.deaths(&a, &t, &k).unwrap(), Some((tx, tx)));
}

// spec/crdt.md §4.8: on a kept map node 3 holds snapshot S (carrying X, a put it never holds)
// and drops it with no held bounded body before it: no residue, so a replay plays X with the
// state, last. Z (another key, after L) arrives, then A (older than S; X dates it), then L,
// late, between S and Z: a replay plays L before the state and dates A at L, though A died
// before L's `ts`; the window judges A too (was: kept A at X).
#[test]
fn late_delta_preempts_state_played_copy_spec_crdt_4_8() {
    use osis_crdt::PathSeg;
    let mut lp = net(4, 87);
    let t = new_thing(&mut lp, 0);
    for i in [1, 2] {
        let p = lp.peers[i].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, p, Some(edge(Role::Write)), None);
    }
    sync(&mut lp, 0, 1);
    sync(&mut lp, 0, 2);
    let k = ak("/t/map");
    let key = |n: &str| vec![PathSeg::Key(s(n))];
    lp.advance(10);
    let a = map_op(&mut lp, 0, t, key("k1"), item("a", 1));
    sync(&mut lp, 0, 1);
    sync(&mut lp, 0, 2);
    lp.advance(10);
    let x = map_op(&mut lp, 1, t, key("k1"), item("x", 2));
    sync(&mut lp, 1, 0);
    lp.advance(10);
    let s1 = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    let l = map_op(&mut lp, 2, t, key("k1"), item("l", 3));
    lp.advance(10);
    let z = map_op(&mut lp, 0, t, key("k2"), item("z", 4));
    let mut all = packages(&mut lp, 0);
    all.extend(packages(&mut lp, 2));
    let mut seen = std::collections::BTreeSet::new();
    all.retain(|p| seen.insert(p.id) && p.id != x);
    let pa = all.iter().find(|p| p.id == a).unwrap().clone();
    let pl = all.iter().find(|p| p.id == l).unwrap().clone();
    let pz = all.iter().find(|p| p.id == z).unwrap().clone();
    for p in all.iter().filter(|p| ![a, l, z].contains(&p.id)) {
        lp.deliver(3, p).unwrap();
    }
    let e = &mut lp.peers[3].engine;
    assert!(e.header(&x).is_none() && e.holds_body(&s1, &t, &k));
    e.drop_body(&s1, &t, &k).unwrap();
    assert_eq!(e.residue_bytes(&t, &k).unwrap(), 0);
    lp.deliver(3, &pz).unwrap();
    lp.deliver(3, &pa).unwrap();
    let tx = lp.peers[1].engine.header(&x).unwrap().ts;
    assert_eq!(lp.peers[3].engine.deaths(&a, &t, &k).unwrap(), Some((tx, tx)));
    osis_node::costs::take();
    lp.deliver(3, &pl).unwrap();
    let costs: Vec<&str> = osis_node::costs::take().into_iter().map(|x| x.0).collect();
    assert!(costs.contains(&"deaths: window") && !costs.contains(&"deaths: whole replay"), "{costs:?}");
    let tl = lp.peers[2].engine.header(&l).unwrap().ts;
    let e = &mut lp.peers[3].engine;
    let got = e.deaths(&a, &t, &k).unwrap();
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!((got, e.deaths(&a, &t, &k).unwrap()), (Some((tl, tl)), Some((tl, tl))), "tx {tx:?} tl {tl:?}");
}

// spec/crdt.md §4.8 (deaths a function of the held set): random histories on a kept register,
// a kept set and a kept map by four writers with compaction snapshots (peer 3's writes reach
// node 4 only as snapshot copies, some others' never), delivered to node 4 in a random order
// with snapshots and writes dropped as they come (with or without a residue) and replays
// batched: every window is checked against a whole replay (debug builds), and the deaths at
// the end against one. The default seeds must reach windows over stray copies, among them one
// that judges every body. Seeds: OSIS_STRAYS_START, OSIS_STRAYS_SEEDS.
#[test]
fn late_deltas_windowed_alike_random_spec_crdt_4_8() {
    let env = |k: &str| std::env::var(k).ok().and_then(|s| s.parse::<u64>().ok());
    let (start, n) = (env("OSIS_STRAYS_START"), env("OSIS_STRAYS_SEEDS"));
    let default = start.is_none() && n.is_none();
    let start = start.unwrap_or(0);
    let mut reached: std::collections::BTreeMap<&'static str, u64> = Default::default();
    osis_node::costs::take();
    // every failing seed is reported
    let failed: Vec<u64> = (start..start + n.unwrap_or(24)).filter(|&seed| std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| strays_history(seed, &mut reached))).is_err()).collect();
    assert!(failed.is_empty(), "strays seeds failed: {failed:?} (replay one: OSIS_STRAYS_START=<seed> OSIS_STRAYS_SEEDS=1)");
    println!("{reached:?}");
    if default {
        for k in ["deaths: window", "deaths: window strays", "deaths: window strays, every body"] {
            assert!(reached.get(k).is_some_and(|n| *n > 0), "not reached: {k} ({reached:?})");
        }
    }
}

// as above, seeds that failed: 1018, a held snapshot between a stray and the late delta gained
// a death (no record before; on main too); 2392, the winner a late join met was a stray, which
// the replay met after another superseder past the hint; 21812, an in-order write killed a
// write dropped without a residue (played with the state) that had dated a late body, which
// kept that death while a replay dated it at the in-order write, and a later window rested on
// it; 1427 (deaths at the end), the same with a dropped snapshot's copy; 32432, a body
// superseding a copy a later held snapshot carried (that had not seen it) dropped without a
// residue, so a replay dated the copy after the snapshot, which gained a death the records
// lacked; 2423 (at the end), the same; 67421 (at the end), a write dropped without a residue
// before the first held bounded body superseded a copy in a later held snapshot that had not
// seen it, and an in-order write killed it: a replay then dated the copy at that write
#[test]
fn late_deltas_windowed_found_histories_spec_crdt_4_8() {
    for seed in [1018, 2392, 21812, 1427, 32432, 2423, 67421] {
        strays_history(seed, &mut Default::default());
    }
}

/// One history of `late_deltas_windowed_alike_random_*`; adds the window spans it ran to
/// `reached`.
fn strays_history(seed: u64, reached: &mut std::collections::BTreeMap<&'static str, u64>) {
    use osis_crdt::PathSeg;
    osis_node::costs::take();
    let mut r = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut below = |n: u64| {
        r ^= r << 13;
        r ^= r >> 7;
        r ^= r << 17;
        r % n
    };
    let mut lp = net(5, 1000 + seed);
    let t = new_thing(&mut lp, 0);
    for i in 1..4 {
        let p = lp.peers[i].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, p, Some(edge(Role::Write)), None);
    }
    for i in 1..5 {
        sync(&mut lp, 0, i);
    }
    let aks = [ak("/t/kept"), ak("/t/keptset"), ak("/t/map")];
    let (mut writes, mut snaps) = (Vec::new(), Vec::new());
    for _ in 0..28 {
        let x = below(100);
        let i = below(4) as usize;
        if x < 55 {
            let v = format!("v{}", below(3));
            let mut m = Mutation::new();
            match below(3) {
                0 => {
                    m.set(t, &KEPT, &s(&v)).unwrap();
                }
                1 => {
                    m.op(t, &KEPTSET, PathOp { path: Vec::new(), op: if below(3) == 0 { Op::Remove(s(&v)) } else { Op::Add(s(&v)) } }).unwrap();
                }
                _ => {
                    let keep = osis_schema::Retention { by: osis_schema::PurgeBy::Writer, at_least: osis_schema::Bound { abs: None, rel: Some(3_600_000) }, at_most: osis_schema::Bound::default() };
                    m.retention(t, &MAP, keep).unwrap();
                    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s(&v))], op: Op::Set(item("e", below(9) as i64)) }).unwrap();
                }
            }
            // a remove of nothing writes no commit
            if let Some(c) = lp.peers[i].commit(m).unwrap() {
                writes.push((i, c));
            }
        } else if x < 72 {
            let j = below(4) as usize;
            if j != i {
                sync(&mut lp, i, j);
            }
        } else if x < 88 {
            let a = below(3) as usize;
            if let Some(c) = lp.peers[i].engine.snapshot(&t, &aks[a]).unwrap() {
                snaps.push((c, a));
            }
        }
        lp.advance(1 + below(12));
    }
    let mut all = Vec::new();
    for i in 0..4 {
        all.extend(packages(&mut lp, i));
    }
    let mut seen = std::collections::BTreeSet::new();
    let withheld: std::collections::BTreeSet<osis_base::CommitId> = writes.iter().filter(|(i, _)| *i == 3 || below(7) == 0).map(|x| x.1).collect();
    all.retain(|p| seen.insert(p.id) && lp.peers[4].engine.header(&p.id).is_none() && !withheld.contains(&p.id));
    let mode = below(3);
    if mode != 1 {
        for i in (1..all.len()).rev() {
            all.swap(i, below(i as u64 + 1) as usize);
        }
        if mode == 2 {
            // snapshots first: they drop before any body older than them arrives (no residue)
            all.sort_by_key(|p| !snaps.iter().any(|x| x.0 == p.id));
        }
    } else {
        // newest first, roughly: snapshots drop before older bodies arrive (no residue)
        let ts = |lp: &osis_node::local_peer::LocalPeer, c: &osis_base::CommitId| (0..4).find_map(|i| lp.peers[i].engine.header(c)).map(|h| h.ts);
        all.sort_by_key(|p| std::cmp::Reverse(ts(&lp, &p.id)));
        let n = all.len();
        for _ in 0..n / 3 {
            let i = below(n as u64) as usize;
            all.swap(i, (i + 1).min(n - 1));
        }
    }
    let mut deferred = false;
    for p in &all {
        if below(4) == 0 {
            deferred = !deferred;
            lp.peers[4].engine.defer_deaths(deferred).unwrap();
        }
        let _ = lp.deliver(4, p);
        let e = &mut lp.peers[4].engine;
        if let Some(&(c, a)) = snaps.iter().find(|x| x.0 == p.id)
            && below(3) == 0
            && e.holds_body(&c, &t, &aks[a])
        {
            e.drop_body(&c, &t, &aks[a]).unwrap();
        }
        if below(5) == 0
            && let Some(&(c, a)) = snaps.get(below(snaps.len().max(1) as u64) as usize)
            && e.holds_body(&c, &t, &aks[a])
        {
            e.drop_body(&c, &t, &aks[a]).unwrap();
        }
        if below(12) == 0
            && let Some(&(_, c)) = writes.get(below(writes.len() as u64) as usize)
        {
            for a in &aks {
                if e.holds_body(&c, &t, a) {
                    e.drop_body(&c, &t, a).unwrap();
                }
            }
        }
    }
    let e = &mut lp.peers[4].engine;
    e.defer_deaths(false).unwrap();
    let ids: Vec<osis_base::CommitId> = writes.iter().map(|x| x.1).chain(snaps.iter().map(|x| x.0)).filter(|c| e.header(c).is_some()).collect();
    // the records are what a whole replay gives
    for a in &aks {
        let have: Vec<_> = ids.iter().map(|c| e.deaths(c, &t, a).ok()).collect();
        e.replay_deaths(&t, a).unwrap();
        let want: Vec<_> = ids.iter().map(|c| e.deaths(c, &t, a).ok()).collect();
        assert_eq!(have, want, "seed {seed} {a:?}");
    }
    for (k, _, c) in osis_node::costs::take() {
        if k.starts_with("deaths: window") {
            *reached.entry(k).or_default() += c;
        }
    }
}

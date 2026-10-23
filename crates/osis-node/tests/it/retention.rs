#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Retention, expiry, purge, compaction snapshots and undo (spec/commits.md §5–§7).

use crate::common;
use common::*;
use osis_commit::{Kind, PurgeItem};
use osis_core::{Role, Value, WallMs};
use osis_crdt::{Op, PathOp};
use osis_node::{Cause, Event, Mutation};

fn set(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: osis_core::Tid, k: &osis_schema::Aspect<Value>, v: &str) -> osis_core::CommitId {
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
    let pk = |c: &osis_core::CommitId| pks.iter().find(|p| p.id == *c).unwrap().clone();
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
    assert_eq!(e.undo(&c1).unwrap(), None);
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
// every body it applied; a node holding only the snapshot reads the same.
#[test]
fn compaction_snapshot_spec_commits_5() {
    let mut lp = net(2, 55);
    let t = new_thing(&mut lp, 0);
    let mut bodies = Vec::new();
    for i in 0..4 {
        let mut m = Mutation::new();
        m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s(&format!("t{i}"))) }).unwrap();
        bodies.push(lp.peers[0].commit(m).unwrap().unwrap());
    }
    let mut m = Mutation::new();
    m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Remove(s("t0")) }).unwrap();
    bodies.push(lp.peers[0].commit(m).unwrap().unwrap());
    let snap = lp.peers[0].engine.snapshot(&t, &ak("/t/tags")).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&snap).unwrap();
    assert_eq!(h.kind, Kind::ContentSnapshot);
    assert_eq!((h.aspects[0].lo, h.aspects[0].hi), (0, 0));
    assert_eq!(h.aspects[0].retention.by, osis_schema::PurgeBy::Writer);
    for c in &bodies {
        assert_eq!(lp.peers[0].engine.covered(&snap, c, &t, &ak("/t/tags")).unwrap(), Some(true));
    }
    // the receiver gets the creation and the snapshot only
    let me0 = lp.peers[0].engine.tid();
    for p in lp.packages(0).unwrap() {
        let h = lp.peers[0].engine.header(&p.id).unwrap();
        let only_tags = h.aspects.iter().all(|a| a.ak.as_str() == "/t/tags");
        if !only_tags || p.id == snap || h.author != me0 {
            lp.deliver(1, &p).unwrap();
        }
    }
    let want = lp.peers[0].engine.get(&t, &ak("/t/tags")).unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/tags")).unwrap(), want);
    // its frontiers count as received
    let r = lp.peers[1].engine.receipt(&t, &ak("/t/tags")).unwrap();
    assert_eq!(r.contiguous(&me0, u64::MAX), 5);
    // spec/commits.md §5 (deaths per body): a write dying later dies in every body carrying
    // it, the snapshot's included, also where its own body was never held
    lp.advance(10);
    let mut m = Mutation::new();
    m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Remove(s("t1")) }).unwrap();
    let kill = lp.peers[0].commit(m).unwrap().unwrap();
    let ts = lp.peers[0].engine.header(&kill).unwrap().ts;
    for p in lp.packages(0).unwrap() {
        if p.id == kill {
            lp.deliver(1, &p).unwrap();
        }
    }
    for i in 0..2 {
        assert_eq!(lp.peers[i].engine.deaths(&snap, &t, &ak("/t/tags")).unwrap(), Some((ts, ts)), "node {i}");
    }
    assert_eq!(lp.peers[0].engine.deaths(&bodies[1], &t, &ak("/t/tags")).unwrap(), Some((ts, ts)));
}

// spec/commits.md §7, spec/crdt.md §4.6: undo and redo; the derived stacks; an admin undoes
// another's change.
#[test]
fn undo_redo_spec_commits_7() {
    let mut lp = net(2, 56);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let me = lp.peers[0].engine.tid();
    set(&mut lp, 0, t, &REG, "a");
    let c2 = set(&mut lp, 0, t, &REG, "b");
    let mut m = Mutation::new();
    m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s("x")) }).unwrap();
    let c3 = lp.peers[0].commit(m).unwrap().unwrap();
    let scope = [(t, ak("/t/reg")), (t, ak("/t/tags"))];
    let (undo, redo) = lp.peers[0].engine.undo_stack(&me, &scope);
    assert_eq!(undo[0], c3);
    assert!(redo.is_empty());
    let u3 = lp.peers[0].engine.undo(&c3).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("/t/tags")).unwrap(), Some(Value::Set(Default::default())));
    let u2 = lp.peers[0].engine.undo(&c2).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s("a")));
    let (undo, redo) = lp.peers[0].engine.undo_stack(&me, &scope);
    assert!(!undo.contains(&c2) && !undo.contains(&c3));
    assert_eq!(redo, vec![u2, u3]);
    // redo = undo of the undo commit
    lp.peers[0].engine.undo(&u2).unwrap().unwrap();
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
    assert!(lp.peers[0].engine.changes(&scope).iter().any(|c| c.0 == cb && c.1 == b));
    lp.peers[0].engine.undo(&cb).unwrap().unwrap();
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
        lp.peers[0].engine.undo(&c).unwrap().unwrap();
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
        lp.peers[0].engine.undo(&e).unwrap().unwrap();
        let n = lp.peers[0].engine.get_at(&t, &big, &[key("n")]).unwrap();
        assert_eq!(n, Some(Value::Map(BTreeMap::from([(s("a"), s("0")), (s("b"), s("1"))]))));
        lp.peers[0].restart(62).unwrap();
        lp.peers[0].engine.state(&t, &big).unwrap()
    };
    assert!(run(false) == run(true), "the undo in a lazily loaded session equals the whole state's");
}

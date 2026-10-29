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
    assert!(e.body_not_dropped(&c1, &t, &ak("/t/kept")));
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
    assert!(!e.body_not_dropped(&c1, &t, &ak("/t/gone")));
    assert_eq!(e.get(&t, &ak("/t/gone")).unwrap(), Some(s("final")));
    assert_eq!(e.revert(&c1).unwrap(), None);
    // every node drops it by the bound, here when it applies the kill
    sync(&mut lp, 0, 1);
    assert!(!lp.peers[1].engine.body_not_dropped(&c1, &t, &ak("/t/gone")));
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
        assert!(!lp.peers[i].engine.body_not_dropped(&c, &t, &ak("/t/brief")));
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
    assert!(lp.peers[1].engine.body_not_dropped(&secret, &t, &ak("/t/reg")));
    // a purges it
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("/t/reg") });
    let pc = lp.peers[0].commit(m).unwrap().unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&secret, &t, &ak("/t/reg")));
    sync(&mut lp, 0, 1);
    assert!(!lp.peers[1].engine.body_not_dropped(&secret, &t, &ak("/t/reg")));
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
    assert!(!lp.peers[2].engine.body_not_dropped(&secret, &t, &ak("/t/reg")));
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
    assert_eq!(lp.peers[0].engine.get(&t, &ak("/t/tags")).unwrap(), None, "exact: the set was absent before");
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
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/tags")).unwrap(), None);
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

// spec/crdt.md §4.8: two snapshots carry K's write on a kept register; Z kills it, Z2 then Z,
// and the second snapshot, taken after Z2 by a writer that saw neither, carries it again. With
// K's body dropped a recompute meets the write in both snapshots; the second copy is not dated
// again at Z2 (was: the first snapshot's last death at Z2).
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

// spec/crdt.md §4.8, §8: a snapshot's copy of a write nested in an entry another held commit
// created (a put into the key's live entry) supersedes that commit's write there; delivered the
// snapshot first, the late creator dies on arrival at the carried write, as in a recompute (was:
// a window dropped the entry's content with the creator's copies, order seed 7233).
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
    lp.deliver(1, &pa).unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.body_not_dropped(&a, &t, &k));
    assert_eq!(e.deaths(&a, &t, &k).unwrap(), Some((tb, tb)));
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(e.deaths(&a, &t, &k).unwrap(), Some((tb, tb)));
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
    assert!(e.header(&x).is_none() && e.body_not_dropped(&s1, &t, &k) && e.body_not_dropped(&y, &t, &k));
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(e.deaths(&a, &t, &k).unwrap(), Some((tx, tx)));
}

// spec/commits.md §5, spec/crdt.md §4.8 (deaths dated per node): X < Y < Z on a kept register and
// on a keep-at-most-10m one. In order X dies at Y; delivered Z first, X dies at Z (the first
// superseder this node held) and stays so when Y comes, never earlier than Y, the earliest:
// keep at least counts from Z there, and keep at most too, so within D of learning of Z. A node
// learning of them past Z's bound drops the dead bodies on arrival.
#[test]
fn deaths_dated_from_first_superseder_held_spec_commits_5() {
    for (k, name) in [(&KEPT, "/t/kept"), (&SHORT, "/t/short")] {
        let kept = name == "/t/kept";
        let mut lp = net(4, 54);
        let t = new_thing(&mut lp, 0);
        let mut ids = Vec::new();
        for v in ["one", "two", "three"] {
            ids.push(set(&mut lp, 0, t, k, v));
            lp.advance(10);
        }
        let ts: Vec<_> = ids.iter().map(|c| lp.peers[0].engine.header(c).unwrap().ts).collect();
        let a = ak(name);
        assert_eq!(lp.peers[0].engine.deaths(&ids[0], &t, &a).unwrap(), Some((ts[1], ts[1])));
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
            for x in &ids[..2] {
                assert_eq!(e.deaths(x, &t, &a).unwrap(), Some((ts[2], ts[2])), "node {to} {name}");
                let keep = e.body_keep(x, &t, &a).unwrap();
                if kept {
                    assert_eq!(keep.at_least, ts[2].wall_ms().0 + 86_400_000, "node {to}");
                } else {
                    assert_eq!(keep.at_most, Some(ts[2].wall_ms().0 + 600_000), "node {to}");
                    assert!(keep.at_most.unwrap() <= e.now().0 + 600_000, "within D of learning");
                }
            }
            assert_eq!(e.deaths(&ids[2], &t, &a).unwrap(), None);
        }
        lp.advance(3_600_000);
        for p in &pks {
            lp.deliver(3, p).unwrap();
        }
        let e = &mut lp.peers[3].engine;
        for x in &ids[..2] {
            assert_eq!(e.body_not_dropped(x, &t, &a), kept, "node 3 {name}");
        }
        assert_eq!(e.get(&t, &a).unwrap(), Some(s("three")));
    }
}

// spec/commits.md §5 (keep at most 0): a write arriving after the write that replaced it dies on
// arrival, and its body drops in the transaction applying it.
#[test]
fn keep_at_most_zero_late_body_dropped_on_arrival_spec_commits_5() {
    let mut lp = net(2, 56);
    let t = new_thing(&mut lp, 0);
    let c1 = set(&mut lp, 0, t, &GONE, "draft");
    let p1 = packages(&mut lp, 0).into_iter().find(|p| p.id == c1).unwrap();
    lp.advance(5);
    set(&mut lp, 0, t, &GONE, "final");
    for p in packages(&mut lp, 0).iter().filter(|p| p.id != c1) {
        lp.deliver(1, p).unwrap();
    }
    lp.deliver(1, &p1).unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.header(&c1).is_some() && !e.body_not_dropped(&c1, &t, &ak("/t/gone")));
    assert_eq!(e.get(&t, &ak("/t/gone")).unwrap(), Some(s("final")));
}

// spec/commits.md §5 (keep at most: a tombstone is no live write): a compaction snapshot carrying a
// keep-at-most map entry, then the entry removed. The tombstone left is keyed by the entry's dot
// but holds the remover's reset, so the snapshot has no live write: under at most 0 it drops with
// the removal; under 10m, held, it is due at the removal plus 10m with no grace; dropped live
// before the removal, it is live no more.
#[test]
fn snapshot_of_removed_entry_no_live_write_spec_commits_5() {
    use osis_crdt::PathSeg;
    for (k, name, zero, dropped) in [(&GONEMAP, "/t/gonemap", true, false), (&SHORTMAP, "/t/shortmap", false, false), (&SHORTMAP, "/t/shortmap", false, true)] {
        let mut lp = net(1, 57);
        let t = new_thing(&mut lp, 0);
        let a = ak(name);
        let mut m = Mutation::new();
        m.op(t, k, PathOp { path: vec![PathSeg::Key(s("k1"))], op: Op::Set(s("v")) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.advance(5);
        let snap = lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
        lp.advance(5);
        let e = &mut lp.peers[0].engine;
        assert!(e.body_live(&snap, &t, &a).unwrap(), "carries the entry");
        if dropped {
            e.drop_body(&snap, &t, &a).unwrap();
            assert!(!e.body_not_dropped(&snap, &t, &a) && e.body_live(&snap, &t, &a).unwrap(), "dropped live");
        }
        let mut m = Mutation::new();
        m.op(t, k, PathOp { path: Vec::new(), op: Op::Remove(s("k1")) }).unwrap();
        let rm = lp.peers[0].commit(m).unwrap().unwrap();
        let e = &mut lp.peers[0].engine;
        if zero {
            assert!(!e.body_not_dropped(&snap, &t, &a), "dropped with the removal");
        } else if dropped {
            assert!(!e.body_live(&snap, &t, &a).unwrap(), "dropped live, live no more");
        } else {
            assert!(e.body_not_dropped(&snap, &t, &a) && !e.body_live(&snap, &t, &a).unwrap(), "held, no live write");
            let ts = e.header(&rm).unwrap().ts;
            assert_eq!(e.body_keep(&snap, &t, &a).unwrap().at_most, Some(ts.wall_ms().0 + 600_000), "no grace");
        }
    }
}

// spec/commits.md §5, spec/crdt.md §4.8 (deaths dated per node, never early): random histories
// on a kept register, a kept set, a kept map and a keep-at-most-10m register by four writers
// with compaction snapshots (peer 3's writes reach node 4 only as snapshot copies, some others'
// never), delivered to node 4 in a random order with snapshots and writes dropped as they come
// and recomputes batched. Node 5 takes the same commits keeping every body (`keep_bodies`) and
// recomputes: each write's earliest superseder. Every body node 4 holds is dated no earlier:
// a body with writes of its own dies iff node 5's does, first and last no earlier; a snapshot's
// last death no earlier. Seeds: OSIS_STRAYS_START, OSIS_STRAYS_SEEDS.
#[test]
fn deaths_never_early_random_spec_commits_5() {
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_STRAYS_START", "OSIS_STRAYS_SEEDS", 0..24);
    // every failing seed is reported
    let t0 = std::time::Instant::now();
    let failed: Vec<u64> = seeds.range.clone().filter(|&seed| std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dating_history(seed))).is_err()).collect();
    let summary = format!("deaths_never_early_random: {seeds}, {} failing, {:.1} s", failed.len(), t0.elapsed().as_secs_f64());
    osis_base::testenv::visible(seeds.overridden, &summary);
    assert!(failed.is_empty(), "{summary}: seeds failed: {failed:?} (replay one: OSIS_STRAYS_START=<seed> OSIS_STRAYS_SEEDS=1)");
}

/// One history of `deaths_never_early_random_*`.
fn dating_history(seed: u64) {
    use osis_crdt::PathSeg;
    let mut r = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut below = |n: u64| {
        r ^= r << 13;
        r ^= r >> 7;
        r ^= r << 17;
        r % n
    };
    let mut lp = net(6, 1000 + seed);
    lp.peers[5].engine.keep_bodies(true);
    let t = new_thing(&mut lp, 0);
    for i in 1..4 {
        let p = lp.peers[i].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, p, Some(edge(Role::Write)), None);
    }
    for i in 1..5 {
        sync(&mut lp, 0, i);
    }
    let aks = [ak("/t/kept"), ak("/t/keptset"), ak("/t/map"), ak("/t/short")];
    let (mut writes, mut snaps) = (Vec::new(), Vec::new());
    for _ in 0..28 {
        let x = below(100);
        let i = below(4) as usize;
        if x < 55 {
            let v = format!("v{}", below(3));
            let mut m = Mutation::new();
            match below(4) {
                0 => {
                    m.set(t, &KEPT, &s(&v)).unwrap();
                }
                1 => {
                    m.op(t, &KEPTSET, PathOp { path: Vec::new(), op: if below(3) == 0 { Op::Remove(s(&v)) } else { Op::Add(s(&v)) } }).unwrap();
                }
                2 => {
                    let keep = osis_schema::Retention { by: osis_schema::PurgeBy::Writer, at_least: osis_schema::Bound { abs: None, rel: Some(3_600_000) }, at_most: osis_schema::Bound::default() };
                    m.retention(t, &MAP, keep).unwrap();
                    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s(&v))], op: Op::Set(item("e", below(9) as i64)) }).unwrap();
                }
                _ => {
                    m.set(t, &SHORT, &s(&v)).unwrap();
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
            let a = below(aks.len() as u64) as usize;
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
    let held: Vec<_> = all.iter().filter(|p| seen.insert(p.id) && !withheld.contains(&p.id)).cloned().collect();
    for p in &held {
        let _ = lp.deliver(5, p);
    }
    // a recompute plays a carried write whose own commit is not held at its snapshot: node 5
    // takes those commits too (each writes one aspect), so it plays every write at its own `ts`
    let carried: std::collections::BTreeSet<(osis_base::Tid, osis_base::Ak, osis_crdt::Dot)> = aks.iter().flat_map(|a| lp.peers[5].engine.carried_dots(&t, a).into_iter().map(|d| (t, a.clone(), d))).collect();
    let header = |lp: &osis_node::local_peer::LocalPeer, c: &osis_base::CommitId| (0..4).find_map(|i| lp.peers[i].engine.header(c));
    let extra: Vec<_> = all.iter().filter(|p| withheld.contains(&p.id) && header(&lp, &p.id).is_some_and(|h| crate::common::owns_carried(&h, &p.id, &carried))).cloned().collect();
    for p in &extra {
        let _ = lp.deliver(5, p);
    }
    let mut all = held;
    all.retain(|p| lp.peers[4].engine.header(&p.id).is_none());
    let mode = below(3);
    if mode != 1 {
        for i in (1..all.len()).rev() {
            all.swap(i, below(i as u64 + 1) as usize);
        }
        if mode == 2 {
            // snapshots first: they drop before any body older than them arrives
            all.sort_by_key(|p| !snaps.iter().any(|x| x.0 == p.id));
        }
    } else {
        // newest first, roughly: superseders drop before older bodies arrive
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
            && e.body_not_dropped(&c, &t, &aks[a])
        {
            e.drop_body(&c, &t, &aks[a]).unwrap();
        }
        if below(5) == 0
            && let Some(&(c, a)) = snaps.get(below(snaps.len().max(1) as u64) as usize)
            && e.body_not_dropped(&c, &t, &aks[a])
        {
            e.drop_body(&c, &t, &aks[a]).unwrap();
        }
        if below(12) == 0
            && let Some(&(_, c)) = writes.get(below(writes.len() as u64) as usize)
        {
            for a in &aks {
                if e.body_not_dropped(&c, &t, a) {
                    e.drop_body(&c, &t, a).unwrap();
                }
            }
        }
    }
    lp.peers[4].engine.defer_deaths(false).unwrap();
    for a in &aks {
        lp.peers[5].engine.replay_deaths(&t, a).unwrap();
    }
    let ids: Vec<(osis_base::CommitId, bool)> = writes.iter().map(|x| (x.1, false)).chain(snaps.iter().map(|x| (x.0, true))).filter(|(c, _)| lp.peers[4].engine.header(c).is_some()).collect();
    for a in &aks {
        for (c, snap) in &ids {
            if !lp.peers[4].engine.body_not_dropped(c, &t, a) {
                continue;
            }
            let x = lp.peers[4].engine.deaths(c, &t, a).unwrap();
            let y = lp.peers[5].engine.deaths(c, &t, a).unwrap();
            // a snapshot's writes die for it after its `ts`; node 5's recompute dates none whose
            // earliest superseder is before it, so a death node 4 met later has no counterpart
            let after = |x: (osis_base::Ts, osis_base::Ts)| lp.peers[4].engine.header(c).is_some_and(|h| x.0 > h.ts);
            let ok = match (x, y, snap) {
                (Some(x), Some(y), false) => x.0 >= y.0 && x.1 >= y.1,
                (None, None, _) => true,
                (Some(x), None, true) => after(x),
                (Some(x), Some(y), true) => after(x) && x.1 >= y.1,
                _ => false,
            };
            assert!(ok, "seed {seed} {a:?} {c:?}: here {x:?}, earliest superseders {y:?}");
        }
    }
}

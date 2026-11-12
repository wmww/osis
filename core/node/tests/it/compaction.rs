#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The compaction trigger on durable data (spec/sync.md §7 Trigger; spec/commits.md §5 Covered,
//! Kept while live): bodies held stay O(1) per aspect whatever was written, kept history is never
//! compacted away, every holder reads alike, and undo works within kept history.

use crate::net::*;
use osis_base::{Ak, CommitId, LabelId, Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_schema::RawKey;
use osis_node::sync::EntryKind;

fn map_ak() -> Ak {
    Ak::new(GONEMAP.ak()).unwrap()
}

/// Node `n` puts `k` -> `v` in `t`'s map, a commit of its own.
fn put(net: &mut Net, n: usize, t: Tid, k: &str, v: &str) -> CommitId {
    let mut m = Mutation::new();
    m.op(t, &GONEMAP, PathOp { path: vec![PathSeg::Key(s(k))], op: Op::Set(s(v)) }).unwrap();
    net.engine(n).commit(m).unwrap().unwrap()
}

/// Puts keys `0..n` apart (each its own commit), syncing every ten.
fn put_apart(net: &mut Net, w: usize, t: Tid, n: usize) -> Vec<CommitId> {
    let mut out = Vec::new();
    for i in 0..n {
        out.push(put(net, w, t, &format!("k{i}"), "v"));
        if i % 10 == 9 {
            net.run();
        }
    }
    net.run();
    out
}

/// Node `n`'s held bodies on `(t, map)`: (plain deltas, snapshots).
fn held(net: &mut Net, n: usize, t: Tid) -> (usize, usize) {
    let k = (t, map_ak());
    let e = net.engine(n);
    let on: Vec<CommitId> = e.core.durable_on(&k).filter(|c| e.body_not_dropped(c, &k.0, &k.1)).collect();
    let snaps = on.iter().filter(|c| e.header(c).is_some_and(|h| h.kind.is_compaction())).count();
    (on.len() - snaps, snaps)
}

/// Entries the host holds under `l` of commits with a part on `(t, map)`, as node `n` names them.
fn at_host(net: &mut Net, host: usize, n: usize, l: &LabelId, t: Tid) -> usize {
    let ids = net.host_ids(host, l);
    let ak = map_ak();
    let entries = net.sync(n).entries(l);
    entries
        .into_iter()
        .filter(|(id, k)| ids.contains(id) && matches!(k, EntryKind::Commit { commit, .. } if net.engine(n).header(commit).is_some_and(|h| h.aspects.iter().any(|a| a.tid == t && a.ak == ak))))
        .count()
}

fn map_of(net: &mut Net, n: usize, t: Tid) -> Option<Value> {
    net.engine(n).get(&t, &map_ak()).unwrap()
}

/// What `n` keys written apart leave held: at the writer, at a reader, at the host, and at a
/// node that joins once the originals are gone there; every one reads the writer's map.
fn written_apart(n: usize) -> [(usize, usize); 4] {
    let (mut net, host, [a, r, late], _g, [t]) = hosted::<3, 1>(&[(1, Role::Read), (2, Role::Read)], ["x"], true);
    net.blocked.insert((late, host));
    put_apart(&mut net, a, t, n);
    net.advance(10_000);
    net.run();
    let l = net.label(a);
    let host_entries = at_host(&mut net, host, a, &l, t);
    net.blocked.clear();
    net.advance(10_000);
    net.run();
    let want = map_of(&mut net, a, t);
    let Some(Value::Map(m)) = &want else { panic!("no map") };
    assert_eq!(m.len(), n);
    for x in [r, late] {
        assert_eq!(map_of(&mut net, x, t), want, "node {x} reads the writer's map");
    }
    [held(&mut net, a, t), held(&mut net, r, t), (host_entries, 0), held(&mut net, late, t)]
}

// spec/sync.md §7 Trigger, spec/commits.md §5 Kept while live: on an aspect no setting keeps, a map
// whose keys are each written apart compacts: its writer, a reader and the host hold a bounded
// number of bodies at n and 10n keys (not one per key), and a node that never received the
// originals reads the same map from the snapshot.
#[test]
fn map_written_apart_holds_bounded_bodies_spec_sync_7() {
    let small = written_apart(20);
    let large = written_apart(200);
    println!("bodies held (deltas, snapshots) at writer, reader, host, late joiner: n=20 {small:?}, n=200 {large:?}");
    for (at, (s, l)) in ["writer", "reader", "host", "late joiner"].iter().zip(small.iter().zip(&large)) {
        assert!(l.0 + l.1 <= 8 && s.0 + s.1 <= 8, "{at}: {s:?} at 20 keys, {l:?} at 200");
    }
}

// spec/crdt.md §8 (Frontiers), spec/commits.md §5 Forgetting, spec/sync.md §7 Trigger: commits a
// writer forgot under its own covers leave its session's counters with a hole no held commit
// fills, yet its later writes keep compacting. On a map whose commits are forgettable (default
// retention): whole replaces its own replaces cover, then keys put apart, each compaction
// snapshot forgotten under the next. The writer holds a bounded number of bodies at n and 10n
// puts, and keeps a bounded number of commits once tombstones age out.
#[test]
fn writes_after_forgotten_ones_compact_spec_crdt_8() {
    let run = |n: usize| {
        let (mut net, _h, [a, r], _g, [t]) = hosted::<2, 1>(&[(1, Role::Read)], ["x"], true);
        let big = Ak::new(BIG.ak()).unwrap();
        for i in 0..4 {
            let mut m = Mutation::new();
            m.op(t, &BIG, PathOp { path: vec![], op: Op::Replace(Value::Map(Default::default())) }).unwrap();
            m.op(t, &BIG, PathOp { path: vec![PathSeg::Key(s(&format!("r{i}")))], op: Op::Set(s("v")) }).unwrap();
            net.engine(a).commit(m).unwrap().unwrap();
            net.advance(1_000);
            net.run();
        }
        for i in 0..n {
            let mut m = Mutation::new();
            m.op(t, &BIG, PathOp { path: vec![PathSeg::Key(s(&format!("k{i}")))], op: Op::Set(s("v")) }).unwrap();
            net.engine(a).commit(m).unwrap().unwrap();
            net.advance(1_000);
            net.run();
        }
        // deletes at the host settle and their tombstones age out (spec/commits.md §5 Forgetting)
        net.advance(osis_base::format::TOMBSTONE_LIFETIME_MS + 60_000);
        net.run();
        net.advance(osis_base::format::TOMBSTONE_LIFETIME_MS + 60_000);
        net.run();
        let want = net.engine(a).get(&t, &big).unwrap();
        let Some(Value::Map(m)) = &want else { panic!("no map") };
        assert_eq!(m.len(), n + 1);
        assert_eq!(net.engine(r).get(&t, &big).unwrap(), want, "the reader reads the writer's map");
        (net.engine(a).held_bodies(&t, &big), net.engine(a).local_census().unwrap().get("c/").map_or(0, |x| x.0))
    };
    let (small, large) = (run(12), run(120));
    assert!(large.0 <= 4 && small.0 <= 4, "bodies held: {small:?} at 12 puts, {large:?} at 120");
    // beside the bodies held: the commits whose bodies are gone stay as many
    assert!(large.1 - large.0 <= small.1 - small.0, "commits kept grew: {small:?} at 12 puts, {large:?} at 120");
}

// spec/commits.md §5 Kept while live, Keep bounds: under a keep-for-D setting the live puts are
// kept history, so the trigger compacts none of them (and writes no snapshot over them: nothing it
// would drop), and a replaced one stays to its bound; past it the replaced bodies compact away and
// every live one stays.
#[test]
fn kept_history_never_compacted_spec_commits_5() {
    let (mut net, host, [a, r], _g, [t]) = hosted::<2, 1>(&[(1, Role::Read)], ["x"], true);
    net.keep(a, t, &[(GONEMAP.ak(), crate::common::DAY)]);
    net.run();
    let live = put_apart(&mut net, a, t, 30);
    // overwrite ten keys: their first puts are replaced, in history for a day
    let mut replaced = Vec::new();
    for (i, c) in live.iter().take(10).enumerate() {
        put(&mut net, a, t, &format!("k{i}"), "w");
        replaced.push(*c);
    }
    net.run();
    let l = net.label(a);
    for n in [a, r] {
        assert_eq!(held(&mut net, n, t), (40, 0), "node {n}: every body kept, no snapshot");
    }
    assert_eq!(at_host(&mut net, host, a, &l, t), 40);
    net.advance(2 * 86_400_000);
    net.run();
    put(&mut net, a, t, "late", "v");
    net.run();
    let k = map_ak();
    for n in [a, r] {
        let e = net.engine(n);
        assert!(live.iter().skip(10).all(|c| e.body_not_dropped(c, &t, &k)), "node {n}: every live put kept");
        assert!(replaced.iter().all(|c| !e.body_not_dropped(c, &t, &k)), "node {n}: the replaced ones went past their bound");
    }
    assert_eq!(map_of(&mut net, r, t), map_of(&mut net, a, t));
}

// spec/commits.md §7 Kept history only, §5 Kept while live: undo of a live put works for as long
// as its aspect keeps it, however much was written beside it; where no setting keeps the aspect
// the trigger compacts it, and its undo is refused (no history promised), never wrong.
#[test]
fn undo_within_kept_history_spec_commits_7() {
    let (mut net, _host, [a, r], _g, [t, u]) = hosted::<2, 2>(&[(1, Role::Read)], ["x", "y"], true);
    net.keep(a, t, &[(GONEMAP.ak(), crate::common::DAY)]);
    net.run();
    let first = put_apart(&mut net, a, t, 30)[0];
    let me = net.tid(a);
    net.engine(a).revert_commit(first, me).unwrap();
    net.run();
    for n in [a, r] {
        let Some(Value::Map(m)) = map_of(&mut net, n, t) else { panic!() };
        assert!(!m.contains_key(&s("k0")) && m.len() == 29, "node {n}: the first put undone");
    }
    // no setting on `u`: its first put compacted away, its undo refused
    let first = put_apart(&mut net, a, u, 30)[0];
    assert!(!net.engine(a).body_not_dropped(&first, &u, &map_ak()) || net.engine(a).header(&first).is_none(), "compacted");
    assert!(matches!(net.engine(a).revert_commit(first, me), Ok(osis_node::ephemeral::Reverted::ContentGone)));
    assert_eq!(map_of(&mut net, r, u), map_of(&mut net, a, u));
}

// spec/sync.md §7 (A snapshot turning invalid), spec/permissions.md §5.2: writer b puts y and
// compacts it under its own snapshot S while admin a is away; past `MAX_DRIFT` b deletes y at the
// host (and, `forgotten`, forgets y once its tombstone ages out). a, holding y but never S,
// demotes b: S falls, y stays valid (the frontier lists it). Both read y again: a holds y
// uncovered and places it again, and b takes it whether it still knew y or not.
fn fallen_own_snapshot_gets_back(forgotten: bool) {
    let (mut net, host, [a, b], g, [t]) = hosted::<2, 1>(&[(1, Role::Write)], ["x"], true);
    let y = put(&mut net, b, t, "y", "v");
    net.run();
    assert!(map_of(&mut net, a, t).is_some());
    net.set_online(a, false);
    net.advance(15_000);
    let acts = net.sync(b).compact_now(&t, &map_ak()).unwrap();
    net.actions(b, acts);
    net.run();
    net.advance(osis_base::format::MAX_DRIFT_MS + 60_000);
    net.run();
    let l = net.label(b);
    assert_eq!(at_host(&mut net, host, b, &l, t), 1, "y deleted at the host, S there");
    if forgotten {
        net.advance(osis_base::format::TOMBSTONE_LIFETIME_MS + 60_000);
        net.run();
        assert!(net.engine(b).header(&y).is_none(), "b forgot y");
    }
    let want = map_of(&mut net, a, t);
    let tb = net.tid(b);
    let edge = osis_schema::core_types::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let d = osis_node::flows::Demotion { holder: tb, new: Some(edge), retain: None };
    let done = net.engine(a).demote(&g, &d).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.set_online(a, true);
    net.run();
    net.advance(15_000);
    net.run();
    assert_eq!(map_of(&mut net, a, t), want, "a reads y");
    assert_eq!(map_of(&mut net, b, t), want, "b got y back");
}

#[test]
fn fallen_own_snapshot_gets_back_known_spec_sync_7() {
    fallen_own_snapshot_gets_back(false);
}

#[test]
fn fallen_own_snapshot_gets_back_forgotten_spec_sync_7() {
    fallen_own_snapshot_gets_back(true);
}

// spec/sync.md §7 (A snapshot turning invalid): as above (y known still at b), then the host is
// wiped: a, back with the demotion, places y there again under its old entry, which b deleted
// under S. S falls at b: its own tombstone of that entry no longer stands, so b fetches y.
#[test]
fn fallen_own_snapshot_lifts_own_tombstone_spec_sync_7() {
    let (mut net, host, [a, b], g, [t]) = hosted::<2, 1>(&[(1, Role::Write)], ["x"], true);
    let y = put(&mut net, b, t, "y", "v");
    net.run();
    let want = map_of(&mut net, a, t);
    assert!(want.is_some());
    net.set_online(a, false);
    net.advance(15_000);
    let acts = net.sync(b).compact_now(&t, &map_ak()).unwrap();
    net.actions(b, acts);
    net.run();
    net.advance(osis_base::format::MAX_DRIFT_MS + 60_000);
    net.run();
    let l = net.label(b);
    let of_y = |net: &mut Net, n: usize| net.sync(n).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == y)).map(|(id, _)| id).collect::<Vec<_>>();
    assert!(of_y(&mut net, b).is_empty(), "b deleted y's entry");
    net.set_online(b, false);
    net.wipe_host(host);
    let tb = net.tid(b);
    let edge = osis_schema::core_types::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let d = osis_node::flows::Demotion { holder: tb, new: Some(edge), retain: None };
    let done = net.engine(a).demote(&g, &d).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.set_online(a, true);
    net.run();
    let placed = of_y(&mut net, a);
    assert!(net.host_ids(host, &l).iter().any(|id| placed.contains(id)), "a placed y again");
    net.set_online(b, true);
    net.run();
    net.advance(15_000);
    net.run();
    assert_eq!(map_of(&mut net, b, t), want, "b got y back");
}

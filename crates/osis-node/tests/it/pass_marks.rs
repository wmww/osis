#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! What a pass judges again after a change (spec/sync.md §6, §7; spec/requirements.md, Scale):
//! the engine marks the commits whose parts, validity or deaths changed, not every commit on
//! their aspect, and an unchanged closure is reused.

use crate::net;
use net::*;
use osis_core::{CommitId, LabelId, Role, Tid, Value};
use osis_node::Mutation;
use osis_node::sync::EntryKind;

/// Sets key `k` of map aspect `asp` of `t` to `v` at node `n`, one commit.
fn put_key(net: &mut Net, n: usize, t: Tid, asp: &osis_schema::Aspect<Value>, k: &str, v: &str) -> CommitId {
    let mut m = Mutation::new();
    m.op(t, asp, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: osis_crdt::Op::Set(s(v)) }).unwrap();
    net.engine(n).commit(m).unwrap().unwrap()
}

/// Server entries of commit `c` under `l`, as node `n` knows them.
fn at_server(net: &mut Net, n: usize, sv: usize, l: &LabelId, c: &CommitId) -> usize {
    let ids = net.server_ids(sv, l);
    net.sync(n).entries(l).into_iter().filter(|(id, k)| ids.contains(id) && matches!(k, EntryKind::Commit { commit, .. } if commit == c)).count()
}

/// Entries of commit `c` node `n` knows under `l`.
fn known(net: &mut Net, n: usize, l: &LabelId, c: &CommitId) -> usize {
    net.sync(n).entries(l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c)).count()
}

// spec/sync.md §5 (expiry), §6: a commit expiring is judged again (its entry goes), the live
// commits of its aspect are not.
#[test]
fn expiry_judges_only_the_expired_commit_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Read)], &[sv]);
    let u = net.item(a, g, g, "u");
    let x = put_key(&mut net, a, u, &BRIEFMAP, "first", "v");
    net.run();
    net.advance(1_800_000);
    let live: Vec<CommitId> = (0..6).map(|i| put_key(&mut net, a, u, &BRIEFMAP, &format!("k{i}"), "v")).collect();
    net.run();
    net.advance(61_000);
    let l = net.label(a);
    assert_eq!(known(&mut net, a, &l, &x), 1);
    let s0 = net.sync(a).pass_stats();
    net.advance(1_800_000);
    let s1 = net.sync(a).pass_stats();
    assert_eq!(known(&mut net, a, &l, &x), 0, "the expired commit was judged: its entry is gone");
    assert!(live.iter().all(|c| at_server(&mut net, a, sv, &l, c) == 1), "the live ones stay");
    assert!(s1.passes > s0.passes);
    assert!(s1.bodies - s0.bodies < 6, "the aspect's live bodies are not judged again: {s0:?} -> {s1:?}");
}

// spec/commits.md §5 (keep at most: a body whose writes all died goes at its bound, by a timed
// delete, spec/sync.md §5), §6: a write re-judges the keep-at-most bodies it killed, not every
// live one of the aspect (bodies holding a map entry stay live, waiting).
#[test]
fn keep_at_most_write_judges_the_bodies_it_killed_spec_commits_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    let t = net.item(a, g, g, "t");
    let live: Vec<CommitId> = (0..6).map(|i| put_key(&mut net, a, t, &SHORTMAP, &format!("k{i}"), "v")).collect();
    // writes only k0's value: dead once that is overwritten
    let over = put_key(&mut net, a, t, &SHORTMAP, "k0", "w");
    net.run();
    net.advance(61_000);
    let l = net.label(a);
    let s0 = net.sync(a).pass_stats();
    put_key(&mut net, a, t, &SHORTMAP, "k0", "x");
    net.run();
    let s1 = net.sync(a).pass_stats();
    assert!(s1.passes > s0.passes);
    assert!(s1.bodies - s0.bodies < 6, "the live bodies are not judged again: {s0:?} -> {s1:?}");
    // past the killed body's bound (its death plus 10 min): its timed delete went up
    net.set_online(a, false);
    net.advance(600_000 + 1_000);
    assert_eq!(at_server(&mut net, a, sv, &l, &over), 0, "the killed body was judged: deleted at its bound");
    assert!(live.iter().all(|c| at_server(&mut net, a, sv, &l, c) == 1), "the live ones stay");
}

// spec/sync.md §3 (closure), §6: a pass reuses an unchanged closure; a thing entering it is
// judged (its commits go up).
#[test]
fn closure_reused_until_it_changes_spec_sync_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    let t = net.item(a, g, g, "t");
    net.run();
    net.advance(61_000);
    let l = net.label(a);
    let s0 = net.sync(a).pass_stats();
    let c = net.write(a, t, "v2");
    net.run();
    let s1 = net.sync(a).pass_stats();
    assert!(s1.passes > s0.passes);
    assert_eq!(at_server(&mut net, a, sv, &l, &c), 1);
    assert_eq!(s1.closures, s0.closures, "an unchanged closure is not walked");
    let u = net.item(a, g, g, "u");
    net.run();
    let s2 = net.sync(a).pass_stats();
    assert!(s2.closures > s1.closures, "a changed one is");
    let c = net.write(a, u, "u2");
    net.run();
    assert_eq!(at_server(&mut net, a, sv, &l, &c), 1, "the new thing's commits go up");
}

/// Commits one root op on map aspect `asp` of `t` at node `n`.
fn map_op(net: &mut Net, n: usize, t: Tid, asp: &osis_schema::Aspect<Value>, op: osis_crdt::Op) -> CommitId {
    let mut m = Mutation::new();
    m.op(t, asp, osis_crdt::PathOp { path: Vec::new(), op }).unwrap();
    net.engine(n).commit(m).unwrap().unwrap()
}

// spec/commits.md §5 (keep at most: a body with no live write goes at its bound by a timed
// delete, spec/sync.md §5): a body whose entry was removed (dead, its dot still held by the
// tombstone) loses its last held dot when the map is reset; that write kills nothing new, yet
// the body must be judged again.
#[test]
fn keep_at_most_reset_after_removal_spec_commits_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    let t = net.item(a, g, g, "t");
    let b = put_key(&mut net, a, t, &SHORTMAP, "k1", "v");
    net.run();
    net.advance(61_000);
    map_op(&mut net, a, t, &SHORTMAP, osis_crdt::Op::Remove(s("k1")));
    net.run();
    net.advance(61_000);
    let ak = osis_core::Ak::new(osis_schema::AspectKey::ak(&SHORTMAP)).unwrap();
    assert!(net.engine(a).deaths(&b, &t, &ak).unwrap().is_some() && net.engine(a).body_live(&b, &t, &ak).unwrap(), "dead, its dot held");
    map_op(&mut net, a, t, &SHORTMAP, osis_crdt::Op::RemoveAspect);
    net.run();
    assert!(!net.engine(a).body_live(&b, &t, &ak).unwrap());
    let l = net.label(a);
    assert_eq!(at_server(&mut net, a, sv, &l, &b), 1);
    // past the removal plus 10 min (no grace: no live write): the timed delete went up
    net.set_online(a, false);
    net.advance(600_000);
    assert_eq!(at_server(&mut net, a, sv, &l, &b), 0, "the body without a live write was deleted at its bound");
}

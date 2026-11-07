#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! What a pass judges again after a change (spec/sync.md §6, §7; spec/requirements.md, Scale):
//! the engine marks the commits whose parts, validity or deaths changed, not every commit on
//! their aspect, and an unchanged closure is reused.

use crate::net;
use net::*;
use osis_base::{CommitId, LabelId, Role, Tid, Value};
use osis_node::Mutation;
use osis_node::sync::EntryKind;

/// Sets key `k` of map aspect `asp` of `t` to `v` at node `n`, one commit.
fn put_key(net: &mut Net, n: usize, t: Tid, asp: &osis_schema::Aspect<Value>, k: &str, v: &str) -> CommitId {
    let mut m = Mutation::new();
    m.op(t, asp, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: osis_crdt::Op::Set(s(v)) }).unwrap();
    net.engine(n).commit(m).unwrap().unwrap()
}

/// Host entries of commit `c` under `l`, as node `n` knows them.
fn at_host(net: &mut Net, n: usize, host: usize, l: &LabelId, c: &CommitId) -> usize {
    let ids = net.host_ids(host, l);
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Read)], &[host]);
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
    assert!(live.iter().all(|c| at_host(&mut net, a, host, &l, c) == 1), "the live ones stay");
    assert!(s1.passes > s0.passes);
    assert!(s1.bodies - s0.bodies < 6, "the aspect's live bodies are not judged again: {s0:?} -> {s1:?}");
}

// spec/sync.md §3 (closure), §6: a pass reuses an unchanged closure; a thing entering it is
// judged (its commits go up).
#[test]
fn closure_reused_until_it_changes_spec_sync_3() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
    let t = net.item(a, g, g, "t");
    net.run();
    net.advance(61_000);
    let l = net.label(a);
    let s0 = net.sync(a).pass_stats();
    let c = net.write(a, t, "v2");
    net.run();
    let s1 = net.sync(a).pass_stats();
    assert!(s1.passes > s0.passes);
    assert_eq!(at_host(&mut net, a, host, &l, &c), 1);
    let u = net.item(a, g, g, "u");
    net.run();
    let c = net.write(a, u, "u2");
    net.run();
    assert_eq!(at_host(&mut net, a, host, &l, &c), 1, "the new thing's commits go up");
}

/// Commits one root op on map aspect `asp` of `t` at node `n`.
fn map_op(net: &mut Net, n: usize, t: Tid, asp: &osis_schema::Aspect<Value>, op: osis_crdt::Op) -> CommitId {
    let mut m = Mutation::new();
    m.op(t, asp, osis_crdt::PathOp { path: Vec::new(), op }).unwrap();
    net.engine(n).commit(m).unwrap().unwrap()
}

// spec/commits.md §5 (purge on replace: a body with no live write goes with the kill, here and at
// hosts in the same sync): a body whose entry was removed is dead with no live write (the
// tombstone keyed by its dot holds the remover's reset, not its creation), so no grace.
#[test]
fn purge_on_replace_removed_entry_no_live_write_spec_commits_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
    let t = net.item(a, g, g, "t");
    let b = put_key(&mut net, a, t, &GONEMAP, "k1", "v");
    net.run();
    net.advance(61_000);
    let l = net.label(a);
    assert_eq!(at_host(&mut net, a, host, &l, &b), 1);
    map_op(&mut net, a, t, &GONEMAP, osis_crdt::Op::Remove(s("k1")));
    net.run();
    let ak = osis_base::Ak::new(osis_schema::RawKey::ak(&GONEMAP)).unwrap();
    assert!(!net.engine(a).body_not_dropped(&b, &t, &ak) && !net.engine(a).body_live(&b, &t, &ak).unwrap(), "dropped with the removal, no live write");
    assert_eq!(at_host(&mut net, a, host, &l, &b), 0, "the body without a live write was deleted in the same sync");
}

// spec/sync.md §6: a `nobody` body with no keep bound is must-hold for good, but nothing is due for
// it: passes do not judge it again.
#[test]
fn nobody_bodies_not_judged_again_spec_sync_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let tags = |i: u32| format!("v{i}");
    for i in 0..20 {
        let mut m = Mutation::new();
        m.retention(t, &REG, crate::common::purgeable_by(osis_base::PurgeBy::Nobody)).unwrap();
        m.set(t, &REG, &s(&tags(i))).unwrap();
        net.engine(a).commit(m).unwrap();
        net.run();
    }
    net.advance(61_000);
    net.run();
    let s0 = net.sync(a).pass_stats();
    net.advance(61_000);
    let t2 = net.item(a, g, g, "other");
    net.write(a, t2, "more");
    net.run();
    let s1 = net.sync(a).pass_stats();
    assert!(s1.passes > s0.passes);
    assert!(s1.bodies - s0.bodies < 15, "the kept bodies are not judged again: {s0:?} -> {s1:?}");
}

// spec/requirements.md Scale (a body's judgment costs O(its parts)), spec/sync.md §6, spec/commits.md
// §5: one body of many parts kept at least is judged with one death read per part, at its author
// and a reader, written and then wholly replaced (each part's keep, or each killed part's keep at
// most, read over the whole body would cost parts²).
#[test]
fn body_judged_once_per_body_spec_requirements_scale() {
    use osis_schema::{History, PurgeBy, Retention};
    let n = 120u64;
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let r = Retention { by: PurgeBy::Writer, history: Some(History::Keep { until: None, after: Some(86_400_000) }) };
    for v in ["v", "w"] {
        let mut m = Mutation::new();
        for i in 0..n {
            let k = osis_base::Ak::new(format!("u:k{i}.0")).unwrap();
            m.retention(t, &k, r).unwrap();
            m.set(t, &k, &s(v)).unwrap();
        }
        let before = [net.engine(a).death_reads(), net.engine(b).death_reads()];
        let c = net.engine(a).commit(m).unwrap().unwrap();
        net.run();
        net.advance(61_000);
        assert!(net.engine(b).header(&c).is_some(), "the reader holds the commit");
        for (x, r0) in [a, b].into_iter().zip(before) {
            let reads = net.engine(x).death_reads() - r0;
            assert!(reads <= 8 * n, "{v}: node {x}: {reads} death reads for a body of {n} parts");
        }
    }
}

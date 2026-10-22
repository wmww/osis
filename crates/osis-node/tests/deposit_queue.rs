#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A non-writer's deposit of its own membership write (spec/sync.md §5): queued once, sent
//! until a server answers, also after the depositor forgot the label.

mod net;
use net::*;
use osis_core::Role;
use osis_node::sync::EntryKind;
use osis_schema::core_types as ct;

/// Node 0 admin of a group with a label, node 1 a reader with invite read, node 2 a stranger
/// node 1 knows. Returns (group, its label, node 1's invite grant of node 2).
fn invite(net: &mut Net, sv: usize) -> (osis_core::Tid, osis_core::LabelId, osis_core::CommitId, osis_node::flows::Done) {
    let g = net.group(0, &[(1, Role::Read)], &[sv]);
    let b = net.tid(1);
    let raise = ct::Edge { role: Role::Read, until: None, invite: Some(Role::Read), since: None };
    let done = net.engine(0).grant(&g, &b, &raise).unwrap();
    let acts = net.sync(0).carry_out(done).unwrap();
    net.actions(0, acts);
    net.run();
    net.pair(2, 1);
    let l = net.engine(0).group_labels(&g).unwrap()[0].id;
    let c = net.tid(2);
    let grant = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
    let done = net.engine(1).grant(&g, &c, &grant).unwrap();
    let commit = *done.commits.last().unwrap();
    (g, l, commit, done)
}

/// Records of the server's log of `l`: (added, deleted).
fn log(net: &Net, sv: usize, l: &osis_core::LabelId) -> (usize, usize) {
    use osis_proto::LabelStore;
    let recs = net.servers[sv].hub.store().log_after(l, 0, 1 << 20).ok().flatten().unwrap_or_default();
    let del = recs.iter().filter(|(_, r)| matches!(r, osis_proto::LogRecord::Deleted(_))).count();
    (recs.len() - del, del)
}

fn copies(net: &mut Net, n: usize, l: &osis_core::LabelId, c: &osis_core::CommitId) -> usize {
    net.sync(n).entries(l).iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c)).count()
}

// spec/sync.md §5: an invite grant by a reader goes under the label as one deposit: its
// author records the queued deposit as its entry at once, so no pass places a second
// encryption while the server has not answered.
#[test]
fn invite_grant_deposited_once_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    for i in 0..3 {
        net.node(10 + i, &[sv]);
    }
    let (_, l, c, done) = invite(&mut net, sv);
    let before = log(&net, sv, &l);
    let acts = net.sync(1).carry_out(done).unwrap();
    net.actions(1, acts);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    let after = log(&net, sv, &l);
    assert_eq!(copies(&mut net, 0, &l, &c), 1, "one entry of the grant under the label");
    assert_eq!(after.1, before.1, "no second encryption deposited (and deleted as a duplicate)");
}

// spec/sync.md §5, spec/permissions.md §3: the deposit goes even when its author forgot the
// label before the server answered.
#[test]
fn queued_deposit_survives_forgetting_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    for i in 0..3 {
        net.node(20 + i, &[sv]);
    }
    let (g, l, c, done) = invite(&mut net, sv);
    net.set_online(1, false);
    net.sync(1).carry_out(done).unwrap();
    // node 1 loses the group before it is back online
    let b = net.tid(1);
    let d = osis_node::flows::Demotion { member: b, new: None, presync: osis_node::flows::PreSync::Synced };
    let done = net.engine(0).demote(&g, &d).unwrap();
    let acts = net.sync(0).carry_out(done).unwrap();
    net.actions(0, acts);
    net.run();
    net.pair(0, 1);
    net.sync(1).drop_lost().unwrap();
    assert!(net.sync(1).labels().iter().all(|(_, x)| x.id != l), "node 1 forgot the label");
    net.set_online(1, true);
    net.run();
    net.advance(61_000);
    assert_eq!(copies(&mut net, 0, &l, &c), 1, "the deposit reached the label");
}

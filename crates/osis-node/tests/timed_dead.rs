#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Timed deletes of bodies whose writes all died (spec/sync.md §5, §7): no carrier snapshot.

mod net;
use net::*;
use osis_node::Mutation;
use osis_node::sync::EntryKind;

// spec/sync.md §7 (a body with live writes is deleted only while another entry carries them;
// one without needs none), spec/commits.md §5: a register under a relative keep-at-most
// replaced whole goes at its bound by a timed delete sent with the replacing upload, and no
// covering snapshot is written for it.
#[test]
fn replaced_register_needs_no_carrier_spec_sync_7() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    let t = net.item(a, g, g, "x");
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("v1")).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    let l = net.label(a);
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("v2")).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    net.run();
    let snapshots = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if net.engine(a).header(commit).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot))).count();
    assert_eq!(snapshots, 0, "no carrier for a body without live writes");
    let before = net.server_ids(sv, &l).len();
    net.set_online(a, false);
    net.clock.advance(3_600_000 + 1_000);
    let now = net.now();
    net.servers[sv].hub.tick(now);
    assert_eq!(net.server_ids(sv, &l).len() + 1, before, "the replaced body went at its bound, nobody online");
}

// spec/permissions.md §5.2 (a write after a revoke's frontier is invalid, whatever the order
// it arrives in), spec/crdt.md §4.6: a member that was offline while a writer's later write
// and a backdated revoke of that writer arrived must read what an online member reads.
// (Was order-dependent: the item's `/created` reached perm after the revoke, osis-perm
// `Timeline::leaf_from`.)
#[test]
fn late_member_judges_backdated_revoke_alike_spec_permissions_5() {
    use osis_core::Role;
    use osis_node::flows::{Demotion, PreSync};
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(13, &[sv]);
    let b = net.node(14, &[sv]);
    let late = net.node(15, &[sv]);
    let on = net.node(16, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (late, Role::Read), (on, Role::Read)], &[sv]);
    net.set_online(late, false);
    let t = net.item(a, g, g, "v1");
    net.run();
    net.advance(60_000);
    let before = net.now();
    net.advance(1_000);
    net.write(b, t, "v2");
    net.run();
    net.advance(1_000);
    let bt = net.tid(b);
    net.set_online(b, false);
    let d = Demotion { member: bt, new: None, presync: PreSync::Backdated(osis_core::WallMs(before)) };
    let done = net.engine(a).demote(&g, &d).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    assert_eq!(net.read(a, t), Some(s("v1")));
    assert_eq!(net.read(on, t), Some(s("v1")), "an online member");
    net.set_online(late, true);
    net.run();
    net.advance(61_000);
    assert_eq!(net.read(late, t), Some(s("v1")), "a member offline throughout");
}

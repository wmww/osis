#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Timed deletes of bodies whose writes all died (spec/sync.md §5, §7): no carrier snapshot.

use crate::net;
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

/// Server entries of commit `c` under `l`, as node `n` knows them.
fn at_server(net: &mut Net, n: usize, sv: usize, l: &osis_base::LabelId, c: &osis_base::CommitId) -> Vec<osis_base::BlobId> {
    let ids = net.server_ids(sv, l);
    net.sync(n).entries(l).into_iter().filter(|(id, k)| ids.contains(id) && matches!(k, EntryKind::Commit { commit, .. } if commit == c)).map(|(id, _)| id).collect()
}

// spec/commits.md §5 (keep at most: a body with a live write keeps `AT_MOST_GRACE`; no
// carrier needed without one), spec/sync.md §5 (a timed delete cannot be withdrawn), §6
// (must-hold): a body whose write died gets a timed delete; a validity flip (the replacing
// writer revoked from before its write) revives the write; the server deletes the body at the
// plain bound all the same, and a right holder online uploads it again at its next resync (a
// fresh encryption): a window, not a loss. Offline, the window lasts until it next syncs; the
// revived write has no death, so the body then stays (no bound). A member offline throughout reads v1
// when it comes back (`late_member_judges_backdated_revoke_alike_*`).
#[test]
fn revived_body_uploaded_again_after_timed_delete_spec_commits_5() {
    use osis_base::Role;
    use osis_node::flows::{Demotion, PreSync};
    let gone = osis_base::Ak::new("/t/gone").unwrap();
    for online in [true, false] {
        let mut net = Net::new();
        let sv = net.add_server();
        let a = net.node(3, &[sv]);
        let b = net.node(4, &[sv]);
        let late = net.node(5, &[sv]);
        let g = net.group(a, &[(b, Role::Write), (late, Role::Read)], &[sv]);
        net.set_online(late, false);
        let t = net.item(a, g, g, "x");
        net.run();
        let l = net.label(a);
        let mut m = Mutation::new();
        m.set(t, &GONE, &s("v1")).unwrap();
        let c1 = net.engine(a).commit(m).unwrap().unwrap();
        net.run();
        net.advance(60_000);
        let before = net.now();
        net.advance(1_000);
        net.run();
        let mut m = Mutation::new();
        m.set(t, &GONE, &s("v2")).unwrap();
        net.engine(b).commit(m).unwrap();
        net.run();
        net.advance(1_000);
        assert_eq!(net.engine(a).get(&t, &gone).unwrap(), Some(s("v2")));
        let first = at_server(&mut net, a, sv, &l, &c1);
        assert_eq!(first.len(), 1, "v1's body is at the server, its delete timed");
        // b revoked from before its write: v2 is void, v1 live again at a
        let bt = net.tid(b);
        net.set_online(b, false);
        let d = Demotion { member: bt, new: None, presync: PreSync::Backdated(osis_base::WallMs(before)) };
        let done = net.engine(a).demote(&g, &d).unwrap();
        let acts = net.sync(a).carry_out(done).unwrap();
        net.actions(a, acts);
        net.run();
        assert_eq!(net.engine(a).get(&t, &gone).unwrap(), Some(s("v1")), "v1 revived");
        net.set_online(a, online);
        // past the plain bound: the server carries out the timed delete
        net.advance(3_600_000);
        net.run();
        let again = at_server(&mut net, a, sv, &l, &c1);
        assert!(!again.contains(&first[0]), "the timed delete went at the plain bound");
        if online {
            // the next resync (`resync_ms`) finds the body missing there
            let resync = net.sync(a).config().resync_ms;
            net.advance(resync);
            assert_eq!(at_server(&mut net, a, sv, &l, &c1).len(), 1, "uploaded again on the next resync");
            net.set_online(late, true);
            net.run();
            net.advance(resync);
            assert_eq!(net.engine(late).get(&t, &gone).unwrap(), Some(s("v1")), "a member offline throughout");
            continue;
        }
        assert!(again.is_empty(), "deleted while no right holder is online");
        net.set_online(a, true);
        net.run();
        assert_eq!(at_server(&mut net, a, sv, &l, &c1).len(), 1, "uploaded again on the next sync");
        // revived, v1 has no death (spec/crdt.md §4.8: only applied valid writes supersede),
        // so no keep-at-most bound: the body stays, as at a node that never saw v2 valid
        assert_eq!(net.engine(a).deaths(&c1, &t, &gone).unwrap(), None);
        net.advance(osis_base::format::AT_MOST_GRACE_MS);
        net.advance(1_000);
        assert_eq!(at_server(&mut net, a, sv, &l, &c1).len(), 1, "kept: v1 is current");
        assert!(net.engine(a).holds_body(&c1, &t, &gone));
        net.set_online(late, true);
        net.run();
        let resync = net.sync(a).config().resync_ms;
        net.advance(resync);
        assert_eq!(net.engine(late).get(&t, &gone).unwrap(), Some(s("v1")), "a member offline throughout");
    }
}

// spec/permissions.md §5.2 (a write after a revoke's frontier is invalid, whatever the order
// it arrives in), spec/crdt.md §4.6: a member that was offline while a writer's later write
// and a backdated revoke of that writer arrived must read what an online member reads.
// (Was order-dependent: the item's `/created` reached perm's walk after the revoke, and the
// walk kept no demotion for it; osis-perm `Walked::alias_leaves`.)
#[test]
fn late_member_judges_backdated_revoke_alike_spec_permissions_5() {
    use osis_base::Role;
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
    let d = Demotion { member: bt, new: None, presync: PreSync::Backdated(osis_base::WallMs(before)) };
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

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Revokes about authors seen under a label (spec/permissions.md §4): a member that syncs the
//! label and holds the revoke places it there, so verifiers judge the author's writes alike.

use crate::net;
use net::*;
use osis_base::Role;
use osis_node::flows::{Demotion, PreSync};
use osis_node::sync::EntryKind;
use osis_schema::core_types as ct;

// spec/permissions.md §4 (any member that syncs a label and holds a revoke about an author seen
// under it places it there): W writes in G through team X; X's admin B, who does not sync G,
// removes W from X; R, a member of X that syncs G through it, places that revoke under G's
// label.
#[test]
fn revoke_about_author_placed_spec_permissions_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let w = net.node(3, &[sv]);
    let r = net.node(4, &[sv]);
    let x = net.group_seeded(b, &[(w, Role::Write), (r, Role::Read)], vec![net.address(sv)], 1);
    net.pair(b, a);
    let g = net.group_seeded(a, &[], vec![net.address(sv)], 2);
    let edge = ct::Edge { role: Role::Write, until: None, invite: None, since: None, tied: false };
    let done = net.engine(a).grant(&g, &x, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.pair(a, w);
    net.pair(a, r);
    net.run();
    assert_eq!(net.engine(w).role_on(&g), Some(Role::Write));
    let t = net.item(w, g, g, "by w");
    for _ in 0..2 {
        net.advance(31_000);
    }
    assert_eq!(net.read(r, t), Some(s("by w")));
    let lg = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1.id;
    assert!(net.sync(b).labels().iter().all(|(x, _)| *x != g), "B does not sync G");
    let wt = net.tid(w);
    let done = net.engine(b).demote(&x, &Demotion { member: wt, new: None, presync: PreSync::Synced }).unwrap();
    let removal = *done.commits.first().unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert!(net.engine(r).header(&removal).is_some(), "R holds the revoke");
    let ids = net.server_ids(sv, &lg);
    let placed = net.sync(r).entries(&lg).into_iter().any(|(id, k)| ids.contains(&id) && matches!(k, EntryKind::Commit { commit, .. } if commit == removal));
    assert!(placed, "the revoke of W on X is under G's label");
    // G's admin learns of it there and rotates G: W reads nothing new
    let u = net.item(a, g, g, "after w left");
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert!(net.engine(a).header(&removal).is_some(), "the admin holds the revoke");
    assert_eq!(net.read(r, u), Some(s("after w left")));
    assert_eq!(net.read(w, u), None);
}

// spec/permissions.md §4 (exception to spec/crypto.md §4: a member that may not rotate the
// label's actor places the revoke of a departure inside a member, the write on the last actor of
// its chain, and each chain actor's newest `/keys`): G <- X1 <- X2 <- {W, R}; X2's admin B, who
// does not sync G, removes W from X2 and rotates X2 and X1 (apart); R reads G through two levels,
// may not rotate it, and places W's removal from X2 and X1's new keys under G's label; G's admin
// rotates, sealing to X1's new keyset, and W reads nothing new.
#[test]
fn nested_departure_revoke_placed_spec_permissions_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let w = net.node(3, &[sv]);
    let r = net.node(4, &[sv]);
    let x2 = net.group_seeded(b, &[(w, Role::Write), (r, Role::Read)], vec![net.address(sv)], 1);
    let x1 = net.group_seeded(b, &[], vec![net.address(sv)], 2);
    let edge = ct::Edge { role: Role::Write, until: None, invite: None, since: None, tied: false };
    let done = net.engine(b).grant(&x1, &x2, &edge).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    net.pair(b, a);
    let g = net.group_seeded(a, &[], vec![net.address(sv)], 3);
    let done = net.engine(a).grant(&g, &x1, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.pair(a, w);
    net.pair(a, r);
    net.run();
    for _ in 0..2 {
        net.advance(31_000);
    }
    assert_eq!(net.engine(w).role_on(&g), Some(Role::Write));
    assert_eq!(net.engine(r).role_on(&g), Some(Role::Read));
    let t = net.item(a, g, g, "before");
    for _ in 0..2 {
        net.advance(31_000);
    }
    assert_eq!(net.read(r, t), Some(s("before")));
    assert_eq!(net.read(w, t), Some(s("before")));
    let lg = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1.id;
    assert!(net.sync(b).labels().iter().all(|(x, _)| *x != g), "B does not sync G");
    let wt = net.tid(w);
    let done = net.engine(b).demote(&x2, &Demotion { member: wt, new: None, presync: PreSync::Synced }).unwrap();
    let removal = *done.commits.first().unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert!(net.engine(r).header(&removal).is_some(), "R holds the revoke");
    let ids = net.server_ids(sv, &lg);
    let placed = net.sync(r).entries(&lg).into_iter().any(|(id, k)| ids.contains(&id) && matches!(k, EntryKind::Commit { commit, .. } if commit == removal));
    assert!(placed, "the revoke of W on X2 is under G's label");
    let u = net.item(a, g, g, "after w left");
    for _ in 0..4 {
        net.advance(31_000);
    }
    assert!(net.engine(a).header(&removal).is_some(), "the admin holds the revoke");
    assert_eq!(net.read(r, u), Some(s("after w left")));
    assert_eq!(net.read(w, u), None, "W reads nothing written after it left");
}

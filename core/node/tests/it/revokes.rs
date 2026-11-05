#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Revokes about authors seen under a label (spec/permissions.md §4): a holder that syncs the
//! label and holds the revoke places it there, so verifiers judge the author's writes alike.

use crate::net;
use net::*;
use osis_base::Role;
use osis_node::flows::{Demotion, PreSync};
use osis_node::sync::EntryKind;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

// spec/permissions.md §4 (chain certificates: current `keys.0` of the actors on a path): W writes
// in G through team X; X's admin B, who does not sync G, removes W from X (the commit writes X's
// new keyset); R, a holder of X that syncs G through it, places it under G's label as X's current
// keys, and G's admin, finding its box to X stale, rotates: W reads nothing new.
#[test]
fn revoke_about_author_placed_spec_permissions_4() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let w = net.node(3, &[host]);
    let r = net.node(4, &[host]);
    let x = net.group_seeded(b, &[(w, Role::Write), (r, Role::Read)], vec![net.address(host)], 1);
    net.pair(b, a);
    let g = net.group_seeded(a, &[], vec![net.address(host)], 2);
    let edge = ct::Edge { role: Role::Write, until: None, invite: None, since: None, tied: None };
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
    let done = net.engine(b).demote(&x, &Demotion { holder: wt, new: None, presync: PreSync::Synced, keep: None }).unwrap();
    let removal = *done.commits.first().unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert!(net.engine(r).header(&removal).is_some(), "R holds the revoke");
    let ids = net.host_ids(host, &lg);
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

// spec/permissions.md §4 (chain certificates: current `keys.0` of the actors on a path),
// spec/crypto.md §4 (holder actors: stale): G <- X1 <- X2 <- {W, R}; X2's admin B, who does not
// sync G, removes W from X2 (rotating X2), then rotates X1 (its box to X2 stale); R reads G
// through two levels, may not rotate it, and is not held back by the stale box: it places X1's new
// keys under G's label. W, still a writer of G through X1 in its own view and in that of G's admin
// (who never learns W left X2), finds G's box to X1 stale too but holds no secret of X1's new
// keyset, so it may not rotate G (spec/crypto.md §4, Possession): it waits, and G's admin rotates.
#[test]
fn nested_departure_removed_writer_waits_spec_crypto_4() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let w = net.node(3, &[host]);
    let r = net.node(4, &[host]);
    let x2 = net.group_seeded(b, &[(w, Role::Write), (r, Role::Read)], vec![net.address(host)], 1);
    let x1 = net.group_seeded(b, &[], vec![net.address(host)], 2);
    let edge = ct::Edge { role: Role::Write, until: None, invite: None, since: None, tied: None };
    let done = net.engine(b).grant(&x1, &x2, &edge).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    net.pair(b, a);
    let g = net.group_seeded(a, &[], vec![net.address(host)], 3);
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
    let done = net.engine(b).demote(&x2, &Demotion { holder: wt, new: None, presync: PreSync::Synced, keep: None }).unwrap();
    let removal = *done.commits.first().unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert!(net.engine(r).header(&removal).is_some(), "R holds the revoke");
    // X1's new keys (B rotated X1: its box to X2 stale) reach G's label as R's chain certificate
    let ids = net.host_ids(host, &lg);
    let placed: BTreeSet<_> = net.sync(r).entries(&lg).into_iter().filter(|(id, _)| ids.contains(id)).filter_map(|(_, k)| if let EntryKind::Commit { commit, .. } = k { Some(commit) } else { None }).collect();
    let x1k = net.engine(r).current_keys(&x1);
    assert!(x1k.iter().any(|c| placed.contains(c)), "X1's current keys.0 under G's label");
    let u = net.item(a, g, g, "after w left");
    for _ in 0..4 {
        net.advance(31_000);
    }
    assert_eq!(net.read(r, u), Some(s("after w left")));
    assert_eq!(net.read(w, u), None, "W reads nothing written after it left");
}

// spec/permissions.md §4: a revoke on a thing the label's actor has no holder path from carries no keyset: W's removal from M, a stranger to G, has M's fresh deposit seed
#[test]
fn revoke_on_an_unrelated_thing_brings_no_keys() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let w = net.node(3, &[host]);
    let r = net.node(4, &[host]);
    let x = net.group_seeded(b, &[(w, Role::Write), (r, Role::Read)], vec![net.address(host)], 1);
    let m = net.group_seeded(b, &[(w, Role::Read), (r, Role::Read)], vec![net.address(host)], 3);
    net.pair(b, a);
    let g = net.group_seeded(a, &[], vec![net.address(host)], 2);
    let edge = ct::Edge { role: Role::Write, until: None, invite: None, since: None, tied: None };
    let done = net.engine(a).grant(&g, &x, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.pair(a, w);
    net.pair(a, r);
    net.run();
    let t = net.item(w, g, g, "by w");
    for _ in 0..2 {
        net.advance(31_000);
    }
    assert_eq!(net.read(r, t), Some(s("by w")));
    let lg = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1.id;
    let wt = net.tid(w);
    let done = net.engine(b).demote(&m, &Demotion { holder: wt, new: None, presync: PreSync::Synced, keep: None }).unwrap();
    let rm = *done.commits.first().unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    let done = net.engine(b).demote(&x, &Demotion { holder: wt, new: None, presync: PreSync::Synced, keep: None }).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert!(net.engine(r).header(&rm).is_some(), "R holds the revoke");
    let ids = net.host_ids(host, &lg);
    let h = net.engine(r).header(&rm).unwrap();
    let placed: Vec<Vec<(usize, usize)>> = net.sync(r).entries(&lg).into_iter().filter(|(id, _)| ids.contains(id)).filter_map(|(_, k)| match k {
        EntryKind::Commit { commit, parts, .. } if commit == rm => Some(parts),
        _ => None,
    }).collect();
    assert!(!placed.is_empty(), "the revoke is under G's label");
    assert!(placed.iter().flatten().all(|(ai, _)| h.aspects[*ai].ak.as_str() != "keys.0"), "no keyset of M");
}

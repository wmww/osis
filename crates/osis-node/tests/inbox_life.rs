#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! An inbox blob's life (spec/sync.md §3): the grantee's certificate copy, deletion of the
//! consumed blob by the inbox's admins, re-sending after `INBOX_LIFETIME`; direct packages kept
//! until the app takes them.

mod net;
use net::*;
use osis_core::format::INBOX_LIFETIME_MS;
use osis_core::{LabelId, Role, Tid};
use osis_node::Mutation;
use osis_node::sync::EntryKind;
use osis_schema::core_types as ct;

/// Alice (node `a`) and Bob (node `b`) as persons on one server; Alice holds Bob's card and a
/// group `g` with a label. Returns (net, sv, a, b, Alice's person, Bob's person, g, Bob's home).
fn alice_and_bob() -> (Net, usize, usize, usize, Tid, Tid, Tid, LabelId) {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let addr = net.address(sv);
    let (alice, done) = net.engine(a).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let (bob, done) = net.engine(b).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    net.run();
    net.pair(b, a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let g = e.new_thing(&mut m, alice.person);
    m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let (_, done) = net.engine(a).create_label(&g, &[addr]).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    let home = net.sync(b).labels().into_iter().find(|(x, _)| *x == bob.person).unwrap().1.id;
    (net, sv, a, b, alice.person, bob.person, g, home)
}

fn grant(net: &mut Net, a: usize, g: Tid, to: Tid) {
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
    let done = net.engine(a).grant(&g, &to, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
}

/// Inbox entries a node knows present at the server under `l`.
fn inbox_at(net: &mut Net, n: usize, sv: usize, l: &LabelId) -> usize {
    let ids = net.server_ids(sv, l);
    net.sync(n).entries(l).into_iter().filter(|(id, k)| matches!(k, EntryKind::Inbox(_)) && ids.contains(id)).count()
}

// spec/sync.md §3: the grantee's device places a certificate copy of the grant under its home
// label (the inbox), and the inbox's admins then delete the consumed inbox blob.
#[test]
fn consumed_inbox_blob_deleted_spec_sync_3() {
    let (mut net, sv, a, b, _, bob, g, home) = alice_and_bob();
    grant(&mut net, a, g, bob);
    let t = net.item(a, g, g, "for bob");
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.read(b, t), Some(s("for bob")));
    let ids = net.server_ids(sv, &home);
    let copies: Vec<(osis_core::BlobId, EntryKind)> = net.sync(b).entries(&home).into_iter().filter(|(id, k)| ids.contains(id) && matches!(k, EntryKind::Commit { .. })).collect();
    let grant: Vec<osis_core::CommitId> = net.engine(b).commit_ids().into_iter().filter(|c| net.engine(b).header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == g && x.ak.as_str() == "/members"))).collect();
    assert!(copies.iter().any(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if grant.contains(commit))), "the grant's copy is under Bob's home label");
    // the grant reached Bob only as an inbox blob: none is left, every entry is a commit blob
    assert_eq!(inbox_at(&mut net, b, sv, &home), 0, "the consumed inbox blob is deleted");
    let known = net.sync(b).entries(&home);
    assert!(net.server_ids(sv, &home).iter().all(|id| known.iter().any(|(x, k)| x == id && matches!(k, EntryKind::Commit { .. }))));
}

// spec/sync.md §3: an inbox blob nobody acts on expires at the server after `INBOX_LIFETIME`;
// the sender seals the commit again and re-sends it, and the member, back online, reads.
#[test]
fn unanswered_inbox_blob_resent_spec_sync_3() {
    let (mut net, sv, a, b, _, bob, g, home) = alice_and_bob();
    net.set_online(b, false);
    grant(&mut net, a, g, bob);
    let t = net.item(a, g, g, "for bob");
    net.run();
    let first = net.server_ids(sv, &home);
    net.advance(INBOX_LIFETIME_MS + 1_000);
    let now = net.server_ids(sv, &home);
    assert!(now.iter().any(|x| !first.contains(x)), "a fresh inbox blob went up");
    assert!(first.iter().any(|x| !now.contains(x)), "the first one expired");
    net.set_online(b, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).role_on(&g), Some(Role::Read));
    assert_eq!(net.read(b, t), Some(s("for bob")));
}

// spec/permissions.md §1 (pairing), spec/sync.md §2: the commits for a node over a direct
// connection stay until the app takes them, across a restart.
#[test]
fn direct_packages_survive_restart_spec_sync_2() {
    let (mut net, _, a, _, alice, _, _, _) = alice_and_bob();
    let c = net.node(3, &[]);
    net.pair(c, a);
    let ct_ = net.tid(c);
    let done = net.engine(a).pair(&alice, &ct_).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.restart(a, 11);
    let pks = net.sync(a).take_direct_for(&ct_);
    assert!(!pks.is_empty(), "kept across the restart");
    assert!(net.sync(a).take_direct_for(&ct_).is_empty(), "taken once");
}

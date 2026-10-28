#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Inbox deposits refused for now (spec/sync.md §3; notes/sync.md Limits): the grantee's inbox
//! label is not registered yet, so the server answers code 13; the sender keeps the blob and
//! deposits it again (backing off from `retry_ms`) until the label exists.

use crate::net;
use net::*;
use osis_base::Role;
use osis_node::Mutation;
use osis_schema::core_types as ct;

// spec/sync.md §3: a grant whose inbox deposit was refused (label unknown) reaches the grantee
// once its device registered the inbox label.
#[test]
fn refused_inbox_deposit_retried_spec_sync_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let addr = net.address(sv);
    // Bob's device cannot reach the server yet: his home label (his inbox) is not registered
    net.blocked.insert((b, sv));
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
    let (_, done) = net.engine(a).create_label(&g, std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
    let done = net.engine(a).grant(&g, &bob.person, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    assert!(net.sync(a).take_diagnostics().iter().any(|d| d.contains("code 13")), "refused: no inbox label yet");
    // Bob comes online: his inbox label registers; Alice deposits again after the back-off
    net.blocked.clear();
    net.advance(1_000);
    assert_ne!(net.engine(b).role_on(&g), Some(Role::Read), "not before the back-off");
    for _ in 0..3 {
        net.advance(10_000);
    }
    assert_eq!(net.engine(b).role_on(&g), Some(Role::Read));
    // spec: none (local store index, notes/node.md Open): the grant reached Bob with a late
    // `/members` part; his `node/edges` row was rewritten with the record, so a reopen from the
    // index equals a rebuild from the commit records and keeps the edge
    let e = net.engine(b);
    let held = |d: String| d.lines().filter(|l| !l.starts_with("held ")).collect::<Vec<_>>().join("\n");
    assert!(e.index_current().unwrap());
    let (perm, index, rows) = (e.perm_digest(false), held(e.index_digest()), e.edges_rows().unwrap());
    e.reload().unwrap();
    assert_eq!(e.role_on(&g), Some(Role::Read), "reopened");
    assert_eq!((e.perm_digest(false), held(e.index_digest())), (perm.clone(), index.clone()), "reopened");
    e.rebuild_index().unwrap();
    assert_eq!((e.perm_digest(false), held(e.index_digest()), e.edges_rows().unwrap()), (perm, index, rows), "rebuilt");
}

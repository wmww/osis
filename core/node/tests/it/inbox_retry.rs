#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Inbox deposits refused for now (spec/sync.md §3; notes/sync.md Limits): the grantee's inbox
//! label is not registered yet, so the host answers code 13; the sender keeps the blob and
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
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let addr = net.address(host);
    // Bob's device cannot reach the host yet: his home label (his inbox) is not registered
    net.blocked.insert((b, host));
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
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None, tied: None, keyset: None, keep: false };
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
    // `roles.0` part; his `node/edges` row was rewritten with the record, so a reopen from the
    // index equals a rebuild from the commit records and keeps the edge
    let e = net.engine(b);
    let held = |d: osis_node::engine::IndexDigest| d.without_held();
    assert!(e.index_current().unwrap());
    let (perm, index, rows) = (e.perm_digest(false), held(e.index_digest()), e.edges_rows().unwrap());
    e.reload().unwrap();
    assert_eq!(e.role_on(&g), Some(Role::Read), "reopened");
    assert_eq!((e.perm_digest(false), held(e.index_digest())), (perm.clone(), index.clone()), "reopened");
    e.rebuild_index().unwrap();
    assert_eq!((e.perm_digest(false), held(e.index_digest()), e.edges_rows().unwrap()), (perm, index, rows), "rebuilt");
}

// spec/sync.md §3: an invite naming a label its sender is registering at a connected host waits for that registration, so the invitee never finds the host without it (a new chat's first invite): at every round the blob at the inbox's host implies the label there
#[test]
fn invite_goes_after_the_labels_registration_spec_sync_3() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let addr = net.address(host);
    let (alice, done) = net.engine(a).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let (bob, done) = net.engine(b).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    net.run();
    net.pair(b, a);
    net.run();
    let inbox = net.engine(a).get_typed(&bob.person, &ct::KEYS).unwrap().unwrap().inbox.unwrap().label;
    let held = net.host_ids(host, &inbox);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let g = e.new_thing(&mut m, alice.person);
    m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let (l, done) = net.engine(a).create_label(&g, std::slice::from_ref(&addr)).unwrap();
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None, tied: None, keyset: None, keep: false };
    let mut acts = net.sync(a).carry_out(done).unwrap();
    let done = net.engine(a).grant(&g, &bob.person, &edge).unwrap();
    acts.extend(net.sync(a).carry_out(done).unwrap());
    net.actions(a, acts);
    let mut came = false;
    for _ in 0..1000 {
        net.round();
        came = net.host_ids(host, &inbox).iter().any(|b| !held.contains(b));
        assert!(!came || net.labels_at(host).contains(&l), "the invite is at the host before the label it names");
        if came {
            break;
        }
    }
    assert!(came);
    net.run();
    assert!(net.engine(b).role_on(&g).is_some() || net.sync(b).invite_requests().unwrap().len() == 1);
}

// spec/sync.md §3: a host of the label silent to its Open holds no invite back while another connected host has it
#[test]
fn silent_host_of_the_label_holds_no_invite_back_spec_sync_3() {
    let mut net = Net::new();
    let (host, silent) = (net.add_host(), net.add_host());
    let a = net.node(1, &[host, silent]);
    let b = net.node(2, &[host]);
    let (addr, other) = (net.address(host), net.address(silent));
    let (alice, done) = net.engine(a).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let (bob, done) = net.engine(b).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    net.run();
    net.pair(b, a);
    net.run();
    let inbox = net.engine(a).get_typed(&bob.person, &ct::KEYS).unwrap().unwrap().inbox.unwrap().label;
    let held = net.host_ids(host, &inbox);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let g = e.new_thing(&mut m, alice.person);
    m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    net.held_hosts.insert(silent);
    let (l, done) = net.engine(a).create_label(&g, &[addr, other]).unwrap();
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None, tied: None, keyset: None, keep: false };
    let mut acts = net.sync(a).carry_out(done).unwrap();
    let done = net.engine(a).grant(&g, &bob.person, &edge).unwrap();
    acts.extend(net.sync(a).carry_out(done).unwrap());
    net.actions(a, acts);
    net.run();
    assert!(net.labels_at(host).contains(&l));
    assert!(!net.labels_at(silent).contains(&l));
    assert!(net.host_ids(host, &inbox).iter().any(|b| !held.contains(b)), "the invite went");
}

/// Nodes a (Alice's device) and b (Bob's), persons on one host, Bob's device cut from it
/// (his inbox label unregistered); Alice's group `g` with a label replaced `replaced` times and
/// an item in it. Returns (net, a, b, bob's person, g, the item).
fn persons(replaced: usize, seed: u64) -> (Net, usize, usize, osis_base::Tid, osis_base::Tid, osis_base::Tid) {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(seed, &[host]);
    let b = net.node(seed + 1, &[host]);
    let addr = net.address(host);
    net.blocked.insert((b, host));
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
    let (mut l, done) = net.engine(a).create_label(&g, std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let item = net.item(a, g, g, "inside");
    net.run();
    for _ in 0..replaced {
        let (new, acts) = net.sync(a).replace_label(&g, &l).unwrap();
        net.actions(a, acts);
        net.run();
        l = new;
    }
    assert_eq!(net.engine(a).group_labels(&g).unwrap().iter().find(|x| x.id == l).unwrap().index, replaced as u64);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None, tied: None, keyset: None, keep: false };
    let done = net.engine(a).grant(&g, &bob.person, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    (net, a, b, bob.person, g, item)
}

// spec/sync.md §3, §5 (a deposit goes until its host takes it): Bob's device is away for
// hours, so every deposit of the grant's inbox blob is refused; Alice keeps one queued deposit
// and Bob gets the grant once his device is back. Past `INBOX_LIFETIME` the re-sent seal
// replaces the queued one.
#[test]
fn inbox_deposit_retried_for_hours_spec_sync_5() {
    let (mut net, a, b, _, g, item) = persons(0, 11);
    assert!(net.sync(a).take_diagnostics().iter().any(|d| d.contains("code 13")), "refused: no inbox label yet");
    for _ in 0..12 {
        net.advance(1_800_000);
    }
    assert_eq!(net.sync(a).deliveries_pending(), 1, "still queued after 6 h of refusals");
    let day = 86_400_000;
    for _ in 0..(osis_base::format::INBOX_LIFETIME_MS / day + 1) {
        net.advance(day);
    }
    assert_eq!(net.sync(a).deliveries_pending(), 1, "the re-sent seal replaced the first");
    net.blocked.clear();
    for _ in 0..4 {
        net.advance(1_800_000);
    }
    assert_eq!(net.engine(b).role_on(&g), Some(Role::Read), "the grant arrived");
    assert_eq!(net.read(b, item), Some(s("inside")));
    assert_eq!(net.sync(a).deliveries_pending(), 0);
}

// spec/wire.md §9, spec/sync.md §2: an inbox blob names each label with its index, so a group
// whose label was replaced several times opens from the grant's hint alone.
#[test]
fn hint_opens_a_label_replaced_many_times_spec_wire_9() {
    let (mut net, a, b, _, g, item) = persons(6, 21);
    net.blocked.clear();
    for _ in 0..4 {
        net.advance(60_000);
    }
    assert_eq!(net.engine(b).role_on(&g), Some(Role::Read), "the grant arrived");
    assert_eq!(net.read(b, item), Some(s("inside")), "the label opened from the hint");
    assert_eq!(net.sync(a).deliveries_pending(), 0);
}

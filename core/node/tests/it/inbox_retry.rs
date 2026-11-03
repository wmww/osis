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
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None, tied: None, keyset: None };
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
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None, tied: None, keyset: None };
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
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None, tied: None, keyset: None };
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
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None, tied: None, keyset: None };
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

/// `n` grants of label-less things of `alice` to `bob`, each as Alice's own commit; the things.
fn grants(net: &mut Net, a: usize, alice: osis_base::Tid, bob: osis_base::Tid, n: usize) -> Vec<osis_base::Tid> {
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None, tied: None, keyset: None };
    let mut things = Vec::new();
    for _ in 0..n {
        let e = net.engine(a);
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, alice);
        m.set(t, &ct::GROUP, &ct::Group::default()).unwrap();
        e.commit(m).unwrap();
        let done = net.engine(a).grant(&t, &bob, &edge).unwrap();
        let acts = net.sync(a).carry_out(done).unwrap();
        net.actions(a, acts);
        things.push(t);
    }
    things
}

/// Alice and Bob as persons on one host, Bob's card held by Alice: (net, host, a, b, alice, bob).
fn two_persons() -> (Net, usize, usize, usize, osis_base::Tid, osis_base::Tid) {
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
    (net, host, a, b, alice.person, bob.person)
}

/// Fills the deposit budget of `l` at the host with what nobody opens, but for `spare` slots.
fn fill_budget(net: &mut Net, host: usize, l: &osis_base::LabelId, spare: u64) -> Vec<osis_base::BlobId> {
    let left = osis_proto::LabelStore::budget(net.hosts[host].hub.store_mut(), l).unwrap().entries_left;
    let mut junk = Vec::new();
    for i in 0..left - spare {
        let blob = [&i.to_be_bytes()[..], &[0; 24]].concat();
        let id = osis_label::blob_id(&blob);
        let put = osis_proto::Put { blob_id: id, blob: &blob, wrap: [7; osis_crypto::WRAP_LEN], stamp: None, expiry: None, ephemeral: false, replaces: &[], now: 0 };
        osis_proto::LabelStore::put(net.hosts[host].hub.store_mut(), l, put).unwrap();
        junk.push(id);
    }
    junk
}

// spec/sync.md §5: a person takes in more grants than the deposit budget holds: each handled inbox blob leaves the budget, so the refused ones get through
#[test]
fn more_grants_than_the_budget_arrive_spec_sync_5() {
    let (mut net, host, a, b, alice, bob) = two_persons();
    let home = net.sync(b).labels().into_iter().find(|(x, _)| *x == bob).unwrap().1.id;
    fill_budget(&mut net, host, &home, 2);
    let things = grants(&mut net, a, alice, bob, 6);
    for _ in 0..8 {
        net.advance(60_000);
    }
    let lacking = things.iter().filter(|t| net.engine(b).role_on(t) != Some(Role::Read)).count();
    assert_eq!(lacking, 0, "grants lacking after 8 minutes");
}

// spec/sync.md §5: a deposit taken at a host and label ends the back-off of the others waiting there: room has appeared
#[test]
fn taken_deposit_ends_the_back_off_of_others_spec_sync_5() {
    let (mut net, host, a, b, alice, bob) = two_persons();
    let home = net.sync(b).labels().into_iter().find(|(x, _)| *x == bob).unwrap().1.id;
    let junk = fill_budget(&mut net, host, &home, 0);
    let waiting = grants(&mut net, a, alice, bob, 1);
    // refused long enough to back off to the cap
    for _ in 0..16 {
        net.advance(600_000);
    }
    assert_ne!(net.engine(b).role_on(&waiting[0]), Some(Role::Read), "refused");
    let now = net.now();
    for id in &junk {
        osis_proto::LabelStore::delete(net.hosts[host].hub.store_mut(), &home, id, now).unwrap();
    }
    let fresh = grants(&mut net, a, alice, bob, 1);
    for _ in 0..2 {
        net.advance(60_000);
    }
    assert_eq!(net.engine(b).role_on(&fresh[0]), Some(Role::Read), "the new one went at once");
    assert_eq!(net.engine(b).role_on(&waiting[0]), Some(Role::Read), "and the waiting one with it");
}

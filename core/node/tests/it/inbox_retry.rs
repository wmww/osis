#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Inbox deposits refused for now (spec/sync.md §3; notes/inbox.md, The outbox): the grantee's inbox
//! label is not registered yet, so the host answers code 13; the sender keeps the blob and
//! deposits it again (backing off from `retry_ms`) until the label exists.

use crate::net;
use net::*;
use osis_base::Role;
use osis_node::Mutation;
use osis_schema::core_types as ct;

// spec/sync.md §3: a grant whose inbox deposit was refused (label unknown) reaches the grantee
// once its node registered the inbox label.
#[test]
fn refused_inbox_deposit_retried_spec_sync_3() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let addr = net.address(host);
    // Bob's node cannot reach the host yet: his home label (his inbox) is not registered
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
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
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
    // spec: none (local store index, notes/engine-store.md Open): the grant reached Bob with a late
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
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
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
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let mut acts = net.sync(a).carry_out(done).unwrap();
    let done = net.engine(a).grant(&g, &bob.person, &edge).unwrap();
    acts.extend(net.sync(a).carry_out(done).unwrap());
    net.actions(a, acts);
    net.run();
    assert!(net.labels_at(host).contains(&l));
    assert!(!net.labels_at(silent).contains(&l));
    assert!(net.host_ids(host, &inbox).iter().any(|b| !held.contains(b)), "the invite went");
}

/// Nodes a (Alice's) and b (Bob's), accounts at one peer, Bob's node cut from it
/// (his inbox label unregistered); Alice's group `g` with a label replaced `replaced` times and
/// an item in it. Returns (net, a, b, bob's account, g, the item).
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
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let done = net.engine(a).grant(&g, &bob.person, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    (net, a, b, bob.person, g, item)
}

// spec/sync.md §3, §5 (a deposit goes until its host takes it): Bob's node is away for
// hours, so every deposit of the grant's inbox blob is refused; Alice keeps one queued deposit
// and Bob gets the grant once his node is back. Past `INBOX_LIFETIME` the re-sent seal
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
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
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

/// Alice and Bob as accounts at one peer, Bob's card held by Alice: (net, host, a, b, alice, bob).
fn two_accounts() -> (Net, usize, usize, usize, osis_base::Tid, osis_base::Tid) {
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

// spec/sync.md §5: an account takes in more grants than the deposit budget holds: each handled inbox blob leaves the budget, so the refused ones get through
#[test]
fn more_grants_than_the_budget_arrive_spec_sync_5() {
    let (mut net, host, a, b, alice, bob) = two_accounts();
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
    let (mut net, host, a, b, alice, bob) = two_accounts();
    let home = net.sync(b).labels().into_iter().find(|(x, _)| *x == bob).unwrap().1.id;
    // away, so nothing clears the budget
    net.set_online(b, false);
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
    net.set_online(b, true);
    for _ in 0..2 {
        net.advance(60_000);
    }
    assert_eq!(net.engine(b).role_on(&fresh[0]), Some(Role::Read), "the new one went at once");
    assert_eq!(net.engine(b).role_on(&waiting[0]), Some(Role::Read), "and the waiting one with it");
}

/// What is left of the deposit budget of `l` at the host: (entries, bytes).
fn budget_left(net: &mut Net, host: usize, l: &osis_base::LabelId) -> (u64, u64) {
    let b = osis_proto::LabelStore::budget(net.hosts[host].hub.store_mut(), l).unwrap();
    (b.entries_left, b.bytes_left)
}

// spec/sync.md §5: junk with no expiry fills an inbox's budget while its account is away; the grants refused meanwhile get through once a node of hers comes back, and what she does not clear leaves the rest of the budget free
#[test]
fn stranger_fill_ends_with_a_pass_spec_sync_5() {
    let (mut net, host, a, b, alice, bob) = two_accounts();
    let home = net.sync(b).labels().into_iter().find(|(x, _)| *x == bob).unwrap().1.id;
    net.set_online(b, false);
    fill_budget(&mut net, host, &home, 0);
    let things = grants(&mut net, a, alice, bob, 2);
    for _ in 0..4 {
        net.advance(60_000);
    }
    assert_eq!(budget_left(&mut net, host, &home).0, 0, "nothing clears it with nobody there");
    net.set_online(b, true);
    for _ in 0..8 {
        net.advance(60_000);
    }
    assert!(things.iter().all(|t| net.engine(b).role_on(t) == Some(Role::Read)), "the grants got through");
    assert!(budget_left(&mut net, host, &home).0 >= osis_base::format::INBOX_WAITING as u64, "half stays free");
}

// spec/sync.md §5: the same fill by bytes, in few large blobs
#[test]
fn stranger_fill_in_bytes_ends_with_a_pass_spec_sync_5() {
    let (mut net, host, _, b, _, bob) = two_accounts();
    let home = net.sync(b).labels().into_iter().find(|(x, _)| *x == bob).unwrap().1.id;
    net.set_online(b, false);
    let size = 512 * 1024;
    let mut i = 0u8;
    while budget_left(&mut net, host, &home).1 >= size as u64 {
        // what a host takes: a well-formed prefix, then anything
        let mut blob = osis_label::Prefix::new([i; 16], None, Vec::new()).unwrap().to_bytes();
        blob.resize(size, 0);
        let put = osis_proto::Put { blob_id: osis_label::blob_id(&blob), blob: &blob, wrap: [7; osis_crypto::WRAP_LEN], stamp: None, expiry: None, ephemeral: false, replaces: &[], now: 0 };
        osis_proto::LabelStore::put(net.hosts[host].hub.store_mut(), &home, put).unwrap();
        i += 1;
    }
    assert!(i < 32, "under the cap in entries: {i}");
    net.set_online(b, true);
    for _ in 0..8 {
        net.advance(60_000);
    }
    assert!(budget_left(&mut net, host, &home).1 >= osis_base::format::INBOX_WAITING_BYTES as u64, "half stays free");
}

// spec/sync.md §5: only an inbox is cleared: deposits under another label stay, here blobs its admin holds the bytes of from another group
#[test]
fn junk_under_another_label_stays_spec_sync_5() {
    let (mut net, host, a, _, alice, _) = two_accounts();
    let group = |net: &mut Net| {
        let e = net.engine(a);
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, alice);
        m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
        e.commit(m).unwrap();
        let addr = net.address(host);
        let (l, acts) = net.sync(a).create_label(&g, vec![addr]).unwrap();
        net.actions(a, acts);
        net.run();
        (g, l)
    };
    let (g, gl) = group(&mut net);
    let (_, l) = group(&mut net);
    // chunks: no commit of hers says where they belong
    let text: String = (0..180_000u32).map(|i| format!("{:x}", i.wrapping_mul(2_654_435_761))).collect();
    net.item(a, g, g, &text);
    net.run();
    let junk: Vec<_> = net.sync(a).entries(&gl).into_iter().filter(|(_, k)| !matches!(k, osis_node::sync::EntryKind::Commit { .. })).map(|x| x.0).collect();
    let size: usize = junk.iter().map(|id| net.engine(a).blob(id).unwrap().unwrap().len()).sum();
    assert!(size > osis_base::format::INBOX_WAITING_BYTES, "{size}");
    net.set_online(a, false);
    for id in &junk {
        let blob = net.engine(a).blob(id).unwrap().unwrap();
        let put = osis_proto::Put { blob_id: *id, blob: &blob, wrap: [7; osis_crypto::WRAP_LEN], stamp: None, expiry: None, ephemeral: false, replaces: &[], now: 0 };
        assert_eq!(osis_proto::LabelStore::put(net.hosts[host].hub.store_mut(), &l, put).unwrap(), osis_proto::Code::OK);
    }
    net.set_online(a, true);
    for _ in 0..4 {
        net.advance(60_000);
    }
    let held = net.host_ids(host, &l);
    assert!(junk.iter().all(|x| held.contains(x)), "kept");
}

// spec/sync.md §3, §5: a share whose inbox blob was cleared before its holder read it is sent
// again after `INBOX_LIFETIME`, though the holder has since written elsewhere where the sender
// sees it (that says nothing of this share; counting it dropped the share for good).
#[test]
fn cleared_share_sent_again_after_the_holder_acted_elsewhere_spec_sync_3() {
    let (mut net, host, a, b, alice, bob) = two_accounts();
    let addr = net.address(host);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let g = e.new_thing(&mut m, alice);
    m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let (_, done) = net.engine(a).create_label(&g, std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    let edge = ct::Edge { role: Role::Write, until: None, invite: None, tied: None };
    let done = net.engine(a).grant(&g, &bob, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    for _ in 0..4 {
        net.advance(60_000);
    }
    assert_eq!(net.engine(b).role_on(&g), Some(Role::Write));
    // Bob away: the share's blob lands in his inbox and is cleared there before he reads it
    let home = net.sync(b).labels().into_iter().find(|(x, _)| *x == bob).unwrap().1.id;
    let before = net.host_ids(host, &home);
    net.set_online(b, false);
    let t = grants(&mut net, a, alice, bob, 1)[0];
    net.run();
    let cleared: Vec<osis_base::BlobId> = net.host_ids(host, &home).into_iter().filter(|x| !before.contains(x)).collect();
    assert!(!cleared.is_empty(), "the share was deposited");
    let now = net.now();
    for x in &cleared {
        osis_proto::LabelStore::delete(net.hosts[host].hub.store_mut(), &home, x, now).unwrap();
    }
    net.set_online(b, true);
    let item = net.item(b, g, g, "from bob");
    for _ in 0..4 {
        net.advance(60_000);
    }
    assert_eq!(net.read(a, item), Some(s("from bob")), "Alice sees Bob act");
    assert_ne!(net.engine(b).role_on(&t), Some(Role::Read), "cleared");
    let day = 86_400_000;
    for _ in 0..osis_base::format::INBOX_LIFETIME_MS / day + 2 {
        net.advance(day);
    }
    assert_eq!(net.engine(b).role_on(&t), Some(Role::Read), "the cleared share came again");
}

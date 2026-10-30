#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A non-writer's deposit of its own membership write (spec/sync.md §5): queued once, sent
//! until a server answers, also after the depositor forgot the label.

use crate::net;
use net::*;
use osis_base::Role;
use osis_node::sync::EntryKind;
use osis_schema::core_types as ct;

/// Node 0 admin of a group with a label, node 1 a reader with invite read, node 2 a stranger
/// node 1 knows. Returns (group, its label, node 1's invite grant of node 2).
fn invite(net: &mut Net, sv: usize) -> (osis_base::Tid, osis_base::LabelId, osis_base::CommitId, osis_node::flows::Done) {
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
fn log(net: &Net, sv: usize, l: &osis_base::LabelId) -> (usize, usize) {
    use osis_proto::LabelStore;
    let recs = net.servers[sv].hub.store().log_after(l, 0, 1 << 20).ok().flatten().unwrap_or_default();
    let del = recs.iter().filter(|(_, r)| matches!(r, osis_proto::LogRecord::Deleted(_))).count();
    (recs.len() - del, del)
}

fn copies(net: &mut Net, n: usize, l: &osis_base::LabelId, c: &osis_base::CommitId) -> usize {
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
    // the grantee stays offline: its inbox copy is no other route to the label
    net.set_online(2, false);
    net.set_online(1, false);
    net.sync(1).carry_out(done).unwrap();
    // node 1 loses the group before it is back online
    let b = net.tid(1);
    let d = osis_node::flows::Demotion { member: b, new: None, presync: osis_node::flows::PreSync::Synced };
    let done = net.engine(0).demote(&g, &d).unwrap();
    // the admin stays offline: the label keeps the deposit key node 1 signed with (the removal
    // refreshed the deposit seed, spec/crypto.md §3; registered, it refuses node 1's deposit)
    net.set_online(0, false);
    let acts = net.sync(0).carry_out(done).unwrap();
    net.actions(0, acts);
    net.run();
    net.pair(0, 1);
    net.sync(1).drop_lost().unwrap();
    assert!(net.sync(1).labels().iter().all(|(_, x)| x.id != l), "node 1 forgot the label");
    let before = log(&net, sv, &l);
    assert_eq!(copies(&mut net, 0, &l, &c), 0, "not under the label yet");
    net.set_online(1, true);
    net.run();
    net.advance(61_000);
    assert!(log(&net, sv, &l).0 > before.0, "node 1 deposited after forgetting the label");
    net.set_online(0, true);
    net.run();
    assert_eq!(copies(&mut net, 0, &l, &c), 1, "the deposit reached the label");
}

// spec/sync.md §5: a queued deposit survives a crash: sent and not answered (or never sent)
// when the node restarts, it goes again and lands once.
#[test]
fn queued_deposit_survives_a_restart_spec_sync_5() {
    for sent in [false, true] {
        let mut net = Net::new();
        let sv = net.add_server();
        for i in 0..3 {
            net.node(40 + i, &[sv]);
        }
        let (_, l, c, done) = invite(&mut net, sv);
        let before = log(&net, sv, &l);
        let acts = net.sync(1).carry_out(done).unwrap();
        assert!(net.sync(1).deliveries_pending() > 0);
        if sent {
            net.actions(1, acts);
        }
        net.restart(1, 88);
        assert!(net.sync(1).deliveries_pending() > 0, "sent {sent}: the deposit reloaded");
        for _ in 0..3 {
            net.run();
            net.advance(61_000);
        }
        assert_eq!(net.sync(1).deliveries_pending(), 0, "sent {sent}: answered");
        assert_eq!(copies(&mut net, 0, &l, &c), 1, "sent {sent}: one entry of the grant under the label");
        assert_eq!(log(&net, sv, &l).1, before.1, "sent {sent}: no second encryption deposited");
    }
}

fn carry(net: &mut Net, n: usize, done: osis_node::flows::Done) {
    let acts = net.sync(n).carry_out(done).unwrap();
    net.actions(n, acts);
}

/// Blob IDs of node `n`'s entries of commit `c`, over every label it knows of.
fn entries_of(net: &mut Net, n: usize, c: &osis_base::CommitId) -> Vec<osis_base::BlobId> {
    let labels: Vec<osis_base::LabelId> = net.sync(n).labels().into_iter().map(|(_, l)| l.id).collect();
    let mut out = Vec::new();
    for l in labels {
        out.extend(net.sync(n).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c)).map(|(id, _)| id));
    }
    out
}

/// Every live entry a server holds, over all its labels.
fn all_ids(net: &Net, sv: usize) -> Vec<osis_base::BlobId> {
    net.labels_at(sv).iter().flat_map(|l| net.server_ids(sv, l)).collect()
}

/// Node `a`'s person shares group T (label at server 0) by a single-use link whose K has its
/// label at server 1; node `x` (a person too) follows K's label. Returns (a, x, T, link, x's
/// person, the held link key).
fn link_setup(net: &mut Net) -> (usize, usize, osis_base::Tid, osis_label::ShareLink, osis_base::Tid, osis_base::Tid) {
    net.add_server();
    net.add_server();
    link_setup_at(net, &[1])
}

/// `link_setup` over the servers `net` has (server 0 the home and T's), K's label at `k`.
fn link_setup_at(net: &mut Net, k: &[usize]) -> (usize, usize, osis_base::Tid, osis_label::ShareLink, osis_base::Tid, osis_base::Tid) {
    use osis_node::Mutation;
    let s0 = 0;
    let all: Vec<usize> = (0..net.servers.len()).collect();
    let a = net.node(30, &all);
    let x = net.node(31, &all);
    let home = vec![net.address(s0)];
    let (pa, done) = net.engine(a).create_person(&home).unwrap();
    carry(net, a, done);
    let (px, done) = net.engine(x).create_person(&home).unwrap();
    carry(net, x, done);
    net.run();
    let e = net.engine(a);
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, pa.person);
    m.set(t, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let (_, acts) = net.sync(a).create_label(&t, home.clone()).unwrap();
    net.actions(a, acts);
    net.run();
    let spec = osis_node::flows::LinkSpec { target: t, role: Role::Read, until: None, servers: k.iter().map(|s| net.address(*s)).collect(), peers: Vec::new(), single_use: true };
    let (link, _, done) = net.engine(a).create_link(&pa.person, &spec).unwrap();
    carry(net, a, done);
    net.run();
    let held = net.engine(x).hold_key_actor(link.seed.clone()).unwrap();
    let acts = net.sync(x).follow(held, link.k, link.k_label, link.servers.clone());
    net.actions(x, acts);
    net.run();
    (a, x, t, link, px.person, held)
}

// spec/sync.md §5 (a node places its commit under its things' labels before any projection
// of it elsewhere), spec/permissions.md §4, §9: a redeemer whose deposit of its redemption
// cannot reach K's server sends no partial copy of it (its `/members` chain copy under the
// target's label, the inbox blob to its own person) to the other server; once the deposit
// lands, they follow and the sharer applies the redemption.
#[test]
fn projections_wait_for_the_full_commit_spec_sync_5() {
    let mut net = Net::new();
    let (a, x, t, link, px, held) = link_setup(&mut net);
    let (s0, s1) = (0, 1);
    // x loses K's server, then redeems
    net.set_online(x, false);
    net.blocked.insert((x, s1));
    net.set_online(x, true);
    let done = net.engine(x).redeem(&link, &px, true).unwrap();
    let c = *done.commits.last().unwrap();
    net.engine(x).drop_key_actor(&held);
    carry(&mut net, x, done);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    let at0 = all_ids(&net, s0);
    assert!(entries_of(&mut net, x, &c).iter().all(|id| !at0.contains(id)), "no copy of the redemption at the other server");
    assert!(net.engine(x).role_on(&t).is_some(), "x reads the target through K");
    assert!(net.engine(a).header(&c).is_none(), "the sharer holds no part of it");
    assert!(net.sync(x).deliveries_pending() > 0, "the inbox blob waits");
    net.blocked.remove(&(x, s1));
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    assert!(net.engine(a).roster(&link.k).contains_key(&px), "the sharer applied the redemption");
    let at0 = all_ids(&net, s0);
    assert!(entries_of(&mut net, x, &c).iter().any(|id| at0.contains(id)), "its copies followed");
    assert_eq!(net.sync(x).deliveries_pending(), 0);
}

// spec/sync.md §5 (the wait ends at `PLACE_WAIT`), spec/commits.md §4 (atomic apply): K's
// server unreachable for the redeemer past the bound, its copies go anyway; the sharer, who
// syncs K, holds the `/members` part of the redemption and waits for the rest
// (issues/link-race-edge-only-pending.md: forever if it never reaches K), applying it once
// the deposit lands.
#[test]
fn projections_go_after_the_bound_spec_sync_5() {
    let mut net = Net::new();
    let (a, x, _, link, px, held) = link_setup(&mut net);
    let (s0, s1) = (0, 1);
    net.set_online(x, false);
    net.blocked.insert((x, s1));
    net.set_online(x, true);
    let done = net.engine(x).redeem(&link, &px, true).unwrap();
    let c = *done.commits.last().unwrap();
    net.engine(x).drop_key_actor(&held);
    carry(&mut net, x, done);
    for _ in 0..7 {
        net.run();
        net.advance(61_000);
    }
    net.run();
    assert!(net.sync(x).take_diagnostics().iter().any(|d| d.contains("not placed")), "reported");
    let at0 = all_ids(&net, s0);
    assert!(entries_of(&mut net, x, &c).iter().any(|id| at0.contains(id)), "its copies went to the other server");
    assert!(net.engine(a).pending().iter().any(|(p, r)| *p == c && *r == osis_node::Reason::WaitDeltas), "the sharer waits for the rest");
    assert!(!net.engine(a).roster(&link.k).contains_key(&px));
    net.blocked.remove(&(x, s1));
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    assert!(net.engine(a).roster(&link.k).contains_key(&px), "applied once placed");
    assert!(net.engine(a).pending().is_empty());
}

// spec/sync.md §3, §5: a crash between a redemption's commit and carrying out its deliveries
// loses neither: the inbox delivery's record was written in the commit's transaction, and
// the deposit of the redeemer's own membership write is placed by its next pass. Single use
// too: L's self-removal, derived from the stored commit after the restart, holds back nothing
// under K until placed (spec/crypto.md §4).
#[test]
fn deliveries_survive_a_crash_before_carry_out_spec_sync_5() {
    for single in [false, true] {
        let mut net = Net::new();
        let (a, x, _, link, px, _) = link_setup(&mut net);
        let done = net.engine(x).redeem(&link, &px, single).unwrap();
        assert!(done.deliveries.iter().any(|d| matches!(d, osis_node::flows::Delivery::Inbox { .. })));
        let c = *done.commits.last().unwrap();
        drop(done);
        net.restart(x, 77);
        assert!(net.sync(x).deliveries_pending() > 0, "the inbox delivery reloaded unsent");
        for _ in 0..3 {
            net.run();
            net.advance(61_000);
        }
        assert!(!entries_of(&mut net, x, &c).is_empty(), "single {single}: the redemption placed under K");
        assert!(net.engine(a).roster(&link.k).contains_key(&px), "single {single}: the sharer applied the redemption");
        assert_eq!(net.sync(x).deliveries_pending(), 0, "single {single}: the inbox blob went");
    }
}

// spec/sync.md §5 (a refused deposit at one server does not hold what another accepted),
// spec/sync.md §3: K's label at two servers, one refusing every entry (storage cap); the
// redeemer's deposit lands at the other, and its inbox blob to its own person goes.
#[test]
fn inbox_goes_when_one_server_refuses_spec_sync_5() {
    let mut net = Net::new();
    net.add_server();
    net.add_server();
    net.add_server_with(osis_server::Policy { cap_entries: 0, ..osis_server::Policy::default() });
    let (a, x, _, link, px, held) = link_setup_at(&mut net, &[1, 2]);
    let inbox = net.engine(x).get_typed(&px, &ct::KEYS).unwrap().unwrap().inbox.unwrap().label;
    let before = net.server_ids(0, &inbox).len();
    let done = net.engine(x).redeem(&link, &px, true).unwrap();
    net.engine(x).drop_key_actor(&held);
    carry(&mut net, x, done);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    assert!(net.engine(a).roster(&link.k).contains_key(&px), "the sharer applied the redemption");
    assert_eq!(net.sync(x).deliveries_pending(), 0);
    assert!(net.server_ids(0, &inbox).len() > before, "the inbox blob reached its label");
}

// spec/permissions.md §3 (a removal goes under the labels the removed party could read in the
// same sync, before any other upload), spec/sync.md §5 (removals are not held): with the
// target's server down, the removal's copy under another label still goes.
#[test]
fn removal_copies_not_held_spec_permissions_3() {
    let mut net = Net::new();
    let s0 = net.add_server();
    let s1 = net.add_server();
    let a = net.node(40, &[s0, s1]);
    let b = net.node(41, &[s0, s1]);
    // K (label at s1) with member b, a member of T (label at s0)
    let k = net.group(a, &[(b, Role::Write)], &[s1]);
    let t = net.group_seeded(a, &[], vec![net.address(s0)], 2);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
    let done = net.engine(a).grant(&t, &k, &edge).unwrap();
    carry(&mut net, a, done);
    net.run();
    net.set_online(a, false);
    net.blocked.insert((a, s1));
    net.set_online(a, true);
    let bt = net.tid(b);
    let d = osis_node::flows::Demotion { member: bt, new: None, presync: osis_node::flows::PreSync::Synced };
    let done = net.engine(a).demote(&k, &d).unwrap();
    let c = *done.commits.last().unwrap();
    carry(&mut net, a, done);
    // under T the copy waits for T's rotation (b read T through K), the next pass there
    net.run();
    net.advance(61_000);
    let at1 = all_ids(&net, s1);
    let at0 = all_ids(&net, s0);
    let ids = entries_of(&mut net, a, &c);
    assert!(ids.iter().all(|id| !at1.contains(id)), "the target's server is down");
    assert!(ids.iter().any(|id| at0.contains(id)), "the removal's copy under T went");
}

// spec/sync.md §5, spec/crypto.md §3: a deposit queued before the label's deposit seed was
// refreshed is refused as signed by an earlier key; it is signed again with the current one
// (or, when this node has not read the new seed yet, dropped: the next pass places it again
// under the current key), never resent unchanged forever.
#[test]
fn queued_deposit_after_seed_refresh_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    for i in 0..4 {
        net.node(60 + i, &[sv]);
    }
    let (g, l, c, done) = invite(&mut net, sv);
    net.pair(3, 0);
    let d = net.tid(3);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
    let grant = net.engine(0).grant(&g, &d, &edge).unwrap();
    carry(&mut net, 0, grant);
    net.run();
    net.set_online(1, false);
    net.sync(1).carry_out(done).unwrap();
    // a refreshed seed, registered by the step the next rotation (a removal) issues
    let actor = net.engine(0).group_actor(&g);
    let done = net.engine(0).refresh_deposit_seed(&actor).unwrap();
    carry(&mut net, 0, done);
    let demotion = osis_node::flows::Demotion { member: d, new: None, presync: osis_node::flows::PreSync::Synced };
    let done = net.engine(0).demote(&g, &demotion).unwrap();
    carry(&mut net, 0, done);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    net.set_online(1, true);
    for _ in 0..6 {
        net.run();
        net.advance(61_000);
    }
    assert_eq!(net.sync(1).deliveries_pending(), 0, "answered, not resent unchanged");
    // the pass also seals the grant again under the epoch the removal rotated to
    assert!(copies(&mut net, 0, &l, &c) >= 1, "the grant reached the label");
}

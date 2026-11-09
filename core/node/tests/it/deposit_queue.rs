#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A non-writer's deposit of its own role write (spec/sync.md §5): queued once, sent
//! until a host answers, also after the depositor forgot the label.

use crate::net;
use net::*;
use osis_base::Role;
use osis_node::sync::EntryKind;
use osis_schema::core_types as ct;

/// Node 0 admin of a group with a label, node 1 a reader with invite read, node 2 a stranger
/// node 1 knows. Returns (group, its label, node 1's invite grant of node 2).
fn invite(net: &mut Net, host: usize) -> (osis_base::Tid, osis_base::LabelId, osis_base::CommitId, osis_node::flows::Done) {
    let g = net.group(0, &[(1, Role::Read)], &[host]);
    let b = net.tid(1);
    let raise = ct::Edge { role: Role::Read, until: None, invite: Some(Role::Read), tied: None };
    let done = net.engine(0).grant(&g, &b, &raise).unwrap();
    let acts = net.sync(0).carry_out(done).unwrap();
    net.actions(0, acts);
    net.run();
    net.pair(2, 1);
    let l = net.engine(0).group_labels(&g).unwrap()[0].id;
    let c = net.tid(2);
    let grant = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let done = net.engine(1).grant(&g, &c, &grant).unwrap();
    let commit = *done.commits.last().unwrap();
    (g, l, commit, done)
}

/// Records of the host's log of `l`: (added, deleted).
fn log(net: &Net, host: usize, l: &osis_base::LabelId) -> (usize, usize) {
    use osis_proto::LabelStore;
    let recs = net.hosts[host].hub.store().log_after(l, 0, 1 << 20).ok().flatten().unwrap_or_default();
    let del = recs.iter().filter(|(_, r)| matches!(r, osis_proto::LogRecord::Deleted(_))).count();
    (recs.len() - del, del)
}

fn copies(net: &mut Net, n: usize, l: &osis_base::LabelId, c: &osis_base::CommitId) -> usize {
    net.sync(n).entries(l).iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c)).count()
}

// spec/sync.md §5: an invite grant by a reader goes under the label as one deposit: its
// author records the queued deposit as its entry at once, so no pass places a second
// encryption while the host has not answered.
#[test]
fn invite_grant_deposited_once_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    for i in 0..3 {
        net.node(10 + i, &[host]);
    }
    let (_, l, c, done) = invite(&mut net, host);
    let before = log(&net, host, &l);
    let acts = net.sync(1).carry_out(done).unwrap();
    net.actions(1, acts);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    let after = log(&net, host, &l);
    assert_eq!(copies(&mut net, 0, &l, &c), 1, "one entry of the grant under the label");
    assert_eq!(after.1, before.1, "no second encryption deposited (and deleted as a duplicate)");
}

// spec/sync.md §5, spec/permissions.md §3: the deposit goes even when its author forgot the
// label before the host answered.
#[test]
fn queued_deposit_survives_forgetting_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    for i in 0..3 {
        net.node(20 + i, &[host]);
    }
    let (g, l, c, done) = invite(&mut net, host);
    // the grantee stays offline: its inbox copy is no other route to the label
    net.set_online(2, false);
    net.set_online(1, false);
    net.sync(1).carry_out(done).unwrap();
    // node 1 loses the group before it is back online
    let b = net.tid(1);
    let d = osis_node::flows::Demotion { holder: b, new: None, retain: None };
    let done = net.engine(0).demote(&g, &d).unwrap();
    // the admin stays offline: the label keeps the deposit key node 1 signed with (the removal
    // refreshed the deposit seed, spec/crypto.md §3; registered, it refuses node 1's deposit)
    net.set_online(0, false);
    let acts = net.sync(0).carry_out(done).unwrap();
    net.actions(0, acts);
    net.run();
    net.pair(0, 1);
    net.sync(1).drop_lost().unwrap();
    assert!(net.group_labels(1).iter().all(|(_, x)| x.id != l), "node 1 forgot the label");
    let before = log(&net, host, &l);
    assert_eq!(copies(&mut net, 0, &l, &c), 0, "not under the label yet");
    net.set_online(1, true);
    net.run();
    net.advance(61_000);
    assert!(log(&net, host, &l).0 > before.0, "node 1 deposited after forgetting the label");
    net.set_online(0, true);
    net.run();
    // the deposit, whole; the admin also places the part it holds, its edge write: node 1's box
    // to node 2 is invalid there (node 1 removed) and went (spec/permissions.md §6)
    let whole = net.sync(0).entries(&l).iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, parts, .. } if *commit == c && parts.len() == 2)).count();
    assert_eq!(whole, 1, "the deposit reached the label");
}

// spec/sync.md §5: a queued deposit survives a crash: sent and not answered (or never sent)
// when the node restarts, it goes again and lands once.
#[test]
fn queued_deposit_survives_a_restart_spec_sync_5() {
    for sent in [false, true] {
        let mut net = Net::new();
        net.home_at_hosts = true;
        let host = net.add_host();
        for i in 0..3 {
            net.node(40 + i, &[host]);
        }
        let (_, l, c, done) = invite(&mut net, host);
        let before = log(&net, host, &l);
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
        assert_eq!(log(&net, host, &l).1, before.1, "sent {sent}: no second encryption deposited");
    }
}

fn carry(net: &mut Net, n: usize, done: osis_node::flows::Done) {
    let acts = net.sync(n).carry_out(done).unwrap();
    net.actions(n, acts);
}

/// Blob IDs of node `n`'s entries of commit `c`, over every label it knows of.
fn entries_of(net: &mut Net, n: usize, c: &osis_base::CommitId) -> Vec<osis_base::BlobId> {
    let labels: Vec<osis_base::LabelId> = net.group_labels(n).into_iter().map(|(_, l)| l.id).collect();
    let mut out = Vec::new();
    for l in labels {
        out.extend(net.sync(n).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c)).map(|(id, _)| id));
    }
    out
}

/// Every live entry a host holds, over all its labels.
fn all_ids(net: &Net, host: usize) -> Vec<osis_base::BlobId> {
    net.labels_at(host).iter().flat_map(|l| net.host_ids(host, l)).collect()
}

/// Node `a`'s account shares group T (label at host 0) by a single-use link whose K has its
/// label at host 1; node `x` (an account too) follows K's label. Returns (a, x, T, link, x's
/// account, the held link key).
fn link_setup(net: &mut Net) -> (usize, usize, osis_base::Tid, osis_label::ShareLink, osis_base::Tid, osis_base::Tid) {
    net.add_host();
    net.add_host();
    link_setup_at(net, &[1])
}

/// `link_setup` over the hosts `net` has (host 0 the home and T's), K's label at `k`.
fn link_setup_at(net: &mut Net, k: &[usize]) -> (usize, usize, osis_base::Tid, osis_label::ShareLink, osis_base::Tid, osis_base::Tid) {
    use osis_node::Mutation;
    let s0 = 0;
    let all: Vec<usize> = (0..net.hosts.len()).collect();
    let a = net.node(30, &all);
    let x = net.node(31, &all);
    let home = vec![net.address(s0)];
    let (pa, done) = net.engine(a).create_account(&home).unwrap();
    carry(net, a, done);
    let (px, done) = net.engine(x).create_account(&home).unwrap();
    carry(net, x, done);
    net.run();
    let e = net.engine(a);
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, pa.account);
    m.set(t, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let (_, acts) = net.sync(a).create_label(&t, home.clone()).unwrap();
    net.actions(a, acts);
    net.run();
    let spec = osis_node::flows::LinkSpec { target: t, role: Role::Read, until: None, hosts: k.iter().map(|s| net.address(*s)).collect(), peers: Vec::new(), single_use: true };
    let (link, _, done) = net.engine(a).create_link(&pa.account, &spec).unwrap();
    carry(net, a, done);
    net.run();
    let held = net.engine(x).hold_key_actor(link.seed.clone()).unwrap();
    let acts = net.sync(x).follow(held, link.k, link.k_label, link.hosts.clone());
    net.actions(x, acts);
    net.run();
    (a, x, t, link, px.account, held)
}

/// Commit `c`'s deltas node `n` lacks (none when it holds no copy of `c`).
fn missing(net: &mut Net, n: usize, c: &osis_base::CommitId) -> usize {
    net.engine(n).commit_bytes(c).unwrap().map_or(0, |b| osis_commit::CommitBlob::decode(&b).unwrap().missing().len())
}

// spec/commits.md §4 (a commit held in part applies, the rest joins on arrival), spec/sync.md §3, §5: a redeemer whose redemption never reaches K's host sends its
// copies at once (its chain copy under the target's label, the inbox blob to its own
// account); the sharer, who syncs K, applies the redemption from them and stays converged
// while the redeemer is gone; once the redeemer is back and reaches K's host, its deposit
// lands and the sharer holds the whole commit.
#[test]
fn copy_applies_when_k_never_gets_it_spec_commits_4() {
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
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    let at0 = all_ids(&net, s0);
    assert!(entries_of(&mut net, x, &c).iter().any(|id| at0.contains(id)), "its copies went to the other host");
    assert!(net.sync(x).deliveries_pending() > 0, "the deposit under K waits");
    // the redeemer gone (its disk lost, or K's host never takes it): nothing waits
    net.set_online(x, false);
    for _ in 0..3 {
        net.run();
        net.advance(3_600_000);
    }
    assert!(net.engine(a).roster(&link.k).contains_key(&px), "the sharer applied the redemption");
    assert!(net.engine(a).pending().is_empty());
    net.blocked.remove(&(x, s1));
    net.set_online(x, true);
    for _ in 0..4 {
        net.run();
        net.advance(3_600_000);
    }
    net.run();
    assert_eq!(net.sync(x).deliveries_pending(), 0, "the deposit landed");
    assert_eq!(missing(&mut net, a, &c), 0, "the sharer holds all of it");
    assert!(net.engine(a).pending().is_empty());
}

// spec/sync.md §3, §5: a crash between a redemption's commit and carrying out its deliveries
// loses neither: the inbox delivery's record was written in the commit's transaction, and
// the deposit of the redeemer's own role write is placed by its next pass. Single use
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

// spec/sync.md §5 (a refused deposit at one host does not hold what another accepted; a
// storage-cap refusal is for now), spec/sync.md §3: K's label at two hosts, one refusing every
// entry (storage cap); the redeemer's deposit lands at the other, and its inbox blob to its own
// account goes; the deposit at the full host is sent again and lands once it has room.
#[test]
fn inbox_goes_when_one_host_refuses_spec_sync_5() {
    let mut net = Net::new();
    net.add_host();
    net.add_host();
    net.add_host_with(osis_host::HostPolicy { cap_entries: 0, ..osis_host::HostPolicy::default() });
    let (a, x, _, link, px, held) = link_setup_at(&mut net, &[1, 2]);
    let inbox = net.engine(x).get_typed(&px, &ct::KEYS).unwrap().unwrap().inbox.unwrap().label;
    let before = net.host_ids(0, &inbox).len();
    let done = net.engine(x).redeem(&link, &px, true).unwrap();
    net.engine(x).drop_key_actor(&held);
    carry(&mut net, x, done);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    assert!(net.engine(a).roster(&link.k).contains_key(&px), "the sharer applied the redemption");
    assert!(net.host_ids(0, &inbox).len() > before, "the inbox blob reached its label");
    // the redemption's deposit (an account's keys travel in its `keys.0`, no keyset commit)
    assert_eq!(net.sync(x).deliveries_pending(), 1, "the full host's deposit is kept");
    let full = net.host_ids(2, &link.k_label).len();
    net.restart_host_with(2, osis_host::HostPolicy::default());
    for _ in 0..4 {
        net.run();
        net.advance(3_600_000);
    }
    net.run();
    assert_eq!(net.sync(x).deliveries_pending(), 0);
    assert!(net.host_ids(2, &link.k_label).len() > full, "the deposit landed once there was room");
}

// spec/permissions.md §3 (a removal goes under the labels the removed party could read in the
// same sync, before any other upload), spec/commits.md §4: with the
// target's host down, the removal's copy under another label still goes.
#[test]
fn removal_copies_not_held_spec_permissions_3() {
    let mut net = Net::new();
    let s0 = net.add_host();
    let s1 = net.add_host();
    let a = net.node(40, &[s0, s1]);
    let b = net.node(41, &[s0, s1]);
    // K (label at s1) with holder b, a holder of T (label at s0)
    let k = net.group(a, &[(b, Role::Write)], &[s1]);
    let t = net.group_seeded(a, &[], vec![net.address(s0)], 2);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let done = net.engine(a).grant(&t, &k, &edge).unwrap();
    carry(&mut net, a, done);
    net.run();
    net.set_online(a, false);
    net.blocked.insert((a, s1));
    net.set_online(a, true);
    let bt = net.tid(b);
    let d = osis_node::flows::Demotion { holder: bt, new: None, retain: None };
    let done = net.engine(a).demote(&k, &d).unwrap();
    let c = *done.commits.last().unwrap();
    carry(&mut net, a, done);
    // under T the copy waits for T's rotation (b read T through K), the next pass there
    net.run();
    net.advance(61_000);
    let at1 = all_ids(&net, s1);
    let at0 = all_ids(&net, s0);
    let ids = entries_of(&mut net, a, &c);
    assert!(ids.iter().all(|id| !at1.contains(id)), "the target's host is down");
    assert!(ids.iter().any(|id| at0.contains(id)), "the removal's copy under T went");
}

// spec/sync.md §5, spec/crypto.md §3: a deposit queued before the label's deposit seed was
// refreshed is refused as signed by an earlier key; it is signed again with the current one
// (or, when this node has not read the new seed yet, dropped: the next pass places it again
// under the current key), never resent unchanged forever.
#[test]
fn queued_deposit_after_seed_refresh_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    net.home_at_hosts = true;
    for i in 0..4 {
        net.node(60 + i, &[host]);
    }
    let (g, l, c, done) = invite(&mut net, host);
    // a shared group brings 0 the keys of 3's account
    net.group(0, &[(3, Role::Read)], &[host]);
    net.run();
    let d = net.tid(3);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let grant = net.engine(0).grant(&g, &d, &edge).unwrap();
    carry(&mut net, 0, grant);
    net.run();
    net.set_online(1, false);
    net.sync(1).carry_out(done).unwrap();
    // a refreshed seed, registered by the step the next rotation (a removal) issues
    let actor = net.engine(0).group_actor(&g);
    let done = net.engine(0).refresh_deposit_seed(&actor).unwrap();
    carry(&mut net, 0, done);
    let demotion = osis_node::flows::Demotion { holder: d, new: None, retain: None };
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

// spec/sync.md §5, spec/permissions.md §3: after an admin refreshes the deposit seed alone and
// registers the new deposit key, a second admin that comes online before it applied the `keys.0`
// write registers no step back to the old key (it waits until what it can open under the label
// is applied), so the host's head keeps the new deposit key.
#[test]
fn lagging_admin_keeps_refreshed_deposit_key_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    net.node(80, &[host]);
    // blobs never inline: the new head arrives before the `keys.0` write it fetches
    net.add_node(81, osis_node::sync::SyncConfig { hosts: vec![net.address(host)], inline_limit: 0, ..Default::default() });
    let g = net.group(0, &[(1, Role::Admin)], &[host]);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    let l = net.engine(0).group_labels(&g).unwrap()[0].id;
    let actor = net.engine(0).group_actor(&g);
    let old = net.engine(1).deposit_seed(&g).unwrap().unwrap();
    let before = net.host_path(host, &l).len();
    let done = net.engine(0).refresh_deposit_seed(&actor).unwrap();
    carry(&mut net, 0, done);
    net.run();
    let new = net.engine(0).deposit_seed(&g).unwrap().unwrap();
    let (old_pk, new_pk) = (osis_crypto::deposit_key(&old, &l).verifying_key(), osis_crypto::deposit_key(&new, &l).verifying_key());
    assert_eq!(net.host_path(host, &l).last().unwrap().keys.deposit, new_pk, "the refresh registered");
    for _ in 0..6 {
        net.run();
        net.advance(61_000);
    }
    assert_eq!(net.engine(1).deposit_seed(&g).unwrap().unwrap().expose(), new.expose(), "the laggard applied the write");
    let path = net.host_path(host, &l);
    assert!(path[before..].iter().all(|s| s.keys.deposit != old_pk), "no step back to the old deposit key");
    assert_eq!(path.len(), before + 1, "the refresh's step only");
    assert_eq!(path.last().unwrap().keys.deposit, new_pk);
}

/// K (label at s1) with holder b, a holder of T (label at s0), both node a's: (a, b, K, T).
fn holder_group(net: &mut Net) -> (usize, usize, osis_base::Tid, osis_base::Tid) {
    let s0 = net.add_host();
    let s1 = net.add_host();
    let a = net.node(40, &[s0, s1]);
    let b = net.node(41, &[s0, s1]);
    let k = net.group(a, &[(b, Role::Write)], &[s1]);
    let t = net.group_seeded(a, &[], vec![net.address(s0)], 2);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let done = net.engine(a).grant(&t, &k, &edge).unwrap();
    carry(net, a, done);
    net.run();
    (a, b, k, t)
}

/// Whether node `n`'s entry of `c` under `l` carrying its delta on aspect `ak` is at host `s`.
fn copy_at(net: &mut Net, n: usize, s: usize, l: &osis_base::LabelId, c: &osis_base::CommitId, ak: &str) -> bool {
    let at = net.host_ids(s, l);
    let h = net.engine(n).header(c).unwrap();
    let on = |ai: &usize| h.aspects.get(*ai).is_some_and(|a| a.ak.as_str() == ak);
    net.sync(n).entries(l).iter().any(|(id, k)| matches!(k, EntryKind::Commit { commit, parts, .. } if commit == c && parts.iter().any(&on)) && at.contains(id))
}

// spec/permissions.md §3 (a removal or lowering goes under the labels the removed party could
// read), spec/crypto.md §4 (encrypting waits for the rotation): b2 lowered to read on K, the
// commit placed first under T (b2 reads T through K); a crash before carrying it out, or while
// that copy waits for T's rotation (b's removal from K just before), still places it once the
// node restarts. T's rotation names only b's removal: nothing else places b2's lowering there.
#[test]
fn first_copy_survives_a_crash_spec_permissions_3() {
    for crash in ["none", "before carry_out", "while it waits"] {
        let mut net = Net::new();
        let s0 = net.add_host();
        let s1 = net.add_host();
        let a = net.node(40, &[s0, s1]);
        let b = net.node(41, &[s0, s1]);
        let b2 = net.node(42, &[s0, s1]);
        let k = net.group(a, &[(b, Role::Write), (b2, Role::Write)], &[s1]);
        let t = net.group_seeded(a, &[], vec![net.address(s0)], 2);
        let read = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        let done = net.engine(a).grant(&t, &k, &read).unwrap();
        carry(&mut net, a, done);
        net.run();
        let tl = net.engine(a).group_labels(&t).unwrap()[0].id;
        // under T alone
        net.set_online(a, false);
        net.blocked.insert((a, s1));
        if crash == "while it waits" {
            let bt = net.tid(b);
            let d = osis_node::flows::Demotion { holder: bt, new: None, retain: None };
            let done = net.engine(a).demote(&k, &d).unwrap();
            carry(&mut net, a, done);
        }
        let b2t = net.tid(b2);
        let d = osis_node::flows::Demotion { holder: b2t, new: Some(read.clone()), retain: None };
        let done = net.engine(a).demote(&k, &d).unwrap();
        assert!(done.deliveries.iter().any(|d| matches!(d, osis_node::flows::Delivery::First { under, .. } if under.contains(&t))));
        let c = *done.commits.last().unwrap();
        if crash == "before carry_out" {
            drop(done);
        } else {
            carry(&mut net, a, done);
            assert_eq!(copies(&mut net, a, &tl, &c) == 0, crash == "while it waits", "{crash}: the copy waits only for T's rotation");
        }
        if crash != "none" {
            net.restart(a, 77);
        }
        net.set_online(a, true);
        for _ in 0..3 {
            net.run();
            net.advance(61_000);
        }
        // b2's new edge: K's new keyset goes under T anyway (a holder's keyset certificate)
        assert!(copy_at(&mut net, a, s0, &tl, &c, "roles.0"), "{crash}: the lowering's copy under T");
    }
}

// spec/permissions.md §2, §3 (a removal of an actor's edge goes under the labels holding the
// actor): K removed from T, its copy under K's label; a crash before carrying it out still
// places it once the node restarts.
#[test]
fn removal_copy_survives_a_crash_spec_permissions_3() {
    for crash in [false, true] {
        let mut net = Net::new();
        let (a, _, k, t) = holder_group(&mut net);
        let s1 = 1;
        let kl = net.engine(a).group_labels(&k).unwrap()[0].id;
        let d = osis_node::flows::Demotion { holder: k, new: None, retain: None };
        let done = net.engine(a).demote(&t, &d).unwrap();
        assert!(done.deliveries.iter().any(|d| matches!(d, osis_node::flows::Delivery::Removal { under, .. } if *under == k)));
        let c = *done.commits.last().unwrap();
        if crash {
            drop(done);
            net.restart(a, 77);
        } else {
            carry(&mut net, a, done);
        }
        for _ in 0..3 {
            net.run();
            net.advance(61_000);
        }
        assert!(copy_at(&mut net, a, s1, &kl, &c, "roles.0"), "crash {crash}: the removal's copy under K");
    }
}

// spec/permissions.md §7, §4 (verifiers of L's commits need its card): a crash before carrying
// out a link's creation still places L's card under K's label once the node restarts.
#[test]
fn link_card_survives_a_crash_spec_permissions_7() {
    use osis_node::Mutation;
    for crash in [false, true] {
        let mut net = Net::bare();
        let (s0, s1) = (net.add_host(), net.add_host());
        let a = net.node(30, &[s0, s1]);
        let home = vec![net.address(s0)];
        let (pa, done) = net.engine(a).create_account(&home).unwrap();
        carry(&mut net, a, done);
        net.run();
        let e = net.engine(a);
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, pa.account);
        m.set(t, &ct::GROUP, &ct::Group::default()).unwrap();
        e.commit(m).unwrap();
        let (_, acts) = net.sync(a).create_label(&t, home.clone()).unwrap();
        net.actions(a, acts);
        net.run();
        let spec = osis_node::flows::LinkSpec { target: t, role: Role::Read, until: None, hosts: vec![net.address(s1)], peers: Vec::new(), single_use: true };
        let (link, _, done) = net.engine(a).create_link(&pa.account, &spec).unwrap();
        let card = done.deliveries.iter().find_map(|d| if let osis_node::flows::Delivery::Certificate { commits, under } = d { (*under == link.k).then(|| commits[0]) } else { None }).unwrap();
        if crash {
            drop(done);
            net.restart(a, 77);
        } else {
            carry(&mut net, a, done);
        }
        for _ in 0..3 {
            net.run();
            net.advance(61_000);
        }
        assert!(copy_at(&mut net, a, s1, &link.k_label, &card, "created.0"), "crash {crash}: L's card under K");
    }
}

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Regression tests from the node-sync review (spec/sync.md §3, §5-§7; spec/crypto.md §4;
//! spec/commits.md §5; spec/permissions.md §3).

use crate::net::{hosted, hosted_nodes};
use crate::net;
use net::*;
use osis_commit::PurgeItem;
use osis_base::{Ak, Role, Tid, WallMs};
use osis_node::Mutation;
use osis_node::sync::{EntryKind, Event, SyncConfig};
use osis_schema::RawKey;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// Blob IDs node `n` knows under `l` holding commit `c`.
fn blobs_of(net: &mut Net, n: usize, l: &osis_base::LabelId, c: &osis_base::CommitId) -> Vec<osis_base::BlobId> {
    net.sync(n).entries(l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c)).map(|(id, _)| id).collect()
}

// spec/crypto.md §4, spec/permissions.md §3: a holder's `until` passes; before this node next
// wraps under the group's read epoch it rotates (flows' cascade), so the departed holder cannot
// read what comes after (and, online, has dropped what it had by itself, spec/permissions.md §2).
// spec/crypto.md §4 (encrypt under covering epoch), spec/permissions.md §3 (required rotation)
#[test]
fn rotates_before_wrapping_after_until_spec_crypto_4() {
    let (mut net, _host, [a, b, c], g, []) = hosted::<3, 0>(&[(1, Role::Write)], [], false);
    net.pair(c, a);
    let ct_ = net.tid(c);
    let until = WallMs(net.now() + 1_000);
    let done = net.engine(a).grant(&g, &ct_, &ct::Edge { role: Role::Read, until: Some(until), invite: None, tied: None }).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    for (_, pks) in net.sync(a).take_direct() {
        for p in pks {
            let _ = net.engine(c).ingest(&p.bytes, p.blobs);
        }
    }
    net.pair(a, c);
    let t = net.item(a, g, g, "before");
    net.run();
    assert_eq!(net.read(c, t), Some(s("before")));
    let n0 = net.engine(a).epochs(&g).unwrap().read.newest().unwrap().n();
    net.clock.advance(2_000);
    net.write(a, t, "after");
    net.run();
    let n1 = net.engine(a).epochs(&g).unwrap().read.newest().unwrap().n();
    assert!(n1 > n0, "rotated before wrapping: {n0} -> {n1}");
    assert_eq!(net.read(b, t), Some(s("after")));
    assert_eq!(net.read(c, t), None, "the departed reader dropped what it had and gets nothing new");
}

// spec/commits.md §5 (purge drops every copy): after a purge applied, a reader holds neither
// the purged body's key nor its ciphertext; a writer without the delete key deletes it at the
// host by delete key.
#[test]
fn purge_leaves_no_copy_spec_commits_5() {
    let (mut net, host, [a, b, r], _g, [t]) = hosted::<3, 1>(&[(1, Role::Write), (2, Role::Read)], ["x"], false);
    net.keep(a, t, &[("t:gone.0", PURGE)]);
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("secret")).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let ids = blobs_of(&mut net, r, &l, &c);
    assert!(!ids.is_empty() && ids.iter().all(|id| net.sync(r).holds_blob(id)));
    // the admin is away: the writer purges, and deletes by delete key
    net.set_online(a, false);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: Ak::new(GONE.ak()).unwrap() });
    m.remove_aspect(t, &GONE).unwrap();
    net.engine(b).commit(m).unwrap();
    net.run();
    net.run();
    net.trace(&[b, r]);
    for id in &ids {
        assert!(!net.sync(r).holds_blob(id), "the reader keeps no key or ciphertext");
        assert!(!net.host_ids(host, &l).contains(id), "deleted at the host by delete key");
    }
    let gone = Ak::new(GONE.ak()).unwrap();
    assert_eq!(net.engine(r).get(&t, &gone).unwrap(), None);
}

// spec/sync.md §6 (a must-not-hold blob holds nothing): writer a purges one delta of commit c
// whose two-delta blob p is under the label; a's rewrite q goes up in that pass and is kept, also
// once writer b (offline through the purge, p was its body) is back and applies the purge.
#[test]
fn purged_superset_holds_nothing_spec_sync_6() {
    let (mut net, host, [a, b], _g, [t, t2]) = hosted::<2, 2>(&[(1, Role::Write)], ["x", "y"], false);
    net.keep(a, t, &[("t:gone.0", PURGE)]);
    let gone = Ak::new(GONE.ak()).unwrap();
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("secret")).unwrap();
    m.set(t2, &GONE, &s("kept")).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let p = blobs_of(&mut net, a, &l, &c);
    assert_eq!(p.len(), 1);
    assert_eq!(blobs_of(&mut net, b, &l, &c), p, "b holds p");
    net.set_online(b, false);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: gone.clone() });
    m.remove_aspect(t, &GONE).unwrap();
    net.engine(a).commit(m).unwrap();
    net.feed(a, Event::Local);
    net.settle(200_000);
    let q: Vec<_> = blobs_of(&mut net, a, &l, &c).into_iter().filter(|id| !p.contains(id)).collect();
    assert_eq!(q.len(), 1, "a's rewrite placed");
    let ids = net.host_ids(host, &l);
    assert!(ids.contains(&q[0]), "q uploaded at once");
    net.run();
    net.run();
    net.set_online(b, true);
    // past the redial pause
    net.advance(6_000);
    net.run();
    net.trace(&[a, b]);
    let ids = net.host_ids(host, &l);
    assert!(!ids.contains(&p[0]), "p deleted once carried");
    assert!(ids.contains(&q[0]), "q kept");
    assert_eq!(net.engine(b).get(&t2, &gone).unwrap(), Some(s("kept")));
    assert_eq!(net.engine(b).get(&t, &gone).unwrap(), None);
}

// spec/sync.md §7 (a body with live writes leaves only while a carrier stays): writer a purges
// one delta of commit c whose two-delta blob p also holds a live write; a's rewrite q is lost on
// the way, so p stays (and the live write with it) until q is at the host.
#[test]
fn purged_body_waits_for_its_rewrite_spec_sync_7() {
    let (mut net, host, [a, b], _g, [t, t2]) = hosted::<2, 2>(&[(1, Role::Write)], ["x", "y"], false);
    net.keep(a, t, &[("t:gone.0", PURGE)]);
    let gone = Ak::new(GONE.ak()).unwrap();
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("secret")).unwrap();
    m.set(t2, &GONE, &s("kept")).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let p = blobs_of(&mut net, a, &l, &c);
    assert_eq!(p.len(), 1);
    net.lose_uploads.insert(a);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: gone.clone() });
    m.remove_aspect(t, &GONE).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    net.run();
    let q: Vec<_> = blobs_of(&mut net, a, &l, &c).into_iter().filter(|id| !p.contains(id)).collect();
    assert_eq!(q.len(), 1, "a's rewrite placed");
    let ids = net.host_ids(host, &l);
    assert!(!ids.contains(&q[0]), "q lost on the way");
    assert!(ids.contains(&p[0]), "p waits for its carrier");
    net.lose_uploads.clear();
    // past the resend pause
    net.advance(60_000);
    net.run();
    net.trace(&[a, b]);
    let ids = net.host_ids(host, &l);
    assert!(ids.contains(&q[0]), "q uploaded again");
    assert!(!ids.contains(&p[0]), "p deleted once carried");
    assert_eq!(net.engine(b).get(&t2, &gone).unwrap(), Some(s("kept")));
    assert_eq!(net.engine(b).get(&t, &gone).unwrap(), None);
}

// spec/sync.md §7 (a rewrite the label refuses for its cap goes up again replacing the purged
// body), §5 (Replace), spec/requirements.md (purge is prompt): as above, but the label is at its
// entry cap, so a's rewrite q is refused (code 12); q goes up again naming p as replaced, and the
// host admits it in p's room and removes p in one step: after every hop the host holds p or
// q (the kept live write is never absent), and ends with q only.
#[test]
fn purged_body_leaves_full_label_spec_sync_7() {
    let (mut net, host, [a, b], _g, [t, t2]) = hosted::<2, 2>(&[(1, Role::Write)], ["x", "y"], false);
    net.keep(a, t, &[("t:gone.0", PURGE)]);
    let gone = Ak::new(GONE.ak()).unwrap();
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("secret")).unwrap();
    m.set(t2, &GONE, &s("kept")).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    net.advance(60_000);
    let l = net.label(a);
    let p = blobs_of(&mut net, a, &l, &c);
    assert_eq!(p.len(), 1);
    let full = net.host_ids(host, &l).len() as u64;
    net.restart_host_with(host, osis_host::HostPolicy { cap_entries: full, ..osis_host::HostPolicy::default() });
    net.run();
    // past the redial pause
    net.advance(66_000);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: gone.clone() });
    m.remove_aspect(t, &GONE).unwrap();
    net.engine(a).commit(m).unwrap();
    net.feed(a, Event::Local);
    let (up, del) = (net.sent_kinds.get(&10).copied().unwrap_or(0), net.sent_kinds.get(&14).copied().unwrap_or(0));
    for _ in 0..200 {
        net.round();
        let ids = net.host_ids(host, &l);
        let q: Vec<_> = blobs_of(&mut net, a, &l, &c).into_iter().filter(|id| !p.contains(id)).collect();
        assert!(ids.contains(&p[0]) || q.iter().any(|x| ids.contains(x)), "neither p nor its rewrite at the host");
    }
    net.run();
    net.trace(&[a, b]);
    let q: Vec<_> = blobs_of(&mut net, a, &l, &c).into_iter().filter(|id| !p.contains(id)).collect();
    assert_eq!(q.len(), 1, "a's rewrite placed");
    let ids = net.host_ids(host, &l);
    assert!(!ids.contains(&p[0]), "p deleted though its rewrite was refused");
    assert!(ids.contains(&q[0]), "q uploaded in the room p freed");
    assert!(net.sent_kinds.get(&10).copied().unwrap_or(0) > up, "uploads sent");
    assert_eq!(net.sent_kinds.get(&14).copied().unwrap_or(0), del, "p went by the replacing upload, no Delete");
    assert_eq!(ids.len() as u64, full, "the label stays full (the purge request itself waits for space)");
}

// spec/permissions.md §3 (complete pass): a role commit pushed to a subscribed node ends
// with a pass: `complete_pass` holds without another Sync.
#[test]
fn complete_pass_after_push_spec_permissions_3() {
    let (mut net, host, [a, b]) = hosted_nodes::<2>();
    let c = net.node(3, &[]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    assert!(net.sync(b).complete_pass(&g));
    net.pair(c, a);
    let ct_ = net.tid(c);
    net.grant(a, g, ct_, Role::Read);
    net.feed(a, Event::Local);
    net.settle(100_000);
    assert!(net.engine(b).roster(&g).contains_key(&ct_), "arrived by push");
    assert!(net.sync(b).complete_pass(&g), "the push run counts as a pass end");
}

// spec/permissions.md §3 (complete pass): a role commit applied from outside a quiet label's
// host stream (handed over directly, as an inbox or a Deposit item brings one) after the label's
// last push: the node asks the host for a pass end, so `complete_pass` holds within one round
// trip, with no push and no time passing.
#[test]
fn complete_pass_after_role_commit_from_elsewhere_spec_permissions_3() {
    let (mut net, a, b, c, g) = quiet_label();
    from_elsewhere(&mut net, a, b, c, g, Role::Write);
    assert!(!net.sync(b).complete_pass(&g), "no pass end after it yet");
    // the request reaches the host, its reply comes back
    net.round();
    net.round();
    assert!(net.sync(b).complete_pass(&g), "a pass end within one round trip");
}

// spec/permissions.md §3 (complete pass): a Sync asked before a role commit from elsewhere
// applied ends no pass after it (the host may have answered before it held what came before
// the commit there): its end asks again, and the pass ends a round trip later.
#[test]
fn sync_sent_before_role_commit_ends_no_pass_after_it_spec_permissions_3() {
    let (mut net, a, b, c, g) = quiet_label();
    from_elsewhere(&mut net, a, b, c, g, Role::Write);
    // the ask reaches the host; its answer is on its way when the next commit applies
    net.round();
    from_elsewhere(&mut net, a, b, c, g, Role::Admin);
    net.round();
    assert!(!net.sync(b).complete_pass(&g), "the answer to a Sync sent before the commit");
    net.round();
    net.round();
    assert!(net.sync(b).complete_pass(&g), "the Sync asked after it");
}

/// Reader `b` of `a`'s group `g` at one host, every pass ended; `a` offline.
fn quiet_label() -> (Net, usize, usize, usize, Tid) {
    let (mut net, _host, [a, b, c], g, []) = hosted::<3, 0>(&[(1, Role::Read), (2, Role::Read)], [], true);
    assert!(net.sync(b).complete_pass(&g));
    net.set_online(a, false);
    net.run();
    (net, a, b, c, g)
}

/// `a` gives `c` `role` on `g`; `b` applies it from `a` directly, not by the host.
fn from_elsewhere(net: &mut Net, a: usize, b: usize, c: usize, g: Tid, role: Role) {
    let tc = net.tid(c);
    let edge = ct::Edge { role, until: None, invite: None, tied: None };
    let done = net.engine(a).grant(&g, &tc, &edge).unwrap();
    // b places it under the label too; that copy's push would end a pass of its own
    net.lose_deposits.extend(done.commits);
    net.pair(a, b);
    net.feed(b, Event::Local);
    assert_eq!(net.engine(b).roster(&g).get(&tc).map(|e| e.role), Some(role), "applied from elsewhere");
}

// spec/sync.md §6-§7 (positive uncovered): a compactor deletes covered bodies; a writer that
// has not fetched the snapshot yet treats them as may-hold and re-uploads nothing.
#[test]
fn no_reupload_ping_pong_spec_sync_6() {
    let (mut net, host, [a]) = hosted_nodes::<1>();
    let b = net.add_node(2, SyncConfig { hosts: vec![net.address(host)], inline_limit: 0, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "v1");
    net.write(a, t, "v2");
    net.write(a, t, "v3");
    net.run();
    let l = net.label(a);
    let acts = net.sync(a).compact(&t, &Ak::new(REG.ak()).unwrap()).unwrap();
    net.actions(a, acts);
    net.run();
    net.run();
    let n1 = net.host_ids(host, &l);
    net.advance(70_000);
    net.advance(70_000);
    net.trace(&[a, b]);
    assert_eq!(net.host_ids(host, &l), n1, "settled: nothing re-uploaded, nothing deleted again");
    assert_eq!(net.read(b, t), Some(s("v3")));
}

// spec/sync.md §3 (one blob per commit, entitlement), spec/commits.md §4 (pending on
// `created.0` only for things whose deltas the node holds or syncs): one commit touching a
// shared thing and a private one goes under the group's label as one blob; a holder opens
// only the shared section and applies it.
#[test]
fn private_and_shared_split_spec_sync_3() {
    let (mut net, _host, [a, b], _g, [t]) = hosted::<2, 1>(&[(1, Role::Read)], ["shared"], false);
    let at = net.tid(a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let p = e.new_thing(&mut m, at);
    m.set(p, &REG, &s("private")).unwrap();
    m.set(t, &REG, &s("shared 2")).unwrap();
    let c = e.commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let h = net.engine(a).header(&c).unwrap();
    let mut seen = false;
    for (_, k) in net.sync(b).entries(&l) {
        if let EntryKind::Commit { commit, parts, ais, .. } = k
            && commit == c
        {
            seen = true;
            assert!(parts.iter().all(|ai| h.aspects[*ai].tid == t), "only the shared deltas open: {parts:?}");
            assert!(ais.iter().any(|ai| h.aspects[*ai].tid != t), "the private section rides sealed: {ais:?}");
        }
    }
    assert!(seen);
    // the holder applies the shared delta and never sees the private one
    assert!(net.engine(b).pending().is_empty(), "{:?}", net.engine(b).pending());
    assert_eq!(net.read(b, t), Some(s("shared 2")));
    assert_eq!(net.read(b, p), None);
    assert!(!net.engine(b).knows(&p));
}

// spec/permissions.md §3 (complete pass): a pass from before going offline still counts (it
// proves what the host held then); a remote role commit received while offline (here
// directly) restarts it.
#[test]
fn complete_pass_survives_disconnect_spec_permissions_3() {
    let (mut net, host, [a, b]) = hosted_nodes::<2>();
    let c = net.node(3, &[]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    assert!(net.sync(b).complete_pass(&g));
    net.blocked.insert((b, host));
    net.drop_link(b, host);
    net.advance(61_000);
    assert!(net.sync(b).complete_pass(&g), "the pass before going offline still counts");
    net.pair(c, a);
    let ct_ = net.tid(c);
    net.grant(a, g, ct_, Role::Read);
    net.pair(a, b);
    net.feed(b, Event::Local);
    net.run();
    assert!(net.engine(b).roster(&g).contains_key(&ct_), "arrived directly");
    assert!(!net.sync(b).complete_pass(&g), "a remote role commit restarts it");
    net.blocked.remove(&(b, host));
    net.advance(61_000);
    net.settle(100_000);
    assert!(net.sync(b).complete_pass(&g), "a pass after reconnecting completes it");
}

// spec/commits.md §5 (purge drops every copy), spec/requirements.md Deletion (purge is prompt):
// a crash after the purging commit lands and before node-sync forgets the purged body's blob
// key and ciphertext leaves neither behind once the node restarts, online or not.
#[test]
fn purge_crash_before_sync_forget_leaves_no_copy_spec_commits_5() {
    for crash in [false, true] {
        let mut net = Net::new();
        let host = net.add_host();
        let a = net.node(1, &[host]);
        let b = net.node(2, &[host]);
        let g = net.group(a, &[(b, Role::Write)], &[host]);
        let t = net.item(a, g, g, "x");
        net.keep(a, t, &[("t:gone.0", PURGE)]);
        let mut m = Mutation::new();
        m.set(t, &GONE, &s("secret")).unwrap();
        let c = net.engine(a).commit(m).unwrap().unwrap();
        net.run();
        let l = net.label(a);
        let ids = blobs_of(&mut net, b, &l, &c);
        assert!(!ids.is_empty() && ids.iter().all(|id| net.sync(b).holds_blob(id)));
        net.set_online(b, false);
        let mut m = Mutation::new();
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: Ak::new(GONE.ak()).unwrap() });
        m.remove_aspect(t, &GONE).unwrap();
        net.engine(b).commit(m).unwrap();
        if crash {
            net.restart(b, 77);
        }
        for _ in 0..3 {
            net.sync(b).handle(Event::Local);
            net.sync(b).handle(Event::Tick);
        }
        for id in &ids {
            assert!(!net.sync(b).holds_blob(id), "crash {crash}: the purger keeps the purged body's key or ciphertext");
            assert!(net.sync(b).entry_meta(&l, id).is_none_or(|(w, _)| w == [0; osis_crypto::WRAP_LEN]), "crash {crash}: the purger keeps the purged body's wrap");
        }
    }
}

// spec/permissions.md §3 (a node that learns it lost read access drops it; a removal goes under
// the labels the removed party could read): a node leaving a group offline, then crashing
// before or after carrying the self-removal out, still places the removal and drops the
// group's secrets and content once back online.
#[test]
fn self_removal_crash_still_drops_spec_permissions_3() {
    for crash in ["none", "before carry_out", "after carry_out"] {
        let mut net = Net::new();
        let host = net.add_host();
        let a = net.node(1, &[host]);
        let b = net.node(2, &[host]);
        let g = net.group(a, &[(b, Role::Write)], &[host]);
        let t = net.item(a, g, g, "marker");
        net.run();
        assert_eq!(net.read(b, t), Some(s("marker")));
        net.set_online(b, false);
        let bt = net.tid(b);
        let d = osis_node::flows::Demotion { holder: bt, new: None, retain: None };
        let done = net.engine(b).demote(&g, &d).unwrap();
        assert!(done.drop_lost);
        if crash != "before carry_out" {
            let acts = net.sync(b).carry_out(done).unwrap();
            net.actions(b, acts);
        }
        if crash != "none" {
            net.restart(b, 77);
        }
        net.set_online(b, true);
        for _ in 0..3 {
            net.run();
            net.advance(61_000);
        }
        assert!(!net.engine(a).roster(&g).contains_key(&bt), "crash {crash}: the removal reached the admin");
        assert!(net.engine(b).epochs(&g).is_none_or(|e| e.read.held().next().is_none()), "crash {crash}: the leaver keeps the group's secrets");
        assert_eq!(net.read(b, t), None, "crash {crash}: the leaver keeps the group's content");
    }
}

// spec/permissions.md §3 (a self-removal drops once placed): a node leaving a group offline
// that then applies a received role change on the group (the lost-access trigger runs) keeps
// the group, and shows it leaving, while the host refuses its uploads; once the host takes the
// removal, the admin learns it and the leaver drops the group.
#[test]
fn self_removal_kept_by_trigger_until_placed_spec_permissions_3() {
    let (mut net, host, [a, b, c], g, [t]) = hosted::<3, 1>(&[(1, Role::Write)], ["marker"], true);
    assert_eq!(net.read(b, t), Some(s("marker")));
    net.set_online(b, false);
    let (bt, ct_) = (net.tid(b), net.tid(c));
    let d = osis_node::flows::Demotion { holder: bt, new: None, retain: None };
    let done = net.engine(b).demote(&g, &d).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    // the admin adds someone meanwhile: b applies a received role commit on g
    net.pair(c, a);
    net.grant(a, g, ct_, Role::Read);
    net.feed(a, Event::Local);
    net.run();
    net.restart_host_with(host, osis_host::HostPolicy { cap_entries: 0, ..osis_host::HostPolicy::default() });
    net.set_online(b, true);
    for _ in 0..3 {
        net.run();
        net.advance(66_000);
    }
    assert!(net.engine(b).roster(&g).contains_key(&ct_), "b applied the admin's commit");
    assert!(net.engine(a).roster(&g).contains_key(&bt), "the host refused b's removal");
    assert_eq!(net.read(b, t), Some(s("marker")), "b keeps the group until its removal is placed");
    assert!(net.sync(b).label_status().iter().any(|l| l.group == g && l.leaving), "b shows the group leaving");
    net.restart_host_with(host, osis_host::HostPolicy::default());
    for _ in 0..3 {
        net.run();
        net.advance(66_000);
    }
    assert!(!net.engine(a).roster(&g).contains_key(&bt), "the removal reached the admin");
    assert!(net.engine(b).epochs(&g).is_none_or(|e| e.read.held().next().is_none()), "the leaver keeps the group's secrets");
    assert_eq!(net.read(b, t), None, "the leaver keeps the group's content");
    assert!(net.sync(b).leaving().next().is_none());
}

// spec/permissions.md §3 (a self-removal drops once placed): leaving two groups, each drops
// once its own removal is placed; one whose host refuses it holds back nothing else.
#[test]
fn self_removals_drop_per_group_spec_permissions_3() {
    let mut net = Net::new();
    let h1 = net.add_host();
    let h2 = net.add_host();
    let a = net.node(1, &[h1, h2]);
    let b = net.node(2, &[h1, h2]);
    let g1 = net.group(a, &[(b, Role::Write)], &[h1]);
    let g2 = net.group(a, &[(b, Role::Write)], &[h2]);
    let t1 = net.item(a, g1, g1, "one");
    let t2 = net.item(a, g2, g2, "two");
    net.run();
    assert_eq!((net.read(b, t1), net.read(b, t2)), (Some(s("one")), Some(s("two"))));
    net.set_online(b, false);
    let bt = net.tid(b);
    for g in [g1, g2] {
        let d = osis_node::flows::Demotion { holder: bt, new: None, retain: None };
        let done = net.engine(b).demote(&g, &d).unwrap();
        let acts = net.sync(b).carry_out(done).unwrap();
        net.actions(b, acts);
    }
    net.restart_host_with(h2, osis_host::HostPolicy { cap_entries: 0, ..osis_host::HostPolicy::default() });
    net.set_online(b, true);
    for _ in 0..3 {
        net.run();
        net.advance(66_000);
    }
    assert!(!net.engine(a).roster(&g1).contains_key(&bt) && net.engine(a).roster(&g2).contains_key(&bt));
    assert_eq!(net.read(b, t1), None, "g1's removal is placed: dropped");
    assert_eq!(net.read(b, t2), Some(s("two")), "g2's is refused: kept");
    let status = net.sync(b).label_status();
    assert!(status.iter().any(|l| l.group == g2 && l.leaving) && !status.iter().any(|l| l.group == g1 && l.leaving));
}

// spec/permissions.md §3 (a self-removal drops once placed): an actor S both left groups hold
// (a subgroup of each) is read through either; leaving one keeps S, leaving both drops S only
// once both removals are placed.
#[test]
fn self_removal_shared_subgroup_spec_permissions_3() {
    let mut net = Net::new();
    let h1 = net.add_host();
    let h2 = net.add_host();
    let a = net.node(1, &[h1, h2]);
    let b = net.node(2, &[h1, h2]);
    let g1 = net.group_seeded(a, &[(b, Role::Write)], vec![net.hosts[h1].address.clone()], 1);
    let g2 = net.group_seeded(a, &[(b, Role::Write)], vec![net.hosts[h2].address.clone()], 2);
    let at = net.tid(a);
    // S: listed in both groups, each a reader of it, with secrets of its own
    let sub = net.item(a, g1, at, "s");
    let e = net.engine(a);
    let mut items = e.get_typed(&g2, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.insert(sub);
    let mut m = Mutation::new();
    m.set(g2, &ct::GROUP, &items).unwrap();
    e.commit(m).unwrap();
    // bare edges: the rotation below boxes both holders before any pass (a grant by hand)
    set_edge(e, sub, g1, Role::Read);
    set_edge(e, sub, g2, Role::Read);
    let rs = recipients_of(e, &[(at, Role::Admin), (g1, Role::Read), (g2, Role::Read)]);
    rotation(e, sub, &rs, 3, false);
    net.write(a, sub, "three");
    let t1 = net.item(a, g1, g1, "one");
    let t2 = net.item(a, g2, g2, "two");
    let t3 = sub;
    net.feed(a, Event::Local);
    for _ in 0..3 {
        net.run();
        net.advance(66_000);
    }
    assert_eq!((net.read(b, t1), net.read(b, t2), net.read(b, t3)), (Some(s("one")), Some(s("two")), Some(s("three"))));
    let bt = net.tid(b);
    net.set_online(b, false);
    let leave = |net: &mut Net, g| {
        let d = osis_node::flows::Demotion { holder: bt, new: None, retain: None };
        let done = net.engine(b).demote(&g, &d).unwrap();
        let acts = net.sync(b).carry_out(done).unwrap();
        net.actions(b, acts);
    };
    leave(&mut net, g1);
    net.set_online(b, true);
    for _ in 0..3 {
        net.run();
        net.advance(66_000);
    }
    assert!(!net.engine(a).roster(&g1).contains_key(&bt));
    assert_eq!((net.read(b, t1), net.read(b, t2), net.read(b, t3)), (None, Some(s("two")), Some(s("three"))), "S still read through g2");
    net.set_online(b, false);
    leave(&mut net, g2);
    net.restart_host_with(h2, osis_host::HostPolicy { cap_entries: 0, ..osis_host::HostPolicy::default() });
    net.set_online(b, true);
    for _ in 0..3 {
        net.run();
        net.advance(66_000);
    }
    assert!(net.engine(a).roster(&g2).contains_key(&bt), "h2 refused the removal");
    assert_eq!((net.read(b, t2), net.read(b, t3)), (Some(s("two")), Some(s("three"))), "S waits for g2's removal");
    net.restart_host_with(h2, osis_host::HostPolicy::default());
    for _ in 0..3 {
        net.run();
        net.advance(66_000);
    }
    assert!(!net.engine(a).roster(&g2).contains_key(&bt));
    assert_eq!((net.read(b, t2), net.read(b, t3)), (None, None), "both placed: all dropped");
    assert!(net.sync(b).leaving().next().is_none());
}

// spec/sync.md §7 (two blobs of one commit with the same delta set: the higher blob ID goes):
// writers a and b both hold commit c while away, and each places its own encryption of its body
// when back, so the host holds two; the admin deletes the higher one.
#[test]
fn duplicate_encryptions_higher_goes_spec_sync_7() {
    let (mut net, host, [a, b], _g, [t]) = hosted::<2, 1>(&[(1, Role::Write)], ["x"], true);
    // neither hears from the host meanwhile
    net.held_to.extend([a, b]);
    let c = net.write(a, t, "y");
    let pk = net.engine(a).package(&c).unwrap().unwrap();
    net.engine(b).ingest(&pk.bytes, pk.blobs).unwrap();
    net.feed(a, Event::Local);
    net.feed(b, Event::Local);
    // past b's relay wait for another's commit
    net.advance(60_000);
    net.settle(200_000);
    let l = net.label(a);
    let mut both: Vec<_> = blobs_of(&mut net, a, &l, &c);
    both.extend(blobs_of(&mut net, b, &l, &c));
    both.sort();
    both.dedup();
    assert!(both.iter().all(|id| net.host_ids(host, &l).contains(id)));
    assert_eq!(both.len(), 2, "each placed its own encryption");
    net.release();
    net.run();
    net.advance(60_000);
    net.run();
    net.trace(&[a, b]);
    let ids = net.host_ids(host, &l);
    assert!(ids.contains(&both[0]), "the lower kept");
    assert!(!ids.contains(&both[1]), "the higher deleted");
    assert_eq!(net.read(b, t), Some(s("y")));
    // and neither places it again
    for _ in 0..3 {
        net.advance(60_000);
        net.run();
    }
    let ids = net.host_ids(host, &l);
    let mut now: Vec<_> = blobs_of(&mut net, a, &l, &c);
    now.extend(blobs_of(&mut net, b, &l, &c));
    now.retain(|id| ids.contains(id));
    now.sort();
    now.dedup();
    assert_eq!(now, vec![both[0]], "one encryption stays");
}

// spec/sync.md §6 (a strict subset is must-not-hold beside a superset under the label, judged
// per host): writer a purges one delta of commit c, so h1 holds its rewrite q and no longer p;
// b, back without hearing of the purge commit, still sees p at h2. At h1, q is no strict subset
// for b (p is not there), so b keeps it, its own uploads (p again) failing meanwhile.
#[test]
fn strict_subset_needs_superset_at_that_host_spec_sync_6() {
    let mut net = Net::new();
    let h1 = net.add_host();
    let h2 = net.add_host();
    let a = net.node(1, &[h1, h2]);
    let b = net.node(2, &[h1, h2]);
    let g = net.group(a, &[(b, Role::Write)], &[h1, h2]);
    let t = net.item(a, g, g, "x");
    net.keep(a, t, &[("t:gone.0", PURGE)]);
    let t2 = net.item(a, g, g, "y");
    let gone = Ak::new(GONE.ak()).unwrap();
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("secret")).unwrap();
    m.set(t2, &GONE, &s("kept")).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let p = blobs_of(&mut net, a, &l, &c);
    assert_eq!(p.len(), 1);
    assert!(net.host_ids(h1, &l).contains(&p[0]) && net.host_ids(h2, &l).contains(&p[0]));
    // a reaches h1 only, b is away
    net.drop_link(a, h2);
    net.blocked.insert((a, h2));
    net.set_online(b, false);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: gone.clone() });
    m.remove_aspect(t, &GONE).unwrap();
    let pc = net.engine(a).commit(m).unwrap().unwrap();
    net.feed(a, Event::Local);
    // b never hears of the purge commit, nor of a's re-snapshot after it (spec/commits.md §5
    // Purge), which carries it
    let mut hide = blobs_of(&mut net, a, &l, &pc);
    assert!(!hide.is_empty());
    let e = net.engine(a);
    let snaps: Vec<_> = e.commit_ids().into_iter().filter(|x| e.header(x).is_some_and(|h| h.kind.is_compaction() && h.aspects.iter().any(|y| y.tid == t && y.ak == gone))).collect();
    for x in snaps {
        hide.extend(blobs_of(&mut net, a, &l, &x));
    }
    net.hide_blobs.insert(b, hide.into_iter().collect());
    net.settle(200_000);
    let q: Vec<_> = blobs_of(&mut net, a, &l, &c).into_iter().filter(|id| !p.contains(id)).collect();
    assert_eq!(q.len(), 1, "a's rewrite placed");
    let ids = net.host_ids(h1, &l);
    assert!(ids.contains(&q[0]) && !ids.contains(&p[0]), "h1 holds q, not p");
    // b back, its uploads failing
    net.lose_uploads.insert(b);
    net.set_online(b, true);
    // past the redial pause
    net.advance(6_000);
    net.run();
    assert_eq!(net.engine(b).get(&t, &gone).unwrap(), Some(s("secret")), "b has not applied the purge");
    for _ in 0..3 {
        net.advance(60_000);
        net.run();
    }
    net.trace(&[a, b]);
    assert!(net.host_ids(h1, &l).contains(&q[0]), "q kept at h1: p is at h2 only");
}

// spec/sync.md §6 (sim host_loses_data once, seed 41): a host's data lost, a node restarted over its
// disk: every must-hold body goes up again.
#[test]
fn wiped_host_gets_bodies_back_from_restarted_node_spec_sync_6() {
    let (mut net, host, [a], _g, [t]) = hosted::<1, 1>(&[], ["v1"], false);
    let c = net.write(a, t, "v2");
    net.run();
    let l = net.label(a);
    let held = blobs_of(&mut net, a, &l, &c);
    assert!(!held.is_empty() && held.iter().all(|id| net.host_ids(host, &l).contains(id)));
    net.set_online(a, false);
    net.wipe_host(host);
    net.restart(a, 7);
    net.set_online(a, true);
    net.run();
    net.advance(61_000);
    net.run();
    let again = blobs_of(&mut net, a, &l, &c);
    assert!(!again.is_empty() && again.iter().all(|id| net.host_ids(host, &l).contains(id)), "{again:?}");
}

// spec/sync.md §6 (no upload of a body a delete removed, keyed per body): commit c writes a plain
// register and a purge-on-replace one, two bodies; both are overwritten, the second's body is
// deleted past its bound, and the host is wiped: the first's body (must-hold, uncovered) goes up
// again though another body of c was deleted
#[test]
fn deleted_body_withholds_only_itself_spec_sync_6() {
    let (mut net, host, [a], _g, [t]) = hosted::<1, 1>(&[], ["v1"], false);
    net.keep(a, t, &[("t:gone.0", PURGE)]);
    let both = |net: &mut Net, v: &str| {
        let mut m = Mutation::new();
        m.set(t, &REG, &s(v)).unwrap();
        m.set(t, &GONE, &s(v)).unwrap();
        let c = net.engine(a).commit(m).unwrap().unwrap();
        net.run();
        c
    };
    let c = both(&mut net, "x");
    let l = net.label(a);
    assert_eq!(blobs_of(&mut net, a, &l, &c).len(), 1, "one blob, two retention classes");
    net.advance(1_000);
    both(&mut net, "y");
    net.advance(osis_base::format::MAX_DRIFT_MS + 60_000);
    net.run();
    let reg_body = |net: &mut Net| {
        let h = net.engine(a).header(&c).unwrap();
        net.sync(a).entries(&l).into_iter().filter_map(|(id, k)| match k {
            EntryKind::Commit { commit, parts, .. } if commit == c && parts.iter().all(|ai| h.aspects[*ai].ak.as_str() == "t:reg.0") => Some(id),
            _ => None,
        }).collect::<Vec<_>>()
    };
    assert_eq!(blobs_of(&mut net, a, &l, &c).len(), 1, "the purge-on-replace body deleted");
    assert_eq!(reg_body(&mut net).len(), 1);
    net.set_online(a, false);
    net.wipe_host(host);
    net.set_online(a, true);
    net.run();
    net.advance(120_000);
    net.run();
    let at_host = net.host_ids(host, &l);
    assert!(reg_body(&mut net).iter().any(|id| at_host.contains(id)), "the register's body uploaded again");
}

fn carry(net: &mut Net, n: usize, done: osis_node::flows::Done) {
    let acts = net.sync(n).carry_out(done).unwrap();
    net.actions(n, acts);
}

/// Node `n`'s account, made on `home`, synced.
fn account(net: &mut Net, n: usize, home: &[osis_label::Address]) -> osis_base::Tid {
    let (p, done) = net.engine(n).create_account(home).unwrap();
    carry(net, n, done);
    p.account
}

/// Node `x`'s account joins by `link`: follows K's label by the link key, redeems, drops the key.
fn join(net: &mut Net, x: usize, px: osis_base::Tid, link: &osis_label::ShareLink) {
    let held = net.engine(x).hold_key_actor(link.seed.clone()).unwrap();
    let acts = net.sync(x).follow(held, link.k, link.k_label, link.hosts.clone());
    net.actions(x, acts);
    net.run();
    let done = net.engine(x).redeem(link, &px, false).unwrap();
    net.engine(x).drop_key_actor(&held);
    carry(net, x, done);
    net.run();
}

// spec/crypto.md §4 (Boxes: a node rotates a role only holding every current epoch's secret;
// Holder actors, Carried), spec/permissions.md §7: a thing C synced as a group of itself and
// shared by a write link; one of two joiners leaves K. The sharer and the other joiner each
// rotate K (a fork) and then C (its box to K stale); the joiner, reading C through K, gets the
// sharer's fork of C only once the K keyset its box names arrives. Merging before that would
// supersede an epoch it cannot read (nothing re-seals a superseded one), lose the sharer's
// write key for the head and leave its own commits unuploadable for good: the thing splits with
// both sides synced. With the rule, the joiner waits for the secret, merges holding every fork,
// and the sharer reads its later write.
#[test]
fn link_joiner_leave_forks_converge_spec_crypto_4() {
    let mut net = Net::bare();
    let host = net.add_host();
    let home = vec![net.address(host)];
    let a = net.node(40, &[host]);
    let b = net.node(41, &[host]);
    let d = net.node(42, &[host]);
    let pa = account(&mut net, a, &home);
    let pb = account(&mut net, b, &home);
    let pd = account(&mut net, d, &home);
    net.run();
    // a plain thing with content, synced as a group of itself (`Osis::sync`: own secrets, a label)
    let e = net.engine(a);
    let mut m = Mutation::new();
    let c = e.new_thing(&mut m, pa);
    m.set(c, &REG, &s("hi")).unwrap();
    e.commit(m).unwrap();
    let done = net.engine(a).give_own_secrets(&c).unwrap();
    carry(&mut net, a, done);
    let (_, acts) = net.sync(a).create_label(&c, home.clone()).unwrap();
    net.actions(a, acts);
    net.run();
    let spec = osis_node::flows::LinkSpec { target: c, role: Role::Write, until: None, hosts: home.clone(), peers: Vec::new(), single_use: false };
    let (link, _, done) = net.engine(a).create_link(&pa, &spec).unwrap();
    carry(&mut net, a, done);
    net.run();
    join(&mut net, b, pb, &link);
    join(&mut net, d, pd, &link);
    assert_eq!(net.read(d, c), Some(s("hi")));
    // B leaves: its own grant is on K
    let done = net.engine(b).demote(&link.k, &osis_node::flows::Demotion { holder: pb, new: None, retain: None }).unwrap();
    carry(&mut net, b, done);
    net.run();
    net.write(d, c, "still here");
    net.run();
    assert_eq!(net.read(a, c), Some(s("still here")), "the sharer reads the joiner's write after the leave");
    net.write(a, c, "and back");
    net.run();
    assert_eq!(net.read(d, c), Some(s("and back")));
    for n in [a, d] {
        let ep = net.engine(n).epochs(&c).unwrap();
        for r in [Role::Read, Role::Write] {
            assert!(ep.role(r).holds_current(), "node {n}: {r:?} secrets whole");
        }
        let st: Vec<_> = net.sync(n).label_status().into_iter().filter(|x| x.group == c).collect();
        assert!(st.iter().all(|x| x.sources == 1 && x.idle == 1 && !x.stranded), "node {n}: {st:?}");
    }
    let (ea, ed) = (net.engine(a).epochs(&c).unwrap(), net.engine(d).epochs(&c).unwrap());
    assert_eq!(ea.read.current(), ed.read.current(), "one current read epoch at both");
}

// spec/sync.md §5 (reading without the head's read epoch: the pass counts as complete only
// once the node holds it), spec/permissions.md §4, spec/crypto.md §4 (Carried): R reads G
// through M (B, M's admin, reads G too). B removes C from M, rotating M; A re-seals G at M's new
// keyset and registers it while R has G open. R holds G's rotation (the epoch established) but
// not M's, withheld from it, so the box to M does not open and its claim (at that keyset) is
// refused: R is stranded at G, not synced, until M's keyset reaches it.
#[test]
fn no_secret_of_the_heads_read_epoch_is_stranded_spec_sync_5() {
    let (mut net, host, [a, b, r, c]) = hosted_nodes::<4>();
    let m = net.group_seeded(b, &[(r, Role::Read), (c, Role::Read)], vec![net.address(host)], 1);
    net.name_inbox_elsewhere(b, m);
    net.pair(b, a);
    // B reads G directly too, so it syncs G's label and places M's new keyset there for A
    let g = net.group_seeded(a, &[(b, Role::Read)], vec![net.address(host)], 2);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let done = net.engine(a).grant(&g, &m, &edge).unwrap();
    carry(&mut net, a, done);
    net.pair(a, r);
    net.pair(a, c);
    net.run();
    for _ in 0..2 {
        net.advance(31_000);
    }
    let t = net.item(a, g, g, "before");
    for _ in 0..2 {
        net.advance(31_000);
    }
    assert_eq!(net.read(r, t), Some(s("before")));
    let lg = net.group_labels(a).into_iter().find(|(x, _)| *x == g).unwrap().1.id;
    let lm = net.group_labels(b).into_iter().find(|(x, _)| *x == m).unwrap().1.id;
    let ct_ = net.tid(c);
    let done = net.engine(b).demote(&m, &osis_node::flows::Demotion { holder: ct_, new: None, retain: None }).unwrap();
    let rot_m = *done.commits.last().unwrap();
    carry(&mut net, b, done);
    // every copy of M's rotation commit (under M's label; B's and A's certificate copies under
    // G's) is kept from R: hidden as each is placed, a round before the host could push it
    let mut hide = |net: &mut Net| {
        let mut hidden: BTreeSet<osis_base::BlobId> = net.hide_blobs.remove(&r).unwrap_or_default();
        for (n, l) in [(b, lm), (b, lg), (a, lg)] {
            hidden.extend(blobs_of(net, n, &l, &rot_m));
        }
        net.hide_blobs.insert(r, hidden);
    };
    let rounds = |net: &mut Net, hide: &mut dyn FnMut(&mut Net)| {
        for _ in 0..8 {
            hide(net);
            net.tick(31_000);
            for n in 0..net.nodes.len() {
                net.feed(n, osis_node::sync::Event::Local);
            }
            while net.queue_len() > 0 {
                hide(net);
                net.round();
            }
        }
    };
    rounds(&mut net, &mut hide);
    let u = net.item(a, g, g, "after");
    rounds(&mut net, &mut hide);
    let g0 = net.engine(a).epochs(&g).unwrap().read.newest().unwrap();
    assert!(g0.n() > 1, "A re-sealed G at M's new keyset: {g0:?}");
    let ep = net.engine(r).epochs(&g).unwrap();
    assert!(ep.read.is_established(&g0) && ep.read.secret(&g0).is_none(), "R holds G's rotation, not its secret");
    let st = net.sync(r).label_status().into_iter().find(|x| x.group == g).unwrap();
    assert!(st.stranded, "no secret of the head's read epoch: {st:?}");
    assert_eq!(net.read(r, u), None);
    // M's keyset reaches R another way (the host's cursor has passed it): the box opens, R
    // reads under the head
    let pk = net.engine(b).package(&rot_m).unwrap().unwrap();
    net.engine(r).ingest(&pk.bytes, pk.blobs).unwrap();
    net.hide_blobs.remove(&r);
    for _ in 0..3 {
        net.advance(31_000);
    }
    let st = net.sync(r).label_status().into_iter().find(|x| x.group == g).unwrap();
    assert!(!st.stranded && st.sources == 1 && st.idle == 1, "{st:?}");
    assert_eq!(net.read(r, u), Some(s("after")));
}


// spec/sync.md §5 (reading without the head's read epoch): another admin removes two readers,
// so the host's head registers the second removal's epoch, whose rotation commit is wrapped
// under the first's (spec/crypto.md §5). The first rotation reaches this admin only after the
// second was listed, which opened under nothing then. A node then holding the first epoch but
// not the head's read epoch opens the second rotation, rather than counting itself stranded
// with it listed, and its writes leave it again (member_churn seeds 9, 9390).
#[test]
fn rotation_wrapped_under_epoch_learned_later_is_read_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    // every entry announced without its bytes: fetched only once its wrap opens
    let a = net.add_node(1, SyncConfig { hosts: vec![net.address(host)], inline_limit: 0, ..SyncConfig::default() });
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let d = net.node(4, &[host]);
    let g = net.group(a, &[(b, Role::Admin), (c, Role::Read), (d, Role::Read)], &[host]);
    let t = net.item(a, g, g, "before");
    net.run();
    let l = net.label(a);
    let n0 = net.engine(a).epochs(&g).unwrap().read.newest().unwrap().n();
    let remove = |net: &mut Net, x: usize| {
        let holder = net.tid(x);
        let done = net.engine(b).demote(&g, &osis_node::flows::Demotion { holder, new: None, retain: None }).unwrap();
        let c = done.commits.first().copied().unwrap();
        let acts = net.sync(b).carry_out(done).unwrap();
        net.actions(b, acts);
        c
    };
    let r1 = remove(&mut net, c);
    let held: Vec<osis_base::BlobId> = blobs_of(&mut net, b, &l, &r1);
    assert!(!held.is_empty());
    net.hold_blobs.extend(held);
    net.run();
    remove(&mut net, d);
    net.run();
    net.advance(61_000);
    assert!(net.engine(a).epochs(&g).unwrap().read.held().all(|(e, _)| e.n() <= n0), "a holds neither new epoch yet");
    net.release();
    net.run();
    net.advance(61_000);
    assert!(net.engine(a).epochs(&g).unwrap().read.held().any(|(e, _)| e.n() == n0 + 2), "a read the head's rotation");
    let w = net.write(a, t, "after");
    net.run();
    assert_eq!(net.read(b, t), Some(s("after")), "a's write {w:?} left it");
}

// spec/sync.md §2, §5 (a step's claim set is the registrar's word), spec/permissions.md §5.1, §7:
// two strangers redeem one single-use link, Y first. The sharer holds only X's redemption when it
// finalizes the link (its frontier leaves Y's out) and rotates K listing X. X, handed Y's earlier
// redemption directly, judges itself out of K until it holds the finalize, which only K's new step
// gives it (the target's label, where K's rotation also goes, is out of its reach): it still claims
// that step as its account, named on K by its own redemption, and so reads the target.
#[test]
fn a_node_judging_itself_out_claims_as_an_actor_a_held_write_names_spec_sync_5() {
    let mut net = Net::new();
    // host 0: the accounts' homes and the target's label; host 1: K's label
    let (s0, s1) = (net.add_host(), net.add_host());
    let home = vec![net.address(s0)];
    let a = net.node(50, &[s0, s1]);
    let x = net.node(51, &[s0, s1]);
    let y = net.node(52, &[s0, s1]);
    let pa = account(&mut net, a, &home);
    let px = account(&mut net, x, &home);
    let py = account(&mut net, y, &home);
    net.run();
    let e = net.engine(a);
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, pa);
    m.set(t, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let (_, acts) = net.sync(a).create_label(&t, home.clone()).unwrap();
    net.actions(a, acts);
    net.run();
    let spec = osis_node::flows::LinkSpec { target: t, role: Role::Read, until: None, hosts: vec![net.address(s1)], peers: Vec::new(), single_use: true };
    let (link, _, done) = net.engine(a).create_link(&pa, &spec).unwrap();
    carry(&mut net, a, done);
    net.run();
    let mut keys = Vec::new();
    for n in [x, y] {
        let l = net.engine(n).hold_key_actor(link.seed.clone()).unwrap();
        let acts = net.sync(n).follow(l, link.k, link.k_label, link.hosts.clone());
        net.actions(n, acts);
        keys.push(l);
    }
    net.run();
    // Y redeems first and stays away; X's redemption reaches K's host while the sharer is away
    net.set_online(y, false);
    net.engine(y).redeem(&link, &py, true).unwrap();
    net.advance(1_000);
    net.set_online(a, false);
    let done = net.engine(x).redeem(&link, &px, true).unwrap();
    net.engine(x).drop_key_actor(&keys[0]);
    carry(&mut net, x, done);
    net.run();
    net.set_online(x, false);
    // the sharer finalizes the link holding X's redemption only, rotating K
    net.set_online(a, true);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    let r = net.engine(a).roster(&link.k);
    assert!(r.contains_key(&px) && !r.contains_key(&py), "the sharer admits X");
    net.pair(y, x);
    assert!(!net.engine(x).roster(&link.k).contains_key(&px), "X, holding Y's earlier redemption, judges itself out");
    net.blocked.insert((x, s0));
    net.set_online(x, true);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    assert!(net.engine(x).roster(&link.k).contains_key(&px), "X opened K's new step and holds the finalize");
    net.blocked.remove(&(x, s0));
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    assert_eq!(net.engine(x).role_on(&t), Some(Role::Read), "X reads the target");
}

// spec/permissions.md §3, §4 (stranded: the node cannot read the label's current epoch by any
// key it holds, wherever its walk stopped; a stranded notice under the admins' inboxes), spec/sync.md
// §5: X, reading as its account, bears a link (reads K through L's static entry) while the sharer
// grants X's account on K, the grant not reaching X, and an admin read rotation of K leaves L out
// and refreshes K's deposit seed. X's walk reaches K's new step with no actor it holds named on K
// and L's entry gone: no key left to try, no claim tried. It is stranded all the same, with no
// deposit key of the label and no peer connected: its stranded notice under the sharer's inbox
// makes the sharer re-seal X's account, and K's label opens again.
#[test]
fn walk_out_of_keys_is_stranded_spec_permissions_4() {
    let mut net = Net::new();
    let s0 = net.add_host();
    let home = vec![net.address(s0)];
    let a = net.node(60, &[s0]);
    let x = net.node(61, &[s0]);
    let pa = account(&mut net, a, &home);
    let px = account(&mut net, x, &home);
    net.run();
    net.pair(x, a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, pa);
    m.set(t, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let (_, acts) = net.sync(a).create_label(&t, home.clone()).unwrap();
    net.actions(a, acts);
    net.run();
    let spec = osis_node::flows::LinkSpec { target: t, role: Role::Read, until: None, hosts: home.clone(), peers: Vec::new(), single_use: false };
    let (link, _, done) = net.engine(a).create_link(&pa, &spec).unwrap();
    carry(&mut net, a, done);
    let k = link.k;
    let l = net.engine(x).bear(&link).unwrap();
    let acts = net.sync(x).follow(l, k, link.k_label, link.hosts.clone());
    net.actions(x, acts);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    let lk = link.k_label;
    let e0 = net.engine(x).epochs(&k).unwrap().read.newest().unwrap();
    let head0 = net.host_path(s0, &lk).last().unwrap().keys.deposit;
    // X away: the sharer grants X's account on K (its delivery lost), and K's admin read
    // rotation boxes the sharer and X's account, not L, with a fresh deposit seed
    net.set_online(x, false);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    net.engine(a).grant(&k, &px, &edge).unwrap();
    let e = net.engine(a);
    let rs = recipients_of(e, &[(pa, Role::Admin), (px, Role::Read)]);
    rotation(e, k, &rs, 61, true);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    let e1 = net.engine(a).epochs(&k).unwrap().read.newest().unwrap();
    assert_ne!(e0, e1);
    assert_ne!(net.host_path(s0, &lk).last().unwrap().keys.deposit, head0, "the head's deposit key is a new one");
    assert!(!net.engine(x).roster(&k).contains_key(&px), "X does not hold its grant");
    net.set_online(x, true);
    for _ in 0..8 {
        net.run();
        net.advance(61_000);
    }
    assert!(net.sync(x).stranded_at(&lk), "X's walk ran out of keys: stranded");
    assert!(net.peer_conns(x).is_empty(), "no peer connected: the notice went by inbox");
    assert_eq!(net.engine(x).epochs(&k).unwrap().read.newest(), Some(e1), "re-sealed: X reads K's new epoch");
    let st = net.sync(x).label_status().into_iter().find(|s| s.label == lk).unwrap();
    assert!(!st.stranded && st.sources == 1, "K's label open again: {st:?}");
}

/// Commits of node `n`'s that write `g`'s `secrets.0` (rotations, re-seals).
fn seals_by(net: &mut Net, n: usize, g: osis_base::Tid) -> usize {
    let e = net.engine(n);
    let me = e.me();
    e.commit_ids().into_iter().filter(|c| e.header(c).is_some_and(|h| h.author == me && h.aspects.iter().any(|a| a.tid == g && a.ak.as_str() == "secrets.0"))).count()
}

/// Admin `a` (dialable) and reader `c` of a group at a host, connected: (net, a, c, g, label, c's
/// end of the connection).
fn stranded_pair() -> (Net, usize, usize, osis_base::Tid, osis_base::LabelId, osis_node::sync::ConnId) {
    let (mut net, host, [a, c]) = hosted_nodes::<2>();
    crate::peers::reach_ed(&mut net, a);
    let g = net.group(a, &[(c, Role::Read)], &[host]);
    net.run();
    net.advance(61_000);
    let l = net.label(a);
    let (conn, ..) = net.peer_conns(c).into_iter().find(|x| x.1 == a).expect("c dialed a");
    (net, a, c, g, l, conn)
}

// spec/permissions.md §4 (Stranded message), §3 (re-seal): a Stranded message naming a current
// holder makes a node that may rotate re-seal that holder at the end of a complete pass, once at
// the actor's current epochs, however often it comes.
#[test]
fn stranded_message_reseals_the_named_holder_spec_permissions_4() {
    let (mut net, a, c, g, l, conn) = stranded_pair();
    let holder = net.tid(c);
    let before = seals_by(&mut net, a, g);
    for i in 0..3 {
        net.inject(c, conn, &osis_proto::Message::Stranded { id: osis_proto::msg::NODE_IDS | (0x7000 + i), label: l, holder, keys: Default::default() });
        net.run();
        net.advance(61_000);
    }
    assert_eq!(seals_by(&mut net, a, g), before + 1, "one re-seal of c's account");
    // an unknown label: nothing
    net.inject(c, conn, &osis_proto::Message::Stranded { id: osis_proto::msg::NODE_IDS | 0x7100, label: osis_base::LabelId([0x44; 16]), holder, keys: Default::default() });
    net.run();
    assert_eq!(seals_by(&mut net, a, g), before + 1);
}

// spec/permissions.md §4 (Stranded: the holder keys), spec/wire.md §9, §11.2: a Stranded message
// carries the current `keys.0` of the holder it names, taken only for a current holder and only
// for it (judged from nothing of the sender). T, a team of reader c's, holds no role on g: T's
// keys sent under the name of c's account (a current holder), or under T's own, give admin `a`
// nothing. (A node gone from the holder taking them: osis
// `sharing::team_left_out_reads_again_by_its_stranded_report_spec_crypto_4`.)
#[test]
fn stranded_message_takes_only_the_named_holders_keys_spec_permissions_4() {
    let (mut net, a, c, g, l, conn) = stranded_pair();
    let t = net.group(c, &[], &[0]);
    net.run();
    let lacks = |net: &mut Net| -> Vec<osis_base::CommitId> { net.engine(c).current_keys(&t).into_iter().filter(|k| net.engine(a).header(k).is_none()).collect() };
    let ts = lacks(&mut net);
    assert!(!ts.is_empty(), "a lacks T's keyset");
    let keys = net.sync(c).holder_keys(&t).unwrap();
    for (i, holder) in [net.tid(c), t].into_iter().enumerate() {
        net.inject(c, conn, &osis_proto::Message::Stranded { id: osis_proto::msg::NODE_IDS | (0x7200 + i as u32), label: l, holder, keys: keys.clone() });
        net.run();
        assert_eq!(lacks(&mut net), ts, "holder {i}: T's keys not taken");
    }
    assert!(net.engine(a).core.key_holders(&g).iter().all(|x| x.0 != t), "T holds nothing on g");
}

// spec/permissions.md §4 (Stranded: the holder keys), spec/commits.md §4 (Pending storage): keys
// a Stranded message brings that pend at the admin (their author's clock two hours ahead) are
// carried by the report, not dropped for want of an entry: a node connected to a writer reports
// by message only, once per step. They apply once their time comes, the reporter connected
// throughout.
#[test]
fn stranded_message_keys_pending_kept_spec_permissions_4() {
    let (mut net, a, c, g, l, conn) = stranded_pair();
    // team T of d's at another host, a holder of g; d reaches neither a nor g's host, so a learns
    // T's keysets only from reports
    let other = net.add_host();
    let d = net.node(3, &[other]);
    for x in [a, c] {
        net.blocked_peers.extend([(d, x), (x, d)]);
    }
    net.blocked.insert((d, 0));
    let t = net.group(d, &[], &[other]);
    net.run();
    let keys = net.sync(d).holder_keys(&t).unwrap();
    net.engine(a).learn_records(keys.records).unwrap();
    for v in keys.commits {
        net.engine(a).ingest(&osis_base::encode(&v), Vec::new()).unwrap();
    }
    net.grant(a, g, t, Role::Read);
    net.run();
    net.set_skew(d, 2 * 3_600_000);
    let dt = net.tid(d);
    let e = net.engine(d);
    let rs = recipients_of(e, &[(dt, Role::Admin)]);
    let k = rotation(e, t, &rs, 43, false);
    net.set_skew(d, 0);
    net.run();
    assert!(net.engine(a).header(&k).is_none(), "a lacks T's new keyset");
    let keys = net.sync(d).holder_keys(&t).unwrap();
    net.inject(c, conn, &osis_proto::Message::Stranded { id: osis_proto::msg::NODE_IDS | 0x7300, label: l, holder: t, keys });
    net.run();
    assert!(net.engine(a).pending().iter().any(|(x, _)| *x == k), "T's new keyset pends at a");
    for _ in 0..3 {
        net.advance(61_000);
        net.run();
    }
    assert!(net.engine(a).pending().iter().any(|(x, _)| *x == k), "kept while the report carries it");
    net.advance(2 * 3_600_000);
    net.run();
    assert!(net.engine(a).current_keys(&t).contains(&k), "applied once its time came");
}

// spec/permissions.md §4 (Stranded: to a connected peer that proved an account holding write or
// above, else an inbox notice): a rotation leaves reader `c` out while it is away; back, stranded
// at the host, it tells the admin it is connected to over the connection, once per step reached,
// deposits no notice, and is re-sealed.
#[test]
fn stranded_goes_to_a_connected_admin_spec_permissions_4() {
    let (mut net, a, c, g, l, _) = stranded_pair();
    net.set_online(c, false);
    let at = net.tid(a);
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin)]);
    rotation(e, g, &rs, 41, false);
    net.run();
    net.advance(61_000);
    let inbox = |net: &mut Net| -> usize {
        let ls: Vec<osis_base::LabelId> = net.sync(a).labels().iter().map(|x| x.1.id).filter(|x| *x != l).collect();
        ls.iter().map(|x| net.sync(a).entries(x).len()).sum()
    };
    let before = inbox(&mut net);
    let e1 = net.engine(a).epochs(&g).unwrap().read.newest();
    net.set_online(c, true);
    for _ in 0..4 {
        net.run();
        net.advance(61_000);
    }
    assert!(net.sync(c).stranded_at(&l), "stranded");
    assert_eq!(net.peer_sent(c, 30), 1, "one Stranded message for the step it reached");
    assert_eq!(inbox(&mut net), before, "no notice under the admin's inbox");
    assert_eq!(net.engine(c).epochs(&g).unwrap().read.newest(), e1, "re-sealed");
}

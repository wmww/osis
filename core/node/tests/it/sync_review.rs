#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Regression tests from the node-sync review (spec/sync.md §3, §5-§7; spec/crypto.md §4;
//! spec/commits.md §5; spec/permissions.md §3).

use crate::net;
use net::*;
use osis_commit::PurgeItem;
use osis_base::{Ak, Role, Value, WallMs};
use osis_node::Mutation;
use osis_node::sync::{EntryKind, Event, SyncConfig};
use osis_schema::AspectKey;
use osis_schema::core_types as ct;

/// Blob IDs node `n` knows under `l` holding commit `c`.
fn blobs_of(net: &mut Net, n: usize, l: &osis_base::LabelId, c: &osis_base::CommitId) -> Vec<osis_base::BlobId> {
    net.sync(n).entries(l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c)).map(|(id, _)| id).collect()
}

// spec/crypto.md §4, spec/permissions.md §3: a holder's `until` passes; before this node next
// wraps under the group's read epoch it rotates (flows' cascade), so the departed holder cannot
// read what comes after.
// spec/crypto.md §4 (encrypt under covering epoch), spec/permissions.md §3 (required rotation)
#[test]
fn rotates_before_wrapping_after_until_spec_crypto_4() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.pair(c, a);
    let ct_ = net.tid(c);
    let until = WallMs(net.now() + 1_000);
    let done = net.engine(a).grant(&g, &ct_, &ct::Edge { role: Role::Read, until: Some(until), invite: None, since: None, tied: None, keyset: None, keep: false }).unwrap();
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
    assert_eq!(net.read(c, t), None, "the departed reader gets nothing new, and its edge said erase");
}

// spec/commits.md §5 (purge drops every copy): after a purge applied, a reader holds neither
// the purged body's key nor its ciphertext; a writer without the delete key deletes it at the
// host by delete key.
#[test]
fn purge_leaves_no_copy_spec_commits_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let r = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Write), (r, Role::Read)], &[host]);
    let t = net.item(a, g, g, "x");
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
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
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
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
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
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    let t2 = net.item(a, g, g, "y");
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
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    assert!(net.sync(b).complete_pass(&g));
    net.pair(c, a);
    let ct_ = net.tid(c);
    set_edge(net.engine(a), g, ct_, Role::Read);
    net.feed(a, Event::Local);
    net.settle(100_000);
    assert!(net.engine(b).roster(&g).contains_key(&ct_), "arrived by push");
    assert!(net.sync(b).complete_pass(&g), "the push run counts as a pass end");
}

// spec/sync.md §6-§7 (positive uncovered): a compactor deletes covered bodies; a writer that
// has not fetched the snapshot yet treats them as may-hold and re-uploads nothing.
#[test]
fn no_reupload_ping_pong_spec_sync_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
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

// spec/sync.md §3 (projection, entitlement), spec/commits.md §4 (pending on `created.0` only
// for things whose deltas the node holds or syncs): one commit touching a shared thing and a
// private one places only the shared deltas under the group's label; a holder applies them.
#[test]
fn private_and_shared_split_spec_sync_3() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    let t = net.item(a, g, g, "shared");
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
    for (_, k) in net.sync(a).entries(&l) {
        if let EntryKind::Commit { commit, parts, .. } = k
            && commit == c
        {
            assert!(parts.iter().all(|(ai, _)| h.aspects[*ai].tid == t), "only the shared deltas: {parts:?}");
        }
    }
    // the holder applies the shared delta and never sees the private one
    assert!(net.engine(b).pending().is_empty(), "{:?}", net.engine(b).pending());
    assert_eq!(net.read(b, t), Some(s("shared 2")));
    assert_eq!(net.read(b, p), None);
    assert!(!net.engine(b).knows(&p));
}

// spec/sync.md §7: compaction deletes exactly the covered bodies, after the snapshot is at the
// host, and the snapshot stays.
#[test]
fn compaction_deletes_exactly_covered_spec_sync_7() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
    let t = net.item(a, g, g, "v1");
    let c2 = net.write(a, t, "v2");
    let c3 = net.write(a, t, "v3");
    net.run();
    let l = net.label(a);
    let old: Vec<_> = [c2, c3].iter().flat_map(|c| blobs_of(&mut net, a, &l, c)).collect();
    assert!(old.iter().all(|id| net.host_ids(host, &l).contains(id)));
    let ak = Ak::new(REG.ak()).unwrap();
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    net.run();
    let ids = net.host_ids(host, &l);
    assert!(old.iter().all(|id| !ids.contains(id)), "covered bodies deleted");
    let snaps: Vec<_> = net.sync(a).entries(&l).into_iter().filter_map(|(id, k)| match k {
        EntryKind::Commit { commit, .. } if net.engine(a).header(&commit).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot) => Some(id),
        _ => None,
    }).collect();
    assert!(!snaps.is_empty() && snaps.iter().all(|id| ids.contains(id)), "the carrier snapshot stays");
    let _ = Value::Bool(true);
}

// spec/permissions.md §3 (complete pass): a pass from before going offline still counts (it
// proves what the host held then); a remote role commit received while offline (here
// directly) restarts it.
#[test]
fn complete_pass_survives_disconnect_spec_permissions_3() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
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
    set_edge(net.engine(a), g, ct_, Role::Read);
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
        let d = osis_node::flows::Demotion { holder: bt, new: None, presync: osis_node::flows::PreSync::Synced };
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
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "marker");
    net.run();
    assert_eq!(net.read(b, t), Some(s("marker")));
    net.set_online(b, false);
    let (bt, ct_) = (net.tid(b), net.tid(c));
    let d = osis_node::flows::Demotion { holder: bt, new: None, presync: osis_node::flows::PreSync::Synced };
    let done = net.engine(b).demote(&g, &d).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    // the admin adds someone meanwhile: b applies a received role commit on g
    set_edge(net.engine(a), g, ct_, Role::Read);
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
        let d = osis_node::flows::Demotion { holder: bt, new: None, presync: osis_node::flows::PreSync::Synced };
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
        let d = osis_node::flows::Demotion { holder: bt, new: None, presync: osis_node::flows::PreSync::Synced };
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
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
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
    // b never hears of the purge commit
    let hide = blobs_of(&mut net, a, &l, &pc);
    assert!(!hide.is_empty());
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

// spec/permissions.md §3 (a node that learns it lost read access MUST drop): node-sync wakes
// when an admin's re-grant it holds pending, keeping a group it was removed from, ages out
// (`PENDING_GRANT_WAIT_MS`), and drops the group then with no other event; also across a
// restart while waiting.
#[test]
fn lost_access_wakes_when_pending_grant_ages_out_spec_permissions_3() {
    for restart in [false, true] {
        let mut net = Net::new();
        let a = net.node(1, &[]);
        let b = net.node(2, &[]);
        let g = net.group(a, &[(b, Role::Read)], &[]);
        let t = net.item(a, g, g, "marker");
        net.pair(a, b);
        net.run();
        assert_eq!(net.read(b, t), Some(s("marker")));
        let d = osis_node::flows::Demotion { holder: net.tid(b), new: None, presync: osis_node::flows::PreSync::Synced };
        net.engine(a).demote(&g, &d).unwrap();
        net.pair(a, b);
        let rcpt = crate::common::read_recipient(net.engine(b));
        let bytes = crate::common::forge_pending_grant(net.engine(a), rcpt, g, 3);
        assert!(matches!(net.engine(b).ingest(&bytes, Vec::new()).unwrap(), osis_node::Ingested::Pending(..)));
        let ts = crate::common::grant_ts(&bytes);
        net.clock.set(ts);
        net.engine(b).freeze_pending();
        let now = net.now();
        let mut acts = net.sync(b).handle(Event::Local);
        assert_eq!(net.read(b, t), Some(s("marker")), "kept while the grant may apply");
        if restart {
            // past the drift bound again while opening examines it
            net.clock.set(osis_base::WallMs(ts.0 - 2 * osis_base::format::MAX_DRIFT_MS));
            net.restart(b, 9);
            net.clock.set(ts);
            net.engine(b).freeze_pending();
            acts = net.sync(b).handle(Event::Local);
        }
        let at = acts.iter().find_map(|x| if let osis_node::sync::Action::Wake { at } = x { Some(*at) } else { None }).expect("a wake");
        assert!(at > now && at <= now + osis_node::rotation::PENDING_GRANT_WAIT_MS + 1, "at {at}, now {now}");
        net.clock.advance(at - now);
        net.sync(b).handle(Event::Tick);
        assert_eq!(net.read(b, t), None, "restart {restart}");
        assert!(net.engine(b).epochs(&g).is_none_or(|e| e.read.held().next().is_none()));
    }
}

// spec/sync.md §6 (no upload of a body a delete removed, keyed per body): commit c writes a plain
// register and a keep-at-most-1h one, two bodies; both are overwritten, the second's body is
// deleted past its bound, and the host is wiped: the first's body (must-hold, uncovered) goes up
// again though another body of c was deleted
#[test]
fn deleted_body_withholds_only_itself_spec_sync_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
    let t = net.item(a, g, g, "v1");
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
    assert_eq!(blobs_of(&mut net, a, &l, &c).len(), 2, "two bodies");
    net.advance(1_000);
    both(&mut net, "y");
    net.advance(osis_base::format::MAX_DRIFT_MS + 60_000);
    net.run();
    let reg_body = |net: &mut Net| {
        let h = net.engine(a).header(&c).unwrap();
        net.sync(a).entries(&l).into_iter().filter_map(|(id, k)| match k {
            EntryKind::Commit { commit, parts, .. } if commit == c && parts.iter().all(|(ai, _)| h.aspects[*ai].ak.as_str() == "t:reg.0") => Some(id),
            _ => None,
        }).collect::<Vec<_>>()
    };
    assert_eq!(blobs_of(&mut net, a, &l, &c).len(), 1, "the keep-at-most body deleted");
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

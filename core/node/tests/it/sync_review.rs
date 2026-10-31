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

fn diags(net: &mut Net, nodes: &[usize]) {
    for n in nodes {
        let d = net.sync(*n).take_diagnostics();
        if !d.is_empty() {
            eprintln!("node {n}: {d:?}");
        }
    }
}

/// Blob IDs node `n` knows under `l` holding commit `c`.
fn blobs_of(net: &mut Net, n: usize, l: &osis_base::LabelId, c: &osis_base::CommitId) -> Vec<osis_base::BlobId> {
    net.sync(n).entries(l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c)).map(|(id, _)| id).collect()
}

// spec/crypto.md §4, spec/permissions.md §3: a member's `until` passes; before this node next
// wraps under the group's read epoch it rotates (flows' cascade), so the departed member cannot
// read what comes after.
// spec/crypto.md §4 (encrypt under covering epoch), spec/permissions.md §3 (required rotation)
#[test]
fn rotates_before_wrapping_after_until_spec_crypto_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.pair(c, a);
    let ct_ = net.tid(c);
    let until = WallMs(net.now() + 1_000);
    let done = net.engine(a).grant(&g, &ct_, &ct::Edge { role: Role::Read, until: Some(until), invite: None, since: None, tied: false }).unwrap();
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
    assert_eq!(net.read(c, t), Some(s("before")), "the departed reader gets nothing new");
}

// spec/commits.md §5 (purge drops every copy): after a purge applied, a reader holds neither
// the purged body's key nor its ciphertext; a writer without the delete key deletes it at the
// server by delete key.
#[test]
fn purge_leaves_no_copy_spec_commits_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let r = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (r, Role::Read)], &[sv]);
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
    diags(&mut net, &[b, r]);
    for id in &ids {
        assert!(!net.sync(r).holds_blob(id), "the reader keeps no key or ciphertext");
        assert!(!net.server_ids(sv, &l).contains(id), "deleted at the server by delete key");
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
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
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
    let ids = net.server_ids(sv, &l);
    assert!(ids.contains(&q[0]), "q uploaded at once");
    net.run();
    net.run();
    net.set_online(b, true);
    // past the redial pause
    net.advance(6_000);
    net.run();
    diags(&mut net, &[a, b]);
    let ids = net.server_ids(sv, &l);
    assert!(!ids.contains(&p[0]), "p deleted once carried");
    assert!(ids.contains(&q[0]), "q kept");
    assert_eq!(net.engine(b).get(&t2, &gone).unwrap(), Some(s("kept")));
    assert_eq!(net.engine(b).get(&t, &gone).unwrap(), None);
}

// spec/sync.md §7 (a body with live writes leaves only while a carrier stays): writer a purges
// one delta of commit c whose two-delta blob p also holds a live write; a's rewrite q is lost on
// the way, so p stays (and the live write with it) until q is at the server.
#[test]
fn purged_body_waits_for_its_rewrite_spec_sync_7() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
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
    let ids = net.server_ids(sv, &l);
    assert!(!ids.contains(&q[0]), "q lost on the way");
    assert!(ids.contains(&p[0]), "p waits for its carrier");
    net.lose_uploads.clear();
    // past the resend pause
    net.advance(60_000);
    net.run();
    diags(&mut net, &[a, b]);
    let ids = net.server_ids(sv, &l);
    assert!(ids.contains(&q[0]), "q uploaded again");
    assert!(!ids.contains(&p[0]), "p deleted once carried");
    assert_eq!(net.engine(b).get(&t2, &gone).unwrap(), Some(s("kept")));
    assert_eq!(net.engine(b).get(&t, &gone).unwrap(), None);
}

// spec/sync.md §7 (a rewrite the label refuses for its cap goes up again replacing the purged
// body), §5 (Replace), spec/requirements.md (purge is prompt): as above, but the label is at its
// entry cap, so a's rewrite q is refused (code 12); q goes up again naming p as replaced, and the
// server admits it in p's room and removes p in one step: after every hop the server holds p or
// q (the kept live write is never absent), and ends with q only.
#[test]
fn purged_body_leaves_full_label_spec_sync_7() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
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
    let full = net.server_ids(sv, &l).len() as u64;
    net.restart_server_with(sv, osis_server::Policy { cap_entries: full, ..osis_server::Policy::default() });
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
        let ids = net.server_ids(sv, &l);
        let q: Vec<_> = blobs_of(&mut net, a, &l, &c).into_iter().filter(|id| !p.contains(id)).collect();
        assert!(ids.contains(&p[0]) || q.iter().any(|x| ids.contains(x)), "neither p nor its rewrite at the server");
    }
    net.run();
    diags(&mut net, &[a, b]);
    let q: Vec<_> = blobs_of(&mut net, a, &l, &c).into_iter().filter(|id| !p.contains(id)).collect();
    assert_eq!(q.len(), 1, "a's rewrite placed");
    let ids = net.server_ids(sv, &l);
    assert!(!ids.contains(&p[0]), "p deleted though its rewrite was refused");
    assert!(ids.contains(&q[0]), "q uploaded in the room p freed");
    assert!(net.sent_kinds.get(&10).copied().unwrap_or(0) > up, "uploads sent");
    assert_eq!(net.sent_kinds.get(&14).copied().unwrap_or(0), del, "p went by the replacing upload, no Delete");
    assert_eq!(ids.len() as u64, full, "the label stays full (the purge request itself waits for space)");
}

// spec/permissions.md §3 (complete pass): a membership commit pushed to a subscribed node ends
// with a pass: `complete_pass` holds without another Sync.
#[test]
fn complete_pass_after_push_spec_permissions_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
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
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], inline_limit: 0, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "v1");
    net.write(a, t, "v2");
    net.write(a, t, "v3");
    net.run();
    let l = net.label(a);
    let acts = net.sync(a).compact(&t, &Ak::new(REG.ak()).unwrap()).unwrap();
    net.actions(a, acts);
    net.run();
    net.run();
    let n1 = net.server_ids(sv, &l);
    net.advance(70_000);
    net.advance(70_000);
    diags(&mut net, &[a, b]);
    assert_eq!(net.server_ids(sv, &l), n1, "settled: nothing re-uploaded, nothing deleted again");
    assert_eq!(net.read(b, t), Some(s("v3")));
}

// spec/sync.md §3 (projection, entitlement), spec/commits.md §4 (pending on `/created` only
// for things whose deltas the node holds or syncs): one commit touching a shared thing and a
// private one places only the shared deltas under the group's label; a member applies them.
#[test]
fn private_and_shared_split_spec_sync_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Read)], &[sv]);
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
    // the member applies the shared delta and never sees the private one
    assert!(net.engine(b).pending().is_empty(), "{:?}", net.engine(b).pending());
    assert_eq!(net.read(b, t), Some(s("shared 2")));
    assert_eq!(net.read(b, p), None);
    assert!(!net.engine(b).knows(&p));
}

// spec/sync.md §7: compaction deletes exactly the covered bodies, after the snapshot is at the
// server, and the snapshot stays.
#[test]
fn compaction_deletes_exactly_covered_spec_sync_7() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    let t = net.item(a, g, g, "v1");
    let c2 = net.write(a, t, "v2");
    let c3 = net.write(a, t, "v3");
    net.run();
    let l = net.label(a);
    let old: Vec<_> = [c2, c3].iter().flat_map(|c| blobs_of(&mut net, a, &l, c)).collect();
    assert!(old.iter().all(|id| net.server_ids(sv, &l).contains(id)));
    let ak = Ak::new(REG.ak()).unwrap();
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    net.run();
    let ids = net.server_ids(sv, &l);
    assert!(old.iter().all(|id| !ids.contains(id)), "covered bodies deleted");
    let snaps: Vec<_> = net.sync(a).entries(&l).into_iter().filter_map(|(id, k)| match k {
        EntryKind::Commit { commit, .. } if net.engine(a).header(&commit).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot) => Some(id),
        _ => None,
    }).collect();
    assert!(!snaps.is_empty() && snaps.iter().all(|id| ids.contains(id)), "the carrier snapshot stays");
    let _ = Value::Bool(true);
}

// spec/permissions.md §3 (complete pass): a pass from before going offline still counts (it
// proves what the server held then); a remote membership commit received while offline (here
// directly) restarts it.
#[test]
fn complete_pass_survives_disconnect_spec_permissions_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    assert!(net.sync(b).complete_pass(&g));
    net.blocked.insert((b, sv));
    net.drop_link(b, sv);
    net.advance(61_000);
    assert!(net.sync(b).complete_pass(&g), "the pass before going offline still counts");
    net.pair(c, a);
    let ct_ = net.tid(c);
    set_edge(net.engine(a), g, ct_, Role::Read);
    net.pair(a, b);
    net.feed(b, Event::Local);
    net.run();
    assert!(net.engine(b).roster(&g).contains_key(&ct_), "arrived directly");
    assert!(!net.sync(b).complete_pass(&g), "a remote membership commit restarts it");
    net.blocked.remove(&(b, sv));
    net.advance(61_000);
    net.settle(100_000);
    assert!(net.sync(b).complete_pass(&g), "a pass after reconnecting completes it");
}

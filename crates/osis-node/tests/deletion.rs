#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Deletions, compaction and re-registration through a blind node (spec/sync.md §5-§7;
//! spec/commits.md §5; spec/permissions.md §3, §4).

mod net;
use net::*;
use osis_core::{Ak, Role};
use osis_node::Mutation;
use osis_node::sync::EntryKind;
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

// spec/sync.md §3 (retag), §5 (deletion by token), §6: a thing leaving the folder takes its own
// bodies out of the folder's label; a writer without the delete key deletes them by token.
#[test]
fn thing_leaving_deleted_by_token_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "x");
    net.run();
    let c = net.write(b, t, "by b");
    net.run();
    let l = net.label(a);
    let blobs: Vec<_> = net.sync(b).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect();
    assert!(!blobs.is_empty() && blobs.iter().all(|id| net.server_ids(sv, &l).contains(id)));
    // the admin is away: only the writer can act, by token
    net.set_online(a, false);
    let e = net.engine(b);
    let mut grp = e.get_typed(&g, &ct::GROUP).unwrap().unwrap();
    grp.items.remove(&t);
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &grp).unwrap();
    e.commit(m).unwrap();
    net.run();
    diags(&mut net, &[b]);
    assert!(!net.engine(b).closure(&g).contains(&t));
    let ids = net.server_ids(sv, &l);
    assert!(blobs.iter().all(|id| !ids.contains(id)), "the commit only on the departed thing went");
}

// spec/sync.md §7, spec/commits.md §5: compaction uploads the snapshot first, then drops and
// deletes the covered bodies; a member joining later reads the live value from the snapshot.
#[test]
fn compaction_then_deletion_spec_sync_7() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let c = net.node(3, &[sv]);
    net.blocked.insert((c, sv));
    let g = net.group(a, &[(c, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "v1");
    net.write(a, t, "v2");
    net.write(a, t, "v3");
    net.run();
    let l = net.label(a);
    let before = net.server_ids(sv, &l).len();
    let ak = Ak::new(REG.ak()).unwrap();
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    net.run();
    diags(&mut net, &[a]);
    let after = net.server_ids(sv, &l).len();
    assert!(after < before, "covered bodies deleted after the snapshot: {before} -> {after}");
    net.blocked.clear();
    net.advance(10_000);
    diags(&mut net, &[c]);
    assert_eq!(net.read(c, t), Some(s("v3")), "the live value is served from the snapshot");
}

// spec/sync.md §5 (re-registration, upload order), spec/permissions.md §3-§4 (stranded
// heartbeat): an admin rotating out a member issues a child step at the server after uploading
// the rotation commit; the remaining writer follows; the removed member's open walks to the new
// step, its claim is refused and it places a stranded heartbeat by deposit.
// spec/permissions.md §4 (stranded heartbeat), spec/crypto.md §4 (removed member)
#[test]
fn reregistration_after_rotation_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "before");
    net.run();
    assert_eq!(net.read(c, t), Some(s("before")));
    let l = net.label(a);
    assert_eq!(net.server_path(sv, &l).len(), 1);
    net.set_online(c, false);
    let (at, bt, ct_) = (net.tid(a), net.tid(b), net.tid(c));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write)]);
    remove_member(e, g, ct_, &rs, 41);
    net.write(a, t, "after");
    net.run();
    diags(&mut net, &[a, b]);
    assert_eq!(net.server_path(sv, &l).len(), 2, "a child step was registered");
    assert_eq!(net.sync(a).labels()[0].1.steps.len(), 2, "and recorded in /label");
    assert_eq!(net.read(b, t), Some(s("after")));
    net.write(b, t, "from b");
    net.run();
    assert_eq!(net.read(a, t), Some(s("from b")), "the writer stamps under the new step");
    // the removed member comes back: walked to the new step, claim refused, stranded heartbeat
    let n_before = net.server_ids(sv, &l).len();
    net.set_online(c, true);
    net.advance(10_000);
    assert_eq!(net.read(c, t), Some(s("before")), "nothing new readable");
    assert!(net.server_ids(sv, &l).len() > n_before, "a stranded heartbeat was deposited");
    net.run();
    let seen = net.engine(a).get_typed(&ct_, &ct::SEEN).unwrap();
    assert!(seen.is_some_and(|x| x.stranded), "co-members read the stranded heartbeat");
}

// spec/commits.md §5, spec/sync.md §5 (timed delete): replacing a body under a relative
// keep-at-most sends the timed delete with the replacing upload, after a covering snapshot; the
// server deletes it at the bound with nobody online.
#[test]
fn timed_delete_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    let t = net.item(a, g, g, "x");
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("v1")).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    let l = net.label(a);
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("v2")).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    net.run();
    diags(&mut net, &[a]);
    let before = net.server_ids(sv, &l).len();
    net.set_online(a, false);
    net.clock.advance(3_600_000 + 1_000);
    let now = net.now();
    net.servers[sv].hub.tick(now);
    let after = net.server_ids(sv, &l).len();
    assert_eq!(after + 1, before, "the replaced body went at its bound, nobody online");
}

/// A record under keep at most 0 (`/t/gonemap`, about 330 KB) with a secret entry, compacted
/// into one snapshot that is at the server: (item, aspect, label, the snapshot).
fn at_most_zero_record(net: &mut Net, a: usize, g: osis_core::Tid, marker: &str) -> (osis_core::Tid, Ak, osis_core::LabelId, osis_core::CommitId) {
    let t = net.item(a, g, g, "x");
    let mut v: std::collections::BTreeMap<osis_core::Value, osis_core::Value> = (0..300).map(|i| (s(&format!("k{i:03}")), s(&"f".repeat(1100)))).collect();
    v.insert(s("secret"), s(marker));
    let mut m = Mutation::new();
    m.set(t, &GONEMAP, &osis_core::Value::Map(v)).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let ak = Ak::new(GONEMAP.ak()).unwrap();
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    let l = net.label(a);
    let snaps = snapshots(net, a, &t, &ak);
    assert_eq!(snaps.len(), 1);
    let s1 = snaps[0];
    assert!(!blobs(net, a, &l, &s1).is_empty() && blobs(net, a, &l, &s1).iter().all(|b| net.server_ids(0, &l).contains(b)), "the snapshot is at the server");
    (t, ak, l, s1)
}

/// Compaction snapshots node `n` holds of `(t, ak)`.
fn snapshots(net: &mut Net, n: usize, t: &osis_core::Tid, ak: &Ak) -> Vec<osis_core::CommitId> {
    let e = net.engine(n);
    e.commit_ids().into_iter().filter(|c| e.header(c).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot && h.aspects.iter().any(|x| x.tid == *t && x.ak == *ak))).collect()
}

fn blobs(net: &mut Net, n: usize, l: &osis_core::LabelId, c: &osis_core::CommitId) -> Vec<osis_core::BlobId> {
    net.sync(n).entries(l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c)).map(|(id, _)| id).collect()
}

/// Removes the secret entry of the record (an erasing edit: it kills a write the snapshot carries).
fn erase_secret(net: &mut Net, a: usize, t: osis_core::Tid) {
    let mut m = Mutation::new();
    m.op(t, &GONEMAP, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s("secret")) }).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
}

// spec/commits.md §5 (keep at most 0: a compaction-snapshot body keeps to the next compaction),
// spec/requirements.md (Scale: cost per change): an erasing edit of a big record under keep at
// most 0 sends O(change), with no new snapshot; the next compaction drops the old snapshot here
// and at the server, and a member joining afterwards cannot read the erased entry.
#[test]
fn at_most_zero_snapshot_goes_at_next_compaction_spec_commits_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let c = net.node(3, &[sv]);
    net.blocked.insert((c, sv));
    let g = net.group(a, &[(c, Role::Read)], &[sv]);
    let (t, ak, l, s1) = at_most_zero_record(&mut net, a, g, "ERASED-7d1e");
    net.sent_bytes = 0;
    erase_secret(&mut net, a, t);
    net.run();
    let sent = net.sent_bytes;
    assert!(sent < 32 * 1024, "an erasing edit sent {sent} bytes (the record is about 330 KB)");
    assert_eq!(snapshots(&mut net, a, &t, &ak), vec![s1], "no re-snapshot per erasing edit");
    assert!(net.engine(a).holds_body(&s1, &t, &ak), "the old snapshot keeps to the next compaction");
    assert!(net.engine(a).deaths(&s1, &t, &ak).unwrap().is_some());
    let at_server = blobs(&mut net, a, &l, &s1);
    // the next compaction: the old snapshot goes here and at the server
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    assert!(!net.engine(a).holds_body(&s1, &t, &ak));
    let ids = net.server_ids(sv, &l);
    assert!(at_server.iter().all(|b| !ids.contains(b)), "the old snapshot deleted at the server");
    // readable by nobody: a member syncing now gets the record without it
    net.blocked.clear();
    net.advance(10_000);
    let ec = net.engine(c);
    assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("k007"))]).unwrap(), Some(s(&"f".repeat(1100))));
    assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("secret"))]).unwrap(), None);
    assert!(!ec.holds_body(&s1, &t, &ak));
}

// spec/commits.md §5 (keep at most 0: a compaction-snapshot body's bound is its first death plus
// `SNAPSHOT_GRACE`), spec/sync.md §7 (snapshot first): with no compaction, the old snapshot goes
// at its bound, after a covering snapshot is at the server.
#[test]
fn at_most_zero_snapshot_goes_at_grace_bound_spec_commits_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let c = net.node(3, &[sv]);
    net.blocked.insert((c, sv));
    let g = net.group(a, &[(c, Role::Read)], &[sv]);
    let (t, ak, l, s1) = at_most_zero_record(&mut net, a, g, "ERASED-90b4");
    erase_secret(&mut net, a, t);
    net.run();
    let at_server = blobs(&mut net, a, &l, &s1);
    net.advance(osis_core::format::SNAPSHOT_GRACE_MS / 2);
    assert!(net.engine(a).holds_body(&s1, &t, &ak), "kept before the bound");
    net.advance(osis_core::format::SNAPSHOT_GRACE_MS / 2 + 1);
    net.run();
    assert!(!net.engine(a).holds_body(&s1, &t, &ak), "dropped at the bound");
    let ids = net.server_ids(sv, &l);
    assert!(at_server.iter().all(|b| !ids.contains(b)), "deleted at the server");
    assert_eq!(snapshots(&mut net, a, &t, &ak).len(), 2, "one carrier written at the bound");
    net.blocked.clear();
    net.advance(10_000);
    let ec = net.engine(c);
    assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("k299"))]).unwrap(), Some(s(&"f".repeat(1100))));
    assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("secret"))]).unwrap(), None);
}

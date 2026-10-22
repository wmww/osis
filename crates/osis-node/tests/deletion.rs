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
// keep-at-most whole sends the timed delete with the replacing upload; the server deletes it at
// the bound with nobody online.
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

/// A record (about 330 KB) with a secret entry on aspect `asp` (a keep-at-most map) in one
/// commit at the server, compacted into one snapshot at the server when `compact`: (item,
/// aspect, label, the body carrying the record: the snapshot, else the commit).
fn kept_record(net: &mut Net, a: usize, g: osis_core::Tid, asp: &osis_schema::Aspect<osis_core::Value>, marker: &str, compact: bool) -> (osis_core::Tid, Ak, osis_core::LabelId, osis_core::CommitId) {
    let t = net.item(a, g, g, "x");
    let mut v: std::collections::BTreeMap<osis_core::Value, osis_core::Value> = (0..300).map(|i| (s(&format!("k{i:03}")), s(&"f".repeat(1100)))).collect();
    v.insert(s("secret"), s(marker));
    let mut m = Mutation::new();
    m.set(t, asp, &osis_core::Value::Map(v)).unwrap();
    let c0 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let ak = Ak::new(asp.ak()).unwrap();
    let l = net.label(a);
    if !compact {
        assert!(blobs(net, a, &l, &c0).iter().any(|b| net.server_ids(0, &l).contains(b)), "the commit is at the server");
        return (t, ak, l, c0);
    }
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    let snaps = snapshots(net, a, &t, &ak);
    assert_eq!(snaps.len(), 1);
    let s1 = snaps[0];
    assert!(!blobs(net, a, &l, &s1).is_empty() && blobs(net, a, &l, &s1).iter().all(|b| net.server_ids(0, &l).contains(b)), "the snapshot is at the server");
    (t, ak, l, s1)
}

/// Compaction snapshots node `n` holds of `(t, ak)` (dropped ones keep their header).
fn snapshots(net: &mut Net, n: usize, t: &osis_core::Tid, ak: &Ak) -> Vec<osis_core::CommitId> {
    let e = net.engine(n);
    e.commit_ids().into_iter().filter(|c| e.header(c).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot && h.aspects.iter().any(|x| x.tid == *t && x.ak == *ak))).collect()
}

fn blobs(net: &mut Net, n: usize, l: &osis_core::LabelId, c: &osis_core::CommitId) -> Vec<osis_core::BlobId> {
    net.sync(n).entries(l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c)).map(|(id, _)| id).collect()
}

/// Removes the secret entry (an erasing edit: it kills a write the snapshot carries).
fn erase_secret(net: &mut Net, a: usize, t: osis_core::Tid, asp: &osis_schema::Aspect<osis_core::Value>) {
    let mut m = Mutation::new();
    m.op(t, asp, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s("secret")) }).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
}

/// The keep-at-most maps: at most 0, at most 10 min.
fn kept_maps() -> [(&'static osis_schema::Aspect<osis_core::Value>, u64); 2] {
    [(&GONEMAP, 0), (&SHORTMAP, 600_000)]
}

/// The cases of the keep-at-most tests: (aspect, D, compacted first).
fn kept_cases() -> Vec<(&'static osis_schema::Aspect<osis_core::Value>, u64, bool)> {
    kept_maps().into_iter().flat_map(|(asp, d)| [(asp, d, true), (asp, d, false)]).collect()
}

// spec/commits.md §5 (keep at most: a body with a live write keeps to its first death plus D
// plus `AT_MOST_GRACE`, the next compaction drops it first), spec/requirements.md (Scale: cost
// per change): under keep at most 0 and 10 min, an erasing edit of a big record (a snapshot or
// an ordinary commit) sends O(change), with no new snapshot; the next compaction drops the old
// body here and at the server, and a member joining afterwards reads the record without the
// erased entry.
#[test]
fn erasing_edit_then_compaction_spec_commits_5() {
    for (i, (asp, _, compact)) in kept_cases().into_iter().enumerate() {
        let mut net = Net::new();
        let sv = net.add_server();
        let a = net.node(1, &[sv]);
        let c = net.node(3, &[sv]);
        net.blocked.insert((c, sv));
        let g = net.group(a, &[(c, Role::Read)], &[sv]);
        let (t, ak, l, s1) = kept_record(&mut net, a, g, asp, "ERASED-7d1e", compact);
        let before = snapshots(&mut net, a, &t, &ak);
        net.sent_bytes = 0;
        erase_secret(&mut net, a, t, asp);
        net.run();
        let sent = net.sent_bytes;
        assert!(sent < 32 * 1024, "case {i}: an erasing edit sent {sent} bytes (the record is about 330 KB)");
        assert_eq!(snapshots(&mut net, a, &t, &ak), before, "case {i}: no re-snapshot per erasing edit");
        assert!(net.engine(a).holds_body(&s1, &t, &ak), "case {i}: the old body keeps to the next compaction");
        assert!(net.engine(a).deaths(&s1, &t, &ak).unwrap().is_some());
        let at_server = blobs(&mut net, a, &l, &s1);
        let acts = net.sync(a).compact(&t, &ak).unwrap();
        net.actions(a, acts);
        net.run();
        assert!(!net.engine(a).holds_body(&s1, &t, &ak), "case {i}");
        let ids = net.server_ids(sv, &l);
        assert!(at_server.iter().all(|b| !ids.contains(b)), "case {i}: the old body deleted at the server");
        net.blocked.clear();
        net.advance(10_000);
        let ec = net.engine(c);
        assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("k007"))]).unwrap(), Some(s(&"f".repeat(1100))), "case {i}");
        assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("secret"))]).unwrap(), None, "case {i}");
        assert!(!ec.holds_body(&s1, &t, &ak));
    }
}

// spec/commits.md §5 (a body with a live write keeps to its first death plus D plus
// `AT_MOST_GRACE`), spec/sync.md §7 (snapshot first): with no compaction, under keep at most 0
// and 10 min, the old body (a snapshot or an ordinary commit) is kept to its bound, with no
// timed delete, then goes here and at the server after a covering snapshot is there; a member
// joining after the bound reads every live entry.
#[test]
fn live_body_goes_at_grace_bound_spec_commits_5() {
    for (i, (asp, d, compact)) in kept_cases().into_iter().enumerate() {
        let mut net = Net::new();
        let sv = net.add_server();
        let a = net.node(1, &[sv]);
        let c = net.node(3, &[sv]);
        net.blocked.insert((c, sv));
        let g = net.group(a, &[(c, Role::Read)], &[sv]);
        let (t, ak, l, s1) = kept_record(&mut net, a, g, asp, "ERASED-90b4", compact);
        let n = snapshots(&mut net, a, &t, &ak).len();
        erase_secret(&mut net, a, t, asp);
        net.run();
        let at_server = blobs(&mut net, a, &l, &s1);
        let bound = d + osis_core::format::AT_MOST_GRACE_MS;
        net.advance(bound / 2);
        assert!(net.engine(a).holds_body(&s1, &t, &ak), "case {i}: kept before the bound");
        assert!(at_server.iter().all(|b| net.server_ids(sv, &l).contains(b)), "case {i}: no timed delete");
        assert_eq!(snapshots(&mut net, a, &t, &ak).len(), n, "case {i}: no carrier before the bound");
        net.advance(bound - bound / 2 + 1);
        net.run();
        assert!(!net.engine(a).holds_body(&s1, &t, &ak), "case {i}: dropped at the bound");
        let ids = net.server_ids(sv, &l);
        assert!(at_server.iter().all(|b| !ids.contains(b)), "case {i}: deleted at the server");
        assert_eq!(snapshots(&mut net, a, &t, &ak).len(), n + 1, "case {i}: one carrier written at the bound");
        net.blocked.clear();
        net.advance(10_000);
        let ec = net.engine(c);
        for k in ["k000", "k150", "k299"] {
            assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s(k))]).unwrap(), Some(s(&"f".repeat(1100))), "case {i}: {k}");
        }
        assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("secret"))]).unwrap(), None, "case {i}");
    }
}

// spec/commits.md §5 (keep at most 0: a body with a live write keeps to the next compaction or
// its first death plus `AT_MOST_GRACE`; one with none goes at the kill), spec/requirements.md
// (Scale: cost per change): a text typed in several commits, then a delete of part of an older
// commit's text: the next pass sends O(change) and writes no snapshot; after the next
// compaction the old body is gone here and at the server, and a reader joining then cannot read
// the erased text.
#[test]
fn text_partly_erased_kept_to_compaction_spec_commits_5() {
    use osis_crdt::{Op, PathOp};
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let c = net.node(3, &[sv]);
    net.blocked.insert((c, sv));
    let g = net.group(a, &[(c, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "x");
    let ak = Ak::new(GONETEXT.ak()).unwrap();
    let marker = "ERASED-TEXT-3f8a";
    let chunk = 60_000;
    let mut ids = Vec::new();
    for k in 0..5 {
        let text = if k == 1 { format!("{}{marker}{}", "a".repeat(chunk / 2), "a".repeat(chunk / 2)) } else { "b".repeat(chunk) };
        let at = k * chunk + if k > 1 { marker.len() } else { 0 };
        let mut m = Mutation::new();
        m.op(t, &GONETEXT, PathOp { path: Vec::new(), op: Op::Insert { at, items: vec![s(&text)] } }).unwrap();
        ids.push(net.engine(a).commit(m).unwrap().unwrap());
        net.run();
    }
    let l = net.label(a);
    let old = ids[1];
    let at_server = blobs(&mut net, a, &l, &old);
    assert!(!at_server.is_empty() && at_server.iter().all(|b| net.server_ids(sv, &l).contains(b)));
    net.sent_bytes = 0;
    let mut m = Mutation::new();
    m.op(t, &GONETEXT, PathOp { path: Vec::new(), op: Op::Delete { at: chunk + chunk / 2 - 10, len: marker.len() + 20 } }).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let sent = net.sent_bytes;
    assert!(sent < 16 * 1024, "a partial delete sent {sent} bytes (the text is about 300 KB)");
    assert!(snapshots(&mut net, a, &t, &ak).is_empty(), "no whole-state snapshot");
    assert!(net.engine(a).holds_body(&old, &t, &ak), "the partly erased body keeps to the next compaction");
    assert!(net.engine(a).body_live(&old, &t, &ak).unwrap());
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    assert!(!net.engine(a).holds_body(&old, &t, &ak), "the old body goes at the compaction");
    let ids_now = net.server_ids(sv, &l);
    assert!(at_server.iter().all(|b| !ids_now.contains(b)), "and at the server");
    let want = net.engine(a).get(&t, &ak).unwrap().unwrap();
    net.blocked.clear();
    net.advance(10_000);
    let ec = net.engine(c);
    let got = ec.get(&t, &ak).unwrap().unwrap();
    assert_eq!(got, want);
    let osis_core::Value::Str(text) = got else { panic!("a text reads as a string") };
    assert_eq!(text.len(), 5 * chunk - 20);
    assert!(!text.contains(marker));
    assert!(!ec.holds_body(&old, &t, &ak));
}

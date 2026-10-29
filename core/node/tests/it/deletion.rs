#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Deletions, compaction and re-registration through a blind node (spec/sync.md §5-§7;
//! spec/commits.md §5; spec/permissions.md §3, §4).

use crate::net;
use net::*;
use osis_base::{Ak, Role};
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

// spec/sync.md §3 (retag), §5 (deletion by delete key), §6: a thing leaving the folder takes its own
// bodies out of the folder's label; a writer without the label delete key deletes them by delete key.
#[test]
fn thing_leaving_deleted_by_delete_key_spec_sync_5() {
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
    // the admin is away: only the writer can act, by delete key
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

/// A record (about 73 KB) with a secret entry on aspect `asp` (a keep-at-most map) in one
/// commit at the server, compacted into one snapshot at the server when `compact`: (item,
/// aspect, label, the body carrying the record: the snapshot, else the commit).
/// Entries of `kept_record`'s map, 1100 B each: just over a page (`PAGE_TARGET`).
const RECORD_KEYS: usize = 66;

fn kept_record(net: &mut Net, a: usize, g: osis_base::Tid, asp: &osis_schema::Aspect<osis_base::Value>, marker: &str, compact: bool) -> (osis_base::Tid, Ak, osis_base::LabelId, osis_base::CommitId) {
    let t = net.item(a, g, g, "x");
    let mut v: std::collections::BTreeMap<osis_base::Value, osis_base::Value> = (0..RECORD_KEYS).map(|i| (s(&format!("k{i:03}")), s(&"f".repeat(1100)))).collect();
    v.insert(s("secret"), s(marker));
    let mut m = Mutation::new();
    m.set(t, asp, &osis_base::Value::Map(v)).unwrap();
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
fn snapshots(net: &mut Net, n: usize, t: &osis_base::Tid, ak: &Ak) -> Vec<osis_base::CommitId> {
    let e = net.engine(n);
    e.commit_ids().into_iter().filter(|c| e.header(c).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot && h.aspects.iter().any(|x| x.tid == *t && x.ak == *ak))).collect()
}

fn blobs(net: &mut Net, n: usize, l: &osis_base::LabelId, c: &osis_base::CommitId) -> Vec<osis_base::BlobId> {
    net.sync(n).entries(l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c)).map(|(id, _)| id).collect()
}

/// Removes the secret entry (an erasing edit: it kills a write the snapshot carries).
fn erase_secret(net: &mut Net, a: usize, t: osis_base::Tid, asp: &osis_schema::Aspect<osis_base::Value>) {
    let mut m = Mutation::new();
    m.op(t, asp, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s("secret")) }).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
}

/// The keep-at-most maps: at most 0, at most 10 min.
fn kept_maps() -> [(&'static osis_schema::Aspect<osis_base::Value>, u64); 2] {
    [(&GONEMAP, 0), (&SHORTMAP, 600_000)]
}

/// The cases of the keep-at-most tests: (aspect, D, compacted first).
fn kept_cases() -> Vec<(&'static osis_schema::Aspect<osis_base::Value>, u64, bool)> {
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
        assert!(sent < 32 * 1024, "case {i}: an erasing edit sent {sent} bytes (the record is about 73 KB)");
        assert_eq!(snapshots(&mut net, a, &t, &ak), before, "case {i}: no re-snapshot per erasing edit");
        assert!(net.engine(a).body_not_dropped(&s1, &t, &ak), "case {i}: the old body keeps to the next compaction");
        assert!(net.engine(a).deaths(&s1, &t, &ak).unwrap().is_some());
        let at_server = blobs(&mut net, a, &l, &s1);
        let acts = net.sync(a).compact(&t, &ak).unwrap();
        net.actions(a, acts);
        net.run();
        assert!(!net.engine(a).body_not_dropped(&s1, &t, &ak), "case {i}");
        let ids = net.server_ids(sv, &l);
        assert!(at_server.iter().all(|b| !ids.contains(b)), "case {i}: the old body deleted at the server");
        net.blocked.clear();
        net.advance(10_000);
        let ec = net.engine(c);
        assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("k007"))]).unwrap(), Some(s(&"f".repeat(1100))), "case {i}");
        assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("secret"))]).unwrap(), None, "case {i}");
        assert!(!ec.body_not_dropped(&s1, &t, &ak));
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
        let bound = d + osis_base::format::AT_MOST_GRACE_MS;
        net.advance(bound / 2);
        assert!(net.engine(a).body_not_dropped(&s1, &t, &ak), "case {i}: kept before the bound");
        assert!(at_server.iter().all(|b| net.server_ids(sv, &l).contains(b)), "case {i}: no timed delete");
        assert_eq!(snapshots(&mut net, a, &t, &ak).len(), n, "case {i}: no carrier before the bound");
        net.advance(bound - bound / 2 + 1);
        net.run();
        assert!(!net.engine(a).body_not_dropped(&s1, &t, &ak), "case {i}: dropped at the bound");
        let ids = net.server_ids(sv, &l);
        assert!(at_server.iter().all(|b| !ids.contains(b)), "case {i}: deleted at the server");
        assert_eq!(snapshots(&mut net, a, &t, &ak).len(), n + 1, "case {i}: one carrier written at the bound");
        net.blocked.clear();
        net.advance(10_000);
        let ec = net.engine(c);
        for k in ["k000", "k033", "k065"] {
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
    let chunk = 3_000;
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
    assert!(sent < 5 * chunk / 8, "a partial delete sent {sent} bytes of a {}-byte text", 5 * chunk);
    assert!(snapshots(&mut net, a, &t, &ak).is_empty(), "no whole-state snapshot");
    assert!(net.engine(a).body_not_dropped(&old, &t, &ak), "the partly erased body keeps to the next compaction");
    assert!(net.engine(a).body_live(&old, &t, &ak).unwrap());
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    assert!(!net.engine(a).body_not_dropped(&old, &t, &ak), "the old body goes at the compaction");
    let ids_now = net.server_ids(sv, &l);
    assert!(at_server.iter().all(|b| !ids_now.contains(b)), "and at the server");
    let want = net.engine(a).get(&t, &ak).unwrap().unwrap();
    net.blocked.clear();
    net.advance(10_000);
    let ec = net.engine(c);
    let got = ec.get(&t, &ak).unwrap().unwrap();
    assert_eq!(got, want);
    let osis_base::Value::Str(text) = got else { panic!("a text reads as a string") };
    assert_eq!(text.len(), 5 * chunk - 20);
    assert!(!text.contains(marker));
    assert!(!ec.body_not_dropped(&old, &t, &ak));
}

// spec/commits.md §5 (a deleted text element's creation stays a live write: a body whose
// text was all erased keeps to the next compaction or its first death plus `AT_MOST_GRACE`;
// the erased data may persist that long), spec/crdt.md §4.8: under keep at most 0, a word
// typed then wholly deleted is kept before the bound with no snapshot, gone here and at the
// server after it, and a reader joining then cannot read it.
#[test]
fn text_fully_erased_kept_to_grace_bound_spec_commits_5() {
    use osis_crdt::{Op, PathOp};
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let c = net.node(3, &[sv]);
    net.blocked.insert((c, sv));
    let g = net.group(a, &[(c, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "x");
    let ak = Ak::new(GONETEXT.ak()).unwrap();
    let mut m = Mutation::new();
    m.op(t, &GONETEXT, PathOp { path: Vec::new(), op: Op::Insert { at: 0, items: vec![s("SECRET")] } }).unwrap();
    let typed = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let at_server = blobs(&mut net, a, &l, &typed);
    let mut m = Mutation::new();
    m.op(t, &GONETEXT, PathOp { path: Vec::new(), op: Op::Delete { at: 0, len: 6 } }).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(net.engine(a).get(&t, &ak).unwrap().unwrap_or(s("")), s(""));
    assert!(net.engine(a).body_live(&typed, &t, &ak).unwrap(), "a deleted char's creation is a live write");
    net.advance(30 * 60_000);
    assert!(net.engine(a).body_not_dropped(&typed, &t, &ak), "held before the bound");
    assert!(at_server.iter().all(|b| net.server_ids(sv, &l).contains(b)), "and at the server");
    assert!(snapshots(&mut net, a, &t, &ak).is_empty(), "no snapshot before the bound");
    net.advance(31 * 60_000);
    net.run();
    assert!(!net.engine(a).body_not_dropped(&typed, &t, &ak), "dropped at the bound");
    let ids = net.server_ids(sv, &l);
    assert!(at_server.iter().all(|b| !ids.contains(b)), "deleted at the server");
    net.blocked.clear();
    net.advance(10_000);
    let ec = net.engine(c);
    assert_eq!(ec.get(&t, &ak).unwrap().unwrap_or(s("")), s(""));
    assert!(!ec.body_not_dropped(&typed, &t, &ak));
}

// spec/commits.md §5 (a dropped body's liveness counts every write the state holds by dot, bare
// anchors too), spec/sync.md §7 (a body with live writes is deleted at a label only while
// another entry carries them): under keep at most 0, a word typed, the text reset, compacted,
// reset again: the snapshot's only live records are the first word's bare anchors (no `ts`).
// At the bound it drops with them live and the carrier written then is lost on its way to the
// server: the snapshot stays at the server until the carrier is there (was: judged dead once
// dropped, deleted without a carrier, and the label lost the anchors a fresh node needs to
// place concurrent inserts).
#[test]
fn dropped_snapshot_waits_for_lost_carrier_spec_sync_7() {
    use osis_crdt::{Op, PathOp};
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    let t = net.item(a, g, g, "x");
    let ak = Ak::new(GONETEXT.ak()).unwrap();
    let edit = |net: &mut Net, op: Option<Op>| {
        let mut m = Mutation::new();
        match op {
            Some(op) => m.op(t, &GONETEXT, PathOp { path: Vec::new(), op }).unwrap(),
            None => m.remove_aspect(t, &GONETEXT).unwrap(),
        };
        net.engine(a).commit(m).unwrap().unwrap();
        net.run();
    };
    edit(&mut net, Some(Op::Insert { at: 0, items: vec![s("SECRET")] }));
    edit(&mut net, None);
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    let snaps = snapshots(&mut net, a, &t, &ak);
    assert_eq!(snaps.len(), 1);
    let s1 = snaps[0];
    let l = net.label(a);
    let at_server = blobs(&mut net, a, &l, &s1);
    assert!(!at_server.is_empty() && at_server.iter().all(|b| net.server_ids(sv, &l).contains(b)), "the snapshot is at the server");
    edit(&mut net, Some(Op::Insert { at: 0, items: vec![s("two")] }));
    edit(&mut net, None);
    assert!(net.engine(a).body_not_dropped(&s1, &t, &ak) && net.engine(a).body_live(&s1, &t, &ak).unwrap(), "the anchors are live writes");
    net.lose_uploads.insert(a);
    net.advance(61 * 60_000);
    net.run();
    assert!(!net.engine(a).body_not_dropped(&s1, &t, &ak), "dropped at the bound");
    assert!(net.engine(a).body_live(&s1, &t, &ak).unwrap(), "dropped live, its anchors still in the state");
    assert!(snapshots(&mut net, a, &t, &ak).len() > 1, "a carrier written");
    let ids = net.server_ids(sv, &l);
    assert!(at_server.iter().all(|b| ids.contains(b)), "kept at the server while the carrier is not there");
    net.lose_uploads.clear();
    net.advance(60_000);
    net.run();
    let ids = net.server_ids(sv, &l);
    assert!(at_server.iter().all(|b| !ids.contains(b)), "deleted once the carrier is there");
    let carried = snapshots(&mut net, a, &t, &ak).into_iter().filter(|c| *c != s1).any(|c| {
        let bs = blobs(&mut net, a, &l, &c);
        !bs.is_empty() && bs.iter().all(|b| ids.contains(b))
    });
    assert!(carried, "a carrier is at the server");
}

// spec/commits.md §5 (a snapshot's bounds come from the writes it carries; a node that may write
// the aspect writes the carrier before dropping a body with live writes), spec/sync.md §7: the
// typed writer of a keep-at-most record goes away; another writer, which never knew the schema,
// erases an entry with an untyped edit and at the bound writes the carrier, with the record's
// bound, and deletes the replaced body at the server (was: no snapshot without the schema, so
// the body stayed).
#[test]
fn carrier_by_writer_without_schema_spec_commits_5() {
    use osis_crdt::{Op, PathOp};
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let (t, ak, l, c0) = kept_record(&mut net, a, g, &SHORTMAP, "ERASED-3c5f", false);
    net.run();
    let _gone = net.take(a);
    let mut m = Mutation::new();
    m.op(t, &ak, PathOp { path: Vec::new(), op: Op::Remove(s("secret")) }).unwrap();
    net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(net.engine(b).get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("secret"))]).unwrap(), None);
    let at_server = blobs(&mut net, b, &l, &c0);
    assert!(!at_server.is_empty());
    let n = snapshots(&mut net, b, &t, &ak).len();
    net.advance(600_000 + osis_base::format::AT_MOST_GRACE_MS + 1);
    net.run();
    assert!(!net.engine(b).body_not_dropped(&c0, &t, &ak), "dropped at the bound");
    let snaps = snapshots(&mut net, b, &t, &ak);
    assert_eq!(snaps.len(), n + 1, "one carrier");
    let r = net.engine(b).header(&snaps[n]).unwrap().aspects[0].retention;
    assert_eq!(r.at_most.rel, Some(600_000), "the record's bound");
    let ids = net.server_ids(sv, &l);
    assert!(at_server.iter().all(|x| !ids.contains(x)), "deleted at the server");
}

// spec/commits.md §5 (purge: a writer holding no covering snapshot after applying the request
// re-snapshots; a snapshot's bounds come from the writes it carries): the typed writer of a
// keep-at-most record, compacted, goes away; another writer, which never knew the schema,
// erases the secret entry with an untyped edit purging the entry's commit: the snapshot carrying
// the secret drops, a new one carries the live entries with the record's bound, and neither the
// secret's commit nor the old snapshot stays at the server.
#[test]
fn purge_resnapshot_by_writer_without_schema_spec_commits_5() {
    use osis_crdt::{Op, PathOp};
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    net.blocked.insert((c, sv));
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "x");
    let ak = Ak::new(SHORTMAP.ak()).unwrap();
    let v: std::collections::BTreeMap<osis_base::Value, osis_base::Value> = (0..4).map(|i| (s(&format!("k{i}")), s("f"))).collect();
    let mut m = Mutation::new();
    m.set(t, &SHORTMAP, &osis_base::Value::Map(v)).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.op(t, &SHORTMAP, PathOp { path: vec![osis_crdt::PathSeg::Key(s("secret"))], op: Op::Put(s("PURGED-51d2")) }).unwrap();
    let c1 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    let l = net.label(a);
    let s1 = snapshots(&mut net, a, &t, &ak)[0];
    let _gone = net.take(a);
    let at_server: Vec<_> = [c1, s1].iter().flat_map(|x| blobs(&mut net, b, &l, x)).collect();
    assert!(!blobs(&mut net, b, &l, &s1).is_empty());
    assert!(at_server.iter().all(|x| net.server_ids(sv, &l).contains(x)));
    let mut m = Mutation::new();
    m.op(t, &ak, PathOp { path: Vec::new(), op: Op::Remove(s("secret")) }).unwrap();
    m.purge(osis_commit::PurgeItem::Commit { commit: c1, tid: t, ak: ak.clone() });
    net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    assert!(!net.engine(b).body_not_dropped(&s1, &t, &ak), "the snapshot carrying the secret dropped");
    let snaps: Vec<_> = snapshots(&mut net, b, &t, &ak).into_iter().filter(|x| *x != s1).collect();
    assert_eq!(snaps.len(), 1, "re-snapshotted");
    assert_eq!(net.engine(b).header(&snaps[0]).unwrap().aspects[0].retention.at_most.rel, Some(600_000), "the record's bound");
    let ids = net.server_ids(sv, &l);
    assert!(at_server.iter().all(|x| !ids.contains(x)), "the purged bodies left the server");
    net.blocked.clear();
    net.advance(10_000);
    let ec = net.engine(c);
    assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("k2"))]).unwrap(), Some(s("f")));
    assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("secret"))]).unwrap(), None);
}

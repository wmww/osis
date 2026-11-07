#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Deletions, compaction and re-registration through a host (spec/sync.md §5-§7;
//! spec/commits.md §5; spec/permissions.md §3, §4).

use crate::net;
use net::*;
use osis_base::{Ak, Role};
use osis_node::Mutation;
use osis_node::sync::EntryKind;
use osis_schema::RawKey;
use osis_schema::core_types as ct;

// spec/sync.md §3 (retag), §5 (deletion by delete key), §6: a thing leaving the folder takes its own
// bodies out of the folder's label; a writer without the label delete key deletes them by delete key.
#[test]
fn thing_leaving_deleted_by_delete_key_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let c = net.write(b, t, "by b");
    net.run();
    let l = net.label(a);
    let blobs: Vec<_> = net.sync(b).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect();
    assert!(!blobs.is_empty() && blobs.iter().all(|id| net.host_ids(host, &l).contains(id)));
    // the admin is away: only the writer can act, by delete key
    net.set_online(a, false);
    let e = net.engine(b);
    let mut grp = e.get_typed(&g, &ct::GROUP).unwrap().unwrap();
    grp.items.remove(&t);
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &grp).unwrap();
    e.commit(m).unwrap();
    net.run();
    net.trace(&[b]);
    assert!(!net.engine(b).closure(&g).contains(&t));
    let ids = net.host_ids(host, &l);
    assert!(blobs.iter().all(|id| !ids.contains(id)), "the commit only on the departed thing went");
}

// spec/commits.md §5 (Covered: a delta with an expiry is covered once held value-less), spec/sync.md
// §7: before its expiry a snapshot does not cover an expiring write (it carries its value
// value-less); past it the write's leftover is covered by that snapshot and dropped like any body
#[test]
fn expired_leftover_dropped_once_covered_spec_commits_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
    let t = net.item(a, g, g, "v1");
    let mut m = Mutation::new();
    m.set(t, &REG, &s("v2")).unwrap();
    m.expires(t, &REG, osis_base::WallMs(net.now() + 5_000)).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let ak = Ak::new(REG.ak()).unwrap();
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    let held = |net: &mut Net| net.engine(a).coverers_of(&c, &t, &ak).is_empty();
    assert!(net.engine(a).body_not_dropped(&c, &t, &ak) && held(&mut net), "not covered before its expiry");
    assert_eq!(net.read(a, t), Some(s("v2")));
    net.advance(6_000);
    assert!(!held(&mut net), "its leftover dropped as covered by the snapshot");
    assert_eq!(net.read(a, t), None);
}

// spec/sync.md §7, spec/commits.md §5: compaction uploads the snapshot first, then drops and
// deletes the covered bodies; a holder joining later reads the live value from the snapshot; the
// carriers go `TOMBSTONE_LIFETIME` after the deletions.
#[test]
fn compaction_then_deletion_spec_sync_7() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let c = net.node(3, &[host]);
    net.blocked.insert((c, host));
    let g = net.group(a, &[(c, Role::Read)], &[host]);
    let t = net.item(a, g, g, "v1");
    net.write(a, t, "v2");
    net.write(a, t, "v3");
    net.run();
    let l = net.label(a);
    let before = net.host_ids(host, &l).len();
    let ak = Ak::new(REG.ak()).unwrap();
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    net.run();
    net.trace(&[a]);
    let after = net.host_ids(host, &l).len();
    assert!(after < before, "covered bodies deleted after the snapshot: {before} -> {after}");
    net.blocked.clear();
    net.advance(10_000);
    net.trace(&[c]);
    assert_eq!(net.read(c, t), Some(s("v3")), "the live value is served from the snapshot");
    // the dropped bodies' carriers go once their entries and tombstones have (growth:
    // notes/growth.md)
    // (the item's creation commit keeps its entry for `created.0`, so its carrier stays)
    assert_eq!(net.sync(a).sync_rows(b's'), 3, "carriers recorded");
    net.advance(osis_base::format::TOMBSTONE_LIFETIME_MS);
    net.advance(60_000);
    assert_eq!(net.sync(a).sync_rows(b's'), 1, "only the carrier of a body with an entry left");
    assert_eq!(net.read(a, t), Some(s("v3")));
}

// spec/sync.md §5 Register: at a host past its byte caps a child step is still taken, once per
// `over_cap_step_ms` per label; a second removal within it is refused for now (code 12): the
// admin's open stays (not stranded) and the step lands once the time has passed.
#[test]
fn rotation_at_full_host_waits_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let d = net.node(4, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read), (d, Role::Read)], &[host]);
    net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    assert_eq!(net.host_path(host, &l).len(), 1);
    let policy = osis_host::HostPolicy { max_bytes: 1, ..osis_host::HostPolicy::default() };
    let wait = policy.over_cap_step_ms;
    net.restart_host_with(host, policy);
    net.run();
    let (at, bt, ct_, dt) = (net.tid(a), net.tid(b), net.tid(c), net.tid(d));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write), (dt, Role::Read)]);
    remove_holder(e, g, ct_, &rs, 41);
    net.run();
    net.advance(60_000);
    assert_eq!(net.host_path(host, &l).len(), 2, "the first step past the cap is taken");
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write)]);
    remove_holder(e, g, dt, &rs, 42);
    net.run();
    net.advance(60_000);
    assert_eq!(net.host_path(host, &l).len(), 2, "the second waits");
    let d = net.sync(a).take_diagnostics();
    assert!(d.iter().any(|x| x.contains("step refused for now (code 12)")), "{d:?}");
    let st = net.sync(a).label_status().into_iter().find(|s| s.label == l).unwrap();
    assert!(!st.stranded && st.open == 1, "{st:?}");
    net.advance(wait);
    net.advance(60_000);
    net.trace(&[a]);
    assert_eq!(net.host_path(host, &l).len(), 3, "it lands after over_cap_step_ms");
}

// spec/sync.md §5 Register (a registrar keeps its open on a step refused for now and registers it
// again after a back-off, never at once): while the host refuses a child step for its cap, the
// admin's own writes (each a pass) do not send it again each time.
#[test]
fn refused_step_backs_off_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let d = net.node(4, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read), (d, Role::Read)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    net.restart_host_with(host, osis_host::HostPolicy { max_bytes: 1, ..osis_host::HostPolicy::default() });
    net.run();
    let (at, bt, ct_, dt) = (net.tid(a), net.tid(b), net.tid(c), net.tid(d));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write), (dt, Role::Read)]);
    remove_holder(e, g, ct_, &rs, 41);
    net.run();
    net.advance(60_000);
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write)]);
    remove_holder(e, g, dt, &rs, 42);
    net.run();
    net.advance(60_000);
    assert_eq!(net.host_path(host, &l).len(), 2, "the second waits");
    let before = net.sent_kinds.get(&7).copied().unwrap_or(0);
    for i in 0..20 {
        net.write(a, t, &format!("v{i}"));
        net.run();
        net.advance(100);
    }
    let sent = net.sent_kinds.get(&7).copied().unwrap_or(0) - before;
    assert!(sent <= 2, "{sent} registrations sent in 2 s");
}

// spec/sync.md §5 Re-registration (a step refused for now holds back nothing else): at a full host
// refusing the child step (a second removal within `over_cap_step_ms`), the admin still deletes
// there what the label must not hold, which is what frees room.
#[test]
fn refused_step_deletes_still_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let d = net.node(4, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read), (d, Role::Read)], &[host]);
    net.item(a, g, g, "x");
    let u = net.item(a, g, g, "y");
    net.run();
    let cu = net.write(a, u, "z");
    net.run();
    let l = net.label(a);
    let blobs: Vec<_> = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == cu)).map(|(id, _)| id).collect();
    assert!(!blobs.is_empty() && blobs.iter().all(|id| net.host_ids(host, &l).contains(id)));
    net.restart_host_with(host, osis_host::HostPolicy { max_bytes: 1, ..osis_host::HostPolicy::default() });
    net.run();
    let (at, bt, ct_, dt) = (net.tid(a), net.tid(b), net.tid(c), net.tid(d));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write), (dt, Role::Read)]);
    remove_holder(e, g, ct_, &rs, 41);
    net.run();
    net.advance(60_000);
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write)]);
    remove_holder(e, g, dt, &rs, 42);
    net.run();
    net.advance(60_000);
    assert_eq!(net.host_path(host, &l).len(), 2, "the second step waits");
    // u leaves the group: its own commit's bodies go from the label while the step waits
    let e = net.engine(a);
    let mut grp = e.get_typed(&g, &ct::GROUP).unwrap().unwrap();
    grp.items.remove(&u);
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &grp).unwrap();
    e.commit(m).unwrap();
    net.run();
    net.advance(1_000);
    assert_eq!(net.host_path(host, &l).len(), 2, "the step still waits");
    let ids = net.host_ids(host, &l);
    assert!(blobs.iter().all(|id| !ids.contains(id)), "deleted while the step waits");
}

// spec/sync.md §5 Re-registration (a step refused for now holds back nothing else): while a host
// refuses the child step for its rate (code 4), the admin's new writes go up under the host's
// head, wrapped under the newest read epoch: the remaining writer reads them, the removed reader,
// whose sync key still opens that head, cannot.
#[test]
fn refused_step_uploads_still_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read)], &[host]);
    let t = net.item(a, g, g, "before");
    net.run();
    assert_eq!(net.read(c, t), Some(s("before")));
    let l = net.label(a);
    net.restart_host_with(host, osis_host::HostPolicy { registers: 0, ..osis_host::HostPolicy::default() });
    net.run();
    net.advance(60_000);
    let old_c = net.engine(c).read_secrets(&g);
    net.set_online(c, false);
    let (at, bt, ct_) = (net.tid(a), net.tid(b), net.tid(c));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write)]);
    remove_holder(e, g, ct_, &rs, 41);
    net.run();
    net.advance(1_000);
    assert_eq!(net.host_path(host, &l).len(), 1, "the step is refused");
    let diag = net.sync(a).take_diagnostics();
    assert!(diag.iter().any(|x| x.contains("step refused for now (code 4)")), "{diag:?}");
    let cw = net.write(a, t, "after");
    net.run();
    let ids: Vec<_> = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == cw)).map(|(id, _)| id).collect();
    assert!(!ids.is_empty());
    for id in &ids {
        let (w, _) = net.sync(a).entry_meta(&l, id).unwrap();
        assert!(osis_label::unwrap_any(old_c.iter(), id, &w).is_none(), "wrapped under the new read epoch");
    }
    net.advance(1_000);
    assert_eq!(net.host_path(host, &l).len(), 1, "the step still waits");
    assert!(ids.iter().all(|id| net.host_ids(host, &l).contains(id)), "uploaded under the host's head");
    assert_eq!(net.read(b, t), Some(s("after")));
    // the removed reader comes back: it opens the old head there, but cannot read the new write
    net.blocked_peers.extend([(a, c), (b, c)]);
    net.set_online(c, true);
    net.advance(10_000);
    assert_ne!(net.read(c, t), Some(s("after")), "nothing new readable to the removed reader");
}

// spec/sync.md §5 (re-registration, upload order), spec/permissions.md §3-§4 (stranded
// heartbeat): an admin rotating out a holder issues a child step at the host after uploading
// the rotation commit; the remaining writer follows; the removed holder's open walks to the new
// step, its claim is refused and it places a stranded heartbeat by deposit.
// spec/permissions.md §4 (stranded heartbeat), spec/crypto.md §4 (removed holder)
#[test]
fn reregistration_after_rotation_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read)], &[host]);
    let t = net.item(a, g, g, "before");
    net.run();
    assert_eq!(net.read(c, t), Some(s("before")));
    let l = net.label(a);
    assert_eq!(net.host_path(host, &l).len(), 1);
    net.set_online(c, false);
    let (at, bt, ct_) = (net.tid(a), net.tid(b), net.tid(c));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write)]);
    remove_holder(e, g, ct_, &rs, 41);
    net.write(a, t, "after");
    net.run();
    net.trace(&[a, b]);
    assert_eq!(net.host_path(host, &l).len(), 2, "a child step was registered");
    assert_eq!(net.sync(a).labels()[0].1.steps.len(), 2, "and recorded in label.0");
    assert_eq!(net.read(b, t), Some(s("after")));
    net.write(b, t, "from b");
    net.run();
    assert_eq!(net.read(a, t), Some(s("from b")), "the writer stamps under the new step");
    // the removed holder comes back: walked to the new step, claim refused, stranded heartbeat
    let n_before = net.host_ids(host, &l).len();
    net.blocked_peers.extend([(a, c), (b, c)]);
    net.set_online(c, true);
    net.advance(10_000);
    assert_eq!(net.read(c, t), Some(s("before")), "nothing new readable");
    assert!(net.host_ids(host, &l).len() > n_before, "a stranded heartbeat was deposited");
    net.run();
    let seen = net.engine(a).get_typed(&ct_, &ct::SEEN).unwrap();
    assert!(seen.is_some_and(|x| x.stranded), "co-holders read the stranded heartbeat");
}

/// A record (about 73 KB) with a secret entry on aspect `asp` (a keep-at-most map) in one
/// commit at the host, compacted into one snapshot at the host when `compact`: (item,
/// aspect, label, the body carrying the record: the snapshot, else the commit).
/// Entries of `kept_record`'s map, 1100 B each: just over a page (`PAGE_TARGET`).
const RECORD_KEYS: usize = 66;

fn kept_record(net: &mut Net, a: usize, g: osis_base::Tid, asp: &osis_schema::Aspect<osis_base::Value>, marker: &str, compact: bool) -> (osis_base::Tid, Ak, osis_base::LabelId, osis_base::CommitId) {
    let t = net.item(a, g, g, "x");
    let mut v: std::collections::BTreeMap<osis_base::Value, osis_base::Value> = (0..RECORD_KEYS).map(|i| (s(&format!("k{i:03}")), s(&"f".repeat(1100)))).collect();
    v.insert(s("secret"), s(marker));
    let mut m = Mutation::new();
    m.set(t, asp, &osis_base::Value::Map(v.into_iter().collect())).unwrap();
    let c0 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let ak = Ak::new(asp.ak()).unwrap();
    let l = net.label(a);
    if !compact {
        assert!(blobs(net, a, &l, &c0).iter().any(|b| net.host_ids(0, &l).contains(b)), "the commit is at the host");
        return (t, ak, l, c0);
    }
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    let snaps = snapshots(net, a, &t, &ak);
    assert_eq!(snaps.len(), 1);
    let s1 = snaps[0];
    assert!(!blobs(net, a, &l, &s1).is_empty() && blobs(net, a, &l, &s1).iter().all(|b| net.host_ids(0, &l).contains(b)), "the snapshot is at the host");
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

// spec/commits.md §5 (keep at most 0 after replaced: a body goes at its first death; one with a
// live write after its carrier), spec/requirements.md (Scale: the exception the bound buys): an
// erasing edit of a big record (a snapshot or an ordinary commit) writes one carrier snapshot
// of the aspect at once; the old body goes here and at the host in the same pass, and a holder
// joining afterwards reads every live entry and not the erased one.
#[test]
fn erasing_edit_carrier_at_once_spec_commits_5() {
    for (i, compact) in [true, false].into_iter().enumerate() {
        let asp = &GONEMAP;
        let mut net = Net::new();
        let host = net.add_host();
        let a = net.node(1, &[host]);
        let c = net.node(3, &[host]);
        net.blocked.insert((c, host));
        let g = net.group(a, &[(c, Role::Read)], &[host]);
        let (t, ak, l, s1) = kept_record(&mut net, a, g, asp, "ERASED-7d1e", compact);
        let n = snapshots(&mut net, a, &t, &ak).len();
        let at_host = blobs(&mut net, a, &l, &s1);
        erase_secret(&mut net, a, t, asp);
        net.run();
        assert!(!net.engine(a).body_not_dropped(&s1, &t, &ak), "case {i}: dropped at its first death");
        assert_eq!(snapshots(&mut net, a, &t, &ak).len(), n + 1, "case {i}: one carrier per erasing edit");
        let ids = net.host_ids(host, &l);
        assert!(at_host.iter().all(|b| !ids.contains(b)), "case {i}: deleted at the host");
        net.blocked.clear();
        net.advance(10_000);
        let ec = net.engine(c);
        for k in ["k000", "k033", "k065"] {
            assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s(k))]).unwrap(), Some(s(&"f".repeat(1100))), "case {i}: {k}");
        }
        assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("secret"))]).unwrap(), None, "case {i}");
        assert!(!ec.body_not_dropped(&s1, &t, &ak));
    }
}

// spec/commits.md §5 (keep at most 0 after replaced: a body with a live write goes at its first
// death after its carrier), spec/requirements.md (Scale: the exception the bound buys): a text
// typed in several commits, then a delete of part of an older commit's text: one carrier
// snapshot of the text, the old body gone here and at the host in the same pass, and a reader
// joining then cannot read the erased text.
#[test]
fn text_partly_erased_carrier_at_once_spec_commits_5() {
    use osis_crdt::{Op, PathOp};
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let c = net.node(3, &[host]);
    net.blocked.insert((c, host));
    let g = net.group(a, &[(c, Role::Read)], &[host]);
    let t = net.item(a, g, g, "x");
    let ak = Ak::new(GONETEXT.ak()).unwrap();
    let marker = "ERASED-TEXT-3f8a";
    let chunk = 200;
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
    let at_host = blobs(&mut net, a, &l, &old);
    assert!(!at_host.is_empty() && at_host.iter().all(|b| net.host_ids(host, &l).contains(b)));
    let mut m = Mutation::new();
    m.op(t, &GONETEXT, PathOp { path: Vec::new(), op: Op::Delete { at: chunk + chunk / 2 - 10, len: marker.len() + 20 } }).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(snapshots(&mut net, a, &t, &ak).len(), 1, "one carrier");
    assert!(!net.engine(a).body_not_dropped(&old, &t, &ak), "the partly erased body goes at its first death");
    let ids_now = net.host_ids(host, &l);
    assert!(at_host.iter().all(|b| !ids_now.contains(b)), "and at the host");
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

// spec: none (a measure, spec/requirements.md Scale; issues/covered-cost-whole-snapshot.md): one
// `covered` of a body of a text aspect against a snapshot, by the text's size. By hand, release:
// `OSIS_SCALE_BODIES=1000 cargo test --release -p osis-node --test it -- --ignored --nocapture deletion::covered_text_cost`
#[test]
#[ignore = "scale: by hand"]
fn covered_text_cost() {
    use osis_crdt::{Op, PathOp};
    let bodies: usize = std::env::var("OSIS_SCALE_BODIES").ok().and_then(|x| x.parse().ok()).unwrap_or(200);
    let chunk = 100;
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
    let t = net.item(a, g, g, "x");
    let ak = Ak::new(GONETEXT.ak()).unwrap();
    let mut ids = Vec::new();
    for k in 0..bodies {
        let mut m = Mutation::new();
        m.op(t, &GONETEXT, PathOp { path: Vec::new(), op: Op::Insert { at: k * chunk, items: vec![s(&"b".repeat(chunk))] } }).unwrap();
        ids.push(net.engine(a).commit(m).unwrap().unwrap());
    }
    let snap = net.engine(a).snapshot(&t, &ak).unwrap().unwrap();
    osis_node::costs::take();
    let at = std::time::Instant::now();
    let checks = ids.len().min(50);
    let every = ids.len() / checks;
    for c in ids.iter().step_by(every).take(checks) {
        assert_eq!(net.engine(a).covered(&snap, c, &t, &ak).unwrap(), Some(true));
    }
    println!("COVERED {bodies} bodies of {chunk} chars: {:?} a check; spans {:?}", at.elapsed() / checks as u32, osis_node::costs::take());
}

// spec/commits.md §5 (a deleted text element's creation stays a live write: a body whose text
// was all erased goes at its first death after a carrier of its anchors), spec/crdt.md §4.8:
// under keep at most 0, a word typed then wholly deleted is gone here and at the host in the
// erasing pass, under one carrier, and a reader joining then cannot read it.
#[test]
fn text_fully_erased_carrier_at_once_spec_commits_5() {
    use osis_crdt::{Op, PathOp};
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let c = net.node(3, &[host]);
    net.blocked.insert((c, host));
    let g = net.group(a, &[(c, Role::Read)], &[host]);
    let t = net.item(a, g, g, "x");
    let ak = Ak::new(GONETEXT.ak()).unwrap();
    let mut m = Mutation::new();
    m.op(t, &GONETEXT, PathOp { path: Vec::new(), op: Op::Insert { at: 0, items: vec![s("SECRET")] } }).unwrap();
    let typed = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let at_host = blobs(&mut net, a, &l, &typed);
    let mut m = Mutation::new();
    m.op(t, &GONETEXT, PathOp { path: Vec::new(), op: Op::Delete { at: 0, len: 6 } }).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(net.engine(a).get(&t, &ak).unwrap().unwrap_or(s("")), s(""));
    assert!(!net.engine(a).body_not_dropped(&typed, &t, &ak), "dropped at its first death");
    assert_eq!(snapshots(&mut net, a, &t, &ak).len(), 1, "one carrier of the anchors");
    let ids = net.host_ids(host, &l);
    assert!(at_host.iter().all(|b| !ids.contains(b)), "deleted at the host");
    net.blocked.clear();
    net.advance(10_000);
    let ec = net.engine(c);
    assert_eq!(ec.get(&t, &ak).unwrap().unwrap_or(s("")), s(""));
    assert!(!ec.body_not_dropped(&typed, &t, &ak));
}

// spec/commits.md §5 (a dropped body's liveness counts every write the state holds by dot, bare
// anchors too), spec/sync.md §7 (a body with live writes is deleted at a label only while
// another entry carries them): under keep at most 0, a word typed and the text reset: the
// carrier written then has as its only live records the word's bare anchors (no `ts`). A word
// typed and the text reset again: the carrier drops at its first death with them live, and the
// carrier written then is lost on its way to the host: the first stays at the host until the
// second is there (was: judged dead once dropped, deleted without a carrier, and the label lost
// the anchors a fresh node needs to place concurrent inserts).
#[test]
fn dropped_snapshot_waits_for_lost_carrier_spec_sync_7() {
    use osis_crdt::{Op, PathOp};
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
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
    let snaps = snapshots(&mut net, a, &t, &ak);
    assert_eq!(snaps.len(), 1, "the carrier of the word's anchors");
    let s1 = snaps[0];
    let l = net.label(a);
    let at_host = blobs(&mut net, a, &l, &s1);
    assert!(!at_host.is_empty() && at_host.iter().all(|b| net.host_ids(host, &l).contains(b)), "the snapshot is at the host");
    edit(&mut net, Some(Op::Insert { at: 0, items: vec![s("two")] }));
    assert!(net.engine(a).body_not_dropped(&s1, &t, &ak) && net.engine(a).body_live(&s1, &t, &ak).unwrap(), "the anchors are live writes");
    net.lose_uploads.insert(a);
    edit(&mut net, None);
    assert!(!net.engine(a).body_not_dropped(&s1, &t, &ak), "dropped at its first death");
    assert!(net.engine(a).body_live(&s1, &t, &ak).unwrap(), "dropped live, its anchors still in the state");
    assert!(snapshots(&mut net, a, &t, &ak).len() > 1, "a carrier written");
    let ids = net.host_ids(host, &l);
    assert!(at_host.iter().all(|b| ids.contains(b)), "kept at the host while the carrier is not there");
    net.lose_uploads.clear();
    net.advance(60_000);
    net.run();
    let ids = net.host_ids(host, &l);
    assert!(at_host.iter().all(|b| !ids.contains(b)), "deleted once the carrier is there");
    let carried = snapshots(&mut net, a, &t, &ak).into_iter().filter(|c| *c != s1).any(|c| {
        let bs = blobs(&mut net, a, &l, &c);
        !bs.is_empty() && bs.iter().all(|b| ids.contains(b))
    });
    assert!(carried, "a carrier is at the host");
}

// spec/commits.md §5 (a snapshot's bounds come from the writes it carries; a node that may write
// the aspect writes the carrier before dropping a body with live writes), spec/sync.md §7: the
// typed writer of a keep-at-most record goes away; another writer, which never knew the schema,
// erases an entry with an untyped edit, writes the carrier at once, with the record's bound,
// and deletes the replaced body at the host (was: no snapshot without the schema, so the body
// stayed).
#[test]
fn carrier_by_writer_without_schema_spec_commits_5() {
    use osis_crdt::{Op, PathOp};
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let (t, ak, l, c0) = kept_record(&mut net, a, g, &GONEMAP, "ERASED-3c5f", false);
    net.run();
    let _gone = net.take(a);
    let at_host = blobs(&mut net, b, &l, &c0);
    assert!(!at_host.is_empty());
    let n = snapshots(&mut net, b, &t, &ak).len();
    let mut m = Mutation::new();
    m.op(t, &ak, PathOp { path: Vec::new(), op: Op::Remove(s("secret")) }).unwrap();
    net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(net.engine(b).get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("secret"))]).unwrap(), None);
    assert!(!net.engine(b).body_not_dropped(&c0, &t, &ak), "dropped at its first death");
    let snaps = snapshots(&mut net, b, &t, &ak);
    assert_eq!(snaps.len(), n + 1, "one carrier");
    let r = net.engine(b).header(&snaps[n]).unwrap().aspects[0].retention;
    assert_eq!(r.at_most.rel, Some(0), "the record's bound");
    let ids = net.host_ids(host, &l);
    assert!(at_host.iter().all(|x| !ids.contains(x)), "deleted at the host");
}

// spec/commits.md §5 (purge: a writer holding no covering snapshot after applying the request
// re-snapshots; a snapshot's bounds come from the writes it carries): the typed writer of a
// keep-at-most record, compacted, goes away; another writer, which never knew the schema,
// erases the secret entry with an untyped edit purging the entry's commit: the snapshot carrying
// the secret drops, a new one carries the live entries with the record's bound, and neither the
// secret's commit nor the old snapshot stays at the host.
#[test]
fn purge_resnapshot_by_writer_without_schema_spec_commits_5() {
    use osis_crdt::{Op, PathOp};
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    net.blocked.insert((c, host));
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read)], &[host]);
    let t = net.item(a, g, g, "x");
    let ak = Ak::new(GONEMAP.ak()).unwrap();
    let v: std::collections::BTreeMap<osis_base::Value, osis_base::Value> = (0..4).map(|i| (s(&format!("k{i}")), s("f"))).collect();
    let mut m = Mutation::new();
    m.set(t, &GONEMAP, &osis_base::Value::Map(v.into_iter().collect())).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.op(t, &GONEMAP, PathOp { path: vec![osis_crdt::PathSeg::Key(s("secret"))], op: Op::Put(s("PURGED-51d2")) }).unwrap();
    let c1 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    let l = net.label(a);
    let s1 = snapshots(&mut net, a, &t, &ak)[0];
    let _gone = net.take(a);
    let at_host: Vec<_> = [c1, s1].iter().flat_map(|x| blobs(&mut net, b, &l, x)).collect();
    assert!(!blobs(&mut net, b, &l, &s1).is_empty());
    assert!(at_host.iter().all(|x| net.host_ids(host, &l).contains(x)));
    let mut m = Mutation::new();
    m.op(t, &ak, PathOp { path: Vec::new(), op: Op::Remove(s("secret")) }).unwrap();
    m.purge(osis_commit::PurgeItem::Commit { commit: c1, tid: t, ak: ak.clone() });
    net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    assert!(!net.engine(b).body_not_dropped(&s1, &t, &ak), "the snapshot carrying the secret dropped");
    let snaps: Vec<_> = snapshots(&mut net, b, &t, &ak).into_iter().filter(|x| *x != s1).collect();
    assert_eq!(snaps.len(), 1, "re-snapshotted");
    assert_eq!(net.engine(b).header(&snaps[0]).unwrap().aspects[0].retention.at_most.rel, Some(0), "the record's bound");
    let ids = net.host_ids(host, &l);
    assert!(at_host.iter().all(|x| !ids.contains(x)), "the purged bodies left the host");
    net.blocked.clear();
    net.advance(10_000);
    let ec = net.engine(c);
    assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("k2"))]).unwrap(), Some(s("f")));
    assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("secret"))]).unwrap(), None);
}

// spec/commits.md §5 (carrier only): compaction writes no snapshot of an aspect whose snapshot
// would keep at least and at most, whether one retention gives both (uniform) or two writes do
// (mixed: w at least 30 min, x at most 0); every body stays.
#[test]
fn compaction_skips_carrier_only_aspect_spec_commits_5() {
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::{Bound, PurgeBy, Retention};
    let least = Retention { by: PurgeBy::Writer, at_least: Bound { abs: None, rel: Some(1_800_000) }, at_most: Bound::default() };
    let most = Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs: None, rel: Some(0) } };
    let both = Retention { by: PurgeBy::Writer, at_least: least.at_least, at_most: most.at_most };
    for (rw, rx) in [(both, both), (least, most)] {
        let mut net = Net::new();
        let host = net.add_host();
        let a = net.node(1, &[host]);
        let g = net.group(a, &[], &[host]);
        let t = net.item(a, g, g, "x");
        let k = Ak::new(BIG.ak()).unwrap();
        let mut put = |key: &str, r: Retention| {
            let mut m = Mutation::new();
            m.retention(t, &BIG, r).unwrap();
            m.op(t, &BIG, PathOp { path: vec![PathSeg::Key(s(key))], op: Op::Set(s("one")) }).unwrap();
            net.engine(a).commit(m).unwrap().unwrap()
        };
        let w = put("w", rw);
        let x = put("x", rx);
        net.run();
        net.advance(10);
        let acts = net.sync(a).compact(&t, &k).unwrap();
        net.actions(a, acts);
        net.run();
        assert!(snapshots(&mut net, a, &t, &k).is_empty(), "no snapshot");
        for c in [w, x] {
            assert!(net.engine(a).body_not_dropped(&c, &t, &k), "body kept");
        }
    }
}

// spec/commits.md §5, spec/sync.md §6 (carrier only, two right holders): a snapshot keeping at
// least and at most (here written directly, as a carrier is) drops no body it covers at either
// node, and the host keeps them (must-hold); once w dies, its own bound (keep at most 0) drops it
// everywhere, and a body left with a live write goes at its first death under a carrier.
#[test]
fn carrier_only_snapshot_drops_nothing_alike_spec_sync_6() {
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::{Bound, PurgeBy, Retention};
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    let k = Ak::new(BIG.ak()).unwrap();
    let r = Retention { by: PurgeBy::Writer, at_least: Bound { abs: None, rel: Some(1_800_000) }, at_most: Bound { abs: None, rel: Some(0) } };
    let put = |net: &mut Net, keys: &[&str]| {
        let mut m = Mutation::new();
        m.retention(t, &BIG, r).unwrap();
        for key in keys {
            m.op(t, &BIG, PathOp { path: vec![PathSeg::Key(s(key))], op: Op::Set(s("one")) }).unwrap();
        }
        net.engine(a).commit(m).unwrap().unwrap()
    };
    let at_host_count = |net: &mut Net, c: osis_base::CommitId| {
        let ids = net.host_ids(host, &l);
        net.sync(a).entries(&l).into_iter().filter(|(id, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == c) && ids.contains(id)).count()
    };
    let w = put(&mut net, &["w"]);
    let x = put(&mut net, &["x"]);
    let yz = put(&mut net, &["y", "z"]);
    net.run();
    net.advance(10);
    let sn = net.engine(a).snapshot(&t, &k).unwrap().unwrap();
    assert!(osis_commit::retention::carrier_only(&net.engine(a).header(&sn).unwrap().aspects[0].retention));
    // it covers none (so no body dropped later counts it as a coverer, `Dropped::covered_by`)
    for c in [w, x, yz] {
        assert_eq!(net.engine(a).covered(&sn, &c, &t, &k).unwrap(), Some(false), "a carrier covers nothing");
    }
    net.run();
    net.advance(60_000 + osis_base::format::MAX_DRIFT_MS);
    for n in [a, b] {
        assert!(net.engine(n).body_not_dropped(&sn, &t, &k), "{n} holds the snapshot");
        for c in [w, x, yz] {
            assert!(net.engine(n).body_not_dropped(&c, &t, &k), "{n} keeps the body");
        }
    }
    for c in [sn, w, x, yz] {
        assert_eq!(at_host_count(&mut net, c), 1, "at the host");
    }
    // must-hold (uploaded again if lost), not may-hold under the carrier
    let key = net.address(host).key;
    for n in [a, b] {
        let v = net.sync(n).verdicts(&key, &l).unwrap().unwrap();
        assert!([w, x, yz].iter().all(|c| v.must_hold.iter().any(|(m, _)| m == c)), "{n} must hold the bodies");
    }
    let mut m = Mutation::new();
    m.op(t, &BIG, PathOp { path: Vec::new(), op: Op::Remove(s("w")) }).unwrap();
    m.op(t, &BIG, PathOp { path: Vec::new(), op: Op::Remove(s("y")) }).unwrap();
    net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    net.advance(1000);
    for n in [a, b] {
        assert!(!net.engine(n).body_not_dropped(&w, &t, &k), "{n} dropped w at its bound");
        assert!(net.engine(n).body_not_dropped(&x, &t, &k), "{n} keeps x");
    }
    assert_eq!(at_host_count(&mut net, w), 0, "w deleted");
    assert_eq!(at_host_count(&mut net, x), 1, "x at the host");
    // y's death cuts z's body (keep at most from its first death): it goes at once, carried; z
    // stays readable
    for n in [a, b] {
        assert!(!net.engine(n).body_not_dropped(&yz, &t, &k), "{n} dropped yz at its bound");
        assert_eq!(net.engine(n).get_at(&t, &k, &[PathSeg::Key(s("z"))]).unwrap(), Some(s("one")), "{n} reads z");
    }
    assert_eq!(at_host_count(&mut net, yz), 0, "yz deleted, carried");
}

fn with_retention(net: &mut Net, n: usize, t: osis_base::Tid, v: &str, r: osis_schema::Retention) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.retention(t, &REG, r).unwrap();
    m.set(t, &REG, &s(v)).unwrap();
    net.engine(n).commit(m).unwrap().unwrap()
}

fn purge_commit(net: &mut Net, n: usize, t: osis_base::Tid, c: osis_base::CommitId) {
    let mut m = Mutation::new();
    m.purge(osis_commit::PurgeItem::Commit { commit: c, tid: t, ak: Ak::new(REG.ak()).unwrap() });
    m.set(t, &REG, &s(&format!("after {n} {c:?}"))).unwrap();
    net.engine(n).commit(m).unwrap();
    net.run();
}

fn blobs_of(net: &mut Net, n: usize, l: &osis_base::LabelId, c: osis_base::CommitId) -> Vec<osis_base::BlobId> {
    net.sync(n).entries(l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect()
}

// spec/commits.md §5, spec/permissions.md §6, spec/crypto.md §7: an `author` delta lists level 2
// alone; an admin's compaction and purge request drop none of it, at the admin or anywhere, and
// its author's purge request drops it and deletes it at the host by the level-2 key, with no
// admin online. The admin's own `admin` delta is the mirror: its author, a writer, cannot.
#[test]
fn author_only_not_the_admins_spec_perm_6() {
    use osis_schema::{Bound, PurgeBy, Retention};
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    let k = Ak::new(REG.ak()).unwrap();
    let kept = Bound { abs: Some(osis_commit::FOREVER), rel: None };
    let c = with_retention(&mut net, b, t, "b's", Retention { by: PurgeBy::Author, at_least: kept, at_most: Bound::default() });
    let h = net.engine(b).header(&c).unwrap();
    let levels: Vec<u8> = h.aspects.iter().find(|x| x.ak == k).unwrap().keys.iter().map(|i| h.keys[*i].level).collect();
    assert_eq!(levels, vec![2]);
    net.run();
    let blobs = blobs_of(&mut net, b, &l, c);
    assert!(!blobs.is_empty() && blobs.iter().all(|id| net.host_ids(host, &l).contains(id)));

    // the admin's purge request names it: nothing goes anywhere
    purge_commit(&mut net, a, t, c);
    net.run();
    assert!(net.engine(a).body_not_dropped(&c, &t, &k), "admin's purge dropped it at the admin");
    assert!(net.engine(b).body_not_dropped(&c, &t, &k), "admin's purge dropped it at the author");
    assert!(blobs.iter().all(|id| net.host_ids(host, &l).contains(id)), "admin's purge deleted it at the host");

    // the mirror: `admin` by the admin, a writer's purge request drops nothing
    let d = with_retention(&mut net, a, t, "a's", Retention { by: PurgeBy::Admin, at_least: kept, at_most: Bound::default() });
    net.run();
    purge_commit(&mut net, b, t, d);
    assert!(net.engine(b).body_not_dropped(&d, &t, &k) && net.engine(a).body_not_dropped(&d, &t, &k));

    // its author, the admin away
    net.set_online(a, false);
    assert!(net.engine(b).delete_secrets_of(&c, &[h.aspects.iter().position(|x| x.ak == k).unwrap()]).iter().flatten().any(|(l, _)| *l == 2));
    purge_commit(&mut net, b, t, c);
    net.run();
    assert!(!net.engine(b).body_not_dropped(&c, &t, &k), "the author's purge drops it");
    let left = net.host_ids(host, &l);
    assert!(blobs.iter().all(|id| !left.contains(id)), "the author's level-2 key deletes it at the host");
}

// spec/commits.md §5, spec/sync.md §7: a snapshot drops a covered body only if its actor holds the
// right over it. Of b's delta, admin a compacting: gone everywhere under `author_or_admin`, kept
// everywhere under `author` and `nobody`. Writer w compacting: only `writer` goes; b's own snapshot
// drops its own under every set holding the author.
#[test]
fn snapshot_needs_the_right_spec_sync_7() {
    use osis_schema::{PurgeBy, Retention};
    let (a, b, w) = (0, 1, 2);
    for (by, by_a, by_b, by_w) in [(PurgeBy::Nobody, false, false, false), (PurgeBy::Admin, true, false, false), (PurgeBy::Author, false, true, false), (PurgeBy::AuthorOrAdmin, true, true, false), (PurgeBy::Writer, true, true, true)] {
        for (who, dropped) in [(a, by_a), (b, by_b), (w, by_w)] {
            let mut net = Net::new();
            let host = net.add_host();
            let ns = [net.node(1, &[host]), net.node(2, &[host]), net.node(3, &[host])];
            let g = net.group(ns[a], &[(ns[b], Role::Write), (ns[w], Role::Write)], &[host]);
            let t = net.item(ns[a], g, g, "x");
            net.run();
            let l = net.label(ns[a]);
            let k = Ak::new(REG.ak()).unwrap();
            let c = with_retention(&mut net, ns[b], t, "old", Retention { by, ..Default::default() });
            net.run();
            let blobs = blobs_of(&mut net, ns[b], &l, c);
            net.write(ns[who], t, "new");
            net.run();
            let acts = net.sync(ns[who]).compact(&t, &k).unwrap();
            net.actions(ns[who], acts);
            net.run();
            net.advance(2 * 3_600_000);
            net.run();
            // right holders drop, no others ever do
            let holder = |n: usize| match n {
                0 => by.admin(),
                1 => by.author(),
                _ => by.writer(),
            };
            for n in [a, b, w] {
                assert_eq!(net.engine(ns[n]).body_not_dropped(&c, &t, &k), !(dropped && holder(n)), "{by:?} compacted by {who}, at {n}");
            }
            let left = net.host_ids(host, &l);
            assert_eq!(blobs.iter().all(|id| !left.contains(id)), dropped, "{by:?} compacted by {who}, at the host");
        }
    }
}

// spec/commits.md §5, spec/sync.md §6: `nobody` bodies are must-hold while kept, covered or not, so
// a label a thing joins gets them; a covered body of another set is may-hold and stays with its
// holders. Taking the thing off the first label deletes there; holders keep their copies.
#[test]
fn second_label_gets_kept_bodies_spec_sync_6() {
    use osis_schema::{PurgeBy, Retention};
    for (by, carried) in [(PurgeBy::Nobody, true), (PurgeBy::Author, false)] {
        let mut net = Net::new();
        let host = net.add_host();
        let a = net.node(1, &[host]);
        let b = net.node(2, &[host]);
        let g = net.group(a, &[(b, Role::Write)], &[host]);
        let t = net.item(a, g, g, "x");
        net.run();
        let k = Ak::new(REG.ak()).unwrap();
        let c = with_retention(&mut net, b, t, "old", Retention { by, ..Default::default() });
        net.run();
        net.write(a, t, "new");
        net.run();
        let acts = net.sync(a).compact(&t, &k).unwrap();
        net.actions(a, acts);
        net.run();
        let l = net.label(a);
        let addrs = vec![net.hosts[host].address.clone()];
        let g2 = net.group_seeded(a, &[(b, Role::Write)], addrs, 2);
        let l2 = net.sync(a).labels().into_iter().find(|x| x.0 == g2).unwrap().1.id;
        // the new group's actor reads the thing
        set_edge(net.engine(a), g, g2, Role::Read);
        net.run();
        let e = net.engine(a);
        let mut grp = e.get_typed(&g2, &ct::GROUP).unwrap().unwrap();
        grp.items.insert(t);
        let mut m = Mutation::new();
        m.set(g2, &ct::GROUP, &grp).unwrap();
        e.commit(m).unwrap();
        net.run();
        net.advance(1_000);
        net.run();
        let there = blobs_of(&mut net, a, &l2, c).into_iter().filter(|id| net.host_ids(host, &l2).contains(id)).count();
        assert_eq!(there > 0, carried, "{by:?} under the label it joined");
        let e = net.engine(a);
        let mut grp = e.get_typed(&g, &ct::GROUP).unwrap().unwrap();
        grp.items.remove(&t);
        let mut m = Mutation::new();
        m.set(g, &ct::GROUP, &grp).unwrap();
        e.commit(m).unwrap();
        net.run();
        let left = net.host_ids(host, &l);
        assert!(blobs_of(&mut net, b, &l, c).iter().all(|id| !left.contains(id)), "{by:?} off the first label");
        assert!(net.engine(a).body_not_dropped(&c, &t, &k) && net.engine(b).body_not_dropped(&c, &t, &k), "{by:?}: holders keep it");
    }
}

fn demote(net: &mut Net, a: usize, g: osis_base::Tid, holder: osis_base::Tid, to: Role) {
    use osis_node::flows::Demotion;
    let new = ct::Edge { role: to, until: None, invite: None, tied: None };
    let done = net.engine(a).demote(&g, &Demotion { holder, new: Some(new), retain: None }).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
}

fn insert(net: &mut Net, n: usize, t: osis_base::Tid, v: &str) -> osis_base::CommitId {
    use osis_crdt::{Op, PathOp};
    let mut m = Mutation::new();
    m.op(t, &SEQ, PathOp { path: Vec::new(), op: Op::Insert { at: 0, items: vec![s(v)] } }).unwrap();
    net.engine(n).commit(m).unwrap().unwrap()
}

fn latest_snapshot(net: &mut Net, n: usize, t: osis_base::Tid, k: &Ak, acts: Vec<osis_node::sync::Action>) -> osis_base::CommitId {
    net.actions(n, acts);
    let e = net.engine(n);
    let me = e.tid();
    e.commit_ids().into_iter().filter(|c| e.header(c).is_some_and(|h| h.author == me && h.kind == osis_commit::Kind::ContentSnapshot && h.aspects.iter().any(|a| a.tid == t && a.ak == *k))).max_by_key(|c| e.header(c).map(|h| h.ts)).unwrap()
}

// spec/commits.md §5: a right holder that dropped a body under a snapshot and learns later that its
// actor had lost the right has only history less: the snapshot stands (demoted to write) and all
// read alike, a node coming later too, with nothing uploaded again; or the snapshot falls
// (demoted to read), the kept copies come back and all read alike.
#[test]
fn stale_drop_reads_alike_spec_commits_5() {
    for to in [Role::Write, Role::Read] {
        let mut net = Net::new();
        let host = net.add_host();
        let (a, x, b, w, f) = (net.node(1, &[host]), net.node(2, &[host]), net.node(3, &[host]), net.node(4, &[host]), net.node(5, &[host]));
        let g = net.group(a, &[(x, Role::Admin), (b, Role::Write), (w, Role::Write), (f, Role::Read)], &[host]);
        let t = net.item(a, g, g, "x");
        net.run();
        net.set_online(f, false);
        let l = net.label(a);
        let k = Ak::new(SEQ.ak()).unwrap();
        let c = insert(&mut net, b, t, "b's");
        net.run();
        let blobs = blobs_of(&mut net, b, &l, c);
        // the demotion stays at a; x, not knowing, writes and compacts after it
        net.set_online(a, false);
        let xt = net.tid(x);
        demote(&mut net, a, g, xt, to);
        net.advance(1_000);
        insert(&mut net, x, t, "x's");
        let acts = net.sync(x).compact(&t, &k).unwrap();
        let snap = latest_snapshot(&mut net, x, t, &k, acts);
        net.run();
        net.advance(2 * 3_600_000);
        net.run();
        assert!(!net.engine(b).body_not_dropped(&c, &t, &k), "the author dropped it, {to:?}");
        assert!(net.engine(w).body_not_dropped(&c, &t, &k), "a plain writer did not, {to:?}");
        assert!(blobs.iter().all(|id| !net.host_ids(host, &l).contains(id)), "gone at the host, {to:?}");
        net.set_online(a, true);
        net.run();
        net.advance(61_000);
        net.run();
        for n in [a, b, w] {
            assert!(!net.engine(n).snapshot_right(&snap, &c, &t, &k), "node {n}: no right now, {to:?}");
        }
        assert!(net.engine(a).body_not_dropped(&c, &t, &k), "the admin keeps it, {to:?}");
        let there = net.engine(b).body_not_dropped(&c, &t, &k) && !net.engine(b).core.ix.commits.get(&c).unwrap().missing.iter().next().is_some();
        let read = |net: &mut Net, n: usize| net.engine(n).get_typed(&t, &SEQ).unwrap();
        let want = read(&mut net, a);
        assert_eq!(read(&mut net, b), want, "{to:?}");
        assert_eq!(read(&mut net, w), want, "{to:?}");
        match to {
            Role::Read => {
                assert_eq!(want, Some(s("b's")), "the fallen snapshot's own write goes");
                assert!(there, "the holder uploaded it again and the author took it");
            }
            _ => {
                assert_eq!(want, Some(s("x'sb's")));
                assert!(!there, "history stays less");
                let live = net.host_ids(host, &l);
                assert!(blobs_of(&mut net, a, &l, c).iter().all(|id| !live.contains(id)), "not uploaded again");
            }
        }
        // a node that was away for all of it reads alike, whatever it finds
        net.set_online(f, true);
        net.run();
        net.advance(61_000);
        net.run();
        assert_eq!(read(&mut net, f), want, "away, {to:?}");
    }
}

// spec/permissions.md §5.2, spec/commits.md §5: the snapshot a body dropped under falls while another
// without the right, which it does not cover and which arrived after the drop, still covers the
// body: no one uploads the body (may-hold), the dropper reads alike through that snapshot's copies.
#[test]
fn snapshot_falls_rightless_one_covers_spec_perm_5_2() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, x, b, w) = (net.node(1, &[host]), net.node(2, &[host]), net.node(3, &[host]), net.node(4, &[host]));
    let g = net.group(a, &[(x, Role::Admin), (b, Role::Write), (w, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let k = Ak::new(SEQ.ak()).unwrap();
    let c = insert(&mut net, b, t, "b's");
    net.run();
    net.set_online(a, false);
    net.set_online(w, false);
    let xt = net.tid(x);
    demote(&mut net, a, g, xt, Role::Read);
    net.advance(1_000);
    insert(&mut net, x, t, "x's");
    let acts = net.sync(x).compact(&t, &k).unwrap();
    let s1 = latest_snapshot(&mut net, x, t, &k, acts);
    net.run();
    net.advance(2 * 3_600_000);
    net.run();
    assert!(!net.engine(b).body_not_dropped(&c, &t, &k));
    insert(&mut net, w, t, "w's");
    let acts = net.sync(w).compact(&t, &k).unwrap();
    let s2 = latest_snapshot(&mut net, w, t, &k, acts);
    net.set_online(w, true);
    net.run();
    assert!(!net.engine(b).snapshot_right(&s2, &c, &t, &k));
    assert_eq!(net.engine(b).covered(&s2, &s1, &t, &k).unwrap(), Some(false));
    net.set_online(a, true);
    net.run();
    net.advance(61_000);
    net.run();
    let read = |net: &mut Net, n: usize| net.engine(n).get_typed(&t, &SEQ).unwrap();
    let want = read(&mut net, a);
    assert_eq!(want, Some(s("w'sb's")));
    assert_eq!(read(&mut net, b), want);
    assert_eq!(read(&mut net, w), want);
    assert!(net.engine(b).core.ix.commits.get(&c).unwrap().missing.len() == 1, "no one uploads it: may-hold");
    assert!(net.engine(b).suspects().unwrap().is_empty(), "the flag is dormant: the held snapshot lists it");
}

// spec/commits.md §5: the right a node learns of late (the snapshot's author's raise arriving after
// the snapshot): nothing lost, the body may stay until the next judgment, and goes then.
#[test]
fn right_learned_late_spec_commits_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, x, n, b) = (net.node(1, &[host]), net.node(2, &[host]), net.node(3, &[host]), net.node(4, &[host]));
    let g = net.group(a, &[(x, Role::Write), (n, Role::Admin), (b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let k = Ak::new(SEQ.ak()).unwrap();
    let c = insert(&mut net, b, t, "b's");
    net.run();
    net.set_online(n, false);
    let xt = net.tid(x);
    set_edge(net.engine(a), g, xt, Role::Admin);
    net.run();
    net.advance(1_000);
    let acts = net.sync(x).compact(&t, &k).unwrap();
    let snap = latest_snapshot(&mut net, x, t, &k, acts);
    net.run();
    let pk = net.engine(x).package(&snap).unwrap().unwrap();
    net.engine(n).ingest(&pk.bytes, pk.blobs.clone()).unwrap();
    assert!(!net.engine(n).snapshot_right(&snap, &c, &t, &k));
    net.advance(2 * 3_600_000);
    net.set_online(n, true);
    net.run();
    net.advance(61_000);
    net.run();
    assert!(net.engine(n).snapshot_right(&snap, &c, &t, &k));
    // a connection's first pass judges everything; any later snapshot would too
    assert!(!net.engine(n).body_not_dropped(&c, &t, &k));
}

// spec/commits.md §5: a node that never held a body another's compaction dropped has a frontier
// stopping at the gap; its compaction still drops that author's later bodies, covered by the join.
#[test]
fn fresh_snapshot_covers_past_a_gap_spec_commits_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, b, f) = (net.node(1, &[host]), net.node(2, &[host]), net.node(3, &[host]));
    let g = net.group(a, &[(b, Role::Write), (f, Role::Admin)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    net.set_online(f, false);
    let k = Ak::new(SEQ.ak()).unwrap();
    insert(&mut net, b, t, "1");
    net.run();
    let acts = net.sync(b).compact(&t, &k).unwrap();
    net.actions(b, acts);
    net.run();
    net.advance(2 * 3_600_000);
    net.run();
    let c = insert(&mut net, b, t, "2");
    net.run();
    net.set_online(f, true);
    net.run();
    assert_eq!(net.engine(f).get_typed(&t, &SEQ).unwrap(), Some(s("21")));
    let acts = net.sync(f).compact(&t, &k).unwrap();
    let snap = latest_snapshot(&mut net, f, t, &k, acts);
    assert!(net.engine(f).snapshot_right(&snap, &c, &t, &k));
    net.run();
    assert!(!net.engine(f).body_not_dropped(&c, &t, &k), "dropped as covered");
    assert_eq!(net.engine(f).get_typed(&t, &SEQ).unwrap(), net.engine(a).get_typed(&t, &SEQ).unwrap());
}

// spec/commits.md §5, spec/sync.md §7: past a frontier gap the join decides what is covered, not who
// may drop it: under `author` and `nobody` an admin's fresh snapshot drops nothing, nor under a
// keep-at-least forever (history).
#[test]
fn gap_covers_nothing_kept_spec_commits_5() {
    use osis_schema::{PurgeBy, Retention};
    let forever = Retention { by: PurgeBy::Writer, at_least: osis_schema::Bound { abs: Some(osis_commit::FOREVER), rel: None }, ..Default::default() };
    let cases = [(Retention { by: PurgeBy::Nobody, ..Default::default() }, false), (Retention { by: PurgeBy::Author, ..Default::default() }, false), (forever, false), (Retention { by: PurgeBy::Writer, ..Default::default() }, true)];
    for (r, goes) in cases {
        let mut net = Net::new();
        let host = net.add_host();
        let (a, b, f) = (net.node(1, &[host]), net.node(2, &[host]), net.node(3, &[host]));
        let g = net.group(a, &[(b, Role::Write), (f, Role::Admin)], &[host]);
        let t = net.item(a, g, g, "x");
        net.run();
        net.set_online(f, false);
        let k = Ak::new(REG.ak()).unwrap();
        net.write(b, t, "first");
        net.run();
        let acts = net.sync(b).compact(&t, &k).unwrap();
        net.actions(b, acts);
        net.run();
        net.advance(2 * 3_600_000);
        net.run();
        let c = with_retention(&mut net, b, t, "old", r);
        net.run();
        // b's session stays in the state, so a snapshot lists it, short of what b dropped
        net.write(b, t, "new");
        net.run();
        net.set_online(f, true);
        net.run();
        let acts = net.sync(f).compact(&t, &k).unwrap();
        net.actions(f, acts);
        net.run();
        let h = net.engine(f).header(&c).unwrap();
        let (src, hi) = (h.form.own_source(h.author, c), h.aspects.iter().find(|x| x.tid == t && x.ak == k).unwrap().hi);
        let short = net.engine(f).core.ix.snapshots.get(&(t, k.clone())).into_iter().flatten().any(|x| x.2.lists(&src) && x.2.of(&src) + 1 < hi);
        assert!(!goes || short, "a snapshot short of the body");
        net.advance(2 * 3_600_000);
        net.run();
        assert_eq!(net.engine(f).body_not_dropped(&c, &t, &k), !goes, "{r:?}");
        assert_eq!(net.engine(f).get_typed(&t, &REG).unwrap(), net.engine(a).get_typed(&t, &REG).unwrap());
    }
}

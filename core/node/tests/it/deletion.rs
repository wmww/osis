#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Deletions, compaction and re-registration through a host (spec/sync.md §5-§7;
//! spec/commits.md §5; spec/permissions.md §3, §4).

use crate::net::{hosted, hosted_nodes};
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
    let (mut net, host, [a, b], g, [t]) = hosted::<2, 1>(&[(1, Role::Write)], ["x"], true);
    let c = net.write_own(b, t, "by b");
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
    let (mut net, _host, [a], _g, [t]) = hosted::<1, 1>(&[], ["v1"], false);
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
// deletes exactly the covered replaced bodies (the live one stays: it is read on its own), and
// the snapshot stays; a holder joining later reads the live value; the carriers go
// `TOMBSTONE_LIFETIME` after the deletions.
#[test]
fn compaction_then_deletion_spec_sync_7() {
    let (mut net, host, [a]) = hosted_nodes::<1>();
    let c = net.node(3, &[host]);
    net.blocked.insert((c, host));
    let g = net.group(a, &[(c, Role::Read)], &[host]);
    let t = net.item(a, g, g, "v1");
    let c2 = net.write(a, t, "v2");
    let c3 = net.write(a, t, "v3");
    let c4 = net.write(a, t, "v4");
    net.run();
    let l = net.label(a);
    let old: Vec<_> = [c2, c3].into_iter().flat_map(|c| blobs_of(&mut net, a, &l, c)).collect();
    let live = blobs_of(&mut net, a, &l, c4);
    assert!(old.iter().all(|id| net.host_ids(host, &l).contains(id)));
    let ak = Ak::new(REG.ak()).unwrap();
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    net.run();
    net.trace(&[a]);
    let ids = net.host_ids(host, &l);
    assert!(old.iter().all(|id| !ids.contains(id)), "covered bodies deleted");
    assert!(!live.is_empty() && live.iter().all(|id| ids.contains(id)), "the live body stays");
    let snaps: Vec<_> = net.sync(a).entries(&l).into_iter().filter_map(|(id, k)| match k {
        EntryKind::Commit { commit, .. } if net.engine(a).header(&commit).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot) => Some(id),
        _ => None,
    }).collect();
    assert!(!snaps.is_empty() && snaps.iter().all(|id| ids.contains(id)), "the carrier snapshot stays");
    net.blocked.clear();
    net.advance(10_000);
    net.trace(&[c]);
    assert_eq!(net.read(c, t), Some(s("v4")), "the live value");
    // the dropped bodies' carriers go once their entries and tombstones have (growth:
    // notes/growth.md)
    // (the item's creation commit keeps its entry for `created.0`, so its carrier stays)
    assert_eq!(net.sync(a).sync_rows(b's'), 3, "carriers recorded");
    net.advance(osis_base::format::TOMBSTONE_LIFETIME_MS);
    net.advance(60_000);
    assert_eq!(net.sync(a).sync_rows(b's'), 1, "only the carrier of a body with an entry left");
    assert_eq!(net.read(a, t), Some(s("v4")));
}

// spec/sync.md §5 Register: at a host past its byte caps a child step is still taken, once per
// `over_cap_step_ms` per label; a second removal within it is refused for now (code 12): the
// admin's open stays (not stranded) and the step lands once the time has passed.
#[test]
fn rotation_at_full_host_waits_spec_sync_5() {
    let (mut net, host, [a, b, c, d], g, []) = hosted::<4, 0>(&[(1, Role::Write), (2, Role::Read), (3, Role::Read)], [], false);
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
    assert!(!st.stranded && st.sources == 1, "{st:?}");
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
    let (mut net, host, [a, b, c, d], g, [t]) = hosted::<4, 1>(&[(1, Role::Write), (2, Role::Read), (3, Role::Read)], ["x"], true);
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
    let (mut net, host, [a, b, c, d], g, []) = hosted::<4, 0>(&[(1, Role::Write), (2, Role::Read), (3, Role::Read)], [], false);
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
    let (mut net, host, [a, b, c], g, [t]) = hosted::<3, 1>(&[(1, Role::Write), (2, Role::Read)], ["before"], true);
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

// spec/sync.md §5 (re-registration, upload order), spec/permissions.md §3-§4 (stranded): an
// admin rotating out a holder issues a child step at the host after uploading the rotation
// commit; the remaining writer follows; the removed holder's open walks to the new step, its
// claim is refused and it sends a stranded notice to the admin's inbox, which re-seals nobody:
// it is no current holder (spec/crypto.md §4, removed holder).
#[test]
fn reregistration_after_rotation_spec_sync_5() {
    let mut net = Net::new();
    // the admin's inbox is at the host
    net.home_at_hosts = true;
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
    assert_eq!(net.group_labels(a)[0].1.steps.len(), 2, "and recorded in label.0");
    assert_eq!(net.read(b, t), Some(s("after")));
    net.write(b, t, "from b");
    net.run();
    assert_eq!(net.read(a, t), Some(s("from b")), "the writer stamps under the new step");
    // the removed holder comes back: walked to the new step, claim refused, stranded
    let ids_before = net.host_ids(host, &l);
    net.blocked_peers.extend([(a, c), (b, c)]);
    net.set_online(c, true);
    net.advance(10_000);
    assert_eq!(net.read(c, t), Some(s("before")), "nothing new readable");
    assert!(net.sync(c).stranded_at(&l), "stranded");
    // (a writer may place its own record blob meanwhile: a promoter counts no deposited one)
    let deposited = net.host_ids(host, &l).into_iter().filter(|x| !ids_before.contains(x)).filter(|x| osis_proto::LabelStore::entry(&*net.hosts[host].hub.store(), &l, x).unwrap().is_some_and(|m| m.stamp.is_none())).count();
    assert_eq!(deposited, 0, "nothing deposited under the label");
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    let diags = net.diagnostics(a);
    assert!(diags.iter().any(|d| d.contains("re-seal of stranded") && d.contains("not a current holder")), "the admin read the notice and re-sealed nobody: {diags:?}");
}

// spec/sync.md §5 (re-registration): two admins holding epochs newer than the head while one's
// rotation is fresh (a grant, then at once a demotion with no rotation, whose rotation of g
// rotates t at once too): neither uploads for a step that cannot go yet, and nothing is sent
// again unchanged (same entry, same stamp), so the role commits travel once and no admin places
// its own copy of another's (deleted again as a duplicate).
#[test]
fn reregistration_waits_and_sends_once_spec_sync_5() {
    let (mut net, _host, [a, _b, c], g, [t]) = hosted::<3, 1>(&[(1, Role::Write), (2, Role::Admin)], ["x"], true);
    let tc = net.tid(c);
    net.sent_kinds.clear();
    net.uploaded.clear();
    net.grant(a, t, tc, Role::Admin);
    // a demotion with no rotation (a hand-built edge write): g's rotation stays due
    let read = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    crate::common::set_edge(net.engine(a), g, tc, Some(read), None);
    net.run();
    let again: Vec<_> = net.uploaded.iter().filter(|(_, n)| **n > 1).collect();
    assert!(again.is_empty(), "sent again unchanged: {again:?}");
    assert_eq!(net.sent_kinds.get(&14), None, "no duplicate entries to delete");
    // the role commits the grant and the rotations it causes write, each once per label
    let uploads = net.sent_kinds.get(&10).copied().unwrap_or(0);
    assert!(uploads <= 30, "{uploads} uploads");
    assert_eq!(net.read(c, t), Some(s("x")));
}

// spec/sync.md §5 (re-registration): an admin that uploaded another admin's rotation while its
// step waited to settle does not upload it again while that upload is unanswered, once the
// step may go
#[test]
fn reregistration_skips_uploads_in_flight_spec_sync_5() {
    let (mut net, host, [a]) = hosted_nodes::<1>();
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(c, Role::Admin)], &[host]);
    net.run();
    let (at, ct_) = (net.tid(a), net.tid(c));
    // c rotates g away from every host; a gets it directly: its step waits for c's
    net.set_online(c, false);
    let e = net.engine(c);
    let rs = recipients_of(e, &[(at, Role::Admin), (ct_, Role::Admin)]);
    rotation(e, g, &rs, 7, false);
    net.pair(c, a);
    // a's uploads stay unanswered; it relays c's rotation before its step may go
    net.held_to.insert(a);
    net.sent_kinds.clear();
    net.uploaded.clear();
    net.run();
    net.advance(29_999);
    assert!(!net.uploaded.is_empty(), "a relayed c's rotation under the head");
    assert_eq!(net.sent_kinds.get(&7), None, "a's step waits");
    net.advance(2_000);
    assert_eq!(net.sent_kinds.get(&7), Some(&1), "a's step went once settled");
    let again: Vec<_> = net.uploaded.iter().filter(|(_, n)| **n > 1).collect();
    assert!(again.is_empty(), "sent again while in flight: {again:?}");
    net.release();
    net.run();
    let l = net.label(a);
    assert_eq!(net.host_path(host, &l).len(), 2, "a's step registered");
}

/// A record (about 73 KB) with a secret entry on aspect `asp` (a purge-on-replace map) in one
/// commit at the host, compacted into one snapshot at the host when `compact`: (item,
/// aspect, label, the body carrying the record: the snapshot, else the commit).
/// Entries of `kept_record`'s map, 1100 B each: just over a page (`PAGE_TARGET`).
const RECORD_KEYS: usize = 66;

fn kept_record(net: &mut Net, a: usize, g: osis_base::Tid, asp: &osis_schema::Aspect<osis_base::Value>, marker: &str, compact: bool) -> (osis_base::Tid, Ak, osis_base::LabelId, osis_base::CommitId) {
    let t = net.item(a, g, g, "x");
    net.keep(a, t, &[(asp.ak(), PURGE)]);
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
/// Admin `a` and reader `c` of group `g` at `host`, `c` cut off from the host: built once
/// (`Net::cached`).
fn blocked_reader() -> (Net, usize, usize, usize, osis_base::Tid) {
    let (net, (host, a, c, g)) = Net::cached("deletion::blocked_reader", || {
        let mut net = Net::new();
        let host = net.add_host();
        let a = net.node(1, &[host]);
        let c = net.node(3, &[host]);
        net.blocked.insert((c, host));
        let g = net.group(a, &[(c, Role::Read)], &[host]);
        (net, (host, a, c, g))
    });
    (net, host, a, c, g)
}

fn erase_secret(net: &mut Net, a: usize, t: osis_base::Tid, asp: &osis_schema::Aspect<osis_base::Value>) {
    let mut m = Mutation::new();
    m.op(t, asp, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s("secret")) }).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
}

// spec/commits.md §5 (purge on replace: the replacing writer covers the body),
// spec/requirements.md (Scale: the cost the app chooses): an erasing edit of a big record
// (a snapshot or an ordinary commit) writes one covering snapshot
// of the aspect at once; the old body goes here and at the host in the same pass, and a holder
// joining afterwards reads every live entry and not the erased one.
#[test]
fn erasing_edit_covered_at_once_spec_commits_5() {
    for (i, compact) in [true, false].into_iter().enumerate() {
        let asp = &GONEMAP;
        let (mut net, host, a, c, g) = blocked_reader();
        let (t, ak, l, s1) = kept_record(&mut net, a, g, asp, "ERASED-7d1e", compact);
        let n = snapshots(&mut net, a, &t, &ak).len();
        let at_host = blobs(&mut net, a, &l, &s1);
        erase_secret(&mut net, a, t, asp);
        net.run();
        assert!(!net.engine(a).body_not_dropped(&s1, &t, &ak), "case {i}: dropped under the cover");
        assert_eq!(snapshots(&mut net, a, &t, &ak).len(), n + 1, "case {i}: one cover per erasing edit");
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

// spec/commits.md §5 (purge on replace: the replacing writer covers the body),
// spec/requirements.md (Scale: the cost the app chooses): a text typed in several commits,
// then a delete of part of an older commit's text: one covering snapshot of the text, the old body gone here and at the host in the same pass, and a reader
// joining then cannot read the erased text.
#[test]
fn text_partly_erased_covered_at_once_spec_commits_5() {
    use osis_crdt::{Op, PathOp};
    let (mut net, host, a, c, g) = blocked_reader();
    let t = net.item(a, g, g, "x");
    net.keep(a, t, &[(GONETEXT.ak(), PURGE)]);
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
    assert_eq!(snapshots(&mut net, a, &t, &ak).len(), 1, "one cover");
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

// spec/commits.md §5 (a deleted text element's creation stays a live write: a body whose text
// was all erased goes under a cover of its anchors), spec/crdt.md §4.8: under purge on replace, a
// word typed then wholly deleted is gone here and at the host in the erasing pass, under one
// cover, and a reader joining then cannot read it.
#[test]
fn text_fully_erased_covered_at_once_spec_commits_5() {
    use osis_crdt::{Op, PathOp};
    let (mut net, host, a, c, g) = blocked_reader();
    let t = net.item(a, g, g, "x");
    net.keep(a, t, &[(GONETEXT.ak(), PURGE)]);
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

// spec/commits.md §5 (a dropped body's liveness counts every write the state holds by dot),
// spec/sync.md §7 (a body with live writes is deleted at a label only while another entry carries
// them): under purge on replace, a word typed and its first char deleted: the carrier written then
// holds the rest of the word live. A word typed and another char deleted: the carrier drops at its
// first death with the rest live, and the carrier written then is lost on its way to the host: the
// first stays at the host until the second is there (was: judged dead once dropped, deleted
// without a carrier, and the label lost the chars a fresh node needs).
#[test]
fn dropped_snapshot_waits_for_lost_carrier_spec_sync_7() {
    use osis_crdt::{Op, PathOp};
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
    let t = net.item(a, g, g, "x");
    net.keep(a, t, &[(GONETEXT.ak(), PURGE)]);
    let ak = Ak::new(GONETEXT.ak()).unwrap();
    let edit = |net: &mut Net, op: Op| {
        let mut m = Mutation::new();
        m.op(t, &GONETEXT, PathOp { path: Vec::new(), op }).unwrap();
        net.engine(a).commit(m).unwrap().unwrap();
        net.run();
    };
    edit(&mut net, Op::Insert { at: 0, items: vec![s("SECRET")] });
    edit(&mut net, Op::Delete { at: 0, len: 1 });
    let snaps = snapshots(&mut net, a, &t, &ak);
    assert_eq!(snaps.len(), 1, "the carrier of the word's rest");
    let s1 = snaps[0];
    let l = net.label(a);
    let at_host = blobs(&mut net, a, &l, &s1);
    assert!(!at_host.is_empty() && at_host.iter().all(|b| net.host_ids(host, &l).contains(b)), "the snapshot is at the host");
    edit(&mut net, Op::Insert { at: 0, items: vec![s("two")] });
    assert!(net.engine(a).body_not_dropped(&s1, &t, &ak) && net.engine(a).body_live(&s1, &t, &ak).unwrap(), "the word's rest is live");
    net.lose_uploads.insert(a);
    // "twoECRET": the `E` goes
    edit(&mut net, Op::Delete { at: 3, len: 1 });
    assert!(!net.engine(a).body_not_dropped(&s1, &t, &ak), "dropped at its first death");
    assert!(net.engine(a).body_live(&s1, &t, &ak).unwrap(), "dropped live, the rest still in the state");
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

// spec/commits.md §5 (purge on replace is the thing's setting; a node that may write the aspect
// writes the carrier before dropping a body with live writes), spec/sync.md §7: the typed writer
// of a purge-on-replace record goes away; another writer, which never knew the schema, erases an
// entry with an untyped edit, writes the carrier at once and deletes the replaced body at the host.
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
    assert_eq!(snaps.len(), n + 1, "one cover");
    let ids = net.host_ids(host, &l);
    assert!(at_host.iter().all(|x| !ids.contains(x)), "deleted at the host");
}

// spec/commits.md §5 (purge: a writer holding no covering snapshot after applying the request
// re-snapshots): the typed writer of a purge-on-replace record, compacted, goes away; another
// writer, which never knew the schema, erases the secret entry with an untyped edit purging the
// entry's commit: the snapshot carrying the secret drops, a new one carries the live entries, and
// neither the secret's commit nor the old snapshot stays at the host.
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
    net.keep(a, t, &[(GONEMAP.ak(), PURGE)]);
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
    let ids = net.host_ids(host, &l);
    assert!(at_host.iter().all(|x| !ids.contains(x)), "the purged bodies left the host");
    net.blocked.clear();
    net.advance(10_000);
    let ec = net.engine(c);
    assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("k2"))]).unwrap(), Some(s("f")));
    assert_eq!(ec.get_at(&t, &ak, &[osis_crdt::PathSeg::Key(s("secret"))]).unwrap(), None);
}

/// Node `n` purges `(t, REG)` commit `c` whole, writing `purge.0` only (no reset).
fn purge_reg(net: &mut Net, n: usize, t: osis_base::Tid, c: osis_base::CommitId) -> osis_base::CommitId {
    let mut m = Mutation::new();
    let now = net.engine(n).now();
    m.set(t, &ct::PURGE, &now).unwrap();
    m.purge(osis_commit::PurgeItem::Commit { commit: c, tid: t, ak: Ak::new(REG.ak()).unwrap() });
    net.engine(n).commit(m).unwrap().unwrap()
}

/// Snapshots of `(t, ak)` node `n` holds that it wrote.
fn own_snapshots(net: &mut Net, n: usize, t: &osis_base::Tid, ak: &Ak) -> usize {
    let me = net.engine(n).me();
    snapshots(net, n, t, ak).into_iter().filter(|c| net.engine(n).header(c).is_some_and(|h| h.author == me)).count()
}

// spec/commits.md §5 Purge (a writer holding no covering snapshot after applying a request
// re-snapshots), spec/requirements.md Deterministic: b's write over a's value, purged whole by b
// (no live write left, so its body goes with no carrier), never reached c. Once c syncs it reads
// what b reads, nothing, not a's older value: b's re-snapshot carries the write value-less.
#[test]
fn purged_delta_never_held_reads_as_purger_spec_commits_5() {
    let (mut net, host, [a, b, c], _g, [t]) = hosted::<3, 1>(&[(1, Role::Write), (2, Role::Read)], ["old"], true);
    assert_eq!(net.engine(c).get(&t, &Ak::new(REG.ak()).unwrap()).unwrap(), Some(s("old")));
    net.set_online(c, false);
    // kept a while, not forever: no lasting header stays to carry the write
    net.keep(a, t, &[(REG.ak(), osis_schema::History::Keep { until: None, after: Some(60_000) })]);
    net.run();
    let mut m = Mutation::new();
    m.retention(t, &REG, osis_schema::Retention { by: osis_schema::PurgeBy::Writer }).unwrap();
    m.set(t, &REG, &s("new")).unwrap();
    let w = net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let at_host = blobs(&mut net, b, &l, &w);
    assert!(!at_host.is_empty() && at_host.iter().all(|x| net.host_ids(host, &l).contains(x)));
    purge_reg(&mut net, b, t, w);
    net.run();
    net.advance(60_000);
    let ids = net.host_ids(host, &l);
    assert!(at_host.iter().all(|x| !ids.contains(x)), "the purged body left the host");
    let ak = Ak::new(REG.ak()).unwrap();
    assert_eq!(net.engine(b).get(&t, &ak).unwrap(), None, "the purged write wins value-less");
    assert_eq!(own_snapshots(&mut net, b, &t, &ak), 1, "the purger re-snapshotted");
    net.set_online(c, true);
    net.advance(10_000);
    assert!(!net.engine(c).commit_ids().contains(&w), "c never held the purged commit");
    assert_eq!(net.engine(c).get(&t, &ak).unwrap(), None, "c reads as the purger");
}

// spec/commits.md §5 Purge: a writer already holding a valid snapshot covering every named body
// it held writes none after the purge: a dead write, kept for its history and covered by a
// snapshot, purged.
#[test]
fn purge_covered_by_held_snapshot_no_resnapshot_spec_commits_5() {
    use osis_schema::{History, PurgeBy, Retention};
    let kept = Retention { by: PurgeBy::Writer };
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
    let t = net.item(a, g, g, "old");
    net.keep(a, t, &[(REG.ak(), History::Keep { until: None, after: Some(86_400_000) })]);
    let ak = Ak::new(REG.ak()).unwrap();
    let mut put = |v: &str| {
        let mut m = Mutation::new();
        m.retention(t, &REG, kept).unwrap();
        m.set(t, &REG, &s(v)).unwrap();
        net.engine(a).commit(m).unwrap().unwrap()
    };
    let w = put("one");
    put("two");
    net.run();
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    let snaps = snapshots(&mut net, a, &t, &ak);
    assert_eq!(snaps.len(), 1);
    assert!(net.engine(a).body_not_dropped(&w, &t, &ak) && net.engine(a).covered(&snaps[0], &w, &t, &ak).unwrap() == Some(true), "w held, covered");
    purge_reg(&mut net, a, t, w);
    net.run();
    assert!(!net.engine(a).body_not_dropped(&w, &t, &ak), "purged");
    assert_eq!(net.engine(a).get(&t, &ak).unwrap(), Some(s("two")));
    assert_eq!(snapshots(&mut net, a, &t, &ak), snaps, "no re-snapshot");
}

// spec/commits.md §5 Purge, Principle (a node without write writes no snapshot): the reader c
// applied a's write w, which no snapshot it holds covers; b, offline, purges w before holding it
// (so b, holding its own earlier snapshot, writes none). c applies the request and writes none
// either: it reads w purged, nothing.
#[test]
fn purge_reader_writes_no_snapshot_spec_commits_5() {
    let (mut net, _host, [a, b, c], _g, [t]) = hosted::<3, 1>(&[(1, Role::Write), (2, Role::Read)], ["old"], true);
    let ak = Ak::new(REG.ak()).unwrap();
    let acts = net.sync(b).compact(&t, &ak).unwrap();
    net.actions(b, acts);
    net.run();
    net.set_online(b, false);
    let mut m = Mutation::new();
    m.retention(t, &REG, osis_schema::Retention { by: osis_schema::PurgeBy::Writer }).unwrap();
    m.set(t, &REG, &s("new")).unwrap();
    let w = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    net.set_online(a, false);
    assert_eq!(net.engine(c).get(&t, &ak).unwrap(), Some(s("new")));
    let n = snapshots(&mut net, c, &t, &ak).len();
    // stamped after w on b's clock
    net.advance(1_000);
    purge_reg(&mut net, b, t, w);
    net.set_online(b, true);
    net.advance(10_000);
    assert_eq!(net.engine(c).get(&t, &ak).unwrap(), None);
    assert_eq!(snapshots(&mut net, c, &t, &ak).len(), n, "no snapshot reached c");
    assert_eq!(own_snapshots(&mut net, c, &t, &ak), 0, "the reader wrote none");
    assert!(!net.diagnostics(c).iter().any(|d| d.contains("re-snapshot")), "nor tried to");
}

fn with_retention(net: &mut Net, n: usize, t: osis_base::Tid, v: &str, r: osis_schema::Retention) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.retention(t, &REG, r).unwrap();
    m.set(t, &REG, &s(v)).unwrap();
    net.engine(n).commit(m).unwrap().unwrap()
}

fn blobs_of(net: &mut Net, n: usize, l: &osis_base::LabelId, c: osis_base::CommitId) -> Vec<osis_base::BlobId> {
    net.sync(n).entries(l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect()
}

// spec/commits.md §5 Out of history, spec/sync.md §7: a body no setting keeps drops under any
// writer's covering snapshot, whoever holds the purge right over it: of b's delta, compacted by
// admin a, by b or by plain writer w, under every purge set, gone at every node and at the host
// (a holds the admin's delete key over every write).
#[test]
fn out_of_history_goes_under_any_writers_cover_spec_sync_7() {
    use osis_schema::PurgeBy;
    let (a, b, w) = (0, 1, 2);
    for by in [PurgeBy::Admin, PurgeBy::AuthorOrAdmin, PurgeBy::Writer] {
        for who in [a, b, w] {
            let (mut net, host, ns, _, [t]) = hosted::<3, 1>(&[(b, Role::Write), (w, Role::Write)], ["x"], true);
            let l = net.label(ns[a]);
            let k = Ak::new(REG.ak()).unwrap();
            let c = with_retention(&mut net, ns[b], t, "old", crate::common::purgeable_by(by));
            net.run();
            let blobs = blobs_of(&mut net, ns[b], &l, c);
            net.write(ns[who], t, "new");
            net.run();
            let acts = net.sync(ns[who]).compact(&t, &k).unwrap();
            net.actions(ns[who], acts);
            net.run();
            net.advance(2 * 3_600_000);
            net.run();
            for n in [a, b, w] {
                assert!(!net.engine(ns[n]).body_not_dropped(&c, &t, &k), "{by:?} compacted by {who}, at {n}");
            }
            let left = net.host_ids(host, &l);
            assert!(blobs.iter().all(|id| !left.contains(id)), "{by:?} compacted by {who}, at the host");
        }
    }
}

// spec/commits.md §5 (host delete margin), spec/sync.md §7: a body that was in history drops at a node
// as covered once out of history on its clock, and leaves the host only `MAX_DRIFT` later, when
// every node's clock agrees (a local drop changes only this node's reads)
#[test]
fn host_delete_waits_drift_past_history_spec_sync_7() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let k = Ak::new(REG.ak()).unwrap();
    net.keep(a, t, &[(REG.ak(), osis_schema::History::Keep { until: None, after: Some(600_000) })]);
    net.run();
    let l = net.label(a);
    let c = net.write(b, t, "old");
    net.run();
    let blobs = blobs_of(&mut net, a, &l, c);
    net.write(a, t, "new");
    net.run();
    net.advance(660_000);
    net.run();
    let acts = net.sync(a).compact(&t, &k).unwrap();
    net.actions(a, acts);
    net.run();
    assert!(!net.engine(a).body_not_dropped(&c, &t, &k), "out of history: dropped here");
    let left = net.host_ids(host, &l);
    assert!(!blobs.is_empty() && blobs.iter().all(|id| left.contains(id)), "kept at the host within MAX_DRIFT");
    net.advance(osis_base::format::MAX_DRIFT_MS);
    net.run();
    let left = net.host_ids(host, &l);
    assert!(blobs.iter().all(|id| !left.contains(id)), "gone from the host past it");
}

// spec/commits.md §5, spec/sync.md §6: bodies in history are must-hold, covered or not, whoever's
// snapshot covers them (here a plain writer's, without the purge right),
// so a label a thing joins and a host that lost its copies get them, and holders keep their copies
// when the thing leaves the first label; a covered body out of history is neither, and goes at its
// holders under the cover.
#[test]
fn second_label_gets_kept_bodies_spec_sync_6() {
    for (kept, carried) in [(true, true), (false, false)] {
        let (mut net, host, [a, b, w], g, [t]) = hosted::<3, 1>(&[(1, Role::Write), (2, Role::Write)], ["x"], true);
        let k = Ak::new(REG.ak()).unwrap();
        if kept {
            net.keep(a, t, &[(REG.ak(), osis_schema::History::FOREVER)]);
        }
        let c = net.write(b, t, "old");
        net.run();
        net.write(a, t, "new");
        net.run();
        let acts = net.sync(w).compact(&t, &k).unwrap();
        net.actions(w, acts);
        net.run();
        let l = net.label(a);
        let addrs = vec![net.hosts[host].address.clone()];
        let g2 = net.group_seeded(a, &[(b, Role::Write)], addrs, 2);
        let l2 = net.group_labels(a).into_iter().find(|x| x.0 == g2).unwrap().1.id;
        // the new group's actor reads the thing
        net.grant(a, g, g2, Role::Read);
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
        assert_eq!(there > 0, carried, "kept {kept}: under the label it joined");
        for x in [a, b, w] {
            net.set_online(x, false);
        }
        net.wipe_host(host);
        for x in [a, b, w] {
            net.set_online(x, true);
        }
        net.run();
        net.advance(120_000);
        net.run();
        for x in [l, l2] {
            let there = blobs_of(&mut net, a, &x, c).into_iter().filter(|id| net.host_ids(host, &x).contains(id)).count();
            assert_eq!(there > 0, carried, "kept {kept}: placed again at the wiped host");
        }
        let e = net.engine(a);
        let mut grp = e.get_typed(&g, &ct::GROUP).unwrap().unwrap();
        grp.items.remove(&t);
        let mut m = Mutation::new();
        m.set(g, &ct::GROUP, &grp).unwrap();
        e.commit(m).unwrap();
        net.run();
        let left = net.host_ids(host, &l);
        assert!(blobs_of(&mut net, b, &l, c).iter().all(|id| !left.contains(id)), "kept {kept}: off the first label");
        for n in [a, b] {
            assert_eq!(net.engine(n).body_not_dropped(&c, &t, &k), kept, "kept {kept}: at {n}");
        }
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

/// `insert` of `v` behind a first character `n` deletes at once: the body holds a dead write and
/// live ones, so a cover may drop it (a delta none of whose writes is dead is read on its own,
/// spec/commits.md §5 Covered). Reads as `insert` of `v`.
fn insert_partly(net: &mut Net, n: usize, t: osis_base::Tid, v: &str) -> osis_base::CommitId {
    use osis_crdt::{Op, PathOp};
    let c = insert(net, n, t, &format!("#{v}"));
    let mut m = Mutation::new();
    m.op(t, &SEQ, PathOp { path: Vec::new(), op: Op::Delete { at: 0, len: 1 } }).unwrap();
    net.engine(n).commit(m).unwrap().unwrap();
    c
}

fn latest_snapshot(net: &mut Net, n: usize, t: osis_base::Tid, k: &Ak, acts: Vec<osis_node::sync::Action>) -> osis_base::CommitId {
    net.actions(n, acts);
    let e = net.engine(n);
    let me = e.me();
    e.commit_ids().into_iter().filter(|c| e.header(c).is_some_and(|h| h.author == me && h.kind == osis_commit::Kind::ContentSnapshot && h.aspects.iter().any(|a| a.tid == t && a.ak == *k))).max_by_key(|c| e.header(c).map(|h| h.ts)).unwrap()
}

// spec/commits.md §5: nodes that dropped a body under a snapshot (out of history, any writer's
// cover) and learn later that its actor had lost the purge right have only history less: the
// snapshot stands (demoted to write) and all read alike, a node coming later too, with nothing
// uploaded again, the admin away throughout dropping it too; or the snapshot falls (demoted to
// read), the admin's kept copy comes back and all read alike.
#[test]
fn stale_drop_reads_alike_spec_commits_5() {
    for to in [Role::Write, Role::Read] {
        let (mut net, host, [a, x, b, w, f], g, [t]) = hosted::<5, 1>(&[(1, Role::Admin), (2, Role::Write), (3, Role::Write), (4, Role::Read)], ["x"], true);
        net.set_online(f, false);
        let l = net.label(a);
        let k = Ak::new(SEQ.ak()).unwrap();
        let c = insert_partly(&mut net, b, t, "b's");
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
        assert!(!net.engine(w).body_not_dropped(&c, &t, &k), "a plain writer too, {to:?}");
        assert!(blobs.iter().all(|id| !net.host_ids(host, &l).contains(id)), "gone at the host, {to:?}");
        net.set_online(a, true);
        net.run();
        net.advance(61_000);
        net.run();
        for n in [a, b, w] {
            assert!(!net.engine(n).snapshot_right(&snap, &c, &t, &k), "node {n}: no right now, {to:?}");
        }
        assert_eq!(net.engine(a).body_not_dropped(&c, &t, &k), to == Role::Read, "the admin keeps it while uncovered, {to:?}");
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
    let c = insert_partly(&mut net, b, t, "b's");
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
    assert!(!net.engine(b).body_not_dropped(&c, &t, &k), "not held at the dropper");
    let l = net.label(a);
    let live = net.host_ids(host, &l);
    for n in [a, b, w] {
        assert!(blobs_of(&mut net, n, &l, c).iter().all(|id| !live.contains(id)), "no one uploads it: may-hold (node {n})");
    }
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
    let c = insert_partly(&mut net, b, t, "b's");
    net.run();
    net.set_online(n, false);
    let xt = net.tid(x);
    net.grant(a, g, xt, Role::Admin);
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
    insert_partly(&mut net, b, t, "1");
    net.run();
    let acts = net.sync(b).compact(&t, &k).unwrap();
    net.actions(b, acts);
    net.run();
    net.advance(2 * 3_600_000);
    net.run();
    let c = insert_partly(&mut net, b, t, "2");
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
// may drop it: an admin's fresh snapshot drops nothing the thing's setting keeps in history.
#[test]
fn gap_covers_nothing_kept_spec_commits_5() {
    for kept in [true, false] {
        let goes = !kept;
        let mut net = Net::new();
        let host = net.add_host();
        let (a, b, f) = (net.node(1, &[host]), net.node(2, &[host]), net.node(3, &[host]));
        let g = net.group(a, &[(b, Role::Write), (f, Role::Admin)], &[host]);
        let t = net.item(a, g, g, "x");
        net.run();
        net.set_online(f, false);
        let k = Ak::new(REG.ak()).unwrap();
        if kept {
            net.keep(a, t, &[(REG.ak(), osis_schema::History::FOREVER)]);
        }
        net.write(b, t, "first");
        net.run();
        let acts = net.sync(b).compact(&t, &k).unwrap();
        net.actions(b, acts);
        net.run();
        net.advance(2 * 3_600_000);
        net.run();
        let c = net.write(b, t, "old");
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
        assert_eq!(net.engine(f).body_not_dropped(&c, &t, &k), !goes, "kept {kept}");
        assert_eq!(net.engine(f).get_typed(&t, &REG).unwrap(), net.engine(a).get_typed(&t, &REG).unwrap());
    }
}

// spec/commits.md §5 Purge: a request names no snapshot (it has no values of its own), so one
// listing a snapshot's commit never drops it: the partly replaced body it covered, dropped and
// deleted at the host, stays carried. a, the
// fresh reader f and r, away through the compaction, all read the live value.
#[test]
fn purge_naming_a_cover_keeps_its_writes_spec_commits_5() {
    let (mut net, host, [a]) = hosted_nodes::<1>();
    let r = net.node(3, &[host]);
    let f = net.node(4, &[host]);
    net.blocked.insert((f, host));
    let g = net.group(a, &[(r, Role::Read), (f, Role::Read)], &[host]);
    let t = net.item(a, g, g, "v1");
    net.keep(a, t, &[("t:gone.0", PURGE)]);
    let c = insert_partly(&mut net, a, t, "v2");
    net.run();
    let ak = Ak::new(SEQ.ak()).unwrap();
    assert_eq!(net.engine(r).get_typed(&t, &SEQ).unwrap(), Some(s("v2")));
    net.blocked.insert((r, host));
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    net.run();
    let snap = snapshots(&mut net, a, &t, &ak)[0];
    assert!(!net.engine(a).body_not_dropped(&c, &t, &ak), "dropped as covered");
    let mut m = Mutation::new();
    m.purge(osis_commit::PurgeItem::Commit { commit: snap, tid: t, ak: ak.clone() });
    m.set(t, &GONE, &s("p")).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    net.blocked.clear();
    net.advance(10_000);
    net.run();
    net.advance(10_000);
    assert_eq!(net.engine(r).get_typed(&t, &SEQ).unwrap(), Some(s("v2")));
    assert_eq!(net.engine(a).get_typed(&t, &SEQ).unwrap(), Some(s("v2")));
    assert_eq!(net.engine(f).get_typed(&t, &SEQ).unwrap(), Some(s("v2")), "a fresh reader too");
    assert!(net.engine(a).body_not_dropped(&snap, &t, &ak), "the snapshot stays held");
}

// spec/permissions.md §6 (a purge's fall), spec/sync.md §7: c was dropped as covered under a's
// snapshot and deleted at the host; x's purge of c strips the snapshot at r and x, then a, which
// never saw the request, demotes x: the request falls. c's body is gone everywhere, the snapshot
// whole only at a. Every node reads c's value again, the reader r and a fresh reader f too.
#[test]
fn purge_fall_after_cover_reads_alike_spec_perm_6() {
    let (mut net, host, [a, x, r, f]) = hosted_nodes::<4>();
    net.set_online(f, false);
    let g = net.group(a, &[(x, Role::Admin), (r, Role::Read), (f, Role::Read)], &[host]);
    let t = net.item(a, g, g, "v1");
    net.keep(a, t, &[("t:gone.0", PURGE)]);
    let c = insert_partly(&mut net, a, t, "v2");
    net.run();
    let ak = Ak::new(SEQ.ak()).unwrap();
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    net.advance(10_000);
    net.run();
    assert!(!net.engine(a).body_not_dropped(&c, &t, &ak), "dropped as covered");
    assert_eq!(net.engine(r).get_typed(&t, &SEQ).unwrap(), Some(s("v2")));
    net.set_online(a, false);
    let mut m = Mutation::new();
    m.purge(osis_commit::PurgeItem::Commit { commit: c, tid: t, ak: ak.clone() });
    m.set(t, &GONE, &s("p")).unwrap();
    net.engine(x).commit(m).unwrap().unwrap();
    net.run();
    net.advance(10_000);
    net.run();
    assert_eq!(net.engine(r).get_typed(&t, &SEQ).unwrap(), Some(s("")), "purged at r");
    let xt = net.tid(x);
    demote(&mut net, a, g, xt, Role::Read);
    net.set_online(a, true);
    for _ in 0..6 {
        net.run();
        net.advance(61_000);
    }
    net.run();
    assert_eq!(net.engine(a).get_typed(&t, &SEQ).unwrap(), Some(s("v2")), "the request never stood at a");
    assert_eq!(net.engine(r).get_typed(&t, &SEQ).unwrap(), Some(s("v2")), "fallen at r");
    assert_eq!(net.engine(x).get_typed(&t, &SEQ).unwrap(), Some(s("v2")), "fallen at x");
    net.set_online(f, true);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    assert_eq!(net.engine(f).get_typed(&t, &SEQ).unwrap(), Some(s("v2")), "a fresh reader");
}

/// A plain thing in a group shared by a and b, with a value by a, its creation purgeable by admins.
fn ending_setup() -> (Net, usize, usize, usize, osis_base::Tid, osis_base::Tid) {
    let (net, host, [a, b], g, [t]) = hosted::<2, 1>(&[(1, Role::Write)], ["x"], true);
    (net, host, a, b, g, t)
}

fn end_request(net: &mut Net, by: usize, t: osis_base::Tid) -> osis_node::Result<Option<osis_base::CommitId>> {
    let mut m = Mutation::new();
    m.set(t, &ct::PURGE, &osis_base::WallMs(net.now())).unwrap();
    m.purge(osis_commit::PurgeItem::Aspect { tid: t, ak: Ak::new(ct::CREATED.ak()).unwrap() });
    net.engine(by).commit(m)
}

// spec/commits.md §5 (Ending), spec/sync.md §5: a purge of a thing's creation by its first admin's
// holder ends it at every node, hosts dropping its blobs; a write after the end is ignored
#[test]
fn purge_ends_the_thing_everywhere_spec_commits_5() {
    let (mut net, host, a, b, g, t) = ending_setup();
    let l = net.label(a);
    let c = net.write(a, t, "y");
    net.run();
    let blobs: Vec<_> = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect();
    assert!(!blobs.is_empty() && blobs.iter().all(|id| net.host_ids(host, &l).contains(id)));
    assert_eq!(net.read(b, t), Some(s("y")));
    end_request(&mut net, a, t).unwrap().unwrap();
    net.run();
    for n in [a, b] {
        assert_eq!(net.read(n, t), None, "node {n}");
        assert!(net.engine(n).get_typed(&t, &ct::CREATED).unwrap().is_none(), "the record goes with the thing");
    }
    let ids = net.host_ids(host, &l);
    assert!(blobs.iter().all(|id| !ids.contains(id)), "hosts drop the ended thing's blobs");
    // a write after the end is on an unknown thing: refused here, ignored where it arrives
    let mut m = Mutation::new();
    m.set(t, &REG, &s("late")).unwrap();
    assert!(net.engine(a).commit(m).is_err());
    assert_eq!(net.read(a, g), net.read(b, g), "the group lives on");
}

// spec/permissions.md §6 (Ending): a writer has no right to end a thing: the writer's own check
// refuses it, and a forged request changes no read
#[test]
fn non_admin_cannot_end_spec_permissions_6() {
    let (mut net, _host, a, b, _g, t) = ending_setup();
    assert!(matches!(end_request(&mut net, b, t), Err(osis_node::Error::Permission { .. })));
    net.run();
    assert_eq!(net.read(a, t), Some(s("x")));
    assert_eq!(net.read(b, t), Some(s("x")));
}

// spec/commits.md §6, notes/expiry-creation-design.md §3: one commit is a disappearing message: the
// creation expires with its content, and the thing is gone at every node at T
#[test]
fn one_commit_disappearing_message_spec_commits_6() {
    let (mut net, _host, a, b, g, _t) = ending_setup();
    let mut m = Mutation::new();
    let msg = net.engine(a).new_thing(&mut m, g);
    m.set(msg, &REG, &s("gone soon")).unwrap();
    let mut items = net.engine(a).get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.insert(msg);
    m.set(g, &ct::GROUP, &items).unwrap();
    m.expires_all(osis_base::WallMs(net.now() + 5_000));
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let h = net.engine(a).header(&c).unwrap();
    assert!(h.expires.is_some() && h.aspects.iter().any(|x| x.ak.as_str() == "created.0"), "one commit");
    assert_eq!(net.read(b, msg), Some(s("gone soon")));
    net.advance(6_000);
    net.run();
    for n in [a, b] {
        assert_eq!(net.read(n, msg), None);
        assert!(net.engine(n).get_typed(&msg, &ct::CREATED).unwrap().is_none());
    }
}

/// Host log records of label `l` (entries added and deleted) so far.
fn log_len(net: &Net, host: usize, l: &osis_base::LabelId) -> usize {
    use osis_proto::LabelStore;
    net.hosts[host].hub.store().log_after(l, 0, 1 << 20).unwrap().unwrap_or_default().len()
}

// spec/sync.md §6, §7 (what a node deletes it would not upload): B writes C on a map and t:seq,
// then replaces part of each (C's other writes stay live), compacts t:seq, and, the admin A away,
// the map; it drops C under both snapshots and deletes it at the host. A demotes B to read with a
// frontier not listing the map snapshot: it falls, C's live map write is covered by nothing, so A,
// which kept C's map part (it never held that snapshot), uploads it. B takes C's map delta back;
// its blob is must-not-hold for B (the t:seq delta dropped), and the fallen snapshot B recorded as
// the map delta's carrier carries nothing: B leaves the blob (a reader writes no snapshot) and the
// label goes quiet.
#[test]
fn fallen_carrier_carries_nothing_spec_sync_7() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    let (map, seq) = (Ak::new(GONEMAP.ak()).unwrap(), Ak::new(SEQ.ak()).unwrap());
    let key = |k: &str, v: &str| PathOp { path: vec![PathSeg::Key(s(k))], op: Op::Set(s(v)) };
    let mut m = Mutation::new();
    m.op(t, &GONEMAP, key("x", "r")).unwrap();
    m.op(t, &GONEMAP, key("y", "r")).unwrap();
    m.op(t, &SEQ, PathOp { path: Vec::new(), op: Op::Insert { at: 0, items: vec![s("#h")] } }).unwrap();
    let c = net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    let mut m = Mutation::new();
    m.op(t, &GONEMAP, key("y", "s")).unwrap();
    m.op(t, &SEQ, PathOp { path: Vec::new(), op: Op::Delete { at: 0, len: 1 } }).unwrap();
    net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    let blobs = blobs_of(&mut net, b, &l, c);
    let acts = net.sync(b).compact(&t, &seq).unwrap();
    net.actions(b, acts);
    net.run();
    net.set_online(a, false);
    let acts = net.sync(b).compact(&t, &map).unwrap();
    net.actions(b, acts);
    net.run();
    net.advance(2 * 3_600_000);
    net.run();
    assert!(!net.engine(b).body_not_dropped(&c, &t, &map) && !net.engine(b).body_not_dropped(&c, &t, &seq), "B dropped C");
    assert!(blobs.iter().all(|id| !net.host_ids(host, &l).contains(id)), "B deleted C at the host");
    let bt = net.tid(b);
    demote(&mut net, a, g, bt, Role::Read);
    net.set_online(a, true);
    net.run();
    net.advance(61_000);
    net.run();
    let before = log_len(&net, host, &l);
    for _ in 0..6 {
        net.advance(5 * 60_000);
        net.run();
    }
    assert_eq!(log_len(&net, host, &l), before, "no upload and delete loop");
    assert!(net.engine(b).body_not_dropped(&c, &t, &map), "B took C's map delta back");
    assert!(!net.engine(b).body_not_dropped(&c, &t, &seq));
    assert!(blobs_of(&mut net, a, &l, c).iter().any(|id| net.host_ids(host, &l).contains(id)), "A placed C again");
    assert_eq!(net.engine(b).get_typed(&t, &GONEMAP).unwrap(), net.engine(a).get_typed(&t, &GONEMAP).unwrap());
}

// spec/commits.md §5 The setting, spec/sync.md §7: one side lacking the thing's setting (writer b
// never hears of its blob) judges X, its own register write, out of history: it compacts, drops X
// and deletes it at the host. Admin a holds the setting keeping the register for good, so X is in
// history there and a keeps it; b's snapshot under the label covers it, so a never places it
// again: X's blobs leave the host once and the label goes quiet (no upload and delete repeat).
#[test]
fn one_side_lacking_the_setting_no_upload_delete_repeat_spec_sync_7() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    let k = Ak::new(REG.ak()).unwrap();
    net.set_online(b, false);
    let setting = net.keep(a, t, &[(REG.ak(), osis_schema::History::FOREVER)]);
    net.run();
    let hidden: std::collections::BTreeSet<_> = blobs_of(&mut net, a, &l, setting).into_iter().collect();
    assert!(!hidden.is_empty());
    net.hide_blobs.insert(b, hidden);
    net.set_online(b, true);
    net.advance(1_000);
    // b's own to delete at the host (author_or_admin)
    let x = net.write_own(b, t, "one");
    net.run();
    net.advance(61_000);
    net.run();
    let xs = blobs_of(&mut net, b, &l, x);
    assert!(!xs.is_empty() && xs.iter().all(|id| net.host_ids(host, &l).contains(id)));
    net.advance(1_000);
    net.write(b, t, "two");
    net.run();
    let acts = net.sync(b).compact(&t, &k).unwrap();
    net.actions(b, acts);
    net.run();
    net.advance(2 * 3_600_000);
    net.run();
    assert!(net.engine(b).core.ix.retention.get(&t).is_none(), "b lacks the setting");
    assert!(!net.engine(b).body_not_dropped(&x, &t, &k), "b dropped X: out of history there");
    assert!(net.engine(a).body_not_dropped(&x, &t, &k), "a keeps X: in history there");
    assert!(xs.iter().all(|id| !net.host_ids(host, &l).contains(id)), "X left the host");
    let before = log_len(&net, host, &l);
    for _ in 0..6 {
        net.advance(5 * 60_000);
        net.run();
        assert!(xs.iter().all(|id| !net.host_ids(host, &l).contains(id)), "X stays out of the host");
    }
    assert_eq!(log_len(&net, host, &l), before, "no upload and delete repeat");
    assert!(net.engine(a).body_not_dropped(&x, &t, &k) && !net.engine(b).body_not_dropped(&x, &t, &k));
}

// spec/permissions.md §6, spec/sync.md §6: a purge of a valid delta takes its blob off the host
// though the blob also holds a delta the purger dropped as invalid (a writer's admin-only write)
#[test]
fn purge_beside_invalid_delta_leaves_host_spec_perm_6() {
    for with_bad in [false, true] {
        let mut net = Net::new();
        let host = net.add_host();
        let a = net.node(1, &[host]);
        let b = net.node(2, &[host]);
        let g = net.group(a, &[(b, Role::Write)], &[host]);
        let t = net.item(a, g, g, "v1");
        net.run();
        let settle = |net: &mut Net| {
            net.run();
            net.advance(10_000);
            net.run();
        };
        let l = net.label(a);
        let (bad, good) = (Ak::new("t:bad^.0").unwrap(), Ak::new("t:good.0").unwrap());
        let before: std::collections::BTreeSet<_> = net.host_ids(host, &l).into_iter().collect();
        let mut m = Mutation::new();
        m.set(t, &good, &s("good")).unwrap();
        if with_bad {
            m.set(t, &bad, &s("bad")).unwrap();
        }
        let cm = net.engine(b).commit_hostile(m).unwrap().unwrap();
        settle(&mut net);
        let new: std::collections::BTreeSet<_> = net.host_ids(host, &l).into_iter().filter(|x| !before.contains(x)).collect();
        assert!(!new.is_empty());
        assert_eq!(net.engine(a).get(&t, &good).unwrap(), Some(s("good")));
        if with_bad {
            assert!(!net.engine(a).body_not_dropped(&cm, &t, &bad), "dropped as invalid");
        }
        net.set_online(b, false);
        let mut m = Mutation::new();
        m.purge(osis_commit::PurgeItem::Commit { commit: cm, tid: t, ak: good.clone() });
        m.remove_aspect(t, &good).unwrap();
        net.engine(a).commit(m).unwrap().unwrap();
        settle(&mut net);
        settle(&mut net);
        assert!(!net.engine(a).body_not_dropped(&cm, &t, &good));
        let left: Vec<_> = net.host_ids(host, &l).into_iter().filter(|x| new.contains(x)).collect();
        assert!(left.is_empty(), "with_bad {with_bad}: the purged blob stays at the host: {left:?}");
    }
}

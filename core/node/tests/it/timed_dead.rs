#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Timed deletes of bodies whose writes all died (spec/sync.md §5, §7): no carrier snapshot.

use crate::net;
use net::*;
use osis_node::Mutation;
use osis_node::sync::EntryKind;

// spec/sync.md §7 (a body with live writes is deleted only while another entry carries them;
// one without needs none), spec/commits.md §5: a register under a relative keep-at-most
// replaced whole goes at its bound by a timed delete sent with the replacing upload, and no
// covering snapshot is written for it; the node's record of the timed delete goes with the entry.
#[test]
fn replaced_register_needs_no_carrier_spec_sync_7() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
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
    let snapshots = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if net.engine(a).header(commit).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot))).count();
    assert_eq!(snapshots, 0, "no carrier for a body without live writes");
    let before = net.host_ids(host, &l).len();
    assert_eq!(net.sync(a).sync_rows(b'd'), 1, "the timed delete the host took is recorded");
    net.set_online(a, false);
    net.clock.advance(3_600_000 + 1_000);
    let now = net.now();
    net.hosts[host].hub.tick(now);
    assert_eq!(net.host_ids(host, &l).len() + 1, before, "the replaced body went at its bound, nobody online");
    // the record goes with the entry (growth: notes/growth.md)
    net.set_online(a, true);
    net.run();
    assert_eq!(net.sync(a).sync_rows(b'd'), 0, "the timed delete's record left with its entry");
}

/// Host entries of commit `c` under `l`, as node `n` knows them.
fn at_host(net: &mut Net, n: usize, host: usize, l: &osis_base::LabelId, c: &osis_base::CommitId) -> Vec<osis_base::BlobId> {
    let ids = net.host_ids(host, l);
    net.sync(n).entries(l).into_iter().filter(|(id, k)| ids.contains(id) && matches!(k, EntryKind::Commit { commit, .. } if commit == c)).map(|(id, _)| id).collect()
}

// spec/commits.md §5 (keep at most: a body with a live write keeps `AT_MOST_GRACE`; no
// carrier needed without one), spec/sync.md §5 (a timed delete cannot be withdrawn), §6
// (must-hold): a body whose write died gets a timed delete; a validity flip (the replacing
// writer revoked from before its write) revives the write; the host deletes the body at the
// plain bound all the same, and a right holder online uploads it again at its next resync (a
// fresh encryption): a window, not a loss. Offline, the window lasts until it next syncs; the
// revived write has no death, so the body then stays (no bound). A holder offline throughout reads v1
// when it comes back (`late_holder_judges_backdated_revoke_alike_*`).
#[test]
fn revived_body_uploaded_again_after_timed_delete_spec_commits_5() {
    use osis_base::Role;
    use osis_node::flows::{Demotion, PreSync};
    let gone = osis_base::Ak::new("t:gone.0").unwrap();
    for online in [true, false] {
        let mut net = Net::new();
        let host = net.add_host();
        let a = net.node(3, &[host]);
        let b = net.node(4, &[host]);
        let late = net.node(5, &[host]);
        let g = net.group(a, &[(b, Role::Write), (late, Role::Read)], &[host]);
        net.set_online(late, false);
        let t = net.item(a, g, g, "x");
        net.run();
        let l = net.label(a);
        let mut m = Mutation::new();
        m.set(t, &GONE, &s("v1")).unwrap();
        let c1 = net.engine(a).commit(m).unwrap().unwrap();
        net.run();
        net.advance(60_000);
        let before = net.now();
        net.advance(1_000);
        net.run();
        let mut m = Mutation::new();
        m.set(t, &GONE, &s("v2")).unwrap();
        net.engine(b).commit(m).unwrap();
        net.run();
        net.advance(1_000);
        assert_eq!(net.engine(a).get(&t, &gone).unwrap(), Some(s("v2")));
        let first = at_host(&mut net, a, host, &l, &c1);
        assert_eq!(first.len(), 1, "v1's body is at the host, its delete timed");
        // b revoked from before its write: v2 is void, v1 live again at a
        let bt = net.tid(b);
        net.set_online(b, false);
        let d = Demotion { holder: bt, new: None, presync: PreSync::Backdated(osis_base::WallMs(before)) };
        let done = net.engine(a).demote(&g, &d).unwrap();
        let acts = net.sync(a).carry_out(done).unwrap();
        net.actions(a, acts);
        net.run();
        assert_eq!(net.engine(a).get(&t, &gone).unwrap(), Some(s("v1")), "v1 revived");
        net.set_online(a, online);
        // past the plain bound: the host carries out the timed delete
        net.advance(3_600_000);
        net.run();
        let again = at_host(&mut net, a, host, &l, &c1);
        assert!(!again.contains(&first[0]), "the timed delete went at the plain bound");
        if online {
            // the next resync (`resync_ms`) finds the body missing there
            let resync = net.sync(a).config().resync_ms;
            net.advance(resync);
            assert_eq!(at_host(&mut net, a, host, &l, &c1).len(), 1, "uploaded again on the next resync");
            net.set_online(late, true);
            net.run();
            net.advance(resync);
            assert_eq!(net.engine(late).get(&t, &gone).unwrap(), Some(s("v1")), "a holder offline throughout");
            continue;
        }
        assert!(again.is_empty(), "deleted while no right holder is online");
        net.set_online(a, true);
        net.run();
        assert_eq!(at_host(&mut net, a, host, &l, &c1).len(), 1, "uploaded again on the next sync");
        // revived, v1 has no death (spec/crdt.md §4.8: only applied valid writes supersede),
        // so no keep-at-most bound: the body stays, as at a node that never saw v2 valid
        assert_eq!(net.engine(a).deaths(&c1, &t, &gone).unwrap(), None);
        net.advance(osis_base::format::AT_MOST_GRACE_MS);
        net.advance(1_000);
        assert_eq!(at_host(&mut net, a, host, &l, &c1).len(), 1, "kept: v1 is current");
        assert!(net.engine(a).body_not_dropped(&c1, &t, &gone));
        net.set_online(late, true);
        net.run();
        let resync = net.sync(a).config().resync_ms;
        net.advance(resync);
        assert_eq!(net.engine(late).get(&t, &gone).unwrap(), Some(s("v1")), "a holder offline throughout");
    }
}

// spec/permissions.md §5.2 (a write after a revoke's frontier is invalid, whatever the order
// it arrives in), spec/crdt.md §4.6: a holder that was offline while a writer's later write
// and a backdated revoke of that writer arrived must read what an online holder reads.
// (Was order-dependent: the item's `created.0` reached perm's walk after the revoke, and the
// walk kept no demotion for it; osis-perm `Walked::alias_leaves`.)
#[test]
fn late_holder_judges_backdated_revoke_alike_spec_permissions_5() {
    use osis_base::Role;
    use osis_node::flows::{Demotion, PreSync};
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(13, &[host]);
    let b = net.node(14, &[host]);
    let late = net.node(15, &[host]);
    let on = net.node(16, &[host]);
    let g = net.group(a, &[(b, Role::Write), (late, Role::Read), (on, Role::Read)], &[host]);
    net.set_online(late, false);
    let t = net.item(a, g, g, "v1");
    net.run();
    net.advance(60_000);
    let before = net.now();
    net.advance(1_000);
    net.write(b, t, "v2");
    net.run();
    net.advance(1_000);
    let bt = net.tid(b);
    net.set_online(b, false);
    let d = Demotion { holder: bt, new: None, presync: PreSync::Backdated(osis_base::WallMs(before)) };
    let done = net.engine(a).demote(&g, &d).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    assert_eq!(net.read(a, t), Some(s("v1")));
    assert_eq!(net.read(on, t), Some(s("v1")), "an online holder");
    net.set_online(late, true);
    net.run();
    net.advance(61_000);
    assert_eq!(net.read(late, t), Some(s("v1")), "a holder offline throughout");
}

/// Commits `c1` = {`GONE` (`r`): "v1", `REG`: "k"} and `c2` = {`GONE` (`r2`): "v2"} on a new item
/// by a node at a host; the time passes (`after`); c1's `GONE` body leaves the host, then a reader
/// syncing the item comes online: c1 applies there, with its `REG` part.
fn reader_applies_after_carrierless_delete(seed: u64, r: Option<osis_schema::Retention>, r2: Option<osis_schema::Retention>, after: u64) {
    use osis_base::Role;
    let (gone, reg) = (osis_base::Ak::new("t:gone.0").unwrap(), osis_base::Ak::new("t:reg.0").unwrap());
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(seed, &[host]);
    let b = net.node(seed + 1, &[host]);
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    assert!(net.engine(b).core.syncs(&t), "a commit waits only where its thing is synced");
    // back only after the delete, so it never sees the body
    net.set_online(b, false);
    let l = net.label(a);
    let mut m = Mutation::new();
    if let Some(r) = r {
        m.retention(t, &GONE, r).unwrap();
    }
    m.set(t, &GONE, &s("v1")).unwrap();
    m.set(t, &REG, &s("k")).unwrap();
    let c1 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(at_host(&mut net, a, host, &l, &c1).len(), 2, "two bodies: two retention classes");
    net.advance(1_000);
    let mut m = Mutation::new();
    if let Some(r) = r2 {
        m.retention(t, &GONE, r).unwrap();
    }
    m.set(t, &GONE, &s("v2")).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    net.advance(after);
    let now = net.now();
    net.hosts[host].hub.tick(now);
    net.run();
    assert_eq!(at_host(&mut net, a, host, &l, &c1).len(), 1, "c1's GONE body left the host");
    let snapshots = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if net.engine(a).header(commit).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot))).count();
    assert_eq!(snapshots, 0, "with no carrier");
    net.set_online(b, true);
    net.run();
    let resync = net.sync(b).config().resync_ms;
    net.advance(resync);
    assert!(net.engine(b).pending().is_empty(), "{:?}", net.engine(b).pending());
    assert_eq!(net.engine(b).get(&t, &reg).unwrap(), Some(s("k")), "as at the writer");
    assert_eq!(net.engine(b).get(&t, &gone).unwrap(), Some(s("v2")));
    assert_eq!(net.engine(b).state(&t, &reg).unwrap(), net.engine(a).state(&t, &reg).unwrap());
    assert_eq!(net.engine(b).state(&t, &gone).unwrap(), net.engine(a).state(&t, &gone).unwrap());
}

fn most(abs: Option<u64>, rel: Option<u64>) -> Option<osis_schema::Retention> {
    use osis_schema::{Bound, PurgeBy, Retention};
    Some(Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs, rel } })
}

// spec/commits.md §4 (a delta past its keep-at-most bound counts as held), §5 (a body with no live
// write needs no carrier), driving the real deletion: at most 0, deleted with the kill's sync.
#[test]
fn reader_after_delete_at_most_zero_spec_commits_4() {
    let r = most(None, Some(0));
    reader_applies_after_carrierless_delete(0x7d10, r, r, 0);
}

// The same with D after replaced: a timed delete, carried out by the host at its bound.
#[test]
fn reader_after_timed_delete_spec_commits_4() {
    let r = most(None, Some(600_000));
    reader_applies_after_carrierless_delete(0x7d20, r, r, 600_000 + 1_000);
}

// spec/commits.md §4: a pending commit whose missing part's bound comes wakes its node at the
// bound, nothing else happening (no resync, no timer of its own).
#[test]
fn wait_wakes_node_at_bound_spec_commits_4() {
    use osis_base::Role;
    const D: u64 = 5_000;
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(0x7d40, &[host]);
    let b = net.node(0x7d41, &[host]);
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    assert!(net.sync(b).config().resync_ms > D);
    net.set_online(a, false);
    let r = most(None, Some(D)).unwrap();
    let mut m = Mutation::new();
    m.retention(t, &GONE, r).unwrap();
    m.set(t, &GONE, &s("v1")).unwrap();
    m.set(t, &REG, &s("k")).unwrap();
    let c1 = net.engine(a).commit(m).unwrap().unwrap();
    net.advance(1);
    let mut m = Mutation::new();
    m.retention(t, &GONE, r).unwrap();
    m.set(t, &GONE, &s("v2")).unwrap();
    let c2 = net.engine(a).commit(m).unwrap().unwrap();
    let pk = net.engine(a).package(&c1).unwrap().unwrap();
    let mut blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let h = blob.header.clone();
    blob.parts.retain(|p| h.aspects[p.ai].ak.as_str() == "t:reg.0");
    net.engine(b).ingest(&blob.encode(), pk.blobs).unwrap();
    let pk = net.engine(a).package(&c2).unwrap().unwrap();
    net.engine(b).ingest(&pk.bytes, pk.blobs).unwrap();
    assert_eq!(net.engine(b).pending().len(), 1);
    let bound = net.now() + D;
    net.feed(b, osis_node::sync::Event::Tick);
    assert!(net.nodes[b].wake.is_some_and(|at| at <= bound), "{:?} vs {bound}", net.nodes[b].wake);
    net.advance(D);
    assert!(net.engine(b).pending().is_empty(), "{:?}", net.engine(b).pending());
}

/// A new item a writer and a reader both sync: (net, writer, reader, item).
fn writer_and_reader(seed: u64) -> (Net, usize, usize, osis_base::Tid) {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(seed, &[host]);
    let b = net.node(seed + 1, &[host]);
    let g = net.group(a, &[(b, osis_base::Role::Read)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    (net, a, b, t)
}

/// Runs a resync, then `t`'s `GONE` as the reader `b` reads it is the writer's `v1`.
fn reader_got_v1(net: &mut Net, a: usize, b: usize, t: osis_base::Tid) {
    let gone = osis_base::Ak::new("t:gone.0").unwrap();
    let resync = net.sync(a).config().resync_ms;
    net.advance(resync);
    net.run();
    assert_eq!(net.engine(a).get(&t, &gone).unwrap(), Some(s("v1")));
    assert_eq!(net.engine(b).get(&t, &gone).unwrap(), Some(s("v1")), "a live write reaches the reader");
}

// spec/commits.md §5 (a body with live writes leaves a label only with a carrier): an absolute
// keep at most already past at the write. Dropping the body in the writing transaction lost the
// write for everyone else: it had never been uploaded and no carrier was written.
#[test]
fn absolute_bound_past_at_write_reaches_reader_spec_commits_5() {
    let (mut net, a, b, t) = writer_and_reader(0x9a10);
    let now = net.now();
    let mut m = Mutation::new();
    m.retention(t, &GONE, most(Some(now - 1), None).unwrap()).unwrap();
    m.set(t, &GONE, &s("v1")).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    reader_got_v1(&mut net, a, b, t);
}

// The same with T passing while the writer is offline, before it ever uploaded the body.
#[test]
fn absolute_bound_passing_offline_reaches_reader_spec_commits_5() {
    let (mut net, a, b, t) = writer_and_reader(0x9a20);
    net.set_online(a, false);
    let now = net.now();
    let mut m = Mutation::new();
    m.retention(t, &GONE, most(Some(now + 10_000), None).unwrap()).unwrap();
    m.set(t, &GONE, &s("v1")).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.advance(20_000);
    net.engine(a).tick().unwrap();
    net.set_online(a, true);
    net.run();
    reader_got_v1(&mut net, a, b, t);
}

// spec/commits.md §4: a reader's first sync, a host hiding one of a commit's two bodies: the other
// waits, as at a reader already syncing the thing. The thing's record is all it shows.
#[test]
fn first_sync_waits_for_hidden_body_spec_commits_4() {
    use osis_base::Role;
    let (gone, reg) = (osis_base::Ak::new("t:gone.0").unwrap(), osis_base::Ak::new("t:reg.0").unwrap());
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(70, &[host]);
    let b = net.node(71, &[host]);
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    net.set_online(b, false);
    let t = net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    let mut m = Mutation::new();
    m.retention(t, &GONE, most(None, Some(3_600_000)).unwrap()).unwrap();
    m.set(t, &GONE, &s("v1")).unwrap();
    m.set(t, &REG, &s("k")).unwrap();
    let c1 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(at_host(&mut net, a, host, &l, &c1).len(), 2, "two bodies: two retention classes");
    let h = net.engine(a).header(&c1).unwrap();
    let ai = h.aspects.iter().position(|x| x.ak == gone).unwrap();
    let hide: std::collections::BTreeSet<_> = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, parts, .. } if *commit == c1 && parts.iter().any(|p| p.0 == ai))).map(|(id, _)| id).collect();
    assert_eq!(hide.len(), 1);
    net.hide_blobs.insert(b, hide);
    net.set_online(b, true);
    net.run();
    assert_eq!(net.engine(b).get(&t, &reg).unwrap(), Some(s("x")), "c1's REG part waits");
    assert_eq!(net.engine(b).get(&t, &gone).unwrap(), None);
    assert_eq!(net.engine(b).pending(), vec![(c1, osis_node::Reason::WaitDeltas)]);
    // the body comes (the host's cursor has passed it: by another way)
    let pk = net.engine(a).package(&c1).unwrap().unwrap();
    net.engine(b).ingest(&pk.bytes, pk.blobs).unwrap();
    assert_eq!(net.engine(b).get(&t, &reg).unwrap(), Some(s("k")));
    assert_eq!(net.engine(b).get(&t, &gone).unwrap(), Some(s("v1")));
}

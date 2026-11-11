#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Deletes of bodies whose writes all died (spec/sync.md §7): under purge on replace the
//! replacing writer's cover is the one snapshot.

use crate::net::hosted;
use crate::net;
use net::*;
use osis_node::Mutation;
use osis_node::sync::EntryKind;

// spec/commits.md §5 (purge on replace), spec/sync.md §7: a register purged on replace and
// replaced whole goes under the writer's one cover, here and at the host in the same sync.
#[test]
fn replaced_register_goes_under_its_cover_spec_sync_7() {
    let (mut net, host, [a], _g, [t]) = hosted::<1, 1>(&[], ["x"], false);
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("v1")).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    let l = net.label(a);
    let before = net.host_ids(host, &l).len();
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("v2")).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    let snapshots = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if net.engine(a).header(commit).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot))).count();
    assert_eq!(snapshots, 1, "the cover");
    assert_eq!(net.host_ids(host, &l).len(), before, "the cover went up, the replaced bodies left");
}

/// Host entries of commit `c` under `l`, as node `n` knows them.
fn at_host(net: &mut Net, n: usize, host: usize, l: &osis_base::LabelId, c: &osis_base::CommitId) -> Vec<osis_base::BlobId> {
    let ids = net.host_ids(host, l);
    net.sync(n).entries(l).into_iter().filter(|(id, k)| ids.contains(id) && matches!(k, EntryKind::Commit { commit, .. } if commit == c)).map(|(id, _)| id).collect()
}

// spec/permissions.md §5.2 (a write after a revoke's frontier is invalid, whatever the order
// it arrives in), spec/crdt.md §4.6: a holder that was offline while a writer's later write
// and a revoke of that writer by an admin that never received it arrived must read what an
// online holder reads. (Was order-dependent: the item's `created.0` reached perm's walk after
// the revoke, and the walk kept no demotion for it; osis-perm `Walked::alias_leaves`.)
#[test]
fn late_holder_judges_revoke_alike_spec_permissions_5() {
    use osis_base::Role;
    use osis_node::flows::Demotion;
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(13, &[host]);
    let b = net.node(14, &[host]);
    let late = net.node(15, &[host]);
    let on = net.node(16, &[host]);
    let x = net.node(17, &[host]);
    let g = net.group(a, &[(b, Role::Write), (late, Role::Read), (on, Role::Read), (x, Role::Admin)], &[host]);
    net.set_online(late, false);
    let t = net.item(a, g, g, "v1");
    net.run();
    net.advance(60_000);
    net.set_online(x, false);
    net.advance(1_000);
    net.write(b, t, "v2");
    net.run();
    assert_eq!(net.read(a, t), Some(s("v2")), "taken before the revoke");
    assert_eq!(net.read(x, t), Some(s("v1")), "the revoker never received it");
    net.advance(1_000);
    let bt = net.tid(b);
    net.set_online(b, false);
    let d = Demotion { holder: bt, new: None, retain: None };
    let done = net.engine(x).demote(&g, &d).unwrap();
    let acts = net.sync(x).carry_out(done).unwrap();
    net.actions(x, acts);
    // back online: reconnects on its next tick
    net.set_online(x, true);
    net.run();
    net.advance(61_000);
    // the admin received v2 before the revoke and vouches for it (spec/permissions.md §5.2,
    // Addenda); an online reader reads it once the addendum reaches it
    assert_eq!(net.read(a, t), Some(s("v2")), "a writer that received it in time");
    net.run();
    net.advance(61_000);
    net.run();
    assert_eq!(net.read(on, t), Some(s("v2")), "an online holder");
    net.set_online(late, true);
    net.run();
    net.advance(61_000);
    // v2 come before the addendum went while invalid (spec/permissions.md §6): fetched again
    net.run();
    net.advance(61_000);
    net.run();
    assert_eq!(net.read(late, t), Some(s("v2")), "a holder offline throughout, once it has the addendum");
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
    assert_eq!(at_host(&mut net, a, host, &l, &c1).len(), 1, "one blob, two retention classes");
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
    assert_eq!(snapshots, 1, "the writer's cover");
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

/// `writer`, purged on replace.
pub(crate) fn purge_on_replace() -> Option<osis_schema::Retention> {
    use osis_schema::{History, PurgeBy, Retention};
    Some(Retention { by: PurgeBy::Writer, history: Some(History::PurgeOnReplace) })
}

// spec/commits.md §4 (a node never waits for a part), §5 (purge on replace), driving the real
// deletion: the replaced body goes with the kill's sync, under the writer's cover.
#[test]
fn reader_after_delete_purge_on_replace_spec_commits_4() {
    let r = purge_on_replace();
    reader_applies_after_carrierless_delete(0x7d10, r, r, 0);
}

// spec/commits.md §4 (a node never waits for a part), §5 (a header-only blob goes under a label only
// as a lasting header): a snapshot taken without an earlier-stamped removal is dead on arrival under
// purge on replace. Nothing of it stays at the host, so a node coming later never hears of it and has
// nothing pending. Handed the bare header anyway, it applies it alone and reads the same.
#[test]
fn snapshot_dead_by_earlier_removal_leaves_no_wait_spec_commits_4() {
    use osis_base::Role;
    use osis_crdt::{Op, PathOp, PathSeg};
    let gone = osis_base::Ak::new("t:gonemap.0").unwrap();
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(0x7d30, &[host]);
    let b = net.node(0x7d31, &[host]);
    let late = net.node(0x7d32, &[host]);
    let g = net.group(a, &[(b, Role::Write), (late, Role::Read)], &[host]);
    net.set_online(late, false);
    let t = net.item(a, g, g, "x");
    let mut m = Mutation::new();
    m.op(t, &GONEMAP, PathOp { path: vec![PathSeg::Key(s("k"))], op: Op::Set(s("v")) }).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    net.set_online(a, false);
    net.advance(1_000);
    let mut m = Mutation::new();
    m.op(t, &GONEMAP, PathOp { path: Vec::new(), op: Op::Remove(s("k")) }).unwrap();
    let rm = net.engine(b).commit(m).unwrap().unwrap();
    let rm_ts = net.engine(b).header(&rm).unwrap().ts;
    net.run();
    net.advance(1_000);
    let snap = net.engine(a).snapshot(&t, &gone).unwrap().unwrap();
    assert!(net.engine(a).header(&snap).unwrap().ts > rm_ts);
    net.set_online(a, true);
    net.run();
    let resync = net.sync(a).config().resync_ms;
    net.advance(resync);
    net.run();
    net.advance(resync);
    net.run();
    for n in [a, b] {
        assert!(!net.engine(n).body_not_dropped(&snap, &t, &gone), "dead, so gone");
    }
    let l = net.label(a);
    assert!(at_host(&mut net, a, host, &l, &snap).is_empty(), "deleted at the host, no carrier");
    net.set_online(late, true);
    net.run();
    net.advance(resync);
    net.run();
    assert_eq!(net.engine(late).pending(), Vec::new());
    assert!(net.engine(late).header(&snap).is_none(), "nothing of it reaches a later node");
    let want = net.engine(a).get(&t, &gone).unwrap();
    assert_eq!(net.engine(late).get(&t, &gone).unwrap(), want);
    let pk = net.engine(a).package(&snap).unwrap().unwrap();
    assert!(net.engine(a).body(&snap).unwrap().is_none());
    assert_eq!(net.engine(late).ingest(&pk.bytes, pk.blobs).unwrap(), osis_node::Ingested::Applied(snap));
    assert_eq!(net.engine(late).pending(), Vec::new());
    assert_eq!(net.engine(late).get(&t, &gone).unwrap(), want);
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
    m.retention(t, &GONE, purge_on_replace().unwrap()).unwrap();
    m.set(t, &GONE, &s("v1")).unwrap();
    m.set(t, &REG, &s("k")).unwrap();
    let c1 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(at_host(&mut net, a, host, &l, &c1).len(), 1, "one blob, two retention classes");
    let h = net.engine(a).header(&c1).unwrap();
    let ai = h.aspects.iter().position(|x| x.ak == gone).unwrap();
    let hide: std::collections::BTreeSet<_> = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, parts, .. } if *commit == c1 && parts.contains(&ai))).map(|(id, _)| id).collect();
    assert_eq!(hide.len(), 1);
    net.hide_blobs.insert(b, hide);
    net.set_online(b, true);
    net.run();
    // one blob per commit: hidden whole, nothing of c1 is received (spec/sync.md §3, §6)
    assert_eq!(net.engine(b).get(&t, &reg).unwrap(), Some(s("x")), "c1's REG part never came");
    assert_eq!(net.engine(b).get(&t, &gone).unwrap(), None);
    assert!(net.engine(b).pending().is_empty());
    // the body comes (the host's cursor has passed it: by another way)
    let pk = net.engine(a).package(&c1).unwrap().unwrap();
    net.engine(b).ingest(&pk.bytes, pk.blobs).unwrap();
    assert_eq!(net.engine(b).get(&t, &reg).unwrap(), Some(s("k")));
    assert_eq!(net.engine(b).get(&t, &gone).unwrap(), Some(s("v1")));
}

// spec/sync.md §6 (must-hold: established uncovered by held snapshots; a commit not judged
// covers nothing): writer b cannot judge a's commit (it also writes thing `u`, whose
// creating commit is hidden from b), which writes `t:reg.0`, and writes `t:reg.0` itself: b's
// body goes to the host all the same (was issue sync-unsettled-deadlock: two writers'
// pending commits, each waiting for the other's body, stopped each other's uploads). One blob
// per commit: a commit waits on a missing record, not on a hidden part.
#[test]
fn pending_commit_holds_back_no_own_upload_spec_sync_6() {
    use osis_base::Role;
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(74, &[host]);
    let b = net.node(75, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    net.set_online(b, false);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let u = e.new_thing(&mut m, g);
    let mut items = e.get_typed(&g, &osis_schema::core_types::GROUP).unwrap().unwrap_or_default();
    items.items.insert(u);
    m.set(g, &osis_schema::core_types::GROUP, &items).unwrap();
    let made = e.commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let hide: std::collections::BTreeSet<_> = at_host(&mut net, a, host, &l, &made).into_iter().collect();
    assert_eq!(hide.len(), 1);
    net.hide_blobs.insert(b, hide);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("k")).unwrap();
    m.set(u, &REG, &s("k")).unwrap();
    let c1 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    net.set_online(b, true);
    net.run();
    net.advance(30_000);
    net.run();
    assert!(net.engine(b).core.ix.commits.get(&c1).is_some_and(|m| !m.missing.is_empty()), "its part on `u` cannot be judged");
    let mut m = Mutation::new();
    m.set(t, &REG, &s("mine")).unwrap();
    let c2 = net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    assert!(net.engine(b).core.ix.commits.get(&c1).is_some_and(|m| !m.missing.is_empty()), "still awaiting");
    assert!(!at_host(&mut net, b, host, &l, &c2).is_empty(), "b's own body held back behind a commit not judged");
}

// spec/commits.md §4, spec/sync.md §3: a reader's first sync of a label, a commit across two of its
// things, a host hiding its one blob: nothing of the commit is received.
#[test]
fn first_sync_waits_across_things_spec_commits_4() {
    use osis_base::Role;
    let (gone, reg) = (osis_base::Ak::new("t:gone.0").unwrap(), osis_base::Ak::new("t:reg.0").unwrap());
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(72, &[host]);
    let b = net.node(73, &[host]);
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    net.set_online(b, false);
    let t = net.item(a, g, g, "t");
    let u = net.item(a, g, g, "u");
    net.run();
    let l = net.label(a);
    let mut m = Mutation::new();
    m.retention(t, &GONE, purge_on_replace().unwrap()).unwrap();
    m.set(t, &GONE, &s("v1")).unwrap();
    m.set(u, &REG, &s("k")).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let h = net.engine(a).header(&c).unwrap();
    let ai = h.aspects.iter().position(|x| x.ak == gone).unwrap();
    let hide: std::collections::BTreeSet<_> = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, parts, .. } if *commit == c && parts.contains(&ai))).map(|(id, _)| id).collect();
    assert_eq!(hide.len(), 1);
    net.hide_blobs.insert(b, hide);
    net.set_online(b, true);
    net.run();
    // one blob per commit: hidden whole, nothing of it is received (spec/sync.md §3, §6)
    assert_eq!(net.engine(b).get(&u, &reg).unwrap(), Some(s("u")), "the part on the other thing never came");
    assert!(net.engine(b).pending().is_empty());
    assert!(net.engine(b).header(&c).is_none());
}

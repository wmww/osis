//! Deletes by level at a node keeping S unread (spec/sync-ids.md §6 Delete, spec/crypto.md §7):
//! a writer that is no admin of S deletes there what it may purge, by the delete keys of the
//! levels it holds, never what it holds no level key for. On `three`: node 0 (admin) makes thing
//! 0, node 1's account keeps it unread, node 2 writes it; `four` adds a second writer, node 3.
//! What each delete may do is judged locally (tests/it/read.rs on a fake ground; the engine's
//! `blob_gone`, `strip_of`, `blob_loses`: osis-engine `sync::tests_facts`); these are the
//! end-to-end arms.

use crate::harness::Step::*;
use crate::harness::history::{Gives, three as three_of, value_ak, world_of};
use crate::harness::{World, edge, fixture_with, play};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Ak, BlobId, CommitId, PurgeBy, Role, SyncId, Tid, Value};
use osis_engine::Mutation;
use osis_sync::ConnId;
use osis_schema::core_types as ct;

/// Node 0 admin, node 1 keeping S unread, node 2 a writer (`history::three`, shared).
fn three() -> (World, Tid, SyncId) {
    let (mut w, t, s) = three_of(Gives::Writes, 2);
    w.cap = crate::harness::WIDE_CAP;
    (w, t, s)
}

/// `three` with node 3 a second writer, built once per process (`fixture_with`).
pub(crate) fn four() -> (World, Tid, SyncId) {
    let (w, (t, s)) = fixture_with("deletes four", || {
        let mut w = world_of(0, 4, 4);
        w.cap = crate::harness::WIDE_CAP;
        let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, Gives::Writes), Grant(0, 0, 3, Gives::Writes), Run], String::new());
        let t = w.history.things[0].0;
        let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
        (w, (t, s))
    });
    (w, t, s)
}

/// Node `i` writes `ak` of thing `t`, purgeable by `by`.
fn write(w: &mut World, i: usize, t: Tid, ak: &Ak, by: PurgeBy) -> CommitId {
    w.write(i, |e| {
        let mut m = Mutation::new();
        m.set(t, ak, &Value::Str(format!("by {i}"))).unwrap().purge_by(t, ak, by).unwrap();
        e.commit(m).unwrap().unwrap()
    })
}

/// Node `i` purges `aks` of commit `c` on thing `t`.
fn purge_of(w: &mut World, i: usize, t: Tid, c: CommitId, aks: &[Ak]) {
    w.write(i, |e| {
        let mut m = Mutation::new();
        let now = e.now();
        m.set(t, &ct::PURGE, &now).unwrap();
        for ak in aks {
            m.purge_commit(c, t, ak.clone());
        }
        e.commit(m).unwrap().unwrap();
    });
}

fn purge(w: &mut World, i: usize, t: Tid, c: CommitId) {
    purge_of(w, i, t, c, &[value_ak()]);
}

/// Node 1's entries of `c` under S (blobs `by` opened to `c`).
fn at_unread(w: &mut World, by: usize, s: &SyncId, c: &CommitId) -> Vec<BlobId> {
    let es = w.store(1).entries(s).unwrap();
    es.into_iter().filter(|e| w.engine(by).blob_commit(&e.blob) == Some(*c)).map(|e| e.blob).collect()
}

fn gone_at_unread(w: &mut World, s: &SyncId, held: &[BlobId]) -> bool {
    held.iter().all(|b| w.store(1).entry(s, b).unwrap().is_none())
}

// spec/sync-ids.md §6 (Delete), spec/crypto.md §7: a writer's purge of its own write reaches a
// node keeping S unread with no admin connected: the entry is deleted there by the writer's level
// keys, and stays deleted across restarts. The commit's two deltas under different purge-by
// frame two commitment groups (levels 1, 2 and levels 1, 2, 3); the groups the writer signs for
// are those the blob's prefix bears, and its level-2 key alone covers both. (Level 3 by a writer
// that is not the author: `a_writer_deletes_only_what_it_may_purge_spec_sync_judgement_3`.)
#[test]
fn a_writers_purge_of_its_own_write_deletes_it_at_a_node_keeping_s_unread_spec_sync_ids_6() {
    let (mut w, t, s) = three();
    let other = Ak::new("u:n.0").unwrap();
    let c = w.write(2, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("a".into())).unwrap().purge_by(t, &value_ak(), PurgeBy::AuthorOrAdmin).unwrap();
        m.set(t, &other, &Value::Str("b".into())).unwrap().purge_by(t, &other, PurgeBy::Writer).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    let held = at_unread(&mut w, 2, &s, &c);
    assert!(!held.is_empty(), "node 1 holds the write");
    for b in &held {
        let bytes = w.bytes(1, b).unwrap();
        let real = osis_blob::clear_prefix(&bytes).unwrap().unwrap();
        let basis = w.engine(2).blob_delete_basis(b).unwrap();
        let set = |p: &osis_blob::Prefix| p.groups().iter().cloned().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(real.groups().len(), 2, "two groups");
        assert_eq!(set(&basis.prefix), set(&real), "the writer's groups are the prefix's");
    }
    w.power_off(0);
    purge_of(&mut w, 2, t, c, &[value_ak(), other]);
    w.run();
    assert!(gone_at_unread(&mut w, &s, &held), "the writer's purge deleted it at node 1");
    for i in 1..3 {
        w.power_off(i);
        w.power_on(i);
    }
    w.power_on(0);
    w.run();
    assert!(gone_at_unread(&mut w, &s, &held), "still gone after restarts");
    assert_eq!(w.engine(0).get(&t, &value_ak()).unwrap(), Some(Value::Str("v1".into())), "the admin reads the purge: what the purged write replaced (spec/crdt.md §4.7)");
}

// spec/sync-judgement.md §3 (Deletes: a holder of the needed delete key or level keys),
// spec/sync-ids.md §6: writer 2 replaces two of writer 3's values, one purgeable by any writer, one
// by its author or an admin only; with the admin and the author away, writer 2 deletes the
// replaced one any writer may purge at the node keeping S unread (level 3), and the other stays
// (it holds no level key there).
#[test]
fn a_writer_deletes_only_what_it_may_purge_spec_sync_judgement_3() {
    let (mut w, t, s) = four();
    let other = Ak::new("u:n.0").unwrap();
    let anyone = write(&mut w, 3, t, &value_ak(), PurgeBy::Writer);
    let authors = write(&mut w, 3, t, &other, PurgeBy::AuthorOrAdmin);
    w.run();
    let (anyone, authors) = (at_unread(&mut w, 3, &s, &anyone), at_unread(&mut w, 3, &s, &authors));
    assert!(!anyone.is_empty() && !authors.is_empty(), "node 1 holds both");
    w.power_off(0);
    w.power_off(3);
    w.advance(10);
    write(&mut w, 2, t, &value_ak(), PurgeBy::Admin);
    write(&mut w, 2, t, &other, PurgeBy::Admin);
    w.run();
    w.advance(MAX_DRIFT_MS + 60_000);
    w.run();
    let held = |w: &mut World, bs: &[BlobId]| bs.iter().any(|b| w.store(1).entry(&s, b).unwrap().is_some());
    assert!(!held(&mut w, &anyone), "the writer deleted the replaced write any writer may purge");
    assert!(held(&mut w, &authors), "the writer deleted a write only its author or an admin may purge");
}

/// `three` where node 2 has written thing `t`'s value, purgeable by its author or an admin, run:
/// the commit and node 1's entries of it; built once per process (`fixture_with`).
fn written() -> (World, Tid, SyncId, CommitId, Vec<BlobId>) {
    let (w, (t, s, c, held)) = fixture_with("deletes written", || {
        let (mut w, t, s) = three();
        let c = write(&mut w, 2, t, &value_ak(), PurgeBy::AuthorOrAdmin);
        w.run();
        let held = at_unread(&mut w, 2, &s, &c);
        assert!(!held.is_empty(), "node 1 holds the write");
        (w, (t, s, c, held))
    });
    (w, t, s, c, held)
}

/// After `written`, node 1 goes away and `purger` (0 the admin, or 2 the author) purges the write
/// with the other one away, so the purger's Delete is the only one; `restart` restarts the purger
/// while node 1 is still away. Node 1 comes back: whether every entry of the commit left it.
fn purged_while_away(purger: usize, restart: bool) -> bool {
    let (mut w, t, s, c, held) = written();
    w.power_off(1);
    w.power_off(2 - purger);
    purge(&mut w, purger, t, c);
    w.run();
    if restart {
        w.power_off(purger);
        w.power_on(purger);
        w.run();
    }
    w.power_on(1);
    w.run();
    gone_at_unread(&mut w, &s, &held)
}

// spec/sync-judgement.md §3 (Deletes; What a source holds): a delete owed at a source keeping S
// unread is owed while its stream shows the entry, up or away: the admin's purge (by its delete
// key) made while node 1 is away deletes the entry there once it is back. (By a writer's level
// key: the next test, which also restarts the purger.)
#[test]
fn a_purge_made_while_the_unread_store_is_away_deletes_there_on_return_spec_sync_judgement_3() {
    assert!(purged_while_away(0, false), "the purge deleted it at node 1 on return");
}

// spec/sync-opens.md §3 (Agreement: nothing of a member goes before the digests agree),
// spec/sync-judgement.md §3 (Deletes: a delete owed stays owed across the source's absence and
// is sent once it is connected): node 1 goes away and comes back once; the admin purges the write
// and its Delete to node 1 is lost as node 1 goes away again; node 1 comes back, and the Delete goes
// again on the new connection, only once its digests agreed there. Fails with acts going on the
// record's connection at its take (`Ground::connected` as `conn_of`).
#[test]
fn an_owed_delete_waits_for_the_digests_to_agree_spec_sync_opens_3() {
    let (mut w, t, s, c, held) = written();
    w.power_off(1);
    w.run();
    w.power_on(1);
    w.run();
    w.power_off(2);
    let deletes = |w: &World| w.net.frames.get(&(0, 1, "Delete")).map_or(0, |x| x.0);
    // steps until `deletes` passes `n`; whether node 0's connection to node 1 had agreed then
    let until_delete = |w: &mut World, n: u64| -> Option<bool> {
        for _ in 0..100_000 {
            if !w.step_or_wake() {
                return None;
            }
            if deletes(w) > n {
                let conns: Vec<ConnId> = w.links_of(0).into_iter().filter(|(_, j)| *j == 1).map(|(c, _)| c).collect();
                return Some(conns.iter().any(|c| w.node(0).node.opens().agreed(*c)));
            }
        }
        None
    };
    purge(&mut w, 0, t, c);
    let n = deletes(&w);
    assert!(until_delete(&mut w, n).is_some(), "no Delete went to node 1");
    w.power_off(1);
    w.run();
    assert!(!gone_at_unread(&mut w, &s, &held), "the Delete reached node 1 before it went away");
    let n = deletes(&w);
    w.power_on(1);
    assert_eq!(until_delete(&mut w, n), Some(true), "the owed Delete went before the digests agreed, or never");
    w.run();
    assert!(gone_at_unread(&mut w, &s, &held), "the purge deleted it at node 1 on return");
}

// spec/sync-judgement.md §3 (Deletes; Dropped bodies): the owed delete survives a restart of the
// purging writer while node 1 is away; it signs from the prefix salt and aspects it kept of the
// dropped blob (`BlobOf`), its bytes gone. (An admin's delete key needs no kept blob.)
#[test]
fn an_owed_delete_survives_the_purgers_restart_spec_sync_judgement_3() {
    assert!(purged_while_away(2, true), "the purge deleted it at node 1 after the purger's restart");
}

// spec/sync-judgement.md §3 (What a source holds), scaling: a store source coming back judges
// again only what is owed there, never each entry its stream shows: its leaving and return
// judge as many bodies toward it with 2 entries shown as with 6.
#[test]
fn a_source_coming_back_judges_only_what_is_owed_there() {
    let toward = |n: usize| {
        let (mut w, t, _) = three();
        for i in 0..n {
            write(&mut w, 2, t, &Ak::new(format!("u:n.{i}")).unwrap(), PurgeBy::Writer);
        }
        w.run();
        osis_base::costs::take();
        for j in [0, 2] {
            w.partition(1, j);
        }
        w.run();
        for j in [0, 2] {
            w.rejoin(1, j);
        }
        w.run();
        osis_base::costs::take().into_iter().filter(|(k, ..)| *k == "read: toward").map(|(.., n)| n).sum::<u64>()
    };
    let (few, many) = (toward(2), toward(6));
    assert_eq!(few, many, "toward judged {few} with 2 entries shown, {many} with 6");
}

// spec/sync-set.md §2 (Sync set; kept unread): node 1 keeps S unread by its sync grant; after
// a restart S stays in its sync set.
#[test]
fn a_sync_id_kept_unread_by_a_grant_stays_synced_across_a_restart_spec_sync_set_2() {
    let (mut w, t, s) = three();
    let unread = Some((std::collections::BTreeSet::from([t]), osis_engine::sync::Holding::Unread));
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), unread, "kept unread before");
    w.power_off(1);
    w.power_on(1);
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), unread, "kept unread after the restart");
}

/// Node 2 writes `value_ak` (marked) and `u:n.0` in one commit, both purgeable by any writer.
fn two_parts(w: &mut World, t: Tid, marker: &str) -> CommitId {
    let other = Ak::new("u:n.0").unwrap();
    w.write(2, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str(marker.into())).unwrap().purge_by(t, &value_ak(), PurgeBy::Writer).unwrap();
        m.set(t, &other, &Value::Str("kept".into())).unwrap().purge_by(t, &other, PurgeBy::Writer).unwrap();
        e.commit(m).unwrap().unwrap()
    })
}

// spec/sync-judgement.md §2 (per blob), spec/commits.md §5 (Purge: one delta of a commit): a
// purge of one part of a two-part commit leaves the commit's old blob in no store: every reader
// logs the rewrite without it (one entry each, the same one), and the writer's delete takes the
// old blob from the node keeping S unread once the rewrite is there; the other part still reads,
// and the purged one reads as if never written.
#[test]
fn a_purge_of_one_part_rewrites_the_blob_everywhere_spec_sync_judgement_2() {
    let (mut w, t, s) = three();
    // what the purged write replaced: the read once it is gone (spec/crdt.md §4.7)
    let before = w.engine(0).get(&t, &value_ak()).unwrap();
    let c = two_parts(&mut w, t, "a");
    w.run();
    let old = at_unread(&mut w, 2, &s, &c);
    assert_eq!(old.len(), 1, "node 1 holds the commit's blob");
    w.advance(10);
    purge(&mut w, 2, t, c);
    w.run();
    let now = at_unread(&mut w, 2, &s, &c);
    assert!(!now.contains(&old[0]), "the old blob left node 1");
    assert!(!now.is_empty(), "node 1 holds the rewrite");
    let mut logged = std::collections::BTreeSet::new();
    for i in [0, 2] {
        let es: Vec<BlobId> = w.store(i).entries(&s).unwrap().into_iter().map(|e| e.blob).filter(|b| w.engine(2).blob_commit(b) == Some(c)).collect();
        assert_eq!(es.len(), 1, "node {i} logs one blob of the commit");
        assert_eq!(w.engine(i).blob_parts(&es[0]).map(|p| p.len()), Some(1), "node {i}: the rewrite holds the other part alone");
        logged.extend(es);
        assert_eq!(w.engine(i).get(&t, &Ak::new("u:n.0").unwrap()).unwrap(), Some(Value::Str("kept".into())), "node {i} reads the other part");
        assert_eq!(w.engine(i).get(&t, &value_ak()).unwrap(), before, "node {i} reads as if the purged write never was");
    }
    assert_eq!(logged.len(), 1, "the readers settle on one rewrite");
}

/// Node 0 makes thing t with `value` under purge on replace and writes one commit holding a
/// marked `value` and a note that stays, then replaces `value`: its cover drops the marked part
/// and strips it from the commit's blobs. Node 1 is a second node of its account. The world,
/// t, the two-part commit and the marker; built once per process (`fixture_with`).
fn replaced_beside_a_kept_part() -> (World, Tid, CommitId, String) {
    let (w, (t, c, marker)) = fixture_with("deletes replaced beside a kept part", build_replaced);
    (w, t, c, marker)
}

fn build_replaced() -> (World, (Tid, CommitId, String)) {
    let mut w = World::new(0);
    w.record = true;
    w.add_node();
    w.pair(0);
    w.run();
    let a = w.node(0).account.unwrap();
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a);
        let x: ct::RetentionSetting = [(value_ak(), ct::RetentionEntry { history: Some(osis_schema::History::PurgeOnReplace), ..Default::default() })].into_iter().collect();
        m.set(t, &ct::RETENTION, &x).unwrap();
        e.commit(m).unwrap();
        t
    });
    w.run();
    let marker = format!("PORMARK-77e3a1b2{}", "x".repeat(300));
    let by = PurgeBy::Writer;
    let c = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str(marker.clone())).unwrap().purge_by(t, &value_ak(), by).unwrap();
        m.set(t, &Ak::new("u:n.0").unwrap(), &Value::Str("kept".into())).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    w.advance(10);
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("final".into())).unwrap().purge_by(t, &value_ak(), by).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    (w, (t, c, marker))
}

// spec/commits.md §5 (Dropping a body; Purge on replace),
// spec/requirements.md (Deletion: one edit of one aspect, forward secure),
// spec/sync-judgement.md §2 (Per blob): a part of a two-part commit purged, and one replaced under
// purge on replace beside a part that stays (dropped as covered by the writer's snapshot, it
// strips like a purged part), leave no copy an attacker holding either device recovers, sync
// stores included; the parts beside them still read, and the same attack recovers the kept one
// (it finds live content). One world for both: an attack per device.
#[test]
fn a_purged_or_replaced_part_is_unrecoverable_from_the_sync_store_spec_commits_5() {
    let (mut w, t, _, replaced) = replaced_beside_a_kept_part();
    let (gone, stays) = (Ak::new("u:p.0").unwrap(), Ak::new("u:k.0").unwrap());
    let purged = format!("PURGED-MARK-5e1f{}", "x".repeat(300));
    let kept = format!("KEPT-MARK-3b7c90{}", "x".repeat(300));
    let c = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &gone, &Value::Str(purged.clone())).unwrap();
        m.set(t, &stays, &Value::Str(kept.clone())).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    w.advance(10);
    purge_of(&mut w, 0, t, c, &[gone]);
    w.run();
    for i in 0..2 {
        let attack = w.forensic(i);
        let found = |marker: &str| attack.iter().any(|r| r.plain.windows(16).any(|x| x == &marker.as_bytes()[..16]));
        assert!(found(&kept), "node {i}: the attack finds the live part");
        for (what, marker) in [("purged", &purged), ("replaced", &replaced)] {
            assert!(!found(marker), "node {i}: the {what} part recovered");
        }
        assert_eq!(w.engine(i).get(&t, &stays).unwrap(), Some(Value::Str(kept.clone())), "node {i} reads the other part");
    }
}

// spec/commits.md §5 (Dropping a body; Purge request): a part already dropped as covered on an
// aspect that does not purge on replace, its blob kept as the commit's (it holds a part that
// stays), is named by a purge request: every local copy goes, the blob's included, at both
// nodes; the part beside it still reads. Fails if a blob keeps a purged part it carried while
// its part was dropped as covered.
#[test]
fn a_purge_strips_a_part_dropped_as_covered_from_its_blobs_spec_commits_5() {
    let mut w = World::new(0);
    w.record = true;
    w.add_node();
    w.pair(0);
    w.run();
    let a = w.node(0).account.unwrap();
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a);
        e.commit(m).unwrap();
        t
    });
    w.run();
    let stays = Ak::new("u:k.0").unwrap();
    let purged = format!("COVERED-PURGED-9a{}", "x".repeat(300));
    let kept = format!("KEPT-BESIDE-4d1e{}", "x".repeat(300));
    let c = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str(purged.clone())).unwrap();
        m.set(t, &stays, &Value::Str(kept.clone())).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    w.advance(10);
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("final".into())).unwrap();
        e.commit(m).unwrap();
        e.snapshot(&t, &value_ak()).unwrap();
    });
    w.run();
    for i in 0..2 {
        let d = w.describe_commit(&c);
        assert!(w.engine(i).holds_commit(&c), "node {i} keeps the commit: {d}");
    }
    w.advance(10);
    purge(&mut w, 0, t, c);
    w.run();
    for i in 0..2 {
        let attack = w.forensic(i);
        let found = |marker: &str| attack.iter().any(|r| r.plain.windows(16).any(|x| x == &marker.as_bytes()[..16]));
        assert!(found(&kept), "node {i}: the attack finds the live part");
        assert!(!found(&purged), "node {i}: the purged part recovered: {}", w.describe_commit(&c));
        assert_eq!(w.engine(i).get(&t, &stays).unwrap(), Some(Value::Str(kept.clone())), "node {i} reads the other part");
    }
}

// spec/commits.md §5 (Covered: a part not held that a held valid snapshot covers by its tables
// drops as covered), spec/sync-judgement.md §2 (Per blob): a new node reading the account
// after the strip receives the commit without its replaced part and the snapshot covering it;
// it counts that part covered, not missing, so it reaches quiet with nothing to fetch (the
// harness checks every must-hold body reached at quiet) and reads both values. Fails if a part a
// strip left out counts missing for good. (That no store it reads holds the part is
// `a_purged_or_replaced_part_is_unrecoverable_from_the_sync_store_spec_commits_5`.)
#[test]
fn a_new_reader_of_a_cover_stripped_commit_misses_nothing_spec_commits_5() {
    let (mut w, t, c, _) = replaced_beside_a_kept_part();
    // t is a dependent of the account: its sync unit's sync ID is the account's
    let a = w.node(0).account.unwrap();
    let s = w.engine(0).sync_id_of(&a).unwrap().unwrap();
    let n = w.pair(0);
    w.run();
    assert!(w.engine(n).holds_commit(&c), "the new node holds the commit");
    assert!(!w.engine(n).read_facts(&s, &osis_engine::sync::BodyId::unit(c)).unwrap().missing, "no part of it counts missing");
    assert_eq!(w.engine(n).get(&t, &value_ak()).unwrap(), Some(Value::Str("final".into())));
    assert_eq!(w.engine(n).get(&t, &Ak::new("u:n.0").unwrap()).unwrap(), Some(Value::Str("kept".into())));
}

/// Node `i` sets thing `t`'s value to `v`.
fn set_value(w: &mut World, i: usize, t: Tid, v: &str) {
    w.write(i, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str(v.into())).unwrap();
        e.commit(m).unwrap()
    });
}

// spec/sync-judgement.md §2 (Per blob: a delta dropped as covered strips only where its aspect
// may be under purge on replace), spec/commits.md §5 (Covered): node 1 makes a thing with a value
// (the making commit also holds its record and the strong from its account), replaces the
// value, and with its sibling node 2 replaces it again at once, after node 2 grants node 0's
// account read (told by a grant signal); node 0 holds the thing. The making commit's value part is dropped as covered, its cover
// covered in turn by a snapshot whose tables no longer name the part's session (no write of it
// is left). A blob stripped of it would leave node 0 counting it never received with no source
// for it; unstripped, node 0 receives the making commit whole (the harness checks every must-hold
// body reached at quiet). It passes with that strip too: node 0 counts the part covered either way
// (the next test), so no test catches it (issues/strip-rule-gaps.md).
#[test]
fn a_reader_receives_a_part_whose_cover_was_covered_whole_spec_sync_judgement_2() {
    covers_cover(false);
}

// spec/crdt.md §8 (or that the writer holds with a delta on the aspect), spec/commits.md
// §5 (Covered), spec/sync-judgement.md §2 (Per blob): as above with the value under purge on
// replace, so the making commit's value part strips once dropped as covered. Its cover is covered
// in turn by a snapshot no write of the making commit is left in; that snapshot still lists the
// making commit, held by its writer, so node 0, receiving the commit stripped, counts the part
// covered, not missing, and reads the value. Fails if a snapshot lists only what occurs in it.
#[test]
fn a_reader_counts_a_stripped_part_covered_by_its_covers_cover_spec_crdt_8() {
    covers_cover(true);
}

/// The two tests above: the making commit's value under purge on replace or not.
fn covers_cover(purge_on_replace: bool) {
    let mut w = crate::harness::siblings();
    let a0 = w.node(0).account.unwrap();
    let d = w.node(1).account.unwrap();
    let (t, c) = w.write(1, |e| {
        let mut m = Mutation::new();
        let t = m.create(e.thing_record(d, None));
        if purge_on_replace {
            let x: ct::RetentionSetting = [(value_ak(), ct::RetentionEntry { history: Some(osis_schema::History::PurgeOnReplace), ..Default::default() })].into_iter().collect();
            m.set(t, &ct::RETENTION, &x).unwrap();
        }
        m.set(t, &value_ak(), &Value::Str("v0".into())).unwrap();
        m.op(d, &ct::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(Value::Strong(t)) }).unwrap();
        (t, e.commit(m).unwrap().unwrap())
    });
    set_value(&mut w, 1, t, "v1");
    w.run();
    w.write(2, |e| e.grant(&t, &a0, &edge(Role::Read)).and_then(|_| e.signal_grant(&t, &a0, &[]))).unwrap();
    set_value(&mut w, 2, t, "v2");
    set_value(&mut w, 1, t, "v3");
    let d = w.node(0).account.unwrap();
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.op(d, &ct::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(Value::Strong(t)) }).unwrap();
        e.commit(m).unwrap()
    });
    w.run();
    let s = w.engine(1).sync_id_of(&t).unwrap().unwrap();
    assert!(w.engine(0).holds_commit(&c), "the reader holds the making commit");
    assert!(!w.engine(0).read_facts(&s, &osis_engine::sync::BodyId::unit(c)).unwrap().missing, "no part of it counts missing");
    assert!(w.engine(0).get(&t, &value_ak()).unwrap().is_some(), "the reader reads the value");
}

/// A thing node 0 mints with its account as admin, held there.
fn make_held(w: &mut World) -> Tid {
    let d = w.node(0).account.unwrap();
    w.write(0, |e| {
        let mut m = Mutation::new();
        let t = m.create(e.thing_record(d, None));
        m.op(d, &ct::HOLDS, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Add(Value::Strong(t)) }).unwrap();
        e.commit(m).unwrap();
        t
    })
}

// notes/slim-design.md B (one stored form per commit): every commit blob a node holds with a seal
// is made again byte for byte from its seal and the commit as held: its own fresh encryptions,
// blobs others sealed, a section it cannot open (kept as it came), and a strip's rewrite. Node
// 0's commit writes A, B and C; node 1 reads A and C, node 2 C alone; node 1 purges A's part and
// rewrites the blob. Each node makes again every held blob it keeps a seal of, and some at each.
// Fails if a seal leaves out what its blob carries (a wrap, a key, a section, the prefix).
#[test]
fn every_held_blob_is_made_again_from_its_seal() {
    let mut w = world_of(0, 3, 3);
    w.cap = crate::harness::WIDE_CAP;
    let [a, b, c] = [0; 3].map(|_| make_held(&mut w));
    for (i, ts) in [(1, vec![a, c]), (2, vec![c])] {
        let to = w.node(i).account.unwrap();
        for t in ts {
            w.write(0, |e| e.grant(&t, &to, &edge(Role::Write)).and_then(|_| e.signal_grant(&t, &to, &[]))).unwrap();
            let d = w.node(i).account.unwrap();
            w.write(i, |e| {
                let mut m = Mutation::new();
                m.op(d, &ct::HOLDS, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Add(Value::Strong(t)) }).unwrap();
                e.commit(m).unwrap();
            });
        }
    }
    w.run();
    let x = w.write(0, |e| {
        let mut m = Mutation::new();
        for t in [a, b, c] {
            m.set(t, &value_ak(), &Value::Str("v".into())).unwrap().purge_by(t, &value_ak(), PurgeBy::Writer).unwrap();
        }
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    w.advance(10);
    purge(&mut w, 1, a, x);
    w.run();
    for i in 0..3 {
        let (made, failed) = w.engine(i).check_seals();
        assert!(failed.is_empty(), "node {i}: {failed:?}");
        assert!(made > 0, "node {i} made no blob again");
    }
}

// notes/slim-design.md B (one stored form per commit): a node keeps no bytes of a blob it makes
// again from its seal, and serves it byte for byte; once it cannot make it (access lost, the
// commit forgotten) the entries it keeps have their bytes again. Node 2 writes thing 0, node 1
// keeps it unread: each commit blob node 2 holds with a seal has no bytes in its store and is made
// to the bytes node 1 serves. Node 0 then lowers node 2 to keeping S unread: node 2 forgets the
// commits and keeps their entries, each with its bytes. Fails if a sealed blob's bytes stay beside
// its seal, if a made blob differs from the one served, or if a lost commit's entries are left
// without bytes.
#[test]
fn a_reader_keeps_no_bytes_of_what_it_makes_again() {
    let (mut w, t, s) = three_of(Gives::Writes, 1);
    for (i, v) in [(0, "v"), (2, "w")] {
        w.write(i, |e| {
            let mut m = Mutation::new();
            m.set(t, &Ak::new(format!("u:n{i}.0")).unwrap(), &Value::Str(v.into())).unwrap();
            e.commit(m).unwrap();
        });
        w.run();
    }
    let mut made = 0;
    for e in w.store(2).entries(&s).unwrap() {
        if w.engine(2).blob_of(&e.blob).is_none_or(|r| r.seal.is_none()) {
            continue;
        }
        made += 1;
        assert!(w.store(2).kept_bytes(&e.blob).unwrap().is_none(), "no bytes beside a seal");
        let bytes = w.bytes(2, &e.blob).expect("made again");
        assert_eq!(osis_blob::blob_id(&bytes), e.blob);
        if w.store(1).entry(&s, &e.blob).unwrap().is_some() {
            assert_eq!(w.bytes(1, &e.blob), Some(bytes), "served byte for byte");
        }
    }
    assert!(made > 0, "node 2 makes some blob again");
    let _ = play(&mut w, &[Lower(0, 0, crate::harness::history::Holder::Node(2), Gives::Syncs), Run], String::new());
    let mut lost = 0;
    for e in w.store(2).entries(&s).unwrap() {
        let bytes = w.bytes(2, &e.blob).expect("every entry kept has its bytes");
        assert_eq!(osis_blob::blob_id(&bytes), e.blob);
        let c = w.engine(2).blob_commit(&e.blob);
        if c.is_some_and(|c| !w.engine(2).holds_commit(&c)) {
            lost += 1;
            assert_eq!(w.store(2).kept_bytes(&e.blob).unwrap(), Some(bytes), "a lost commit's blob kept as bytes");
        }
    }
    assert!(lost > 0, "node 2 keeps entries of commits it lost");
}

// spec/sync-judgement.md §1 (One blob per commit: a section a node cannot open goes into its
// fresh encryption only where every held blob of the commit carries it), §2 (Per blob):
// `Engine::held_sections`. Node 0's commit writes A, B and C, each independent;
// node 1 writes A and C, node 2 B and C, node 3 C alone, each cut off from the others. Node 1
// purges A's part and node 2 B's: each rewrites the blob without its own, the other's section
// copied as it came. Node 3, opening neither, opens both rewrites, then holds the bytes of the
// first blob and node 2's rewrite alone: its fresh encryption leaves out both purged sections,
// as a blob it opened lacks each, its bytes held or not. Fails if only the held blobs' lists
// count (two strips of different parts never meet at a node opening neither).
#[test]
fn strips_of_two_parts_by_nodes_apart_meet_at_a_node_reading_neither_spec_sync_judgement_1() {
    let mut w = world_of(0, 4, 4);
    w.cap = crate::harness::WIDE_CAP;
    let [a, b, c] = [0; 3].map(|_| make_held(&mut w));
    for (i, ts) in [(1, vec![a, c]), (2, vec![b, c]), (3, vec![c])] {
        let to = w.node(i).account.unwrap();
        for t in ts {
            w.write(0, |e| e.grant(&t, &to, &edge(Role::Write)).and_then(|_| e.signal_grant(&t, &to, &[]))).unwrap();
            let d = w.node(i).account.unwrap();
            w.write(i, |e| {
                let mut m = Mutation::new();
                m.op(d, &ct::HOLDS, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Add(Value::Strong(t)) }).unwrap();
                e.commit(m).unwrap();
            });
        }
    }
    w.run();
    let by = PurgeBy::Writer;
    let x = w.write(0, |e| {
        let mut m = Mutation::new();
        for t in [a, b, c] {
            m.set(t, &value_ak(), &Value::Str("v".into())).unwrap().purge_by(t, &value_ak(), by).unwrap();
        }
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    let s = w.engine(3).sync_id_of(&c).unwrap().unwrap();
    for i in 0..4 {
        for j in i + 1..4 {
            w.partition(i, j);
        }
    }
    // node i's entry of the commit, its own where `own`
    let entry = |w: &mut World, i: usize, own: bool| {
        let e = w.store(i).entries(&s).unwrap().into_iter().find(|e| (e.own || !own) && w.engine(i).blob_commit(&e.blob) == Some(x)).expect("a blob of the commit");
        let bytes = w.bytes(i, &e.blob).unwrap();
        (e.blob, osis_engine::sync::HeldBlob { sync_id: s, wrap: e.wrap, bytes })
    };
    let (_, first) = entry(&mut w, 3, false);
    w.advance(10);
    purge(&mut w, 1, a, x);
    purge(&mut w, 2, b, x);
    w.run();
    let (ra, by_1) = entry(&mut w, 1, true);
    let (rb, by_2) = entry(&mut w, 2, true);
    let h = w.engine(0).header(&x).unwrap();
    let ai = |t: Tid| h.aspects.iter().position(|e| e.tid == t && e.ak == value_ak()).unwrap();
    for (id, r) in [(ra, &by_1), (rb, &by_2)] {
        w.engine(3).open_entry(&s, &id, &r.wrap, &r.bytes, &[], u64::MAX).unwrap();
        assert!(w.engine(3).blob_of(&id).is_some(), "node 3 opened a rewrite");
    }
    let rng = &mut osis_crypto::SeededRng::from_u64(1);
    let (sealed, _) = w.engine(3).seal_body(&s, &osis_engine::sync::BodyId::unit(x), &[first, by_2], rng).unwrap().expect("node 3 encrypts the commit");
    assert!(!sealed.ais.contains(&ai(a)) && !sealed.ais.contains(&ai(b)), "node 3's fresh encryption keeps a purged section: {:?}", sealed.ais);
    assert!(sealed.ais.contains(&ai(c)), "it carries C's part");
}

// spec/sync-judgement.md §2 (Loggable; Per blob: the rewrite is the rest of the body, a fresh
// encryption where no held blob is it): node 1 makes a thing (its record, a value under purge on
// replace, the strong from its account in the same commit) and replaces the value while cut
// off from its sibling, node 2. Node 1 strips the value from the making commit and drops the
// account's `holds.0` part as covered, which strips nothing. The rest is still must-hold and
// loggable at node 1: its fresh encryption takes the covered part from the held blob it opened.
// Rejoined, node 2 receives the making commit, so the thing's record. Fails if a part dropped
// here that strips nothing makes the rest unloggable.
#[test]
fn a_making_commit_stripped_before_a_siblings_fetch_reaches_the_sibling_spec_sync_judgement_2() {
    let mut w = crate::harness::siblings();
    w.partition(1, 2);
    let d = w.node(1).account.unwrap();
    let (t, c) = w.write(1, |e| {
        let mut m = Mutation::new();
        let t = m.create(e.thing_record(d, None));
        let x: ct::RetentionSetting = [(value_ak(), ct::RetentionEntry { history: Some(osis_schema::History::PurgeOnReplace), ..Default::default() })].into_iter().collect();
        m.set(t, &ct::RETENTION, &x).unwrap();
        m.set(t, &value_ak(), &Value::Str("v0".into())).unwrap();
        m.op(d, &ct::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(Value::Strong(t)) }).unwrap();
        (t, e.commit(m).unwrap().unwrap())
    });
    set_value(&mut w, 1, t, "v1");
    w.run();
    // t is a dependent of the account: its sync unit's sync ID is the account's
    let s = w.engine(1).sync_id_of(&d).unwrap().unwrap();
    assert!(!w.engine(2).holds_commit(&c), "node 2 is cut off");
    w.heal();
    w.run();
    assert!(w.engine(2).holds_commit(&c), "node 2 holds the making commit");
    assert!(!w.engine(2).read_facts(&s, &osis_engine::sync::BodyId::unit(c)).unwrap().missing, "no part of it counts missing");
    assert_eq!(w.engine(2).get(&t, &value_ak()).unwrap(), Some(Value::Str("v1".into())));
}

// notes/slim-design.md B (one stored form per commit), spec/sync-ids.md §5 (Across sync IDs): node 2 loses power at each durable write in turn, while it writes a commit (its blob's
// bytes go once its seal is durable) and while node 0 lowers it to keeping S unread (its commits
// lost, their blobs' bytes kept again), and restarts in place. Every entry it keeps then has its
// blob's bytes, kept or made again, and every seal makes its blob. Fails if a crash between the
// engine's store and the sync store leaves an entry with neither bytes nor a seal. By hand: about
// 400 restarts.
#[test]
#[ignore = "by hand: a restart per durable write"]
fn a_crash_at_any_write_leaves_each_blob_kept_or_made_again() {
    use crate::harness::DiskFault;
    let (w, t, s) = three_of(Gives::Writes, 1);
    let write = |w: &mut World, v: &str| {
        w.write(2, |e| {
            let mut m = Mutation::new();
            m.set(t, &Ak::new("u:n2.0").unwrap(), &Value::Str(v.into())).unwrap();
            let _ = e.commit(m);
        });
        w.run();
    };
    let lower = |w: &mut World| drop(play(w, &[Lower(0, 0, crate::harness::history::Holder::Node(2), Gives::Syncs), Run], String::new()));
    let mut crashed = [0; 2];
    for (phase, n) in crashed.iter_mut().enumerate() {
        let mut base = w.copy();
        if phase == 1 {
            write(&mut base, "w");
        }
        for k in 0.. {
            let mut w = base.copy();
            w.disk_fault(2, k, DiskFault::Crash);
            match phase {
                0 => write(&mut w, "w"),
                _ => lower(&mut w),
            }
            if w.crashes == 0 {
                break;
            }
            *n += 1;
            w.run();
            for e in w.store(2).entries(&s).unwrap() {
                if w.store(2).blob_len(&e.blob).unwrap().is_none() {
                    continue;
                }
                let bytes = w.bytes(2, &e.blob);
                assert!(bytes.as_ref().is_some_and(|v| osis_blob::blob_id(v) == e.blob), "phase {phase}, crash at write {k}: an entry held without its bytes");
            }
            let (_, failed) = w.engine(2).check_seals();
            assert!(failed.is_empty(), "phase {phase}, crash at write {k}: {failed:?}");
        }
    }
    assert!(crashed.iter().all(|n| *n > 0), "a crash in each phase: {crashed:?}");
}

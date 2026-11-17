//! Deletes by level at a node keeping S unread (spec/sync-ids.md §6 Delete, spec/crypto.md §7):
//! a writer that is no admin of S deletes there what it may purge, by the delete keys of the
//! levels it holds, never what it holds no level key for. Node 0 (admin) makes thing 0; node 1's
//! account keeps it unread; nodes 2 and 3 write it.

use crate::harness::Step::*;
use crate::harness::history::{Gives, value_ak, world};
use crate::harness::{World, fixture_with, play};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Ak, BlobId, CommitId, PurgeBy, Role, SyncId, Tid, Value};
use osis_schema::core_types::Edge;
use osis_engine::Mutation;
use osis_schema::core_types as ct;

/// The common start, built once per process (`fixture_with`).
fn setup() -> (World, Tid, SyncId) {
    let (w, (t, s)) = fixture_with("deletes setup", || {
        let mut w = world(0, 4);
        w.cap = 20_000;
        let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, Gives::Writes), Grant(0, 0, 3, Gives::Writes), Run], String::new());
        let t = w.history.things[0].0;
        let s = w.engine(0).home_sync_id(&t).unwrap().unwrap();
        (w, (t, s))
    });
    (w, t, s)
}

/// Node `i` writes `ak` of thing `t`, purgeable by `by`.
fn write(w: &mut World, i: usize, t: Tid, ak: &Ak, by: PurgeBy) -> CommitId {
    w.write(i, |e| {
        let mut m = Mutation::new();
        m.set(t, ak, &Value::Str(format!("by {i}"))).unwrap().retention(t, ak, osis_schema::Retention { by }).unwrap();
        e.commit(m).unwrap().unwrap()
    })
}

fn purge(w: &mut World, i: usize, t: Tid, c: CommitId) {
    w.write(i, |e| {
        let mut m = Mutation::new();
        let now = e.now();
        m.set(t, &ct::PURGE, &now).unwrap();
        m.purge_commit(c, t, value_ak());
        e.commit(m).unwrap().unwrap();
    });
}

/// Node 1's entries of `c` under S (blobs `by` opened to `c`).
fn at_unread(w: &mut World, by: usize, s: &SyncId, c: &CommitId) -> Vec<BlobId> {
    let es = w.store(1).entries(s).unwrap();
    es.into_iter().filter(|e| w.engine(by).blob_commit(&e.blob) == Some(*c)).map(|e| e.blob).collect()
}

// spec/sync-ids.md §6 (Delete), spec/crypto.md §7: a writer's purge of its own write
// reaches a node keeping S unread with no admin connected: the entry is deleted there by the
// writer's level keys (level 2 with the sync key, or level 3 with the write key), and stays
// deleted across restarts.
#[test]
fn a_writers_purge_of_its_own_write_deletes_it_at_a_node_keeping_s_unread_spec_sync_ids_6() {
    for by in [PurgeBy::AuthorOrAdmin, PurgeBy::Writer] {
        let (mut w, t, s) = setup();
        let c = write(&mut w, 2, t, &value_ak(), by);
        w.run();
        let held = at_unread(&mut w, 2, &s, &c);
        assert!(!held.is_empty(), "{by:?}: node 1 holds the write");
        w.power_off(0);
        purge(&mut w, 2, t, c);
        w.run();
        let gone = |w: &mut World| held.iter().all(|b| w.store(1).entry(&s, b).unwrap().is_none());
        assert!(gone(&mut w), "{by:?}: the writer's purge deleted it at node 1");
        for i in 1..3 {
            w.power_off(i);
            w.power_on(i);
        }
        w.power_on(0);
        w.run();
        assert!(gone(&mut w), "{by:?}: still gone after restarts");
        assert_eq!(w.engine(3).get(&t, &value_ak()).unwrap(), None, "{by:?}: the other writer reads the purge");
    }
}

// spec/sync-ids.md §6 (Delete), spec/crypto.md §7: one commit's two deltas under different
// retention frame two commitment groups (levels 1, 2 and levels 1, 2, 3); the groups the writer
// signs for are those the blob's prefix bears, and its purge of both deletes the blob at the node
// keeping S unread with its level-2 key, which alone covers both.
#[test]
fn a_writers_delete_covers_every_commitment_group_spec_sync_ids_6() {
    let (mut w, t, s) = setup();
    let other = Ak::new("u:n.0").unwrap();
    let c = w.write(2, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("a".into())).unwrap().retention(t, &value_ak(), osis_schema::Retention { by: PurgeBy::AuthorOrAdmin }).unwrap();
        m.set(t, &other, &Value::Str("b".into())).unwrap().retention(t, &other, osis_schema::Retention { by: PurgeBy::Writer }).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    let held = at_unread(&mut w, 2, &s, &c);
    assert!(!held.is_empty(), "node 1 holds the write");
    // the groups the writer signs for are those the blob's prefix bears
    for b in &held {
        let bytes = w.store(1).bytes(b).unwrap().unwrap();
        let real = osis_blob::clear_prefix(&bytes).unwrap().unwrap();
        let basis = w.engine(2).blob_delete_basis(b).unwrap();
        let set = |p: &osis_blob::Prefix| p.groups().iter().cloned().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(real.groups().len(), 2, "two groups");
        assert_eq!(set(&basis.prefix), set(&real), "the writer's groups are the prefix's");
    }
    w.power_off(0);
    w.write(2, |e| {
        let mut m = Mutation::new();
        let now = e.now();
        m.set(t, &ct::PURGE, &now).unwrap();
        m.purge_commit(c, t, value_ak()).purge_commit(c, t, other.clone());
        e.commit(m).unwrap().unwrap();
    });
    w.run();
    assert!(held.iter().all(|b| w.store(1).entry(&s, b).unwrap().is_none()), "the writer deleted it at node 1");
}

// spec/sync-judgement.md §3 (Deletes: a holder of the needed delete key or level keys),
// spec/sync-ids.md §6: writer 2 replaces two of writer 3's values, one purgeable by any writer, one
// by its author or an admin only; with the admin and the author away, writer 2 deletes the
// replaced one any writer may purge at the node keeping S unread (level 3), and the other stays
// (it holds no level key there).
#[test]
fn a_writer_deletes_only_what_it_may_purge_spec_sync_judgement_3() {
    let (mut w, t, s) = setup();
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

/// Node 2 writes thing `t`'s value (purgeable by its author or an admin); node 1 goes away and
/// `purger` (0 the admin, or 2 the author) purges it with the other one away, so the purger's
/// Delete is the only one; `restart` restarts the purger while node 1 is still away. Node 1 comes
/// back: whether every entry of the commit left it.
fn purged_while_away(purger: usize, restart: bool) -> bool {
    let (mut w, t, s) = setup();
    let c = write(&mut w, 2, t, &value_ak(), PurgeBy::AuthorOrAdmin);
    w.run();
    let held = at_unread(&mut w, 2, &s, &c);
    assert!(!held.is_empty(), "{purger}: node 1 holds the write");
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
    held.iter().all(|b| w.store(1).entry(&s, b).unwrap().is_none())
}

// spec/sync-judgement.md §3 (Deletes; What a source holds): a delete owed at a source keeping S
// unread is owed while its stream shows the entry, up or away: a purge (by the admin's delete key
// or the writer's level key) made while node 1 is away deletes the entry there once it is back.
#[test]
fn a_purge_made_while_the_unread_store_is_away_deletes_there_on_return_spec_sync_judgement_3() {
    for purger in [0, 2] {
        assert!(purged_while_away(purger, false), "{purger}: the purge deleted it at node 1 on return");
    }
}

// spec/sync-judgement.md §3 (Deletes; Dropped bodies): the owed delete survives a restart of the
// purger while node 1 is away; the writer signs it from the prefix salt and aspects it kept of
// the dropped blob (`BlobOf`), its bytes gone.
#[test]
fn an_owed_delete_survives_the_purgers_restart_spec_sync_judgement_3() {
    for purger in [0, 2] {
        assert!(purged_while_away(purger, true), "{purger}: the purge deleted it at node 1 after the purger's restart");
    }
}

// spec/sync-judgement.md §3 (What a source holds), scaling: a store source coming back judges
// again only what is owed there, never each entry its stream shows: its leaving and return
// judge as many bodies toward it with 2 entries shown as with 6.
#[test]
fn a_source_coming_back_judges_only_what_is_owed_there() {
    let toward = |n: usize| {
        let (mut w, t, _) = setup();
        for i in 0..n {
            write(&mut w, 2, t, &Ak::new(format!("u:n.{i}")).unwrap(), PurgeBy::Writer);
        }
        w.run();
        osis_base::costs::take();
        for j in [0, 2, 3] {
            w.partition(1, j);
        }
        w.run();
        for j in [0, 2, 3] {
            w.rejoin(1, j);
        }
        w.run();
        osis_base::costs::take().into_iter().filter(|(k, ..)| *k == "read: toward").map(|(.., n)| n).sum::<u64>()
    };
    let (few, many) = (toward(2), toward(6));
    assert_eq!(few, many, "toward judged {few} with 2 entries shown, {many} with 6");
}

// spec/sync-set.md §2 (the sync set is the node closure's walk over what is held): node 1 keeps
// S unread by the ticket the grant fired on its inbox; a restart, which takes the account up
// after the open's walk (the ticket opens to the account), enters it again, so S stays in its
// sync set.
#[test]
fn a_sync_id_kept_unread_by_ticket_stays_synced_across_a_restart_spec_sync_set_2() {
    let (mut w, t, s) = setup();
    let unread = Some((std::collections::BTreeSet::from([t]), osis_engine::sync::Holding::Unread));
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), unread, "kept unread before");
    w.power_off(1);
    w.power_on(1);
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), unread, "kept unread after the restart");
}

// spec/sync-set.md §1 (The account's tickets): node 1 keeps S unread by the ticket its grant fired
// on its inbox; past the inbox's lifetime that fire is gone, and D's ticket, written as the walk
// entered the thing, keeps it kept unread.
#[test]
fn a_sync_id_kept_unread_outlives_its_inbox_ticket_spec_sync_set_1() {
    let (mut w, t, s) = setup();
    w.advance(osis_base::format::INBOX_LIFETIME_MS + 86_400_000);
    w.run();
    let unread = Some((std::collections::BTreeSet::from([t]), osis_engine::sync::Holding::Unread));
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), unread, "kept unread past the inbox's lifetime");
}


/// Node 2 writes `value_ak` (marked) and `u:n.0` in one commit, both purgeable by any writer.
fn two_parts(w: &mut World, t: Tid, marker: &str) -> CommitId {
    let other = Ak::new("u:n.0").unwrap();
    w.write(2, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str(marker.into())).unwrap().retention(t, &value_ak(), osis_schema::Retention { by: PurgeBy::Writer }).unwrap();
        m.set(t, &other, &Value::Str("kept".into())).unwrap().retention(t, &other, osis_schema::Retention { by: PurgeBy::Writer }).unwrap();
        e.commit(m).unwrap().unwrap()
    })
}

// spec/sync-judgement.md §2 (per blob), spec/commits.md §5 (Purge: one delta of a commit): a
// purge of one part of a two-part commit leaves the commit's old blob in no store: every reader
// logs the rewrite without it (one entry each, the same one), and the writer's delete takes the
// old blob from the node keeping S unread once the rewrite is there; the other part still reads.
#[test]
fn a_purge_of_one_part_rewrites_the_blob_everywhere_spec_sync_judgement_2() {
    let (mut w, t, s) = setup();
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
    for i in [0, 2, 3] {
        let es: Vec<BlobId> = w.store(i).entries(&s).unwrap().into_iter().map(|e| e.blob).filter(|b| w.engine(2).blob_commit(b) == Some(c)).collect();
        assert_eq!(es.len(), 1, "node {i} logs one blob of the commit");
        assert_eq!(w.engine(i).blob_parts(&es[0]).map(|p| p.len()), Some(1), "node {i}: the rewrite holds the other part alone");
        logged.extend(es);
        assert_eq!(w.engine(i).get(&t, &Ak::new("u:n.0").unwrap()).unwrap(), Some(Value::Str("kept".into())), "node {i} reads the other part");
        assert_eq!(w.engine(i).get(&t, &value_ak()).unwrap(), None, "node {i} reads the purge");
    }
    assert_eq!(logged.len(), 1, "the readers settle on one rewrite");
}

// spec/commits.md §5 (Dropping a body destroys every local copy), spec/requirements.md
// (Deletion: one edit of one aspect, forward secure): after a purge of one part of a two-part
// commit, an attacker holding either node's device recovers nothing of it, sync stores included.
#[test]
fn a_purged_part_of_a_commit_is_unrecoverable_from_the_sync_store_spec_commits_5() {
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
    let marker = format!("PURGED-MARK-5e1f{}", "x".repeat(300));
    let c = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str(marker.clone())).unwrap();
        m.set(t, &Ak::new("u:n.0").unwrap(), &Value::Str("kept".into())).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    let found = |w: &mut World, i: usize| w.forensic(i).iter().any(|r| r.plain.windows(16).any(|x| x == &marker.as_bytes()[..16]));
    assert!(found(&mut w, 1), "the attack finds live content");
    w.advance(10);
    purge(&mut w, 0, t, c);
    w.run();
    for i in 0..2 {
        assert!(!found(&mut w, i), "node {i}: the purged part recovered");
        assert_eq!(w.engine(i).get(&t, &Ak::new("u:n.0").unwrap()).unwrap(), Some(Value::Str("kept".into())), "node {i} reads the other part");
    }
}

/// Node 0 makes thing t with `value` under purge on replace and writes one commit holding a
/// marked `value` and a note that stays, then replaces `value`: its cover drops the marked part
/// and strips it from the commit's blobs. Node 1 is a second device of its account. The world,
/// t, the two-part commit and the marker.
fn replaced_beside_a_kept_part() -> (World, Tid, CommitId, String) {
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
    let by = osis_schema::Retention { by: PurgeBy::Writer };
    let c = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str(marker.clone())).unwrap().retention(t, &value_ak(), by).unwrap();
        m.set(t, &Ak::new("u:n.0").unwrap(), &Value::Str("kept".into())).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    w.advance(10);
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("final".into())).unwrap().retention(t, &value_ak(), by).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    (w, t, c, marker)
}

// spec/commits.md §5 (Purge on replace) and spec/requirements.md (Deletion: one edit of one
// aspect): a part replaced under purge on replace beside a part that stays leaves no copy in the
// sync store: dropped as covered by the writer's snapshot, it strips like a purged part
// (spec/sync-judgement.md §2 Per blob).
#[test]
fn a_part_purged_on_replace_is_unrecoverable_from_the_sync_store_spec_commits_5() {
    let (mut w, _, _, marker) = replaced_beside_a_kept_part();
    for i in 0..2 {
        assert!(!w.forensic(i).iter().any(|r| r.plain.windows(16).any(|x| x == &marker.as_bytes()[..16])), "node {i}: the replaced part recovered");
    }
}

// spec/commits.md §5 (Covered: a part not held that a held valid snapshot covers by its tables
// drops as covered), spec/sync-judgement.md §2 (Per blob): a new device reading the account
// after the strip receives the commit without its replaced part and the snapshot covering it;
// it counts that part covered, not missing, so it reaches quiet with nothing to fetch (the
// harness checks every must-hold body reached at quiet) and reads both values. Fails if a part a
// strip left out counts missing for good.
#[test]
fn a_new_reader_of_a_cover_stripped_commit_misses_nothing_spec_commits_5() {
    let (mut w, t, c, marker) = replaced_beside_a_kept_part();
    let s = w.engine(0).home_sync_id(&t).unwrap().unwrap();
    let n = w.pair(0);
    w.run();
    assert!(!w.forensic(n).iter().any(|r| r.plain.windows(16).any(|x| x == &marker.as_bytes()[..16])), "the new device never saw the replaced part");
    assert!(w.engine(n).holds_commit(&c), "the new device holds the commit");
    assert!(!w.engine(n).read_facts(&s, &c).unwrap().missing, "no part of it counts missing");
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
// (the making commit also holds its record and the strong from its account root), replaces the
// value, and with its sibling node 2 replaces it again at once, after node 2 grants node 0's
// account read; node 0 accepts. The making commit's value part is dropped as covered, its cover
// covered in turn by a snapshot whose tables no longer name the part's session (no write of it
// is left). A blob stripped of it would leave node 0 counting it never received with no source
// for it; unstripped, node 0 receives the making commit whole (the harness checks every must-hold
// body reached at quiet). Fails if a part dropped as covered strips under no purge on replace.
#[test]
fn a_reader_receives_a_part_whose_cover_was_covered_whole_spec_sync_judgement_2() {
    let mut w = crate::harness::siblings();
    let a0 = w.node(0).account.unwrap();
    let (t, c) = w.write(1, |e| {
        let d = e.account_root().unwrap();
        let mut m = Mutation::new();
        let t = m.create(e.thing_record(d));
        m.set(t, &value_ak(), &Value::Str("v0".into())).unwrap();
        m.op(d, &ct::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(Value::Strong(t)) }).unwrap();
        (t, e.commit(m).unwrap().unwrap())
    });
    set_value(&mut w, 1, t, "v1");
    w.run();
    w.write(2, |e| e.grant(&t, &a0, &Edge { role: Role::Read, until: None, invite: None, floor: None })).unwrap();
    set_value(&mut w, 2, t, "v2");
    set_value(&mut w, 1, t, "v3");
    w.write(0, |e| {
        let d = e.account_root().unwrap();
        let mut m = Mutation::new();
        m.op(d, &ct::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(Value::Strong(t)) }).unwrap();
        e.commit(m).unwrap()
    });
    w.run();
    let s = w.engine(1).home_sync_id(&t).unwrap().unwrap();
    assert!(w.engine(0).holds_commit(&c), "the reader holds the making commit");
    assert!(!w.engine(0).read_facts(&s, &c).unwrap().missing, "no part of it counts missing");
}

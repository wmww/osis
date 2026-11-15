//! Deletes by level at a node keeping S unread (spec/sync-ids.md §6 Delete, spec/crypto.md §7):
//! a writer that is no admin of S deletes there what it may purge, by the delete keys of the
//! levels it holds, never what it holds no level key for. Node 0 (admin) makes thing 0; node 1's
//! account keeps it unread; nodes 2 and 3 write it.

use crate::harness::Step::*;
use crate::harness::history::{Gives, value_ak, world};
use crate::harness::{World, fixture_with, play};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Ak, BlobId, CommitId, PurgeBy, SyncId, Tid, Value};
use osis_engine::Mutation;
use osis_schema::core_types as ct;

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
    es.into_iter().filter(|e| w.engine(by).blob_commit(&e.blob).ok().flatten() == Some(*c)).map(|e| e.blob).collect()
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

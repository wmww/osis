//! Destruction and mintings end to end (spec/commits.md §5 Destruction, A thing's mintings travel
//! with its record; spec/requirements.md Deletion: purging or expiring a thing's creation destroys
//! it at every node): node 0 makes thing t with a home sync ID S, node 1's account syncs it (kept
//! unread), node 2's writes it; node 0 destroys it. The engine's judgement of a destroyed thing is
//! the engine's and held-model's; these check what crosses nodes: the destruction reaches every
//! node, holds over a restart, a write after it counts nowhere, S empties once nothing needs it,
//! and the copies of a thing's mintings under a sync ID lacking it converge.

use crate::harness::Step::*;
use crate::harness::history::{Gives, value_ak, world};
use crate::harness::{World, play};
use osis_base::format::{ROLE_KEEP_MS, TOMBSTONE_LIFETIME_MS};
use osis_base::{CommitId, SyncId, Tid, Value};
use osis_commit::PurgeItem;
use osis_engine::Mutation;
use osis_schema::core_types as ct;

/// Node 0 makes thing 0 (a value, filed in its D) and gives it a sync ID of its own, granting
/// node 1's account sync and node 2's write; both accept (after the first run) and sync.
fn three() -> (World, Tid, SyncId) {
    let mut w = world(0, 3);
    w.cap = 20_000;
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, Gives::Writes), Run, Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).home_sync_id(&t).unwrap().unwrap();
    assert!(w.engine(2).knows(&t) && w.engine(2).get(&t, &value_ak()).unwrap().is_some(), "node 2 reads t");
    assert!(!w.store(1).entries(&s).unwrap().is_empty(), "node 1 keeps S");
    (w, t, s)
}

/// A purge of t's creation by node `by` (an item on `created.0` names every minting).
fn purge_thing(w: &mut World, by: usize, t: Tid) -> CommitId {
    w.write(by, |e| {
        let mut m = Mutation::new();
        let now = e.now();
        m.set(t, &ct::PURGE, &now).unwrap();
        m.purge(PurgeItem::Aspect { tid: t, ak: ct::CREATED.name() });
        e.commit(m).unwrap().unwrap()
    })
}

/// Nothing of t reads as existing at node `i`, and a write to it is refused as unknown.
#[track_caller]
fn gone(w: &mut World, i: usize, t: Tid) {
    let e = w.engine(i);
    assert!(!e.knows(&t), "node {i}: t known");
    assert!(!e.has_content(&t).unwrap(), "node {i}: content");
    assert!(e.roster(&t).is_empty(), "node {i}: roster");
    assert_eq!(e.get(&t, &value_ak()).unwrap(), None, "node {i}: its value");
    let mut m = Mutation::new();
    m.set(t, &value_ak(), &Value::Str("late".into())).unwrap();
    assert!(matches!(e.commit(m), Err(osis_engine::Error::UnknownThing(_))), "node {i}: a write refused as unknown");
}

// spec/commits.md §5 (Destruction: a thing whose every held minting is purged by a request
// holding the right is destroyed; in the same transaction the node drops every part on it), spec/sync-judgement.md §2:
// node 0's purge of t's creation reaches node 2, which reads t absent, also after a restart.
#[test]
fn a_purged_creation_destroys_the_thing_at_every_node_spec_commits_5() {
    let (mut w, t, _) = three();
    purge_thing(&mut w, 0, t);
    w.run();
    for i in [0, 2] {
        gone(&mut w, i, t);
    }
    w.power_off(2);
    w.power_on(2);
    w.run();
    gone(&mut w, 2, t);
}

// spec/commits.md §5 (Destruction: nobody writes a thing after its destruction: a part stamped
// after it is a part on an unknown thing): node 2, cut off, writes t after node 0 destroyed it;
// back, its write is applied nowhere and t stays destroyed everywhere.
#[test]
fn a_write_after_the_destruction_counts_nowhere_spec_commits_5() {
    let (mut w, t, _) = three();
    w.partition(0, 2);
    w.partition(1, 2);
    purge_thing(&mut w, 0, t);
    w.run();
    w.advance(10);
    let late = w.write(2, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("late".into())).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.heal();
    w.run();
    for i in [0, 2] {
        gone(&mut w, i, t);
    }
    assert!(!w.engine(0).commit_ids().contains(&late), "node 0 applied a write after the destruction");
}

// spec/commits.md §5 (Destruction: once no request is in force and nothing needs it, it keeps
// nothing, and every entry under its own sync IDs is must-not-hold), spec/sync-judgement.md §5
// (Emptying: but the destroying requests, which leave at their expiry): past a purge's window
// (`ROLE_KEEP`), S keeps only the request's entries at node 0's, node 2's and node 1's stores
// (node 1 keeps S unread; record blobs gone too, spec/sync-judgement.md §2). The purge has no
// expiry: S stays with it, so a node away for the window learns of the destruction.
#[test]
fn a_destroyed_things_sync_id_empties_but_its_request_past_its_window_spec_sync_judgement_5() {
    let (mut w, t, s) = three();
    let q = purge_thing(&mut w, 0, t);
    w.run();
    w.advance(ROLE_KEEP_MS + 60_000);
    w.run();
    let request = w.engine(0).commit_blobs(&q).unwrap();
    for i in 0..3 {
        let left: Vec<_> = w.store(i).entries(&s).unwrap().into_iter().filter(|e| !request.contains(&e.blob)).collect();
        assert!(left.is_empty(), "node {i} holds {} entries under S but the request's", left.len());
    }
    assert!(w.store(1).entries(&s).unwrap().iter().any(|e| request.contains(&e.blob)), "node 1 lost the request");
    assert!(w.engine(0).destruction(&t).is_some_and(|d| d.requests == vec![q]), "the purge is a destroying request");
}

// spec/commits.md §5 (Destruction: a release request destroys things as storage reclaim; a
// destroyed thing reads as absent to every read and write), spec/permissions.md §6: node 0's
// release of t reaches node 2, which reads it absent. spec/sync-judgement.md §5 (Emptying): the
// requests leave at their expiry; it forgets the sync IDs once its sources are heard out with
// nothing known there and none keeps S unread (it registers the closing step there, §6 Closes),
// only then the thing's secrets: past the request's expiry S empties at every store and, past
// the deletes' tombstones, node 0 forgets S and t's secrets, and node 1 (kept unread) forgets S
// and its account's record of it.
#[test]
fn a_released_thing_reads_absent_and_its_sync_id_is_forgotten_spec_sync_judgement_5() {
    let (mut w, t, s) = three();
    w.write(0, |e| e.release(&[t])).unwrap().expect("a release request");
    w.run();
    for i in [0, 2] {
        gone(&mut w, i, t);
    }
    w.advance(ROLE_KEEP_MS + 60_000);
    w.run();
    for i in 0..3 {
        let left = w.store(i).entries(&s).unwrap();
        assert!(left.is_empty(), "node {i} holds {} entries under S", left.len());
    }
    w.cap = 200_000;
    w.advance(TOMBSTONE_LIFETIME_MS);
    w.run();
    assert_eq!(w.engine(0).sync_holder(&s).unwrap(), None, "node 0 still syncs S");
    assert!(w.engine(0).epochs(&t).is_none(), "node 0 still holds t's secrets");
    // §6 Closes: node 1, keeping S unread, took the closing step: its account's record keeps S no
    // more, and S, its path and its store are gone
    assert!(w.store(1).path(&s).unwrap().is_none(), "node 1 keeps S's path");
    assert!(w.engine(1).sync_record(&t).is_none(), "node 1's account still records S");
}

// spec/sync-judgement.md §5 (Emptying), spec/sync-status.md §1 (heard out), as a lifecycle duty
// reads it (no peer sharing S: heard out at once): a node alone gives t secrets of its own,
// releases it and, past the request's expiry, forgets S and t's secrets.
#[test]
fn a_node_alone_forgets_a_released_things_sync_id_spec_sync_judgement_5() {
    let mut w = world(0, 1);
    let _ = play(&mut w, &[New(0), Run], String::new());
    let t = w.history.things[0].0;
    w.write(0, |e| e.give_own_secrets(&t)).unwrap();
    w.run();
    let s = w.engine(0).home_sync_id(&t).unwrap().expect("t's own sync ID");
    w.write(0, |e| e.release(&[t])).unwrap().expect("a release request");
    w.run();
    w.advance(ROLE_KEEP_MS + 60_000);
    w.run();
    w.advance(TOMBSTONE_LIFETIME_MS);
    w.run();
    assert_eq!(w.engine(0).sync_holder(&s).unwrap(), None, "node 0 still syncs S");
    assert!(w.engine(0).epochs(&t).is_none(), "node 0 still holds t's secrets");
}

/// At node `i` (an account's node): thing t (its account first admin), minted with `expires`
/// when given and filed nowhere, and u, t its first admin, filed in the account's D, so t's
/// record goes under D's sync ID as a certificate (u's record chain) while D's closure lacks t.
/// Run to quiet. Returns (t, t's minting, D's sync ID).
fn admin_outside(w: &mut World, i: usize, expires: Option<u64>) -> (Tid, CommitId, SyncId) {
    admin_outside_by(w, i, expires, osis_schema::PurgeBy::Admin)
}

/// `admin_outside` with t's minting purgeable by `by`.
fn admin_outside_by(w: &mut World, i: usize, expires: Option<u64>, by: osis_schema::PurgeBy) -> (Tid, CommitId, SyncId) {
    let (t, m) = w.write(i, |e| {
        let me = e.me();
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, me);
        m.set(t, &value_ak(), &Value::Str("t".into())).unwrap();
        m.retention(t, &ct::CREATED, osis_schema::Retention { by }).unwrap();
        if let Some(x) = expires {
            m.expires_all(osis_base::WallMs(x));
        }
        (t, e.commit(m).unwrap().unwrap())
    });
    let d = w.write(i, |e| {
        let (_, d) = e.account().unwrap().unwrap();
        let mut m = Mutation::new();
        let u = e.new_thing(&mut m, t);
        m.set(u, &value_ak(), &Value::Str("u".into())).unwrap();
        let mut g = e.get_typed(&d, &ct::GROUP).unwrap().unwrap_or_default();
        g.items.insert(u);
        m.set(d, &ct::GROUP, &g).unwrap();
        e.commit(m).unwrap().unwrap();
        d
    });
    w.run();
    let s = w.engine(i).home_sync_id(&d).unwrap().expect("D's sync ID");
    (t, m, s)
}

/// Whether node `i`'s store holds an entry of commit `c` under `s`.
fn holds(w: &mut World, i: usize, s: &SyncId, c: &CommitId) -> bool {
    let blobs = w.engine(i).commit_blobs(c).unwrap();
    w.store(i).entries(s).unwrap().iter().any(|e| blobs.contains(&e.blob))
}

// spec/commits.md §5 (A thing's mintings travel with its record: the witness is logged where no
// entry holds a minting of its standing, a lower copy goes where one of the witness's standing
// expiring later is held), spec/sync-judgement.md §2: siblings 1 and 2 sync D; t's record goes
// under D as a certificate, minted at node 1 with an expiry. Node 2 mints t again, durable: the
// two nodes' witnesses differ until node 1 holds the new minting, then both judge it the witness,
// keep its copy under D and drop the expiring one's; neither loses the copy the other keeps.
#[test]
fn two_nodes_with_different_witnesses_keep_the_same_copy_spec_commits_5() {
    let mut w = crate::harness::siblings();
    w.cap = 20_000;
    let far = w.engine(1).now().0 + 10 * ROLE_KEEP_MS;
    let (t, first, s) = admin_outside(&mut w, 1, Some(far));
    assert!(holds(&mut w, 2, &s, &first), "node 2 pulled t's witness under D");
    let again = w.write(2, |e| {
        let rec = e.core.created(&t).cloned().expect("node 2 holds t's record");
        let mut m = Mutation::new();
        m.create(rec);
        e.commit_hostile(m).unwrap().unwrap()
    });
    w.run();
    for i in [1, 2] {
        let e = w.engine(i);
        assert_eq!(e.witness(&t).map(|m| m.commit), Some(again), "node {i}: the durable minting is the witness");
        assert!(holds(&mut w, i, &s, &again), "node {i}: the witness's copy under D");
        assert!(!holds(&mut w, i, &s, &first), "node {i}: the lower copy left D");
    }
}

// spec/commits.md §5 (A thing's mintings travel with its record; Destruction: a destroyed thing a
// live thing needs keeps its record and requests), spec/sync-judgement.md §2: node 1 destroys t, which u (in D) names first admin; a
// sibling paired later holds t's record, its value-less witness and the request, and judges t
// destroyed as node 1 does.
#[test]
fn a_destroyed_things_witness_reaches_a_late_node_spec_commits_5() {
    let mut w = crate::harness::contacts();
    w.cap = 20_000;
    let (t, first, s) = admin_outside(&mut w, 1, None);
    let q = purge_thing(&mut w, 1, t);
    w.run();
    assert!(w.engine(1).destroyed(&t), "node 1: t destroyed");
    let late = w.pair(1);
    w.run();
    let e = w.engine(late);
    assert!(e.destroyed(&t) && !e.knows(&t), "the late node judges t destroyed");
    assert!(e.witness(&t).is_some_and(|m| m.commit == first && !m.standing.valued), "the late node holds t's value-less witness");
    assert!(e.header(&q).is_some(), "the late node holds the request");
    assert!(holds(&mut w, late, &s, &first), "the witness's copy under D at the late node");
}

// spec/commits.md §5 (A thing's mintings travel with its record: a lower copy goes only where an
// entry holds a minting of the witness's standing expiring later, by any node judging so; one
// lacking a request ranks a minting no lower than one holding it does), spec/sync-judgement.md
// §2: siblings 1 and 2 sync D; t (u's first admin, outside D) is minted at node 1 expiring at E,
// purgeable by nobody, and again at node 2, durable. Node 1 purges t's creation while it
// withholds its log: the request drops node 2's minting alone, so node 1's witness is its own
// and node 2's the durable one, each lower at the other. Node 1 keeps node 2's witness's copy
// (it expires later), so the two never each drop what the other keeps; healed, and past E, both
// judge t destroyed by the same witness.
#[test]
fn nodes_with_different_witnesses_never_each_drop_the_others_spec_commits_5() {
    let mut w = crate::harness::siblings();
    w.cap = 20_000;
    let end = w.engine(1).now().0 + 2 * ROLE_KEEP_MS;
    let (t, first, s) = admin_outside_by(&mut w, 1, Some(end), osis_schema::PurgeBy::Nobody);
    let again = w.write(2, |e| {
        let rec = e.core.created(&t).cloned().expect("node 2 holds t's record");
        let mut m = Mutation::new();
        m.create(rec);
        e.commit_hostile(m).unwrap().unwrap()
    });
    w.run();
    for i in [1, 2] {
        assert_eq!(w.engine(i).witness(&t).map(|m| m.commit), Some(again), "node {i}: the durable minting is the witness");
        assert!(holds(&mut w, i, &s, &again), "node {i}: the witness's copy under D");
    }
    w.lie(1, Some(crate::harness::lies::Lie::Withhold));
    let q = purge_thing(&mut w, 1, t);
    w.run();
    let witness = |w: &mut World, i: usize| w.engine(i).witness(&t).map(|m| m.commit);
    assert_eq!(witness(&mut w, 1), Some(first), "node 1: the request drops the durable minting alone");
    assert_eq!(witness(&mut w, 2), Some(again), "node 2 lacks the request");
    assert!(w.engine(2).header(&q).is_none(), "node 2 lacks the request");
    assert!(holds(&mut w, 1, &s, &first), "node 1 logs its witness");
    assert!(holds(&mut w, 1, &s, &again), "node 1 drops node 2's witness's copy");
    assert!(holds(&mut w, 2, &s, &again), "node 2 drops its witness's copy");
    w.lie(1, None);
    w.run();
    assert!(holds(&mut w, 1, &s, &first) && holds(&mut w, 1, &s, &again), "node 1 keeps both copies");
    assert!(holds(&mut w, 2, &s, &again), "node 2 keeps its witness's copy");
    w.advance(2 * ROLE_KEEP_MS + 1_000);
    w.run();
    for i in [1, 2] {
        let e = w.engine(i);
        assert!(e.destroyed(&t), "node {i}: t destroyed past E");
        assert_eq!(e.witness(&t).map(|m| m.commit), Some(first), "node {i}: the expired minting is the witness");
        assert!(e.header(&q).is_some(), "node {i} holds the request");
    }
}

/// At node `i`, t minted again (hostile: an honest writer mints once), purgeable by `by`, with
/// `expires` when given.
fn mint_again(w: &mut World, i: usize, t: Tid, by: osis_schema::PurgeBy, expires: Option<u64>) -> CommitId {
    w.write(i, |e| {
        let rec = e.core.created(&t).cloned().expect("the record held");
        let mut m = Mutation::new();
        m.create(rec);
        m.retention(t, &ct::CREATED, osis_schema::Retention { by }).unwrap();
        if let Some(x) = expires {
            m.expires_all(osis_base::WallMs(x));
        }
        e.commit_hostile(m).unwrap().unwrap()
    })
}

/// At node `i`, a request ending t's minting `c` alone (an item naming its stamp): refused, as
/// every item on `created.0` but the whole aspect is bad input.
fn purge_minting_refused(w: &mut World, i: usize, t: Tid, c: CommitId) {
    w.write(i, |e| {
        let h = e.header(&c).expect("the minting's header");
        let mut m = Mutation::new();
        let now = e.now();
        m.set(t, &ct::PURGE, &now).unwrap();
        m.purge(PurgeItem::Commit { tid: t, ak: ct::CREATED.name(), ts: h.ts, src: h.form.own_source(h.author, c) });
        assert!(e.commit(m).is_err(), "node {i}: a request ending one minting refused");
    })
}

/// Node 1's account grants node 0's account read on its D, which node 0's user accepts: node 0
/// joins D's sync ID late, holding nothing of t but what D carries. Run to quiet.
fn contact_joins(w: &mut World) {
    let holder = w.node(0).account.expect("node 0's account");
    let d = w.write(1, |e| {
        let (_, d) = e.account().unwrap().unwrap();
        let edge = osis_schema::core_types::Edge { role: osis_base::Role::Read, until: None, invite: None, tied: None, floor: None };
        e.grant(&d, &holder, &edge).unwrap();
        d
    });
    w.history.accepts.insert((d, 0));
    w.run();
    for _ in 0..2 {
        crate::harness::history::accept(w);
        w.run();
    }
}

// spec/commits.md §5 (A thing's mintings travel with its record: a kept copy stands in for a
// dropped one only if it cannot decide the thing's fate any earlier, so a lower copy goes only
// below one whose purge rights are contained in its own): t (u's first admin, outside D) minted
// at node 1 purgeable by admins, expiring; node 2 mints it again, durable, purgeable by its
// author too. Both copies stay under D, so node 0, joining D later, holds both; destroyed, it
// judges t as nodes 1 and 2 do.
#[test]
fn a_remint_wider_to_purge_keeps_the_lower_copy_spec_commits_5() {
    let mut w = crate::harness::siblings();
    w.cap = 20_000;
    let far = w.engine(1).now().0 + 10 * ROLE_KEEP_MS;
    let (t, first, s) = admin_outside(&mut w, 1, Some(far));
    let again = mint_again(&mut w, 2, t, osis_schema::PurgeBy::AuthorOrAdmin, None);
    w.run();
    for i in [1, 2] {
        assert_eq!(w.engine(i).witness(&t).map(|m| m.commit), Some(again), "node {i}: the durable minting is the witness");
        assert!(holds(&mut w, i, &s, &first), "node {i}: the lower copy kept under D");
    }
    contact_joins(&mut w);
    assert!(holds(&mut w, 0, &s, &again) && holds(&mut w, 0, &s, &first), "node 0 holds both copies under D");
    purge_thing(&mut w, 2, t);
    w.run();
    for i in 0..3 {
        assert!(w.engine(i).destroyed(&t), "node {i}: t live");
    }
}

// spec/commits.md §5 (Destruction: an item on `created.0` names every minting; A thing's
// mintings travel with its record: a kept copy stands in for a dropped one), spec/wire.md §4:
// t minted at node 1 expiring at E and again at node 2, durable, both purgeable by admins: the
// durable copy stands in for the expiring one, which leaves D. Node 1, holding the right over
// both, cannot end the durable minting alone (refused as bad input), so node 0, joining D later
// with the durable copy only, judges t as nodes 1 and 2 do: live past E, then destroyed by one
// request.
#[test]
fn no_request_ends_a_standing_in_minting_alone_spec_commits_5() {
    let mut w = crate::harness::siblings();
    w.cap = 20_000;
    let end = w.engine(1).now().0 + 2 * ROLE_KEEP_MS;
    let (t, first, s) = admin_outside(&mut w, 1, Some(end));
    let again = mint_again(&mut w, 2, t, osis_schema::PurgeBy::Admin, None);
    w.run();
    for i in [1, 2] {
        assert_eq!(w.engine(i).witness(&t).map(|m| m.commit), Some(again), "node {i}: the durable minting is the witness");
        assert!(!holds(&mut w, i, &s, &first), "node {i}: the lower copy left D");
    }
    purge_minting_refused(&mut w, 1, t, again);
    w.run();
    contact_joins(&mut w);
    assert!(holds(&mut w, 0, &s, &again) && !holds(&mut w, 0, &s, &first), "node 0 holds the durable copy alone");
    w.advance(2 * ROLE_KEEP_MS + 1_000);
    w.run();
    for i in 0..3 {
        let e = w.engine(i);
        assert!(!e.destroyed(&t), "node {i}: t destroyed past E");
        assert_eq!(e.witness(&t).map(|m| m.commit), Some(again), "node {i}: the durable minting is the witness");
    }
    purge_thing(&mut w, 1, t);
    w.run();
    for i in 0..3 {
        assert!(w.engine(i).destroyed(&t), "node {i}: t live");
    }
}

// spec/commits.md §5 (A thing's mintings travel with its record: a lower copy goes only below one
// expiring no earlier): t (u's first admin, outside D) minted at node 1, durable; node 2 mints it
// again expiring at E, purgeable by nobody; node 1 purges t, which drops its own minting alone, so the expiring
// one is the witness. The durable copy stays under D (the expiring one could end it first, were
// the purge to fall or not reach a node): node 0, joining D later, holds both. Node 1, the remint
// not yet held, destroys t and logs the request under D; node 2, where t never died, pulls it:
// outside D's required set there (spec/sync-judgement.md §2), it leaves every store of D once t
// lives at node 1, and node 0 never holds it.
#[test]
fn a_remint_expiring_earlier_keeps_the_lower_copy_spec_commits_5() {
    let mut w = crate::harness::siblings();
    w.cap = 20_000;
    let end = w.engine(1).now().0 + 2 * ROLE_KEEP_MS;
    let (t, first, s) = admin_outside(&mut w, 1, None);
    let again = mint_again(&mut w, 2, t, osis_schema::PurgeBy::Nobody, Some(end));
    w.run();
    let q = purge_thing(&mut w, 1, t);
    w.run();
    for i in [1, 2] {
        assert_eq!(w.engine(i).witness(&t).map(|m| m.commit), Some(again), "node {i}: the expiring minting is the witness");
        assert!(holds(&mut w, i, &s, &first), "node {i}: the lower copy kept under D");
        assert!(!holds(&mut w, i, &s, &q), "node {i}: the request outside D's required set is dropped");
    }
    contact_joins(&mut w);
    assert!(holds(&mut w, 0, &s, &again), "node 0 holds the witness's copy under D");
    assert!(holds(&mut w, 0, &s, &first), "node 0 holds the lower copy under D");
    for i in 0..3 {
        assert!(!holds(&mut w, i, &s, &q), "node {i} holds the request under D");
    }
}

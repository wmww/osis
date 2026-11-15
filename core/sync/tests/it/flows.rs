//! Flows between nodes of different accounts end to end through the product's sync, nothing
//! carried by hand after the contact exchange (`introduce`).

use crate::harness::{World, contacts, fixture_with};
use crate::harness::history::file;
use osis_base::{Ak, Role, Value};
use osis_engine::Mutation;
use osis_engine::flows::Demotion;
use osis_sync::types::{Scope, Waiting};
use osis_schema::core_types as ct;

pub(crate) fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None, floor: None }
}


// spec/sync-inbox.md §2 (taking: a connected sender), spec/sync-set.md §4 (accepting), spec/sync.md
// §3 (read): node 0 writes a thing in its synced group and grants node 1's account read; the
// grant reaches node 1 through node 1's inbox (a Deposit item), node 1 files the thing, follows
// the sync ID the blob named, opens it at node 0 and reads the write; a later write follows.
#[test]
fn a_granted_thing_is_read_once_accepted_spec_sync_inbox_2() {
    let mut w = contacts();
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a0);
        m.set(t, &ak, &Value::Str("x".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    file(&mut w, 0, vec![t], Vec::new());
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Read))).unwrap();
    w.run();
    let inv = w.engine(1).invitations().unwrap();
    assert!(inv.iter().any(|i| i.thing == t && i.taken && i.role == Role::Read), "a taken invitation: {inv:?}");
    file(&mut w, 1, Vec::new(), vec![t]);
    w.run();
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), Some(Value::Str("x".into())));
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("y".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), Some(Value::Str("y".into())));
}

/// Node 0 makes a thing, grants node 1's account sync on it, node 1's user accepts it (at once,
/// or after a run: `later`), node 0 writes again: node 1 keeps the thing unread with S's genesis
/// registered and both writes held.
fn kept_unread(later: bool) -> (World, osis_base::Tid) {
    kept_unread_away(later, false)
}

fn kept_unread_away(later: bool, away: bool) -> (World, osis_base::Tid) {
    let mut w = contacts();
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let write = |w: &mut World, t: Option<osis_base::Tid>, v: &str| {
        w.write(0, |e| {
            let mut m = Mutation::new();
            let t = t.unwrap_or_else(|| e.new_thing(&mut m, a0));
            m.set(t, &ak, &Value::Str(v.into())).unwrap();
            e.commit(m).unwrap();
            t
        })
    };
    let t = write(&mut w, None, "x");
    file(&mut w, 0, vec![t], Vec::new());
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Sync))).unwrap();
    // the grant delivered (an accept takes only what is held), then tested at node 1 (`later`)
    if later {
        w.run();
    } else {
        w.flush();
    }
    if away {
        w.partition(0, 1);
        w.run();
    }
    file(&mut w, 1, Vec::new(), vec![t]);
    w.run();
    if away {
        w.heal();
        w.run();
    }
    write(&mut w, Some(t), "y");
    w.run();
    let s = w.engine(0).home_sync_id(&t).unwrap().unwrap();
    assert_eq!(w.engine(1).thing_sync(&t).unwrap(), osis_engine::sync::ThingSync::Unread(vec![s]));
    let st = &w.node(1).store;
    assert!(st.path(&s).unwrap().is_some(), "S's genesis registered");
    assert!(st.entries(&s).unwrap().len() >= 2, "both writes held");
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), None, "unread");
    (w, t)
}

// spec/sync-ids.md §6 (walk: moving it, genesis first while the source's step is not known),
// spec/sync-opens.md §4 (Admissible: with no head, a node keeping S unread shows its newest
// sync secret's key), spec/sync-judgement.md §6 (takes): node 0 grants node 1's account sync on a thing node 1
// accepts at once; it keeps the thing unread with no step and opens S by its grant's sync proof;
// node 0 registers S's genesis there and node 1 holds node 0's writes, unread.
#[test]
fn a_sync_grant_is_kept_unread_with_the_writes_spec_sync_ids_6() {
    kept_unread(false);
}

// spec/sync-ids.md §6 (walk: a source's newly shown credentials are found by its own test): as
// above, the user accepting after node 0 first tested S at node 1 (its Behind then answered 13):
// S joins node 1's sync set with no head, its `changed_at` moves, and node 1's own test opens S.
#[test]
fn a_sync_grant_accepted_later_is_kept_unread_with_the_writes_spec_sync_ids_6() {
    kept_unread(true);
}

// spec/sync-ids.md §6 (walk: a source's newly shown credentials are found by its own test): as
// above, the user accepting while node 0 is out of reach: node 1's test on the next connection
// opens S.
#[test]
fn a_sync_grant_accepted_while_away_is_kept_unread_with_the_writes_spec_sync_ids_6() {
    kept_unread_away(true, true);
}

/// Node 0 makes a thing in its synced group, `u:v.0` = "x".
fn made(w: &mut World) -> (osis_base::Tid, Ak) {
    let a0 = w.node(0).account.unwrap();
    let ak = Ak::new("u:v.0").unwrap();
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a0);
        m.set(t, &ak, &Value::Str("x".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    file(w, 0, vec![t], Vec::new());
    (t, ak)
}

/// Node `i` writes `v` on thing `t`.
fn set(w: &mut World, i: usize, t: osis_base::Tid, v: &str) {
    w.write(i, |e| {
        let mut m = Mutation::new();
        m.set(t, &Ak::new("u:v.0").unwrap(), &Value::Str(v.into())).unwrap();
        e.commit(m).unwrap();
    });
}

/// Node `i` grants node `j`'s account `role` on `t`.
fn grant(w: &mut World, i: usize, t: osis_base::Tid, j: usize, role: Role) -> osis_engine::Result<()> {
    let a = w.node(j).account.unwrap();
    w.write(i, |e| e.grant(&t, &a, &edge(role))).map(drop)
}

/// Node `i` removes node `j`'s account from `t`.
fn remove(w: &mut World, i: usize, t: osis_base::Tid, j: usize) {
    let holder = w.node(j).account.unwrap();
    w.write(i, |e| e.demote(&t, &Demotion { holder, new: None, retain: None })).unwrap();
}

/// Node `j`'s user accepts `t`: an invitation not yet taken is accepted, else `t` is filed.
fn accept(w: &mut World, j: usize, t: osis_base::Tid) {
    let invited = w.engine(j).invitations().unwrap().iter().any(|x| x.thing == t && !x.taken);
    if invited {
        let (_, d) = w.engine(j).account().unwrap().unwrap();
        w.write(j, |e| e.accept_invite(&t, &d)).unwrap();
    } else {
        file(w, j, Vec::new(), vec![t]);
    }
    w.run();
}

fn reads(w: &mut World, i: usize, t: osis_base::Tid) -> Option<Value> {
    w.engine(i).get(&t, &Ak::new("u:v.0").unwrap()).unwrap()
}

// spec/sync-opens.md §3 (`changed_at`: advanced when a credential of S changes, here the
// grantee's): a reader removed, then granted again after a write it could not read, reads that
// write.
#[test]
fn a_reader_granted_again_reads_the_write_made_while_removed_spec_sync_opens_3() {
    let (mut w, t, _) = granted_and_read(Role::Read);
    remove(&mut w, 0, t, 1);
    w.run();
    set(&mut w, 0, t, "y");
    grant(&mut w, 0, t, 1, Role::Read).unwrap();
    w.run();
    accept(&mut w, 1, t);
    assert_eq!(reads(&mut w, 1, t), Some(Value::Str("y".into())));
}

// spec/sync-ids.md §5 (the store is the truth for ciphertext: so after a failure): a grant whose
// durable write fails unsynced (its outcome unknown) and stands makes node 0's engine read its
// store again; sync starts again from the store, so the grant reaches node 1, which reads the
// thing once it accepts it. The fault goes at each of the grant's durable writes in turn until
// one leaves the grant standing.
#[test]
fn a_grant_of_unknown_outcome_that_stands_reaches_the_grantee_spec_sync_ids_5() {
    let (mut w, t) = (0..8)
        .find_map(|n| {
            let mut w = contacts();
            let (t, _) = made(&mut w);
            w.disk_fault(0, n, crate::harness::DiskFault::Unsynced);
            let r = grant(&mut w, 0, t, 1, Role::Read);
            w.run();
            let a1 = w.node(1).account.unwrap();
            let stands = w.engine(0).roster(&t).get(&a1).is_some_and(|e| e.role == Role::Read);
            (r.is_err() && stands).then_some((w, t))
        })
        .expect("a grant of unknown outcome that stands");
    accept(&mut w, 1, t);
    assert_eq!(reads(&mut w, 1, t), Some(Value::Str("x".into())));
}

// spec/sync-judgement.md §6 (read and unread move: a node raised to read opens what is there): a
// node keeping S unread, holding writes there, raised to read reads them.
#[test]
fn raised_from_sync_to_read_reads_what_is_held_spec_sync_judgement_6() {
    let (mut w, t) = kept_unread(true);
    grant(&mut w, 0, t, 1, Role::Read).unwrap();
    w.run();
    accept(&mut w, 1, t);
    assert_eq!(reads(&mut w, 1, t), Some(Value::Str("y".into())));
}

// spec/permissions.md §3 (Lost access), spec/sync-judgement.md §3 (own store): a writer removed
// and granted write again reads the write made before its removal (its own logs of the commits
// that went with the lost access open again).
#[test]
fn a_writer_granted_again_reads_what_it_held_spec_permissions_3() {
    let (mut w, t, _) = granted_and_read(Role::Write);
    set(&mut w, 0, t, "y");
    w.run();
    remove(&mut w, 0, t, 1);
    w.run();
    grant(&mut w, 0, t, 1, Role::Write).unwrap();
    w.run();
    accept(&mut w, 1, t);
    assert_eq!(reads(&mut w, 1, t), Some(Value::Str("y".into())));
}

// spec/permissions.md §3 (Lost access: a sync holder keeps its store, kept unread),
// spec/sync-judgement.md §6 (read and unread move: raised to read opens what is held): a writer
// lowered to sync forgets its own write with the lost access while its store keeps its own entry
// of it, the only one of that write it holds; raised to read again, that entry opens and it reads
// the write.
#[test]
fn a_writer_lowered_to_sync_and_raised_reads_its_own_write_spec_sync_judgement_6() {
    let (mut w, t, _) = granted_and_read(Role::Write);
    set(&mut w, 1, t, "z");
    w.run();
    assert_eq!(reads(&mut w, 0, t), Some(Value::Str("z".into())));
    let holder = w.node(1).account.unwrap();
    w.write(0, |e| e.demote(&t, &Demotion { holder, new: Some(edge(Role::Sync)), retain: None })).unwrap();
    w.run();
    assert_eq!(reads(&mut w, 1, t), None, "lowered to sync: unread");
    grant(&mut w, 0, t, 1, Role::Read).unwrap();
    w.run();
    accept(&mut w, 1, t);
    assert_eq!(reads(&mut w, 1, t), Some(Value::Str("z".into())));
}

// spec/commits.md §4 (Pending storage: an entry whose commit pends gives nothing held, so it is its
// commit's carrier, charged to its bringer), spec/sync-ids.md §5 (Peer budget): node 1, reading
// t, opens node 0's entry of a write on a thing t2 made under t before the entry of t2's
// creation: the write pends, and the entry is kept as its carrier (`Opening::Pends`, which streams
// charges to the peer that brought it: streams::a_flood_of_pending_commits_is_bounded_per_peer).
// Once the creation's entry opens, the write is held.
#[test]
fn an_entry_whose_commit_pends_is_its_carrier_spec_commits_4() {
    use osis_sync::streams::{Opening, opening};
    let (mut w, t, ak) = granted_and_read(Role::Read);
    w.partition(0, 1);
    let (made, wrote) = w.write(0, |e| {
        let mut m = Mutation::new();
        let t2 = e.new_thing(&mut m, t);
        m.set(t2, &ak, &Value::Str("new".into())).unwrap();
        let made = e.commit(m).unwrap().unwrap();
        let mut m = Mutation::new();
        m.set(t2, &ak, &Value::Str("w".into())).unwrap();
        (made, e.commit(m).unwrap().unwrap())
    });
    w.run();
    let s = w.engine(0).sync_ids(&t).unwrap()[0].id;
    let entry_of = |w: &mut World, c| {
        let blobs = w.engine(0).commit_blobs(&c).unwrap();
        let e = w.store(0).entries(&s).unwrap().into_iter().find(|e| blobs.contains(&e.blob)).expect("an entry of the commit under S");
        let bytes = w.store(0).bytes(&e.blob).unwrap().unwrap();
        (e, bytes)
    };
    let (we, wb) = entry_of(&mut w, wrote);
    let (me, mb) = entry_of(&mut w, made);
    let store = w.store(1).clone();
    assert_eq!(opening(w.engine(1), &store, &s, &we, &wb).unwrap(), Opening::Pends);
    assert!(matches!(opening(w.engine(1), &store, &s, &me, &mb).unwrap(), Opening::Held { gave: true }));
    assert!(w.engine(1).holds_commit(&wrote), "the write applies once its thing's record is held");
}

// spec/sync-inbox.md §2 (Re-send: an open by a store credential shows a delivery taken only to a
// holder of sync alone): node 1 keeps S unread, is raised to write and removed; node 0 grants it
// read, and node 1's take of that grant fails (a failed durable write: it restarts in place and
// opens S again by its store credential, the grant not yet taken). That open shows node 0
// nothing, so node 0 sends the grant again and node 1 reads the thing. The fault goes at each of
// node 1's first durable writes in turn.
#[test]
fn a_store_open_by_a_removed_sync_holder_shows_no_read_grant_taken_spec_sync_inbox_2() {
    let removed = || {
        fixture_with("kept unread, raised to write, removed", || {
            let (mut w, t) = kept_unread(true);
            grant(&mut w, 0, t, 1, Role::Write).unwrap();
            remove(&mut w, 0, t, 1);
            w.run();
            (w, t)
        })
    };
    for n in 0..6 {
        let (mut w, t) = removed();
        w.disk_fault(1, n, crate::harness::DiskFault::Fail);
        grant(&mut w, 0, t, 1, Role::Read).unwrap();
        w.run();
        accept(&mut w, 1, t);
        assert_eq!(reads(&mut w, 1, t), Some(Value::Str("y".into())), "node 1's durable write {n} failing");
    }
}

// spec/sync.md §2 (Work in proportion to change), spec/sync-streams.md §4 (Fill order: what does
// not open is held and opened as secrets arrive): an entry that did not open is parked under its
// sync ID's read secrets, so a read secret arriving examines the parked entries alone, never the
// entries that opened (counted at n and 10n writes); and the parked entry is examined then.
#[test]
fn a_read_secret_arriving_examines_only_what_did_not_open_spec_sync_2() {
    let examined = |n: usize| {
        let (mut w, t, _) = granted_and_read(Role::Read);
        for i in 0..n {
            w.write(0, |e| {
                let mut m = Mutation::new();
                m.set(t, &Ak::new(format!("u:w{i}.0")).unwrap(), &Value::Int(i as i64)).unwrap();
                e.commit(m).unwrap();
            });
        }
        w.run();
        let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
        assert!(w.store(1).entries(&s).unwrap().len() >= n, "node 1 holds every write");
        // a peer's entry no read secret held opens
        let p = osis_blob::Prefix::for_keys([7; 16], &[1; 16], None, &[]).unwrap();
        let (_, bytes) = osis_blob::frame(&p, &[7; 64], &mut osis_crypto::SeededRng::from_u64(7)).unwrap();
        let b = osis_blob::blob_id(&bytes);
        let e = osis_sync::types::Entry { blob: b, wrap: [7; osis_crypto::WRAP_LEN], stamp: None, deposited: true, own: false, role: false, class: osis_blob::Class::Durable, expires: None };
        let mut st = w.store(1).clone();
        st.log(&s, e, Some(bytes), None).unwrap();
        w.run();
        let epoch = |w: &mut World| *w.engine(1).epochs(&t).unwrap().read.current().last().unwrap();
        let before = epoch(&mut w);
        let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
        osis_base::costs::take();
        w.write(0, |e| e.rotate_boxing_only(&[t], &[Role::Read], &[a0, a1])).unwrap().expect("a rotation");
        w.run();
        let count = osis_base::costs::take().into_iter().filter(|(k, ..)| *k == "store: parked examined").map(|(.., n)| n).sum::<u64>();
        assert_ne!(epoch(&mut w), before, "node 1 took a new read secret");
        assert!(w.store(1).entry(&s, &b).unwrap().is_some(), "kept, parked");
        count
    };
    let (a, b) = (examined(4), examined(40));
    assert_eq!(a, 1, "the parked entry alone is examined as the secret arrives");
    assert_eq!(a, b, "entries examined: {a} after n writes, {b} after 10n");
}

/// Node 0 makes a thing in its synced group and grants node 1's account `role` on it; node 1
/// accepts it and reads it.
pub(crate) fn granted_and_read(role: Role) -> (World, osis_base::Tid, Ak) {
    let mut w = contacts();
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a0);
        m.set(t, &ak, &Value::Str("x".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    file(&mut w, 0, vec![t], Vec::new());
    w.write(0, |e| e.grant(&t, &a1, &edge(role))).unwrap();
    w.run();
    file(&mut w, 1, Vec::new(), vec![t]);
    w.run();
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), Some(Value::Str("x".into())));
    (w, t, ak)
}

// spec/sync-status.md §2 (held elsewhere: an entry at a source that reads S, by its stream or a
// reported position), §3 (synced: heard out and each own commit under S held elsewhere): the
// writer's sync ID of a thing is not synced while its write is only here, and is once the reader
// holds it. A wait on the thing also covers each node's home, which no peer shares: it holds
// neither wait, the granter's nor the accepter's; the peer away, its record holding S does.
#[test]
fn a_write_is_synced_once_a_reader_holds_it_spec_sync_status_3() {
    let (mut w, t, ak) = granted_and_read(Role::Read);
    let s = w.engine(0).sync_ids(&t).unwrap()[0].id;
    let synced = |w: &World| w.status(0).get(&s).is_some_and(|x| x.synced());
    w.run();
    assert!(synced(&w), "everything written is held at node 1");
    w.partition(0, 1);
    w.run();
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("y".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert!(!synced(&w) && w.status(0)[&s].unheld == Some(1), "unconnected, the write only here");
    w.heal();
    w.run();
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), Some(Value::Str("y".into())));
    assert!(synced(&w));
    assert_eq!(w.wait(0, Scope::Thing(t)), Waiting::Done, "node 0's home carries it too, shared by no peer");
    assert_eq!(w.wait(1, Scope::Thing(t)), Waiting::Done, "the accepter's home, filing it, likewise");
    w.partition(0, 1);
    w.run();
    assert_eq!(w.wait(0, Scope::Thing(t)), Waiting::Pending, "node 1 away: its record holds S");
    assert_eq!(w.wait(1, Scope::Thing(t)), Waiting::Pending);
}

// spec/sync-status.md §2 (held elsewhere), spec/permissions.md §3 (Lost access): node 1 leaves a
// thing it writes (a self-removal); it keeps its secrets while node 0 is out of reach (node 0's
// record holds S: a peer away), through a restart, and drops them once node 0 holds the removal.
#[test]
fn a_self_removal_drops_its_secrets_once_held_elsewhere_spec_sync_status_2() {
    let (mut w, t, _) = granted_and_read(Role::Write);
    let a1 = w.node(1).account.unwrap();
    w.partition(0, 1);
    w.run();
    let c = w.write(1, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap().commits[0];
    w.run();
    assert!(w.engine(1).waiting_removals().unwrap().contains(&c), "only here");
    assert!(w.engine(1).epochs(&t).is_some_and(|x| x.read.holds_any()), "kept while it waits");
    w.power_off(1);
    w.power_on(1);
    w.run();
    assert!(w.engine(1).waiting_removals().unwrap().contains(&c), "a restart finds it waiting");
    w.heal();
    w.run();
    assert!(w.engine(1).waiting_removals().unwrap().is_empty(), "node 0 holds it");
    assert!(w.engine(1).epochs(&t).is_none_or(|e| e.read.held().next().is_none()), "dropped");
}

// spec/permissions.md §3 (Lost access): node 0 unsyncs a thing node 1 writes; node 1, sharing it
// with nobody now, leaves it (a self-removal) and drops its secrets at once: nothing waits for a
// peer that could never take the removal.
#[test]
fn a_self_removal_nobody_shares_drops_at_once_spec_perm_3() {
    let (mut w, t, _) = granted_and_read(Role::Write);
    let a1 = w.node(1).account.unwrap();
    let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
    w.write(0, |e| {
        let d = e.account().unwrap().unwrap().1;
        let mut g = e.get_typed(&d, &ct::GROUP).unwrap().unwrap_or_default();
        g.items.retain(|x| *x != t);
        let mut m = Mutation::new();
        m.set(d, &ct::GROUP, &g).unwrap();
        e.commit(m).unwrap();
        // its grant made here shared it here too (spec/sync-set.md §2 Shared here)
        e.unshare(&t).unwrap();
    });
    w.run();
    assert!(w.store(0).synced(&s).is_none(), "node 0 stopped syncing it");
    let c = w.write(1, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap().commits[0];
    w.run();
    assert!(!w.engine(1).waiting_removals().unwrap().contains(&c), "no peer shares it: done at once");
    assert!(w.engine(1).epochs(&t).is_none_or(|e| e.read.held().next().is_none()), "dropped");
}

// spec/sync-set.md §3 (while it waits, S stays a member of its shared sets as before;
// Unsyncing): node 1 writes a thing it reads and writes while node 0 is out of reach, then
// unsyncs it (takes it out of its synced group) and restarts. S stays synced at node 1 through
// the restart, the write reaches node 0 once healed, and only then is node 1's copy forgotten.
#[test]
fn an_unsynced_write_reaches_a_peer_before_the_copy_goes_spec_sync_set_3() {
    let (mut w, t, ak) = granted_and_read(Role::Write);
    w.cap = 4_000;
    let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
    let mine = Some(Value::Str("from 1".into()));
    w.partition(0, 1);
    w.run();
    w.write(1, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("from 1".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    w.write(1, |e| {
        let d = e.account().unwrap().unwrap().1;
        let mut g = e.get_typed(&d, &ct::GROUP).unwrap().unwrap_or_default();
        g.subgroups.retain(|x| *x != t);
        let mut m = Mutation::new();
        m.set(d, &ct::GROUP, &g).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert!(!w.engine(1).sync_set().unwrap().ids.contains_key(&s), "left the sync set");
    assert!(w.store(1).synced(&s).is_some(), "still synced while its write is only here");
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), mine);
    w.power_off(1);
    w.power_on(1);
    w.run();
    assert!(w.store(1).synced(&s).is_some(), "a restart finds it waiting");
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), mine);
    w.heal();
    w.run();
    assert_eq!(w.engine(0).get(&t, &ak).unwrap(), mine, "the write reached node 0");
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), None, "then forgotten here");
    assert!(w.store(1).synced(&s).is_none() && !w.store(1).held_ids().unwrap().contains(&s), "stopped and shredded");
}

/// Node `i` unsyncs `t`: out of its synced group, and shared there no more (spec/sync-set.md §2).
fn unfile(w: &mut World, i: usize, t: osis_base::Tid) {
    w.write(i, |e| {
        let d = e.account().unwrap().unwrap().1;
        let mut g = e.get_typed(&d, &ct::GROUP).unwrap().unwrap_or_default();
        g.subgroups.retain(|x| *x != t);
        g.items.retain(|x| *x != t);
        let mut m = Mutation::new();
        m.set(d, &ct::GROUP, &g).unwrap();
        e.commit(m).unwrap();
        e.unshare(&t).unwrap();
    });
}

// spec/sync-set.md §3 (it waits only while some peer is to be waited for on S: one the rosters name, never told of S): node 1
// makes a thing outside its synced group and grants node 0's account write, which node 0
// accepts; apart from node 0, node 1 files the thing, writes it and unfiles it. No record holds
// S (it joined node 1's sync set after the two parted), but node 0's account holds a role on it
// and node 0's record was never told of S, so node 1 keeps S until its write reached node 0.
#[test]
fn an_unsynced_write_on_a_sync_id_just_joined_reaches_the_peer_first_spec_sync_set_3() {
    let mut w = contacts();
    w.cap = 4_000;
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let t = w.write(1, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a1);
        m.set(t, &ak, &Value::Str("x".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    // shared no more at node 1: S joins its sync set only by its filing below
    w.write(1, |e| {
        e.grant(&t, &a0, &edge(Role::Write)).unwrap();
        e.unshare(&t).unwrap();
    });
    w.run();
    file(&mut w, 0, Vec::new(), vec![t]);
    w.run();
    let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
    assert!(w.store(0).synced(&s).is_some() && w.store(1).synced(&s).is_none(), "node 0 syncs S, node 1 not yet");
    w.partition(0, 1);
    w.run();
    file(&mut w, 1, Vec::new(), vec![t]);
    w.run();
    let mine = Some(Value::Str("from 1".into()));
    w.write(1, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("from 1".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    unfile(&mut w, 1, t);
    w.run();
    assert!(!w.engine(1).sync_set().unwrap().ids.contains_key(&s), "left the sync set");
    assert!(w.store(1).synced(&s).is_some(), "still synced: node 0 was never told of S");
    w.power_off(1);
    w.power_on(1);
    w.run();
    assert!(w.store(1).synced(&s).is_some(), "a restart finds it waiting");
    w.heal();
    w.run();
    assert_eq!(w.engine(0).get(&t, &ak).unwrap(), mine, "the write reached node 0");
    assert!(w.store(1).synced(&s).is_none(), "then stopped");
}

// spec/sync-set.md §3 (with none, it stops at once): node 1 grants a thing it made
// outside its synced group to node 0's account and removes it again; apart from node 0 it files
// the thing, writes it and unfiles it. Node 0's record was never told of S, but no roster names
// another holder of it any more, so it stops at once.
#[test]
fn a_thing_no_other_node_may_hold_leaves_at_once_spec_sync_set_3() {
    let mut w = contacts();
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let t = w.write(1, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a1);
        m.set(t, &ak, &Value::Str("x".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    w.write(1, |e| e.grant(&t, &a0, &edge(Role::Write))).unwrap();
    w.run();
    w.write(1, |e| e.demote(&t, &Demotion { holder: a0, new: None, retain: None })).unwrap();
    w.run();
    w.partition(0, 1);
    w.run();
    file(&mut w, 1, Vec::new(), vec![t]);
    w.run();
    let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
    assert!(w.store(1).synced(&s).is_some());
    w.write(1, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("y".into())).unwrap();
        e.commit(m).unwrap();
    });
    unfile(&mut w, 1, t);
    w.run();
    assert!(w.store(1).synced(&s).is_none(), "stopped at once");
}

// spec/sync-set.md §3 (it waits only while some peer is to be waited for on S: a peer told them that does not share S is not): as above, but node 0 unfiles the
// thing while apart; once the two meet node 0's record acknowledges S with S not a member, so
// node 1 stops though its write is held nowhere else (a peer that does not hold S takes nothing).
#[test]
fn a_peer_acknowledging_a_sync_id_it_does_not_hold_ends_the_wait_spec_sync_set_3() {
    let mut w = contacts();
    w.cap = 4_000;
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let t = w.write(1, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a1);
        e.commit(m).unwrap();
        t
    });
    // shared no more at node 1: S joins its sync set only by its filing below, apart from node 0
    w.write(1, |e| {
        e.grant(&t, &a0, &edge(Role::Write)).unwrap();
        e.unshare(&t).unwrap();
    });
    w.run();
    file(&mut w, 0, Vec::new(), vec![t]);
    w.run();
    let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
    w.partition(0, 1);
    w.run();
    unfile(&mut w, 0, t);
    file(&mut w, 1, Vec::new(), vec![t]);
    w.run();
    unfile(&mut w, 1, t);
    w.run();
    assert!(w.store(0).synced(&s).is_none(), "node 0 stopped syncing S");
    assert!(w.store(1).synced(&s).is_some(), "node 1 waits: node 0 was never told of S");
    w.heal();
    w.run();
    assert!(w.store(1).synced(&s).is_none(), "told, node 0 does not hold S: stopped");
}

// spec/permissions.md §3 (Lost access: a self-remover keeps the secrets until its self-removal is
// held elsewhere, waiting while a peer could take it): node 1 reads and writes a thing, unfiles
// it (its copy goes), then, apart from node 0, files it again and leaves it. S joined node 1's
// sync set after the two parted, so no record holds it, yet node 1 waits, and the removal reaches
// node 0's account once the two meet.
#[test]
fn a_self_removal_on_a_sync_id_just_joined_reaches_the_granter_spec_perm_3() {
    let (mut w, t, _) = granted_and_read(Role::Write);
    let a1 = w.node(1).account.unwrap();
    let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
    unfile(&mut w, 1, t);
    w.run();
    assert!(w.store(1).synced(&s).is_none(), "stopped syncing it");
    w.partition(0, 1);
    w.run();
    file(&mut w, 1, Vec::new(), vec![t]);
    w.run();
    assert!(w.store(1).synced(&s).is_some(), "synced again");
    let c = w.write(1, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap().commits[0];
    w.run();
    assert!(w.engine(1).waiting_removals().unwrap().contains(&c), "waits for node 0");
    w.heal();
    w.run();
    assert!(w.engine(0).commit_ids().contains(&c), "the removal reached node 0");
    assert!(w.engine(1).waiting_removals().unwrap().is_empty(), "then dropped");
}

// spec/permissions.md §3 (Re-seal: a node that may rotate re-seals a current holder without a box
// at a current epoch; Complete pass: it decides at the end of a complete pass of the actor's sync
// IDs): node 0 grants node 2 read while node 1, an admin cut off from it, removes node 3 (a
// rotation); once healed node 2 has no box at node 1's epoch, and an admin re-seals it at the end
// of the complete pass a role commit from elsewhere began, so node 2 reads a write under it.
#[test]
fn a_raced_grant_is_resealed_at_a_complete_passs_end_spec_perm_3() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, check, world};
    let mut w = world(0, 4);
    w.cap = crate::harness::STORM_CAP;
    let _ = crate::harness::play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Writes), Grant(0, 0, 3, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Admin))).unwrap();
    w.run();
    let _script = crate::harness::play(&mut w, &[Partition(0, 1), Partition(1, 2), Partition(1, 3), Grant(0, 0, 2, Gives::Reads), Run, Remove(1, 0, 3), Run, Heal, Run, Write(0, 0), Run], String::new());
    check(&mut w);
}

// spec/sync-opens.md §6 (ended: `until`, the highest position at which an entry in S of a
// rotation superseding that credential's epoch was first logged, else the node log's end): at
// node 0 a member opened by node 1's read secret would end at the log's end while nothing
// supersedes that epoch, and at the removal's rotation entry once node 1 is removed, whatever is
// logged after it.
#[test]
fn an_ended_members_until_is_the_superseding_rotations_entry_spec_sync_opens_6() {
    use osis_sync::types::Credential;
    let (mut w, t, ak) = granted_and_read(Role::Read);
    let s = w.engine(0).sync_ids(&t).unwrap()[0].id;
    let e1 = *w.engine(0).epochs(&t).unwrap().read.current().last().unwrap();
    let end = |w: &World| w.store(0).log_bounds().unwrap().0;
    assert_eq!(w.member_until(0, &s, &Credential::ReadSecret(e1)), end(&w), "nothing supersedes it: the log's end");
    let a1 = w.node(1).account.unwrap();
    let c = w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap().commits[0];
    w.run();
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("after".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    let blobs = w.engine(0).commit_blobs(&c).unwrap();
    let at = blobs.iter().filter_map(|b| w.store(0).first_logged(&s, b).unwrap()).max().expect("the removal is logged under S");
    assert!(at < end(&w), "a write logged after it");
    assert_eq!(w.member_until(0, &s, &Credential::ReadSecret(e1)), at);
    assert_eq!(w.member_until(0, &s, &Credential::SyncKey), end(&w), "a credential with no epoch at a reader: the log's end");
}

// spec/sync-opens.md §6 (the position of its head's event): an ended member's `until` at a node keeping S unread;
// node 1 keeps S unread with S's genesis registered.
#[test]
fn an_ended_member_at_a_node_keeping_s_unread_ends_at_its_heads_event_spec_sync_opens_6() {
    let (mut w, t) = kept_unread(false);
    let s = w.engine(0).sync_ids(&t).unwrap()[0].id;
    let head = w.store(1).head_at(&s).unwrap().expect("a head logged");
    assert_eq!(w.member_until(1, &s, &osis_sync::types::Credential::SyncKey), head);
}

// spec/sync-inbox.md §2 (Re-send: until seen taken): a wait on deliveries ends once every
// delivery this node owes is seen taken, and a wait on all waits for them too.
#[test]
fn a_wait_on_deliveries_ends_once_the_grant_is_taken_spec_sync_inbox_2() {
    let mut w = contacts();
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a0);
        e.commit(m).unwrap();
        t
    });
    file(&mut w, 0, vec![t], Vec::new());
    w.partition(0, 1);
    w.run();
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Read))).unwrap();
    w.run();
    assert_eq!(w.wait(0, Scope::Deliveries), Waiting::Pending, "the grant is owed");
    w.heal();
    w.run();
    file(&mut w, 1, Vec::new(), vec![t]);
    w.run();
    assert!(w.engine(0).deliveries().unwrap().is_empty());
    assert_eq!(w.wait(0, Scope::Deliveries), Waiting::Done, "seen taken");
}

// spec/permissions.md §3 (Own secrets add only): node 0 makes group G (secrets of its own) and T
// under it (plain, first admin G, an item of G); node 1's account reads G. T gets secrets of its
// own, boxed to G like any holder: node 1 reads T's next write through G, with nothing granted on T;
// the delivery to G's inbox (node 0 reads it) ends once logged (spec/sync-inbox.md §2 Re-send).
#[test]
fn own_secrets_keep_a_reader_of_the_first_admin_reading_spec_perm_3() {
    let mut w = contacts();
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let (g, t) = w.write(0, |e| {
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, a0);
        e.commit(m).unwrap();
        e.give_own_secrets(&g).unwrap();
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, g);
        m.set(t, &ak, &Value::Str("x".into())).unwrap();
        m.set(g, &ct::GROUP, &ct::Group { items: [t].into(), ..Default::default() }).unwrap();
        e.commit(m).unwrap();
        (g, t)
    });
    file(&mut w, 0, vec![g], Vec::new());
    w.write(0, |e| e.grant(&g, &a1, &edge(Role::Read))).unwrap();
    w.run();
    file(&mut w, 1, Vec::new(), vec![g]);
    w.run();
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), Some(Value::Str("x".into())), "T read through G while plain");
    let owed = w.engine(0).give_own_secrets(&t).map(|_| w.engine(0).deliveries().unwrap()).unwrap();
    assert!(owed.iter().any(|(_, to)| *to == g), "the rotation goes to G's inbox: {owed:?}");
    w.deliver(0, osis_sync::types::Input::Wrote);
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("y".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), Some(Value::Str("y".into())), "T read through G with secrets of its own");
    // the rotation's delivery to G's inbox, which node 0 reads, ends once logged: owed neither twice nor for good
    assert!(w.engine(0).deliveries().unwrap().is_empty(), "nothing owed: {:?}", w.engine(0).deliveries().unwrap());
}

/// Node 0 grants account 1 read on a thing; node 1 takes it, and accepts it (`accept`) or not;
/// node 2, account 1's second node, is away until the inbox blob expired and node 0 is gone, then
/// comes back with node 1. Whether node 2 then lists the invitation, and whether it reads the thing.
fn away_past_inbox_lifetime(accept: bool) -> (bool, bool) {
    let mut w = contacts();
    let n2 = w.pair(1);
    w.run();
    w.power_off(n2);
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a0);
        m.set(t, &ak, &Value::Str("x".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    file(&mut w, 0, vec![t], Vec::new());
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Read))).unwrap();
    w.run();
    let invited = |w: &mut World, i: usize| w.engine(i).invitations().unwrap().iter().any(|x| x.thing == t && x.role == Role::Read);
    assert!(invited(&mut w, 1), "node 1 took the grant");
    if accept {
        file(&mut w, 1, Vec::new(), vec![t]);
        w.run();
        assert_eq!(w.engine(1).get(&t, &ak).unwrap(), Some(Value::Str("x".into())), "node 1 reads it");
    }
    w.power_off(0);
    w.power_off(1);
    w.advance(osis_base::format::INBOX_LIFETIME_MS + 3 * osis_base::format::MAX_DRIFT_MS);
    w.power_on(1);
    w.power_on(n2);
    w.run();
    let reads = w.engine(n2).get(&t, &ak).unwrap() == Some(Value::Str("x".into()));
    (invited(&mut w, n2), reads)
}

// spec/sync-inbox.md §5 (Grant copy: kept once the account accepted the thing), spec/sync-set.md §4
// (Accepting): node 1 accepts a grant; node 2, away past the inbox blob's lifetime, reads the thing.
#[test]
fn an_accepted_grant_reaches_a_node_away_past_inbox_lifetime_spec_sync_inbox_5() {
    assert_eq!(away_past_inbox_lifetime(true), (false, true));
}

// spec/sync-inbox.md §5 (Grant copy: a grant from an author without write on the account, not
// accepted, is no grant copy), §2 (Re-send): node 1 takes a grant and leaves it unaccepted; node
// 2, away past the inbox blob's lifetime, never learns it.
#[test]
fn an_unaccepted_grant_expires_for_a_node_away_past_inbox_lifetime_spec_sync_inbox_5() {
    assert_eq!(away_past_inbox_lifetime(false), (false, false));
}

/// Node 0 (account A) grants sync on a thing it made to account B (nodes 1 and 2) that never
/// imported A's card, so A is no connected author there; the grant waits as an invitation.
fn sync_grant_from_a_stranger() -> (World, osis_base::Tid, osis_base::SyncId, usize) {
    let mut w = World::new(0);
    w.add_node();
    w.add_node();
    let n2 = w.pair(1);
    w.run();
    // A learns B's keys by hand and finds node 1 on the LAN: no role of A's anywhere B syncs
    crate::harness::history::hand(&mut w, 1, 0);
    w.discover(0, 1);
    w.run();
    let (a0, b) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a0);
        m.set(t, &Ak::new("u:v.0").unwrap(), &Value::Str("x".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    file(&mut w, 0, vec![t], Vec::new());
    w.write(0, |e| e.grant(&t, &b, &edge(Role::Sync))).unwrap();
    w.run();
    let s = w.engine(0).home_sync_id(&t).unwrap().unwrap();
    for i in [1, n2] {
        let inv = w.engine(i).invitations().unwrap();
        assert!(inv.iter().any(|x| x.thing == t && !x.taken && x.role == Role::Sync), "node {i}: an invite request: {inv:?}");
    }
    (w, t, s, n2)
}

// spec/sync-inbox.md §2 Taking (the user accepted it; a writer of the inbox stamped it: Stamping
// in place), spec/sync-set.md §4 (accepting): a sync grant by an author not connected at the
// recipient is an invite request at both of its account's nodes; the user accepts it on node 1,
// which takes it whole (its sync ID) and stamps it in its inbox; node 2 takes the stamped blob
// whole too: both keep the thing unread under the granter's sync ID.
#[test]
fn a_sync_grant_accepted_on_one_node_is_taken_at_its_sibling_spec_sync_inbox_2() {
    let (mut w, t, s, n2) = sync_grant_from_a_stranger();
    file(&mut w, 1, Vec::new(), vec![t]);
    w.run();
    for i in [1, n2] {
        assert_eq!(w.engine(i).thing_sync(&t).unwrap(), osis_engine::sync::ThingSync::Unread(vec![s]), "node {i}");
    }
}

// spec/permissions.md §2 (Finalize: before the next commit encrypting under the target),
// spec/crypto.md §4 (Encrypting under), spec/crypto.md §4 (encrypt under covering epoch),
// spec/permissions.md §3 (required rotation): a reader's `until` passes with no write at all; node 0's
// step finalizes it with the rotation at the wake, so the departed reader reads nothing written
// after. (A run moves the clock only within its horizon, so the `until` lies beyond it.)
#[test]
fn a_passed_until_rotates_at_its_wake_spec_permissions_2() {
    let mut w = contacts();
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let set = |w: &mut World, t: Option<osis_base::Tid>, v: &str| {
        w.write(0, |e| {
            let mut m = Mutation::new();
            let t = t.unwrap_or_else(|| e.new_thing(&mut m, a0));
            m.set(t, &ak, &Value::Str(v.into())).unwrap();
            e.commit(m).unwrap();
            t
        })
    };
    let t = set(&mut w, None, "before");
    file(&mut w, 0, vec![t], Vec::new());
    let until = osis_base::WallMs(w.now().0 + 10 * w.horizon_ms);
    w.write(0, |e| e.grant(&t, &a1, &ct::Edge { until: Some(until), ..edge(Role::Read) })).unwrap();
    w.run();
    file(&mut w, 1, Vec::new(), vec![t]);
    w.run();
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), Some(Value::Str("before".into())));
    let read = |w: &mut World| w.engine(0).epochs(&t).unwrap().role(Role::Read).newest_secret().unwrap().0;
    let e0 = read(&mut w);
    let at = 20 * w.horizon_ms;
    w.advance(at);
    assert_ne!(read(&mut w), e0, "rotated at the wake, before any write");
    set(&mut w, Some(t), "after");
    w.run();
    assert_ne!(w.engine(1).get(&t, &ak).unwrap(), Some(Value::Str("after".into())), "the departed reader reads nothing new");
}

// spec/permissions.md §2 (tied edge removed): a node holding a current tied grant (G, T) whose
// element is dead in G's `group.0` removes the edge when it may: node 0, admin of both, takes t
// out of g with g's tied write grant on t standing; after a complete pass of t's sync ID (node 2
// reads t) the edge is gone at both nodes.
#[test]
fn a_dead_tie_is_removed_after_a_pass_spec_permissions_2() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, world};
    let mut w = world(0, 3);
    w.cap = 20_000;
    let _ = crate::harness::play(&mut w, &[New(0), New(0), Grant(0, 1, 2, Gives::Reads), Run], String::new());
    let (g, t) = (w.history.things[0].0, w.history.things[1].0);
    w.write(0, |e| {
        e.give_own_secrets(&g).unwrap();
        let mut x = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
        x.items.insert(t);
        let mut m = Mutation::new();
        m.set(g, &ct::GROUP, &x).unwrap();
        e.commit(m).unwrap();
        let tie = e.placement(&t, &g, false).unwrap().unwrap();
        e.grant(&t, &g, &ct::Edge { tied: Some(osis_engine::flows::tied::tie_ct(tie)), ..edge(Role::Write) }).unwrap();
    });
    w.run();
    assert!(w.engine(2).roster(&t).contains_key(&g), "the tied grant reached node 2");
    w.write(0, |e| {
        let mut x = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
        x.items.retain(|y| *y != t);
        let mut m = Mutation::new();
        m.set(g, &ct::GROUP, &x).unwrap();
        e.commit(m).unwrap();
        assert!(e.tied_unplaced(&Default::default(), &Default::default(), true).unwrap().contains(&(t, g)), "the tie is dead");
    });
    w.run();
    w.advance(60_000);
    w.run();
    for i in [0, 2] {
        assert!(!w.engine(i).roster(&t).contains_key(&g), "node {i}: g's tied edge on t stands");
    }
}

// spec/permissions.md §3 (removal logged first): a node that removes a holder logs the removal,
// in the same sync and before anything else it logs, under every sync ID the removed party could
// read. Node 0 writes t, then removes node 2's account from t, before its sync steps: the
// removal's entry under S is logged before the write's.
#[test]
#[ignore = "issues/removal-not-logged-first.md"]
fn repro_a_removal_is_logged_before_what_was_written_before_it_spec_permissions_3() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, value_ak, world};
    let mut w = world(0, 3);
    w.cap = 20_000;
    let _ = crate::harness::play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).home_sync_id(&t).unwrap().unwrap();
    let a2 = w.node(2).account.unwrap();
    // both written before node 0's sync next steps: one sync logs both
    let (c, r) = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("before the removal".into())).unwrap();
        let c = e.commit(m).unwrap().unwrap();
        (c, e.demote(&t, &Demotion { holder: a2, new: None, retain: None }).unwrap().commits[0])
    });
    w.run();
    let at = |w: &mut World, x: osis_base::CommitId| {
        let es = w.store(0).entries(&s).unwrap();
        let b = es.into_iter().find(|e| w.engine(0).blob_commit(&e.blob).ok().flatten() == Some(x)).expect("an own entry under S").blob;
        w.store(0).first_logged(&s, &b).unwrap().expect("logged")
    };
    let (pc, pr) = (at(&mut w, c), at(&mut w, r));
    assert!(pr < pc, "the removal ({pr:?}) logged before the write ({pc:?})");
}

// spec/sync-set.md §3 (One rule ends syncing it: a complete pass after it left first, then the rules apply): node 0 removes
// node 1's account from a thing node 1 reads, then writes; node 1 syncs S one more pass after the
// removal reaches it, opens nothing written after, and then stops syncing S.
#[test]
fn a_removed_reader_opens_nothing_after_and_stops_spec_sync_set_3() {
    let mut w = contacts();
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let set = |w: &mut World, t: Option<osis_base::Tid>, v: &str| {
        w.write(0, |e| {
            let mut m = Mutation::new();
            let t = t.unwrap_or_else(|| e.new_thing(&mut m, a0));
            m.set(t, &ak, &Value::Str(v.into())).unwrap();
            e.commit(m).unwrap();
            t
        })
    };
    let t = set(&mut w, None, "before");
    file(&mut w, 0, vec![t], Vec::new());
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Read))).unwrap();
    w.run();
    file(&mut w, 1, Vec::new(), vec![t]);
    w.run();
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), Some(Value::Str("before".into())));
    let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
    assert!(w.store(1).synced(&s).is_some());
    w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap();
    set(&mut w, Some(t), "after");
    w.run();
    assert_ne!(w.engine(1).get(&t, &ak).unwrap(), Some(Value::Str("after".into())), "nothing written after the removal");
    assert!(w.store(1).synced(&s).is_none(), "S synced no more once its pass ended");
}

// spec/sync-set.md §2 (key home): node 0 files X (its secrets derive from group Y) in group G,
// which reads Y by role; node 1's account reads G and Y. While node 1 is away, node 0 writes X
// and removes G from Y: G's sync ID carries X no more, but Y's carries it, listed nowhere under Y
// (X's key home is Y). Node 1 gets that write and a later one under Y's sync ID.
#[test]
fn a_thing_read_through_its_key_home_arrives_listed_nowhere_there_spec_sync_set_2() {
    let mut w = contacts();
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let (g, y, x) = w.write(0, |e| {
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, a0);
        let y = e.new_thing(&mut m, a0);
        e.commit(m).unwrap();
        e.give_own_secrets(&g).unwrap();
        e.give_own_secrets(&y).unwrap();
        let mut m = Mutation::new();
        let x = e.new_thing(&mut m, y);
        m.set(x, &ak, &Value::Str("before".into())).unwrap();
        let mut items = ct::Group::default();
        items.items.insert(x);
        m.set(g, &ct::GROUP, &items).unwrap();
        e.commit(m).unwrap();
        e.grant(&y, &g, &edge(Role::Read)).unwrap();
        e.grant(&g, &a1, &edge(Role::Read)).unwrap();
        e.grant(&y, &a1, &edge(Role::Read)).unwrap();
        (g, y, x)
    });
    file(&mut w, 0, Vec::new(), vec![g, y]);
    w.run();
    file(&mut w, 1, Vec::new(), vec![g, y]);
    w.run();
    assert_eq!(w.engine(1).get(&x, &ak).unwrap(), Some(Value::Str("before".into())), "node 1 reads X");
    w.partition(0, 1);
    let write = |w: &mut World, v: &str| {
        w.write(0, |e| {
            let mut m = Mutation::new();
            m.set(x, &ak, &Value::Str(v.into())).unwrap();
            e.commit(m).unwrap();
        })
    };
    write(&mut w, "after");
    w.write(0, |e| e.demote(&y, &Demotion { holder: g, new: None, retain: None })).unwrap();
    w.run();
    assert!(!w.engine(0).reads_in(&g, &x), "G reads X no more");
    w.heal();
    w.run();
    assert_eq!(w.engine(1).get(&x, &ak).unwrap(), Some(Value::Str("after".into())), "the write before the removal arrives");
    write(&mut w, "later");
    w.run();
    assert_eq!(w.engine(1).get(&x, &ak).unwrap(), Some(Value::Str("later".into())), "a later write arrives");
}

// spec/sync-set.md §2 (key home), spec/permissions.md §3 (Own secrets add only): node 1 files Y
// (as a subgroup, or as an item) and reads it; X (made under Y) and C (made under X) are listed
// nowhere and reach node 1 under Y's sync ID. X then gets secrets of its own: both stay under Y's
// sync ID and C goes under X's own too, which node 1 syncs through Y either way; both keep
// arriving.
#[test]
fn dependants_keep_arriving_when_their_key_home_moves_spec_sync_set_2() {
    keep_arriving(false);
    keep_arriving(true);
}

fn keep_arriving(as_item: bool) {
    let mut w = contacts();
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let (y, x, c) = w.write(0, |e| {
        let mut m = Mutation::new();
        let y = e.new_thing(&mut m, a0);
        e.commit(m).unwrap();
        e.give_own_secrets(&y).unwrap();
        let mut m = Mutation::new();
        let x = e.new_thing(&mut m, y);
        let c = e.new_thing(&mut m, x);
        m.set(x, &ak, &Value::Str("x".into())).unwrap();
        m.set(c, &ak, &Value::Str("c".into())).unwrap();
        e.commit(m).unwrap();
        e.grant(&y, &a1, &edge(Role::Read)).unwrap();
        (y, x, c)
    });
    file(&mut w, 0, Vec::new(), vec![y]);
    w.run();
    if as_item {
        file(&mut w, 1, vec![y], Vec::new());
    } else {
        file(&mut w, 1, Vec::new(), vec![y]);
    }
    w.run();
    let reads = |w: &mut World, v: [&str; 2]| [x, c].map(|t| w.engine(1).get(&t, &ak).unwrap()) == v.map(|s| Some(Value::Str(s.into())));
    assert!(reads(&mut w, ["x", "c"]), "X and C arrive under Y's sync ID (Y an item: {as_item})");
    w.write(0, |e| e.give_own_secrets(&x)).unwrap();
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(x, &ak, &Value::Str("x2".into())).unwrap();
        m.set(c, &ak, &Value::Str("c2".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert!(reads(&mut w, ["x2", "c2"]), "both arrive after X has secrets of its own (Y an item: {as_item})");
}

// spec/sync-judgement.md §2 (required set: a certificate blob is in it by the chain certificates
// of an author of a body under S it carries, the same at every node), spec/permissions.md §4
// (Chain certificates: every line of an account's signing chain): writers of two accounts each
// log their own account's certificates under the thing's sync ID as copies; through role
// changes, each account's rotation (a node paired and removed) and the thing filed in a group
// and out again, each followed by complete passes, neither node drops or deletes a copy of the
// other's (no tombstone of one at either node), both judge every copy either holds, of both
// accounts, inside S's required set, and both stores hold copies of the same bodies, each
// account's rotations among them.
#[test]
fn writers_of_two_accounts_keep_each_others_certificates_spec_sync_judgement_2() {
    let (mut w, t, ak) = granted_and_read(Role::Write);
    let s = w.engine(0).sync_ids(&t).unwrap()[0].id;
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let write = |w: &mut World, i: usize, v: &str| {
        w.write(i, |e| {
            let mut m = Mutation::new();
            m.set(t, &ak, &Value::Str(v.into())).unwrap();
            e.commit(m).unwrap();
        })
    };
    // the certificate copies node i holds under S, whoever logged them (a copy as the node that
    // opened or sealed it knows it)
    let copies = |w: &mut World, i: usize| -> std::collections::BTreeSet<osis_base::BlobId> {
        let held: Vec<osis_base::BlobId> = w.store(i).entries(&s).unwrap().iter().map(|e| e.blob).collect();
        held.into_iter().filter(|b| (0..2).any(|j| w.engine(j).blob_of(b).unwrap().is_some_and(|x| x.copy))).collect()
    };
    let mut ever = std::collections::BTreeSet::new();
    let mut settle = |w: &mut World, step: &str| {
        w.run();
        // two passes: a copy a rotation leaves unnamed (an old card, an old line's part) goes a
        // pass after the rotation's copies arrive
        for _ in 0..2 {
            w.advance(osis_proto::limits::PASS_WAIT_MS + 1);
            w.run();
        }
        let (c0, c1) = (copies(w, 0), copies(w, 1));
        ever.extend(c0.iter().chain(&c1).copied());
        // the same bodies: two nodes may each log a copy of one at once (a header-only copy of
        // a line both find unnamed past one pass), each a fresh encryption
        let bodies = |w: &mut World, cs: &std::collections::BTreeSet<osis_base::BlobId>| -> std::collections::BTreeSet<(osis_base::CommitId, Vec<usize>)> {
            let e = w.engine(0);
            cs.iter().map(|b| (e.blob_commit(b).unwrap().unwrap(), e.blob_parts(b).unwrap().unwrap_or_default().into_iter().collect())).collect()
        };
        let (b0, b1) = (bodies(w, &c0), bodies(w, &c1));
        assert_eq!(b0, b1, "{step}: both stores hold copies of the same certificate bodies");
        let mut authors = std::collections::BTreeSet::new();
        for b in c0.iter().chain(&c1) {
            // one judgement of the blob at both nodes: in S's required set
            for i in 0..2 {
                let e = w.engine(i);
                let c = e.blob_commit(b).unwrap().unwrap();
                assert!(e.body_facts(&s, &c).unwrap().required, "{step}: node {i} judges a copy outside the required set");
                authors.insert(e.header(&c).unwrap().author);
            }
        }
        assert!(authors.contains(&a0) && authors.contains(&a1), "{step}: copies of both accounts' chains: {authors:?}");
        for b in &ever {
            for j in 0..2 {
                assert!(w.store(j).tombstone(&s, b).unwrap().is_none(), "{step}: node {j} dropped or deleted a certificate copy");
            }
        }
    };
    write(&mut w, 1, "y");
    settle(&mut w, "both written");
    w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: Some(edge(Role::Read)), retain: None })).unwrap();
    w.run();
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Write))).unwrap();
    w.run();
    write(&mut w, 1, "z");
    settle(&mut w, "lowered and raised");
    for i in [1, 0] {
        let n = w.pair(i);
        w.run();
        let (node, d) = (w.engine(n).tid(), w.engine(i).account().unwrap().unwrap().1);
        w.write(i, |e| e.demote(&d, &Demotion { holder: node, new: None, retain: None })).unwrap();
        w.power_off(n);
        write(&mut w, i, &format!("after {i} rotated"));
        settle(&mut w, &format!("account {i} rotated"));
    }
    // every line of each writer's signing chain is in S's required set at both nodes, whichever
    // account's it is
    for (a, i) in [(a0, 0), (a1, 1)] {
        for r in w.engine(i).account_rotations(&a) {
            for j in 0..2 {
                assert!(w.engine(j).body_facts(&s, &r).unwrap().required, "node {j}: a rotation of account {i} outside S's required set");
                let blobs: Vec<osis_base::BlobId> = (0..2).flat_map(|k| w.engine(k).commit_blobs(&r).unwrap().iter().copied().collect::<Vec<_>>()).collect();
                assert!(blobs.iter().any(|b| w.store(j).entry(&s, b).ok().flatten().is_some()), "node {j}: a rotation of account {i} not held under S");
            }
        }
    }
    let rots = [w.engine(0).account_rotations(&a1).len(), w.engine(1).account_rotations(&a0).len(), w.engine(1).account_rotations(&a1).len(), w.engine(0).account_rotations(&a0).len()];
    assert!(rots[0] >= 1 && rots[0] == rots[2] && rots[1] >= 1 && rots[1] == rots[3], "each account rotated, seen at the other: {rots:?}");
    let g = w.write(0, |e| {
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, a0);
        m.set(g, &ct::GROUP, &ct::Group { items: [t].into(), ..Default::default() }).unwrap();
        e.commit(m).unwrap();
        g
    });
    file(&mut w, 0, vec![g], Vec::new());
    write(&mut w, 1, "in a group");
    settle(&mut w, "filed in a group");
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
        e.commit(m).unwrap();
    });
    settle(&mut w, "unfiled");
}

// spec/permissions.md §4 (a commit's author's chain: to each thing it writes and to its actor),
// §5.2 (Acting), spec/sync-judgement.md §2 (required set): node 2's team Y grants node 1's
// account X write; X writes node 0's thing T, on which Y holds no role, acting for Y. Node 0
// reads T alone (nothing of Y): X's chain to Y travels under T's sync ID, so node 0 reads the
// write as node 1 does, after a restart too; Y removing X travels the same way and both read
// the write gone. `late`: node 0 is off while X writes and catches up afterwards.
fn acting_for_an_actor_off_the_path(late: bool) {
    let mut w = crate::harness::history::world(0, 3);
    let (a0, a1, a2) = (w.node(0).account.unwrap(), w.node(1).account.unwrap(), w.node(2).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let new = |w: &mut World, i: usize, a: osis_base::Tid| {
        w.write(i, |e| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a);
            m.set(t, &ak, &Value::Str("x".into())).unwrap();
            e.commit(m).unwrap();
            t
        })
    };
    let y = new(&mut w, 2, a2);
    file(&mut w, 2, vec![y], Vec::new());
    w.write(2, |e| e.grant(&y, &a1, &edge(Role::Write))).unwrap();
    let t = new(&mut w, 0, a0);
    file(&mut w, 0, vec![t], Vec::new());
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Write))).unwrap();
    w.run();
    file(&mut w, 1, Vec::new(), vec![y, t]);
    w.run();
    assert!(!w.engine(0).sync_set().unwrap().ids.values().any(|(x, _)| *x == y), "node 0 syncs nothing of Y");
    let read = |w: &mut World, i: usize| w.engine(i).get(&t, &ak).unwrap();
    let settle = |w: &mut World| {
        w.run();
        for _ in 0..2 {
            w.advance(osis_proto::limits::PASS_WAIT_MS + 1);
            w.run();
        }
    };
    if late {
        w.power_off(0);
    }
    w.write(1, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("as y".into())).unwrap();
        m.act_as(y);
        e.commit(m).unwrap();
    });
    w.power_on(0);
    settle(&mut w);
    let as_y = Some(Value::Str("as y".into()));
    assert_eq!(read(&mut w, 1), as_y, "node 1 reads X's write for Y");
    assert_eq!(read(&mut w, 0), as_y, "node 0, reading T alone, judges X's write for Y as node 1 does");
    w.power_off(0);
    w.power_on(0);
    settle(&mut w);
    assert_eq!(read(&mut w, 0), as_y, "after a restart");
    w.write(2, |e| e.demote(&y, &Demotion { holder: a1, new: None, retain: None })).unwrap();
    settle(&mut w);
    let x = Some(Value::Str("x".into()));
    assert_eq!(read(&mut w, 1), x, "X acts for Y no more: its write is invalid at node 1");
    assert_eq!(read(&mut w, 0), x, "and at node 0, by Y's demotion under T's sync ID");
}

// spec/permissions.md §4, §5.2, spec/sync-judgement.md §2: `acting_for_an_actor_off_the_path`, node 0 online.
#[test]
fn a_write_acting_off_the_path_is_judged_alike_spec_permissions_5_2() {
    acting_for_an_actor_off_the_path(false);
}

// spec/permissions.md §4, §5.2, spec/sync-judgement.md §2: `acting_for_an_actor_off_the_path`, node 0 off while X writes.
#[test]
fn a_write_acting_off_the_path_is_judged_alike_late_spec_permissions_5_2() {
    acting_for_an_actor_off_the_path(true);
}

// spec/permissions.md §4 (Chain certificates: an account's current `keys.0` commits with their
// `keys.0` part, its other rotations, every line, as header-only copies), §5.5 (Chains travel),
// spec/sync-judgement.md §2 (required set: a header-only copy of a rotation): after a writer's
// account rotates twice, every node reading S holds the old rotation under S as header-only
// copies alone and the current one with its `keys.0` part (no old epoch's deposit seed under S;
// a copy logged while its rotation was current leaves once it is not), a fresh reader of S among
// them, cut off while the rotations were current; it verifies the rotation signed at the closed
// epoch and holds no old rotation's `keys.0` part (no old deposit seed reaches a non-member).
#[test]
fn old_rotation_lines_go_as_headers_alone_spec_permissions_4() {
    let mut w = crate::harness::history::world(0, 3);
    let (a0, a1, a2) = (w.node(0).account.unwrap(), w.node(1).account.unwrap(), w.node(2).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a0);
        m.set(t, &ak, &Value::Str("x".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    file(&mut w, 0, vec![t], Vec::new());
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Write))).unwrap();
    w.run();
    file(&mut w, 1, Vec::new(), vec![t]);
    w.run();
    // a content write at the first epoch, which the first rotation closes and lists under S
    let c = w.write(1, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("y".into())).unwrap();
        e.commit(m).unwrap()
    }).unwrap();
    w.run();
    // two rotations, the second signed at the epoch the first mints; each goes under every sync
    // ID the account acts in, streamed by every node on both connections of each pair (about
    // 1 000 deliveries each)
    // node 2, cut off meanwhile, sees none of them while current (its dials toward both add up)
    w.cap = 5 * crate::harness::RULE_CAP;
    w.partition(0, 2);
    w.partition(1, 2);
    for _ in 0..2 {
        w.write(1, |e| e.rotate_account(&a1)).unwrap().expect("rotated");
        w.run();
    }
    w.advance(osis_proto::limits::PASS_WAIT_MS + 1);
    w.run();
    w.heal();
    let s = w.engine(0).sync_ids(&t).unwrap()[0].id;
    let rots = w.engine(1).account_rotations(&a1);
    let current = w.engine(1).current_keys(&a1);
    assert_eq!(rots.len(), 2, "two rotations");
    assert_eq!(rots.iter().filter(|r| current.contains(r)).count(), 1, "one current rotation");
    // a fresh reader of S verifies the rotation signed at the closed epoch by the header of the
    // rotation minting it
    w.write(0, |e| e.grant(&t, &a2, &edge(Role::Read))).unwrap();
    w.run();
    file(&mut w, 2, Vec::new(), vec![t]);
    w.run();
    assert!(w.engine(2).sync_ids(&t).unwrap().iter().any(|x| x.id == s), "the fresh reader reads S");
    let pending: Vec<osis_base::CommitId> = w.engine(2).pending().into_iter().map(|x| x.0).collect();
    for r in &rots {
        let e = w.engine(2);
        assert!(e.header(r).is_some() && !pending.contains(r), "a rotation signed at an old epoch verifies at a fresh reader");
    }
    // the fresh reader, no node of the account, holds the current deposit seed and no old one:
    // an old rotation's `keys.0` part never reached it
    let missing = w.engine(2).commit_parts_missing();
    for r in &rots {
        let h = w.engine(2).header(r).unwrap();
        let ai = h.aspects.iter().position(|x| x.tid == a1 && x.ak.as_str() == "keys.0").expect("a rotation writes keys.0");
        let held = !missing.get(r).is_some_and(|m| m.contains(&ai));
        assert_eq!(held, current.contains(r), "fresh reader: {r:?}'s keys.0 part held iff the rotation is current");
    }
    w.advance(osis_proto::limits::PASS_WAIT_MS + 1);
    w.run();
    // the rotator's thing list for T naming the write at the closed epoch is held at every
    // reader of S (spec/permissions.md §5.5 Rotation's list; spec/sync-judgement.md §1 List
    // blobs), so the write counts where it is held (§5.5 Epoch rule): its node proved its account
    // again after rotating, so S stays shared with it (spec/sync-opens.md §1, §2). The fresh
    // reader may hold only the later commit covering it.
    let names = |w: &mut World, j: usize| rots.iter().any(|r| w.engine(j).rotation_lists(r).unwrap().iter().any(|(x, cs)| *x == t && cs.contains(&c)));
    for j in 0..3 {
        assert!(names(&mut w, j), "node {j}: no thing list of T naming the write");
    }
    for j in 0..2 {
        assert_eq!(w.engine(j).held_part(&t, &ak, &c, 1 << 20).unwrap().map(|p| p.valid), Some(true), "node {j}: the write at the closed epoch is not valid");
    }
    assert_eq!(w.engine(2).get(&t, &ak).unwrap(), Some(Value::Str("y".into())), "the fresh reader reads the write");
    for j in 0..3 {
        let held: Vec<osis_base::BlobId> = w.store(j).entries(&s).unwrap().iter().map(|e| e.blob).collect();
        for r in &rots {
            let e = w.engine(j);
            let parts: Vec<usize> = held.iter().filter(|b| e.blob_commit(b).unwrap() == Some(*r)).collect::<Vec<_>>().into_iter().map(|b| e.blob_parts(b).unwrap().map_or(0, |p| p.len())).collect();
            assert!(!parts.is_empty(), "node {j}: a rotation not held under S");
            match current.contains(r) {
                true => assert!(parts.iter().any(|n| *n > 0), "node {j}: the current rotation without its keys.0 part under S"),
                false => assert!(parts.iter().all(|n| *n == 0), "node {j}: an old rotation's keys.0 part under S"),
            }
        }
    }
}

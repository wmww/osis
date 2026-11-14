//! Flows between nodes of different accounts end to end through the product's sync, nothing
//! carried by hand after the contact exchange (`introduce`).

use crate::harness::{World, contacts};
use crate::harness::history::file;
use osis_base::{Ak, Role, Value};
use osis_engine::Mutation;
use osis_engine::flows::Demotion;
use osis_sync::types::{Scope, Waiting};
use osis_schema::core_types as ct;

fn edge(role: Role) -> ct::Edge {
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

// spec/sync-inbox.md §2 (Re-send: until seen taken): a grant, its removal and a grant again,
// written before any of them reached the grantee, all reach it: it reads the thing (an open by
// the first grant's read secret does not show the grant again taken). Found by the differential.
#[test]
fn a_grant_again_after_a_removal_reaches_the_grantee_spec_sync_inbox_2() {
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    let mut w = crate::harness::history::world(15, 3);
    w.cap = crate::harness::STORM_CAP;
    let _ = crate::harness::play(&mut w, &[New(2), Grant(2, 0, 1, Gives::Reads), Remove(2, 0, 1), Grant(2, 0, 1, Gives::Reads), Run], String::new());
    crate::harness::history::check(&mut w);
}

// spec/sync-opens.md §3 (`changed_at`: advanced when a role on S changes): a reader removed, then
// granted again after a write it could not read, opens S again (by J: no credential of its own
// moved) and reads that write. Found by the differential.
#[test]
fn a_reader_granted_again_opens_by_its_role_spec_sync_opens_3() {
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    let mut w = crate::harness::history::world(15, 3);
    w.cap = crate::harness::STORM_CAP;
    let _ = crate::harness::play(&mut w, &[New(2), Grant(2, 0, 1, Gives::Reads), Run, Remove(2, 0, 1), Run, Write(2, 0), Grant(2, 0, 1, Gives::Reads), Run], String::new());
    crate::harness::history::check(&mut w);
}

// spec/sync-ids.md §5 (the store is the truth for ciphertext: so after a failure): a write of node 1's whose sync
// failed (its outcome unknown) makes its engine read its store again, which replaces what sync
// follows of it; sync starts again from the store, so a grant node 1 makes later still reaches
// its grantee. Found by the differential.
#[test]
fn sync_follows_an_engine_that_read_its_store_again_spec_sync_ids_5() {
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(15, 3, &[New(2), Disk(1, 0, crate::harness::DiskFault::Unsynced), Grant(2, 0, 1, Gives::Syncs), New(1), New(1), New(1), Grant(1, 3, 2, Gives::Reads)], String::new());
}

// spec/sync-judgement.md §6 (read and unread move: a node raised to read opens what is there): a node keeping S unread, holding a
// write there, raised to read reads it. Found by the differential.
#[test]
fn raised_from_sync_to_read_opens_what_is_held_spec_sync_judgement_6() {
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(5, 3, &[New(2), New(2), Grant(2, 1, 0, Gives::Syncs), Run, Grant(2, 1, 0, Gives::Reads)], String::new());
}

// spec/sync-inbox.md §2 (Re-send): a holder of sync alone, removed and granted read before either
// reached it, reads the thing: its open by its old sync credential does not show the read grant
// taken. Found by the differential.
#[test]
fn a_read_grant_after_a_sync_removal_reaches_the_grantee_spec_sync_inbox_2() {
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(16, 3, &[New(0), New(1), New(0), Grant(0, 2, 1, Gives::Syncs), Run, Remove(0, 2, 1), Grant(0, 2, 1, Gives::Reads)], String::new());
}

// spec/sync-judgement.md §3 (own store), spec/sync-compaction.md §1: a reader removed and
// granted again (no run between) reads the write made while it was removed. Found by the
// differential (clean seed 78): the grantee pulls under its older read secret and opens what it
// kept once the newer one arrives.
#[test]
fn a_reader_granted_again_reads_what_a_snapshot_carries_spec_sync_judgement_3() {
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(78, 3, &[New(0), Write(0, 0), Grant(0, 0, 2, Gives::Reads), Grant(0, 0, 2, Gives::Reads), Remove(0, 0, 2), Write(0, 0), Grant(0, 0, 2, Gives::Reads)], String::new());
}

// spec/sync-inbox.md §2 (Re-send): as above, with a failed write at the grantee (faulty seed 77).
#[test]
fn a_writer_granted_again_after_a_failed_write_reads_spec_sync_inbox_2() {
    use crate::harness::DiskFault::Fail;
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(77, 3, &[New(2), Disk(0, 1, Fail), New(1), New(1), Write(1, 1), Grant(1, 1, 0, Gives::Writes), Remove(1, 1, 0), Grant(1, 1, 0, Gives::Writes)], String::new());
}

// spec/sync-inbox.md §2 (Re-send): as above, the grantee off while it is granted, removed and
// granted again (faulty seed 93).
#[test]
fn a_reader_off_through_a_grant_a_removal_and_a_grant_again_reads_spec_sync_inbox_2() {
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(93, 3, &[New(1), PowerOff(2), Run, Grant(1, 0, 2, Gives::Reads), Remove(1, 0, 2), Grant(1, 0, 2, Gives::Reads)], String::new());
}

// spec/sync-streams.md §4 (Fill order: what does not open is ranked again as secrets arrive): a
// reader granted sync and read, removed, and granted read again after a sync holder's grant (no
// run between) pulls S under its older read secret before the grant boxing the newer one is
// taken; it keeps the entries that did not open and opens them when the secret arrives, so it
// reads the sync holder's edge. Found by the differential (faulty seed 7).
#[test]
fn a_reader_opens_what_it_pulled_before_its_secret_spec_sync_streams_4() {
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(7, 3, &[New(1), Grant(1, 0, 0, Gives::Syncs), Grant(1, 0, 0, Gives::Reads), Remove(1, 0, 0), Grant(1, 0, 2, Gives::Syncs), Grant(1, 0, 0, Gives::Reads)], String::new());
}

// spec/sync-streams.md §4 (Fill order: what does not open is held and opened as secrets arrive):
// a reader granted, removed and granted again while a durable write of its fails reads the value
// (the full-size differential, seed 468073306024 shrunk).
#[test]
fn a_reader_granted_again_through_a_failed_write_reads_spec_sync_streams_4() {
    use crate::harness::DiskFault::Fail;
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(468073306024, 3, &[New(0), Grant(0, 0, 2, Gives::Syncs), Write(0, 0), Disk(1, 20, Fail), Write(0, 0), Remove(0, 0, 2), Grant(0, 0, 1, Gives::Reads), Remove(0, 0, 1), Grant(0, 0, 1, Gives::Reads)], String::new());
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
        let p = osis_label::Prefix::for_keys([7; 16], &[1; 16], None, &[]).unwrap();
        let (_, bytes) = osis_label::frame(&p, &[7; 64], &mut osis_crypto::SeededRng::from_u64(7)).unwrap();
        let b = osis_label::blob_id(&bytes);
        let e = osis_sync::types::Entry { blob: b, wrap: [7; osis_crypto::WRAP_LEN], stamp: None, deposited: true, own: false, role: false, class: osis_label::Class::Durable, expires: None };
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

// spec/commits.md §4 (Unjudgeable: fetched again when what it awaits arrives): a reader granted
// after a writer's removal pulls that writer's last write before the grant that leads from the
// writer to the thing; the engine keeps nothing of it, so sync keeps the entry and opens it
// again once that grant is held, and the new reader reads the write. Found by the full-size
// differential (clean seed 188669321708, shrunk).
#[test]
fn a_reader_granted_after_a_writers_removal_reads_its_last_write_spec_commits_4() {
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(188669321708, 3, &[New(0), New(0), New(0), Grant(0, 2, 1, Gives::Writes), Run, Write(1, 2), Run, Remove(0, 2, 1), Grant(0, 2, 2, Gives::Reads)], String::new());
}

// spec/sync-set.md §3 (On stopping: S dropped from every record in that step): a holder of sync
// alone, removed, then granted read while cut off from its granter, reads the thing once healed.
// The stop shreds S and closes its members in one step; the member leaving after the shred keeps
// no position of S, so S read again is pulled from the start. Found by the full-size
// differential (faulty seed 188669321550, shrunk).
#[test]
fn a_sync_holder_removed_and_granted_read_while_away_reads_spec_sync_set_3() {
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(188669321550, 3, &[New(1), Grant(1, 0, 2, Gives::Syncs), Run, Remove(1, 0, 2), Partition(1, 2), Grant(1, 0, 2, Gives::Reads)], String::new());
}

// spec/sync-ids.md §5 (the store is the truth for ciphertext: so after a failure): a read grant
// whose durable write fails unsynced at the granter (its outcome unknown) stands there, reaches
// the grantee, and the grantee, accepting it (spec/sync-set.md §4), reads the thing. Found by the
// full-size differential (faulty seed 188669321416, shrunk).
#[test]
fn a_reader_granted_through_an_unsynced_write_reads_spec_sync_ids_5() {
    use crate::harness::DiskFault::Unsynced;
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(188669321416, 3, &[New(1), Write(1, 0), Write(1, 0), Write(1, 0), Disk(1, 24, Unsynced), Write(1, 0), Write(1, 0), Grant(1, 0, 0, Gives::Reads)], String::new());
}

// spec/sync-judgement.md §3 (Dropped bodies: a body counting as never received again is fetched
// again where present), spec/requirements.md Convergence: node 0 grants nodes 1 and 2 write; in
// one fresh millisecond node 1 writes v5 and node 0, not having seen it, removes node 1, so both
// carry the same `ts` and their authors' tids order them (here v5 first). Node 2 receives v5
// before the removal and writes an addendum listing it; node 0 drops v5 as invalid on arrival,
// then the addendum makes it valid again and its body counts missing: node 0 fetches it again
// from a source showing it. At quiet the readers (0 and 2) hold the same commits but bodies a
// snapshot held by both covers, and all read v5 (spec/permissions.md §5.2 Addenda; main's engine
// reads the same: core/node/tests/it/validity.rs
// `a_removed_writers_last_write_reads_alike_at_every_holder_spec_perm_5_2`). Under the rule that
// a write at its removal's own `ts` counts as before it and survives exactly when an addendum
// lists it, the value is v5 too: node 2's addendum lists it. Found by the full-size differential
// (clean seed 347110580059, shrunk).
#[test]
fn a_removed_writers_last_write_reads_alike_at_every_holder_spec_sync_judgement_3() {
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    use std::collections::BTreeSet;
    let steps = [New(1), New(0), Write(0, 1), Grant(0, 1, 1, Gives::Writes), Write(0, 1), Grant(0, 1, 2, Gives::Writes), Run, Write(1, 1), Remove(0, 1, 1)];
    crate::convergence::converge(347110580059, 3, &steps, String::new());
    let mut w = crate::harness::history::world(347110580059, 3);
    w.cap = crate::harness::STORM_CAP;
    let _script = crate::harness::play(&mut w, &steps, String::new());
    for s in [Lossy(crate::harness::Loss::NONE), Heal, PowerOn(0), PowerOn(1), PowerOn(2), Run] {
        crate::harness::step(&mut w, &s);
    }
    let t = w.history.things[1].0;
    let v5 = w.history.values["v5"];
    let (alice, bob) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    assert!(bob < alice, "the seed orders v5 before the removal");
    let ak = crate::harness::history::value_ak();
    // node 1 drops what it lost once it holds the removal (spec/permissions.md §3 Lost access),
    // v5 among it when no peer took it first: the readers then read alike without it
    let held = [0, 2].map(|i| w.engine(i).commit_bytes(&v5).unwrap().is_some());
    assert_eq!(held[0], held[1], "both readers hold v5's body, or neither");
    let want = if held[0] { Some(Value::Str("v5".into())) } else { w.engine(0).get(&t, &ak).unwrap() };
    for i in [0, 2] {
        assert_eq!(w.engine(i).get(&t, &ak).unwrap(), want, "node {i} reads alike");
    }
    // the commits on the thing each reader holds; a difference is only a body a snapshot both hold covers
    let on = |w: &mut World, i: usize| -> BTreeSet<_> { w.engine(i).commit_ids().into_iter().filter(|c| w.engine(i).header(c).is_some_and(|h| h.aspects.iter().any(|a| a.tid == t))).collect() };
    let (h0, h2) = (on(&mut w, 0), on(&mut w, 2));
    let snaps: Vec<_> = h0.intersection(&h2).filter_map(|c| w.engine(0).header(c)).filter(|h| h.kind.is_compaction()).map(|h| h.ts).collect();
    for c in h0.symmetric_difference(&h2) {
        let h = w.engine(0).header(c).or_else(|| w.engine(2).header(c)).unwrap();
        assert!(!h.kind.is_role() && !h.kind.is_compaction() && snaps.iter().any(|ts| *ts > h.ts), "readers differ by {c:?}, which no snapshot both hold covers");
    }
}

// spec/sync-inbox.md §2 (Re-send: a commit sealed under an older epoch shows nothing): a sync
// holder raised to write, removed, then granted read again, which writes the thing before it
// takes the grant (a failed durable write of its delays the take, so the granter holds a
// snapshot of that write, stamped after the grant, first), still gets the grant: the snapshot is
// sealed under the epoch from before its removal, so the granter re-sends.
// Found by the full-size differential (faulty seed 347110579992, shrunk).
#[test]
fn a_member_granted_again_writing_before_it_takes_it_reads_it_spec_sync_inbox_2() {
    use crate::harness::DiskFault::Fail;
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(347110579992, 3, &[New(0), Write(0, 0), Grant(0, 0, 1, Gives::Syncs), Run, Grant(0, 0, 1, Gives::Writes), Remove(0, 0, 1), Run, Disk(1, 3, Fail), Grant(0, 0, 1, Gives::Reads), Write(1, 0)], String::new());
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
// holds it. (A wait on the thing also covers node 0's home, which nobody else opens.)
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
    assert_eq!(w.wait(0, Scope::Thing(t)), Waiting::Pending, "node 0's home carries it too, unconnected");
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
#[ignore = "issues/tied-edge-never-removed.md"]
fn repro_a_dead_tie_is_removed_after_a_pass_spec_permissions_2() {
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

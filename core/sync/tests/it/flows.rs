//! Flows between nodes of different accounts end to end through the product's sync, nothing
//! carried by hand after the contact exchange (`introduce`).

use crate::harness::World;
use crate::harness::history::{file, introduce};
use osis_base::{Ak, Role, Value};
use osis_engine::Mutation;
use osis_schema::core_types as ct;

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None }
}

/// Two contacts on one LAN, quiet.
fn contacts() -> World {
    crate::harness::fixture("flows: two contacts", || {
        let mut w = World::new(0);
        w.add_node();
        w.add_node();
        introduce(&mut w);
        w.discover(0, 1);
        w.discover(1, 0);
        w.run();
        w
    })
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

// spec/sync-inbox.md §2 (Re-send: until seen taken): a grant, its removal and a grant again,
// written before any of them reached the grantee, all reach it: it reads the thing (an open by
// the first grant's read secret does not show the grant again taken). Found by the differential.
#[test]
fn a_grant_again_after_a_removal_reaches_the_grantee_spec_sync_inbox_2() {
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    let mut w = crate::harness::history::world(15, 3);
    w.cap = 200_000;
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
    w.cap = 200_000;
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
// differential (clean seed 78); fails: issues/sync-convergence-leftovers.md.
#[test]
#[ignore = "fails: issues/sync-convergence-leftovers.md"]
fn a_reader_granted_again_reads_what_a_snapshot_carries_spec_sync_judgement_3() {
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(78, 3, &[New(0), Write(0, 0), Grant(0, 0, 2, Gives::Reads), Grant(0, 0, 2, Gives::Reads), Remove(0, 0, 2), Write(0, 0), Grant(0, 0, 2, Gives::Reads)], String::new());
}

// spec/sync-inbox.md §2 (Re-send): as above, with a failed write at the grantee (faulty seed 77).
#[test]
#[ignore = "fails: issues/sync-convergence-leftovers.md"]
fn a_writer_granted_again_after_a_failed_write_reads_spec_sync_inbox_2() {
    use crate::harness::DiskFault::Fail;
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(77, 3, &[New(2), Disk(0, 1, Fail), New(1), New(1), Write(1, 1), Grant(1, 1, 0, Gives::Writes), Remove(1, 1, 0), Grant(1, 1, 0, Gives::Writes)], String::new());
}

// spec/sync-inbox.md §2 (Re-send): as above, the grantee off while it is granted, removed and
// granted again (faulty seed 93).
#[test]
#[ignore = "fails: issues/sync-convergence-leftovers.md"]
fn a_reader_off_through_a_grant_a_removal_and_a_grant_again_reads_spec_sync_inbox_2() {
    use crate::harness::Step::*;
    use crate::harness::history::Gives;
    crate::convergence::converge(93, 3, &[New(1), PowerOff(2), Run, Grant(1, 0, 2, Gives::Reads), Remove(1, 0, 2), Grant(1, 0, 2, Gives::Reads)], String::new());
}

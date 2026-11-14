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

// spec/sync-opens.md §3 (`changed_at` advances when a role on S changes): a reader removed, then
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

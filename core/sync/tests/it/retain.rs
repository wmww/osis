//! Retain through sync (spec/permissions.md §3, Retain): a removed holder's node keeping a
//! read-only copy, with the sync IDs that carried it. The copy's own rules (what it reads,
//! refuses, erases) are core/osis/tests/it/retain.rs, on hand-carried commits.

use crate::flows::{edge, granted_and_read};
use crate::harness::{World, fixture_with};
use crate::harness::history::file;
use osis_base::{Ak, BlobId, Role, SyncId, Tid, Value};
use std::collections::BTreeSet;
use osis_engine::Mutation;
use osis_engine::flows::Demotion;

fn cursor() -> Ak {
    Ak::new("u:c+.0").unwrap()
}

/// Node `i` writes `v` at `(t, ak)`, durable or ephemeral.
fn set(w: &mut World, i: usize, t: Tid, ak: &Ak, v: &str, durable: bool) {
    w.write(i, |e| {
        let mut m = Mutation::new();
        m.set(t, ak, &Value::Str(v.into())).unwrap();
        if durable {
            e.commit(m).unwrap();
        } else {
            e.write(m).unwrap();
        }
    });
}

fn val(v: &str) -> Option<Value> {
    Some(Value::Str(v.into()))
}

// spec/permissions.md §3 (Retain: a read-only copy; a later part on it is not joined; It
// retains only while the node has H): node 1's account, reading t ("x"), is removed saying
// retain; node 0 then writes t durable and ephemeral. Node 1 keeps reading t as it was, takes
// neither write, and holds no entry of t's sync ID to serve.
#[test]
fn a_copy_takes_nothing_new_and_holds_nothing_to_serve_spec_permissions_3() {
    let (mut w, t, ak) = granted_and_read(Role::Read);
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: Some(true) })).unwrap();
    w.run();
    set(&mut w, 0, t, &ak, "y", true);
    set(&mut w, 0, t, &cursor(), "here", false);
    w.run();
    let s = w.engine(0).sync_ids(&t).unwrap()[0].id;
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), val("x"), "node 1 reads its copy");
    assert_eq!(w.engine(1).get(&t, &cursor()).unwrap(), None, "the ephemeral write reaches no copy");
    assert!(w.store(1).entries(&s).unwrap().is_empty(), "node 1 holds no entry of S");
}

/// `granted_and_read`, with node 1's team T (node 0's account reads it) granted sync on t, then
/// node 1's account removed from t saying retain: node 1 keeps a copy and keeps t's sync ID S
/// unread through T. Node 0 then writes t durable ("y") and ephemeral (its cursor). Built once.
/// (world, t, ak, S, node 1's own entries of S before the removal)
fn copy_kept_unread() -> (World, Tid, Ak, SyncId, BTreeSet<BlobId>) {
    let (w, x) = fixture_with("retain copy kept unread", || {
        let (mut w, t, ak) = granted_and_read(Role::Read);
        let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
        let team = w.write(1, |e| {
            let mut m = Mutation::new();
            let x = e.new_thing(&mut m, a1);
            e.commit(m).unwrap();
            x
        });
        file(&mut w, 1, vec![team], Vec::new());
        w.write(1, |e| e.grant(&team, &a0, &edge(Role::Read))).unwrap();
        w.run();
        file(&mut w, 0, Vec::new(), vec![team]);
        w.run();
        w.write(0, |e| e.grant(&t, &team, &edge(Role::Sync))).unwrap();
        w.run();
        let s = w.engine(0).sync_ids(&t).unwrap()[0].id;
        let own = own_entries(&w, 1, &s);
        w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: Some(true) })).unwrap();
        w.run();
        set(&mut w, 0, t, &ak, "y", true);
        set(&mut w, 0, t, &cursor(), "here", false);
        w.run();
        (w, (t, ak, s, own))
    });
    let (t, ak, s, own) = x;
    (w, t, ak, s, own)
}

fn own_entries(w: &World, i: usize, s: &SyncId) -> BTreeSet<BlobId> {
    w.store(i).entries(s).unwrap().into_iter().filter(|e| e.own).map(|e| e.blob).collect()
}

// spec/permissions.md §3 (Lost access: a node holding sync keeps its store of the actor's sync
// IDs, kept unread; Retain: a later part on the copy is not joined; It retains only while the
// node has H), spec/sync-judgement.md §6: node 1, a copy kept unread through T, holds the
// writes made after its removal, durable and ephemeral, and reads neither; it logs nothing of
// the copy.
#[test]
fn a_copy_kept_unread_holds_later_writes_unread_spec_permissions_3() {
    let (mut w, t, ak, s, own) = copy_kept_unread();
    let held = |w: &World, i: usize| w.store(i).entries(&s).unwrap().len();
    let n0 = held(&w, 0);
    assert_eq!(held(&w, 1), n0, "node 1 holds every entry of S node 0 holds");
    assert_eq!(w.engine(1).sync_holder(&s).unwrap().map(|h| h.1), Some(osis_engine::sync::Holding::Unread));
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), val("x"), "node 1 reads its copy");
    assert_eq!(w.engine(1).get(&t, &cursor()).unwrap(), None);
    assert_eq!(own_entries(&w, 1, &s), own, "node 1 logs nothing of the copy");
}

// spec/permissions.md §3 (Retain: a role on A with a secret of it again ends the copy),
// spec/sync-judgement.md §6 (Read and unread move): node 1, a copy kept unread, granted read
// again, reads the durable and the ephemeral write it held unread.
#[test]
fn a_copy_kept_unread_granted_again_reads_what_it_held_spec_permissions_3() {
    let (mut w, t, ak, _, _) = copy_kept_unread();
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Read))).unwrap();
    w.flush();
    w.partition(0, 1);
    file(&mut w, 1, Vec::new(), vec![t]);
    w.flush();
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), val("y"), "from what node 1 held");
    assert_eq!(w.engine(1).get(&t, &cursor()).unwrap(), val("here"));
}

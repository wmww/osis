//! More of the sharing and sync surface through blind servers in process (notes/api.md Sharing
//! and membership, Sync configuration and status, Diagnostics), no tokio: see common/world.rs.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis::internals::Internals as _;
use crate::common;
use common::world::World;
use common::*;
use crate::common::CreateIn;
use osis::{Demotion, DiagnosticKind, Error, Lower, Osis, Role, SyncScope, SyncState, Tid, Value, WaitForSync};
use std::time::Duration;

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn item(db: &Osis, owner: Tid, g: Tid, v: &str) -> Tid {
    let mut w = db.write();
    let t = w.create_in(owner, &[g]).unwrap();
    w.at(t, ak("/t/x")).set(&s(v)).unwrap();
    w.commit().unwrap();
    t
}

fn x(db: &Osis, t: Tid) -> Option<Value> {
    db.get(t, ak("/t/x")).unwrap()
}

fn group(db: &Osis) -> Tid {
    let mut w = db.write();
    let g = w.create_in(db.me(), &[db.home()]).unwrap();
    w.make_group(g).unwrap();
    w.commit().unwrap();
    db.sync(g, &[]).unwrap();
    g
}

/// Alice and Bob on one server, Bob granted `role` on Alice's synced group.
fn alice_bob(w: &mut World, role: Role) -> (Osis, Osis, Tid) {
    let sv = w.add_server();
    let (alice, _) = w.person(1, &[sv]);
    let (bob, _) = w.person(2, &[sv]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let g = group(&alice);
    alice.grant(g, b, role, Default::default()).unwrap();
    w.run();
    (alice, bob, g)
}

/// Diagnostics of `kind` a database reports from now on.
fn diags(db: &Osis, kind: DiagnosticKind) -> std::sync::mpsc::Receiver<Vec<Tid>> {
    let (tx, rx) = std::sync::mpsc::channel();
    db.on_diagnostic(move |_, d| {
        if d.kind == kind {
            let _ = tx.send(d.tids);
        }
    })
    .detach();
    rx
}

// notes/api.md Sharing (change_edge, leave), spec/permissions.md §2: a raise is a change, a
// lower role is refused there (`demote`); a member's self-removal reaches the admin.
#[test]
fn change_edge_and_leave_spec_permissions_2() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Read);
    assert_eq!(bob.role_on(g), Some(Role::Read));
    alice.change_edge(g, bob.me(), Role::Write, Default::default()).unwrap();
    assert!(matches!(alice.change_edge(g, bob.me(), Role::Read, Default::default()), Err(Error::Invalid(_))));
    w.run();
    assert_eq!(bob.role_on(g), Some(Role::Write));
    let u = item(&bob, g, g, "as a writer");
    w.run();
    assert_eq!(x(&alice, u), Some(s("as a writer")));
    bob.leave(g).unwrap();
    w.run();
    assert!(!alice.roster(g).contains_key(&bob.me()));
    assert_eq!(bob.role_on(g), None);
}

// notes/api.md Sharing (revoke_link), spec/permissions.md §9: revoking a multi-use link removes
// its key; `links` no longer lists it.
#[test]
fn revoke_link_spec_permissions_9() {
    let mut w = World::new();
    let sv = w.add_server();
    let (alice, _) = w.person(1, &[sv]);
    let g = group(&alice);
    alice.make_link(g, Role::Read, Default::default()).unwrap();
    let ls = alice.links(g);
    assert_eq!(ls.len(), 1);
    assert!(!ls[0].single_use);
    w.run();
    w.until(alice.revoke_link(ls[0].id, Demotion { sync: WaitForSync::Skip, backdate: None }), 1000, 5).unwrap();
    assert!(alice.links(g).is_empty());
}

// spec/permissions.md §5.3, notes/api.md Demotion: offline, `Required` fails `Unsynced` after
// `PRESYNC_WAIT`; `Try` proceeds after its timeout with an `Unsynced` diagnostic.
#[test]
fn demotion_presync_policies_spec_permissions_5_3() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Write);
    item(&bob, g, g, "bob wrote");
    w.run();
    w.set_online(&alice, false);
    let r = w.until(alice.demote(g, bob.me(), Lower::Remove, Demotion::default()), 10_000, 10);
    assert!(matches!(r, Err(Error::Unsynced { ref groups }) if groups.contains(&g)), "{r:?}");
    assert!(alice.roster(g).contains_key(&bob.me()), "nothing stamped");
    let unsynced = diags(&alice, DiagnosticKind::Unsynced);
    let t = Demotion { sync: WaitForSync::Try(Duration::from_secs(5)), backdate: None };
    w.until(alice.demote(g, bob.me(), Lower::To(Role::Read), t), 1000, 10).unwrap();
    assert_eq!(alice.roster(g).get(&bob.me()).map(|e| e.role), Some(Role::Read));
    assert!(recv(&unsynced).contains(&g));
}

// notes/api.md Sync status (watch_status, Stranded), Diagnostics: a watcher sees the home group
// synced; a device removed while away is stranded on the home label and says so.
// spec/permissions.md §3
#[test]
fn watch_status_and_stranded_spec_permissions_3() {
    let mut w = World::new();
    let sv = w.add_server();
    let (da, _) = w.person(1, &[sv]);
    let (tx, rx) = std::sync::mpsc::channel();
    let _sub = da.watch_status(move |_, st| {
        let _ = tx.send(st);
    });
    w.run();
    let home = da.home();
    let mut seen = recv(&rx);
    while seen.groups.get(&home).map(|g| g.state) != Some(SyncState::Synced) {
        seen = recv(&rx);
    }
    let join = Osis::pair(w.cfg(2, &[]), &da.pair_offer().unwrap()).unwrap();
    let (node, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    w.run();
    let stranded = diags(&db, DiagnosticKind::Stranded);
    w.set_online(&db, false);
    w.until(da.remove_device(node, Demotion { sync: WaitForSync::Skip, backdate: None }), 1000, 5).unwrap();
    item(&da, da.me(), home, "after the removal");
    w.run();
    w.set_online(&db, true);
    for _ in 0..3 {
        w.advance(70_000);
    }
    assert_eq!(db.status().unwrap().groups.get(&home).map(|g| g.state), Some(SyncState::Stranded));
    assert!(recv(&stranded).contains(&home));
}

// spec/sync.md §11, notes/api.md Sync (bundles): a device that cannot reach the server takes
// what it misses from a bundle another device exported.
#[test]
fn bundle_round_trip_spec_sync_11() {
    let mut w = World::new();
    let sv = w.add_server();
    let (da, _) = w.person(1, &[sv]);
    w.run();
    let join = Osis::pair(w.cfg(2, &[]), &da.pair_offer().unwrap()).unwrap();
    let (_, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    w.run();
    w.set_online(&db, false);
    let t = item(&da, da.me(), da.home(), "by bundle");
    w.until(da.wait_synced(SyncScope::All, Duration::from_secs(30)), 1000, 5).unwrap();
    let mut b = Vec::new();
    da.export_bundle(&[da.home()], &mut b).unwrap();
    assert_eq!(x(&db, t), None);
    db.import_bundle(&b[..]).unwrap();
    db.settle();
    assert_eq!(x(&db, t), Some(s("by bundle")));
}

// notes/api.md Handle (restore), Sharing (redeem): waits time out with `Network`; a failed
// restore leaves no person record; a dropped redemption leaves no waiter and no held key.
// spec: none (API surface, notes/api.md)
#[test]
fn waits_time_out_and_roll_back_spec_api_handle() {
    let mut a = World::new();
    let sv = a.add_server();
    let (alice, card) = a.person(1, &[sv]);
    let g = group(&alice);
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    a.run();
    // a world without that server: nothing answers
    let mut w = World::new();
    let store = osis::MemStore::new();
    let mut c = w.cfg(4, &[]);
    c.store = osis::StoreAt::Memory(store);
    c.wait_timeout = Duration::from_secs(5);
    let r = w.until(Osis::restore(c.clone(), &card), 1000, 10);
    assert!(matches!(r, Err(Error::Network(_))), "{r:?}");
    assert!(Osis::open(c).is_err(), "no person record after a failed restore");
    let (bob, _) = a.person(2, &[sv]);
    {
        let f = bob.redeem(&link);
        let mut f = std::pin::pin!(f);
        assert!(std::future::Future::poll(f.as_mut(), &mut std::task::Context::from_waker(std::task::Waker::noop())).is_pending());
        assert_eq!(bob.waiting(), 1);
        assert_eq!(bob.engine(|e| e.held_key_actors()), 1);
    }
    a.run();
    assert_eq!(bob.waiting(), 0, "a dropped future leaves no waiter");
    assert_eq!(bob.engine(|e| e.held_key_actors()), 0, "nor the link key");
}

// spec/permissions.md §5.1 Frontier (chain-write forgery): Bob removes Carol without having
// received anything of hers; Carol, offline with a lagging clock, then writes Bob's admin edge
// with an `until`, stamped before the removal, and hands it over directly. Bob's frontier does not cover it: it drops,
// Bob keeps admin without `until` and Carol stays removed.
#[test]
fn removed_admin_cannot_backdate_removers_edge_spec_permissions_5_1() {
    let mut w = World::new();
    let sv = w.add_server();
    let (alice, _) = w.person(1, &[sv]);
    let (bob, _) = w.person(2, &[sv]);
    // Carol's own clock: kept with the world's, then left behind while she is offline
    let cl = clock();
    let mut c = w.cfg(3, &[sv]);
    c.clock = Some(cl.clone());
    let carol = Osis::create(c).unwrap().0;
    w.run();
    let (bc, cc) = (bob.contact_card().unwrap(), carol.contact_card().unwrap());
    w.run();
    let b = w.until(alice.import_contact(&bc), 1000, 10).unwrap();
    cl.set(osis::WallMs(w.now()));
    let c = w.until(alice.import_contact(&cc), 1000, 10).unwrap();
    cl.set(osis::WallMs(w.now()));
    let g = group(&alice);
    alice.grant(g, b, Role::Admin, Default::default()).unwrap();
    alice.grant(g, c, Role::Admin, Default::default()).unwrap();
    w.run();
    cl.set(osis::WallMs(w.now()));
    w.run();
    assert_eq!((bob.role_on(g), carol.role_on(g)), (Some(Role::Admin), Some(Role::Admin)));
    w.set_online(&carol, false);
    w.advance(60_000);
    w.until(bob.demote(g, c, Lower::Remove, Demotion { sync: WaitForSync::Skip, backdate: None }), 1000, 10).unwrap();
    w.run();
    let until = osis::WallMs(w.now() + 3_600_000);
    carol.change_edge(g, b, Role::Admin, osis::EdgeOpts { until: Some(until), invite: None }).unwrap();
    assert_eq!(carol.roster(g).get(&b).and_then(|e| e.until), Some(until), "carol wrote it");
    // straight to Alice and Bob (G's servers refuse her stale write key)
    deliver(&carol, &alice);
    deliver(&carol, &bob);
    w.run();
    w.advance(3_700_000);
    for db in [&alice, &bob] {
        let r = db.roster(g);
        assert_eq!(r.get(&b).map(|e| (e.role, e.until)), Some((Role::Admin, None)));
        assert!(!r.contains_key(&c));
    }
    assert_eq!(bob.role_on(g), Some(Role::Admin));
}

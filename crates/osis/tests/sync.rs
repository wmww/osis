//! Sharing and sync through blind servers in process (notes/api.md Sharing and membership,
//! Sync configuration and status; plans/api.md step 4), no tokio: see common/world.rs.

mod common;
use common::world::World;
use common::*;
use osis::{Osis, Place, Role, SyncScope, SyncState, Tid, Value};
use std::time::Duration;

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

/// A thing in `g` (owned by `owner`) with `/t/x` = `v`.
fn item(db: &Osis, owner: Tid, g: Tid, v: &str) -> Tid {
    let mut w = db.write();
    let t = w.create(owner, Place::In(g)).unwrap();
    w.at(t, ak("/t/x")).set(&s(v)).unwrap();
    w.commit().unwrap();
    t
}

fn x(db: &Osis, t: Tid) -> Option<Value> {
    db.get(t, ak("/t/x")).unwrap()
}

// notes/api.md Handle (create), Sync status; spec/sync.md §2 (home label): a new person's home
// label registers at its server; status turns Synced and wait_synced resolves after a write.
#[test]
fn create_syncs_home_spec_sync_2() {
    let mut w = World::new();
    let sv = w.add_server();
    let (db, _card) = w.person(1, &[sv]);
    w.run();
    let st = db.status().unwrap();
    assert_eq!(st.groups.get(&db.home()).map(|g| g.state), Some(SyncState::Synced), "{st:?}");
    assert_eq!(st.connected, 1);
    item(&db, db.me(), db.home(), "hello");
    assert_ne!(db.status().unwrap().groups.get(&db.home()).map(|g| g.state), Some(SyncState::Synced), "a local commit is not at the server yet");
    w.until(db.wait_synced(SyncScope::All, Duration::from_secs(60)), 1000, 10).unwrap();
}

// notes/api.md Sharing (devices), spec/sync.md §2 (pairing: the only way a node receives a
// grant): the app carries the request and the reply; the new device becomes an admin of the
// person, reads the home group and its writes reach the first device.
#[test]
fn pairing_spec_permissions_1() {
    let mut w = World::new();
    let sv = w.add_server();
    let (da, _) = w.person(1, &[sv]);
    w.run();
    let t = item(&da, da.me(), da.home(), "before pairing");
    let offer = da.pair_offer().unwrap();
    let join = Osis::pair(w.cfg(2, &[]), &offer).unwrap();
    let req: osis::PairRequest = join.request().to_string().parse().unwrap();
    let (node, reply) = da.pair_accept(&req).unwrap();
    assert_eq!(node, join.node());
    assert!(da.pair_accept(&req).is_err(), "an offer is used once");
    let db = join.finish(&reply).unwrap();
    assert_eq!(db.me(), da.me());
    w.run();
    assert_eq!(x(&db, t), Some(s("before pairing")));
    let u = item(&db, db.me(), db.home(), "from the new device");
    w.run();
    assert_eq!(x(&da, u), Some(s("from the new device")));
    let devs: Vec<Tid> = da.devices().unwrap().into_iter().map(|d| d.node).collect();
    assert!(devs.contains(&da.node()) && devs.contains(&db.node()), "{devs:?}");
}

// spec/permissions.md §9 (recovery card), notes/api.md Handle (restore): a fresh device with
// the card claims the home label by the recovery key, downloads it and becomes an admin.
#[test]
fn restore_from_card_spec_permissions_9() {
    let mut w = World::new();
    let sv = w.add_server();
    let (da, card) = w.person(1, &[sv]);
    let t = item(&da, da.me(), da.home(), "kept by the server");
    w.run();
    let card: osis::RecoveryCard = card.to_string().parse().unwrap();
    w.advance(1000);
    let dc = w.until(Osis::restore(w.cfg(4, &[]), &card), 1000, 10).unwrap();
    w.run();
    assert_eq!(dc.me(), da.me());
    assert_eq!(x(&dc, t), Some(s("kept by the server")));
    assert_eq!(dc.role_on(dc.me()), Some(Role::Admin));
    let u = item(&dc, dc.me(), dc.home(), "after restore");
    w.run();
    assert_eq!(x(&da, u), Some(s("after restore")));
}

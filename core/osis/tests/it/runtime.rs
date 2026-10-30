//! The background runtime (notes/api.md Design rules: async only where another node is waited
//! on; sync runs on the handle's tokio runtime): two databases on `Runtime::Tokio` reach an
//! osis-server driver (one on the app's runtime, one on `Runtime::Own`) over in-process sessions (tier 1, a guard timeout against a hang) and over
//! localhost QUIC (tier 2, ignored).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis::internals::Internals as _;
use crate::common;
use common::ak;
use crate::common::CreateIn;
use osis::{Config, MemStore, Osis, Runtime, ServerAddr, StoreAt, SyncScope, Transport, Value};
use osis_crypto::SeededRng;
use osis_server::{BackendStore, Endpoint, Hub, Policy};
use osis_store::MemoryBackend;
use osis_transport::{ListenConfig, Listener, StaticSecret, Transport as _};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const GUARD: Duration = Duration::from_secs(30);

fn cfg(seed: u64, servers: Vec<ServerAddr>, t: Transport) -> Config {
    let mut c = Config::at(StoreAt::Memory(MemStore::new()));
    c.seed = Some(seed);
    c.runtime = Runtime::Tokio(tokio::runtime::Handle::current());
    c.transport = Some(t);
    c.servers = servers;
    c
}

/// A person writes into its home group and waits until it is at the server; a fresh device
/// restores the person from the card and reads it. `p2p`: the server then stops, and a write
/// reaches the other device directly (each listens with its dialable key, spec/sync.md §5, §10).
async fn round_trip<T: osis_transport::Transport>(server_ep: T, url: &str, a: Transport, b: Transport, p2p: bool) {
    let secret = StaticSecret::from_bytes([0x52; 32]);
    let listener = server_ep.listen(ListenConfig { url: url.into(), secret: secret.clone() }).await.unwrap();
    let addr = listener.address();
    let clock: Arc<dyn osis::Clock> = Arc::new(osis_base::SystemClock);
    let store = BackendStore::open(MemoryBackend::new(), clock.clone(), Policy::default(), &mut SeededRng::from_u64(5)).unwrap();
    let hub = Hub::new(store, addr.key, Box::new(SeededRng::from_u64(6)));
    let (sctl, srx) = mpsc::channel(8);
    let server = tokio::spawn(osis_server::run(hub, Endpoint { transport: server_ep, listener, secret }, vec![], clock, srx, Arc::new(|_: &str| {})));
    let sv = ServerAddr::new(&addr.url, addr.key);

    let (da, card) = Osis::create(cfg(1, vec![sv.clone()], a)).unwrap();
    let mut w = da.write();
    let t = w.create_in(da.me(), &[da.home()]).unwrap();
    w.at(t, ak("/t/x")).set(&Value::Str("over the wire".into())).unwrap();
    w.commit().unwrap();
    tokio::time::timeout(GUARD, da.wait_synced(SyncScope::All, GUARD)).await.unwrap().unwrap();

    // the fresh device syncs on a runtime of osis's own (`Runtime::Own`)
    let mut own = cfg(2, vec![], b);
    own.runtime = Runtime::Own;
    let db = tokio::time::timeout(GUARD, Osis::restore(own, &card.unwrap())).await.unwrap().unwrap();
    assert_eq!(db.get(t, ak("/t/x")).unwrap(), Some(Value::Str("over the wire".into())));
    // the server, and the first device as a co-reader once its connection is up
    assert!(db.status().unwrap().connected >= 1);
    if p2p {
        assert!(sctl.send(osis_server::Control::Shutdown).await.is_ok());
        let mut w = da.write();
        w.at(t, ak("/t/x")).set(&Value::Str("peer to peer".into())).unwrap();
        w.commit().unwrap();
        let want = Some(Value::Str("peer to peer".into()));
        tokio::time::timeout(GUARD, async {
            while db.get(t, ak("/t/x")).unwrap() != want {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }
    // close() returns once the database is closed (the driver held only a weak reference)
    let weak = da.downgrade();
    da.close().unwrap();
    assert!(weak.upgrade().is_none());
    drop(db);
    if !p2p {
        assert!(sctl.send(osis_server::Control::Shutdown).await.is_ok());
    }
    server.await.unwrap();
}

// notes/api.md Handle (Config.runtime), spec/sync.md §10: the tokio driver under the handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_in_process_spec_sync_10() {
    let net = osis_transport::Net::new(3);
    round_trip(net.endpoint("s"), "mem://s", Transport::InProcess(net.endpoint("a")), Transport::InProcess(net.endpoint("b")), false).await;
}

// spec/sync.md §5 (member peer), §10, notes/api.md (Config.peers): two devices under the
// handle's driver keep syncing peer to peer once their server is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_peers_in_process_spec_sync_5() {
    let net = osis_transport::Net::new(5);
    round_trip(net.endpoint("s"), "mem://s", Transport::InProcess(net.endpoint("a")), Transport::InProcess(net.endpoint("b")), true).await;
}

// spec/sync.md §10: the same over localhost QUIC (tier 2: touches the network).
// Run: `cargo test --workspace --test it runtime:: -- --ignored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn runtime_quic_localhost_spec_sync_10() {
    round_trip(osis_transport::Quic::new(), "quic://127.0.0.1:0", Transport::Quic, Transport::Quic, false).await;
}

/// Bob redeems Alice's write link to a synced group, both on the tokio driver.
async fn redeem_over<T: osis_transport::Transport>(server_ep: T, url: &str, a: Transport, b: Transport) {
    let secret = StaticSecret::from_bytes([0x53; 32]);
    let listener = server_ep.listen(ListenConfig { url: url.into(), secret: secret.clone() }).await.unwrap();
    let addr = listener.address();
    let clock: Arc<dyn osis::Clock> = Arc::new(osis_base::SystemClock);
    let store = BackendStore::open(MemoryBackend::new(), clock.clone(), Policy::default(), &mut SeededRng::from_u64(7)).unwrap();
    let hub = Hub::new(store, addr.key, Box::new(SeededRng::from_u64(8)));
    let (sctl, srx) = mpsc::channel(8);
    let server = tokio::spawn(osis_server::run(hub, Endpoint { transport: server_ep, listener, secret }, vec![], clock, srx, Arc::new(|_: &str| {})));
    let sv = ServerAddr::new(&addr.url, addr.key);
    let alice = Osis::create(cfg(1, vec![sv.clone()], a)).unwrap().0;
    let bob = Osis::create(cfg(2, vec![sv.clone()], b)).unwrap().0;
    let mut w = alice.write();
    let g = w.create_in(alice.me(), &[alice.home()]).unwrap();
    w.make_group(g).unwrap();
    w.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    let link = alice.make_link(g, osis::Role::Write, Default::default()).unwrap();
    tokio::time::timeout(GUARD, alice.wait_synced(SyncScope::All, GUARD)).await.unwrap().unwrap();
    assert_eq!(tokio::time::timeout(Duration::from_secs(90), bob.redeem(&link)).await.unwrap().unwrap(), g);
    // spec/permissions.md §4, notes/sync.md: `/reach` under the home group, not under a group
    // shared with a non-contact, until the policy says so
    let home = alice.home();
    assert!(alice.sync_engine(|s| s.publishes_reach(&home)));
    assert!(!alice.sync_engine(|s| s.publishes_reach(&g)));
    alice.sync_policy(g, osis::GroupPolicy { publish_reach: Some(true) });
    assert!(alice.sync_engine(|s| s.publishes_reach(&g)));
    drop((alice, bob));
    assert!(sctl.send(osis_server::Control::Shutdown).await.is_ok());
    server.await.unwrap();
}

// spec/permissions.md §9 (links), spec/sync.md §10: a link redeemed over the tokio driver.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redeem_in_process_spec_permissions_9() {
    let net = osis_transport::Net::new(4);
    redeem_over(net.endpoint("s"), "mem://s", Transport::InProcess(net.endpoint("a")), Transport::InProcess(net.endpoint("b"))).await;
}

// spec/permissions.md §9, spec/sync.md §10: the same over localhost QUIC (tier 2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn redeem_quic_localhost_spec_permissions_9() {
    redeem_over(osis_transport::Quic::new(), "quic://127.0.0.1:0", Transport::Quic, Transport::Quic).await;
}

// notes/api.md Text editing sessions, spec/requirements.md (Generality: one commit per editing
// pause): with a runtime, a session commits after `idle_commit` without edits, with no further
// edit or call. Tier 2: it waits on a real 20 ms timer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "tier 2"]
async fn text_idle_commit_api_text_sessions() {
    let net = osis_transport::Net::new(4);
    let mut c = cfg(1, vec![], Transport::InProcess(net.endpoint("a")));
    c.idle_commit = Duration::from_millis(20);
    let db = Osis::create(c).unwrap().0;
    let k = ak("/t/body");
    let t = db.write_with(|w| w.create(db.me())).unwrap();
    let s = db.edit_text(t, k.clone(), osis::Path::root()).unwrap();
    let watch = db.at(t, k.clone()).watch().unwrap();
    s.insert(0, "hi").unwrap();
    tokio::time::timeout(GUARD, watch.changed()).await.unwrap();
    assert_eq!(db.get(t, k).unwrap(), Some(Value::Str("hi".into())));
    assert_eq!(s.commit().unwrap(), None, "already committed");
}

/// Waits until `db` published its `/reach` (the driver listens with its dialable key).
async fn reach_of(db: &Osis) -> osis::internals::node::sync::peers::Peer {
    tokio::time::timeout(GUARD, async {
        loop {
            if let Some(r) = db.sync_engine(|s| s.own_reach()) {
                return osis::internals::node::sync::peers::Peer { node: db.node(), reach: r, labels: Default::default() };
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

// spec/permissions.md §9 (first contact: the link carries the sharer's dialable key and relays),
// spec/sync.md §5 (member peer): Bob cannot reach Alice's server; he redeems her direct link at
// her device, opening the link's label there by the link key, and then syncs the target with
// her device though neither publishes `/reach` to the other's groups by default.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redeem_direct_in_process_spec_permissions_9() {
    let net = osis_transport::Net::new(6);
    let server_ep = net.endpoint("s");
    let secret = StaticSecret::from_bytes([0x54; 32]);
    let listener = server_ep.listen(ListenConfig { url: "mem://s".into(), secret: secret.clone() }).await.unwrap();
    let addr = listener.address();
    let clock: Arc<dyn osis::Clock> = Arc::new(osis_base::SystemClock);
    let store = BackendStore::open(MemoryBackend::new(), clock.clone(), Policy::default(), &mut SeededRng::from_u64(9)).unwrap();
    let hub = Hub::new(store, addr.key, Box::new(SeededRng::from_u64(10)));
    let (sctl, srx) = mpsc::channel(8);
    let server = tokio::spawn(osis_server::run(hub, Endpoint { transport: server_ep, listener, secret }, vec![], clock, srx, Arc::new(|_: &str| {})));
    let sv = ServerAddr::new(&addr.url, addr.key);
    net.partition("b", "s");
    let alice = Osis::create(cfg(1, vec![sv], Transport::InProcess(net.endpoint("a")))).unwrap().0;
    let mut c = cfg(2, vec![], Transport::InProcess(net.endpoint("b")));
    c.wait_timeout = GUARD;
    let bob = Osis::create(c).unwrap().0;
    let me = reach_of(&alice).await;
    let mut w = alice.write();
    let g = w.create_in(alice.me(), &[alice.home()]).unwrap();
    w.make_group(g).unwrap();
    w.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    let mut w = alice.write();
    let t = w.create_in(g, &[g]).unwrap();
    w.at(t, ak("/t/x")).set(&Value::Str("first contact".into())).unwrap();
    w.commit().unwrap();
    // `/reach` went under g (only Alice reads it); the link's K joining g makes g stop
    // qualifying, so the key rotates, and the link carries the new one, listened on
    tokio::time::timeout(GUARD, alice.wait_synced(SyncScope::All, GUARD)).await.unwrap().unwrap();
    let link = alice.make_link(g, osis::Role::Write, osis::LinkOpts { direct: true, ..Default::default() }).unwrap();
    let now = alice.sync_engine(|s| s.own_reach()).unwrap();
    assert_ne!(now.dialable, me.reach.dialable, "rotated: g no longer qualifies");
    let parsed = osis_label::ShareLink::from_text(&link.to_string()).unwrap();
    assert_eq!(parsed.peers, vec![osis_label::Peer { dialable: now.dialable, relays: vec![] }]);
    let probe = net.endpoint("probe");
    tokio::time::timeout(GUARD, async {
        while probe.dial(&osis_transport::Address { url: osis_transport::peer_url(&[]), key: now.dialable }).await.is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(GUARD, alice.wait_synced(SyncScope::All, GUARD)).await.unwrap().unwrap();
    assert_eq!(tokio::time::timeout(GUARD, bob.redeem(&link)).await.unwrap().unwrap(), g);
    let want = Some(Value::Str("first contact".into()));
    tokio::time::timeout(GUARD, async {
        while bob.get(t, ak("/t/x")).unwrap() != want {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // Bob's writes reach Alice the same way
    let mut w = bob.write();
    w.at(t, ak("/t/x")).set(&Value::Str("back".into())).unwrap();
    w.commit().unwrap();
    let back = Some(Value::Str("back".into()));
    tokio::time::timeout(GUARD, async {
        while alice.get(t, ak("/t/x")).unwrap() != back {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // Bob keeps the sharer from the link; Alice never saw his dialable key (no member proof)
    assert_eq!(bob.sync_engine(|s| s.link_peer_keys()), [now.dialable].into());
    let bob_key = bob.sync_engine(|s| s.own_reach()).unwrap().dialable;
    assert!(!alice.sync_engine(|s| s.served_members()).contains(&bob_key));
    // the link ends (revoked): the key it carried rotates
    let k = alice.links(g)[0].id;
    tokio::time::timeout(GUARD, alice.revoke_link(k, osis::Demotion { sync: osis::WaitForSync::Skip, backdate: None })).await.unwrap().unwrap();
    tokio::time::timeout(GUARD, async {
        while alice.sync_engine(|s| s.own_reach()).unwrap().dialable == now.dialable {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // a later holder of the link reaches nothing, and its follow is forgotten
    let mut c = cfg(3, vec![], Transport::InProcess(net.endpoint("c")));
    c.wait_timeout = Duration::from_secs(2);
    let carol = Osis::create(c).unwrap().0;
    net.partition("c", "s");
    assert!(matches!(carol.redeem(&link).await, Err(osis::Error::Network(_))));
    assert!(carol.sync_engine(|s| s.link_peer_keys()).is_empty());
    assert_eq!(carol.role_on(g), None);
    // even at the sharer's current key, K refuses the revoked link's key: the open fails there.
    // Erin waits as long as the guard (a short wait could end before a loaded machine gets the
    // open refused) and drops her redemption once refused; the new key is listened on first (a
    // dial before that pauses the peer)
    let nk = alice.sync_engine(|s| s.own_reach()).unwrap().dialable;
    tokio::time::timeout(GUARD, async {
        while probe.dial(&osis_transport::Address { url: osis_transport::peer_url(&[]), key: nk }).await.is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let mut patched = parsed.clone();
    patched.peers = vec![osis_label::Peer { dialable: nk, relays: vec![] }];
    let patched: osis::ShareLink = patched.to_text().unwrap().parse().unwrap();
    let mut e = cfg(5, vec![], Transport::InProcess(net.endpoint("e")));
    e.wait_timeout = GUARD;
    let erin = Osis::create(e).unwrap().0;
    net.partition("e", "s");
    let refused = async {
        loop {
            if erin.sync_engine(|s| s.describe()).iter().any(|d| d.contains("Failed")) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        r = erin.redeem(&patched) => panic!("K's open was refused at the sharer: {r:?}"),
        _ = refused => {}
    }
    assert!(erin.sync_engine(|s| s.link_peer_keys()).is_empty());
    assert_eq!(erin.role_on(g), None);
    // a redemption dropped while it waits forgets its follow too (the key guard)
    let dave = Osis::create(cfg(4, vec![], Transport::InProcess(net.endpoint("d")))).unwrap().0;
    assert!(tokio::time::timeout(Duration::from_millis(300), dave.redeem(&link)).await.is_err());
    assert!(dave.sync_engine(|s| s.link_peer_keys()).is_empty());
    drop((alice, bob, carol, dave, erin));
    assert!(sctl.send(osis_server::Control::Shutdown).await.is_ok());
    server.await.unwrap();
}

// spec/permissions.md §9 (a node without servers makes only direct links), spec/sync.md §5
// (member peer: a label synced with nobody is served complete): Alice has no server and no
// other device; Bob redeems her direct link at her device and the two sync the target there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redeem_direct_no_server_in_process_spec_permissions_9() {
    let net = osis_transport::Net::new(9);
    let alice = Osis::create(cfg(1, vec![], Transport::InProcess(net.endpoint("a")))).unwrap().0;
    let mut c = cfg(2, vec![], Transport::InProcess(net.endpoint("b")));
    c.wait_timeout = GUARD;
    let bob = Osis::create(c).unwrap().0;
    reach_of(&alice).await;
    let mut w = alice.write();
    let g = w.create_in(alice.me(), &[alice.home()]).unwrap();
    w.make_group(g).unwrap();
    w.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    let mut w = alice.write();
    let t = w.create_in(g, &[g]).unwrap();
    w.at(t, ak("/t/x")).set(&Value::Str("no server".into())).unwrap();
    w.commit().unwrap();
    let link = alice.make_link(g, osis::Role::Write, osis::LinkOpts { direct: true, ..Default::default() }).unwrap();
    assert_eq!(tokio::time::timeout(GUARD, bob.redeem(&link)).await.unwrap().unwrap(), g);
    let want = Some(Value::Str("no server".into()));
    tokio::time::timeout(GUARD, async {
        while bob.get(t, ak("/t/x")).unwrap() != want {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let mut w = bob.write();
    w.at(t, ak("/t/x")).set(&Value::Str("back".into())).unwrap();
    w.commit().unwrap();
    let back = Some(Value::Str("back".into()));
    tokio::time::timeout(GUARD, async {
        while alice.get(t, ak("/t/x")).unwrap() != back {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

// spec/permissions.md §9 (a single-use link finalized by its redemption does not rotate): Bob
// redeems Alice's single-use direct link with no server between them; once Alice finalizes it,
// her key is the one the link carried and Bob's writes still reach her directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_use_direct_keeps_key_in_process_spec_permissions_9() {
    let net = osis_transport::Net::new(8);
    let server_ep = net.endpoint("s");
    let secret = StaticSecret::from_bytes([0x55; 32]);
    let listener = server_ep.listen(ListenConfig { url: "mem://s".into(), secret: secret.clone() }).await.unwrap();
    let addr = listener.address();
    let clock: Arc<dyn osis::Clock> = Arc::new(osis_base::SystemClock);
    let store = BackendStore::open(MemoryBackend::new(), clock.clone(), Policy::default(), &mut SeededRng::from_u64(11)).unwrap();
    let hub = Hub::new(store, addr.key, Box::new(SeededRng::from_u64(12)));
    let (sctl, srx) = mpsc::channel(8);
    let server = tokio::spawn(osis_server::run(hub, Endpoint { transport: server_ep, listener, secret }, vec![], clock, srx, Arc::new(|_: &str| {})));
    net.partition("b", "s");
    let alice = Osis::create(cfg(1, vec![ServerAddr::new(&addr.url, addr.key)], Transport::InProcess(net.endpoint("a")))).unwrap().0;
    let mut c = cfg(2, vec![], Transport::InProcess(net.endpoint("b")));
    c.wait_timeout = GUARD;
    let bob = Osis::create(c).unwrap().0;
    reach_of(&alice).await;
    let mut w = alice.write();
    let g = w.create_in(alice.me(), &[alice.home()]).unwrap();
    w.make_group(g).unwrap();
    w.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    let link = alice.make_link(g, osis::Role::Write, osis::LinkOpts { direct: true, single_use: true, ..Default::default() }).unwrap();
    let key = alice.sync_engine(|s| s.own_reach()).unwrap().dialable;
    assert_eq!(osis_label::ShareLink::from_text(&link.to_string()).unwrap().peers[0].dialable, key);
    tokio::time::timeout(GUARD, alice.wait_synced(SyncScope::All, GUARD)).await.unwrap().unwrap();
    assert_eq!(tokio::time::timeout(GUARD, bob.redeem(&link)).await.unwrap().unwrap(), g);
    tokio::time::timeout(GUARD, async {
        while !alice.links(g).is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(alice.sync_engine(|s| s.own_reach()).unwrap().dialable, key, "finalized by redemption: kept");
    let mut w = bob.write();
    let t = w.create_in(g, &[g]).unwrap();
    w.at(t, ak("/t/x")).set(&Value::Str("still direct".into())).unwrap();
    w.commit().unwrap();
    let want = Some(Value::Str("still direct".into()));
    tokio::time::timeout(GUARD, async {
        while alice.get(t, ak("/t/x")).unwrap() != want {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    drop((alice, bob));
    assert!(sctl.send(osis_server::Control::Shutdown).await.is_ok());
    server.await.unwrap();
}

// spec/sync.md §10, notes/api.md (`rotate_reach`): a rotated dialable key is listened on at once,
// without a restart, and the old one no longer answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotate_reach_relistens_in_process_spec_sync_10() {
    let net = osis_transport::Net::new(7);
    let db = Osis::create(cfg(1, vec![], Transport::InProcess(net.endpoint("a")))).unwrap().0;
    let old = reach_of(&db).await.reach;
    // spec/permissions.md §9: direct is opt-in; without servers a link must be direct
    assert!(matches!(db.make_link(db.home(), osis::Role::Read, Default::default()), Err(osis::Error::Invalid(_))));
    let probe = net.endpoint("probe");
    let dial = |key: [u8; 32]| {
        let probe = probe.clone();
        async move { osis_transport::Transport::dial(&probe, &osis_transport::Address { url: osis_transport::peer_url(&[]), key }).await.is_ok() }
    };
    assert!(dial(old.dialable).await);
    db.rotate_reach();
    let new = db.sync_engine(|s| s.own_reach()).unwrap();
    assert_ne!(new.dialable, old.dialable);
    assert_ne!(new.lan_secret, old.lan_secret);
    tokio::time::timeout(GUARD, async {
        while !dial(new.dialable).await || dial(old.dialable).await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

// notes/api.md Handle and sync: closing a database whose own runtime's driver is inside an
// engine call (its `block_in_place`) must not let the driver poll a timer of the shut-down
// runtime (tokio panics "... it is being shutdown" on an `osis-sync` thread). spec: none (an API property)
#[test]
fn close_while_driver_runs_no_timer_panic() {
    count_shutdown_panics();
    let net = osis_transport::Net::new(9);
    std::thread::scope(|sc| {
        for t in 0..8u64 {
            let net = net.clone();
            sc.spawn(move || {
                for i in 0..40 {
                    let mut c = Config::at(StoreAt::Memory(MemStore::new()));
                    c.seed = Some(t * 1000 + i);
                    c.runtime = Runtime::Own;
                    c.transport = Some(Transport::InProcess(net.endpoint(&format!("c{t}-{i}"))));
                    let (db, _) = Osis::create(c).unwrap();
                    let _ = common::block_on(db.wait_synced(osis::SyncScope::All, Duration::from_secs(1)));
                    db.close().unwrap();
                }
            });
        }
    });
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(shutdown_panics("osis-sync"), 0);
}

/// Names of the threads that panicked on a timer of a shut-down tokio runtime.
static SHUTDOWN_PANICS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Installs (once) a panic hook recording `SHUTDOWN_PANICS`.
fn count_shutdown_panics() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |i| {
            if i.to_string().contains("being shutdown") {
                let name = std::thread::current().name().unwrap_or("").to_string();
                SHUTDOWN_PANICS.lock().unwrap_or_else(|p| p.into_inner()).push(name);
            }
            prev(i);
        }));
    });
}

/// How many threads named `prefix...` panicked on a timer of a shut-down runtime.
fn shutdown_panics(prefix: &str) -> usize {
    SHUTDOWN_PANICS.lock().unwrap_or_else(|p| p.into_inner()).iter().filter(|n| n.starts_with(prefix)).count()
}

// notes/api.md Handle and sync: `close` returns once the store is closed, also with
// `Runtime::Own` (whose runtime stops in the background): the store opens again at once and
// holds every write. spec: none (an API property)
#[test]
fn own_runtime_reopen_right_after_close() {
    let dir = std::env::temp_dir().join(format!("osis-reopen-{}-{}", std::process::id(), rand_suffix()));
    let net = osis_transport::Net::new(10);
    let at = |i: u64| {
        let mut c = Config::at(StoreAt::Dir(dir.clone()));
        c.seed = Some(i);
        c.runtime = Runtime::Own;
        c.transport = Some(Transport::InProcess(net.endpoint(&format!("r{i}"))));
        c
    };
    let (db, _) = Osis::create(at(0)).unwrap();
    let t = db.write_with(|w| w.create_durable(db.me())).unwrap();
    db.close().unwrap();
    for i in 1..12u64 {
        let db = Osis::open(at(i)).unwrap();
        assert_eq!(db.get(t, ak("/n/v")).unwrap(), (i > 1).then(|| Value::Int(i as i64 - 1)));
        db.write_with(|w| w.at(t, ak("/n/v")).set(&Value::Int(i as i64))).unwrap();
        db.close().unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn rand_suffix() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u8(0);
    h.finish()
}

// notes/api.md Handle and sync: closing a database on the app's runtime (`Runtime::Tokio`)
// and then shutting that runtime down must not let the driver poll a timer of the shut-down
// runtime. spec: none (an API property)
#[test]
fn tokio_runtime_close_then_shutdown_no_timer_panic() {
    count_shutdown_panics();
    let net = osis_transport::Net::new(11);
    std::thread::scope(|sc| {
        for t in 0..8u64 {
            let net = net.clone();
            sc.spawn(move || {
                for i in 0..40 {
                    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("tk-close").enable_all().build().unwrap();
                    let mut c = Config::at(StoreAt::Memory(MemStore::new()));
                    c.seed = Some(t * 1000 + i);
                    c.runtime = Runtime::Tokio(rt.handle().clone());
                    c.transport = Some(Transport::InProcess(net.endpoint(&format!("k{t}-{i}"))));
                    let (db, _) = Osis::create(c).unwrap();
                    let _ = common::block_on(db.wait_synced(osis::SyncScope::All, Duration::from_secs(1)));
                    db.close().unwrap();
                    drop(rt);
                }
            });
        }
    });
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(shutdown_panics("tk-close"), 0);
}

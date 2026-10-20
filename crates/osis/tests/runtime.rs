//! The background runtime (notes/api.md Design rules: async only where another node is waited
//! on; sync runs on the handle's tokio runtime): two databases on `Runtime::Tokio` reach an
//! osis-server driver (one on the app's runtime, one on `Runtime::Own`) over in-process sessions (tier 1, a guard timeout against a hang) and over
//! localhost QUIC (tier 2, ignored).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;
use common::ak;
use osis::{Config, MemStore, Osis, Place, Runtime, ServerAddr, StoreAt, SyncScope, Transport, Value};
use osis_crypto::SeededRng;
use osis_server::{BackendStore, Endpoint, Hub, Policy};
use osis_store::MemoryBackend;
use osis_transport::{ListenConfig, Listener, StaticSecret};
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
    let clock: Arc<dyn osis::Clock> = Arc::new(osis_core::SystemClock);
    let store = BackendStore::open(MemoryBackend::new(), clock.clone(), Policy::default(), &mut SeededRng::from_u64(5)).unwrap();
    let hub = Hub::new(store, addr.key, Box::new(SeededRng::from_u64(6)));
    let (sctl, srx) = mpsc::channel(8);
    let server = tokio::spawn(osis_server::run(hub, Endpoint { transport: server_ep, listener, secret }, vec![], clock, srx, Arc::new(|_: &str| {})));
    let sv = ServerAddr::new(&addr.url, addr.key);

    let (da, card) = Osis::create(cfg(1, vec![sv.clone()], a)).unwrap();
    let mut w = da.write();
    let t = w.create(da.me(), Place::In(da.home())).unwrap();
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
// Run: `cargo test -p osis --features quic --test runtime -- --ignored`.
#[cfg(feature = "quic")]
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
    let clock: Arc<dyn osis::Clock> = Arc::new(osis_core::SystemClock);
    let store = BackendStore::open(MemoryBackend::new(), clock.clone(), Policy::default(), &mut SeededRng::from_u64(7)).unwrap();
    let hub = Hub::new(store, addr.key, Box::new(SeededRng::from_u64(8)));
    let (sctl, srx) = mpsc::channel(8);
    let server = tokio::spawn(osis_server::run(hub, Endpoint { transport: server_ep, listener, secret }, vec![], clock, srx, Arc::new(|_: &str| {})));
    let sv = ServerAddr::new(&addr.url, addr.key);
    let alice = Osis::create(cfg(1, vec![sv.clone()], a)).unwrap().0;
    let bob = Osis::create(cfg(2, vec![sv.clone()], b)).unwrap().0;
    let mut w = alice.write();
    let g = w.create(alice.me(), Place::In(alice.home())).unwrap();
    w.make_group(g).unwrap();
    w.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    let link = alice.make_link(g, osis::Role::Write, Default::default()).unwrap();
    tokio::time::timeout(GUARD, alice.wait_synced(SyncScope::All, GUARD)).await.unwrap().unwrap();
    assert_eq!(tokio::time::timeout(Duration::from_secs(90), bob.redeem(&link)).await.unwrap().unwrap(), g);
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
#[cfg(feature = "quic")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn redeem_quic_localhost_spec_permissions_9() {
    redeem_over(osis_transport::Quic::new(), "quic://127.0.0.1:0", Transport::Quic, Transport::Quic).await;
}

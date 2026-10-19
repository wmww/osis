#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
#![cfg(feature = "driver")]
//! The tokio driver over osis-transport's `InProcess` against the osis-server driver (spec/sync.md
//! §10): event-driven, nothing sleeps; a timeout guards against a hang.

mod net;
use net::*;
use osis_core::{Clock, CommitId, Role, Tid, Value};
use osis_crypto::SeededRng;
use osis_label::Address;
use osis_node::Event as EngineEvent;
use osis_node::sync::driver::{self, Control};
use osis_node::sync::{Event, SyncEngine};
use osis_server::{BackendStore, Endpoint, Hub, Policy};
use osis_store::MemoryBackend;
use osis_transport::{ListenConfig, Listener, StaticSecret, Transport};
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const GUARD: Duration = Duration::from_secs(30);

fn log() -> driver::Log {
    Arc::new(|_: &str| {})
}

/// Waits (off the async workers) until `rx` reports commit `id` applied.
async fn applied(rx: Receiver<EngineEvent>, id: CommitId) -> Receiver<EngineEvent> {
    tokio::task::spawn_blocking(move || {
        loop {
            match rx.recv_timeout(GUARD).expect("commit never applied") {
                EngineEvent::Applied { id: x, .. } if x == id => return rx,
                _ => {}
            }
        }
    })
    .await
    .unwrap()
}

async fn call<R: Send + 'static>(ctl: &mpsc::Sender<Control>, f: impl FnOnce(&mut SyncEngine) -> R + Send + 'static) -> R {
    let (tx, rx) = oneshot::channel();
    let c: driver::Call = Box::new(move |s: &mut SyncEngine| {
        let _ = tx.send(f(s));
        s.handle(Event::Local)
    });
    assert!(ctl.send(Control::Call(c)).await.is_ok());
    tokio::time::timeout(GUARD, rx).await.unwrap().unwrap()
}

fn read(s: &mut SyncEngine, t: Tid) -> Option<Value> {
    s.engine_mut().get(&t, &osis_core::Ak::new("/t/reg").unwrap()).unwrap()
}

/// Two nodes of one group under the tokio driver converge through the server's driver: the
/// server listens on `ep` at `url`; the nodes dial with `a` and `b`.
async fn converge<T: Transport>(ep: T, url: &str, a_ep: T, b_ep: T) {
    let secret = StaticSecret::from_bytes([0x51; 32]);
    let listener = ep.listen(ListenConfig { url: url.into(), secret: secret.clone() }).await.unwrap();
    let addr = listener.address();
    let mut net = Net::new();
    let clock: Arc<dyn Clock> = net.clock.clone();
    let store = BackendStore::open(MemoryBackend::new(), clock.clone(), Policy::default(), &mut SeededRng::from_u64(5)).unwrap();
    let hub = Hub::new(store, addr.key, Box::new(SeededRng::from_u64(6)));
    let (sctl, srx) = mpsc::channel(8);
    let server = tokio::spawn(osis_server::run(hub, Endpoint { transport: ep, listener, secret }, vec![], clock.clone(), srx, log()));

    let addr = Address { url: addr.url, key: addr.key };
    let cfg = osis_node::sync::SyncConfig { servers: vec![addr.clone()], ..Default::default() };
    let a = net.add_node(1, cfg.clone());
    let b = net.add_node(2, cfg);
    let g = net.group_at(a, &[(b, Role::Write)], vec![addr]);
    let t = net.item(a, g, g, "first");
    let brx = net.engine(b).subscribe();
    let (sa, sb) = (net.take(a), net.take(b));
    let (actl, arx) = mpsc::channel(8);
    let (bctl, brx2) = mpsc::channel(8);
    let da = tokio::spawn(driver::run(sa, a_ep, clock.clone(), arx, log()));
    let db = tokio::spawn(driver::run(sb, b_ep, clock.clone(), brx2, log()));

    let c = call(&actl, move |s| {
        let mut m = osis_node::Mutation::new();
        m.set(t, &REG, &s_("second")).unwrap();
        s.engine_mut().commit(m).unwrap().unwrap()
    })
    .await;
    let _ = applied(brx, c).await;
    assert_eq!(call(&bctl, move |s| read(s, t)).await, Some(s_("second")));

    for ctl in [&actl, &bctl] {
        assert!(ctl.send(Control::Shutdown).await.is_ok());
    }
    da.await.unwrap();
    db.await.unwrap();
    assert!(sctl.send(osis_server::Control::Shutdown).await.is_ok());
    server.await.unwrap();
}

// spec/sync.md §5, §6, §10: two nodes under the tokio driver converge through the server's
// driver over in-process sessions (ephemeral client keys, the server's key checked).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_in_process_spec_sync_10() {
    let tnet = osis_transport::Net::new(3);
    converge(tnet.endpoint("s"), "mem://s", tnet.endpoint("a"), tnet.endpoint("b")).await;
}

// spec/sync.md §10: the same over QUIC on localhost (tier 2: touches the network).
// Run: `cargo test -p osis-node --features quic --test driver -- --ignored`.
#[cfg(feature = "quic")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_quic_localhost_spec_sync_10() {
    use osis_transport::Quic;
    converge(Quic::new(), "quic://127.0.0.1:0", Quic::new(), Quic::new()).await;
}

fn s_(x: &str) -> Value {
    Value::Str(x.into())
}

/// Two members of a group whose label names no server converge peer to peer under the tokio
/// driver: each listens on its endpoint with its dialable secret, publishes the listener's key
/// in `/reach`, dials the other at `peer://` and serves the other's sessions (member peer).
/// `direct`: publish the listener's own address hints as relays (a localhost stand-in for LAN
/// discovery; `/reach` never carries addresses otherwise).
pub async fn converge_p2p<T: Transport>(a_ep: T, a_url: &str, b_ep: T, b_url: &str, direct: bool) {
    let mut net = Net::new();
    let clock: Arc<dyn Clock> = net.clock.clone();
    let a = net.add_node(1, Default::default());
    let b = net.add_node(2, Default::default());
    let mut listeners = Vec::new();
    for (n, ep, url) in [(a, &a_ep, a_url), (b, &b_ep, b_url)] {
        let secret = net.sync(n).dialable_secret();
        let l = ep.listen(ListenConfig { url: url.into(), secret: StaticSecret::from_bytes(*secret.expose()) }).await.unwrap();
        let relays = if direct { osis_transport::peer_relays(&l.address().url).unwrap() } else { vec![] };
        let acts = net.sync(n).publish_reach(l.address().key, relays).unwrap();
        net.actions(n, acts);
        listeners.push(l);
    }
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    let t = net.item(a, g, g, "first");
    let brx = net.engine(b).subscribe();
    let (sa, sb) = (net.take(a), net.take(b));
    let (actl, arx) = mpsc::channel(8);
    let (bctl, brx2) = mpsc::channel(8);
    let lb: Vec<_> = listeners.pop().into_iter().collect();
    let la: Vec<_> = listeners.pop().into_iter().collect();
    let da = tokio::spawn(driver::run_serving(sa, a_ep, la, clock.clone(), arx, log()));
    let db = tokio::spawn(driver::run_serving(sb, b_ep, lb, clock.clone(), brx2, log()));
    let c = call(&actl, move |s| {
        let mut m = osis_node::Mutation::new();
        m.set(t, &REG, &s_("second")).unwrap();
        s.engine_mut().commit(m).unwrap().unwrap()
    })
    .await;
    let _ = applied(brx, c).await;
    assert_eq!(call(&bctl, move |s| read(s, t)).await, Some(s_("second")));
    for ctl in [&actl, &bctl] {
        assert!(ctl.send(Control::Shutdown).await.is_ok());
    }
    da.await.unwrap();
    db.await.unwrap();
}

// spec/sync.md §5 (member peer), §10: two nodes sync a label with no server under the tokio
// driver over in-process sessions, each dialing the other by its dialable key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_p2p_in_process_spec_sync_5() {
    let tnet = osis_transport::Net::new(4);
    converge_p2p(tnet.endpoint("a"), "mem://a", tnet.endpoint("b"), "mem://b", false).await;
}

// spec/sync.md §5, §10: the same over iroh on localhost, no relay (tier 2: touches the network).
// Run: `cargo test -p osis-node --features iroh --test driver -- --ignored`.
#[cfg(feature = "iroh")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_p2p_iroh_localhost_spec_sync_10() {
    use osis_transport::Iroh;
    converge_p2p(Iroh::new(), "peer://127.0.0.1:0", Iroh::new(), "peer://127.0.0.1:0", true).await;
}

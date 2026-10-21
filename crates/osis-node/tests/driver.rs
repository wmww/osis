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

async fn call<R: Send + 'static>(ctl: &mpsc::UnboundedSender<Control>, f: impl FnOnce(&mut SyncEngine) -> R + Send + 'static) -> R {
    let (tx, rx) = oneshot::channel();
    let c: driver::Call = Box::new(move |s: &mut SyncEngine| {
        let _ = tx.send(f(s));
        s.handle(Event::Local)
    });
    assert!(ctl.send(Control::Call(c)).is_ok());
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
    let (actl, arx) = mpsc::unbounded_channel();
    let (bctl, brx2) = mpsc::unbounded_channel();
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
        assert!(ctl.send(Control::Shutdown).is_ok());
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

/// How the nodes of `converge_p2p` find each other besides `/reach`.
pub enum Direct<'a> {
    None,
    /// Each also listens at its URL with a fresh LAN key (`SyncEngine::lan_secret`) and the other hears
    /// its signed announcement from 127.0.0.1.
    Heard([&'a str; 2]),
    /// Each runs the driver's LAN loop.
    #[allow(dead_code)]
    Loop([driver::LanConfig; 2]),
}

/// Two members of a group whose label names no server converge peer to peer under the tokio
/// driver: each listens on its endpoint with its dialable secret, publishes the listener's key
/// in `/reach`, dials the other at `peer://` and serves the other's sessions (member peer).
/// `/reach` carries `relays` and no address; `direct` says how else the nodes find each other
/// (spec/sync.md §10).
pub async fn converge_p2p<T: Transport>(a_ep: T, a_url: &str, b_ep: T, b_url: &str, relays: Vec<String>, direct: Direct<'_>) {
    let mut net = Net::new();
    let clock: Arc<dyn Clock> = net.clock.clone();
    let a = net.add_node(1, Default::default());
    let b = net.add_node(2, Default::default());
    let mut listeners = [Vec::new(), Vec::new()];
    for (i, n, ep, url) in [(0, a, &a_ep, a_url), (1, b, &b_ep, b_url)] {
        let secret = net.sync(n).dialable_secret();
        let l = ep.listen(ListenConfig { url: url.into(), secret: StaticSecret::from_bytes(*secret.expose()) }).await.unwrap();
        let acts = net.sync(n).publish_reach(l.address().key, relays.clone()).unwrap();
        net.actions(n, acts);
        listeners[i].push(l);
    }
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    let t = net.item(a, g, g, "first");
    let brx = net.engine(b).subscribe();
    // `Heard`: each listens on the LAN with a fresh key and announces it
    let mut anns = Vec::new();
    if let Direct::Heard(urls) = &direct {
        for (i, n, ep, url) in [(0, a, &a_ep, urls[0]), (1, b, &b_ep, urls[1])] {
            let secret = StaticSecret::from_bytes(*net.sync(n).lan_secret().expose());
            let l = ep.listen(ListenConfig { url: url.into(), secret }).await.unwrap();
            let addr = l.address();
            let port = addr.url.split_once("://").and_then(|(_, h)| h.split(' ').find_map(|x| x.parse::<std::net::SocketAddr>().ok())).map_or(1, |x| x.port());
            anns.push(net.sync(n).lan_announcement(addr.key, port).expect("signed announcement"));
            listeners[i].push(l);
        }
    }
    let (sa, sb) = (net.take(a), net.take(b));
    let (actl, arx) = mpsc::unbounded_channel();
    let (bctl, brx2) = mpsc::unbounded_channel();
    let [la, lb] = listeners;
    let da = tokio::spawn(driver::run_serving(sa, a_ep, la, clock.clone(), arx, log()));
    let db = tokio::spawn(driver::run_serving(sb, b_ep, lb, clock.clone(), brx2, log()));
    let lan_loop = matches!(direct, Direct::Loop(_));
    if let Direct::Loop(cfgs) = direct {
        for (ctl, cfg) in [&actl, &bctl].into_iter().zip(cfgs) {
            assert!(ctl.send(Control::Lan(cfg)).is_ok());
        }
    } else if !anns.is_empty() {
        // a hears b's announcement and b hears a's
        for (ctl, ann) in [(&actl, anns[1]), (&bctl, anns[0])] {
            let f: driver::Call = Box::new(move |s: &mut SyncEngine| s.lan_seen(&ann, (std::net::Ipv4Addr::LOCALHOST, 47380).into()).1);
            assert!(ctl.send(Control::Call(f)).is_ok());
        }
    }
    let c = call(&actl, move |s| {
        let mut m = osis_node::Mutation::new();
        m.set(t, &REG, &s_("second")).unwrap();
        s.engine_mut().commit(m).unwrap().unwrap()
    })
    .await;
    let _ = applied(brx, c).await;
    assert_eq!(call(&bctl, move |s| read(s, t)).await, Some(s_("second")));
    // with the LAN loop each ends on the other's LAN route alone, whatever it reached first
    // (spec/sync.md §10: the proven route first)
    if lan_loop {
        let ctl = actl.clone();
        tokio::time::timeout(GUARD, async move {
            loop {
                let routes = call(&ctl, |s| s.peer_routes()).await;
                if let [(_, a, true)] = routes.as_slice()
                    && osis_transport::peer_relays(&a.url).is_some_and(|h| h.iter().any(|x| x.parse::<std::net::SocketAddr>().is_ok()))
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
    }
    for ctl in [&actl, &bctl] {
        assert!(ctl.send(Control::Shutdown).is_ok());
    }
    da.await.unwrap();
    db.await.unwrap();
}

// spec/sync.md §5 (member peer), §10: two nodes sync a label with no server under the tokio
// driver over in-process sessions, each dialing the other by its dialable key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_p2p_in_process_spec_sync_5() {
    let tnet = osis_transport::Net::new(4);
    converge_p2p(tnet.endpoint("a"), "mem://a", tnet.endpoint("b"), "mem://b", vec![], Direct::None).await;
}

// spec/sync.md §10: the same with each node also listening with a fresh LAN key and hearing
// the other's signed announcement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_p2p_lan_in_process_spec_sync_10() {
    let tnet = osis_transport::Net::new(5);
    converge_p2p(tnet.endpoint("a"), "mem://a", tnet.endpoint("b"), "mem://b", vec![], Direct::Heard(["mem://a-lan", "mem://b-lan"])).await;
}

// spec/sync.md §5, §10: the same over iroh on localhost, no relay (tier 2: touches the network).
// Run: `cargo test -p osis-node --features iroh --test driver -- --ignored`.
#[cfg(feature = "iroh")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_p2p_iroh_localhost_spec_sync_10() {
    use osis_transport::Iroh;
    converge_p2p(Iroh::new(), "peer://127.0.0.1:0", Iroh::new(), "peer://127.0.0.1:0", vec![], Direct::Heard(["peer://127.0.0.1:0", "peer://127.0.0.1:0"])).await;
}

// spec/sync.md §10: two nodes over iroh find each other only by the driver's LAN loop: fresh
// keys per network, signed announcements over UDP on localhost (tier 2).
// Run: `cargo test -p osis-node --features iroh,lan --test driver -- --ignored`.
#[cfg(all(feature = "iroh", feature = "lan"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_lan_loop_localhost_spec_sync_10() {
    use osis_transport::Iroh;
    // two announcement ports, each node announcing to the other's
    let base = 40_000 + (std::process::id() % 10_000) as u16 * 2;
    let to = |p: u16| vec![std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, p))];
    let cfg = |port: u16, other: u16| driver::LanConfig { port, to: to(other), listen: "peer://127.0.0.1:0".into(), watch: false, rejoin_min: driver::LAN_REJOIN_MIN };
    converge_p2p(Iroh::new(), "peer://127.0.0.1:0", Iroh::new(), "peer://127.0.0.1:0", vec![], Direct::Loop([cfg(base, base + 1), cfg(base + 1, base)])).await;
}

// spec/sync.md §10 (IPv6 LAN discovery): the same over IPv6 loopback: announcements on the IPv6
// socket carry the listener's IPv6 port and are dialed at their IPv6 source (tier 2).
// Run: `cargo test -p osis-node --features iroh,lan --test driver -- --ignored`.
#[cfg(all(feature = "iroh", feature = "lan"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_lan_loop_ipv6_localhost_spec_sync_10() {
    use osis_transport::Iroh;
    let base = 30_000 + (std::process::id() % 10_000) as u16 * 2;
    let to = |p: u16| vec![std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, p))];
    let cfg = |port: u16, other: u16| driver::LanConfig { port, to: to(other), listen: "peer://[::1]:0".into(), watch: false, rejoin_min: driver::LAN_REJOIN_MIN };
    converge_p2p(Iroh::new(), "peer://127.0.0.1:0", Iroh::new(), "peer://127.0.0.1:0", vec![], Direct::Loop([cfg(base, base + 1), cfg(base + 1, base)])).await;
}

// spec/sync.md §10 (the proven route first): two nodes whose `/reach` names only a relay on
// localhost also run the LAN loop: whatever route came up first, each ends on the other's LAN
// route alone (a relay connection is replaced once the LAN one is up) (tier 2).
// Run: `cargo test -p osis-node --features relay,lan --test driver -- --ignored`.
#[cfg(all(feature = "relay", feature = "lan"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_lan_replaces_relay_localhost_spec_sync_10() {
    use osis_transport::{Iroh, TestRelay};
    let relay = TestRelay::spawn().await.unwrap();
    let r = vec![relay.url.clone()];
    let url = format!("peer://{}", relay.url);
    let base = 20_000 + (std::process::id() % 10_000) as u16 * 2;
    let to = |p: u16| vec![std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, p))];
    let cfg = |port: u16, other: u16| driver::LanConfig { port, to: to(other), listen: "peer://127.0.0.1:0".into(), watch: false, rejoin_min: driver::LAN_REJOIN_MIN };
    converge_p2p(Iroh::new(), &url, Iroh::new(), &url, r, Direct::Loop([cfg(base, base + 1), cfg(base + 1, base)])).await;
}

// spec/sync.md §10: two nodes over iroh reach each other through a self-hosted relay on
// localhost, the only route `/reach` names (tier 2).
// Run: `cargo test -p osis-node --features relay --test driver -- --ignored`.
#[cfg(feature = "relay")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_p2p_relay_localhost_spec_sync_10() {
    use osis_transport::{Iroh, TestRelay};
    let relay = TestRelay::spawn().await.unwrap();
    let r = vec![relay.url.clone()];
    let url = format!("peer://127.0.0.1:0 {}", relay.url);
    converge_p2p(Iroh::new(), &url, Iroh::new(), &url, r, Direct::None).await;
}

// spec/sync.md §10 (a fresh key per network join), notes/networking.md (rejoin interval): a
// network change right after a join is deferred to `rejoin_min` (each join drops the LAN
// listener and its connections); the deferred join then announces a fresh key (tier 2: UDP and
// iroh on localhost).
// Run: `cargo test -p osis-node --features iroh,lan --test driver -- --ignored`.
#[cfg(all(feature = "iroh", feature = "lan"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn lan_rejoin_interval_spec_sync_10() {
    use osis_crypto::SigningSecret;
    use osis_transport::lan::Lan;
    let mut net = Net::new();
    let clock: Arc<dyn Clock> = net.clock.clone();
    let a = net.add_node(1, Default::default());
    let secret = net.sync(a).dialable_secret();
    let k = SigningSecret::from_seed(&secret).verifying_key().to_bytes();
    let acts = net.sync(a).publish_reach(k, vec![]).unwrap();
    net.actions(a, acts);
    let ear = Lan::bind(0).await.unwrap();
    let to = vec![std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, ear.port()))];
    let cfg = driver::LanConfig { port: 0, to, listen: "peer://127.0.0.1:0".into(), watch: false, rejoin_min: Duration::from_millis(500) };
    let (ctl, rx) = mpsc::unbounded_channel();
    let d = tokio::spawn(driver::run(net.take(a), osis_transport::Iroh::new(), clock, rx, log()));
    assert!(ctl.send(Control::Lan(cfg)).is_ok());
    let (first, _) = tokio::time::timeout(GUARD, ear.recv()).await.unwrap().unwrap();
    // a change at once: deferred, nothing announced now
    assert!(ctl.send(Control::LanRejoin).is_ok());
    assert!(tokio::time::timeout(Duration::from_millis(300), ear.recv()).await.is_err(), "no join inside the interval");
    // the LAN timer runs the deferred join: a fresh key
    let (next, _) = tokio::time::timeout(driver::LAN_CHECK * 2, ear.recv()).await.unwrap().unwrap();
    assert_ne!(next.key, first.key);
    assert!(ctl.send(Control::Shutdown).is_ok());
    d.await.unwrap();
}

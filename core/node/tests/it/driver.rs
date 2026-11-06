#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The tokio driver over osis-transport's `InProcess`, one node hosting (spec/sync.md §10):
//! event-driven, nothing sleeps; a timeout guards against a hang.

use crate::net;
use net::*;
use osis_base::{Clock, CommitId, Role, Tid, Value};
use osis_label::Address;
use osis_node::Event as EngineEvent;
use osis_node::sync::driver::{self, Control};
use osis_node::sync::{Event, SyncEngine};
use osis_schema::core_types as ct;
use osis_transport::{ListenConfig, Listener, StaticSecret, Transport};
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const GUARD: Duration = Duration::from_secs(30);

fn log() -> driver::Log {
    Arc::new(|s: &str| eprintln!("{s}"))
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
    s.engine_mut().get(&t, &osis_base::Ak::new("t:reg.0").unwrap()).unwrap()
}

/// Two nodes of one group under the tokio driver converge through a's host (notes/serving.md,
/// Hosting in the node): a's `host.0^` has it listen at `url` with `own` admission, and the group's label
/// names a's host address. b is served from a's host store; a's own copy reaches its host over
/// the in-process loopback (`cut` then cuts a's transport from itself, so nothing else could).
async fn converge<T: Transport>(url: &str, a_ep: T, b_ep: T, cut: impl FnOnce()) {
    let mut net = Net::new();
    let clock: Arc<dyn Clock> = net.clock.clone();
    let a = net.add_node(1, Default::default());
    let b = net.add_node(2, Default::default());
    let me = net.tid(a);
    let mut m = osis_node::Mutation::new();
    m.replace(me, &ct::HOST, &ct::Host { listen: vec![url.into()], admit: ct::Admit::Own, ..Default::default() }).unwrap();
    net.engine(a).commit(m).unwrap();
    let key = net.sync(a).host_key().or_else(|| net.sync(a).host_config().map(|c| c.key)).unwrap();
    let addr = Address { url: url.into(), key };
    let g = net.group_at(a, &[(b, Role::Write)], vec![addr.clone()]);
    let t = net.item(a, g, g, "first");
    let l = net.label(a);
    assert_eq!(net.sync(a).host_config().unwrap().admission, osis_host::Admission::Only([l].into()), "own: the label naming this host");
    cut();
    let brx = net.engine(b).subscribe();
    let (sa, sb) = (net.take(a), net.take(b));
    let (actl, arx) = mpsc::unbounded_channel();
    let (bctl, brx2) = mpsc::unbounded_channel();
    let da = tokio::spawn(driver::run(sa, a_ep, clock.clone(), arx, log()));
    // b dials once a listens (the manual clock never brings a redial)
    tokio::time::timeout(GUARD, async {
        while !matches!(call(&actl, |s| s.host_status().clone()).await, osis_node::sync::HostStatus::Listening(_)) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
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
}

// spec/sync.md §5, §6, §10, notes/serving.md, Hosting in the node: two nodes under the tokio driver converge
// through one node's host over in-process sessions (ephemeral client keys, the host's key
// checked); the hosting node reaches its own host only through the loopback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_in_process_spec_sync_10() {
    let tnet = osis_transport::Net::new(3);
    let t2 = tnet.clone();
    converge("mem://s", tnet.endpoint("a"), tnet.endpoint("b"), move || t2.partition("a", "a")).await;
}

// spec/sync.md §10: the same over QUIC on localhost (tier 2: touches the network).
// Run: `cargo test-net -- --ignored driver::`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_quic_localhost_spec_sync_10() {
    use osis_transport::Quic;
    let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    converge(&format!("quic://127.0.0.1:{port}"), Quic::new(), Quic::new(), || {}).await;
}

// spec/requirements.md Deletion, notes/serving.md Hosting in the node: the host secret lives only
// while `host.0^` is set. Removing it shreds the secret, and the driver taking the earlier
// config late gets no secret for it: a stale `Action::Host` cannot bring a shredded secret back
// (nor listen with a key other than the config's), and a new start has a new key.
#[test]
fn host_secret_not_revived_by_stale_config_spec_sync_10() {
    use osis_node::sync::Action;
    let mut net = Net::new();
    let a = net.add_node(1, Default::default());
    let me = net.tid(a);
    let host = ct::Host { listen: vec!["mem://s".into()], ..Default::default() };
    let set = |net: &mut Net, on: bool| {
        let mut m = osis_node::Mutation::new();
        if on {
            m.replace(me, &ct::HOST, &host).unwrap();
        } else {
            m.remove_aspect(me, &ct::HOST).unwrap();
        }
        net.engine(a).commit(m).unwrap();
        net.sync(a).handle(Event::Local).into_iter().find_map(|x| match x {
            Action::Host(c) => Some(c),
            _ => None,
        })
    };
    let k1 = set(&mut net, true).flatten().expect("a host config").key;
    assert_eq!(net.sync(a).host_key(), Some(k1));
    assert!(net.sync(a).host_secret_for(&k1).is_some());
    assert_eq!(set(&mut net, false), Some(None), "stop");
    assert_eq!(net.sync(a).host_key(), None, "shredded");
    assert!(net.sync(a).host_secret_for(&k1).is_none());
    assert_eq!(net.sync(a).host_key(), None, "a stale config made no secret");
    let k2 = set(&mut net, true).flatten().expect("a host config").key;
    assert_ne!(k1, k2, "a new start has a new key");
    assert!(net.sync(a).host_secret_for(&k1).is_none(), "the stale config's key is not the secret's");
}

fn s_(x: &str) -> Value {
    Value::Str(x.into())
}

/// How the nodes of `converge_p2p` find each other besides `reach.0`.
pub enum Direct<'a> {
    None,
    /// Each also listens at its URL with a fresh LAN key (`SyncEngine::lan_secret`) and the other hears
    /// its signed announcement from 127.0.0.1.
    Heard([&'a str; 2]),
    /// Each runs the driver's LAN loop.
    #[allow(dead_code)]
    Loop([driver::LanConfig; 2]),
}

/// Two holders of a group whose label names no host converge peer to peer under the tokio
/// driver: each listens on its endpoint with its dialable secret, publishes the listener's key
/// in `reach.0`, dials the other at `peer://` and serves the other's sessions (co-reader peer).
/// `reach.0` carries `relays` and no address; `direct` says how else the nodes find each other
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
        // a's announcement socket is bound before b announces (the driver handles controls in
        // order, so a call answered after `Lan` means a joined): an announcement to a port not
        // bound yet is lost, the next comes only after `LAN_ANNOUNCE` (30 s, tokio time), which
        // is `GUARD`, and only a's routes are checked
        for (ctl, cfg) in [&actl, &bctl].into_iter().zip(cfgs) {
            assert!(ctl.send(Control::Lan(cfg)).is_ok());
            call(ctl, |_| ()).await;
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
                    && osis_transport::peer_items(&a.url).is_some_and(|h| h.iter().any(|x| x.parse::<std::net::SocketAddr>().is_ok()))
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

// spec/sync.md §5 (co-reader peer), §10: two nodes sync a label with no host under the tokio
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

// spec/sync.md §10 (IP consent): the driver dials a co-reader's node with this node's dialable
// key, so the target can judge consent on the key the transport proves (in-process: the key a
// listener sees is the dialer's).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_dials_co_reader_as_dialable_spec_sync_10() {
    let tnet = osis_transport::Net::new(6);
    let mut net = Net::new();
    let clock: Arc<dyn Clock> = net.clock.clone();
    let a = net.add_node(1, Default::default());
    let b = net.add_node(2, Default::default());
    let mut ls = Vec::new();
    for (n, url) in [(a, "mem://a"), (b, "mem://b")] {
        let secret = StaticSecret::from_bytes(*net.sync(n).dialable_secret().expose());
        let l = tnet.endpoint(url).listen(ListenConfig { url: url.into(), secret }).await.unwrap();
        let acts = net.sync(n).publish_reach(l.address().key, vec![]).unwrap();
        net.actions(n, acts);
        ls.push(l);
    }
    let _g = net.group_at(a, &[(b, Role::Write)], vec![]);
    let ka = ls[0].address().key;
    let mut lb = ls.remove(1);
    let (ctl, rx) = mpsc::unbounded_channel();
    let d = tokio::spawn(driver::run(net.take(a), tnet.endpoint("a"), clock, rx, log()));
    assert!(ctl.send(Control::Local).is_ok());
    let c = tokio::time::timeout(GUARD, lb.accept()).await.unwrap().unwrap();
    assert_eq!(osis_transport::Connection::peer_key(&c), ka);
    assert!(ctl.send(Control::Shutdown).is_ok());
    d.await.unwrap();
}

// notes/peers.md (driver): `Control::Reach` listens at the first of its URLs that listens (a
// node's fixed P2P port, else any) and publishes that listener's key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reach_takes_first_url_that_listens() {
    let tnet = osis_transport::Net::new(7);
    let mut net = Net::new();
    let clock: Arc<dyn Clock> = net.clock.clone();
    let a = net.add_node(1, Default::default());
    // the first URL is taken
    let _taken = tnet.endpoint("x").listen(ListenConfig { url: "mem://a-fixed".into(), secret: StaticSecret::from_bytes([9; 32]) }).await.unwrap();
    let (ctl, rx) = mpsc::unbounded_channel();
    let d = tokio::spawn(driver::run(net.take(a), tnet.endpoint("a"), clock, rx, log()));
    let (tx, reply) = oneshot::channel();
    assert!(ctl.send(Control::Reach { urls: vec!["mem://a-fixed".into(), "mem://a-any".into()], reply: Some(tx) }).is_ok());
    let addr = tokio::time::timeout(GUARD, reply).await.unwrap().unwrap().unwrap();
    assert_eq!(addr.url, "mem://a-any");
    assert_eq!(call(&ctl, |s| s.own_reach().map(|r| r.dialable)).await, Some(addr.key));
    assert!(ctl.send(Control::Shutdown).is_ok());
    d.await.unwrap();
}

/// A P2P transport over QUIC, exchanging addresses with no key: a node's `punching` accepts
/// co-readers' dialable keys only (osis), never the per-network LAN keys it dials LAN routes by.
fn p2p() -> osis_transport::P2p<osis_transport::QuicUdp> {
    osis_transport::P2p::new(osis_transport::QuicUdp::new()).punching(Arc::new(|_| false))
}

/// A relaying node on localhost (for anyone), its listener kept while the test runs, and its
/// `peer://` relay item.
async fn relay_node() -> (osis_transport::P2pListener<osis_transport::QuicUdp>, String) {
    let r = p2p().relaying(osis_transport::RelayConfig::new(Arc::new(|_| true))).unwrap();
    let l = r.listen(ListenConfig { url: "peer://127.0.0.1:0".into(), secret: StaticSecret::from_bytes([77; 32]) }).await.unwrap();
    let addr = l.address().url.strip_prefix("peer://").unwrap().parse().unwrap();
    let item = osis_transport::p2p::Relay { key: l.address().key, addr }.item();
    (l, item)
}

// spec/sync.md §5, §10: the same over P2P (QUIC) on localhost, no relay (tier 2: touches the
// network). Run: `cargo test-net -- --ignored driver::`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_p2p_localhost_spec_sync_10() {
    converge_p2p(p2p(), "peer://127.0.0.1:0", p2p(), "peer://127.0.0.1:0", vec![], Direct::Heard(["peer://127.0.0.1:0", "peer://127.0.0.1:0"])).await;
}

// spec/sync.md §10: two nodes over P2P find each other only by the driver's LAN loop: fresh
// keys per network, signed announcements over UDP on localhost (tier 2).
// Run: `cargo test-net -- --ignored driver::`.
#[cfg(feature = "lan")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_lan_loop_localhost_spec_sync_10() {
    // two announcement ports, each node announcing to the other's
    let base = 40_000 + (std::process::id() % 10_000) as u16 * 2;
    let to = |p: u16| vec![std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, p))];
    let cfg = |port: u16, other: u16| driver::LanConfig { port, to: to(other), listen: "peer://127.0.0.1:0".into(), watch: false, rejoin_min: driver::LAN_REJOIN_MIN };
    converge_p2p(p2p(), "peer://127.0.0.1:0", p2p(), "peer://127.0.0.1:0", vec![], Direct::Loop([cfg(base, base + 1), cfg(base + 1, base)])).await;
}

// spec/sync.md §10 (IPv6 LAN discovery): the same over IPv6 loopback: announcements on the IPv6
// socket carry the listener's IPv6 port and are dialed at their IPv6 source (tier 2).
// Run: `cargo test-net -- --ignored driver::`.
#[cfg(feature = "lan")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_lan_loop_ipv6_localhost_spec_sync_10() {
    let base = 30_000 + (std::process::id() % 10_000) as u16 * 2;
    let to = |p: u16| vec![std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, p))];
    let cfg = |port: u16, other: u16| driver::LanConfig { port, to: to(other), listen: "peer://[::1]:0".into(), watch: false, rejoin_min: driver::LAN_REJOIN_MIN };
    converge_p2p(p2p(), "peer://127.0.0.1:0", p2p(), "peer://127.0.0.1:0", vec![], Direct::Loop([cfg(base, base + 1), cfg(base + 1, base)])).await;
}

// spec/sync.md §10 (the proven route first): two nodes whose `reach.0` names only a relay on
// localhost also run the LAN loop: whatever route came up first, each ends on the other's LAN
// route alone (a relay connection is replaced once the LAN one is up) (tier 2).
// Run: `cargo test-net -- --ignored driver::`.
#[cfg(feature = "lan")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_lan_replaces_relay_localhost_spec_sync_10() {
    let (_relay, item) = relay_node().await;
    let r = vec![item.clone()];
    let url = format!("peer://127.0.0.1:0 {item}");
    let base = 20_000 + (std::process::id() % 10_000) as u16 * 2;
    let to = |p: u16| vec![std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, p))];
    let cfg = |port: u16, other: u16| driver::LanConfig { port, to: to(other), listen: "peer://127.0.0.1:0".into(), watch: false, rejoin_min: driver::LAN_REJOIN_MIN };
    converge_p2p(p2p(), &url, p2p(), &url, r, Direct::Loop([cfg(base, base + 1), cfg(base + 1, base)])).await;
}

// spec/sync.md §10: two nodes over P2P reach each other through a relaying node on localhost,
// the only route `reach.0` names (tier 2).
// Run: `cargo test-net -- --ignored driver::`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_p2p_relay_localhost_spec_sync_10() {
    let (_relay, item) = relay_node().await;
    let r = vec![item.clone()];
    let url = format!("peer://127.0.0.1:0 {item}");
    converge_p2p(p2p(), &url, p2p(), &url, r, Direct::None).await;
}

// spec/sync.md §10 (a fresh key per network join), notes/networking.md (rejoin interval): a
// network change right after a join is deferred to `rejoin_min` (each join drops the LAN
// listener and its connections); the deferred join then announces a fresh key (tier 2: UDP and
// P2P on localhost).
// Run: `cargo test-net -- --ignored driver::`.
#[cfg(feature = "lan")]
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
    let d = tokio::spawn(driver::run(net.take(a), p2p(), clock, rx, log()));
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

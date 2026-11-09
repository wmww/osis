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
/// Hosting in the node): a's `host^.0` has it listen at `url` with `own` admission, and the group's label
/// names a's host address. b is served from a's host store; a's own copy reaches its host over
/// the in-process loopback (`cut` then cuts a's transport from itself, so nothing else could).
async fn converge<T: Transport>(url: &str, a_ep: T, b_ep: T, cut: impl FnOnce()) {
    let mut net = Net::new();
    let clock: Arc<dyn Clock> = net.clock.clone();
    let a = net.add_node(1, Default::default());
    let b = net.add_node(2, Default::default());
    let me = net.node_tid(a);
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
// Run: `cargo test -p osis-node --test it -- --ignored driver:: --skip repro_`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_quic_localhost_spec_sync_10() {
    use osis_transport::Quic;
    let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    converge(&format!("quic://127.0.0.1:{port}"), Quic::new(), Quic::new(), || {}).await;
}

// spec/requirements.md Deletion, notes/serving.md Hosting in the node: the host secret lives only
// while `host^.0` is set. Removing it shreds the secret, and the driver taking the earlier
// config late gets no secret for it: a stale `Action::Host` cannot bring a shredded secret back
// (nor listen with a key other than the config's), and a new start has a new key.
#[test]
fn host_secret_not_revived_by_stale_config_spec_sync_10() {
    use osis_node::sync::Action;
    let mut net = Net::new();
    let a = net.add_node(1, Default::default());
    let me = net.node_tid(a);
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
    /// Each also listens at its URL with a fresh LAN key (`SyncEngine::lan_secret`) and the other
    /// hears its signed announcement from that node's IP.
    Heard([(&'a str, std::net::IpAddr); 2]),
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
    if let Direct::Heard(heard) = &direct {
        for (i, n, ep, (url, _)) in [(0, a, &a_ep, heard[0]), (1, b, &b_ep, heard[1])] {
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
    } else if let Direct::Heard(heard) = direct {
        // a hears b's announcement and b hears a's, from each one's IP
        for (ctl, ann, ip) in [(&actl, anns[1], heard[1].1), (&bctl, anns[0], heard[0].1)] {
            let f: driver::Call = Box::new(move |s: &mut SyncEngine| s.lan_seen(&ann, (ip, 47380).into()).1);
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

/// `P2p` on a host at `ip` (behind the NAT at `nat`) of `tnet`.
fn on_host(tnet: &osis_transport::Net, name: &str, ip: &str, nat: Option<std::net::IpAddr>) -> osis_transport::P2p<osis_transport::MemUdp> {
    osis_transport::P2p::new(tnet.udp(name, ip.parse().unwrap(), nat))
}

// spec/sync.md §5 (co-reader peer), §10: two nodes behind NATs sync a label with no host under
// the tokio driver over the real P2P code, each dialing the other by its dialable key through a
// relay it names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_p2p_in_process_spec_sync_5() {
    let tnet = osis_transport::Net::new(4);
    tnet.run_on_tokio();
    let r = on_host(&tnet, "r", "198.51.100.1", None).relaying(osis_transport::RelayConfig::new(Arc::new(|_| true))).unwrap();
    let rl = r.listen(ListenConfig { url: "peer://198.51.100.1:4040".into(), secret: StaticSecret::from_bytes([77; 32]) }).await.unwrap();
    let item = osis_transport::p2p::Relay { key: rl.address().key, addr: "198.51.100.1:4040".parse().unwrap() }.item();
    // symmetric NATs: no punching, the relay is the one route
    for public in ["203.0.113.1", "203.0.113.2"] {
        tnet.add_nat(public.parse().unwrap(), osis_transport::Nat::SYMMETRIC);
    }
    let (a, b) = (on_host(&tnet, "a", "10.0.1.2", Some("203.0.113.1".parse().unwrap())), on_host(&tnet, "b", "10.0.2.2", Some("203.0.113.2".parse().unwrap())));
    converge_p2p(a, &format!("peer://10.0.1.2:7000 {item}"), b, &format!("peer://10.0.2.2:7000 {item}"), vec![item.clone()], Direct::None).await;
}

/// Waits until `f` holds.
async fn until(f: impl Fn() -> bool) {
    tokio::time::timeout(GUARD, async {
        while !f() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

// spec/sync.md §10 (switching), notes/networking.md: two nodes behind cone NATs, synced through a
// relay, switch to direct: the punch, once it can get through, ends the relayed connections, the
// engine's redial takes the parked direct ones, and the nodes keep syncing with the relay gone.
// The hosts cannot reach each other (`partition`) until the relayed sessions are up, so the
// direct connection always comes after them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_relayed_becomes_direct_spec_sync_10() {
    let tnet = osis_transport::Net::new(6);
    tnet.run_on_tokio();
    let r = on_host(&tnet, "r", "198.51.100.1", None).relaying(osis_transport::RelayConfig::new(Arc::new(|_| true))).unwrap();
    let rl = r.listen(ListenConfig { url: "peer://198.51.100.1:4040".into(), secret: StaticSecret::from_bytes([77; 32]) }).await.unwrap();
    let item = osis_transport::p2p::Relay { key: rl.address().key, addr: "198.51.100.1:4040".parse().unwrap() }.item();
    for public in ["203.0.113.1", "203.0.113.2"] {
        tnet.add_nat(public.parse().unwrap(), osis_transport::Nat::CONE);
    }
    tnet.partition("a", "b");
    let (ta, tb) = (on_host(&tnet, "a", "10.0.1.2", Some("203.0.113.1".parse().unwrap())), on_host(&tnet, "b", "10.0.2.2", Some("203.0.113.2".parse().unwrap())));

    let mut net = Net::new();
    let clock: Arc<dyn Clock> = net.clock.clone();
    let a = net.add_node(1, Default::default());
    let b = net.add_node(2, Default::default());
    let mut listeners = Vec::new();
    for (n, ep, url) in [(a, &ta, format!("peer://10.0.1.2:7000 {item}")), (b, &tb, format!("peer://10.0.2.2:7000 {item}"))] {
        let secret = net.sync(n).dialable_secret();
        let l = ep.listen(ListenConfig { url, secret: StaticSecret::from_bytes(*secret.expose()) }).await.unwrap();
        let acts = net.sync(n).publish_reach(l.address().key, vec![item.clone()]).unwrap();
        net.actions(n, acts);
        listeners.push(vec![l]);
    }
    // registered before the drivers dial: a dial the relay cannot place waits the retry pause,
    // which the manual clock never ends
    until(|| listeners.iter().all(|l: &Vec<osis_transport::P2pListener<osis_transport::MemUdp>>| l[0].observed().len() == 1)).await;
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    let t = net.item(a, g, g, "first");
    let brx = net.engine(b).subscribe();
    let (sa, sb) = (net.take(a), net.take(b));
    let (actl, arx) = mpsc::unbounded_channel();
    let (bctl, brx2) = mpsc::unbounded_channel();
    let lb = listeners.pop().unwrap();
    let la = listeners.pop().unwrap();
    let da = tokio::spawn(driver::run_serving(sa, ta, la, clock.clone(), arx, log()));
    let db = tokio::spawn(driver::run_serving(sb, tb, lb, clock.clone(), brx2, log()));
    let write = async |value: &'static str| {
        call(&actl, move |s| {
            let mut m = osis_node::Mutation::new();
            m.set(t, &REG, &s_(value)).unwrap();
            s.engine_mut().commit(m).unwrap().unwrap()
        })
        .await
    };

    // through the relay: no direct connection can exist yet
    let c = write("relayed").await;
    let brx = applied(brx, c).await;
    assert_eq!(tnet.connections_between("a", "b"), 0);

    // the punch gets through: the relayed connections end, leaving each node its registration
    tnet.heal("a", "b");
    until(|| tnet.connections_between("a", "b") >= 1 && tnet.connections_between("a", "r") == 1 && tnet.connections_between("b", "r") == 1).await;

    // the relay goes: only a direct session can carry this
    tnet.kill("r");
    let c = write("direct").await;
    let _ = applied(brx, c).await;
    assert_eq!(call(&bctl, move |s| read(s, t)).await, Some(s_("direct")));
    for ctl in [&actl, &bctl] {
        assert!(ctl.send(Control::Shutdown).is_ok());
    }
    da.await.unwrap();
    db.await.unwrap();
}

// spec/sync.md §10: the same behind one NAT with no relay: each node also listens with a fresh
// LAN key, hears the other's signed announcement and dials its LAN address (the only route).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_p2p_lan_in_process_spec_sync_10() {
    let tnet = osis_transport::Net::new(5);
    tnet.run_on_tokio();
    let lan: std::net::IpAddr = "203.0.113.5".parse().unwrap();
    tnet.add_nat(lan, osis_transport::Nat::CONE);
    let (ipa, ipb): (std::net::IpAddr, std::net::IpAddr) = ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
    let (a, b) = (on_host(&tnet, "a", "10.0.0.1", Some(lan)), on_host(&tnet, "b", "10.0.0.2", Some(lan)));
    converge_p2p(a, "peer://10.0.0.1:7000", b, "peer://10.0.0.2:7000", vec![], Direct::Heard([("peer://10.0.0.1:7001", ipa), ("peer://10.0.0.2:7001", ipb)])).await;
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

/// A P2P transport over QUIC.
fn p2p() -> osis_transport::P2p<osis_transport::QuicUdp> {
    osis_transport::P2p::new(osis_transport::QuicUdp::new())
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
// network). Run: `cargo test -p osis-node --test it -- --ignored driver:: --skip repro_`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_p2p_localhost_spec_sync_10() {
    converge_p2p(p2p(), "peer://127.0.0.1:0", p2p(), "peer://127.0.0.1:0", vec![], Direct::Heard([("peer://127.0.0.1:0", std::net::Ipv4Addr::LOCALHOST.into()), ("peer://127.0.0.1:0", std::net::Ipv4Addr::LOCALHOST.into())])).await;
}

/// Two UDP ports free on `ip` now, picked by the OS so concurrent runs do not meet, for LAN
/// loops confined to loopback (never `lan::PORT`: tools/policy.py).
fn free_udp_ports(ip: std::net::IpAddr) -> [u16; 2] {
    let (a, b) = (std::net::UdpSocket::bind((ip, 0)).unwrap(), std::net::UdpSocket::bind((ip, 0)).unwrap());
    [a.local_addr().unwrap().port(), b.local_addr().unwrap().port()]
}

// spec/sync.md §10: two nodes over P2P find each other only by the driver's LAN loop: fresh
// keys per network, signed announcements over UDP on localhost (tier 2).
// Run: `cargo test -p osis-node --test it -- --ignored driver:: --skip repro_`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_lan_loop_localhost_spec_sync_10() {
    // two announcement ports, each node announcing to the other's
    let [p, q] = free_udp_ports(std::net::Ipv4Addr::LOCALHOST.into());
    let to = |p: u16| vec![std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, p))];
    let cfg = |port: u16, other: u16| driver::LanConfig { port, to: to(other), listen: "peer://127.0.0.1:0".into(), watch: false, announce: driver::LAN_ANNOUNCE, join_repeats: 0, join_gap: Duration::ZERO, rejoin_min: driver::LAN_REJOIN_MIN };
    converge_p2p(p2p(), "peer://127.0.0.1:0", p2p(), "peer://127.0.0.1:0", vec![], Direct::Loop([cfg(p, q), cfg(q, p)])).await;
}

// spec/sync.md §10 (IPv6 LAN discovery): the same over IPv6 loopback: announcements on the IPv6
// socket carry the listener's IPv6 port and are dialed at their IPv6 source (tier 2).
// Run: `cargo test -p osis-node --test it -- --ignored driver:: --skip repro_`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_lan_loop_ipv6_localhost_spec_sync_10() {
    let [p, q] = free_udp_ports(std::net::Ipv6Addr::LOCALHOST.into());
    let to = |p: u16| vec![std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, p))];
    let cfg = |port: u16, other: u16| driver::LanConfig { port, to: to(other), listen: "peer://[::1]:0".into(), watch: false, announce: driver::LAN_ANNOUNCE, join_repeats: 0, join_gap: Duration::ZERO, rejoin_min: driver::LAN_REJOIN_MIN };
    converge_p2p(p2p(), "peer://127.0.0.1:0", p2p(), "peer://127.0.0.1:0", vec![], Direct::Loop([cfg(p, q), cfg(q, p)])).await;
}

// spec/sync.md §10 (the proven route first): two nodes whose `reach.0` names only a relay on
// localhost also run the LAN loop: whatever route came up first, each ends on the other's LAN
// route alone (a relay connection is replaced once the LAN one is up) (tier 2).
// Run: `cargo test -p osis-node --test it -- --ignored driver:: --skip repro_`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn driver_lan_replaces_relay_localhost_spec_sync_10() {
    let (_relay, item) = relay_node().await;
    let r = vec![item.clone()];
    let url = format!("peer://127.0.0.1:0 {item}");
    let [p, q] = free_udp_ports(std::net::Ipv4Addr::LOCALHOST.into());
    let to = |p: u16| vec![std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, p))];
    let cfg = |port: u16, other: u16| driver::LanConfig { port, to: to(other), listen: "peer://127.0.0.1:0".into(), watch: false, announce: driver::LAN_ANNOUNCE, join_repeats: 0, join_gap: Duration::ZERO, rejoin_min: driver::LAN_REJOIN_MIN };
    converge_p2p(p2p(), &url, p2p(), &url, r, Direct::Loop([cfg(p, q), cfg(q, p)])).await;
}

// spec/sync.md §10: two nodes over P2P reach each other through a relaying node on localhost,
// the only route `reach.0` names (tier 2).
// Run: `cargo test -p osis-node --test it -- --ignored driver:: --skip repro_`.
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
// listener and its connections); the deferred join then announces a fresh key (tier 2: over the
// nat.rs model, but it watches wall-clock gaps: a tier-1 run on a loaded box could stall past them).
// Run: `cargo test -p osis-node --test it -- --ignored driver:: --skip repro_`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn lan_rejoin_interval_spec_sync_10() {
    use osis_transport::lan::LanSocket;
    let tnet = osis_transport::Net::new(26);
    tnet.run_on_tokio();
    let a = lan_host(&tnet, "a", "10.0.0.1", &[("s", "10.0.0.1")]);
    let ear = lan_host(&tnet, "e", "10.0.0.9", &[("s", "10.0.0.9")]).lan_socket(osis_transport::lan::PORT).unwrap();
    let (to, listen) = lan_v4();
    let cfg = driver::LanConfig { port: osis_transport::lan::PORT, to: vec![to], listen: listen.into(), watch: false, announce: driver::LAN_ANNOUNCE, join_repeats: 0, join_gap: Duration::ZERO, rejoin_min: Duration::from_secs(2) };
    let run = lan_run_with(vec![a], cfg).await;
    let (first, _) = tokio::time::timeout(GUARD, ear.recv()).await.unwrap().unwrap();
    // a change at once: deferred, nothing announced now
    assert!(run.ctl[0].send(Control::LanRejoin).is_ok());
    assert!(tokio::time::timeout(Duration::from_millis(300), ear.recv()).await.is_err(), "no join inside the interval");
    // the LAN timer runs the deferred join: a fresh key
    let (next, _) = tokio::time::timeout(Duration::from_secs(10), ear.recv()).await.unwrap().unwrap();
    assert_ne!(next.key, first.key);
    tokio::time::timeout(GUARD, run.stop()).await.unwrap();
}

/// How often the in-process LAN tests' nodes announce (only how soon the tests finish).
const LAN_REPEAT: Duration = Duration::from_millis(20);

fn ip(s: &str) -> std::net::IpAddr {
    s.parse().unwrap()
}

/// A host of `tnet` at `at`, on `segments` (name, its address there), no NAT.
fn lan_host(tnet: &osis_transport::Net, name: &str, at: &str, segments: &[(&str, &str)]) -> osis_transport::MemUdp {
    let h = tnet.udp(name, ip(at), None);
    for (seg, a) in segments {
        h.on_lan(seg, ip(a));
    }
    h
}

/// Announcements `ear` hears until `n` came from `from`; every one's source is among `allowed`.
async fn heard_from(ear: &osis_transport::MemLan, from: std::net::IpAddr, n: usize, allowed: &[std::net::IpAddr]) {
    use osis_transport::lan::LanSocket;
    let mut count = 0;
    while count < n {
        let (_, src) = tokio::time::timeout(GUARD, ear.recv()).await.expect("nothing heard").unwrap();
        assert!(allowed.contains(&src.ip()), "heard {src}");
        if src.ip() == from {
            assert_eq!(src.port(), osis_transport::lan::PORT, "the announcement socket's port");
            count += 1;
        }
    }
}

/// Holders of one group (the first has written `t`), each on its driver with the LAN loop over
/// the model's segments.
struct LanRun {
    ctl: Vec<mpsc::UnboundedSender<Control>>,
    tasks: Vec<tokio::task::JoinHandle<SyncEngine>>,
    t: Tid,
    /// The last node's commit events.
    last: Receiver<EngineEvent>,
}

/// Runs the LAN loop on each of `hosts`, announcing to `to`, listening at `listen`.
async fn lan_run(hosts: Vec<osis_transport::MemUdp>, to: std::net::SocketAddr, listen: &str, announce: Duration) -> LanRun {
    lan_run_rejoin(hosts, to, listen, announce, driver::LAN_REJOIN_MIN).await
}

/// `lan_run` with network changes rejoining at most every `rejoin_min`.
async fn lan_run_rejoin(hosts: Vec<osis_transport::MemUdp>, to: std::net::SocketAddr, listen: &str, announce: Duration, rejoin_min: Duration) -> LanRun {
    let cfg = driver::LanConfig { port: osis_transport::lan::PORT, to: vec![to], listen: listen.into(), watch: false, announce, join_repeats: 0, join_gap: Duration::ZERO, rejoin_min };
    lan_run_with(hosts, cfg).await
}

/// `lan_run` with every node on the LAN loop settings `cfg`.
async fn lan_run_with(hosts: Vec<osis_transport::MemUdp>, cfg: driver::LanConfig) -> LanRun {
    let mut net = Net::new();
    let clock: Arc<dyn Clock> = net.clock.clone();
    let nodes: Vec<_> = (0..hosts.len()).map(|i| net.add_node(i as u64 + 1, Default::default())).collect();
    for n in &nodes {
        let secret = net.sync(*n).dialable_secret();
        let k = osis_crypto::SigningSecret::from_seed(&secret).verifying_key().to_bytes();
        let acts = net.sync(*n).publish_reach(k, vec![]).unwrap();
        net.actions(*n, acts);
    }
    let writers: Vec<_> = nodes[1..].iter().map(|n| (*n, Role::Write)).collect();
    let g = net.group_at(nodes[0], &writers, vec![]);
    let t = net.item(nodes[0], g, g, "first");
    let last = net.engine(*nodes.last().unwrap()).subscribe();
    let (mut ctl, mut tasks) = (Vec::new(), Vec::new());
    for (n, udp) in nodes.iter().zip(hosts) {
        let (tx, rx) = mpsc::unbounded_channel();
        tasks.push(tokio::spawn(driver::run(net.take(*n), osis_transport::P2p::new(udp), clock.clone(), rx, log())));
        assert!(tx.send(Control::Lan(cfg.clone())).is_ok());
        ctl.push(tx);
    }
    LanRun { ctl, tasks, t, last }
}

impl LanRun {
    /// The first node writes; the last applies it (only a connection between them can carry it).
    async fn write_reaches_last(self) -> Self {
        let LanRun { ctl, tasks, t, last } = self;
        let c = call(&ctl[0], move |s| {
            let mut m = osis_node::Mutation::new();
            m.set(t, &REG, &s_("second")).unwrap();
            s.engine_mut().commit(m).unwrap().unwrap()
        })
        .await;
        let last = applied(last, c).await;
        LanRun { ctl, tasks, t, last }
    }

    async fn stop(self) {
        for c in &self.ctl {
            let _ = c.send(Control::Shutdown);
        }
        for t in self.tasks {
            t.await.unwrap();
        }
    }
}

/// Waits until node `ctl`'s peer routes are up at exactly the IPs `want`.
async fn routes_at(ctl: &mpsc::UnboundedSender<Control>, want: &[&str]) {
    let want: Vec<std::net::IpAddr> = want.iter().map(|x| ip(x)).collect();
    let ctl = ctl.clone();
    tokio::time::timeout(GUARD, async move {
        loop {
            let routes = call(&ctl, |s| s.peer_routes()).await;
            let mut up: Vec<std::net::IpAddr> = routes.iter().filter(|(_, _, up)| *up).filter_map(|(_, a, _)| osis_transport::peer_items(&a.url)?.first()?.parse::<std::net::SocketAddr>().ok()).map(|a| a.ip()).collect();
            up.sort();
            if up == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

/// Broadcast target and listener URL for IPv4 hosts.
fn lan_v4() -> (std::net::SocketAddr, &'static str) {
    (osis_transport::lan::broadcast(osis_transport::lan::PORT), "peer://0.0.0.0:0")
}

/// All-nodes target and listener URL for IPv6 hosts.
fn lan_v6() -> (std::net::SocketAddr, &'static str) {
    (osis_transport::lan::multicast(osis_transport::lan::PORT), "peer://[::]:0")
}

// spec/sync.md §10: two nodes on one LAN segment find each other only by the driver's LAN loop,
// connect at the addresses their announcements came from, and sync.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_lan_same_segment_finds_and_connects_spec_sync_10() {
    let tnet = osis_transport::Net::new(11);
    tnet.run_on_tokio();
    let (a, b) = (lan_host(&tnet, "a", "10.0.0.1", &[("s", "10.0.0.1")]), lan_host(&tnet, "b", "10.0.0.2", &[("s", "10.0.0.2")]));
    let (to, listen) = lan_v4();
    let run = lan_run(vec![a, b], to, listen, LAN_REPEAT).await.write_reaches_last().await;
    routes_at(&run.ctl[0], &["10.0.0.2"]).await;
    routes_at(&run.ctl[1], &["10.0.0.1"]).await;
    run.stop().await;
}

// spec/sync.md §10: an announcement stays on its segment: an ear on each hears only its own
// segment's node, repeatedly, and the two nodes (holders of one group) never connect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_lan_other_segment_not_found_spec_sync_10() {
    use osis_transport::lan::PORT;
    let tnet = osis_transport::Net::new(12);
    tnet.run_on_tokio();
    let (a, b) = (lan_host(&tnet, "a", "10.0.1.1", &[("s1", "10.0.1.1")]), lan_host(&tnet, "b", "10.0.2.1", &[("s2", "10.0.2.1")]));
    let ear1 = lan_host(&tnet, "e1", "10.0.1.9", &[("s1", "10.0.1.9")]).lan_socket(PORT).unwrap();
    let ear2 = lan_host(&tnet, "e2", "10.0.2.9", &[("s2", "10.0.2.9")]).lan_socket(PORT).unwrap();
    let (to, listen) = lan_v4();
    let run = lan_run(vec![a, b], to, listen, LAN_REPEAT).await;
    heard_from(&ear1, ip("10.0.1.1"), 3, &[ip("10.0.1.1")]).await;
    heard_from(&ear2, ip("10.0.2.1"), 3, &[ip("10.0.2.1")]).await;
    assert_eq!(tnet.connections_between("a", "b"), 0);
    run.stop().await;
}

// spec/sync.md §10: a node on two segments is found on each, at its address on that segment,
// by nodes that cannot hear each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_lan_two_segments_found_on_each_spec_sync_10() {
    let tnet = osis_transport::Net::new(13);
    tnet.run_on_tokio();
    let a = lan_host(&tnet, "a", "10.0.1.1", &[("s1", "10.0.1.1")]);
    let m = lan_host(&tnet, "m", "10.0.1.9", &[("s1", "10.0.1.9"), ("s2", "192.168.2.9")]);
    let b = lan_host(&tnet, "b", "192.168.2.1", &[("s2", "192.168.2.1")]);
    let (to, listen) = lan_v4();
    let run = lan_run(vec![a, m, b], to, listen, LAN_REPEAT).await;
    routes_at(&run.ctl[0], &["10.0.1.9"]).await;
    routes_at(&run.ctl[2], &["192.168.2.9"]).await;
    run.stop().await;
}

// spec/sync.md §10: announcements repeat, so losing them only delays finding a neighbour: nothing
// connects while every one is lost, and a later one connects the nodes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_lan_lost_announcement_recovered_by_later_spec_sync_10() {
    let tnet = osis_transport::Net::new(14);
    tnet.run_on_tokio();
    let (a, b) = (lan_host(&tnet, "a", "10.0.0.1", &[("s", "10.0.0.1")]), lan_host(&tnet, "b", "10.0.0.2", &[("s", "10.0.0.2")]));
    tnet.set_lan_loss("s", 100);
    let (to, listen) = lan_v4();
    let run = lan_run(vec![a, b], to, listen, LAN_REPEAT).await;
    until(|| tnet.lan_lost("s") >= 4).await;
    assert_eq!(tnet.connections_between("a", "b"), 0, "every announcement lost");
    tnet.set_lan_loss("s", 0);
    let run = run.write_reaches_last().await;
    run.stop().await;
}

// spec/sync.md §10: the receiver sees the announcement's source as the model assigns it (the
// sender's address on that segment, not its host address), and dials that address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_lan_source_is_the_segment_address_spec_sync_10() {
    use osis_transport::lan::PORT;
    let tnet = osis_transport::Net::new(15);
    tnet.run_on_tokio();
    let (a, b) = (lan_host(&tnet, "a", "10.0.0.1", &[("s", "172.16.0.5")]), lan_host(&tnet, "b", "10.0.0.2", &[("s", "172.16.0.6")]));
    let ear = lan_host(&tnet, "e", "10.0.0.9", &[("s", "172.16.0.9")]).lan_socket(PORT).unwrap();
    let (to, listen) = lan_v4();
    let run = lan_run(vec![a, b], to, listen, LAN_REPEAT).await;
    heard_from(&ear, ip("172.16.0.5"), 2, &[ip("172.16.0.5"), ip("172.16.0.6")]).await;
    routes_at(&run.ctl[1], &["172.16.0.5"]).await;
    run.stop().await;
}

// spec/sync.md §10: a stopped node stops announcing: an ear bound after it stopped hears the
// node that still runs, repeatedly, and never the stopped one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_lan_stopped_node_not_announced_spec_sync_10() {
    use osis_transport::lan::PORT;
    let tnet = osis_transport::Net::new(16);
    tnet.run_on_tokio();
    let (a, b) = (lan_host(&tnet, "a", "10.0.0.1", &[("s", "10.0.0.1")]), lan_host(&tnet, "b", "10.0.0.2", &[("s", "10.0.0.2")]));
    let before = lan_host(&tnet, "e1", "10.0.0.8", &[("s", "10.0.0.8")]).lan_socket(PORT).unwrap();
    let (to, listen) = lan_v4();
    let mut run = lan_run(vec![a, b], to, listen, LAN_REPEAT).await;
    heard_from(&before, ip("10.0.0.1"), 2, &[ip("10.0.0.1"), ip("10.0.0.2")]).await;
    let (ctl_a, task_a) = (run.ctl.remove(0), run.tasks.remove(0));
    assert!(ctl_a.send(Control::Shutdown).is_ok());
    task_a.await.unwrap();
    let after = lan_host(&tnet, "e2", "10.0.0.9", &[("s", "10.0.0.9")]).lan_socket(PORT).unwrap();
    heard_from(&after, ip("10.0.0.2"), 3, &[ip("10.0.0.2")]).await;
    run.stop().await;
}

// spec/sync.md §10: a network change inside the rejoin interval is not lost: with nothing else
// due (announcements never repeat, the interval's end is the only timer), the loop joins again
// with a fresh key when the interval ends. `Duration::MAX` announces once and does not overflow.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_lan_deferred_rejoin_runs_when_due_spec_sync_10() {
    use osis_transport::lan::{LanSocket, PORT};
    let tnet = osis_transport::Net::new(24);
    tnet.run_on_tokio();
    let (a, b) = (lan_host(&tnet, "a", "10.0.0.1", &[("s", "10.0.0.1")]), lan_host(&tnet, "b", "10.0.0.2", &[("s", "10.0.0.2")]));
    let ear = lan_host(&tnet, "e", "10.0.0.9", &[("s", "10.0.0.9")]).lan_socket(PORT).unwrap();
    let (to, listen) = lan_v4();
    let run = lan_run_rejoin(vec![a, b], to, listen, Duration::MAX, Duration::from_millis(300)).await;
    let from_a = |x: (osis_transport::lan::Announce, std::net::SocketAddr)| (x.1.ip() == ip("10.0.0.1")).then_some(x.0.key);
    let first = loop {
        if let Some(k) = from_a(tokio::time::timeout(GUARD, ear.recv()).await.unwrap().unwrap()) {
            break k;
        }
    };
    assert!(run.ctl[0].send(Control::LanRejoin).is_ok());
    let next = loop {
        if let Some(k) = from_a(tokio::time::timeout(GUARD, ear.recv()).await.unwrap().unwrap()) {
            break k;
        }
    };
    assert_ne!(next, first, "a fresh key");
    run.stop().await;
}

// spec/sync.md §10: `LanConfig::announce` 0 repeats as fast as the loop runs and the driver still
// takes controls: it stops when asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_lan_zero_announce_interval_stops_spec_sync_10() {
    use osis_transport::lan::PORT;
    let tnet = osis_transport::Net::new(25);
    tnet.run_on_tokio();
    let (a, b) = (lan_host(&tnet, "a", "10.0.0.1", &[("s", "10.0.0.1")]), lan_host(&tnet, "b", "10.0.0.2", &[("s", "10.0.0.2")]));
    let ear = lan_host(&tnet, "e", "10.0.0.9", &[("s", "10.0.0.9")]).lan_socket(PORT).unwrap();
    let (to, listen) = lan_v4();
    let run = lan_run(vec![a, b], to, listen, Duration::ZERO).await;
    heard_from(&ear, ip("10.0.0.1"), 3, &[ip("10.0.0.1"), ip("10.0.0.2")]).await;
    tokio::time::timeout(GUARD, run.stop()).await.unwrap();
}

// spec/sync.md §10 (Joining): a join announces a few more times soon after, so a lost first
// announcement does not wait a whole announcement period.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_lan_join_repeats_its_announcement_spec_sync_10() {
    let tnet = osis_transport::Net::new(24);
    tnet.run_on_tokio();
    let a = lan_host(&tnet, "a", "10.0.0.1", &[("s", "10.0.0.1")]);
    let ear = lan_host(&tnet, "e", "10.0.0.9", &[("s", "10.0.0.9")]).lan_socket(osis_transport::lan::PORT).unwrap();
    let (to, listen) = lan_v4();
    let cfg = driver::LanConfig { port: osis_transport::lan::PORT, to: vec![to], listen: listen.into(), watch: false, announce: Duration::from_secs(3600), join_repeats: 2, join_gap: Duration::from_millis(5), rejoin_min: driver::LAN_REJOIN_MIN };
    let run = lan_run_with(vec![a], cfg).await;
    heard_from(&ear, ip("10.0.0.1"), 3, &[ip("10.0.0.1")]).await;
    tokio::time::timeout(GUARD, run.stop()).await.unwrap();
}

// spec/sync.md §10: a node that cannot bind the announcement port (taken, denied) has no LAN loop
// and works on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_lan_failed_bind_leaves_the_node_working_spec_sync_10() {
    let tnet = osis_transport::Net::new(25);
    tnet.run_on_tokio();
    let a = lan_host(&tnet, "a", "10.0.0.1", &[("s", "10.0.0.1")]);
    let _taken = a.lan_socket(osis_transport::lan::PORT).unwrap();
    let (to, listen) = lan_v4();
    let run = lan_run(vec![a], to, listen, LAN_REPEAT).await;
    let t = run.t;
    let c = call(&run.ctl[0], move |s| {
        let mut m = osis_node::Mutation::new();
        m.set(t, &REG, &s_("still here")).unwrap();
        s.engine_mut().commit(m).unwrap().is_some()
    })
    .await;
    assert!(c, "a write commits after the failed bind");
    tokio::time::timeout(GUARD, run.stop()).await.unwrap();
}

/// Two nodes at `addrs` on one segment connect through the LAN loop.
async fn lan_pair_connects(seed: u64, addrs: [&str; 2], (to, listen): (std::net::SocketAddr, &str)) {
    let tnet = osis_transport::Net::new(seed);
    tnet.run_on_tokio();
    let (a, b) = (lan_host(&tnet, "a", addrs[0], &[("s", addrs[0])]), lan_host(&tnet, "b", addrs[1], &[("s", addrs[1])]));
    lan_run(vec![a, b], to, listen, LAN_REPEAT).await.write_reaches_last().await.stop().await;
}

// spec/sync.md §10: announcements from private IPv4 and IPv6 sources (row 30's controls) match.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_lan_private_sources_connect_spec_sync_10() {
    lan_pair_connects(17, ["10.3.0.1", "10.3.0.2"], lan_v4()).await;
    lan_pair_connects(18, ["fc00::1", "fc00::2"], lan_v6()).await;
    lan_pair_connects(19, ["fe80::1", "fe80::2"], lan_v6()).await;
}

// issues/no-server-audit.md row 30: nodes on one segment connect whatever their addresses look
// like; the source filter (`lan.rs` `is_local`, `lan_seen`) drops CGNAT, global IPv4 and IPv6 and
// Yggdrasil sources.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "issues/net-connect.md"]
async fn repro_lan_any_source_connects() {
    lan_pair_connects(20, ["100.64.0.1", "100.64.0.2"], lan_v4()).await;
    lan_pair_connects(21, ["203.0.113.1", "203.0.113.2"], lan_v4()).await;
    lan_pair_connects(22, ["2001:db8::1", "2001:db8::2"], lan_v6()).await;
    lan_pair_connects(23, ["200::1", "200::2"], lan_v6()).await;
}

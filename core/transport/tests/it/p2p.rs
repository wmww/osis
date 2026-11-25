//! P2P (`p2p`) over the in-process NAT model (`nat`): relaying, observed addresses, hole
//! punching, switching to direct, relay limits; the relay wire bytes. spec/sync-transport.md §3.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::{ip, now_or_never};
use osis_transport::p2p::{Alpn, Relay, Sock, Udp};
use osis_transport::*;
use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn secret(b: u8) -> StaticSecret {
    StaticSecret::from_bytes([b; 32])
}

const RELAY_IP: &str = "198.51.100.1";

/// A net with a relaying node at `RELAY_IP:4040` (key of secret 1), its listener running.
struct World {
    net: Net,
    sched: Sched,
    relay: Relay,
    /// The relaying node.
    node: P2p<MemUdp>,
    _relay_l: P2pListener<MemUdp>,
}

fn world(seed: u64, cfg: RelayConfig) -> World {
    world_at(seed, cfg, RELAY_IP, None)
}

/// A world whose relay is at `at`, behind the NAT at `nat` if any.
fn world_at(seed: u64, cfg: RelayConfig, at: &str, nat: Option<IpAddr>) -> World {
    let net = Net::new(seed);
    let mut sched = Sched::new(seed, Some(net.clone()));
    let node = P2p::new(net.udp(ip(at), nat)).relaying(cfg);
    let (r, url) = (node.clone(), format!("peer://{at}:4040"));
    let l = sched.block_on(async move { r.listen(ListenConfig { url, secret: secret(1) }).await.unwrap() }).unwrap();
    let relay = Relay { key: l.address().key, addr: sa(&format!("{at}:4040")) };
    World { net, sched, relay, node, _relay_l: l }
}

/// `udp` listens at `<at>:7000` and registers at `w`'s relay, under `w`'s scheduler.
fn listen_via(w: &mut World, udp: MemUdp, at: &str, s: u8) -> P2pListener<MemUdp> {
    let b = P2p::new(udp);
    let url = format!("peer://{at}:7000 {}", w.relay.item());
    let l = w.sched.block_on(async move { b.listen(ListenConfig { url, secret: secret(s) }).await.unwrap() }).unwrap();
    w.sched.run();
    l
}

fn anyone() -> RelayConfig {
    RelayConfig::new(Arc::new(|_| true))
}

/// A host at `inside`, behind a NAT at `public` with `nat` (none: `inside` is public).
fn host(net: &Net, inside: &str, public: &str, nat: Option<Nat>) -> MemUdp {
    match nat {
        Some(n) => {
            net.add_nat(ip(public), n);
            net.udp(ip(inside), Some(ip(public)))
        }
        None => net.udp(ip(inside), None),
    }
}

/// Accepts connections; echoes each stream chunk by chunk; records whether each was relayed.
fn echo(sched: &Sched, mut l: P2pListener<MemUdp>) -> Rc<RefCell<Vec<bool>>> {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let (sp, s2) = (sched.spawner(), seen.clone());
    sched.spawn(async move {
        while let Ok(c) = l.accept().await {
            s2.borrow_mut().push(c.rank() == RANK_RELAYED);
            let sp2 = sp.clone();
            sp.spawn(async move {
                while let Ok((tx, rx)) = c.accept_stream().await {
                    sp2.spawn(pipe(rx, tx));
                }
            });
        }
    });
    seen
}

async fn try_round_trip(c: &P2pConn<MemConn>, data: &[u8]) -> Result<(P2pSend<MemConn>, P2pRecv<MemConn>), Error> {
    let (mut tx, mut rx) = c.open_stream().await?;
    tx.write_all(data).await?;
    let mut got = vec![0u8; data.len()];
    let mut at = 0;
    while at < got.len() {
        let n = rx.read(&mut got[at..]).await?;
        assert!(n > 0);
        at += n;
    }
    assert_eq!(got, data);
    Ok((tx, rx))
}

async fn round_trip(c: &P2pConn<MemConn>, data: &[u8]) -> (P2pSend<MemConn>, P2pRecv<MemConn>) {
    try_round_trip(c, data).await.unwrap()
}

use osis_transport::p2p::{P2pRecv, P2pSend};

/// A dials B (behind `nat_b`) through the relay only; returns whether the first connection was
/// direct and whether a direct one exists after the punch settled. Checks the session both ways.
/// A host with no NAT is at its public address.
fn punch(seed: u64, nat_a: Option<Nat>, nat_b: Option<Nat>) -> (bool, bool) {
    punch_counted(seed, nat_a, nat_b).0
}

/// `punch`, and how many punch packets went out.
fn punch_counted(seed: u64, nat_a: Option<Nat>, nat_b: Option<Nat>) -> ((bool, bool), u64) {
    let w = world(seed, anyone());
    let at = |inside, public, nat: Option<Nat>| if nat.is_some() { inside } else { public };
    let b_at = at("10.0.0.2", "203.0.113.2", nat_b);
    let (a, b) = (host(&w.net, at("10.0.1.2", "203.0.113.1", nat_a), "203.0.113.1", nat_a), host(&w.net, b_at, "203.0.113.2", nat_b));
    let net = w.net.clone();
    let r = punch_in(w, a, b, b_at, "203.0.113.2");
    (r, net.punches())
}

/// `punch` between hosts `a` and `b` (at `b_at`) of world `w`; the relay must see `b` at `seen`.
fn punch_in(mut w: World, a: MemUdp, b: MemUdp, b_at: &str, seen: &str) -> (bool, bool) {
    let lb = listen_via(&mut w, b, b_at, 2);
    let kb = lb.address().key;
    // observed address: the NAT's public address (or the host's own)
    let obs = lb.observed();
    assert_eq!(obs.len(), 1, "registered");
    assert_eq!(obs[0].1.ip(), ip(seen));
    let seen = echo(&w.sched, lb);
    let a = P2p::new(a);
    let addr = Address { url: peer_url(&[w.relay.item()]), key: kb };
    let net = w.net.clone();
    let (first_direct, direct_now) = w
        .sched
        .block_on(async move {
            let c = a.dial(&addr).await.unwrap();
            assert_eq!(c.peer_key(), kb);
            // a relayed connection may switch to direct (and close) before the reply
            let rt = try_round_trip(&c, b"hello through").await;
            // every packet of the punch goes out in its first resends: a punch that has not
            // got through after this long never does
            net.sleep(10_000).await;
            if c.rank() != RANK_RELAYED {
                rt.unwrap();
                return (true, true);
            }
            // switched: the relayed connection closed, the next dial takes the parked direct one
            let switched = match rt {
                Err(_) => true,
                Ok((_t, mut r)) => now_or_never(r.read(&mut [0u8; 8])).await.is_some_and(|x| x.is_err()),
            };
            let next = a.dial(&addr).await.unwrap();
            let _ = round_trip(&next, b"again").await;
            assert_eq!(next.rank() == RANK_RELAYED, !switched, "a switch leaves a parked direct connection");
            (false, switched)
        })
        .unwrap();
    w.sched.run();
    let accepted = seen.borrow().clone();
    assert_eq!(accepted.iter().any(|r| !r), direct_now, "B accepted a direct connection iff one exists: {accepted:?}");
    (first_direct, direct_now)
}

// spec/sync-transport.md §3 (switching): a punch that lands between `dial` returning and the caller opening
// its stream does not end that connection (the caller would see a dial that failed): it stays
// relayed and carries the session.
#[test]
fn punch_before_stream_open_stays_relayed_spec_sync_10() {
    let mut w = world(0, anyone());
    let b = host(&w.net, "10.0.0.2", "203.0.113.2", Some(Nat::CONE));
    let lb = listen_via(&mut w, b, "10.0.0.2", 2);
    let addr = Address { url: peer_url(&[w.relay.item()]), key: lb.address().key };
    let _seen = echo(&w.sched, lb);
    let a = P2p::new(host(&w.net, "10.0.1.2", "203.0.113.1", Some(Nat::CONE)));
    let net = w.net.clone();
    w.sched
        .block_on(async move {
            let c = a.dial(&addr).await.unwrap();
            assert_eq!(c.rank(), RANK_RELAYED);
            // the direct attempt completes here
            net.sleep(10_000).await;
            let _s = round_trip(&c, b"over the relay").await;
            assert_eq!(c.rank(), RANK_RELAYED);
        })
        .unwrap();
}

// spec/sync-transport.md §3 (hole punching; IP consent): the dialer, here with an ephemeral key (as a
// link's redeemer), dials the target's observed address from the socket it reached the relay
// from while the target punches back. Direct where a NAT's mapping
// does not depend on the remote (or there is none) and the other side's filter allows the
// punched pair; relayed where a mapping depends on the remote (address-dependent, symmetric) or
// where only the target could open a path (the target never dials back).
#[test]
fn punch_by_nat_type_spec_sync_10() {
    let full = Nat { mapping: Dep::Endpoint, filtering: Dep::Endpoint };
    let restricted = Nat { mapping: Dep::Endpoint, filtering: Dep::Address };
    let cases: &[(Option<Nat>, Option<Nat>, bool)] = &[
        (None, None, true),
        (None, Some(Nat::CONE), true),
        (Some(Nat::CONE), None, true),
        (Some(Nat::CONE), Some(Nat::CONE), true),
        (Some(full), Some(restricted), true),
        (Some(restricted), Some(Nat::CONE), true),
        (Some(Nat::SYMMETRIC), Some(full), true),
        (Some(Nat::CONE), Some(Nat::SYMMETRIC), false),
        (Some(Nat::SYMMETRIC), Some(Nat::CONE), false),
        (Some(Nat::SYMMETRIC), Some(Nat::SYMMETRIC), false),
        (Some(Nat::ADDRESS), Some(Nat::ADDRESS), false),
        (None, Some(Nat::SYMMETRIC), false),
        (Some(Nat::SYMMETRIC), Some(restricted), true),
        (Some(Nat::ADDRESS), Some(Nat::CONE), false),
        (Some(Nat::ADDRESS), Some(restricted), true),
    ];
    for (i, (na, nb, want)) in cases.iter().enumerate() {
        assert_eq!(nat::punch_opens(*na, *nb), *want, "case {i}: the rule the sims use (osis_sim::reach)");
        for seed in 0..3u64 {
            let (_, direct) = punch(seed, *na, *nb);
            assert_eq!(direct, *want, "case {i} {na:?} -> {nb:?} seed {seed}");
        }
    }
}

// spec/sync-transport.md §3 (hole punching): a relayed connection makes the target send one punch
// datagram to the dialer's address, and none to an address the dialer may not have it punch:
// here a dialer at a private address seen through a global relay (as one that lied in the
// exchange), which stays relayed. Which addresses: `punchable_addresses_spec_sync_10`.
#[test]
fn one_punch_and_none_to_a_refused_address_spec_sync_10() {
    let (_, sent) = punch_counted(0, Some(Nat::CONE), Some(Nat::CONE));
    assert_eq!(sent, 1, "one datagram per relayed connection");
    let mut w = world(0, anyone());
    let b = host(&w.net, "10.0.0.2", "203.0.113.2", Some(Nat::CONE));
    let a = host(&w.net, "10.0.1.2", "", None);
    let lb = listen_via(&mut w, b, "10.0.0.2", 2);
    let addr = Address { url: peer_url(&[w.relay.item()]), key: lb.address().key };
    let _seen = echo(&w.sched, lb);
    let a = P2p::new(a);
    w.sched
        .block_on(async move {
            let c = a.dial(&addr).await.unwrap();
            let _s = round_trip(&c, b"relayed").await;
            assert_eq!(c.rank(), RANK_RELAYED);
        })
        .unwrap();
    w.sched.run();
    assert_eq!(w.net.punches(), 0);
}

// spec/sync-transport.md §3 (hole punching): a punch or a direct dial goes only to a unicast address with
// a port, global unless the relay is not.
#[test]
fn punchable_addresses_spec_sync_10() {
    let global = sa("198.51.100.1:4040");
    for (to, via, want) in [
        ("203.0.113.1:5000", global, true),
        ("[2001:db8::1]:5000", global, true),
        ("[::ffff:203.0.113.1]:5000", global, true),
        ("203.0.113.1:0", global, false),
        ("10.0.0.2:5000", global, false),
        ("192.168.1.2:5000", global, false),
        ("100.64.0.1:5000", global, false),
        ("127.0.0.1:5000", global, false),
        ("[::1]:5000", global, false),
        ("[fe80::1]:5000", global, false),
        ("[::ffff:10.0.0.2]:5000", global, false),
        ("0.0.0.0:5000", global, false),
        ("255.255.255.255:5000", global, false),
        ("224.0.0.1:5000", global, false),
        ("[ff02::1]:5000", global, false),
        ("10.0.0.2:5000", sa("10.0.0.9:4040"), true),
        ("127.0.0.1:5000", sa("127.0.0.1:4040"), true),
        ("203.0.113.1:5000", sa("10.0.0.9:4040"), true),
        ("10.0.0.2:0", sa("10.0.0.9:4040"), false),
        ("255.255.255.255:5000", sa("10.0.0.9:4040"), false),
        ("[ff02::1]:5000", sa("[fe80::9]:4040"), false),
    ] {
        assert_eq!(osis_transport::p2p::punchable(sa(to), via), want, "{to} via {via}");
    }
}

// spec/sync-transport.md §3: `nat::punch_opens`, the rule the sims apply, is what the packet machine does
// for every mapping and filtering on either side, not only the table above.
#[test]
fn punch_rule_matches_the_packet_machine_spec_sync_10() {
    let deps = [Dep::Endpoint, Dep::Address, Dep::AddressPort];
    let kinds: Vec<Option<Nat>> = std::iter::once(None).chain(deps.iter().flat_map(|m| deps.iter().map(|f| Some(Nat { mapping: *m, filtering: *f })))).collect();
    for na in &kinds {
        for nb in &kinds {
            let (_, direct) = punch(0, *na, *nb);
            assert_eq!(nat::punch_opens(*na, *nb), direct, "{na:?} -> {nb:?}");
        }
    }
}

// spec/sync-transport.md §3: a relay on the pair's own LAN (here behind their one NAT) sees each one's LAN
// address, so the punch stays on the LAN and goes direct whatever the NAT does (what
// `osis_sim::reach` models as `Route::Punch` for a relay on a segment).
#[test]
fn punch_over_a_relay_on_the_pairs_lan_is_direct_spec_sync_10() {
    let deps = [Dep::Endpoint, Dep::Address, Dep::AddressPort];
    for nat in deps.iter().flat_map(|m| deps.iter().map(|f| Nat { mapping: *m, filtering: *f })) {
        let public = ip("203.0.113.9");
        let w = {
            let mut w = world_at(0, anyone(), "10.0.0.9", Some(public));
            w.net.add_nat(public, nat);
            w.sched.run();
            w
        };
        let (a, b) = (w.net.udp(ip("10.0.0.1"), Some(public)), w.net.udp(ip("10.0.0.2"), Some(public)));
        let (_, direct) = punch_in(w, a, b, "10.0.0.2", "10.0.0.2");
        assert!(direct, "{nat:?}");
    }
}

// spec/sync-transport.md §1 (node key check): direct socket addresses in the URL are dialed as they are; the key is pinned
// (another key: KeyMismatch); nothing listening there and no relay: Unreachable.
#[test]
fn direct_items_spec_sync_10() {
    let mut w = world(0, anyone());
    let b = P2p::new(host(&w.net, "192.0.2.7", "", None));
    let lb = w.sched.block_on(async move { b.listen(ListenConfig { url: "peer://192.0.2.7:7000".into(), secret: secret(3) }).await.unwrap() }).unwrap();
    let kb = lb.address().key;
    assert_eq!(lb.address().url, "peer://192.0.2.7:7000");
    let _seen = echo(&w.sched, lb);
    let a = P2p::new(host(&w.net, "10.9.0.2", "203.0.113.9", Some(Nat::SYMMETRIC)));
    let r = w.sched.block_on(async move {
        let c = a.dial(&Address { url: "peer://192.0.2.7:7000".into(), key: kb }).await.unwrap();
        assert_eq!(c.rank(), RANK_DIRECT);
        let _ = round_trip(&c, b"direct").await;
        let wrong = a.dial(&Address { url: "peer://192.0.2.7:7000".into(), key: [9; 32] }).await;
        let none = a.dial(&Address { url: "peer://192.0.2.8:7000".into(), key: kb }).await;
        let empty = a.dial(&Address { url: "peer://".into(), key: kb }).await;
        (wrong.err(), none.err(), empty.err())
    });
    let (wrong, none, empty) = r.unwrap();
    assert_eq!(wrong, Some(Error::KeyMismatch));
    assert!(matches!(none, Some(Error::Unreachable(_))), "{none:?}");
    assert!(matches!(empty, Some(Error::Unreachable(_))), "{empty:?}");
}

// spec/sync-transport.md §3: through a relay the dialer pins the target's key end to end (TLS over the
// forwarded stream) and the target sees the dialer's key, fresh per dial; a key nobody registered
// is unreachable. Both ends rank it relayed (§1 (route rank)).
#[test]
fn relayed_keys_spec_sync_10() {
    let mut w = world(0, anyone());
    let b = host(&w.net, "10.0.0.2", "203.0.113.2", Some(Nat::SYMMETRIC));
    let mut lb = listen_via(&mut w, b, "10.0.0.2", 2);
    let kb = lb.address().key;
    let a = P2p::new(host(&w.net, "10.0.1.2", "203.0.113.1", Some(Nat::SYMMETRIC)));
    let url = peer_url(&[w.relay.item()]);
    let (a2, u2) = (a.clone(), url.clone());
    let got = w.sched.block_on(async move {
        let c1 = a2.dial(&Address { url: u2.clone(), key: kb }).await.unwrap();
        let (_t1, _r1) = request(&c1, b"x").await;
        let s1 = lb.accept().await.unwrap();
        let c2 = a2.dial(&Address { url: u2.clone(), key: kb }).await.unwrap();
        let s2 = lb.accept().await.unwrap();
        let none = a2.dial(&Address { url: u2, key: [7; 32] }).await.err();
        assert!([c1.rank(), c2.rank(), s1.rank(), s2.rank()] == [RANK_RELAYED; 4], "both ends rank a relayed connection alike");
        // one stream per relayed connection
        assert!(matches!(c1.open_stream().await, Err(Error::Protocol(_))));
        (s1.peer_key(), s2.peer_key(), none)
    });
    let (k1, k2, none) = got.unwrap();
    assert_ne!(k1, k2);
    assert!(matches!(none, Some(Error::Unreachable(_))), "{none:?}");
}

// spec/sync-transport.md §5 (Key change), §3 (relays): a listener listened again at its own URL
// keeps its socket and the connections it took, and registers at its relay under the new key:
// a dial through the relay reaches it under the new key, none under the old.
#[test]
fn a_relayed_listener_relistens_under_a_new_key_spec_sync_transport_5() {
    let mut w = world(0, anyone());
    let b = host(&w.net, "10.0.0.2", "203.0.113.2", Some(Nat::SYMMETRIC));
    let mut lb = listen_via(&mut w, b, "10.0.0.2", 2);
    let old = lb.address();
    let a = P2p::new(host(&w.net, "10.0.1.2", "203.0.113.1", Some(Nat::SYMMETRIC)));
    let via = peer_url(&[w.relay.item()]);
    let (a2, via2, old2) = (a.clone(), via.clone(), old.clone());
    let (lb, c1, s1) = w
        .sched
        .block_on(async move {
            let c1 = a2.dial(&Address { url: via2, key: old2.key }).await.unwrap();
            let (_t1, _r1) = request(&c1, b"x").await;
            let s1 = lb.accept().await.unwrap();
            assert!(lb.relisten(&ListenConfig { url: old2.url.clone(), secret: secret(3) }).await.unwrap(), "its own URL");
            let other = ListenConfig { url: "peer://10.0.0.2:7001".into(), secret: secret(3) };
            assert!(!lb.relisten(&other).await.unwrap(), "another socket");
            (lb, c1, s1)
        })
        .unwrap();
    assert_eq!((lb.address().url, lb.address().key), (old.url.clone(), secret(3).public_key()));
    // its registration under the new key settles
    w.sched.run();
    let mut lb = lb;
    let got = w.sched.block_on(async move {
        let c2 = a.dial(&Address { url: via.clone(), key: secret(3).public_key() }).await.unwrap();
        let (_t2, _r2) = request(&c2, b"y").await;
        let s2 = lb.accept().await.unwrap();
        let stale = a.dial(&Address { url: via, key: old.key }).await.err();
        // the connection taken under the old key goes on
        let (_ts, mut rs) = s1.accept_stream().await.unwrap();
        let mut x = [0u8; 1];
        rs.read(&mut x).await.unwrap();
        drop((c1, c2));
        (s2.peer_key() != s1.peer_key(), stale, x)
    });
    let (two, stale, x) = got.unwrap();
    assert!(two);
    assert_eq!(&x, b"x");
    assert!(matches!(stale, Some(Error::Unreachable(_))), "{stale:?}");
}

// spec/sync-transport.md §5 (Key change), §3 (relays): listening again ends the old key's
// registrations: after 10n relistens as many tasks wait (target and relay alike) as after n.
#[test]
fn relistens_leave_no_registrations_behind_spec_sync_transport_5() {
    fn tasks_after(n: u8) -> usize {
        let mut w = world(0, anyone());
        let b = host(&w.net, "10.0.0.2", "203.0.113.2", Some(Nat::SYMMETRIC));
        let lb = listen_via(&mut w, b, "10.0.0.2", 2);
        let url = lb.address().url;
        let lb = Rc::new(RefCell::new(Some(lb)));
        for i in 0..n {
            let (l, url) = (lb.clone(), url.clone());
            w.sched
                .block_on(async move {
                    let mut g = l.borrow_mut().take().unwrap();
                    assert!(g.relisten(&ListenConfig { url, secret: secret(10 + i) }).await.unwrap());
                    *l.borrow_mut() = Some(g);
                })
                .unwrap();
            w.sched.run();
        }
        w.sched.run()
    }
    assert_eq!(tasks_after(10), tasks_after(1));
}

/// Forwards `r` to `t` until it ends.
async fn pipe(mut r: impl RecvStream, mut t: impl SendStream) {
    let mut b = [0u8; 4096];
    while let Ok(n) = r.read(&mut b).await {
        if n == 0 {
            let _ = t.finish().await;
            return;
        }
        if t.write_all(&b[..n]).await.is_err() {
            return;
        }
    }
}

// spec: none (notes/networking.md, Implementation `P2p`: `dialer_limits`): a relay connection
// dialed ephemerally (a dial through the relay) lets the relay open no stream, so a hostile relay
// a link names makes the dialer buffer nothing; a registration (dialed with its key) lets it
// open the forwarded streams.
#[test]
fn relay_dial_grants_relay_no_streams() {
    let net = Net::new(0);
    let mut sched = Sched::new(0, Some(net.clone()));
    let m = host(&net, "198.51.100.9", "", None);
    let msock = Arc::new(m.bind(sa("198.51.100.9:4040"), Some(&secret(9))).unwrap());
    let (to, key) = (msock.local(), secret(9).public_key());
    let a = host(&net, "192.0.2.5", "", None);
    let opened = sched.block_on(async move {
        let mut opened = Vec::new();
        for own in [None, Some(secret(2))] {
            let c = a.bind(sa("0.0.0.0:0"), None).unwrap().dial(to, key, own, Alpn::Relay).await.unwrap().0;
            let (rc, alpn, _) = msock.accept().await.unwrap();
            assert_eq!(alpn, Alpn::Relay);
            opened.push(now_or_never(rc.open_stream()).await.is_some_and(|r| r.is_ok()));
            drop(c);
        }
        opened
    });
    assert_eq!(opened, Some(vec![false, true]));
}

// spec/sync-transport.md §3 (relayed connection): a hostile relay answering a dial for key K and
// forwarding the stream to another node Z (registered at an honest relay) cannot pass Z off as
// K: the dialer pins K end to end and gets KeyMismatch.
#[test]
fn relay_cannot_impersonate_spec_sync_10() {
    let mut w = world(0, anyone());
    let relay = w.relay.clone();
    let z = host(&w.net, "192.0.2.3", "", None);
    let lz = listen_via(&mut w, z, "192.0.2.3", 3);
    let kz = lz.address().key;
    let _seen = echo(&w.sched, lz);
    // the hostile relay: answers any dial with a stream to Z through the honest relay
    let m = host(&w.net, "198.51.100.9", "", None);
    let msock = Arc::new(m.bind(sa("198.51.100.9:4040"), Some(&secret(9))).unwrap());
    let hostile = Relay { key: secret(9).public_key(), addr: msock.local() };
    let net = w.net.clone();
    let ms = msock.clone();
    w.net.spawn(async move {
        let (c, alpn, _) = ms.accept().await.unwrap();
        assert_eq!(alpn, Alpn::Relay);
        let (mut t, mut r) = c.accept_stream().await.unwrap();
        let _ = read_n(&mut r, 33).await;
        let up = relay_conn(&m, "0.0.0.0:0", &relay, None).await;
        let (ut, mut ur) = request(&up, &dial_req(&kz)).await;
        let reply = read_n(&mut ur, 19).await;
        t.write_all(&reply).await.unwrap();
        net.spawn(pipe(r, ut));
        pipe(ur, t).await;
        let _ = (c, up);
    });
    let a = P2p::new(host(&w.net, "192.0.2.5", "", None));
    let want = secret(2).public_key();
    let addr = Address { url: peer_url(&[hostile.item()]), key: want };
    let r = w.sched.block_on(async move { a.dial(&addr).await.err() });
    assert_eq!(r, Some(Some(Error::KeyMismatch)));
    drop(msock);
}

/// A stream opened on `c`, `req` sent on it.
async fn request<C: Connection>(c: &C, req: &[u8]) -> (C::Send, C::Recv) {
    let (mut t, r) = c.open_stream().await.unwrap();
    t.write_all(req).await.unwrap();
    (t, r)
}

/// A raw connection to `relay` from a fresh socket of `m` at `at`, under the static key of
/// secret `s` (none: ephemeral).
async fn relay_conn(m: &MemUdp, at: &str, relay: &Relay, s: Option<u8>) -> MemConn {
    m.bind(sa(at), None).unwrap().dial(relay.addr, relay.key, s.map(secret), Alpn::Relay).await.unwrap().0
}

/// Registers on `c`: the stream, to hold open, and the first byte of the answer.
async fn register(c: &MemConn) -> (MemSend, MemRecv, u8) {
    let (t, mut r) = request(c, &[1]).await;
    let ok = read_n(&mut r, 1).await[0];
    (t, r, ok)
}

/// The relay wire's dial request for `key`.
fn dial_req(key: &[u8; 32]) -> Vec<u8> {
    [&[2], &key[..]].concat()
}

/// Reads exactly `n` bytes.
async fn read_n<R: RecvStream>(r: &mut R, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    let mut at = 0;
    while at < n {
        let k = r.read(&mut out[at..]).await.unwrap();
        assert!(k > 0, "ended after {at} of {n}");
        at += k;
    }
    out
}

fn wire_addr(a: SocketAddr) -> Vec<u8> {
    let v6 = match a.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    let mut o = v6.octets().to_vec();
    o.extend_from_slice(&a.port().to_be_bytes());
    o
}

// spec/sync-transport.md §3 (relay wire): register (kind 1, the connection's key) answers 0 and the
// observed address; dial (kind 2 and the key) answers 0 and the dialer's own observed address,
// never the target's; the target gets a stream starting with the byte 2, never the dialer's
// address; then bytes pass unchanged both ways, ends included. Unknown key: 2. A key the relay does not allow: 1.
#[test]
fn relay_wire_spec_sync_10() {
    let allowed = secret(2).public_key();
    let mut w = world(0, RelayConfig::new(Arc::new(move |k| *k == allowed)));
    let relay = w.relay.clone();
    let b = host(&w.net, "10.0.0.2", "203.0.113.2", Some(Nat::CONE));
    let a = host(&w.net, "192.0.2.5", "", None);
    let done = w.sched.block_on(async move {
        let cb = relay_conn(&b, "0.0.0.0:6000", &relay, Some(2)).await;
        let (_tb, mut rb, ok) = register(&cb).await;
        assert_eq!(ok, 0);
        let reply = read_n(&mut rb, 18).await;
        let obs_b = SocketAddr::new(ip("203.0.113.2"), u16::from_be_bytes([reply[16], reply[17]]));
        assert_eq!(reply, wire_addr(obs_b));
        // a key the relay does not allow
        let cx = relay_conn(&b, "0.0.0.0:6001", &relay, Some(4)).await;
        assert_eq!(register(&cx).await.2, 1);
        // dial the registered key
        let ca = relay_conn(&a, "0.0.0.0:5000", &relay, None).await;
        let (mut ta, mut ra2) = request(&ca, &dial_req(&allowed)).await;
        let reply = read_n(&mut ra2, 19).await;
        assert_eq!(reply[0], 0);
        assert_eq!(reply[1..19], wire_addr(sa("192.0.2.5:5000"))[..]);
        let (mut fb, mut gb) = cb.accept_stream().await.unwrap();
        assert_eq!(read_n(&mut gb, 1).await, [2]);
        ta.write_all(b"ping").await.unwrap();
        ta.finish().await.unwrap();
        assert_eq!(read_n(&mut gb, 4).await, b"ping");
        assert_eq!(gb.read(&mut [0u8; 4]).await.unwrap(), 0);
        fb.write_all(b"pong").await.unwrap();
        fb.finish().await.unwrap();
        assert_eq!(read_n(&mut ra2, 4).await, b"pong");
        assert_eq!(ra2.read(&mut [0u8; 4]).await.unwrap(), 0);
        // a key nobody registered
        let (_tu, mut ru) = request(&ca, &dial_req(&[7; 32])).await;
        assert_eq!(read_n(&mut ru, 1).await, [2]);
        true
    });
    assert_eq!(done, Some(true));
}

// spec/sync-transport.md §3 (relaying): a newer registration of a key replaces the older one,
// and the older one's end leaves it: a dial then reaches the newer.
#[test]
fn a_replaced_registration_ending_leaves_the_newer_spec_sync_10() {
    let mut w = world(0, anyone());
    let relay = w.relay.clone();
    let b = host(&w.net, "192.0.2.2", "", None);
    let a = host(&w.net, "192.0.2.5", "", None);
    let net = w.net.clone();
    let done = w.sched.block_on(async move {
        let mut regs = Vec::new();
        for _ in 0..2 {
            let c = relay_conn(&b, "0.0.0.0:0", &relay, Some(2)).await;
            let (t, r, ok) = register(&c).await;
            assert_eq!(ok, 0);
            regs.push((c, t, r));
        }
        let (_old, mut t_old, _r_old) = regs.remove(0);
        t_old.finish().await.unwrap();
        net.sleep(100).await;
        let ca = relay_conn(&a, "0.0.0.0:0", &relay, None).await;
        let (_ta, mut r) = request(&ca, &dial_req(&secret(2).public_key())).await;
        assert_eq!(read_n(&mut r, 1).await, [0], "the newer registration answers");
        let (_f, mut g) = regs[0].0.accept_stream().await.unwrap();
        assert_eq!(read_n(&mut g, 1).await, [2]);
        true
    });
    assert_eq!(done, Some(true));
}

// spec/sync-transport.md §3 (relaying): relay limits: forwarding is held to the per-source rate (virtual time), and
// past the connection cap the source holding the most gives one up, else the newcomer is refused.
#[test]
fn relay_limits_spec_sync_10() {
    let mut cfg = anyone();
    cfg.rate = 10_000;
    cfg.max_conns = 3;
    let mut w = world(0, cfg);
    let relay = w.relay.clone();
    let b = host(&w.net, "192.0.2.2", "", None);
    let a = host(&w.net, "192.0.2.5", "", None);
    let c = host(&w.net, "192.0.2.6", "", None);
    let net = w.net.clone();
    let done = w.sched.block_on(async move {
        let cb = relay_conn(&b, "0.0.0.0:0", &relay, Some(2)).await;
        let (_tb, _rb, ok) = register(&cb).await;
        assert_eq!(ok, 0);
        let ca = relay_conn(&a, "0.0.0.0:0", &relay, None).await;
        let (mut ta, mut ra2) = request(&ca, &dial_req(&secret(2).public_key())).await;
        assert_eq!(read_n(&mut ra2, 19).await[0], 0);
        let (_fb, mut gb) = cb.accept_stream().await.unwrap();
        assert_eq!(read_n(&mut gb, 1).await, [2]);
        // 50 kB at 10 kB/s with a one-second burst: at least four seconds
        let t0 = net.now();
        ta.write_all(&vec![7u8; 50_000]).await.unwrap();
        let _ = read_n(&mut gb, 50_000).await;
        let took = net.now() - t0;
        assert!((4000..6000).contains(&took), "{took} ms");
        // connections: b and a hold two of three; a second from a fills the cap
        let ca2 = relay_conn(&a, "0.0.0.0:0", &relay, None).await;
        let (_t2, r2) = request(&ca2, &[2, 0]).await;
        // c arrives: a (two) gives one up, its oldest
        let cc = relay_conn(&c, "0.0.0.0:0", &relay, None).await;
        let (_t3, mut r3) = request(&cc, &dial_req(&[7; 32])).await;
        assert_eq!(read_n(&mut r3, 1).await, [2], "c served");
        assert!(ra2.read(&mut [0u8; 8]).await.is_err(), "a's oldest connection closed");
        drop(r2);
        // a third from c: c holds one, a one, b one: refused
        let cc2 = relay_conn(&c, "0.0.0.0:0", &relay, None).await;
        let (mut t4, mut r4) = cc2.open_stream().await.unwrap();
        let _ = t4.write_all(&[2]).await;
        assert!(r4.read(&mut [0u8; 8]).await.is_err(), "newcomer refused");
        true
    });
    assert_eq!(done, Some(true));
}

// spec/sync-transport.md §3: a listener whose relay refuses its key stays unregistered (no observed
// address) and retries with backoff; dials through that relay find nobody.
#[test]
fn registration_refused_spec_sync_10() {
    let mut w = world(0, RelayConfig::new(Arc::new(|_| false)));
    w.sched.set_max_steps(200);
    let b = host(&w.net, "192.0.2.2", "", None);
    let lb = listen_via(&mut w, b, "192.0.2.2", 2);
    assert!(lb.observed().is_empty());
    let a = P2p::new(host(&w.net, "192.0.2.5", "", None));
    let addr = Address { url: peer_url(&[w.relay.item()]), key: lb.address().key };
    let r = w.sched.block_on(async move { a.dial(&addr).await.err() });
    assert!(matches!(r, Some(Some(Error::Unreachable(_)))), "{r:?}");
}

// spec: none (NAT model): mappings and filters behave as RFC 4787 describes
#[test]
fn nat_model() {
    let net = Net::new(0);
    let mut sched = Sched::new(0, Some(net.clone()));
    net.add_nat(ip("203.0.113.1"), Nat::SYMMETRIC);
    let a = net.udp(ip("10.0.0.2"), Some(ip("203.0.113.1")));
    let lan = net.udp(ip("10.0.0.3"), Some(ip("203.0.113.1")));
    let p = net.udp(ip("192.0.2.1"), None);
    let r = sched.block_on(async move {
        let sp = p.bind(sa("0.0.0.0:80"), Some(&secret(1))).unwrap();
        let sp2 = p.bind(sa("0.0.0.0:81"), Some(&secret(1))).unwrap();
        let k = secret(1).public_key();
        let sl = lan.bind(sa("0.0.0.0:90"), Some(&secret(1))).unwrap();
        let s = a.bind(sa("0.0.0.0:0"), None).unwrap();
        // out to two ports of one host: two mappings
        let _c1 = s.dial(sp.local(), k, None, Alpn::Osis).await.unwrap().0;
        let (_, _, f1) = sp.accept().await.unwrap();
        let _c2 = s.dial(sp2.local(), k, None, Alpn::Osis).await.unwrap().0;
        let (_, _, f2) = sp2.accept().await.unwrap();
        assert_eq!(f1.ip(), ip("203.0.113.1"));
        assert_ne!(f1.port(), f2.port());
        // the same LAN at its own address, untranslated; not at the public one
        let _c3 = s.dial(sl.local(), k, None, Alpn::Osis).await.unwrap().0;
        let (_, _, f3) = sl.accept().await.unwrap();
        assert_eq!(f3, s.local());
        // a socket that only dials accepts nothing
        let s2 = a.bind(sa("0.0.0.0:0"), None).unwrap();
        let r = s.dial(s2.local(), k, None, Alpn::Osis).await;
        (f1, r.err())
    });
    let (_, err) = r.unwrap();
    assert!(matches!(err, Some(Error::Unreachable(_))));
}

/// Echoes the first stream of `c` (real QUIC), then waits for the dialer's close.
async fn quic_echo(c: P2pConn<QuicConn>) {
    if let Ok((tx, rx)) = c.accept_stream().await {
        pipe(rx, tx).await;
        let _ = c.accept_stream().await;
    }
}

/// A relaying node (real QUIC) listening at `at` under secret `s`, and its relay item.
async fn quic_relay(cfg: RelayConfig, at: &str, s: u8) -> (P2p<QuicUdp>, P2pListener<QuicUdp>, Relay) {
    let r = P2p::new(QuicUdp::new()).relaying(cfg);
    let l = r.listen(ListenConfig { url: format!("peer://{at}"), secret: secret(s) }).await.unwrap();
    let relay = Relay { key: l.address().key, addr: bound(&l.address()) };
    (r, l, relay)
}

/// The socket address a `peer://` listener is bound at (its URL's first item).
fn bound(a: &Address) -> SocketAddr {
    sa(a.url.strip_prefix("peer://").unwrap().split(' ').next().unwrap())
}

/// Accepts `l`'s connections and echoes each (`quic_echo`) until aborted.
fn quic_echoes(mut l: P2pListener<QuicUdp>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::spawn(quic_echo(l.accept().await.unwrap()));
        }
    })
}

/// Waits (up to 5 s) until `l` is registered at `n` relays.
async fn registered(l: &P2pListener<QuicUdp>, n: usize) {
    for _ in 0..100 {
        if l.observed().len() == n {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Dials `key` through `relay` (real QUIC), its key pinned, and runs a `session` on it.
async fn session_through(relay: &Relay, key: PublicKey) {
    let a = P2p::new(QuicUdp::new());
    let addr = Address { url: peer_url(&[relay.item()]), key };
    let c = a.dial(&addr).await.unwrap();
    assert_eq!(c.peer_key(), key);
    if let Err(e) = session(&c).await {
        // a relayed connection closes once the direct one completes; the next dial takes that
        assert_eq!(c.rank(), RANK_RELAYED, "{e:?}");
        let d = a.dial(&addr).await.unwrap();
        assert_eq!(d.rank(), RANK_DIRECT);
        session(&d).await.unwrap();
    }
}

/// Sends, reads the echo, finishes and reads the end.
async fn session<C: Connection>(c: &C) -> Result<(), Error> {
    let (mut tx, mut rx) = c.open_stream().await?;
    tx.write_all(b"over quic").await?;
    let mut got = Vec::new();
    let mut b = [0u8; 64];
    loop {
        let n = rx.read(&mut b).await?;
        if n == 0 {
            break;
        }
        got.extend_from_slice(&b[..n]);
        if got.len() == 9 {
            tx.finish().await?;
        }
    }
    assert_eq!(got, b"over quic");
    Ok(())
}

// spec/sync-transport.md §3 (relay wire), by hand, loopback QUIC: a listener registers at a relaying node over ALPN
// `osis-relay` and learns its observed address; the relay wire runs over real QUIC; a dial
// through the relay reaches the listener (directly once punched: no NAT on loopback) with the
// key pinned.
#[test]
#[ignore]
fn quic_relay_loopback_spec_sync_10() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let (r, _lr, relay) = quic_relay(anyone(), "127.0.0.1:0", 1).await;
        let b = P2p::new(QuicUdp::new());
        let lb = b.listen(ListenConfig { url: format!("peer://127.0.0.1:0 {}", relay.item()), secret: secret(2) }).await.unwrap();
        let kb = lb.address().key;
        registered(&lb, 1).await;
        assert_eq!(lb.observed(), vec![(relay.clone(), bound(&lb.address()))]);
        assert_eq!(r.relayed_keys(), vec![kb]);
        // the wire, by hand: a dial request answers the dialer's own observed address
        let s = QuicUdp::new().bind(sa("127.0.0.1:0"), None).unwrap();
        let c = s.dial(relay.addr, relay.key, None, Alpn::Relay).await.unwrap().0;
        let (t, mut rr) = request(&c, &dial_req(&kb)).await;
        let reply = read_n(&mut rr, 19).await;
        assert_eq!(reply[0], 0);
        assert_eq!(reply[1..19], wire_addr(s.local())[..]);
        drop((t, rr, c));
        // through the relay with p2p
        let echo = quic_echoes(lb);
        session_through(&relay, kb).await;
        echo.abort();
    });
}

// spec/sync-transport.md §3 (registration streams), by hand: loopback QUIC: relayed sessions whose bytes
// the target never reads hold only their own stream's window of its registration connection:
// with more unread in them than a `quic://` connection window, forwarding to the target
// goes on and a new dial still connects.
#[test]
#[ignore]
fn quic_relay_unread_sessions_spec_sync_10() {
    const UNREAD: usize = 6;
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        // the rate out of the way: every dialer here is one source
        let mut cfg = anyone();
        cfg.rate = 1 << 40;
        // relayed only: a dual-stack relay that the target reaches over IPv6 and the dialer over
        // IPv4, so the dialer's direct attempt to the target's IPv6 address fails (its socket is
        // IPv4) and the target's punch to the dialer's IPv4 address too
        let (_r, _lr, any) = quic_relay(cfg, "[::]:0", 1).await;
        let port = any.addr.port();
        let relay6 = Relay { key: any.key, addr: sa(&format!("[::1]:{port}")) };
        let relay = Relay { key: any.key, addr: sa(&format!("127.0.0.1:{port}")) };
        let b = P2p::new(QuicUdp::new());
        let mut lb = b.listen(ListenConfig { url: format!("peer://[::1]:0 {}", relay6.item()), secret: secret(2) }).await.unwrap();
        let kb = lb.address().key;
        registered(&lb, 1).await;
        // the first UNREAD connections are held and never read; later ones are echoed
        let target = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let c = lb.accept().await.unwrap();
                if held.len() < UNREAD {
                    held.push(c);
                    continue;
                }
                tokio::spawn(quic_echo(c));
            }
        });
        let a = P2p::new(QuicUdp::new());
        let addr = Address { url: peer_url(&[relay.item()]), key: kb };
        let mut writers = Vec::new();
        for _ in 0..UNREAD {
            let c = a.dial(&addr).await.unwrap();
            assert_eq!(c.rank(), RANK_RELAYED);
            let (mut tx, rx) = c.open_stream().await.unwrap();
            writers.push(tokio::spawn(async move {
                let _ = tx.write_all(&vec![0u8; 2 << 20]).await;
                let _held = (rx, c);
                std::future::pending::<()>().await
            }));
        }
        // the unread bytes reach the target's side of the relay
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let next = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            let c = a.dial(&addr).await.unwrap();
            session(&c).await
        })
        .await;
        assert!(matches!(next, Ok(Ok(()))), "a dial after unread relayed sessions: {next:?}");
        writers.iter().for_each(|w| w.abort());
        target.abort();
    });
}

/// Opens `n` dial streams to `key` at the relay from host `m`, 16 per connection (as the relay
/// allows), and sends nothing more; returns each answer byte and the streams.
async fn raw_dials(m: &MemUdp, relay: &Relay, key: [u8; 32], n: usize) -> (Vec<u8>, Vec<(MemSend, MemRecv)>, Vec<MemConn>) {
    let mut answers = Vec::new();
    let mut held = Vec::new();
    let mut conns = Vec::new();
    while answers.len() < n {
        let c = relay_conn(m, "0.0.0.0:0", relay, None).await;
        for _ in 0..16.min(n - answers.len()) {
            let (t, mut r) = request(&c, &dial_req(&key)).await;
            answers.push(read_n(&mut r, 1).await[0]);
            held.push((t, r));
        }
        conns.push(c);
    }
    (answers, held, conns)
}

// spec/sync-transport.md §3 (registration streams): relay limits: dials that never start their handshake cannot block a target.
// Each forwarded stream takes one of the streams the target's registration grants its relay;
// the target ends the oldest it has not handed to `accept` past MAX_FORWARDED, so an honest
// dial after a flood of silent ones still connects, and the oldest silent ones see their end.
#[test]
fn silent_dials_do_not_block_spec_sync_10() {
    let mut w = world(0, anyone());
    let b = host(&w.net, "10.0.0.2", "203.0.113.2", Some(Nat::SYMMETRIC));
    let lb = listen_via(&mut w, b, "10.0.0.2", 2);
    let kb = lb.address().key;
    let _seen = echo(&w.sched, lb);
    let m = host(&w.net, "192.0.2.66", "", None);
    let relay = w.relay.clone();
    let flood = p2p::MAX_FORWARDED + 64;
    let (answers, mut held, _conns) = w.sched.block_on(async move { raw_dials(&m, &relay, kb, flood).await }).unwrap();
    assert!(answers.iter().all(|a| *a == 0), "every silent dial forwarded");
    w.sched.run();
    let a = P2p::new(host(&w.net, "10.0.1.2", "203.0.113.1", Some(Nat::SYMMETRIC)));
    let addr = Address { url: peer_url(&[w.relay.item()]), key: kb };
    let ok = w.sched.block_on(async move {
        let c = a.dial(&addr).await.unwrap();
        let _ = round_trip(&c, b"after the flood").await;
        // the oldest silent dial was ended by the target: its stream ends after the answer
        let (_, r) = &mut held[0];
        let _ = read_n(r, 18).await;
        let mut b = [0u8; 8];
        matches!(r.read(&mut b).await, Ok(0) | Err(_))
    });
    assert_eq!(ok, Some(true));
}

// spec/sync-transport.md §3 (relay wire): a relay never waits for room on a registration connection: a
// dial it cannot open a stream for at once is answered busy (3). A registration that accepts no
// streams fills after REG_STREAMS dials.
#[test]
fn relay_busy_spec_sync_10() {
    let mut w = world(0, anyone());
    let b = host(&w.net, "192.0.2.2", "", None);
    let m = host(&w.net, "192.0.2.66", "", None);
    let relay = w.relay.clone();
    let done = w.sched.block_on(async move {
        let cb = relay_conn(&b, "0.0.0.0:0", &relay, Some(2)).await;
        let (_tb, _rb, ok) = register(&cb).await;
        assert_eq!(ok, 0);
        let n = p2p::REG_STREAMS as usize;
        let (answers, held, conns) = raw_dials(&m, &relay, secret(2).public_key(), n + 1).await;
        assert!(answers[..n].iter().all(|a| *a == 0));
        assert_eq!(answers[n], 3, "busy");
        drop((held, conns, cb));
        true
    });
    assert_eq!(done, Some(true));
}

// spec/sync-transport.md §3 (`peer://`): a listener is listed at each global address it is bound
// to, an unspecified IP standing for the routes' local addresses of the families it serves,
// then its relays; local, loopback and carrier-NAT addresses are not listed.
#[test]
fn peer_url_items_global_addresses_spec_sync_10() {
    use osis_transport::p2p::peer_url_items;
    let relay = Relay { key: [7; 32], addr: sa("192.0.2.1:4040") }.item();
    let routes = [ip("192.168.1.5"), ip("2001:db8::5")];
    let wide = [ip("203.0.113.7"), ip("2001:db8::5")];
    assert_eq!(peer_url_items(&peer_url(&["[::]:47381".into(), relay.clone()]), &wide), vec!["203.0.113.7:47381".to_owned(), "[2001:db8::5]:47381".into(), relay.clone()]);
    assert_eq!(peer_url_items(&peer_url(&["[::]:47381".into(), relay.clone()]), &routes), vec!["[2001:db8::5]:47381".to_owned(), relay.clone()]);
    assert_eq!(peer_url_items(&peer_url(&["0.0.0.0:9".into()]), &wide), vec!["203.0.113.7:9".to_owned()]);
    assert_eq!(peer_url_items(&peer_url(&["0.0.0.0:9".into()]), &[ip("100.64.0.9"), ip("10.0.0.2")]), Vec::<String>::new());
    assert_eq!(peer_url_items(&peer_url(&["127.0.0.1:9".into(), "[fd00::1]:9".into(), "[fe80::1]:9".into()]), &wide), Vec::<String>::new());
    assert_eq!(peer_url_items(&peer_url(&["203.0.113.8:9".into()]), &[]), vec!["203.0.113.8:9".to_owned()]);
    assert_eq!(peer_url_items("mem://a", &wide), Vec::<String>::new());
}

// spec/sync-transport.md §3 (relaying): a key the relay stops allowing loses its registration at its next
// dial (answered as unknown) or when the relay rechecks.
#[test]
fn allow_rechecked_spec_sync_10() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let ok = Arc::new(AtomicBool::new(true));
    let o2 = ok.clone();
    let mut w = world(0, RelayConfig::new(Arc::new(move |_| o2.load(Ordering::SeqCst))));
    let (r, relay) = (w.node.clone(), w.relay.clone());
    let (b, c) = (host(&w.net, "192.0.2.2", "", None), host(&w.net, "192.0.2.3", "", None));
    let lb = listen_via(&mut w, b, "192.0.2.2", 2);
    let lc = listen_via(&mut w, c, "192.0.2.3", 3);
    let (kb, kc) = (lb.address().key, lc.address().key);
    assert_eq!(r.relayed_keys().len(), 2);
    ok.store(false, Ordering::SeqCst);
    // a refused registration retries for good
    w.sched.set_max_steps(100);
    let m = host(&w.net, "192.0.2.66", "", None);
    let answers = w.sched.block_on(async move { raw_dials(&m, &relay, kb, 1).await.0 }).unwrap();
    assert_eq!(answers, vec![2]);
    assert_eq!(r.relayed_keys(), vec![kc]);
    r.recheck_relayed();
    assert!(r.relayed_keys().is_empty());
}

// spec/sync-transport.md §3 (hole punching), by hand, loopback QUIC: a punch is the one byte 0x00 from the
// listening socket's own port (a dual-stack one reaching an IPv4 address too), and the QUIC
// endpoint answers a punch with nothing and still accepts connections after it.
#[test]
#[ignore]
fn quic_punch_is_one_unanswered_datagram_spec_sync_10() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let raw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        raw.set_read_timeout(Some(std::time::Duration::from_millis(500))).unwrap();
        for at in ["127.0.0.1:0", "[::]:0"] {
            let s = QuicUdp::new().bind(sa(at), Some(&secret(1))).unwrap();
            s.punch(raw.local_addr().unwrap());
            let mut buf = [0u8; 2048];
            let (n, from) = raw.recv_from(&mut buf).unwrap();
            assert_eq!((&buf[..n], from.port()), (&p2p::PUNCH[..], s.local().port()), "{at}");
            let to = SocketAddr::new(sa("127.0.0.1:0").ip(), s.local().port());
            raw.send_to(&p2p::PUNCH, to).unwrap();
            assert!(raw.recv_from(&mut buf).is_err(), "{at}: a punch is answered");
            let c = QuicUdp::new().bind(sa("127.0.0.1:0"), None).unwrap();
            c.dial(to, secret(1).public_key(), None, Alpn::Osis).await.unwrap();
        }
    });
}

// spec/sync-transport.md §3 (relay wire), by hand, loopback QUIC: a listener bound at `[::]` (as nodes bind) registers
// at an IPv6 relay and at an IPv4 one from its one dual-stack socket, and a dial through either
// relay reaches it.
#[test]
#[ignore]
fn quic_relay_dual_stack_spec_sync_10() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let mut relays = Vec::new();
        let mut held = Vec::new();
        for (at, s) in [("[::1]:0", 1), ("127.0.0.1:0", 3)] {
            let (r, l, relay) = quic_relay(anyone(), at, s).await;
            relays.push(relay);
            held.push((r, l));
        }
        let b = P2p::new(QuicUdp::new());
        let lb = b.listen(ListenConfig { url: format!("peer://[::]:0 {} {}", relays[0].item(), relays[1].item()), secret: secret(2) }).await.unwrap();
        let kb = lb.address().key;
        registered(&lb, 2).await;
        let port = bound(&lb.address()).port();
        let mut seen = lb.observed();
        seen.sort_by_key(|(r, _)| r.addr.is_ipv4());
        assert_eq!(seen, vec![(relays[0].clone(), sa(&format!("[::1]:{port}"))), (relays[1].clone(), sa(&format!("127.0.0.1:{port}")))]);
        let echo = quic_echoes(lb);
        for relay in &relays {
            session_through(relay, kb).await;
        }
        echo.abort();
    });
}

// spec/sync-transport.md §3 (a fresh UDP socket per dial and address family), by hand: loopback QUIC: a dial reaches each item from a socket of
// its address family: with an IPv4 item first (a node of another key) the IPv6 item still
// connects.
#[test]
#[ignore]
fn quic_dial_mixed_families_spec_sync_10() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let other = P2p::new(QuicUdp::new());
        let lo = other.listen(ListenConfig { url: "peer://127.0.0.1:0".into(), secret: secret(3) }).await.unwrap();
        let b = P2p::new(QuicUdp::new());
        let mut lb = b.listen(ListenConfig { url: "peer://[::1]:0".into(), secret: secret(2) }).await.unwrap();
        let kb = lb.address().key;
        let url = peer_url(&[bound(&lo.address()).to_string(), bound(&lb.address()).to_string()]);
        let accept = tokio::spawn(async move { lb.accept().await.map(|_| ()) });
        let c = P2p::new(QuicUdp::new()).dial(&Address { url, key: kb }).await.unwrap();
        assert_eq!(c.peer_key(), kb);
        assert_eq!(c.rank(), RANK_DIRECT);
        accept.await.unwrap().unwrap();
    });
}

// ---- `peer://` routes over the NAT model ----

/// `to` listens at `url` under `w`'s scheduler (registered at relays it lists).
fn listen_at(w: &mut World, to: P2p<MemUdp>, url: String, s: u8) -> P2pListener<MemUdp> {
    let l = w.sched.block_on(async move { to.listen(ListenConfig { url, secret: secret(s) }).await.unwrap() }).unwrap();
    w.sched.run();
    l
}

/// `from` dials `addr`, and the connection carries bytes both ways (the listener echoes); the
/// dial's error if it fails.
fn dial_route(w: &mut World, from: P2p<MemUdp>, addr: Address, l: P2pListener<MemUdp>) -> Result<(), Error> {
    let _ = echo(&w.sched, l);
    w.sched
        .block_on(async move {
            let c = from.dial(&addr).await?;
            assert_eq!(c.peer_key(), addr.key);
            try_round_trip(&c, b"ping").await.map(drop)
        })
        .unwrap()
}

const B_PUBLIC: &str = "203.0.113.2";

fn peer_addr(items: &[String], s: u8) -> Address {
    Address { url: peer_url(items), key: secret(s).public_key() }
}

// spec/sync-transport.md §3: a dial with no route fails, whoever listens with the key: an empty URL, an
// address the dialer cannot reach (another NAT's inside), a relay the target is not at.
#[test]
fn peer_no_route_fails_spec_sync_10() {
    let mut w = world(0, anyone());
    let b = P2p::new(host(&w.net, "10.0.0.2", B_PUBLIC, Some(Nat::SYMMETRIC)));
    let lb = listen_at(&mut w, b, "peer://10.0.0.2:7000".into(), 2);
    let a = P2p::new(host(&w.net, "10.9.0.2", "203.0.113.1", Some(Nat::CONE)));
    for items in [vec![], vec!["10.0.0.2:7000".to_owned()], vec![w.relay.item()]] {
        let (a2, addr) = (a.clone(), peer_addr(&items, 2));
        let r = w.sched.block_on(async move { a2.dial(&addr).await.map(drop) }).unwrap();
        assert!(matches!(r, Err(Error::Unreachable(_))), "{items:?}: {r:?}");
    }
    drop(lb);
}

// spec/sync-transport.md §3: a route the dialer can reach connects, the target's key proven: a
// direct item; a relay the target registered at, with no direct item; two hosts behind one NAT
// at their LAN addresses.
#[test]
fn peer_routes_connect_spec_sync_10() {
    for case in ["direct", "relay", "lan"] {
        let mut w = world(0, anyone());
        let item = w.relay.item();
        let behind = |w: &World| host(&w.net, "10.0.0.2", B_PUBLIC, Some(Nat::SYMMETRIC));
        let (b, url, items) = match case {
            "direct" => (host(&w.net, B_PUBLIC, B_PUBLIC, None), format!("peer://{B_PUBLIC}:7000"), vec![format!("{B_PUBLIC}:7000")]),
            "relay" => (behind(&w), format!("peer://10.0.0.2:7000 {item}"), vec![item]),
            _ => (behind(&w), "peer://10.0.0.2:7000".to_owned(), vec!["10.0.0.2:7000".to_owned()]),
        };
        let lb = listen_at(&mut w, P2p::new(b), url, 2);
        let a = match case {
            "direct" => host(&w.net, "10.9.0.2", "203.0.113.1", Some(Nat::CONE)),
            "relay" => host(&w.net, "10.9.0.2", "203.0.113.1", Some(Nat::SYMMETRIC)),
            _ => w.net.udp(ip("10.0.0.3"), Some(ip(B_PUBLIC))),
        };
        dial_route(&mut w, P2p::new(a), peer_addr(&items, 2), lb).unwrap_or_else(|e| panic!("{case}: {e:?}"));
    }
}

// spec/sync-transport.md §1 (route rank), §3 (a LAN listener serves ALPN `osis-lan` only), §4, by hand, loopback QUIC: a session dial offers
// `osis` and `osis-lan`; a LAN listener's socket chooses `osis-lan` (rank 0), any other socket
// `osis` (rank 1), and both ends see the same choice; a relay dial to a LAN listener fails.
#[test]
#[ignore]
fn quic_session_protocol_ranks_alike_spec_sync_10() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let u = QuicUdp::new();
        for (lan, want) in [(true, Alpn::Lan), (false, Alpn::Osis)] {
            let s = if lan { u.bind_lan(sa("127.0.0.1:0"), &secret(1)).unwrap() } else { u.bind(sa("127.0.0.1:0"), Some(&secret(1))).unwrap() };
            let c = u.bind(sa("127.0.0.1:0"), None).unwrap();
            let (_, got) = c.dial(s.local(), secret(1).public_key(), None, Alpn::Osis).await.unwrap();
            let (_, theirs, _) = s.accept().await.unwrap();
            assert_eq!((got, theirs), (want, want), "lan {lan}");
            assert_eq!(want.rank(), if lan { RANK_LAN } else { RANK_DIRECT });
            if lan {
                assert!(c.dial(s.local(), secret(1).public_key(), None, Alpn::Relay).await.is_err());
            }
        }
    });
}

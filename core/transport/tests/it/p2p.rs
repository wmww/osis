//! P2P (`p2p`) over the in-process NAT model (`nat`): relaying, observed addresses, hole
//! punching, switching to direct, relay limits; the relay wire bytes. spec/sync.md §10.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_transport::p2p::{Alpn, Relay, Sock, Udp};
use osis_transport::*;
use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr};
use std::future::{poll_fn, Future};
use std::rc::Rc;
use std::sync::Arc;
use std::task::Poll;

/// `f`'s output if it is ready at once.
async fn now_or_never<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = std::pin::pin!(f);
    poll_fn(|cx| Poll::Ready(match f.as_mut().poll(cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }))
    .await
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

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
    _relay_l: P2pListener<MemUdp>,
}

fn world(seed: u64, cfg: RelayConfig) -> World {
    world_at(seed, cfg, RELAY_IP, None)
}

/// A world whose relay is at `at`, behind the NAT at `nat` if any.
fn world_at(seed: u64, cfg: RelayConfig, at: &str, nat: Option<IpAddr>) -> World {
    let net = Net::new(seed);
    let mut sched = Sched::new(seed, Some(net.clone()));
    let r = P2p::new(net.udp("r", ip(at), nat)).relaying(cfg).unwrap();
    let url = format!("peer://{at}:4040");
    let l = sched.block_on(async move { r.listen(ListenConfig { url, secret: secret(1) }).await.unwrap() }).unwrap();
    let relay = Relay { key: l.address().key, addr: sa(&format!("{at}:4040")) };
    World { net, sched, relay, _relay_l: l }
}

fn anyone() -> RelayConfig {
    RelayConfig::new(Arc::new(|_| true))
}

/// A host at `inside`, behind a NAT at `public` with `nat` (none: `inside` is public).
fn host(net: &Net, name: &str, inside: &str, public: &str, nat: Option<Nat>) -> MemUdp {
    match nat {
        Some(n) => {
            net.add_nat(ip(public), n);
            net.udp(name, ip(inside), Some(ip(public)))
        }
        None => net.udp(name, ip(inside), None),
    }
}

/// Accepts connections; echoes each stream chunk by chunk; records whether each was relayed.
fn echo(sched: &Sched, mut l: P2pListener<MemUdp>) -> Rc<RefCell<Vec<bool>>> {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let (sp, s2) = (sched.spawner(), seen.clone());
    sched.spawn(async move {
        while let Ok(c) = l.accept().await {
            s2.borrow_mut().push(c.is_relayed());
            let sp2 = sp.clone();
            sp.spawn(async move {
                while let Ok((mut tx, mut rx)) = c.accept_stream().await {
                    sp2.spawn(async move {
                        let mut b = [0u8; 4096];
                        while let Ok(n) = rx.read(&mut b).await {
                            if n == 0 {
                                let _ = tx.finish().await;
                                return;
                            }
                            if tx.write_all(&b[..n]).await.is_err() {
                                return;
                            }
                        }
                    });
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
fn punch(seed: u64, nat_a: Option<Nat>, nat_b: Option<Nat>) -> (bool, bool) {
    let w = world(seed, anyone());
    let (a, b) = (host(&w.net, "a", "10.0.1.2", "203.0.113.1", nat_a), host(&w.net, "b", "10.0.0.2", "203.0.113.2", nat_b));
    punch_in(w, a, b, if nat_b.is_some() { "203.0.113.2" } else { "10.0.0.2" })
}

/// `punch` between hosts `a` and `b` of world `w`; the relay must see `b` at `seen`.
fn punch_in(mut w: World, a: MemUdp, b: MemUdp, seen: &str) -> (bool, bool) {
    let b = P2p::new(b);
    let url = format!("peer://10.0.0.2:7000 {}", w.relay.item());
    let lb = w.sched.block_on(async move { b.listen(ListenConfig { url, secret: secret(2) }).await.unwrap() }).unwrap();
    w.sched.run();
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
            if !c.is_relayed() {
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
            assert_eq!(next.is_relayed(), !switched, "a switch leaves a parked direct connection");
            (false, switched)
        })
        .unwrap();
    w.sched.run();
    let accepted = seen.borrow().clone();
    assert_eq!(accepted.iter().any(|r| !r), direct_now, "B accepted a direct connection iff one exists: {accepted:?}");
    (first_direct, direct_now)
}

// spec/sync.md §10 (hole punching, IP consent): the dialer, here with an ephemeral key (as a
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
            let (_, direct) = punch(seed * 100 + i as u64, *na, *nb);
            assert_eq!(direct, *want, "case {i} {na:?} -> {nb:?} seed {seed}");
        }
    }
}

// spec/sync.md §10: `nat::punch_opens`, the rule the sims apply, is what the packet machine does
// for every mapping and filtering on either side, not only the table above.
#[test]
fn punch_rule_matches_the_packet_machine_spec_sync_10() {
    let deps = [Dep::Endpoint, Dep::Address, Dep::AddressPort];
    let kinds: Vec<Option<Nat>> = std::iter::once(None).chain(deps.iter().flat_map(|m| deps.iter().map(|f| Some(Nat { mapping: *m, filtering: *f })))).collect();
    for (i, na) in kinds.iter().enumerate() {
        for (j, nb) in kinds.iter().enumerate() {
            let (_, direct) = punch((i * 100 + j) as u64, *na, *nb);
            assert_eq!(nat::punch_opens(*na, *nb), direct, "{na:?} -> {nb:?}");
        }
    }
}

// spec/sync.md §10: a relay on the pair's own LAN (here behind their one NAT) sees each one's LAN
// address, so the punch stays on the LAN and goes direct whatever the NAT does (what
// `osis_sim::reach` models as `Route::Punch` for a relay on a segment).
#[test]
fn punch_over_a_relay_on_the_pairs_lan_is_direct_spec_sync_10() {
    let deps = [Dep::Endpoint, Dep::Address, Dep::AddressPort];
    for (i, nat) in deps.iter().flat_map(|m| deps.iter().map(|f| Nat { mapping: *m, filtering: *f })).enumerate() {
        let public = ip("203.0.113.9");
        let net_seed = i as u64;
        let w = {
            let mut w = world_at(net_seed, anyone(), "10.0.0.9", Some(public));
            w.net.add_nat(public, nat);
            w.sched.run();
            w
        };
        let (a, b) = (w.net.udp("a", ip("10.0.0.1"), Some(public)), w.net.udp("b", ip("10.0.0.2"), Some(public)));
        let (_, direct) = punch_in(w, a, b, "10.0.0.2");
        assert!(direct, "{nat:?}");
    }
}

// spec/sync.md §10: direct socket addresses in the URL are dialed as they are; the key is pinned
// (another key: KeyMismatch); nothing listening there and no relay: Unreachable.
#[test]
fn direct_items_spec_sync_10() {
    let mut w = world(7, anyone());
    let b = P2p::new(host(&w.net, "b", "192.0.2.7", "", None));
    let lb = w.sched.block_on(async move { b.listen(ListenConfig { url: "peer://192.0.2.7:7000".into(), secret: secret(3) }).await.unwrap() }).unwrap();
    let kb = lb.address().key;
    assert_eq!(lb.address().url, "peer://192.0.2.7:7000");
    let _seen = echo(&w.sched, lb);
    let a = P2p::new(host(&w.net, "a", "10.9.0.2", "203.0.113.9", Some(Nat::SYMMETRIC)));
    let r = w.sched.block_on(async move {
        let c = a.dial(&Address { url: "peer://192.0.2.7:7000".into(), key: kb }).await.unwrap();
        assert!(!c.is_relayed());
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

// spec/sync.md §10: through a relay the dialer pins the target's key end to end (TLS over the
// forwarded stream) and the target sees the dialer's key: fresh per dial, or its own with dial_as;
// a key nobody registered is unreachable.
#[test]
fn relayed_keys_spec_sync_10() {
    let mut w = world(8, anyone());
    let b = P2p::new(host(&w.net, "b", "10.0.0.2", "203.0.113.2", Some(Nat::SYMMETRIC)));
    let url = format!("peer://10.0.0.2:7000 {}", w.relay.item());
    let mut lb = w.sched.block_on(async move { b.listen(ListenConfig { url, secret: secret(2) }).await.unwrap() }).unwrap();
    w.sched.run();
    let kb = lb.address().key;
    let a = P2p::new(host(&w.net, "a", "10.0.1.2", "203.0.113.1", Some(Nat::SYMMETRIC)));
    let url = peer_url(&[w.relay.item()]);
    let (a2, u2) = (a.clone(), url.clone());
    let got = w.sched.block_on(async move {
        let c1 = a2.dial(&Address { url: u2.clone(), key: kb }).await.unwrap();
        let (mut t1, _r1) = c1.open_stream().await.unwrap();
        t1.write_all(b"x").await.unwrap();
        let s1 = lb.accept().await.unwrap();
        let c2 = a2.dial_as(&Address { url: u2.clone(), key: kb }, &secret(5)).await.unwrap();
        let s2 = lb.accept().await.unwrap();
        let none = a2.dial(&Address { url: u2, key: [7; 32] }).await.err();
        assert!(c1.is_relayed() && c2.is_relayed() && s1.is_relayed() && s2.is_relayed());
        // one stream per relayed connection
        assert!(matches!(c1.open_stream().await, Err(Error::Protocol(_))));
        (s1.peer_key(), s2.peer_key(), none)
    });
    let (k1, k2, none) = got.unwrap();
    assert_ne!(k1, InProcess::public_key(&secret(5)));
    assert_eq!(k2, InProcess::public_key(&secret(5)));
    assert!(matches!(none, Some(Error::Unreachable(_))), "{none:?}");
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
    let net = Net::new(21);
    let mut sched = Sched::new(21, Some(net.clone()));
    let m = host(&net, "m", "198.51.100.9", "", None);
    let msock = Arc::new(m.bind(sa("198.51.100.9:4040"), Some(&secret(9))).unwrap());
    let (to, key) = (msock.local(), InProcess::public_key(&secret(9)));
    let a = host(&net, "a", "192.0.2.5", "", None);
    let opened = sched.block_on(async move {
        let mut opened = Vec::new();
        for own in [None, Some(secret(2))] {
            let c = a.bind(sa("0.0.0.0:0"), None).unwrap().dial(to, key, own, Alpn::Relay).await.unwrap();
            let (rc, alpn, _) = msock.accept().await.unwrap();
            assert_eq!(alpn, Alpn::Relay);
            opened.push(now_or_never(rc.open_stream()).await.is_some_and(|r| r.is_ok()));
            drop(c);
        }
        opened
    });
    assert_eq!(opened, Some(vec![false, true]));
}

// spec/sync.md §10 (relayed connection): a hostile relay answering a dial for key K and
// forwarding the stream to another node Z (registered at an honest relay) cannot pass Z off as
// K: the dialer pins K end to end and gets KeyMismatch.
#[test]
fn relay_cannot_impersonate_spec_sync_10() {
    let mut w = world(13, anyone());
    let (rk, ra) = (w.relay.key, w.relay.addr);
    let z = P2p::new(host(&w.net, "z", "192.0.2.3", "", None));
    let url = format!("peer://192.0.2.3:7000 {}", w.relay.item());
    let lz = w.sched.block_on(async move { z.listen(ListenConfig { url, secret: secret(3) }).await.unwrap() }).unwrap();
    w.sched.run();
    let kz = lz.address().key;
    let _seen = echo(&w.sched, lz);
    // the hostile relay: answers any dial with a stream to Z through the honest relay
    let m = host(&w.net, "m", "198.51.100.9", "", None);
    let msock = Arc::new(m.bind(sa("198.51.100.9:4040"), Some(&secret(9))).unwrap());
    let hostile = Relay { key: InProcess::public_key(&secret(9)), addr: msock.local() };
    let net = w.net.clone();
    let ms = msock.clone();
    w.net.spawn(async move {
        let (c, alpn, _) = ms.accept().await.unwrap();
        assert_eq!(alpn, Alpn::Relay);
        let (mut t, mut r) = c.accept_stream().await.unwrap();
        let _ = read_n(&mut r, 33).await;
        let up = m.bind(sa("0.0.0.0:0"), None).unwrap().dial(ra, rk, None, Alpn::Relay).await.unwrap();
        let (mut ut, mut ur) = up.open_stream().await.unwrap();
        let mut req = vec![2];
        req.extend_from_slice(&kz);
        ut.write_all(&req).await.unwrap();
        let reply = read_n(&mut ur, 19).await;
        t.write_all(&reply).await.unwrap();
        net.spawn(pipe(r, ut));
        pipe(ur, t).await;
        let _ = (c, up);
    });
    let a = P2p::new(host(&w.net, "a", "192.0.2.5", "", None));
    let want = InProcess::public_key(&secret(2));
    let addr = Address { url: peer_url(&[hostile.item()]), key: want };
    let r = w.sched.block_on(async move { a.dial(&addr).await.err() });
    assert_eq!(r, Some(Some(Error::KeyMismatch)));
    drop(msock);
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

// spec/sync.md §10 (relay wire): register (kind 1, the connection's key) answers 0 and the
// observed address; dial (kind 2 and the key) answers 0 and the dialer's own observed address,
// never the target's; the target gets a stream starting with a 16-byte tag of the dialer's
// source, never its address (the same for every dial from that source, another for another
// source); then bytes pass unchanged both ways, ends included. Unknown key: 2. A key the relay
// does not allow: 1.
#[test]
fn relay_wire_spec_sync_10() {
    let allowed = InProcess::public_key(&secret(2));
    let mut w = world(9, RelayConfig::new(Arc::new(move |k| *k == allowed)));
    let (rk, ra) = (w.relay.key, w.relay.addr);
    let b = host(&w.net, "b", "10.0.0.2", "203.0.113.2", Some(Nat::CONE));
    let a = host(&w.net, "a", "192.0.2.5", "", None);
    let done = w.sched.block_on(async move {
        let sb = b.bind(sa("0.0.0.0:6000"), None).unwrap();
        let cb = sb.dial(ra, rk, Some(secret(2)), Alpn::Relay).await.unwrap();
        let (mut tb, mut rb) = cb.open_stream().await.unwrap();
        tb.write_all(&[1]).await.unwrap();
        let reply = read_n(&mut rb, 19).await;
        assert_eq!(reply[0], 0);
        let obs_b = SocketAddr::new(ip("203.0.113.2"), u16::from_be_bytes([reply[17], reply[18]]));
        assert_eq!(reply[1..], wire_addr(obs_b)[..]);
        // a key the relay does not allow
        let sx = b.bind(sa("0.0.0.0:6001"), None).unwrap();
        let cx = sx.dial(ra, rk, Some(secret(4)), Alpn::Relay).await.unwrap();
        let (mut tx, mut rx) = cx.open_stream().await.unwrap();
        tx.write_all(&[1]).await.unwrap();
        assert_eq!(read_n(&mut rx, 1).await, [1]);
        // dial the registered key
        let sa_ = a.bind(sa("0.0.0.0:5000"), None).unwrap();
        let ca = sa_.dial(ra, rk, None, Alpn::Relay).await.unwrap();
        let (mut ta, mut ra2) = ca.open_stream().await.unwrap();
        let mut req = vec![2];
        req.extend_from_slice(&allowed);
        ta.write_all(&req).await.unwrap();
        let reply = read_n(&mut ra2, 19).await;
        assert_eq!(reply[0], 0);
        assert_eq!(reply[1..19], wire_addr(sa("192.0.2.5:5000"))[..]);
        let (mut fb, mut gb) = cb.accept_stream().await.unwrap();
        let tag = read_n(&mut gb, 16).await;
        assert_ne!(tag[..], wire_addr(sa("192.0.2.5:5000"))[..16]);
        ta.write_all(b"ping").await.unwrap();
        ta.finish().await.unwrap();
        assert_eq!(read_n(&mut gb, 4).await, b"ping");
        assert_eq!(gb.read(&mut [0u8; 4]).await.unwrap(), 0);
        fb.write_all(b"pong").await.unwrap();
        fb.finish().await.unwrap();
        assert_eq!(read_n(&mut ra2, 4).await, b"pong");
        assert_eq!(ra2.read(&mut [0u8; 4]).await.unwrap(), 0);
        // tags: the same source again (another port), and another source
        for (host, same) in [(&a, true), (&b, false)] {
            let c2 = host.bind(sa("0.0.0.0:0"), None).unwrap().dial(ra, rk, None, Alpn::Relay).await.unwrap();
            let (mut t2, mut r2) = c2.open_stream().await.unwrap();
            let mut req = vec![2];
            req.extend_from_slice(&allowed);
            t2.write_all(&req).await.unwrap();
            assert_eq!(read_n(&mut r2, 19).await[0], 0);
            let (_f2, mut g2) = cb.accept_stream().await.unwrap();
            assert_eq!(read_n(&mut g2, 16).await == tag, same);
        }
        // a key nobody registered
        let (mut tu, mut ru) = ca.open_stream().await.unwrap();
        let mut req = vec![2];
        req.extend_from_slice(&[7; 32]);
        tu.write_all(&req).await.unwrap();
        assert_eq!(read_n(&mut ru, 1).await, [2]);
        true
    });
    assert_eq!(done, Some(true));
}

// spec/sync.md §10 (relay limits): forwarding is held to the per-source rate (virtual time), and
// past the connection cap the source holding the most gives one up, else the newcomer is refused.
#[test]
fn relay_limits_spec_sync_10() {
    let mut cfg = anyone();
    cfg.rate = 10_000;
    cfg.max_conns = 3;
    let mut w = world(10, cfg);
    let (rk, ra) = (w.relay.key, w.relay.addr);
    let b = host(&w.net, "b", "192.0.2.2", "", None);
    let a = host(&w.net, "a", "192.0.2.5", "", None);
    let c = host(&w.net, "c", "192.0.2.6", "", None);
    let net = w.net.clone();
    let done = w.sched.block_on(async move {
        let sb = b.bind(sa("0.0.0.0:6000"), None).unwrap();
        let cb = sb.dial(ra, rk, Some(secret(2)), Alpn::Relay).await.unwrap();
        let (mut tb, mut rb) = cb.open_stream().await.unwrap();
        tb.write_all(&[1]).await.unwrap();
        assert_eq!(read_n(&mut rb, 19).await[0], 0);
        let sa_ = a.bind(sa("0.0.0.0:5000"), None).unwrap();
        let ca = sa_.dial(ra, rk, None, Alpn::Relay).await.unwrap();
        let (mut ta, mut ra2) = ca.open_stream().await.unwrap();
        let mut req = vec![2];
        req.extend_from_slice(&InProcess::public_key(&secret(2)));
        ta.write_all(&req).await.unwrap();
        assert_eq!(read_n(&mut ra2, 19).await[0], 0);
        let (_fb, mut gb) = cb.accept_stream().await.unwrap();
        let _ = read_n(&mut gb, 16).await;
        // 50 kB at 10 kB/s with a one-second burst: at least four seconds
        let t0 = net.now();
        ta.write_all(&vec![7u8; 50_000]).await.unwrap();
        let _ = read_n(&mut gb, 50_000).await;
        let took = net.now() - t0;
        assert!((4000..6000).contains(&took), "{took} ms");
        // connections: b and a hold two of three; a second from a fills the cap
        let ca2 = sa_.dial(ra, rk, None, Alpn::Relay).await.unwrap();
        let (mut t2, r2) = ca2.open_stream().await.unwrap();
        t2.write_all(&[2, 0]).await.unwrap();
        // c arrives: a (two) gives one up, its oldest
        let sc = c.bind(sa("0.0.0.0:5001"), None).unwrap();
        let cc = sc.dial(ra, rk, None, Alpn::Relay).await.unwrap();
        let (mut t3, mut r3) = cc.open_stream().await.unwrap();
        let mut req = vec![2];
        req.extend_from_slice(&[7; 32]);
        t3.write_all(&req).await.unwrap();
        assert_eq!(read_n(&mut r3, 1).await, [2], "c served");
        assert!(ra2.read(&mut [0u8; 8]).await.is_err(), "a's oldest connection closed");
        drop(r2);
        // a third from c: c holds one, a one, b one: refused
        let cc2 = sc.dial(ra, rk, None, Alpn::Relay).await.unwrap();
        let (mut t4, mut r4) = cc2.open_stream().await.unwrap();
        let _ = t4.write_all(&[2]).await;
        assert!(r4.read(&mut [0u8; 8]).await.is_err(), "newcomer refused");
        true
    });
    assert_eq!(done, Some(true));
}

// spec/sync.md §10: a listener whose relay refuses its key stays unregistered (no observed
// address) and retries with backoff; dials through that relay find nobody.
#[test]
fn registration_refused_spec_sync_10() {
    let mut w = world(11, RelayConfig::new(Arc::new(|_| false)));
    w.sched.set_max_steps(200);
    let b = P2p::new(host(&w.net, "b", "192.0.2.2", "", None));
    let url = format!("peer://192.0.2.2:7000 {}", w.relay.item());
    let lb = w.sched.block_on(async move { b.listen(ListenConfig { url, secret: secret(2) }).await.unwrap() }).unwrap();
    w.sched.run();
    assert!(lb.observed().is_empty());
    let a = P2p::new(host(&w.net, "a", "192.0.2.5", "", None));
    let addr = Address { url: peer_url(&[w.relay.item()]), key: lb.address().key };
    let r = w.sched.block_on(async move { a.dial(&addr).await.err() });
    assert!(matches!(r, Some(Some(Error::Unreachable(_)))), "{r:?}");
}

// spec: none (NAT model): mappings and filters behave as RFC 4787 describes
#[test]
fn nat_model() {
    let net = Net::new(12);
    let mut sched = Sched::new(12, Some(net.clone()));
    net.add_nat(ip("203.0.113.1"), Nat::SYMMETRIC);
    let a = net.udp("a", ip("10.0.0.2"), Some(ip("203.0.113.1")));
    let lan = net.udp("lan", ip("10.0.0.3"), Some(ip("203.0.113.1")));
    let p = net.udp("p", ip("192.0.2.1"), None);
    let r = sched.block_on(async move {
        let sp = p.bind(sa("0.0.0.0:80"), Some(&secret(1))).unwrap();
        let sp2 = p.bind(sa("0.0.0.0:81"), Some(&secret(1))).unwrap();
        let k = InProcess::public_key(&secret(1));
        let sl = lan.bind(sa("0.0.0.0:90"), Some(&secret(1))).unwrap();
        let s = a.bind(sa("0.0.0.0:0"), None).unwrap();
        // out to two ports of one host: two mappings
        let _c1 = s.dial(sp.local(), k, None, Alpn::Osis).await.unwrap();
        let (_, _, f1) = sp.accept().await.unwrap();
        let _c2 = s.dial(sp2.local(), k, None, Alpn::Osis).await.unwrap();
        let (_, _, f2) = sp2.accept().await.unwrap();
        assert_eq!(f1.ip(), ip("203.0.113.1"));
        assert_ne!(f1.port(), f2.port());
        // the same LAN at its own address, untranslated; not at the public one
        let _c3 = s.dial(sl.local(), k, None, Alpn::Osis).await.unwrap();
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

// spec/sync.md §10 (tier 2, loopback QUIC): a listener registers at a relaying node over ALPN
// `osis-relay` and learns its observed address; the relay wire runs over real QUIC; a dial
// through the relay reaches the listener (directly once punched: no NAT on loopback) with the
// key pinned.
#[test]
#[ignore]
fn quic_relay_loopback_spec_sync_10() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let r = P2p::new(QuicUdp::new()).relaying(anyone()).unwrap();
        let lr = r.listen(ListenConfig { url: "peer://127.0.0.1:0".into(), secret: secret(1) }).await.unwrap();
        let ra = lr.address().url.strip_prefix("peer://").unwrap().parse::<SocketAddr>().unwrap();
        let relay = Relay { key: lr.address().key, addr: ra };
        let b = P2p::new(QuicUdp::new());
        let mut lb = b.listen(ListenConfig { url: format!("peer://127.0.0.1:0 {}", relay.item()), secret: secret(2) }).await.unwrap();
        let kb = lb.address().key;
        for _ in 0..100 {
            if !lb.observed().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let bound = lb.address().url.strip_prefix("peer://").unwrap().split(' ').next().unwrap().parse::<SocketAddr>().unwrap();
        assert_eq!(lb.observed(), vec![(relay.clone(), bound)]);
        assert_eq!(r.relayed_keys(), vec![kb]);
        // the wire, by hand: a dial request answers the dialer's own observed address
        let s = QuicUdp::new().bind(sa("127.0.0.1:0"), None).unwrap();
        let c = s.dial(ra, relay.key, None, Alpn::Relay).await.unwrap();
        let (mut t, mut rr) = c.open_stream().await.unwrap();
        let mut req = vec![2];
        req.extend_from_slice(&kb);
        t.write_all(&req).await.unwrap();
        let reply = read_n(&mut rr, 19).await;
        assert_eq!(reply[0], 0);
        assert_eq!(reply[1..19], wire_addr(s.local())[..]);
        drop((t, rr, c));
        // through the relay with p2p
        let echo = tokio::spawn(async move {
            loop {
                let c = lb.accept().await.unwrap();
                tokio::spawn(async move {
                    if let Ok((mut tx, mut rx)) = c.accept_stream().await {
                        let mut b = [0u8; 1024];
                        while let Ok(n) = rx.read(&mut b).await {
                            if n == 0 || tx.write_all(&b[..n]).await.is_err() {
                                break;
                            }
                        }
                        let _ = tx.finish().await;
                        let _ = c.accept_stream().await;
                    }
                });
            }
        });
        let a = P2p::new(QuicUdp::new());
        let addr = Address { url: peer_url(&[relay.item()]), key: kb };
        let c = a.dial_as(&addr, &secret(5)).await.unwrap();
        assert_eq!(c.peer_key(), kb);
        if let Err(e) = session(&c).await {
            // a relayed connection closes once the direct one completes; the next dial takes that
            assert!(c.is_relayed(), "{e:?}");
            let d = a.dial_as(&addr, &secret(5)).await.unwrap();
            assert!(!d.is_relayed());
            session(&d).await.unwrap();
        }
        echo.abort();
    });
}

// spec/sync.md §10 (registration streams, tier 2: loopback QUIC): relayed sessions whose bytes
// the target never reads hold only their own stream's window of its registration connection:
// with more unread in them than a `quic://` connection window (4 MiB), forwarding to the target
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
        let r = P2p::new(QuicUdp::new()).relaying(cfg).unwrap();
        let lr = r.listen(ListenConfig { url: "peer://[::]:0".into(), secret: secret(1) }).await.unwrap();
        let port = lr.address().url.strip_prefix("peer://").unwrap().split(' ').next().unwrap().parse::<SocketAddr>().unwrap().port();
        let relay6 = Relay { key: lr.address().key, addr: sa(&format!("[::1]:{port}")) };
        let relay = Relay { key: lr.address().key, addr: sa(&format!("127.0.0.1:{port}")) };
        let b = P2p::new(QuicUdp::new());
        let mut lb = b.listen(ListenConfig { url: format!("peer://[::1]:0 {}", relay6.item()), secret: secret(2) }).await.unwrap();
        let kb = lb.address().key;
        for _ in 0..100 {
            if !lb.observed().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        // the first UNREAD connections are held and never read; later ones are echoed
        let target = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let c = lb.accept().await.unwrap();
                if held.len() < UNREAD {
                    held.push(c);
                    continue;
                }
                tokio::spawn(async move {
                    if let Ok((mut tx, mut rx)) = c.accept_stream().await {
                        let mut b = [0u8; 1024];
                        while let Ok(n) = rx.read(&mut b).await {
                            if n == 0 || tx.write_all(&b[..n]).await.is_err() {
                                break;
                            }
                        }
                        let _ = tx.finish().await;
                        let _ = c.accept_stream().await;
                    }
                });
            }
        });
        let a = P2p::new(QuicUdp::new());
        let addr = Address { url: peer_url(&[relay.item()]), key: kb };
        let mut writers = Vec::new();
        for _ in 0..UNREAD {
            let c = a.dial(&addr).await.unwrap();
            assert!(c.is_relayed());
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
    let s = m.bind(sa("0.0.0.0:0"), None).unwrap();
    while answers.len() < n {
        let c = s.dial(relay.addr, relay.key, None, Alpn::Relay).await.unwrap();
        for _ in 0..16.min(n - answers.len()) {
            let (mut t, mut r) = c.open_stream().await.unwrap();
            let mut req = vec![2];
            req.extend_from_slice(&key);
            t.write_all(&req).await.unwrap();
            answers.push(read_n(&mut r, 1).await[0]);
            held.push((t, r));
        }
        conns.push(c);
    }
    (answers, held, conns)
}

// spec/sync.md §10 (relay limits): dials that never start their handshake cannot block a target.
// Each forwarded stream takes one of the streams the target's registration grants its relay;
// the target ends the oldest it has not handed to `accept` past MAX_FORWARDED, so an honest
// dial after a flood of silent ones still connects, and the oldest silent ones see their end.
#[test]
fn silent_dials_do_not_block_spec_sync_10() {
    let mut w = world(14, anyone());
    let b = P2p::new(host(&w.net, "b", "10.0.0.2", "203.0.113.2", Some(Nat::SYMMETRIC)));
    let url = format!("peer://10.0.0.2:7000 {}", w.relay.item());
    let lb = w.sched.block_on(async move { b.listen(ListenConfig { url, secret: secret(2) }).await.unwrap() }).unwrap();
    w.sched.run();
    let kb = lb.address().key;
    let _seen = echo(&w.sched, lb);
    let m = host(&w.net, "m", "192.0.2.66", "", None);
    let relay = w.relay.clone();
    let flood = p2p::MAX_FORWARDED + 64;
    let (answers, mut held, _conns) = w.sched.block_on(async move { raw_dials(&m, &relay, kb, flood).await }).unwrap();
    assert!(answers.iter().all(|a| *a == 0), "every silent dial forwarded");
    w.sched.run();
    let a = P2p::new(host(&w.net, "a", "10.0.1.2", "203.0.113.1", Some(Nat::SYMMETRIC)));
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

// spec/sync.md §10 (relay wire): a relay never waits for room on a registration connection: a
// dial it cannot open a stream for at once is answered busy (3). A registration that accepts no
// streams fills after REG_STREAMS dials.
#[test]
fn relay_busy_spec_sync_10() {
    let mut w = world(15, anyone());
    let (rk, ra) = (w.relay.key, w.relay.addr);
    let b = host(&w.net, "b", "192.0.2.2", "", None);
    let m = host(&w.net, "m", "192.0.2.66", "", None);
    let relay = w.relay.clone();
    let done = w.sched.block_on(async move {
        let sb = b.bind(sa("0.0.0.0:6000"), None).unwrap();
        let cb = sb.dial(ra, rk, Some(secret(2)), Alpn::Relay).await.unwrap();
        let (mut tb, mut rb) = cb.open_stream().await.unwrap();
        tb.write_all(&[1]).await.unwrap();
        assert_eq!(read_n(&mut rb, 19).await[0], 0);
        let n = p2p::REG_STREAMS as usize;
        let (answers, held, conns) = raw_dials(&m, &relay, InProcess::public_key(&secret(2)), n + 1).await;
        assert!(answers[..n].iter().all(|a| *a == 0));
        assert_eq!(answers[n], 3, "busy");
        drop((held, conns, cb));
        true
    });
    assert_eq!(done, Some(true));
}

// spec/sync.md §10 (`reach.0` items): a listener is listed at each global address it is bound
// to, an unspecified IP standing for the routes' local addresses of the families it serves,
// then its relays; local, loopback and carrier-NAT addresses are not listed.
#[test]
fn reach_items_global_addresses_spec_sync_10() {
    use osis_transport::p2p::reach_items;
    let relay = Relay { key: [7; 32], addr: sa("192.0.2.1:4040") }.item();
    let routes = [ip("192.168.1.5"), ip("2001:db8::5")];
    let wide = [ip("203.0.113.7"), ip("2001:db8::5")];
    assert_eq!(reach_items(&peer_url(&["[::]:47381".into(), relay.clone()]), &wide), vec!["203.0.113.7:47381".to_owned(), "[2001:db8::5]:47381".into(), relay.clone()]);
    assert_eq!(reach_items(&peer_url(&["[::]:47381".into(), relay.clone()]), &routes), vec!["[2001:db8::5]:47381".to_owned(), relay.clone()]);
    assert_eq!(reach_items(&peer_url(&["0.0.0.0:9".into()]), &wide), vec!["203.0.113.7:9".to_owned()]);
    assert_eq!(reach_items(&peer_url(&["0.0.0.0:9".into()]), &[ip("100.64.0.9"), ip("10.0.0.2")]), Vec::<String>::new());
    assert_eq!(reach_items(&peer_url(&["127.0.0.1:9".into(), "[fd00::1]:9".into(), "[fe80::1]:9".into()]), &wide), Vec::<String>::new());
    assert_eq!(reach_items(&peer_url(&["203.0.113.8:9".into()]), &[]), vec!["203.0.113.8:9".to_owned()]);
    assert_eq!(reach_items("mem://a", &wide), Vec::<String>::new());
}

// spec/sync.md §10 (relaying): a key the relay stops allowing loses its registration at its next
// dial (answered as unknown) or when the relay rechecks.
#[test]
fn allow_rechecked_spec_sync_10() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let ok = Arc::new(AtomicBool::new(true));
    let o2 = ok.clone();
    let net = Net::new(17);
    let mut sched = Sched::new(17, Some(net.clone()));
    let r = P2p::new(net.udp("r", ip(RELAY_IP), None)).relaying(RelayConfig::new(Arc::new(move |_| o2.load(Ordering::SeqCst)))).unwrap();
    let r2 = r.clone();
    let _lr = sched.block_on(async move { r2.listen(ListenConfig { url: format!("peer://{RELAY_IP}:4040"), secret: secret(1) }).await.unwrap() }).unwrap();
    let relay = Relay { key: InProcess::public_key(&secret(1)), addr: sa(&format!("{RELAY_IP}:4040")) };
    let listen = |sched: &mut Sched, name: &str, ipa: &str, s: u8| {
        let b = P2p::new(net.udp(name, ip(ipa), None));
        let url = format!("peer://{ipa}:7000 {}", relay.item());
        sched.block_on(async move { b.listen(ListenConfig { url, secret: secret(s) }).await.unwrap() }).unwrap()
    };
    let lb = listen(&mut sched, "b", "192.0.2.2", 2);
    let lc = listen(&mut sched, "c", "192.0.2.3", 3);
    sched.set_max_steps(100);
    sched.run();
    let (kb, kc) = (lb.address().key, lc.address().key);
    assert_eq!(r.relayed_keys().len(), 2);
    ok.store(false, Ordering::SeqCst);
    let m = net.udp("m", ip("192.0.2.66"), None);
    let rl = relay.clone();
    let answers = sched.block_on(async move { raw_dials(&m, &rl, kb, 1).await.0 }).unwrap();
    assert_eq!(answers, vec![2]);
    assert_eq!(r.relayed_keys(), vec![kc]);
    r.recheck_relayed();
    assert!(r.relayed_keys().is_empty());
}

// spec/sync.md §10 (tier 2, loopback QUIC): a listener bound at `[::]` (as nodes bind) registers
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
            let r = P2p::new(QuicUdp::new()).relaying(anyone()).unwrap();
            let l = r.listen(ListenConfig { url: format!("peer://{at}"), secret: secret(s) }).await.unwrap();
            let ra = l.address().url.strip_prefix("peer://").unwrap().parse::<SocketAddr>().unwrap();
            relays.push(Relay { key: l.address().key, addr: ra });
            held.push((r, l));
        }
        let b = P2p::new(QuicUdp::new());
        let mut lb = b.listen(ListenConfig { url: format!("peer://[::]:0 {} {}", relays[0].item(), relays[1].item()), secret: secret(2) }).await.unwrap();
        let kb = lb.address().key;
        for _ in 0..100 {
            if lb.observed().len() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let port = lb.address().url.strip_prefix("peer://").unwrap().split(' ').next().unwrap().parse::<SocketAddr>().unwrap().port();
        let mut seen = lb.observed();
        seen.sort_by_key(|(r, _)| r.addr.is_ipv4());
        assert_eq!(seen, vec![(relays[0].clone(), sa(&format!("[::1]:{port}"))), (relays[1].clone(), sa(&format!("127.0.0.1:{port}")))]);
        let echo = tokio::spawn(async move {
            loop {
                let c = lb.accept().await.unwrap();
                tokio::spawn(async move {
                    if let Ok((mut tx, mut rx)) = c.accept_stream().await {
                        let mut b = [0u8; 1024];
                        while let Ok(n) = rx.read(&mut b).await {
                            if n == 0 || tx.write_all(&b[..n]).await.is_err() {
                                break;
                            }
                        }
                        let _ = tx.finish().await;
                        let _ = c.accept_stream().await;
                    }
                });
            }
        });
        for (i, relay) in relays.iter().enumerate() {
            let a = P2p::new(QuicUdp::new());
            let addr = Address { url: peer_url(&[relay.item()]), key: kb };
            let own = secret(5 + i as u8);
            let c = a.dial_as(&addr, &own).await.unwrap();
            assert_eq!(c.peer_key(), kb);
            if let Err(e) = session(&c).await {
                // a relayed connection closes once the direct one completes; the next dial takes that
                assert!(c.is_relayed(), "{e:?}");
                let d = a.dial_as(&addr, &own).await.unwrap();
                assert!(!d.is_relayed());
                session(&d).await.unwrap();
            }
        }
        echo.abort();
    });
}

// spec/sync.md §10 (dialing, tier 2: loopback QUIC): a dial reaches each item from a socket of
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
        let at = |l: &osis_transport::Address| l.url.strip_prefix("peer://").unwrap().split(' ').next().unwrap().to_owned();
        let url = peer_url(&[at(&lo.address()), at(&lb.address())]);
        let accept = tokio::spawn(async move { lb.accept().await.map(|_| ()) });
        let c = P2p::new(QuicUdp::new()).dial(&Address { url, key: kb }).await.unwrap();
        assert_eq!(c.peer_key(), kb);
        assert!(!c.is_relayed());
        accept.await.unwrap().unwrap();
    });
}

// ---- `peer://` routes through `Multi` over the NAT model ----

/// A `Multi` whose `peer://` is `P2p` on `udp`.
fn multi(udp: MemUdp) -> Multi<MemUdp> {
    Multi { p2p: Some(P2p::new(udp)), ..Multi::default() }
}

/// `to` listens at `url` under `w`'s scheduler (registered at relays it lists).
fn listen_at(w: &mut World, to: Multi<MemUdp>, url: String, s: u8) -> MultiListener<MemUdp> {
    let l = w.sched.block_on(async move { to.listen(ListenConfig { url, secret: secret(s) }).await.unwrap() }).unwrap();
    w.sched.run();
    l
}

/// `from` dials `addr`, and the connection carries bytes both ways (the listener's side echoes
/// one stream); the dial's error if it fails.
fn dial_route(w: &mut World, from: Multi<MemUdp>, addr: Address, mut l: MultiListener<MemUdp>) -> Result<(), Error> {
    let sp = w.sched.spawner();
    let sp2 = sp.clone();
    sp.spawn(async move {
        while let Ok(c) = l.accept().await {
            sp2.spawn(async move {
                if let Ok((mut tx, mut rx)) = c.accept_stream().await {
                    let mut b = [0u8; 4];
                    if let Ok(n) = rx.read(&mut b).await {
                        let _ = tx.write_all(&b[..n]).await;
                    }
                    // the connection outlives the echo: until the dialer is done
                    let _ = rx.read(&mut b).await;
                }
            });
        }
    });
    w.sched.block_on(async move {
        let c = from.dial(&addr).await?;
        assert_eq!(c.peer_key(), addr.key);
        let (mut tx, mut rx) = c.open_stream().await?;
        tx.write_all(b"ping").await?;
        let mut got = [0u8; 4];
        let mut at = 0;
        while at < got.len() {
            at += rx.read(&mut got[at..]).await?;
        }
        assert_eq!(&got, b"ping");
        Ok(())
    })
    .unwrap()
}

const B_PUBLIC: &str = "203.0.113.2";

fn peer_addr(items: &[String], s: u8) -> Address {
    Address { url: peer_url(items), key: InProcess::public_key(&secret(s)) }
}

// spec/sync.md §10: a dial with no route fails, whoever listens with the key: an empty URL, an
// address the dialer cannot reach (another NAT's inside), a relay the target is not at.
#[test]
fn peer_no_route_fails_spec_sync_10() {
    let mut w = world(61, anyone());
    let b = multi(host(&w.net, "b", "10.0.0.2", B_PUBLIC, Some(Nat::SYMMETRIC)));
    let lb = listen_at(&mut w, b, "peer://10.0.0.2:7000".into(), 2);
    let a = multi(host(&w.net, "a", "10.9.0.2", "203.0.113.1", Some(Nat::CONE)));
    for items in [vec![], vec!["10.0.0.2:7000".to_owned()], vec![w.relay.item()]] {
        let (a2, addr) = (a.clone(), peer_addr(&items, 2));
        let r = w.sched.block_on(async move { a2.dial(&addr).await.map(drop) }).unwrap();
        assert!(matches!(r, Err(Error::Unreachable(_))), "{items:?}: {r:?}");
    }
    drop(lb);
}

// spec/sync.md §10: a direct item the dialer can reach connects, the target's key proven.
#[test]
fn peer_direct_item_connects_spec_sync_10() {
    let mut w = world(62, anyone());
    let b = multi(host(&w.net, "b", B_PUBLIC, B_PUBLIC, None));
    let lb = listen_at(&mut w, b, format!("peer://{B_PUBLIC}:7000"), 2);
    let a = multi(host(&w.net, "a", "10.9.0.2", "203.0.113.1", Some(Nat::CONE)));
    dial_route(&mut w, a, peer_addr(&[format!("{B_PUBLIC}:7000")], 2), lb).unwrap();
}

// spec/sync.md §10: a relay the target registered at connects, with no direct item.
#[test]
fn peer_relay_connects_spec_sync_10() {
    let mut w = world(63, anyone());
    let b = multi(host(&w.net, "b", "10.0.0.2", B_PUBLIC, Some(Nat::SYMMETRIC)));
    let item = w.relay.item();
    let lb = listen_at(&mut w, b, format!("peer://10.0.0.2:7000 {item}"), 2);
    let a = multi(host(&w.net, "a", "10.9.0.2", "203.0.113.1", Some(Nat::SYMMETRIC)));
    dial_route(&mut w, a, peer_addr(&[item], 2), lb).unwrap();
}

// spec/sync.md §10: two hosts behind one NAT reach each other at their LAN addresses; a host
// behind another NAT does not.
#[test]
fn peer_lan_address_connects_spec_sync_10() {
    let mut w = world(64, anyone());
    let b = multi(host(&w.net, "b", "10.0.0.2", B_PUBLIC, Some(Nat::SYMMETRIC)));
    let lb = listen_at(&mut w, b, "peer://10.0.0.2:7000".into(), 2);
    let a = multi(w.net.udp("a", ip("10.0.0.3"), Some(ip(B_PUBLIC))));
    dial_route(&mut w, a, peer_addr(&["10.0.0.2:7000".to_owned()], 2), lb).unwrap();
}

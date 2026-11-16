//! The in-process net (`Net`, `MemUdp`) under `Sched`: the connection contract
//! (spec/sync-transport.md §1) without tokio or sleeps, and `listen_all` over it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_base::{Classified, ErrorClass};
use osis_transport::p2p::{Alpn, Sock, Udp};
use osis_transport::*;
use std::net::SocketAddr;

fn secret(b: u8) -> StaticSecret {
    StaticSecret::from_bytes([b; 32])
}

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A net under a scheduler, a socket accepting at `192.0.2.1:7000` (secret 7) and a host to dial from.
fn setup() -> (Net, Sched, MemSock, MemSock) {
    let net = Net::new(0);
    let s = Sched::new(0, Some(net.clone()));
    let l = net.udp(sa("192.0.2.1:0").ip(), None).bind(sa("192.0.2.1:7000"), Some(&secret(7))).unwrap();
    let d = net.udp(sa("192.0.2.2:0").ip(), None).bind(sa("192.0.2.2:0"), None).unwrap();
    (net, s, l, d)
}

const AT: &str = "192.0.2.1:7000";

async fn read_to_end<R: RecvStream>(r: &mut R) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
    }
}

// spec/sync-transport.md §1: ordered bidirectional streams; the dialer checks the listener's key
// and presents a fresh ephemeral key per connection.
#[test]
fn round_trip_and_keys() {
    let (_net, mut s, l, d) = setup();
    let key = secret(7).public_key();
    let mut bad = key;
    bad[0] ^= 1;
    let out = s
        .block_on(async move {
            assert_eq!(d.dial(sa(AT), bad, None, Alpn::Osis).await.map(|_| ()), Err(Error::KeyMismatch));
            let (c1, _) = d.dial(sa(AT), key, None, Alpn::Osis).await.unwrap();
            let (c2, _) = d.dial(sa(AT), key, None, Alpn::Osis).await.unwrap();
            assert_eq!(c1.peer_key(), key);
            let (s1, _, _) = l.accept().await.unwrap();
            let (s2, _, _) = l.accept().await.unwrap();
            assert_ne!(s1.peer_key(), s2.peer_key());
            assert_ne!(s1.peer_key(), key);
            let (mut tx, mut rx) = c1.open_stream().await.unwrap();
            for part in [&b"hel"[..], b"lo"] {
                tx.write_all(part).await.unwrap();
            }
            tx.finish().await.unwrap();
            let (mut tx2, mut rx2) = s1.accept_stream().await.unwrap();
            let got = read_to_end(&mut rx2).await.unwrap();
            tx2.write_all(&got).await.unwrap();
            tx2.finish().await.unwrap();
            drop(c2);
            read_to_end(&mut rx).await.unwrap()
        })
        .unwrap();
    assert_eq!(out, b"hello");
    assert_eq!(Error::KeyMismatch.class(), ErrorClass::BadInput);
}

// spec/sync-transport.md §1: a reset connection fails pending and later operations on both
// sides; dropping a side's last handle resets it; nothing stays behind.
#[test]
fn close_resets_both_sides() {
    let (net, mut s, l, d) = setup();
    let key = secret(7).public_key();
    let (c, a) = s.block_on(async move { (d.dial(sa(AT), key, None, Alpn::Osis).await.unwrap().0, l.accept().await.unwrap().0) }).unwrap();
    let (c2, a2) = (c.clone(), a.clone());
    let pending = s.block_on(async move {
        let (mut tx, _rx) = c2.open_stream().await.unwrap();
        tx.write_all(b"x").await.unwrap();
        let (_tx, mut rx) = a2.accept_stream().await.unwrap();
        let mut b = [0u8; 8];
        assert_eq!(rx.read(&mut b).await, Ok(1));
        (tx, rx)
    });
    let (mut tx, mut rx) = pending.unwrap();
    a.close();
    let r = s.block_on(async move { (rx.read(&mut [0u8; 8]).await, tx.write_all(b"y").await) }).unwrap();
    assert_eq!(r, (Err(Error::Closed), Err(Error::Closed)));
    let c2 = c.clone();
    assert!(s.block_on(async move { c2.open_stream().await.map(|_| ()) }).unwrap().is_err());
    assert_eq!(net.connections(), 0);
    // dropping the last handle of a side closes it for the other
    let d = net.udp(sa("192.0.2.4:0").ip(), None).bind(sa("192.0.2.4:0"), None).unwrap();
    drop((c, a));
    let l = net.udp(sa("192.0.2.5:0").ip(), None).bind(sa("192.0.2.5:7000"), Some(&secret(7))).unwrap();
    let (c, a) = s.block_on(async move { (d.dial(sa("192.0.2.5:7000"), key, None, Alpn::Osis).await.unwrap().0, l.accept().await.unwrap().0) }).unwrap();
    assert_eq!(net.connections(), 1);
    drop(c);
    assert_eq!(net.connections(), 0);
    assert!(s.block_on(async move { a.accept_stream().await.map(|_| ()) }).unwrap().is_err());
}

// spec/sync-transport.md §1: closing a socket resets connections it never accepted: the dialer
// sees Closed, no hang.
#[test]
fn socket_close_resets_queued() {
    let (net, mut s, l, d) = setup();
    let key = secret(7).public_key();
    let c = s.block_on(async move { d.dial(sa(AT), key, None, Alpn::Osis).await.unwrap().0 }).unwrap();
    drop(l);
    assert_eq!(s.block_on(async move { c.open_stream().await.map(|_| ()) }).unwrap(), Err(Error::Closed));
    assert_eq!(net.connections(), 0);
}

// spec: none (virtual timers fire by model time, never by wall time)
#[test]
fn virtual_sleep() {
    let net = Net::new(0);
    let mut s = Sched::new(0, Some(net.clone()));
    let n = net.clone();
    assert_eq!(s.block_on(async move {
        n.sleep(5).await;
        n.now()
    }), Some(5));
}

// spec/sync-transport.md §5 (one key; key change): every listener listens under the one key; a
// URL that cannot be listened on is an error naming it, never an `Ok`, and leaves none of the
// others listening; the old listeners handed in keep their sockets under the new key.
#[test]
fn listen_all_is_all_or_none() {
    let net = Net::new(0);
    let mut s = Sched::new(0, Some(net.clone()));
    let host = net.udp(sa("192.0.2.1:0").ip(), None);
    let (p, other) = (P2p::new(host.clone()), P2p::new(net.udp(sa("192.0.2.9:0").ip(), None)));
    let urls: Vec<String> = vec!["peer://192.0.2.1:7001".into(), "peer://192.0.2.1:7002".into()];
    let done = s.block_on(async move {
        let ls = listen_all(&p, Vec::new(), &urls, &secret(1)).await.unwrap();
        assert!(ls.iter().all(|l| l.address().key == secret(1).public_key()));
        let taken = host.bind(sa("192.0.2.1:7003"), None).unwrap();
        let more = [urls.clone(), vec!["peer://192.0.2.1:7003".into()]].concat();
        let err = listen_all(&p, ls, &more, &secret(2)).await.err();
        assert!(matches!(&err, Some(Error::Listen(u, _)) if u == "peer://192.0.2.1:7003"), "{err:?}");
        let key2 = secret(2).public_key();
        assert!(other.dial(&Address { url: "peer://192.0.2.1:7001".into(), key: key2 }).await.is_err(), "none left listening");
        drop(taken);
        let ls = listen_all(&p, Vec::new(), &more, &secret(2)).await.unwrap();
        assert!(other.dial(&Address { url: "peer://192.0.2.1:7001".into(), key: key2 }).await.is_ok());
        assert!(matches!(other.dial(&Address { url: "peer://192.0.2.1:7002".into(), key: secret(1).public_key() }).await, Err(Error::KeyMismatch)), "nothing under the old key");
        ls.len()
    });
    assert_eq!(done, Some(3));
}

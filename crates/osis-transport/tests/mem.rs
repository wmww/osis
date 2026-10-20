//! InProcess transport and Sched: the trait contract (spec/sync.md §10) without tokio or sleeps.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_core::{Classified, ErrorClass};
use osis_transport::*;
use std::cell::RefCell;
use std::rc::Rc;

fn secret(b: u8) -> StaticSecret {
    StaticSecret::from_bytes([b; 32])
}

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

/// Echo server: for each connection, each stream: read to end, write it back, finish.
fn echo_server(sp: &Spawner, mut l: MemListener) {
    let sp2 = sp.clone();
    sp.spawn(async move {
        while let Ok(c) = l.accept().await {
            let sp3 = sp2.clone();
            sp2.spawn(async move {
                while let Ok((mut tx, mut rx)) = c.accept_stream().await {
                    sp3.spawn(async move {
                        if let Ok(d) = read_to_end(&mut rx).await {
                            let _ = tx.write_all(&d).await;
                            let _ = tx.finish().await;
                        }
                    });
                }
            });
        }
    });
}

async fn mk_listener(net: Net, name: &'static str, s: u8) -> MemListener {
    net.endpoint(name).listen(ListenConfig { url: format!("mem://{name}"), secret: secret(s) }).await.unwrap()
}

async fn echo(c: &MemConn, data: &[u8]) -> Vec<u8> {
    let (mut tx, mut rx) = c.open_stream().await.unwrap();
    tx.write_all(data).await.unwrap();
    tx.finish().await.unwrap();
    read_to_end(&mut rx).await.unwrap()
}

// spec/sync.md §10: ordered bidirectional byte stream; the client checks the server key; ephemeral client keys.
#[test]
fn round_trip_and_keys() {
    let net = Net::new(1);
    let mut s = Sched::new(1, Some(net.clone()));
    let l = s.block_on(mk_listener(net.clone(), "srv", 7)).unwrap();
    let addr = l.address();
    assert_eq!(addr.key, InProcess::public_key(&secret(7)));
    echo_server(&s.spawner(), l);
    let cli = net.endpoint("cli");
    let out = s
        .block_on(async move {
            let c1 = cli.dial(&addr).await.unwrap();
            let c2 = cli.dial(&addr).await.unwrap();
            assert_eq!(c1.peer_key(), addr.key);
            let a = echo(&c1, b"hello").await;
            let b = echo(&c2, b"world").await;
            (a, b)
        })
        .unwrap();
    assert_eq!(out, (b"hello".to_vec(), b"world".to_vec()));
}

// spec/sync.md §10: each connection gets a fresh ephemeral client key, seen as the server's peer key.
#[test]
fn ephemeral_client_keys_differ() {
    let net = Net::new(2);
    let mut s = Sched::new(2, Some(net.clone()));
    let mut l = s.block_on(mk_listener(net.clone(), "srv", 7)).unwrap();
    let addr = l.address();
    let cli = net.endpoint("cli");
    let keys = s
        .block_on(async move {
            let _c1 = cli.dial(&addr).await.unwrap();
            let _c2 = cli.dial(&addr).await.unwrap();
            let s1 = l.accept().await.unwrap();
            let s2 = l.accept().await.unwrap();
            (s1.peer_key(), s2.peer_key(), addr.key)
        })
        .unwrap();
    assert_ne!(keys.0, keys.1);
    assert_ne!(keys.0, keys.2);
}

// spec/sync.md §10: a client MUST check the server's key against the address.
// spec/sync.md §10 (server key check)
#[test]
fn pinned_key_mismatch_refused() {
    let net = Net::new(3);
    let mut s = Sched::new(3, Some(net.clone()));
    let l = s.block_on(mk_listener(net.clone(), "srv", 7)).unwrap();
    let mut addr = l.address();
    addr.key[0] ^= 1;
    let cli = net.endpoint("cli");
    let r = s.block_on(async move { cli.dial(&addr).await.map(|_| ()) }).unwrap();
    assert_eq!(r, Err(Error::KeyMismatch));
    assert_eq!(Error::KeyMismatch.class(), ErrorClass::BadInput);
    assert_eq!(net.connections(), 0);
}

// spec: none (URL scheme dispatch; an unknown scheme parks, notes/architecture.md §3)
#[test]
fn unknown_scheme_and_unreachable() {
    let net = Net::new(4);
    let mut s = Sched::new(4, Some(net.clone()));
    let cli = net.endpoint("cli");
    let r = s
        .block_on(async move {
            let a = cli.dial(&Address { url: "carrier-pigeon://x".into(), key: [0; 32] }).await.map(|_| ());
            let b = cli.dial(&Address { url: "mem://nobody".into(), key: [0; 32] }).await.map(|_| ());
            (a, b)
        })
        .unwrap();
    assert_eq!(r.0, Err(Error::UnknownScheme("carrier-pigeon".into())));
    assert_eq!(r.0.unwrap_err().class(), ErrorClass::Parked);
    assert!(matches!(r.1, Err(Error::Unreachable(_))));
}

// spec/sync.md §10: a partition holds data and refuses dials; after healing the stream completes intact.
#[test]
fn partition_heals() {
    let net = Net::new(5);
    let mut s = Sched::new(5, Some(net.clone()));
    let l = s.block_on(mk_listener(net.clone(), "srv", 7)).unwrap();
    let addr = l.address();
    echo_server(&s.spawner(), l);
    let cli = net.endpoint("cli");
    let (c1, a1) = (cli.clone(), addr.clone());
    let c = s.block_on(async move { c1.dial(&a1).await.unwrap() }).unwrap();
    net.partition("cli", "srv");
    let a2 = addr.clone();
    let refused = s.block_on(async move { cli.dial(&a2).await.map(|_| ()) }).unwrap();
    assert!(matches!(refused, Err(Error::Unreachable(_))));
    let got = Rc::new(RefCell::new(None));
    let g = got.clone();
    s.spawn(async move {
        *g.borrow_mut() = Some(echo(&c, b"through the cut").await);
    });
    assert!(s.run() > 0);
    assert!(got.borrow().is_none());
    net.heal("cli", "srv");
    s.run();
    assert_eq!(got.borrow().as_deref(), Some(&b"through the cut"[..]));
}

// spec/sync.md §10: a reset connection fails pending and later operations on both sides.
#[test]
fn disconnect_resets() {
    let net = Net::new(6);
    let mut s = Sched::new(6, Some(net.clone()));
    let mut l = s.block_on(mk_listener(net.clone(), "srv", 7)).unwrap();
    let addr = l.address();
    let cli = net.endpoint("cli");
    let res = Rc::new(RefCell::new(Vec::new()));
    let r1 = res.clone();
    s.spawn(async move {
        let c = l.accept().await.unwrap();
        let (_tx, mut rx) = c.accept_stream().await.unwrap();
        let mut b = [0u8; 8];
        let a = rx.read(&mut b).await;
        r1.borrow_mut().push(a);
        let a = rx.read(&mut b).await;
        r1.borrow_mut().push(a);
        let a = c.accept_stream().await.map(|_| 1);
        r1.borrow_mut().push(a);
    });
    let n2 = net.clone();
    let c = s
        .block_on(async move {
            let c = cli.dial(&addr).await.unwrap();
            let (mut tx, _rx) = c.open_stream().await.unwrap();
            tx.write_all(b"x").await.unwrap();
            n2.sleep(1).await;
            (c, tx)
        })
        .unwrap();
    net.disconnect("srv", "cli");
    s.run();
    assert_eq!(*res.borrow(), vec![Ok(1), Err(Error::Closed), Err(Error::Closed)]);
    let (c, mut tx) = c;
    let w = s.block_on(async move { tx.write_all(b"y").await }).unwrap();
    assert_eq!(w, Err(Error::Closed));
    assert!(s.block_on(async move { c.open_stream().await.map(|_| ()) }).unwrap().is_err());
    assert_eq!(net.connections(), 0);
}

// spec: none (dropping the last handle of a side closes the connection)
#[test]
fn drop_closes() {
    let net = Net::new(7);
    let mut s = Sched::new(7, Some(net.clone()));
    let mut l = s.block_on(mk_listener(net.clone(), "srv", 7)).unwrap();
    let addr = l.address();
    let cli = net.endpoint("cli");
    let c = s.block_on(async move { cli.dial(&addr).await.unwrap() }).unwrap();
    let sc = s.block_on(async move { l.accept().await.unwrap() }).unwrap();
    assert_eq!(net.connections(), 1);
    drop(c);
    assert_eq!(net.connections(), 0);
    assert!(s.block_on(async move { sc.accept_stream().await.map(|_| ()) }).unwrap().is_err());
}

/// Runs a faulty-network scenario; returns the delivery log (virtual step, client, bytes so far).
fn scenario(seed: u64) -> Vec<(u64, usize, usize)> {
    let net = Net::new(seed);
    net.set_faults(Faults { latency: 2, jitter: 5, bandwidth: Some(1000) });
    let mut s = Sched::new(seed, Some(net.clone()));
    let l = s.block_on(mk_listener(net.clone(), "srv", 7)).unwrap();
    let addr = l.address();
    echo_server(&s.spawner(), l);
    let log = Rc::new(RefCell::new(Vec::new()));
    for i in 0..3usize {
        let (cli, addr, log, net) = (net.endpoint(&format!("c{i}")), addr.clone(), log.clone(), net.clone());
        s.spawn(async move {
            let c = cli.dial(&addr).await.unwrap();
            let data: Vec<u8> = (0..5000u32).map(|k| (k as usize * 7 + i) as u8).collect();
            let (mut tx, mut rx) = c.open_stream().await.unwrap();
            for part in data.chunks(700) {
                tx.write_all(part).await.unwrap();
            }
            tx.finish().await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = rx.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                log.borrow_mut().push((net.now(), i, got.len()));
            }
            assert_eq!(got, data);
        });
    }
    assert_eq!(s.run(), 1); // the echo accept loop stays blocked
    log.take()
}

// spec/sync.md §10: ordered streams under latency, jitter and a bandwidth cap; same seed, same run.
#[test]
fn deterministic_under_seed() {
    let a = scenario(42);
    assert_eq!(a.iter().filter(|e| e.2 == 5000).count(), 3);
    assert!(a.last().unwrap().0 >= 10, "bandwidth cap spreads delivery over steps");
    assert_eq!(a, scenario(42));
    assert_ne!(a, scenario(43));
}

// spec/sync.md §10: a large transfer arrives intact and in order through a capped link.
#[test]
fn large_transfer_capped() {
    let net = Net::new(8);
    net.set_faults(Faults { latency: 1, jitter: 0, bandwidth: Some(64 * 1024) });
    let mut s = Sched::new(8, Some(net.clone()));
    let l = s.block_on(mk_listener(net.clone(), "srv", 7)).unwrap();
    let addr = l.address();
    echo_server(&s.spawner(), l);
    let cli = net.endpoint("cli");
    let data: Vec<u8> = (0..(4u32 << 20)).map(|k| (k ^ (k >> 11)) as u8).collect();
    let d2 = data.clone();
    let got = s.block_on(async move { echo(&cli.dial(&addr).await.unwrap(), &d2).await }).unwrap();
    assert!(got == data);
    assert!(net.now() >= 128, "two directions of 64 steps each");
}

// spec: none (virtual timers fire by step, never by wall time)
#[test]
fn virtual_sleep() {
    let net = Net::new(9);
    let mut s = Sched::new(9, Some(net.clone()));
    let n = net.clone();
    let at = s.block_on(async move {
        n.sleep(5).await;
        n.now()
    });
    assert_eq!(at, Some(5));
}

// spec/sync.md §10: closing a listener resets connections it never accepted; the dialer sees Closed, no hang.
#[test]
fn listener_close_resets_queued() {
    let net = Net::new(13);
    let mut s = Sched::new(13, Some(net.clone()));
    let l = s.block_on(mk_listener(net.clone(), "srv", 7)).unwrap();
    let addr = l.address();
    let cli = net.endpoint("cli");
    let c = s.block_on(async move { cli.dial(&addr).await.unwrap() }).unwrap();
    drop(l);
    let r = s.block_on(async move { c.open_stream().await.map(|_| ()) }).unwrap();
    assert_eq!(r, Err(Error::Closed));
    assert_eq!(net.connections(), 0);
}

// spec/sync.md §10: a pending read on a queued connection ends when the listener closes.
#[test]
fn listener_close_ends_pending_read() {
    let net = Net::new(15);
    let mut s = Sched::new(15, Some(net.clone()));
    let l = s.block_on(mk_listener(net.clone(), "srv", 7)).unwrap();
    let addr = l.address();
    let cli = net.endpoint("cli");
    let got = Rc::new(RefCell::new(None));
    let g = got.clone();
    s.spawn(async move {
        let c = cli.dial(&addr).await.unwrap();
        let (mut tx, mut rx) = c.open_stream().await.unwrap();
        tx.write_all(b"hello").await.unwrap();
        let mut b = [0u8; 4];
        let r = rx.read(&mut b).await;
        *g.borrow_mut() = Some(r);
    });
    assert_eq!(s.run(), 1);
    drop(l);
    assert_eq!(s.run(), 0);
    assert_eq!(*got.borrow(), Some(Err(Error::Closed)));
}

// spec/sync.md §10: a server dialing a peer server authenticates with its own static key.
#[test]
fn dial_as_presents_static_key() {
    let net = Net::new(14);
    let mut s = Sched::new(14, Some(net.clone()));
    let mut l = s.block_on(mk_listener(net.clone(), "srv", 7)).unwrap();
    let addr = l.address();
    let me = net.endpoint("peer");
    let k = s
        .block_on(async move {
            let _c = me.dial_as(&addr, &secret(9)).await.unwrap();
            l.accept().await.unwrap().peer_key()
        })
        .unwrap();
    assert_eq!(k, InProcess::public_key(&secret(9)));
}

type Log = Vec<(u64, usize, usize)>;

/// Three clients echo through a partition, a heal and a kill; returns the delivery log and outcomes.
fn faulty(seed: u64) -> (Log, Vec<(usize, bool)>) {
    let net = Net::new(seed);
    net.set_faults(Faults { latency: 1, jitter: 4, bandwidth: Some(0) }); // 0 is taken as 1
    let mut s = Sched::new(seed, Some(net.clone()));
    s.set_max_steps(200_000);
    let l = s.block_on(mk_listener(net.clone(), "srv", 7)).unwrap();
    let addr = l.address();
    echo_server(&s.spawner(), l);
    let log = Rc::new(RefCell::new(Vec::new()));
    let ends = Rc::new(RefCell::new(Vec::new()));
    for i in 0..3usize {
        let (cli, addr, log, ends, net) = (net.endpoint(&format!("c{i}")), addr.clone(), log.clone(), ends.clone(), net.clone());
        s.spawn(async move {
            let c = cli.dial(&addr).await.unwrap();
            let (mut tx, mut rx) = c.open_stream().await.unwrap();
            let data = vec![i as u8; 300];
            let r = async {
                tx.write_all(&data).await?;
                tx.finish().await?;
                let mut got = 0;
                let mut buf = [0u8; 64];
                loop {
                    let n = rx.read(&mut buf).await?;
                    if n == 0 {
                        return Ok::<_, Error>(got);
                    }
                    got += n;
                    log.borrow_mut().push((net.now(), i, got));
                }
            }
            .await;
            ends.borrow_mut().push((i, r == Ok(300)));
        });
    }
    let n2 = net.clone();
    s.spawn(async move {
        n2.sleep(5).await;
        n2.partition("c0", "srv");
        n2.sleep(40).await;
        n2.heal("c0", "srv");
        n2.kill("c2");
    });
    s.run();
    assert!(!s.capped());
    (log.take(), ends.take())
}

// spec/sync.md §10: partitions, heals and kills replay identically under one seed; streams never corrupt.
#[test]
fn deterministic_with_partition_heal_kill() {
    let a = faulty(7);
    let mut ends = a.1.clone();
    ends.sort();
    assert_eq!(ends, vec![(0, true), (1, true), (2, false)]);
    assert_eq!(a, faulty(7));
}

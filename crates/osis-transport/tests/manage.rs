//! Connection helpers and a frame-shaped loopback session over InProcess (no tokio, no sleeps).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use osis_transport::*;
use std::cell::RefCell;
use std::rc::Rc;

// spec: none (reconnect policy): delays grow to the cap, jitter stays in [d/2, d], same seed same delays.
#[test]
fn backoff_grows_and_is_seeded() {
    let mut b = Backoff::with(100, 3000, 1);
    let d: Vec<u64> = (0..8).map(|_| b.next_delay_ms()).collect();
    for (i, &x) in d.iter().enumerate() {
        let cap = (100u64 << i).min(3000);
        assert!(x <= cap && x >= cap / 2, "{i}: {x}");
    }
    let mut b2 = Backoff::with(100, 3000, 1);
    assert_eq!(d, (0..8).map(|_| b2.next_delay_ms()).collect::<Vec<_>>());
    b.reset();
    assert!(b.next_delay_ms() <= 100);
}

// spec/sync.md §10: reconnect retries network failures until the server is back.
#[test]
fn connect_retries_until_listening() {
    let net = Net::new(11);
    let mut s = Sched::new(11, Some(net.clone()));
    let secret = StaticSecret::from_bytes([3; 32]);
    let addr = Address { url: "mem://srv".into(), key: InProcess::public_key(&secret) };
    // the server comes up after 50 virtual steps
    let (n2, srv) = (net.clone(), net.endpoint("srv"));
    let keep = Rc::new(RefCell::new(None));
    let k2 = keep.clone();
    s.spawn(async move {
        n2.sleep(50).await;
        *k2.borrow_mut() = Some(srv.listen(ListenConfig { url: "mem://srv".into(), secret }).await.unwrap());
    });
    let (n3, cli) = (net.clone(), net.endpoint("cli"));
    let sleeps = Rc::new(RefCell::new(0u32));
    let sl = sleeps.clone();
    let c = s
        .block_on(async move {
            let mut b = Backoff::with(4, 40, 5);
            // one virtual step per millisecond
            connect(&cli, &addr, &mut b, 100, |ms| {
                *sl.borrow_mut() += 1;
                n3.sleep(ms)
            })
            .await
        })
        .unwrap();
    assert!(c.is_ok());
    assert!(net.now() >= 50);
    assert!(*sleeps.borrow() >= 3);
}

// spec/sync.md §10: a pinned-key mismatch is not retried.
#[test]
fn connect_does_not_retry_key_mismatch() {
    let net = Net::new(12);
    let mut s = Sched::new(12, Some(net.clone()));
    let srv = net.endpoint("srv");
    let l = s
        .block_on(async move { srv.listen(ListenConfig { url: "mem://srv".into(), secret: StaticSecret::from_bytes([3; 32]) }).await.unwrap() })
        .unwrap();
    let mut addr = l.address();
    addr.key[0] ^= 1;
    let cli = net.endpoint("cli");
    let r = s
        .block_on(async move {
            let mut b = Backoff::new(1);
            connect(&cli, &addr, &mut b, 100, |_| async { panic!("retried") }).await.map(|_| ())
        })
        .unwrap();
    assert_eq!(r, Err(Error::KeyMismatch));
    drop(l);
}

// spec/wire.md §11.1: framed requests and replies on one stream, then a graceful close, under
// latency, jitter and a bandwidth cap; nothing lost at the close.
#[test]
fn framed_session_loopback() {
    for seed in 0..4 {
        let net = Net::new(seed);
        net.set_faults(Faults { latency: 1, jitter: 3, bandwidth: Some(2000) });
        let mut s = Sched::new(seed, Some(net.clone()));
        let srv = net.endpoint("srv");
        let mut l = s
            .block_on(async move { srv.listen(ListenConfig { url: "mem://srv".into(), secret: StaticSecret::from_bytes([3; 32]) }).await.unwrap() })
            .unwrap();
        let addr = l.address();
        s.spawn(async move { common::serve(l.accept().await.unwrap()).await });
        let cli = net.endpoint("cli");
        let out = s.block_on(async move { common::client(cli.dial(&addr).await.unwrap(), 23).await }).unwrap();
        assert_eq!(out.len(), 23);
        assert_eq!(s.run(), 0, "server task finished");
        assert_eq!(net.connections(), 0);
    }
}

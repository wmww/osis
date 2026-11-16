//! Redial backoff and a frame-shaped loopback session over the in-process net (no tokio, no sleeps).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use osis_transport::*;

// spec: none (reconnect policy): delays grow to the cap, jitter stays in [d/2, d], same seed same delays.
#[test]
fn backoff_grows_and_is_seeded() {
    let mut b = Backoff::with(100, 3000, 0);
    let d: Vec<u64> = (0..8).map(|_| b.next_delay_ms()).collect();
    for (i, &x) in d.iter().enumerate() {
        let cap = (100u64 << i).min(3000);
        assert!(x <= cap && x >= cap / 2, "{i}: {x}");
    }
    let mut b2 = Backoff::with(100, 3000, 0);
    assert_eq!(d, (0..8).map(|_| b2.next_delay_ms()).collect::<Vec<_>>());
    b.reset();
    assert!(b.next_delay_ms() <= 100);
}

// spec/wire.md §11.1: framed requests and replies on one stream over a `peer://` connection,
// then a graceful close; nothing lost at the close.
#[test]
fn framed_session_loopback() {
    let net = Net::new(0);
    let mut s = Sched::new(0, Some(net.clone()));
    let serving = P2p::new(net.udp("192.0.2.1".parse().unwrap(), None));
    let mut l = s.block_on(async move { serving.listen(ListenConfig { url: "peer://192.0.2.1:7000".into(), secret: StaticSecret::from_bytes([3; 32]) }).await.unwrap() }).unwrap();
    let addr = l.address();
    s.spawn(async move { common::serve(l.accept().await.unwrap()).await });
    let cli = P2p::new(net.udp("192.0.2.2".parse().unwrap(), None));
    let out = s.block_on(async move { common::client(cli.dial(&addr).await.unwrap(), 23).await }).unwrap();
    assert_eq!(out.len(), 23);
    assert_eq!(net.connections(), 0);
}

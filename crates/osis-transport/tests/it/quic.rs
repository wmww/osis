//! QUIC transport on localhost (tier 2: touches the network). spec/sync.md §10.
//! Run: `cargo test -p osis-transport --features quic -- --ignored`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_transport::*;
use std::sync::{Arc, Mutex};

type Keys = Arc<Mutex<Vec<PublicKey>>>;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

async fn read_to_end<R: RecvStream>(r: &mut R) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf).await.unwrap();
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

/// Listens on localhost; echoes every stream; records each connection's peer key.
async fn echo_server(seed: u8) -> (Address, Keys) {
    let cfg = ListenConfig { url: "quic://127.0.0.1:0".into(), secret: StaticSecret::from_bytes([seed; 32]) };
    let mut l = Quic::new().listen(cfg).await.unwrap();
    let addr = l.address();
    let rx = Keys::default();
    let tx = rx.clone();
    tokio::spawn(async move {
        while let Ok(c) = l.accept().await {
            tx.lock().unwrap().push(c.peer_key());
            tokio::spawn(async move {
                while let Ok((mut s, mut r)) = c.accept_stream().await {
                    tokio::spawn(async move {
                        let d = read_to_end(&mut r).await;
                        s.write_all(&d).await.unwrap();
                        s.finish().await.unwrap();
                    });
                }
            });
        }
    });
    (addr, rx)
}

async fn echo(c: &QuicConn, data: &[u8]) -> Vec<u8> {
    let (mut s, mut r) = c.open_stream().await.unwrap();
    s.write_all(data).await.unwrap();
    s.finish().await.unwrap();
    read_to_end(&mut r).await
}

// spec/sync.md §10: pinned server key, ephemeral client key per connection, ordered byte stream.
#[test]
#[ignore]
fn quic_round_trip_keys() {
    rt().block_on(async {
        let (addr, keys) = echo_server(7).await;
        assert_eq!(addr.key, Quic::public_key(&StaticSecret::from_bytes([7; 32])).unwrap());
        let t = Quic::new();
        let c1 = t.dial(&addr).await.unwrap();
        let c2 = t.dial(&addr).await.unwrap();
        assert_eq!(c1.peer_key(), addr.key);
        assert_eq!(echo(&c1, b"hello").await, b"hello");
        assert_eq!(echo(&c2, b"world").await, b"world");
        let ks = keys.lock().unwrap().clone();
        let (k1, k2) = (ks[0], ks[1]);
        assert_ne!(k1, k2);
        assert_ne!(k1, addr.key);
    });
}

// spec/sync.md §10: a client MUST check the server's key against the address.
// spec/sync.md §10 (server key check)
#[test]
#[ignore]
fn quic_pinned_key_mismatch_refused() {
    rt().block_on(async {
        let (mut addr, _keys) = echo_server(8).await;
        addr.key[5] ^= 0x40;
        let r = Quic::new().dial(&addr).await.map(|_| ());
        assert_eq!(r, Err(Error::KeyMismatch));
    });
}

// spec/sync.md §10: a large stream transfer arrives intact and in order.
#[test]
#[ignore]
fn quic_large_transfer() {
    rt().block_on(async {
        let (addr, _keys) = echo_server(9).await;
        let c = Quic::new().dial(&addr).await.unwrap();
        let data: Vec<u8> = (0..(16u32 << 20)).map(|k| (k ^ (k >> 13)) as u8).collect();
        assert!(echo(&c, &data).await == data);
    });
}

// spec: none (URL dispatch: other schemes are not this transport's)
#[test]
fn quic_unknown_scheme() {
    rt().block_on(async {
        let r = Quic::new().dial(&Address { url: "mem://x".into(), key: [0; 32] }).await.map(|_| ());
        assert_eq!(r, Err(Error::UnknownScheme("mem".into())));
    });
}

use crate::common;

// spec/wire.md §11.1: framed requests and replies on one stream, graceful close, over QUIC.
#[test]
#[ignore]
fn quic_framed_session() {
    rt().block_on(async {
        let cfg = ListenConfig { url: "quic://127.0.0.1:0".into(), secret: StaticSecret::from_bytes([4; 32]) };
        let mut l = Quic::new().listen(cfg).await.unwrap();
        let addr = l.address();
        let srv = tokio::spawn(async move { common::serve(l.accept().await.unwrap()).await });
        let out = common::client(Quic::new().dial(&addr).await.unwrap(), 23).await;
        assert_eq!(out.len(), 23);
        srv.await.unwrap();
    });
}

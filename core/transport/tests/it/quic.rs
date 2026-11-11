//! QUIC transport on localhost (by hand: touches the network). spec/sync.md §10.
//! Run: `cargo test -p osis-transport --test it -- --ignored quic::`.
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
async fn echo_listener(seed: u8) -> (Address, Keys) {
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

// spec/sync.md §10: pinned host key, ephemeral client key per connection, ordered byte stream.
#[test]
#[ignore]
fn quic_round_trip_keys() {
    rt().block_on(async {
        let (addr, keys) = echo_listener(7).await;
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

// spec/sync.md §10: a client MUST check the host's key against the address.
// spec/sync.md §10 (host key check)
#[test]
#[ignore]
fn quic_pinned_key_mismatch_refused() {
    rt().block_on(async {
        let (mut addr, _keys) = echo_listener(8).await;
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
        let (addr, _keys) = echo_listener(9).await;
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
        let serving = tokio::spawn(async move { common::serve(l.accept().await.unwrap()).await });
        let out = common::client(Quic::new().dial(&addr).await.unwrap(), 23).await;
        assert_eq!(out.len(), 23);
        serving.await.unwrap();
    });
}

// spec/sync.md §10 (Served connections; by hand: loopback QUIC): what a dialer sends on sessions
// the listener's consumer does not read stays in one connection window there
// (`quic::CONN_WINDOW`, shared by the streams; links read only as asked), so a served connection
// holds at most `link::CONN_MEMORY`; read again, the rest goes through
#[test]
#[ignore]
fn quic_unread_sessions_hold_one_window_spec_sync_10() {
    const STREAMS: usize = 4;
    const PIECE: usize = 4096;
    rt().block_on(async {
        let cfg = ListenConfig { url: "quic://127.0.0.1:0".into(), secret: StaticSecret::from_bytes([5; 32]) };
        let l = Quic::new().listen(cfg).await.unwrap();
        let addr = l.address();
        let (out, mut incoming) = tokio::sync::mpsc::channel(STREAMS);
        let w = std::time::Duration::from_secs(30);
        tokio::spawn(link::serve(l, w, w, out));
        let c = Quic::new().dial(&addr).await.unwrap();
        let written = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut writers = Vec::new();
        for _ in 0..STREAMS {
            let (mut tx, rx) = c.open_stream().await.unwrap();
            let wr = written.clone();
            writers.push(tokio::spawn(async move {
                let _rx = rx;
                while tx.write_all(&[7; PIECE]).await.is_ok() {
                    wr.fetch_add(PIECE, std::sync::atomic::Ordering::Relaxed);
                }
            }));
        }
        // until nothing moves for half a second
        let settle = || async {
            let (mut last, mut still) = (usize::MAX, 0);
            while still < 5 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                let n = written.load(std::sync::atomic::Ordering::Relaxed);
                still = if n == last { still + 1 } else { 0 };
                last = n;
            }
            last
        };
        let held = settle().await;
        let window = quic::CONN_WINDOW as usize;
        assert!(held >= window / 2, "flow stopped early: {held}");
        assert!(held <= window + STREAMS * PIECE, "{held} sent into a window of {window}");
        assert!(window + quic::MAX_STREAMS as usize * link::READ_CHUNK <= link::CONN_MEMORY);
        // read again: the rest moves
        for _ in 0..STREAMS {
            let mut s = incoming.recv().await.unwrap();
            tokio::spawn(async move { while s.rx.recv().await.is_some() {} });
        }
        while written.load(std::sync::atomic::Ordering::Relaxed) < held + 4 * window {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        for t in writers {
            t.abort();
        }
    });
}

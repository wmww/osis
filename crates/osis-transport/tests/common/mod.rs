//! Frame-shaped sessions shared by the InProcess and QUIC loopback tests: a stand-in for proto
//! engines (4-byte big-endian length frames, spec/wire.md §11.1) until osis-proto lands.
#![allow(dead_code)]

use osis_transport::*;

pub fn frame(body: &[u8]) -> Vec<u8> {
    let mut f = (body.len() as u32).to_be_bytes().to_vec();
    f.extend_from_slice(body);
    f
}

/// Splits complete frames off `buf`.
pub fn take_frames(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let n = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        if buf.len() < 4 + n {
            break;
        }
        out.push(buf[4..4 + n].to_vec());
        buf.drain(..4 + n);
    }
    out
}

/// Server side: answers each request frame with its body reversed, until the client finishes.
pub async fn serve<C: Connection>(c: C) {
    let (mut tx, mut rx) = c.accept_stream().await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1000];
    loop {
        let n = rx.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        for f in take_frames(&mut buf) {
            let r: Vec<u8> = f.iter().rev().copied().collect();
            tx.write_all(&frame(&r)).await.unwrap();
        }
    }
    assert!(buf.is_empty());
    tx.finish().await.unwrap();
    // the dialer closes; dropping first could cut its read of our tail
    assert!(c.accept_stream().await.is_err());
}

/// Client side: sends `n` requests in bursts, reads the replies, closes gracefully. Returns replies.
pub async fn client<C: Connection>(c: C, n: usize) -> Vec<Vec<u8>> {
    let (mut tx, mut rx) = c.open_stream().await.unwrap();
    let reqs: Vec<Vec<u8>> = (0..n).map(|i| (0..(i * 37 % 3000)).map(|k| (k + i) as u8).collect()).collect();
    let mut out = Vec::new();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 777];
    for burst in reqs.chunks(5) {
        for r in burst {
            tx.write_all(&frame(r)).await.unwrap();
        }
        let want = out.len() + burst.len();
        while out.len() < want {
            let k = rx.read(&mut chunk).await.unwrap();
            assert!(k > 0);
            buf.extend_from_slice(&chunk[..k]);
            out.extend(take_frames(&mut buf));
        }
    }
    close_gracefully(&c, &mut tx, &mut rx, |b| buf.extend_from_slice(b)).await.unwrap();
    assert!(buf.is_empty());
    for (q, a) in reqs.iter().zip(&out) {
        assert!(q.iter().rev().eq(a.iter()));
    }
    out
}

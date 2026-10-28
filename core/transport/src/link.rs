//! Sessions over any `Transport` for tokio drivers: a `Link` is one stream's two
//! directions as channel ends, with pump tasks between them and the stream. The dialer opens one
//! stream per session and closes the connection when the session ends; the accepting side takes
//! every stream the dialer opens as a session (spec/sync.md §10), finishes its side when a session
//! ends, and closes only once the dialer closed or the connection sat idle without sessions.

use crate::{Address, Connection, Error, Listener, PublicKey, RecvStream, SendStream, StaticSecret, Transport};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Largest piece the reader pump hands over.
const READ_CHUNK: usize = 64 * 1024;
/// Pieces read ahead of the consumer; past that the transport's flow control holds the peer.
const READ_AHEAD: usize = 16;

/// The sending end of a link. Dropping it ends our side of the stream (after what is queued).
#[derive(Debug)]
pub struct LinkTx {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    queued: Arc<AtomicUsize>,
}

impl LinkTx {
    /// Queues `bytes` unless more than `cap` bytes would then wait unwritten (one run always fits
    /// an empty queue) or the stream is gone; false when refused.
    #[must_use]
    pub fn send(&self, bytes: Vec<u8>, cap: usize) -> bool {
        let n = bytes.len();
        let q = self.queued.load(Ordering::Acquire);
        if q > 0 && q.saturating_add(n) > cap {
            return false;
        }
        self.queued.fetch_add(n, Ordering::AcqRel);
        self.tx.send(bytes).is_ok()
    }

    /// Bytes queued and not yet taken by the transport.
    pub fn queued(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }
}

/// The receiving end of a link: `None` once the peer finished or the stream failed.
#[derive(Debug)]
pub struct LinkRx(mpsc::Receiver<Vec<u8>>);

impl LinkRx {
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.0.recv().await
    }

    /// A piece already read, if any.
    pub fn try_recv(&mut self) -> Option<Vec<u8>> {
        self.0.try_recv().ok()
    }
}

/// One session: the peer's authenticated static key (spec/wire.md §11.1) and its byte stream.
#[derive(Debug)]
pub struct Link {
    pub peer_key: PublicKey,
    pub tx: LinkTx,
    pub rx: LinkRx,
}

/// Counts a connection's live sessions; decrements on drop.
struct Live(Arc<AtomicUsize>);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Spawns the pumps of one stream. `closer`: the connection to close once our side is finished
/// (the dialer's role). `wait` bounds the finish.
fn session<C: Connection>(peer_key: PublicKey, mut send: C::Send, mut recv: C::Recv, closer: Option<C>, live: Option<Live>, wait: Duration) -> Link {
    let (tx, mut wrx) = mpsc::unbounded_channel::<Vec<u8>>();
    let queued = Arc::new(AtomicUsize::new(0));
    let q = queued.clone();
    tokio::spawn(async move {
        while let Some(b) = wrx.recv().await {
            let r = send.write_all(&b).await;
            q.fetch_sub(b.len(), Ordering::AcqRel);
            if r.is_err() {
                break;
            }
        }
        drop(wrx);
        let _ = timeout(wait, send.finish()).await;
        if let Some(c) = closer {
            c.close();
        }
        drop(live);
    });
    let (rtx, rrx) = mpsc::channel(READ_AHEAD);
    tokio::spawn(async move {
        let mut buf = vec![0u8; READ_CHUNK];
        while let Ok(n) = recv.read(&mut buf).await {
            match buf.get(..n) {
                Some([]) | None => break,
                Some(b) => {
                    if rtx.send(b.to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    Link { peer_key, tx: LinkTx { tx, queued }, rx: LinkRx(rrx) }
}

/// Dials `addr` (as `secret`'s static key if given, else with an ephemeral key) and opens one
/// session on it. The connection closes when the session ends.
pub async fn dial<T: Transport>(t: &T, addr: &Address, secret: Option<&StaticSecret>, wait: Duration) -> Result<Link, Error> {
    let c = match secret {
        Some(s) => t.dial_as(addr, s).await?,
        None => t.dial(addr).await?,
    };
    let (send, recv) = c.open_stream().await?;
    Ok(session(c.peer_key(), send, recv, Some(c), None, wait))
}

/// Accepts connections on `l` and hands each stream they open to `out` as a session, until
/// `out` or the listener closes. A connection with no live session for `idle` is closed.
pub async fn serve<L: Listener>(l: L, idle: Duration, wait: Duration, out: mpsc::Sender<Link>) {
    serve_max(l, idle, wait, out, usize::MAX).await
}

/// `serve` with at most `max` connections open at once; more are closed on arrival.
pub async fn serve_max<L: Listener>(mut l: L, idle: Duration, wait: Duration, out: mpsc::Sender<Link>, max: usize) {
    let open = Arc::new(AtomicUsize::new(0));
    while let Ok(c) = l.accept().await {
        if out.is_closed() {
            break;
        }
        if open.load(Ordering::Acquire) >= max {
            c.close();
            continue;
        }
        open.fetch_add(1, Ordering::AcqRel);
        let held = Live(open.clone());
        let out = out.clone();
        tokio::spawn(async move {
            let _held = held;
            let live = Arc::new(AtomicUsize::new(0));
            loop {
                match timeout(idle, c.accept_stream()).await {
                    Ok(Ok((send, recv))) => {
                        live.fetch_add(1, Ordering::AcqRel);
                        let link = session::<L::Conn>(c.peer_key(), send, recv, None, Some(Live(live.clone())), wait);
                        if out.send(link).await.is_err() {
                            break;
                        }
                    }
                    Ok(Err(_)) => break,
                    Err(_) if live.load(Ordering::Acquire) == 0 => break,
                    Err(_) => {}
                }
            }
            c.close();
        });
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{InProcess, ListenConfig, Net};

    const W: Duration = Duration::from_secs(5);

    // spec/sync.md §10, spec/wire.md §11.1: a session per dialer stream, peer keys as the transport authenticated them, bytes in order both ways, the end of one side ends the other's link
    #[tokio::test]
    async fn session_round_trip_and_end() {
        let net = Net::new(1);
        let l = net.endpoint("s").listen(ListenConfig { url: "mem://s".into(), secret: StaticSecret::from_bytes([1; 32]) }).await.unwrap();
        let addr = l.address();
        let (out, mut incoming) = mpsc::channel(4);
        tokio::spawn(serve(l, W, W, out));
        let own = StaticSecret::from_bytes([2; 32]);
        let mut a = dial(&net.endpoint("c"), &addr, Some(&own), W).await.unwrap();
        assert_eq!(a.peer_key, addr.key);
        assert!(a.tx.send(b"hi".to_vec(), usize::MAX));
        let mut b = incoming.recv().await.unwrap();
        assert_eq!(b.peer_key, InProcess::public_key(&own));
        assert_eq!(b.rx.recv().await.unwrap(), b"hi");
        assert!(b.tx.send(b"yo".to_vec(), usize::MAX));
        assert_eq!(a.rx.recv().await.unwrap(), b"yo");
        drop(b.tx);
        assert_eq!(a.rx.recv().await, None);
        drop(a.tx);
        assert_eq!(b.rx.recv().await, None);
    }

    // spec: none (driver policy): bytes the transport has not taken count against the cap; one run fits an empty queue
    #[test]
    fn send_cap() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let t = LinkTx { tx, queued: Arc::new(AtomicUsize::new(0)) };
        assert!(t.send(vec![0; 100], 10));
        assert!(!t.send(vec![0; 1], 10));
        assert_eq!(t.queued(), 100);
    }
}

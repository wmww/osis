//! Sessions over any `Transport` for tokio drivers: a `Link` is one stream's two
//! directions as channel ends, with pump tasks between them and the stream. The dialer opens one
//! stream per session and closes the connection when the session ends; the accepting side takes
//! every stream the dialer opens as a session (spec/sync.md §10), finishes its side when a session
//! ends, and closes only once the dialer closed or the connection sat idle without sessions.

use crate::{Address, Connection, Error, Listener, PublicKey, RecvStream, SendStream, Source, StaticSecret, Transport};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Largest piece the reader pump hands over.
const READ_CHUNK: usize = 64 * 1024;
/// Pieces read ahead of the consumer; past that the transport's flow control holds the peer.
const READ_AHEAD: usize = 16;
/// Largest piece the writer pump hands the transport at once: the grain of `LinkTx::taken`
/// (progress a slow link shows, spec/sync.md §6). Minor: smaller costs more awaits, larger
/// shows a link slower than a piece per stall timeout as stalled.
const WRITE_CHUNK: usize = 16 * 1024;

/// The sending end of a link. Dropping it ends our side of the stream (after what is queued).
#[derive(Debug)]
pub struct LinkTx {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    queued: Arc<AtomicUsize>,
    taken: Arc<AtomicU64>,
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

    /// Bytes the transport has taken so far (grows as the link moves our bytes).
    pub fn taken(&self) -> u64 {
        self.taken.load(Ordering::Acquire)
    }
}

/// The receiving end of a link: `None` once the peer finished or the stream failed.
#[derive(Debug)]
pub struct LinkRx(mpsc::Receiver<Vec<u8>>);

impl LinkRx {
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.0.recv().await
    }
}

/// Runs blocking driver work (storage, engine calls) without stalling the runtime:
/// `block_in_place` on a multi-thread runtime, inline otherwise.
pub fn blocking<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
    }
}

/// Forwards a session's bytes into a driver's event channel as `bytes(b)`, then `closed` once
/// the peer finished or the stream failed; stops when the channel is gone.
pub async fn forward<E>(mut rx: LinkRx, ev: mpsc::Sender<E>, bytes: impl Fn(Vec<u8>) -> E, closed: E) {
    while let Some(b) = rx.recv().await {
        if ev.send(bytes(b)).await.is_err() {
            return;
        }
    }
    let _ = ev.send(closed).await;
}

/// One session: the peer's authenticated static key (spec/wire.md §11.1) and its byte stream.
#[derive(Debug)]
pub struct Link {
    pub peer_key: PublicKey,
    /// Where the connection carrying it comes from (`Connection::source`).
    pub source: Option<Source>,
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
fn session<C: Connection>(peer_key: PublicKey, source: Option<Source>, mut send: C::Send, mut recv: C::Recv, closer: Option<C>, live: Option<Live>, wait: Duration) -> Link {
    let (tx, mut wrx) = mpsc::unbounded_channel::<Vec<u8>>();
    let queued = Arc::new(AtomicUsize::new(0));
    let taken = Arc::new(AtomicU64::new(0));
    let (q, t) = (queued.clone(), taken.clone());
    tokio::spawn(async move {
        'pump: while let Some(b) = wrx.recv().await {
            for piece in b.chunks(WRITE_CHUNK) {
                let r = send.write_all(piece).await;
                q.fetch_sub(piece.len(), Ordering::AcqRel);
                if r.is_err() {
                    break 'pump;
                }
                t.fetch_add(piece.len() as u64, Ordering::AcqRel);
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
    Link { peer_key, source, tx: LinkTx { tx, queued, taken }, rx: LinkRx(rrx) }
}

/// Dials `addr` (as `secret`'s static key if given, else with an ephemeral key) and opens one
/// session on it. The connection closes when the session ends.
pub async fn dial<T: Transport>(t: &T, addr: &Address, secret: Option<&StaticSecret>, wait: Duration) -> Result<Link, Error> {
    let c = match secret {
        Some(s) => t.dial_as(addr, s).await?,
        None => t.dial(addr).await?,
    };
    let (send, recv) = c.open_stream().await?;
    Ok(session(c.peer_key(), c.source(), send, recv, Some(c), None, wait))
}

/// The connections `serve` holds open, by arrival, with their sources.
type Open<C> = BTreeMap<u64, (Option<Source>, C)>;

/// Accepts connections on `l` and hands each stream they open to `out` as a session, until
/// `out` or the listener closes. At most `max` connections are open at once, shared fairly by
/// source: when all are taken, a newcomer takes the newest connection of the source holding the
/// most if that source holds at least two more than the newcomer's (`evict_for`), else it is
/// closed on arrival. One with no live session for `idle` is closed.
pub async fn serve<L: Listener>(mut l: L, idle: Duration, wait: Duration, out: mpsc::Sender<Link>, max: usize) {
    let open: Arc<Mutex<Open<L::Conn>>> = Arc::default();
    let mut next = 0u64;
    while let Ok(c) = l.accept().await {
        if out.is_closed() {
            break;
        }
        let id = next;
        next += 1;
        {
            let mut m = open.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if m.len() >= max {
                let mut held = BTreeMap::new();
                for (s, _) in m.values() {
                    *held.entry(*s).or_insert(0usize) += 1;
                }
                let victim = crate::evict_for(&held, &c.source()).and_then(|v| m.iter().rev().find(|(_, (s, _))| *s == v).map(|(k, _)| *k));
                match victim.and_then(|k| m.remove(&k)) {
                    Some((_, old)) => old.close(),
                    None => {
                        c.close();
                        continue;
                    }
                }
            }
            m.insert(id, (c.source(), c.clone()));
        }
        let open = open.clone();
        let out = out.clone();
        tokio::spawn(async move {
            let live = Arc::new(AtomicUsize::new(0));
            loop {
                match timeout(idle, c.accept_stream()).await {
                    Ok(Ok((send, recv))) => {
                        live.fetch_add(1, Ordering::AcqRel);
                        let link = session::<L::Conn>(c.peer_key(), c.source(), send, recv, None, Some(Live(live.clone())), wait);
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
            open.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&id);
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
        tokio::spawn(serve(l, W, W, out, usize::MAX));
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

    // spec: none (server policy): full connection slots are shared by source: a newcomer from
    // another source takes the newest connection of the source holding the most; one from that
    // source is refused
    #[tokio::test]
    async fn full_slots_shared_by_source() {
        let net = Net::new(1);
        let l = net.endpoint("s").listen(ListenConfig { url: "mem://s".into(), secret: StaticSecret::from_bytes([1; 32]) }).await.unwrap();
        let addr = l.address();
        let (out, mut incoming) = mpsc::channel(8);
        tokio::spawn(serve(l, W, W, out, 3));
        let up = |name: &'static str| {
            let (net, addr) = (net.clone(), addr.clone());
            async move {
                let link = dial(&net.endpoint(name), &addr, None, W).await.unwrap();
                assert!(link.tx.send(b"hi".to_vec(), usize::MAX));
                link
            }
        };
        let (mut a, mut served) = (Vec::new(), Vec::new());
        for _ in 0..3 {
            a.push(up("a").await);
            let mut s = timeout(W, incoming.recv()).await.unwrap().unwrap();
            assert_eq!(s.rx.recv().await.unwrap(), b"hi");
            served.push(s);
        }
        let b = up("b").await;
        let mut s = timeout(W, incoming.recv()).await.unwrap().unwrap();
        assert_eq!(s.rx.recv().await.unwrap(), b"hi");
        assert_ne!(s.source, None);
        served.push(s);
        // a's newest connection went for it
        assert_eq!(timeout(W, a[2].rx.recv()).await.unwrap(), None);
        // a now holds 2 against b's 1: another from a is refused
        let mut a4 = up("a").await;
        assert_eq!(timeout(W, a4.rx.recv()).await.unwrap(), None);
        assert!(b.tx.send(b"still".to_vec(), usize::MAX));
    }

    // spec/sync.md §6: `taken` counts what the transport took, piece by piece, for the stall timeout
    #[tokio::test]
    async fn taken_counts_written_bytes() {
        let net = Net::new(1);
        let l = net.endpoint("s").listen(ListenConfig { url: "mem://s".into(), secret: StaticSecret::from_bytes([1; 32]) }).await.unwrap();
        let addr = l.address();
        let (out, mut incoming) = mpsc::channel(4);
        tokio::spawn(serve(l, W, W, out, usize::MAX));
        let a = dial(&net.endpoint("c"), &addr, None, W).await.unwrap();
        let n = 3 * WRITE_CHUNK + 5;
        assert!(a.tx.send(vec![7; n], usize::MAX));
        let mut b = incoming.recv().await.unwrap();
        let mut got = 0;
        while got < n {
            got += b.rx.recv().await.unwrap().len();
        }
        timeout(W, async {
            while a.tx.taken() < n as u64 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(a.tx.taken(), n as u64);
    }

    // spec: none (driver policy): bytes the transport has not taken count against the cap; one run fits an empty queue
    #[test]
    fn send_cap() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let t = LinkTx { tx, queued: Arc::new(AtomicUsize::new(0)), taken: Arc::new(AtomicU64::new(0)) };
        assert!(t.send(vec![0; 100], 10));
        assert!(!t.send(vec![0; 1], 10));
        assert_eq!(t.queued.load(Ordering::Acquire), 100);
    }
}

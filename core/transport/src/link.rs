//! Sessions over any `Transport` for tokio drivers: a `Link` is one stream's two
//! directions as channel ends, with pump tasks between them and the stream. The dialer opens one
//! stream per session and closes the connection when the session ends; the accepting side takes
//! every stream the dialer opens as a session (spec/sync.md §10), finishes its side when a session
//! ends, and closes only once the dialer closed or the connection sat idle without sessions.

use crate::{Address, Connection, Error, Listener, Peer, PublicKey, RecvStream, SendStream, Source, StaticSecret, Transport};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Largest piece the reader pump hands over. A session reads its stream only when its consumer
/// asks (`LinkRx::recv`), so beyond the transport's own window it holds at most this, twice
/// after a cancelled `recv`.
pub const READ_CHUNK: usize = 64 * 1024;
/// The most the transport holds for one served connection in either direction, outside the
/// hub's counts (spec/sync.md §10 Served connections): received, the QUIC connection window
/// (`quic`'s, which a `peer://` direct connection shares) and one read per stream the peer may
/// open; sent, the QUIC send window, as large as the connection window. A relayed connection holds
/// less (its bytes ride its registration's windows, `p2p::RELAY_STREAM_WINDOW` per stream); a
/// unix one, the kernel's socket buffers.
pub const CONN_MEMORY: usize = crate::quic::CONN_WINDOW as usize + crate::quic::MAX_STREAMS as usize * READ_CHUNK;
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

/// The receiving end of a link: `None` once the peer finished or the stream failed. The stream
/// is read only as `recv` asks: what the consumer has not asked for stays in the transport,
/// under its flow-control window.
#[derive(Debug)]
pub struct LinkRx {
    rx: mpsc::Receiver<Vec<u8>>,
    want: Arc<tokio::sync::Notify>,
}

impl LinkRx {
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.want.notify_one();
        self.rx.recv().await
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
    /// The peer as the transport type tells it (`Connection::peer`).
    pub peer: Peer,
    /// Where the connection carrying it comes from (`Connection::source`).
    pub source: Option<Source>,
    /// A relay carries the connection (`Connection::relayed`).
    pub relayed: bool,
    /// Set by the driver while the session shares something (node sync's word: an open, a
    /// member of its shared set, an authenticated client): `serve` then no longer counts the
    /// connection or evicts it. Per connection.
    pub kept: Arc<AtomicBool>,
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
fn session<C: Connection>((peer, peer_key, source, kept): (Peer, PublicKey, Option<Source>, Arc<AtomicBool>), mut send: C::Send, mut recv: C::Recv, closer: Option<C>, live: Option<Live>, wait: Duration) -> Link {
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
    let (rtx, rrx) = mpsc::channel(1);
    let want = Arc::new(tokio::sync::Notify::new());
    let asked = want.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = asked.notified() => {}
                () = rtx.closed() => break,
            }
            // a buffer per read, handed over whole: an idle session holds none
            let mut buf = vec![0u8; READ_CHUNK];
            let Ok(n) = recv.read(&mut buf).await else { break };
            if n == 0 || n > READ_CHUNK {
                break;
            }
            buf.truncate(n);
            if rtx.send(buf).await.is_err() {
                break;
            }
        }
    });
    Link { peer_key, peer, source, relayed: false, kept, tx: LinkTx { tx, queued, taken }, rx: LinkRx { rx: rrx, want } }
}

/// Dials `addr` (as `secret`'s static key if given, else with an ephemeral key) and opens one
/// session on it. The connection closes when the session ends.
pub async fn dial<T: Transport>(t: &T, addr: &Address, secret: Option<&StaticSecret>, wait: Duration) -> Result<Link, Error> {
    let c = match secret {
        Some(s) => t.dial_as(addr, s).await?,
        None => t.dial(addr).await?,
    };
    let (send, recv) = c.open_stream().await?;
    let relayed = c.relayed();
    Ok(Link { relayed, ..session((c.peer(), c.peer_key(), c.source(), Arc::default()), send, recv, Some(c), None, wait) })
}

/// Two ends of one in-process session, no transport between them: `a` sees `b_key` as its
/// peer and `b` sees `a_key`. A node's own sessions to the host it runs go over one.
pub fn pair(a_key: PublicKey, b_key: PublicKey) -> (Link, Link) {
    let (a_tx, b_rx) = pipe();
    let (b_tx, a_rx) = pipe();
    (Link { peer_key: b_key, peer: Peer::Key(b_key), source: None, relayed: false, kept: Arc::default(), tx: a_tx, rx: a_rx }, Link { peer_key: a_key, peer: Peer::Key(a_key), source: None, relayed: false, kept: Arc::default(), tx: b_tx, rx: b_rx })
}

/// One direction of a `pair`: a pump moves what is sent into the receiver's bounded queue,
/// counting it taken. Dropping the sender ends the receiver once the queue is drained.
fn pipe() -> (LinkTx, LinkRx) {
    let (tx, mut wrx) = mpsc::unbounded_channel::<Vec<u8>>();
    let queued = Arc::new(AtomicUsize::new(0));
    let taken = Arc::new(AtomicU64::new(0));
    let (q, t) = (queued.clone(), taken.clone());
    let (rtx, rrx) = mpsc::channel(1);
    tokio::spawn(async move {
        while let Some(b) = wrx.recv().await {
            let n = b.len();
            if rtx.send(b).await.is_err() {
                break;
            }
            q.fetch_sub(n, Ordering::AcqRel);
            t.fetch_add(n as u64, Ordering::AcqRel);
        }
    });
    (LinkTx { tx, queued, taken }, LinkRx { rx: rrx, want: Arc::default() })
}

/// Transport connections served at once, shared by every listener `serve` runs with it: a
/// node's one count over its served connections, so what the transport holds for them
/// (`CONN_MEMORY` each) is bounded by `max` whatever the number of listeners.
pub struct Slots {
    max: AtomicUsize,
    next: AtomicU64,
    /// By arrival: source, whether kept (`Link::kept`), and how to close it.
    open: Mutex<BTreeMap<u64, Slot>>,
}

type Slot = (Option<Source>, Arc<AtomicBool>, Box<dyn Fn() + Send>);

impl Slots {
    pub fn new(max: usize) -> Arc<Slots> {
        Arc::new(Slots { max: AtomicUsize::new(max), next: AtomicU64::new(0), open: Mutex::default() })
    }

    /// Takes effect for the next newcomer.
    pub fn set_max(&self, max: usize) {
        self.max.store(max, Ordering::Release);
    }

    /// Connections held.
    pub fn len(&self) -> usize {
        crate::util::lock(&self.open).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A slot for a newcomer from `source`, making room as `make_room` says (the evicted one
    /// closed); none: refused.
    fn take(&self, source: Option<Source>, kept: Arc<AtomicBool>, close: Box<dyn Fn() + Send>) -> Option<u64> {
        let mut m = crate::util::lock(&self.open);
        match make_room(&m, &source, self.max.load(Ordering::Acquire)) {
            Ok(None) => {}
            Ok(Some(k)) => {
                if let Some((_, _, old)) = m.remove(&k) {
                    old();
                }
            }
            Err(()) => return None,
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        m.insert(id, (source, kept, close));
        Some(id)
    }

    fn free(&self, id: u64) {
        crate::util::lock(&self.open).remove(&id);
    }
}

/// Which connection goes for a newcomer from `new` (`Err`: the newcomer is refused), or
/// `Ok(None)` when there is room. At most `max` connections are held, kept ones (`Link::kept`:
/// sharing something, by the engine's word) counted but never evicted. When all are taken a
/// newcomer takes the newest connection not kept of the source holding the most such if it
/// holds at least two more than the newcomer's (`evict_for`); while every source holds the same,
/// the oldest one not kept: a flood from many sources delays a peer or client by its turn, never
/// shuts it out or touches a kept one. A source already holding the most is refused (it waits
/// for its own connections), as is every newcomer while all held are kept.
fn make_room(open: &BTreeMap<u64, Slot>, new: &Option<Source>, max: usize) -> Result<Option<u64>, ()> {
    if open.len() < max {
        return Ok(None);
    }
    let evictable = |a: &AtomicBool| !a.load(Ordering::Acquire);
    let mut held = BTreeMap::new();
    for (s, a, _) in open.values() {
        if evictable(a) {
            *held.entry(*s).or_insert(0usize) += 1;
        }
    }
    let newest_of = |v: Option<Source>| open.iter().rev().find(|(_, (s, a, _))| *s == v && evictable(a)).map(|(k, _)| *k);
    if let Some(v) = crate::evict_for(&held, new).and_then(newest_of) {
        return Ok(Some(v));
    }
    if held.get(new).copied().unwrap_or(0) == 0 {
        return match open.iter().find(|(_, (_, a, _))| evictable(a)) {
            Some((k, _)) => Ok(Some(*k)),
            None => Err(()),
        };
    }
    Err(())
}

/// Accepts connections on `l` and hands each stream they open to `out` as a session, until
/// `out` or the listener closes. Connections take `slots` (`make_room`). One with no live
/// session for `idle` is closed.
pub async fn serve<L: Listener>(mut l: L, idle: Duration, wait: Duration, out: mpsc::Sender<Link>, slots: Arc<Slots>) {
    while let Ok(c) = l.accept().await {
        if out.is_closed() {
            break;
        }
        let kept = Arc::new(AtomicBool::new(false));
        let closer = c.clone();
        let Some(id) = slots.take(c.source(), kept.clone(), Box::new(move || closer.close())) else {
            c.close();
            continue;
        };
        let slots = slots.clone();
        let out = out.clone();
        tokio::spawn(async move {
            let live = Arc::new(AtomicUsize::new(0));
            loop {
                match timeout(idle, c.accept_stream()).await {
                    Ok(Ok((send, recv))) => {
                        live.fetch_add(1, Ordering::AcqRel);
                        let link = Link { relayed: c.relayed(), ..session::<L::Conn>((c.peer(), c.peer_key(), c.source(), kept.clone()), send, recv, None, Some(Live(live.clone())), wait) };
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
            slots.free(id);
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
        tokio::spawn(serve(l, W, W, out, Slots::new(usize::MAX)));
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

    // spec/sync.md §10: an in-process pair carries bytes in order both ways with each side's key,
    // counts them taken, and ends the other side's link when one sender is dropped
    #[tokio::test]
    async fn pair_round_trip_and_end() {
        let (mut a, mut b) = pair([1; 32], [2; 32]);
        assert_eq!((a.peer_key, b.peer_key), ([2; 32], [1; 32]));
        assert!(a.tx.send(b"one".to_vec(), usize::MAX) && a.tx.send(b"two".to_vec(), usize::MAX));
        assert_eq!(b.rx.recv().await.unwrap(), b"one");
        assert_eq!(b.rx.recv().await.unwrap(), b"two");
        assert!(b.tx.send(b"back".to_vec(), usize::MAX));
        assert_eq!(a.rx.recv().await.unwrap(), b"back");
        assert_eq!(a.tx.taken(), 6);
        drop(a.tx);
        assert_eq!(b.rx.recv().await, None);
    }

    // spec: none (node policy): full connection slots are shared by source: a newcomer from
    // another source takes the newest connection of the source holding the most; one from that
    // source is refused
    #[tokio::test]
    async fn full_slots_shared_by_source() {
        let net = Net::new(1);
        let l = net.endpoint("s").listen(ListenConfig { url: "mem://s".into(), secret: StaticSecret::from_bytes([1; 32]) }).await.unwrap();
        let addr = l.address();
        let (out, mut incoming) = mpsc::channel(8);
        tokio::spawn(serve(l, W, W, out, Slots::new(3)));
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

    // spec/sync.md §10, notes/client-port.md §5: a flood from many sources takes the oldest
    // slot not kept, never refuses a newcomer while one is, and never evicts a kept connection
    // (an authenticated client)
    #[tokio::test]
    async fn a_flood_keeps_a_client_in() {
        let net = Net::new(1);
        let l = net.endpoint("s").listen(ListenConfig { url: "mem://s".into(), secret: StaticSecret::from_bytes([1; 32]) }).await.unwrap();
        let addr = l.address();
        let (out, mut incoming) = mpsc::channel(64);
        tokio::spawn(serve(l, W, W, out, Slots::new(3)));
        let up = |name: String| {
            let (net, addr) = (net.clone(), addr.clone());
            async move {
                let link = dial(&net.endpoint(&name), &addr, None, W).await.unwrap();
                assert!(link.tx.send(b"hi".to_vec(), usize::MAX));
                link
            }
        };
        // a client comes in and authenticates
        let mut client = up("client".into()).await;
        let s = timeout(W, incoming.recv()).await.unwrap().unwrap();
        s.kept.store(true, Ordering::Release);
        // a flood from many sources, one connection each, past the two pending slots
        let mut flood = Vec::new();
        for i in 0..6 {
            flood.push(up(format!("f{i}")).await);
            let mut f = timeout(W, incoming.recv()).await.unwrap().unwrap();
            assert_eq!(f.rx.recv().await.unwrap(), b"hi");
            std::mem::forget(f.tx);
        }
        // the oldest of the flood went, not the newest, and not the client
        assert_eq!(timeout(W, flood[0].rx.recv()).await.unwrap(), None);
        let newest = flood.last_mut().unwrap();
        assert!(timeout(Duration::from_millis(50), newest.rx.recv()).await.is_err());
        assert!(s.tx.send(b"yo".to_vec(), usize::MAX));
        assert_eq!(client.rx.recv().await.unwrap(), b"yo");
        // a late client still gets in while the flood goes on
        let _late = up("late".into()).await;
        let mut t = timeout(W, incoming.recv()).await.unwrap().unwrap();
        assert_eq!(t.rx.recv().await.unwrap(), b"hi");
    }

    // spec/sync.md §10 (Served connections): every listener's connections share one count, kept
    // ones in it: with all slots kept a newcomer on any listener is refused; one freed takes it
    #[tokio::test]
    async fn listeners_share_slots() {
        let net = Net::new(1);
        let slots = Slots::new(2);
        let (out, mut incoming) = mpsc::channel(8);
        let mut addrs = Vec::new();
        for (url, k) in [("mem://s1", 1), ("mem://s2", 2)] {
            let l = net.endpoint(url).listen(ListenConfig { url: url.into(), secret: StaticSecret::from_bytes([k; 32]) }).await.unwrap();
            addrs.push(l.address());
            tokio::spawn(serve(l, W, W, out.clone(), slots.clone()));
        }
        let up = |name: &'static str, at: usize| {
            let (net, addr) = (net.clone(), addrs[at].clone());
            async move {
                let link = dial(&net.endpoint(name), &addr, None, W).await.unwrap();
                assert!(link.tx.send(b"hi".to_vec(), usize::MAX));
                link
            }
        };
        let mut served = Vec::new();
        for (name, at) in [("a", 0), ("b", 1)] {
            let _c = up(name, at).await;
            let s = timeout(W, incoming.recv()).await.unwrap().unwrap();
            s.kept.store(true, Ordering::Release);
            served.push((_c, s));
        }
        assert_eq!(slots.len(), 2);
        let mut c = up("c", 0).await;
        assert_eq!(timeout(W, c.rx.recv()).await.unwrap(), None, "refused: every slot is kept");
        assert_eq!(slots.len(), 2);
        let (a, sa) = served.remove(0);
        drop((a, sa));
        timeout(W, async {
            while slots.len() > 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let _d = up("d", 1).await;
        let mut sd = timeout(W, incoming.recv()).await.unwrap().unwrap();
        assert_eq!(sd.rx.recv().await.unwrap(), b"hi");
    }

    // spec/sync.md §6: `taken` counts what the transport took, piece by piece, for the stall timeout
    #[tokio::test]
    async fn taken_counts_written_bytes() {
        let net = Net::new(1);
        let l = net.endpoint("s").listen(ListenConfig { url: "mem://s".into(), secret: StaticSecret::from_bytes([1; 32]) }).await.unwrap();
        let addr = l.address();
        let (out, mut incoming) = mpsc::channel(4);
        tokio::spawn(serve(l, W, W, out, Slots::new(usize::MAX)));
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

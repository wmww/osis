//! `Net`: the in-process network under the NAT model (`nat`; a test network, spec: none): virtual
//! time (model milliseconds, timers), a seeded rng, and connections as in-memory pipes. Runs under
//! `Sched` (deterministic, no tokio). A write is readable at once; streams never lose or reorder
//! bytes.

use crate::util::{lock, Rng};
use crate::{Connection, Error, PublicKey, RecvStream, SendStream};
use std::collections::{BTreeMap, VecDeque};
use std::future::{poll_fn, Future};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

/// The shared in-process network. Clones share it.
#[derive(Clone)]
pub struct Net(Arc<Mutex<State>>);

pub(crate) struct State {
    now: u64,
    rng: Rng,
    conns: BTreeMap<u64, Conn>,
    timers: BTreeMap<(u64, u64), Waker>,
    next_id: u64,
    /// Hosts, NATs and sockets of the NAT model (`nat`).
    pub(crate) udp: crate::nat::Udp,
    /// Tasks spawned through the net (`Net::spawn`), for `Sched` to take.
    spawned: Vec<Spawned>,
}

/// A task spawned through a `Net`.
pub(crate) type Spawned = std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;

/// Side 0 dialed, side 1 accepted.
struct Conn {
    keys: [PublicKey; 2],
    streams: BTreeMap<u64, Strm>,
    accept: [VecDeque<u64>; 2],
    accept_waker: [Option<Waker>; 2],
    next_stream: u64,
    /// Reset: operations fail; kept until both sides' handles drop.
    closed: bool,
    /// Sides whose last handle dropped (side 1 counts as dropped until accepted); the entry
    /// goes when both have.
    dropped: [bool; 2],
    /// Streams side `i` may have open at once (the other side's grant, as QUIC's
    /// MAX_STREAMS): one counts until its peer accepted it and dropped both its halves.
    limit: [usize; 2],
    /// An `open_stream` of side `i` waiting for room.
    open_waker: [Option<Waker>; 2],
}

struct Strm {
    opener: usize,
    /// `pipes[i]` carries what side `i` writes.
    pipes: [Pipe; 2],
    /// The opener's first write or finish showed the stream to the peer's `accept_stream`.
    announced: bool,
    /// Live halves (`MemSend`, `MemRecv`) per side; the stream goes once the peer accepted it
    /// and every half dropped.
    halves: [u8; 2],
    accepted: bool,
}

#[derive(Default)]
struct Pipe {
    data: VecDeque<u8>,
    /// The writer finished: the reader reads `Ok(0)` after `data`.
    fin: bool,
    waker: Option<Waker>,
}

pub(crate) fn wake(w: &mut Option<Waker>) {
    if let Some(w) = w.take() {
        w.wake();
    }
}

impl Conn {
    /// Drops one half of stream `s` on `side`, and the stream once nothing can use it.
    fn drop_half(&mut self, s: u64, side: usize) {
        let Some(st) = self.streams.get_mut(&s) else { return };
        if let Some(n) = st.halves.get_mut(side) {
            *n = n.saturating_sub(1);
        }
        if st.accepted && st.halves == [0, 0] {
            self.streams.remove(&s);
        }
        for w in &mut self.open_waker {
            wake(w);
        }
    }

    /// Streams side `side` has open against its limit.
    fn open_by(&self, side: usize) -> usize {
        self.streams.values().filter(|s| s.opener == side && !(s.accepted && s.halves.get(1 - side) == Some(&0))).count()
    }

    /// A handle on side `side` (0 or 1) of this connection `id`.
    fn handle(&self, net: &Net, id: u64, side: usize) -> MemConn {
        let peer = self.keys.get(1 - side).copied().unwrap_or_default();
        MemConn(Arc::new(Handle { net: net.clone(), id, side, peer }))
    }
}

impl State {
    pub(crate) fn close(&mut self, id: u64) {
        if let Some(c) = self.conns.get_mut(&id).filter(|c| !c.closed) {
            c.closed = true;
            for s in c.streams.values_mut() {
                for p in &mut s.pipes {
                    p.data.clear();
                    wake(&mut p.waker);
                }
            }
            for w in c.accept_waker.iter_mut().chain(&mut c.open_waker) {
                wake(w);
            }
        }
    }

    fn live(&mut self, id: u64) -> Option<&mut Conn> {
        self.conns.get_mut(&id).filter(|c| !c.closed)
    }

    pub(crate) fn id(&mut self) -> u64 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }

    pub(crate) fn rng(&mut self) -> &mut Rng {
        &mut self.rng
    }

    /// A new connection presenting `keys` (side 0 dialed), side 1 not yet accepted
    /// (`accept_conn`), side `i` opening at most `limit[i]` streams at once; the dialer's
    /// handle.
    pub(crate) fn new_conn(&mut self, net: &Net, keys: [PublicKey; 2], limit: [usize; 2]) -> (u64, MemConn) {
        let id = self.id();
        let c = Conn { keys, streams: BTreeMap::new(), accept: [VecDeque::new(), VecDeque::new()], accept_waker: [None, None], next_stream: 0, closed: false, dropped: [false, true], limit, open_waker: [None, None] };
        let h = c.handle(net, id, 0);
        self.conns.insert(id, c);
        (id, h)
    }

    /// Side 1 of connection `id`; `None` once reset.
    pub(crate) fn accept_conn(&mut self, net: &Net, id: u64) -> Option<MemConn> {
        let c = self.live(id)?;
        let [_, d1] = &mut c.dropped;
        *d1 = false;
        Some(c.handle(net, id, 1))
    }
}

impl Net {
    pub fn new(seed: u64) -> Net {
        Net(Arc::new(Mutex::new(State { now: 0, rng: Rng::new(seed), conns: BTreeMap::new(), timers: BTreeMap::new(), next_id: 0, udp: crate::nat::Udp::default(), spawned: Vec::new() })))
    }

    pub(crate) fn state(&self) -> std::sync::MutexGuard<'_, State> {
        lock(&self.0)
    }

    /// Runs `f` as a task of the `Sched` stepping this net (from its next turn).
    pub fn spawn(&self, f: impl Future<Output = ()> + Send + 'static) {
        lock(&self.0).spawned.push(Box::pin(f));
    }

    pub(crate) fn take_spawned(&self) -> Vec<Spawned> {
        std::mem::take(&mut lock(&self.0).spawned)
    }

    /// Whether a timer is set.
    pub(crate) fn pending(&self) -> bool {
        !lock(&self.0).timers.is_empty()
    }

    /// Moves time to the next timer and fires every timer due then.
    pub(crate) fn advance(&self) {
        let mut st = lock(&self.0);
        let Some(&(at, _)) = st.timers.keys().next() else { return };
        st.now = st.now.max(at);
        let now = st.now;
        while let Some(e) = st.timers.first_entry() {
            if e.key().0 > now {
                break;
            }
            e.remove().wake();
        }
    }

    /// Model milliseconds since the net was made.
    pub fn now(&self) -> u64 {
        lock(&self.0).now
    }

    /// Open connections.
    pub fn connections(&self) -> usize {
        lock(&self.0).conns.values().filter(|c| !c.closed).count()
    }

    /// Completes after `ms` model milliseconds.
    pub fn sleep(&self, ms: u64) -> impl Future<Output = ()> + Send + use<> {
        let net = self.clone();
        let mut key: Option<(u64, u64)> = None;
        poll_fn(move |cx| {
            let mut st = lock(&net.0);
            let k = match key {
                Some(k) => k,
                None => {
                    let k = (st.now.saturating_add(ms), st.id());
                    key = Some(k);
                    k
                }
            };
            if st.now >= k.0 {
                st.timers.remove(&k);
                return Poll::Ready(());
            }
            st.timers.insert(k, cx.waker().clone());
            Poll::Pending
        })
    }
}

/// One side of a connection; the connection resets when the last handle of either side drops.
struct Handle {
    net: Net,
    id: u64,
    side: usize,
    peer: PublicKey,
}

impl Drop for Handle {
    fn drop(&mut self) {
        let mut st = lock(&self.net.0);
        st.close(self.id);
        let gone = st.conns.get_mut(&self.id).is_some_and(|c| {
            if let Some(d) = c.dropped.get_mut(self.side) {
                *d = true;
            }
            c.dropped == [true, true]
        });
        if gone {
            st.conns.remove(&self.id);
        }
    }
}

#[derive(Clone)]
pub struct MemConn(Arc<Handle>);

impl Connection for MemConn {
    type Send = MemSend;
    type Recv = MemRecv;

    fn peer_key(&self) -> PublicKey {
        self.0.peer
    }

    /// Waits while this side has its limit of streams open.
    fn open_stream(&self) -> impl Future<Output = Result<(MemSend, MemRecv), Error>> + Send {
        poll_fn(|cx| {
            let mut st = lock(&self.0.net.0);
            let side = self.0.side;
            let Some(c) = st.live(self.0.id) else { return Poll::Ready(Err(Error::Closed)) };
            if c.open_by(side) >= c.limit.get(side).copied().unwrap_or(0) {
                if let Some(w) = c.open_waker.get_mut(side) {
                    *w = Some(cx.waker().clone());
                }
                return Poll::Pending;
            }
            let s = c.next_stream;
            c.next_stream = s.wrapping_add(1);
            let mut halves = [0; 2];
            if let Some(n) = halves.get_mut(side) {
                *n = 2;
            }
            c.streams.insert(s, Strm { opener: side, pipes: [Pipe::default(), Pipe::default()], announced: false, halves, accepted: false });
            Poll::Ready(Ok(self.halves(s)))
        })
    }

    fn accept_stream(&self) -> impl Future<Output = Result<(MemSend, MemRecv), Error>> + Send {
        poll_fn(|cx| {
            let mut st = lock(&self.0.net.0);
            let side = self.0.side;
            let Some(c) = st.live(self.0.id) else { return Poll::Ready(Err(Error::Closed)) };
            match c.accept.get_mut(side).and_then(|q| q.pop_front()) {
                Some(s) => {
                    if let Some(st) = c.streams.get_mut(&s) {
                        st.accepted = true;
                        if let Some(n) = st.halves.get_mut(side) {
                            *n = 2;
                        }
                    }
                    Poll::Ready(Ok(self.halves(s)))
                }
                None => {
                    if let Some(w) = c.accept_waker.get_mut(side) {
                        *w = Some(cx.waker().clone());
                    }
                    Poll::Pending
                }
            }
        })
    }

    fn close(&self) {
        lock(&self.0.net.0).close(self.0.id);
    }
}

impl MemConn {
    fn halves(&self, s: u64) -> (MemSend, MemRecv) {
        (MemSend { h: self.0.clone(), s }, MemRecv { h: self.0.clone(), s })
    }
}

pub struct MemSend {
    h: Arc<Handle>,
    s: u64,
}

impl MemSend {
    /// Hands `data` (then, with `fin`, the end) to the reader; the opener's first push shows the
    /// stream to the peer.
    fn push(&mut self, data: &[u8], fin: bool) -> Result<(), Error> {
        let mut st = lock(&self.h.net.0);
        let side = self.h.side;
        let c = st.live(self.h.id).ok_or(Error::Closed)?;
        let s = c.streams.get_mut(&self.s).ok_or(Error::Closed)?;
        let p = s.pipes.get_mut(side).ok_or(Error::Closed)?;
        if p.fin {
            return Err(Error::Closed);
        }
        p.data.extend(data);
        p.fin = fin;
        wake(&mut p.waker);
        if s.opener == side && !s.announced {
            s.announced = true;
            if let (Some(q), Some(w)) = (c.accept.get_mut(1 - side), c.accept_waker.get_mut(1 - side)) {
                q.push_back(self.s);
                wake(w);
            }
        }
        Ok(())
    }

    /// Whether this side finished the stream.
    fn finished(&self) -> bool {
        let st = lock(&self.h.net.0);
        st.conns.get(&self.h.id).and_then(|c| c.streams.get(&self.s)).and_then(|s| s.pipes.get(self.h.side)).is_some_and(|p| p.fin)
    }
}

impl SendStream for MemSend {
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<(), Error>> + Send {
        std::future::ready(if buf.is_empty() { Ok(()) } else { self.push(buf, false) })
    }

    /// Done at once: what was written is the reader's already, even if the connection closed since.
    fn finish(&mut self) -> impl Future<Output = Result<(), Error>> + Send {
        std::future::ready(if self.finished() { Ok(()) } else { self.push(&[], true) })
    }
}

impl Drop for MemSend {
    fn drop(&mut self) {
        let _ = self.push(&[], true);
        if let Some(c) = lock(&self.h.net.0).conns.get_mut(&self.h.id) {
            c.drop_half(self.s, self.h.side);
        }
    }
}

pub struct MemRecv {
    h: Arc<Handle>,
    s: u64,
}

impl RecvStream for MemRecv {
    /// An empty `buf` reads `Ok(0)` at once.
    fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize, Error>> + Send {
        poll_fn(move |cx| {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let mut st = lock(&self.h.net.0);
            let peer = 1 - self.h.side;
            let Some(p) = st.live(self.h.id).and_then(|c| c.streams.get_mut(&self.s)).and_then(|s| s.pipes.get_mut(peer)) else {
                return Poll::Ready(Err(Error::Closed));
            };
            if !p.data.is_empty() {
                let n = buf.len().min(p.data.len());
                for (d, b) in buf.iter_mut().zip(p.data.drain(..n)) {
                    *d = b;
                }
                return Poll::Ready(Ok(n));
            }
            if p.fin {
                return Poll::Ready(Ok(0));
            }
            p.waker = Some(cx.waker().clone());
            Poll::Pending
        })
    }
}

impl Drop for MemRecv {
    fn drop(&mut self) {
        if let Some(c) = lock(&self.h.net.0).conns.get_mut(&self.h.id) {
            c.drop_half(self.s, self.h.side);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::p2p::{Alpn, Sock, Udp};
    use crate::{Sched, StaticSecret};

    // spec: none (bounded memory): a connection keeps no state of streams both sides are done
    // with, accepted or not yet when the opener finished, nor of a dial never accepted
    #[test]
    fn finished_streams_and_dials_dropped() {
        let net = Net::new(0);
        let mut s = Sched::new(0, Some(net.clone()));
        let l = net.udp("192.0.2.1".parse().unwrap(), None).bind("192.0.2.1:7000".parse().unwrap(), Some(&StaticSecret::from_bytes([1; 32]))).unwrap();
        let d = net.udp("192.0.2.2".parse().unwrap(), None).bind("192.0.2.2:0".parse().unwrap(), None).unwrap();
        let key = StaticSecret::from_bytes([1; 32]).public_key();
        let (c, a) = s.block_on(async move { (d.dial("192.0.2.1:7000".parse().unwrap(), key, None, Alpn::Osis).await.unwrap().0, l.accept().await.unwrap().0) }).unwrap();
        let streams = |net: &Net| lock(&net.0).conns.values().map(|c| c.streams.len()).sum::<usize>();
        for i in 0..100u8 {
            let (c2, a2) = (c.clone(), a.clone());
            s.block_on(async move {
                let (mut tx, rx) = c2.open_stream().await.unwrap();
                tx.write_all(&[i]).await.unwrap();
                tx.finish().await.unwrap();
                drop((tx, rx));
                let (mut tx2, mut rx2) = a2.accept_stream().await.unwrap();
                let mut b = [0u8; 4];
                assert_eq!(rx2.read(&mut b).await.unwrap(), 1);
                assert_eq!(rx2.read(&mut b).await.unwrap(), 0);
                tx2.finish().await.unwrap();
            })
            .unwrap();
            assert_eq!(streams(&net), 0, "after session {i}");
        }
        let c2 = c.clone();
        let kept = s.block_on(async move { c2.open_stream().await.unwrap() }).unwrap();
        assert_eq!(streams(&net), 1);
        drop(kept);
        assert_eq!(streams(&net), 1, "not accepted yet: the peer may still read its fin");
        drop((c, a));
        assert_eq!(lock(&net.0).conns.len(), 0);
        // a dial never accepted goes when the dialer drops
        let l = net.udp("192.0.2.3".parse().unwrap(), None).bind("192.0.2.3:7000".parse().unwrap(), Some(&StaticSecret::from_bytes([1; 32]))).unwrap();
        let d = net.udp("192.0.2.4".parse().unwrap(), None).bind("192.0.2.4:0".parse().unwrap(), None).unwrap();
        let c = s.block_on(async move { d.dial("192.0.2.3:7000".parse().unwrap(), key, None, Alpn::Osis).await.unwrap().0 }).unwrap();
        drop(c);
        assert_eq!(lock(&net.0).conns.len(), 0);
        drop(l);
    }
}

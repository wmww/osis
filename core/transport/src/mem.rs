//! `InProcess`: endpoints on a shared `Net`, connections as in-memory pipes, faults driven by
//! a virtual step counter and a seeded rng. Runs under `Sched` (deterministic, no tokio) or any
//! executor. With no latency, jitter or bandwidth cap, a write is readable at once; otherwise
//! data waits for `Net::step` (which `Sched` calls when every task is blocked).
//!
//! Faults: per-chunk `latency` plus seeded `jitter` (per-stream order is kept, so jitter only
//! reorders deliveries across streams and connections); a per-pipe `bandwidth` cap in bytes per
//! step; `partition` (dials fail, in-flight data waits until `heal`); `disconnect`/`kill`
//! (connections reset). Streams never lose or reorder bytes: that is the contract.

use crate::util::{lock, Rng};
use crate::{Address, Connection, Error, ListenConfig, Listener, PublicKey, RecvStream, SendStream, StaticSecret, Transport};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::{poll_fn, Future};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

/// URL scheme of in-process listeners: `mem://name`.
pub const SCHEME: &str = "mem";

/// Fault settings; the default is a perfect network.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Faults {
    /// Steps between a write and its delivery.
    pub latency: u64,
    /// Extra seeded delay per chunk, `0..=jitter` steps.
    pub jitter: u64,
    /// Bytes per step per stream direction; `None` = unlimited.
    pub bandwidth: Option<usize>,
}

/// The shared in-process network. Clones share it.
#[derive(Clone)]
pub struct Net(Arc<Mutex<State>>);

struct State {
    step: u64,
    rng: Rng,
    faults: Faults,
    listeners: BTreeMap<String, Lst>,
    conns: BTreeMap<u64, Conn>,
    cut: BTreeSet<(String, String)>,
    timers: BTreeMap<(u64, u64), Waker>,
    next_id: u64,
}

struct Lst {
    id: u64,
    endpoint: String,
    key: PublicKey,
    queue: VecDeque<u64>,
    waker: Option<Waker>,
}

/// Side 0 dialed, side 1 accepted.
struct Conn {
    ends: [String; 2],
    keys: [PublicKey; 2],
    streams: BTreeMap<u64, Strm>,
    accept: [VecDeque<u64>; 2],
    accept_waker: [Option<Waker>; 2],
    next_stream: u64,
    /// Reset: operations fail; kept until the other side's handle drops so a `finish` can
    /// still tell whether its data got through.
    closed: bool,
    /// Sides whose last handle dropped (side 1 counts as dropped until accepted); the entry
    /// goes when both have.
    dropped: [bool; 2],
}

struct Strm {
    opener: usize,
    /// `pipes[i]` carries what side `i` writes.
    pipes: [Pipe; 2],
    /// Live halves (`MemSend`, `MemRecv`) per side; the stream goes once the peer accepted it
    /// and every half dropped.
    halves: [u8; 2],
    accepted: bool,
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
    }
}

#[derive(Default)]
struct Pipe {
    flight: VecDeque<Chunk>,
    ready: VecDeque<u8>,
    fin: bool,
    fin_sent: bool,
    announced: bool,
    last_at: u64,
    /// (step, bytes delivered in that step) for the bandwidth cap.
    used: (u64, usize),
    waker: Option<Waker>,
    /// A `finish` waiting for the flight to drain.
    send_waker: Option<Waker>,
}

struct Chunk {
    at: u64,
    data: Vec<u8>,
    fin: bool,
}

fn pair(a: &str, b: &str) -> (String, String) {
    if a <= b { (a.to_owned(), b.to_owned()) } else { (b.to_owned(), a.to_owned()) }
}

fn wake(w: &mut Option<Waker>) {
    if let Some(w) = w.take() {
        w.wake();
    }
}

impl Conn {
    fn wake_all(&mut self) {
        for s in self.streams.values_mut() {
            for p in &mut s.pipes {
                wake(&mut p.waker);
                wake(&mut p.send_waker);
            }
        }
        for w in &mut self.accept_waker {
            wake(w);
        }
    }

    /// Moves due chunks to the readers, within the bandwidth cap.
    fn deliver(&mut self, step: u64, bandwidth: Option<usize>) {
        for (&id, s) in self.streams.iter_mut() {
            for side in 0..2 {
                let Some(p) = s.pipes.get_mut(side) else { continue };
                let mut moved = false;
                while let Some(c) = p.flight.front_mut() {
                    if c.at > step {
                        break;
                    }
                    if p.used.0 != step {
                        p.used = (step, 0);
                    }
                    let room = bandwidth.map_or(usize::MAX, |b| b.saturating_sub(p.used.1));
                    if room == 0 && !c.data.is_empty() {
                        break;
                    }
                    let n = c.data.len().min(room);
                    p.ready.extend(c.data.drain(..n));
                    p.used.1 = p.used.1.saturating_add(n);
                    moved = true;
                    if !c.data.is_empty() {
                        break;
                    }
                    if c.fin {
                        p.fin = true;
                    }
                    p.flight.pop_front();
                }
                if moved {
                    wake(&mut p.waker);
                    if p.flight.is_empty() {
                        wake(&mut p.send_waker);
                    }
                    if side == s.opener && !p.announced {
                        p.announced = true;
                        let peer = 1 - side;
                        if let (Some(q), Some(w)) = (self.accept.get_mut(peer), self.accept_waker.get_mut(peer)) {
                            q.push_back(id);
                            wake(w);
                        }
                    }
                }
            }
        }
    }

    fn has_flight(&self) -> bool {
        self.streams.values().any(|s| s.pipes.iter().any(|p| !p.flight.is_empty()))
    }
}

impl State {
    fn is_cut(&self, c: &Conn) -> bool {
        let [a, b] = &c.ends;
        self.cut.contains(&pair(a, b))
    }

    fn deliver_conn(&mut self, id: u64) {
        let (step, bw) = (self.step, self.faults.bandwidth);
        let cut = match self.conns.get(&id) {
            Some(c) => self.is_cut(c),
            None => return,
        };
        if let (false, Some(c)) = (cut, self.conns.get_mut(&id)) {
            c.deliver(step, bw);
        }
    }

    fn deliver_all(&mut self) {
        let ids: Vec<u64> = self.conns.keys().copied().collect();
        for id in ids {
            self.deliver_conn(id);
        }
    }

    fn close(&mut self, id: u64) {
        if let Some(c) = self.conns.get_mut(&id).filter(|c| !c.closed) {
            c.closed = true;
            for st in c.streams.values_mut() {
                for p in &mut st.pipes {
                    p.flight.clear();
                    p.ready.clear();
                }
            }
            c.wake_all();
        }
    }

    /// Removes listener `name` (if `id` matches) and resets the connections queued on it.
    fn drop_listener(&mut self, name: &str, id: Option<u64>) {
        if self.listeners.get(name).is_some_and(|l| id.is_none_or(|i| i == l.id))
            && let Some(mut l) = self.listeners.remove(name)
        {
            wake(&mut l.waker);
            for c in l.queue {
                self.close(c);
            }
        }
    }

    fn live(&mut self, id: u64) -> Option<&mut Conn> {
        self.conns.get_mut(&id).filter(|c| !c.closed)
    }

    fn id(&mut self) -> u64 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }
}

impl Net {
    pub fn new(seed: u64) -> Net {
        Net(Arc::new(Mutex::new(State {
            step: 0,
            rng: Rng::new(seed),
            faults: Faults::default(),
            listeners: BTreeMap::new(),
            conns: BTreeMap::new(),
            cut: BTreeSet::new(),
            timers: BTreeMap::new(),
            next_id: 0,
        })))
    }

    /// A transport whose dials and listeners belong to endpoint `name` (for partitions).
    pub fn endpoint(&self, name: &str) -> InProcess {
        InProcess { net: self.clone(), name: name.to_owned() }
    }

    /// A `bandwidth` of `Some(0)` is taken as `Some(1)` (zero would stall forever).
    pub fn set_faults(&self, mut f: Faults) {
        f.bandwidth = f.bandwidth.map(|b| b.max(1));
        lock(&self.0).faults = f;
    }

    /// Cuts endpoints `a` and `b` apart: dials fail, data in flight waits.
    pub fn partition(&self, a: &str, b: &str) {
        lock(&self.0).cut.insert(pair(a, b));
    }

    pub fn heal(&self, a: &str, b: &str) {
        let mut st = lock(&self.0);
        st.cut.remove(&pair(a, b));
        st.deliver_all();
    }

    /// Resets every connection between endpoints `a` and `b`.
    pub fn disconnect(&self, a: &str, b: &str) {
        let mut st = lock(&self.0);
        let p = pair(a, b);
        let ids: Vec<u64> = st.conns.iter().filter(|(_, c)| !c.closed && pair(&c.ends[0], &c.ends[1]) == p).map(|(i, _)| *i).collect();
        for id in ids {
            st.close(id);
        }
    }

    /// Resets every connection of endpoint `a` and closes its listeners.
    pub fn kill(&self, a: &str) {
        let mut st = lock(&self.0);
        let ids: Vec<u64> = st.conns.iter().filter(|(_, c)| !c.closed && c.ends.iter().any(|e| e == a)).map(|(i, _)| *i).collect();
        for id in ids {
            st.close(id);
        }
        let names: Vec<String> = st.listeners.iter().filter(|(_, l)| l.endpoint == a).map(|(n, _)| n.clone()).collect();
        for n in names {
            st.drop_listener(&n, None);
        }
    }

    /// Advances virtual time one step: delivers due data, fires due timers.
    pub fn step(&self) {
        let mut st = lock(&self.0);
        st.step = st.step.saturating_add(1);
        st.deliver_all();
        let now = st.step;
        while let Some(e) = st.timers.first_entry() {
            if e.key().0 > now {
                break;
            }
            e.remove().wake();
        }
    }

    /// Jumps to the step before the next timer when nothing is in flight, so `step` fires it.
    pub(crate) fn skip_idle(&self) {
        let mut st = lock(&self.0);
        let flight = st.conns.values().any(|c| !st.is_cut(c) && c.has_flight());
        if let (false, Some(&(at, _))) = (flight, st.timers.keys().next()) {
            st.step = st.step.max(at.saturating_sub(1));
        }
    }

    pub fn now(&self) -> u64 {
        lock(&self.0).step
    }

    /// Whether stepping would deliver something or fire a timer (data held by a partition does not count).
    pub fn pending(&self) -> bool {
        let st = lock(&self.0);
        !st.timers.is_empty() || st.conns.values().any(|c| !st.is_cut(c) && c.has_flight())
    }

    /// Open connections.
    pub fn connections(&self) -> usize {
        lock(&self.0).conns.values().filter(|c| !c.closed).count()
    }

    /// Completes after `steps` virtual steps.
    pub fn sleep(&self, steps: u64) -> impl Future<Output = ()> + Send + use<> {
        let net = self.clone();
        let mut key: Option<(u64, u64)> = None;
        poll_fn(move |cx| {
            let mut st = lock(&net.0);
            let k = match key {
                Some(k) => k,
                None => {
                    let k = (st.step.saturating_add(steps), st.id());
                    key = Some(k);
                    k
                }
            };
            if st.step >= k.0 {
                st.timers.remove(&k);
                return Poll::Ready(());
            }
            st.timers.insert(k, cx.waker().clone());
            Poll::Pending
        })
    }
}

/// An endpoint of a `Net`.
#[derive(Clone)]
pub struct InProcess {
    net: Net,
    name: String,
}

impl InProcess {
    /// The public key a listener with `secret` presents: Ed25519 with `secret` as seed, as
    /// `Quic` and `Iroh` (spec/sync.md §10).
    pub fn public_key(secret: &crate::StaticSecret) -> PublicKey {
        ed25519_dalek::SigningKey::from_bytes(secret.as_bytes()).verifying_key().to_bytes()
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

fn mem_name(url: &str) -> Result<&str, Error> {
    crate::check_url(url)?;
    match url.split_once("://") {
        Some((SCHEME, n)) if !n.is_empty() => Ok(n),
        Some((SCHEME, _)) | None => Err(Error::BadUrl(url.to_owned())),
        Some((s, _)) => Err(Error::UnknownScheme(s.to_owned())),
    }
}

impl Transport for InProcess {
    type Conn = MemConn;
    type Listener = MemListener;

    fn dial(&self, addr: &Address) -> impl Future<Output = Result<MemConn, Error>> + Send {
        std::future::ready(self.dial_with(addr, None))
    }

    fn dial_as(&self, addr: &Address, secret: &StaticSecret) -> impl Future<Output = Result<MemConn, Error>> + Send {
        std::future::ready(self.dial_with(addr, Some(InProcess::public_key(secret))))
    }

    fn listen(&self, cfg: ListenConfig) -> impl Future<Output = Result<MemListener, Error>> + Send {
        let r = (|| {
            let name = mem_name(&cfg.url)?.to_owned();
            let key = InProcess::public_key(&cfg.secret);
            let mut st = lock(&self.net.0);
            if st.listeners.contains_key(&name) {
                return Err(Error::Io(format!("address in use: {}", cfg.url)));
            }
            let id = st.id();
            st.listeners.insert(name.clone(), Lst { id, endpoint: self.name.clone(), key, queue: VecDeque::new(), waker: None });
            Ok(MemListener { net: self.net.clone(), name, id, addr: Address { url: cfg.url, key } })
        })();
        std::future::ready(r)
    }
}

impl InProcess {
    fn dial_with(&self, addr: &Address, own: Option<PublicKey>) -> Result<MemConn, Error> {
        crate::check_url(&addr.url)?;
        let mut st = lock(&self.net.0);
        // `peer://`: the listener presenting the key, as P2P transports dial
        let name = match crate::peer_relays(&addr.url) {
            Some(_) => match st.listeners.iter().find(|(_, l)| l.key == addr.key) {
                Some((n, _)) => n.clone(),
                None => return Err(Error::Unreachable(addr.url.clone())),
            },
            None => mem_name(&addr.url)?.to_owned(),
        };
        let name = name.as_str();
        let Some(l) = st.listeners.get(name) else { return Err(Error::Unreachable(addr.url.clone())) };
        let (lend, lkey) = (l.endpoint.clone(), l.key);
        if st.cut.contains(&pair(&self.name, &lend)) {
            return Err(Error::Unreachable(addr.url.clone()));
        }
        if lkey != addr.key {
            return Err(Error::KeyMismatch);
        }
        let mine = own.unwrap_or_else(|| st.rng.bytes32());
        let source = name_source(&lend);
        let id = st.id();
        st.conns.insert(id, Conn {
            ends: [self.name.clone(), lend],
            keys: [mine, lkey],
            streams: BTreeMap::new(),
            accept: [VecDeque::new(), VecDeque::new()],
            accept_waker: [None, None],
            next_stream: 0,
            closed: false,
            dropped: [false, true],
        });
        if let Some(l) = st.listeners.get_mut(name) {
            l.queue.push_back(id);
            wake(&mut l.waker);
        }
        Ok(MemConn(Arc::new(Handle { net: self.net.clone(), id, side: 0, peer: lkey, source })))
    }
}

pub struct MemListener {
    net: Net,
    name: String,
    id: u64,
    addr: Address,
}

impl Listener for MemListener {
    type Conn = MemConn;

    fn accept(&mut self) -> impl Future<Output = Result<MemConn, Error>> + Send {
        poll_fn(|cx| {
            let mut st = lock(&self.net.0);
            loop {
                let Some(l) = st.listeners.get_mut(&self.name).filter(|l| l.id == self.id) else {
                    return Poll::Ready(Err(Error::Closed));
                };
                match l.queue.pop_front() {
                    Some(id) => {
                        if let Some(c) = st.live(id) {
                            let [_, d1] = &mut c.dropped;
                            *d1 = false;
                            let [peer, _] = c.keys;
                            let source = name_source(c.ends.first().map_or("", String::as_str));
                            return Poll::Ready(Ok(MemConn(Arc::new(Handle { net: self.net.clone(), id, side: 1, peer, source }))));
                        }
                        // reset before accept: side 0 dropping removes it
                    }
                    None => {
                        l.waker = Some(cx.waker().clone());
                        return Poll::Pending;
                    }
                }
            }
        })
    }

    fn address(&self) -> Address {
        self.addr.clone()
    }

    fn close(&self) {
        lock(&self.net.0).drop_listener(&self.name, Some(self.id));
    }
}

impl Drop for MemListener {
    fn drop(&mut self) {
        self.close();
    }
}

/// One side of a connection; the connection resets when the last handle of either side drops.
struct Handle {
    net: Net,
    id: u64,
    side: usize,
    peer: PublicKey,
    /// The other end's endpoint name, hashed.
    source: crate::Source,
}

fn name_source(name: &str) -> crate::Source {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut h);
    let mut s = [0u8; 16];
    if let Some(d) = s.get_mut(..8) {
        d.copy_from_slice(&h.finish().to_be_bytes());
    }
    s
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

    fn source(&self) -> Option<crate::Source> {
        Some(self.0.source)
    }

    fn open_stream(&self) -> impl Future<Output = Result<(MemSend, MemRecv), Error>> + Send {
        let r = (|| {
            let mut st = lock(&self.0.net.0);
            let c = st.live(self.0.id).ok_or(Error::Closed)?;
            let s = c.next_stream;
            c.next_stream = s.wrapping_add(1);
            let mut halves = [0; 2];
            if let Some(n) = halves.get_mut(self.0.side) {
                *n = 2;
            }
            c.streams.insert(s, Strm { opener: self.0.side, pipes: [Pipe::default(), Pipe::default()], halves, accepted: false });
            Ok(self.halves(s))
        })();
        std::future::ready(r)
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
    /// Runs `f` on our pipe with the connection's closed flag.
    fn pipe<R>(&self, f: impl FnOnce(&mut Pipe, bool) -> R) -> Option<R> {
        let mut st = lock(&self.h.net.0);
        let side = self.h.side;
        let c = st.conns.get_mut(&self.h.id)?;
        let closed = c.closed;
        c.streams.get_mut(&self.s).and_then(|s| s.pipes.get_mut(side)).map(|p| f(p, closed))
    }

    fn push(&mut self, data: &[u8], fin: bool) -> Result<(), Error> {
        let mut st = lock(&self.h.net.0);
        let (step, f) = (st.step, st.faults);
        let delay = f.latency.saturating_add(st.rng.below(f.jitter.saturating_add(1)));
        let side = self.h.side;
        let p = st
            .live(self.h.id)
            .and_then(|c| c.streams.get_mut(&self.s))
            .and_then(|s| s.pipes.get_mut(side))
            .ok_or(Error::Closed)?;
        if p.fin_sent {
            return Err(Error::Closed);
        }
        let at = step.saturating_add(delay).max(p.last_at);
        p.last_at = at;
        p.fin_sent = fin;
        p.flight.push_back(Chunk { at, data: data.to_vec(), fin });
        st.deliver_conn(self.h.id);
        Ok(())
    }
}

impl SendStream for MemSend {
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<(), Error>> + Send {
        let r = if buf.is_empty() { Ok(()) } else { self.push(buf, false) };
        std::future::ready(r)
    }

    fn finish(&mut self) -> impl Future<Output = Result<(), Error>> + Send {
        let mut pushed = None;
        poll_fn(move |cx| {
            if pushed.is_none() {
                let sent = self.pipe(|p, closed| (p.fin_sent, closed));
                pushed = Some(match sent {
                    Some((false, false)) => self.push(&[], true),
                    Some((true, _)) => Ok(()),
                    _ => Err(Error::Closed),
                });
            }
            if let Some(Err(e)) = &pushed {
                return Poll::Ready(Err(e.clone()));
            }
            let w = cx.waker().clone();
            // done once the fin (so all data) reached the peer, even if it closed since
            match self.pipe(move |p, closed| {
                if !p.fin && !closed {
                    p.send_waker = Some(w);
                }
                (p.fin, closed)
            }) {
                Some((true, _)) => Poll::Ready(Ok(())),
                Some((false, false)) => Poll::Pending,
                _ => Poll::Ready(Err(Error::Closed)),
            }
        })
    }
}

impl Drop for MemSend {
    fn drop(&mut self) {
        if self.pipe(|p, closed| p.fin_sent || closed) == Some(false) {
            let _ = self.push(&[], true);
        }
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
            if !p.ready.is_empty() {
                let n = buf.len().min(p.ready.len());
                for (d, b) in buf.iter_mut().zip(p.ready.drain(..n)) {
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
    use crate::{Sched, StaticSecret};

    // spec: none (no leaked entries: a dial never accepted is removed when the dialer drops)
    #[test]
    fn unaccepted_conn_removed_on_drop() {
        let net = Net::new(1);
        let mut s = Sched::new(1, Some(net.clone()));
        let srv = net.endpoint("srv");
        let l = s
            .block_on(async move { srv.listen(ListenConfig { url: "mem://srv".into(), secret: StaticSecret::from_bytes([1; 32]) }).await.unwrap() })
            .unwrap();
        let (cli, addr) = (net.endpoint("cli"), l.address());
        let c = s.block_on(async move { cli.dial(&addr).await.unwrap() }).unwrap();
        drop(c);
        assert_eq!(lock(&net.0).conns.len(), 0);
        drop(l);
    }

    // spec/sync.md §10: a peer is dialed by its dialable key alone (`peer://`), never by a
    // published address; the relays in the URL do not matter in process.
    #[test]
    fn peer_url_dials_by_key_spec_sync_10() {
        let net = Net::new(2);
        let mut s = Sched::new(2, Some(net.clone()));
        let srv = net.endpoint("srv");
        let l = s
            .block_on(async move { srv.listen(ListenConfig { url: "mem://srv".into(), secret: StaticSecret::from_bytes([3; 32]) }).await.unwrap() })
            .unwrap();
        let key = l.address().key;
        let cli = net.endpoint("cli");
        let url = crate::peer_url(&["https://relay.example".into()]);
        assert_eq!(crate::peer_relays(&url), Some(vec!["https://relay.example".to_owned()]));
        assert_eq!(crate::peer_relays(&crate::peer_url(&[])), Some(vec![]));
        let (u, c2) = (url.clone(), cli.clone());
        let c = s.block_on(async move { c2.dial(&Address { url: u, key }).await.unwrap() }).unwrap();
        assert_eq!(c.peer_key(), key);
        let r = s.block_on(async move { cli.dial(&Address { url, key: [9; 32] }).await }).unwrap();
        assert!(matches!(r, Err(Error::Unreachable(_))));
        drop(l);
    }

    // spec: none (bounded memory): a long-lived connection keeps no state of sessions both
    // sides are done with, accepted or not yet when the opener finished
    #[test]
    fn finished_streams_dropped() {
        let net = Net::new(3);
        let mut s = Sched::new(3, Some(net.clone()));
        let srv = net.endpoint("srv");
        let mut l = s
            .block_on(async move { srv.listen(ListenConfig { url: "mem://srv".into(), secret: StaticSecret::from_bytes([1; 32]) }).await.unwrap() })
            .unwrap();
        let (cli, addr) = (net.endpoint("cli"), l.address());
        let c = s.block_on(async move { cli.dial(&addr).await.unwrap() }).unwrap();
        let a = s.block_on(async move { l.accept().await.unwrap() }).unwrap();
        let streams = |net: &Net| lock(&net.0).conns.values().map(|c| c.streams.len()).sum::<usize>();
        for i in 0..100u8 {
            let (c2, a2) = (c.clone(), a.clone());
            s.block_on(async move {
                let (mut tx, rx) = c2.open_stream().await.unwrap();
                tx.write_all(&[i]).await.unwrap();
                // the opener is done before the peer accepts
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
        // a stream still held on one side stays
        let c2 = c.clone();
        let kept = s.block_on(async move { c2.open_stream().await.unwrap() }).unwrap();
        assert_eq!(streams(&net), 1);
        drop(kept);
        assert_eq!(streams(&net), 1, "not accepted yet: the peer may still read its fin");
    }
}

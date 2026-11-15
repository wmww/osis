//! The product's `Links` over osis-transport (tokio): dials, listeners, discovery, each link's
//! bytes and what the transport took of them, and the node's one wake, all turned into `Input`s
//! (`TransportLinks::next`); the node's owner steps it on them (the osis handle's driver task). Sync above this never learns how a peer
//! is reached: a connection is its key, its rank and its bytes.

use crate::session::STALL_TIMEOUT_MS;
use crate::types::{ConnId, Input, NodeKey};
use crate::Links;
use osis_base::{Clock, WallMs};
use osis_blob::Address;
use osis_transport::link::{self, Link, LinkTx};
use osis_transport::lan::Found;
use osis_transport::{Error, StaticSecret, Transport};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// How long a served connection with no session stays, and how long a session's last bytes may
/// take to go at its end: the stall bound (minor consequence: at 0 a served connection closes
/// before its first session and a close may cut the last bytes; at infinity a dialer that opens
/// no session holds its connection until the transport's idle timeout).
const LINGER: Duration = Duration::from_millis(STALL_TIMEOUT_MS);

/// What the transport's tasks report.
enum Event {
    Dialed(ConnId, Result<Link, Error>, [u8; 32]),
    /// A session a listener took: its set (none: discovery's) and the key it took it under.
    Accepted(Link, Option<Listening>, [u8; 32]),
    /// A link this side cut (`TransportLinks::listen`): reported closed.
    Cut(ConnId),
    Bytes(ConnId, Vec<u8>),
    Ended(ConnId),
    Taken(ConnId, u64),
    Found(Address),
}

/// One live link: its sender and its tasks.
struct Live {
    tx: LinkTx,
    /// Over the unix transport (spec/sync-transport.md §6): a main session's.
    unix: bool,
    /// Accepted by a listener of this set under this key.
    took: Option<(Listening, [u8; 32])>,
    tasks: [JoinHandle<()>; 2],
}

impl Drop for Live {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Who owns a set of listeners (`TransportLinks::listen`): each set is replaced or closed only
/// by its own owner, never by another's listen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Listening {
    /// Direct sync's dialable listener (`peer://`), what the node publishes in `reach.0`.
    Dialable,
    /// The URLs the app listens at (`Osis::listen`).
    Urls,
    /// The client socket (`Osis::listen_socket`).
    Socket,
}

/// A listener serving: `serve` hands its sessions to `fwd`, which reports them; aborting `fwd`
/// ends `serve`, which gives the listener back (a listener dropped closes).
struct Served<L> {
    serve: JoinHandle<L>,
    fwd: JoinHandle<()>,
}

/// The product's `Links` over transport `T`.
pub struct TransportLinks<T: Transport> {
    transport: Arc<T>,
    clock: Arc<dyn Clock>,
    tx: mpsc::UnboundedSender<Event>,
    rx: mpsc::UnboundedReceiver<Event>,
    live: BTreeMap<ConnId, Live>,
    /// Dials in flight: one closed before its result came is not here, and its result is dropped.
    dialing: BTreeMap<ConnId, JoinHandle<()>>,
    /// Each listener set's listeners, each serving in its task.
    listeners: BTreeMap<Listening, Vec<Served<T::Listener>>>,
    discovery: Vec<JoinHandle<()>>,
    wake: Option<WallMs>,
    accepted: u64,
}

impl<T: Transport> Drop for TransportLinks<T> {
    fn drop(&mut self) {
        for s in self.listeners.values().flatten() {
            s.serve.abort();
            s.fwd.abort();
        }
        for t in self.dialing.values().chain(&self.discovery) {
            t.abort();
        }
    }
}

impl<T: Transport> TransportLinks<T> {
    /// Links over `transport`, the node's time from `clock` (its engine's).
    pub fn new(transport: Arc<T>, clock: Arc<dyn Clock>) -> TransportLinks<T> {
        let (tx, rx) = mpsc::unbounded_channel();
        TransportLinks { transport, clock, tx, rx, live: BTreeMap::new(), dialing: BTreeMap::new(), listeners: BTreeMap::new(), discovery: Vec::new(), wake: None, accepted: 0 }
    }

    /// Replaces listener set `set` (spec/sync-transport.md §5 One key, Key change): it listens at
    /// every URL of `urls` under `secret`, all or none (`osis_transport::listen_all`: a URL a
    /// listener of the set is bound at keeps that listener and its connections, under `secret`;
    /// the set's other listeners close first; none: the set stays closed and the error is
    /// returned). Each session a listener takes comes up as an accepted connection. The sessions
    /// the set's listeners took under a key none of them listens under any more (`secret`'s
    /// after a failure) close, reported `Closed`: a key change leaves nobody served under the old
    /// key. The other sets, and every other connection, go on. Their addresses.
    pub async fn listen(&mut self, set: Listening, urls: &[String], secret: &StaticSecret) -> Result<Vec<Address>, Error> {
        let old = self.take_listeners(set).await;
        let r = osis_transport::listen_all(&*self.transport, old, urls, secret).await;
        let mut keys = vec![secret.public_key()];
        if let Ok(ls) = &r {
            use osis_transport::Listener;
            keys.extend(ls.iter().map(|l| l.address().key));
        }
        let cut: Vec<ConnId> = self.live.iter().filter(|(_, l)| l.took.is_some_and(|(s, k)| s == set && !keys.contains(&k))).map(|(c, _)| *c).collect();
        for conn in cut {
            self.live.remove(&conn);
            let _ = self.tx.send(Event::Cut(conn));
        }
        let ls = r?;
        let mut out = Vec::new();
        let served = self.listeners.entry(set).or_default();
        for l in ls {
            use osis_transport::Listener;
            let addr = l.address();
            let (stx, mut srx) = mpsc::channel(1);
            let serve = tokio::spawn(link::serve(l, LINGER, LINGER, stx));
            let tx = self.tx.clone();
            let key = addr.key;
            let fwd = tokio::spawn(async move {
                while let Some(link) = srx.recv().await {
                    if tx.send(Event::Accepted(link, Some(set), key)).is_err() {
                        return;
                    }
                }
            });
            served.push(Served { serve, fwd });
            out.push(addr);
        }
        Ok(out)
    }

    /// Whether `conn` runs over the unix transport, whose listener takes only this process's own
    /// uid (spec/sync-transport.md §6): a session on it is a main session.
    pub fn unix(&self, conn: ConnId) -> bool {
        self.live.get(&conn).is_some_and(|l| l.unix)
    }

    /// Listener set `set`'s listeners, served no more (their tasks ended, not just told to).
    async fn take_listeners(&mut self, set: Listening) -> Vec<T::Listener> {
        let mut out = Vec::new();
        for s in self.listeners.remove(&set).unwrap_or_default() {
            s.fwd.abort();
            let _ = s.fwd.await;
            // `serve` ends once `fwd`'s receiver is gone
            if let Ok(l) = s.serve.await {
                out.push(l);
            }
        }
        out
    }

    /// Starts the transport's discovery (spec/sync-transport.md §4): what it finds comes as
    /// `Input::Discovered`, what its listeners take as accepted connections.
    pub async fn discover(&mut self) -> Result<(), Error> {
        let mut d = self.transport.discover().await?;
        let tx = self.tx.clone();
        self.discovery.push(tokio::spawn(async move {
            while let Some(f) = d.next().await {
                match f {
                    Found::Dial(a) => {
                        if tx.send(Event::Found(a)).is_err() {
                            return;
                        }
                    }
                    Found::Conn(c, key) => {
                        let (stx, mut srx) = mpsc::channel(1);
                        tokio::spawn(link::serve_conn(c, LINGER, LINGER, stx));
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            while let Some(link) = srx.recv().await {
                                if tx.send(Event::Accepted(link, None, key)).is_err() {
                                    return;
                                }
                            }
                        });
                    }
                }
            }
        }));
        Ok(())
    }

    /// The node's next input: what a link reported, or a `Tick` at its wake.
    pub async fn next(&mut self) -> Input {
        loop {
            let ev = match self.wake {
                Some(at) => {
                    let now = self.clock.now_wall_ms();
                    let wait = Duration::from_millis(at.0.saturating_sub(now.0));
                    tokio::select! {
                        ev = self.rx.recv() => ev,
                        () = tokio::time::sleep(wait) => {
                            self.wake = None;
                            return Input::Tick { now: self.clock.now_wall_ms() };
                        }
                    }
                }
                None => self.rx.recv().await,
            };
            // the sender lives in `self`: the channel never ends
            let Some(ev) = ev else { continue };
            if let Some(input) = self.input(ev) {
                return input;
            }
        }
    }

    fn input(&mut self, ev: Event) -> Option<Input> {
        match ev {
            Event::Dialed(conn, r, key) => {
                self.dialing.remove(&conn)?;
                match r {
                    Ok(l) => Some(self.up(conn, l, true, None, key)),
                    Err(e) => Some(Input::Down { conn, error: e.to_string() }),
                }
            }
            Event::Accepted(l, set, key) => {
                self.accepted += 1;
                let conn = ConnId(ConnId::ACCEPTED | self.accepted);
                Some(self.up(conn, l, false, set, key))
            }
            Event::Cut(conn) => Some(Input::Closed { conn }),
            Event::Bytes(conn, bytes) => self.live.contains_key(&conn).then_some(Input::Bytes { conn, bytes }),
            Event::Taken(conn, bytes) => self.live.contains_key(&conn).then_some(Input::Taken { conn, bytes }),
            Event::Ended(conn) => self.live.remove(&conn).map(|_| Input::Closed { conn }),
            Event::Found(addr) => Some(Input::Discovered { addr }),
        }
    }

    /// A link up: its bytes and what the transport took of ours are read into events. `set`:
    /// the listener set that took it.
    fn up(&mut self, conn: ConnId, l: Link, dialed: bool, set: Option<Listening>, listener: [u8; 32]) -> Input {
        let took = set.map(|s| (s, listener));
        let Link { peer_key, rank, tx, mut rx, peer, .. } = l;
        let unix = matches!(peer, osis_transport::Peer::Unix { .. });
        let ev = self.tx.clone();
        let reader = tokio::spawn(async move {
            while let Some(b) = rx.recv().await {
                if ev.send(Event::Bytes(conn, b)).is_err() {
                    return;
                }
            }
            let _ = ev.send(Event::Ended(conn));
        });
        let ev = self.tx.clone();
        let progress = tx.progress();
        let taken = tokio::spawn(async move {
            loop {
                let n = progress.next().await;
                if ev.send(Event::Taken(conn, n)).is_err() {
                    return;
                }
            }
        });
        self.live.insert(conn, Live { tx, unix, took, tasks: [reader, taken] });
        Input::Up { conn, peer: NodeKey(peer_key), rank, dialed, listener: NodeKey(listener) }
    }
}

impl<T: Transport> Links for TransportLinks<T> {
    fn dial(&mut self, conn: ConnId, to: &Address) {
        let (t, to, ev) = (self.transport.clone(), to.clone(), self.tx.clone());
        self.dialing.insert(
            conn,
            tokio::spawn(async move {
                let r = link::dial(&*t, &to, LINGER).await;
                let _ = ev.send(Event::Dialed(conn, r, to.key));
            }),
        );
    }

    fn send(&mut self, conn: ConnId, bytes: &[u8]) {
        // flow control is the session's (spec/sync-streams.md §1-§2): the link queues all
        if let Some(l) = self.live.get(&conn) {
            let _ = l.tx.send(bytes.to_vec(), usize::MAX);
        }
    }

    fn close(&mut self, conn: ConnId) {
        // dropping the sender finishes this side; a dialer's connection closes with its session
        self.live.remove(&conn);
        if let Some(d) = self.dialing.remove(&conn) {
            d.abort();
        }
    }

    fn wake(&mut self, at: WallMs) {
        self.wake = Some(at);
    }
}

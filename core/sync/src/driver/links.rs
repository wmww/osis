//! The product's `Links` over osis-transport (tokio): dials, listeners, discovery, each link's
//! bytes and what the transport took of them, and the node's one wake, all turned into `Input`s
//! (`TransportLinks::next`); the node's owner steps it on them (the osis handle's driver task). Sync above this never learns how a peer
//! is reached: a connection is its key, its rank and its bytes.

use crate::session::STALL_TIMEOUT_MS;
use crate::types::{ConnId, Input, NodeKey};
use crate::Links;
use osis_base::{Clock, WallMs};
use osis_label::Address;
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
    Accepted(Link, [u8; 32]),
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
    tasks: [JoinHandle<()>; 2],
}

impl Drop for Live {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
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
    background: Vec<JoinHandle<()>>,
    wake: Option<WallMs>,
    accepted: u64,
}

impl<T: Transport> Drop for TransportLinks<T> {
    fn drop(&mut self) {
        for t in self.dialing.values().chain(&self.background) {
            t.abort();
        }
    }
}

impl<T: Transport> TransportLinks<T> {
    /// Links over `transport`, the node's time from `clock` (its engine's).
    pub fn new(transport: Arc<T>, clock: Arc<dyn Clock>) -> TransportLinks<T> {
        let (tx, rx) = mpsc::unbounded_channel();
        TransportLinks { transport, clock, tx, rx, live: BTreeMap::new(), dialing: BTreeMap::new(), background: Vec::new(), wake: None, accepted: 0 }
    }

    /// Listens at every URL of `urls` under `secret`, all or none (spec/sync-transport.md §5 One
    /// key): each session a listener takes comes up as an accepted connection. Their addresses.
    pub async fn listen(&mut self, urls: &[String], secret: &StaticSecret) -> Result<Vec<Address>, Error> {
        let ls = osis_transport::listen_all(&*self.transport, urls, secret).await?;
        let mut out = Vec::new();
        for l in ls {
            use osis_transport::Listener;
            let addr = l.address();
            let (stx, mut srx) = mpsc::channel(1);
            self.background.push(tokio::spawn(link::serve(l, LINGER, LINGER, stx)));
            let tx = self.tx.clone();
            let key = addr.key;
            self.background.push(tokio::spawn(async move {
                while let Some(link) = srx.recv().await {
                    if tx.send(Event::Accepted(link, key)).is_err() {
                        return;
                    }
                }
            }));
            out.push(addr);
        }
        Ok(out)
    }

    /// Whether `conn` runs over the unix transport, whose listener takes only this process's own
    /// uid (spec/sync-transport.md §6): a session on it is a main session.
    pub fn unix(&self, conn: ConnId) -> bool {
        self.live.get(&conn).is_some_and(|l| l.unix)
    }

    /// Ends every listener `listen` started and the discovery `discover` started (their
    /// connections go on).
    pub fn stop_background(&mut self) {
        for t in self.background.drain(..) {
            t.abort();
        }
    }

    /// Starts the transport's discovery (spec/sync-transport.md §4): what it finds comes as
    /// `Input::Discovered`, what its listeners take as accepted connections.
    pub async fn discover(&mut self) -> Result<(), Error> {
        let mut d = self.transport.discover().await?;
        let tx = self.tx.clone();
        self.background.push(tokio::spawn(async move {
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
                                if tx.send(Event::Accepted(link, key)).is_err() {
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
                    Ok(l) => Some(self.up(conn, l, true, key)),
                    Err(_) => Some(Input::Down { conn }),
                }
            }
            Event::Accepted(l, key) => {
                self.accepted += 1;
                let conn = ConnId(ConnId::ACCEPTED | self.accepted);
                Some(self.up(conn, l, false, key))
            }
            Event::Bytes(conn, bytes) => self.live.contains_key(&conn).then_some(Input::Bytes { conn, bytes }),
            Event::Taken(conn, bytes) => self.live.contains_key(&conn).then_some(Input::Taken { conn, bytes }),
            Event::Ended(conn) => self.live.remove(&conn).map(|_| Input::Closed { conn }),
            Event::Found(addr) => Some(Input::Discovered { addr }),
        }
    }

    /// A link up: its bytes and what the transport took of ours are read into events.
    fn up(&mut self, conn: ConnId, l: Link, dialed: bool, listener: [u8; 32]) -> Input {
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
        self.live.insert(conn, Live { tx, unix, tasks: [reader, taken] });
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

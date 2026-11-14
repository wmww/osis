//! The node, dials, timers and outputs (spec/sync-opens.md §1, spec/sync-transport.md).
//!
//! `Node::handle` is the whole of sync as a sans-IO step: it routes an input to its module, then
//! settles every module (store, unread, read, inbox, opens, streams, status, again while one
//! acted), then collects sessions' bytes and the earliest wake. `apply` is the one place outputs
//! are carried out, through a `Links`: the product's transports or a test's network. Sync never
//! knows how a peer is reached.
//!
//! State: connections and their sessions; dial candidates (`reach.0`, `dial.0`, grant hints,
//! link sharers, configured addresses, discovery), redial times, dial timeouts, one connection
//! per pair. Depends on every module. Not built: dialing (no candidate is dialed), restart in place
//! after a store failure (the node closes every connection and goes on), the memo clock's wake,
//! and `TransportLinks` (the tokio driver over osis-transport, behind the `driver` feature).

use crate::inbox::Inbox;
use crate::opens::Opens;
use crate::read::Read;
use crate::session::{Session, To};
use crate::status::{Status, StatusView};
use crate::store::Store;
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Error, Input, Out, Result, Scope, SyncConfig, Waiting};
use crate::unread::Unread;
use osis_base::WallMs;
use osis_crypto::NodeRng;
use osis_engine::Engine;
use osis_label::Address;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Where a node's outputs go: a transport, or a test's network. Synchronous; what comes of each
/// call comes back as `Input`s (a dial as `Up` or `Down`, a peer's bytes as `Bytes`, a close as
/// `Closed` at the other end, a wake as `Tick`).
pub trait Links {
    fn dial(&mut self, conn: ConnId, to: &Address);
    fn send(&mut self, conn: ConnId, bytes: &[u8]);
    fn close(&mut self, conn: ConnId);
    /// The node's one wake: replaces any earlier one.
    fn wake(&mut self, at: WallMs);
}

/// Carries out `out`, the one place outputs are: sends and dials in the order made, then
/// closes (a closing node's last bytes go first, spec/sync-streams.md §4 Reports), then one
/// wake, the earliest given (a wake that comes early costs one idle `Tick`; one lost would stop
/// the node).
pub fn apply(out: Vec<Out>, links: &mut impl Links) {
    let mut closes = Vec::new();
    let mut wake: Option<WallMs> = None;
    for o in out {
        match o {
            Out::Send(c, bytes) => links.send(c, &bytes),
            Out::Dial(c, to) => links.dial(c, &to),
            Out::Close(c) => closes.push(c),
            Out::Wake(at) => wake = Some(wake.map_or(at, |w| w.min(at))),
        }
    }
    for c in closes {
        links.close(c);
    }
    if let Some(at) = wake {
        links.wake(at);
    }
}

/// The driver's own state.
#[derive(Clone, Debug, Default)]
struct Driver {
    conns: BTreeMap<ConnId, Session>,
}

/// One node's sync: its engine, its store and every module.
pub struct Node {
    engine: Engine,
    store: Store,
    rng: Box<dyn NodeRng>,
    cfg: SyncConfig,
    now: WallMs,
    /// Outputs made outside `handle` (a status read): the next `handle` returns them first.
    pending: Vec<Out>,
    driver: Driver,
    opens: Opens,
    read: Read,
    unread: Unread,
    streams: Streams,
    inbox: Inbox,
    status: Status,
}

/// The `Cx` over a node's fields, borrowed apart from its modules.
macro_rules! cx {
    ($n:expr, $out:expr) => {
        Cx { engine: &mut $n.engine, store: &mut $n.store, now: $n.now, rng: &mut *$n.rng, out: $out }
    };
}

impl Node {
    /// A node over `engine`, whose ciphertext door is `store` (`Store::cipher`). Its first
    /// `handle` settles every module.
    pub fn open(engine: Engine, store: Store, cfg: SyncConfig, rng: Box<dyn NodeRng>) -> Result<Node> {
        let now = engine.now();
        Ok(Node { engine, store, rng, cfg, now, pending: Vec::new(), driver: Driver::default(), opens: Opens::default(), read: Read::default(), unread: Unread::default(), streams: Streams::default(), inbox: Inbox::default(), status: Status::default() })
    }

    /// One step: `input` taken, every module settled. The outputs must all reach `apply`.
    #[must_use = "every output must reach `apply`"]
    pub fn handle(&mut self, input: Input) -> Vec<Out> {
        let mut out = std::mem::take(&mut self.pending);
        self.now = self.now.max(self.engine.now());
        if let Err(e) = self.step(input, &mut out).and_then(|()| self.settle(&mut out)) {
            self.failed(e, &mut out);
        }
        for (c, s) in &mut self.driver.conns {
            let bytes = s.take_bytes();
            if !bytes.is_empty() {
                out.push(Out::Send(*c, bytes));
            }
        }
        if let Some(at) = self.next_wake() {
            out.push(Out::Wake(at));
        }
        out
    }

    /// The osis handle's writes and reads; after a write, `handle(Input::Wrote)`.
    pub fn engine(&mut self) -> &mut Engine {
        &mut self.engine
    }

    pub fn config(&self) -> &SyncConfig {
        &self.cfg
    }

    /// Status now (a memo value).
    pub fn status(&mut self) -> Arc<StatusView> {
        let mut out = std::mem::take(&mut self.pending);
        let v = self.status.view(&mut cx!(self, &mut out));
        self.pending = out;
        v
    }

    pub fn wait(&mut self, scope: Scope) -> Waiting {
        let mut out = std::mem::take(&mut self.pending);
        let w = self.status.wait(&mut cx!(self, &mut out), scope);
        self.pending = out;
        w
    }

    fn step(&mut self, input: Input, out: &mut Vec<Out>) -> Result<()> {
        match input {
            Input::Up { conn, peer, rank, dialed } => {
                let s = Session::new(conn, peer, dialed, rank, &mut cx!(self, out));
                self.driver.conns.insert(conn, s);
            }
            Input::Bytes { conn, bytes } => self.bytes(conn, &bytes, out),
            Input::Closed { conn } | Input::Down { conn } => self.closed(conn, out),
            Input::Tick { now } => {
                self.now = self.now.max(now);
                self.engine.set_now(self.now);
                self.engine.tick()?;
            }
            Input::Wrote => {}
        }
        Ok(())
    }

    fn bytes(&mut self, conn: ConnId, bytes: &[u8], out: &mut Vec<Out>) {
        let Some(mut s) = self.driver.conns.remove(&conn) else { return };
        let close = {
            let mut cx = cx!(self, out);
            match s.receive(bytes, &mut cx) {
                Ok(ms) => {
                    let mut close = false;
                    for m in ms {
                        match m.to() {
                            Some(To::Opens) => self.opens.on_message(&mut cx, conn, &mut s, m),
                            Some(To::Streams) => self.streams.on_message(&mut cx, conn, &mut s, m),
                            Some(To::Inbox) => self.inbox.on_message(&mut cx, conn, &mut s, m),
                            None => {
                                close = true;
                                break;
                            }
                        }
                    }
                    close
                }
                Err(_) => true,
            }
        };
        if close {
            out.push(Out::Close(conn));
            self.closed_session(conn, s, out);
        } else {
            self.driver.conns.insert(conn, s);
        }
    }

    fn closed(&mut self, conn: ConnId, out: &mut Vec<Out>) {
        if let Some(s) = self.driver.conns.remove(&conn) {
            self.closed_session(conn, s, out);
        }
    }

    /// A connection's session ended: its last bytes go (before the close, `apply`), its members
    /// close.
    fn closed_session(&mut self, conn: ConnId, mut s: Session, out: &mut Vec<Out>) {
        let bytes = s.take_bytes();
        if !bytes.is_empty() {
            out.push(Out::Send(conn, bytes));
        }
        let mut cx = cx!(self, out);
        let members: Vec<_> = self.opens.members(conn).keys().copied().collect();
        for m in members {
            self.streams.on_close(&mut cx, conn, &m, None);
        }
        self.opens.on_closed(&mut cx, conn);
    }

    /// Every module settled, again while one acted.
    fn settle(&mut self, out: &mut Vec<Out>) -> Result<()> {
        loop {
            let mut cx = cx!(self, out);
            let mut acted = cx.store.settle(cx.engine, cx.now)?;
            acted |= self.unread.settle(&mut cx)?;
            acted |= self.read.settle(&mut cx, &self.opens, &self.streams)?;
            acted |= self.inbox.settle(&mut cx, &self.opens, &self.streams)?;
            acted |= self.opens.settle(&mut cx, &self.unread)?;
            acted |= self.streams.settle(&mut cx)?;
            acted |= self.status.settle(&mut cx, &self.opens, &self.streams)?;
            if !acted {
                return Ok(());
            }
        }
    }

    /// A step failed: every connection closes (spec: a store failure reopens the node from
    /// its store; not built).
    fn failed(&mut self, e: Error, out: &mut Vec<Out>) {
        let _ = e;
        let conns: Vec<ConnId> = self.driver.conns.keys().copied().collect();
        for c in conns {
            out.push(Out::Close(c));
            self.closed(c, out);
        }
    }

    /// The earliest wake any module, the store or the engine needs.
    fn next_wake(&mut self) -> Option<WallMs> {
        let engine = self.engine.next_timer().ok().flatten().map(WallMs);
        [self.store.next_wake(), self.opens.next_wake(), self.read.next_wake(), self.unread.next_wake(), self.streams.next_wake(), self.inbox.next_wake(), self.status.next_wake(), engine].into_iter().flatten().min()
    }

    /// Tests only: a copy of this node inside a world copy (`osis_base::copying`), its clock
    /// `clock`.
    #[doc(hidden)]
    pub fn test_copy(&self, clock: Arc<dyn osis_base::Clock>) -> Result<Node> {
        osis_base::copying::copying(|| {
            Ok(Node {
                engine: self.engine.test_copy(clock.clone())?,
                store: self.store.test_copy(clock)?,
                rng: self.rng.test_copy(),
                cfg: self.cfg.clone(),
                now: self.now,
                pending: self.pending.clone(),
                driver: self.driver.clone(),
                opens: self.opens.clone(),
                read: self.read.clone(),
                unread: self.unread.clone(),
                streams: self.streams.clone(),
                inbox: self.inbox.clone(),
                status: self.status.clone(),
            })
        })
    }
}

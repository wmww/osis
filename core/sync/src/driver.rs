//! The node, dials, timers and outputs (spec/sync-opens.md §1, spec/sync-transport.md).
//!
//! `Node::handle` is the whole of sync as a sans-IO step: it routes an input to its module (and
//! each member opens reports moved to streams), then settles every module (store, unread, opens,
//! read, inbox, streams, status, again while one acted), then collects sessions' bytes and the
//! earliest wake. `apply` is the one place outputs
//! are carried out, through a `Links`: the product's transports or a test's network. Sync never
//! knows how a peer is reached.
//!
//! State: connections and their sessions; dial candidates (`reach.0`, `dial.0`, grant hints,
//! link sharers, configured addresses, discovery), redial times, dial timeouts, one connection
//! per pair. Depends on every module. Not built: dialing (no candidate is dialed), restart in place
//! after a store failure (the node closes every connection and goes on), the memo clock's wake,
//! and `TransportLinks` (the tokio driver over osis-transport, behind the `driver` feature).

use crate::inbox::Inbox;
use crate::opens::{Moved, Opens};
use crate::read::Read;
use crate::session::{Session, Sessions, To};
use crate::status::{Status, StatusView};
use crate::store::Store;
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Error, Input, Out, Result, Scope, SyncConfig, Waiting};
use crate::unread::Unread;
use osis_base::WallMs;
use osis_crypto::NodeRng;
use osis_engine::Engine;
use osis_label::Address;
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
    sessions: Sessions,
}

/// One node's sync: its engine, its store and every module.
pub struct Node {
    engine: Engine,
    store: Store,
    rng: Box<dyn NodeRng>,
    cfg: SyncConfig,
    now: WallMs,
    /// Settle rounds of the last step (tests: `rounds`).
    rounds: u64,
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
        Ok(Node { engine, store, rng, cfg, now, rounds: 0, driver: Driver::default(), opens: Opens::default(), read: Read::default(), unread: Unread::default(), streams: Streams::default(), inbox: Inbox::default(), status: Status::default() })
    }

    /// One step: `input` taken, every module settled. The outputs must all reach `apply`.
    #[must_use = "every output must reach `apply`"]
    pub fn handle(&mut self, input: Input) -> Vec<Out> {
        let mut out = Vec::new();
        self.now = self.now.max(self.engine.now());
        self.rounds = 0;
        if let Err(e) = self.step(input, &mut out).and_then(|()| self.settle(&mut out)) {
            self.failed(e, &mut out);
        }
        self.driver.sessions.take_sends(&mut out);
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

    /// Status as of the last step.
    pub fn status(&self) -> Arc<StatusView> {
        self.status.view()
    }

    pub fn wait(&mut self, scope: Scope) -> Waiting {
        self.status.wait(&mut self.engine, scope)
    }

    /// Tests only: the settle rounds the last step took (the harness caps them: a settle loop
    /// that does not end is a pair of modules undoing each other).
    #[doc(hidden)]
    pub fn rounds(&self) -> u64 {
        self.rounds
    }

    fn step(&mut self, input: Input, out: &mut Vec<Out>) -> Result<()> {
        match input {
            Input::Up { conn, peer, rank, dialed } => {
                let s = Session::new(conn, peer, dialed, rank, &mut cx!(self, out));
                self.driver.sessions.insert(s);
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
        let Some(s) = self.driver.sessions.get_mut(conn) else { return };
        let mut close = false;
        match s.receive(bytes, &mut cx!(self, out)) {
            Ok(ms) => {
                let mut moved = Vec::new();
                for m in ms {
                    let mut cx = cx!(self, out);
                    let sessions = &mut self.driver.sessions;
                    match m.to() {
                        Some(To::Opens) => self.opens.on_message(&mut cx, sessions, conn, m, &mut moved),
                        Some(To::Streams) => self.streams.on_message(&mut cx, sessions, &self.opens, conn, m),
                        Some(To::Inbox) => self.inbox.on_message(&mut cx, sessions, conn, m),
                        None => {
                            close = true;
                            break;
                        }
                    }
                    self.moved(&mut moved, out);
                }
            }
            Err(_) => close = true,
        }
        if close {
            out.push(Out::Close(conn));
            self.closed(conn, out);
        }
    }

    /// Hands each member opens reported moved to streams.
    fn moved(&mut self, moved: &mut Vec<Moved>, out: &mut Vec<Out>) {
        let mut cx = cx!(self, out);
        for m in moved.drain(..) {
            self.streams.moved(&mut cx, &mut self.driver.sessions, m);
        }
    }

    /// A connection ended: its last bytes go (before the close, `apply`), its members leave.
    fn closed(&mut self, conn: ConnId, out: &mut Vec<Out>) {
        let Some(mut s) = self.driver.sessions.remove(conn) else { return };
        let bytes = s.take_bytes();
        if !bytes.is_empty() {
            out.push(Out::Send(conn, bytes));
        }
        let mut moved = Vec::new();
        self.opens.on_closed(&mut cx!(self, out), conn, &mut moved);
        self.moved(&mut moved, out);
    }

    /// Every module settled, again while one acted: opens before read and inbox, so they act on
    /// this round's shared set.
    fn settle(&mut self, out: &mut Vec<Out>) -> Result<()> {
        let mut moved = Vec::new();
        loop {
            self.rounds += 1;
            let mut cx = cx!(self, out);
            let sessions = &mut self.driver.sessions;
            let mut acted = cx.store.settle(cx.engine, cx.now)?;
            acted |= self.unread.settle(&mut cx)?;
            acted |= self.opens.settle(&mut cx, sessions, &self.unread, &mut moved)?;
            self.moved(&mut moved, out);
            let mut cx = cx!(self, out);
            let sessions = &mut self.driver.sessions;
            acted |= self.read.settle(&mut cx, sessions, &self.opens, &self.streams)?;
            acted |= self.inbox.settle(&mut cx, sessions, &self.opens, &self.streams)?;
            acted |= self.streams.settle(&mut cx, sessions, &self.opens)?;
            acted |= self.status.settle(&mut cx, &self.opens, &self.streams, &self.read)?;
            if !acted {
                return Ok(());
            }
        }
    }

    /// A step failed: every connection closes (spec: a store failure reopens the node from
    /// its store; not built).
    fn failed(&mut self, e: Error, out: &mut Vec<Out>) {
        let _ = e;
        let conns: Vec<ConnId> = self.driver.sessions.conns().collect();
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
                rounds: self.rounds,
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

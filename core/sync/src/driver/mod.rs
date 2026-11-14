//! The node, dials, timers and outputs (spec/sync-opens.md §1, spec/sync-transport.md).
//!
//! `Node::handle` is the whole of sync as a sans-IO step: it routes an input to its module (and
//! each member opens reports moved to streams), then settles every module (leave, store, unread,
//! opens, read, inbox, streams, status, life, again while one acted),
//! then decides its dials (`dials`), closes what a module closed, and collects sessions' bytes
//! and the earliest wake. `apply` is the one place outputs are carried out, through a `Links`:
//! the product's transports (`links`) or a test's network. Sync never knows how a peer is reached.
//!
//! State: connections and their sessions; dial candidates, redial times and the pair rule's held
//! dials (`dials`); whether a store failure's stretch is under way. A step that fails closes
//! every connection and restarts the modules from the store (once per stretch, until a durable
//! commit of either store lands): what they keep in memory goes, the store's memory part stays.
//! A connection this node dialed closes once it shares nothing and nothing is under way on it
//! (`keep_or_close`).

pub mod dials;
#[cfg(feature = "driver")]
pub mod links;

pub use dials::{DISCOVERED_KEEP, MAX_PEERS, REDIAL_MS};

use crate::inbox::Inbox;
use crate::opens::{Moved, Opens, Reported};
use crate::read::Read;
use crate::session::{Incoming, Session, Sessions, To};
use crate::status::{NetView, Status, SyncStatus};
use crate::store::Store;
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Error, Input, Out, Result, Scope, SyncConfig, Waiting};
use dials::{Dials, NodePeers, Why};
use osis_base::Tid;
use crate::unread::Unread;
use crate::leave::Leave;
use crate::life::Life;
use osis_base::{SyncId, WallMs};
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
    sessions: Sessions,
    /// Reported positions streams gave this step, for opens.
    reported: Vec<Reported>,
    dials: Dials,
    /// What the store follows of the engine.
    store: crate::store::Follow,
    /// The memo effects the dial peers follow.
    fx: dials::PeersFx,
    /// Opens' `changed_end` the dials last followed.
    changed: u64,
    /// The actors this node proves for, as of the last owner's write.
    proving: Vec<Tid>,
    /// A store failure's stretch, while no commit of the store has landed since it began.
    failing: Option<Stretch>,
    /// Restarts in place so far (tests).
    restarts: u64,
    /// The engine store's writes of unknown outcome as of the last look (`engine_reloaded`).
    engine_unknown: u64,
    /// `Engine::loads` as of the last look (`engine_reloaded`).
    engine_loads: u64,
    /// What the client port's owner has to answer or forget (`Node::port`).
    port: Vec<PortEvent>,
    /// Outputs made outside a step (`Node::redeem`), carried out with the next step's.
    pending: Vec<Out>,
    /// The owner's client connections (`Node::connect`), dialing or up, and the last one's
    /// number.
    clients: std::collections::BTreeSet<ConnId>,
    next_client: u64,
}

/// The client port as the node's owner sees it (spec/wire.md §11.2 kinds 24-29): sync carries
/// these requests and their answers on its sessions and judges none of them. Served: a peer's
/// requests on any connection. Used: the owner's own requests on its client connections
/// (`Node::connect`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortEvent {
    /// A request of the peer's (Auth, Call, Sub, Unsub): answered with `Node::port_answer`.
    Request(ConnId, crate::session::RequestId, Box<osis_proto::Msg>),
    /// A client connection came up: its requests may go (`Node::port_request`).
    Up(ConnId),
    /// The answer to the owner's request (`Node::port_request`): Reply, Ok or Error.
    Reply(ConnId, crate::session::RequestId, Box<osis_proto::Msg>),
    /// A Notify on a client connection.
    Notify(ConnId, Box<osis_proto::Msg>),
    /// A connection ended, or a client connection's dial failed: its port session goes, and
    /// every request of the owner's on it is unanswered.
    Closed(ConnId),
}

/// The wait after a step fails before the node's next wake, doubling while steps go on failing
/// up to `RETRY_MAX_MS` (the store's own recovery pace). Minor consequence: at 0 a failing store
/// is tried again at the speed of the loop (a wake due now fails and wakes again at once); at
/// infinity a failed node waits for an input from outside.
pub const RETRY_FIRST_MS: u64 = 1_000;
/// The longest wait between tries (minor consequence: the node comes back up to this late after
/// the device works again; at 0 as `RETRY_FIRST_MS`'s, at infinity it stops trying by itself).
pub const RETRY_MAX_MS: u64 = 60_000;

/// A store failure's stretch.
#[derive(Clone, Copy, Debug)]
struct Stretch {
    /// The durable commits (`Node::committed`) when the modules restarted: one since ends the
    /// stretch.
    committed: u64,
    /// No wake before this; and the wait after the next failure.
    retry_at: WallMs,
    wait: u64,
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
    leave: Leave,
    life: Life,
}

/// The `Cx` over a node's fields, borrowed apart from its modules.
macro_rules! cx {
    ($n:expr, $out:expr) => {
        Cx { engine: &mut $n.engine, store: &mut $n.store, now: $n.now, rng: &mut *$n.rng, out: $out, policy: &$n.cfg.policy }
    };
}

impl Node {
    /// A node over `engine`, whose ciphertext door is `store` (`Store::cipher`). Its first
    /// `handle` settles every module.
    pub fn open(engine: Engine, store: Store, cfg: SyncConfig, rng: Box<dyn NodeRng>) -> Result<Node> {
        let now = engine.now();
        let store_handle = store.clone();
        let mut driver = Driver { engine_loads: engine.loads(), ..Driver::default() };
        driver.dials.set_node(cfg.key.map(|k| k.0), &cfg.policy);
        Ok(Node { engine, store, rng, cfg, now, rounds: 0, driver, opens: Opens::default(), read: Read::default(), unread: Unread::default(), streams: Streams::new(store_handle), inbox: Inbox::default(), status: Status::default(), leave: Leave::default(), life: Life::default() })
    }

    /// One step: `input` taken, every module settled. The outputs must all reach `apply`.
    #[must_use = "every output must reach `apply`"]
    pub fn handle(&mut self, input: Input) -> Vec<Out> {
        let mut out = std::mem::take(&mut self.driver.pending);
        self.now = self.now.max(self.engine.now());
        self.driver.sessions.set_now(self.now);
        self.rounds = 0;
        self.engine_reloaded(&mut out);
        // the compaction trigger runs at each step (spec/sync-compaction.md §1): what its snapshots
        // cover is judged by the settle after it
        let r = self.step(input, &mut out).and_then(|()| self.engine.compactions().map(drop).map_err(Error::from)).and_then(|()| self.settle(&mut out)).and_then(|()| self.flush());
        // a durable commit since the restart ends the stretch, whatever this step did
        if self.driver.failing.is_some_and(|f| self.committed() > f.committed) {
            self.driver.failing = None;
        }
        if let Err(e) = r {
            self.failed(e, &mut out);
        }
        // a write of this step whose outcome was unknown: the engine reads its store again
        self.engine_reloaded(&mut out);
        self.dial(&mut out);
        self.keep_or_close(&mut out);
        for c in self.driver.sessions.closing() {
            out.push(Out::Close(c));
            self.closed(c, &mut out);
        }
        self.driver.sessions.take_sends(&mut out);
        // a failing stretch wakes no sooner than its retry (a wake due now would fail again)
        let floor = self.driver.failing.map(|f| f.retry_at);
        if let Some(at) = self.next_wake().map(|at| floor.map_or(at, |f| at.max(f))) {
            out.push(Out::Wake(at));
        }
        out
    }

    /// The osis handle's writes and reads; after a write, `handle(Input::Wrote)`.
    pub fn engine(&mut self) -> &mut Engine {
        &mut self.engine
    }

    /// The node's store per sync ID, for reads (status views, tests).
    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn config(&self) -> &SyncConfig {
        &self.cfg
    }

    /// The owner changed its configuration; the next step follows it (`Input::Wrote`).
    pub fn set_config(&mut self, cfg: SyncConfig) {
        self.cfg = cfg;
        self.driver.dials.set_node(self.cfg.key.map(|k| k.0), &self.cfg.policy);
    }

    /// Where the node's dials stand.
    pub fn dials(&self) -> &Dials {
        &self.driver.dials
    }

    /// Tests only: restarts in place after a store failure so far.
    #[doc(hidden)]
    pub fn restarts(&self) -> u64 {
        self.driver.restarts
    }

    /// Tests only: entries of a read S that wait for a read secret yet are not parked
    /// (`store::Follow::lost_parks`).
    #[doc(hidden)]
    pub fn lost_parks(&mut self) -> Result<Vec<(SyncId, osis_base::BlobId)>> {
        self.driver.store.lost_parks(&mut self.engine, &self.store)
    }

    /// Tests only: connection `c`'s session.
    #[doc(hidden)]
    pub fn session(&self, c: ConnId) -> Option<&Session> {
        self.driver.sessions.get(c)
    }

    /// How every sync ID held or shared stands, as of the last step (spec/sync-status.md §3).
    /// O(sync IDs × their sources): `status_of` reads one.
    pub fn status(&self) -> BTreeMap<SyncId, SyncStatus> {
        self.status.all(&self.net())
    }

    /// How S stands, as of the last step: O(its sources).
    pub fn status_of(&self, s: &SyncId) -> Option<SyncStatus> {
        self.status.of(s, &self.net())
    }

    /// Connections up now, whichever side dialed.
    pub fn connections(&self) -> usize {
        self.driver.sessions.conns().count()
    }

    /// The client port's requests and ended connections since the last call, in order.
    pub fn port(&mut self) -> Vec<PortEvent> {
        std::mem::take(&mut self.driver.port)
    }

    /// Answers the client port's request `id` on `conn`; the bytes to send. Nothing for a
    /// connection gone.
    #[must_use = "every output must reach `apply`"]
    pub fn port_answer(&mut self, conn: ConnId, id: crate::session::RequestId, m: osis_proto::Msg) -> Vec<Out> {
        let Some(s) = self.driver.sessions.get_mut(conn) else { return Vec::new() };
        s.answer(id, m);
        let bytes = s.take_bytes();
        if bytes.is_empty() { Vec::new() } else { vec![Out::Send(conn, bytes)] }
    }

    /// Dials `to` as a client connection (spec/sync-transport.md §6), the owner's own: it proves
    /// nothing and shares nothing, so it carries only the client port's requests, kept until the
    /// owner ends it (`disconnect`) or it closes (`PortEvent::Closed`). `PortEvent::Up` once it is
    /// up. No dial candidate, never counted against `max_peers`.
    #[must_use = "every output must reach `apply`"]
    pub fn connect(&mut self, to: Address) -> (ConnId, Vec<Out>) {
        self.driver.next_client += 1;
        let conn = ConnId(ConnId::CLIENT | self.driver.next_client);
        self.driver.clients.insert(conn);
        self.driver.sessions.set_now(self.now.max(self.engine.now()));
        self.driver.sessions.dialing(conn);
        let mut out = vec![Out::Dial(conn, to)];
        self.wake(&mut out);
        (conn, out)
    }

    /// Ends client connection `conn` (`connect`); `PortEvent::Closed` follows.
    #[must_use = "every output must reach `apply`"]
    pub fn disconnect(&mut self, conn: ConnId) -> Vec<Out> {
        let mut out = Vec::new();
        if self.driver.clients.contains(&conn) {
            out.push(Out::Close(conn));
            self.closed(conn, &mut out);
            self.wake(&mut out);
        }
        out
    }

    /// Sends the owner's request `m` (Auth, Call, Sub, Unsub) on client connection `conn`, under
    /// the window; its answer comes as `PortEvent::Reply` with the id returned. `None`: the
    /// connection is not up.
    #[must_use = "every output must reach `apply`"]
    pub fn port_request(&mut self, conn: ConnId, m: osis_proto::Msg) -> Option<(crate::session::RequestId, Vec<Out>)> {
        if !self.driver.clients.contains(&conn) {
            return None;
        }
        self.driver.sessions.set_now(self.now.max(self.engine.now()));
        let id = self.driver.sessions.get_mut(conn)?.request(To::Port, m);
        let mut out = Vec::new();
        self.driver.sessions.take_sends(&mut out);
        self.wake(&mut out);
        Some((id, out))
    }

    /// Pushes a Notify on `conn` under the push rule (spec/sync-streams.md §2), or with `now`
    /// whatever the room (a lapse, the one small Notify that must go); `None`: it did not go, for
    /// lack of room (or the connection is gone).
    #[must_use = "every output must reach `apply`"]
    pub fn port_push(&mut self, conn: ConnId, m: osis_proto::Msg, now: bool) -> Option<Vec<Out>> {
        let s = self.driver.sessions.get_mut(conn)?;
        if now {
            s.push_now(m);
        } else if !s.push(m) {
            return None;
        }
        let mut out = Vec::new();
        self.driver.sessions.take_sends(&mut out);
        Some(out)
    }

    /// The node's wake as it stands, outside a step.
    fn wake(&mut self, out: &mut Vec<Out>) {
        if let Some(at) = self.next_wake() {
            out.push(Out::Wake(at));
        }
    }

    /// Redeems a share link (spec/sync-inbox.md §6): first contact, kept until the join is held
    /// elsewhere. `Done` once the join is written.
    pub fn redeem(&mut self, link: &osis_label::ShareLink) -> Waiting {
        let mut out = Vec::new();
        let w = self.inbox.redeem(&mut cx!(self, &mut out), link);
        self.driver.pending.extend(out);
        w
    }

    /// Writes a bundle of the sync IDs `ids` held here (spec/sync-streams.md §6, spec/wire.md
    /// §12): each one's path, then its entries with their blobs, durable ones only.
    pub fn export_bundle(&self, ids: &[SyncId], out: &mut dyn std::io::Write) -> Result<()> {
        use osis_label::Record;
        let proto = |e: osis_label::Error| Error::Proto(osis_proto::Error::Label(e));
        let mut w = osis_label::BundleWriter::new(out).map_err(proto)?;
        let mut sent = std::collections::BTreeSet::new();
        for s in ids {
            let Some(path) = self.store.path(s)? else { continue };
            w.record(&Record::Path { label: *s, steps: path.steps.clone() }).map_err(proto)?;
            for e in self.store.entries(s)? {
                if e.class != osis_label::Class::Durable {
                    continue;
                }
                if sent.insert(e.blob) {
                    let Some(b) = self.store.bytes(&e.blob)? else { continue };
                    w.record(&Record::Blob(b)).map_err(proto)?;
                }
                w.record(&Record::Entry { label: *s, blob: e.blob, wrap: e.wrap, stamp: e.stamp }).map_err(proto)?;
            }
        }
        w.finish().map_err(proto)?;
        Ok(())
    }

    /// Takes a bundle as a source with no cursor (spec/sync-streams.md §6); then `handle`
    /// (`Input::Wrote`) settles what it brought.
    pub fn import_bundle(&mut self, bundle: &mut dyn std::io::Read) -> Result<()> {
        let mut out = Vec::new();
        let r = self.streams.import(&mut cx!(self, &mut out), bundle);
        self.driver.pending.extend(out);
        r
    }

    /// No request, fill or Hello outstanding on any connection (spec/sync-status.md §3).
    pub fn idle(&self) -> bool {
        self.driver.sessions.idle()
    }

    /// Where a wait on `scope` stands (spec/sync-status.md §3): status's for its sync IDs, and
    /// for `All` and `Deliveries` every delivery this node owes taken (the engine owes none).
    pub fn wait(&mut self, scope: Scope) -> Waiting {
        let net = NetView { streams: &self.streams, unread: &self.unread };
        let engine = &mut self.engine;
        let w = self.status.wait(&net, scope, |t| Ok(engine.carrying(t)?.into_iter().collect()));
        let mut owes = || engine.deliveries().map_or(true, |d| !d.is_empty());
        match (w, scope) {
            (Waiting::Done, Scope::All | Scope::Deliveries) if owes() => Waiting::Pending,
            (w, _) => w,
        }
    }

    fn net(&self) -> NetView<'_> {
        NetView { streams: &self.streams, unread: &self.unread }
    }

    /// Tests only: where a member of S opened by `by` would end if ended now (`opens`' `until`,
    /// spec/sync-opens.md §6).
    #[doc(hidden)]
    pub fn member_until(&mut self, s: &SyncId, by: &crate::types::Credential) -> crate::types::Position {
        let mut out = Vec::new();
        crate::opens::holds::member_until(&mut cx!(self, &mut out), s, by).unwrap_or(0)
    }

    /// Tests only: the settle rounds the last step took (the harness caps them: a settle loop
    /// that does not end is a pair of modules undoing each other).
    #[doc(hidden)]
    pub fn rounds(&self) -> u64 {
        self.rounds
    }

    fn step(&mut self, input: Input, out: &mut Vec<Out>) -> Result<()> {
        match input {
            Input::Up { conn, peer, rank, dialed, listener } => {
                if dialed {
                    self.driver.dials.up(conn);
                }
                let mut s = Session::new(conn, peer, dialed, rank, listener, &mut cx!(self, out));
                if self.driver.clients.contains(&conn) {
                    s.client();
                    self.driver.port.push(PortEvent::Up(conn));
                }
                self.driver.sessions.insert(s);
            }
            Input::Taken { conn, bytes } => self.driver.sessions.taken(conn, bytes),
            Input::Bytes { conn, bytes } => self.bytes(conn, &bytes, out),
            Input::Closed { conn } | Input::Down { conn } => self.closed(conn, out),
            Input::Tick { now } => {
                self.now = self.now.max(now);
                self.engine.set_now(self.now);
                self.engine.tick()?;
                for (conn, _) in self.driver.sessions.tick(self.now) {
                    out.push(Out::Close(conn));
                    self.closed(conn, out);
                }
            }
            Input::Wrote => {
                self.driver.dials.configure(&self.cfg.dial, self.now);
                self.proving(out)?;
            }
            Input::Discovered { addr } => self.driver.dials.offer(Why::Discovered, addr, self.now),
        }
        Ok(())
    }

    /// spec/sync-opens.md §1: a connection proves once, at its start: one where this node proved
    /// its own and now acts for an actor it did not prove there closes, and its dialer dials
    /// again. The actors it acts for move only by its owner's writes (an account taken up, a link
    /// key held), so they are read at `Wrote`, compared, and the sessions walked only on a move.
    fn proving(&mut self, out: &mut Vec<Out>) -> Result<()> {
        let mut now: Vec<Tid> = self.engine.provers(false)?.into_iter().map(|(_, r)| r.tid()).collect();
        now.sort();
        if now == self.driver.proving {
            return Ok(());
        }
        let stale: Vec<ConnId> = self.driver.sessions.conns().filter(|c| self.driver.sessions.get(*c).is_some_and(|s| !s.proved().is_empty() && now.iter().any(|a| !s.proved().contains(a)))).collect();
        self.driver.proving = now;
        for c in stale {
            self.driver.dials.redial_now(c);
            out.push(Out::Close(c));
            self.closed(c, out);
        }
        Ok(())
    }

    /// The dials the node makes now (spec/sync-opens.md §1): the dial peers that moved, a change
    /// that could make a peer share something, the pauses ended, within `max_peers`.
    fn dial(&mut self, out: &mut Vec<Out>) {
        let now = self.now;
        let d = &mut self.driver;
        d.dials.settle_peers(&mut NodePeers { engine: &mut self.engine, store: &self.store, fx: &mut d.fx }, now);
        let inbox = &self.inbox;
        if let Some(hints) = d.fx.hints_moved(|| inbox.dial_hints().into_iter().filter_map(|h| Some(Address { url: h.urls.first()?.clone(), key: h.dialable })).collect()) {
            d.dials.hint(&hints, now);
        }
        let changed = self.opens.changed_end();
        if changed != d.changed {
            d.changed = changed;
            d.dials.changed(now);
        }
        d.dials.tick(now);
        for (conn, to) in d.dials.dial(now, self.cfg.max_peers) {
            d.sessions.dialing(conn);
            out.push(Out::Dial(conn, to));
        }
    }

    /// Durable commits of the node's two stores (the sync store and the engine's) since they
    /// opened: any one landing ends a store failure's stretch.
    fn committed(&self) -> u64 {
        self.store.committed().saturating_add(self.engine.store_writes().committed)
    }

    /// Keep or close (spec/sync-opens.md §1), for the connections this node dialed (it never
    /// closes one it serves for sharing nothing, spec/sync-transport.md §5; those it dialed are
    /// at most `max_peers` sharing ones plus those about to close, so each step reads them all):
    /// one whose shared set has no member, with nothing of opens under way, no deposit to it that
    /// may land, and a quiet peer (`Session::quiet`: whatever the peer sent in answer to this
    /// side has arrived) closes; its candidate is dialed again after a change.
    fn keep_or_close(&mut self, out: &mut Vec<Out>) {
        let mut close = Vec::new();
        for c in self.driver.dials.dialed_conns() {
            if !self.driver.sessions.get(c).is_some_and(|s| s.dialer && s.closing().is_none()) || !self.opens.idle(c) || self.inbox.may_deposit(c) {
                continue;
            }
            if self.driver.sessions.get_mut(c).is_some_and(Session::quiet) {
                close.push(c);
            }
        }
        for c in close {
            self.driver.dials.closed_quiet(c, self.now);
            out.push(Out::Close(c));
            self.closed(c, out);
        }
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
                    let proved = matches!(m, Incoming::Proved);
                    match m.to() {
                        Some(To::Opens) => self.opens.on_message(&mut cx, sessions, &self.unread, conn, m, &mut moved),
                        Some(To::Streams) => self.streams.on_message(&mut cx, sessions, &self.opens, conn, m, &mut self.driver.reported),
                        Some(To::Read) => self.read.on_message(&mut cx, sessions, conn, m),
                        Some(To::Inbox) => self.inbox.on_message(&mut cx, sessions, &self.opens, &self.streams, conn, m),
                        Some(To::Port) => match m {
                            Incoming::Request(id, m) => self.driver.port.push(PortEvent::Request(conn, id, Box::new(m))),
                            Incoming::Reply(_, id, m) => self.driver.port.push(PortEvent::Reply(conn, id, Box::new(m))),
                            // a Notify only where this node is the client
                            Incoming::Push(m) if self.driver.clients.contains(&conn) => self.driver.port.push(PortEvent::Notify(conn, Box::new(m))),
                            _ => {}
                        },
                        None => {
                            close = true;
                            break;
                        }
                    }
                    // after opens took it: the actors it names for the connection are known
                    if proved {
                        self.inbox.proved(conn, &crate::inbox::Links { sessions: &mut self.driver.sessions, opens: &self.opens, streams: &self.streams });
                    }
                    self.moved(&mut moved, out);
                    if self.driver.sessions.get(conn).is_some_and(|s| s.closing().is_some()) {
                        close = true;
                        break;
                    }
                }
            }
            Err(_) => close = true,
        }
        if close {
            out.push(Out::Close(conn));
            self.closed(conn, out);
        }
    }

    /// Hands each member opens reported moved to streams (and counts it for `max_peers`), then
    /// streams' reported positions to opens.
    fn moved(&mut self, moved: &mut Vec<Moved>, out: &mut Vec<Out>) {
        let mut cx = cx!(self, out);
        for m in moved.drain(..) {
            self.status.moved(&self.driver.sessions, &self.opens, &m);
            self.read.moved(&m, &self.opens);
            self.inbox.moved(&m, &crate::inbox::Links { sessions: &mut self.driver.sessions, opens: &self.opens, streams: &self.streams });
            let c = m.conn();
            self.driver.dials.sharing(c, !self.opens.members(c).is_empty());
            self.streams.moved(&mut cx, &mut self.driver.sessions, &self.opens, m, &mut self.driver.reported);
        }
        self.reports(out);
    }

    /// Streams' reported positions to opens; the members that closes go back to streams, until
    /// nothing is left.
    fn reports(&mut self, out: &mut Vec<Out>) {
        let mut moved = Vec::new();
        while !self.driver.reported.is_empty() {
            let mut cx = cx!(self, out);
            self.opens.on_reported(&mut cx, &mut self.driver.sessions, &self.unread, &mut self.driver.reported, &mut moved);
            for m in moved.drain(..) {
                let c = m.conn();
                self.read.moved(&m, &self.opens);
                self.driver.dials.sharing(c, !self.opens.members(c).is_empty());
                self.streams.moved(&mut cx, &mut self.driver.sessions, &self.opens, m, &mut self.driver.reported);
            }
        }
    }

    /// A connection ended: its last bytes go (before the close, `apply`), its members leave.
    fn closed(&mut self, conn: ConnId, out: &mut Vec<Out>) {
        // a dial that lost its pair to a live connection is held by it (spec/sync-opens.md §1)
        let lost = self.opens.lost_to(conn).filter(|w| self.driver.sessions.get(*w).is_some());
        let s = self.driver.sessions.remove(conn);
        self.driver.dials.ended(conn, lost, self.now);
        if self.driver.clients.remove(&conn) && s.is_none() {
            self.driver.port.push(PortEvent::Closed(conn));
        }
        let Some(mut s) = s else { return };
        let bytes = s.take_bytes();
        if !bytes.is_empty() {
            out.push(Out::Send(conn, bytes));
        }
        self.streams.closed(conn);
        let mut moved = Vec::new();
        self.opens.on_closed(&mut cx!(self, out), conn, &mut moved);
        self.moved(&mut moved, out);
        self.inbox.on_closed(conn);
        self.driver.port.push(PortEvent::Closed(conn));
        // a store failure here reopens the node, whose start drops the same entries
        let _ = self.store.gone(crate::store::Source::Conn(conn));
    }

    /// Every module settled, again while one acted or the engine's per-entry values moved
    /// (`Engine::follow`, before each module's settle: a module's `due` sees an entry move only
    /// once it is refreshed): opens before read and inbox, so they act on this round's shared set.
    fn settle(&mut self, out: &mut Vec<Out>) -> Result<()> {
        let mut moved = Vec::new();
        loop {
            self.rounds += 1;
            let mut cx = cx!(self, out);
            let sessions = &mut self.driver.sessions;
            let mut acted = cx.engine.follow()?;
            // leave first: what this node syncs, which every other module follows
            acted |= self.leave.settle(&mut crate::leave::Live { cx: &mut cx, sources: &self.streams, opens: &self.opens })?;
            acted |= self.driver.store.settle(cx.engine, cx.store, cx.now)?;
            acted |= self.unread.settle(&mut cx)?;
            acted |= self.opens.settle(&mut cx, sessions, &self.unread, &mut moved)?;
            self.moved(&mut moved, out);
            let mut cx = cx!(self, out);
            let sessions = &mut self.driver.sessions;
            let mut fetches = Vec::new();
            acted |= cx.engine.follow()?;
            acted |= self.read.settle(&mut cx, sessions, &self.opens, &self.streams, &self.status, &self.unread, &mut fetches)?;
            for (conn, s, b) in fetches {
                let mut cx = cx!(self, out);
                self.streams.fetch_again(&mut cx, &mut self.driver.sessions, &self.opens, conn, s, b, &mut self.driver.reported);
            }
            let mut cx = cx!(self, out);
            let sessions = &mut self.driver.sessions;
            acted |= cx.engine.follow()?;
            acted |= self.inbox.settle(&mut cx, sessions, &self.opens, &self.streams, &self.status)?;
            acted |= self.streams.settle(&mut cx, sessions, &self.opens, &mut self.driver.reported)?;
            self.reports(out);
            let mut cx = cx!(self, out);
            let mut pulls = Vec::new();
            acted |= self.status.settle(&mut cx, &self.opens, &self.streams, &self.read, &self.unread, &mut pulls)?;
            for conn in pulls {
                let mut cx = cx!(self, out);
                self.streams.pull_again(&mut cx, &mut self.driver.sessions, &self.opens, conn, &mut self.driver.reported);
                acted = true;
            }
            self.reports(out);
            // the lifecycle duties the engine judges (`life`), on what this round settled
            let net = NetView { streams: &self.streams, unread: &self.unread };
            let (status, opens, store) = (&self.status, &self.opens, &self.store);
            // a sync ID no peer shares is heard out at once (the rule a leave's wait reads)
            acted |= self.life.settle(&mut self.engine, &self.store, |s| status.heard_out_or_alone(opens, store, s, &net))?;
            // the engine read its store again (a forgetting drop): every feed followed is stale,
            // so the settle ends and the step restarts the modules (`engine_reloaded`)
            if !acted || self.engine.loads() != self.driver.engine_loads {
                return Ok(());
            }
        }
    }

    /// The end of a step: opens writes what changed of its records and evicts past
    /// `RECORD_BUDGET` (each record with every row of it and what was charged to it).
    fn flush(&mut self) -> Result<()> {
        self.opens.flush(&mut self.store).map(drop)
    }

    /// A step failed (a store failure): every connection closes, and the modules restart from
    /// the store, once per stretch until a commit of the store lands (scenario store-reopen).
    /// The store's memory part (ephemeral entries) stays as it is: a failure judges none of it.
    /// Nothing the failed step queued goes (every step sends all it queued, so that is all a
    /// session holds): a frame may tell of what the failure undid (an Applied of a cursor not
    /// stored, a record answered but not written, opens' rows of the step); the peers see a
    /// dropped connection, which every rule already survives.
    fn failed(&mut self, e: Error, out: &mut Vec<Out>) {
        let _ = e;
        let conns: Vec<ConnId> = self.driver.sessions.conns().collect();
        for c in conns {
            if let Some(s) = self.driver.sessions.get_mut(c) {
                drop(s.take_bytes());
            }
        }
        self.close_all(out);
        if let Some(f) = &mut self.driver.failing {
            f.wait = f.wait.saturating_mul(2).min(RETRY_MAX_MS);
            f.retry_at = WallMs(self.now.0.saturating_add(f.wait));
            return;
        }
        self.driver.failing = Some(Stretch { committed: self.committed(), retry_at: WallMs(self.now.0.saturating_add(RETRY_FIRST_MS)), wait: RETRY_FIRST_MS });
        self.driver.restarts += 1;
        self.restart_modules(out);
    }

    /// Every module starts again from the store, then settles (a store failure, or the engine
    /// having read its store again).
    fn restart_modules(&mut self, out: &mut Vec<Out>) {
        self.opens = Opens::default();
        self.read = Read::default();
        self.unread = Unread::default();
        self.streams = Streams::new(self.store.clone());
        self.inbox = Inbox::default();
        self.status = Status::default();
        self.leave = Leave::default();
        self.life = Life::default();
        self.driver.changed = 0;
        self.driver.store = crate::store::Follow::default();
        // the dial peers and hints follow the modules' and the engine's stamps afresh
        self.driver.fx = dials::PeersFx::default();
        self.driver.dials.forget_peers();
        if self.settle(out).and_then(|()| self.flush()).is_err() {
            self.close_all(out);
        }
    }

    /// The engine read its store again since the last look (`Engine::loads`: a write of unknown
    /// outcome, or a drop that forgot things: lost access, a self-removal placed, unsyncing,
    /// spec/sync-judgement.md §3), which replaces every index the modules follow (memo feeds,
    /// stamps): every connection closes and the modules start again from the store, as at an open
    /// (spec/sync-ids.md §5: the store is the truth after a failure). One rule for every reload:
    /// the settle ends at the round it happened in (`settle`), and the step restarts here. Whether
    /// it restarted.
    fn engine_reloaded(&mut self, out: &mut Vec<Out>) -> bool {
        let unknown = self.engine.store_writes().unknown;
        if unknown == self.driver.engine_unknown && self.engine.loads() == self.driver.engine_loads {
            return false;
        }
        self.driver.engine_unknown = unknown;
        // a write of unknown outcome: the engine reads its store at its next transaction
        let r = self.engine.run(|_| Ok(()));
        self.driver.engine_loads = self.engine.loads();
        if let Err(e) = r {
            self.failed(e.into(), out);
            return true;
        }
        self.close_all(out);
        self.restart_modules(out);
        true
    }

    fn close_all(&mut self, out: &mut Vec<Out>) {
        let conns: Vec<ConnId> = self.driver.sessions.conns().collect();
        for c in conns {
            out.push(Out::Close(c));
            self.closed(c, out);
        }
    }

    /// The earliest wake any module, the store or the engine needs.
    fn next_wake(&mut self) -> Option<WallMs> {
        let engine = self.engine.next_timer().ok().flatten().map(WallMs);
        let clock = self.engine.clock_next();
        [self.driver.sessions.next_wake(), self.driver.dials.next_wake(), self.store.next_wake(), self.opens.next_wake(), self.read.next_wake(), self.unread.next_wake(), self.streams.next_wake(), self.inbox.next_wake(), self.status.next_wake(), engine, clock].into_iter().flatten().min()
    }

    /// Tests only: a copy of this node inside a world copy (`osis_base::copying`), its clock
    /// `clock`.
    #[doc(hidden)]
    pub fn test_copy(&self, clock: Arc<dyn osis_base::Clock>) -> Result<Node> {
        osis_base::copying::copying(|| {
            let store = self.store.test_copy(clock.clone())?;
            let mut streams = self.streams.clone();
            streams.set_store(store.clone());
            Ok(Node {
                engine: self.engine.test_copy(clock)?,
                store,
                rng: self.rng.test_copy(),
                cfg: self.cfg.clone(),
                now: self.now,
                rounds: self.rounds,
                driver: self.driver.clone(),
                opens: self.opens.clone(),
                read: self.read.clone(),
                unread: self.unread.clone(),
                streams,
                inbox: self.inbox.clone(),
                status: self.status.clone(),
                leave: self.leave.clone(),
                life: self.life.clone(),
            })
        })
    }
}

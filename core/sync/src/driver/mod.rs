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
use crate::unread::Unread;
use crate::leave::Leave;
use crate::life::Life;
use osis_base::{Mono, SyncId, WallMs};
use osis_crypto::NodeRng;
use osis_engine::Engine;
use osis_blob::Address;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Where a node's outputs go: a transport, or a test's network. Synchronous; what comes of each
/// call comes back as `Input`s (a dial as `Up` or `Down`, a peer's bytes as `Bytes`, a close as
/// `Closed` at the other end, a wake as `Tick`).
pub trait Links {
    fn dial(&mut self, conn: ConnId, to: &Address);
    fn send(&mut self, conn: ConnId, bytes: &[u8]);
    fn close(&mut self, conn: ConnId);
    /// Reads `conn`'s bytes (`on`) or stops reading them until told again (`Out::Read`); a
    /// connection up is read.
    fn read(&mut self, conn: ConnId, on: bool);
    /// The node's one wake, on its monotonic clock (`Engine::mono`): replaces any earlier one.
    fn wake(&mut self, at: Mono);
}

/// Carries out `out`, the one place outputs are: sends and dials in the order made, then
/// closes (a closing node's last bytes go first, spec/sync-streams.md §4 Reports), then one
/// wake, the earliest given (a wake that comes early costs one idle `Tick`; one lost would stop
/// the node).
pub fn apply(out: Vec<Out>, links: &mut impl Links) {
    let mut closes = Vec::new();
    let mut wake: Option<Mono> = None;
    for o in out {
        match o {
            Out::Send(c, bytes) => links.send(c, &bytes),
            Out::Dial(c, to) => links.dial(c, &to),
            Out::Close(c) => closes.push(c),
            Out::Read(c, on) => links.read(c, on),
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
    /// The actors this node proves for, each with the key it proves with, as of the last
    /// owner's write.
    proving: Vec<osis_store::Claim>,
    /// A store failure's stretch, while no commit of the store has landed since it began.
    failing: Option<Stretch>,
    /// Restarts in place so far (tests).
    restarts: u64,
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
    retry_at: Mono,
    wait: u64,
}

/// One node's sync: its engine, its store and every module.
pub struct Node {
    engine: Engine,
    store: Store,
    rng: Box<dyn NodeRng>,
    cfg: SyncConfig,
    /// The wall clock, for stamps and what judges them: the latest reading, so it never goes
    /// back for the node (spec/sync-streams.md §1 Waits).
    now: WallMs,
    /// The monotonic clock every wait kept in memory runs on.
    mono: Mono,
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

/// What acted in one settle round (`Node::settle`), shown when its loop guard fires.
#[derive(Clone, Copy)]
enum Act {
    InboxStart,
    Follow,
    Leave,
    Store,
    Unread,
    Opens,
    Read,
    Inbox,
    Streams,
    Status,
    Pull,
    Life,
    Admit,
}

const ACTS: [&str; 13] = ["inbox start", "engine follow", "leave", "store", "unread", "opens", "read", "inbox", "streams", "status", "pull again", "life", "admit"];

/// The `Act`s of one round, a bit each.
#[derive(Clone, Copy)]
struct Acts(u16);

impl Acts {
    /// `acted`, noted as `a`'s when true.
    fn by(&mut self, a: Act, acted: bool) -> bool {
        self.0 |= u16::from(acted) << a as u16;
        acted
    }
}

impl std::fmt::Debug for Acts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(ACTS.iter().enumerate().filter(|(i, _)| self.0 >> i & 1 == 1).map(|(_, n)| n)).finish()
    }
}

/// The `Cx` over a node's fields, borrowed apart from its modules.
macro_rules! cx {
    ($n:expr, $out:expr) => {
        Cx { engine: &mut $n.engine, store: &mut $n.store, now: $n.now, mono: $n.mono, rng: &mut *$n.rng, out: $out, policy: &$n.cfg.policy }
    };
}

impl Node {
    /// A node over `engine`, whose ciphertext door is `store` (`Store::cipher`). Its first
    /// `handle` settles every module.
    pub fn open(engine: Engine, store: Store, cfg: SyncConfig, rng: Box<dyn NodeRng>) -> Node {
        let (now, mono) = (engine.now(), engine.mono());
        let store_handle = store.clone();
        let mut driver = Driver { engine_loads: engine.loads(), ..Driver::default() };
        driver.dials.set_node(cfg.key.map(|k| k.0), &cfg.policy);
        Node { engine, store, rng, cfg, now, mono, rounds: 0, driver, opens: Opens::default(), read: Read::default(), unread: Unread::default(), streams: Streams::new(store_handle), inbox: Inbox::default(), status: Status::default(), leave: Leave::default(), life: Life::default() }
    }

    /// One step: `input` taken, every module settled. The outputs must all reach `apply`.
    #[must_use = "every output must reach `apply`"]
    pub fn handle(&mut self, input: Input) -> Vec<Out> {
        let mut out = std::mem::take(&mut self.driver.pending);
        self.read_clocks();
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
            self.closed(c, "closed here", &mut out);
        }
        self.driver.sessions.take_sends(&mut out);
        // a failing stretch wakes no sooner than its retry (a wake due now would fail again)
        let floor = self.driver.failing.map(|f| f.retry_at);
        if let Some(at) = osis_base::costs::scoped("next wake", || self.next_wake()).map(|at| floor.map_or(at, |f| at.max(f))) {
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

    /// Blob `b`'s bytes held here (`store::blob_bytes`).
    pub fn blob_bytes(&mut self, b: &osis_base::BlobId) -> Result<Option<Vec<u8>>> {
        crate::store::blob_bytes(&mut self.engine, &self.store, b)
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

    /// Tests only: the opens (`Opens`).
    #[doc(hidden)]
    pub fn opens(&self) -> &Opens {
        &self.opens
    }

    /// Tests only: read (`Read`).
    #[doc(hidden)]
    pub fn read(&self) -> &crate::read::Read {
        &self.read
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
        self.read_clocks();
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
            self.closed(conn, "disconnected by the owner", &mut out);
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
        self.read_clocks();
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

    /// Redeems a link (spec/sync-inbox.md §6) for `joiner` (an own thing or a thing its own
    /// things administer, such as the node's account, spec/permissions.md §7): a share link's
    /// first contact, kept until the join is held elsewhere, `Done` once the join is written; a
    /// locator's, `Done` once the node closure holds its target (spec/sync-set.md §4).
    pub fn redeem(&mut self, link: &osis_blob::Link, joiner: osis_base::Tid) -> Waiting {
        // its follow time runs from now (`Policy::follow_link_ms`)
        self.read_clocks();
        let mut out = Vec::new();
        let w = self.inbox.redeem(&mut cx!(self, &mut out), link, joiner);
        self.driver.pending.extend(out);
        w
    }

    /// Whether link K (a locator: its target) is being redeemed here (`redeem`): not joined
    /// yet or the join not yet held at a source, and not ended or given up
    /// (`Policy::follow_link_ms`).
    pub fn redeeming(&self, k: &osis_base::Tid) -> bool {
        self.inbox.redeeming(k)
    }

    /// Where a wait on `scope` stands (spec/sync-status.md §3): status's for its sync IDs.
    pub fn wait(&mut self, scope: Scope) -> Waiting {
        let net = NetView { streams: &self.streams, unread: &self.unread };
        let engine = &mut self.engine;
        let carrying = match scope {
            Scope::Thing(t) => engine.carrying(&t).map(|x| x.into_iter().collect()).map_err(Into::into),
            Scope::All => Ok(Vec::new()),
        };
        // by the rosters, not by who has S open: a sync ID just joined is open at no peer yet;
        // a failed read keeps the wait waiting
        let w = self.status.wait(&net, scope, |_| carrying, |s| engine.others_may_hold(s).unwrap_or(true));
        // a wait on all also waits for each sealed fire this node sends to be delivered: a write
        // of this node's held nowhere else until a peer takes it
        match (scope, w) {
            (Scope::All, Waiting::Done) if engine.delivering() => Waiting::Pending,
            (_, w) => w,
        }
    }

    fn net(&self) -> NetView<'_> {
        NetView { streams: &self.streams, unread: &self.unread }
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
                let how = match (dialed, self.driver.dials.dialed_to(conn)) {
                    (true, Some(to)) => format!("dialed {}", osis_blob::address_to_text(&to)),
                    (true, None) => "dialed".into(),
                    (false, _) => "accepted".into(),
                };
                let detail = format!("{} up: {how}", conn_name(conn));
                self.report_conn(conn, detail);
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
            Input::Closed { conn } => self.closed(conn, "ended", out),
            Input::Down { conn, error } => self.closed(conn, &error, out),
            Input::Tick => {
                self.engine.set_now(self.now);
                self.engine.tick()?;
                for (conn, why) in self.driver.sessions.tick(self.mono) {
                    out.push(Out::Close(conn));
                    self.closed(conn, why.0, out);
                }
            }
            Input::Wrote => {
                self.driver.dials.configure(&self.cfg.dial, self.mono);
                self.proving(out)?;
            }
            Input::Discovered { addr } => self.driver.dials.offer(Why::Discovered, addr, self.mono),
        }
        Ok(())
    }

    /// spec/sync-opens.md §1: a connection proves once, at its start: one where this node now
    /// acts for a claim it did not act for when it proved there (none, a policy proving nothing,
    /// counts) closes, and its dialer dials again. What it acts for moves by writes (a link key
    /// held, an account made or joined), so it is read at `Wrote`, compared, and the sessions
    /// walked only on a move.
    fn proving(&mut self, out: &mut Vec<Out>) -> Result<()> {
        let mut now: Vec<osis_store::Claim> = self.engine.proving()?.provers.iter().map(|p| p.claim()).collect();
        now.sort();
        if now == self.driver.proving {
            return Ok(());
        }
        let stale: Vec<ConnId> = self.driver.sessions.conns().filter(|c| self.driver.sessions.get(*c).is_some_and(|s| s.acted_for().is_some_and(|was| now.iter().any(|a| !was.contains(a))))).collect();
        self.driver.proving = now;
        for c in stale {
            self.driver.dials.redial_now(c);
            out.push(Out::Close(c));
            self.closed(c, "this node acts for a thing it did not prove there", out);
        }
        Ok(())
    }

    /// The dials the node makes now (spec/sync-opens.md §1): the dial peers that moved, a change
    /// that could make a peer share something, the pauses ended, within `max_peers`.
    fn dial(&mut self, out: &mut Vec<Out>) {
        let now = self.mono;
        let d = &mut self.driver;
        d.dials.settle_peers(&mut NodePeers { engine: &mut self.engine, store: &self.store, fx: &mut d.fx }, now);
        let (inbox, engine) = (&self.inbox, &mut self.engine);
        // the links' peers and the held grant signals' (spec/sync-inbox.md §5 Grant signal)
        let all = || {
            let mut hs = inbox.dial_hints();
            hs.extend(engine.signal_hints().unwrap_or_default());
            hs.into_iter().filter_map(|h| Some(Address { url: h.urls.first()?.clone(), key: h.dialable })).collect()
        };
        if let Some(hints) = d.fx.hints_moved(all) {
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
            self.driver.dials.closed_quiet(c, self.mono);
            out.push(Out::Close(c));
            self.closed(c, "shares nothing", out);
        }
    }

    fn bytes(&mut self, conn: ConnId, bytes: &[u8], out: &mut Vec<Out>) {
        let Some(s) = self.driver.sessions.get_mut(conn) else { return };
        let r = s.receive(bytes, &mut cx!(self, out));
        self.dispatch(conn, r, out);
        // past the node-wide bound on bytes received, the connection holding the most closes
        // (spec/sync-transport.md §5 Served connections)
        while let Some(c) = self.driver.sessions.over_in() {
            out.push(Out::Close(c));
            self.closed(c, "holds the most received past the node's bound", out);
        }
    }

    /// The requests that waited for room and fit now, each handed on with what its connection
    /// reads after it (`Sessions::admit`). Whether one went.
    fn admit(&mut self, out: &mut Vec<Out>) -> bool {
        let admitted = self.driver.sessions.admit(&mut cx!(self, out));
        let any = !admitted.is_empty();
        for (conn, r) in admitted {
            self.dispatch(conn, r, out);
        }
        any
    }

    /// What `conn`'s session read (`Session::receive`), each message to its module; a close
    /// closes the connection.
    fn dispatch(&mut self, conn: ConnId, r: std::result::Result<Vec<Incoming>, crate::session::Close>, out: &mut Vec<Out>) {
        let mut close = None;
        match r {
            Ok(ms) => {
                let mut moved = Vec::new();
                for m in ms {
                    let mut cx = cx!(self, out);
                    let sessions = &mut self.driver.sessions;
                    let proved = matches!(m, Incoming::Proved);
                    match m.to() {
                        Some(To::Opens) => self.opens.on_message(&mut cx, sessions, &self.unread, conn, m, &mut moved),
                        Some(To::Streams) => self.streams.on_message(&mut cx, sessions, &self.opens, conn, m, &mut self.driver.reported),
                        Some(To::Read) => self.read.on_message(conn, m),
                        Some(To::Inbox) => self.inbox.on_message(&mut cx, sessions, &self.opens, &self.streams, conn, m),
                        Some(To::Port) => match m {
                            Incoming::Request(id, m) => self.driver.port.push(PortEvent::Request(conn, id, Box::new(m))),
                            Incoming::Reply(_, id, m) => self.driver.port.push(PortEvent::Reply(conn, id, Box::new(m))),
                            // a Notify only where this node is the client
                            Incoming::Push(m) if self.driver.clients.contains(&conn) => self.driver.port.push(PortEvent::Notify(conn, Box::new(m))),
                            _ => {}
                        },
                        None => {
                            close = Some("a message for no module");
                            break;
                        }
                    }
                    // after opens took it: the actors it names for the connection are known
                    if proved {
                        self.inbox.proved(conn, &crate::inbox::Links { sessions: &mut self.driver.sessions, opens: &self.opens, streams: &self.streams });
                    }
                    self.moved(&mut moved, out);
                    if self.driver.sessions.get(conn).is_some_and(|s| s.closing().is_some()) {
                        close = Some("closed here");
                        break;
                    }
                }
            }
            Err(e) => close = Some(e.0),
        }
        if let Some(why) = close {
            out.push(Out::Close(conn));
            self.closed(conn, why, out);
        }
    }

    /// Hands each member opens reported moved to every module that follows members (and counts
    /// it for `max_peers`), then streams' reported positions to opens.
    fn moved(&mut self, moved: &mut Vec<Moved>, out: &mut Vec<Out>) {
        self.hand(moved, out);
        self.reports(out);
    }

    /// Each member in `moved` to status, read, inbox, dials and streams: the one place a moved
    /// member goes, whatever moved it.
    fn hand(&mut self, moved: &mut Vec<Moved>, out: &mut Vec<Out>) {
        let mut cx = cx!(self, out);
        for m in moved.drain(..) {
            osis_base::costs::scoped("status", || self.status.moved(&self.driver.sessions, &self.opens, &m));
            osis_base::costs::scoped("inbox", || self.inbox.moved(&m, &crate::inbox::Links { sessions: &mut self.driver.sessions, opens: &self.opens, streams: &self.streams }));
            if let Some(c) = m.conn() {
                self.driver.dials.sharing(c, !self.opens.members(c).is_empty());
            }
            self.streams.moved(&mut cx, &mut self.driver.sessions, &self.opens, m, &mut self.driver.reported);
        }
    }

    /// Streams' reported positions to opens; the members that closes are handed on (`hand`),
    /// until nothing is left.
    fn reports(&mut self, out: &mut Vec<Out>) {
        let mut moved = Vec::new();
        while !self.driver.reported.is_empty() {
            let mut cx = cx!(self, out);
            self.opens.on_reported(&mut cx, &mut self.driver.sessions, &self.unread, &mut self.driver.reported, &mut moved);
            self.hand(&mut moved, out);
        }
    }

    /// A connection ended: its last bytes go (before the close, `apply`), its members leave.
    /// Connection `conn` ended or its dial failed, `why` (a module's own reason first).
    fn closed(&mut self, conn: ConnId, why: &str, out: &mut Vec<Out>) {
        // a dial that lost its pair to a live connection is held by it (spec/sync-opens.md §1)
        let lost = self.opens.lost_to(conn).filter(|w| self.driver.sessions.get(*w).is_some());
        let to = self.driver.dials.dialed_to(conn).map(|a| osis_blob::address_to_text(&a));
        let detail = match (self.driver.sessions.get(conn), to) {
            (Some(s), to) => format!("{} closed: {}{}", conn_name(conn), s.closing().unwrap_or(why), to.map(|t| format!(" (dialed {t})")).unwrap_or_default()),
            (None, Some(to)) => format!("{} dial to {to} failed: {why}", conn_name(conn)),
            (None, None) => String::new(),
        };
        if !detail.is_empty() {
            self.report_conn(conn, detail);
        }
        let s = self.driver.sessions.remove(conn);
        self.driver.dials.ended(conn, lost, self.mono);
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
        self.opens.closed(conn, &mut moved);
        self.moved(&mut moved, out);
        self.inbox.on_closed(conn);
        self.read.closed(conn);
        self.driver.port.push(PortEvent::Closed(conn));
        // a store failure here reopens the node, whose start drops the same entries
        let _ = self.store.gone(crate::store::Source::Conn(conn));
    }

    /// A connection came up or ended, or a dial failed (`DiagnosticKind::Connection`): for a log
    /// (`osis serve`, `diag --follow`), never read back. Rate-limited per remote: a dial per
    /// address dialed (this node's own dials, as many as its dial set), every accepted
    /// connection together and every client one together (unproven when they come up: a remote
    /// opening and dropping them floods only their bucket, never a dial failure).
    fn report_conn(&mut self, conn: ConnId, detail: String) {
        let remote = match self.driver.dials.dialed_to(conn) {
            Some(to) => osis_blob::address_to_text(&to).into_bytes(),
            None if conn.accepted() => b"accepted".to_vec(),
            None if conn.0 & ConnId::CLIENT != 0 => b"client".to_vec(),
            None => b"dialed".to_vec(),
        };
        self.engine.report_from(osis_engine::Diagnostic { kind: osis_engine::DiagnosticKind::Connection, tids: Vec::new(), commit: None, peer: None, detail }, remote);
    }

    /// Every module settled, again while one acted or the engine's per-entry values moved:
    /// opens before read and inbox, so they act on this round's shared set. One `Engine::follow`
    /// per round, before the modules: a module's `due` sees an entry move only once it is
    /// refreshed, and a module that writes the engine acts, so the next round's follow refreshes
    /// what it moved. A round ends the loop only when its follow moved nothing and no module
    /// wrote after it.
    fn settle(&mut self, out: &mut Vec<Out>) -> Result<()> {
        let mut moved = Vec::new();
        let mut guard = osis_base::loop_guard::LoopGuard::new("node-sync settle loop (Node::settle)");
        loop {
            self.rounds += 1;
            let mut acts = Acts(0);
            // requests that waited for room the last round freed
            let mut acted = acts.by(Act::Admit, self.admit(out));
            let mut cx = cx!(self, out);
            let sessions = &mut self.driver.sessions;
            // inbox's start first: what it has the engine follow is part of the sync set, so only
            // then does the engine let go of what it keeps for sync IDs not read
            acted |= acts.by(Act::InboxStart, osis_base::costs::scoped("inbox", || self.inbox.start(&mut cx))?);
            if acted {
                cx.engine.forget_unread()?;
            }
            // the round's one follow: every module below sees what earlier rounds wrote
            let followed = cx.engine.follow()?;
            osis_base::costs::count("settle follows moved", u64::from(followed));
            acted |= acts.by(Act::Follow, followed);
            // leave first: what this node syncs, which every other module follows
            acted |= acts.by(Act::Leave, self.leave.settle(&mut crate::leave::Live { cx: &mut cx, status: &self.status })?);
            acted |= acts.by(Act::Store, osis_base::costs::scoped("driver store", || self.driver.store.settle(cx.engine, cx.store, cx.now))?);
            acted |= acts.by(Act::Unread, self.unread.settle(&mut cx)?);
            acted |= acts.by(Act::Opens, self.opens.settle(&mut cx, sessions, &self.unread, &mut moved)?);
            self.moved(&mut moved, out);
            let mut cx = cx!(self, out);
            let sessions = &mut self.driver.sessions;
            let (mut fetches, mut gives) = (Vec::new(), Vec::new());
            acted |= acts.by(Act::Read, self.read.settle(&mut cx, sessions, &self.opens, &self.streams, &self.status, &self.unread, &mut fetches, &mut gives)?);
            for (conn, s, b, head) in gives {
                self.inbox.offer_on(conn, s, b, head);
            }
            for (conn, s, ask) in fetches {
                let mut cx = cx!(self, out);
                self.streams.ask(&mut cx, &mut self.driver.sessions, &self.opens, conn, s, ask, &mut self.driver.reported);
            }
            let mut cx = cx!(self, out);
            let sessions = &mut self.driver.sessions;
            acted |= acts.by(Act::Inbox, osis_base::costs::scoped("inbox", || self.inbox.settle(&mut cx, sessions, &self.opens, &self.streams, &self.status))?);
            acted |= acts.by(Act::Streams, self.streams.settle(&mut cx, sessions, &self.opens, &mut self.driver.reported)?);
            self.reports(out);
            let mut cx = cx!(self, out);
            let mut pulls = Vec::new();
            acted |= acts.by(Act::Status, osis_base::costs::scoped("status", || self.status.settle(&mut cx, &self.opens, &self.streams, &self.read, &self.unread, &self.leave, &mut pulls))?);
            for conn in pulls {
                let mut cx = cx!(self, out);
                self.streams.pull_again(&mut cx, &mut self.driver.sessions, &self.opens, conn, &mut self.driver.reported);
                acted = acts.by(Act::Pull, true);
            }
            self.reports(out);
            // the lifecycle duties the engine judges (`life`), on what this round settled
            let (status, opens, store) = (&self.status, &self.opens, &self.store);
            // a sync ID no peer is to be waited for on is heard out at once (the rule a leave's
            // wait reads)
            acted |= acts.by(Act::Life, self.life.settle(&mut self.engine, &mut LifeHears { status, opens, store })?);
            // the engine read its store again (a write of unknown outcome): every feed followed is
            // stale, so the settle ends and the step restarts the modules (`engine_reloaded`)
            if !acted || self.engine.loads() != self.driver.engine_loads {
                return Ok(());
            }
            guard.round(acts, || self.settle_bound());
        }
    }

    /// The most settle rounds one step can take (debug builds, `LoopGuard`): each act a round
    /// runs again for is one module moving one sync ID's or connection's state, and each of those
    /// settles once every module has read it, so a step takes at most every module acting once
    /// per sync ID and connection. At 0 every step that acts panics; at infinity a settle loop of
    /// two modules undoing each other's acts hangs the node instead of failing.
    fn settle_bound(&self) -> (u64, String) {
        let (syncs, conns) = (self.store.syncs().len(), self.driver.sessions.conns().count());
        (ACTS.len() as u64 * (syncs + conns + 1) as u64, format!("{syncs} sync IDs, {conns} connections"))
    }

    /// The end of a step: opens writes what changed of its records and evicts past
    /// `RECORD_BUDGET` (each record with every row of it and what was charged to it).
    fn flush(&mut self) -> Result<()> {
        for id in self.opens.flush(&mut self.store)? {
            self.inbox.record_gone(id);
            self.status.record_gone(id);
        }
        for id in self.opens.unloaded() {
            self.streams.record_left(id);
        }
        Ok(())
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
            f.retry_at = self.mono.after(f.wait);
            return;
        }
        self.driver.failing = Some(Stretch { committed: self.committed(), retry_at: self.mono.after(RETRY_FIRST_MS), wait: RETRY_FIRST_MS });
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

    /// The engine read its store again since the last look (`Engine::loads`), or owes it (a
    /// failed write, `Engine::reload_owed`): that replaces every index the modules follow (memo feeds,
    /// stamps): every connection closes and the modules start again from the store, as at an open
    /// (spec/sync-ids.md §5: the store is the truth after a failure). One rule for every reload:
    /// the settle ends at the round it happened in (`settle`), and the step restarts here. Whether
    /// it restarted.
    fn engine_reloaded(&mut self, out: &mut Vec<Out>) -> bool {
        if !self.engine.reload_owed() && self.engine.loads() == self.driver.engine_loads {
            return false;
        }
        // a failed write: the engine reads its store at its next transaction
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
            self.closed(c, "the node restarted", out);
        }
    }

    /// The earliest wake any module, the store or the engine needs.
    /// The node's next wake, on its monotonic clock: the earliest of every wait (kept on it) and
    /// every time a stamped value is judged by (on the wall clock, as far ahead of the wall
    /// clock's reading now: a wall clock moved before it comes is followed at the next step).
    fn next_wake(&mut self) -> Option<Mono> {
        let engine = self.engine.next_timer().ok().flatten().map(WallMs);
        let clock = self.engine.clock_next();
        let wall = [self.store.next_wake(), self.read.next_wake(), engine, clock].into_iter().flatten().min();
        let (wall_now, mono) = (self.engine.now(), self.engine.mono());
        let wall = wall.map(|t| mono.after(t.0.saturating_sub(wall_now.0)));
        [self.driver.sessions.next_wake(), self.driver.dials.next_wake(), self.opens.next_wake(), self.streams.next_wake(), self.inbox.next_wake(), self.status.next_wake(), wall].into_iter().flatten().min()
    }

    /// Reads the clocks into the node's step (`now` and `mono` never go back).
    fn read_clocks(&mut self) {
        self.now = self.now.max(self.engine.now());
        self.mono = self.mono.max(self.engine.mono());
        self.driver.sessions.set_now(self.now, self.mono);
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
                mono: self.mono,
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

/// How a connection is named in a diagnostic: `d` dialed, `a` accepted, `c` the owner's client
/// connection, then its number.
fn conn_name(c: ConnId) -> String {
    let (tag, n) = if c.accepted() {
        ("a", c.0 & !ConnId::ACCEPTED)
    } else if c.0 & ConnId::CLIENT != 0 {
        ("c", c.0 & !ConnId::CLIENT)
    } else {
        ("d", c.0)
    };
    format!("connection {tag}{n}")
}

/// What life reads of sync (`life::Hears`).
struct LifeHears<'a> {
    status: &'a Status,
    opens: &'a Opens,
    store: &'a Store,
}

impl crate::life::Hears for LifeHears<'_> {

    fn timed_heard(&mut self, engine: &mut Engine, s: &SyncId, passed: bool) -> Result<bool> {
        if !self.opens.waited(engine, self.store, s, true)? {
            return Ok(true);
        }
        Ok(passed && self.status.sourced(s) && crate::leave::own_elsewhere(engine, self.store, s)?)
    }
}

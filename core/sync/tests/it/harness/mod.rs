//! The one sync test harness (notes/sync-test-harness.md): a deterministic world of product
//! nodes (engine, store, `osis_sync::Node`) in one process, one manual clock that jumps to the
//! next wake (each node reading it through its own skew), a seeded rng, and a network of real
//! encoded frames routed by the reachability model (`reach`). Every node output goes through
//! `osis_sync::apply` into the network (`Net`, the test `Links`), and every node input through
//! `World::deliver`, the one place a node is stepped: a test can reach a node's engine and status
//! but never its `handle`, so no test can drop an output. Faults are content-blind: the network
//! loses, repeats and delays sends (`Loss`), partitions and cuts; a node's device fails a durable
//! write (`DiskFault`) or loses power; a hostile node is an honest one whose frames pass through
//! a `Lie` (`lies`). Fixtures are worlds built once per process through the product's own flows
//! and copied per test (`fixture`). Random layers write a `Vec<Step>` and replay it with `play`;
//! a failure prints the script, `OSIS_SYNC_SHRINK=1` shrinks it.

#![allow(dead_code)]

pub mod history;
pub mod lies;
pub mod reach;
pub mod scripted;

use lies::{Lie, Liar};
use osis_base::testenv::Script;
use osis_base::{Clock, ManualClock, Tid, WallMs};
use osis_crypto::{RngCore, SeededRng};
use osis_engine::Engine;
use osis_label::Address;
use osis_store::{Fault, Faults, MemoryBackend, MemoryRoot};
use osis_sync::{ConnId, Input, Links, Node, NodeKey, Out, Store, SyncConfig, apply};
use reach::{Reach, Route, Uplink, Who};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

/// Deliveries one world may make before it panics as a storm, unless a test sets its own
/// (`World::cap`). The rule-test layer's cap (notes/sync-test-harness.md, Enforcement).
pub const RULE_CAP: u64 = 2_000;

/// Settle rounds one step may take before the world panics: a settle loop that never ends is
/// two modules undoing each other's acts. A round runs again only for an act a module reads, so
/// a step takes a few. At 0 every step fails; at infinity such a loop hangs the test instead of
/// failing it.
pub const ROUND_CAP: u64 = 16;

/// How far ahead `run` looks for a wake before it calls the world quiet: an hour of simulated
/// time (`World::horizon_ms`). At 0, quiet is an empty queue, timers never run; at infinity a
/// node with a periodic timer is never quiet and runs into the delivery cap.
pub const HORIZON_MS: u64 = 3_600_000;

/// The world's start time (any fixed value).
pub const START: WallMs = WallMs(1_700_000_000_000);

/// A node's clock: the world's, moved by the node's skew (`World::skew`).
#[derive(Debug)]
pub struct NodeClock {
    world: Arc<ManualClock>,
    skew: AtomicI64,
}

impl Clock for NodeClock {
    fn now_wall_ms(&self) -> WallMs {
        WallMs(self.world.now_wall_ms().0.saturating_add_signed(self.skew.load(Ordering::SeqCst)))
    }
}

/// A node's durable state (engine and store, each a backend and its root record) on one device
/// with one fault plan: it survives a power loss, and the node reopens over it.
#[derive(Clone)]
struct Disks {
    engine: (MemoryBackend, MemoryRoot),
    store: (MemoryBackend, MemoryRoot),
    faults: Faults,
}

impl Disks {
    fn new() -> Disks {
        let f = Faults::new();
        let pair = || (MemoryBackend::with_faults(f.clone()), MemoryRoot::with_faults(f.clone()));
        Disks { engine: pair(), store: pair(), faults: f }
    }

    fn power_cut(&self) {
        self.engine.0.power_cut();
        self.engine.1.power_cut();
        self.store.0.power_cut();
        self.store.1.power_cut();
    }

    /// Tests of copies: inside the same `osis_base::copying` as the node's copy, so the copy's
    /// handles are the copied node's (one plan stays one plan).
    fn test_copy(&self) -> Disks {
        Disks { engine: (self.engine.0.test_copy(), self.engine.1.test_copy()), store: (self.store.0.test_copy(), self.store.1.test_copy()), faults: self.faults.test_copy() }
    }
}

/// One world node.
pub struct WNode {
    pub node: Node,
    disks: Disks,
    /// The node's store, the handle its node holds (tests reach its rows directly).
    pub store: Store,
    clock: Arc<NodeClock>,
    pub key: NodeKey,
    /// Its account (`Engine::create_account`).
    pub account: Option<Tid>,
    /// Its account's profile thing, made with the account.
    pub profile: Option<Tid>,
}

/// One delivery, as `World::trace` records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seen {
    Up { node: usize, conn: ConnId, dialed: bool, rank: u8 },
    Bytes { node: usize, conn: ConnId, len: usize },
    Taken { node: usize, conn: ConnId, bytes: u64 },
    Closed { node: usize, conn: ConnId },
    Down { node: usize, conn: ConnId },
    Tick { node: usize, at: WallMs },
    Wrote { node: usize },
    Discovered { node: usize, key: [u8; 32] },
}

impl Seen {
    fn of(node: usize, input: &Input) -> Seen {
        match input {
            Input::Up { conn, rank, dialed, .. } => Seen::Up { node, conn: *conn, dialed: *dialed, rank: *rank },
            Input::Bytes { conn, bytes } => Seen::Bytes { node, conn: *conn, len: bytes.len() },
            Input::Taken { conn, bytes } => Seen::Taken { node, conn: *conn, bytes: *bytes },
            Input::Closed { conn } => Seen::Closed { node, conn: *conn },
            Input::Down { conn } => Seen::Down { node, conn: *conn },
            Input::Tick { now } => Seen::Tick { node, at: *now },
            Input::Wrote => Seen::Wrote { node },
            Input::Discovered { addr } => Seen::Discovered { node, key: addr.key },
        }
    }
}

/// The network's content-blind faults, per send of bytes, each in thousandths: the send is lost
/// and its connection resets (`drop`: an ordered stream never delivers past a hole, so both ends
/// are told it closed); it arrives, then its connection resets (`dup`: its sender cannot tell it
/// arrived and sends it again on a later connection, the one way a message repeats over an
/// ordered stream, which never repeats within itself); or it is held back 1..=`delay_ms` ms
/// (`delay`), later bytes on its connection queued behind it, so delay reorders across
/// connections, never within one. Drawn from the world's seed in send order; all zero, nothing
/// is drawn.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Loss {
    pub drop: u16,
    pub dup: u16,
    pub delay: u16,
    pub delay_ms: u64,
}

impl Loss {
    pub const NONE: Loss = Loss { drop: 0, dup: 0, delay: 0, delay_ms: 0 };

    fn none(&self) -> bool {
        self.drop == 0 && self.dup == 0 && (self.delay == 0 || self.delay_ms == 0)
    }
}

/// What a device does at a planned durable write (`osis_store::Fault`), named here so a printed
/// script compiles with `use crate::harness::script::*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskFault {
    /// The write fails without effect.
    Fail,
    /// It reads as written, but its sync fails: a power loss drops it.
    Unsynced,
    /// Power loss at that write: the node restarts in place over what reached its disks.
    Crash,
}

impl DiskFault {
    fn store(self) -> Fault {
        match self {
            DiskFault::Fail => Fault::Fail,
            DiskFault::Unsynced => Fault::Unsynced,
            DiskFault::Crash => Fault::Crash,
        }
    }
}

/// The network: links between world nodes, the inputs in flight (queued now, or held back to a
/// time), the wakes asked.
#[derive(Clone, Default)]
pub struct Net {
    pub reach: Reach,
    /// Each end of each connection up: (node, its conn) -> (peer, the peer's conn).
    links: BTreeMap<(usize, ConnId), (usize, ConnId)>,
    queue: VecDeque<(usize, Input)>,
    /// Inputs held back (`Loss::delay`), by (due, order).
    delayed: BTreeMap<(WallMs, u64), (usize, Input)>,
    /// Per receiving end, the due time of its last held-back input: later ones wait behind it.
    held_until: BTreeMap<(usize, ConnId), WallMs>,
    held: u64,
    /// The world's time, as the network last saw it.
    now: WallMs,
    /// Each node's one wake (`Links::wake` replaces it), in world time.
    wakes: BTreeMap<usize, WallMs>,
    /// Each node's clock skew (`World::skew`): its wakes come in its own time.
    skew: BTreeMap<usize, i64>,
    /// Node pairs a partition separates (lower index first).
    cut_off: BTreeSet<(usize, usize)>,
    online: Vec<bool>,
    accepted: Vec<u64>,
    /// Bytes carried so far.
    pub bytes: u64,
    /// Bytes each end sent on each connection: the transport takes them at once (no buffer), so
    /// each send is answered `Taken` with the total.
    written: BTreeMap<(usize, ConnId), u64>,
    /// Hostile peers: bytes a deaf node is sent, and bytes a mute node sends, are lost (the
    /// transport still takes them).
    pub deaf: BTreeSet<usize>,
    pub mute: BTreeSet<usize>,
    /// Silent routes: a dial to one of these nodes neither comes up nor fails (the dialer's
    /// timeout ends it).
    pub hang: BTreeSet<usize>,
    /// Every dial made: (dialer, its conn, target key).
    pub dials: Vec<(usize, ConnId, [u8; 32])>,
    /// Every dial that came up: (dialer, target node).
    pub ups: Vec<(usize, usize)>,
    pub loss: Loss,
    /// What the faults did so far: (lost, arrived then reset, held back).
    pub faulted: (u64, u64, u64),
    rng_seed: u64,
    ephemerals: u64,
    draws: u64,
}

/// splitmix64: one deterministic draw.
fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

impl Net {
    fn blocked(&self, a: Who, b: Who) -> bool {
        match (a, b) {
            (Who::Node(x), Who::Node(y)) => self.cut_off.contains(&(x.min(y), x.max(y))),
            _ => false,
        }
    }

    /// A fresh ephemeral key for a dialer (spec/sync-transport.md §1): deterministic per world.
    fn ephemeral(&mut self) -> NodeKey {
        self.ephemerals += 1;
        let mut k = [0u8; 32];
        SeededRng::from_u64(self.rng_seed ^ self.ephemerals.rotate_left(17)).fill_bytes(&mut k);
        NodeKey(k)
    }

    /// The next fault draw, in 0..1000.
    fn draw(&mut self) -> u64 {
        self.draws += 1;
        mix(self.rng_seed ^ self.draws.wrapping_mul(0x2545_f491_4f6c_dd1d)) % 1000
    }

    /// `input` to `to`'s end `tc`, `delay` ms from now and never before what that end already
    /// waits for.
    fn push(&mut self, to: usize, tc: ConnId, input: Input, delay: u64) {
        let behind = self.held_until.get(&(to, tc)).copied().filter(|t| *t > self.now);
        let due = WallMs(self.now.0.saturating_add(delay));
        let due = behind.map_or(due, |b| b.max(due));
        if due > self.now {
            self.held += 1;
            self.delayed.insert((due, self.held), (to, input));
            self.held_until.insert((to, tc), due);
        } else {
            self.queue.push_back((to, input));
        }
    }

    /// Moves every held-back input due by now to the queue, in order.
    fn release(&mut self) {
        while let Some(e) = self.delayed.first_entry() {
            if e.key().0 > self.now {
                break;
            }
            let (to, input) = e.remove();
            self.queue.push_back((to, input));
        }
    }

    fn dial(&mut self, from: usize, conn: ConnId, to: &Address) {
        self.dials.push((from, conn, to.key));
        if self.reach.node_of(&to.key).is_some_and(|t| self.hang.contains(&t)) {
            return;
        }
        let route = self.reach.node_of(&to.key).filter(|t| *t != from && self.online.get(*t) == Some(&true)).and_then(|t| Some((t, self.reach.route(from, t, &to.url, |a, b| self.blocked(a, b))?)));
        let Some((target, route)) = route else {
            self.queue.push_back((from, Input::Down { conn }));
            return;
        };
        let rank = match route {
            Route::Lan(_) => 0,
            Route::Public | Route::Punch(_) => 1,
            Route::Relay(_) => 2,
        };
        let n = self.accepted.get_mut(target).map(|a| {
            *a += 1;
            *a
        });
        let accepted = ConnId(ConnId::ACCEPTED | n.unwrap_or(0));
        let eph = self.ephemeral();
        self.ups.push((from, target));
        self.links.insert((from, conn), (target, accepted));
        self.links.insert((target, accepted), (from, conn));
        self.queue.push_back((from, Input::Up { conn, peer: NodeKey(to.key), rank, dialed: true, listener: NodeKey(to.key) }));
        self.queue.push_back((target, Input::Up { conn: accepted, peer: eph, rank, dialed: false, listener: NodeKey(to.key) }));
    }

    fn send(&mut self, from: usize, conn: ConnId, bytes: &[u8]) {
        // bytes on a connection the peer already closed are lost, as on a transport
        let Some((to, tc)) = self.links.get(&(from, conn)).copied() else { return };
        self.bytes += bytes.len() as u64;
        let w = self.written.entry((from, conn)).or_default();
        *w += bytes.len() as u64;
        let total = *w;
        if !self.mute.contains(&from) && !self.deaf.contains(&to) {
            self.carry(from, conn, to, tc, bytes);
        }
        self.queue.push_back((from, Input::Taken { conn, bytes: total }));
    }

    /// `bytes` from `from`'s end `conn` to `to`'s end `tc`, through the faults.
    fn carry(&mut self, from: usize, conn: ConnId, to: usize, tc: ConnId, bytes: &[u8]) {
        let bytes = || Input::Bytes { conn: tc, bytes: bytes.to_vec() };
        if self.loss.none() {
            return self.push(to, tc, bytes(), 0);
        }
        let (l, r) = (self.loss, self.draw());
        let (drop, dup, delay) = (u64::from(l.drop), u64::from(l.dup), u64::from(l.delay));
        if r < drop {
            self.faulted.0 += 1;
            self.reset(from, conn);
        } else if r < drop + dup {
            self.faulted.1 += 1;
            self.push(to, tc, bytes(), 0);
            self.reset(from, conn);
        } else if r < drop + dup + delay && l.delay_ms > 0 {
            self.faulted.2 += 1;
            let d = 1 + self.draw() * l.delay_ms / 1000;
            self.push(to, tc, bytes(), d);
        } else {
            self.push(to, tc, bytes(), 0);
        }
    }

    fn close(&mut self, from: usize, conn: ConnId) {
        if let Some((to, tc)) = self.links.remove(&(from, conn)) {
            self.links.remove(&(to, tc));
            self.push(to, tc, Input::Closed { conn: tc }, 0);
        }
    }

    /// The connection resets: both ends are told it closed.
    fn reset(&mut self, from: usize, conn: ConnId) {
        if self.links.contains_key(&(from, conn)) {
            self.close(from, conn);
            self.push(from, conn, Input::Closed { conn }, 0);
        }
    }

    /// Cuts every connection of `n`, both ends told (its own end only when `tell_self`).
    fn cut(&mut self, n: usize, tell_self: bool) {
        let ends: Vec<_> = self.links.keys().filter(|(m, _)| *m == n).copied().collect();
        for (m, c) in ends {
            if tell_self {
                self.reset(m, c);
            } else {
                self.close(m, c);
            }
        }
    }

    /// The earliest wake of an online node or held-back input due by `until`.
    fn next_due(&self, until: WallMs) -> Option<WallMs> {
        let wake = self.wakes.iter().filter(|(n, _)| self.online.get(**n) == Some(&true)).map(|(_, at)| *at).min();
        let held = self.delayed.keys().next().map(|k| k.0);
        [wake, held].into_iter().flatten().min().filter(|at| *at <= until)
    }
}

/// The `Links` of one node: its outputs into the network.
struct NodeLinks<'a> {
    net: &'a mut Net,
    node: usize,
}

impl Links for NodeLinks<'_> {
    fn dial(&mut self, conn: ConnId, to: &Address) {
        self.net.dial(self.node, conn, to);
    }

    fn send(&mut self, conn: ConnId, bytes: &[u8]) {
        self.net.send(self.node, conn, bytes);
    }

    fn close(&mut self, conn: ConnId) {
        self.net.close(self.node, conn);
    }

    fn wake(&mut self, at: WallMs) {
        // the node's own time to the world's
        let skew = self.net.skew.get(&self.node).copied().unwrap_or(0);
        self.net.wakes.insert(self.node, WallMs(at.0.saturating_add_signed(-skew)));
    }
}

/// A world: nodes, the network, one clock, a seeded rng.
pub struct World {
    pub clock: Arc<ManualClock>,
    rng: SeededRng,
    nodes: Vec<WNode>,
    pub net: Net,
    /// Hostile nodes: each one's frames pass through its lie.
    liars: BTreeMap<usize, Liar>,
    /// Deliveries so far; past `cap` the world panics as a storm.
    pub deliveries: u64,
    pub cap: u64,
    pub horizon_ms: u64,
    /// Records every delivery in `seen` while set, and each step's restarts and sends in
    /// `stepped`.
    pub trace: bool,
    pub seen: Vec<Seen>,
    /// Per step traced: the node, whether the step failed (a restart in place), its sends.
    pub stepped: Vec<(usize, bool, usize)>,
    /// Restarts in place after a device crash (`DiskFault::Crash`), so far.
    pub crashes: u64,
    /// The differential's state: things made, values written, commits handed to the reference.
    pub history: history::Made,
    /// The fixture this world is a copy of, live in this test.
    fixture: Option<String>,
}

thread_local! {
    /// Fixtures copied and still live on this thread (one test): a second live copy of one
    /// fixture is refused (one node twice would reuse nonces).
    static LIVE: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
}

impl Drop for World {
    fn drop(&mut self) {
        if let Some(k) = self.fixture.take() {
            LIVE.with(|l| l.borrow_mut().remove(&k));
        }
    }
}

impl World {
    /// An empty world, its rng and its faults seeded by `seed` (0 in rule tests).
    pub fn new(seed: u64) -> World {
        let mut net = Net { rng_seed: seed ^ 0x6e65_7421, now: START, ..Net::default() };
        net.reach = Reach::default();
        World {
            clock: Arc::new(ManualClock::new(START)),
            rng: SeededRng::from_u64(seed),
            nodes: Vec::new(),
            net,
            liars: BTreeMap::new(),
            deliveries: 0,
            cap: RULE_CAP,
            horizon_ms: HORIZON_MS,
            trace: false,
            seen: Vec::new(),
            stepped: Vec::new(),
            crashes: 0,
            history: history::Made::default(),
            fixture: None,
        }
    }

    /// The world's time.
    pub fn now(&self) -> WallMs {
        self.clock.now_wall_ms()
    }

    /// Node `i`'s time: the world's moved by its skew.
    pub fn node_now(&self, i: usize) -> WallMs {
        self.node(i).clock.now_wall_ms()
    }

    fn set_clock(&mut self, t: WallMs) {
        if t > self.now() {
            self.clock.set(t);
        }
        self.net.now = self.now();
        self.net.release();
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    fn seed(&mut self) -> u64 {
        self.rng.next_u64()
    }

    /// A new node with an account of its own (`Engine::create_account`), on LAN segment 0 with a
    /// public address, listening under a fresh key and publishing where (`publish`). Settled once.
    pub fn add_node(&mut self) -> usize {
        let i = self.add_bare_node();
        let made = self.engine(i).create_account().expect("account").0;
        if let Some(n) = self.nodes.get_mut(i) {
            n.account = Some(made.account);
            n.profile = Some(made.profile);
        }
        self.publish(i);
        i
    }

    /// Node `i` publishes its address as it listens (`Engine::publish_reach`: its `reach.0` and
    /// its profile's dial list entry), as the product's `listen` does; then it is stepped.
    pub fn publish(&mut self, i: usize) {
        let (key, items) = (self.node(i).key.0, self.net.reach.items(i));
        self.write(i, |e| e.publish_reach(key, items)).expect("publish reach");
    }

    /// A new node with no account, placed and listening as `add_node`'s.
    pub fn add_bare_node(&mut self) -> usize {
        let i = self.nodes.len();
        let seed = self.seed();
        let disks = Disks::new();
        let clock = Arc::new(NodeClock { world: self.clock.clone(), skew: AtomicI64::new(0) });
        let store = Store::open(Box::new(disks.store.0.clone()), Box::new(disks.store.1.clone()), Box::new(SeededRng::from_u64(seed ^ 1))).expect("store");
        let c: Arc<dyn Clock> = clock.clone();
        let engine = Engine::create(Box::new(disks.engine.0.clone()), Box::new(disks.engine.1.clone()), store.cipher(), osis_engine::Config::default(), c, Box::new(SeededRng::from_u64(seed))).expect("engine");
        let mut key = [0u8; 32];
        self.rng.fill_bytes(&mut key);
        let key = NodeKey(key);
        let node = Node::open(engine, store.clone(), SyncConfig { key: Some(key), ..SyncConfig::default() }, Box::new(SeededRng::from_u64(seed ^ 2))).expect("node");
        self.net.reach.place(i, &[0], Uplink::Public, &[]);
        self.net.reach.listen(i, key.0);
        self.net.online.push(true);
        self.net.accepted.push(0);
        self.nodes.push(WNode { node, disks, store, clock, key, account: None, profile: None });
        self.tick(i);
        i
    }

    pub fn node(&self, i: usize) -> &WNode {
        self.nodes.get(i).expect("no such node")
    }

    pub fn online(&self, i: usize) -> bool {
        self.net.online.get(i) == Some(&true)
    }

    /// Node `i`'s engine, for reads. A write goes through `write`.
    pub fn engine(&mut self, i: usize) -> &mut Engine {
        self.nodes.get_mut(i).expect("no such node").node.engine()
    }

    /// Node `i`'s store, for reads.
    pub fn store(&self, i: usize) -> &Store {
        self.node(i).node.store()
    }

    /// Runs `f` on node `i`'s engine, then tells the node it wrote (or, when the write crashed
    /// its device, restarts it in place).
    pub fn write<T>(&mut self, i: usize, f: impl FnOnce(&mut Engine) -> T) -> T {
        let t = f(self.engine(i));
        if !self.crashed(i) {
            self.deliver(i, Input::Wrote);
        }
        t
    }

    pub fn status(&self, i: usize) -> std::collections::BTreeMap<osis_base::SyncId, osis_sync::status::SyncStatus> {
        self.node(i).node.status()
    }

    /// Node `i`'s address: its dialable key and what it lists in `reach.0`.
    pub fn address(&self, i: usize) -> Address {
        Address { url: osis_transport::peer_url(&self.net.reach.items(i)), key: self.node(i).key.0 }
    }

    fn tick(&mut self, i: usize) {
        let now = self.node_now(i);
        self.deliver(i, Input::Tick { now });
    }

    /// Steps node `i` with `input` and carries out every output: the one place a node is stepped.
    pub fn deliver(&mut self, i: usize, input: Input) {
        self.deliveries += 1;
        if self.deliveries > self.cap {
            let flowing: Vec<Seen> = self.net.queue.iter().take(8).map(|(n, x)| Seen::of(*n, x)).collect();
            panic!("storm: past {} deliveries; still flowing (first 8 of {}): {flowing:?}; wakes {:?}", self.cap, self.net.queue.len(), self.net.wakes);
        }
        let seen = Seen::of(i, &input);
        if self.trace {
            self.seen.push(seen.clone());
        }
        if let Some(l) = self.liars.get_mut(&i) {
            match &input {
                Input::Bytes { conn, bytes } => {
                    let nodes = &self.nodes;
                    l.heard(*conn, bytes, &|s, b| nodes.iter().any(|n| n.node.store().entry(s, b).ok().flatten().is_some_and(|e| e.role)));
                }
                Input::Closed { conn } | Input::Down { conn } => l.closed(*conn),
                _ => {}
            }
        }
        let n = self.nodes.get_mut(i).expect("no such node");
        let restarts = n.node.restarts();
        let mut out = n.node.handle(input);
        if self.trace {
            self.stepped.push((i, n.node.restarts() > restarts, out.iter().filter(|o| matches!(o, Out::Send(..))).count()));
        }
        if n.node.rounds() > ROUND_CAP {
            panic!("settle loop: {} rounds in one step ({seen:?})", n.node.rounds());
        }
        // one place of outputs (scenario no-host-chain): a step gives at most one wake, last
        let wakes = out.iter().filter(|o| matches!(o, Out::Wake(_))).count();
        assert!(wakes <= 1 && (wakes == 0 || matches!(out.last(), Some(Out::Wake(_)))), "a step's wake is one and last: {out:?}");
        if let Some(l) = self.liars.get_mut(&i) {
            out = l.rewrite(out);
        }
        apply(out, &mut NodeLinks { net: &mut self.net, node: i });
        self.crashed(i);
    }

    /// Whether node `i`'s device crashed (`DiskFault::Crash`); if so the node lost power at that
    /// write and restarted in place.
    fn crashed(&mut self, i: usize) -> bool {
        if !self.node(i).disks.faults.crashed() {
            return false;
        }
        self.crashes += 1;
        self.power_off(i);
        self.power_on(i);
        true
    }

    /// Changes node `i`'s sync configuration, then steps it (`Input::Wrote`).
    pub fn configure(&mut self, i: usize, f: impl FnOnce(&mut SyncConfig)) {
        let n = self.nodes.get_mut(i).expect("no such node");
        let mut cfg = n.node.config().clone();
        f(&mut cfg);
        n.node.set_config(cfg);
        self.deliver(i, Input::Wrote);
    }

    /// Node `i` discovers node `j` (its address), as LAN discovery hands it up.
    pub fn discover(&mut self, i: usize, j: usize) {
        let addr = self.address(j);
        self.deliver(i, Input::Discovered { addr });
    }

    /// Node `i`'s dial state.
    pub fn dials(&self, i: usize) -> &osis_sync::driver::dials::Dials {
        self.node(i).node.dials()
    }

    /// Node `i`'s restarts in place after store failures.
    pub fn restarts(&self, i: usize) -> u64 {
        self.node(i).node.restarts()
    }

    /// The fault plan of node `i`'s store device.
    pub fn store_faults(&self, i: usize) -> osis_store::Faults {
        self.node(i).disks.store.0.faults().clone()
    }

    /// Connections up at node `i` (each end of each link).
    pub fn links_of(&self, i: usize) -> Vec<(ConnId, usize)> {
        self.net.links.iter().filter(|((m, _), _)| *m == i).map(|((_, c), (t, _))| (*c, *t)).collect()
    }

    /// Tests of the harness only: carries out `out` as node `i`'s outputs.
    pub fn apply_as(&mut self, i: usize, out: Vec<Out>) {
        apply(out, &mut NodeLinks { net: &mut self.net, node: i });
    }

    /// Delivers the next input in flight now; whether there was one.
    pub fn step(&mut self) -> bool {
        let Some((i, input)) = self.net.queue.pop_front() else { return false };
        if self.online(i) {
            self.deliver(i, input);
        }
        true
    }

    /// Delivers what is in flight now, in order.
    pub fn flush(&mut self) {
        while let Some((i, input)) = self.net.queue.pop_front() {
            if self.online(i) {
                self.deliver(i, input);
            }
        }
    }

    /// Moves the clock to `at` (when later), releases what is held back to then, and ticks the
    /// node whose wake is earliest by then.
    fn fire(&mut self, at: WallMs) {
        self.set_clock(at);
        let now = self.now();
        let next = self.net.wakes.iter().filter(|(n, w)| **w <= now && self.net.online.get(**n) == Some(&true)).min_by_key(|(n, w)| (**w, **n)).map(|(n, _)| *n);
        if let Some(n) = next {
            self.net.wakes.remove(&n);
            self.tick(n);
        }
    }

    /// Runs to quiet: delivers everything in flight, then jumps the clock to the earliest wake or
    /// held-back input within `horizon_ms`, until neither is left.
    pub fn run(&mut self) {
        let horizon = WallMs(self.now().0.saturating_add(self.horizon_ms));
        loop {
            self.flush();
            match self.net.next_due(horizon) {
                Some(at) => self.fire(at),
                None => return,
            }
        }
    }

    /// Moves the clock by `ms` (tests about time only) and runs every wake up to then.
    pub fn advance(&mut self, ms: u64) {
        let to = WallMs(self.now().0.saturating_add(ms));
        loop {
            self.flush();
            match self.net.next_due(to) {
                Some(at) => self.fire(at),
                None => break,
            }
        }
        self.set_clock(to);
        self.flush();
    }

    /// Separates `a` and `b`: their connections are cut (both ends told), no dial between them
    /// connects.
    pub fn partition(&mut self, a: usize, b: usize) {
        self.net.cut_off.insert((a.min(b), a.max(b)));
        self.cut(a, b);
    }

    /// Cuts the connections between `a` and `b`, both ends told; they may dial again.
    pub fn cut(&mut self, a: usize, b: usize) {
        let ends: Vec<_> = self.net.links.iter().filter(|((m, _), (t, _))| (*m, *t) == (a, b)).map(|(k, _)| *k).collect();
        for (m, c) in ends {
            self.net.reset(m, c);
        }
    }

    pub fn heal(&mut self) {
        self.net.cut_off.clear();
    }

    /// Node `i`'s clock runs `ms` ahead of the world's (behind when negative) from now on.
    pub fn skew(&mut self, i: usize, ms: i64) {
        let old = self.net.skew.insert(i, ms).unwrap_or(0);
        self.node(i).clock.skew.store(ms, Ordering::SeqCst);
        // its wake stays at the same time of its own
        if let Some(w) = self.net.wakes.get_mut(&i) {
            *w = WallMs(w.0.saturating_add_signed(old - ms));
        }
    }

    /// Node `i`'s device does `f` at its `n`-th durable write from now (0: the next).
    pub fn disk_fault(&mut self, i: usize, n: u64, f: DiskFault) {
        self.node(i).disks.faults.at(n, f.store());
    }

    /// Node `i`'s frames pass through `lie` from now on (`None`: it tells the truth again).
    pub fn lie(&mut self, i: usize, lie: Option<Lie>) {
        match lie {
            Some(l) => self.liars.insert(i, Liar::new(l)),
            None => self.liars.remove(&i),
        };
    }

    /// Node `i` loses power: its connections are cut (peers told), its wake and inputs in flight
    /// to it are lost, and so is all it held in memory: it reopens over what reached its disks
    /// (`MemoryBackend::power_cut`; a crashed device powers up again), and is stepped again at
    /// `power_on`.
    pub fn power_off(&mut self, i: usize) {
        self.net.cut(i, false);
        self.net.wakes.remove(&i);
        self.net.queue.retain(|(n, _)| *n != i);
        self.net.delayed.retain(|_, (n, _)| *n != i);
        self.net.held_until.retain(|(n, _), _| *n != i);
        if let Some(l) = self.liars.get_mut(&i) {
            *l = Liar::new(l.lie);
        }
        if let Some(o) = self.net.online.get_mut(i) {
            *o = false;
        }
        let seed = self.seed();
        let n = self.nodes.get_mut(i).expect("no such node");
        n.disks.faults.revive();
        n.disks.power_cut();
        let clock: Arc<dyn Clock> = n.clock.clone();
        let d = &n.disks;
        let store = Store::open(Box::new(d.store.0.clone()), Box::new(d.store.1.clone()), Box::new(SeededRng::from_u64(seed ^ 1))).expect("store reopens");
        let engine = Engine::open(Box::new(d.engine.0.clone()), Box::new(d.engine.1.clone()), store.cipher(), osis_engine::Config::default(), clock, Box::new(SeededRng::from_u64(seed))).expect("engine reopens");
        let cfg = n.node.config().clone();
        n.store = store.clone();
        n.node = Node::open(engine, store, cfg, Box::new(SeededRng::from_u64(seed ^ 2))).expect("node reopens");
    }

    pub fn power_on(&mut self, i: usize) {
        if self.online(i) {
            return;
        }
        if let Some(o) = self.net.online.get_mut(i) {
            *o = true;
        }
        self.tick(i);
    }

    /// An exact copy sharing nothing with this world (`osis_base::copying`).
    pub fn copy(&self) -> World {
        let clock = Arc::new(ManualClock::new(self.now()));
        let nodes = osis_base::copying::copying(|| {
            self.nodes
                .iter()
                .map(|n| {
                    let c = Arc::new(NodeClock { world: clock.clone(), skew: AtomicI64::new(n.clock.skew.load(Ordering::SeqCst)) });
                    let dc: Arc<dyn Clock> = c.clone();
                    let node = n.node.test_copy(dc.clone()).expect("node copy");
                    let store = n.store.test_copy(dc).expect("store copy");
                    WNode { node, disks: n.disks.test_copy(), store, clock: c, key: n.key, account: n.account, profile: n.profile }
                })
                .collect()
        });
        World {
            clock,
            rng: self.rng.test_copy(),
            nodes,
            net: self.net.clone(),
            liars: self.liars.clone(),
            deliveries: 0,
            cap: self.cap,
            horizon_ms: self.horizon_ms,
            trace: self.trace,
            seen: Vec::new(),
            stepped: Vec::new(),
            crashes: 0,
            history: self.history.clone(),
            fixture: None,
        }
    }
}

/// A copy of the world `build` makes, built once per process per `key` (a name for the build
/// and every parameter it takes), through the product's own flows. A second live copy of one
/// fixture in one test is refused.
pub fn fixture(key: &str, build: impl FnOnce() -> World) -> World {
    LIVE.with(|l| {
        if !l.borrow_mut().insert(key.to_string()) {
            panic!("fixture {key}: a second live copy in one test");
        }
    });
    let mut w = osis_base::copying::cached(key, build, |w: &mut World| w.copy());
    w.fixture = Some(key.to_string());
    w
}

/// Two nodes, each with an account of its own, quiet.
pub fn two_nodes() -> World {
    fixture("two_nodes", || {
        let mut w = World::new(0);
        w.add_node();
        w.add_node();
        w.run();
        w
    })
}

/// Two nodes of two accounts, each the other's contact (`history::introduce`), quiet: each dials
/// the other by its dial list once they share something.
pub fn contacts() -> World {
    fixture("two contacts", || {
        let mut w = World::new(0);
        w.add_node();
        w.add_node();
        history::introduce(&mut w);
        w.run();
        w
    })
}

/// One step of a scripted run: what a random layer generates and `play` replays. Printed as
/// Rust on failure (`osis_base::testenv::Script`; `use crate::harness::script::*` brings every
/// name a printed step uses).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Run to quiet.
    Run,
    /// Move the clock this many ms.
    Advance(u64),
    Partition(usize, usize),
    Heal,
    /// Cut the connections between two nodes (both told); they may dial again.
    Cut(usize, usize),
    PowerOff(usize),
    PowerOn(usize),
    /// The network's faults from now on.
    Lossy(Loss),
    /// A node's clock runs this many ms ahead of the world's (behind when negative).
    Skew(usize, i64),
    /// A node's device does this at its n-th durable write from now.
    Disk(usize, u64, DiskFault),
    /// A node's frames pass through this lie from now on.
    Lies(usize, Lie),
    /// A node tells the truth again.
    Truth(usize),
    /// The differential's writes (`history`): node i makes a thing (its account the first admin,
    /// a value written); writes thing k; grants node j's account a role on thing k; removes node
    /// j's account from thing k; rotates thing k's secrets.
    New(usize),
    Write(usize, usize),
    Grant(usize, usize, usize, history::Gives),
    Remove(usize, usize, usize),
    Rotate(usize, usize),
}

/// Every name a printed script uses.
#[allow(unused_imports)]
pub mod script {
    pub use super::DiskFault::*;
    pub use super::Loss;
    pub use super::Step::*;
    pub use super::history::Gives::*;
    pub use super::lies::Lie::*;
}

impl Step {
    /// Simpler forms of this step, for shrinking: shorter times, fewer faults, a later device
    /// fault, a smaller skew, a lesser role.
    pub fn simpler(&self) -> Vec<Step> {
        match self {
            Step::Advance(ms) if *ms > 1 => vec![Step::Advance(ms / 2)],
            Step::Lossy(l) if !l.none() => {
                let mut v = Vec::new();
                for (i, f) in [l.drop, l.dup, l.delay].into_iter().enumerate() {
                    if f > 0 {
                        let mut x = *l;
                        let half = f / 2;
                        match i {
                            0 => x.drop = half,
                            1 => x.dup = half,
                            _ => x.delay = half,
                        }
                        v.push(Step::Lossy(x));
                    }
                }
                if l.delay_ms > 1 {
                    v.push(Step::Lossy(Loss { delay_ms: l.delay_ms / 2, ..*l }));
                }
                v
            }
            Step::Skew(i, ms) if *ms != 0 => vec![Step::Skew(*i, ms / 2)],
            Step::Disk(i, n, f) => {
                let mut v: Vec<Step> = (*f != DiskFault::Fail).then_some(Step::Disk(*i, *n, DiskFault::Fail)).into_iter().collect();
                if *n > 0 {
                    v.push(Step::Disk(*i, n / 2, *f));
                }
                v
            }
            Step::Grant(i, k, j, g) => g.lesser().map(|x| Step::Grant(*i, *k, *j, x)).into_iter().collect(),
            _ => Vec::new(),
        }
    }
}

/// The variable that shrinks a failing script.
pub const SHRINK_VAR: &str = "OSIS_SYNC_SHRINK";

/// Plays one step on `w`; a note of what it did (empty: nothing to say).
pub fn step(w: &mut World, s: &Step) -> String {
    let note = step_of(w, s);
    history::accept(w);
    note
}

fn step_of(w: &mut World, s: &Step) -> String {
    match s {
        Step::Run => w.run(),
        Step::Advance(ms) => w.advance(*ms),
        Step::Partition(a, b) => w.partition(*a, *b),
        Step::Heal => w.heal(),
        Step::Cut(a, b) => w.cut(*a, *b),
        Step::PowerOff(i) => w.power_off(*i),
        Step::PowerOn(i) => w.power_on(*i),
        Step::Lossy(l) => w.net.loss = *l,
        Step::Skew(i, ms) => w.skew(*i, *ms),
        Step::Disk(i, n, f) => w.disk_fault(*i, *n, *f),
        Step::Lies(i, l) => w.lie(*i, Some(*l)),
        Step::Truth(i) => w.lie(*i, None),
        Step::New(..) | Step::Write(..) | Step::Grant(..) | Step::Remove(..) | Step::Rotate(..) => return history::step(w, s),
    }
    String::new()
}

/// Plays `steps` on `w`, recording each so a failure prints the script with `replay` (the call
/// that replays it). The script is returned: held while the caller checks the outcome, a failed
/// check prints it too.
pub fn play(w: &mut World, steps: &[Step], replay: String) -> Script<Step> {
    let mut script = Script::new("crate::harness::script", SHRINK_VAR, replay);
    for s in steps {
        script.push(s.clone(), String::new());
        let note = step(w, s);
        if !note.is_empty() {
            script.note(note);
        }
    }
    script
}

/// Runs `run` (which plays a script with `play`); with `OSIS_SYNC_SHRINK` set, a failure is
/// shrunk by `replay` (`osis_base::testenv::shrinking`).
pub fn shrinking(run: impl FnOnce(), replay: impl Fn(&[Step])) {
    osis_base::testenv::shrinking(SHRINK_VAR, run, replay, Step::simpler);
}

//! The one sync test harness (notes/sync-test-harness.md): a deterministic world of product
//! nodes (engine, store, `osis_sync::Node`) in one process, one manual clock that jumps to the
//! next wake, a seeded rng, and a network of real encoded frames routed by the reachability
//! model (`reach`). Every node output goes through `osis_sync::apply` into the network (`Net`,
//! the test `Links`), and every node input through `World::deliver`, the one place a node is
//! stepped: a test can reach a node's engine and status but never its `handle`, so no test can
//! drop an output. Fixtures are worlds built once per process through the product's own flows
//! and copied per test (`fixture`). Random layers write a `Vec<Step>` and replay it with `play`;
//! a failure prints the script, `OSIS_SYNC_SHRINK=1` shrinks it.

#![allow(dead_code)]

pub mod reach;

use osis_base::testenv::Script;
use osis_base::{Clock, ManualClock, Tid, WallMs};
use osis_crypto::{RngCore, SeededRng};
use osis_engine::Engine;
use osis_label::Address;
use osis_store::{MemoryBackend, MemoryRoot};
use osis_sync::{ConnId, Input, Links, Node, NodeKey, Out, Store, SyncConfig, apply};
use reach::{Reach, Route, Uplink, Who};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

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

/// A node's durable state (engine and store, each a backend and its root record): it survives a
/// power loss, and the node reopens over it.
#[derive(Clone)]
struct Disks {
    engine: (MemoryBackend, MemoryRoot),
    store: (MemoryBackend, MemoryRoot),
}

impl Disks {
    fn new() -> Disks {
        Disks { engine: (MemoryBackend::new(), MemoryRoot::new()), store: (MemoryBackend::new(), MemoryRoot::new()) }
    }

    fn power_cut(&self) {
        self.engine.0.power_cut();
        self.store.0.power_cut();
    }

    /// Tests of copies: inside the same `osis_base::copying` as the node's copy, so the copy's
    /// handles are the copied node's.
    fn test_copy(&self) -> Disks {
        Disks { engine: (self.engine.0.test_copy(), self.engine.1.test_copy()), store: (self.store.0.test_copy(), self.store.1.test_copy()) }
    }
}

/// One world node.
pub struct WNode {
    node: Node,
    disks: Disks,
    pub key: NodeKey,
    /// Its account (`Engine::create_account`).
    pub account: Option<Tid>,
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
        }
    }
}

/// The network: links between world nodes, the queue of inputs in flight, the wakes asked.
#[derive(Clone, Default)]
pub struct Net {
    pub reach: Reach,
    /// Each end of each connection up: (node, its conn) -> (peer, the peer's conn).
    links: BTreeMap<(usize, ConnId), (usize, ConnId)>,
    queue: VecDeque<(usize, Input)>,
    /// Each node's one wake (`Links::wake` replaces it).
    wakes: BTreeMap<usize, WallMs>,
    /// Node pairs a partition separates (lower index first).
    cut_off: BTreeSet<(usize, usize)>,
    online: Vec<bool>,
    accepted: Vec<u64>,
    /// Bytes carried so far.
    pub bytes: u64,
    /// Bytes each end sent on each connection: the transport takes them at once (no buffer), so
    /// each send is answered `Taken` with the total.
    written: BTreeMap<(usize, ConnId), u64>,
    rng_seed: u64,
    dials: u64,
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
        self.dials += 1;
        let mut k = [0u8; 32];
        SeededRng::from_u64(self.rng_seed ^ self.dials.rotate_left(17)).fill_bytes(&mut k);
        NodeKey(k)
    }

    fn dial(&mut self, from: usize, conn: ConnId, to: &Address) {
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
        self.links.insert((from, conn), (target, accepted));
        self.links.insert((target, accepted), (from, conn));
        self.queue.push_back((from, Input::Up { conn, peer: NodeKey(to.key), rank, dialed: true }));
        self.queue.push_back((target, Input::Up { conn: accepted, peer: eph, rank, dialed: false }));
    }

    fn send(&mut self, from: usize, conn: ConnId, bytes: &[u8]) {
        // bytes on a connection the peer already closed are lost, as on a transport
        if let Some((to, tc)) = self.links.get(&(from, conn)).copied() {
            self.bytes += bytes.len() as u64;
            let w = self.written.entry((from, conn)).or_default();
            *w += bytes.len() as u64;
            let total = *w;
            self.queue.push_back((to, Input::Bytes { conn: tc, bytes: bytes.to_vec() }));
            self.queue.push_back((from, Input::Taken { conn, bytes: total }));
        }
    }

    fn close(&mut self, from: usize, conn: ConnId) {
        if let Some((to, tc)) = self.links.remove(&(from, conn)) {
            self.links.remove(&(to, tc));
            self.queue.push_back((to, Input::Closed { conn: tc }));
        }
    }

    /// Cuts every connection of `n`, both ends told (its own end only when `tell_self`).
    fn cut(&mut self, n: usize, tell_self: bool) {
        let ends: Vec<_> = self.links.keys().filter(|(m, _)| *m == n).copied().collect();
        for (m, c) in ends {
            if let Some((to, tc)) = self.links.remove(&(m, c)) {
                self.links.remove(&(to, tc));
                self.queue.push_back((to, Input::Closed { conn: tc }));
                if tell_self {
                    self.queue.push_back((m, Input::Closed { conn: c }));
                }
            }
        }
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
        self.net.wakes.insert(self.node, at);
    }
}

/// A world: nodes, the network, one clock, a seeded rng.
pub struct World {
    pub clock: Arc<ManualClock>,
    rng: SeededRng,
    nodes: Vec<WNode>,
    pub net: Net,
    /// Deliveries so far; past `cap` the world panics as a storm.
    pub deliveries: u64,
    pub cap: u64,
    pub horizon_ms: u64,
    /// Records every delivery in `seen` while set.
    pub trace: bool,
    pub seen: Vec<Seen>,
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
    /// An empty world, its rng seeded by `seed` (0 in rule tests).
    pub fn new(seed: u64) -> World {
        let mut net = Net { rng_seed: seed ^ 0x6e65_7421, ..Net::default() };
        net.reach = Reach::default();
        World { clock: Arc::new(ManualClock::new(START)), rng: SeededRng::from_u64(seed), nodes: Vec::new(), net, deliveries: 0, cap: RULE_CAP, horizon_ms: HORIZON_MS, trace: false, seen: Vec::new(), fixture: None }
    }

    pub fn now(&self) -> WallMs {
        self.clock.now_wall_ms()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    fn seed(&mut self) -> u64 {
        self.rng.next_u64()
    }

    /// A new node with an account of its own (`Engine::create_account`), on LAN segment 0 with a
    /// public address, listening under a fresh key. Settled once.
    pub fn add_node(&mut self) -> usize {
        let i = self.add_bare_node();
        let account = {
            let e = self.engine(i);
            e.create_account(&[]).expect("account").0.account
        };
        if let Some(n) = self.nodes.get_mut(i) {
            n.account = Some(account);
        }
        self.deliver(i, Input::Wrote);
        i
    }

    /// A new node with no account, placed and listening as `add_node`'s.
    pub fn add_bare_node(&mut self) -> usize {
        let i = self.nodes.len();
        let seed = self.seed();
        let disks = Disks::new();
        let store = Store::open(Box::new(disks.store.0.clone()), Box::new(disks.store.1.clone()), Box::new(SeededRng::from_u64(seed ^ 1))).expect("store");
        let clock: Arc<dyn Clock> = self.clock.clone();
        let engine = Engine::create(Box::new(disks.engine.0.clone()), Box::new(disks.engine.1.clone()), store.cipher(), osis_engine::Config::default(), clock, Box::new(SeededRng::from_u64(seed))).expect("engine");
        let mut key = [0u8; 32];
        self.rng.fill_bytes(&mut key);
        let key = NodeKey(key);
        let node = Node::open(engine, store, SyncConfig { key: Some(key), dial: Vec::new() }, Box::new(SeededRng::from_u64(seed ^ 2))).expect("node");
        self.net.reach.place(i, &[0], Uplink::Public, &[]);
        self.net.reach.listen(i, key.0);
        self.net.online.push(true);
        self.net.accepted.push(0);
        self.nodes.push(WNode { node, disks, key, account: None });
        self.deliver(i, Input::Tick { now: self.now() });
        i
    }

    pub fn node(&self, i: usize) -> &WNode {
        self.nodes.get(i).expect("no such node")
    }

    /// Node `i`'s engine, for reads. A write goes through `write`.
    pub fn engine(&mut self, i: usize) -> &mut Engine {
        self.nodes.get_mut(i).expect("no such node").node.engine()
    }

    /// Runs `f` on node `i`'s engine, then tells the node it wrote.
    pub fn write<T>(&mut self, i: usize, f: impl FnOnce(&mut Engine) -> T) -> T {
        let t = f(self.engine(i));
        self.deliver(i, Input::Wrote);
        t
    }

    pub fn status(&self, i: usize) -> Arc<osis_sync::status::StatusView> {
        self.node(i).node.status()
    }

    /// Node `i`'s address: its dialable key and what it lists in `reach.0`.
    pub fn address(&self, i: usize) -> Address {
        Address { url: osis_transport::peer_url(&self.net.reach.items(i)), key: self.node(i).key.0 }
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
        let n = self.nodes.get_mut(i).expect("no such node");
        let out = n.node.handle(input);
        if n.node.rounds() > ROUND_CAP {
            panic!("settle loop: {} rounds in one step ({seen:?})", n.node.rounds());
        }
        apply(out, &mut NodeLinks { net: &mut self.net, node: i });
    }

    /// Tests of the harness only: carries out `out` as node `i`'s outputs.
    pub fn apply_as(&mut self, i: usize, out: Vec<Out>) {
        apply(out, &mut NodeLinks { net: &mut self.net, node: i });
    }

    /// Delivers what is in flight, in order.
    pub fn flush(&mut self) {
        while let Some((i, input)) = self.net.queue.pop_front() {
            if self.net.online.get(i) == Some(&true) {
                self.deliver(i, input);
            }
        }
    }

    /// Runs to quiet: delivers everything in flight, then jumps the clock to the earliest wake
    /// within `horizon_ms` and ticks that node, until neither is left.
    pub fn run(&mut self) {
        let horizon = WallMs(self.now().0.saturating_add(self.horizon_ms));
        loop {
            self.flush();
            let next = self.net.wakes.iter().filter(|(n, _)| self.net.online.get(**n) == Some(&true)).min_by_key(|(n, at)| (**at, **n)).map(|(n, at)| (*n, *at));
            match next {
                Some((n, at)) if at <= horizon => {
                    self.net.wakes.remove(&n);
                    if at > self.now() {
                        self.clock.set(at);
                    }
                    self.deliver(n, Input::Tick { now: self.now() });
                }
                _ => return,
            }
        }
    }

    /// Moves the clock by `ms` (tests about time only) and runs every wake up to then.
    pub fn advance(&mut self, ms: u64) {
        let to = WallMs(self.now().0.saturating_add(ms));
        loop {
            self.flush();
            let next = self.net.wakes.iter().filter(|(n, at)| **at <= to && self.net.online.get(**n) == Some(&true)).min_by_key(|(n, at)| (**at, **n)).map(|(n, at)| (*n, *at));
            let Some((n, at)) = next else { break };
            self.net.wakes.remove(&n);
            if at > self.now() {
                self.clock.set(at);
            }
            self.deliver(n, Input::Tick { now: self.now() });
        }
        self.clock.set(to);
    }

    /// Separates `a` and `b`: their connections are cut (both ends told), no dial between them
    /// connects.
    pub fn partition(&mut self, a: usize, b: usize) {
        self.net.cut_off.insert((a.min(b), a.max(b)));
        let ends: Vec<_> = self.net.links.iter().filter(|((m, _), (t, _))| (*m, *t) == (a, b)).map(|(k, _)| *k).collect();
        for (m, c) in ends {
            self.net.close(m, c);
            self.net.queue.push_back((m, Input::Closed { conn: c }));
        }
    }

    pub fn heal(&mut self) {
        self.net.cut_off.clear();
    }

    /// Node `i` loses power: its connections are cut (peers told), its wake and inputs in flight
    /// to it are lost, and so is all it held in memory: it reopens over what reached its disks
    /// (`MemoryBackend::power_cut`), and is stepped again at `power_on`.
    pub fn power_off(&mut self, i: usize) {
        self.net.cut(i, false);
        self.net.wakes.remove(&i);
        self.net.queue.retain(|(n, _)| *n != i);
        if let Some(o) = self.net.online.get_mut(i) {
            *o = false;
        }
        let seed = self.seed();
        let clock: Arc<dyn Clock> = self.clock.clone();
        let n = self.nodes.get_mut(i).expect("no such node");
        n.disks.power_cut();
        let d = &n.disks;
        let store = Store::open(Box::new(d.store.0.clone()), Box::new(d.store.1.clone()), Box::new(SeededRng::from_u64(seed ^ 1))).expect("store reopens");
        let engine = Engine::open(Box::new(d.engine.0.clone()), Box::new(d.engine.1.clone()), store.cipher(), osis_engine::Config::default(), clock, Box::new(SeededRng::from_u64(seed))).expect("engine reopens");
        let cfg = n.node.config().clone();
        n.node = Node::open(engine, store, cfg, Box::new(SeededRng::from_u64(seed ^ 2))).expect("node reopens");
    }

    pub fn power_on(&mut self, i: usize) {
        if let Some(o) = self.net.online.get_mut(i) {
            *o = true;
        }
        self.deliver(i, Input::Tick { now: self.now() });
    }

    /// An exact copy sharing nothing with this world (`osis_base::copying`).
    pub fn copy(&self) -> World {
        let clock = Arc::new(ManualClock::new(self.now()));
        let dyn_clock: Arc<dyn Clock> = clock.clone();
        let nodes = osis_base::copying::copying(|| {
            self.nodes.iter().map(|n| WNode { node: n.node.test_copy(dyn_clock.clone()).expect("node copy"), disks: n.disks.test_copy(), key: n.key, account: n.account }).collect()
        });
        World { clock, rng: self.rng.test_copy(), nodes, net: self.net.clone(), deliveries: 0, cap: self.cap, horizon_ms: self.horizon_ms, trace: self.trace, seen: Vec::new(), fixture: None }
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

/// One step of a scripted run: what a random layer generates and `play` replays. Printed as
/// Rust on failure (`osis_base::testenv::Script`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Run to quiet.
    Run,
    /// Move the clock this many ms.
    Advance(u64),
    Partition(usize, usize),
    Heal,
    PowerOff(usize),
    PowerOn(usize),
}

impl Step {
    /// Simpler forms of this step, for shrinking.
    pub fn simpler(&self) -> Vec<Step> {
        match self {
            Step::Advance(ms) if *ms > 1 => vec![Step::Advance(ms / 2)],
            _ => Vec::new(),
        }
    }
}

/// The variable that shrinks a failing script.
pub const SHRINK_VAR: &str = "OSIS_SYNC_SHRINK";

/// Plays `steps` on `w`, recording each so a failure prints the script with `replay` (the call
/// that replays it).
pub fn play(w: &mut World, steps: &[Step], replay: String) {
    let mut script = Script::new("crate::harness::Step", SHRINK_VAR, replay);
    for s in steps {
        script.push(s.clone(), String::new());
        match s {
            Step::Run => w.run(),
            Step::Advance(ms) => w.advance(*ms),
            Step::Partition(a, b) => w.partition(*a, *b),
            Step::Heal => w.heal(),
            Step::PowerOff(i) => w.power_off(*i),
            Step::PowerOn(i) => w.power_on(*i),
        }
    }
}

/// Runs `run` (which plays a script with `play`); with `OSIS_SYNC_SHRINK` set, a failure is
/// shrunk by `replay` (`osis_base::testenv::shrinking`).
pub fn shrinking(run: impl FnOnce(), replay: impl Fn(&[Step])) {
    osis_base::testenv::shrinking(SHRINK_VAR, run, replay, Step::simpler);
}

//! The one sync test harness (notes/sync-test-harness.md): a deterministic world of product
//! nodes (engine, store, `osis_sync::Node`) in one process, one manual clock that jumps to the
//! next wake (each node reading its wall clock through its own skew), a seeded rng, and a network of real
//! encoded frames routed by the reachability model (`reach`). Every node output goes through
//! `osis_sync::apply` into the network (`Net`, the test `Links`), and every node input through
//! `World::deliver`, the one place a node is stepped: a test can reach a node's engine and status
//! but never its `handle`, so no test can drop an output. Faults are content-blind: the network
//! loses, repeats and delays sends (`Loss`), partitions and cuts; a node's device fails a durable
//! write (`DiskFault`) or loses power; a hostile node is an honest one whose frames pass through
//! a `Lie` (`lies`). Fixtures are worlds built once per process through the product's own flows
//! and copied per test (`fixture`). Random layers write a `Vec<Step>` and replay it with `play`;
//! a failure prints the script, `OSIS_SYNC_SHRINK=1` shrinks it.


pub mod history;
pub mod lies;
pub mod reach;
pub mod scripted;
pub mod sid;
pub mod trace;

use lies::{Lie, Liar};
use osis_base::testenv::Script;
use osis_base::{Clock, ManualClock, Tid, WallMs};
use osis_crypto::{RngCore, SeededRng};
use osis_engine::Engine;
use osis_proto::FrameDecoder;
use osis_blob::Address;
use osis_store::{Fault, Faults, MemoryBackend, MemoryRoot};
use osis_sync::{ConnId, Input, Links, Node, NodeKey, Out, Store, SyncConfig, apply};
use reach::{Reach, Route, Uplink, Who};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Deliveries one world may make before it panics as a storm, unless a test sets its own
/// (`World::cap`). The rule-test layer's cap (notes/sync-test-harness.md, Enforcement).
pub const RULE_CAP: u64 = 2_000;

/// Deliveries a differential history, simulation or flow world may make before it panics as a
/// storm: about 5x the most any default seed makes (5,800; median 740). At 0 every history
/// storms; at infinity a livelock runs until the seed timeout (600 CPU-s) instead of failing in
/// seconds.
pub const STORM_CAP: u64 = 30_000;

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

/// A node's clock: the world's, its wall clock moved by the node's skew (`World::skew`), its
/// monotonic clock started again from 0 at each power loss (`World::power_off`), as a process's
/// is (`SystemClock`).
#[derive(Debug)]
pub struct NodeClock {
    world: Arc<ManualClock>,
    skew: AtomicI64,
    /// The world's monotonic clock at the node's last power loss (0 before any).
    boot: AtomicU64,
}

impl NodeClock {
    fn new(world: Arc<ManualClock>) -> NodeClock {
        NodeClock { world, skew: AtomicI64::new(0), boot: AtomicU64::new(0) }
    }

    fn boot(&self) -> u64 {
        self.boot.load(Ordering::SeqCst)
    }
}

impl Clock for NodeClock {
    fn now_wall_ms(&self) -> WallMs {
        WallMs(self.world.now_wall_ms().0.saturating_add_signed(self.skew.load(Ordering::SeqCst)))
    }
    /// The world's since the last power loss: a skew moves the wall clock alone.
    fn mono(&self) -> osis_base::Mono {
        osis_base::Mono(self.world.mono().0.saturating_sub(self.boot()))
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
    /// The thing it acts as: its node thing (`Engine::me`).
    pub account: Option<Tid>,
    /// Its account's profile thing: brought back by making an account
    /// (notes/accounts-switch-brief.md).
    pub profile: Option<Tid>,
}

/// One delivery, as `World::trace` records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seen {
    Up { node: usize, conn: ConnId, dialed: bool, rank: u8 },
    /// `digest`: the first 8 bytes of the bytes' BLAKE3, so a replay that sends other bytes differs.
    Bytes { node: usize, conn: ConnId, len: usize, digest: [u8; 8] },
    Taken { node: usize, conn: ConnId, bytes: u64 },
    Closed { node: usize, conn: ConnId },
    Down { node: usize, conn: ConnId },
    /// `at`: the node's monotonic clock then.
    Tick { node: usize, at: osis_base::Mono },
    Wrote { node: usize },
    Discovered { node: usize, key: [u8; 32] },
}

impl Seen {
    fn of(node: usize, input: &Input, mono: osis_base::Mono) -> Seen {
        match input {
            Input::Up { conn, rank, dialed, .. } => Seen::Up { node, conn: *conn, dialed: *dialed, rank: *rank },
            Input::Bytes { conn, bytes } => Seen::Bytes { node, conn: *conn, len: bytes.len(), digest: osis_base::hash::hash(bytes)[..8].try_into().unwrap() },
            Input::Taken { conn, bytes } => Seen::Taken { node, conn: *conn, bytes: *bytes },
            Input::Closed { conn } => Seen::Closed { node, conn: *conn },
            Input::Down { conn, .. } => Seen::Down { node, conn: *conn },
            Input::Tick => Seen::Tick { node, at: mono },
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
    /// Each node's one wake (`Links::wake` replaces it), in world time: a node's waits run on its
    /// monotonic clock, which no skew moves (its boot offset added back: `NodeLinks::boot`).
    wakes: BTreeMap<usize, WallMs>,
    /// Node pairs a partition separates (lower index first).
    cut_off: BTreeSet<(usize, usize)>,
    online: Vec<bool>,
    accepted: Vec<u64>,
    /// Bytes carried so far.
    pub bytes: u64,
    /// Bytes each node sent each other node, every connection between them summed.
    pub between: BTreeMap<(usize, usize), u64>,
    /// The frames each node sent each other node, per message kind (`Hello`, a `Msg` variant):
    /// (count, bytes with the length prefix). `census` prints it.
    pub frames: BTreeMap<(usize, usize, &'static str), (u64, u64)>,
    /// Set: each blob each node was sent with its entry in a FetchReply by each other node, and
    /// how many times (`fetched`); off, no frame is decoded for it.
    pub count_fetched: bool,
    pub fetched: BTreeMap<(usize, usize), BTreeMap<osis_base::BlobId, u64>>,
    /// Each end's sent bytes split into frames for `frames`, and whether its Hello went by.
    splitters: BTreeMap<(usize, ConnId), (FrameDecoder, bool)>,
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
    /// Ends their node stopped reading (`Links::read`), with the bytes and close held for them.
    paused: BTreeMap<(usize, ConnId), Vec<Input>>,
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
            self.enqueue(to, input);
        }
    }

    /// `input` to node `to` now, or held while it reads its end no more.
    fn enqueue(&mut self, to: usize, input: Input) {
        if let Input::Bytes { conn, .. } | Input::Closed { conn } = &input
            && let Some(held) = self.paused.get_mut(&(to, *conn))
        {
            return held.push(input);
        }
        self.queue.push_back((to, input));
    }

    /// Node `n` reads its end `conn` (`on`) or stops reading it: what was held for it goes, in
    /// order.
    fn read(&mut self, n: usize, conn: ConnId, on: bool) {
        match on {
            false => {
                self.paused.entry((n, conn)).or_default();
            }
            true => {
                for i in self.paused.remove(&(n, conn)).unwrap_or_default() {
                    self.queue.push_back((n, i));
                }
            }
        }
    }

    /// Moves every held-back input due by now to the queue, in order.
    fn release(&mut self) {
        while let Some(e) = self.delayed.first_entry() {
            if e.key().0 > self.now {
                break;
            }
            let (to, input) = e.remove();
            self.enqueue(to, input);
        }
    }

    fn dial(&mut self, from: usize, conn: ConnId, to: &Address) {
        self.dials.push((from, conn, to.key));
        if self.reach.node_of(&to.key).is_some_and(|t| self.hang.contains(&t)) {
            return;
        }
        let route = self.reach.node_of(&to.key).filter(|t| *t != from && self.online.get(*t) == Some(&true)).and_then(|t| Some((t, self.reach.route(from, t, &to.url, |a, b| self.blocked(a, b))?)));
        let Some((target, route)) = route else {
            self.queue.push_back((from, Input::Down { conn, error: "unreachable".into() }));
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
        *self.between.entry((from, to)).or_default() += bytes.len() as u64;
        let (f, hello) = self.splitters.entry((from, conn)).or_default();
        f.push(bytes);
        while let Ok(Some(body)) = f.next_frame() {
            let kind = if std::mem::replace(hello, true) { trace::kind_name(&body) } else { "Hello" };
            let t = self.frames.entry((from, to, kind)).or_default();
            t.0 += 1;
            t.1 += 4 + body.len() as u64;
            if self.count_fetched
                && kind == "FetchReply"
                && let Ok(osis_proto::Msg::FetchReply { items, .. }) = osis_proto::Msg::decode(&body)
            {
                let per = self.fetched.entry((from, to)).or_default();
                for f in items.iter().filter(|f| f.entry.is_some()) {
                    *per.entry(f.blob_id).or_default() += 1;
                }
            }
        }
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
        self.paused.remove(&(from, conn));
        self.splitters.remove(&(from, conn));
        if let Some((to, tc)) = self.links.remove(&(from, conn)) {
            self.links.remove(&(to, tc));
            self.splitters.remove(&(to, tc));
            self.push(to, tc, Input::Closed { conn: tc }, 0);
        }
    }

    /// `frames`, one line per node pair, kinds by bytes, largest first.
    pub fn census(&self) -> String {
        let all: Vec<_> = self.frames.iter().collect();
        let mut out = String::from("frames sent (kind count/bytes):");
        for pair in all.chunk_by(|x, y| (x.0.0, x.0.1) == (y.0.0, y.0.1)) {
            let mut kinds = pair.to_vec();
            kinds.sort_by_key(|((_, _, k), (_, bytes))| (std::cmp::Reverse(*bytes), *k));
            let kinds: Vec<String> = kinds.iter().map(|((_, _, k), (n, bytes))| format!("{k} {n}/{bytes}")).collect();
            out.push_str(&format!("\n  n{} -> n{}: {}", pair[0].0.0, pair[0].0.1, kinds.join(", ")));
        }
        out
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
    /// The node's `NodeClock::boot`: its monotonic clock plus this is the world's.
    boot: u64,
}

impl Links for NodeLinks<'_> {
    fn dial(&mut self, conn: ConnId, to: &Address) {
        self.net.dial(self.node, conn, to);
    }

    fn send(&mut self, conn: ConnId, bytes: &[u8]) {
        self.net.send(self.node, conn, bytes);
    }

    fn read(&mut self, conn: ConnId, on: bool) {
        self.net.read(self.node, conn, on);
    }

    fn close(&mut self, conn: ConnId) {
        self.net.close(self.node, conn);
    }

    fn wake(&mut self, at: osis_base::Mono) {
        // the world's clock never goes back: its monotonic clock reads as its time
        self.net.wakes.insert(self.node, WallMs(at.0.saturating_add(self.boot)));
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
    /// Deliveries so far by node (the storm panic names the busiest).
    delivered: BTreeMap<usize, u64>,
    pub cap: u64,
    pub horizon_ms: u64,
    /// Records every delivery in `seen` while set, and each step's restarts and sends in
    /// `stepped`.
    pub trace: bool,
    pub seen: Vec<Seen>,
    /// Per step traced: the node, whether the step failed (a restart in place), its sends.
    pub stepped: Vec<(usize, bool, usize)>,
    /// Checks after every script step that no entry whose commit the engine knows is left
    /// unparked from a read secret it awaits (`Node::lost_parks`); an entry that never opened (no
    /// commit known) is outside it (issues/sync-parks-check.md).
    pub parks: bool,
    /// Nodes added from now on record every row and blob their disks are given (`forensic`,
    /// `recorded`), for what an attacker holding a device or watching a store learns.
    pub record: bool,
    /// Restarts in place after a device crash (`DiskFault::Crash`), so far.
    pub crashes: u64,
    /// The differential's state: things made, values written, commits handed to the reference.
    pub history: history::Made,
    /// The fixture this world is a copy of, live in this test.
    fixture: Option<String>,
    /// The per-node trace (`OSIS_SYNC_TRACE`, `trace`); none when off.
    tracer: Option<Box<trace::Tracer>>,
}

thread_local! {
    /// Fixtures copied and still live on this thread (one test): a second live copy of one
    /// fixture is refused (one node twice would reuse nonces).
    static LIVE: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
}

impl Drop for World {
    fn drop(&mut self) {
        // the trace's summary
        if self.tracer.is_some() && !osis_base::testenv::quiet() {
            eprintln!("{}", self.net.census());
        }
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
            delivered: BTreeMap::new(),
            cap: RULE_CAP,
            horizon_ms: HORIZON_MS,
            trace: false,
            seen: Vec::new(),
            stepped: Vec::new(),
            parks: false,
            record: false,
            crashes: 0,
            history: history::Made::default(),
            fixture: None,
            tracer: trace::Tracer::from_env().map(Box::new),
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

    /// A new node acting as its node thing, on LAN segment 0 with a public address, listening
    /// under a fresh key and publishing where (`publish`). Settled once.
    pub fn add_node(&mut self) -> usize {
        let i = self.add_bare_node();
        let me = self.engine(i).me();
        if let Some(n) = self.nodes.get_mut(i) {
            n.account = Some(me);
        }
        self.publish(i);
        i
    }

    /// A new node paired as a second node of node `i`'s account: brought back by pairing
    /// (notes/accounts-switch-brief.md).
    pub fn pair(&mut self, _i: usize) -> usize {
        unimplemented!("accounts: pairing")
    }

    /// Node `i` publishes its address as it listens (`Engine::publish_reach`: its `reach.0` and
    /// its profile's dial list entry), as the product's `listen` does; then it is stepped.
    pub fn publish(&mut self, i: usize) {
        let (key, items) = (self.node(i).key.0, self.net.reach.items(i));
        self.write(i, |e| e.publish_reach(key, items)).expect("publish reach");
    }

    /// Node `i`'s read link to `target` as the product's `make_link` makes it (spec/wire.md §10:
    /// the node's dialable key and where it is reached, as first-contact hints).
    pub fn make_link(&mut self, i: usize, target: Tid, role: osis_base::Role) -> osis_blob::ShareLink {
        let me = self.node(i).account.expect("an account");
        let peers = osis_blob::link_peers(self.node(i).key.0, &self.net.reach.items(i), &self.node(i).node.config().dial);
        let spec = osis_engine::flows::LinkSpec { target, role, until: None, peers, single_use: false };
        self.write(i, |e| e.create_link(&me, &spec)).expect("a link").0
    }

    /// Node `i` redeems `link` (`Node::redeem`), then it is stepped.
    pub fn redeem(&mut self, i: usize, link: &osis_blob::ShareLink) -> osis_sync::types::Waiting {
        let w = self.nodes.get_mut(i).expect("no such node").node.redeem(link);
        self.deliver(i, Input::Wrote);
        w
    }

    /// A new node with no account, placed and listening as `add_node`'s.
    pub fn add_bare_node(&mut self) -> usize {
        let i = self.nodes.len();
        let seed = self.seed();
        let disks = Disks::new();
        if self.record {
            for b in [&disks.engine.0, &disks.store.0] {
                b.record_history();
            }
        }
        let clock = Arc::new(NodeClock::new(self.clock.clone()));
        let store = Store::open(Box::new(disks.store.0.clone()), Box::new(disks.store.1.clone()), Box::new(SeededRng::from_u64(seed ^ 1))).expect("store");
        let c: Arc<dyn Clock> = clock.clone();
        let engine = Engine::create(Box::new(disks.engine.0.clone()), Box::new(disks.engine.1.clone()), store.cipher(), osis_engine::Config::default(), c, Box::new(SeededRng::from_u64(seed))).expect("engine");
        let mut key = [0u8; 32];
        self.rng.fill_bytes(&mut key);
        let key = NodeKey(key);
        let node = Node::open(engine, store.clone(), SyncConfig { key: Some(key), ..SyncConfig::default() }, Box::new(SeededRng::from_u64(seed ^ 2)));
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

    /// What an attacker holding node `i`'s device recovers (`Engine::forensic`: every row and
    /// blob its engine's and store's disks were given since it was added under `record`).
    pub fn forensic(&mut self, i: usize) -> Vec<osis_store::Recovered> {
        assert!(self.record, "forensic needs a recording world");
        let n = self.nodes.get_mut(i).expect("no such node");
        let (eb, sb) = (n.disks.engine.0.clone(), n.disks.store.0.clone());
        n.node.engine().forensic(&eb, &sb).expect("forensic")
    }

    /// What node `i`'s two disks hold, engine's then store's: (rows, row bytes, blobs, blob bytes).
    pub fn disk_use(&self, i: usize) -> [(u64, u64, u64, u64); 2] {
        let d = &self.node(i).disks;
        [&d.engine.0, &d.store.0].map(|b| {
            let (rb, bb, bn) = b.held_split();
            (b.dump().len() as u64, rb, bn, bb)
        })
    }

    /// Debug builds: why node `i` still holds `t` (`Engine::why_kept`; notes/test-harnesses.md,
    /// Why kept and row dumps).
    #[cfg(debug_assertions)]
    pub fn why_kept(&mut self, i: usize, t: &Tid) -> String {
        self.engine(i).why_kept(t)
    }

    /// Debug builds: node `i`'s role on `t` and its secrets (`Engine::why_role`;
    /// notes/test-harnesses.md, Why kept and row dumps).
    #[cfg(debug_assertions)]
    pub fn why_role(&mut self, i: usize, t: &Tid) -> String {
        self.engine(i).why_role(t)
    }

    /// Debug: per node, how it syncs thing `t`, one line each: the sync IDs its sync store syncs
    /// with `t` among their things and how (`Store::syncs`), those `t` owns by its held `sync.0`
    /// (`Engine::sync_ids`, `hint` marked) and those carrying it (`Engine::carrying`). Sync IDs as
    /// the trace prints them, so a reader syncing another sync ID than its writers shows at once.
    pub fn sync_ids_of(&mut self, t: &Tid) -> String {
        let s = trace::short;
        let mut out = Vec::new();
        for i in 0..self.nodes.len() {
            let synced: Vec<String> = self.store(i).syncs().into_iter().filter(|(_, (ts, _))| ts.contains(t)).map(|(x, (_, h))| format!("{} {h:?}", s(&x))).collect();
            let e = self.engine(i);
            let line = osis_base::costs::paused(|| {
                let owned: Vec<String> = e.sync_ids(t).map(|v| v.iter().map(|o| format!("{}{}", s(&o.id), if o.hint { " hint" } else { "" })).collect()).unwrap_or_else(|x| vec![format!("{x:?}")]);
                let carrying: Vec<String> = e.carrying(t).map(|v| v.iter().map(s).collect()).unwrap_or_else(|x| vec![format!("{x:?}")]);
                format!("n{i}: syncs [{}]; owns [{}]; carrying [{}]", synced.join(", "), owned.join(", "), carrying.join(", "))
            });
            out.push(line);
        }
        out.join("\n")
    }

    /// Debug builds: commit `c` named, for a trace's `C..` (`Engine::describe_commit`, by the
    /// first node holding its record), each node's tid marked `(n<j>)`.
    #[cfg(debug_assertions)]
    pub fn describe_commit(&mut self, c: &osis_base::CommitId) -> String {
        let names: Vec<(String, String)> = (0..self.nodes.len()).map(|j| (self.engine(j).tid().to_string(), format!("n{j}"))).collect();
        let Some(mut d) = (0..self.nodes.len()).find_map(|i| self.engine(i).describe_commit(c)) else {
            return format!("{c:?}: held by no node");
        };
        for (tid, name) in names {
            d = d.replace(&tid, &format!("{tid} ({name})"));
        }
        d
    }

    /// Debug builds: node `i`'s local rows, its engine's (`"engine"`) and its sync store's
    /// (`"store"`), described by its engine (`Engine::describe_rows`), where the family starts
    /// with `prefix` and, with `tid`, the row names it.
    #[cfg(debug_assertions)]
    pub fn rows(&mut self, i: usize, prefix: &str, tid: Option<&Tid>) -> Vec<(&'static str, osis_engine::engine::Row)> {
        let store = self.store(i).with_read(|t| t.scan_local(b"", b"", usize::MAX)).expect("scan").into_iter().map(|kv| (kv.0, kv.1)).collect();
        let e = self.engine(i);
        let mut out: Vec<_> = e.rows(prefix.as_bytes(), tid).expect("rows").into_iter().map(|r| ("engine", r)).collect();
        out.extend(e.describe_rows(store, prefix.as_bytes(), tid).into_iter().map(|r| ("store", r)));
        out
    }

    /// Node `i`'s store, for reads.
    pub fn store(&self, i: usize) -> &Store {
        self.node(i).node.store()
    }

    /// Runs `f` on node `i`'s engine, then tells the node it wrote (or, when the write crashed
    /// its device, restarts it in place).
    pub fn write<T>(&mut self, i: usize, f: impl FnOnce(&mut Engine) -> T) -> T {
        let t = f(self.engine(i));
        self.noted(Some(i));
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
        self.deliver(i, Input::Tick);
    }

    /// Steps node `i` with `input` and carries out every output: the one place a node is stepped.
    pub fn deliver(&mut self, i: usize, input: Input) {
        self.deliveries += 1;
        *self.delivered.entry(i).or_default() += 1;
        MOST.set(MOST.get().max(self.deliveries));
        if CANDIDATE_CAP.get().is_some_and(|c| self.deliveries > c && c < self.cap) {
            std::panic::panic_any(Capped);
        }
        if self.deliveries > self.cap {
            let flowing: Vec<Seen> = self.net.queue.iter().take(8).map(|(n, x)| Seen::of(*n, x, self.node(*n).clock.mono())).collect();
            let off: Vec<usize> = (0..self.net.online.len()).filter(|n| !self.online(*n)).collect();
            let (busiest, most) = self.delivered.iter().max_by_key(|x| *x.1).map_or((0, 0), |(n, k)| (*n, *k));
            panic!(
                "storm: past the cap of {} deliveries over this world's whole run (not one `run`: a long test or the dial ticks toward a partitioned or powered-off peer add up; `World::cap` raises it, `flush()` delivers without firing wakes); node {busiest} stepped most ({most} deliveries), its wake {:?} at {:?}; partitioned {:?}, powered off {off:?}; still flowing (first 8 of {}): {flowing:?}; wakes {:?}",
                self.cap, self.net.wakes.get(&busiest), self.now(), self.net.cut_off, self.net.queue.len(), self.net.wakes
            );
        }
        let seen = Seen::of(i, &input, self.node(i).clock.mono());
        if self.trace {
            self.seen.push(seen.clone());
        }
        let traced = self.tracer.as_ref().is_some_and(|t| t.traces(i));
        // engine and node lines (`osis_base::trace`) from outside a step: a check's reads
        self.noted(None);
        if traced && let Some(t) = self.tracer.as_mut() {
            let conn = match &input {
                Input::Up { conn, .. } | Input::Bytes { conn, .. } => Some(*conn),
                _ => None,
            };
            t.received(i, &input, conn.and_then(|c| self.net.links.get(&(i, c))).map(|x| x.0));
        }
        if let Some(l) = self.liars.get_mut(&i) {
            match &input {
                Input::Bytes { conn, bytes } => {
                    let nodes = &self.nodes;
                    l.heard(*conn, bytes, &|s, b| nodes.iter().any(|n| n.node.store().entry(s, b).ok().flatten().is_some_and(|e| e.role)));
                }
                Input::Closed { conn } | Input::Down { conn, .. } => l.closed(*conn),
                _ => {}
            }
        }
        let n = self.nodes.get_mut(i).expect("no such node");
        let restarts = n.node.restarts();
        let mut out = n.node.handle(input);
        let (restarted, rounds) = (n.node.restarts() > restarts, n.node.rounds());
        self.noted(Some(i));
        if self.trace {
            self.stepped.push((i, restarted, out.iter().filter(|o| matches!(o, Out::Send(..))).count()));
        }
        // round counts a test reads with `costs::take` (notes/test-harnesses.md, Measuring)
        osis_base::costs::count("settle steps", 1);
        osis_base::costs::count("settle rounds", rounds);
        osis_base::costs::peak("settle rounds most", rounds);
        if rounds > ROUND_CAP {
            panic!("settle loop: {rounds} rounds in one step ({seen:?})");
        }
        // one place of outputs (scenario one-wake-last): a step gives at most one wake, last
        let wakes = out.iter().filter(|o| matches!(o, Out::Wake(_))).count();
        assert!(wakes <= 1 && (wakes == 0 || matches!(out.last(), Some(Out::Wake(_)))), "a step's wake is one and last: {out:?}");
        if let Some(l) = self.liars.get_mut(&i) {
            out = l.rewrite(out);
        }
        if traced && let Some(t) = self.tracer.as_mut() {
            let links = &self.net.links;
            t.sent(i, &out, |c| links.get(&(i, c)).map(|x| x.0));
        }
        let boot = self.node(i).clock.boot();
        apply(out, &mut NodeLinks { net: &mut self.net, node: i, boot });
        self.crashed(i);
        if traced {
            self.traced(i);
        }
    }

    /// With `parks`, every entry of each node on waiting for a read secret is parked
    /// (`Node::lost_parks`, a full scan): after each step, not each delivery (an entry left
    /// unparked stays unopened, so the step's end still finds it).
    pub fn check_parks(&mut self) {
        if !self.parks {
            return;
        }
        for i in 0..self.nodes.len() {
            if !self.online(i) {
                continue;
            }
            let lost = self.nodes.get_mut(i).expect("no such node").node.lost_parks().expect("a full scan");
            assert!(lost.is_empty(), "node {i}: entries waiting for a read secret, not parked: {lost:?} (after {} deliveries)", self.deliveries);
        }
    }

    /// Stops this world's trace (`OSIS_SYNC_TRACE`): a replay that would print it again.
    pub fn untrace(&mut self) {
        self.tracer = None;
    }

    /// Debug builds, traced: hands the trace the lines the engines and nodes noted
    /// (`osis_base::trace`: verdicts moving, lost access, refused transactions) as node `i`'s
    /// (`None`: noted outside a step, printed as `n?`); turns the sink on for this thread.
    fn noted(&mut self, i: Option<usize>) {
        #[cfg(debug_assertions)]
        if let Some(t) = self.tracer.as_mut() {
            if !osis_base::trace::on() {
                osis_base::trace::set(true);
            }
            let lines = osis_base::trace::take();
            if i.is_none_or(|i| t.traces(i)) {
                t.noted(i, lines);
            }
        }
        #[cfg(not(debug_assertions))]
        let _ = i;
    }

    /// The trace of node `i`'s step: what it holds now against before, then the step's lines.
    fn traced(&mut self, i: usize) {
        let Some(mut t) = self.tracer.take() else { return };
        let store = self.store(i);
        let entries = store.held_ids().unwrap_or_default().into_iter().flat_map(|s| store.entries(&s).unwrap_or_default().into_iter().map(move |e| (s, e.blob))).collect();
        let commits = self.engine(i).commit_ids().into_iter().collect();
        t.applied(i, entries, commits);
        let mut things = Vec::new();
        for k in t.things() {
            let Some((tid, maker)) = self.history.things.get(k).copied() else { continue };
            things.push(tid.to_string());
            for s in self.engine(maker).sync_ids(&tid).map(|v| v.iter().map(|o| trace::short(&o.id)).collect::<Vec<_>>()).unwrap_or_default() {
                things.push(s);
            }
        }
        t.flush(self.deliveries, self.now().0.saturating_sub(START.0), &things);
        self.tracer = Some(t);
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
        let boot = self.node(i).clock.boot();
        apply(out, &mut NodeLinks { net: &mut self.net, node: i, boot });
    }

    /// Delivers the next input in flight now; whether there was one.
    pub fn step(&mut self) -> bool {
        let Some((i, input)) = self.net.queue.pop_front() else { return false };
        if self.online(i) {
            self.deliver(i, input);
        }
        true
    }

    /// One input: the next in flight, else the earliest wake or held-back input within the
    /// horizon (`run`'s order, one at a time). False at quiet.
    pub fn step_or_wake(&mut self) -> bool {
        if self.step() {
            return true;
        }
        let horizon = WallMs(self.now().0.saturating_add(self.horizon_ms));
        let Some(at) = self.net.next_due(horizon) else { return false };
        self.fire(at);
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
    /// held-back input within `horizon_ms`, until neither is left. A complete pass still under way
    /// there ends within `PASS_WAIT_MS` (spec/sync-status.md §1): quiet waits it out, once.
    pub fn run(&mut self) {
        let mut horizon = WallMs(self.now().0.saturating_add(self.horizon_ms));
        let mut waited = false;
        loop {
            self.flush();
            match self.net.next_due(horizon) {
                Some(at) => self.fire(at),
                None if !waited && self.passes_under_way() => {
                    waited = true;
                    horizon = WallMs(self.now().0.saturating_add(osis_proto::limits::PASS_WAIT_MS));
                }
                None => break,
            }
        }
        // a by-hand replay inspecting the world (notes/test-harnesses.md, Why kept and row dumps);
        // the checks are the harness's: their reads are not the product's work
        if osis_base::testenv::end_checks() {
            osis_base::costs::paused(|| {
                self.sources_are_members();
                self.unlogged_must_holds();
                self.wanted_blobs_in_reach();
            });
        }
    }

    /// Whether an online node has a complete pass under way.
    fn passes_under_way(&self) -> bool {
        (0..self.nodes.len()).filter(|i| self.online(*i)).any(|i| self.node(i).node.status().values().any(|x| x.pass_waits.is_some()))
    }

    /// At quiet, every source status counts of S at a node is a connection up on which S is a
    /// member (spec/sync-status.md §1: the sources connected now), whatever closed the member.
    fn sources_are_members(&mut self) {
        let mut stale = Vec::new();
        for i in (0..self.nodes.len()).filter(|i| self.online(*i)) {
            let up: BTreeSet<ConnId> = self.net.links.keys().filter(|(m, _)| *m == i).map(|(_, c)| *c).collect();
            for (s, st) in self.node(i).node.status() {
                for c in st.sources.keys() {
                    if !up.contains(c) || !self.node(i).node.opens().members(*c).contains_key(&s) {
                        stale.push((i, s, *c));
                    }
                }
            }
        }
        assert!(stale.is_empty(), "sources status counts that are no member at quiet (node, S, conn): {stale:?}");
    }

    /// At quiet, each node logs every body it judges must-hold under S, wherever a reader can
    /// pull S from it and the body counts as held (spec/sync-judgement.md §2: must-hold only what
    /// it may log under S; §3 Own store).
    fn unlogged_must_holds(&mut self) {
        let mut stuck = Vec::new();
        for i in 0..self.nodes.len() {
            let reach = self.engine(i).publishes_dial().unwrap();
            for c in self.engine(i).commit_ids() {
                let bodies = self.engine(i).sync_bodies(&c).unwrap();
                for (s, on) in bodies.keys() {
                    let id = osis_engine::sync::BodyId { commit: c, on: *on };
                    if self.node(i).node.body_verdict(s, &id) != Some(osis_sync::read::Verdict::Must) {
                        continue;
                    }
                    if !reach && self.node(i).node.status_of(s).is_none_or(|x| x.sources.is_empty()) {
                        continue;
                    }
                    if self.engine(i).read_facts(s, &id).unwrap().missing {
                        continue;
                    }
                    let blobs = self.body_blobs(i, s, &id);
                    if !blobs.iter().any(|b| self.store(i).entry(s, b).unwrap().is_some()) {
                        stuck.push((i, *s, id));
                    }
                }
            }
        }
        let statuses: BTreeSet<String> = stuck.iter().map(|(i, s, _)| format!("\n  node {i} {s:?}: {:?}", self.node(*i).node.status_of(s))).collect();
        assert!(stuck.is_empty(), "must-hold bodies with no entry at quiet (node, S, commit): {stuck:?}\nS's status there:{}", statuses.into_iter().collect::<String>());
        self.unreached_must_holds();
    }

    /// The blobs of body `id` under `s` as node `i` opened or sealed them (`Engine::blob_body`).
    fn body_blobs(&mut self, i: usize, s: &osis_base::SyncId, id: &osis_engine::sync::BodyId) -> Vec<osis_base::BlobId> {
        let blobs = self.engine(i).commit_blobs(&id.commit).unwrap();
        blobs.iter().copied().filter(|b| self.engine(i).blob_body(s, b).unwrap() == Some(*id)).collect()
    }

    /// At quiet, a body some node judges must-hold under S (so may log, and logs) reaches every
    /// reader of S connected to it, caught up on S there and able to open that node's entry of
    /// it (spec/sync-judgement.md §2 Loggable is no way to lose a body a reader needs: who may
    /// log it does). Not while a node lies (it may withhold).
    fn unreached_must_holds(&mut self) {
        if !self.liars.is_empty() {
            return;
        }
        let mut lost = Vec::new();
        let on: Vec<usize> = (0..self.nodes.len()).filter(|j| self.online(*j)).collect();
        for &j in &on {
            let peers: BTreeMap<ConnId, usize> = self.net.links.iter().filter(|((m, _), _)| *m == j).map(|((_, c), (t, _))| (*c, *t)).collect();
            for (s, (t, h)) in self.store(j).syncs() {
                if h != osis_engine::sync::Holding::Read {
                    continue;
                }
                let Some(st) = self.node(j).node.status_of(&s) else { continue };
                let holders: Vec<usize> = st.sources.iter().filter(|(_, x)| x.caught_up).filter_map(|(c, _)| peers.get(c).copied()).filter(|i| on.contains(i)).collect();
                let secrets: Vec<_> = t.iter().flat_map(|t| self.engine(j).read_secrets(t)).flat_map(|x| [x.clone(), osis_crypto::roles_secret(&x)]).collect();
                for i in holders {
                    let ids: Vec<osis_engine::sync::BodyId> = self.engine(i).commit_ids().into_iter().flat_map(|c| self.engine(i).sync_bodies(&c).unwrap().keys().filter(|k| k.0 == s).map(|k| osis_engine::sync::BodyId { commit: c, on: k.1 }).collect::<Vec<_>>()).collect();
                    for c in ids {
                        if self.node(i).node.body_verdict(&s, &c) != Some(osis_sync::read::Verdict::Must) {
                            continue;
                        }
                        let blobs = self.body_blobs(i, &s, &c);
                        // needed: j opens the wrap of an entry of it at i (one under an epoch j
                        // never held, say before a cut, is not j's to read)
                        let opens = blobs.iter().any(|b| self.store(i).entry(&s, b).unwrap().is_some_and(|e| osis_blob::unwrap_any(secrets.iter(), b, &e.wrap).is_some()));
                        if !opens {
                            continue;
                        }
                        // held with no part of its body under S missing, or an entry of it
                        // fetched that waits to open (parked)
                        let reached = if self.engine(j).holds_commit(&c.commit) {
                            !self.engine(j).read_facts(&s, &c).unwrap().missing
                        } else {
                            blobs.iter().any(|b| self.store(j).entry(&s, b).unwrap().is_some())
                        };
                        if !reached {
                            lost.push((i, j, s, c));
                        }
                    }
                }
            }
        }
        let first = lost.first().map(|&(i, j, s, c)| self.lost_body(i, j, &s, &c)).unwrap_or_default();
        assert!(lost.is_empty(), "must-hold bodies a caught-up reader lacks at quiet (holder, reader, S, commit): {lost:?}\nthe first: {first}");
    }

    /// At quiet, no commit waits at a node for a blob in its reach: one its own sync store holds
    /// the bytes of, or one a source connected to it holds an entry of under a sync ID the node
    /// pulls from that source, which waits on neither full nor refusing (spec/sync-streams.md §5: a waiting commit's blobs are
    /// fetched from the sources showing them). Not while a node lies (it may withhold).
    fn wanted_blobs_in_reach(&mut self) {
        if !self.liars.is_empty() {
            return;
        }
        let mut stalled = Vec::new();
        let on: Vec<usize> = (0..self.nodes.len()).filter(|j| self.online(*j)).collect();
        for &j in &on {
            let wants = self.engine(j).blob_wants().unwrap().missing;
            if wants.is_empty() {
                continue;
            }
            let peers: BTreeMap<ConnId, usize> = self.net.links.iter().filter(|((m, _), _)| *m == j).map(|((_, c), (t, _))| (*c, *t)).collect();
            let status = self.node(j).node.status();
            for b in wants {
                if self.store(j).bytes(&b).unwrap().is_some() {
                    stalled.push((j, j, None, b));
                }
                for (s, st) in &status {
                    for (c, x) in st.sources.iter().filter(|(_, x)| x.waited()) {
                        let Some(i) = peers.get(c).copied().filter(|i| on.contains(i)) else { continue };
                        if self.store(i).entry(s, &b).unwrap().is_some() {
                            stalled.push((j, i, Some((*s, x.caught_up)), b));
                        }
                    }
                }
            }
        }
        let first = stalled.first().map(|(j, _, _, b)| {
            let waiting: Vec<String> = self.engine(*j).pending().into_iter().map(|(c, r)| format!("{c:?} {r:?}: {}", self.engine(*j).describe_commit(&c).unwrap_or_default())).collect();
            format!("{b:?}; pending at node {j}:\n  {}", waiting.join("\n  "))
        }).unwrap_or_default();
        assert!(stalled.is_empty(), "commits waiting at quiet for a blob in reach (node, holder, S and whether caught up there, blob): {stalled:?}\nthe first: {first}");
    }

    /// What holder `i` and reader `j` each hold of commit `c` under `s`, for a failing must-hold
    /// check: the reader's verdict and read facts, the commit's missing parts, and per blob each
    /// side's entry and whether the engine holds the body.
    fn lost_body(&mut self, i: usize, j: usize, s: &osis_base::SyncId, id: &osis_engine::sync::BodyId) -> String {
        let c = &id.commit;
        let mut out = format!("\n  body {id:?}");
        if let Some(h) = self.engine(i).header(c) {
            let parts: Vec<String> = h.aspects.iter().enumerate().map(|(ai, a)| format!("{ai} {:?} {}", a.tid, a.ak.as_str())).collect();
            out += &format!("\n  {:?} by {:?}: {}; S's things at the reader {:?}", h.kind, h.signer, parts.join(", "), self.store(j).syncs().into_iter().find(|(x, _)| x == s).map(|(_, (t, _))| t));
        }
        for (who, n) in [("holder", i), ("reader", j)] {
            let held = self.engine(n).holds_commit(c);
            let verdict = self.node(n).node.body_verdict(s, id);
            let facts = if held { format!("{:?}", self.engine(n).read_facts(s, id)) } else { "-".into() };
            let missing = self.engine(n).commit_parts_missing().get(c).cloned();
            out += &format!("\n  {who} {n}: holds commit {held}, verdict {verdict:?}, missing parts {missing:?}, facts {facts}");
            for b in self.engine(i).commit_blobs(c).unwrap().iter() {
                let entry = self.store(n).entry(s, b).unwrap().is_some();
                let body = self.engine(n).holds_body(s, b).unwrap();
                out += &format!("\n    blob {b:?}: entry {entry}, holds body {body}");
            }
        }
        out
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

    /// Moves the clock `ms` on with no wake fired between, as if every node slept through it, then
    /// runs: a long absence costs no dial ticks.
    pub fn jump(&mut self, ms: u64) {
        let to = WallMs(self.now().0.saturating_add(ms));
        self.set_clock(to);
        self.run();
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

    /// Ends `partition(a, b)` alone.
    pub fn rejoin(&mut self, a: usize, b: usize) {
        self.net.cut_off.remove(&(a.min(b), a.max(b)));
    }

    /// Node `i`'s wall clock runs `ms` ahead of the world's (behind when negative) from now on;
    /// its monotonic clock does not move.
    pub fn skew(&mut self, i: usize, ms: i64) {
        self.node(i).clock.skew.store(ms, Ordering::SeqCst);
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
    /// (`MemoryBackend::power_cut`; a crashed device powers up again) with its monotonic clock at
    /// 0, and is stepped again at `power_on`.
    pub fn power_off(&mut self, i: usize) {
        if let Some(t) = self.tracer.as_mut().filter(|t| t.traces(i)) {
            t.restarted(i);
        }
        self.net.cut(i, false);
        self.net.wakes.remove(&i);
        self.net.queue.retain(|(n, _)| *n != i);
        self.net.delayed.retain(|_, (n, _)| *n != i);
        self.net.held_until.retain(|(n, _), _| *n != i);
        self.net.paused.retain(|(n, _), _| *n != i);
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
        n.clock.boot.store(self.clock.mono().0, Ordering::SeqCst);
        let clock: Arc<dyn Clock> = n.clock.clone();
        let d = &n.disks;
        let store = Store::open(Box::new(d.store.0.clone()), Box::new(d.store.1.clone()), Box::new(SeededRng::from_u64(seed ^ 1))).expect("store reopens");
        let engine = Engine::open(Box::new(d.engine.0.clone()), Box::new(d.engine.1.clone()), store.cipher(), osis_engine::Config::default(), clock, Box::new(SeededRng::from_u64(seed))).expect("engine reopens");
        let cfg = n.node.config().clone();
        n.store = store.clone();
        n.node = Node::open(engine, store, cfg, Box::new(SeededRng::from_u64(seed ^ 2)));
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
                    let c = Arc::new(NodeClock { world: clock.clone(), skew: AtomicI64::new(n.clock.skew.load(Ordering::SeqCst)), boot: AtomicU64::new(n.clock.boot()) });
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
            delivered: BTreeMap::new(),
            cap: self.cap,
            horizon_ms: self.horizon_ms,
            trace: self.trace,
            seen: Vec::new(),
            stepped: Vec::new(),
            parks: self.parks,
            record: self.record,
            crashes: 0,
            history: self.history.clone(),
            fixture: None,
            tracer: self.tracer.clone(),
        }
    }
}

/// A copy of the world `build` makes, built once per process per `key` (a name for the build
/// and every parameter it takes), through the product's own flows. A second live copy of one
/// fixture in one test is refused; a fixture may be built on another.
pub fn fixture(key: &str, build: impl FnOnce() -> World) -> World {
    fixture_with(key, || (build(), ())).0
}

/// `fixture` with a value the build names (the things it made) handed out beside each copy.
pub fn fixture_with<T: Clone + Send + 'static>(key: &str, build: impl FnOnce() -> (World, T)) -> (World, T) {
    LIVE.with(|l| {
        if !l.borrow_mut().insert(key.to_string()) {
            panic!("fixture {key}: a second live copy in one test");
        }
    });
    let built = || {
        let (mut w, x) = build();
        // the kept original is no live copy of the fixture it was built on
        if let Some(k) = w.fixture.take() {
            LIVE.with(|l| l.borrow_mut().remove(&k));
        }
        (w, x)
    };
    let (mut w, x) = osis_base::copying::cached(key, built, |(w, x): &mut (World, T)| (w.copy(), x.clone()));
    w.fixture = Some(key.to_string());
    (w, x)
}

/// A plain edge of `role`: no `until`, may-grant flag, retain or floor.
pub fn edge(role: osis_base::Role) -> osis_schema::core_types::Edge {
    osis_schema::core_types::Edge { role, until: None, may_grant: false, retain: false, floor: None }
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

/// `contacts` with node 2 paired to node 1's account (`World::pair`: the product's pairing),
/// quiet: two sibling nodes and a contact.
pub fn siblings() -> World {
    fixture("siblings", || {
        let mut w = contacts();
        w.pair(1);
        w.run();
        w
    })
}

/// Two bare nodes (`World::add_bare_node`), quiet, no connection.
pub fn bare_pair() -> World {
    fixture("bare pair", || {
        let mut w = World::new(0);
        w.add_bare_node();
        w.add_bare_node();
        w.run();
        w
    })
}

/// Store caps of these policy entries, the rest default.
pub fn caps(policy: &[(&str, u64)]) -> osis_engine::sync::Caps {
    osis_engine::sync::Caps { policy: policy.iter().map(|(k, v)| (k.to_string(), *v)).collect(), ..Default::default() }
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
    /// The differential's writes (`history`), each by node i: mints a thing with its account as admin
    /// root (`New`) or with thing k as admin (`NewIn`), a value written, held by a strong from where it
    /// was made; writes thing k; gives a holder a role on thing k (`Give`: nothing more);
    /// `Grant`, a rule test's shorthand: gives node j's account the role and node j holds the
    /// thing from its account root; lowers a holder to a role; removes node j's account (`Remove`)
    /// or any holder (`Revoke`); rotates thing k's secrets; adds or removes a strong from its
    /// account root (`None`) or from a thing to thing k; pairs a new node to its account (the next
    /// index).
    New(usize),
    NewIn(usize, usize),
    Write(usize, usize),
    Give(usize, usize, history::Holder, history::Gives),
    Grant(usize, usize, usize, history::Gives),
    Lower(usize, usize, history::Holder, history::Gives),
    Remove(usize, usize, usize),
    Revoke(usize, usize, history::Holder),
    Rotate(usize, usize),
    Strong(usize, Option<usize>, usize),
    Unstrong(usize, Option<usize>, usize),
    Pair(usize),
}

/// Every name a printed script uses.
#[allow(unused_imports)]
pub mod script {
    pub use super::DiskFault::*;
    pub use super::Loss;
    pub use super::Step::*;
    pub use super::history::Gives::*;
    pub use super::history::Holder;
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
            Step::Give(i, k, h, g) => g.lesser().map(|x| Step::Give(*i, *k, *h, x)).into_iter().collect(),
            _ => Vec::new(),
        }
    }
}

/// The variable that shrinks a failing script.
pub const SHRINK_VAR: &str = "OSIS_SYNC_SHRINK";

/// Plays one step on `w`; a note of what it did (empty: nothing to say).
pub fn step(w: &mut World, s: &Step) -> String {
    let note = step_of(w, s);
    w.check_parks();
    note
}

fn step_of(w: &mut World, s: &Step) -> String {
    // a node a shrunk script no longer makes (its `Pair` dropped) is skipped, as history steps are
    let named = match s {
        Step::Partition(a, b) | Step::Cut(a, b) => vec![*a, *b],
        Step::PowerOff(i) | Step::PowerOn(i) | Step::Skew(i, _) | Step::Disk(i, ..) | Step::Lies(i, _) | Step::Truth(i) => vec![*i],
        _ => Vec::new(),
    };
    if named.iter().any(|i| *i >= w.len()) {
        return "skipped: no such node".into();
    }
    match s {
        Step::Run => {
            w.run();
            history::ran(w);
        }
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
        Step::New(..) | Step::NewIn(..) | Step::Write(..) | Step::Give(..) | Step::Grant(..) | Step::Lower(..) | Step::Remove(..) | Step::Revoke(..) | Step::Rotate(..) | Step::Strong(..) | Step::Unstrong(..) | Step::Pair(..) => return history::step(w, s),
    }
    String::new()
}

/// Plays `steps` on `w`, recording each so a failure prints the script with `replay` (the call
/// that replays it). The script is returned: held while the caller checks the outcome, a failed
/// check prints it too.
pub fn play(w: &mut World, steps: &[Step], replay: String) -> Script<Step> {
    let mut script = Script::new("crate::harness::script", SHRINK_VAR, replay);
    for (k, s) in steps.iter().enumerate() {
        if w.tracer.is_some() && !osis_base::testenv::quiet() {
            eprintln!("step {k}: {s:?}");
        }
        script.push(s.clone(), String::new());
        let note = step(w, s);
        if !note.is_empty() {
            script.note(note);
        }
    }
    script
}

/// A shrink candidate (`shrinking`) that makes more than this many times the deliveries of the
/// run it shrinks counts as not failing: a storm the shrink made, not the failure (a failing run
/// that storms meets its world's own cap first). At 1 a candidate that only delivers in another
/// order may be cut; at infinity a livelocked candidate runs to its world's cap (`STORM_CAP`,
/// several histories' worth).
pub const SHRINK_STORM: u64 = 3;

thread_local! {
    /// The most deliveries any world on this thread has made (`shrinking` measures the run it
    /// shrinks by it).
    static MOST: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// The delivery cap of the shrink candidate this thread plays (`capped`).
    static CANDIDATE_CAP: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// The panic of a world past its candidate cap (`capped`).
struct Capped;

/// `f` with every world on this thread capped at `cap` deliveries: `None` when one went past
/// it (its world's own cap, when lower, panics as a storm as ever).
pub fn capped<T>(cap: u64, f: impl FnOnce() -> T) -> Option<T> {
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
    let prev = CANDIDATE_CAP.replace(Some(cap));
    let r = catch_unwind(AssertUnwindSafe(f));
    CANDIDATE_CAP.set(prev);
    match r {
        Ok(t) => Some(t),
        Err(e) if e.is::<Capped>() => None,
        Err(e) => resume_unwind(e),
    }
}

/// Runs `run` (which plays a script with `play`); with `OSIS_SYNC_SHRINK` set, a failure is
/// shrunk (`osis_base::testenv::shrinking`): each candidate played once by `replay(steps,
/// false)` under a delivery cap of `SHRINK_STORM` times the most any world of `run` made
/// (`capped`; past it the candidate does not fail), the shrunk run by `replay(steps, true)`.
pub fn shrinking(run: impl FnOnce(), replay: impl Fn(&[Step], bool)) {
    MOST.set(0);
    let base = std::cell::Cell::new(None);
    let candidate = |steps: &[Step], last: bool| {
        if last {
            return replay(steps, true);
        }
        // the run shrunk is measured before its first candidate plays
        let most = base.get().unwrap_or_else(|| MOST.get());
        base.set(Some(most));
        let _ = capped(most.saturating_mul(SHRINK_STORM).max(1), || replay(steps, false));
    };
    osis_base::testenv::shrinking(SHRINK_VAR, run, candidate, Step::simpler);
}

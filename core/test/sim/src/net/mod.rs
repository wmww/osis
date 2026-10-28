//! Phase B harness: real node sync engines (`SyncEngine`) and blind servers (osis-server `Hub`
//! over `BackendStore<MemoryBackend>`) exchanging proto bytes engine to engine, no tokio
//! (notes/architecture.md §2). Connections are ordered byte streams: a fault cuts one (a lost
//! message on a stream is a broken stream), delays a message (per-stream order kept), duplicates
//! one, or reorders deliveries across streams. Partitions block (node, server) and (server,
//! server) pairs; nodes and servers crash (now, or at a durable write) and restart over their
//! durable state; a server may lose its data; a node may lose its disk (recovery from the card).
//! Servers replicate to their peers (push). Everything is driven from one `Dice`.

pub mod adversary;
pub mod check;
pub mod library;
pub mod rogue;
pub mod scenarios;
pub mod skew;

use crate::check::Checker;
use crate::dice::Dice;
use crate::harness::{ClockSpec, Failure, Report, Res, T0, wall_of};
use crate::workload;
use osis_core::{Clock, CommitId, LabelId, ManualClock, Role, Tid, WallMs};
use osis_crypto::SeededRng;
use osis_label::Address;
use osis_node::flows::Done;
use osis_node::sync::{Action, ConnId, Event, SyncConfig, SyncEngine};
use osis_node::{Engine, Mutation};
use osis_schema::core_types as ct;
use osis_server::{BackendStore, Hub, HubOutput, Policy};
use osis_store::{Fault, Faults, MemoryBackend, MemoryRoot};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::mpsc::Receiver;

const TRACE: usize = 60;
/// Messages one settle may deliver before it calls the run a storm.
const STORM: u64 = 5_000;

/// Faults on connections, per message sent (off during quiescence).
#[derive(Clone, Copy, Debug, Default)]
pub struct LinkFaults {
    /// The message is lost and its connection cut.
    pub cut_pct: u32,
    /// The message arrives twice.
    pub dup_pct: u32,
    pub max_delay_ms: u64,
    /// Deliver any due message, not the earliest (each stream stays in order).
    pub reorder: bool,
}

/// Relative weights of the scheduler's events (0 disables one).
#[derive(Clone, Copy, Debug)]
pub struct NetWeights {
    pub write: u32,
    pub deliver: u32,
    pub tick: u32,
    pub crash: u32,
    pub restart: u32,
    pub server_crash: u32,
    pub server_restart: u32,
    pub partition: u32,
    pub heal: u32,
}

impl Default for NetWeights {
    fn default() -> NetWeights {
        NetWeights { write: 3, deliver: 12, tick: 2, crash: 0, restart: 0, server_crash: 0, server_restart: 0, partition: 0, heal: 0 }
    }
}

#[derive(Clone, Debug)]
pub struct NetConfig {
    pub faults: LinkFaults,
    pub weights: NetWeights,
    /// A tick advances virtual time by 1..=this.
    pub max_tick_ms: u64,
    pub policy: Policy,
}

impl Default for NetConfig {
    fn default() -> NetConfig {
        NetConfig { faults: LinkFaults::default(), weights: NetWeights::default(), max_tick_ms: 20_000, policy: Policy::default() }
    }
}

thread_local! {
    static FULL_PASSES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `f` with every node added meanwhile on this thread judging everything at each pass
/// (`SyncConfig::full_passes`): the reference the work sets are compared against.
pub fn with_full_passes<T>(f: impl FnOnce() -> T) -> T {
    let was = FULL_PASSES.with(|x| x.replace(true));
    let r = f();
    FULL_PASSES.with(|x| x.set(was));
    r
}

/// One simulated device.
pub struct NetNode {
    pub sync: Option<SyncEngine>,
    events: Option<Receiver<osis_node::Event>>,
    backend: MemoryBackend,
    root: MemoryRoot,
    pub faults: Faults,
    pub clock: Arc<ManualClock>,
    pub spec: ClockSpec,
    pub cfg: SyncConfig,
    wake: Option<u64>,
    pub up: bool,
    /// Its disk is gone for good.
    pub lost: bool,
    pub tid: Tid,
    /// Bytes the node sent (to servers and peers) so far.
    pub sent_bytes: u64,
}

impl NetNode {
    /// When the node asked to be woken (its last `Wake` not yet fired).
    pub fn wake_at(&self) -> Option<u64> {
        self.wake
    }
}

/// One blind server.
pub struct NetServer {
    hub: Option<Hub<MemoryBackend>>,
    backend: MemoryBackend,
    pub faults: Faults,
    pub key: [u8; 32],
    pub address: Address,
    /// Servers it replicates to.
    pub peers: Vec<usize>,
    pub up: bool,
    /// A dishonest server: what it does to its outgoing messages.
    pub evil: Option<Evil>,
    /// Messages it sent per connection (an evil server replays them).
    sent: BTreeMap<u64, Vec<Vec<u8>>>,
}

/// A dishonest server's behavior on what it sends (adversary scenarios): per message, silently
/// drop it (the stream stays up), hold it back and send it after the next one or when `quiet`
/// starts (reorder within the stream; never while calm), or also replay an older message of the
/// same connection.
#[derive(Clone, Copy, Debug, Default)]
pub struct Evil {
    pub drop_pct: u32,
    pub hold_pct: u32,
    pub replay_pct: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Party {
    N(usize),
    S(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    Node(usize, ConnId),
    Hub(usize, u64),
}

impl End {
    fn party(self) -> Party {
        match self {
            End::Node(n, _) => Party::N(n),
            End::Hub(s, _) => Party::S(s),
        }
    }
}

struct Link {
    dialer: End,
    acceptor: End,
    /// Latest delivery time queued per direction (to dialer, to acceptor): streams stay ordered.
    last: [u64; 2],
}

enum Payload {
    Up,
    Bytes(Vec<u8>),
    Down,
}

struct Msg {
    link: u64,
    to: End,
    at: u64,
    seq: u64,
    what: Payload,
}

/// (label, blob) -> (commit, delta parts) of every commit blob a node opened.
pub type Known = BTreeMap<(LabelId, osis_core::BlobId), (CommitId, Vec<(usize, usize)>)>;

/// A labeled group the scenario writes to, and the things written.
#[derive(Clone, Debug)]
pub struct Group {
    pub g: Tid,
    /// Its owner (the group itself for a person's home).
    pub owner: Tid,
    pub items: Vec<Tid>,
}

pub struct NetSim {
    pub scenario: String,
    pub seed: u64,
    pub dice: Dice,
    /// Virtual time since T0 (ms); servers run on true time.
    pub elapsed: u64,
    server_clock: Arc<ManualClock>,
    pub nodes: Vec<NetNode>,
    pub servers: Vec<NetServer>,
    pub groups: Vec<Group>,
    pub cfg: NetConfig,
    pub report: Report,
    /// No new writes, crashes, partitions or message faults: setup and quiescence (`run` turns
    /// them on, `run_until_quiescent` off again).
    pub calm: bool,
    links: BTreeMap<u64, Link>,
    next_link: u64,
    next_hub_conn: u64,
    queue: Vec<Msg>,
    seq: u64,
    pub blocked: BTreeSet<(Party, Party)>,
    /// Pairs that never connect (partitions healed at quiescence are `blocked`).
    pub unreachable: BTreeSet<(Party, Party)>,
    trace: VecDeque<String>,
    check: Checker,
    /// Every commit blob any node opened under a label: (label, blob) -> (commit, parts).
    pub known: Known,
    /// Purges issued: (commit, thing, aspect).
    pub purged: Vec<(CommitId, Tid, osis_core::Ak)>,
    /// Tombstones seen per server (cleared when the server loses its data).
    pub tombs: BTreeMap<usize, BTreeSet<(LabelId, osis_core::BlobId)>>,
    /// Nodes no check expects to read (removed, stranded on purpose).
    pub excused: BTreeSet<usize>,
    /// The person each node is a device of.
    pub person_of: BTreeMap<usize, Tid>,
    /// Print every trace line (`OSIS_SIM_TRACE`).
    pub verbose: bool,
    /// Invariants switched off for a scenario, each naming the issue that breaks it.
    pub waivers: BTreeSet<&'static str>,
    /// Record entry kinds after every node call (failure detail).
    watch: bool,
    /// Servers whose stores the label invariants do not judge (adversaries).
    pub dishonest: BTreeSet<usize>,
    /// Commits expected to stay parked at quiescence (version skew: a newer format).
    pub parked_ok: BTreeSet<CommitId>,
    /// Entries each node sent by Upload while `count_uploads` is on: (node, label, blob).
    pub uploads: Vec<(usize, LabelId, osis_core::BlobId)>,
    pub count_uploads: bool,
    /// Held-back messages of evil servers per connection.
    held: BTreeMap<(usize, u64), Vec<u8>>,
    /// Blobs whose uploads and deposits by nodes are counted in `sent_watched` (adversaries).
    pub watched: BTreeSet<osis_core::BlobId>,
    pub sent_watched: u64,
}

/// The proto messages in a run of bytes, shortened (trace only).
fn frames(b: &[u8]) -> String {
    let mut d = osis_proto::FrameDecoder::default();
    d.push(b);
    let mut v = Vec::new();
    while let Ok(Some(f)) = d.next_frame() {
        let s = match osis_proto::Message::decode(&f) {
            Ok(m) => format!("{m:?}"),
            Err(_) => format!("<{} bytes>", f.len()),
        };
        v.push(s.chars().take(110).collect::<String>());
    }
    if v.is_empty() { format!("<{} bytes>", b.len()) } else { v.join(" | ") }
}

/// Uploads and deposits of `watched` blobs among the frames in `b`.
fn watched_in(watched: &BTreeSet<osis_core::BlobId>, b: &[u8]) -> u64 {
    let mut d = osis_proto::FrameDecoder::default();
    d.push(b);
    let mut n = 0u64;
    while let Ok(Some(f)) = d.next_frame() {
        let blobs: Vec<Vec<u8>> = match osis_proto::Message::decode(&f) {
            Ok(osis_proto::Message::Upload { entries, .. } | osis_proto::Message::Sync { entries, .. }) => entries.into_iter().map(|e| e.blob).collect(),
            Ok(osis_proto::Message::Deposit { blob, .. }) => vec![blob],
            _ => Vec::new(),
        };
        n += blobs.iter().filter(|x| watched.contains(&osis_label::blob_id(x))).count() as u64;
    }
    n
}

pub fn server_key(i: usize) -> [u8; 32] {
    let mut k = [0x50u8; 32];
    k[0] = 0x50u8.wrapping_add(i as u8);
    k
}

fn open_engine(backend: &MemoryBackend, root: &MemoryRoot, clock: &Arc<ManualClock>, seed: u64, create: bool) -> osis_node::Result<Engine> {
    let c: Arc<dyn Clock> = clock.clone();
    let rng = Box::new(SeededRng::from_u64(seed));
    if create {
        Engine::create(Box::new(backend.clone()), Box::new(root.clone()), osis_node::Config::default(), c, rng)
    } else {
        Engine::open(Box::new(backend.clone()), Box::new(root.clone()), osis_node::Config::default(), c, rng)
    }
}

impl NetSim {
    pub fn new(scenario: &str, seed: u64, cfg: NetConfig) -> NetSim {
        NetSim {
            scenario: scenario.into(),
            seed,
            dice: Dice::new(seed),
            elapsed: 0,
            server_clock: Arc::new(ManualClock::new(WallMs(T0))),
            nodes: Vec::new(),
            servers: Vec::new(),
            groups: Vec::new(),
            cfg,
            report: Report::default(),
            calm: true,
            links: BTreeMap::new(),
            next_link: 1,
            next_hub_conn: 1,
            queue: Vec::new(),
            seq: 0,
            blocked: BTreeSet::new(),
            unreachable: BTreeSet::new(),
            trace: VecDeque::new(),
            check: Checker::default(),
            known: BTreeMap::new(),
            purged: Vec::new(),
            tombs: BTreeMap::new(),
            excused: BTreeSet::new(),
            person_of: BTreeMap::new(),
            verbose: std::env::var_os("OSIS_SIM_TRACE").is_some(),
            waivers: BTreeSet::new(),
            watch: false,
            dishonest: BTreeSet::new(),
            parked_ok: BTreeSet::new(),
            uploads: Vec::new(),
            count_uploads: false,
            held: BTreeMap::new(),
            watched: BTreeSet::new(),
            sent_watched: 0,
        }
    }

    pub fn fail(&self, what: impl Into<String>) -> Failure {
        Failure { scenario: self.scenario.clone(), seed: self.seed, step: self.report.steps, what: what.into(), trace: self.trace.iter().cloned().collect() }
    }

    pub fn note(&mut self, s: String) {
        if self.trace.len() == TRACE {
            self.trace.pop_front();
        }
        let line = format!("[{} t+{}ms] {s}", self.report.steps, self.elapsed);
        if self.verbose {
            eprintln!("{line}");
        }
        self.trace.push_back(line);
    }

    pub fn now(&self) -> u64 {
        T0.saturating_add(self.elapsed)
    }

    pub fn waived(&self, issue: &str) -> bool {
        self.waivers.contains(issue)
    }

    // ---- servers

    pub fn add_server(&mut self) -> Res<usize> {
        let i = self.servers.len();
        let key = server_key(i);
        let faults = Faults::new();
        let backend = MemoryBackend::with_faults(faults.clone());
        self.servers.push(NetServer { hub: None, backend, faults, key, address: Address { url: format!("quic://server{i}:1"), key }, peers: Vec::new(), up: false, evil: None, sent: BTreeMap::new() });
        self.start_server(i)?;
        Ok(i)
    }

    fn start_server(&mut self, s: usize) -> Res<()> {
        let seed = self.dice.u64();
        let clock: Arc<dyn Clock> = self.server_clock.clone();
        let policy = self.cfg.policy.clone();
        let sv = self.server(s)?;
        sv.faults.revive();
        let store = BackendStore::open(sv.backend.clone(), clock, policy, &mut SeededRng::from_u64(seed));
        let store = store.map_err(|e| self.fail(format!("server {s} open: {e}")))?;
        let sv = self.server(s)?;
        sv.hub = Some(Hub::new(store, sv.key, Box::new(SeededRng::from_u64(seed ^ 0x5eed))));
        sv.up = true;
        Ok(())
    }

    /// Server `a` replicates to `b` and back.
    pub fn replicate(&mut self, a: usize, b: usize) -> Res<()> {
        self.server(a)?.peers.push(b);
        self.server(b)?.peers.push(a);
        Ok(())
    }

    fn server(&mut self, s: usize) -> Res<&mut NetServer> {
        let f = self.fail(format!("no server {s}"));
        self.servers.get_mut(s).ok_or(f)
    }

    pub fn address(&self, s: usize) -> Address {
        self.servers.get(s).map(|x| x.address.clone()).unwrap_or(Address { url: String::new(), key: [0; 32] })
    }

    pub fn addresses(&self, ss: &[usize]) -> Vec<Address> {
        ss.iter().map(|s| self.address(*s)).collect()
    }

    pub fn hub(&self, s: usize) -> Option<&Hub<MemoryBackend>> {
        self.servers.get(s).and_then(|x| x.hub.as_ref())
    }

    // ---- nodes

    /// A node knowing servers `servers` (its `SyncConfig.servers`).
    pub fn add_node(&mut self, servers: &[usize], spec: ClockSpec) -> Res<usize> {
        let cfg = SyncConfig { servers: self.addresses(servers), ..SyncConfig::default() };
        self.add_node_with(cfg, spec)
    }

    pub fn add_node_with(&mut self, mut cfg: SyncConfig, spec: ClockSpec) -> Res<usize> {
        cfg.full_passes |= FULL_PASSES.with(|x| x.get());
        let i = self.nodes.len();
        let faults = Faults::new();
        let backend = MemoryBackend::with_faults(faults.clone());
        let root = MemoryRoot::with_faults(faults.clone());
        let clock = Arc::new(ManualClock::new(WallMs(wall_of(spec, self.elapsed))));
        let seed = self.dice.u64();
        let engine = open_engine(&backend, &root, &clock, seed, true).map_err(|e| self.fail(format!("node {i} create: {e}")))?;
        let tid = engine.tid();
        self.nodes.push(NetNode { sync: None, events: None, backend, root, faults, clock, spec, cfg, wake: None, up: false, lost: false, tid, sent_bytes: 0 });
        self.boot(i, engine)?;
        Ok(i)
    }

    fn boot(&mut self, n: usize, mut engine: Engine) -> Res<()> {
        let seed = self.dice.u64();
        let events = engine.subscribe();
        let node = self.node(n)?;
        let c: Arc<dyn Clock> = node.clock.clone();
        let sync = SyncEngine::new(engine, c, Box::new(SeededRng::from_u64(seed)), node.cfg.clone());
        let sync = sync.map_err(|e| self.fail(format!("node {n} sync start: {e}")))?;
        let node = self.node(n)?;
        node.sync = Some(sync);
        node.events = Some(events);
        node.up = true;
        node.wake = None;
        self.feed(n, Event::Tick)
    }

    fn node(&mut self, n: usize) -> Res<&mut NetNode> {
        let f = self.fail(format!("no node {n}"));
        self.nodes.get_mut(n).ok_or(f)
    }

    pub fn sync(&mut self, n: usize) -> Res<&mut SyncEngine> {
        let f = self.fail(format!("node {n} is down"));
        self.node(n)?.sync.as_mut().ok_or(f)
    }

    pub fn engine(&mut self, n: usize) -> Res<&mut Engine> {
        Ok(self.sync(n)?.engine_mut())
    }

    pub fn tid(&self, n: usize) -> Res<Tid> {
        self.nodes.get(n).map(|x| x.tid).ok_or_else(|| self.fail(format!("no node {n}")))
    }

    pub fn is_up(&self, n: usize) -> bool {
        self.nodes.get(n).is_some_and(|x| x.up)
    }

    /// Feeds node `n` an event and carries out its actions.
    pub fn feed(&mut self, n: usize, ev: Event) -> Res<()> {
        let Some(node) = self.nodes.get_mut(n) else { return Ok(()) };
        if !node.up {
            return Ok(());
        }
        let Some(sync) = node.sync.as_mut() else { return Ok(()) };
        let acts = sync.handle(ev);
        self.after_node(n, acts)
    }

    /// After any call into node `n`: checker events, diagnostics, a crash, then its actions.
    fn after_node(&mut self, n: usize, acts: Vec<Action>) -> Res<()> {
        self.drain(n)?;
        if self.watch {
            self.observe_node(n);
        }
        if self.nodes.get(n).is_some_and(|x| x.faults.crashed()) {
            self.report.crashes = self.report.crashes.saturating_add(1);
            self.note(format!("node {n} crashed mid-write"));
            return self.node_down(n);
        }
        self.actions(n, acts)
    }

    /// Checker events and diagnostics of node `n`.
    fn drain(&mut self, n: usize) -> Res<()> {
        let Some(node) = self.nodes.get_mut(n) else { return Ok(()) };
        let evs: Vec<osis_node::Event> = node.events.as_ref().map(|r| r.try_iter().collect()).unwrap_or_default();
        let diags = node.sync.as_mut().map(|s| s.take_diagnostics()).unwrap_or_default();
        for ev in evs {
            let r = match self.nodes.get(n).and_then(|x| x.sync.as_ref()) {
                Some(s) => self.check.event(n, s.engine(), &ev),
                None => Ok(()),
            };
            r.map_err(|w| self.fail(w))?;
        }
        for d in diags {
            self.report.diagnostics = self.report.diagnostics.saturating_add(1);
            self.note(format!("node {n} diagnostic: {}", d.chars().take(160).collect::<String>()));
        }
        Ok(())
    }

    /// Carries out a node's actions.
    pub fn actions(&mut self, n: usize, acts: Vec<Action>) -> Res<()> {
        for a in acts {
            match a {
                Action::Dial { conn, address } => self.dial(n, conn, &address)?,
                Action::Send { conn, bytes } => {
                    if let Some(x) = self.nodes.get_mut(n) {
                        x.sent_bytes = x.sent_bytes.saturating_add(bytes.len() as u64);
                    }
                    if self.count_uploads {
                        let mut d = osis_proto::FrameDecoder::new();
                        d.push(&bytes);
                        while let Ok(Some(body)) = d.next_frame() {
                            if let Ok(osis_proto::Message::Upload { label, entries, .. }) = osis_proto::Message::decode(&body) {
                                self.uploads.extend(entries.iter().map(|e| (n, label, osis_label::blob_id(&e.blob))));
                            }
                        }
                    }
                    if !self.watched.is_empty() {
                        self.sent_watched = self.sent_watched.saturating_add(watched_in(&self.watched, &bytes));
                    }
                    if let Some((id, to)) = self.peer_end(End::Node(n, conn)) {
                        self.send(id, to, Payload::Bytes(bytes));
                    }
                }
                Action::Close { conn } => {
                    if let Some((id, to)) = self.peer_end(End::Node(n, conn)) {
                        self.links.remove(&id);
                        self.notify_closed(to);
                    }
                }
                Action::Wake { at } => self.node(n)?.wake = Some(at),
                // the simulated transport finds a node by its current `/reach`
                Action::Reach => {}
            }
        }
        Ok(())
    }

    fn dial(&mut self, n: usize, conn: ConnId, address: &Address) -> Res<()> {
        let s = self.servers.iter().position(|x| x.key == address.key);
        let ok = s.filter(|s| self.servers.get(*s).is_some_and(|x| x.up) && !self.is_blocked(Party::N(n), Party::S(*s)));
        let Some(s) = ok else {
            self.push(0, End::Node(n, conn), 0, Payload::Down);
            return Ok(());
        };
        let hc = self.next_hub_conn;
        self.next_hub_conn += 1;
        let id = self.next_link;
        self.next_link += 1;
        self.links.insert(id, Link { dialer: End::Node(n, conn), acceptor: End::Hub(s, hc), last: [0; 2] });
        self.send(id, End::Node(n, conn), Payload::Up);
        let mut peer = [0u8; 32];
        peer[..8].copy_from_slice(&self.dice.u64().to_le_bytes());
        let now = self.now();
        let out = match self.servers.get_mut(s).and_then(|x| x.hub.as_mut()) {
            Some(h) => h.accept(now, hc, peer),
            None => Vec::new(),
        };
        self.hub_out(s, out)
    }

    /// The link of an end and the other end.
    fn peer_end(&self, e: End) -> Option<(u64, End)> {
        self.links.iter().find_map(|(id, l)| {
            if l.dialer == e {
                Some((*id, l.acceptor))
            } else if l.acceptor == e {
                Some((*id, l.dialer))
            } else {
                None
            }
        })
    }

    pub fn is_blocked(&self, a: Party, b: Party) -> bool {
        [&self.blocked, &self.unreachable].iter().any(|s| s.contains(&(a, b)) || s.contains(&(b, a)))
    }

    fn push(&mut self, link: u64, to: End, at: u64, what: Payload) {
        self.seq += 1;
        let at = at.max(self.elapsed);
        self.queue.push(Msg { link, to, at, seq: self.seq, what });
    }

    /// Queues a message on a stream, through the faults.
    fn send(&mut self, id: u64, to: End, what: Payload) {
        self.report.sent = self.report.sent.saturating_add(1);
        if self.verbose
            && let Payload::Bytes(b) = &what
        {
            self.note(format!("link {id} -> {to:?}: {}", frames(b)));
        }
        let f = self.cfg.faults;
        let faulty = !self.calm && matches!(what, Payload::Bytes(_));
        if faulty && self.dice.pct(f.cut_pct) {
            self.report.dropped = self.report.dropped.saturating_add(1);
            self.note(format!("link {id} cut"));
            self.cut(id);
            return;
        }
        let delay = if self.calm { 0 } else { self.dice.below(f.max_delay_ms.saturating_add(1)) };
        let dir = usize::from(self.links.get(&id).is_some_and(|l| l.acceptor == to));
        let mut at = self.elapsed.saturating_add(delay);
        if let Some(l) = self.links.get_mut(&id)
            && let Some(last) = l.last.get_mut(dir)
        {
            at = at.max(*last);
            *last = at;
        }
        if faulty && self.dice.pct(f.dup_pct)
            && let Payload::Bytes(b) = &what
        {
            self.report.duplicated = self.report.duplicated.saturating_add(1);
            let copy = Payload::Bytes(b.clone());
            self.push(id, to, at, copy);
        }
        self.push(id, to, at, what);
    }

    /// Cuts a link: both ends learn it is gone.
    fn cut(&mut self, id: u64) {
        if let Some(l) = self.links.remove(&id) {
            self.notify_closed(l.dialer);
            self.notify_closed(l.acceptor);
        }
    }

    fn notify_closed(&mut self, e: End) {
        match e {
            End::Node(..) => {
                let d = if self.calm { 0 } else { self.dice.below(self.cfg.faults.max_delay_ms.saturating_add(1)) };
                let at = self.elapsed.saturating_add(d);
                self.push(0, e, at, Payload::Down);
            }
            End::Hub(s, hc) => {
                if let Some(h) = self.servers.get_mut(s).and_then(|x| x.hub.as_mut()) {
                    h.closed(hc);
                }
            }
        }
    }

    fn hub_out(&mut self, s: usize, out: Vec<HubOutput>) -> Res<()> {
        for o in out {
            match o {
                HubOutput::Send(hc, bytes) => {
                    let evil = self.servers.get(s).and_then(|x| x.evil);
                    let msgs = match evil {
                        Some(e) => self.evil_send(s, hc, e, bytes),
                        None => vec![bytes],
                    };
                    if let Some((id, to)) = self.peer_end(End::Hub(s, hc)) {
                        for b in msgs {
                            self.send(id, to, Payload::Bytes(b));
                        }
                    }
                }
                HubOutput::Close(hc) => {
                    if let Some((id, to)) = self.peer_end(End::Hub(s, hc)) {
                        self.links.remove(&id);
                        self.notify_closed(to);
                    }
                }
                HubOutput::Diagnostic(d) => {
                    self.report.diagnostics = self.report.diagnostics.saturating_add(1);
                    self.note(format!("server {s} diagnostic: {}", d.chars().take(160).collect::<String>()));
                }
            }
        }
        if self.servers.get(s).is_some_and(|x| x.up && x.faults.crashed()) {
            self.report.server_crashes = self.report.server_crashes.saturating_add(1);
            self.note(format!("server {s} crashed mid-write"));
            self.server_down(s)?;
        }
        Ok(())
    }

    /// What an evil server sends instead of `bytes` on connection `hc`.
    fn evil_send(&mut self, s: usize, hc: u64, e: Evil, bytes: Vec<u8>) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.dice.pct(e.drop_pct) {
            self.report.evil = self.report.evil.saturating_add(1);
            self.note(format!("server {s} drops a message on conn {hc}"));
        } else if !self.calm && !self.held.contains_key(&(s, hc)) && self.dice.pct(e.hold_pct) {
            self.report.evil = self.report.evil.saturating_add(1);
            self.held.insert((s, hc), bytes.clone());
        } else {
            out.push(bytes.clone());
            if let Some(h) = self.held.remove(&(s, hc)) {
                out.push(h);
            }
        }
        if self.dice.pct(e.replay_pct) {
            let old = self.servers.get(s).and_then(|x| x.sent.get(&hc)).and_then(|v| self.dice.pick(v).cloned());
            if let Some(o) = old {
                self.report.evil = self.report.evil.saturating_add(1);
                out.push(o);
            }
        }
        if let Some(sv) = self.servers.get_mut(s) {
            let v = sv.sent.entry(hc).or_default();
            if v.len() < 64 {
                v.push(bytes);
            }
        }
        out
    }

    /// Evil servers send what they held back (a delay, not a drop).
    fn flush_held(&mut self) {
        for ((s, hc), b) in std::mem::take(&mut self.held) {
            if let Some((id, to)) = self.peer_end(End::Hub(s, hc)) {
                self.send(id, to, Payload::Bytes(b));
            }
        }
    }

    fn links_of(&self, p: Party) -> Vec<u64> {
        self.links.iter().filter(|(_, l)| l.dialer.party() == p || l.acceptor.party() == p).map(|(id, _)| *id).collect()
    }

    /// Node `n` stops (crash, power off): its connections drop.
    pub fn node_down(&mut self, n: usize) -> Res<()> {
        for id in self.links_of(Party::N(n)) {
            if let Some(l) = self.links.remove(&id) {
                for e in [l.dialer, l.acceptor] {
                    if !matches!(e, End::Node(x, _) if x == n) {
                        self.notify_closed(e);
                    }
                }
            }
        }
        let node = self.node(n)?;
        node.up = false;
        node.sync = None;
        node.events = None;
        node.wake = None;
        Ok(())
    }

    /// Powers node `n` up again over its durable state.
    pub fn restart_node(&mut self, n: usize) -> Res<()> {
        let seed = self.dice.u64();
        let node = self.node(n)?;
        if node.lost {
            return Ok(());
        }
        node.faults.revive();
        let (b, r, c) = (node.backend.clone(), node.root.clone(), node.clock.clone());
        let engine = open_engine(&b, &r, &c, seed, false).map_err(|e| self.fail(format!("node {n} reopen: {e}")))?;
        self.report.restarts = self.report.restarts.saturating_add(1);
        self.note(format!("node {n} restarted"));
        self.boot(n, engine)
    }

    /// Node `n` loses its disk: gone for good.
    pub fn lose_disk(&mut self, n: usize) -> Res<()> {
        self.node_down(n)?;
        self.node(n)?.lost = true;
        self.excused.insert(n);
        self.note(format!("node {n} lost its disk"));
        Ok(())
    }

    /// Server `s` stops: its connections drop.
    pub fn server_down(&mut self, s: usize) -> Res<()> {
        for id in self.links_of(Party::S(s)) {
            if let Some(l) = self.links.remove(&id) {
                for e in [l.dialer, l.acceptor] {
                    if !matches!(e, End::Hub(x, _) if x == s) {
                        self.notify_closed(e);
                    }
                }
            }
        }
        let sv = self.server(s)?;
        sv.up = false;
        sv.hub = None;
        Ok(())
    }

    pub fn restart_server(&mut self, s: usize) -> Res<()> {
        self.note(format!("server {s} restarted"));
        self.report.restarts = self.report.restarts.saturating_add(1);
        self.start_server(s)
    }

    /// Server `s` loses everything it stored and starts empty.
    pub fn wipe_server(&mut self, s: usize) -> Res<()> {
        self.server_down(s)?;
        let sv = self.server(s)?;
        sv.faults = Faults::new();
        sv.backend = MemoryBackend::with_faults(sv.faults.clone());
        self.tombs.remove(&s);
        self.note(format!("server {s} lost its data"));
        self.start_server(s)
    }

    // ---- time

    /// Moves virtual time on by `ms` and fires what is due.
    pub fn advance(&mut self, ms: u64) -> Res<()> {
        self.elapsed = self.elapsed.saturating_add(ms);
        self.server_clock.set(WallMs(self.now()));
        for n in &self.nodes {
            n.clock.set(WallMs(wall_of(n.spec, self.elapsed)));
        }
        self.timers()
    }

    /// Node wakes, server ticks, server redials.
    fn timers(&mut self) -> Res<()> {
        let now = self.now();
        for s in 0..self.servers.len() {
            let due = self.servers.get(s).and_then(|x| x.hub.as_ref()).and_then(|h| h.next_due(now)).is_some_and(|t| t <= now);
            if due {
                let out = self.servers.get_mut(s).and_then(|x| x.hub.as_mut()).map(|h| h.tick(now)).unwrap_or_default();
                self.hub_out(s, out)?;
            }
        }
        self.redial()?;
        for n in 0..self.nodes.len() {
            let due = self.nodes.get(n).is_some_and(|x| x.up && x.wake.is_some_and(|w| w <= x.clock.now_wall_ms().0));
            if due {
                self.node(n)?.wake = None;
                self.feed(n, Event::Tick)?;
            }
        }
        Ok(())
    }

    /// Servers dial the peers they replicate to when not connected.
    fn redial(&mut self) -> Res<()> {
        for s in 0..self.servers.len() {
            let peers = self.servers.get(s).filter(|x| x.up).map(|x| x.peers.clone()).unwrap_or_default();
            for p in peers {
                let linked = self.links.values().any(|l| matches!(l.dialer, End::Hub(x, _) if x == s) && matches!(l.acceptor, End::Hub(y, _) if y == p));
                if linked || !self.servers.get(p).is_some_and(|x| x.up) || self.is_blocked(Party::S(s), Party::S(p)) {
                    continue;
                }
                let (hs, hp) = (self.next_hub_conn, self.next_hub_conn + 1);
                self.next_hub_conn += 2;
                let id = self.next_link;
                self.next_link += 1;
                self.links.insert(id, Link { dialer: End::Hub(s, hs), acceptor: End::Hub(p, hp), last: [0; 2] });
                let now = self.now();
                let (ks, kp) = (server_key(s), server_key(p));
                let out = self.servers.get_mut(p).and_then(|x| x.hub.as_mut()).map(|h| h.accept(now, hp, ks)).unwrap_or_default();
                self.hub_out(p, out)?;
                let out = self.servers.get_mut(s).and_then(|x| x.hub.as_mut()).map(|h| h.peer_up(now, hs, kp)).unwrap_or_default();
                self.hub_out(s, out)?;
            }
        }
        Ok(())
    }

    // ---- delivery

    /// Delivers one due message (the earliest, or under reorder any due stream head); waits for
    /// the earliest stream head when none is due (a message sent on a stream after its cut may
    /// be due before its predecessors). False when nothing is queued.
    fn deliver_next(&mut self) -> Res<bool> {
        let heads: Vec<usize> = (0..self.queue.len())
            .filter(|k| {
                let Some(m) = self.queue.get(*k) else { return false };
                !self.queue.iter().any(|o| o.link == m.link && o.link != 0 && o.to == m.to && o.seq < m.seq)
            })
            .collect();
        let Some(first) = heads.iter().filter_map(|k| self.queue.get(*k)).map(|m| m.at).min() else { return Ok(false) };
        if first > self.elapsed {
            self.advance(first - self.elapsed)?;
        }
        let heads: Vec<usize> = heads.into_iter().filter(|k| self.queue.get(*k).is_some_and(|m| m.at <= self.elapsed)).collect();
        let pick = if self.cfg.faults.reorder && !self.calm {
            self.dice.pick(&heads).copied()
        } else {
            heads.iter().copied().min_by_key(|k| self.queue.get(*k).map(|m| (m.at, m.seq)))
        };
        let Some(k) = pick else { return Ok(true) };
        let m = self.queue.remove(k);
        self.report.delivered = self.report.delivered.saturating_add(1);
        let alive = self.links.contains_key(&m.link);
        let now = self.now();
        match (m.to, m.what) {
            (End::Node(n, c), Payload::Down) => self.feed(n, Event::Down { conn: c })?,
            (End::Node(n, c), Payload::Up) if alive => self.feed(n, Event::Up { conn: c })?,
            (End::Node(n, c), Payload::Bytes(b)) if alive => self.feed(n, Event::Bytes { conn: c, bytes: b })?,
            (End::Hub(s, hc), Payload::Bytes(b)) if alive => {
                let out = self.servers.get_mut(s).and_then(|x| x.hub.as_mut()).map(|h| h.input(now, hc, b)).unwrap_or_default();
                self.hub_out(s, out)?;
            }
            _ => {}
        }
        Ok(true)
    }

    /// Delivers everything queued (time moving to each message), then what that queued.
    pub fn drain_queue(&mut self) -> Res<()> {
        let mut k = 0u64;
        while self.deliver_next()? {
            k += 1;
            if k > STORM {
                // what the storm keeps changing at the servers
                self.observe()?;
                let heads = check::log_heads(self);
                self.watch = true;
                for _ in 0..400 {
                    self.deliver_next()?;
                }
                let churn = check::churn(self, &heads);
                return Err(self.fail(format!("message storm: {STORM} deliveries without the queue emptying; meanwhile {churn:?}")));
            }
        }
        Ok(())
    }

    /// Every up node looks at its engine; everything queued is delivered.
    pub fn settle(&mut self) -> Res<()> {
        for n in 0..self.nodes.len() {
            self.feed(n, Event::Local)?;
        }
        self.drain_queue()
    }

    // ---- the scheduler

    pub fn step(&mut self) -> Res<()> {
        self.report.steps = self.report.steps.saturating_add(1);
        let w = self.cfg.weights;
        let calm = self.calm;
        let any_down = self.nodes.iter().any(|n| !n.up && !n.lost);
        let server_down = self.servers.iter().any(|s| !s.up);
        let gate = |on: bool, x: u32| if on { x } else { 0 };
        let options: [(u32, u8); 9] = [
            (gate(!calm, w.write), 0),
            (gate(!self.queue.is_empty(), w.deliver), 1),
            (w.tick.max(1), 2),
            (gate(!calm, w.crash), 3),
            (gate(any_down, w.restart), 4),
            (gate(!calm, w.server_crash), 5),
            (gate(server_down, w.server_restart), 6),
            (gate(!calm, w.partition), 7),
            (gate(!self.blocked.is_empty(), w.heal), 8),
        ];
        let total: u64 = options.iter().map(|o| u64::from(o.0)).sum();
        let mut r = self.dice.below(total);
        let mut pick = 2;
        for (wt, a) in options {
            if r < u64::from(wt) {
                pick = a;
                break;
            }
            r -= u64::from(wt);
        }
        match pick {
            0 => self.random_write()?,
            1 => {
                self.deliver_next()?;
            }
            3 => self.random_crash()?,
            4 => {
                let down: Vec<usize> = (0..self.nodes.len()).filter(|i| self.nodes.get(*i).is_some_and(|n| !n.up && !n.lost)).collect();
                if let Some(&n) = self.dice.pick(&down) {
                    self.restart_node(n)?;
                }
            }
            5 => self.random_server_crash()?,
            6 => {
                let down: Vec<usize> = (0..self.servers.len()).filter(|i| self.servers.get(*i).is_some_and(|s| !s.up)).collect();
                if let Some(&s) = self.dice.pick(&down) {
                    self.restart_server(s)?;
                }
            }
            7 => self.random_partition(),
            8 => {
                let b: Vec<(Party, Party)> = self.blocked.iter().copied().collect();
                if let Some(p) = self.dice.pick(&b).copied() {
                    self.blocked.remove(&p);
                    self.note(format!("healed {p:?}"));
                }
            }
            _ => {
                let dt = 1 + self.dice.below(self.cfg.max_tick_ms.max(1));
                self.advance(dt)?;
            }
        }
        Ok(())
    }

    pub fn run(&mut self, n: u64) -> Res<()> {
        self.calm = false;
        for _ in 0..n {
            self.step()?;
        }
        Ok(())
    }

    fn up_nodes(&self) -> Vec<usize> {
        (0..self.nodes.len()).filter(|i| self.is_up(*i)).collect()
    }

    /// A random up node writes 1..=3 random ops on scenario items it may write.
    fn random_write(&mut self) -> Res<()> {
        let ups = self.up_nodes();
        let Some(&n) = self.dice.pick(&ups) else { return Ok(()) };
        let items: Vec<Tid> = self.groups.iter().flat_map(|g| g.items.iter().copied()).collect();
        let e = self.engine(n)?;
        let writable: Vec<Tid> = items.into_iter().filter(|t| e.role_on(t).is_some_and(|r| r >= Role::Write)).collect();
        if writable.is_empty() {
            return Ok(());
        }
        let mut m = Mutation::new();
        for _ in 0..1 + self.dice.below(3) {
            let Some(&t) = self.dice.pick(&writable) else { continue };
            workload::random_op(&mut self.dice, &mut m, t).map_err(|e| self.fail(format!("building op: {e}")))?;
        }
        let r = self.engine(n)?.commit(m);
        match r {
            Ok(id) => {
                self.report.writes = self.report.writes.saturating_add(1);
                self.note(format!("node {n} write {id:?}"));
            }
            Err(e) => {
                if self.nodes.get(n).is_some_and(|x| x.faults.crashed()) {
                    self.report.crashes = self.report.crashes.saturating_add(1);
                    self.note(format!("node {n} crashed during a write"));
                    return self.node_down(n);
                }
                return Err(self.fail(format!("node {n} write: {e}")));
            }
        }
        self.feed(n, Event::Local)
    }

    fn random_crash(&mut self) -> Res<()> {
        let ups = self.up_nodes();
        let Some(&n) = self.dice.pick(&ups) else { return Ok(()) };
        if self.dice.pct(50) {
            self.report.crashes = self.report.crashes.saturating_add(1);
            self.note(format!("node {n} crashed"));
            self.node_down(n)
        } else {
            let at = self.dice.below(6);
            self.note(format!("node {n} will crash at its write {at}"));
            self.node(n)?.faults.at(at, Fault::Crash);
            Ok(())
        }
    }

    fn random_server_crash(&mut self) -> Res<()> {
        let ups: Vec<usize> = (0..self.servers.len()).filter(|s| self.servers.get(*s).is_some_and(|x| x.up)).collect();
        let Some(&s) = self.dice.pick(&ups) else { return Ok(()) };
        if self.dice.pct(50) {
            self.report.server_crashes = self.report.server_crashes.saturating_add(1);
            self.note(format!("server {s} crashed"));
            self.server_down(s)
        } else {
            let at = self.dice.below(8);
            self.note(format!("server {s} will crash at its write {at}"));
            self.server(s)?.faults.at(at, Fault::Crash);
            Ok(())
        }
    }

    /// Blocks a random (node, server) or (server, server) pair and cuts its links.
    fn random_partition(&mut self) {
        let (nn, ns) = (self.nodes.len(), self.servers.len());
        if ns == 0 {
            return;
        }
        let a = if ns > 1 && self.dice.pct(30) { Party::S(self.dice.index(ns)) } else { Party::N(self.dice.index(nn.max(1))) };
        let b = Party::S(self.dice.index(ns));
        if a == b {
            return;
        }
        self.partition(a, b);
    }

    /// Blocks a pair of parties and cuts the links between them.
    pub fn partition(&mut self, a: Party, b: Party) {
        self.blocked.insert((a, b));
        self.report.partitions = self.report.partitions.saturating_add(1);
        self.note(format!("partition {a:?} | {b:?}"));
        self.cut_pair(a, b);
    }

    /// `a` and `b` never connect again (a node that cannot reach a server).
    pub fn sever(&mut self, a: Party, b: Party) {
        self.unreachable.insert((a, b));
        self.cut_pair(a, b);
    }

    fn cut_pair(&mut self, a: Party, b: Party) {
        let ids: Vec<u64> = self.links.iter().filter(|(_, l)| (l.dialer.party() == a && l.acceptor.party() == b) || (l.dialer.party() == b && l.acceptor.party() == a)).map(|(id, _)| *id).collect();
        for id in ids {
            self.cut(id);
        }
    }

    /// Cuts every node's connections (they redial and reopen at the servers' current heads).
    pub fn reconnect_all(&mut self) {
        let ids: Vec<u64> = self.links.iter().filter(|(_, l)| matches!(l.dialer, End::Node(..))).map(|(id, _)| *id).collect();
        for id in ids {
            self.cut(id);
        }
    }

    /// `a` and `b` may connect again after `sever`.
    pub fn unsever(&mut self, a: Party, b: Party) {
        self.unreachable.remove(&(a, b));
        self.unreachable.remove(&(b, a));
    }

    /// Node `n`'s clock is set `skew_ms` off true time from now on (a thief winding it back).
    pub fn set_skew(&mut self, n: usize, skew_ms: i64) -> Res<()> {
        let elapsed = self.elapsed;
        let node = self.node(n)?;
        node.spec.skew_ms = skew_ms;
        node.clock.set(WallMs(wall_of(node.spec, elapsed)));
        Ok(())
    }

    pub fn heal(&mut self, a: Party, b: Party) {
        self.blocked.remove(&(a, b));
        self.blocked.remove(&(b, a));
    }

    // ---- setup helpers (flows)

    /// Carries out a flow's result on node `n`: placements and inbox blobs through its sync
    /// engine, direct commits to the nodes they name (pairing).
    pub fn carry(&mut self, n: usize, done: Done) -> Res<()> {
        let acts = self.sync(n)?.carry_out(done).map_err(|e| self.fail(format!("node {n} carry_out: {e}")))?;
        let direct = self.sync(n)?.take_direct();
        self.after_node(n, acts)?;
        for (to, pkgs) in direct {
            let Some(m) = self.nodes.iter().position(|x| x.tid == to && x.up) else { continue };
            for p in pkgs {
                let r = self.engine(m)?.ingest(&p.bytes, p.blobs);
                r.map_err(|e| self.fail(format!("node {m} direct ingest: {e}")))?;
            }
            self.feed(m, Event::Local)?;
        }
        Ok(())
    }

    /// Hands every commit node `from` holds to node `to` over a direct connection (a card
    /// exchange before pairing or a grant).
    pub fn direct(&mut self, from: usize, to: usize) -> Res<()> {
        let ids = self.engine(from)?.commit_ids();
        for id in ids {
            let p = self.engine(from)?.package(&id).map_err(|e| self.fail(e.to_string()))?;
            let Some(p) = p else { continue };
            let r = self.engine(to)?.ingest(&p.bytes, p.blobs);
            r.map_err(|e| self.fail(format!("node {to} direct ingest: {e}")))?;
        }
        self.feed(to, Event::Local)
    }

    /// Node `x` hands what it holds (its device and person cards) to node `y` over a direct
    /// connection: a contact exchange, so `y` can grant `x`'s person.
    pub fn introduce(&mut self, x: usize, y: usize) -> Res<()> {
        self.direct(x, y)
    }

    /// Node `n` creates a person with its home label at `servers`.
    pub fn person(&mut self, n: usize, servers: &[usize]) -> Res<osis_node::flows::Person> {
        let addrs = self.addresses(servers);
        let r = self.engine(n)?.create_person(&addrs);
        let (p, done) = r.map_err(|e| self.fail(format!("node {n} create_person: {e}")))?;
        self.carry(n, done)?;
        self.person_of.insert(n, p.person);
        Ok(p)
    }

    /// Pairs node `new` to `person` through node `have` (spec/sync.md §2: the device card over
    /// a direct connection, the grant back).
    pub fn pair(&mut self, have: usize, new: usize, person: Tid) -> Res<()> {
        self.direct(new, have)?;
        let nt = self.tid(new)?;
        let r = self.engine(have)?.pair(&person, &nt);
        let done = r.map_err(|e| self.fail(format!("node {have} pair: {e}")))?;
        let grant = done.commits.last().copied();
        self.person_of.insert(new, person);
        self.carry(have, done)?;
        if let Some(grant) = grant {
            let r = self.engine(new)?.paired(&person, &grant);
            if let Ok(done) = r {
                self.carry(new, done)?;
            }
        }
        Ok(())
    }

    /// Node `n` creates a group owned by `owner` with a label at `servers`.
    pub fn group(&mut self, n: usize, owner: Tid, servers: &[usize]) -> Res<Tid> {
        self.group_with(n, owner, servers, false)
    }

    /// `group`, with secrets of its own before the label when `own`.
    pub fn group_with(&mut self, n: usize, owner: Tid, servers: &[usize], own: bool) -> Res<Tid> {
        let e = self.engine(n)?;
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, owner);
        m.set(g, &ct::GROUP, &ct::Group::default()).map_err(|e| self.fail(e.to_string()))?;
        let r = self.engine(n)?.commit(m);
        r.map_err(|e| self.fail(format!("node {n} group: {e}")))?;
        if own {
            let r = self.engine(n)?.give_own_secrets(&g);
            let done = r.map_err(|e| self.fail(format!("node {n} own secrets: {e}")))?;
            self.carry(n, done)?;
        }
        let addrs = self.addresses(servers);
        let r = self.sync(n)?.create_label(&g, addrs);
        let (_, acts) = r.map_err(|e| self.fail(format!("node {n} create_label: {e}")))?;
        self.after_node(n, acts)?;
        self.groups.push(Group { g, owner, items: Vec::new() });
        Ok(g)
    }

    /// Registers an existing labeled group (a person's home) as a write target.
    pub fn track(&mut self, g: Tid) {
        if !self.groups.iter().any(|x| x.g == g) {
            self.groups.push(Group { g, owner: g, items: Vec::new() });
        }
    }

    /// Node `n` creates a thing owned by `g` and lists it in `g`'s `/group`.
    pub fn item(&mut self, n: usize, g: Tid) -> Res<Tid> {
        let e = self.engine(n)?;
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, g);
        let r = m.set(t, &workload::REG, &osis_core::Value::Str("new".into()));
        r.map_err(|e| self.fail(e.to_string()))?;
        let mut items = self.engine(n)?.get_typed(&g, &ct::GROUP).map_err(|e| self.fail(e.to_string()))?.unwrap_or_default();
        items.items.insert(t);
        m.set(g, &ct::GROUP, &items).map_err(|e| self.fail(e.to_string()))?;
        let r = self.engine(n)?.commit(m);
        r.map_err(|e| self.fail(format!("node {n} item: {e}")))?;
        self.track(g);
        if let Some(x) = self.groups.iter_mut().find(|x| x.g == g) {
            x.items.push(t);
        }
        self.feed(n, Event::Local)?;
        Ok(t)
    }

    /// Node `n` grants `member` `role` on `target` (spec/permissions.md §2).
    pub fn grant(&mut self, n: usize, target: Tid, member: Tid, role: Role) -> Res<()> {
        let edge = ct::Edge { role, until: None, invite: None, since: None };
        let r = self.engine(n)?.grant(&target, &member, &edge);
        let done = r.map_err(|e| self.fail(format!("node {n} grant: {e}")))?;
        self.carry(n, done)
    }

    /// Node `n` removes `member` from `target` with the rotation (spec/permissions.md §3, §5).
    pub fn remove(&mut self, n: usize, target: Tid, member: Tid) -> Res<()> {
        let d = osis_node::flows::Demotion { member, new: None, presync: osis_node::flows::PreSync::Synced };
        let r = self.engine(n)?.demote(&target, &d);
        let done = r.map_err(|e| self.fail(format!("node {n} remove: {e}")))?;
        self.carry(n, done)
    }

    /// Node `n` commits `m` (errors fail the run; a crash at a planned durable write takes the
    /// node down and commits nothing).
    pub fn commit(&mut self, n: usize, m: Mutation) -> Res<Option<CommitId>> {
        let r = self.engine(n)?.commit(m);
        let id = match r {
            Ok(id) => id,
            Err(_) if self.nodes.get(n).is_some_and(|x| x.faults.crashed()) => {
                self.report.crashes = self.report.crashes.saturating_add(1);
                self.note(format!("node {n} crashed during a scenario write"));
                self.node_down(n)?;
                return Ok(None);
            }
            Err(e) => return Err(self.fail(format!("node {n} commit: {e}"))),
        };
        self.feed(n, Event::Local)?;
        Ok(id)
    }

    /// Records what every up node knows of commit blobs under its labels.
    pub fn observe(&mut self) -> Res<()> {
        for n in 0..self.nodes.len() {
            self.observe_node(n);
        }
        Ok(())
    }

    fn observe_node(&mut self, n: usize) {
        let Some(s) = self.nodes.get_mut(n).and_then(|x| x.sync.as_mut()) else { return };
        for (_, gl) in s.labels() {
            for (b, k) in s.entries(&gl.id) {
                if let osis_node::sync::EntryKind::Commit { commit, parts, .. } = k {
                    self.known.insert((gl.id, b), (commit, parts));
                }
            }
        }
    }

    // ---- quiescence

    /// Stops writes, crashes and faults, heals partitions, restarts every node and server, and
    /// lets the system run (time moving a resync interval at a time) until every node is idle
    /// and nothing changes for two rounds; then the quiescent invariants. Fails past
    /// `max_rounds`.
    pub fn run_until_quiescent(&mut self, max_rounds: u64) -> Res<()> {
        self.quiet(max_rounds)?;
        self.observe()?;
        check::quiescent(self)
    }

    /// `run_until_quiescent` without the invariants (setup steps).
    pub fn quiet(&mut self, max_rounds: u64) -> Res<()> {
        self.calm = true;
        self.blocked.clear();
        self.flush_held();
        for s in 0..self.servers.len() {
            if !self.servers.get(s).is_some_and(|x| x.up) {
                self.restart_server(s)?;
            }
            self.server(s)?.faults.revive();
        }
        for n in 0..self.nodes.len() {
            if !self.is_up(n) {
                self.restart_node(n)?;
            }
            self.node(n)?.faults.revive();
        }
        let mut last = None;
        let heads0 = check::log_heads(self);
        let mut stable = 0;
        for round in 0..max_rounds {
            self.settle()?;
            let fp = self.fingerprint();
            let idle = self.nodes.iter().all(|n| !n.up || n.sync.as_ref().is_some_and(|s| s.is_idle()));
            if self.verbose {
                let busy: Vec<usize> = (0..self.nodes.len()).filter(|n| self.nodes.get(*n).is_some_and(|x| x.up && !x.sync.as_ref().is_some_and(|s| s.is_idle()))).collect();
                self.note(format!("round {round}: idle {idle} busy {busy:?} fp {fp:?}"));
            }
            if idle && last.as_ref() == Some(&fp) {
                stable += 1;
                if stable >= 2 {
                    self.note(format!("quiescent after {round} rounds"));
                    return Ok(());
                }
            } else {
                stable = 0;
            }
            last = Some(fp);
            self.advance(61_000)?;
        }
        let busy: Vec<String> = (0..self.nodes.len()).filter_map(|n| self.nodes.get(n).and_then(|x| x.sync.as_ref()).filter(|s| !s.is_idle()).map(|s| format!("node {n}: {:?}", s.describe()))).collect();
        // what the rounds changed at the servers
        self.watch = true;
        self.observe()?;
        let heads = heads0;
        self.advance(61_000)?;
        self.settle()?;
        self.observe()?;
        let churn = check::churn(self, &heads);
        let fp = self.fingerprint();
        Err(self.fail(format!("not quiescent after {max_rounds} rounds; one more round changes {churn:?}; busy: {busy:?}; fingerprint {last:?} -> {fp:?}")))
    }

    /// What changes while the system is still moving: nodes' commits and pending, servers' logs.
    fn fingerprint(&self) -> Vec<u64> {
        let mut v = Vec::new();
        for n in &self.nodes {
            if let Some(s) = &n.sync {
                v.push(s.engine().commit_ids().len() as u64);
                v.push(s.engine().pending().len() as u64);
            }
        }
        for s in &self.servers {
            let Some(h) = &s.hub else { continue };
            use osis_proto::LabelStore;
            for l in h.store().labels_after(None, 4096).unwrap_or_default() {
                v.push(h.store().log_head(&l).map(|x| x.1).unwrap_or(0));
            }
        }
        v
    }

    pub fn finish(&mut self) -> Res<Report> {
        let mut h = osis_core::hash::Hasher::new();
        let mut commits = BTreeSet::new();
        for n in 0..self.nodes.len() {
            let Some(s) = self.nodes.get_mut(n).and_then(|x| x.sync.as_mut()) else { continue };
            for c in s.engine().commit_ids() {
                h.update(&c.0);
                commits.insert(c);
            }
            // what the node keeps locally: entries, presence, blob records, held bytes
            h.update(&s.state_digest());
            let r = crate::check::reads(s.engine_mut()).map_err(|x| x.to_string());
            let r = r.map_err(|x| self.fail(format!("read: {x}")))?;
            h.update(format!("{r:?}").as_bytes());
        }
        for s in &self.servers {
            let Some(hub) = &s.hub else { continue };
            use osis_proto::LabelStore;
            for l in hub.store().labels_after(None, 4096).unwrap_or_default() {
                for b in hub.store().live_ids(&l).unwrap_or_default() {
                    h.update(&b.0);
                }
                // the whole log: every upload and delete, in order
                let mut after = 0;
                while let Ok(Some(recs)) = hub.store().log_after(&l, after, 1024) {
                    let Some(last) = recs.last().map(|x| x.0) else { break };
                    for r in &recs {
                        h.update(format!("{r:?}").as_bytes());
                    }
                    after = last;
                }
            }
        }
        self.report.commits = commits.len();
        self.report.digest = h.finalize();
        Ok(self.report.clone())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // spec/sync.md §6 (ordered streams): a message sent on a stream after its cut can be due
    // before its predecessors; delivery waits for the stream's head instead of spinning
    // (evil_server sweep seed 134 reported this as a message storm).
    #[test]
    fn stream_head_due_after_successor_spec_sync_6() {
        let mut sim = NetSim::new("t", 1, NetConfig::default());
        sim.push(7, End::Node(0, 1), 500, Payload::Bytes(vec![1]));
        sim.push(7, End::Node(0, 1), 10, Payload::Bytes(vec![2]));
        sim.drain_queue().unwrap();
        assert!(sim.queue.is_empty());
        assert_eq!(sim.elapsed, 500);
    }
}

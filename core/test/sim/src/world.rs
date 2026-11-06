//! An API-level world: `osis::Osis` handles on `Runtime::Manual` exchange bytes with osis-host
//! `Hub`s over in-memory queues under one `ManualClock`. A hub is either the world's own host
//! (`add_host`) or a node's, run while its `host.0^` says so (`Action::Host`; reached at its
//! first listen URL, its store in memory; replication is not carried). No tokio, no threads of its own, no
//! sleeps: time moves only by `advance`, so a run is a function of its seeds. The osis crate's
//! tests drive it. It panics rather than return failure: a storm, a future that never resolves.

use osis::internals::node::sync::{Action, ConnId, Event, HostStatus};
use osis::internals::{Internals, ManualNet};
use osis::{MemStore, Osis, RecoveryCard, Runtime, Address, Store, Time};
use osis::internals::{ManualClock};
use osis_crypto::SeededRng;
use osis_proto::{FrameDecoder, Message};
use osis_host::{HostStore, Hub, HubOutput, HostPolicy};
use osis_store::MemoryBackend;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

/// Start of the world's wall clock (ms).
pub const T0: u64 = 1_700_000_000_000;

/// Rounds one `pump` may take before it panics as a message storm. M: the osis tests' busiest
/// settle takes about 300; at 0 every settle panics, at infinity a storm hangs the test.
pub const STORM: usize = 5_000;
/// Rounds a storm is watched for after `STORM`, to name what it carries.
const STORM_TRACE: usize = 500;

/// One host.
pub struct Host {
    pub hub: Hub,
    pub addr: Address,
    /// The node running it (by start order), if not the world's own.
    pub node: Option<usize>,
    /// It runs (a node's host stops when its `host.0^` goes).
    pub up: bool,
    /// Its store's rows, every write recorded (`MemoryBackend::history`).
    pub backend: MemoryBackend,
}

enum Msg {
    Up(usize, ConnId),
    ToHub(usize, u64, Vec<u8>),
    ToDb(usize, ConnId, Vec<u8>),
    Down(usize, ConnId),
}

/// Bytes a node exchanged with hosts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    pub up: u64,
    pub down: u64,
}

/// Cost spans by name: time and count.
type DbSpans = BTreeMap<&'static str, (Duration, u64)>;

pub struct World {
    pub clock: Arc<ManualClock>,
    pub hosts: Vec<Host>,
    /// Every node made with `cfg`, by start order (also those a future opened).
    pub net: ManualNet,
    /// (db, conn) -> (host, hub conn)
    links: BTreeMap<(usize, ConnId), (usize, u64)>,
    queue: VecDeque<(u64, Msg)>,
    /// Sizes where a settle is long by design (scale checks): no storm check.
    pub no_storm: bool,
    /// Generation of the last carried message (`hops`).
    hop: u64,
    next_hub: u64,
    /// Nodes cut off the network.
    offline: Vec<bool>,
    /// Nodes put to sleep for good (`sleep`): not polled, not ticked.
    asleep: BTreeSet<usize>,
    /// (db, host): a node cut off one host only.
    cut: BTreeSet<(usize, usize)>,
    /// Nodes whose user leaves invite requests alone (the others accept each as it
    /// appears, spec/sync.md §3), by start order.
    pub holds_invites: BTreeSet<usize>,
    /// Per node, by start order.
    traffic: Vec<Traffic>,
    /// Per node, by start order: time inside its `take_actions` and `feed` (its passes and
    /// receives). All nodes share a thread, so this is what one machine would spend.
    busy: Vec<Duration>,
    /// Per node, the cost spans since `spans_by_db` (a scale check's breakdown).
    db_spans: Option<BTreeMap<usize, DbSpans>>,
    /// Time inside host hubs.
    hub_busy: Duration,
    /// With `tally`: upstream frames per (node, message kind): count and bytes.
    tally: Option<BTreeMap<(usize, String), (u64, u64)>>,
    decoders: BTreeMap<(usize, ConnId, bool), FrameDecoder>,
    /// Engine diagnostics per node since the last `diagnostics` call.
    diags: Arc<Mutex<BTreeMap<usize, Vec<String>>>>,
}

impl Default for World {
    fn default() -> World {
        World::new()
    }
}

impl World {
    pub fn new() -> World {
        World {
            clock: Arc::new(ManualClock::new(Time(T0))),
            hosts: Vec::new(),
            net: ManualNet::new(),
            links: BTreeMap::new(),
            queue: VecDeque::new(),
            no_storm: false,
            hop: 0,
            next_hub: 1,
            offline: Vec::new(),
            asleep: BTreeSet::new(),
            cut: BTreeSet::new(),
            holds_invites: BTreeSet::new(),
            traffic: Vec::new(),
            busy: Vec::new(),
            db_spans: None,
            hub_busy: Duration::ZERO,
            tally: None,
            decoders: BTreeMap::new(),
            diags: Arc::default(),
        }
    }

    pub fn now(&self) -> u64 {
        osis::internals::Clock::now_wall_ms(&*self.clock).0
    }

    /// A new host (keys and rng from its index).
    #[allow(clippy::panic)] // test harness: fail the test loudly
    pub fn add_host(&mut self) -> usize {
        let i = self.hosts.len();
        let b = 0x50u8.wrapping_add(i as u8);
        let key = [b; 32];
        let backend = MemoryBackend::new();
        let store = match host_store(&backend, 900 + i as u64).and_then(|st| HostStore::open(st, self.clock.clone(), HostPolicy::default(), Box::new(SeededRng::from_u64(900 + i as u64)))) {
            Ok(s) => s,
            Err(e) => panic!("host store: {e:?}"),
        };
        let hub = Hub::new(store, key, Box::new(SeededRng::from_u64(950 + i as u64)));
        self.hosts.push(Host { hub, addr: format!("quic://host{i}:1#{}", osis_schema::osis_base::base64url::encode(&key)).parse().unwrap_or_else(|e| panic!("{e:?}")), node: None, up: true, backend });
        i
    }

    /// The hub node `d` runs, if it ever did.
    pub fn host_of(&self, d: usize) -> Option<usize> {
        self.hosts.iter().position(|h| h.node == Some(d))
    }

    /// Node `d` serves with `cfg`, or stops (none): its hub starts (its own store, in memory, every
    /// write recorded: `Host::backend`), changes, or stops with its connections.
    #[allow(clippy::panic)] // test harness: fail the test loudly
    fn host(&mut self, d: usize, cfg: Option<Box<osis_host::HostConfig>>) {
        let s = self.host_of(d).filter(|s| self.hosts.get(*s).is_some_and(|h| cfg.as_ref().is_none_or(|c| h.hub.static_key() == c.key)));
        let Some(cfg) = cfg else {
            if let Some(s) = s {
                if let Some(h) = self.hosts.get_mut(s) {
                    h.up = false;
                }
                let gone: Vec<((usize, ConnId), u64)> = self.links.iter().filter(|(_, (x, _))| *x == s).map(|(k, (_, hc))| (*k, *hc)).collect();
                for ((db, c), hc) in gone {
                    self.links.remove(&(db, c));
                    if let Some(h) = self.hosts.get_mut(s) {
                        let _ = h.hub.closed(hc);
                    }
                    self.send_msg(Msg::Down(db, c));
                }
            }
            return;
        };
        let s = match s {
            Some(s) => s,
            None => {
                let backend = MemoryBackend::new();
                backend.record_history();
                let store = match host_store(&backend, 700 + d as u64).and_then(|st| HostStore::open(st, self.clock.clone(), cfg.policy.clone(), Box::new(SeededRng::from_u64(700 + d as u64)))) {
                    Ok(s) => s,
                    Err(e) => panic!("host store: {e:?}"),
                };
                let hub = Hub::new(store, cfg.key, Box::new(SeededRng::from_u64(750 + d as u64)));
                let url = cfg.listen.first().cloned().unwrap_or_else(|| format!("quic://node{d}:1"));
                // a restart from off has a new key: the old hub stays down
                if let Some(h) = self.host_of(d).and_then(|old| self.hosts.get_mut(old)) {
                    h.node = None;
                }
                self.hosts.push(Host { hub, addr: format!("{url}#{}", osis_schema::osis_base::base64url::encode(&cfg.key)).parse().unwrap_or_else(|e| panic!("{e:?}")), node: Some(d), up: true, backend });
                self.hosts.len() - 1
            }
        };
        let addr = match self.hosts.get_mut(s) {
            Some(h) => {
                h.up = true;
                h.hub.store_mut().set_policy(cfg.policy.clone());
                h.hub.store_mut().set_admission(cfg.admission.clone(), cfg.caps.clone());
                h.addr.to_string()
            }
            None => return,
        };
        let Ok(a) = osis_label::address_from_text(&addr) else { return };
        self.with(d, |db| db.sync_engine(|e| e.set_host_status(HostStatus::Listening(vec![a]))));
    }

    pub fn addr(&self, s: usize) -> Option<Address> {
        self.hosts.get(s).map(|x| x.addr.clone())
    }

    /// A config for a node of this world: manual runtime, the world's clock, `seed`, the
    /// given hosts, a fresh memory store.
    pub fn cfg(&self, seed: u64, hosts: &[usize]) -> osis::internals::Opening {
        let mut c = osis::internals::Opening::at(Store::Memory(MemStore::new()));
        c.app.internals.seed = Some(seed);
        c.app.internals.clock = Some(self.clock.clone());
        c.runtime = Runtime::Manual(self.net.clone());
        c.hosts = hosts.iter().filter_map(|s| self.addr(*s)).collect();
        c
    }

    /// A new account's node syncing with `hosts` (at least one), with its recovery card.
    #[allow(clippy::panic)] // test harness: fail the test loudly
    pub fn account(&mut self, seed: u64, hosts: &[usize]) -> (Osis, RecoveryCard) {
        match osis::internals::create(self.cfg(seed, hosts)) {
            Ok((db, Some(card))) => (db, card),
            Ok((_, None)) => panic!("an account without hosts has no recovery card"),
            Err(e) => panic!("create: {e:?}"),
        }
    }

    fn dbs(&mut self) -> Vec<Option<Osis>> {
        let v = self.net.dbs();
        if v.len() > self.offline.len() {
            for (i, db) in v.iter().enumerate().skip(self.offline.len()) {
                if let Some(db) = db {
                    let diags = self.diags.clone();
                    // a node of this harness is local: registering cannot fail
                    if let Ok(sub) = db.on_diagnostic(move |_, d| diags.lock().unwrap_or_else(|e| e.into_inner()).entry(i).or_default().push(d.to_string())) {
                        sub.detach();
                    }
                }
            }
            self.offline.resize(v.len(), false);
            self.traffic.resize(v.len(), Traffic::default());
            self.busy.resize(v.len(), Duration::ZERO);
        }
        v
    }

    /// The index of a node in this world.
    pub fn index(&mut self, db: &Osis) -> Option<usize> {
        self.dbs().iter().position(|d| d.as_ref().is_some_and(|d| d.node() == db.node()))
    }

    /// `db`'s diagnostics since the last call: the sync engine's and the engine's (refusals that
    /// change nothing a test reads, e.g. a value past a bound). Those from before the world first
    /// saw `db` (its first settle) are the sync engine's only.
    pub fn diagnostics(&mut self, db: &Osis) -> Vec<String> {
        let mut out = db.sync_engine(|s| s.take_diagnostics());
        let Some(i) = self.index(db) else { return out };
        let engine = self.diags.lock().unwrap_or_else(|e| e.into_inner()).remove(&i).unwrap_or_default();
        for d in engine {
            if !out.iter().any(|x| d.ends_with(x.as_str())) {
                out.push(d);
            }
        }
        out
    }

    /// Prints every node's diagnostics (stderr, shown when a test fails).
    pub fn trace(&mut self) {
        for (i, db) in self.dbs().iter().enumerate() {
            if let Some(db) = db {
                let d = self.diagnostics(db);
                if !d.is_empty() {
                    eprintln!("db {i}: {d:?}");
                }
            }
        }
    }

    /// Starts counting the messages nodes send, by kind (cost analysis; slows the run).
    pub fn start_tally(&mut self) {
        self.tally = Some(BTreeMap::new());
    }

    /// What `db` sent since `start_tally`, and got (`down <kind>`; one first frame of a connection
    /// decodes as `Hello`): message kind -> (count, frame bytes).
    pub fn tally(&mut self, db: &Osis) -> BTreeMap<String, (u64, u64)> {
        let Some(i) = self.index(db) else { return BTreeMap::new() };
        let Some(t) = &self.tally else { return BTreeMap::new() };
        t.iter().filter(|((d, _), _)| *d == i).map(|((_, k), v)| (k.clone(), *v)).collect()
    }

    fn count(&mut self, d: usize, conn: ConnId, bytes: &[u8], down: bool) {
        let Some(t) = &mut self.tally else { return };
        let dec = self.decoders.entry((d, conn, down)).or_default();
        dec.push(bytes);
        while let Ok(Some(f)) = dec.next_frame() {
            let k = frame_kind(&f);
            let e = t.entry((d, if down { format!("down {k}") } else { k })).or_default();
            e.0 += 1;
            e.1 += f.len() as u64 + 4;
        }
    }

    /// Bytes `db` exchanged with hosts so far.
    pub fn traffic(&mut self, db: &Osis) -> Traffic {
        self.index(db).and_then(|i| self.traffic.get(i).copied()).unwrap_or_default()
    }

    /// Time `db` spent in its passes and receives so far (not the caller's direct calls on it).
    pub fn busy(&mut self, db: &Osis) -> Duration {
        self.index(db).and_then(|i| self.busy.get(i).copied()).unwrap_or_default()
    }

    /// Time every node spent so far, by start order.
    pub fn busy_all(&mut self) -> Vec<Duration> {
        self.dbs();
        self.busy.clone()
    }

    /// Time host hubs spent so far.
    pub fn hub_busy(&self) -> Duration {
        self.hub_busy
    }

    /// Starts keeping cost spans per node (`take_db_spans`).
    pub fn spans_by_db(&mut self) {
        osis_node::costs::take();
        self.db_spans = Some(BTreeMap::new());
    }

    /// The spans of node `d` since `spans_by_db`, and stops keeping them.
    pub fn take_db_spans(&mut self, d: usize) -> Vec<(&'static str, Duration, u64)> {
        let mut all = self.db_spans.take().unwrap_or_default();
        all.remove(&d).unwrap_or_default().into_iter().map(|(k, (t, n))| (k, t, n)).collect()
    }

    fn charge(&mut self, d: usize, t: Instant) {
        if let Some(b) = self.busy.get_mut(d) {
            *b += t.elapsed();
        }
        if let Some(m) = &mut self.db_spans {
            let m = m.entry(d).or_default();
            for (k, t, n) in osis_node::costs::take() {
                let e = m.entry(k).or_default();
                e.0 += t;
                e.1 += n;
            }
        }
    }

    fn with(&mut self, d: usize, f: impl FnOnce(&Osis)) {
        if let Some(Some(db)) = self.dbs().get(d) {
            let t = Instant::now();
            f(db);
            self.charge(d, t);
        }
    }

    fn is_offline(&self, d: usize) -> bool {
        self.offline.get(d).copied().unwrap_or(false)
    }

    /// Cuts a node off the network (its connections go down) or lets it dial again.
    pub fn set_online(&mut self, db: &Osis, on: bool) {
        let Some(i) = self.index(db) else { return };
        if let Some(o) = self.offline.get_mut(i) {
            *o = !on;
        }
        if !on {
            let mine: Vec<(ConnId, (usize, u64))> = self.links.iter().filter(|((d, _), _)| *d == i).map(|((_, c), v)| (*c, *v)).collect();
            for (c, (s, hc)) in mine {
                self.links.remove(&(i, c));
                let out = self.hosts.get_mut(s).map(|host| host.hub.closed(hc)).unwrap_or_default();
                self.hub_out(s, out);
                db.feed(Event::Down { conn: c });
            }
            db.take_actions();
        }
    }

    /// Cuts a node off the network for good and stops polling it: a scale check's M-node sizes,
    /// where the sim's own work per step would otherwise be O(M).
    pub fn sleep(&mut self, db: &Osis) {
        self.set_online(db, false);
        if let Some(i) = self.index(db) {
            self.asleep.insert(i);
        }
    }

    /// Cuts a node off one host (its connections there go down) or lets it dial it again.
    pub fn set_reachable(&mut self, db: &Osis, host: usize, on: bool) {
        let Some(i) = self.index(db) else { return };
        if on {
            self.cut.remove(&(i, host));
            return;
        }
        self.cut.insert((i, host));
        let mine: Vec<(ConnId, u64)> = self.links.iter().filter(|((d, _), (s, _))| *d == i && *s == host).map(|((_, c), (_, h))| (*c, *h)).collect();
        for (c, hc) in mine {
            self.links.remove(&(i, c));
            let out = self.hosts.get_mut(host).map(|host| host.hub.closed(hc)).unwrap_or_default();
            self.hub_out(host, out);
            db.feed(Event::Down { conn: c });
        }
    }

    fn send_msg(&mut self, m: Msg) {
        self.queue.push_back((self.hop + 1, m));
    }

    /// The longest chain of messages each caused by the last so far: twice the round trips.
    pub fn hops(&self) -> u64 {
        self.hop
    }

    fn actions(&mut self, d: usize, acts: Vec<Action>) {
        for a in acts {
            match a {
                Action::Dial { conn, address } => {
                    let want = format!("{}#{}", address.url, osis_schema::osis_base::base64url::encode(&address.key));
                    let s = self.hosts.iter().position(|x| x.up && x.addr.to_string() == want).filter(|s| !self.is_offline(d) && !self.cut.contains(&(d, *s)));
                    let Some(s) = s else {
                        self.send_msg(Msg::Down(d, conn));
                        continue;
                    };
                    let hc = self.next_hub;
                    self.next_hub += 1;
                    self.links.insert((d, conn), (s, hc));
                    self.send_msg(Msg::Up(d, conn));
                    let now = self.now();
                    let out = match self.hosts.get_mut(s) {
                        Some(host) => host.hub.accept(now, hc, [0xe0; 32]),
                        None => Vec::new(),
                    };
                    self.hub_out(s, out);
                }
                Action::Send { conn, bytes } => {
                    if let Some((s, hc)) = self.links.get(&(d, conn)).copied() {
                        if let Some(t) = self.traffic.get_mut(d) {
                            t.up += bytes.len() as u64;
                        }
                        self.count(d, conn, &bytes, false);
                        self.send_msg(Msg::ToHub(s, hc, bytes));
                    }
                }
                Action::Close { conn } => {
                    if let Some((s, hc)) = self.links.remove(&(d, conn)) {
                        let out = self.hosts.get_mut(s).map(|host| host.hub.closed(hc)).unwrap_or_default();
                        self.hub_out(s, out);
                    }
                }
                Action::Host(cfg) => self.host(d, cfg),
                // no client port in the sim
                Action::Request { .. } | Action::Room { .. } | Action::Ended { .. } | Action::Authed { .. } => {}
                Action::Wake { .. } | Action::Reach => {}
            }
        }
    }

    fn link_of(&self, s: usize, hc: u64) -> Option<(usize, ConnId)> {
        self.links.iter().find(|(_, (x, h))| *x == s && *h == hc).map(|(k, _)| *k)
    }

    fn hub_out(&mut self, s: usize, out: Vec<HubOutput>) {
        for o in out {
            match o {
                HubOutput::Send(hc, bytes) => {
                    if let Some((d, c)) = self.link_of(s, hc) {
                        self.send_msg(Msg::ToDb(d, c, bytes));
                    }
                }
                HubOutput::Close(hc) => {
                    if let Some((d, c)) = self.link_of(s, hc) {
                        self.links.remove(&(d, c));
                        self.send_msg(Msg::Down(d, c));
                    }
                }
                HubOutput::Diagnostic(_) => {}
            }
        }
    }

    /// Carries every queued action and message until nothing moves. Panics on a message storm
    /// (`STORM` rounds), naming what the storm carries.
    #[allow(clippy::panic)] // test harness: fail the test loudly
    pub fn pump(&mut self) {
        for _ in 0..STORM {
            if !self.step(None) {
                return;
            }
        }
        if self.no_storm {
            while self.step(None) {}
            return;
        }
        let mut seen = BTreeMap::new();
        let mut settled = false;
        for _ in 0..STORM_TRACE {
            if !self.step(Some(&mut seen)) {
                settled = true;
                break;
            }
        }
        let mut seen: Vec<(u64, String)> = seen.into_iter().map(|(k, n)| (n, k)).collect();
        seen.sort_by(|a, b| b.cmp(a));
        let lines: Vec<String> = seen.iter().take(20).map(|(n, k)| format!("  {n} x {k}")).collect();
        let end = if settled { "settled during the trace" } else { "still moving" };
        panic!("message storm: {STORM} rounds without settling ({end}); the next {STORM_TRACE} rounds carried:\n{}", lines.join("\n"));
    }

    /// One round of `pump`: every node's actions, then one queued message. False if nothing
    /// moved. With `seen`, counts what it carries.
    pub fn step(&mut self, mut seen: Option<&mut BTreeMap<String, u64>>) -> bool {
        let mut moved = false;
        let dbs = self.dbs();
        for (d, db) in dbs.iter().enumerate() {
            let Some(db) = db.as_ref().filter(|_| !self.asleep.contains(&d)) else { continue };
            let t = Instant::now();
            let acts = db.take_actions();
            self.charge(d, t);
            if !acts.is_empty() {
                moved = true;
                if let Some(seen) = seen.as_deref_mut() {
                    for a in &acts {
                        let k = match a {
                            Action::Send { .. } => continue,
                            Action::Dial { .. } => "dial",
                            Action::Close { .. } => "close",
                            Action::Wake { .. } => "wake",
                            Action::Reach => "reach",
                            Action::Host(_) => "host",
                            Action::Request { .. } | Action::Room { .. } | Action::Ended { .. } | Action::Authed { .. } => "port",
                        };
                        *seen.entry(format!("db {d} action {k}")).or_default() += 1;
                    }
                }
                // offline: dials fail, nothing is sent
                self.actions(d, acts);
            }
        }
        let Some((hop, m)) = self.queue.pop_front() else {
            return moved;
        };
        self.hop = self.hop.max(hop);
        if let Some(seen) = seen {
            let k = match &m {
                Msg::Up(d, c) => format!("up db {d} conn {c:?}"),
                Msg::ToHub(s, hc, b) => format!("db {:?} -> host {s}: {}", self.links.iter().find(|(_, v)| **v == (*s, *hc)).map(|(k, _)| k.0), kind(b)),
                Msg::ToDb(d, _, b) => format!("host -> db {d}: {}", kind(b)),
                Msg::Down(d, c) => format!("down db {d} conn {c:?}"),
            };
            *seen.entry(k).or_default() += 1;
        }
        let now = self.now();
        match m {
            Msg::Up(d, c) => self.with(d, |db| db.feed(Event::Up { conn: c })),
            Msg::ToHub(s, hc, b) => {
                let t = Instant::now();
                let out = match self.hosts.get_mut(s) {
                    Some(host) => host.hub.input(now, hc, b),
                    None => Vec::new(),
                };
                self.hub_busy += t.elapsed();
                self.hub_out(s, out);
            }
            Msg::ToDb(d, c, b) => {
                if let Some(t) = self.traffic.get_mut(d) {
                    t.down += b.len() as u64;
                }
                self.count(d, c, &b, true);
                self.with(d, |db| db.feed(Event::Bytes { conn: c, bytes: b }))
            }
            Msg::Down(d, c) => self.with(d, |db| db.feed(Event::Down { conn: c })),
        }
        true
    }

    /// Moves time on by `ms`: host ticks, node ticks, then everything settles.
    pub fn advance(&mut self, ms: u64) {
        self.tick(ms);
        self.pump();
    }

    /// `advance` without settling: messages stay queued, for stepping (`step`).
    pub fn tick(&mut self, ms: u64) {
        self.clock.advance(ms);
        let now = self.now();
        for s in 0..self.hosts.len() {
            let out = match self.hosts.get_mut(s).filter(|h| h.up) {
                Some(host) => host.hub.tick(now),
                None => Vec::new(),
            };
            self.hub_out(s, out);
        }
        self.tick_all();
    }

    fn tick_all(&mut self) {
        let dbs = self.dbs();
        // an offline node's clock runs too: expiry, retention and timeouts
        for (d, db) in dbs.iter().enumerate() {
            let Some(db) = db.as_ref().filter(|_| !self.asleep.contains(&d)) else { continue };
            let t = Instant::now();
            db.feed(Event::Tick);
            self.charge(d, t);
        }
    }

    /// Lets everything settle (several rounds: a pass may start another). Panics on a storm.
    /// Invite requests that appeared are accepted (`accept_invites`) and settled again.
    pub fn run(&mut self) {
        loop {
            for _ in 0..3 {
                self.pump();
                self.tick_all();
            }
            self.pump();
            if !self.accept_invites() {
                return;
            }
        }
    }

    /// Every online node's user but those in `holds_invites` accepts its invite requests
    /// (a user clicking accept). Whether any was.
    fn accept_invites(&mut self) -> bool {
        let mut any = false;
        for (d, db) in self.dbs().iter().enumerate() {
            if let Some(db) = db
                && !self.asleep.contains(&d)
                && !self.holds_invites.contains(&d)
                && !self.offline.get(d).copied().unwrap_or(false)
            {
                for r in db.invite_requests().unwrap_or_default() {
                    any |= db.accept_invite(r).is_ok();
                }
            }
        }
        any
    }

    /// Drives the world until `f` resolves: settling, then stepping time by `step_ms`, at most
    /// `steps` times. Panics if it did not resolve, after printing every node's diagnostics.
    #[allow(clippy::panic)] // test harness: fail the test loudly
    pub fn until<F: Future>(&mut self, f: F, step_ms: u64, steps: usize) -> F::Output {
        match self.try_until(f, step_ms, steps) {
            Some(v) => v,
            None => {
                self.trace();
                panic!("future did not resolve in {steps} steps of {step_ms} ms");
            }
        }
    }

    /// `until`, what a caller's timeout does: `None`, and `f` dropped, if it did not resolve.
    pub fn try_until<F: Future>(&mut self, f: F, step_ms: u64, steps: usize) -> Option<F::Output> {
        let mut f = std::pin::pin!(f);
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..steps {
            if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return Some(v);
            }
            self.run();
            if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return Some(v);
            }
            self.advance(step_ms);
        }
        None
    }
}

/// A frame's message kind (`Hello` for the handshake, which `Message` does not decode).
fn frame_kind(f: &[u8]) -> String {
    match Message::decode(f) {
        Ok(m) => format!("{m:?}").split([' ', '{', '(']).next().unwrap_or("?").to_string(),
        Err(_) => "Hello".to_string(),
    }
}

/// The kind of the first message in `bytes` (a chunk a connection carried), for storm reports.
fn kind(bytes: &[u8]) -> String {
    let mut dec = FrameDecoder::default();
    dec.push(bytes);
    match dec.next_frame() {
        Ok(Some(f)) => frame_kind(&f),
        _ => format!("{} bytes", bytes.len()),
    }
}

/// A host's own store over `backend`.
fn host_store(backend: &MemoryBackend, seed: u64) -> Result<osis_store::Store, osis_proto::StoreError> {
    let (b, r) = (Box::new(backend.clone()), Box::new(osis_store::MemoryRoot::new()));
    osis_store::Store::create(b, r, osis_store::StoreConfig::default(), &mut SeededRng::from_u64(seed ^ 0x570e)).map_err(|e| osis_proto::StoreError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec: none (test harness): a storm fails at once and names what it carries.
    #[test]
    #[should_panic(expected = "down db 7 conn 1")]
    fn storm_panics_naming_messages() {
        let mut w = World::new();
        for _ in 0..STORM + STORM_TRACE {
            w.queue.push_back((0, Msg::Down(7, 1)));
        }
        w.pump();
    }
}

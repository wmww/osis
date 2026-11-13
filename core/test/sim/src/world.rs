//! An API-level world: `osis::Osis` handles on `Runtime::Manual` exchange bytes with osis-host
//! `Hub`s over in-memory queues under one `ManualClock`. A hub is either the world's own host
//! (`add_host`) or a node's (`node_hub`): every node serves its peers through one, reached by
//! its key at any URL, its store the host store while its `host^.0` says so (`Action::Host`; in
//! memory, every write recorded); nodes reach each other's hubs over
//! `peer://` through the reachability model (`crate::reach`). No tokio, no threads of its own, no
//! sleeps: time moves only by `advance`, so a run is a function of its seeds. The osis crate's
//! tests drive it. It panics rather than return failure: a storm, a future that never resolves.

use osis::internals::node::sync::{Action, ConnId, Event, SyncConfig, SyncEngine};
use osis::internals::{Internals, ManualNet};
use osis::{MemStore, Osis, Runtime, Address, Store, Time};
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
use crate::harness::{ClockSpec, wall_of};
use crate::reach::{Reach, RelayId, Route, Seg, Uplink, Who};

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
    /// It runs (a node's stops with the node).
    pub up: bool,
    /// The world's own host's node sync above its hub (a bare engine: no account, no group).
    pub sync: Option<SyncEngine>,
}

#[derive(Clone)]
enum Msg {
    /// Node `db`'s dial `conn` is up, as connection `hc` of its hub `s`, to the listener of
    /// `key` (`relayed`: the transport's word).
    Up { db: usize, conn: ConnId, s: usize, hc: u64, key: [u8; 32], relayed: bool },
    ToHub(usize, u64, Vec<u8>),
    /// Node `db`'s dial `conn` failed (never up).
    Down(usize, ConnId),
    /// The other end closed: the hub connection ends after the bytes sent before it, as a
    /// transport link finishes after what is queued (`osis_transport::link::LinkTx`).
    Closed(usize, u64),
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
    /// Both directions: (hub, its conn) -> (hub, its conn). Every connection runs between two
    /// hubs: a node's dialed ones are sessions of its own hub (`node_hub`).
    links: BTreeMap<(usize, u64), (usize, u64)>,
    /// The dialer's end of each connection a node dialed: (its hub, conn) -> the node.
    dialed: BTreeMap<(usize, u64), usize>,
    /// Dials not up yet: (node, its node sync's conn) -> (its hub, conn).
    dials: BTreeMap<(usize, ConnId), (usize, u64)>,
    /// A peer connection, by its dialer's end: (hub, conn) -> (dialer, node dialed, the route).
    /// The connection is in `links` too.
    peer_links: BTreeMap<(usize, u64), (usize, usize, Route)>,
    /// Nodes by their key (`node_hub`).
    node_keys: BTreeMap<[u8; 32], usize>,
    /// Pairs a partition separates on peer links (`set_peer_reachable`).
    peer_cut: BTreeSet<(Who, Who)>,
    /// Who can reach whom over `peer://` (`reach`).
    pub reach: Reach,
    /// `peer://` dials by (dialer, node listening at the dialed key), routed or not.
    peer_dials: BTreeMap<(usize, usize), u64>,
    /// Clocks of the nodes made with `cfg_clocked`.
    own_clocks: Vec<(Arc<ManualClock>, ClockSpec)>,
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
            dialed: BTreeMap::new(),
            dials: BTreeMap::new(),
            peer_links: BTreeMap::new(),
            node_keys: BTreeMap::new(),
            peer_cut: BTreeSet::new(),
            reach: Reach::default(),
            peer_dials: BTreeMap::new(),
            own_clocks: Vec::new(),
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

    /// An exact copy of this world as it stands (notes/test-harnesses.md, Copied worlds): every node
    /// (`ManualNet::test_copy`, in start order, closed ones closed) and host (`Hub::test_copy`,
    /// `SyncEngine::test_copy`), on one new clock at the same time and new own clocks
    /// (`cfg_clocked`) at theirs, the queues, links, model and counters, the diagnostics not yet
    /// taken: run the same steps on both and they do the same. With the copies of the nodes, by
    /// start order (`None`: closed): a copy is open while a handle to it is held. Fresh in the
    /// copy: each node's dispatcher, with no subscription but the world's own diagnostics one.
    #[allow(clippy::panic, clippy::clone_on_copy)] // test harness: fail the test loudly
    pub fn copy(&mut self) -> (World, Vec<Option<Osis>>) {
        osis_base::copying::copying(|| {
            let clock = Arc::new(ManualClock::new(Time(self.now())));
            let own_clocks: Vec<(Arc<ManualClock>, ClockSpec)> = self.own_clocks.iter().map(|(c, spec)| (Arc::new(ManualClock::new(osis::internals::Clock::now_wall_ms(&**c))), *spec)).collect();
            let ptr = |c: &Arc<dyn osis::internals::Clock>| Arc::as_ptr(c) as *const () as usize;
            let (net, dbs) = self.net.test_copy(|c| {
                if ptr(c) == Arc::as_ptr(&self.clock) as *const () as usize {
                    return clock.clone();
                }
                match self.own_clocks.iter().position(|(o, _)| ptr(c) == Arc::as_ptr(o) as *const () as usize).and_then(|i| own_clocks.get(i)) {
                    Some((n, _)) => n.clone(),
                    None => panic!("copy: a node on a clock this world did not make"),
                }
            }).unwrap_or_else(|e| panic!("copy: {e:?}"));
            let c: Arc<dyn osis::internals::Clock> = clock.clone();
            let hosts = self.hosts.iter_mut().map(|h| {
                let sync = h.sync.as_mut().map(|s| s.test_copy(c.clone()).unwrap_or_else(|e| panic!("copy: host engine: {e:?}")));
                // a node's hub shares the copied node's store (`Hub::test_copy` inside the copy)
                let hub = h.hub.test_copy(c.clone()).unwrap_or_else(|e| panic!("copy: hub: {e:?}"));
                Host { hub, addr: h.addr.clone(), node: h.node, up: h.up, sync }
            }).collect();
            let diags: BTreeMap<usize, Vec<String>> = self.diags.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let w = World {
                clock,
                hosts,
                net,
                links: self.links.clone(),
                dialed: self.dialed.clone(),
                dials: self.dials.clone(),
                peer_links: self.peer_links.clone(),
                node_keys: self.node_keys.clone(),
                peer_cut: self.peer_cut.clone(),
                reach: self.reach.clone(),
                peer_dials: self.peer_dials.clone(),
                own_clocks,
                queue: self.queue.clone(),
                no_storm: self.no_storm,
                hop: self.hop,
                next_hub: self.next_hub,
                offline: self.offline.clone(),
                asleep: self.asleep.clone(),
                cut: self.cut.clone(),
                holds_invites: self.holds_invites.clone(),
                traffic: self.traffic.clone(),
                busy: self.busy.clone(),
                db_spans: self.db_spans.clone(),
                hub_busy: self.hub_busy,
                tally: self.tally.clone(),
                decoders: self.decoders.clone(),
                diags: Arc::new(Mutex::new(diags)),
            };
            // the world's diagnostics subscription, on the nodes it had seen
            for (i, db) in dbs.iter().enumerate().take(w.offline.len()) {
                if let Some(db) = db {
                    w.watch_diagnostics(i, db);
                }
            }
            (w, dbs)
        })
    }

    /// A copy (`copy`) of the world `build` makes with the nodes it returns (every node it leaves
    /// open) and `extra`: built once per test process per `key`, which names the build and every
    /// parameter it takes (`osis_base::copying::cached`).
    #[allow(clippy::panic)] // test harness: fail the test loudly
    pub fn cached<const N: usize, T: Clone + Send + 'static>(key: &str, build: impl FnOnce() -> (World, [Osis; N], T)) -> (World, [Osis; N], T) {
        osis_base::copying::cached(key, || {
            let (mut w, dbs, t) = build();
            // its diagnostics subscriptions are in place before the first copy
            w.dbs();
            (w, dbs, t)
        }, |(w, dbs, t)| {
            let at: Vec<usize> = dbs.iter().map(|d| w.index(d).unwrap_or_else(|| panic!("cached: a node of another world"))).collect();
            let open = w.net.dbs().iter().filter(|d| d.is_some()).count();
            assert_eq!(open, at.len(), "cached: {key} leaves open a node it does not return");
            let (copy, mut copies) = w.copy();
            let out = at.iter().map(|i| copies.get_mut(*i).and_then(Option::take).unwrap_or_else(|| panic!("cached: node {i}"))).collect::<Vec<_>>();
            let out: [Osis; N] = out.try_into().unwrap_or_else(|_| panic!("cached: {N} nodes"));
            (copy, out, t.clone())
        })
    }

    /// The world's own subscription to node `i`'s diagnostics (`diagnostics`).
    fn watch_diagnostics(&self, i: usize, db: &Osis) {
        let diags = self.diags.clone();
        // a node of this harness is local: registering cannot fail
        if let Ok(sub) = db.on_diagnostic(move |_, d| diags.lock().unwrap_or_else(|e| e.into_inner()).entry(i).or_default().push(d.to_string())) {
            sub.detach();
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
        let store = match host_store(&MemoryBackend::new(), 900 + i as u64).and_then(|st| HostStore::open(st, self.clock.clone(), HostPolicy::default(), Box::new(SeededRng::from_u64(900 + i as u64)))) {
            Ok(s) => Arc::new(Mutex::new(s)),
            Err(e) => panic!("host store: {e:?}"),
        };
        let c: Arc<dyn osis::internals::Clock> = self.clock.clone();
        let engine = osis_node::Engine::create(Box::new(MemoryBackend::new()), Box::new(osis_store::MemoryRoot::new()), store.clone(), osis_node::Config::default(), c, Box::new(SeededRng::from_u64(920 + i as u64)));
        let sync = engine.and_then(|e| SyncEngine::new(e, Box::new(SeededRng::from_u64(940 + i as u64)), SyncConfig { peers: false, ..SyncConfig::default() })).unwrap_or_else(|e| panic!("host engine: {e:?}"));
        let hub = Hub::new(store, Box::new(SeededRng::from_u64(950 + i as u64)));
        self.hosts.push(Host { hub, addr: format!("quic://host{i}:1#{}", osis_schema::osis_base::base64url::encode(&key)).parse().unwrap_or_else(|e| panic!("{e:?}")), node: None, up: true, sync: Some(sync) });
        i
    }

    /// The hub node `d` runs, if it ever did.
    pub fn host_of(&self, d: usize) -> Option<usize> {
        self.hosts.iter().position(|h| h.node == Some(d))
    }

    /// Node `d`'s hub (made on first use), as a host index; its key now names the node.
    #[allow(clippy::panic)] // test harness: fail the test loudly
    fn node_hub(&mut self, d: usize) -> usize {
        if let Some(key) = self.dbs().get(d).and_then(|x| x.as_ref()).map(|db| db.sync_engine(|s| s.dialable_key())) {
            self.node_keys.insert(key, d);
        }
        if let Some(s) = self.host_of(d) {
            return s;
        }
        // the node's one store, beside its engine
        let Some(store) = self.dbs().get(d).and_then(|x| x.as_ref()).map(|db| db.sync_engine(|s| s.hub_store())) else { panic!("node {d} is not open") };
        let hub = Hub::new(store, Box::new(SeededRng::from_u64(750 + d as u64)));
        self.hosts.push(Host { hub, addr: format!("quic://node{d}:1#{}", osis_schema::osis_base::base64url::encode(&[0; 32])).parse().unwrap_or_else(|e| panic!("{e:?}")), node: Some(d), up: true, sync: None });
        self.hosts.len() - 1
    }

    /// The open node whose key is `key`.
    fn node_by_key(&mut self, key: &[u8; 32]) -> Option<usize> {
        let dbs = self.dbs();
        if let Some(m) = self.node_keys.get(key).copied().filter(|m| dbs.get(*m).is_some_and(Option::is_some)) {
            return Some(m);
        }
        let m = dbs.iter().position(|d| d.as_ref().is_some_and(|db| db.sync_engine(|s| s.dialable_key()) == *key))?;
        self.node_keys.insert(*key, m);
        Some(m)
    }

    /// Node `d` serves with `cfg`, or stops (none: what its store kept for others goes, and
    /// connections that opened something there close), as the node driver's `host_update`.
    fn host(&mut self, d: usize, cfg: Option<Box<osis_host::HostConfig>>) {
        let s = self.node_hub(d);
        let Some(h) = self.hosts.get_mut(s) else { return };
        match cfg {
            Some(cfg) => {
                let mut st = h.hub.store();
                st.set_policy(cfg.policy.clone());
                st.set_admission(cfg.admission.clone(), cfg.caps.clone());
            }
            None => {
                {
                    let mut st = h.hub.store();
                    st.set_policy(HostPolicy::default());
                    st.set_admission(osis_host::Admission::Only(Default::default()), Default::default());
                }
                let out = h.hub.stop_hosting(&|_| true);
                self.hub_out(s, out);
            }
        }
    }

    /// Ends the connection of hub `s`'s `hc` (both ways): the other end, if it was up.
    fn unlink(&mut self, s: usize, hc: u64) -> Option<(usize, u64)> {
        let other = self.links.remove(&(s, hc))?;
        self.links.remove(&other);
        for e in [(s, hc), other] {
            self.peer_links.remove(&e);
            self.dialed.remove(&e);
        }
        Some(other)
    }

    /// Ends the connection of hub `s`'s `hc` at once, both ends told.
    fn cut_link(&mut self, s: usize, hc: u64) {
        if let Some((t, thc)) = self.unlink(s, hc) {
            for (x, c) in [(s, hc), (t, thc)] {
                let out = self.hosts.get_mut(x).map(|h| h.hub.closed(c)).unwrap_or_default();
                self.hub_out(x, out);
            }
        }
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

    /// `cfg` on a clock of this node's own: skewed and drifting by `spec` as the world's moves.
    pub fn cfg_clocked(&mut self, seed: u64, hosts: &[usize], spec: ClockSpec) -> osis::internals::Opening {
        let clock = Arc::new(ManualClock::new(Time(wall_of(spec, self.now().saturating_sub(T0)))));
        self.own_clocks.push((clock.clone(), spec));
        let mut c = self.cfg(seed, hosts);
        c.app.internals.clock = Some(clock);
        c
    }

    /// A new account's node syncing with `hosts`.
    #[allow(clippy::panic)] // test harness: fail the test loudly
    pub fn account(&mut self, seed: u64, hosts: &[usize]) -> Osis {
        match osis::internals::create(self.cfg(seed, hosts)) {
            Ok(db) => db,
            Err(e) => panic!("create: {e:?}"),
        }
    }

    fn dbs(&mut self) -> Vec<Option<Osis>> {
        let v = self.net.dbs();
        if v.len() > self.offline.len() {
            for (i, db) in v.iter().enumerate().skip(self.offline.len()) {
                if let Some(db) = db {
                    self.watch_diagnostics(i, db);
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
    /// decodes as `Hello`): message kind -> (count, frame bytes); an Offer's Deposit items also count
    /// as `Deposit` (count, blob bytes).
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
            let side = |k: &str| if down { format!("down {k}") } else { k.to_string() };
            let e = t.entry((d, side(&k))).or_default();
            e.0 += 1;
            e.1 += f.len() as u64 + 4;
            if let Ok(Message::Offer { items, .. }) = Message::decode(&f) {
                for i in items {
                    if let osis_proto::msg::OfferItem::Deposit { blob, .. } = i {
                        let e = t.entry((d, side("Deposit"))).or_default();
                        e.0 += 1;
                        e.1 += blob.len() as u64;
                    }
                }
            }
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
            self.drop_peer_links(|n, _, _| n == i);
            // its hub's connections, dialed and served (a dial not up yet fails at its `Up`)
            if let Some(s) = self.host_of(i) {
                let mine: Vec<u64> = self.links.keys().filter(|(x, _)| *x == s).map(|(_, hc)| *hc).collect();
                for hc in mine {
                    self.cut_link(s, hc);
                }
            }
            // offline: its dials fail, nothing it sends goes
            let acts = db.take_actions();
            self.actions(i, acts);
        }
    }

    /// Ends the peer connections whose (dialer, node dialed, route) `which` picks: both ends told.
    fn drop_peer_links(&mut self, which: impl Fn(usize, usize, Route) -> bool) {
        let gone: Vec<(usize, u64)> = self.peer_links.iter().filter(|(_, v)| which(v.0, v.1, v.2)).map(|(k, _)| *k).collect();
        for (s, dc) in gone {
            // the dialed end at once, the dialer after what is on its way
            if let Some((t, hc)) = self.unlink(s, dc) {
                let out = self.hosts.get_mut(t).map(|h| h.hub.closed(hc)).unwrap_or_default();
                self.hub_out(t, out);
                self.send_msg(Msg::Closed(s, dc));
            }
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
        let mine: Vec<(usize, u64)> = self.dialed.iter().filter(|(e, d)| **d == i && self.links.get(e).is_some_and(|(s, _)| *s == host)).map(|(e, _)| *e).collect();
        for (s, dc) in mine {
            self.cut_link(s, dc);
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
                Action::Dial { conn, address, .. } if osis_transport::peer_items(&address.url).is_some() => self.dial_peer(d, conn, &address),
                Action::Dial { conn, address, .. } => {
                    let want = format!("{}#{}", address.url, osis_schema::osis_base::base64url::encode(&address.key));
                    // the world's own hosts by address, a node's hub by its key at any URL
                    let s = match self.hosts.iter().position(|x| x.up && x.node.is_none() && x.addr.to_string() == want) {
                        Some(s) => Some(s),
                        None => self.node_by_key(&address.key).filter(|m| !self.is_offline(*m)).map(|m| self.node_hub(m)),
                    };
                    let s = s.filter(|s| !self.is_offline(d) && !self.cut.contains(&(d, *s)));
                    let Some(s) = s else {
                        self.send_msg(Msg::Down(d, conn));
                        continue;
                    };
                    let hc = self.next_hub;
                    self.next_hub += 1;
                    let (sd, dc) = self.new_dial(d, conn, (s, hc));
                    self.send_msg(Msg::Up { db: d, conn, s: sd, hc: dc, key: address.key, relayed: false });
                    let now = self.now();
                    let out = match self.hosts.get_mut(s) {
                        Some(host) => host.hub.accept(now, hc, address.key, osis_host::Remote::key([0xe0; 32])),
                        None => Vec::new(),
                    };
                    self.hub_out(s, out);
                }
                // a dial given up before it was up (once up, node sync closes it at its hub)
                Action::Close { conn } => {
                    if let Some((sd, dc)) = self.dials.remove(&(d, conn))
                        && let Some(other) = self.unlink(sd, dc)
                    {
                        self.send_msg(Msg::Closed(other.0, other.1));
                    }
                }
                Action::Host(cfg) => self.host(d, cfg),
                Action::Hub { conn, down } => {
                    let now = self.now();
                    let s = self.node_hub(d);
                    let out = self.hosts.get_mut(s).map(|h| h.hub.down(now, vec![(conn, down)])).unwrap_or_default();
                    self.hub_out(s, out);
                }
                // no client port in the sim
                Action::Request { .. } | Action::Room { .. } | Action::Ended { .. } => {}
                Action::Reach => {
                    self.node_hub(d);
                    let key = self.dbs().get(d).and_then(|x| x.as_ref()).and_then(|db| db.sync_engine(|s| s.own_reach())).map(|r| r.dialable);
                    if let Some(key) = key {
                        self.reach.listen(d, key);
                    }
                }
                Action::Wake { .. } => {}
            }
        }
    }

    /// A `peer://` dial: reaches the hub of the node listening with the address's key when the
    /// model routes it.
    fn dial_peer(&mut self, d: usize, conn: ConnId, address: &osis_label::Address) {
        let dbs = self.dbs();
        if let Some(m) = self.reach.node_of(&address.key) {
            *self.peer_dials.entry((d, m)).or_default() += 1;
        }
        let target = self.reach.node_of(&address.key).filter(|m| *m != d && !self.is_offline(*m) && !self.is_offline(d));
        let cut = &self.peer_cut;
        let route = target.and_then(|m| self.reach.route(d, m, &address.url, |a, b| cut.contains(&(a, b)) || cut.contains(&(b, a))));
        let found = target.zip(route).filter(|(m, _)| dbs.get(*m).is_some_and(Option::is_some));
        let Some((m, route)) = found else {
            self.send_msg(Msg::Down(d, conn));
            return;
        };
        let s = self.node_hub(m);
        let mut peer = [0xd0u8; 32];
        peer[..8].copy_from_slice(&self.next_hub.to_le_bytes());
        let hc = self.next_hub;
        self.next_hub += 1;
        // both ends tell a relayed connection, as the driver does from the transport
        let relayed = matches!(route, Route::Relay(_));
        let (sd, dc) = self.new_dial(d, conn, (s, hc));
        self.peer_links.insert((sd, dc), (d, m, route));
        self.send_msg(Msg::Up { db: d, conn, s: sd, hc: dc, key: address.key, relayed });
        let now = self.now();
        let remote = osis_host::Remote { peer: osis_transport::Peer::Key(peer), relayed };
        let out = match self.hosts.get_mut(s) {
            Some(h) => h.hub.accept(now, hc, address.key, remote),
            None => Vec::new(),
        };
        self.hub_out(s, out);
    }

    /// A connection of node `d`'s hub for its dial `conn` to `to` (hub, conn), linked; up at its
    /// `Msg::Up`.
    fn new_dial(&mut self, d: usize, conn: ConnId, to: (usize, u64)) -> (usize, u64) {
        let sd = self.node_hub(d);
        let dc = self.next_hub;
        self.next_hub += 1;
        self.links.insert((sd, dc), to);
        self.links.insert(to, (sd, dc));
        self.dialed.insert((sd, dc), d);
        self.dials.insert((d, conn), (sd, dc));
        (sd, dc)
    }

    /// How many `peer://` dials `from` made so far to the node `to` listens as, whether they
    /// reached it or not.
    pub fn peer_dials(&mut self, from: &Osis, to: &Osis) -> u64 {
        let (Some(f), Some(t)) = (self.index(from), self.index(to)) else { return 0 };
        self.peer_dials.get(&(f, t)).copied().unwrap_or(0)
    }

    /// A relay of the reachability model (`Reach::add_relay`).
    pub fn add_relay(&mut self, seg: Option<Seg>) -> RelayId {
        self.reach.add_relay(seg)
    }

    /// Places node `db` in the reachability model and has it listen: its `reach.0` published with
    /// the model's items, its dialable key the listener's (what the driver does at start).
    pub fn place(&mut self, db: &Osis, lans: &[Seg], uplink: Uplink, relays: &[RelayId]) {
        let Some(i) = self.index(db) else { return };
        self.reach.place(i, lans, uplink, relays);
        let key = db.sync_engine(|s| osis_crypto::SigningSecret::from_seed(&s.dialable_secret()).verifying_key().to_bytes());
        self.reach.listen(i, key);
        let items = self.reach.items(i);
        if let Ok(acts) = db.sync_engine(|s| s.publish_reach(key, items)) {
            self.actions(i, acts);
        }
    }

    /// Node `db` announces itself on its LAN segments; each node `hears` picks gets it
    /// (`lan_announcement`, `lan_seen`). Partitioned nodes never do.
    pub fn lan_announce(&mut self, db: &Osis, hears: impl Fn(usize) -> bool) {
        let Some(i) = self.index(db) else { return };
        if self.is_offline(i) {
            return;
        }
        let dbs = self.dbs();
        for seg in self.reach.segments(i) {
            let fresh = db.sync_engine(|s| s.lan_secret());
            let key = self.reach.lan_key(i, seg, || osis_crypto::SigningSecret::from_seed(&fresh).verifying_key().to_bytes());
            let Some(a) = db.sync_engine(|s| s.lan_announcement(key, crate::reach::PORT)) else { continue };
            let Some(from) = self.reach.lan_addr(i, seg) else { continue };
            for m in self.reach.on_segment(seg, i) {
                if self.is_offline(m) || self.peer_cut.contains(&(Who::Node(i), Who::Node(m))) || self.peer_cut.contains(&(Who::Node(m), Who::Node(i))) || !hears(m) {
                    continue;
                }
                let Some(Some(other)) = dbs.get(m) else { continue };
                let acts = other.sync_engine(|s| s.lan_seen(&a, from).1);
                self.actions(m, acts);
            }
        }
    }

    /// Partitions two nodes' peer links, or lets them connect again (their connections go down).
    pub fn set_peer_reachable(&mut self, a: &Osis, b: &Osis, on: bool) {
        let (Some(i), Some(j)) = (self.index(a), self.index(b)) else { return };
        let (x, y) = (Who::Node(i), Who::Node(j));
        if on {
            self.peer_cut.remove(&(x, y));
            self.peer_cut.remove(&(y, x));
            return;
        }
        self.peer_cut.insert((x, y));
        self.drop_peer_links(|a, b, _| (a, b) == (i, j) || (a, b) == (j, i));
    }

    /// A relay stops (its relayed connections go down) or starts.
    pub fn set_relay_up(&mut self, r: RelayId, up: bool) {
        self.reach.set_relay_up(r, up);
        if !up {
            self.drop_peer_links(|_, _, route| route.relayed_by() == Some(r));
        }
    }

    /// How `db`'s peer connections connect.
    pub fn peer_routes(&mut self, db: &Osis) -> Vec<Route> {
        let Some(i) = self.index(db) else { return Vec::new() };
        self.peer_links.values().filter(|v| v.0 == i || v.1 == i).map(|v| v.2).collect()
    }

    /// Closes `db` and opens the node again from the same store with `cfg`: its place in the
    /// model, keys and reachability stay (a restart: the new handle has a new index). The clock
    /// is `cfg`'s: a node of `cfg_clocked` restarts with `cfg_clocked` and the same spec.
    #[allow(clippy::panic)] // test harness: fail the test loudly
    pub fn restart(&mut self, db: Osis, cfg: osis::internals::Opening) -> Osis {
        let Some(old) = self.index(&db) else { panic!("restart: not a node of this world") };
        self.set_online(&db, false);
        // its hub's store is the closed node's: the new node gets a hub of its own
        for h in self.hosts.iter_mut().filter(|h| h.node == Some(old)) {
            h.up = false;
        }
        match db.close() {
            Ok(osis::Close::Closed) => {}
            other => panic!("restart: close: {other:?}"),
        }
        let new = match osis::internals::open(cfg) {
            Ok(n) => n,
            Err(e) => panic!("restart: open: {e:?}"),
        };
        let Some(i) = self.index(&new) else { panic!("restart: the new node") };
        self.reach.renumber(old, i);
        let moved = |w: Who| if w == Who::Node(old) { Who::Node(i) } else { w };
        self.peer_cut = std::mem::take(&mut self.peer_cut).into_iter().map(|(a, b)| (moved(a), moved(b))).collect();
        new
    }

    fn hub_out(&mut self, s: usize, out: Vec<HubOutput>) {
        let mut ups = Vec::new();
        let mut moved = false;
        for o in out {
            match o {
                HubOutput::Moved => moved = true,
                HubOutput::Send(hc, bytes) => {
                    if let Some((t, thc)) = self.links.get(&(s, hc)).copied() {
                        if let Some(d) = self.dialed.get(&(s, hc)).copied() {
                            if let Some(t) = self.traffic.get_mut(d) {
                                t.up += bytes.len() as u64;
                            }
                            self.count(d, hc, &bytes, false);
                        }
                        self.send_msg(Msg::ToHub(t, thc, bytes));
                    }
                }
                HubOutput::Close(hc) => {
                    if let Some((t, thc)) = self.unlink(s, hc) {
                        self.send_msg(Msg::Closed(t, thc));
                    }
                }
                HubOutput::Diagnostic(_) => {}
                HubOutput::Up(hc, up) => ups.push((hc, up)),
            }
        }
        // node sync above the hub of a node, by function call as the node's driver does
        let node = self.hosts.get(s).and_then(|h| h.node);
        if !moved && ups.is_empty() {
            return;
        }
        match node {
            Some(d) => self.with(d, |db| db.feed(Event::Hub { ups })),
            None => self.host_feed(s, Event::Hub { ups }),
        }
    }

    /// Feeds an event to the world's own host `s`'s node sync and carries out what it hands its
    /// hub (it dials nothing: no group, no peer).
    #[allow(clippy::panic)] // test harness: fail the test loudly
    fn host_feed(&mut self, s: usize, ev: Event) {
        let now = self.now();
        let Some(acts) = self.hosts.get_mut(s).filter(|h| h.up).and_then(|h| h.sync.as_mut()).map(|sy| sy.handle(ev)) else { return };
        for a in acts {
            match a {
                Action::Hub { conn, down } => {
                    let out = self.hosts.get_mut(s).map(|h| h.hub.down(now, vec![(conn, down)])).unwrap_or_default();
                    self.hub_out(s, out);
                }
                Action::Dial { .. } | Action::Close { .. } => panic!("host {s} dialed: {a:?}"),
                _ => {}
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
                            Action::Dial { .. } => "dial",
                            Action::Close { .. } => "close",
                            Action::Wake { .. } => "wake",
                            Action::Reach => "reach",
                            Action::Host(_) => "host",
                            Action::Hub { .. } => "hub",
                            Action::Request { .. } | Action::Room { .. } | Action::Ended { .. } => "port",
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
                Msg::Up { db, conn, .. } => format!("up db {db} conn {conn:?}"),
                Msg::ToHub(s, hc, b) => format!("{} -> {}: {}", self.links.get(&(*s, *hc)).map_or("?".into(), |x| self.party(x.0)), self.party(*s), kind(b)),
                Msg::Down(d, c) => format!("down db {d} conn {c:?}"),
                Msg::Closed(s, _) => format!("closed at host {s}"),
            };
            *seen.entry(k).or_default() += 1;
        }
        let now = self.now();
        match m {
            Msg::Up { db: d, conn, s, hc, key, relayed } => {
                if self.dials.remove(&(d, conn)).is_none() {
                    return true;
                }
                // cut before it was up: the dial failed
                if !self.links.contains_key(&(s, hc)) {
                    self.with(d, |db| db.feed(Event::Down { conn }));
                    return true;
                }
                let remote = osis_host::Remote { peer: osis_transport::Peer::Key(key), relayed };
                let out = self.hosts.get_mut(s).map(|h| h.hub.dial(now, hc, key, remote)).unwrap_or_default();
                self.with(d, |db| db.feed(Event::Up { conn, hub: hc }));
                self.hub_out(s, out);
            }
            Msg::ToHub(s, hc, b) => {
                if let Some(d) = self.dialed.get(&(s, hc)).copied() {
                    if let Some(t) = self.traffic.get_mut(d) {
                        t.down += b.len() as u64;
                    }
                    self.count(d, hc, &b, true);
                }
                let t = Instant::now();
                let out = match self.hosts.get_mut(s) {
                    Some(host) => host.hub.input(now, hc, b),
                    None => Vec::new(),
                };
                self.hub_busy += t.elapsed();
                self.hub_out(s, out);
            }
            Msg::Down(d, c) => self.with(d, |db| db.feed(Event::Down { conn: c })),
            Msg::Closed(s, hc) => {
                let out = self.hosts.get_mut(s).map(|host| host.hub.closed(hc)).unwrap_or_default();
                self.hub_out(s, out);
            }
        }
        true
    }

    /// Who runs hub `s` (trace).
    fn party(&self, s: usize) -> String {
        match self.hosts.get(s).and_then(|h| h.node) {
            Some(d) => format!("db {d}"),
            None => format!("host {s}"),
        }
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
        for (c, spec) in &self.own_clocks {
            c.set(Time(wall_of(*spec, now.saturating_sub(T0))));
        }
        for s in 0..self.hosts.len() {
            let out = match self.hosts.get_mut(s).filter(|h| h.up) {
                Some(host) => host.hub.tick(now),
                None => Vec::new(),
            };
            self.hub_out(s, out);
            self.host_feed(s, Event::Tick);
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

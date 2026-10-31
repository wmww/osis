//! An API-level world: `osis::Osis` handles on `Runtime::Manual` exchange bytes with osis-server
//! `Hub`s over in-memory queues under one `ManualClock`. No tokio, no threads of its own, no
//! sleeps: time moves only by `advance`, so a run is a function of its seeds. The example apps
//! (examples/*) and their end-to-end tests drive it; core/osis/tests/it/common/world.rs is the
//! osis crate's own copy (it cannot depend on this crate).

use osis::internals::node::sync::{Action, ConnId, Event};
use osis::internals::{Internals, ManualNet};
use osis::{Config, ManualClock, MemStore, Osis, RecoveryCard, Runtime, ServerAddr, StoreAt, WallMs};
use osis_crypto::SeededRng;
use osis_proto::{FrameDecoder, Message, StoreError};
use osis_server::{BackendStore, Hub, HubOutput, Policy};
use osis_store::MemoryBackend;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

/// Start of the world's wall clock (ms).
pub const T0: u64 = 1_700_000_000_000;

/// One blind server.
pub struct Server {
    pub hub: Hub<MemoryBackend>,
    pub addr: ServerAddr,
}

enum Msg {
    Up(usize, ConnId),
    ToHub(usize, u64, Vec<u8>),
    ToDb(usize, ConnId, Vec<u8>),
    Down(usize, ConnId),
}

/// Bytes a database exchanged with servers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    pub up: u64,
    pub down: u64,
}

pub struct World {
    pub clock: Arc<ManualClock>,
    pub servers: Vec<Server>,
    /// Every database made with `cfg`, by start order (also those a future opened).
    pub net: ManualNet,
    /// (db, conn) -> (server, hub conn)
    links: BTreeMap<(usize, ConnId), (usize, u64)>,
    queue: VecDeque<Msg>,
    next_hub: u64,
    /// Databases cut off the network.
    offline: Vec<bool>,
    /// Databases whose user leaves invite requests alone (the others accept each as it
    /// appears, spec/sync.md §3), by start order.
    pub holds_invites: BTreeSet<usize>,
    /// Per database, by start order.
    traffic: Vec<Traffic>,
    /// With `tally`: upstream frames per (database, message kind): count and bytes.
    tally: Option<BTreeMap<(usize, String), (u64, u64)>>,
    decoders: BTreeMap<(usize, ConnId), FrameDecoder>,
    /// Messages one `pump` carries at most before it reports a storm.
    pub max_pump: usize,
}

impl Default for World {
    fn default() -> World {
        World::new()
    }
}

impl World {
    pub fn new() -> World {
        World {
            clock: Arc::new(ManualClock::new(WallMs(T0))),
            servers: Vec::new(),
            net: ManualNet::new(),
            links: BTreeMap::new(),
            queue: VecDeque::new(),
            next_hub: 1,
            offline: Vec::new(),
            holds_invites: BTreeSet::new(),
            traffic: Vec::new(),
            tally: None,
            decoders: BTreeMap::new(),
            max_pump: 200_000,
        }
    }

    pub fn now(&self) -> u64 {
        osis::Clock::now_wall_ms(&*self.clock).0
    }

    /// A new blind server (keys and rng from its index).
    pub fn add_server(&mut self) -> Result<usize, StoreError> {
        let i = self.servers.len();
        let b = 0x50u8.wrapping_add(i as u8);
        let key = [b; 32];
        let store = BackendStore::open(MemoryBackend::new(), self.clock.clone(), Policy::default(), &mut SeededRng::from_u64(900 + i as u64))?;
        let hub = Hub::new(store, key, Box::new(SeededRng::from_u64(950 + i as u64)));
        self.servers.push(Server { hub, addr: ServerAddr::new(&format!("quic://server{i}:1"), key) });
        Ok(i)
    }

    pub fn addr(&self, s: usize) -> Option<ServerAddr> {
        self.servers.get(s).map(|x| x.addr.clone())
    }

    /// A config for a database of this world: manual runtime, the world's clock, `seed`, the
    /// given servers, a fresh memory store.
    pub fn cfg(&self, seed: u64, servers: &[usize]) -> Config {
        let mut c = Config::at(StoreAt::Memory(MemStore::new()));
        c.seed = Some(seed);
        c.clock = Some(self.clock.clone());
        c.runtime = Runtime::Manual(self.net.clone());
        c.servers = servers.iter().filter_map(|s| self.addr(*s)).collect();
        c
    }

    /// A new person's database syncing with `servers`, with its recovery card (`None` without
    /// servers).
    pub fn person(&mut self, seed: u64, servers: &[usize]) -> osis::Result<(Osis, Option<RecoveryCard>)> {
        Osis::create(self.cfg(seed, servers))
    }

    fn dbs(&mut self) -> Vec<Option<Osis>> {
        let v = self.net.dbs();
        if v.len() > self.offline.len() {
            self.offline.resize(v.len(), false);
            self.traffic.resize(v.len(), Traffic::default());
        }
        v
    }

    /// The index of a database in this world.
    pub fn index(&mut self, db: &Osis) -> Option<usize> {
        self.dbs().iter().position(|d| d.as_ref().is_some_and(|d| d.node() == db.node()))
    }

    /// Starts counting the messages databases send, by kind (cost analysis; slows the run).
    pub fn start_tally(&mut self) {
        self.tally = Some(BTreeMap::new());
    }

    /// What `db` sent since `start_tally`: message kind -> (count, frame bytes).
    pub fn tally(&mut self, db: &Osis) -> BTreeMap<String, (u64, u64)> {
        let Some(i) = self.index(db) else { return BTreeMap::new() };
        let Some(t) = &self.tally else { return BTreeMap::new() };
        t.iter().filter(|((d, _), _)| *d == i).map(|((_, k), v)| (k.clone(), *v)).collect()
    }

    fn count(&mut self, d: usize, conn: ConnId, bytes: &[u8]) {
        let Some(t) = &mut self.tally else { return };
        let dec = self.decoders.entry((d, conn)).or_default();
        dec.push(bytes);
        while let Ok(Some(f)) = dec.next_frame() {
            let kind = match Message::decode(&f) {
                Ok(m) => format!("{m:?}").split([' ', '{', '(']).next().unwrap_or("?").to_string(),
                Err(_) => "Hello".to_string(),
            };
            let e = t.entry((d, kind)).or_default();
            e.0 += 1;
            e.1 += f.len() as u64 + 4;
        }
    }

    /// Bytes `db` exchanged with servers so far.
    pub fn traffic(&mut self, db: &Osis) -> Traffic {
        self.index(db).and_then(|i| self.traffic.get(i).copied()).unwrap_or_default()
    }

    fn with(&mut self, d: usize, f: impl FnOnce(&Osis)) {
        if let Some(Some(db)) = self.dbs().get(d) {
            f(db)
        }
    }

    fn is_offline(&self, d: usize) -> bool {
        self.offline.get(d).copied().unwrap_or(false)
    }

    /// Cuts a database off the network (its connections go down) or lets it dial again.
    pub fn set_online(&mut self, db: &Osis, on: bool) {
        let Some(i) = self.index(db) else { return };
        if let Some(o) = self.offline.get_mut(i) {
            *o = !on;
        }
        if !on {
            let mine: Vec<(ConnId, (usize, u64))> = self.links.iter().filter(|((d, _), _)| *d == i).map(|((_, c), v)| (*c, *v)).collect();
            for (c, (s, hc)) in mine {
                self.links.remove(&(i, c));
                let now = self.now();
                let out = self.servers.get_mut(s).map(|sv| sv.hub.closed(now, hc)).unwrap_or_default();
                self.hub_out(s, out);
                db.feed(Event::Down { conn: c });
            }
            db.take_actions();
        }
    }

    fn actions(&mut self, d: usize, acts: Vec<Action>) {
        for a in acts {
            match a {
                Action::Dial { conn, address } => {
                    let want = ServerAddr::new(&address.url, address.key).to_string();
                    let s = self.servers.iter().position(|x| x.addr.to_string() == want).filter(|_| !self.is_offline(d));
                    let Some(s) = s else {
                        self.queue.push_back(Msg::Down(d, conn));
                        continue;
                    };
                    let hc = self.next_hub;
                    self.next_hub += 1;
                    self.links.insert((d, conn), (s, hc));
                    self.queue.push_back(Msg::Up(d, conn));
                    let now = self.now();
                    let out = match self.servers.get_mut(s) {
                        Some(sv) => sv.hub.accept(now, hc, [0xe0; 32]),
                        None => Vec::new(),
                    };
                    self.hub_out(s, out);
                }
                Action::Send { conn, bytes } => {
                    if let Some((s, hc)) = self.links.get(&(d, conn)).copied() {
                        if let Some(t) = self.traffic.get_mut(d) {
                            t.up += bytes.len() as u64;
                        }
                        self.count(d, conn, &bytes);
                        self.queue.push_back(Msg::ToHub(s, hc, bytes));
                    }
                }
                Action::Close { conn } => {
                    if let Some((s, hc)) = self.links.remove(&(d, conn)) {
                        let now = self.now();
                        let out = self.servers.get_mut(s).map(|sv| sv.hub.closed(now, hc)).unwrap_or_default();
                        self.hub_out(s, out);
                    }
                }
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
                        self.queue.push_back(Msg::ToDb(d, c, bytes));
                    }
                }
                HubOutput::Close(hc) => {
                    if let Some((d, c)) = self.link_of(s, hc) {
                        self.links.remove(&(d, c));
                        self.queue.push_back(Msg::Down(d, c));
                    }
                }
                HubOutput::Diagnostic(_) => {}
            }
        }
    }

    /// Carries every queued action and message until nothing moves. False if it did not
    /// settle within a bound (a message storm).
    pub fn pump(&mut self) -> bool {
        for _ in 0..self.max_pump {
            let mut moved = false;
            let dbs = self.dbs();
            for (d, db) in dbs.iter().enumerate() {
                let Some(db) = db else { continue };
                let acts = db.take_actions();
                if !acts.is_empty() {
                    moved = true;
                    // offline: dials fail, nothing is sent
                    self.actions(d, acts);
                }
            }
            let Some(m) = self.queue.pop_front() else {
                if moved {
                    continue;
                }
                return true;
            };
            let now = self.now();
            match m {
                Msg::Up(d, c) => self.with(d, |db| db.feed(Event::Up { conn: c })),
                Msg::ToHub(s, hc, b) => {
                    let out = match self.servers.get_mut(s) {
                        Some(sv) => sv.hub.input(now, hc, b),
                        None => Vec::new(),
                    };
                    self.hub_out(s, out);
                }
                Msg::ToDb(d, c, b) => {
                    if let Some(t) = self.traffic.get_mut(d) {
                        t.down += b.len() as u64;
                    }
                    self.with(d, |db| db.feed(Event::Bytes { conn: c, bytes: b }))
                }
                Msg::Down(d, c) => self.with(d, |db| db.feed(Event::Down { conn: c })),
            }
        }
        false
    }

    /// Moves time on by `ms`: server ticks, database ticks, then everything settles.
    pub fn advance(&mut self, ms: u64) -> bool {
        self.clock.advance(ms);
        let now = self.now();
        for s in 0..self.servers.len() {
            let out = match self.servers.get_mut(s) {
                Some(sv) => sv.hub.tick(now),
                None => Vec::new(),
            };
            self.hub_out(s, out);
        }
        self.tick_all();
        self.pump()
    }

    fn tick_all(&mut self) {
        let dbs = self.dbs();
        // an offline database's clock runs too: expiry, retention and timeouts
        for db in dbs.iter().flatten() {
            db.feed(Event::Tick);
        }
    }

    /// Lets everything settle (several rounds: a pass may start another). False on a storm.
    /// Invite requests that appeared are accepted (`accept_invites`) and settled again.
    pub fn run(&mut self) -> bool {
        let mut ok = true;
        loop {
            for _ in 0..3 {
                ok &= self.pump();
                self.tick_all();
            }
            ok &= self.pump();
            if !ok || !self.accept_invites() {
                return ok;
            }
        }
    }

    /// Every online database's user but those in `holds_invites` accepts its invite requests
    /// (a user clicking accept). Whether any was.
    fn accept_invites(&mut self) -> bool {
        let mut any = false;
        for (d, db) in self.dbs().iter().enumerate() {
            if let Some(db) = db
                && !self.holds_invites.contains(&d)
                && !self.offline.get(d).copied().unwrap_or(false)
            {
                for r in db.invite_requests().unwrap_or_default() {
                    any |= db.accept_invite(r.id).is_ok();
                }
            }
        }
        any
    }

    /// Drives the world until `f` resolves: settling, then stepping time by `step_ms`, at most
    /// `steps` times. `None` if it did not resolve.
    pub fn until<F: Future>(&mut self, f: F, step_ms: u64, steps: usize) -> Option<F::Output> {
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

//! Databases and blind servers in process, no tokio: `Osis` handles on `Runtime::Manual` exchange
//! bytes with osis-server `Hub`s over in-memory queues under one manual clock (the pattern of
//! osis-node's tests/net). Futures of the API are polled by hand while the world runs.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis::node::sync::{Action, ConnId, Event};
use osis::{Config, ManualClock, ManualNet, MemStore, Osis, Runtime, ServerAddr, StoreAt, WallMs};
use osis_crypto::SeededRng;
use osis_server::{BackendStore, Hub, HubOutput, Policy};
use osis_store::MemoryBackend;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use super::T0;

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
    pub offline: Vec<bool>,
}

impl World {
    pub fn new() -> World {
        World { clock: Arc::new(ManualClock::new(WallMs(T0))), servers: Vec::new(), net: ManualNet::new(), links: BTreeMap::new(), queue: VecDeque::new(), next_hub: 1, offline: Vec::new() }
    }

    pub fn now(&self) -> u64 {
        osis::Clock::now_wall_ms(&*self.clock).0
    }

    pub fn add_server(&mut self) -> usize {
        let i = self.servers.len();
        let key = [0x50 + i as u8; 32];
        let store = BackendStore::open(MemoryBackend::new(), self.clock.clone(), Policy::default(), &mut SeededRng::from_u64(900 + i as u64)).unwrap();
        let hub = Hub::new(store, key, Box::new(SeededRng::from_u64(950 + i as u64)));
        self.servers.push(Server { hub, addr: ServerAddr::new(&format!("quic://server{i}:1"), key) });
        i
    }

    pub fn addr(&self, s: usize) -> ServerAddr {
        self.servers[s].addr.clone()
    }

    /// A config for a database of this world: manual runtime, the world's clock, `seed`, the
    /// given servers.
    pub fn cfg(&self, seed: u64, servers: &[usize]) -> Config {
        let mut c = Config::at(StoreAt::Memory(MemStore::new()));
        c.seed = Some(seed);
        c.clock = Some(self.clock.clone());
        c.runtime = Runtime::Manual(self.net.clone());
        c.servers = servers.iter().map(|s| self.addr(*s)).collect();
        c
    }

    fn dbs(&mut self) -> Vec<Option<Osis>> {
        let v = self.net.dbs();
        if v.len() > self.offline.len() && std::env::var_os("OSIS_TEST_DIAG").is_some() {
            for (i, db) in v.iter().enumerate().skip(self.offline.len()) {
                if let Some(db) = db {
                    db.on_diagnostic(move |_, d| eprintln!("db {i}: {d:?}")).detach();
                }
            }
        }
        self.offline.resize(v.len(), false);
        v
    }

    /// A new person's database syncing with `servers`, with its recovery card.
    pub fn person(&mut self, seed: u64, servers: &[usize]) -> (Osis, osis::RecoveryCard) {
        let (db, card) = Osis::create(self.cfg(seed, servers)).unwrap();
        (db, card.unwrap())
    }

    /// The index of a database in this world.
    pub fn index(&mut self, db: &Osis) -> usize {
        self.dbs().iter().position(|d| d.as_ref().is_some_and(|d| d.node() == db.node())).unwrap()
    }

    fn with(&mut self, d: usize, f: impl FnOnce(&Osis)) {
        if let Some(Some(db)) = self.dbs().get(d) {
            f(db)
        }
    }

    pub fn set_online(&mut self, db: &Osis, on: bool) {
        let i = self.index(db);
        self.offline[i] = !on;
        if !on {
            let mine: Vec<(ConnId, (usize, u64))> = self.links.iter().filter(|((d, _), _)| *d == i).map(|((_, c), v)| (*c, *v)).collect();
            for (c, (s, hc)) in mine {
                self.links.remove(&(i, c));
                self.servers[s].hub.closed(hc);
                db.feed(Event::Down { conn: c });
            }
            db.take_actions();
        }
    }

    fn actions(&mut self, d: usize, acts: Vec<Action>) {
        for a in acts {
            match a {
                Action::Dial { conn, address } => {
                    let Some(s) = self.servers.iter().position(|x| x.addr.to_string() == ServerAddr::new(&address.url, address.key).to_string()).filter(|_| !self.offline[d]) else {
                        self.queue.push_back(Msg::Down(d, conn));
                        continue;
                    };
                    let hc = self.next_hub;
                    self.next_hub += 1;
                    self.links.insert((d, conn), (s, hc));
                    self.queue.push_back(Msg::Up(d, conn));
                    let now = self.now();
                    let out = self.servers[s].hub.accept(now, hc, [0xe0; 32]);
                    self.hub_out(s, out);
                }
                Action::Send { conn, bytes } => {
                    if let Some((s, hc)) = self.links.get(&(d, conn)).copied() {
                        self.queue.push_back(Msg::ToHub(s, hc, bytes));
                    }
                }
                Action::Close { conn } => {
                    if let Some((s, hc)) = self.links.remove(&(d, conn)) {
                        self.servers[s].hub.closed(hc);
                    }
                }
                Action::Wake { .. } => {}
            }
        }
    }

    fn hub_out(&mut self, s: usize, out: Vec<HubOutput>) {
        for o in out {
            match o {
                HubOutput::Send(hc, bytes) => {
                    if let Some(((d, c), _)) = self.links.iter().find(|(_, (x, h))| *x == s && *h == hc) {
                        self.queue.push_back(Msg::ToDb(*d, *c, bytes));
                    }
                }
                HubOutput::Close(hc) => {
                    if let Some(((d, c), _)) = self.links.iter().find(|(_, (x, h))| *x == s && *h == hc).map(|(k, v)| (*k, *v)) {
                        self.links.remove(&(d, c));
                        self.queue.push_back(Msg::Down(d, c));
                    }
                }
                HubOutput::Diagnostic(_) => {}
            }
        }
    }

    /// Carries every queued action and message until nothing moves.
    pub fn pump(&mut self) {
        for _ in 0..200_000 {
            let mut moved = false;
            let dbs = self.dbs();
            for (d, db) in dbs.iter().enumerate() {
                let Some(db) = db else { continue };
                let acts = db.take_actions();
                if !acts.is_empty() {
                    moved = true;
                    if !self.offline[d] {
                        self.actions(d, acts);
                    }
                }
            }
            let Some(m) = self.queue.pop_front() else {
                if moved {
                    continue;
                }
                return;
            };
            let now = self.now();
            match m {
                Msg::Up(d, c) => self.with(d, |db| db.feed(Event::Up { conn: c })),
                Msg::ToHub(s, hc, b) => {
                    let out = self.servers[s].hub.input(now, hc, b);
                    self.hub_out(s, out);
                }
                Msg::ToDb(d, c, b) => self.with(d, |db| db.feed(Event::Bytes { conn: c, bytes: b })),
                Msg::Down(d, c) => self.with(d, |db| db.feed(Event::Down { conn: c })),
            }
        }
        panic!("no quiescence");
    }

    /// Moves time on by `ms`: server ticks, database ticks, then everything settles.
    pub fn advance(&mut self, ms: u64) {
        self.clock.advance(ms);
        let now = self.now();
        for s in 0..self.servers.len() {
            let out = self.servers[s].hub.tick(now);
            self.hub_out(s, out);
        }
        self.tick_all();
        self.pump();
    }

    fn tick_all(&mut self) {
        let dbs = self.dbs();
        for (d, db) in dbs.iter().enumerate() {
            match db {
                Some(db) if !self.offline[d] => db.feed(Event::Tick),
                // an offline database's clock still runs: its waits time out
                Some(db) => {
                    db.waiting();
                }
                None => {}
            }
        }
    }

    /// Lets everything settle (several rounds: a pass may start another).
    pub fn run(&mut self) {
        for _ in 0..3 {
            self.pump();
            self.tick_all();
        }
        self.pump();
    }

    /// Drives the world until `f` resolves: settling, then stepping time by `step_ms`, at most
    /// `steps` times.
    pub fn until<F: Future>(&mut self, f: F, step_ms: u64, steps: usize) -> F::Output {
        let mut f = std::pin::pin!(f);
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..steps {
            if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
            self.run();
            if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
            if std::env::var_os("OSIS_TEST_TRACE").is_some() {
                for (i, db) in self.dbs().iter().enumerate() {
                    if let Some(db) = db {
                        let (d, g) = db.sync_engine(|s| (s.describe(), s.take_diagnostics()));
                        let d: Vec<String> = d.into_iter().filter(|x| !x.contains("Open synced true syncing false dirty false")).collect();
                        eprintln!("t={} db {i}: {d:?} {g:?} pending {:?}", self.now(), db.engine(|e| e.pending()));
                    }
                }
            }
            self.advance(step_ms);
        }
        panic!("future did not resolve");
    }
}

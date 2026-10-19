#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, dead_code)]
//! Sync engines and blind nodes in process, no tokio: `SyncEngine`s exchanging bytes with
//! osis-server `Hub`s over in-memory queues, one manual clock. Group setup stands in for pairing
//! (direct delivery of the setup commits).

use osis_core::{Clock, CommitId, ManualClock, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::SeededRng;
use osis_keys::{MemberKeys, Recipient, rotate};
use osis_label::Address;
use osis_node::sync::{Action, ConnId, Event, SyncConfig, SyncEngine};
use osis_node::{Config, Engine, Mutation};
use osis_schema::core_types as ct;
use osis_schema::{AspectKey, Codec};
use osis_proto::LabelStore;
use osis_server::{BackendStore, Hub, HubOutput, Policy};
use osis_store::{MemoryBackend, MemoryRoot};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

pub const T0: u64 = 1_700_000_000_000;

pub struct Server {
    pub hub: Hub<MemoryBackend>,
    pub backend: MemoryBackend,
    pub address: Address,
}

pub struct Node {
    pub sync: Option<SyncEngine>,
    pub backend: MemoryBackend,
    pub root: MemoryRoot,
    pub online: bool,
    pub wake: Option<u64>,
}

enum Msg {
    /// node, conn -> hub
    Up(usize, ConnId),
    ToHub(usize, ConnId, Vec<u8>),
    ToNode(usize, ConnId, Vec<u8>),
    Close(usize, ConnId),
}

pub struct Net {
    pub clock: Arc<ManualClock>,
    pub nodes: Vec<Node>,
    pub servers: Vec<Server>,
    /// (node, conn) -> (server, hub conn)
    links: BTreeMap<(usize, ConnId), (usize, u64)>,
    queue: VecDeque<Msg>,
    next_hub_conn: u64,
    pub steps: usize,
}

pub fn server_key(i: usize) -> [u8; 32] {
    [0x50 + i as u8; 32]
}

impl Net {
    pub fn new() -> Net {
        Net { clock: Arc::new(ManualClock::new(WallMs(T0))), nodes: vec![], servers: vec![], links: BTreeMap::new(), queue: VecDeque::new(), next_hub_conn: 1, steps: 0 }
    }

    pub fn now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    pub fn add_server(&mut self) -> usize {
        let i = self.servers.len();
        let backend = MemoryBackend::new();
        let store = BackendStore::open(backend.clone(), self.clock.clone(), Policy::default(), &mut SeededRng::from_u64(900 + i as u64)).unwrap();
        let hub = Hub::new(store, server_key(i), Box::new(SeededRng::from_u64(950 + i as u64)));
        self.servers.push(Server { hub, backend, address: Address { url: format!("quic://server{i}:1"), key: server_key(i) } });
        i
    }

    pub fn address(&self, s: usize) -> Address {
        self.servers[s].address.clone()
    }

    pub fn add_node(&mut self, seed: u64, cfg: SyncConfig) -> usize {
        let (backend, root) = (MemoryBackend::new(), MemoryRoot::new());
        let c: Arc<dyn Clock> = self.clock.clone();
        let engine = Engine::create(Box::new(backend.clone()), Box::new(root.clone()), Config::default(), c.clone(), Box::new(SeededRng::from_u64(seed))).unwrap();
        let sync = SyncEngine::new(engine, c, Box::new(SeededRng::from_u64(seed + 7)), cfg).unwrap();
        self.nodes.push(Node { sync: Some(sync), backend, root, online: true, wake: None });
        self.nodes.len() - 1
    }

    /// A node with the default config syncing with servers `servers`.
    pub fn node(&mut self, seed: u64, servers: &[usize]) -> usize {
        let cfg = SyncConfig { servers: servers.iter().map(|s| self.address(*s)).collect(), ..SyncConfig::default() };
        self.add_node(seed, cfg)
    }

    pub fn sync(&mut self, n: usize) -> &mut SyncEngine {
        self.nodes[n].sync.as_mut().unwrap()
    }

    pub fn engine(&mut self, n: usize) -> &mut Engine {
        self.sync(n).engine_mut()
    }

    pub fn tid(&mut self, n: usize) -> Tid {
        self.engine(n).tid()
    }

    /// Restarts a node over its store (sync state reloads).
    pub fn restart(&mut self, n: usize, seed: u64) {
        let cfg = self.sync(n).config().clone();
        self.disconnect(n);
        let c: Arc<dyn Clock> = self.clock.clone();
        let node = &mut self.nodes[n];
        node.sync = None;
        let engine = Engine::open(Box::new(node.backend.clone()), Box::new(node.root.clone()), Config::default(), c.clone(), Box::new(SeededRng::from_u64(seed))).unwrap();
        node.sync = Some(SyncEngine::new(engine, c, Box::new(SeededRng::from_u64(seed + 7)), cfg).unwrap());
    }

    fn disconnect(&mut self, n: usize) {
        let mine: Vec<(ConnId, (usize, u64))> = self.links.iter().filter(|((x, _), _)| *x == n).map(|((_, c), v)| (*c, *v)).collect();
        for (c, (s, hc)) in mine {
            self.links.remove(&(n, c));
            self.servers[s].hub.closed(hc);
            if let Some(sy) = self.nodes[n].sync.as_mut() {
                sy.handle(Event::Down { conn: c });
            }
        }
    }

    pub fn set_online(&mut self, n: usize, on: bool) {
        if !on {
            self.disconnect(n);
        }
        self.nodes[n].online = on;
    }

    /// Feeds an event to node `n` and queues its actions.
    pub fn feed(&mut self, n: usize, ev: Event) {
        if !self.nodes[n].online {
            return;
        }
        let acts = self.sync(n).handle(ev);
        self.actions(n, acts);
    }

    pub fn actions(&mut self, n: usize, acts: Vec<Action>) {
        for a in acts {
            if std::env::var_os("OSIS_SYNC_TRACE").is_some() {
                eprintln!("node {n} action {}", format!("{a:?}").chars().take(120).collect::<String>());
            }
            match a {
                Action::Dial { conn, address } => {
                    let Some(s) = self.servers.iter().position(|x| x.address.key == address.key) else {
                        self.queue.push_back(Msg::Close(n, conn));
                        continue;
                    };
                    let hc = self.next_hub_conn;
                    self.next_hub_conn += 1;
                    self.links.insert((n, conn), (s, hc));
                    self.queue.push_back(Msg::Up(n, conn));
                    let now = self.now();
                    let out = self.servers[s].hub.accept(now, hc, [0xe0; 32]);
                    self.hub_out(s, out);
                }
                Action::Send { conn, bytes } => {
                    if let Some((s, hc)) = self.links.get(&(n, conn)).copied() {
                        self.queue.push_back(Msg::ToHub(s, hc as ConnId, bytes));
                    }
                }
                Action::Close { conn } => {
                    if let Some((s, hc)) = self.links.remove(&(n, conn)) {
                        self.servers[s].hub.closed(hc);
                    }
                }
                Action::Wake { at } => self.nodes[n].wake = Some(at),
            }
        }
    }

    fn hub_out(&mut self, s: usize, out: Vec<HubOutput>) {
        for o in out {
            match o {
                HubOutput::Send(hc, bytes) => {
                    if let Some(((n, c), _)) = self.links.iter().find(|(_, (x, h))| *x == s && *h == hc) {
                        self.queue.push_back(Msg::ToNode(*n, *c, bytes));
                    }
                }
                HubOutput::Close(hc) => {
                    if let Some(((n, c), _)) = self.links.iter().find(|(_, (x, h))| *x == s && *h == hc).map(|(k, v)| (*k, *v)) {
                        self.links.remove(&(n, c));
                        self.queue.push_back(Msg::Close(n, c));
                    }
                }
                HubOutput::Diagnostic(_) => {}
            }
        }
    }

    /// Delivers queued messages until none are left (at most `max`).
    pub fn settle(&mut self, max: usize) {
        let mut i = 0;
        while let Some(m) = self.queue.pop_front() {
            i += 1;
            self.steps += 1;
            assert!(i < max, "no quiescence after {max} messages");
            let now = self.now();
            match m {
                Msg::Up(n, c) => self.feed(n, Event::Up { conn: c }),
                Msg::ToHub(s, hc, b) => {
                    let out = self.servers[s].hub.input(now, hc, b);
                    self.hub_out(s, out);
                }
                Msg::ToNode(n, c, b) => self.feed(n, Event::Bytes { conn: c, bytes: b }),
                Msg::Close(n, c) => self.feed(n, Event::Down { conn: c }),
            }
            for s in 0..self.servers.len() {
                if self.servers[s].hub.next_due(now).is_some_and(|t| t <= now) {
                    let out = self.servers[s].hub.tick(now);
                    self.hub_out(s, out);
                }
            }
        }
    }

    /// Every online node looks at its engine, then everything settles.
    pub fn run(&mut self) {
        for n in 0..self.nodes.len() {
            self.feed(n, Event::Local);
        }
        self.settle(200_000);
        for n in 0..self.nodes.len() {
            self.feed(n, Event::Local);
        }
        self.settle(200_000);
    }

    /// Moves time on by `ms`, firing node wakes and server ticks, then settles.
    pub fn advance(&mut self, ms: u64) {
        self.clock.advance(ms);
        let now = self.now();
        for s in 0..self.servers.len() {
            let out = self.servers[s].hub.tick(now);
            self.hub_out(s, out);
        }
        for n in 0..self.nodes.len() {
            self.feed(n, Event::Tick);
        }
        self.run();
    }

    /// Delivers every commit `from` holds to `to` directly (pairing stand-in).
    pub fn pair(&mut self, from: usize, to: usize) {
        let ids = self.engine(from).commit_ids();
        for id in ids {
            let pk = self.engine(from).package(&id).unwrap().unwrap();
            let _ = self.engine(to).ingest(&pk.bytes, pk.blobs);
        }
    }

    /// A group owned by node `admin` with secrets of its own, `members` granted with their roles
    /// (rotation boxing every member), a deposit seed and a label at `servers`; the setup
    /// commits delivered to the members directly.
    pub fn group(&mut self, admin: usize, members: &[(usize, Role)], servers: &[usize]) -> Tid {
        for (m, _) in members {
            self.pair(*m, admin);
        }
        let me = self.tid(admin);
        let e = self.engine(admin);
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
        e.commit(m).unwrap();
        let mut recipients = vec![recipient(e, me, Role::Admin)];
        let mtids: Vec<(Tid, Role)> = members.iter().map(|(n, r)| (self.tid(*n), *r)).collect();
        for (t, r) in &mtids {
            let e = self.engine(admin);
            set_edge(e, g, *t, *r);
            recipients.push(recipient(e, *t, *r));
        }
        let e = self.engine(admin);
        rotation(e, g, &recipients, 1, true);
        let addrs: Vec<Address> = servers.iter().map(|s| self.servers[*s].address.clone()).collect();
        self.engine(admin).create_label(&g, addrs, &mut SeededRng::from_u64(77)).unwrap();
        for (m, _) in members {
            self.pair(admin, *m);
        }
        g
    }

    /// A content thing in group `g` written by node `n`: created under `owner`, listed in
    /// `/group` of `g`.
    pub fn item(&mut self, n: usize, g: Tid, owner: Tid, v: &str) -> Tid {
        let e = self.engine(n);
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, owner);
        m.set(t, &REG, &s(v)).unwrap();
        let mut items = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
        items.items.insert(t);
        m.set(g, &ct::GROUP, &items).unwrap();
        e.commit(m).unwrap();
        t
    }

    pub fn write(&mut self, n: usize, t: Tid, v: &str) -> CommitId {
        let mut m = Mutation::new();
        m.set(t, &REG, &s(v)).unwrap();
        self.engine(n).commit(m).unwrap().unwrap()
    }

    pub fn read(&mut self, n: usize, t: Tid) -> Option<Value> {
        let ak = osis_core::Ak::new(REG.ak()).unwrap();
        self.engine(n).get(&t, &ak).unwrap()
    }

    /// Live entry IDs the server holds under a label.
    pub fn server_ids(&self, s: usize, l: &osis_core::LabelId) -> Vec<osis_core::BlobId> {
        self.servers[s].hub.store().live_ids(l).unwrap()
    }

    pub fn labels_at(&self, s: usize) -> Vec<osis_core::LabelId> {
        self.servers[s].hub.store().labels_after(None, 1000).unwrap()
    }
}

pub static TEST: osis_schema::StaticSchema = osis_schema::StaticSchema::new(
    "test.osis",
    r#"
schema 0x0123456789abcdef0123456789abcdee;
revision 1;
aspect /t/reg: string;
aspect /t/gone: string [by: writer, keep_at_most: 1h];
aspect /t/brief: string [expires: 1h];
"#,
);

pub const REG: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/t/reg", &TEST);
pub const GONE: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/t/gone", &TEST);
pub const BRIEF: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/t/brief", &TEST);

pub fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn recipient(e: &mut Engine, t: Tid, role: Role) -> Recipient {
    let kem = if t == e.tid() {
        e.identity().keys().kem.public().clone()
    } else {
        let k = e.get_typed(&t, &ct::KEYS).unwrap().unwrap();
        let ct::KemKey::X25519MlKem768(b) = k.key.unwrap();
        osis_crypto::KemPublicKey::from_slice(&b).unwrap()
    };
    Recipient { member: t, role, keys: MemberKeys::KeyActor { kem, seed: None } }
}

pub fn set_edge(e: &mut Engine, thing: Tid, member: Tid, role: Role) -> CommitId {
    let mut m = Mutation::new();
    let edge = ct::Edge { role, until: None, invite: None, since: None };
    m.op(thing, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(member))], op: Op::Set(edge.to_value()) }).unwrap();
    e.commit(m).unwrap().unwrap()
}

/// A rotation of every role of `a` boxing `recipients`, with a deposit seed when `seed`.
pub fn rotation(e: &mut Engine, a: Tid, recipients: &[Recipient], rng: u64, seed: bool) -> CommitId {
    let roles = BTreeSet::from([Role::Read, Role::Write, Role::Admin]);
    let view = e.epochs(&a).unwrap();
    let state = e.get_typed(&a, &ct::SECRETS).unwrap().unwrap_or_default();
    let r = rotate(&a, &roles, &view, &state, recipients, &|_, _| true, &mut SeededRng::from_u64(rng)).unwrap();
    let mut m = Mutation::new();
    for (k, b) in &r.secrets.boxes {
        m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(k.to_value())], op: Op::Set(b.to_value()) }).unwrap();
    }
    for k in &r.secrets.removed {
        m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(k.to_value()) }).unwrap();
    }
    for (k, h) in &r.secrets.history {
        m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(k.to_value())], op: Op::Set(Value::Bytes(h.clone())) }).unwrap();
    }
    for (role, ks) in &r.keys.keysets {
        let f = match role {
            Role::Read => 0,
            Role::Write => 1,
            Role::Admin => 2,
        };
        m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(f)], op: Op::Replace(Some(ks.clone()).to_value()) }).unwrap();
    }
    if seed {
        m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(5)], op: Op::Replace(Some([0x5e; 32]).to_value()) }).unwrap();
    }
    e.commit(m).unwrap().unwrap()
}

pub fn recipients_of(e: &mut Engine, members: &[(Tid, Role)]) -> Vec<Recipient> {
    members.iter().map(|(t, r)| recipient(e, *t, *r)).collect()
}

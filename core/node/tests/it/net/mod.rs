#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, dead_code)]
//! Sync engines and blind nodes in process, no tokio: `SyncEngine`s exchanging bytes with
//! osis-server `Hub`s over in-memory queues, one manual clock. Group setup stands in for pairing
//! (direct delivery of the setup commits).

use osis_base::{Clock, CommitId, ManualClock, Role, Tid, Value, WallMs};
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
    /// Added to the wall clock this server reports (handshakes, pongs) and acts on.
    pub skew: i64,
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
    /// (node, server) pairs that cannot connect.
    pub blocked: BTreeSet<(usize, usize)>,
    /// Node-to-node sessions, both directions: (node, conn) -> (node, conn).
    plinks: BTreeMap<(usize, ConnId), (usize, ConnId)>,
    /// (node, node) pairs that cannot connect.
    pub blocked_peers: BTreeSet<(usize, usize)>,
    /// LAN transport keys nodes listen with (peer dials to them reach that node).
    pub lan_keys: BTreeMap<[u8; 32], usize>,
    /// (from node, to node): peer bytes held back until `release`.
    pub held: BTreeSet<(usize, usize)>,
    held_msgs: Vec<Msg>,
    /// Message kinds nodes sent to servers, by kind.
    pub sent_kinds: BTreeMap<u64, usize>,
    /// Bytes nodes sent to servers.
    pub sent_bytes: usize,
    /// Every dial: (node, address).
    pub dialed: Vec<(usize, Address)>,
    /// Nodes added from now on judge everything at every pass (`SyncConfig::full_passes`).
    pub full_passes: bool,
    /// Nodes whose Upload requests to servers are lost on the way (never answered).
    pub lose_uploads: BTreeSet<usize>,
    /// Servers whose messages to nodes are held back until `release` (a slow server).
    pub held_servers: BTreeSet<usize>,
    /// Time spent in each node's `handle` and in the hubs (scale tests).
    pub busy: BTreeMap<usize, std::time::Duration>,
    pub hub_busy: std::time::Duration,
}

pub fn server_key(i: usize) -> [u8; 32] {
    [0x50 + i as u8; 32]
}

impl Net {
    pub fn new() -> Net {
        Net { clock: Arc::new(ManualClock::new(WallMs(T0))), nodes: vec![], servers: vec![], links: BTreeMap::new(), queue: VecDeque::new(), next_hub_conn: 1, steps: 0, blocked: BTreeSet::new(), plinks: BTreeMap::new(), blocked_peers: BTreeSet::new(), lan_keys: BTreeMap::new(), held: BTreeSet::new(), held_msgs: Vec::new(), sent_kinds: BTreeMap::new(), sent_bytes: 0, dialed: Vec::new(), full_passes: false, lose_uploads: BTreeSet::new(), held_servers: BTreeSet::new(), busy: BTreeMap::new(), hub_busy: std::time::Duration::ZERO }
    }

    pub fn now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    pub fn add_server(&mut self) -> usize {
        self.add_server_with(Policy::default())
    }

    pub fn add_server_with(&mut self, policy: Policy) -> usize {
        let i = self.servers.len();
        let backend = MemoryBackend::new();
        let store = BackendStore::open(backend.clone(), self.clock.clone(), policy, &mut SeededRng::from_u64(900 + i as u64)).unwrap();
        let hub = Hub::new(store, server_key(i), Box::new(SeededRng::from_u64(950 + i as u64)));
        self.servers.push(Server { hub, backend, address: Address { url: format!("quic://server{i}:1"), key: server_key(i) }, skew: 0 });
        i
    }

    /// Server `s` loses everything it stored (same key and address).
    pub fn wipe_server(&mut self, s: usize) {
        let backend = MemoryBackend::new();
        let store = BackendStore::open(backend.clone(), self.clock.clone(), Policy::default(), &mut SeededRng::from_u64(990 + s as u64)).unwrap();
        let hub = Hub::new(store, server_key(s), Box::new(SeededRng::from_u64(995 + s as u64)));
        let (address, skew) = (self.servers[s].address.clone(), self.servers[s].skew);
        self.servers[s] = Server { hub, backend, address, skew };
    }

    /// Restarts server `s` over its durable state: its connections are gone, its in-memory
    /// (ephemeral) entries too.
    pub fn restart_server(&mut self, s: usize) {
        let mine: Vec<((usize, ConnId), u64)> = self.links.iter().filter(|(_, (x, _))| *x == s).map(|(k, (_, hc))| (*k, *hc)).collect();
        for ((n, c), _) in mine {
            self.links.remove(&(n, c));
            self.queue.push_back(Msg::Close(n, c));
        }
        let backend = self.servers[s].backend.clone();
        let store = BackendStore::open(backend.clone(), self.clock.clone(), Policy::default(), &mut SeededRng::from_u64(980 + s as u64)).unwrap();
        let hub = Hub::new(store, server_key(s), Box::new(SeededRng::from_u64(985 + s as u64)));
        let (address, skew) = (self.servers[s].address.clone(), self.servers[s].skew);
        self.servers[s] = Server { hub, backend, address, skew };
    }

    /// Server `s`'s wall clock.
    pub fn now_at(&self, s: usize) -> u64 {
        self.now().saturating_add_signed(self.servers[s].skew)
    }

    pub fn address(&self, s: usize) -> Address {
        self.servers[s].address.clone()
    }

    pub fn add_node(&mut self, seed: u64, cfg: SyncConfig) -> usize {
        let cfg = SyncConfig { full_passes: cfg.full_passes || self.full_passes, ..cfg };
        let (backend, root) = (MemoryBackend::new(), MemoryRoot::new());
        let c: Arc<dyn Clock> = self.clock.clone();
        let mut engine = Engine::create(Box::new(backend.clone()), Box::new(root.clone()), Config::default(), c.clone(), Box::new(SeededRng::from_u64(seed))).unwrap();
        // every node knows the test schema (compaction needs it, spec/commits.md §5)
        engine.register_schema(Arc::new(crate::common::TEST.get().clone())).unwrap();
        let sync = SyncEngine::new(engine, c, Box::new(SeededRng::from_u64(seed + 7)), cfg).unwrap();
        self.nodes.push(Node { sync: Some(sync), backend, root, online: true, wake: None });
        self.nodes.len() - 1
    }

    /// A node with the default config syncing with servers `servers`.
    pub fn node(&mut self, seed: u64, servers: &[usize]) -> usize {
        let cfg = SyncConfig { servers: servers.iter().map(|s| self.address(*s)).collect(), ..SyncConfig::default() };
        self.add_node(seed, cfg)
    }

    /// Takes node `n`'s sync engine out (to run it under a driver).
    pub fn take(&mut self, n: usize) -> SyncEngine {
        self.nodes[n].online = false;
        self.nodes[n].sync.take().unwrap()
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
        let peers: Vec<((usize, ConnId), (usize, ConnId))> = self.plinks.iter().filter(|((x, _), _)| *x == n).map(|(k, v)| (*k, *v)).collect();
        for ((_, c), (m, pc)) in peers {
            self.plinks.remove(&(n, c));
            self.plinks.remove(&(m, pc));
            self.queue.push_back(Msg::Close(m, pc));
            if let Some(sy) = self.nodes[n].sync.as_mut() {
                sy.handle(Event::Down { conn: c });
            }
        }
        let servers: Vec<usize> = self.links.iter().filter(|((x, _), _)| *x == n).map(|(_, (s, _))| *s).collect();
        for s in servers {
            self.drop_link(n, s);
        }
    }

    /// Closes node `n`'s connection to server `s` on both sides; what `s` held back for it is
    /// dropped.
    pub fn drop_link(&mut self, n: usize, s: usize) {
        let mine: Vec<(ConnId, u64)> = self.links.iter().filter(|((x, _), (y, _))| *x == n && *y == s).map(|((_, c), (_, hc))| (*c, *hc)).collect();
        for (c, hc) in mine {
            self.links.remove(&(n, c));
            self.held_msgs.retain(|m| !matches!(m, Msg::ToNode(x, y, _) if *x == n && *y == c));
            let now = self.now_at(s);
            let out = self.servers[s].hub.closed(now, hc);
            self.hub_out(s, out);
            if let Some(sy) = self.nodes[n].sync.as_mut() {
                sy.handle(Event::Down { conn: c });
            }
        }
    }

    /// Node `n` drops off the network without its servers noticing (a crash behind a half-open
    /// connection): its links go, the hubs keep their side open; the node is offline.
    pub fn vanish(&mut self, n: usize) {
        self.links.retain(|(x, _), _| *x != n);
        self.nodes[n].online = false;
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
        let t = std::time::Instant::now();
        let acts = self.sync(n).handle(ev);
        *self.busy.entry(n).or_default() += t.elapsed();
        self.actions(n, acts);
    }

    pub fn actions(&mut self, n: usize, acts: Vec<Action>) {
        for a in acts {
            if std::env::var_os("OSIS_SYNC_TRACE").is_some() {
                eprintln!("node {n} action {}", format!("{a:?}").chars().take(120).collect::<String>());
            }
            if let Action::Dial { address, .. } = &a {
                self.dialed.push((n, address.clone()));
            }
            match a {
                Action::Dial { conn, address } if address.url.starts_with("peer://") => {
                    // by dialable key, or by a LAN transport key a node listens with
                    let lan = self.lan_keys.get(&address.key).copied();
                    let target = lan.filter(|m| self.nodes[*m].online).or_else(|| (0..self.nodes.len()).find(|m| *m != n && self.nodes[*m].online && self.nodes[*m].sync.as_mut().and_then(|s| s.own_reach()).is_some_and(|r| r.dialable == address.key)));
                    let Some(m) = target.filter(|m| !self.blocked_peers.contains(&(n, *m)) && !self.blocked_peers.contains(&(*m, n))) else {
                        self.queue.push_back(Msg::Close(n, conn));
                        continue;
                    };
                    let (pc, acts) = self.sync(m).accept(address.key, [0xd0 + n as u8; 32]);
                    self.plinks.insert((n, conn), (m, pc));
                    self.plinks.insert((m, pc), (n, conn));
                    self.queue.push_back(Msg::Up(n, conn));
                    self.actions(m, acts);
                }
                Action::Dial { conn, address } => {
                    let Some(s) = self.servers.iter().position(|x| x.address.key == address.key).filter(|s| !self.blocked.contains(&(n, *s))) else {
                        self.queue.push_back(Msg::Close(n, conn));
                        continue;
                    };
                    let hc = self.next_hub_conn;
                    self.next_hub_conn += 1;
                    self.links.insert((n, conn), (s, hc));
                    self.queue.push_back(Msg::Up(n, conn));
                    let now = self.now_at(s);
                    let out = self.servers[s].hub.accept(now, hc, [0xe0; 32]);
                    self.hub_out(s, out);
                }
                Action::Send { conn, bytes } if self.plinks.contains_key(&(n, conn)) => {
                    let (m, pc) = self.plinks[&(n, conn)];
                    if self.held.contains(&(n, m)) {
                        self.held_msgs.push(Msg::ToNode(m, pc, bytes));
                    } else {
                        self.queue.push_back(Msg::ToNode(m, pc, bytes));
                    }
                }
                Action::Close { conn } if self.plinks.contains_key(&(n, conn)) => {
                    let (m, pc) = self.plinks.remove(&(n, conn)).unwrap();
                    self.plinks.remove(&(m, pc));
                    self.queue.push_back(Msg::Close(m, pc));
                }
                Action::Send { conn, mut bytes } => {
                    self.sent_bytes += bytes.len();
                    let mut d = osis_proto::FrameDecoder::new();
                    d.push(&bytes);
                    let mut kept = Vec::new();
                    while let Ok(Some(body)) = d.next_frame() {
                        if let Ok(m) = osis_proto::Message::decode(&body) {
                            *self.sent_kinds.entry(m.kind()).or_default() += 1;
                            if self.lose_uploads.contains(&n) && matches!(m, osis_proto::Message::Upload { .. }) {
                                continue;
                            }
                        }
                        kept.extend(osis_proto::encode_frame(&body));
                    }
                    if self.lose_uploads.contains(&n) {
                        bytes = kept;
                    }
                    if let Some((s, hc)) = self.links.get(&(n, conn)).copied() {
                        self.queue.push_back(Msg::ToHub(s, hc as ConnId, bytes));
                    }
                }
                Action::Close { conn } => {
                    if let Some((s, hc)) = self.links.remove(&(n, conn)) {
                        let now = self.now_at(s);
                        let out = self.servers[s].hub.closed(now, hc);
                        self.hub_out(s, out);
                    }
                }
                Action::Wake { at } => self.nodes[n].wake = Some(at),
                // peers are found by their current `/reach`
                Action::Reach => {}
            }
        }
    }

    fn hub_out(&mut self, s: usize, out: Vec<HubOutput>) {
        for o in out {
            match o {
                HubOutput::Send(hc, bytes) => {
                    if let Some(((n, c), _)) = self.links.iter().find(|(_, (x, h))| *x == s && *h == hc) {
                        let m = Msg::ToNode(*n, *c, bytes);
                        if self.held_servers.contains(&s) {
                            self.held_msgs.push(m);
                        } else {
                            self.queue.push_back(m);
                        }
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

    /// Delivers the peer and server bytes held back (`held` and `held_servers` are cleared).
    pub fn release(&mut self) {
        self.held.clear();
        self.held_servers.clear();
        self.queue.extend(self.held_msgs.drain(..));
    }

    /// Delivers queued messages until none are left (at most `max`).
    pub fn settle(&mut self, max: usize) {
        let mut i = 0;
        while let Some(m) = self.queue.pop_front() {
            i += 1;
            self.steps += 1;
            assert!(i < max, "no quiescence after {max} messages");
            self.deliver(m);
        }
    }

    /// Delivers the messages queued now; what they cause waits for the next round (one hop of
    /// latency per round).
    pub fn round(&mut self) {
        let n = self.queue.len();
        for _ in 0..n {
            let Some(m) = self.queue.pop_front() else { break };
            self.steps += 1;
            self.deliver(m);
        }
    }

    fn deliver(&mut self, m: Msg) {
        match m {
            Msg::Up(n, c) => self.feed(n, Event::Up { conn: c }),
            Msg::ToHub(s, hc, b) => {
                let now = self.now_at(s);
                let t = std::time::Instant::now();
                let out = self.servers[s].hub.input(now, hc, b);
                self.hub_busy += t.elapsed();
                self.hub_out(s, out);
            }
            Msg::ToNode(n, c, b) => self.feed(n, Event::Bytes { conn: c, bytes: b }),
            Msg::Close(n, c) => self.feed(n, Event::Down { conn: c }),
        }
        for s in 0..self.servers.len() {
            let now = self.now_at(s);
            if self.servers[s].hub.next_due(now).is_some_and(|t| t <= now) {
                let out = self.servers[s].hub.tick(now);
                self.hub_out(s, out);
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
        for s in 0..self.servers.len() {
            let now = self.now_at(s);
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
        let addrs: Vec<Address> = servers.iter().map(|s| self.servers[*s].address.clone()).collect();
        self.group_at(admin, members, addrs)
    }

    /// `group` with server addresses.
    pub fn group_at(&mut self, admin: usize, members: &[(usize, Role)], addrs: Vec<Address>) -> Tid {
        self.group_seeded(admin, members, addrs, 1)
    }

    /// `group_at` with the rotation's rng seed: groups of one admin need distinct seeds, or they
    /// get equal secrets and so one label ID.
    pub fn group_seeded(&mut self, admin: usize, members: &[(usize, Role)], addrs: Vec<Address>, rng: u64) -> Tid {
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
        rotation(e, g, &recipients, rng, true);
        self.engine(admin).create_label(&g, &addrs).unwrap();
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

    /// Node `n` writes `v` to the ephemeral (or presence, signal) key `key` of `t`, then lets
    /// its sync engine see it.
    pub fn eph_write(&mut self, n: usize, t: Tid, key: &osis_schema::Untyped, v: Value) {
        let mut m = Mutation::new();
        m.set(t, key, &v).unwrap();
        self.engine(n).write(m).unwrap();
        let acts = self.sync(n).handle(Event::Local);
        self.actions(n, acts);
    }

    /// Node `n`'s value of ephemeral (or any) aspect `ak` of `t`.
    pub fn eph_read(&mut self, n: usize, t: Tid, ak: &str) -> Option<Value> {
        let ak = osis_base::Ak::new(ak).unwrap();
        self.engine(n).get(&t, &ak).unwrap()
    }

    /// The engine events node `n` sends from now on.
    pub fn listen(&mut self, n: usize) -> std::sync::mpsc::Receiver<osis_node::Event> {
        self.engine(n).subscribe()
    }

    pub fn read(&mut self, n: usize, t: Tid) -> Option<Value> {
        let ak = osis_base::Ak::new(REG.ak()).unwrap();
        self.engine(n).get(&t, &ak).unwrap()
    }

    /// The registration path a server holds for a label.
    pub fn server_path(&self, s: usize, l: &osis_base::LabelId) -> Vec<osis_label::Step> {
        self.servers[s].hub.store().path(l).unwrap()
    }

    /// The first label node `n` syncs.
    pub fn label(&mut self, n: usize) -> osis_base::LabelId {
        self.sync(n).labels().into_iter().next().unwrap().1.id
    }

    /// Live entry IDs the server holds under a label.
    pub fn server_ids(&self, s: usize, l: &osis_base::LabelId) -> Vec<osis_base::BlobId> {
        self.servers[s].hub.store().live_ids(l).unwrap()
    }

    /// Node `n`'s connection to server `s`, if up (to inject a hostile server's frames).
    pub fn conn_to(&self, n: usize, s: usize) -> Option<ConnId> {
        self.links.iter().find(|((x, _), (y, _))| *x == n && *y == s).map(|((_, c), _)| *c)
    }

    pub fn labels_at(&self, s: usize) -> Vec<osis_base::LabelId> {
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
aspect /t/blob: blob;
aspect /t/big: map<string, string>;
aspect /t/gonemap: map<string, string> [by: writer, keep_at_most: 0s];
aspect /t/shortmap: map<string, string> [by: writer, keep_at_most: 10m];
aspect /t/gonetext: text [by: writer, keep_at_most: 0s];
aspect /t/briefmap: map<string, string> [expires: 1h];
"#,
);

pub const REG: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/t/reg", &TEST);
pub const GONE: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/t/gone", &TEST);
pub const BRIEF: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/t/brief", &TEST);
pub const BLOB: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/t/blob", &TEST);
pub const BIG: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/t/big", &TEST);
pub const GONEMAP: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/t/gonemap", &TEST);
pub const SHORTMAP: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/t/shortmap", &TEST);
pub const GONETEXT: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/t/gonetext", &TEST);
pub const BRIEFMAP: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/t/briefmap", &TEST);

/// The signal parts fired among the events received so far: (thing, aspect, value, origin).
pub fn fired(rx: &std::sync::mpsc::Receiver<osis_node::Event>) -> Vec<(Tid, String, Value, osis_node::Origin)> {
    let mut out = Vec::new();
    while let Ok(e) = rx.try_recv() {
        if let osis_node::Event::Ephemeral { signals, origin, .. } = e {
            out.extend(signals.into_iter().map(|(t, ak, v)| (t, ak.as_str().to_string(), v, origin)));
        }
    }
    out
}

/// An untyped key of `ak` with the given lifetime.
pub fn ukey(ak: &str, l: osis_schema::Lifetime) -> osis_schema::Untyped {
    osis_schema::Untyped::new(osis_base::Ak::new(ak).unwrap(), l)
}

pub fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn recipient(e: &mut Engine, t: Tid, role: Role) -> Recipient {
    if t == e.tid() {
        return Recipient { member: t, role, keys: MemberKeys::KeyActor { kem: e.identity().keys().kem.public().clone(), seed: None } };
    }
    let k = e.get_typed(&t, &ct::KEYS).unwrap().unwrap();
    let mut keys = MemberKeys::from_keys(&k).unwrap();
    if let Some(own) = e.epochs(&t).filter(|_| matches!(keys, MemberKeys::Actor { .. })) {
        keys = keys.with_own(&own);
    }
    Recipient { member: t, role, keys }
}

pub fn set_edge(e: &mut Engine, thing: Tid, member: Tid, role: Role) -> CommitId {
    let mut m = Mutation::new();
    let edge = ct::Edge { role, until: None, invite: None, since: None };
    // remove + put (spec/permissions.md §2)
    m.op(thing, &ct::MEMBERS, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(member)) }).unwrap();
    m.op(thing, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(member))], op: Op::Set(edge.to_value()) }).unwrap();
    e.commit(m).unwrap().unwrap()
}

/// A rotation of every role of `a` boxing `recipients`, with a deposit seed when `seed`.
pub fn rotation(e: &mut Engine, a: Tid, recipients: &[Recipient], rng: u64, seed: bool) -> CommitId {
    let mut m = Mutation::new();
    rotation_ops(e, &mut m, a, recipients, rng, seed);
    e.commit(m).unwrap().unwrap()
}

/// Removes `member` from `a` with the rotation boxing `recipients`, in one membership commit
/// (spec/permissions.md §3).
pub fn remove_member(e: &mut Engine, a: Tid, member: Tid, recipients: &[Recipient], rng: u64) -> CommitId {
    let mut m = Mutation::new();
    m.op(a, &ct::MEMBERS, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(member)) }).unwrap();
    rotation_ops(e, &mut m, a, recipients, rng, false);
    e.commit(m).unwrap().unwrap()
}

fn rotation_ops(e: &mut Engine, m: &mut Mutation, a: Tid, recipients: &[Recipient], rng: u64, seed: bool) {
    let roles = BTreeSet::from([Role::Read, Role::Write, Role::Admin]);
    let view = e.epochs(&a).unwrap();
    let state = e.get_typed(&a, &ct::SECRETS).unwrap().unwrap_or_default();
    let r = rotate(&a, &roles, &view, &state, recipients, &|_, _| true, &mut SeededRng::from_u64(rng)).unwrap();
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
}

pub fn recipients_of(e: &mut Engine, members: &[(Tid, Role)]) -> Vec<Recipient> {
    members.iter().map(|(t, r)| recipient(e, *t, *r)).collect()
}

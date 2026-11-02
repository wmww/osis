#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, dead_code)]
//! Sync engines and hosts in process, no tokio: `SyncEngine`s exchanging bytes with
//! osis-host `Hub`s over in-memory queues, one manual clock. Group setup stands in for pairing
//! (direct delivery of the setup commits).

use osis_base::{Clock, CommitId, ManualClock, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::SeededRng;
use osis_keys::{HolderKeys, Recipient, rotate};
use osis_label::Address;
use osis_node::sync::{Action, ConnId, Event, SyncConfig, SyncEngine};
use osis_node::{Config, Engine, Mutation};
use osis_schema::core_types as ct;
use osis_schema::{AspectKey, Codec};
use osis_proto::LabelStore;
use osis_host::{HostStore, Hub, HubOutput, HostPolicy};
use osis_store::{MemoryBackend, MemoryRoot, Store, StoreConfig};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::mpsc::Receiver;

pub const T0: u64 = 1_700_000_000_000;

pub struct Host {
    pub hub: Hub,
    /// Its own store's device.
    pub backend: MemoryBackend,
    pub root: MemoryRoot,
    pub address: Address,
    /// Added to the wall clock this host reports (handshakes, pongs) and acts on.
    pub skew: i64,
}

pub struct Node {
    pub sync: Option<SyncEngine>,
    pub backend: MemoryBackend,
    pub root: MemoryRoot,
    pub online: bool,
    pub wake: Option<u64>,
    /// Restarts so far (`Msg`).
    pub life: u64,
    /// Its user accepts every invite request (spec/sync.md §3) as it appears (default).
    pub accepts: bool,
    /// Its engine's durable events, for `diagnostics`.
    events: Receiver<osis_node::Event>,
}

/// Messages to a node carry its `life` when sent: one sent before it restarted is dropped (it
/// numbers connections from 1 again, so the old connection's bytes would land on a new one).
enum Msg {
    /// node, life, conn -> hub
    Up(usize, u64, ConnId),
    ToHub(usize, ConnId, Vec<u8>),
    ToNode(usize, u64, ConnId, Vec<u8>),
    Close(usize, u64, ConnId),
}

pub struct Net {
    pub clock: Arc<ManualClock>,
    pub nodes: Vec<Node>,
    pub hosts: Vec<Host>,
    /// (node, conn) -> (host, hub conn)
    links: BTreeMap<(usize, ConnId), (usize, u64)>,
    queue: VecDeque<Msg>,
    next_hub_conn: u64,
    pub steps: usize,
    /// (node, host) pairs that cannot connect.
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
    /// Message kinds nodes sent to hosts, by kind.
    pub sent_kinds: BTreeMap<u64, usize>,
    /// Bytes nodes sent to hosts.
    pub sent_bytes: usize,
    /// Every dial: (node, address).
    pub dialed: Vec<(usize, Address)>,
    /// Nodes added from now on judge everything at every pass (`SyncConfig::full_passes`).
    pub full_passes: bool,
    /// Nodes whose Upload requests to hosts are lost on the way (answered rate-limited for
    /// the host: a request is never left unanswered on an ordered stream).
    pub lose_uploads: BTreeSet<usize>,
    /// Deposits of these blobs to a peer are lost on the way (answered rate-limited).
    pub lose_deposits: BTreeSet<osis_base::BlobId>,
    /// Hosts whose messages to nodes are held back until `release` (a slow host).
    pub held_hosts: BTreeSet<usize>,
    /// Time spent in each node's `handle` and in the hubs (scale tests).
    pub busy: BTreeMap<usize, std::time::Duration>,
    pub hub_busy: std::time::Duration,
    /// Per watched node, the blob IDs hosts announced or sent it (pushes, sync and fetch
    /// replies).
    pub told: BTreeMap<usize, BTreeSet<osis_base::BlobId>>,
    /// Per watched node, every blob a host's fetch reply carried it, in order.
    pub fetched: BTreeMap<usize, Vec<osis_base::BlobId>>,
    /// Nodes that take nothing from hosts (bytes dropped, connections kept): a node that
    /// ignores what it is sent.
    pub deaf: BTreeSet<usize>,
    /// Nodes whose host bytes are held back (until `release`) from the first Opened reply
    /// on: an open answered, nothing after it delivered yet.
    pub hold_opened: BTreeSet<usize>,
    /// Nodes whose host bytes are held back until `release` (a node reading nothing for a while).
    pub held_to: BTreeSet<usize>,
    /// Per node, the `gained` lists of the Syncs it sent to hosts (non-empty ones).
    pub gained: BTreeMap<usize, Vec<Vec<osis_base::BlobId>>>,
    /// Host messages announcing or carrying one of these blobs are held back until `release`
    /// (a slow fetch of one entry).
    pub hold_blobs: BTreeSet<osis_base::BlobId>,
    /// Per node, blobs whose announcements and fetch replies hosts never deliver to it (the
    /// rest of each message is): a node that never hears of one entry.
    pub hide_blobs: BTreeMap<usize, BTreeSet<osis_base::BlobId>>,
}

/// Whether whole frames `b` hold an Opened reply.
fn has_opened(b: &[u8]) -> bool {
    let mut d = osis_proto::FrameDecoder::new();
    d.push(b);
    while let Ok(Some(body)) = d.next_frame() {
        if matches!(osis_proto::Message::decode(&body), Ok(osis_proto::Message::Opened { .. })) {
            return true;
        }
    }
    false
}

/// Blob IDs whole frames `b` from a host announce or carry.
fn told_ids(b: &[u8]) -> Vec<osis_base::BlobId> {
    use osis_proto::{Event as E, Message as M};
    let mut d = osis_proto::FrameDecoder::new();
    d.push(b);
    let mut v = Vec::new();
    while let Ok(Some(body)) = d.next_frame() {
        match osis_proto::Message::decode(&body) {
            Ok(M::Push { events, .. } | M::SyncReply { events, .. }) => v.extend(events.iter().filter_map(|e| if let E::Added { blob_id, .. } = e { Some(*blob_id) } else { None })),
            Ok(M::FetchReply { items, .. }) => v.extend(items.iter().filter(|i| i.entry.is_some()).map(|i| i.blob_id)),
            _ => {}
        }
    }
    v
}

/// Whole frames `b` from a host with every announcement and fetch reply item of a blob in
/// `hide` left out.
fn without_blobs(b: &[u8], hide: &BTreeSet<osis_base::BlobId>) -> Vec<u8> {
    use osis_proto::{Event as E, Message as M};
    let mut d = osis_proto::FrameDecoder::new();
    d.push(b);
    let mut out = Vec::new();
    while let Ok(Some(body)) = d.next_frame() {
        match osis_proto::Message::decode(&body) {
            Ok(mut m) => {
                match &mut m {
                    M::Push { events, .. } | M::SyncReply { events, .. } => events.retain(|e| !matches!(e, E::Added { blob_id, .. } if hide.contains(blob_id))),
                    M::FetchReply { items, .. } => items.retain(|i| !hide.contains(&i.blob_id)),
                    _ => {}
                }
                out.extend(osis_proto::encode_frame(&m.encode()));
            }
            Err(_) => out.extend(osis_proto::encode_frame(&body)),
        }
    }
    out
}

/// Blob IDs whole frames `b` from a host carry in fetch replies.
fn fetched_ids(b: &[u8]) -> Vec<osis_base::BlobId> {
    let mut d = osis_proto::FrameDecoder::new();
    d.push(b);
    let mut v = Vec::new();
    while let Ok(Some(body)) = d.next_frame() {
        if let Ok(osis_proto::Message::FetchReply { items, .. }) = osis_proto::Message::decode(&body) {
            v.extend(items.iter().filter(|i| i.entry.is_some()).map(|i| i.blob_id));
        }
    }
    v
}

pub fn host_key(i: usize) -> [u8; 32] {
    [0x50 + i as u8; 32]
}

impl Net {
    pub fn new() -> Net {
        Net { clock: Arc::new(ManualClock::new(WallMs(T0))), nodes: vec![], hosts: vec![], links: BTreeMap::new(), queue: VecDeque::new(), next_hub_conn: 1, steps: 0, blocked: BTreeSet::new(), plinks: BTreeMap::new(), blocked_peers: BTreeSet::new(), lan_keys: BTreeMap::new(), held: BTreeSet::new(), held_msgs: Vec::new(), sent_kinds: BTreeMap::new(), sent_bytes: 0, dialed: Vec::new(), full_passes: false, lose_uploads: BTreeSet::new(), lose_deposits: BTreeSet::new(), held_hosts: BTreeSet::new(), busy: BTreeMap::new(), hub_busy: std::time::Duration::ZERO, told: BTreeMap::new(), fetched: BTreeMap::new(), deaf: BTreeSet::new(), hold_opened: BTreeSet::new(), held_to: BTreeSet::new(), gained: BTreeMap::new(), hold_blobs: BTreeSet::new(), hide_blobs: BTreeMap::new() }
    }

    pub fn now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    pub fn add_host(&mut self) -> usize {
        self.add_host_with(HostPolicy::default())
    }

    pub fn add_host_with(&mut self, policy: HostPolicy) -> usize {
        let i = self.hosts.len();
        let (backend, root) = (MemoryBackend::new(), MemoryRoot::new());
        let store = self.host_store(&backend, &root, policy, 900 + i as u64);
        let hub = Hub::new(store, host_key(i), Box::new(SeededRng::from_u64(950 + i as u64)));
        self.hosts.push(Host { hub, backend, root, address: Address { url: format!("quic://host{i}:1"), key: host_key(i) }, skew: 0 });
        i
    }

    /// A host store over `backend` and `root` (created on first use).
    fn host_store(&self, backend: &MemoryBackend, root: &MemoryRoot, policy: HostPolicy, seed: u64) -> HostStore {
        let store = Store::open_or_create(Box::new(backend.clone()), Box::new(root.clone()), StoreConfig::default(), &mut SeededRng::from_u64(seed)).unwrap();
        HostStore::open(store, self.clock.clone(), policy, Box::new(SeededRng::from_u64(seed ^ 0x570e))).unwrap()
    }

    /// Host `s` loses everything it stored (same key and address).
    pub fn wipe_host(&mut self, s: usize) {
        let (backend, root) = (MemoryBackend::new(), MemoryRoot::new());
        let store = self.host_store(&backend, &root, HostPolicy::default(), 990 + s as u64);
        let hub = Hub::new(store, host_key(s), Box::new(SeededRng::from_u64(995 + s as u64)));
        let (address, skew) = (self.hosts[s].address.clone(), self.hosts[s].skew);
        self.hosts[s] = Host { hub, backend, root, address, skew };
    }

    /// Restarts host `s` over its durable state: its connections are gone, its in-memory
    /// (ephemeral) entries too.
    pub fn restart_host(&mut self, s: usize) {
        self.restart_host_with(s, HostPolicy::default());
    }

    /// `restart_host` with another policy.
    pub fn restart_host_with(&mut self, s: usize, policy: HostPolicy) {
        let mine: Vec<((usize, ConnId), u64)> = self.links.iter().filter(|(_, (x, _))| *x == s).map(|(k, (_, hc))| (*k, *hc)).collect();
        for ((n, c), _) in mine {
            self.links.remove(&(n, c));
            self.queue.push_back(Msg::Close(n, self.nodes[n].life, c));
        }
        let (backend, root) = (self.hosts[s].backend.clone(), self.hosts[s].root.clone());
        let store = self.host_store(&backend, &root, policy, 980 + s as u64);
        let hub = Hub::new(store, host_key(s), Box::new(SeededRng::from_u64(985 + s as u64)));
        let (address, skew) = (self.hosts[s].address.clone(), self.hosts[s].skew);
        self.hosts[s] = Host { hub, backend, root, address, skew };
    }

    /// Host `s`'s wall clock.
    pub fn now_at(&self, s: usize) -> u64 {
        self.now().saturating_add_signed(self.hosts[s].skew)
    }

    pub fn address(&self, s: usize) -> Address {
        self.hosts[s].address.clone()
    }

    pub fn add_node(&mut self, seed: u64, cfg: SyncConfig) -> usize {
        self.add_node_on(seed, cfg, MemoryBackend::new(), MemoryRoot::new(), Config::default())
    }

    /// A node for forensic checks: every row and blob it writes recorded, a small key tree and
    /// pages (a shred elsewhere does not incidentally rotate a leaked copy away); `faults` on
    /// its device.
    pub fn forensic_node(&mut self, seed: u64, hosts: &[usize], faults: &osis_store::Faults) -> usize {
        let backend = MemoryBackend::with_faults(faults.clone());
        backend.record_history();
        let cfg = SyncConfig { hosts: hosts.iter().map(|s| self.address(*s)).collect(), ..SyncConfig::default() };
        let store = StoreConfig { arity: 4, depth: 8, page_max: 512, ..StoreConfig::default() };
        self.add_node_on(seed, cfg, backend, MemoryRoot::with_faults(faults.clone()), Config { store, ..Config::default() })
    }

    /// Where an attacker holding node `n`'s device recovers `marker` (`Engine::forensic`; the
    /// node must record, `forensic_node`).
    pub fn forensic(&mut self, n: usize, marker: &[u8]) -> Vec<osis_store::Source> {
        let backend = self.nodes[n].backend.clone();
        let found = self.engine(n).forensic(&backend).unwrap();
        found.into_iter().filter(|r| r.plain.windows(marker.len()).any(|w| w == marker)).map(|r| r.from).collect()
    }

    fn add_node_on(&mut self, seed: u64, cfg: SyncConfig, backend: MemoryBackend, root: MemoryRoot, engine_cfg: Config) -> usize {
        let cfg = SyncConfig { full_passes: cfg.full_passes || self.full_passes, ..cfg };
        let c: Arc<dyn Clock> = self.clock.clone();
        let engine = Engine::create(Box::new(backend.clone()), Box::new(root.clone()), engine_cfg, c.clone(), Box::new(SeededRng::from_u64(seed))).unwrap();
        let mut sync = SyncEngine::new(engine, c, Box::new(SeededRng::from_u64(seed + 7)), cfg).unwrap();
        let events = sync.engine_mut().subscribe_durable();
        self.nodes.push(Node { sync: Some(sync), backend, root, online: true, wake: None, life: 0, accepts: true, events });
        self.nodes.len() - 1
    }

    /// A node with the default config syncing with hosts `hosts`.
    pub fn node(&mut self, seed: u64, hosts: &[usize]) -> usize {
        let cfg = SyncConfig { hosts: hosts.iter().map(|s| self.address(*s)).collect(), ..SyncConfig::default() };
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
        node.life += 1;
        let engine = Engine::open(Box::new(node.backend.clone()), Box::new(node.root.clone()), Config::default(), c.clone(), Box::new(SeededRng::from_u64(seed))).unwrap();
        let mut sync = SyncEngine::new(engine, c, Box::new(SeededRng::from_u64(seed + 7)), cfg).unwrap();
        node.events = sync.engine_mut().subscribe_durable();
        node.sync = Some(sync);
    }

    /// Node `n`'s diagnostics since the last call: the sync engine's and the engine's (refusals
    /// that change nothing a test reads, e.g. an ephemeral commit past its room).
    pub fn diagnostics(&mut self, n: usize) -> Vec<String> {
        let mut out = self.sync(n).take_diagnostics();
        for e in self.nodes[n].events.try_iter() {
            if let osis_node::Event::Diagnostic(d) = e
                && !out.contains(&d.detail)
            {
                out.push(format!("{:?}: {}", d.kind, d.detail));
            }
        }
        out
    }

    /// Prints the diagnostics of `nodes` (stderr, shown when a test fails).
    pub fn trace(&mut self, nodes: &[usize]) {
        for n in nodes {
            let d = self.diagnostics(*n);
            if !d.is_empty() {
                eprintln!("node {n}: {d:?}");
            }
        }
    }

    fn disconnect(&mut self, n: usize) {
        let peers: Vec<((usize, ConnId), (usize, ConnId))> = self.plinks.iter().filter(|((x, _), _)| *x == n).map(|(k, v)| (*k, *v)).collect();
        for ((_, c), (m, pc)) in peers {
            self.plinks.remove(&(n, c));
            self.plinks.remove(&(m, pc));
            self.queue.push_back(Msg::Close(m, self.nodes[m].life, pc));
            self.forget_conn(n, c);
            if let Some(sy) = self.nodes[n].sync.as_mut() {
                sy.handle(Event::Down { conn: c });
            }
        }
        let hosts: Vec<usize> = self.links.iter().filter(|((x, _), _)| *x == n).map(|(_, (s, _))| *s).collect();
        for s in hosts {
            self.drop_link(n, s);
        }
    }

    /// Nothing more reaches node `n` on its closed connection `c`, queued or held back.
    fn forget_conn(&mut self, n: usize, c: ConnId) {
        let to = |m: &Msg| matches!(m, Msg::Up(x, _, y) | Msg::ToNode(x, _, y, _) | Msg::Close(x, _, y) if *x == n && *y == c);
        self.queue.retain(|m| !to(m));
        self.held_msgs.retain(|m| !to(m));
    }

    /// Closes node `n`'s connection to host `s` on both sides; what `s` held back for it is
    /// dropped.
    pub fn drop_link(&mut self, n: usize, s: usize) {
        let mine: Vec<(ConnId, u64)> = self.links.iter().filter(|((x, _), (y, _))| *x == n && *y == s).map(|((_, c), (_, hc))| (*c, *hc)).collect();
        for (c, hc) in mine {
            self.links.remove(&(n, c));
            self.forget_conn(n, c);
            let out = self.hosts[s].hub.closed(hc);
            self.hub_out(s, out);
            if let Some(sy) = self.nodes[n].sync.as_mut() {
                sy.handle(Event::Down { conn: c });
            }
        }
    }

    /// Node `n` drops off the network without its hosts noticing (a crash behind a half-open
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
        let mut acts = self.sync(n).handle(ev);
        if self.nodes[n].accepts {
            acts.extend(self.accept_invites(n));
        }
        *self.busy.entry(n).or_default() += t.elapsed();
        self.actions(n, acts);
    }

    /// Node `n`'s user accepts every waiting invite request.
    pub fn accept_invites(&mut self, n: usize) -> Vec<Action> {
        let mut acts = Vec::new();
        for r in self.sync(n).invite_requests().unwrap() {
            acts.extend(self.sync(n).accept_invite(r).unwrap().1);
        }
        acts
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
                        self.queue.push_back(Msg::Close(n, self.nodes[n].life, conn));
                        continue;
                    };
                    let (pc, acts) = self.sync(m).accept(address.key, [0xd0 + n as u8; 32]);
                    self.plinks.insert((n, conn), (m, pc));
                    self.plinks.insert((m, pc), (n, conn));
                    self.queue.push_back(Msg::Up(n, self.nodes[n].life, conn));
                    self.actions(m, acts);
                }
                Action::Dial { conn, address } => {
                    let Some(s) = self.hosts.iter().position(|x| x.address.key == address.key).filter(|s| !self.blocked.contains(&(n, *s))) else {
                        self.queue.push_back(Msg::Close(n, self.nodes[n].life, conn));
                        continue;
                    };
                    let hc = self.next_hub_conn;
                    self.next_hub_conn += 1;
                    self.links.insert((n, conn), (s, hc));
                    self.queue.push_back(Msg::Up(n, self.nodes[n].life, conn));
                    let now = self.now_at(s);
                    let out = self.hosts[s].hub.accept(now, hc, [0xe0; 32]);
                    self.hub_out(s, out);
                }
                Action::Send { conn, mut bytes } if self.plinks.contains_key(&(n, conn)) => {
                    let (m, pc) = self.plinks[&(n, conn)];
                    if !self.lose_deposits.is_empty() {
                        let mut d = osis_proto::FrameDecoder::new();
                        d.push(&bytes);
                        let mut kept = Vec::new();
                        while let Ok(Some(body)) = d.next_frame() {
                            if let Ok(osis_proto::Message::Deposit { id, blob, .. }) = osis_proto::Message::decode(&body)
                                && self.lose_deposits.contains(&osis_label::blob_id(&blob))
                            {
                                let e = osis_proto::Message::Error { id, code: osis_proto::Code::RATE_LIMITED };
                                self.queue.push_back(Msg::ToNode(n, self.nodes[n].life, conn, osis_proto::encode_frame(&e.encode())));
                                continue;
                            }
                            kept.extend(osis_proto::encode_frame(&body));
                        }
                        bytes = kept;
                    }
                    if self.held.contains(&(n, m)) {
                        self.held_msgs.push(Msg::ToNode(m, self.nodes[m].life, pc, bytes));
                    } else {
                        self.queue.push_back(Msg::ToNode(m, self.nodes[m].life, pc, bytes));
                    }
                }
                Action::Close { conn } if self.plinks.contains_key(&(n, conn)) => {
                    let (m, pc) = self.plinks.remove(&(n, conn)).unwrap();
                    self.plinks.remove(&(m, pc));
                    self.queue.push_back(Msg::Close(m, self.nodes[m].life, pc));
                }
                Action::Send { conn, mut bytes } => {
                    self.sent_bytes += bytes.len();
                    let mut d = osis_proto::FrameDecoder::new();
                    d.push(&bytes);
                    let mut kept = Vec::new();
                    while let Ok(Some(body)) = d.next_frame() {
                        if let Ok(m) = osis_proto::Message::decode(&body) {
                            *self.sent_kinds.entry(m.kind()).or_default() += 1;
                            if let osis_proto::Message::Sync { gained, .. } = &m
                                && !gained.is_empty()
                            {
                                self.gained.entry(n).or_default().push(gained.clone());
                            }
                            if self.lose_uploads.contains(&n)
                                && let osis_proto::Message::Upload { id, .. } = m
                            {
                                let e = osis_proto::Message::Error { id, code: osis_proto::Code::RATE_LIMITED };
                                self.queue.push_back(Msg::ToNode(n, self.nodes[n].life, conn, osis_proto::encode_frame(&e.encode())));
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
                        let out = self.hosts[s].hub.closed(hc);
                        self.hub_out(s, out);
                    }
                }
                Action::Wake { at } => self.nodes[n].wake = Some(at),
                // peers are found by their current `reach.0`
                Action::Reach | Action::Host(_) | Action::Request { .. } | Action::Room { .. } | Action::Ended { .. } | Action::Authed { .. } => {}
            }
        }
    }

    fn hub_out(&mut self, s: usize, out: Vec<HubOutput>) {
        for o in out {
            match o {
                HubOutput::Send(hc, bytes) => {
                    if let Some(((n, c), _)) = self.links.iter().find(|(_, (x, h))| *x == s && *h == hc) {
                        let bytes = match self.hide_blobs.get(n) {
                            Some(hide) => without_blobs(&bytes, hide),
                            None => bytes,
                        };
                        let held = self.held_to.contains(n) || self.hold_opened.contains(n) && (has_opened(&bytes) || self.held_msgs.iter().any(|m| matches!(m, Msg::ToNode(x, ..) if x == n))) || (!self.hold_blobs.is_empty() && told_ids(&bytes).iter().any(|b| self.hold_blobs.contains(b)));
                        let m = Msg::ToNode(*n, self.nodes[*n].life, *c, bytes);
                        if self.held_hosts.contains(&s) || held {
                            self.held_msgs.push(m);
                        } else {
                            self.queue.push_back(m);
                        }
                    }
                }
                HubOutput::Close(hc) => {
                    if let Some(((n, c), _)) = self.links.iter().find(|(_, (x, h))| *x == s && *h == hc).map(|(k, v)| (*k, *v)) {
                        self.links.remove(&(n, c));
                        self.queue.push_back(Msg::Close(n, self.nodes[n].life, c));
                    }
                }
                HubOutput::Diagnostic(_) => {}
            }
        }
    }

    /// Delivers the peer and host bytes held back (`held` and `held_hosts` are cleared).
    pub fn release(&mut self) {
        self.held.clear();
        self.held_hosts.clear();
        self.hold_opened.clear();
        self.held_to.clear();
        self.hold_blobs.clear();
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
            Msg::Up(n, l, _) | Msg::ToNode(n, l, _, _) | Msg::Close(n, l, _) if l != self.nodes[n].life => {}
            Msg::Up(n, _, c) => self.feed(n, Event::Up { conn: c }),
            Msg::ToHub(s, hc, b) => {
                let now = self.now_at(s);
                let t = std::time::Instant::now();
                let out = self.hosts[s].hub.input(now, hc, b);
                self.hub_busy += t.elapsed();
                self.hub_out(s, out);
            }
            Msg::ToNode(n, _, c, b) => {
                if let Some(told) = self.told.get_mut(&n) {
                    told.extend(told_ids(&b));
                }
                if let Some(f) = self.fetched.get_mut(&n) {
                    f.extend(fetched_ids(&b));
                }
                if !self.deaf.contains(&n) {
                    self.feed(n, Event::Bytes { conn: c, bytes: b })
                }
            }
            Msg::Close(n, _, c) => self.feed(n, Event::Down { conn: c }),
        }
        for s in 0..self.hosts.len() {
            let now = self.now_at(s);
            if self.hosts[s].hub.next_due(now).is_some_and(|t| t <= now) {
                let out = self.hosts[s].hub.tick(now);
                self.hub_out(s, out);
            }
        }
    }

    /// Every online node looks at its engine, then everything settles.
    pub fn run(&mut self) {
        osis_base::testenv::checkpoint();
        for n in 0..self.nodes.len() {
            self.feed(n, Event::Local);
        }
        self.settle(200_000);
        for n in 0..self.nodes.len() {
            self.feed(n, Event::Local);
        }
        self.settle(200_000);
    }

    /// Moves time on by `ms`, firing node wakes and host ticks, then settles.
    pub fn advance(&mut self, ms: u64) {
        self.clock.advance(ms);
        for s in 0..self.hosts.len() {
            let now = self.now_at(s);
            let out = self.hosts[s].hub.tick(now);
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

    /// A group owned by node `admin` with secrets of its own, `holders` granted with their roles
    /// (rotation boxing every holder), a deposit seed and a label at `hosts`; the setup
    /// commits delivered to the holders directly.
    pub fn group(&mut self, admin: usize, holders: &[(usize, Role)], hosts: &[usize]) -> Tid {
        let addrs: Vec<Address> = hosts.iter().map(|s| self.hosts[*s].address.clone()).collect();
        self.group_at(admin, holders, addrs)
    }

    /// `group` with host addresses.
    pub fn group_at(&mut self, admin: usize, holders: &[(usize, Role)], addrs: Vec<Address>) -> Tid {
        self.group_seeded(admin, holders, addrs, 1)
    }

    /// `group_at` with the rotation's rng seed: groups of one admin need distinct seeds, or they
    /// get equal secrets and so one label ID.
    pub fn group_seeded(&mut self, admin: usize, holders: &[(usize, Role)], addrs: Vec<Address>, rng: u64) -> Tid {
        for (m, _) in holders {
            self.pair(*m, admin);
        }
        let me = self.tid(admin);
        let e = self.engine(admin);
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
        e.commit(m).unwrap();
        let mut recipients = vec![recipient(e, me, Role::Admin)];
        let mtids: Vec<(Tid, Role)> = holders.iter().map(|(n, r)| (self.tid(*n), *r)).collect();
        for (t, r) in &mtids {
            let e = self.engine(admin);
            set_edge(e, g, *t, *r);
            recipients.push(recipient(e, *t, *r));
        }
        let e = self.engine(admin);
        rotation(e, g, &recipients, rng, true);
        self.engine(admin).create_label(&g, &addrs).unwrap();
        for (m, _) in holders {
            self.pair(admin, *m);
        }
        g
    }

    /// A content thing in group `g` written by node `n`: created under `owner`, listed in
    /// `group.0` of `g`.
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

    /// Node `n` writes `v` to the ephemeral (or signal) key `key` of `t`, then lets its sync
    /// engine see it.
    pub fn eph_write(&mut self, n: usize, t: Tid, key: &osis_base::Ak, v: Value) {
        self.eph_write_expiring(n, t, key, v, None);
    }

    /// `eph_write` whose write expires `ms` from now (`None`: never).
    pub fn eph_write_expiring(&mut self, n: usize, t: Tid, key: &osis_base::Ak, v: Value, ms: Option<u64>) {
        let mut m = Mutation::new();
        m.set(t, key, &v).unwrap();
        if let Some(ms) = ms {
            m.expires(t, key, WallMs(self.now() + ms)).unwrap();
        }
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

    /// The registration path a host holds for a label.
    pub fn host_path(&self, s: usize, l: &osis_base::LabelId) -> Vec<osis_label::Step> {
        self.hosts[s].hub.store().path(l).unwrap()
    }

    /// The first label node `n` syncs.
    pub fn label(&mut self, n: usize) -> osis_base::LabelId {
        self.sync(n).labels().into_iter().next().unwrap().1.id
    }

    /// Live entry IDs the host holds under a label.
    pub fn host_ids(&self, s: usize, l: &osis_base::LabelId) -> Vec<osis_base::BlobId> {
        self.hosts[s].hub.store().live_ids(l).unwrap()
    }

    /// Node `n`'s connection to host `s`, if up (to inject a hostile host's frames).
    pub fn conn_to(&self, n: usize, s: usize) -> Option<ConnId> {
        self.links.iter().find(|((x, _), (y, _))| *x == n && *y == s).map(|((_, c), _)| *c)
    }

    pub fn labels_at(&self, s: usize) -> Vec<osis_base::LabelId> {
        self.hosts[s].hub.store().labels_after(None, 1000).unwrap()
    }
}

pub static TEST: osis_schema::StaticSchema = osis_schema::StaticSchema::new(
    "test.osis",
    r#"
version 1;
aspect t:reg.0: string;
aspect t:gone.0: string [by: writer, keep_at_most: 1h];
aspect t:brief.0: string [expires: 1h];
aspect t:blob.0: blob;
aspect t:big.0: map<string, string>;
aspect t:gonemap.0: map<string, string> [by: writer, keep_at_most: 0s];
aspect t:shortmap.0: map<string, string> [by: writer, keep_at_most: 10m];
aspect t:gonetext.0: text [by: writer, keep_at_most: 0s];
aspect t:briefmap.0: map<string, string> [expires: 1h];
"#,
);

pub const REG: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:reg.0", &TEST);
pub const GONE: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:gone.0", &TEST);
pub const BRIEF: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:brief.0", &TEST);
pub const BLOB: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:blob.0", &TEST);
pub const BIG: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:big.0", &TEST);
pub const GONEMAP: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:gonemap.0", &TEST);
pub const SHORTMAP: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:shortmap.0", &TEST);
pub const GONETEXT: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:gonetext.0", &TEST);
pub const BRIEFMAP: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:briefmap.0", &TEST);

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


pub fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn recipient(e: &mut Engine, t: Tid, role: Role) -> Recipient {
    if t == e.tid() {
        return Recipient { holder: t, role, keys: HolderKeys::KeyActor { kem: e.identity().keys().kem.public().clone(), seed: None } };
    }
    let k = e.get_typed(&t, &ct::KEYS).unwrap().unwrap();
    let mut keys = HolderKeys::from_keys(&k).unwrap();
    if let Some(own) = e.epochs(&t).filter(|_| matches!(keys, HolderKeys::Actor { .. })) {
        keys = keys.with_own(&own);
    }
    Recipient { holder: t, role, keys }
}

pub fn set_edge(e: &mut Engine, thing: Tid, holder: Tid, role: Role) -> CommitId {
    let mut m = Mutation::new();
    let edge = ct::Edge { role, until: None, invite: None, since: None, tied: None, keyset: None };
    // remove + put (spec/permissions.md §2)
    m.op(thing, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(holder)) }).unwrap();
    m.op(thing, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(edge.to_value()) }).unwrap();
    e.commit(m).unwrap().unwrap()
}

/// A rotation of every role of `a` boxing `recipients`, with a deposit seed when `seed`.
pub fn rotation(e: &mut Engine, a: Tid, recipients: &[Recipient], rng: u64, seed: bool) -> CommitId {
    let mut m = Mutation::new();
    rotation_ops(e, &mut m, a, recipients, rng, seed, &osis_keys::Names::default());
    e.commit(m).unwrap().unwrap()
}

/// Removes `holder` from `a` with the rotation boxing `recipients`, in one role commit
/// (spec/permissions.md §3), naming itself (its departs mark, spec/crypto.md §4) as the engine's
/// removal does.
pub fn remove_holder(e: &mut Engine, a: Tid, holder: Tid, recipients: &[Recipient], rng: u64) -> CommitId {
    let mut m = Mutation::new();
    m.op(a, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(holder)) }).unwrap();
    let ts = m.take_ts(e);
    let names = osis_keys::Names { departs: Some(osis_keys::Own { ts: ts.to_u64(), node: e.tid() }), ..osis_keys::Names::default() };
    rotation_ops(e, &mut m, a, recipients, rng, false, &names);
    e.commit(m).unwrap().unwrap()
}

fn rotation_ops(e: &mut Engine, m: &mut Mutation, a: Tid, recipients: &[Recipient], rng: u64, seed: bool, names: &osis_keys::Names) {
    let roles = BTreeSet::from([Role::Read, Role::Write, Role::Admin]);
    let view = e.epochs(&a).unwrap();
    let state = e.get_typed(&a, &ct::SECRETS).unwrap().unwrap_or_default();
    let r = rotate(&a, &roles, &view, &state, recipients, names, &mut SeededRng::from_u64(rng)).unwrap();
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

pub fn recipients_of(e: &mut Engine, holders: &[(Tid, Role)]) -> Vec<Recipient> {
    holders.iter().map(|(t, r)| recipient(e, *t, *r)).collect()
}

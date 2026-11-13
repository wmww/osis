#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, dead_code)]
//! Sync engines and hosts in process, no tokio: `SyncEngine`s exchanging bytes with
//! osis-host `Hub`s over in-memory queues, one manual clock (nodes may run off it: `set_skew`).
//! Every node's connections, dialed and served, are sessions of a hub of its own (`Node::hub`,
//! node sync above it as in the driver, on the node's clock); its hub's connection IDs are at
//! least `HUB_BASE`, so one `ConnId` space names both ends of a link. Group setup stands in for pairing
//! (direct delivery of the setup commits).

use osis_base::{Clock, CommitId, ManualClock, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::SeededRng;
use osis_keys::{HolderKeys, Recipient, rotate};
use osis_label::Address;
use osis_node::sync::{Action, ConnId, Event, SyncConfig, SyncEngine};
use osis_node::{Config, Engine, Mutation};
use osis_schema::core_types as ct;
use osis_schema::{RawKey, Codec};
use osis_proto::LabelStore;
use osis_host::{Hub, HubOutput, HostPolicy};
use osis_store::{MemoryBackend, MemoryRoot, StoreConfig};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::mpsc::Receiver;

pub const T0: u64 = 1_700_000_000_000;

/// Per (node, label, blob ID, stamp; none: deposited), how often a node's stream showed a peer
/// that entry (`Net::shown`).
pub type Shown = BTreeMap<(usize, osis_base::LabelId, osis_base::BlobId, Option<[u8; 64]>), usize>;

/// A backup of a peer's store and engine, its durable state (`Net::backup_store`).
pub struct StoreDisk {
    hub: (MemoryBackend, MemoryRoot),
    engine: (MemoryBackend, MemoryRoot),
}

/// A node that keeps what it cannot read for others: its hub, node sync above it (a bare engine:
/// no account, no group), on a clock of its own (`set_host_skew`).
pub struct Host {
    pub hub: Hub,
    pub sync: Option<SyncEngine>,
    /// Its one store's device (the hub's).
    pub backend: MemoryBackend,
    pub root: MemoryRoot,
    /// Its engine's device.
    pub engine_disk: (MemoryBackend, MemoryRoot),
    pub address: Address,
    pub clock: Arc<NodeClock>,
}

/// A node's wall clock: the net's plus a skew of its own (`Net::set_skew`).
pub struct NodeClock {
    base: Arc<ManualClock>,
    skew: std::sync::atomic::AtomicI64,
}

impl Clock for NodeClock {
    fn now_wall_ms(&self) -> WallMs {
        WallMs(self.base.now_wall_ms().0.saturating_add_signed(self.skew.load(std::sync::atomic::Ordering::SeqCst)))
    }
}

pub struct Node {
    pub sync: Option<SyncEngine>,
    pub clock: Arc<NodeClock>,
    /// The hub every peer dialing this node reaches (an empty store: it hosts nothing).
    pub hub: Hub,
    pub backend: MemoryBackend,
    pub root: MemoryRoot,
    /// The backend and root of its one store beside the engine (the hub's).
    pub hub_disk: (MemoryBackend, MemoryRoot),
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
#[derive(Clone)]
enum Msg {
    /// A dial of node, life, conn is up as the node's hub connection, to the key dialed.
    Up(usize, u64, ConnId, ConnId, [u8; 32]),
    ToHub(usize, ConnId, Vec<u8>),
    ToNode(usize, u64, ConnId, Vec<u8>),
    Close(usize, u64, ConnId),
}

/// A hand peer's connection to a node hub: the frames it was sent since last asked, and whether
/// it was closed.
type Hand = (Vec<Vec<u8>>, bool);

/// See `Net::tamper`.
pub type Tamper = Box<dyn FnMut(&osis_proto::Message) -> Option<osis_proto::Message>>;

pub struct Net {
    pub clock: Arc<ManualClock>,
    pub nodes: Vec<Node>,
    pub hosts: Vec<Host>,
    /// (node, its hub's conn) -> (host, the host hub's conn)
    links: BTreeMap<(usize, ConnId), (usize, u64)>,
    queue: VecDeque<Msg>,
    next_hub_conn: u64,
    next_node_hub: u64,
    pub steps: usize,
    /// (node, host) pairs that cannot connect.
    pub blocked: BTreeSet<(usize, usize)>,
    /// Node-to-node sessions, both directions: (node, conn) -> (node, conn), each side's its
    /// hub's (`HUB_BASE` and up).
    plinks: BTreeMap<(usize, ConnId), (usize, ConnId)>,
    /// (node, node) pairs that cannot connect.
    pub blocked_peers: BTreeSet<(usize, usize)>,
    /// LAN transport keys nodes listen with (peer dials to them reach that node).
    pub lan_keys: BTreeMap<[u8; 32], usize>,
    /// (from node, to node): peer bytes held back until `release`.
    pub held: BTreeSet<(usize, usize)>,
    held_messages: Vec<Msg>,
    /// Message kinds nodes sent to hosts, by kind.
    pub sent_kinds: BTreeMap<u64, usize>,
    /// Entries nodes' streams showed the peers they connect to (Added events, by stamp; Deposit
    /// items, stampless), by (node, label, blob, stamp): how often each went (the same stamp twice:
    /// shown again with nothing changed).
    pub shown: Shown,
    /// Of `shown`'s Added events in follow pushes (Stream: a log event, not a page of a join
    /// from the start), those showing the peer an entry it held already with that wrap and stamp
    /// when it was sent: logged again with nothing changed for it.
    pub shown_held: Shown,
    /// Of `shown`'s Added events, those in follow pushes (Stream).
    pub pushed: Shown,
    /// Delete items nodes sent to hosts, by (node, label, blob): how often each went.
    pub deleted: BTreeMap<(usize, osis_base::LabelId, osis_base::BlobId), usize>,
    /// Messages sent on peer links, by sender and kind.
    pub peer_kinds: BTreeMap<(usize, u64), usize>,
    /// Bytes nodes sent to hosts.
    pub sent_bytes: usize,
    /// Per blob, the bytes of it nodes sent to hosts (inline in stream events, or in fetch
    /// replies), summed over every crossing.
    pub crossed: BTreeMap<osis_base::BlobId, usize>,
    /// Every dial: (node, address).
    pub dialed: Vec<(usize, Address)>,
    /// Nodes added from now on judge everything at every pass (`SyncConfig::full_passes`).
    pub full_passes: bool,
    /// Nodes added from now on join no account of their own (`Net::bare`).
    bare: bool,
    /// New nodes' accounts have their home label (their inbox) at the node's hosts.
    pub home_at_hosts: bool,
    /// Nodes whose entries peers that cannot read never pull: the entries their streams show
    /// those peers and the bytes they fetch from them are lost on the way.
    pub unpulled: BTreeSet<usize>,
    /// (node, host): as `unpulled`, toward that host alone.
    pub unpulled_at: BTreeSet<(usize, usize)>,
    /// Blobs carrying these commits (by any node's entry for the blob) never reach a peer that
    /// cannot read the label: Deposits and Deposit items of them are lost on the way, and the
    /// streams and fetch replies it pulls drop them; a reader's stream and fetches drop them too.
    pub lose_deposits: BTreeSet<CommitId>,
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
    /// Nodes whose host bytes are held back until `release` (a node reading nothing for a while).
    pub held_to: BTreeSet<usize>,
    /// Host messages announcing or carrying one of these blobs are held back until `release`
    /// (a slow fetch of one entry), and what follows such a fetch reply on its connection.
    pub hold_blobs: BTreeSet<osis_base::BlobId>,
    /// Per node, blobs whose announcements and fetch replies hosts never deliver to it (the
    /// rest of each message is): a node that never hears of one entry.
    pub hide_blobs: BTreeMap<usize, BTreeSet<osis_base::BlobId>>,
    /// Per node, blobs hosts announce to it without their bytes and leave out of their fetch
    /// replies: a node that knows the entry and never holds it.
    pub bare_blobs: BTreeMap<usize, BTreeSet<osis_base::BlobId>>,
    /// A node between peers: a message it returns replaces the frame (peer sessions only).
    pub tamper: Option<Tamper>,
    /// Set: `tamper` sees only what this node sends to that one.
    pub tamper_link: Option<(usize, usize)>,
    /// `tamper` for what hosts send nodes (a hostile host's replies).
    pub host_tamper: Option<Tamper>,
    /// Peer links (from, to) whose sender answers no request: every reply it sends there is
    /// dropped; its pushes and its own requests go.
    pub silent: BTreeSet<(usize, usize)>,
    /// Peer links (from, to) whose sender trickles: from its first reply there on, what it sends
    /// waits here (the receiver's connection, the bytes) and goes only by `trickle_out`.
    pub trickle: BTreeMap<(usize, usize), (ConnId, Vec<u8>)>,
    /// Host links (host, node) whose host trickles: from its first fetch reply there on, what it
    /// sends waits here (the node's connection, the bytes) and goes only by `trickle_host_out`.
    pub trickle_hosts: BTreeMap<(usize, usize), (ConnId, Vec<u8>)>,
    /// Peer bytes sent on a link before the last ones queued there were delivered join them:
    /// one input of several frames, as a real driver's read (else each send is its own input).
    pub batch_reads: bool,
    /// Peer connections a node closed over the peer's messages (`Action::Close`).
    pub peer_closes: usize,
    /// Hand peers' connections to node hubs (`hand_accept`): what each was sent since last
    /// asked, and whether it was closed.
    hands: BTreeMap<(usize, ConnId), Hand>,
    /// The client-port actions nodes emitted (`Action::Request`, `Room`, `Ended`), by node.
    pub port: Vec<(usize, Action)>,
}

/// A `Net` without its tampers (closures, not `Send`): what `Net::cached` keeps between tests.
struct Parts {
    clock: Arc<ManualClock>,
    nodes: Vec<Node>,
    hosts: Vec<Host>,
    links: BTreeMap<(usize, ConnId), (usize, u64)>,
    queue: VecDeque<Msg>,
    next_hub_conn: u64,
    steps: usize,
    blocked: BTreeSet<(usize, usize)>,
    plinks: BTreeMap<(usize, ConnId), (usize, ConnId)>,
    blocked_peers: BTreeSet<(usize, usize)>,
    lan_keys: BTreeMap<[u8; 32], usize>,
    held: BTreeSet<(usize, usize)>,
    held_messages: Vec<Msg>,
    sent_kinds: BTreeMap<u64, usize>,
    shown: Shown,
    shown_held: Shown,
    pushed: Shown,
    deleted: BTreeMap<(usize, osis_base::LabelId, osis_base::BlobId), usize>,
    peer_kinds: BTreeMap<(usize, u64), usize>,
    sent_bytes: usize,
    crossed: BTreeMap<osis_base::BlobId, usize>,
    dialed: Vec<(usize, Address)>,
    full_passes: bool,
    bare: bool,
    home_at_hosts: bool,
    unpulled: BTreeSet<usize>,
    unpulled_at: BTreeSet<(usize, usize)>,
    lose_deposits: BTreeSet<CommitId>,
    held_hosts: BTreeSet<usize>,
    busy: BTreeMap<usize, std::time::Duration>,
    hub_busy: std::time::Duration,
    told: BTreeMap<usize, BTreeSet<osis_base::BlobId>>,
    fetched: BTreeMap<usize, Vec<osis_base::BlobId>>,
    deaf: BTreeSet<usize>,
    held_to: BTreeSet<usize>,
    hold_blobs: BTreeSet<osis_base::BlobId>,
    hide_blobs: BTreeMap<usize, BTreeSet<osis_base::BlobId>>,
    bare_blobs: BTreeMap<usize, BTreeSet<osis_base::BlobId>>,
    tamper_link: Option<(usize, usize)>,
    silent: BTreeSet<(usize, usize)>,
    trickle: BTreeMap<(usize, usize), (ConnId, Vec<u8>)>,
    trickle_hosts: BTreeMap<(usize, usize), (ConnId, Vec<u8>)>,
    batch_reads: bool,
    peer_closes: usize,
    next_node_hub: u64,
    hands: BTreeMap<(usize, ConnId), Hand>,
    port: Vec<(usize, Action)>,
}

impl Net {
    fn into_parts(self) -> Parts {
        assert!(self.tamper.is_none() && self.host_tamper.is_none(), "a tamper cannot be kept");
        Parts { clock: self.clock, nodes: self.nodes, hosts: self.hosts, links: self.links, queue: self.queue, next_hub_conn: self.next_hub_conn, steps: self.steps, blocked: self.blocked, plinks: self.plinks, blocked_peers: self.blocked_peers, lan_keys: self.lan_keys, held: self.held, held_messages: self.held_messages, sent_kinds: self.sent_kinds, shown: self.shown, shown_held: self.shown_held, pushed: self.pushed, deleted: self.deleted, peer_kinds: self.peer_kinds, sent_bytes: self.sent_bytes, crossed: self.crossed, dialed: self.dialed, full_passes: self.full_passes, bare: self.bare, home_at_hosts: self.home_at_hosts, unpulled: self.unpulled, unpulled_at: self.unpulled_at, lose_deposits: self.lose_deposits, held_hosts: self.held_hosts, busy: self.busy, hub_busy: self.hub_busy, told: self.told, fetched: self.fetched, deaf: self.deaf, held_to: self.held_to, hold_blobs: self.hold_blobs, hide_blobs: self.hide_blobs, bare_blobs: self.bare_blobs, tamper_link: self.tamper_link, silent: self.silent, trickle: self.trickle, trickle_hosts: self.trickle_hosts, batch_reads: self.batch_reads, peer_closes: self.peer_closes, next_node_hub: self.next_node_hub, hands: self.hands, port: self.port }
    }

    fn from_parts(p: Parts) -> Net {
        let Parts { clock, nodes, hosts, links, queue, next_hub_conn, steps, blocked, plinks, blocked_peers, lan_keys, held, held_messages, sent_kinds, shown, shown_held, pushed, deleted, peer_kinds, sent_bytes, crossed, dialed, full_passes, bare, home_at_hosts, unpulled, unpulled_at, lose_deposits, held_hosts, busy, hub_busy, told, fetched, deaf, held_to, hold_blobs, hide_blobs, bare_blobs, tamper_link, silent, trickle, trickle_hosts, batch_reads, peer_closes, next_node_hub, hands, port } = p;
        Net { clock, nodes, hosts, links, queue, next_hub_conn, steps, blocked, plinks, blocked_peers, lan_keys, held, held_messages, sent_kinds, shown, shown_held, pushed, deleted, peer_kinds, sent_bytes, crossed, dialed, full_passes, bare, home_at_hosts, unpulled, unpulled_at, lose_deposits, held_hosts, busy, hub_busy, told, fetched, deaf, held_to, hold_blobs, hide_blobs, bare_blobs, tamper_link, silent, trickle, trickle_hosts, batch_reads, peer_closes, next_node_hub, hands, port, tamper: None, host_tamper: None }
    }
}

impl Net {
    /// A copy (`copy`) of the world `build` makes, with what it returned: built once per test
    /// process per `key`, which names the build and every parameter it takes
    /// (`osis_base::copying::cached`).
    pub fn cached<T: Clone + Send + 'static>(key: &str, build: impl FnOnce() -> (Net, T)) -> (Net, T) {
        let (parts, t) = osis_base::copying::cached(key, || {
            let (n, t) = build();
            (Some(n.into_parts()), t)
        }, |(parts, t)| {
            let mut net = Net::from_parts(parts.take().expect("kept"));
            let copy = net.copy();
            *parts = Some(net.into_parts());
            (Some(copy.into_parts()), t.clone())
        });
        (Net::from_parts(parts.expect("copied")), t)
    }
}

/// `Net::new`, one host, `N` nodes at it (seeds 1 to `N`, in order): built once (`Net::cached`).
pub fn hosted_nodes<const N: usize>() -> (Net, usize, [usize; N]) {
    let (net, (host, nodes)) = Net::cached(&format!("hosted_nodes/{N}"), || {
        let mut net = Net::new();
        let host = net.add_host();
        let nodes = std::array::from_fn(|i| net.node(i as u64 + 1, &[host]));
        (net, (host, nodes))
    });
    (net, host, nodes)
}

/// `hosted_nodes`, then a group of node 0's at the host with `holders` (node, role), items
/// `items` written by node 0 in it (each `net.item(0, g, g, v)`), and `net.run()` if `settle`:
/// built once per parameter value (`Net::cached`).
pub fn hosted<const N: usize, const I: usize>(holders: &[(usize, Role)], items: [&str; I], settle: bool) -> (Net, usize, [usize; N], Tid, [Tid; I]) {
    let key = format!("hosted/{N}/{holders:?}/{items:?}/{settle}");
    let holders = holders.to_vec();
    let items: Vec<String> = items.iter().map(|v| v.to_string()).collect();
    let (net, (host, nodes, g, ts)) = Net::cached(&key, move || {
        let mut net = Net::new();
        let host = net.add_host();
        let nodes: [usize; N] = std::array::from_fn(|i| net.node(i as u64 + 1, &[host]));
        let g = net.group(nodes[0], &holders, &[host]);
        let ts: Vec<Tid> = items.iter().map(|v| net.item(nodes[0], g, g, v)).collect();
        if settle {
            net.run();
        }
        (net, (host, nodes, g, ts))
    });
    (net, host, nodes, g, ts.try_into().unwrap())
}

/// `Net::new`, one host, node 1 with an account of its own (`connection_proofs::account_node`) and
/// node 2 paired as its second node (`paired_node`): built once (`Net::cached`). Returns (net,
/// host, first node, second node, account).
pub fn account_pair() -> (Net, usize, usize, usize, Tid) {
    let (net, (host, a, b, account)) = Net::cached("account_pair", || {
        let mut net = Net::new();
        let host = net.add_host();
        let (a, account) = crate::connection_proofs::account_node(&mut net, 1, host);
        let b = crate::connection_proofs::paired_node(&mut net, 2, host, a, account);
        (net, (host, a, b, account))
    });
    (net, host, a, b, account)
}

/// `Net::new`, one host and nodes with accounts of their own (`connection_proofs::account_node`)
/// seeded `seeds`: built once per `seeds` (`Net::cached`). Returns (net, host, [(node, account)]).
pub fn account_nodes<const N: usize>(seeds: [u64; N]) -> (Net, usize, [(usize, Tid); N]) {
    let (net, (host, ns)) = Net::cached(&format!("account_nodes/{seeds:?}"), || {
        let mut net = Net::new();
        let host = net.add_host();
        let ns: Vec<(usize, Tid)> = seeds.iter().map(|s| crate::connection_proofs::account_node(&mut net, *s, host)).collect();
        (net, (host, ns))
    });
    (net, host, ns.try_into().unwrap())
}

/// `Net::new` and `N` nodes syncing with no host (seeds 1 to `N`): built once (`Net::cached`).
pub fn local_nodes<const N: usize>() -> (Net, [usize; N]) {
    Net::cached(&format!("local_nodes/{N}"), || {
        let mut net = Net::new();
        let nodes = std::array::from_fn(|i| net.node(i as u64 + 1, &[]));
        (net, nodes)
    })
}

/// Blob IDs whole frames `b` from a host announce or carry.
fn told_ids(b: &[u8]) -> Vec<osis_base::BlobId> {
    use osis_proto::{Event as E, Message as M};
    let mut d = osis_proto::FrameDecoder::new();
    d.push(b);
    let mut v = Vec::new();
    while let Ok(Some(body)) = d.next_frame() {
        match osis_proto::Message::decode(&body) {
            Ok(M::PullReply(r)) => v.extend(r.events.iter().filter_map(|(_, e)| if let E::Added { blob_id, .. } = e { Some(*blob_id) } else { None })),
            Ok(M::Stream(r)) => v.extend(r.events.iter().filter_map(|(_, e)| if let E::Added { blob_id, .. } = e { Some(*blob_id) } else { None })),
            Ok(M::FetchReply { items, .. }) => v.extend(items.iter().filter(|i| i.entry.is_some()).map(|i| i.blob_id)),
            _ => {}
        }
    }
    v
}

/// Whole frames `b` from a host with every announcement and fetch reply item of a blob in
/// `hide` left out.
fn without_blobs(b: &[u8], hide: &BTreeSet<osis_base::BlobId>, bare: bool) -> Vec<u8> {
    use osis_proto::{Event as E, Message as M};
    let mut d = osis_proto::FrameDecoder::new();
    d.push(b);
    let mut out = Vec::new();
    while let Ok(Some(body)) = d.next_frame() {
        match osis_proto::Message::decode(&body) {
            Ok(mut m) => {
                let strip = |events: &mut Vec<(osis_base::LabelId, E)>| {
                    if bare {
                        for (_, e) in events.iter_mut() {
                            if let E::Added { blob_id, blob, .. } = e
                                && hide.contains(blob_id)
                            {
                                *blob = None;
                            }
                        }
                    } else {
                        events.retain(|(_, e)| !matches!(e, E::Added { blob_id, .. } if hide.contains(blob_id)));
                    }
                };
                match &mut m {
                    M::PullReply(r) => strip(&mut r.events),
                    M::Stream(r) => strip(&mut r.events),
                    M::FetchReply { items, .. } => items.retain(|i| !hide.contains(&i.blob_id)),
                    _ => {}
                }
                // a cursorless push carries at least one event: one emptied is dropped whole
                if matches!(&m, M::Stream(r) if r.events.is_empty() && r.cursor.is_none()) {
                    continue;
                }
                out.extend(osis_proto::encode_frame(&m.encode()));
            }
            Err(_) => out.extend(osis_proto::encode_frame(&body)),
        }
    }
    out
}

/// Blob IDs whole frames `b` from a host carry in fetch replies.
pub fn fetched_ids(b: &[u8]) -> Vec<osis_base::BlobId> {
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

/// Node hubs' connection IDs start here (engine connection IDs stay below).
pub const HUB_BASE: ConnId = 1 << 40;

/// Rounds of messages one `Net::settle` delivers at most before it fails as a loop. The clock
/// stands still within a settle, so nothing timed ends a loop there; its messages grow costly
/// (a loop holds more each round), and the message cap alone let one run past the seed's CPU
/// limit (random churn seed 460971879377: 32 CPU-s to fail here). The node tests' settles
/// take at most about 210 rounds (random churn and window seeds 90). Minor consequence,
/// test-only: near 0 every settle fails; at infinity a loop runs to the seed's CPU timeout.
const SETTLE_ROUNDS: usize = 2_000;

/// What a peer that cannot read `l` streams to a reader: `events` of `l` at a position `at`
/// names (a hostile peer's push, or a replay).
pub fn stream_msg(l: osis_base::LabelId, events: Vec<osis_proto::Event>, at: u64) -> osis_proto::Message {
    osis_proto::Message::Stream(Box::new(osis_proto::msg::Stream { events: events.into_iter().map(|e| (l, e)).collect(), cursor: Some(at.to_be_bytes().to_vec()), report: false, seq: 0 }))
}

pub fn host_key(i: usize) -> [u8; 32] {
    [0x50 + i as u8; 32]
}

impl Net {
    /// A network whose new nodes are each their own account's only node.
    pub fn new() -> Net {
        Net { bare: false, home_at_hosts: false, clock: Arc::new(ManualClock::new(WallMs(T0))), nodes: vec![], hosts: vec![], links: BTreeMap::new(), queue: VecDeque::new(), next_hub_conn: 1, next_node_hub: HUB_BASE, steps: 0, blocked: BTreeSet::new(), plinks: BTreeMap::new(), blocked_peers: BTreeSet::new(), lan_keys: BTreeMap::new(), held: BTreeSet::new(), held_messages: Vec::new(), sent_kinds: BTreeMap::new(), shown: BTreeMap::new(), shown_held: BTreeMap::new(), pushed: BTreeMap::new(), deleted: BTreeMap::new(), peer_kinds: BTreeMap::new(), sent_bytes: 0, crossed: BTreeMap::new(), dialed: Vec::new(), full_passes: false, unpulled: BTreeSet::new(), unpulled_at: BTreeSet::new(), lose_deposits: BTreeSet::new(), held_hosts: BTreeSet::new(), busy: BTreeMap::new(), hub_busy: std::time::Duration::ZERO, told: BTreeMap::new(), fetched: BTreeMap::new(), deaf: BTreeSet::new(), held_to: BTreeSet::new(), hold_blobs: BTreeSet::new(), hide_blobs: BTreeMap::new(), bare_blobs: BTreeMap::new(), tamper: None, tamper_link: None, host_tamper: None, silent: BTreeSet::new(), trickle: BTreeMap::new(), trickle_hosts: BTreeMap::new(), batch_reads: false, peer_closes: 0, hands: BTreeMap::new(), port: Vec::new() }
    }

    /// An exact copy of this network as it stands (notes/test-harnesses.md, Copied worlds): every node
    /// (`SyncEngine::test_copy`) and host (`Hub::test_copy`) with its device, on one new clock at
    /// the same time (each node's skew kept), the queues, links and counters: run the same steps
    /// on both and they do the same. Unread engine events stay readable on both (`&mut`). A net
    /// with a `tamper` set cannot be copied (a closure); a node taken out (`take`) stays out.
    // every field `clone`d, whatever its type: none is left out by accident
    #[allow(clippy::clone_on_copy)]
    pub fn copy(&mut self) -> Net {
        assert!(self.tamper.is_none() && self.host_tamper.is_none(), "a tamper cannot be copied");
        osis_base::copying::copying(|| {
            let clock = Arc::new(ManualClock::new(self.clock.now_wall_ms()));
            let nodes = self.nodes.iter_mut().map(|n| {
                let nc = Arc::new(NodeClock { base: clock.clone(), skew: n.clock.skew.load(std::sync::atomic::Ordering::SeqCst).into() });
                let c: Arc<dyn Clock> = nc.clone();
                let mut sync = n.sync.as_mut().map(|s| s.test_copy(c).unwrap());
                let pending: Vec<osis_node::Event> = n.events.try_iter().collect();
                // the node's own receiver needs an engine to subscribe to: a node taken out keeps its own
                let events = match (n.sync.as_mut(), sync.as_mut()) {
                    (Some(o), Some(cp)) => {
                        n.events = o.engine_mut().test_subscribe_with(pending.clone(), true);
                        cp.engine_mut().test_subscribe_with(pending, true)
                    }
                    _ => std::sync::mpsc::channel().1,
                };
                // the copied engine's copy of the store it shares with the hub
                let hub = match &sync {
                    Some(s) => n.hub.test_copy_over(s.hub_store()),
                    None => n.hub.test_copy(nc.clone()).unwrap(),
                };
                Node { sync, clock: nc, hub, backend: n.backend.test_copy(), root: n.root.test_copy(), hub_disk: (n.hub_disk.0.test_copy(), n.hub_disk.1.test_copy()), online: n.online, wake: n.wake, life: n.life, accepts: n.accepts, events }
            }).collect();
            let hosts = self.hosts.iter_mut().map(|h| {
                let nc = Arc::new(NodeClock { base: clock.clone(), skew: h.clock.skew.load(std::sync::atomic::Ordering::SeqCst).into() });
                let c: Arc<dyn Clock> = nc.clone();
                let sync = h.sync.as_mut().map(|s| s.test_copy(c).unwrap());
                let hub = h.hub.test_copy_over(sync.as_ref().expect("a host runs").hub_store());
                Host { hub, sync, backend: h.backend.test_copy(), root: h.root.test_copy(), engine_disk: (h.engine_disk.0.test_copy(), h.engine_disk.1.test_copy()), address: h.address.clone(), clock: nc }
            }).collect();
            Net {
                clock,
                nodes,
                hosts,
                links: self.links.clone(),
                queue: self.queue.clone(),
                next_hub_conn: self.next_hub_conn.clone(),
                steps: self.steps.clone(),
                blocked: self.blocked.clone(),
                plinks: self.plinks.clone(),
                blocked_peers: self.blocked_peers.clone(),
                lan_keys: self.lan_keys.clone(),
                held: self.held.clone(),
                held_messages: self.held_messages.clone(),
                sent_kinds: self.sent_kinds.clone(),
                shown: self.shown.clone(),
                shown_held: self.shown_held.clone(),
                pushed: self.pushed.clone(),
                deleted: self.deleted.clone(),
                peer_kinds: self.peer_kinds.clone(),
                sent_bytes: self.sent_bytes.clone(),
                crossed: self.crossed.clone(),
                dialed: self.dialed.clone(),
                full_passes: self.full_passes.clone(),
                bare: self.bare.clone(),
                home_at_hosts: self.home_at_hosts.clone(),
                unpulled: self.unpulled.clone(),
                unpulled_at: self.unpulled_at.clone(),
                lose_deposits: self.lose_deposits.clone(),
                held_hosts: self.held_hosts.clone(),
                busy: self.busy.clone(),
                hub_busy: self.hub_busy.clone(),
                told: self.told.clone(),
                fetched: self.fetched.clone(),
                deaf: self.deaf.clone(),
                held_to: self.held_to.clone(),
                hold_blobs: self.hold_blobs.clone(),
                hide_blobs: self.hide_blobs.clone(),
                bare_blobs: self.bare_blobs.clone(),
                tamper: None,
                tamper_link: self.tamper_link.clone(),
                host_tamper: None,
                silent: self.silent.clone(),
                trickle: self.trickle.clone(),
                trickle_hosts: self.trickle_hosts.clone(),
                batch_reads: self.batch_reads.clone(),
                peer_closes: self.peer_closes.clone(),
                next_node_hub: self.next_node_hub.clone(),
                hands: self.hands.clone(),
                port: self.port.clone(),
            }
        })
    }

    /// A network whose new nodes join no account: the test makes or pairs them.
    pub fn bare() -> Net {
        Net { bare: true, ..Net::new() }
    }

    pub fn now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    pub fn add_host(&mut self) -> usize {
        self.add_host_with(HostPolicy::default())
    }

    pub fn add_host_with(&mut self, policy: HostPolicy) -> usize {
        let i = self.hosts.len();
        let clock = Arc::new(NodeClock { base: self.clock.clone(), skew: 0.into() });
        let host = self.peer_on(i, (MemoryBackend::new(), MemoryRoot::new()), (MemoryBackend::new(), MemoryRoot::new()), clock, policy, 900 + i as u64, true);
        self.hosts.push(host);
        i
    }

    /// Host `i` over its devices (created when `new`, else opened), its engine on `clock`.
    #[allow(clippy::too_many_arguments)]
    fn peer_on(&self, i: usize, hub_disk: (MemoryBackend, MemoryRoot), engine_disk: (MemoryBackend, MemoryRoot), clock: Arc<NodeClock>, policy: HostPolicy, seed: u64, new: bool) -> Host {
        let c: Arc<dyn Clock> = clock.clone();
        let blobs = Net::hub_store(&hub_disk, c.clone(), seed);
        let (b, r) = (Box::new(engine_disk.0.clone()), Box::new(engine_disk.1.clone()));
        let engine = if new { Engine::create(b, r, blobs, Config::default(), c, Box::new(SeededRng::from_u64(seed))) } else { Engine::open(b, r, blobs, Config::default(), c, Box::new(SeededRng::from_u64(seed))) }.unwrap();
        let mut sync = SyncEngine::new(engine, Box::new(SeededRng::from_u64(seed + 7)), SyncConfig { peers: false, ..SyncConfig::default() }).unwrap();
        {
            let store = sync.hub_store();
            let mut st = store.lock().unwrap();
            st.set_policy(policy);
            st.set_admission(osis_host::Admission::Open, BTreeMap::new());
        }
        let hub = self.node_hub(&mut sync, seed);
        Host { hub, sync: Some(sync), backend: hub_disk.0, root: hub_disk.1, engine_disk, address: Address { url: format!("quic://host{i}:1"), key: host_key(i) }, clock }
    }

    /// A node's hub over its one store (`SyncEngine::hub_store`).
    fn node_hub(&self, sync: &mut SyncEngine, seed: u64) -> Hub {
        Hub::new(sync.hub_store(), Box::new(SeededRng::from_u64(seed ^ 0x4ab)))
    }

    /// The node's one store beside the engine over `disk` (opened or created), on its clock.
    fn hub_store(disk: &(MemoryBackend, MemoryRoot), clock: Arc<dyn Clock>, seed: u64) -> Arc<dyn osis_store::Ciphertext> {
        osis_node::sync::hub_store_on(Box::new(disk.0.clone()), Box::new(disk.1.clone()), clock, Box::new(SeededRng::from_u64(seed ^ 0x40b ^ 0x570e))).unwrap()
    }

    /// Host `s` loses everything it stored (same key and address).
    pub fn wipe_host(&mut self, s: usize) {
        self.close_host(s);
        let clock = self.hosts[s].clock.clone();
        self.hosts[s] = self.peer_on(s, (MemoryBackend::new(), MemoryRoot::new()), (MemoryBackend::new(), MemoryRoot::new()), clock, HostPolicy::default(), 990 + s as u64, true);
    }

    /// A backup of peer `s`'s durable state (its hub's store and its engine's), as a backup
    /// takes it (`restore_store`).
    pub fn backup_store(&self, s: usize) -> StoreDisk {
        let h = &self.hosts[s];
        StoreDisk { hub: (h.backend.copy(), h.root.copy()), engine: (h.engine_disk.0.copy(), h.engine_disk.1.copy()) }
    }

    /// Restarts peer `s` over `disk` (a backup of its durable state): its connections are gone.
    pub fn restore_store(&mut self, s: usize, disk: StoreDisk) {
        self.close_host(s);
        let clock = self.hosts[s].clock.clone();
        self.hosts[s] = self.peer_on(s, disk.hub, disk.engine, clock, HostPolicy::default(), 970 + s as u64, false);
    }

    /// Restarts host `s` over its durable state: its connections are gone, its in-memory
    /// (ephemeral) entries too.
    pub fn restart_host(&mut self, s: usize) {
        self.restart_host_with(s, HostPolicy::default());
    }

    /// `restart_host` with another policy.
    pub fn restart_host_with(&mut self, s: usize, policy: HostPolicy) {
        self.close_host(s);
        let h = &self.hosts[s];
        let (hub_disk, engine_disk, clock) = ((h.backend.clone(), h.root.clone()), h.engine_disk.clone(), h.clock.clone());
        self.hosts[s] = self.peer_on(s, hub_disk, engine_disk, clock, policy, 980 + s as u64, false);
    }

    /// Every node's connection to host `s` ends (the host going away).
    fn close_host(&mut self, s: usize) {
        let mine: Vec<((usize, ConnId), u64)> = self.links.iter().filter(|(_, (x, _))| *x == s).map(|(k, (_, hc))| (*k, *hc)).collect();
        for ((n, c), _) in mine {
            self.links.remove(&(n, c));
            self.queue.push_back(Msg::Close(n, self.nodes[n].life, c));
        }
    }

    /// Sets host `s`'s clock `ms` off the net's.
    pub fn set_host_skew(&mut self, s: usize, ms: i64) {
        self.hosts[s].clock.skew.store(ms, std::sync::atomic::Ordering::SeqCst);
    }

    /// Sets node `n`'s clock `ms` off the net's.
    pub fn set_skew(&mut self, n: usize, ms: i64) {
        self.nodes[n].clock.skew.store(ms, std::sync::atomic::Ordering::SeqCst);
    }

    /// Host `s`'s wall clock.
    pub fn now_at(&self, s: usize) -> u64 {
        self.hosts[s].clock.now_wall_ms().0
    }

    pub fn address(&self, s: usize) -> Address {
        self.hosts[s].address.clone()
    }

    pub fn add_node(&mut self, seed: u64, cfg: SyncConfig) -> usize {
        self.add_node_on(seed, cfg, (MemoryBackend::new(), MemoryRoot::new()), (MemoryBackend::new(), MemoryRoot::new()), Config::default())
    }

    /// A node for forensic checks: every row and blob it writes recorded, a small key tree and
    /// pages (a shred elsewhere does not incidentally rotate a leaked copy away); `faults` on
    /// its device.
    pub fn forensic_node(&mut self, seed: u64, hosts: &[usize], faults: &osis_store::Faults) -> usize {
        let backend = MemoryBackend::with_faults(faults.clone());
        backend.record_history();
        let cfg = SyncConfig { hosts: hosts.iter().map(|s| self.address(*s)).collect(), ..SyncConfig::default() };
        let store = StoreConfig { arity: 4, depth: 8, page_max: 512, ..StoreConfig::default() };
        let hub = MemoryBackend::with_faults(faults.clone());
        hub.record_history();
        let disks = ((backend, MemoryRoot::with_faults(faults.clone())), (hub, MemoryRoot::with_faults(faults.clone())));
        self.add_node_on(seed, cfg, disks.0, disks.1, Config { store, ..Config::default() })
    }

    /// The blobs on node `n`'s one store's disk (the hub's: the engine's and its entry rows').
    pub fn blobs_on_disk(&self, n: usize) -> u64 {
        self.nodes[n].hub_disk.0.held_split().2
    }

    /// Where an attacker holding node `n`'s device recovers `marker` (`Engine::forensic`; the
    /// node must record, `forensic_node`).
    pub fn forensic(&mut self, n: usize, marker: &[u8]) -> Vec<osis_store::Source> {
        let (backend, hub) = (self.nodes[n].backend.clone(), self.nodes[n].hub_disk.0.clone());
        let found = self.engine(n).forensic(&backend, &hub).unwrap();
        found.into_iter().filter(|r| r.plain.windows(marker.len()).any(|w| w == marker)).map(|r| r.from).collect()
    }

    fn add_node_on(&mut self, seed: u64, cfg: SyncConfig, (backend, root): (MemoryBackend, MemoryRoot), hub_disk: (MemoryBackend, MemoryRoot), engine_cfg: Config) -> usize {
        let cfg = SyncConfig { full_passes: cfg.full_passes || self.full_passes, ..cfg };
        let clock = Arc::new(NodeClock { base: self.clock.clone(), skew: 0.into() });
        let c: Arc<dyn Clock> = clock.clone();
        let blobs = Net::hub_store(&hub_disk, c.clone(), seed);
        let mut engine = Engine::create(Box::new(backend.clone()), Box::new(root.clone()), blobs, engine_cfg, c, Box::new(SeededRng::from_u64(seed))).unwrap();
        let home: Vec<Address> = if self.home_at_hosts { cfg.hosts.clone() } else { Vec::new() };
        let done = if self.bare { None } else { let d = engine.create_account(&home).unwrap().1; (!home.is_empty()).then_some(d) };
        let mut sync = SyncEngine::new(engine, Box::new(SeededRng::from_u64(seed + 7)), cfg).unwrap();
        let events = sync.engine_mut().subscribe_durable();
        let acts = done.map(|d| sync.carry_out(d).unwrap());
        let hub = self.node_hub(&mut sync, seed);
        self.nodes.push(Node { sync: Some(sync), clock, hub, backend, root, hub_disk, online: true, wake: None, life: 0, accepts: true, events });
        let n = self.nodes.len() - 1;
        if let Some(acts) = acts {
            self.actions(n, acts);
        }
        n
    }

    /// A new node running a copy of node `n`'s store (a copied or restored device), online beside
    /// `n` if `n` still runs.
    pub fn copy_node(&mut self, n: usize, seed: u64) -> usize {
        let cfg = self.sync(n).config().clone();
        let clock = Arc::new(NodeClock { base: self.clock.clone(), skew: self.nodes[n].clock.skew.load(std::sync::atomic::Ordering::SeqCst).into() });
        let c: Arc<dyn Clock> = clock.clone();
        let (backend, root) = (self.nodes[n].backend.copy(), self.nodes[n].root.copy());
        let hub_disk = (self.nodes[n].hub_disk.0.copy(), self.nodes[n].hub_disk.1.copy());
        let blobs = Net::hub_store(&hub_disk, c.clone(), seed);
        let engine = Engine::open(Box::new(backend.clone()), Box::new(root.clone()), blobs, Config::default(), c, Box::new(SeededRng::from_u64(seed))).unwrap();
        let mut sync = SyncEngine::new(engine, Box::new(SeededRng::from_u64(seed + 7)), cfg).unwrap();
        let events = sync.engine_mut().subscribe_durable();
        let hub = self.node_hub(&mut sync, seed);
        self.nodes.push(Node { sync: Some(sync), clock, hub, backend, root, hub_disk, online: true, wake: None, life: 0, accepts: true, events });
        self.nodes.len() - 1
    }

    /// A node with the default config syncing with hosts `hosts`.
    pub fn node(&mut self, seed: u64, hosts: &[usize]) -> usize {
        let cfg = SyncConfig { hosts: hosts.iter().map(|s| self.address(*s)).collect(), ..SyncConfig::default() };
        self.add_node(seed, cfg)
    }

    /// `node` for a node that joins no account of its own: a second node, to be paired.
    pub fn joining_node(&mut self, seed: u64, hosts: &[usize]) -> usize {
        let was = std::mem::replace(&mut self.bare, true);
        let n = self.node(seed, hosts);
        self.bare = was;
        n
    }

    /// Takes node `n`'s sync engine out (to run it under a driver).
    pub fn take(&mut self, n: usize) -> SyncEngine {
        self.nodes[n].online = false;
        self.nodes[n].sync.take().unwrap()
    }

    /// Node `n`'s end `c` of a peer link as its engine names it (a served one by the session).
    fn engine_conn(&self, n: usize, c: ConnId) -> ConnId {
        if c < HUB_BASE {
            return c;
        }
        self.nodes[n].sync.as_ref().and_then(|s| s.served_conn(c)).unwrap_or(c)
    }

    /// Node `n`'s engine connection `c` as the link names it: its hub's ID.
    pub fn link_conn(&self, n: usize, c: ConnId) -> ConnId {
        self.nodes[n].sync.as_ref().and_then(|s| s.hub_conn(c)).unwrap_or(c)
    }

    /// Node `n`'s peer connections, as the engines name them: its end, the other node, the
    /// other end.
    pub fn peer_conns(&self, n: usize) -> Vec<(ConnId, usize, ConnId)> {
        self.plinks.iter().filter(|((x, _), _)| *x == n).map(|((_, c), (m, pc))| (self.engine_conn(n, *c), *m, self.engine_conn(*m, *pc))).collect()
    }

    /// Messages of `kind` node `n` sent on peer links so far.
    pub fn peer_sent(&self, n: usize, kind: u64) -> usize {
        self.peer_kinds.get(&(n, kind)).copied().unwrap_or(0)
    }

    /// Delivers the first `k` bytes a trickling link (`trickle`) holds back.
    pub fn trickle_out(&mut self, from: usize, to: usize, k: usize) {
        let Some((pc, held)) = self.trickle.get_mut(&(from, to)) else { return };
        let bytes: Vec<u8> = held.drain(..k.min(held.len())).collect();
        let pc = *pc;
        if !bytes.is_empty() {
            self.queue.push_back(Msg::ToNode(to, self.nodes[to].life, pc, bytes));
        }
    }

    /// Delivers the first `k` bytes a trickling host link (`trickle_hosts`) holds back.
    pub fn trickle_host_out(&mut self, s: usize, n: usize, k: usize) {
        let Some((c, held)) = self.trickle_hosts.get_mut(&(s, n)) else { return };
        let bytes: Vec<u8> = held.drain(..k.min(held.len())).collect();
        let c = *c;
        if !bytes.is_empty() {
            self.queue.push_back(Msg::ToNode(n, self.nodes[n].life, c, bytes));
        }
    }

    /// The other end of peer connection `(n, c)` (engine connection IDs).
    pub fn peer_of(&self, n: usize, c: ConnId) -> Option<(usize, ConnId)> {
        self.plinks.get(&(n, self.link_conn(n, c))).map(|(m, pc)| (*m, self.engine_conn(*m, *pc)))
    }

    /// Queues `m` on peer connection `(n, c)` (`c` its engine's) as if node `n` sent it (a hand
    /// peer's message).
    pub fn inject(&mut self, n: usize, c: ConnId, m: &osis_proto::Message) {
        let (to, pc) = self.plinks[&(n, self.link_conn(n, c))];
        let bytes = self.in_order(to, self.engine_conn(to, pc), osis_proto::encode_frame(&m.encode()), true);
        self.queue.push_back(Msg::ToNode(to, self.nodes[to].life, pc, bytes));
    }

    /// Bytes arrive at once on node `n`'s connection `c` (its engine's ID), dialed or served, as
    /// if its peer sent them: into its hub's session, what that hands up to its node sync.
    pub fn receive(&mut self, n: usize, c: ConnId, bytes: Vec<u8>) {
        let bytes = self.in_order(n, c, bytes, false);
        let hc = self.link_conn(n, c);
        let now = self.node_now(n);
        let out = self.nodes[n].hub.input(now, hc, bytes);
        self.node_hub_out(n, out);
    }

    /// `bytes` with each push holding a cursor numbered as the next node `n` takes on `c`, its
    /// peer counting it as its own
    /// (`Stream::seq`): a hand-made push comes in order, as a peer's would.
    /// `queued`: they go behind what is queued on `c` (`inject`), else at once (`receive`).
    fn in_order(&mut self, n: usize, c: ConnId, bytes: Vec<u8>, queued: bool) -> Vec<u8> {
        let mut next = self.sync(n).stream_next_push(c);
        if queued {
            let hc = self.link_conn(n, c);
            let pushes = |b: &[u8]| {
                let mut d = osis_proto::FrameDecoder::new();
                d.push(b);
                let mut k = 0;
                while let Ok(Some(f)) = d.next_frame() {
                    k += u64::from(matches!(osis_proto::Message::decode(&f), Ok(osis_proto::Message::Stream(st)) if st.cursor.is_some()));
                }
                k
            };
            next += self.queue.iter().map(|m| match m {
                Msg::ToNode(x, _, y, b) if *x == n && *y == hc => pushes(b),
                _ => 0,
            }).sum::<u64>();
        }
        let mut d = osis_proto::FrameDecoder::new();
        d.push(&bytes);
        let mut out = Vec::new();
        while let Ok(Some(body)) = d.next_frame() {
            match osis_proto::Message::decode(&body) {
                Ok(osis_proto::Message::Stream(mut st)) if st.cursor.is_some() => {
                    st.seq = next;
                    next += 1;
                    self.sent_in_place(n, c);
                    out.extend(osis_proto::encode_frame(&osis_proto::Message::Stream(st).encode()));
                }
                _ => out.extend(osis_proto::encode_frame(&body)),
            }
        }
        out
    }

    /// The peer of node `n` on its connection `c` counts a push a test sent in its place
    /// (`SyncEngine::stream_push_sent`).
    fn sent_in_place(&mut self, n: usize, c: ConnId) {
        let hc = self.link_conn(n, c);
        if let Some((s, shc)) = self.links.get(&(n, hc)).copied() {
            if let Some(sync) = self.hosts[s].sync.as_mut() {
                let sc = sync.served_conn(shc).unwrap_or(shc);
                let _ = sync.stream_push_sent(sc);
            }
        } else if let Some((m, pc)) = self.plinks.get(&(n, hc)).copied() {
            let mc = self.engine_conn(m, pc);
            if let Some(sync) = self.nodes[m].sync.as_mut() {
                let _ = sync.stream_push_sent(mc);
            }
        }
    }

    /// `receive`, returning the actions node sync takes for what the hub handed up instead of
    /// carrying them out (the hub's own output goes).
    pub fn hub_in(&mut self, n: usize, c: ConnId, bytes: Vec<u8>) -> Vec<Action> {
        let bytes = self.in_order(n, c, bytes, false);
        let hc = self.link_conn(n, c);
        let now = self.node_now(n);
        let (mut ups, mut rest, mut moved) = (Vec::new(), Vec::new(), false);
        for o in self.nodes[n].hub.input(now, hc, bytes) {
            match o {
                HubOutput::Up(h, u) => ups.push((h, u)),
                HubOutput::Moved => moved = true,
                x => rest.push(x),
            }
        }
        self.node_hub_out(n, rest);
        if ups.is_empty() && !moved {
            return Vec::new();
        }
        self.sync(n).handle(Event::Hub { ups })
    }

    /// The messages node actions `acts` send on hub connection `hc` (`link_conn`).
    pub fn sent_on(acts: &[Action], hc: ConnId) -> Vec<osis_proto::Message> {
        acts.iter().filter_map(|a| match a {
            Action::Hub { conn, down: osis_host::Down::Message(m) } if *conn == hc => Some((**m).clone()),
            _ => None,
        }).collect()
    }

    pub fn sync(&mut self, n: usize) -> &mut SyncEngine {
        self.nodes[n].sync.as_mut().unwrap()
    }

    /// Host `s`'s node sync.
    pub fn host_sync(&mut self, s: usize) -> &mut SyncEngine {
        self.hosts[s].sync.as_mut().unwrap()
    }

    pub fn engine(&mut self, n: usize) -> &mut Engine {
        self.sync(n).engine_mut()
    }

    /// Node `n` grants `holder` `role` on `target` (`Engine::grant`: secrets in the same step)
    /// and carries it out; the grant's commit. Tests that set up access use this, not `set_edge`.
    pub fn grant(&mut self, n: usize, target: Tid, holder: Tid, role: Role) -> CommitId {
        let edge = ct::Edge { role, until: None, invite: None, tied: None };
        let done = self.engine(n).grant(&target, &holder, &edge).unwrap();
        let c = *done.commits.last().unwrap();
        let acts = self.sync(n).carry_out(done).unwrap();
        self.actions(n, acts);
        c
    }

    /// Whether blob `b` under `l` carries one of `commits`, by some node's entry for it.
    fn carries(&self, l: &osis_base::LabelId, b: &osis_base::BlobId, commits: &BTreeSet<CommitId>) -> bool {
        !commits.is_empty() && self.nodes.iter().filter_map(|x| x.sync.as_ref()).any(|s| s.entries(l).into_iter().any(|(x, k)| x == *b && matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if commits.contains(&commit))))
    }

    /// The account of node `n`.
    pub fn tid(&mut self, n: usize) -> Tid {
        self.engine(n).me()
    }

    /// Node `n` itself (not its account): what its own card is written on.
    pub fn node_tid(&mut self, n: usize) -> Tid {
        self.engine(n).tid()
    }

    /// Restarts a node over its store (sync state reloads).
    pub fn restart(&mut self, n: usize, seed: u64) {
        let cfg = self.sync(n).config().clone();
        self.disconnect(n);
        let node = &mut self.nodes[n];
        let c: Arc<dyn Clock> = node.clock.clone();
        node.sync = None;
        node.life += 1;
        let blobs = Net::hub_store(&node.hub_disk, c.clone(), seed);
        let engine = Engine::open(Box::new(node.backend.clone()), Box::new(node.root.clone()), blobs, Config::default(), c, Box::new(SeededRng::from_u64(seed))).unwrap();
        let mut sync = SyncEngine::new(engine, Box::new(SeededRng::from_u64(seed + 7)), cfg).unwrap();
        node.events = sync.engine_mut().subscribe_durable();
        let hub = self.node_hub(&mut sync, seed);
        let node = &mut self.nodes[n];
        node.sync = Some(sync);
        node.hub = hub;
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
            let out = self.nodes[n].hub.closed(c);
            self.node_hub_out(n, out);
        }
        let hosts: Vec<usize> = self.links.iter().filter(|((x, _), _)| *x == n).map(|(_, (s, _))| *s).collect();
        for s in hosts {
            self.drop_link(n, s);
        }
    }

    /// Nothing more reaches node `n` on its closed connection `c`, queued or held back.
    fn forget_conn(&mut self, n: usize, c: ConnId) {
        let to = |m: &Msg| matches!(m, Msg::Up(x, _, _, y, _) | Msg::ToNode(x, _, y, _) | Msg::Close(x, _, y) if *x == n && *y == c);
        self.queue.retain(|m| !to(m));
        self.held_messages.retain(|m| !to(m));
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
            let out = self.nodes[n].hub.closed(c);
            self.node_hub_out(n, out);
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
            // closes already sent reach it first: a real transport tells a node of a dead
            // connection, while an offline node here hears nothing (a served session it never
            // ended would win a later dial's record as a duplicate)
            let (closes, rest): (VecDeque<Msg>, VecDeque<Msg>) = std::mem::take(&mut self.queue).into_iter().partition(|m| matches!(m, Msg::Close(x, ..) if *x == n));
            self.queue = rest;
            for m in closes {
                self.deliver(m);
            }
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

    /// Carries out node `n`'s actions in order, as its driver does: its hub takes the downs
    /// after the rest, so a nested call's `Wake` is not overwritten by this call's older one.
    pub fn actions(&mut self, n: usize, acts: Vec<Action>) {
        let mut downs = Vec::new();
        for a in acts {
            if std::env::var_os("OSIS_SYNC_TRACE").is_some() {
                eprintln!("node {n} action {}", format!("{a:?}").chars().take(300).collect::<String>());
            }
            if let Action::Dial { address, .. } = &a {
                self.dialed.push((n, address.clone()));
            }
            match a {
                Action::Dial { conn, address, .. } if address.url.starts_with("peer://") => {
                    // by dialable key, or by a LAN transport key a node listens with
                    let lan = self.lan_keys.get(&address.key).copied();
                    let target = lan.filter(|m| self.nodes[*m].online).or_else(|| (0..self.nodes.len()).find(|m| *m != n && self.nodes[*m].online && self.nodes[*m].sync.as_mut().and_then(|s| s.own_reach()).is_some_and(|r| r.dialable == address.key)));
                    let Some(m) = target.filter(|m| !self.blocked_peers.contains(&(n, *m)) && !self.blocked_peers.contains(&(*m, n))) else {
                        self.queue.push_back(Msg::Close(n, self.nodes[n].life, conn));
                        continue;
                    };
                    let (dc, pc) = (self.next_node_hub, self.next_node_hub + 1);
                    self.next_node_hub += 2;
                    self.plinks.insert((n, dc), (m, pc));
                    self.plinks.insert((m, pc), (n, dc));
                    self.queue.push_back(Msg::Up(n, self.nodes[n].life, conn, dc, address.key));
                    let now = self.node_now(m);
                    let out = self.nodes[m].hub.accept(now, pc, address.key, osis_host::Remote::key([0xd0 + n as u8; 32]));
                    self.node_hub_out(m, out);
                }
                Action::Dial { conn, address, .. } => {
                    let Some(s) = self.hosts.iter().position(|x| x.address.key == address.key).filter(|s| !self.blocked.contains(&(n, *s))) else {
                        self.queue.push_back(Msg::Close(n, self.nodes[n].life, conn));
                        continue;
                    };
                    let hc = self.next_hub_conn;
                    self.next_hub_conn += 1;
                    let dc = self.next_node_hub;
                    self.next_node_hub += 1;
                    self.links.insert((n, dc), (s, hc));
                    self.queue.push_back(Msg::Up(n, self.nodes[n].life, conn, dc, address.key));
                    let now = self.now_at(s);
                    let key = self.hosts[s].address.key;
                    let out = self.hosts[s].hub.accept(now, hc, key, osis_host::Remote::key([0xe0; 32]));
                    self.hub_out(s, out);
                }
                // a dial given up before it was up: its `Up` closes it (node sync)
                Action::Close { .. } => {}
                Action::Wake { at } => self.nodes[n].wake = Some(at),
                // peers are found by their current `reach.0`
                Action::Hub { conn, down } => downs.push((conn, down)),
                a @ (Action::Request { .. } | Action::Room { .. } | Action::Ended { .. }) => self.port.push((n, a)),
                Action::Reach | Action::Host(_) => {}
            }
        }
        if !downs.is_empty() {
            let now = self.node_now(n);
            let out = self.nodes[n].hub.down(now, downs);
            self.node_hub_out(n, out);
        }
    }

    /// Bytes node `n`'s hub sends on its connection `conn` to a host, through the link's faults
    /// and counters.
    fn host_send(&mut self, n: usize, conn: ConnId, mut bytes: Vec<u8>) {
        self.sent_bytes += bytes.len();
        let unpulled = self.unpulled.contains(&n) || self.links.get(&(n, conn)).is_some_and(|(s, _)| self.unpulled_at.contains(&(n, *s)));
        let mut d = osis_proto::FrameDecoder::new();
        d.push(&bytes);
        let mut kept = Vec::new();
        while let Ok(Some(body)) = d.next_frame() {
            if let Ok(m) = osis_proto::Message::decode(&body) {
                *self.sent_kinds.entry(m.kind()).or_default() += 1;
                let events = match &m {
                    osis_proto::Message::Stream(x) => &x.events[..],
                    osis_proto::Message::PullReply(r) => &r.events[..],
                    _ => &[],
                };
                for (label, e) in events {
                    if let osis_proto::Event::Added { blob_id, blob, wrap, stamp } = e {
                        *self.shown.entry((n, *label, *blob_id, stamp.map(|x| x.0))).or_default() += 1;
                        let held = self.links.get(&(n, conn)).and_then(|(s, _)| osis_proto::LabelStore::entry(&*self.hosts[*s].hub.store(), label, blob_id).ok().flatten());
                        if matches!(m, osis_proto::Message::Stream(_)) {
                            *self.pushed.entry((n, *label, *blob_id, stamp.map(|x| x.0))).or_default() += 1;
                        }
                        if matches!(m, osis_proto::Message::Stream(_)) && held.is_some_and(|h| h.wrap == *wrap && h.stamp == *stamp) {
                            *self.shown_held.entry((n, *label, *blob_id, stamp.map(|x| x.0))).or_default() += 1;
                        }
                        if let Some(b) = blob {
                            *self.crossed.entry(*blob_id).or_default() += b.len();
                        }
                    }
                }
                if let osis_proto::Message::Offer { items, .. } = &m {
                    for i in items {
                        if let osis_proto::msg::OfferItem::Deposit { label, blob, .. } = i {
                            *self.shown.entry((n, *label, osis_label::blob_id(blob), None)).or_default() += 1;
                        }
                    }
                }
                if let osis_proto::Message::FetchReply { items, .. } = &m {
                    for f in items {
                        if let Some((b, ..)) = &f.entry {
                            *self.crossed.entry(f.blob_id).or_default() += b.len();
                        }
                    }
                }
                if let osis_proto::Message::Delete { label, items, .. } = &m {
                    for i in items {
                        *self.deleted.entry((n, *label, i.blob)).or_default() += 1;
                    }
                }
                // a node's deposited entries reach the peer by its stream, or as Deposit
                // items: lost there
                if !self.lose_deposits.is_empty() {
                    let lost = |l: &osis_base::LabelId, b: &osis_base::BlobId| self.carries(l, b, &self.lose_deposits);
                    let added = |(l, e): &(osis_base::LabelId, osis_proto::Event)| matches!(e, osis_proto::Event::Added { blob_id, .. } if lost(l, blob_id));
                    match m {
                        osis_proto::Message::Stream(mut x) if x.events.iter().any(added) => {
                            x.events.retain(|x| !added(x));
                            kept.extend(osis_proto::encode_frame(&osis_proto::Message::Stream(x).encode()));
                            continue;
                        }
                        osis_proto::Message::PullReply(mut r) if r.events.iter().any(added) => {
                            r.events.retain(|x| !added(x));
                            kept.extend(osis_proto::encode_frame(&osis_proto::Message::PullReply(r).encode()));
                            continue;
                        }
                        osis_proto::Message::Offer { id, mut items } if items.iter().any(|i| matches!(i, osis_proto::msg::OfferItem::Deposit { label, blob, .. } if lost(label, &osis_label::blob_id(blob)))) => {
                            items.retain(|i| !matches!(i, osis_proto::msg::OfferItem::Deposit { label, blob, .. } if lost(label, &osis_label::blob_id(blob))));
                            if !items.is_empty() {
                                kept.extend(osis_proto::encode_frame(&osis_proto::Message::Offer { id, items }.encode()));
                            }
                            continue;
                        }
                        // or as fetched bodies
                        osis_proto::Message::FetchReply { id, mut items } => {
                            let labels = self.nodes[n].sync.as_ref().map(|s| s.shared_members(self.engine_conn(n, conn))).unwrap_or_default();
                            for f in &mut items {
                                if labels.iter().any(|l| lost(l, &f.blob_id)) {
                                    f.entry = None;
                                }
                            }
                            kept.extend(osis_proto::encode_frame(&osis_proto::Message::FetchReply { id, items }.encode()));
                            continue;
                        }
                        _ => {}
                    }
                }
                if unpulled {
                    match m {
                        osis_proto::Message::Stream(mut x) => {
                            x.events.retain(|(_, e)| !matches!(e, osis_proto::Event::Added { .. }));
                            if !x.events.is_empty() {
                                kept.extend(osis_proto::encode_frame(&osis_proto::Message::Stream(x).encode()));
                            }
                            continue;
                        }
                        osis_proto::Message::PullReply(mut r) => {
                            r.events.retain(|(_, e)| !matches!(e, osis_proto::Event::Added { .. }));
                            kept.extend(osis_proto::encode_frame(&osis_proto::Message::PullReply(r).encode()));
                            continue;
                        }
                        osis_proto::Message::FetchReply { id, mut items } => {
                            for f in &mut items {
                                f.entry = None;
                            }
                            kept.extend(osis_proto::encode_frame(&osis_proto::Message::FetchReply { id, items }.encode()));
                            continue;
                        }
                        _ => {}
                    }
                }
            }
            kept.extend(osis_proto::encode_frame(&body));
        }
        if unpulled || !self.lose_deposits.is_empty() {
            bytes = kept;
        }
        if let Some((s, hc)) = self.links.get(&(n, conn)).copied() {
            self.queue.push_back(Msg::ToHub(s, hc as ConnId, bytes));
        }
    }

    /// Bytes node `n`'s hub sends on its end `conn` of a peer link, through the link's faults.
    fn peer_send(&mut self, n: usize, conn: ConnId, mut bytes: Vec<u8>) {
        let (m, pc) = self.plinks[&(n, conn)];
        {
            let mut d = osis_proto::FrameDecoder::new();
            d.push(&bytes);
            while let Ok(Some(body)) = d.next_frame() {
                if let Ok(x) = osis_proto::Message::decode(&body) {
                    *self.peer_kinds.entry((n, x.kind())).or_default() += 1;
                }
            }
        }
        if let Some(t) = &mut self.tamper
            && self.tamper_link.is_none_or(|x| x == (n, m))
        {
            let mut d = osis_proto::FrameDecoder::new();
            d.push(&bytes);
            let mut kept = Vec::new();
            while let Ok(Some(body)) = d.next_frame() {
                match osis_proto::Message::decode(&body).ok().and_then(|x| t(&x)) {
                    Some(r) => kept.extend(osis_proto::encode_frame(&r.encode())),
                    None => kept.extend(osis_proto::encode_frame(&body)),
                }
            }
            bytes = kept;
        }
        if self.silent.contains(&(n, m)) {
            let mut d = osis_proto::FrameDecoder::new();
            d.push(&bytes);
            let mut kept = Vec::new();
            while let Ok(Some(body)) = d.next_frame() {
                if osis_proto::Message::decode(&body).is_ok_and(|x| x.is_request() || x.id() == 0) {
                    kept.extend(osis_proto::encode_frame(&body));
                }
            }
            bytes = kept;
        }
        if let Some((c, held)) = self.trickle.get_mut(&(n, m)) {
            *c = pc;
            let mut d = osis_proto::FrameDecoder::new();
            d.push(&bytes);
            let mut kept = Vec::new();
            while let Ok(Some(body)) = d.next_frame() {
                let reply = osis_proto::Message::decode(&body).is_ok_and(|x| !x.is_request() && x.id() != 0);
                if held.is_empty() && !reply {
                    kept.extend(osis_proto::encode_frame(&body));
                } else {
                    held.extend(osis_proto::encode_frame(&body));
                }
            }
            bytes = kept;
        }
        if !self.lose_deposits.is_empty() {
            let mut d = osis_proto::FrameDecoder::new();
            d.push(&bytes);
            let mut kept = Vec::new();
            while let Ok(Some(body)) = d.next_frame() {
                let lost = |l: &osis_base::LabelId, b: &osis_base::BlobId| self.carries(l, b, &self.lose_deposits);
                let added = |(l, e): &(osis_base::LabelId, osis_proto::Event)| matches!(e, osis_proto::Event::Added { blob_id, .. } if lost(l, blob_id));
                match osis_proto::Message::decode(&body) {
                    // a reader's own entries reach a co-reader by its stream: lost there
                    Ok(osis_proto::Message::PullReply(mut r)) => {
                        r.events.retain(|x| !added(x));
                        kept.extend(osis_proto::encode_frame(&osis_proto::Message::PullReply(r).encode()));
                    }
                    Ok(osis_proto::Message::Stream(mut x)) => {
                        x.events.retain(|x| !added(x));
                        if !x.events.is_empty() {
                            kept.extend(osis_proto::encode_frame(&osis_proto::Message::Stream(x).encode()));
                        }
                    }
                    Ok(osis_proto::Message::FetchReply { id, mut items }) => {
                        let labels = self.nodes[m].sync.as_ref().map(|s| s.shared_members(self.engine_conn(m, pc))).unwrap_or_default();
                        for f in &mut items {
                            if labels.iter().any(|l| lost(l, &f.blob_id)) {
                                f.entry = None;
                            }
                        }
                        kept.extend(osis_proto::encode_frame(&osis_proto::Message::FetchReply { id, items }.encode()));
                    }
                    _ => kept.extend(osis_proto::encode_frame(&body)),
                }
            }
            bytes = kept;
        }
        let life = self.nodes[m].life;
        if self.held.contains(&(n, m)) {
            self.held_messages.push(Msg::ToNode(m, life, pc, bytes));
        } else if let Some(Msg::ToNode(_, _, _, b)) = self.queue.iter_mut().rev().find(|x| matches!(x, Msg::Up(y, _, _, c, _) | Msg::ToNode(y, _, c, _) | Msg::Close(y, _, c) if *y == m && *c == pc)).filter(|x| self.batch_reads && matches!(x, Msg::ToNode(_, l, ..) if *l == life)) {
            b.extend(bytes);
        } else {
            self.queue.push_back(Msg::ToNode(m, life, pc, bytes));
        }
    }

    /// A hand peer connects to node `n`'s hub on the listener of key `local` as `peer`: its
    /// connection (the hub's ID) and the frames it was sent (the Hello).
    pub fn hand_accept(&mut self, n: usize, local: [u8; 32], peer: osis_transport::Peer) -> (ConnId, Vec<Vec<u8>>) {
        let hc = self.next_node_hub;
        self.next_node_hub += 1;
        self.hands.insert((n, hc), (Vec::new(), false));
        let now = self.node_now(n);
        let out = self.nodes[n].hub.accept(now, hc, local, osis_host::Remote { peer, relayed: false });
        self.node_hub_out(n, out);
        (hc, self.hand_sent(n, hc))
    }

    /// Bytes from hand peer connection `hc` of node `n` (`hand_accept`); returns the frames
    /// sent to it meanwhile.
    pub fn hand_input(&mut self, n: usize, hc: ConnId, bytes: Vec<u8>) -> Vec<Vec<u8>> {
        let now = self.node_now(n);
        let out = self.nodes[n].hub.input(now, hc, bytes);
        self.node_hub_out(n, out);
        self.hand_sent(n, hc)
    }

    /// The frames hand peer connection `hc` of node `n` was sent since last asked.
    pub fn hand_sent(&mut self, n: usize, hc: ConnId) -> Vec<Vec<u8>> {
        self.hands.get_mut(&(n, hc)).map(|(v, _)| std::mem::take(v)).unwrap_or_default()
    }

    /// The client-port actions node `n` emitted since last asked.
    pub fn take_port(&mut self, n: usize) -> Vec<Action> {
        let (mine, rest) = std::mem::take(&mut self.port).into_iter().partition(|(x, _)| *x == n);
        self.port = rest;
        mine.into_iter().map(|(_, a)| a).collect()
    }

    /// Whether node `n` closed hand peer connection `hc`.
    pub fn hand_closed(&self, n: usize, hc: ConnId) -> bool {
        self.hands.get(&(n, hc)).is_some_and(|(_, c)| *c)
    }

    /// The hand peer connection `hc` of node `n` ends from the peer's side.
    pub fn hand_close(&mut self, n: usize, hc: ConnId) {
        if let Some((_, c)) = self.hands.get_mut(&(n, hc)) {
            *c = true;
        }
        let out = self.nodes[n].hub.closed(hc);
        self.node_hub_out(n, out);
    }

    /// A hand peer's dialer `d` on node `n`'s hub connection `hc`: node `n` carries out `acts`,
    /// then frames go both ways until neither side has more (with `settle`, the network settles
    /// between rounds), starting with what `d` put out in `outs`; the messages `d`'s session
    /// handed up (answers to its requests, the node's own requests and pushes).
    pub fn hand_exchange(&mut self, n: usize, hc: ConnId, d: &mut osis_proto::examples::Dialer, acts: Vec<Action>, mut outs: Vec<osis_proto::SessionOutput>, settle: bool) -> Vec<osis_proto::Message> {
        self.actions(n, acts);
        let mut got = Vec::new();
        loop {
            let now = self.now();
            let mut frames = self.hand_sent(n, hc);
            got.extend(osis_proto::examples::up(&outs));
            for b in osis_proto::examples::frames(&outs) {
                frames.extend(self.hand_input(n, hc, b));
            }
            outs.clear();
            if settle {
                self.settle(100_000);
                frames.extend(self.hand_sent(n, hc));
            }
            if frames.is_empty() {
                return got;
            }
            for f in frames {
                outs.extend(d.bytes(now, f));
            }
        }
    }

    /// Node `n`'s wall clock (its hub runs on it).
    pub fn node_now(&self, n: usize) -> u64 {
        self.nodes[n].clock.now_wall_ms().0
    }

    /// Node `n`'s served session on its hub's connection `hc` (its engine's ID).
    pub fn served(&self, n: usize, hc: ConnId) -> ConnId {
        self.engine_conn(n, hc)
    }

    /// What node `n`'s hub handed out: bytes and closes on its peer links, ups to its node sync.
    fn node_hub_out(&mut self, n: usize, out: Vec<HubOutput>) {
        let mut ups = Vec::new();
        let mut moved = false;
        for o in out {
            match o {
                HubOutput::Moved => moved = true,
                HubOutput::Send(hc, bytes) if self.hands.contains_key(&(n, hc)) => {
                    let mut d = osis_proto::FrameDecoder::new();
                    d.push(&bytes);
                    while let Ok(Some(body)) = d.next_frame() {
                        if let Some((v, _)) = self.hands.get_mut(&(n, hc)) {
                            v.push(osis_proto::encode_frame(&body));
                        }
                    }
                }
                HubOutput::Close(hc) if self.hands.contains_key(&(n, hc)) => {
                    if let Some((_, c)) = self.hands.get_mut(&(n, hc)) {
                        *c = true;
                    }
                }
                HubOutput::Send(hc, bytes) => {
                    if self.plinks.contains_key(&(n, hc)) {
                        self.peer_send(n, hc, bytes);
                    } else if self.links.contains_key(&(n, hc)) {
                        self.host_send(n, hc, bytes);
                    }
                }
                HubOutput::Close(hc) => {
                    if let Some((m, c)) = self.plinks.remove(&(n, hc)) {
                        self.peer_closes += 1;
                        self.plinks.remove(&(m, c));
                        self.queue.push_back(Msg::Close(m, self.nodes[m].life, c));
                    } else if let Some((s, c)) = self.links.remove(&(n, hc)) {
                        let out = self.hosts[s].hub.closed(c);
                        self.hub_out(s, out);
                    }
                }
                HubOutput::Diagnostic(_) => {}
                HubOutput::Up(hc, up) => ups.push((hc, up)),
            }
        }
        if moved || !ups.is_empty() {
            self.feed(n, Event::Hub { ups });
        }
    }

    fn hub_out(&mut self, s: usize, out: Vec<HubOutput>) {
        let mut ups = Vec::new();
        let mut moved = false;
        for o in out {
            match o {
                HubOutput::Send(hc, bytes) => {
                    if let Some(((n, c), _)) = self.links.iter().find(|(_, (x, h))| *x == s && *h == hc) {
                        let bytes = match self.hide_blobs.get(n) {
                            Some(hide) => without_blobs(&bytes, hide, false),
                            None => bytes,
                        };
                        let mut bytes = match self.bare_blobs.get(n) {
                            Some(bare) => without_blobs(&bytes, bare, true),
                            None => bytes,
                        };
                        if let Some(t) = &mut self.host_tamper {
                            let mut d = osis_proto::FrameDecoder::new();
                            d.push(&bytes);
                            let mut kept = Vec::new();
                            while let Ok(Some(body)) = d.next_frame() {
                                match osis_proto::Message::decode(&body).ok().and_then(|x| t(&x)) {
                                    Some(r) => kept.extend(osis_proto::encode_frame(&r.encode())),
                                    None => kept.extend(osis_proto::encode_frame(&body)),
                                }
                            }
                            bytes = kept;
                        }
                        if let Some((tc, held)) = self.trickle_hosts.get_mut(&(s, *n)) {
                            *tc = *c;
                            if !held.is_empty() || !fetched_ids(&bytes).is_empty() {
                                held.extend(bytes);
                                continue;
                            }
                        }
                        // a connection delivers in order: what follows a held fetch reply waits too
                        // (a later reply arriving first says the peer skipped it)
                        let behind = self.held_messages.iter().any(|m| matches!(m, Msg::ToNode(x, _, y, b) if x == n && y == c && fetched_ids(b).iter().any(|b| self.hold_blobs.contains(b))));
                        let held = self.held_to.contains(n) || behind || (!self.hold_blobs.is_empty() && told_ids(&bytes).iter().any(|b| self.hold_blobs.contains(b)));
                        let m = Msg::ToNode(*n, self.nodes[*n].life, *c, bytes);
                        if self.held_hosts.contains(&s) || held {
                            self.held_messages.push(m);
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
                HubOutput::Up(hc, up) => ups.push((hc, up)),
                HubOutput::Moved => moved = true,
                HubOutput::Diagnostic(_) => {}
            }
        }
        if moved || !ups.is_empty() {
            self.host_feed(s, Event::Hub { ups });
        }
    }

    /// Feeds an event to host `s`'s node sync and carries out its actions: what it hands its
    /// hub, and its dials of nodes by their dialable keys (`SyncEngine::set_hosts`).
    pub fn host_feed(&mut self, s: usize, ev: Event) {
        let Some(sync) = self.hosts[s].sync.as_mut() else { return };
        let acts = sync.handle(ev);
        for a in acts {
            match a {
                Action::Hub { conn, down } => {
                    let now = self.now_at(s);
                    let out = self.hosts[s].hub.down(now, vec![(conn, down)]);
                    self.hub_out(s, out);
                }
                Action::Dial { conn, address, .. } => self.host_dial(s, conn, address.key),
                // a dial given up before it was up: its `Up` closes it (node sync)
                Action::Close { .. } => {}
                _ => {}
            }
        }
    }

    /// Delivers the peer and host bytes held back (`held` and `held_hosts` are cleared).
    pub fn release(&mut self) {
        self.held.clear();
        self.held_hosts.clear();
        self.held_to.clear();
        self.hold_blobs.clear();
        self.queue.extend(self.held_messages.drain(..));
    }

    /// Delivers what host `s` held back (`held_hosts`), and holds it no more.
    pub fn release_host(&mut self, s: usize) {
        self.held_hosts.remove(&s);
        let conns: BTreeSet<(usize, ConnId)> = self.links.iter().filter(|(_, (x, _))| *x == s).map(|(k, _)| *k).collect();
        let (go, stay) = std::mem::take(&mut self.held_messages).into_iter().partition(|m| matches!(m, Msg::ToNode(n, _, c, _) if conns.contains(&(*n, *c))));
        self.held_messages = stay;
        let go: Vec<Msg> = go;
        self.queue.extend(go);
    }

    /// Delivers queued messages until none are left (at most `max`, and `SETTLE_ROUNDS` rounds:
    /// what the messages of one round cause is the next).
    pub fn settle(&mut self, max: usize) {
        let mut i = 0;
        let (mut round, mut ends) = (0usize, self.queue.len());
        while let Some(m) = self.queue.pop_front() {
            i += 1;
            self.steps += 1;
            assert!(i < max, "no quiescence after {max} messages");
            self.deliver(m);
            if i >= ends {
                round += 1;
                ends = i + self.queue.len();
                assert!(round < SETTLE_ROUNDS, "no quiescence after {SETTLE_ROUNDS} rounds ({i} messages): a loop");
            }
        }
    }

    /// Delivers one queued message; whether there was one.
    pub fn step(&mut self) -> bool {
        let Some(m) = self.queue.pop_front() else { return false };
        self.steps += 1;
        self.deliver(m);
        true
    }

    pub fn queue_len(&self) -> usize {
        self.queue.len()
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

    /// Host `s` dials the node whose dialable key is `key` (its connection `conn`): up at once,
    /// or down when no such node is online (`blocked` holds only the node's dials).
    fn host_dial(&mut self, s: usize, conn: ConnId, key: [u8; 32]) {
        let target = (0..self.nodes.len()).find(|m| self.nodes[*m].online && self.nodes[*m].sync.as_mut().and_then(|x| x.own_reach()).is_some_and(|r| r.dialable == key));
        let Some(m) = target else {
            self.host_feed(s, Event::Down { conn });
            return;
        };
        let (hc, pc) = (self.next_hub_conn, self.next_node_hub);
        self.next_hub_conn += 1;
        self.next_node_hub += 1;
        self.links.insert((m, pc), (s, hc));
        let now = self.node_now(m);
        let accepted = self.nodes[m].hub.accept(now, pc, key, osis_host::Remote::key([0xe1; 32]));
        let now = self.now_at(s);
        let dialed = self.hosts[s].hub.dial(now, hc, key, osis_host::Remote::key(key));
        self.host_feed(s, Event::Up { conn, hub: hc });
        self.hub_out(s, dialed);
        self.node_hub_out(m, accepted);
    }

    fn deliver(&mut self, m: Msg) {
        match m {
            Msg::Up(n, l, ..) | Msg::ToNode(n, l, _, _) | Msg::Close(n, l, _) if l != self.nodes[n].life => {}
            Msg::Up(n, _, c, dc, key) if !self.nodes[n].online => {
                // up while it went offline: it never comes up (dials it makes meanwhile fail too)
                self.plinks.remove(&(n, dc)).map(|(m, pc)| self.plinks.remove(&(m, pc)));
                self.links.remove(&(n, dc));
                let _ = key;
                if let Some(sy) = self.nodes[n].sync.as_mut() {
                    let mut down = vec![c];
                    while let Some(d) = down.pop() {
                        down.extend(sy.handle(Event::Down { conn: d }).iter().filter_map(|a| if let Action::Dial { conn, .. } = a { Some(*conn) } else { None }));
                    }
                }
            }
            Msg::Up(n, _, c, dc, key) => {
                let now = self.node_now(n);
                let out = self.nodes[n].hub.dial(now, dc, key, osis_host::Remote::key(key));
                self.feed(n, Event::Up { conn: c, hub: dc });
                self.node_hub_out(n, out);
            }
            Msg::ToNode(n, _, c, b) if c >= HUB_BASE => {
                if std::env::var_os("OSIS_SYNC_TRACE").is_some() {
                    let mut d = osis_proto::FrameDecoder::new();
                    d.push(&b);
                    while let Ok(Some(body)) = d.next_frame() {
                        eprintln!("node {n} conn {c} recv {}", format!("{:?}", osis_proto::Message::decode(&body)).chars().take(300).collect::<String>());
                    }
                }
                if self.links.contains_key(&(n, c)) {
                    if let Some(told) = self.told.get_mut(&n) {
                        told.extend(told_ids(&b));
                    }
                    if let Some(f) = self.fetched.get_mut(&n) {
                        f.extend(fetched_ids(&b));
                    }
                    if self.deaf.contains(&n) {
                        return;
                    }
                }
                let now = self.node_now(n);
                let out = self.nodes[n].hub.input(now, c, b);
                self.node_hub_out(n, out);
            }
            Msg::Close(n, _, c) if c >= HUB_BASE => {
                let out = self.nodes[n].hub.closed(c);
                self.node_hub_out(n, out);
            }
            Msg::ToHub(s, hc, b) => {
                let now = self.now_at(s);
                let t = std::time::Instant::now();
                let out = self.hosts[s].hub.input(now, hc, b);
                self.hub_busy += t.elapsed();
                self.hub_out(s, out);
            }
            Msg::ToNode(..) => unreachable!("bytes go to a node's hub"),
            // a dial that failed
            Msg::Close(n, _, c) => self.feed(n, Event::Down { conn: c }),
        }
        for s in 0..self.hosts.len() {
            let now = self.now_at(s);
            if self.hosts[s].hub.next_due(now).is_some_and(|t| t <= now) {
                let out = self.hosts[s].hub.tick(now);
                self.hub_out(s, out);
            }
        }
        for n in 0..self.nodes.len() {
            let now = self.node_now(n);
            if self.nodes[n].hub.next_due(now).is_some_and(|t| t <= now) {
                let out = self.nodes[n].hub.tick(now);
                self.node_hub_out(n, out);
            }
        }
    }

    /// Every online node looks at its engine, then everything settles.
    pub fn run(&mut self) {
        osis_base::testenv::checkpoint();
        for n in 0..self.nodes.len() {
            self.feed(n, Event::Local);
        }
        for s in 0..self.hosts.len() {
            self.host_feed(s, Event::Local);
        }
        self.settle(200_000);
        for n in 0..self.nodes.len() {
            self.feed(n, Event::Local);
        }
        self.settle(200_000);
    }

    /// Moves time on by `ms`, firing node wakes and host ticks, then settles.
    pub fn advance(&mut self, ms: u64) {
        self.tick(ms);
        self.run();
    }

    /// `advance`, leaving what the wakes caused queued (`round`).
    pub fn tick(&mut self, ms: u64) {
        self.clock.advance(ms);
        for s in 0..self.hosts.len() {
            let now = self.now_at(s);
            let out = self.hosts[s].hub.tick(now);
            self.hub_out(s, out);
        }
        for n in 0..self.nodes.len() {
            let now = self.node_now(n);
            let out = self.nodes[n].hub.tick(now);
            self.node_hub_out(n, out);
        }
        for n in 0..self.nodes.len() {
            self.feed(n, Event::Tick);
        }
        for s in 0..self.hosts.len() {
            self.host_feed(s, Event::Tick);
        }
    }

    /// Delivers every commit `from` holds to `to` directly (pairing stand-in).
    pub fn pair(&mut self, from: usize, to: usize) {
        let ids = self.engine(from).commit_ids();
        for id in ids {
            let pk = self.engine(from).package(&id).unwrap().unwrap();
            let _ = self.engine(to).ingest(&pk.bytes, pk.blobs);
        }
    }

    /// A group whose first admin is node `admin`, `holders` granted with their roles, then given
    /// secrets of its own with its sync ID at `hosts` (the rotation boxing every holder, a deposit
    /// seed; spec/sync.md §2); the setup commits delivered to the holders directly.
    pub fn group(&mut self, admin: usize, holders: &[(usize, Role)], hosts: &[usize]) -> Tid {
        let addrs: Vec<Address> = hosts.iter().map(|s| self.hosts[*s].address.clone()).collect();
        self.group_at(admin, holders, addrs)
    }

    /// `group` with host addresses.
    pub fn group_at(&mut self, admin: usize, holders: &[(usize, Role)], addrs: Vec<Address>) -> Tid {
        for (m, _) in holders {
            self.pair(*m, admin);
        }
        let me = self.engine(admin).me();
        let e = self.engine(admin);
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
        e.commit(m).unwrap();
        for (n, r) in holders {
            let t = self.tid(*n);
            // bare edges: the rotation below boxes every holder before any pass (a grant by hand)
            set_edge(self.engine(admin), g, t, *r);
        }
        self.engine(admin).give_own_secrets_on(&g, &addrs).unwrap();
        for (m, _) in holders {
            self.pair(admin, *m);
        }
        g
    }

    /// A content thing in group `g` written by node `n`: created under `admin`, listed in
    /// `group.0` of `g`.
    pub fn item(&mut self, n: usize, g: Tid, admin: Tid, v: &str) -> Tid {
        let e = self.engine(n);
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, admin);
        m.set(t, &REG, &s(v)).unwrap();
        let mut items = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
        items.items.insert(t);
        m.set(g, &ct::GROUP, &items).unwrap();
        e.commit(m).unwrap();
        t
    }

    /// Node `n`, an admin of `t`, writes `t`'s setting keeping `history` for each aspect named
    /// (spec/commits.md §5 The setting): its commit.
    pub fn keep(&mut self, n: usize, t: Tid, entries: &[(&str, osis_schema::History)]) -> CommitId {
        let x: ct::RetentionSetting = entries.iter().map(|(a, h)| (osis_base::Ak::new(*a).unwrap(), ct::RetentionEntry { history: Some(*h), ..Default::default() })).collect();
        let mut m = Mutation::new();
        m.set(t, &ct::RETENTION, &x).unwrap();
        self.engine(n).commit(m).unwrap().unwrap()
    }

    pub fn write(&mut self, n: usize, t: Tid, v: &str) -> CommitId {
        let mut m = Mutation::new();
        m.set(t, &REG, &s(v)).unwrap();
        self.engine(n).commit(m).unwrap().unwrap()
    }

    /// As `write`, purgeable by its author too (`author_or_admin`): its author holds a level-2
    /// delete key for it.
    pub fn write_own(&mut self, n: usize, t: Tid, v: &str) -> CommitId {
        let mut m = Mutation::new();
        m.set(t, &REG, &s(v)).unwrap();
        m.retention(t, &REG, osis_schema::Retention { by: osis_base::PurgeBy::AuthorOrAdmin }).unwrap();
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

    /// The engine events node `n` sends from now on, commit events among them.
    pub fn listen(&mut self, n: usize) -> std::sync::mpsc::Receiver<osis_node::Event> {
        self.engine(n).watch_commits();
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
        self.group_labels(n).into_iter().next().unwrap().1.id
    }

    /// Node `n`'s synced labels without its account's home label.
    pub fn group_labels(&mut self, n: usize) -> Vec<(Tid, std::sync::Arc<osis_node::labeling::GroupLabel>)> {
        let home = self.engine(n).account().unwrap().map(|(_, d)| d);
        self.sync(n).labels().into_iter().filter(|(g, _)| Some(*g) != home).collect()
    }

    /// Names an inbox for group `g` in its `keys.0` other than its own label (one nobody opens),
    /// so its label is no inbox at its readers (spec/sync.md §2): tests of a label's unopened
    /// entries that are no inbox deposits.
    pub fn name_inbox_elsewhere(&mut self, n: usize, g: Tid) {
        let e = self.engine(n);
        let mut m = Mutation::new();
        let inbox = ct::Inbox { label: osis_base::LabelId([0x1b; 16]), hosts: Vec::new() };
        m.op(g, &ct::KEYS, PathOp { path: vec![PathSeg::Field(4)], op: Op::Set(Some(inbox).to_value()) }).unwrap();
        e.commit(m).unwrap();
    }

    /// Live entry IDs the host holds under a label.
    pub fn host_ids(&self, s: usize, l: &osis_base::LabelId) -> Vec<osis_base::BlobId> {
        self.hosts[s].hub.store().live_ids(l).unwrap()
    }

    /// Peer `s`'s node log end: the position its last event took (an entry's earlier event is
    /// replaced by its next, so only this shows that something was logged).
    pub fn log_end(&self, s: usize) -> u64 {
        self.hosts[s].hub.store().node_log(|t| t.log_end()).unwrap()
    }

    /// What peer `s`'s node log holds of `l`, in log order: the entries it shows added and
    /// those it shows removed (deletes and expiries; an entry's earlier events compact away).
    pub fn logged_at(&self, s: usize, l: &osis_base::LabelId) -> (Vec<osis_base::BlobId>, Vec<osis_base::BlobId>) {
        let (mut added, mut removed) = (Vec::new(), Vec::new());
        let mut at = 0;
        loop {
            let (page, next, more) = self.hosts[s].hub.store().node_log(|t| t.log_after(at, 1 << 16)).unwrap();
            for e in page {
                match e.event {
                    osis_store::NodeEvent::Added(x, id) if x == *l => added.push(id),
                    osis_store::NodeEvent::Deleted { label, blob, .. } if label == *l => removed.push(blob),
                    _ => {}
                }
            }
            if !more {
                return (added, removed);
            }
            at = next;
        }
    }

    /// What remains of `l`'s deposit budget at peer `s` (spec/sync.md §5, spec/wire.md §2: 64
    /// entries plus 4 per claim slot of the head's set, of `DEPOSIT_ENTRY_BYTES` each, times the
    /// policy's `deposit_factor`), less its deposited entries: (entries, bytes).
    pub fn deposit_room(&self, s: usize, l: &osis_base::LabelId) -> (u64, u64) {
        let store = self.hosts[s].hub.store();
        let head = osis_proto::LabelStore::head(&*store, l).unwrap().unwrap();
        let slots = osis_proto::LabelStore::claim_set(&*store, l, &head).unwrap().map_or(0, |c| c.claims.len() as u64);
        let max = store.policy().deposit_factor.max(1) * (64 + 4 * slots);
        let (mut n, mut bytes) = (0, 0);
        for id in osis_proto::LabelStore::live_ids(&*store, l).unwrap() {
            if let Some(m) = osis_proto::LabelStore::entry(&*store, l, &id).unwrap().filter(|m| m.stamp.is_none()) {
                n += 1;
                bytes += m.size;
            }
        }
        (max.saturating_sub(n), (max * osis_host::DEPOSIT_ENTRY_BYTES).saturating_sub(bytes))
    }

    /// A Deposit item reaching peer `s` for `l`, taken by its store's Deposit rules (spec/sync.md
    /// §5), then the net runs.
    pub fn deposit_at(&mut self, s: usize, l: &osis_base::LabelId, blob: &[u8], wrap: [u8; osis_crypto::WRAP_LEN], sig: &osis_crypto::Signature) -> osis_proto::Code {
        let now = self.now_at(s);
        let code = {
            let mut store = self.hosts[s].hub.store();
            let k = osis_proto::LabelStore::head_keys(&*store, l).unwrap().unwrap();
            osis_proto::session::deposit(&mut *store, now, l, &k, blob, wrap, sig, &mut false).unwrap().0
        };
        self.run();
        code
    }

    /// The entries of `l` peer `s`'s store counts against its caps (role entries are outside them).
    pub fn capped_entries(&self, s: usize, l: &osis_base::LabelId) -> u64 {
        self.hosts[s].hub.store().capped(l).unwrap().0
    }

    /// The bytes of `l` peer `s`'s store counts against its caps.
    pub fn capped_bytes(&self, s: usize, l: &osis_base::LabelId) -> u64 {
        self.hosts[s].hub.store().capped(l).unwrap().1
    }

    /// Whether node `n`'s status shows label `l` not caught up at a source it has (a peer lacks
    /// something `n` placed there): sources, none of them stranded, and fewer idle.
    pub fn lags(&mut self, n: usize, l: &osis_base::LabelId) -> bool {
        self.sync(n).label_status().into_iter().find(|s| s.label == *l).is_some_and(|s| !s.stranded && s.sources > 0 && s.idle < s.sources)
    }

    /// Whether node `n`'s status names a node that will not take label `l`, or not all of it (a
    /// full peer: `LabelStatus::refused_by`).
    pub fn refused_at(&mut self, n: usize, l: &osis_base::LabelId) -> bool {
        self.sync(n).label_status().into_iter().find(|s| s.label == *l).is_some_and(|s| !s.refused_by.is_empty())
    }

    /// Host `s` sends node `n` message `m` on their connection (a hostile host's own frame).
    pub fn host_inject(&mut self, s: usize, n: usize, m: &osis_proto::Message) {
        let ec = self.conn_to(n, s).unwrap();
        let c = self.link_conn(n, ec);
        let bytes = self.in_order(n, ec, osis_proto::encode_frame(&m.encode()), true);
        self.queue.push_back(Msg::ToNode(n, self.nodes[n].life, c, bytes));
    }

    /// Node `n`'s connection to host `s` (its engine's ID), if up (to inject a hostile host's
    /// frames).
    pub fn conn_to(&self, n: usize, s: usize) -> Option<ConnId> {
        self.links.iter().find(|((x, _), (y, _))| *x == n && *y == s).map(|((_, c), _)| self.engine_conn(n, *c))
    }

    pub fn labels_at(&self, s: usize) -> Vec<osis_base::LabelId> {
        self.hosts[s].hub.store().labels_after(None, 1000).unwrap()
    }
}

pub static TEST: osis_schema::StaticSchema = osis_schema::StaticSchema::new(
    "test.osis",
    r#"
revision 1;
aspect t:reg.0: string;
purgeable_by(writer) aspect t:gone.0: string;
expires(1h) aspect t:brief.0: string;
aspect t:blob.0: blob;
aspect t:big.0: map<string, string>;
purgeable_by(writer) aspect t:gonemap.0: map<string, string>;
purgeable_by(writer) aspect t:gonetext.0: text;
expires(1h) aspect t:briefmap.0: map<string, string>;
aspect t:seq.0: text;
aspect t:items.0: list<string>;
"#,
);

pub const REG: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:reg.0", &TEST);
pub const GONE: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:gone.0", &TEST);
pub const BRIEF: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:brief.0", &TEST);
pub const BLOB: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:blob.0", &TEST);
pub const BIG: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:big.0", &TEST);
/// Purge on replace (`PURGE`) where a test's setting says so.
pub const PURGE: osis_schema::History = osis_schema::History::PurgeOnReplace;
pub const GONEMAP: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:gonemap.0", &TEST);
pub const GONETEXT: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:gonetext.0", &TEST);
pub const BRIEFMAP: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:briefmap.0", &TEST);
pub const SEQ: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:seq.0", &TEST);
pub const ITEMS: osis_schema::Aspect<Value> = osis_schema::Aspect::new("t:items.0", &TEST);

/// The ephemeral signal parts fired among the events received so far (history entries nobody
/// holds): (thing, aspect, value, author).
pub fn fired(rx: &std::sync::mpsc::Receiver<osis_node::Event>) -> Vec<(Tid, String, Value, Tid)> {
    let mut out = Vec::new();
    while let Ok(e) = rx.try_recv() {
        if let osis_node::Event::Commits(ch) = e {
            for c in ch.iter() {
                let Some(row) = &c.fired else { continue };
                for p in row.parts.iter().filter(|p| p.tid == c.tid && p.ak == c.ak) {
                    if let osis_node::engine::listing::PartBody::Held(Some(v)) = &p.body {
                        out.push((c.tid, c.ak.as_str().to_string(), v.clone(), row.node));
                    }
                }
            }
        }
    }
    out
}


pub fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn recipient(e: &mut Engine, t: Tid, role: Role) -> Recipient {
    if e.core.is_account(&t) {
        return Recipient { holder: t, role, keys: e.account_holder_keys(&t).unwrap() };
    }
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

/// A bare edge write: no secrets with it, so the holder gets them only from a later repair (a
/// plain thing's own secrets, `reseal` at a complete pass). Setting up access: `Net::grant`.
pub fn set_edge(e: &mut Engine, thing: Tid, holder: Tid, role: Role) -> CommitId {
    let mut m = Mutation::new();
    let edge = ct::Edge { role, until: None, invite: None, tied: None };
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
    // an explicit removal: with no frontier it would be a finalize (spec/permissions.md §2)
    m.frontier(ct::Frontier::default().to_value());
    let ts = m.take_ts(e);
    let blind = m.take_blind(e);
    let names = osis_keys::Names { departs: Some(osis_keys::Own { ts: ts.to_u64(), author: e.me(), blind }), ..osis_keys::Names::default() };
    rotation_ops(e, &mut m, a, recipients, rng, false, &names);
    e.commit(m).unwrap().unwrap()
}

fn rotation_ops(e: &mut Engine, m: &mut Mutation, a: Tid, recipients: &[Recipient], rng: u64, seed: bool, names: &osis_keys::Names) {
    let roles = BTreeSet::from(Role::ALL);
    let view = e.epochs(&a).unwrap();
    let state = e.get_typed(&a, &ct::SECRETS).unwrap().unwrap_or_default();
    // seeded per thing too: two things rotated with one seed get distinct secrets (equal ones
    // would give their labels one ID)
    let rng = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        (a, rng).hash(&mut h);
        h.finish()
    };
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
        let f = osis_keys::aspects::keyset_field(*role);
        m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(f)], op: Op::Replace(Some(ks.clone()).to_value()) }).unwrap();
    }
    if seed {
        m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(5)], op: Op::Replace(Some([0x5e; 32]).to_value()) }).unwrap();
    }
}

pub fn recipients_of(e: &mut Engine, holders: &[(Tid, Role)]) -> Vec<Recipient> {
    holders.iter().map(|(t, r)| recipient(e, *t, *r)).collect()
}

/// `holder`'s recipient for `role` with its KEM keys swapped for this engine's own: the box is
/// there, and `holder` cannot open it (a key it no longer holds, as after its own rotation).
pub fn unopenable_recipient(e: &mut Engine, holder: Tid, role: Role) -> Recipient {
    let wrong = e.identity().keys().kem.public().clone();
    let mut r = recipient(e, holder, role);
    match &mut r.keys {
        HolderKeys::KeyActor { kem, seed } => (*kem, *seed) = (wrong, None),
        HolderKeys::Account { kem, keys, .. } => (*kem, *keys) = (wrong, None),
        HolderKeys::Actor { keysets, own } => {
            keysets.values_mut().flatten().for_each(|k| k.1 = wrong.clone());
            own.clear();
        }
    }
    r
}

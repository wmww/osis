//! Where background sync runs (`Runtime`, `Lan`) and how a node's sync outputs are carried out:
//! the handle holds one `osis_sync::Node` under its lock and steps it after each write
//! (`Input::Wrote`) and on each input its links report; `Net` carries out what a step gives:
//! with no network (dials fail at once), through the driver task over the product's transports
//! (`TransportLinks`), or through a test's in-process fabric (`ManualNet`).

use crate::error::{Error, Result};
use crate::handle::{Locked, WeakOsis};
use crate::watch::lock;
use osis_base::{Clock, ManualClock, WallMs};
use osis_sync::{ConnId, Input, Links, NodeKey, Out, TransportLinks, apply};
use osis_transport::{StaticSecret, Transport};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

/// Where background sync runs.
#[derive(Clone, Debug, Default)]
pub enum Runtime {
    /// No network: everything works locally; calls that wait for another node fail `Network`.
    #[default]
    None,
    /// The app's tokio runtime (multi-thread recommended: osis's work blocks its thread for a moment).
    Tokio(tokio::runtime::Handle),
    /// A small tokio runtime of osis's own.
    Own,
}

/// Whether a node with direct sync on (`Config::direct_sync`) finds other nodes on its local
/// network and is found by them, by a small UDP datagram it broadcasts there every so often.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lan {
    /// Announce on the local network.
    On {
        /// Further addresses to announce to, ones a broadcast does not reach, such as nodes of a
        /// routed mesh (each `<ip>:47380` unless it listens elsewhere).
        also_announce_to: Vec<std::net::SocketAddr>,
    },
    /// Stay quiet on the local network.
    Off,
}

impl Default for Lan {
    fn default() -> Lan {
        Lan::On { also_announce_to: Vec::new() }
    }
}

/// Runs `f`, which blocks; inside a multi-thread runtime in place, so that worker's tasks move
/// to others meanwhile.
pub(crate) fn blocking<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
    }
}

/// What the handle asks of its driver task.
pub(crate) enum Ctl {
    /// A step's outputs, in step order.
    Out(Vec<Out>),
    /// Listen under `secret` at `urls` in place of the URLs before (none: the same ones), and at
    /// the client socket `socket` if given (it stays once given); every listener starts again.
    Listen { urls: Option<Vec<String>>, socket: Option<String>, secret: StaticSecret, reply: oneshot::Sender<std::result::Result<Vec<osis_label::Address>, String>> },
}

/// Where the driver task runs and what it hears from the handle.
pub(crate) type DriverStart = (tokio::runtime::Handle, mpsc::UnboundedReceiver<Ctl>);

/// osis's own runtime, shut down without waiting when the node goes (from any thread, its own
/// workers included).
pub(crate) struct OwnRuntime(Option<tokio::runtime::Runtime>);

impl Drop for OwnRuntime {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            rt.shutdown_background();
        }
    }
}

/// Where a node's outputs go.
pub(crate) enum Net {
    /// No network: a dial fails at once (`Input::Down`), a wake runs at the next call.
    Off,
    /// The driver task (`drive`) over the product's transports.
    Driver { ctl: mpsc::UnboundedSender<Ctl>, _own: OwnRuntime },
    /// A test's in-process fabric, this node its `index`.
    Manual { net: ManualNet, index: usize },
}

impl Net {
    /// The net for `rt`, with the handle of the runtime the driver task runs on.
    pub(crate) fn new(rt: &Runtime, manual: Option<&ManualNet>) -> Result<(Net, Option<DriverStart>)> {
        if let Some(m) = manual {
            return Ok((Net::Manual { net: m.clone(), index: usize::MAX }, None));
        }
        let (handle, own) = match rt {
            Runtime::None => return Ok((Net::Off, None)),
            Runtime::Tokio(h) => (h.clone(), None),
            Runtime::Own => {
                let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("osis-sync").enable_all().build().map_err(|e| Error::Network(e.to_string()))?;
                (rt.handle().clone(), Some(rt))
            }
        };
        let (ctl, rx) = mpsc::unbounded_channel();
        Ok((Net::Driver { ctl, _own: OwnRuntime(own) }, Some((handle, rx))))
    }

    /// Whether another node can ever be reached.
    pub(crate) fn online(&self) -> bool {
        !matches!(self, Net::Off)
    }

    /// Carries out the outputs a step under the lock gave (`l.out`), in order. Off, a dial fails
    /// at once: its `Down` is handled here, under the same lock.
    pub(crate) fn carry(&self, l: &mut Locked) {
        loop {
            let out = std::mem::take(&mut l.out);
            if out.is_empty() {
                return;
            }
            match self {
                Net::Off => {
                    let mut downs = Vec::new();
                    for o in out {
                        match o {
                            Out::Dial(conn, _) => downs.push(conn),
                            Out::Wake(at) => l.wake = Some(at),
                            Out::Send(..) | Out::Close(_) => {}
                        }
                    }
                    for conn in downs {
                        let o = l.node.handle(Input::Down { conn });
                        l.out.extend(o);
                    }
                }
                Net::Driver { ctl, .. } => {
                    // the task gone means the node is closing: nothing is carried out any more
                    let _ = ctl.send(Ctl::Out(out));
                }
                Net::Manual { net, index } => net.queue(*index, out),
            }
        }
    }

    /// Listens under `secret` (see `Ctl::Listen`); the addresses of `urls`.
    pub(crate) fn listen(&self, urls: Option<Vec<String>>, socket: Option<String>, secret: StaticSecret) -> Result<Vec<osis_label::Address>> {
        match self {
            Net::Off => Err(Error::Network("no runtime: listening needs one (Config.runtime)".into())),
            Net::Manual { net, index } => {
                let key = secret.public_key();
                net.listen(*index, key);
                Ok(urls.unwrap_or_default().into_iter().map(|url| osis_label::Address { url, key }).collect())
            }
            Net::Driver { ctl, .. } => {
                let (tx, rx) = oneshot::channel();
                ctl.send(Ctl::Listen { urls, socket, secret, reply: tx }).map_err(|_| Error::Network("sync stopped".into()))?;
                match blocking(|| rx.blocking_recv()) {
                    Ok(r) => r.map_err(Error::Network),
                    Err(_) => Err(Error::Network("sync stopped".into())),
                }
            }
        }
    }
}

/// What the driver task does before its loop: listen (direct sync), discover (LAN).
pub(crate) struct Start {
    listen: Option<(Vec<String>, StaticSecret)>,
    discover: bool,
}

impl crate::Osis {
    /// Puts the node on its network: the driver task started (listening with direct sync,
    /// discovering with LAN on), or this node placed on a test's network.
    pub(crate) fn go_online(&self, cfg: &crate::Config, driver: Option<DriverStart>) -> Result<()> {
        let secret = self.locked(|l| StaticSecret::from_bytes(*l.secret.as_bytes()));
        match &self.inner.net {
            Net::Off => {}
            Net::Manual { net, index } => {
                net.bind(*index, self.downgrade());
                if cfg.direct_sync {
                    net.listen(*index, secret.public_key());
                }
            }
            Net::Driver { .. } => {
                let Some((handle, rx)) = driver else { return Ok(()) };
                let relays: Vec<String> = cfg.relays.iter().filter_map(crate::share::Address::relay_item).collect();
                let mut lan = osis_transport::lan::LanConfig::default();
                if let Lan::On { also_announce_to } = &cfg.lan {
                    lan.to.extend(also_announce_to.iter().copied());
                }
                let multi = osis_transport::Multi { mem: cfg.app.internals.transport.clone(), quic: Some(osis_transport::Quic::new()), p2p: Some(osis_transport::P2p::new(osis_transport::QuicUdp::new()).lan(lan)), unix: Some(osis_transport::Unix) };
                let clock: Arc<dyn Clock> = self.inner.clock.clone();
                let links = TransportLinks::new(Arc::new(multi), clock);
                let start = Start { listen: cfg.direct_sync.then(|| (vec![osis_transport::peer_url(&relays)], secret)), discover: cfg.direct_sync && matches!(cfg.lan, Lan::On { .. }) };
                let db = self.downgrade();
                handle.spawn(drive(db, links, rx, start));
            }
        }
        Ok(())
    }

    /// Serves clients on this store's own unix socket: processes of this uid that connect
    /// (`Osis::connect_socket` with this store's directory) act as this node's main actor, with
    /// no authentication (there is no security boundary between them); the kernel refuses
    /// others. `Invalid` for a store in memory (no directory names it); `Storage` when the
    /// socket's directory is not safely this user's; `Network` without a runtime.
    pub fn listen_socket(&self) -> Result<()> {
        let Some(dir) = &self.inner.store_dir else { return Err(Error::Invalid("a store in memory has no client socket".into())) };
        let url = osis_transport::unix::url_of(&crate::sources::socket_path(dir)?);
        let secret = self.locked(|l| StaticSecret::from_bytes(*l.secret.as_bytes()));
        self.inner.net.listen(None, Some(url), secret).map(drop)
    }

    /// Listens at `urls` (`quic://example.org:4040`) under this node's one key: other nodes sync
    /// with it there, and clients use it as actors they authenticate for (`add_client`). Returns
    /// each address (with its real port) to hand out. Replaces the listeners of an earlier call;
    /// no URL stops them. Needs a runtime. Listening does not last past this process: call it at
    /// each start.
    pub fn listen(&self, urls: &[crate::Url]) -> Result<Vec<crate::Address>> {
        let secret = self.locked(|l| StaticSecret::from_bytes(*l.secret.as_bytes()));
        let a = self.inner.net.listen(Some(urls.iter().map(ToString::to_string).collect()), None, secret)?;
        Ok(a.into_iter().map(crate::Address).collect())
    }

    /// Gives this node a new key, so a new address for direct sync and for `listen`: every
    /// listener moves to it, and nodes that knew the old one reach this node again through
    /// what the account tells them (`reach.0`). Links made before stop reaching it directly. Never
    /// done by itself.
    pub fn rotate_peer_address(&self) -> Result<()> {
        let secret = self.locked(|l| -> Result<StaticSecret> {
            let s = crate::handle::new_node_secret(l.engine())?;
            let mut c = l.node.config().clone();
            c.key = Some(osis_sync::NodeKey(s.public_key()));
            l.node.set_config(c);
            l.secret = StaticSecret::from_bytes(*s.as_bytes());
            l.handle(Input::Wrote);
            Ok(s)
        })?;
        match &self.inner.net {
            Net::Off => Ok(()),
            net => net.listen(None, None, secret).map(drop),
        }
    }
}

/// The driver task: steps the node on each input its links report (blocking work in place, the
/// lock held only for the step) and carries out what each step gave, until the node goes.
async fn drive<T: Transport>(db: WeakOsis, mut links: TransportLinks<T>, mut rx: mpsc::UnboundedReceiver<Ctl>, start: Start) {
    let (mut urls, mut socket) = (Vec::new(), None::<String>);
    // a failed start is the node's to report: it syncs with what it dials meanwhile
    if let Some((u, secret)) = start.listen {
        let _ = links.listen(&u, &secret).await;
        urls = u;
    }
    if start.discover {
        let _ = links.discover().await;
    }
    loop {
        tokio::select! {
            input = links.next() => {
                let main = matches!(input, Input::Up { conn, .. } if links.unix(conn));
                let Some(db) = db.hold() else { return };
                blocking(|| db.step(input, main));
            }
            c = rx.recv() => match c {
                None => return,
                Some(Ctl::Out(out)) => apply(out, &mut links),
                Some(Ctl::Listen { urls: new, socket: sock, secret, reply }) => {
                    links.stop_background();
                    let asked = new.is_some();
                    if let Some(u) = new {
                        urls = u;
                    }
                    if sock.is_some() {
                        socket = sock;
                    }
                    let mut r = links.listen(&urls, &secret).await.map_err(|e| e.to_string());
                    if let (Some(s), true) = (&socket, r.is_ok()) {
                        r = links.listen(std::slice::from_ref(s), &secret).await.map(|_| Vec::<osis_label::Address>::new()).map_err(|e| e.to_string()).and(r);
                    }
                    if start.discover {
                        let _ = links.discover().await;
                    }
                    let _ = reply.send(if asked { r } else { r.map(|_| Vec::new()) });
                }
            },
        }
    }
}

/// A test network: every node made with it (`internals::Knobs::net`) reaches the others by key,
/// in one process, deterministically, on one manual clock. Nothing moves until `run` (or
/// `advance`) delivers: each delivery steps one node under its lock, and what the step gives is
/// queued here. Sync never knows it runs on this: the nodes' outputs are their own.
#[derive(Clone)]
pub struct ManualNet(Arc<Mutex<Fabric>>);

struct Fabric {
    clock: Arc<ManualClock>,
    nodes: Vec<(Option<WeakOsis>, Option<[u8; 32]>)>,
    queue: VecDeque<(usize, Input)>,
    wakes: BTreeMap<usize, WallMs>,
    /// Each live connection end: (node, conn) -> the other end.
    links: BTreeMap<(usize, ConnId), (usize, ConnId)>,
    /// Bytes each end sent so far (what the transport took).
    sent: BTreeMap<(usize, ConnId), u64>,
    accepted: u64,
    /// Nodes cut off from the network: dials to and from them fail.
    offline: std::collections::BTreeSet<usize>,
    /// Connections that came up at each node so far (tests: what dialed).
    ups: BTreeMap<usize, usize>,
    /// Deliveries so far, against `cap`.
    deliveries: u64,
    cap: u64,
}

/// Deliveries one `run` may make before it panics as a storm. At 0 nothing runs; at infinity a
/// storm hangs the test instead of failing it.
pub const MANUAL_CAP: u64 = 20_000;

/// How far ahead `run` looks for a wake before it calls the network quiet: an hour of simulated
/// time. At 0 timers never run; at infinity a node with a periodic timer never lets `run` end.
pub const MANUAL_HORIZON_MS: u64 = 3_600_000;

impl ManualNet {
    /// A network whose nodes run on `clock` (give each node the same clock, `Knobs::clock`).
    pub fn new(clock: Arc<ManualClock>) -> ManualNet {
        ManualNet(Arc::new(Mutex::new(Fabric { clock, nodes: Vec::new(), queue: VecDeque::new(), wakes: BTreeMap::new(), links: BTreeMap::new(), sent: BTreeMap::new(), ups: BTreeMap::new(), accepted: 0, offline: Default::default(), deliveries: 0, cap: MANUAL_CAP })))
    }

    /// A new node's place (`Osis::start`).
    pub(crate) fn join(&self) -> usize {
        let mut f = lock(&self.0);
        f.nodes.push((None, None));
        f.nodes.len() - 1
    }

    pub(crate) fn bind(&self, i: usize, db: WeakOsis) {
        if let Some(n) = lock(&self.0).nodes.get_mut(i) {
            n.0 = Some(db);
        }
    }

    fn listen(&self, i: usize, key: [u8; 32]) {
        if let Some(n) = lock(&self.0).nodes.get_mut(i) {
            n.1 = Some(key);
        }
    }

    /// Cuts node `i` off (`false`) or brings it back: its connections end, both ends told.
    pub fn set_online(&self, i: usize, online: bool) {
        let mut f = lock(&self.0);
        if online {
            f.offline.remove(&i);
            return;
        }
        f.offline.insert(i);
        let ends: Vec<_> = f.links.iter().filter(|((a, _), (b, _))| *a == i || *b == i).map(|(k, _)| *k).collect();
        for (a, c) in ends {
            f.cut(a, c);
        }
    }

    /// The node at place `i` of this network, while it is open.
    pub fn node(&self, i: usize) -> Option<crate::Osis> {
        lock(&self.0).nodes.get(i).and_then(|n| n.0.as_ref()).and_then(WeakOsis::upgrade)
    }

    /// Connections that came up at node `i` so far.
    pub fn ups(&self, i: usize) -> usize {
        lock(&self.0).ups.get(&i).copied().unwrap_or(0)
    }

    /// The places of this network's nodes, open or not.
    pub fn len(&self) -> usize {
        lock(&self.0).nodes.len()
    }

    /// No node joined.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn queue(&self, from: usize, out: Vec<Out>) {
        let mut f = lock(&self.0);
        apply(out, &mut FabricLinks { f: &mut f, node: from });
    }

    /// Delivers until nothing is queued and no wake is due within an hour of simulated time,
    /// moving the clock to each wake. Panics past `MANUAL_CAP` deliveries (a storm).
    pub fn run(&self) {
        let horizon = WallMs(lock(&self.0).clock.now_wall_ms().0.saturating_add(MANUAL_HORIZON_MS));
        self.until(horizon, false);
    }

    /// Delivers every input and wake up to `ms` from now, then sets the clock there.
    pub fn advance(&self, ms: u64) {
        let to = WallMs(lock(&self.0).clock.now_wall_ms().0.saturating_add(ms));
        self.until(to, true);
    }

    fn until(&self, to: WallMs, set: bool) {
        lock(&self.0).deliveries = 0;
        loop {
            let next = {
                let mut f = lock(&self.0);
                if let Some(x) = f.queue.pop_front() {
                    Some(x)
                } else {
                    let w = f.wakes.iter().filter(|(n, at)| **at <= to && !f.offline.contains(n)).min_by_key(|(n, at)| (**at, **n)).map(|(n, at)| (*n, *at));
                    w.map(|(n, at)| {
                        f.wakes.remove(&n);
                        if at > f.clock.now_wall_ms() {
                            f.clock.set(at);
                        }
                        (n, Input::Tick { now: f.clock.now_wall_ms() })
                    })
                }
            };
            let Some((i, input)) = next else { break };
            let db = {
                let mut f = lock(&self.0);
                f.deliveries += 1;
                assert!(f.deliveries <= f.cap, "manual net: past {} deliveries (a storm); queued {}", f.cap, f.queue.len());
                f.nodes.get(i).and_then(|n| n.0.as_ref()).and_then(WeakOsis::hold)
            };
            if let Some(db) = db {
                db.step(input, false);
            }
        }
        if set {
            let f = lock(&self.0);
            if f.clock.now_wall_ms() < to {
                f.clock.set(to);
            }
        }
    }
}

impl Fabric {
    /// Ends the connection at (`a`, `c`): the other end hears `Closed`.
    fn cut(&mut self, a: usize, c: ConnId) {
        if let Some((b, d)) = self.links.remove(&(a, c)) {
            self.links.remove(&(b, d));
            self.queue.push_back((a, Input::Closed { conn: c }));
            self.queue.push_back((b, Input::Closed { conn: d }));
        }
    }
}

/// One node's `Links` on the fabric.
struct FabricLinks<'a> {
    f: &'a mut Fabric,
    node: usize,
}

impl Links for FabricLinks<'_> {
    fn dial(&mut self, conn: ConnId, to: &osis_label::Address) {
        let f = &mut *self.f;
        let target = f.nodes.iter().position(|n| n.1 == Some(to.key));
        let Some(t) = target.filter(|t| *t != self.node && !f.offline.contains(t) && !f.offline.contains(&self.node)) else {
            f.queue.push_back((self.node, Input::Down { conn }));
            return;
        };
        f.accepted += 1;
        let acc = ConnId(ConnId::ACCEPTED | f.accepted);
        f.links.insert((self.node, conn), (t, acc));
        f.links.insert((t, acc), (self.node, conn));
        // a dialer's key is ephemeral (spec/sync-transport.md §1): any key no node listens with
        let mut eph = [0u8; 32];
        eph[..8].copy_from_slice(&f.accepted.to_le_bytes());
        eph[31] = 0xee;
        f.queue.push_back((self.node, Input::Up { conn, peer: NodeKey(to.key), rank: 0, dialed: true, listener: NodeKey(to.key) }));
        *f.ups.entry(self.node).or_default() += 1;
        *f.ups.entry(t).or_default() += 1;
        f.queue.push_back((t, Input::Up { conn: acc, peer: NodeKey(eph), rank: 0, dialed: false, listener: NodeKey(to.key) }));
    }

    fn send(&mut self, conn: ConnId, bytes: &[u8]) {
        let f = &mut *self.f;
        let Some((t, c)) = f.links.get(&(self.node, conn)).copied() else { return };
        let total = f.sent.entry((self.node, conn)).or_default();
        *total += bytes.len() as u64;
        let total = *total;
        f.queue.push_back((t, Input::Bytes { conn: c, bytes: bytes.to_vec() }));
        f.queue.push_back((self.node, Input::Taken { conn, bytes: total }));
    }

    fn close(&mut self, conn: ConnId) {
        let f = &mut *self.f;
        if let Some((t, c)) = f.links.remove(&(self.node, conn)) {
            f.links.remove(&(t, c));
            f.queue.push_back((t, Input::Closed { conn: c }));
        }
    }

    fn wake(&mut self, at: WallMs) {
        self.f.wakes.insert(self.node, at);
    }
}

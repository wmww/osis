//! The tokio driver (feature `driver`; notes/architecture.md §2): moves the `SyncEngine`'s bytes
//! over osis-transport `link` sessions (one dialed stream per connection, an ephemeral transport
//! key per connection, the peer's key checked by the transport, spec/sync.md §10) and fires its
//! timers. Every session a peer opens on one of the node's listeners is a session of its hub
//! (`hub`, osis-host's sans-I/O `Hub`, driven in this loop with node sync above it): the
//! dialable key's listeners (`Control::Reach`, `Control::Listen`), the unix socket's
//! (`Control::Socket`) and the LAN loop's per-network one. `Control::Lan` runs the LAN loop
//! (spec/sync.md §10): per network a fresh transport key and listener, announced on join and
//! every `LAN_ANNOUNCE`; announcements heard go to `SyncEngine::lan_seen`. No sync logic lives
//! here: every input is an `Event`, every output an `Action`. Engine calls run under
//! `block_in_place` on a multi-thread runtime. The engine lives in a `Shared`: owned by the
//! driver (`run`), or shared with the app (`run_shared`: the `osis` handle keeps it behind its own
//! lock and hands the driver the actions of its calls). While the node hosts (`Action::Host`,
//! from its `host^.0`) the hub's store is the host store, opened by the holder
//! (`Shared::host_store`); else an empty one in memory. The node's own dials of a key it listens
//! under reach the hub over an in-process link pair, no socket (notes/serving.md, The hub in the
//! node).

mod hub;

use super::{Action, ConnId, Event, SyncEngine};
use osis_base::Clock;
use osis_crypto::RngCore;
use hub::HubRun;
use osis_host::HostConfig;
use osis_transport::link::{self, Link, LinkTx, blocking};
use osis_transport::lan::Announce;
use osis_transport::{Address, ListenConfig, Listener, StaticSecret, Transport};
use osis_host::HostPolicy;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Longest wait between ticks.
pub const MAX_IDLE: Duration = Duration::from_secs(60);
/// How long a session's end waits for the host to take our last bytes.
pub const FINISH_WAIT: Duration = Duration::from_secs(10);
/// Bytes queued for a connection and not yet taken by the transport before it is dropped: a peer
/// that does not read (resource bound; a connection's replies and pushes stay within `SEND_QUEUE`,
/// its own requests within `WINDOW_QUEUE` more, spec/sync.md §6). 0 drops every session with a
/// request queued behind another, infinity buffers a non-reading peer without end.
pub const MAX_QUEUED: usize = 64 * 1024 * 1024;
const _: () = assert!(MAX_QUEUED >= osis_proto::serving::SEND_QUEUE + osis_proto::client::WINDOW_QUEUE);
/// How often the LAN loop repeats an announcement (`LanConfig::announce`; provisional, minor: a
/// lost one costs this much longer to find a neighbour; 0: a busy loop, infinity: one chance).
pub const LAN_ANNOUNCE: Duration = Duration::from_secs(30);
/// Network changes rejoin the LAN at most this often (each join drops the LAN listener and its
/// connections; provisional).
pub const LAN_REJOIN_MIN: Duration = Duration::from_secs(30);
/// How long `Control::Listen` tries a URL again when replacing its listeners, and how often: the
/// old one's UDP socket lives until its connections finished closing. Minor: 0 fails the replace
/// when they have not (calling it again works), infinity waits on a port someone else holds; each
/// try blocks this driver as any listen does.
const REBIND_WAIT: Duration = Duration::from_secs(5);
const REBIND_RETRY: Duration = Duration::from_millis(50);
/// A failed listen with a new dialable key is tried again after this long.
pub const RELISTEN_RETRY: Duration = Duration::from_secs(5);

/// A call on the sync engine from the app (create a label, compact, read the engine):
/// its actions are carried out.
pub type Call = Box<dyn FnOnce(&mut SyncEngine) -> Vec<Action> + Send>;

/// A join announces this many more times after the first (minor: 0: a lost first announcement
/// waits for `LAN_ANNOUNCE`; unbounded: one datagram per `LAN_JOIN_GAP` forever).
pub const LAN_JOIN_REPEATS: u32 = 2;
/// The time between a join's first announcements (minor: 0: one loss burst takes them all;
/// unbounded: as `LAN_JOIN_REPEATS` 0).
pub const LAN_JOIN_GAP: Duration = Duration::from_secs(1);

/// The LAN loop's settings.
#[derive(Clone, Debug)]
pub struct LanConfig {
    /// The announcement socket's port (`lan::PORT`; 0: any, tests).
    pub port: u16,
    /// Where announcements go (the IPv4 broadcast address and the IPv6 all-nodes group at
    /// `lan::PORT`; single addresses in tests). Each carries the listener's port on its family.
    pub to: Vec<std::net::SocketAddr>,
    /// The LAN listener's URL (`peer://[::]:0`: one dual-stack socket on all interfaces, any
    /// port; `peer://0.0.0.0:0` where IPv6 cannot be bound).
    pub listen: String,
    /// Whether the network watch runs (off in tests: joins come from `Control::LanRejoin`).
    pub watch: bool,
    /// Announcements repeat this often (`LAN_ANNOUNCE`).
    pub announce: Duration,
    /// After a join, this many more announcements (`LAN_JOIN_REPEATS`), `join_gap` apart.
    pub join_repeats: u32,
    /// The time between a join's first announcements (`LAN_JOIN_GAP`).
    pub join_gap: Duration,
    /// Network changes rejoin at most this often (`LAN_REJOIN_MIN`).
    pub rejoin_min: Duration,
}

impl Default for LanConfig {
    fn default() -> LanConfig {
        let p = osis_transport::lan::PORT;
        LanConfig { port: p, to: vec![osis_transport::lan::broadcast(p), osis_transport::lan::multicast(p)], listen: "peer://[::]:0".into(), watch: true, announce: LAN_ANNOUNCE, join_repeats: LAN_JOIN_REPEATS, join_gap: LAN_JOIN_GAP, rejoin_min: LAN_REJOIN_MIN }
    }
}

/// Commands to a running driver.
pub enum Control {
    /// The engine changed through local calls: look at its events.
    Local,
    /// Run timers now.
    Tick,
    Call(Call),
    /// Actions the holder's own calls produced: carry them out.
    Apply(Vec<Action>),
    /// Listen at the first of `urls` that listens, with the engine's dialable secret, and
    /// publish `reach.0` with that listener's key and items (spec/data-model.md §9). For
    /// `P2p`, a URL lists the socket address to bind and the relays the listener registers at;
    /// `reach.0` lists its global addresses (`p2p::reach_items`) and those relays.
    Reach { urls: Vec<String>, reply: Option<oneshot::Sender<Result<Address, String>>> },
    /// Serve the sessions a unix socket at `url` accepts (its peers of this uid act as the main
    /// actor, notes/client-port.md §5), beside the other listeners.
    Socket { url: String, reply: Option<oneshot::Sender<Result<Address, String>>> },
    /// Listen at `urls` with the dialable secret, in place of the URLs of an earlier `Listen`
    /// (their sessions end; none: stop). Answers the addresses. All or none: on an error nothing
    /// of them listens.
    Listen { urls: Vec<String>, reply: oneshot::Sender<Result<Vec<Address>, String>> },
    /// Run the LAN loop (no announcement socket: logged, nothing runs, the node works on).
    Lan(LanConfig),
    /// The network may have changed (an app's OS callback): join the LAN again with a fresh key
    /// and listener, at most every `LanConfig::rejoin_min`.
    LanRejoin,
    /// Hand the dialable keys of this node's co-readers (`SyncEngine::peers`) to this sink now
    /// and whenever they change: who the transport relays for (`p2p::RelayConfig::allow`).
    PeerKeys(PeerKeys),
    /// Close every connection and return the engine.
    Shutdown,
}

/// Takes the co-readers' dialable keys (`Control::PeerKeys`).
pub type PeerKeys = Arc<dyn Fn(&BTreeSet<[u8; 32]>) + Send + Sync>;

/// Where diagnostics go.
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

enum Ev {
    /// A dialed connection is up: its sending half, and whether a relay carries it.
    Up(ConnId, LinkTx, bool),
    Failed(ConnId, String),
    Bytes(ConnId, Vec<u8>),
    Closed(ConnId),
}

/// Forwards a session's bytes to the driver, then its end.
async fn forward(conn: ConnId, rx: link::LinkRx, ev: mpsc::Sender<Ev>) {
    link::forward(rx, ev, move |b| Ev::Bytes(conn, b), Ev::Closed(conn)).await
}

struct Conn {
    tx: Option<LinkTx>,
    task: JoinHandle<()>,
    /// `LinkTx::taken` when last reported (`Event::Sent`; `u64::MAX` before the first report).
    taken: u64,
}

/// Where the sync engine lives while a driver runs.
pub trait Shared: Send + Sync + 'static {
    /// Runs `f` on the engine; returns its actions. `None`: the engine is gone (the driver stops).
    fn with(&self, f: &mut dyn FnMut(&mut SyncEngine) -> Vec<Action>) -> Option<Vec<Action>>;
    /// Opens the store the node's host keeps, its own beside the node's (once per start of
    /// hosting; closed, then erased, when it stops). In memory unless the holder says otherwise.
    fn host_store(&self) -> Result<osis_store::Store, String> {
        let (b, r) = (Box::new(osis_store::MemoryBackend::new()), Box::new(osis_store::MemoryRoot::new()));
        osis_store::Store::create(b, r, osis_store::StoreConfig::default(), &mut osis_crypto::OsRng).map_err(|e| e.to_string())
    }
    /// Erases the host store (its key root first: that crypto-shreds it), never while it is
    /// open; the next `host_store` is empty.
    fn erase_host_store(&self) -> Result<(), String> {
        Ok(())
    }
}

/// The local record of the host store naming the run of hosting it belongs to.
const HOST_RUN_RECORD: &[u8] = b"host run";

/// Opens the host store of run of hosting `key` (`HostConfig::store_id`). One not recording
/// `key` (another run's: hosting stopped and started again while no driver ran, or before it
/// carried out the stop; recording none: new, or half erased by a crash) is erased first, then
/// records `key` before any entry goes in.
fn open_host_store(shared: &dyn Shared, key: &[u8; 32]) -> Result<osis_store::Store, String> {
    let e = |e: osis_store::Error| e.to_string();
    let mut s = shared.host_store()?;
    let mut rng = osis_crypto::OsRng;
    let kept = s.transaction(&mut rng).and_then(|mut t| t.get_local(HOST_RUN_RECORD)).map_err(e)?;
    if kept.as_deref() == Some(key.as_slice()) {
        return Ok(s);
    }
    drop(s);
    shared.erase_host_store()?;
    let mut s = shared.host_store()?;
    let mut t = s.transaction(&mut rng).map_err(e)?;
    t.put_local(HOST_RUN_RECORD, key, osis_store::Shred::No).map_err(e)?;
    t.commit().map_err(e)?;
    Ok(s)
}

/// A holder of the engine itself (`run`).
pub struct Owned(std::sync::Mutex<SyncEngine>);

impl Shared for Owned {
    fn with(&self, f: &mut dyn FnMut(&mut SyncEngine) -> Vec<Action>) -> Option<Vec<Action>> {
        let mut g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        Some(f(&mut g))
    }
}

/// A transport secret from the engine's 32 bytes.
fn transport_secret(s: &osis_crypto::Secret32) -> StaticSecret {
    StaticSecret::from_bytes(*s.expose())
}

/// The LAN loop's state.
struct LanLoop {
    cfg: LanConfig,
    sock: Arc<dyn osis_transport::lan::LanSocket>,
    /// Announcements left of the join's quick repeats.
    repeats: u32,
    /// Join at the next check (start, network change, new dialable key).
    rejoin: bool,
    /// When it last joined (network changes rejoin at most every `LAN_REJOIN_MIN`).
    joined: Option<tokio::time::Instant>,
    /// This network's listener: its key, its IPv4 and IPv6 ports and its hub listener group.
    listener: Option<([u8; 32], Ports, u64)>,
    /// When the next announcement is due (`None`: past what the clock can hold, never).
    next: Option<tokio::time::Instant>,
    /// The announcement receiver and the network watch.
    tasks: Vec<JoinHandle<()>>,
}

/// A listener's port per address family.
#[derive(Clone, Copy, Debug, Default)]
struct Ports {
    v4: Option<u16>,
    v6: Option<u16>,
}

/// The ports of the socket addresses a listener URL lists, per family; `[::]` (dual-stack)
/// counts for both.
fn listen_ports(url: &str) -> Ports {
    let mut p = Ports::default();
    for a in osis_transport::peer_items(url).unwrap_or_default().iter().filter_map(|h| h.parse::<std::net::SocketAddr>().ok()) {
        if a.is_ipv4() || a.ip().is_unspecified() {
            p.v4.get_or_insert(a.port());
        }
        if a.is_ipv6() {
            p.v6.get_or_insert(a.port());
        }
    }
    p
}

/// A listener URL with its `[::]` socket address as `0.0.0.0` (a machine without IPv6).
fn v4_only(url: &str) -> Option<String> {
    let items = osis_transport::peer_items(url)?;
    let v4: Vec<String> = items.iter().map(|h| match h.parse::<std::net::SocketAddr>() {
        Ok(a) if a.is_ipv6() && a.ip().is_unspecified() => std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, a.port())).to_string(),
        _ => h.clone(),
    }).collect();
    (v4 != items).then(|| osis_transport::peer_url(&v4))
}

struct Driver<T: Transport, H: Shared> {
    shared: H,
    gone: bool,
    transport: Arc<T>,
    clock: Arc<dyn Clock>,
    log: Log,
    conns: HashMap<ConnId, Conn>,
    wake: Option<u64>,
    ev_tx: mpsc::Sender<Ev>,
    lan: Option<LanLoop>,
    lan_tx: mpsc::Sender<(Announce, std::net::SocketAddr)>,
    /// Network changes from the LAN loop's watch.
    net_tx: mpsc::Sender<()>,
    /// The dialable listener's URLs (`Control::Reach`), its key and hub listener group.
    reach: Option<Vec<String>>,
    dialable: Option<([u8; 32], u64)>,
    /// `Control::Listen`'s URLs (as bound) and their hub listener group.
    listen: Option<(Vec<String>, u64)>,
    /// `Control::Socket`'s hub listener groups.
    sockets: Vec<u64>,
    /// Where the co-readers' dialable keys go, and the last keys given (`Control::PeerKeys`).
    peer_keys: Option<(PeerKeys, BTreeSet<[u8; 32]>)>,
    /// The engine rotated the dialable secret (`Action::Reach`): listen again (not before
    /// `relisten_at` after a failure).
    relisten: bool,
    relisten_at: Option<tokio::time::Instant>,
    /// The hub, and a host config for it not yet carried out (`host_update`).
    hub: HubRun,
    host_want: Option<Option<Box<HostConfig>>>,
    /// Between the hub and node sync (`hub_pump`): the engine's `Action::Hub` not yet handed to
    /// the hub, and what the hub handed up not yet fed to the engine.
    hub_downs: Vec<(osis_host::ConnId, osis_host::Down)>,
    hub_ups: Vec<(osis_host::ConnId, osis_host::Up)>,
}

/// A host store in memory, empty and admitting nothing, under the default policy: the hub's
/// while the node hosts nothing.
fn empty_store(clock: Arc<dyn Clock>) -> osis_host::HostStore {
    let (b, r) = (Box::new(osis_store::MemoryBackend::new()), Box::new(osis_store::MemoryRoot::new()));
    #[allow(clippy::expect_used)]
    let s = osis_store::Store::create(b, r, osis_store::StoreConfig::default(), &mut osis_crypto::OsRng).expect("a store in memory");
    #[allow(clippy::expect_used)]
    let mut store = osis_host::HostStore::open(s, clock, HostPolicy::default(), Box::new(osis_crypto::OsRng)).expect("a host store in memory");
    // it takes no label
    store.set_admission(osis_host::Admission::Only(Default::default()), Default::default());
    store
}

impl<T: Transport, H: Shared> Driver<T, H> {
    fn call(&mut self, f: &mut dyn FnMut(&mut SyncEngine) -> Vec<Action>) {
        let shared = &self.shared;
        match blocking(|| shared.with(f)) {
            Some(acts) => self.apply(acts),
            None => self.gone = true,
        }
    }

    /// Reads something off the engine (no actions).
    fn read<R>(&mut self, f: impl FnOnce(&mut SyncEngine) -> R) -> Option<R> {
        let mut f = Some(f);
        let mut out = None;
        let shared = &self.shared;
        let r = blocking(|| {
            shared.with(&mut |s| {
                if let Some(f) = f.take() {
                    out = Some(f(s));
                }
                Vec::new()
            })
        });
        if r.is_none() {
            self.gone = true;
        }
        out
    }

    fn feed(&mut self, ev: Event) {
        self.call(&mut |s| s.handle(ev.clone()));
    }

    fn apply(&mut self, acts: Vec<Action>) {
        for a in acts {
            match a {
                Action::Dial { conn, address } => {
                    let t = self.transport.clone();
                    let ev = self.ev_tx.clone();
                    let addr = Address { url: address.url, key: address.key };
                    // a key this node listens under: an in-process session with an ephemeral key
                    let own = self.hub.listens_as(&addr.key).then(|| {
                        let mut k = [0u8; 32];
                        osis_crypto::OsRng.fill_bytes(&mut k);
                        let (mine, theirs) = link::pair(k, addr.key);
                        self.hub.accept_own(addr.key, theirs);
                        mine
                    });
                    let task = tokio::spawn(async move {
                        let dialed = match own {
                            Some(mine) => Ok(mine),
                            None => link::dial(&*t, &addr, None, FINISH_WAIT).await.map_err(|e| e.to_string()),
                        };
                        let link = match dialed {
                            Ok(l) => l,
                            Err(e) => {
                                let _ = ev.send(Ev::Failed(conn, e)).await;
                                return;
                            }
                        };
                        let Link { tx, rx, relayed, .. } = link;
                        if ev.send(Ev::Up(conn, tx, relayed)).await.is_ok() {
                            forward(conn, rx, ev).await;
                        }
                    });
                    self.conns.insert(conn, Conn { tx: None, task, taken: u64::MAX });
                }
                Action::Send { conn, bytes } => {
                    let ok = self.conns.get(&conn).and_then(|c| c.tx.as_ref()).is_some_and(|tx| tx.send(bytes, MAX_QUEUED));
                    if !ok {
                        (self.log)(&format!("connection {conn}: closed (slow or gone)"));
                        self.close(conn);
                        self.feed(Event::Down { conn });
                    }
                }
                Action::Close { conn } => self.close(conn),
                Action::Wake { at } => self.wake = Some(at),
                Action::Reach => self.relisten = true,
                Action::Host(cfg) => self.host_want = Some(cfg),
                Action::Hub { conn, down } => self.hub_downs.push((conn, down)),
                // the client port is the engine holder's (`osis`); a bare driver answers none
                Action::Request { .. } | Action::Room { .. } | Action::Ended { .. } => {}
            }
        }
    }

    /// Reports the connections whose bytes the transport took since the last report, then ticks.
    fn tick(&mut self) {
        let mut moved = Vec::new();
        for (id, c) in &mut self.conns {
            if let Some(n) = c.tx.as_ref().map(LinkTx::taken).filter(|n| *n != c.taken) {
                c.taken = n;
                moved.push((*id, n));
            }
        }
        if !moved.is_empty() {
            self.feed(Event::Sent { conns: moved });
        }
        self.feed(Event::Tick);
        self.give_peer_keys(false);
    }

    /// Hands the co-readers' keys to the `Control::PeerKeys` sink when they changed (`force`: now).
    fn give_peer_keys(&mut self, force: bool) {
        if self.peer_keys.is_none() {
            return;
        }
        let Some(keys) = self.read(|s| s.peers().keys().copied().collect::<BTreeSet<_>>()) else { return };
        if let Some((sink, last)) = self.peer_keys.as_mut().filter(|(_, last)| force || *last != keys) {
            sink(&keys);
            *last = keys;
        }
    }

    fn close(&mut self, conn: ConnId) {
        if let Some(c) = self.conns.remove(&conn) {
            // dropping the sending end finishes the stream; the dialer's connection then closes
            drop(c.tx);
            c.task.abort();
        }
    }

    fn idle(&self) -> Duration {
        let now = self.clock.now_wall_ms().0;
        self.wake.map_or(MAX_IDLE, |t| Duration::from_millis(t.saturating_sub(now)).min(MAX_IDLE))
    }

    /// Listens at one URL into the hub; returns the address and its listener group.
    async fn listen_one(&mut self, cfg: ListenConfig) -> Result<(Address, u64), String> {
        match self.transport.listen(cfg).await {
            Ok(l) => {
                let a = l.address();
                let g = self.hub.listen(a.key, vec![l]);
                Ok((a, g))
            }
            Err(e) => {
                (self.log)(&format!("listen: {e}"));
                Err(e.to_string())
            }
        }
    }

    fn dialable_secret(&mut self) -> Option<StaticSecret> {
        self.read(|s| transport_secret(&s.dialable_secret()))
    }

    /// Listens at `urls` with the dialable secret in place of `Control::Listen`'s earlier URLs:
    /// the old ones stop first with their sessions (a new one may want the same URL, a socket a
    /// session's connection still holds); every URL listens or none does. A UDP port the old
    /// connections still drain is tried again for `REBIND_WAIT`.
    async fn listen(&mut self, urls: Vec<String>) -> Result<Vec<Address>, String> {
        if let Some((_, g)) = self.listen.take() {
            self.hub.unlisten(g).await;
        }
        if urls.is_empty() {
            return Ok(Vec::new());
        }
        let Some(secret) = self.dialable_secret() else { return Err("engine gone".into()) };
        let mut ls = Vec::new();
        for url in urls {
            let end = tokio::time::Instant::now() + REBIND_WAIT;
            ls.push(loop {
                match self.transport.listen(ListenConfig { url: url.clone(), secret: secret.clone() }).await {
                    Ok(l) => break l,
                    Err(e) if tokio::time::Instant::now() >= end => return Err(e.to_string()),
                    Err(_) => tokio::time::sleep(REBIND_RETRY).await,
                }
            });
        }
        let addrs: Vec<Address> = ls.iter().map(Listener::address).collect();
        if let Some(a) = addrs.first() {
            let g = self.hub.listen(a.key, ls);
            self.listen = Some((addrs.iter().map(|x| x.url.clone()).collect(), g));
        }
        Ok(addrs)
    }

    /// Listens on a unix socket at `url`, beside the other listeners.
    async fn socket(&mut self, url: String) -> Result<Address, String> {
        let Some(secret) = self.dialable_secret() else { return Err("engine gone".into()) };
        let (a, g) = self.listen_one(ListenConfig { url, secret }).await?;
        self.sockets.push(g);
        Ok(a)
    }

    /// Listens with the dialable secret and publishes `reach.0` with that listener's key and
    /// items (its global addresses as of now, its relays); a listener of an older dialable key
    /// stops.
    async fn reach(&mut self, urls: Vec<String>) -> Result<Address, String> {
        self.reach = Some(urls.clone());
        let Some(secret) = self.dialable_secret() else { return Err("engine gone".into()) };
        let mut res = Err("no URL to listen at".to_string());
        for url in urls {
            res = self.listen_one(ListenConfig { url, secret: secret.clone() }).await;
            if res.is_ok() {
                break;
            }
        }
        let (addr, g) = res?;
        let key = addr.key;
        if let Some((_, old)) = self.dialable.replace((key, g)) {
            self.hub.unlisten(old).await;
        }
        // an unspecified bound IP stands for the routes' local addresses
        let unspecified = osis_transport::p2p::items(&addr.url).is_ok_and(|it| it.direct.iter().any(|a| a.ip().is_unspecified()));
        let routes: Vec<std::net::IpAddr> = if unspecified {
            let (v4, v6) = osis_transport::lan::route_ips().await;
            v4.into_iter().chain(v6).collect()
        } else {
            Vec::new()
        };
        let items = osis_transport::p2p::reach_items(&addr.url, &routes);
        self.call(&mut |s| match s.publish_reach(key, items.clone()) {
            Ok(a) => a,
            Err(e) => {
                s.diag(format!("publishing reach.0: {e}"));
                Vec::new()
            }
        });
        Ok(addr)
    }

    fn event(&mut self, ev: Ev) {
        match ev {
            Ev::Up(conn, tx, relayed) => {
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.tx = Some(tx);
                    if relayed {
                        self.call(&mut |s| {
                            s.set_relayed(conn);
                            Vec::new()
                        });
                    }
                    self.feed(Event::Up { conn });
                }
            }
            Ev::Failed(conn, e) => {
                (self.log)(&format!("connection {conn}: {e}"));
                self.conns.remove(&conn);
                self.feed(Event::Down { conn });
            }
            Ev::Bytes(conn, bytes) => {
                let Some(c) = self.conns.get_mut(&conn) else { return };
                if let Some(n) = c.tx.as_ref().map(LinkTx::taken).filter(|n| *n != c.taken) {
                    c.taken = n;
                    self.feed(Event::Sent { conns: vec![(conn, n)] });
                }
                self.feed(Event::Bytes { conn, bytes });
            }
            Ev::Closed(conn) => {
                if self.conns.remove(&conn).is_some() {
                    self.feed(Event::Down { conn });
                }
            }
        }
    }

    /// Starts the LAN loop: binds the announcement socket (the transport's); the first check
    /// joins the network.
    async fn lan_start(&mut self, cfg: LanConfig) {
        if let Some(old) = self.lan.take() {
            old.tasks.iter().for_each(JoinHandle::abort);
        }
        let sock = match self.transport.lan(cfg.port).await {
            Ok(s) => s,
            Err(e) => {
                (self.log)(&format!("LAN: {e}"));
                return;
            }
        };
        let (s2, tx, log) = (sock.clone(), self.lan_tx.clone(), self.log.clone());
        let mut tasks = vec![tokio::spawn(async move {
            loop {
                match s2.recv().await {
                    // a flood is dropped, not queued
                    Ok(x) => {
                        if let Err(mpsc::error::TrySendError::Closed(_)) = tx.try_send(x) {
                            return;
                        }
                    }
                    // announcements go on going out; hearing stops until the node restarts
                    Err(e) => return log(&format!("LAN receive: {e}")),
                }
            }
        })];
        if cfg.watch {
            let tx = self.net_tx.clone();
            tasks.push(tokio::spawn(async move {
                let mut w = osis_transport::lan::NetWatch::new().await;
                loop {
                    w.changed().await;
                    if let Err(mpsc::error::TrySendError::Closed(_)) = tx.try_send(()) {
                        return;
                    }
                }
            }));
        }
        self.lan = Some(LanLoop { cfg, sock, repeats: 0, rejoin: true, joined: None, listener: None, next: Some(tokio::time::Instant::now()), tasks });
        self.lan_check().await;
    }

    /// Joins the network again at the next check (a network change, a new dialable key).
    /// `force` (a new dialable key): at once; else (a network change) at most every
    /// `LAN_REJOIN_MIN`, the LAN timer doing a deferred one.
    async fn lan_rejoin(&mut self, force: bool) {
        if let Some(x) = self.lan.as_mut() {
            x.rejoin = true;
            if force {
                x.joined = None;
            }
            self.lan_check().await;
        }
    }

    /// The LAN loop's timer: a join (start, network change, new dialable key) drops the old
    /// listener and listens with a fresh key, announced at once and `join_repeats` more times
    /// soon after; announcements then repeat every `LanConfig::announce`, each family's carrying the listener's port on that family.
    async fn lan_check(&mut self) {
        let now = tokio::time::Instant::now();
        let Some((old, url)) = self.lan.as_mut().filter(|x| x.rejoin && x.joined.is_none_or(|t| t.checked_add(x.cfg.rejoin_min).is_some_and(|due| due <= now))).map(|x| {
            x.rejoin = false;
            x.joined = Some(now);
            (x.listener.take(), x.cfg.listen.clone())
        }) else {
            return self.lan_announce().await;
        };
        if let Some((_, _, g)) = old {
            self.hub.unlisten(g).await;
        }
        let Some(secret) = self.read(|s| transport_secret(&s.lan_secret())) else { return };
        let mut r = self.listen_one(ListenConfig { url: url.clone(), secret: secret.clone() }).await;
        if r.is_err()
            && let Some(v4) = v4_only(&url)
        {
            r = self.listen_one(ListenConfig { url: v4, secret }).await;
        }
        if let Some(x) = self.lan.as_mut() {
            x.listener = r.ok().map(|(a, g)| (a.key, listen_ports(&a.url), g));
            x.next = Some(tokio::time::Instant::now());
            x.repeats = x.cfg.join_repeats;
        }
        self.lan_announce().await;
    }

    /// Announces this network's listener when due.
    async fn lan_announce(&mut self) {
        let now = tokio::time::Instant::now();
        let Some((key, ports, to, sock)) = self.lan.as_ref().filter(|x| x.next.is_some_and(|n| n <= now)).and_then(|x| x.listener.map(|(k, p, _)| (k, p, x.cfg.to.clone(), x.sock.clone()))) else { return };
        if let Some(x) = self.lan.as_mut() {
            let wait = if x.repeats > 0 { x.cfg.join_gap } else { x.cfg.announce };
            x.repeats = x.repeats.saturating_sub(1);
            x.next = now.checked_add(wait);
        }
        for (port, fam) in [(ports.v4, false), (ports.v6, true)] {
            let Some(port) = port else { continue };
            let targets: Vec<std::net::SocketAddr> = to.iter().filter(|t| t.is_ipv6() == fam && (!fam || sock.has_v6())).copied().collect();
            if targets.is_empty() {
                continue;
            }
            let Some(Some(a)) = self.read(|s| s.lan_announcement(key, port)) else { continue };
            for t in targets {
                if let Err(e) = sock.announce(&a, t).await {
                    (self.log)(&format!("LAN announce to {t}: {e}"));
                }
            }
        }
    }

    /// When the LAN loop next has work: the next announcement, or a join a network change
    /// deferred to `rejoin_min`.
    fn lan_due(&self) -> Option<tokio::time::Instant> {
        let x = self.lan.as_ref()?;
        let announce = x.listener.and(x.next);
        let join = x.joined.filter(|_| x.rejoin).and_then(|t| t.checked_add(x.cfg.rejoin_min));
        announce.into_iter().chain(join).min()
    }

    /// Carries out a control; false: shut down.
    async fn control(&mut self, c: Option<Control>) -> bool {
        match c {
            Some(Control::Local) => {
                self.feed(Event::Local);
                self.give_peer_keys(false);
            }
            Some(Control::PeerKeys(sink)) => {
                self.peer_keys = Some((sink, BTreeSet::new()));
                self.give_peer_keys(true);
            }
            Some(Control::Tick) => self.tick(),
            Some(Control::Call(f)) => {
                let mut f = Some(f);
                self.call(&mut |s| f.take().map(|f| f(s)).unwrap_or_default());
            }
            Some(Control::Apply(acts)) => self.apply(acts),
            Some(Control::Reach { urls, reply }) => {
                let r = self.reach(urls).await;
                if let Some(reply) = reply {
                    let _ = reply.send(r);
                }
            }
            Some(Control::Socket { url, reply }) => {
                let r = self.socket(url).await;
                if let Some(reply) = reply {
                    let _ = reply.send(r);
                }
            }
            Some(Control::Listen { urls, reply }) => {
                let r = self.listen(urls).await;
                let _ = reply.send(r);
            }
            Some(Control::Lan(cfg)) => self.lan_start(cfg).await,
            Some(Control::LanRejoin) => self.lan_rejoin(false).await,
            Some(Control::Shutdown) | None => return false,
        }
        true
    }

    /// Passes what the hub handed up to node sync and node sync's answers down, until neither
    /// has more (one function call each way, no channel).
    fn hub_pump(&mut self) {
        while !self.gone {
            let downs = std::mem::take(&mut self.hub_downs);
            if !downs.is_empty() {
                self.hub.down(downs);
            }
            self.hub_ups.extend(self.hub.take_ups());
            if self.hub_ups.is_empty() {
                return;
            }
            let ups = std::mem::take(&mut self.hub_ups);
            self.feed(Event::Hub { ups });
        }
    }

    /// Serves `store` from now on; the one served before is dropped (closed).
    fn hub_store(&mut self, store: osis_host::HostStore) {
        let (old, out) = self.hub.hub_mut().replace_store(store);
        drop(old);
        self.hub.applied(out);
    }

    /// Carries out the last `Action::Host`: hosting stops (the hub's store goes back to an empty
    /// one, the host store is erased once the engine no longer hosts), starts (the host store of
    /// its run opened), or changes in place (admission, caps, policy, replication peers).
    async fn host_update(&mut self) {
        let Some(want) = self.host_want.take() else { return };
        let Some(cfg) = want else {
            let hosted = self.hub.cfg.take().is_some();
            self.hub.replicate(&self.transport, &[], None);
            if hosted {
                self.hub_store(empty_store(self.clock.clone()));
            }
            // hosting stopped (not the driver): the host store goes with the run
            if self.read(|s| !s.hosts()) == Some(true) {
                let shared = &self.shared;
                if let Err(e) = blocking(|| shared.erase_host_store()) {
                    (self.log)(&format!("erasing the host store: {e}"));
                }
            }
            return;
        };
        let cfg = *cfg;
        // a config of a run that is over (hosting stopped and maybe started again since it was
        // emitted): the newer `Action::Host` is on its way
        if self.read(|s| s.host_current(&cfg)) != Some(true) {
            return;
        }
        if self.hub.cfg.as_ref().is_none_or(|c| c.store_id != cfg.store_id) {
            // the store of an older run closes before the new one opens
            if self.hub.cfg.take().is_some() {
                self.hub_store(empty_store(self.clock.clone()));
            }
            let shared = &self.shared;
            let opened = blocking(|| open_host_store(shared, &cfg.store_id).and_then(|s| osis_host::HostStore::open(s, self.clock.clone(), cfg.policy.clone(), Box::new(osis_crypto::OsRng)).map_err(|e| e.to_string())));
            match opened {
                Ok(store) => self.hub_store(store),
                Err(e) => {
                    let e = format!("hosting: host store: {e}");
                    (self.log)(&e);
                    self.call(&mut |s| {
                        s.diag(e.clone());
                        Vec::new()
                    });
                    return;
                }
            }
        }
        let store = self.hub.hub_mut().store_mut();
        store.set_policy(cfg.policy.clone());
        store.set_admission(cfg.admission.clone(), cfg.caps.clone());
        if self.hub.cfg.as_ref().is_none_or(|c| c.replicate != cfg.replicate) {
            let secret = self.dialable_secret();
            self.hub.replicate(&self.transport, &cfg.replicate, secret);
        }
        self.hub.cfg = Some(cfg);
    }

    /// After `Action::Reach`: every listener of the dialable key listens again with the new
    /// secret (the old ones stop) and the LAN is joined again, so nothing announced or listening
    /// carries the old key. A unix socket has no key of the node's (the kernel names its peers):
    /// it stays.
    async fn after_rotation(&mut self) {
        if !self.relisten || self.relisten_at.is_some_and(|t| t > tokio::time::Instant::now()) {
            return;
        }
        self.relisten = false;
        self.relisten_at = None;
        self.hub.own = self.read(SyncEngine::dialable_key);
        if let Some(urls) = self.reach.clone() {
            // the old listener goes first: the new one takes its place (its URL, its relays)
            if let Some((_, old)) = self.dialable.take() {
                self.hub.unlisten(old).await;
            }
            if let Err(e) = self.reach(urls).await {
                // `reach.0` already names the new key: keep trying
                (self.log)(&format!("listening with the new dialable key: {e}; again in {RELISTEN_RETRY:?}"));
                self.relisten = true;
                self.relisten_at = Some(tokio::time::Instant::now() + RELISTEN_RETRY);
            }
        }
        if let Some((urls, _)) = self.listen.clone()
            && let Err(e) = self.listen(urls).await
        {
            (self.log)(&format!("listening with the new dialable key: {e}"));
        }
        // replication dials as the node's key
        if let Some(cfg) = self.hub.cfg.clone() {
            let secret = self.dialable_secret();
            self.hub.replicate(&self.transport, &cfg.replicate, secret);
        }
        if !self.relisten {
            self.lan_rejoin(true).await;
        }
    }
}

/// Runs the sync engine until `Control::Shutdown` (or the control sender is dropped) and
/// returns it. Dials what it asks for over `transport`; ticks when its wake comes due.
pub async fn run<T: Transport>(sync: SyncEngine, transport: T, clock: Arc<dyn Clock>, control: mpsc::UnboundedReceiver<Control>, log: Log) -> SyncEngine {
    run_serving(sync, transport, Vec::new(), clock, control, log).await
}

/// `run`, its hub also serving the sessions `listeners` accept, each under its own key.
pub async fn run_serving<T: Transport>(sync: SyncEngine, transport: T, listeners: Vec<T::Listener>, clock: Arc<dyn Clock>, control: mpsc::UnboundedReceiver<Control>, log: Log) -> SyncEngine {
    let Owned(m) = run_shared(Owned(std::sync::Mutex::new(sync)), transport, listeners, clock, control, log).await;
    m.into_inner().unwrap_or_else(|p| p.into_inner())
}

/// `run_serving` over a holder; returns it at `Control::Shutdown`, when the control sender is
/// dropped or when the holder's engine is gone. More listeners come with `Control::Reach`,
/// `Control::Listen`, `Control::Socket` and the LAN loop. Never put a listener's
/// `address().url` into `reach.0` as it is: it lists bound IP addresses; `p2p::reach_items` says
/// what goes there.
pub async fn run_shared<T: Transport, H: Shared>(shared: H, transport: T, listeners: Vec<T::Listener>, clock: Arc<dyn Clock>, mut control: mpsc::UnboundedReceiver<Control>, log: Log) -> H {
    let (ev_tx, mut ev_rx) = mpsc::channel(1024);
    let (lan_tx, mut lan_rx) = mpsc::channel(64);
    let (net_tx, mut net_rx) = mpsc::channel::<()>(1);
    // unbounded, yet at most a read and an end per hub connection, a link per dial task and the
    // listeners' accepts (`link::serve`'s slots)
    let (hub_tx, mut hub_rx) = mpsc::unbounded_channel();
    let mut hub = HubRun::new(osis_host::Hub::new(empty_store(clock.clone()), Box::new(osis_crypto::OsRng)), clock.clone(), log.clone(), hub_tx);
    for l in listeners {
        let key = l.address().key;
        hub.listen(key, vec![l]);
    }
    let mut d = Driver {
        shared,
        gone: false,
        transport: Arc::new(transport),
        clock,
        log,
        conns: HashMap::new(),
        wake: None,
        ev_tx,
        lan: None,
        lan_tx,
        net_tx,
        reach: None,
        dialable: None,
        listen: None,
        sockets: Vec::new(),
        peer_keys: None,
        relisten: false,
        relisten_at: None,
        hub,
        host_want: None,
        hub_downs: Vec::new(),
        hub_ups: Vec::new(),
    };
    d.call(&mut |s| {
        s.host_restart();
        Vec::new()
    });
    d.hub.own = d.read(SyncEngine::dialable_key);
    // a host store left by a stop no driver carried out (not hosting: erased)
    d.host_want = Some(None);
    d.host_update().await;
    d.feed(Event::Tick);
    while !d.gone {
        let idle = d.idle();
        let lan_due = d.lan_due();
        let hub_due = d.hub.due();
        let hub_waiting = d.hub.waiting();
        // timers wait while control has a message: a `Shutdown` queued just before the holder's
        // runtime shuts down (the task resuming after an engine call's `block_in_place`) is
        // seen before a timer of the shut-down runtime is polled (tokio panics)
        let quiet = control.is_empty();
        tokio::select! {
            Some(ev) = ev_rx.recv() => d.event(ev),
            c = control.recv() => {
                if !d.control(c).await {
                    break;
                }
            }
            _ = sleep_until(lan_due), if quiet => d.lan_check().await,
            Some((a, from)) = lan_rx.recv() => d.call(&mut |s| s.lan_seen(&a, from).1),
            Some(()) = net_rx.recv() => d.lan_rejoin(false).await,
            Some(ev) = hub_rx.recv() => d.hub.event(ev),
            () = std::future::ready(()), if hub_waiting => {
                // every read that arrived takes its place in the turns first
                while let Ok(ev) = hub_rx.try_recv() {
                    d.hub.event(ev);
                }
                d.hub.serve();
            }
            _ = tokio::time::sleep_until(hub_due), if quiet => d.hub.tick(),
            _ = sleep_until(d.relisten_at), if quiet => {}
            _ = tokio::time::sleep(idle), if quiet => {
                d.wake = None;
                d.tick();
            }
        }
        d.hub_pump();
        d.after_rotation().await;
        d.host_update().await;
        d.hub_pump();
    }
    if let Some(x) = d.lan.take() {
        x.tasks.iter().for_each(JoinHandle::abort);
    }
    let ups = d.hub.stop();
    d.hub_ups.extend(ups);
    d.hub_pump();
    let ids: Vec<ConnId> = d.conns.keys().copied().collect();
    for id in ids {
        d.close(id);
    }
    d.shared
}

/// Until `at`, else never.
async fn sleep_until(at: Option<tokio::time::Instant>) {
    match at {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending::<()>().await,
    }
}

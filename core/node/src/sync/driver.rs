//! The tokio driver (feature `driver`; notes/architecture.md §2): moves the `SyncEngine`'s bytes
//! over osis-transport `link` sessions (one dialed stream per connection, an ephemeral transport
//! key per connection, the peer's key checked by the transport, spec/sync.md §10) and fires its timers. Every session a peer opens on one of its
//! listeners is served by the engine (`SyncEngine::accept`, co-reader peer, spec/sync.md §5);
//! more listeners come while it runs (`Control::Reach`, the LAN loop's per-network listener).
//! With feature `lan`, `Control::Lan` runs the LAN loop (spec/sync.md §10): per network a fresh
//! transport key and listener, announced on join and every `LAN_ANNOUNCE`; announcements heard go
//! to `SyncEngine::lan_seen`. No sync logic lives here: every input is an `Event`, every output an
//! `Action`. Engine calls run under `block_in_place` on a multi-thread runtime. The engine lives
//! in a `Shared`: owned by the driver (`run`), or shared with the app (`run_shared`: the `osis` handle
//! keeps it behind its own lock and hands the driver the actions of its calls).
//! While the node hosts (`Action::Host`, from its `host.0^`) the driver runs osis-host's driver
//! as a task beside it over the same transport: its listeners use the host secret, its store is
//! its own osis-store `Store`, opened by the holder (`Shared::host_store`), and the node's own dials of the host address go to it
//! over an in-process link pair, no socket (notes/sync.md Hosting).

use super::{Action, ConnId, Event, HostStatus, SyncEngine};
use osis_base::Clock;
use osis_crypto::RngCore;
use osis_host::{HostConfig, driver as host};
use osis_transport::link::{self, Link, LinkTx, blocking};
use osis_transport::lan::Announce;
use osis_transport::{Address, ListenConfig, Listener, StaticSecret, Transport};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// A served connection with no session for this long is closed.
pub const SERVE_IDLE: Duration = Duration::from_secs(120);

/// Longest wait between ticks.
pub const MAX_IDLE: Duration = Duration::from_secs(60);
/// How long a session's end waits for the host to take our last bytes.
pub const FINISH_WAIT: Duration = Duration::from_secs(10);
/// Bytes queued for a connection and not yet taken by the transport before it is dropped: a peer
/// that does not read (resource bound; a session's own traffic stays within `WINDOW_QUEUE`, a
/// served one's within `SEND_QUEUE`, spec/sync.md §6). 0 drops every session with a request
/// queued behind another, infinity buffers a non-reading peer without end.
pub const MAX_QUEUED: usize = 64 * 1024 * 1024;
const _: () = assert!(MAX_QUEUED >= osis_proto::serving::SEND_QUEUE);
/// LAN loop: how often it looks whether an announcement is due, and how often they repeat
/// (provisional). Network changes come from `lan::NetWatch`.
pub const LAN_CHECK: Duration = Duration::from_secs(5);
pub const LAN_ANNOUNCE: Duration = Duration::from_secs(30);
/// Network changes rejoin the LAN at most this often (each join drops the LAN listener and its
/// connections; provisional).
pub const LAN_REJOIN_MIN: Duration = Duration::from_secs(30);
/// A failed listen with a new dialable key is tried again after this long.
pub const RELISTEN_RETRY: Duration = Duration::from_secs(5);

/// A call on the sync engine from the app (create a label, compact, read the engine):
/// its actions are carried out.
pub type Call = Box<dyn FnOnce(&mut SyncEngine) -> Vec<Action> + Send>;

/// The LAN loop's settings (feature `lan`).
#[derive(Clone, Debug)]
pub struct LanConfig {
    /// The announcement socket's port (`lan::PORT`; 0: any, tests).
    pub port: u16,
    /// Where announcements go (the IPv4 broadcast address and the IPv6 all-nodes group at
    /// `lan::PORT`; single addresses in tests). Each carries the listener's port on its family.
    pub to: Vec<std::net::SocketAddr>,
    /// The LAN listener's URL (`peer://0.0.0.0:0 [::]:0`: all interfaces of both families, any
    /// port; IPv4 only where IPv6 cannot be bound).
    pub listen: String,
    /// Whether the network watch runs (off in tests: joins come from `Control::LanRejoin`).
    pub watch: bool,
    /// Network changes rejoin at most this often (`LAN_REJOIN_MIN`).
    pub rejoin_min: Duration,
}

impl Default for LanConfig {
    fn default() -> LanConfig {
        let p = osis_transport::lan::PORT;
        LanConfig { port: p, to: vec![osis_transport::lan::broadcast(p), osis_transport::lan::multicast(p)], listen: "peer://0.0.0.0:0 [::]:0".into(), watch: true, rejoin_min: LAN_REJOIN_MIN }
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
    /// Listen at `url` with the engine's dialable secret and publish `reach.0` with that
    /// listener's key and `relays` (spec/data-model.md §9). For iroh, `url` lists the relays the
    /// listener registers at (`peer_url(relays)`).
    Reach { url: String, relays: Vec<String>, reply: Option<oneshot::Sender<Result<Address, String>>> },
    /// Serve the sessions a listener at `url` accepts (a client socket, `unix://`; its
    /// sessions are clients, notes/client-port.md §5), with a fresh secret of its own.
    Listen { url: String, reply: Option<oneshot::Sender<Result<Address, String>>> },
    /// Run the LAN loop (feature `lan`; ignored without it).
    Lan(LanConfig),
    /// The network may have changed (an app's OS callback): join the LAN again with a fresh key
    /// and listener, at most every `LanConfig::rejoin_min`.
    LanRejoin,
    /// Close every connection and return the engine.
    Shutdown,
}

/// Where diagnostics go.
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

enum Ev {
    Up(ConnId, LinkTx),
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

/// The local record of the host store naming the host key it belongs to.
const HOST_KEY_RECORD: &[u8] = b"host key";

/// Opens the host store for host key `key`. One not recording `key` (kept for another key:
/// hosting stopped and started again while no driver ran, or before it carried out the stop;
/// recording none: new, or half erased by a crash) is erased first, then records `key` before
/// any entry goes in.
fn open_host_store(shared: &dyn Shared, key: &[u8; 32]) -> Result<osis_store::Store, String> {
    let e = |e: osis_store::Error| e.to_string();
    let mut s = shared.host_store()?;
    let mut rng = osis_crypto::OsRng;
    let kept = s.transaction(&mut rng).and_then(|mut t| t.get_local(HOST_KEY_RECORD)).map_err(e)?;
    if kept.as_deref() == Some(key.as_slice()) {
        return Ok(s);
    }
    drop(s);
    shared.erase_host_store()?;
    let mut s = shared.host_store()?;
    let mut t = s.transaction(&mut rng).map_err(e)?;
    t.put_local(HOST_KEY_RECORD, key, osis_store::Shred::No).map_err(e)?;
    t.commit().map_err(e)?;
    Ok(s)
}

/// The host task while the node hosts.
struct HostTask {
    cfg: HostConfig,
    ctl: mpsc::Sender<host::Control>,
    task: JoinHandle<osis_host::Hub>,
}

/// A holder owning the engine (`run`).
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

/// The LAN loop's state (feature `lan`).
#[cfg(feature = "lan")]
struct LanLoop {
    cfg: LanConfig,
    sock: Arc<osis_transport::lan::Lan>,
    /// Join at the next check (start, network change, new dialable key).
    rejoin: bool,
    /// When it last joined (network changes rejoin at most every `LAN_REJOIN_MIN`).
    joined: Option<tokio::time::Instant>,
    /// This network's listener: its key and its IPv4 and IPv6 ports.
    listener: Option<([u8; 32], Ports)>,
    next: tokio::time::Instant,
    /// The announcement receiver and the network watch.
    tasks: Vec<JoinHandle<()>>,
}

/// A listener's port per address family.
#[cfg(feature = "lan")]
#[derive(Clone, Copy, Debug, Default)]
struct Ports {
    v4: Option<u16>,
    v6: Option<u16>,
}

/// The ports of the socket addresses a listener URL lists, per family.
#[cfg(feature = "lan")]
fn listen_ports(url: &str) -> Ports {
    let mut p = Ports::default();
    for a in osis_transport::peer_relays(url).unwrap_or_default().iter().filter_map(|h| h.parse::<std::net::SocketAddr>().ok()) {
        let slot = if a.is_ipv4() { &mut p.v4 } else { &mut p.v6 };
        slot.get_or_insert(a.port());
    }
    p
}

/// A listener URL without its IPv6 socket addresses (a machine without IPv6).
#[cfg(feature = "lan")]
fn v4_only(url: &str) -> Option<String> {
    let items = osis_transport::peer_relays(url)?;
    let kept: Vec<String> = items.iter().filter(|h| !h.parse::<std::net::SocketAddr>().is_ok_and(|a| a.is_ipv6())).cloned().collect();
    (kept.len() < items.len()).then(|| osis_transport::peer_url(&kept))
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
    /// Accepted sessions with the key of the listener that took them.
    link_tx: mpsc::Sender<([u8; 32], Link)>,
    /// Running listeners by key: their serve and forward tasks.
    listeners: HashMap<[u8; 32], [JoinHandle<()>; 2]>,
    max_served: usize,
    #[cfg(feature = "lan")]
    lan: Option<LanLoop>,
    #[cfg_attr(not(feature = "lan"), allow(dead_code))]
    lan_tx: mpsc::Sender<(Announce, std::net::SocketAddr)>,
    /// Network changes from the LAN loop's watch.
    #[cfg_attr(not(feature = "lan"), allow(dead_code))]
    net_tx: mpsc::Sender<()>,
    /// The dialable listener's URL and relays (`Control::Reach`), and its key.
    reach: Option<(String, Vec<String>)>,
    dialable: Option<[u8; 32]>,
    /// The engine rotated the dialable secret (`Action::Reach`): listen again (not before
    /// `relisten_at` after a failure).
    relisten: bool,
    relisten_at: Option<tokio::time::Instant>,
    /// Sessions each listener accepted, by its key: they close with it.
    served_by: HashMap<[u8; 32], Vec<ConnId>>,
    /// The running host, and a config change for it not yet carried out (`host_update`).
    host: Option<HostTask>,
    host_want: Option<Option<Box<HostConfig>>>,
    /// The control channel of a host about to start: dials of its address made before it runs
    /// wait there.
    host_chan: Option<(mpsc::Sender<host::Control>, mpsc::Receiver<host::Control>)>,
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
        // a host config first: dials of its address in the same batch go to it
        for a in &acts {
            if let Action::Host(cfg) = a {
                self.host_want = Some(cfg.clone());
            }
        }
        for a in acts {
            match a {
                Action::Dial { conn, address } => {
                    let t = self.transport.clone();
                    let ev = self.ev_tx.clone();
                    let addr = Address { url: address.url, key: address.key };
                    let own = self.own_host(&addr.key);
                    let task = tokio::spawn(async move {
                        let dialed = match own {
                            // the host this node runs: an in-process session with an ephemeral key
                            Some(ctl) => {
                                let mut k = [0u8; 32];
                                osis_crypto::OsRng.fill_bytes(&mut k);
                                let (mine, theirs) = link::pair(k, addr.key);
                                match ctl.send(host::Control::Accept(theirs)).await {
                                    Ok(()) => Ok(mine),
                                    Err(_) => Err("own host stopped".to_string()),
                                }
                            }
                            None => link::dial(&*t, &addr, None, FINISH_WAIT).await.map_err(|e| e.to_string()),
                        };
                        let link = match dialed {
                            Ok(l) => l,
                            Err(e) => {
                                let _ = ev.send(Ev::Failed(conn, e)).await;
                                return;
                            }
                        };
                        let Link { tx, rx, .. } = link;
                        if ev.send(Ev::Up(conn, tx)).await.is_ok() {
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
                Action::Host(_) => {}
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

    /// Serves the sessions `l` accepts (replacing a listener of the same key).
    fn serve(&mut self, l: T::Listener) -> Address {
        let addr = l.address();
        let key = addr.key;
        self.unlisten(key);
        let (tx, mut rx) = mpsc::channel::<Link>(64);
        let serve = tokio::spawn(link::serve(l, SERVE_IDLE, FINISH_WAIT, tx, self.max_served));
        let out = self.link_tx.clone();
        let fwd = tokio::spawn(async move {
            while let Some(link) = rx.recv().await {
                if out.send((key, link)).await.is_err() {
                    return;
                }
            }
        });
        self.listeners.insert(key, [serve, fwd]);
        addr
    }

    fn unlisten(&mut self, key: [u8; 32]) {
        if let Some(ts) = self.listeners.remove(&key) {
            for t in ts {
                t.abort();
            }
        }
    }

    /// `unlisten`, returning once the listener is dropped (its address is free again), and
    /// closing the sessions it accepted (as an iroh endpoint closes its connections).
    async fn unlisten_now(&mut self, key: [u8; 32]) {
        if let Some(ts) = self.listeners.remove(&key) {
            for t in ts {
                t.abort();
                let _ = t.await;
            }
        }
        for conn in self.served_by.remove(&key).unwrap_or_default() {
            if self.conns.contains_key(&conn) {
                self.close(conn);
                self.feed(Event::Down { conn });
            }
        }
    }

    async fn listen(&mut self, cfg: ListenConfig) -> Result<Address, String> {
        match self.transport.listen(cfg).await {
            Ok(l) => Ok(self.serve(l)),
            Err(e) => {
                (self.log)(&format!("listen: {e}"));
                Err(e.to_string())
            }
        }
    }

    /// Listens with the dialable secret and publishes `reach.0` with that listener's key; a
    /// listener of an older dialable key stops.
    async fn reach(&mut self, url: String, relays: Vec<String>) -> Result<Address, String> {
        self.reach = Some((url.clone(), relays.clone()));
        let Some(secret) = self.read(|s| transport_secret(&s.dialable_secret())) else { return Err("engine gone".into()) };
        let addr = self.listen(ListenConfig { url, secret }).await?;
        let key = addr.key;
        if let Some(old) = self.dialable.replace(key).filter(|k| *k != key) {
            self.unlisten(old);
        }
        self.call(&mut |s| match s.publish_reach(key, relays.clone()) {
            Ok(a) => a,
            Err(e) => {
                s.diag(format!("publishing reach.0: {e}"));
                Vec::new()
            }
        });
        Ok(addr)
    }

    /// A peer's session on the listener of key `key`.
    fn accepted(&mut self, key: [u8; 32], l: Link) {
        let Link { peer, tx, rx, .. } = l;
        // the connection exists before its first actions are carried out
        let mut conn = None;
        let shared = &self.shared;
        let acts = blocking(|| {
            shared.with(&mut |s| {
                let (c, acts) = s.accept_peer(key, peer);
                conn = Some(c);
                acts
            })
        });
        if let Some(conn) = conn {
            let task = tokio::spawn(forward(conn, rx, self.ev_tx.clone()));
            self.conns.insert(conn, Conn { tx: Some(tx), task, taken: u64::MAX });
            let conns = &self.conns;
            let v = self.served_by.entry(key).or_default();
            v.retain(|c| conns.contains_key(c));
            v.push(conn);
        }
        match acts {
            Some(a) => self.apply(a),
            None => self.gone = true,
        }
    }

    fn event(&mut self, ev: Ev) {
        match ev {
            Ev::Up(conn, tx) => {
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.tx = Some(tx);
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

    /// Starts the LAN loop (feature `lan`): binds the announcement socket; the first check
    /// joins the network.
    #[cfg(feature = "lan")]
    async fn lan_start(&mut self, cfg: LanConfig) {
        if let Some(old) = self.lan.take() {
            old.tasks.iter().for_each(JoinHandle::abort);
        }
        let sock = match osis_transport::lan::Lan::bind(cfg.port).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                (self.log)(&format!("LAN: {e}"));
                return;
            }
        };
        let (s2, tx) = (sock.clone(), self.lan_tx.clone());
        let mut tasks = vec![tokio::spawn(async move {
            while let Ok(x) = s2.recv().await {
                // a flood is dropped, not queued
                if let Err(mpsc::error::TrySendError::Closed(_)) = tx.try_send(x) {
                    return;
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
        self.lan = Some(LanLoop { cfg, sock, rejoin: true, joined: None, listener: None, next: tokio::time::Instant::now(), tasks });
        self.lan_check().await;
    }

    /// Joins the network again at the next check (a network change, a new dialable key).
    #[cfg(feature = "lan")]
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
    /// listener and listens with a fresh key, announced at once; announcements repeat every
    /// `LAN_ANNOUNCE`, each family's carrying the listener's port on that family.
    #[cfg(feature = "lan")]
    async fn lan_check(&mut self) {
        let now = tokio::time::Instant::now();
        let Some((old, url)) = self.lan.as_mut().filter(|x| x.rejoin && x.joined.is_none_or(|t| t + x.cfg.rejoin_min <= now)).map(|x| {
            x.rejoin = false;
            x.joined = Some(now);
            (x.listener.take(), x.cfg.listen.clone())
        }) else {
            return self.lan_announce().await;
        };
        if let Some((k, _)) = old {
            self.unlisten_now(k).await;
        }
        let Some(secret) = self.read(|s| transport_secret(&s.lan_secret())) else { return };
        let mut r = self.listen(ListenConfig { url: url.clone(), secret: secret.clone() }).await;
        if r.is_err()
            && let Some(v4) = v4_only(&url)
        {
            r = self.listen(ListenConfig { url: v4, secret }).await;
        }
        if let Some(x) = self.lan.as_mut() {
            x.listener = r.ok().map(|a| (a.key, listen_ports(&a.url)));
            x.next = tokio::time::Instant::now();
        }
        self.lan_announce().await;
    }

    /// Announces this network's listener when due.
    #[cfg(feature = "lan")]
    async fn lan_announce(&mut self) {
        let now = tokio::time::Instant::now();
        let Some((key, ports, to, sock)) = self.lan.as_ref().filter(|x| x.next <= now).and_then(|x| x.listener.map(|(k, p)| (k, p, x.cfg.to.clone(), x.sock.clone()))) else { return };
        if let Some(x) = self.lan.as_mut() {
            x.next = now + LAN_ANNOUNCE;
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

    fn lan_on(&self) -> bool {
        #[cfg(feature = "lan")]
        return self.lan.is_some();
        #[cfg(not(feature = "lan"))]
        false
    }

    /// Carries out a control; false: shut down.
    async fn control(&mut self, c: Option<Control>) -> bool {
        match c {
            Some(Control::Local) => self.feed(Event::Local),
            Some(Control::Tick) => self.tick(),
            Some(Control::Call(f)) => {
                let mut f = Some(f);
                self.call(&mut |s| f.take().map(|f| f(s)).unwrap_or_default());
            }
            Some(Control::Apply(acts)) => self.apply(acts),
            Some(Control::Reach { url, relays, reply }) => {
                let r = self.reach(url, relays).await;
                if let Some(reply) = reply {
                    let _ = reply.send(r);
                }
            }
            Some(Control::Listen { url, reply }) => {
                let mut k = [0u8; 32];
                osis_crypto::OsRng.fill_bytes(&mut k);
                let r = self.listen(ListenConfig { url, secret: StaticSecret::from_bytes(k) }).await;
                if let Some(reply) = reply {
                    let _ = reply.send(r);
                }
            }
            #[cfg(feature = "lan")]
            Some(Control::Lan(cfg)) => self.lan_start(cfg).await,
            #[cfg(feature = "lan")]
            Some(Control::LanRejoin) => self.lan_rejoin(false).await,
            #[cfg(not(feature = "lan"))]
            Some(Control::Lan(_) | Control::LanRejoin) => (self.log)("LAN: built without feature `lan`"),
            Some(Control::Shutdown) | None => return false,
        }
        true
    }

    /// The control channel of the host this node runs (or is about to start) under `key`.
    fn own_host(&mut self, key: &[u8; 32]) -> Option<mpsc::Sender<host::Control>> {
        if let Some(h) = self.host.as_ref().filter(|h| h.cfg.key == *key) {
            return Some(h.ctl.clone());
        }
        let Some(Some(c)) = &self.host_want else { return None };
        (c.key == *key).then(|| self.host_chan.get_or_insert_with(|| mpsc::channel(64)).0.clone())
    }

    /// Carries out the last `Action::Host`: stops the host, starts it, or changes it in place
    /// (only the admission or caps changed) or by a restart (its hub kept).
    async fn host_update(&mut self) {
        let Some(want) = self.host_want.take() else { return };
        // dials waiting for a host that does not start fail
        let chan = self.host_chan.take();
        let Some(cfg) = want else {
            if let Some(h) = self.host.take() {
                let _ = h.ctl.send(host::Control::Shutdown).await;
                // the hub, and with it the host store, closes here
                drop(h.task.await);
            }
            // hosting stopped (not the driver): the host store goes with the host secret
            if self.read(|s| s.host_key().is_none()) == Some(true) {
                let shared = &self.shared;
                if let Err(e) = blocking(|| shared.erase_host_store()) {
                    (self.log)(&format!("erasing the host store: {e}"));
                }
            }
            return;
        };
        let cfg = *cfg;
        if let Some(h) = self.host.as_mut()
            && (HostConfig { admission: cfg.admission.clone(), caps: cfg.caps.clone(), ..h.cfg.clone() }) == cfg
        {
            let _ = h.ctl.send(host::Control::Admit(cfg.admission.clone(), cfg.caps.clone())).await;
            h.cfg = cfg;
            return;
        }
        // a config whose key is no longer the node's (hosting stopped and maybe started again
        // since it was emitted): the newer `Action::Host` is on its way
        let Some(Some(secret)) = self.read(|s| s.host_secret_for(&cfg.key).map(|x| transport_secret(&x))) else { return };
        let hub = match self.host.take() {
            Some(h) => {
                let _ = h.ctl.send(host::Control::Shutdown).await;
                h.task.await.ok()
            }
            None => None,
        };
        let hub = match hub {
            Some(mut hub) if hub.static_key() == cfg.key => {
                hub.store_mut().set_policy(cfg.policy.clone());
                hub
            }
            old => {
                // an old key's hub closes its store before it is opened again
                drop(old);
                let shared = &self.shared;
                let opened = blocking(|| open_host_store(shared, &cfg.key).and_then(|s| osis_host::HostStore::open(s, self.clock.clone(), cfg.policy.clone(), Box::new(osis_crypto::OsRng)).map_err(|e| e.to_string())));
                match opened {
                    Ok(store) => osis_host::Hub::new(store, cfg.key, Box::new(osis_crypto::OsRng)),
                    Err(e) => return self.host_status(HostStatus::Failed(format!("host store: {e}"))),
                }
            }
        };
        let mut hub = hub;
        hub.store_mut().set_admission(cfg.admission.clone(), cfg.caps.clone());
        let mut listeners = Vec::new();
        let mut addrs = Vec::new();
        for url in &cfg.listen {
            match self.transport.listen(ListenConfig { url: url.clone(), secret: secret.clone() }).await {
                Ok(l) => {
                    let a = l.address();
                    addrs.push(osis_label::Address { url: a.url, key: a.key });
                    listeners.push(l);
                }
                Err(e) => return self.host_status(HostStatus::Failed(format!("listen {url}: {e}"))),
            }
        }
        let (ctl, rx) = chan.unwrap_or_else(|| mpsc::channel(64));
        let ep = host::Endpoint { transport: self.transport.clone(), listeners, secret };
        let task = tokio::spawn(host::run(hub, ep, cfg.replicate.clone(), self.clock.clone(), rx, self.log.clone()));
        self.host = Some(HostTask { cfg, ctl, task });
        self.host_status(HostStatus::Listening(addrs));
    }

    fn host_status(&mut self, st: HostStatus) {
        if let HostStatus::Failed(e) = &st {
            (self.log)(&format!("hosting: {e}"));
        }
        self.call(&mut |s| {
            s.set_host_status(st.clone());
            Vec::new()
        });
    }

    /// After `Action::Reach`: listens with the new dialable secret (the old listener stops) and
    /// joins the LAN again, so nothing announced or listening carries the old key.
    async fn after_rotation(&mut self) {
        if !self.relisten || self.relisten_at.is_some_and(|t| t > tokio::time::Instant::now()) {
            return;
        }
        self.relisten = false;
        self.relisten_at = None;
        if let Some((url, relays)) = self.reach.clone() {
            // the old listener goes first: the new one takes its place (its URL, its relays)
            if let Some(old) = self.dialable.take() {
                self.unlisten_now(old).await;
            }
            if let Err(e) = self.reach(url, relays).await {
                // `reach.0` already names the new key: keep trying
                (self.log)(&format!("listening with the new dialable key: {e}; again in {RELISTEN_RETRY:?}"));
                self.relisten = true;
                self.relisten_at = Some(tokio::time::Instant::now() + RELISTEN_RETRY);
            }
        }
        #[cfg(feature = "lan")]
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

/// `run`, also serving the peer sessions the `listeners` accept (more come with
/// `Control::Reach` and the LAN loop): one listening with the engine's `dialable_secret`
/// (publish its `address().key` with `publish_reach`), and one per LAN join with a fresh secret
/// whose key is announced with the LAN tag (spec/sync.md §10). Never put a listener's
/// `address().url` into `reach.0`: it lists bound IP addresses, which are never published
/// (spec/sync.md §10); only its key and the relays go there.
pub async fn run_serving<T: Transport>(sync: SyncEngine, transport: T, listeners: Vec<T::Listener>, clock: Arc<dyn Clock>, control: mpsc::UnboundedReceiver<Control>, log: Log) -> SyncEngine {
    let Owned(m) = run_shared(Owned(std::sync::Mutex::new(sync)), transport, listeners, clock, control, log).await;
    m.into_inner().unwrap_or_else(|p| p.into_inner())
}

/// `run_serving` over a holder; returns it at `Control::Shutdown`, when the control sender is
/// dropped or when the holder's engine is gone.
pub async fn run_shared<T: Transport, H: Shared>(shared: H, transport: T, listeners: Vec<T::Listener>, clock: Arc<dyn Clock>, mut control: mpsc::UnboundedReceiver<Control>, log: Log) -> H {
    let (ev_tx, mut ev_rx) = mpsc::channel(1024);
    let (link_tx, mut link_rx) = mpsc::channel::<([u8; 32], Link)>(64);
    let (lan_tx, mut lan_rx) = mpsc::channel(64);
    #[cfg_attr(not(feature = "lan"), allow(unused_mut))]
    let (net_tx, mut net_rx) = mpsc::channel::<()>(1);
    let mut max = 0;
    let _ = shared.with(&mut |s| {
        max = s.config().max_served;
        Vec::new()
    });
    let mut d = Driver {
        shared,
        gone: false,
        transport: Arc::new(transport),
        clock,
        log,
        conns: HashMap::new(),
        wake: None,
        ev_tx,
        link_tx,
        listeners: HashMap::new(),
        max_served: max,
        #[cfg(feature = "lan")]
        lan: None,
        lan_tx,
        net_tx,
        reach: None,
        dialable: None,
        relisten: false,
        relisten_at: None,
        served_by: HashMap::new(),
        host: None,
        host_want: None,
        host_chan: None,
    };
    for l in listeners {
        d.serve(l);
    }
    d.call(&mut |s| {
        s.host_restart();
        Vec::new()
    });
    // a host store left by a stop no driver carried out (not hosting: erased)
    d.host_want = Some(None);
    d.host_update().await;
    d.feed(Event::Tick);
    let mut lan_tick = tokio::time::interval(LAN_CHECK);
    while !d.gone {
        let idle = d.idle();
        let lan_on = d.lan_on();
        // timers wait while control has a message: a `Shutdown` queued just before the holder's
        // runtime shuts down (the task resuming after an engine call's `block_in_place`) is
        // seen before a timer of the shut-down runtime is polled (tokio panics)
        let quiet = control.is_empty();
        tokio::select! {
            Some((key, l)) = link_rx.recv() => d.accepted(key, l),
            Some(ev) = ev_rx.recv() => d.event(ev),
            c = control.recv() => {
                if !d.control(c).await {
                    break;
                }
            }
            _ = lan_tick_wait(&mut lan_tick, lan_on), if quiet => {
                #[cfg(feature = "lan")]
                d.lan_check().await;
            }
            Some((a, from)) = lan_rx.recv() => d.call(&mut |s| s.lan_seen(&a, from).1),
            Some(()) = net_rx.recv() => {
                #[cfg(feature = "lan")]
                d.lan_rejoin(false).await;
            }
            _ = sleep_until(d.relisten_at), if quiet => {}
            _ = tokio::time::sleep(idle), if quiet => {
                d.wake = None;
                d.tick();
            }
        }
        d.after_rotation().await;
        d.host_update().await;
    }
    d.host_want = Some(None);
    d.host_update().await;
    #[cfg(feature = "lan")]
    if let Some(x) = d.lan.take() {
        x.tasks.iter().for_each(JoinHandle::abort);
    }
    let keys: Vec<[u8; 32]> = d.listeners.keys().copied().collect();
    for k in keys {
        d.unlisten(k);
    }
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

/// The LAN check timer while the loop runs, else never.
async fn lan_tick_wait(t: &mut tokio::time::Interval, on: bool) {
    if on {
        t.tick().await;
    } else {
        std::future::pending::<()>().await
    }
}

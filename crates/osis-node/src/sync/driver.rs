//! The tokio driver (feature `driver`; notes/architecture.md §2): moves the `SyncEngine`'s bytes
//! over osis-transport `link` sessions (one dialed stream per connection, an ephemeral transport
//! key per connection, the peer's key checked by the transport, spec/sync.md §10) and fires its timers. Every session a peer opens on one of its
//! listeners is served by the engine (`SyncEngine::accept`, member peer, spec/sync.md §5);
//! more listeners come while it runs (`Control::Reach`, the LAN loop's per-network listener).
//! With feature `lan`, `Control::Lan` runs the LAN loop (spec/sync.md §10): per network a fresh
//! transport key and listener, announced on join and every `LAN_ANNOUNCE`; announcements heard go
//! to `SyncEngine::lan_seen`. No sync logic lives here: every input is an `Event`, every output an
//! `Action`. Engine calls run under `block_in_place` on a multi-thread runtime. The engine lives
//! in a `Host`: owned by the driver (`run`), or shared with the app (`run_host`: the `osis` handle
//! keeps it behind its own lock and hands the driver the actions of its calls).

use super::{Action, ConnId, Event, SyncEngine};
use osis_core::Clock;
use osis_transport::link::{self, Link, LinkTx};
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
/// How long a session's end waits for the server to take our last bytes.
pub const FINISH_WAIT: Duration = Duration::from_secs(10);
/// Bytes queued for a connection and not yet taken by the transport before it is dropped.
pub const MAX_QUEUED: usize = 64 * 1024 * 1024;
/// LAN loop: how often the route is checked for a network change, and announcements repeat
/// (provisional).
pub const LAN_CHECK: Duration = Duration::from_secs(5);
pub const LAN_ANNOUNCE: Duration = Duration::from_secs(30);

/// A call on the sync engine from the app (create a label, signal, compact, read the engine):
/// its actions are carried out.
pub type Call = Box<dyn FnOnce(&mut SyncEngine) -> Vec<Action> + Send>;

/// The LAN loop's settings (feature `lan`).
#[derive(Clone, Debug)]
pub struct LanConfig {
    /// The announcement socket's port (`lan::PORT`; 0: any, tests).
    pub port: u16,
    /// Where announcements go (the broadcast address at `lan::PORT`; hosts in tests).
    pub to: Vec<std::net::SocketAddr>,
    /// The LAN listener's URL (`peer://0.0.0.0:0`: all IPv4 interfaces, any port).
    pub listen: String,
}

impl Default for LanConfig {
    fn default() -> LanConfig {
        LanConfig { port: osis_transport::lan::PORT, to: vec![osis_transport::lan::broadcast(osis_transport::lan::PORT)], listen: "peer://0.0.0.0:0".into() }
    }
}

/// Commands to a running driver.
pub enum Control {
    /// The engine changed through local calls: look at its events.
    Local,
    /// Run timers now.
    Tick,
    Call(Call),
    /// Actions the host's own calls produced: carry them out.
    Apply(Vec<Action>),
    /// Listen at `url` with the engine's dialable secret and publish `/reach` with that
    /// listener's key and `relays` (spec/data-model.md §9). For iroh, `url` lists the relays the
    /// listener registers at (`peer_url(relays)`).
    Reach { url: String, relays: Vec<String>, reply: Option<oneshot::Sender<Result<Address, String>>> },
    /// Run the LAN loop (feature `lan`; ignored without it).
    Lan(LanConfig),
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

/// Pumps a session's bytes to the driver.
fn pump(conn: ConnId, mut rx: link::LinkRx, ev: mpsc::Sender<Ev>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(b) = rx.recv().await {
            if ev.send(Ev::Bytes(conn, b)).await.is_err() {
                return;
            }
        }
        let _ = ev.send(Ev::Closed(conn)).await;
    })
}

struct Conn {
    tx: Option<LinkTx>,
    task: JoinHandle<()>,
}

fn blocking<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
    }
}

/// Where the sync engine lives while a driver runs.
pub trait Host: Send + Sync + 'static {
    /// Runs `f` on the engine; returns its actions. `None`: the engine is gone (the driver stops).
    fn with(&self, f: &mut dyn FnMut(&mut SyncEngine) -> Vec<Action>) -> Option<Vec<Action>>;
}

/// A host owning the engine (`run`).
pub struct Owned(std::sync::Mutex<SyncEngine>);

impl Host for Owned {
    fn with(&self, f: &mut dyn FnMut(&mut SyncEngine) -> Vec<Action>) -> Option<Vec<Action>> {
        let mut g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        Some(f(&mut g))
    }
}

/// A transport secret from the engine's 32 bytes.
fn static_secret(s: &osis_crypto::Secret32) -> StaticSecret {
    StaticSecret::from_bytes(*s.expose())
}

/// The LAN loop's state (feature `lan`).
#[cfg(feature = "lan")]
struct LanLoop {
    cfg: LanConfig,
    sock: Arc<osis_transport::lan::Lan>,
    /// The route's local IP at the last join (`None` inside: no route).
    route: Option<Option<std::net::IpAddr>>,
    /// This network's listener: its key and port.
    listener: Option<([u8; 32], u16)>,
    next: tokio::time::Instant,
    recv: JoinHandle<()>,
}

/// The port of the first socket address a listener URL lists.
#[cfg(feature = "lan")]
fn listen_port(url: &str) -> Option<u16> {
    let rest = url.split_once("://")?.1;
    rest.split(' ').find_map(|h| h.parse::<std::net::SocketAddr>().ok()).map(|a| a.port())
}

struct Driver<T: Transport, H: Host> {
    host: H,
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
    lan_tx: mpsc::Sender<(Announce, std::net::IpAddr)>,
}

impl<T: Transport, H: Host> Driver<T, H> {
    fn call(&mut self, f: &mut dyn FnMut(&mut SyncEngine) -> Vec<Action>) {
        let host = &self.host;
        match blocking(|| host.with(f)) {
            Some(acts) => self.apply(acts),
            None => self.gone = true,
        }
    }

    /// Reads something off the engine (no actions).
    fn read<R>(&mut self, f: impl FnOnce(&mut SyncEngine) -> R) -> Option<R> {
        let mut f = Some(f);
        let mut out = None;
        let host = &self.host;
        let r = blocking(|| {
            host.with(&mut |s| {
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
                    let task = tokio::spawn(async move {
                        let link = match link::dial(&*t, &addr, None, FINISH_WAIT).await {
                            Ok(l) => l,
                            Err(e) => {
                                let _ = ev.send(Ev::Failed(conn, e.to_string())).await;
                                return;
                            }
                        };
                        let Link { tx, mut rx, .. } = link;
                        if ev.send(Ev::Up(conn, tx)).await.is_err() {
                            return;
                        }
                        while let Some(b) = rx.recv().await {
                            if ev.send(Ev::Bytes(conn, b)).await.is_err() {
                                return;
                            }
                        }
                        let _ = ev.send(Ev::Closed(conn)).await;
                    });
                    self.conns.insert(conn, Conn { tx: None, task });
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
            }
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

    /// Serves the sessions `l` accepts (replacing a listener of the same key).
    fn serve(&mut self, l: T::Listener) -> Address {
        let addr = l.address();
        let key = addr.key;
        self.unlisten(key);
        let (tx, mut rx) = mpsc::channel::<Link>(64);
        let serve = tokio::spawn(link::serve_max(l, SERVE_IDLE, FINISH_WAIT, tx, self.max_served));
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

    async fn listen(&mut self, cfg: ListenConfig) -> Result<Address, String> {
        match self.transport.listen(cfg).await {
            Ok(l) => Ok(self.serve(l)),
            Err(e) => {
                (self.log)(&format!("listen: {e}"));
                Err(e.to_string())
            }
        }
    }

    /// Listens with the dialable secret and publishes `/reach` with that listener's key.
    async fn reach(&mut self, url: String, relays: Vec<String>) -> Result<Address, String> {
        let Some(secret) = self.read(|s| static_secret(&s.dialable_secret())) else { return Err("engine gone".into()) };
        let addr = self.listen(ListenConfig { url, secret }).await?;
        let key = addr.key;
        self.call(&mut |s| match s.publish_reach(key, relays.clone()) {
            Ok(a) => a,
            Err(e) => {
                s.diag(format!("publishing /reach: {e}"));
                Vec::new()
            }
        });
        Ok(addr)
    }

    /// A peer's session on the listener of key `key`.
    fn accepted(&mut self, key: [u8; 32], l: Link) {
        let Link { peer_key, tx, rx } = l;
        // the connection exists before its first actions are carried out
        let mut conn = None;
        let host = &self.host;
        let acts = blocking(|| {
            host.with(&mut |s| {
                let (c, acts) = s.accept(key, peer_key);
                conn = Some(c);
                acts
            })
        });
        if let Some(conn) = conn {
            let task = pump(conn, rx, self.ev_tx.clone());
            self.conns.insert(conn, Conn { tx: Some(tx), task });
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
                if self.conns.contains_key(&conn) {
                    self.feed(Event::Bytes { conn, bytes });
                }
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
            old.recv.abort();
        }
        let sock = match osis_transport::lan::Lan::bind(cfg.port).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                (self.log)(&format!("LAN: {e}"));
                return;
            }
        };
        let (s2, tx) = (sock.clone(), self.lan_tx.clone());
        let recv = tokio::spawn(async move {
            while let Ok(x) = s2.recv().await {
                // a flood is dropped, not queued
                if let Err(mpsc::error::TrySendError::Closed(_)) = tx.try_send(x) {
                    return;
                }
            }
        });
        self.lan = Some(LanLoop { cfg, sock, route: None, listener: None, next: tokio::time::Instant::now(), recv });
        self.lan_check().await;
    }

    /// The LAN loop's timer: a new route means a new network (a fresh key and listener,
    /// announced at once); announcements repeat every `LAN_ANNOUNCE`.
    #[cfg(feature = "lan")]
    async fn lan_check(&mut self) {
        let Some(route) = (match &self.lan {
            Some(_) => Some(osis_transport::lan::route_ip().await),
            None => None,
        }) else {
            return;
        };
        let joined = self.lan.as_ref().is_some_and(|x| x.route != Some(route));
        if joined {
            let (old, url) = match self.lan.as_mut() {
                Some(x) => {
                    x.route = Some(route);
                    (x.listener.take(), x.cfg.listen.clone())
                }
                None => return,
            };
            if let Some((k, _)) = old {
                self.unlisten(k);
            }
            let Some(secret) = self.read(|s| static_secret(&s.lan_secret())) else { return };
            let joined = match self.listen(ListenConfig { url, secret }).await {
                Ok(a) => listen_port(&a.url).map(|p| (a.key, p)),
                Err(_) => None,
            };
            if let Some(x) = self.lan.as_mut() {
                x.listener = joined;
                x.next = tokio::time::Instant::now();
            }
        }
        let now = tokio::time::Instant::now();
        let Some((key, port, to, sock)) = self.lan.as_ref().filter(|x| x.next <= now).and_then(|x| x.listener.map(|(k, p)| (k, p, x.cfg.to.clone(), x.sock.clone()))) else { return };
        if let Some(x) = self.lan.as_mut() {
            x.next = now + LAN_ANNOUNCE;
        }
        if let Some(Some(a)) = self.read(|s| s.lan_announcement(key, port)) {
            for t in to {
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
            Some(Control::Tick) => self.feed(Event::Tick),
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
            #[cfg(feature = "lan")]
            Some(Control::Lan(cfg)) => self.lan_start(cfg).await,
            #[cfg(not(feature = "lan"))]
            Some(Control::Lan(_)) => (self.log)("LAN: built without feature `lan`"),
            Some(Control::Shutdown) | None => return false,
        }
        true
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
/// `address().url` into `/reach`: it lists bound IP addresses, which are never published
/// (spec/sync.md §10); only its key and the relays go there.
pub async fn run_serving<T: Transport>(sync: SyncEngine, transport: T, listeners: Vec<T::Listener>, clock: Arc<dyn Clock>, control: mpsc::UnboundedReceiver<Control>, log: Log) -> SyncEngine {
    let Owned(m) = run_host(Owned(std::sync::Mutex::new(sync)), transport, listeners, clock, control, log).await;
    m.into_inner().unwrap_or_else(|p| p.into_inner())
}

/// `run_serving` over a host; returns it at `Control::Shutdown`, when the control sender is
/// dropped or when the host's engine is gone.
pub async fn run_host<T: Transport, H: Host>(host: H, transport: T, listeners: Vec<T::Listener>, clock: Arc<dyn Clock>, mut control: mpsc::UnboundedReceiver<Control>, log: Log) -> H {
    let (ev_tx, mut ev_rx) = mpsc::channel(1024);
    let (link_tx, mut link_rx) = mpsc::channel::<([u8; 32], Link)>(64);
    let (lan_tx, mut lan_rx) = mpsc::channel(64);
    let mut max = 0;
    let _ = host.with(&mut |s| {
        max = s.config().max_served;
        Vec::new()
    });
    let mut d = Driver {
        host,
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
    };
    for l in listeners {
        d.serve(l);
    }
    d.feed(Event::Tick);
    let mut lan_tick = tokio::time::interval(LAN_CHECK);
    while !d.gone {
        let idle = d.idle();
        let lan_on = d.lan_on();
        tokio::select! {
            Some((key, l)) = link_rx.recv() => d.accepted(key, l),
            Some(ev) = ev_rx.recv() => d.event(ev),
            c = control.recv() => {
                if !d.control(c).await {
                    break;
                }
            }
            _ = lan_tick_wait(&mut lan_tick, lan_on) => {
                #[cfg(feature = "lan")]
                d.lan_check().await;
            }
            Some((a, from)) = lan_rx.recv() => d.call(&mut |s| s.lan_seen(&a, from).1),
            _ = tokio::time::sleep(idle) => {
                d.wake = None;
                d.feed(Event::Tick);
            }
        }
    }
    #[cfg(feature = "lan")]
    if let Some(x) = d.lan.take() {
        x.recv.abort();
    }
    let keys: Vec<[u8; 32]> = d.listeners.keys().copied().collect();
    for k in keys {
        d.unlisten(k);
    }
    let ids: Vec<ConnId> = d.conns.keys().copied().collect();
    for id in ids {
        d.close(id);
    }
    d.host
}

/// The LAN check timer while the loop runs, else never.
async fn lan_tick_wait(t: &mut tokio::time::Interval, on: bool) {
    if on {
        t.tick().await;
    } else {
        std::future::pending::<()>().await
    }
}

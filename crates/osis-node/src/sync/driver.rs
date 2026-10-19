//! The tokio driver (feature `driver`; notes/architecture.md §2): moves the `SyncEngine`'s bytes
//! over osis-transport `link` sessions (one dialed stream per server connection, an ephemeral
//! transport key per connection, the server's key checked by the transport, spec/sync.md §10)
//! and fires its timers. With a listener (`run_serving`), every session a peer opens on it is
//! served by the engine (`SyncEngine::accept`, member peer, spec/sync.md §5). No sync logic lives here: every input is an `Event`, every output an
//! `Action`. Engine calls run under `block_in_place` on a multi-thread runtime.

use super::{Action, ConnId, Event, SyncEngine};
use osis_core::Clock;
use osis_transport::link::{self, Link, LinkTx};
use osis_transport::{Listener, Transport};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// A served connection with no session for this long is closed.
pub const SERVE_IDLE: Duration = Duration::from_secs(120);

/// Longest wait between ticks.
pub const MAX_IDLE: Duration = Duration::from_secs(60);
/// How long a session's end waits for the server to take our last bytes.
pub const FINISH_WAIT: Duration = Duration::from_secs(10);
/// Bytes queued for a connection and not yet taken by the transport before it is dropped.
pub const MAX_QUEUED: usize = 64 * 1024 * 1024;

/// A call on the sync engine from the app (create a label, signal, compact, read the engine):
/// its actions are carried out.
pub type Call = Box<dyn FnOnce(&mut SyncEngine) -> Vec<Action> + Send>;

/// Commands to a running driver.
pub enum Control {
    /// The engine changed through local calls: look at its events.
    Local,
    /// Run timers now.
    Tick,
    Call(Call),
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

/// Pumps a served session's bytes to the driver.
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

struct Driver<T: Transport> {
    sync: SyncEngine,
    transport: Arc<T>,
    clock: Arc<dyn Clock>,
    log: Log,
    conns: HashMap<ConnId, Conn>,
    wake: Option<u64>,
    ev_tx: mpsc::Sender<Ev>,
}

impl<T: Transport> Driver<T> {
    fn feed(&mut self, ev: Event) {
        let acts = blocking(|| self.sync.handle(ev));
        self.apply(acts);
    }

    fn apply(&mut self, acts: Vec<Action>) {
        for a in acts {
            match a {
                Action::Dial { conn, address } => {
                    let t = self.transport.clone();
                    let ev = self.ev_tx.clone();
                    let addr = osis_transport::Address { url: address.url, key: address.key };
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
}

/// Runs the sync engine until `Control::Shutdown` (or the control sender is dropped) and
/// returns it. Dials what it asks for over `transport`; ticks when its wake comes due.
pub async fn run<T: Transport>(sync: SyncEngine, transport: T, clock: Arc<dyn Clock>, control: mpsc::Receiver<Control>, log: Log) -> SyncEngine {
    run_serving(sync, transport, Vec::new(), clock, control, log).await
}

/// `run`, also serving the peer sessions the `listeners` accept: one listening with the engine's
/// `dialable_secret` (publish its `address().key` with `publish_reach`), and one per LAN join
/// with a fresh secret whose key is announced with the LAN tag (spec/sync.md §10). Never put a
/// listener's `address().url` into `/reach`: it lists bound IP addresses, which are never
/// published (spec/sync.md §10); only its key and the relays go there.
pub async fn run_serving<T: Transport>(sync: SyncEngine, transport: T, listeners: Vec<T::Listener>, clock: Arc<dyn Clock>, mut control: mpsc::Receiver<Control>, log: Log) -> SyncEngine {
    let (ev_tx, mut ev_rx) = mpsc::channel(1024);
    let (link_tx, mut link_rx) = mpsc::channel::<([u8; 32], Link)>(64);
    let mut serving = Vec::new();
    let max = sync.config().max_served;
    for l in listeners {
        let key = l.address().key;
        let (tx, mut rx) = mpsc::channel::<Link>(64);
        serving.push(tokio::spawn(link::serve_max(l, SERVE_IDLE, FINISH_WAIT, tx, max)));
        let out = link_tx.clone();
        serving.push(tokio::spawn(async move {
            while let Some(link) = rx.recv().await {
                if out.send((key, link)).await.is_err() {
                    return;
                }
            }
        }));
    }
    drop(link_tx);
    let mut d = Driver { sync, transport: Arc::new(transport), clock, log, conns: HashMap::new(), wake: None, ev_tx };
    d.feed(Event::Tick);
    loop {
        let idle = d.idle();
        tokio::select! {
            Some((key, l)) = link_rx.recv() => {
                let Link { peer_key, tx, rx } = l;
                let (conn, acts) = blocking(|| d.sync.accept(key, peer_key));
                let task = pump(conn, rx, d.ev_tx.clone());
                d.conns.insert(conn, Conn { tx: Some(tx), task });
                d.apply(acts);
            }
            Some(ev) = ev_rx.recv() => match ev {
                Ev::Up(conn, tx) => {
                    if let Some(c) = d.conns.get_mut(&conn) {
                        c.tx = Some(tx);
                        d.feed(Event::Up { conn });
                    }
                }
                Ev::Failed(conn, e) => {
                    (d.log)(&format!("connection {conn}: {e}"));
                    d.conns.remove(&conn);
                    d.feed(Event::Down { conn });
                }
                Ev::Bytes(conn, bytes) => {
                    if d.conns.contains_key(&conn) {
                        d.feed(Event::Bytes { conn, bytes });
                    }
                }
                Ev::Closed(conn) => {
                    if d.conns.remove(&conn).is_some() {
                        d.feed(Event::Down { conn });
                    }
                }
            },
            c = control.recv() => match c {
                Some(Control::Local) => d.feed(Event::Local),
                Some(Control::Tick) => d.feed(Event::Tick),
                Some(Control::Call(f)) => {
                    let acts = blocking(|| f(&mut d.sync));
                    d.apply(acts);
                }
                Some(Control::Shutdown) | None => break,
            },
            _ = tokio::time::sleep(idle) => {
                d.wake = None;
                d.feed(Event::Tick);
            }
        }
    }
    for s in serving {
        s.abort();
    }
    let ids: Vec<ConnId> = d.conns.keys().copied().collect();
    for id in ids {
        d.close(id);
    }
    d.sync
}

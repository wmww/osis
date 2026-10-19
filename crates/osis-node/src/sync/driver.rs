//! The tokio driver (feature `driver`; notes/architecture.md §2): moves the `SyncEngine`'s bytes
//! over osis-transport `link` sessions (one dialed stream per server connection, an ephemeral
//! transport key per connection, the server's key checked by the transport, spec/sync.md §10)
//! and fires its timers. No sync logic lives here: every input is an `Event`, every output an
//! `Action`. Engine calls run under `block_in_place` on a multi-thread runtime. The engine
//! lives in a `Host`: owned by the driver (`run`), or shared with the app (`run_host`: the
//! `osis` handle keeps it behind its own lock and hands the driver the actions of its calls).

use super::{Action, ConnId, Event, SyncEngine};
use osis_core::Clock;
use osis_transport::link::{self, Link, LinkTx};
use osis_transport::Transport;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

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
    /// Actions the host's own calls produced: carry them out.
    Apply(Vec<Action>),
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

struct Driver<T: Transport, H: Host> {
    host: H,
    gone: bool,
    transport: Arc<T>,
    clock: Arc<dyn Clock>,
    log: Log,
    conns: HashMap<ConnId, Conn>,
    wake: Option<u64>,
    ev_tx: mpsc::Sender<Ev>,
}

impl<T: Transport, H: Host> Driver<T, H> {
    fn call(&mut self, f: &mut dyn FnMut(&mut SyncEngine) -> Vec<Action>) {
        let host = &self.host;
        match blocking(|| host.with(f)) {
            Some(acts) => self.apply(acts),
            None => self.gone = true,
        }
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
pub async fn run<T: Transport>(sync: SyncEngine, transport: T, clock: Arc<dyn Clock>, control: mpsc::UnboundedReceiver<Control>, log: Log) -> SyncEngine {
    let Owned(m) = run_host(Owned(std::sync::Mutex::new(sync)), transport, clock, control, log).await;
    m.into_inner().unwrap_or_else(|p| p.into_inner())
}

/// `run` over a host; returns it at `Control::Shutdown`, when the control sender is dropped
/// or when the host's engine is gone.
pub async fn run_host<T: Transport, H: Host>(host: H, transport: T, clock: Arc<dyn Clock>, mut control: mpsc::UnboundedReceiver<Control>, log: Log) -> H {
    let (ev_tx, mut ev_rx) = mpsc::channel(1024);
    let mut d = Driver { host, gone: false, transport: Arc::new(transport), clock, log, conns: HashMap::new(), wake: None, ev_tx };
    d.feed(Event::Tick);
    while !d.gone {
        let idle = d.idle();
        tokio::select! {
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
                    let mut f = Some(f);
                    d.call(&mut |s| f.take().map(|f| f(s)).unwrap_or_default());
                }
                Some(Control::Apply(acts)) => d.apply(acts),
                Some(Control::Shutdown) | None => break,
            },
            _ = tokio::time::sleep(idle) => {
                d.wake = None;
                d.feed(Event::Tick);
            }
        }
    }
    let ids: Vec<ConnId> = d.conns.keys().copied().collect();
    for id in ids {
        d.close(id);
    }
    d.host
}

//! The async driver: one task owns the `Hub` (and so the store); per link a reader task feeds it
//! bytes; writes go to the link's queue (a full queue drops the slow connection); per configured
//! peer a dial task reconnects with backoff; sweeps and replication timers run when due. The
//! only async code of the crate (notes/architecture.md §2).

use crate::hub::{ConnId, Hub, HubOutput};
use crate::net::{Dialer, Link, Listener};
use osis_core::Clock;
use osis_label::Address;
use osis_store::Backend;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Longest wait between ticks (sweeps also run on this beat).
pub const MAX_IDLE: Duration = Duration::from_secs(60);
/// Redial backoff bounds.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Commands to a running driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    /// Run due sweeps and timers now.
    Tick,
    /// Close every connection and return the hub.
    Shutdown,
}

/// Where diagnostics go.
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

enum Ev {
    Bytes(ConnId, Vec<u8>),
    Closed(ConnId),
    PeerUp(Link, oneshot::Sender<()>),
}

struct ConnState {
    tx: mpsc::Sender<Vec<u8>>,
    reader: JoinHandle<()>,
    /// A dial task waiting for this peer link to end.
    done: Option<oneshot::Sender<()>>,
}

struct Driver<B: Backend> {
    hub: Hub<B>,
    clock: Arc<dyn Clock>,
    log: Log,
    conns: HashMap<ConnId, ConnState>,
    next: ConnId,
    ev_tx: mpsc::Sender<Ev>,
}

impl<B: Backend> Driver<B> {
    fn now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    fn add(&mut self, link: Link, done: Option<oneshot::Sender<()>>) -> ConnId {
        let id = self.next;
        self.next += 1;
        let Link { tx, mut rx, .. } = link;
        let ev = self.ev_tx.clone();
        let reader = tokio::spawn(async move {
            while let Some(b) = rx.recv().await {
                if ev.send(Ev::Bytes(id, b)).await.is_err() {
                    return;
                }
            }
            let _ = ev.send(Ev::Closed(id)).await;
        });
        self.conns.insert(id, ConnState { tx, reader, done });
        id
    }

    fn drop_conn(&mut self, id: ConnId) {
        if let Some(c) = self.conns.remove(&id) {
            c.reader.abort();
            if let Some(d) = c.done {
                let _ = d.send(());
            }
        }
        self.hub.closed(id);
    }

    fn apply(&mut self, out: Vec<HubOutput>) {
        for o in out {
            match o {
                HubOutput::Send(id, b) => {
                    let full = self.conns.get(&id).is_some_and(|c| c.tx.try_send(b).is_err());
                    if full {
                        (self.log)(&format!("connection {id}: closed (slow or gone)"));
                        self.drop_conn(id);
                    }
                }
                HubOutput::Close(id) => self.drop_conn(id),
                HubOutput::Diagnostic(d) => (self.log)(&d),
            }
        }
    }

    fn tick(&mut self) {
        let now = self.now();
        let out = self.hub.tick(now);
        self.apply(out);
    }

    fn idle(&self) -> Duration {
        let now = self.now();
        self.hub.next_due().map_or(MAX_IDLE, |t| Duration::from_millis(t.saturating_sub(now)).min(MAX_IDLE))
    }
}

/// Keeps a link to `addr` up: dials, hands the link to the driver, waits for it to end, redials
/// with backoff.
async fn keep_dialing(dialer: Arc<dyn Dialer>, addr: Address, ev: mpsc::Sender<Ev>, log: Log) {
    let mut backoff = BACKOFF_MIN;
    loop {
        match dialer.dial(&addr).await {
            Ok(link) if link.peer_key == addr.key => {
                let (done, ended) = oneshot::channel();
                if ev.send(Ev::PeerUp(link, done)).await.is_err() {
                    return;
                }
                let _ = ended.await;
                backoff = BACKOFF_MIN;
            }
            Ok(_) => log(&format!("peer {}: wrong key", addr.url)),
            Err(e) => log(&format!("peer {}: {e}", addr.url)),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

/// Runs the blind node until `Control::Shutdown` (or the control sender is dropped): accepts
/// links from `listener`, keeps a replication link to each of `peers`, and returns the hub.
pub async fn run<B: Backend + 'static>(hub: Hub<B>, mut listener: Listener, peers: Vec<Address>, dialer: Arc<dyn Dialer>, clock: Arc<dyn Clock>, mut control: mpsc::Receiver<Control>, log: Log) -> Hub<B> {
    let (ev_tx, mut ev_rx) = mpsc::channel(1024);
    let dials: Vec<JoinHandle<()>> = peers.into_iter().map(|a| tokio::spawn(keep_dialing(dialer.clone(), a, ev_tx.clone(), log.clone()))).collect();
    let mut d = Driver { hub, clock, log, conns: HashMap::new(), next: 1, ev_tx };
    let mut listening = true;
    loop {
        let idle = d.idle();
        tokio::select! {
            link = listener.incoming.recv(), if listening => match link {
                Some(link) => {
                    let id = d.add(link, None);
                    let now = d.now();
                    let out = d.hub.accept(now, id);
                    d.apply(out);
                }
                None => listening = false,
            },
            Some(ev) = ev_rx.recv() => {
                let now = d.now();
                match ev {
                    Ev::Bytes(id, b) => {
                        let out = d.hub.input(now, id, b);
                        d.apply(out);
                    }
                    Ev::Closed(id) => d.drop_conn(id),
                    Ev::PeerUp(link, done) => {
                        let key = link.peer_key;
                        let id = d.add(link, Some(done));
                        let out = d.hub.peer_up(now, id, key);
                        d.apply(out);
                    }
                }
            }
            c = control.recv() => match c {
                Some(Control::Tick) => d.tick(),
                Some(Control::Shutdown) | None => break,
            },
            _ = tokio::time::sleep(idle) => d.tick(),
        }
    }
    for t in dials {
        t.abort();
    }
    let ids: Vec<ConnId> = d.conns.keys().copied().collect();
    for id in ids {
        d.drop_conn(id);
    }
    d.hub
}

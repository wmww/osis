//! The async driver over any `T: Transport` (notes/architecture.md §2): one task owns the `Hub`
//! (and so the store); sessions arrive as osis-transport `Link`s (`link::serve`: one per stream a
//! dialer opens, peer key as the transport authenticated it); per link a reader task feeds the
//! hub bytes; writes go to the link's queue (more than `max_queued_bytes` the transport has not
//! taken drops the session); per configured peer a dial task (`dial_as` with this server's static
//! secret, so the peer sees its address key) reconnects with backoff; sweeps, Hello deadlines and
//! replication work run when due. Hub calls (storage, fsyncs) run under `block_in_place` on a
//! multi-thread runtime. The only async code of the crate.

use crate::hub::{ConnId, Hub, HubOutput};
use osis_base::Clock;
use osis_label::Address;
use osis_store::Backend;
use osis_transport::link::{self, Link, LinkTx};
use osis_transport::{Backoff, Listener, StaticSecret, Transport};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Longest wait between ticks (sweeps also run on this beat).
pub const MAX_IDLE: Duration = Duration::from_secs(60);
/// Redial backoff bounds (ms).
const BACKOFF_MIN: u64 = 1000;
const BACKOFF_MAX: u64 = 60_000;
/// How long a session's end waits for the peer to take our last bytes.
pub const FINISH_WAIT: Duration = Duration::from_secs(10);

/// What the driver serves on: a transport, its listener and the static secret it listens with
/// (also used to dial peer servers).
pub struct Endpoint<T: Transport> {
    pub transport: T,
    pub listener: T::Listener,
    pub secret: StaticSecret,
}

impl<T: Transport> Endpoint<T> {
    /// The key this node is reached under (the hub's static key).
    pub fn key(&self) -> [u8; 32] {
        self.listener.address().key
    }
}

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
    tx: LinkTx,
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

/// Runs blocking hub work off the async worker when the runtime allows it.
fn blocking<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
    }
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
        let now = self.now();
        let out = blocking(|| self.hub.closed(now, id));
        self.apply(out);
    }

    fn apply(&mut self, out: Vec<HubOutput>) {
        for o in out {
            match o {
                HubOutput::Send(id, b) => {
                    let cap = self.hub.store().policy().max_queued_bytes;
                    let full = self.conns.get(&id).is_some_and(|c| !c.tx.send(b, cap));
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
        let out = blocking(|| self.hub.tick(now));
        self.apply(out);
    }

    fn idle(&self) -> Duration {
        let now = self.now();
        self.hub.next_due(now).map_or(MAX_IDLE, |t| Duration::from_millis(t.saturating_sub(now)).min(MAX_IDLE))
    }
}

/// Keeps a session to `addr` up: dials as this server, hands the link to the driver, waits for it
/// to end, redials with seeded backoff. Stops on errors redialing cannot fix (bad URL, unknown
/// scheme).
async fn keep_dialing<T: Transport>(t: Arc<T>, secret: StaticSecret, addr: Address, ev: mpsc::Sender<Ev>, log: Log) {
    let seed = addr.key.iter().take(8).fold(0u64, |s, b| s << 8 | u64::from(*b));
    let mut backoff = Backoff::with(BACKOFF_MIN, BACKOFF_MAX, seed);
    let target = osis_transport::Address { url: addr.url.clone(), key: addr.key };
    loop {
        match link::dial(&*t, &target, Some(&secret), FINISH_WAIT).await {
            Ok(link) => {
                let (done, ended) = oneshot::channel();
                if ev.send(Ev::PeerUp(link, done)).await.is_err() {
                    return;
                }
                let _ = ended.await;
                backoff.reset();
            }
            Err(e @ (osis_transport::Error::BadUrl(_) | osis_transport::Error::UnknownScheme(_))) => {
                log(&format!("peer {}: {e}; not dialing it", addr.url));
                return;
            }
            Err(e) => log(&format!("peer {}: {e}", addr.url)),
        }
        tokio::time::sleep(Duration::from_millis(backoff.next_delay_ms())).await;
    }
}

/// Runs the blind node until `Control::Shutdown` (or the control sender is dropped): serves
/// sessions on `ep`, keeps a replication session to each of `peers`, and returns the hub. The
/// hub's static key must be `ep.key()`.
pub async fn run<B: Backend + 'static, T: Transport>(hub: Hub<B>, ep: Endpoint<T>, peers: Vec<Address>, clock: Arc<dyn Clock>, mut control: mpsc::Receiver<Control>, log: Log) -> Hub<B> {
    let (ev_tx, mut ev_rx) = mpsc::channel(1024);
    let Endpoint { transport, listener, secret } = ep;
    let transport = Arc::new(transport);
    let dials: Vec<JoinHandle<()>> = peers.into_iter().map(|a| tokio::spawn(keep_dialing(transport.clone(), secret.clone(), a, ev_tx.clone(), log.clone()))).collect();
    let (in_tx, mut incoming) = mpsc::channel(64);
    let idle = Duration::from_millis(hub.store().policy().hello_ms);
    // transport connections capped like sessions (each connection may carry several)
    let max = hub.store().policy().max_connections;
    let server = tokio::spawn(link::serve(listener, idle, FINISH_WAIT, in_tx, max));
    let mut d = Driver { hub, clock, log, conns: HashMap::new(), next: 1, ev_tx };
    let mut listening = true;
    loop {
        let idle = d.idle();
        tokio::select! {
            link = incoming.recv(), if listening => match link {
                Some(link) => {
                    let key = link.peer_key;
                    let id = d.add(link, None);
                    let now = d.now();
                    let out = blocking(|| d.hub.accept(now, id, key));
                    d.apply(out);
                }
                None => listening = false,
            },
            Some(ev) = ev_rx.recv() => {
                let now = d.now();
                match ev {
                    Ev::Bytes(id, b) => {
                        let out = blocking(|| d.hub.input(now, id, b));
                        d.apply(out);
                    }
                    Ev::Closed(id) => d.drop_conn(id),
                    Ev::PeerUp(link, done) => {
                        let key = link.peer_key;
                        let id = d.add(link, Some(done));
                        let out = blocking(|| d.hub.peer_up(now, id, key));
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
    server.abort();
    for t in dials {
        t.abort();
    }
    let ids: Vec<ConnId> = d.conns.keys().copied().collect();
    for id in ids {
        d.drop_conn(id);
    }
    d.hub
}

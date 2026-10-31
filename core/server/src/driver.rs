//! The async driver over any `T: Transport` (notes/architecture.md §2): one task owns the `Hub`
//! (and so the store); sessions arrive as osis-transport `Link`s (`link::serve`: one per stream a
//! dialer opens, peer key as the transport authenticated it); per link a reader task hands the
//! hub its reads one at a time (the next once the hub took the last), served in turns
//! round-robin by source (`Turns`); writes go to the link's queue (more than `max_queued_bytes`
//! the transport has not taken drops the session); per configured peer a dial task (`dial_as` with this server's static
//! secret, so the peer sees its address key) reconnects with backoff; sweeps, Hello deadlines and
//! replication work run when due. Hub calls (storage, fsyncs) run under `block_in_place` on a
//! multi-thread runtime. The only async code of the crate.

use crate::hub::{ConnId, Hub, HubOutput};
use osis_base::Clock;
use osis_label::Address;
use osis_store::Backend;
use osis_transport::link::{self, Link, LinkRx, LinkTx, blocking};
use osis_transport::{Backoff, Listener, Source, StaticSecret, Transport};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, mpsc, oneshot};
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
    source: Option<Source>,
    /// The read waiting for its turn (the reader sends the next only after `turn`).
    input: Option<Vec<u8>>,
    /// Told when the hub took `input`.
    turn: Arc<Notify>,
    /// A dial task waiting for this peer link to end.
    done: Option<oneshot::Sender<()>>,
    /// `LinkTx::taken` when last reported (`Hub::sent`; `u64::MAX` before the first report).
    taken: u64,
}

struct Driver<B: Backend> {
    hub: Hub<B>,
    clock: Arc<dyn Clock>,
    log: Log,
    conns: HashMap<ConnId, ConnState>,
    turns: Turns,
    next: ConnId,
    ev_tx: mpsc::UnboundedSender<Ev>,
}

/// Connections with a read waiting, served one read per turn, round-robin by source and within
/// a source by connection: while S sources wait, a waiting connection is served within S turns
/// times the number of its source's waiting connections. Entries of closed connections are
/// skipped when their turn comes.
#[derive(Default)]
struct Turns {
    /// Sources with a waiting connection, in turn order (each once).
    order: VecDeque<Option<Source>>,
    waiting: BTreeMap<Option<Source>, VecDeque<ConnId>>,
}

impl Turns {
    fn push(&mut self, source: Option<Source>, id: ConnId) {
        let q = self.waiting.entry(source).or_default();
        if q.is_empty() {
            self.order.push_back(source);
        }
        q.push_back(id);
    }

    /// The connection whose turn it is.
    fn next(&mut self) -> Option<ConnId> {
        let s = self.order.pop_front()?;
        let q = self.waiting.get_mut(&s)?;
        let id = q.pop_front();
        if q.is_empty() {
            self.waiting.remove(&s);
        } else {
            self.order.push_back(s);
        }
        id
    }

    fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// Hands a session's reads to the driver one at a time: the next only after the hub took the
/// last (`turn`), so a connection never has more than one read waiting; then `Closed`.
async fn read(id: ConnId, mut rx: LinkRx, ev: mpsc::UnboundedSender<Ev>, turn: Arc<Notify>) {
    while let Some(b) = rx.recv().await {
        if ev.send(Ev::Bytes(id, b)).is_err() {
            return;
        }
        turn.notified().await;
    }
    let _ = ev.send(Ev::Closed(id));
}

impl<B: Backend> Driver<B> {
    fn now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    fn add(&mut self, link: Link, done: Option<oneshot::Sender<()>>) -> ConnId {
        let id = self.next;
        self.next += 1;
        let Link { tx, rx, source, .. } = link;
        let turn = Arc::new(Notify::new());
        let reader = tokio::spawn(read(id, rx, self.ev_tx.clone(), turn.clone()));
        self.conns.insert(id, ConnState { tx, reader, source, input: None, turn, done, taken: u64::MAX });
        id
    }

    fn event(&mut self, ev: Ev) {
        match ev {
            Ev::Bytes(id, b) => {
                if let Some(c) = self.conns.get_mut(&id) {
                    debug_assert!(c.input.is_none(), "a second read waiting");
                    c.input = Some(b);
                    self.turns.push(c.source, id);
                }
            }
            Ev::Closed(id) => self.drop_conn(id),
            Ev::PeerUp(link, done) => {
                let key = link.peer_key;
                let id = self.add(link, Some(done));
                let now = self.now();
                let out = blocking(|| self.hub.peer_up(now, id, key));
                self.apply(out);
            }
        }
    }

    /// Feeds the hub the read of the connection whose turn it is, then lets its reader go on.
    fn serve(&mut self) {
        let Some(id) = self.turns.next() else { return };
        let Some(b) = self.conns.get_mut(&id).and_then(|c| c.input.take()) else { return };
        let now = self.now();
        self.moved(now, id);
        let out = blocking(|| self.hub.input(now, id, b));
        self.apply(out);
        if let Some(c) = self.conns.get(&id) {
            c.turn.notify_one();
        }
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
        let mut moved = Vec::new();
        for (id, c) in &mut self.conns {
            let n = c.tx.taken();
            if n != c.taken {
                c.taken = n;
                moved.push((*id, n));
            }
        }
        if !moved.is_empty() {
            let out = blocking(|| self.hub.sent(now, &moved));
            self.apply(out);
        }
        let out = blocking(|| self.hub.tick(now));
        self.apply(out);
    }

    /// Reports what the transport took of `id` before its input (`Hub::sent`).
    fn moved(&mut self, now: u64, id: ConnId) {
        let Some(c) = self.conns.get_mut(&id) else { return };
        let n = c.tx.taken();
        if n != c.taken {
            c.taken = n;
            let out = blocking(|| self.hub.sent(now, &[(id, n)]));
            self.apply(out);
        }
    }

    fn idle(&self) -> Duration {
        let now = self.now();
        self.hub.next_due(now).map_or(MAX_IDLE, |t| Duration::from_millis(t.saturating_sub(now)).min(MAX_IDLE))
    }
}

/// Keeps a session to `addr` up: dials as this server, hands the link to the driver, waits for it
/// to end, redials with seeded backoff. Stops on errors redialing cannot fix (bad URL, unknown
/// scheme).
async fn keep_dialing<T: Transport>(t: Arc<T>, secret: StaticSecret, addr: Address, ev: mpsc::UnboundedSender<Ev>, log: Log) {
    let seed = addr.key.iter().take(8).fold(0u64, |s, b| s << 8 | u64::from(*b));
    let mut backoff = Backoff::with(BACKOFF_MIN, BACKOFF_MAX, seed);
    let target = osis_transport::Address { url: addr.url.clone(), key: addr.key };
    loop {
        match link::dial(&*t, &target, Some(&secret), FINISH_WAIT).await {
            Ok(link) => {
                let (done, ended) = oneshot::channel();
                if ev.send(Ev::PeerUp(link, done)).is_err() {
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
    // unbounded, yet at most a read and an end per connection and a link per dial task
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
    let Endpoint { transport, listener, secret } = ep;
    let transport = Arc::new(transport);
    let dials: Vec<JoinHandle<()>> = peers.into_iter().map(|a| tokio::spawn(keep_dialing(transport.clone(), secret.clone(), a, ev_tx.clone(), log.clone()))).collect();
    let (in_tx, mut incoming) = mpsc::channel(64);
    let idle = Duration::from_millis(hub.store().policy().hello_ms);
    // transport connections capped like sessions (each connection may carry several)
    let max = hub.store().policy().max_connections;
    let server = tokio::spawn(link::serve(listener, idle, FINISH_WAIT, in_tx, max));
    let mut d = Driver { hub, clock, log, conns: HashMap::new(), turns: Turns::default(), next: 1, ev_tx };
    let mut listening = true;
    loop {
        let idle = d.idle();
        tokio::select! {
            link = incoming.recv(), if listening => match link {
                Some(link) => {
                    let (key, source) = (link.peer_key, link.source);
                    let id = d.add(link, None);
                    let now = d.now();
                    let out = blocking(|| d.hub.accept_from(now, id, key, source));
                    d.apply(out);
                }
                None => listening = false,
            },
            Some(ev) = ev_rx.recv() => d.event(ev),
            () = std::future::ready(()), if !d.turns.is_empty() => {
                // every read that arrived takes its place in the turns first
                while let Ok(ev) = ev_rx.try_recv() {
                    d.event(ev);
                }
                d.serve();
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

#[cfg(test)]
mod tests {
    use super::*;

    // spec: none (driver policy, notes/sync.md Hub stall bounds): turns go round-robin by source,
    // then by connection within a source, so a source's many connections share one turn
    #[test]
    fn turns_by_source() {
        let mut t = Turns::default();
        let (a, b, c) = (Some([1; 16]), Some([2; 16]), None);
        for id in 1..=4 {
            t.push(a, id);
        }
        t.push(b, 10);
        t.push(c, 20);
        let mut got = vec![];
        while let Some(id) = t.next() {
            got.push(id);
            // a's connections and b's come back for another read; c's does not
            if id < 20 && got.len() < 9 {
                t.push(if id < 10 { a } else { b }, id);
            }
        }
        assert_eq!(got, vec![1, 10, 20, 2, 10, 3, 10, 4, 10, 1, 2, 3, 4]);
        assert!(t.is_empty());
    }
}

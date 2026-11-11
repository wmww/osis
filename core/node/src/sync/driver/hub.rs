//! The hub in the node driver's loop (notes/serving.md, Hosting in the node): while the node
//! hosts, the driver owns osis-host's sans-I/O `Hub` (and so the host store) and moves its bytes
//! beside the sync engine's, one call at a time on the same task. Sessions arrive as
//! osis-transport `Link`s from the host listeners (`link::serve`, one per stream a dialer opens),
//! from the node's own dials of the host key (an in-process `link::pair`) and from replication
//! dials (`dial_as` with the host secret, so the peer sees this host's key: echo suppression).
//! Per link a reader task hands the loop one read at a time (the next once the hub took the
//! last), served in turns round-robin by source (`Turns`); writes go to the link's queue (more
//! than `max_queued_bytes` the transport has not taken drops the session). No task waits on the
//! loop and the loop waits on no connection.

use super::{FINISH_WAIT, Log, MAX_IDLE};
use osis_base::Clock;
use osis_host::{ConnId, HostConfig, Hub, HubOutput};
use osis_label::Address;
use osis_transport::link::{self, Link, LinkRx, LinkTx, blocking};
use osis_transport::{Backoff, Source, StaticSecret, Transport};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinHandle;

/// Redial backoff bounds of a replication peer (ms).
const BACKOFF_MIN: u64 = 1000;
const BACKOFF_MAX: u64 = 60_000;

/// What the hub's tasks hand the loop. `run`: the hub run it belongs to (a stale one is dropped).
pub(super) enum HubEv {
    Accepted(u64, Link),
    PeerUp(u64, Link, oneshot::Sender<()>),
    Bytes(ConnId, Vec<u8>),
    Closed(ConnId),
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

/// Hands a session's reads to the loop one at a time: the next only after the hub took the
/// last (`turn`), so a connection never has more than one read waiting; then `Closed`.
async fn read(id: ConnId, mut rx: LinkRx, ev: mpsc::UnboundedSender<HubEv>, turn: Arc<Notify>) {
    while let Some(b) = rx.recv().await {
        if ev.send(HubEv::Bytes(id, b)).is_err() {
            return;
        }
        turn.notified().await;
    }
    let _ = ev.send(HubEv::Closed(id));
}

/// Keeps a session to `addr` up: dials as this host, hands the link to the loop, waits for it
/// to end, redials with seeded backoff. Stops on errors redialing cannot fix (bad URL, unknown
/// scheme).
async fn keep_dialing<T: Transport>(t: Arc<T>, secret: StaticSecret, addr: Address, run: u64, ev: mpsc::UnboundedSender<HubEv>, log: Log) {
    let seed = addr.key.iter().take(8).fold(0u64, |s, b| s << 8 | u64::from(*b));
    let mut backoff = Backoff::with(BACKOFF_MIN, BACKOFF_MAX, seed);
    let target = osis_transport::Address { url: addr.url.clone(), key: addr.key };
    loop {
        match link::dial(&*t, &target, Some(&secret), FINISH_WAIT).await {
            Ok(link) => {
                let (done, ended) = oneshot::channel();
                if ev.send(HubEv::PeerUp(run, link, done)).is_err() {
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

/// The running hub: its config, connections and tasks (listeners, replication dials).
pub(super) struct HubRun {
    pub cfg: HostConfig,
    hub: Hub,
    /// This run's tag on its tasks' events.
    run: u64,
    /// The next connection's ID (kept across runs: a closed run's late events match nothing).
    next: ConnId,
    conns: HashMap<ConnId, ConnState>,
    turns: Turns,
    /// When `tick` is due: moved only earlier until it runs, so a due counted from now (a held
    /// connection's push poll, the idle beat) is not put off by every pass of the loop.
    at: Option<tokio::time::Instant>,
    tasks: Vec<JoinHandle<()>>,
    clock: Arc<dyn Clock>,
    log: Log,
    ev: mpsc::UnboundedSender<HubEv>,
}

impl HubRun {
    /// Serves `hub` on `listeners` (listening with the host secret `secret`), keeps a replication
    /// session to each of `cfg.replicate`. `next`: the first connection ID and run tag, above
    /// every earlier run's.
    #[allow(clippy::too_many_arguments)]
    pub fn start<T: Transport>(cfg: HostConfig, hub: Hub, next: u64, transport: &Arc<T>, listeners: Vec<T::Listener>, secret: StaticSecret, clock: Arc<dyn Clock>, log: Log, ev: mpsc::UnboundedSender<HubEv>) -> HubRun {
        let run = next;
        let mut tasks: Vec<JoinHandle<()>> = cfg.replicate.iter().map(|a| tokio::spawn(keep_dialing(transport.clone(), secret.clone(), a.clone(), run, ev.clone(), log.clone()))).collect();
        let idle = Duration::from_millis(hub.store().policy().hello_ms);
        // transport connections capped like sessions (each connection may carry several)
        let max = hub.store().policy().max_connections;
        let (in_tx, mut incoming) = mpsc::channel(64);
        tasks.extend(listeners.into_iter().map(|l| tokio::spawn(link::serve(l, idle, FINISH_WAIT, in_tx.clone(), link::Slots::Shared(max)))));
        drop(in_tx);
        let fwd = ev.clone();
        tasks.push(tokio::spawn(async move {
            while let Some(l) = incoming.recv().await {
                if fwd.send(HubEv::Accepted(run, l)).is_err() {
                    return;
                }
            }
        }));
        HubRun { cfg, hub, run, next: next + 1, conns: HashMap::new(), turns: Turns::default(), at: None, tasks, clock, log, ev }
    }

    /// Closes every connection and stops the tasks; returns the hub and the next free ID.
    pub fn stop(mut self) -> (Hub, u64) {
        for t in std::mem::take(&mut self.tasks) {
            t.abort();
        }
        let ids: Vec<ConnId> = self.conns.keys().copied().collect();
        for id in ids {
            self.drop_conn(id);
        }
        (self.hub, self.next)
    }

    pub fn hub_mut(&mut self) -> &mut Hub {
        &mut self.hub
    }

    fn now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    fn add(&mut self, link: Link, done: Option<oneshot::Sender<()>>) -> ConnId {
        let id = self.next;
        self.next += 1;
        let Link { tx, rx, source, .. } = link;
        let turn = Arc::new(Notify::new());
        let reader = tokio::spawn(read(id, rx, self.ev.clone(), turn.clone()));
        self.conns.insert(id, ConnState { tx, reader, source, input: None, turn, done, taken: u64::MAX });
        id
    }

    /// A session to serve: from a host listener, or the node's own dial of the host key.
    pub fn accept(&mut self, link: Link) {
        let (key, source) = (link.peer_key, link.source);
        let id = self.add(link, None);
        let now = self.now();
        let out = blocking(|| self.hub.accept_from(now, id, key, source));
        self.apply(out);
    }

    pub fn event(&mut self, ev: HubEv) {
        match ev {
            HubEv::Accepted(run, link) if run == self.run => self.accept(link),
            HubEv::PeerUp(run, link, done) if run == self.run => {
                let key = link.peer_key;
                let id = self.add(link, Some(done));
                let now = self.now();
                let out = blocking(|| self.hub.peer_up(now, id, key));
                self.apply(out);
            }
            HubEv::Accepted(..) | HubEv::PeerUp(..) => {}
            HubEv::Bytes(id, b) => {
                if let Some(c) = self.conns.get_mut(&id) {
                    debug_assert!(c.input.is_none(), "a second read waiting");
                    c.input = Some(b);
                    self.turns.push(c.source, id);
                }
            }
            HubEv::Closed(id) => self.drop_conn(id),
        }
    }

    /// A read waits for its turn.
    pub fn waiting(&self) -> bool {
        !self.turns.is_empty()
    }

    /// Feeds the hub the read of the connection whose turn it is, then lets its reader go on.
    pub fn serve(&mut self) {
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
        let out = blocking(|| self.hub.closed(id));
        self.apply(out);
    }

    fn apply(&mut self, out: Vec<HubOutput>) {
        for o in out {
            match o {
                HubOutput::Send(id, b) => {
                    let cap = self.hub.store().policy().max_queued_bytes;
                    let full = self.conns.get(&id).is_some_and(|c| !c.tx.send(b, cap));
                    if full {
                        (self.log)(&format!("host connection {id}: closed (slow or gone)"));
                        self.drop_conn(id);
                    }
                }
                HubOutput::Close(id) => self.drop_conn(id),
                HubOutput::Diagnostic(d) => (self.log)(&d),
            }
        }
    }

    /// Reports what the transport took since the last report, then runs what is due.
    pub fn tick(&mut self) {
        self.at = None;
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

    /// When `tick` has work (at most `MAX_IDLE` after the last).
    pub fn due(&mut self) -> tokio::time::Instant {
        let now = self.now();
        let wait = self.hub.next_due(now).map_or(MAX_IDLE, |t| Duration::from_millis(t.saturating_sub(now)).min(MAX_IDLE));
        let at = self.at.map_or(tokio::time::Instant::now() + wait, |a| a.min(tokio::time::Instant::now() + wait));
        self.at = Some(at);
        at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec: none (driver policy, notes/flow-control.md Hub stall bounds): turns go round-robin by source,
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

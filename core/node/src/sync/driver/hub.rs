//! The hub in the node driver's loop (notes/serving.md, The hub in the node): the driver owns
//! osis-host's sans-I/O `Hub` and moves its bytes beside the sync engine's, one call at a time on
//! the same task. Every listener of the node feeds it (`listen`: the dialable key's, the LAN's,
//! the unix socket's), each connection served under the key of the listener that took it; the
//! node's own dials of a key it listens under reach it over an in-process `link::pair`
//! (`accept_own`); replication dials (`dial_as` with the dialable secret, so the peer sees this
//! node's key: echo suppression) run while it hosts. Per link a reader task hands the loop one
//! read at a time (the next once the hub took the last), served in turns round-robin by source
//! (`Turns`), none while the hub is full (`Hub::full`: what it wrote waits to be read, and the
//! reads wait in the transport's window); writes go to the link's queue (more than `max_queued_bytes` the transport has not
//! taken drops the session). No task waits on the loop and the loop waits on no connection.
//! What the hub hands node sync (`HubOutput::Up`) waits in `ups` until the driver feeds it to
//! the engine (`Event::Hub`); the engine's `Action::Hub` come back by `down`, in the same pass of
//! the loop.

use super::{FINISH_WAIT, Log, MAX_IDLE};
use osis_base::Clock;
use osis_host::{ConnId, Down, HostConfig, Hub, HubOutput, Up};
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

/// What the hub's tasks hand the loop.
pub(super) enum HubEv {
    /// A session on listener group `group`, whose key is `key`.
    Accepted(u64, [u8; 32], Link),
    /// A replication session of replication run `run` is up.
    PeerUp(u64, Link, oneshot::Sender<()>),
    Bytes(ConnId, Vec<u8>),
    Closed(ConnId),
}

struct ConnState {
    tx: LinkTx,
    /// Its transport slot is kept (`Down::Keep`, `Link::kept`).
    kept: Arc<std::sync::atomic::AtomicBool>,
    reader: JoinHandle<()>,
    source: Option<Source>,
    /// The listener group that took it (none: the node's own dial, a replication session).
    group: Option<u64>,
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

/// Keeps a session to `addr` up: dials as this node, hands the link to the loop, waits for it
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

/// The running hub: its hosting config, listeners, connections and replication dials.
pub(super) struct HubRun {
    /// What it hosts by (none: an empty store in memory).
    pub cfg: Option<HostConfig>,
    hub: Hub,
    /// The next connection ID.
    next: ConnId,
    conns: HashMap<ConnId, ConnState>,
    turns: Turns,
    /// Transport connections of every listener (`max_connections` of them).
    slots: Arc<link::Slots>,
    /// The node's dialable key: its own dials of it reach the hub whether or not a listener
    /// of it runs yet.
    pub own: Option<[u8; 32]>,
    /// Listener groups by ID: their key and tasks.
    groups: HashMap<u64, ([u8; 32], Vec<JoinHandle<()>>)>,
    next_group: u64,
    /// Replication dials and the run tag their sessions carry (a stopped run's are dropped).
    repl: Vec<JoinHandle<()>>,
    repl_run: u64,
    /// When `tick` is due: moved only earlier until it runs, so a due counted from now (a held
    /// connection's push poll, the idle beat) is not put off by every pass of the loop.
    at: Option<tokio::time::Instant>,
    clock: Arc<dyn Clock>,
    log: Log,
    ev: mpsc::UnboundedSender<HubEv>,
    /// What the hub handed up for node sync, not yet fed to it.
    ups: Vec<(ConnId, Up)>,
}

impl HubRun {
    pub fn new(hub: Hub, clock: Arc<dyn Clock>, log: Log, ev: mpsc::UnboundedSender<HubEv>) -> HubRun {
        let slots = link::Slots::new(hub.store().policy().max_connections);
        HubRun { cfg: None, hub, own: None, next: 1, conns: HashMap::new(), turns: Turns::default(), slots, groups: HashMap::new(), next_group: 1, repl: Vec::new(), repl_run: 0, at: None, clock, log, ev, ups: Vec::new() }
    }

    /// Serves the sessions `listeners` accept, under their key `key`; returns their group.
    /// Transport connections of all listeners are capped as sessions are (`max_connections`;
    /// each may carry several), shared by source.
    pub fn listen<L: osis_transport::Listener + 'static>(&mut self, key: [u8; 32], listeners: Vec<L>) -> u64 {
        let group = self.next_group;
        self.next_group += 1;
        let idle = Duration::from_millis(self.hub.store().policy().hello_ms);
        let (in_tx, mut incoming) = mpsc::channel(64);
        let mut tasks: Vec<JoinHandle<()>> = listeners.into_iter().map(|l| tokio::spawn(link::serve(l, idle, FINISH_WAIT, in_tx.clone(), self.slots.clone()))).collect();
        drop(in_tx);
        let fwd = self.ev.clone();
        tasks.push(tokio::spawn(async move {
            while let Some(l) = incoming.recv().await {
                if fwd.send(HubEv::Accepted(group, key, l)).is_err() {
                    return;
                }
            }
        }));
        self.groups.insert(group, (key, tasks));
        group
    }

    /// Stops listener group `group` (returning once its listeners are dropped, so their address
    /// is free again) and closes the sessions it accepted (as a P2P listener's socket ends its
    /// connections).
    pub async fn unlisten(&mut self, group: u64) {
        let Some((_, tasks)) = self.groups.remove(&group) else { return };
        for t in tasks {
            t.abort();
            let _ = t.await;
        }
        let ids: Vec<ConnId> = self.conns.iter().filter(|(_, c)| c.group == Some(group)).map(|(id, _)| *id).collect();
        for id in ids {
            self.drop_conn(id);
        }
    }

    /// Whether `key` is this node's (its dialable key, or one it listens under): a dial of it is
    /// the node's own.
    pub fn listens_as(&self, key: &[u8; 32]) -> bool {
        self.own.as_ref() == Some(key) || self.groups.values().any(|(k, _)| k == key)
    }

    /// Dials replication peers `peers` as this node (`secret`), in place of those dialed so far.
    pub fn replicate<T: Transport>(&mut self, transport: &Arc<T>, peers: &[Address], secret: Option<StaticSecret>) {
        for t in self.repl.drain(..) {
            t.abort();
        }
        self.repl_run += 1;
        let Some(secret) = secret else { return };
        let run = self.repl_run;
        self.repl = peers.iter().map(|a| tokio::spawn(keep_dialing(transport.clone(), secret.clone(), a.clone(), run, self.ev.clone(), self.log.clone()))).collect();
    }

    /// Closes every connection and stops the tasks; returns what is left for node sync (the
    /// connections' ends).
    pub fn stop(&mut self) -> Vec<(ConnId, Up)> {
        for t in self.repl.drain(..).chain(self.groups.drain().flat_map(|(_, (_, t))| t)) {
            t.abort();
        }
        let ids: Vec<ConnId> = self.conns.keys().copied().collect();
        for id in ids {
            self.drop_conn(id);
        }
        std::mem::take(&mut self.ups)
    }

    /// What the hub handed up since the last call, for node sync (`Event::Hub`).
    pub fn take_ups(&mut self) -> Vec<(ConnId, Up)> {
        std::mem::take(&mut self.ups)
    }

    /// Node sync's messages, answers, room requests and closes for the hub's connections; its
    /// `Keep`s set their links' transport slots.
    pub fn down(&mut self, mut downs: Vec<(ConnId, Down)>) {
        downs.retain(|(id, d)| match d {
            Down::Keep(k) => {
                if let Some(c) = self.conns.get(id) {
                    c.kept.store(*k, std::sync::atomic::Ordering::Release);
                }
                false
            }
            _ => true,
        });
        let now = self.now();
        let out = blocking(|| self.hub.down(now, downs));
        self.apply(out);
    }

    /// The hub's policy changed: listeners take its `max_connections` from the next newcomer.
    pub fn policy_changed(&self) {
        self.slots.set_max(self.hub.store().policy().max_connections);
    }

    pub fn hub_mut(&mut self) -> &mut Hub {
        &mut self.hub
    }

    /// Carries out what a change of the hub (its store replaced) handed out.
    pub fn applied(&mut self, out: Vec<HubOutput>) {
        self.apply(out);
    }

    fn now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    fn add(&mut self, link: Link, group: Option<u64>, done: Option<oneshot::Sender<()>>) -> ConnId {
        let id = self.next;
        self.next += 1;
        let Link { tx, rx, source, kept, .. } = link;
        let turn = Arc::new(Notify::new());
        let reader = tokio::spawn(read(id, rx, self.ev.clone(), turn.clone()));
        self.conns.insert(id, ConnState { tx, kept, reader, source, group, input: None, turn, done, taken: u64::MAX });
        id
    }

    fn accept(&mut self, key: [u8; 32], link: Link, group: Option<u64>) {
        let remote = osis_host::Remote { peer: link.peer, source: link.source, relayed: link.relayed };
        let id = self.add(link, group, None);
        let now = self.now();
        let out = blocking(|| self.hub.accept(now, id, key, remote));
        self.apply(out);
    }

    /// The node's own session to its key `key` (an in-process pair's far end).
    pub fn accept_own(&mut self, key: [u8; 32], link: Link) {
        self.accept(key, link, None);
    }

    pub fn event(&mut self, ev: HubEv) {
        match ev {
            HubEv::Accepted(group, key, link) => {
                if self.groups.contains_key(&group) {
                    self.accept(key, link, Some(group));
                }
            }
            HubEv::PeerUp(run, link, done) if run == self.repl_run => {
                let key = link.peer_key;
                let id = self.add(link, None, Some(done));
                let now = self.now();
                let out = blocking(|| self.hub.peer_up(now, id, key));
                self.apply(out);
            }
            HubEv::PeerUp(..) => {}
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

    /// A read waits for its turn, and the hub takes input (none while it is full: readers drain
    /// what it holds first, `Hub::full`).
    pub fn waiting(&self) -> bool {
        !self.turns.is_empty() && !self.hub.full()
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
                        (self.log)(&format!("hub connection {id}: closed (slow or gone)"));
                        self.drop_conn(id);
                    }
                }
                HubOutput::Close(id) => self.drop_conn(id),
                HubOutput::Diagnostic(d) => (self.log)(&d),
                HubOutput::Up(id, up) => self.ups.push((id, up)),
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

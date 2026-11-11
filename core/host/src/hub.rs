//! `Hub`: a node's connections over one store, sans-I/O (spec/sync.md §5-§10). One osis-proto
//! `ServingSession` per accepted connection, under the key of the listener that took it, one
//! `Replicator` per connection this node dialed to a peer host; cross-connection notices
//! (`Changed` to every connection and replicator, `Relay` to every other connection), bounded
//! sweeps, Hello deadlines, stalls of the upper layer's requests and timers. Node sync is every
//! session's upper layer (issues/net-one-peer.md step 3): the hub hands it each connection's
//! start, node-kind messages, client-port requests, whether the session opened something, push
//! room and end (`HubOutput::Up`) and takes its messages, answers and closes down (`Hub::down`),
//! judging none of them. The node's driver and the simulator only move bytes, pass `Up` and
//! `Down` between the hub and node sync, and call `tick` when `next_due` says.

use crate::replicate::Replicator;
use crate::store::HostStore;
use std::sync::{Arc, Mutex, MutexGuard};
use osis_base::LabelId;
use osis_proto::{ClientInput, ClientOutput, Message, ServingConfig, ServingSession, ServingInput, ServingOutput};
use osis_transport::{Peer, Source};
use std::collections::{BTreeMap, VecDeque};

/// A connection's handle, chosen by the driver.
pub type ConnId = u64;

/// Index rows one `tick` sweeps at most.
pub const SWEEP_BUDGET: usize = 1024;
/// Pause after a failed sweep.
const SWEEP_BACKOFF_MS: u64 = 1_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HubOutput {
    /// Bytes to write on the connection.
    Send(ConnId, Vec<u8>),
    /// Close the connection (the hub has forgotten it).
    Close(ConnId),
    /// Something worth logging (a peer's protocol error, a storage failure, a refused replication).
    Diagnostic(String),
    /// For node sync, the session's upper layer.
    Up(ConnId, Up),
    /// The batch changed a sync ID node sync reads (`HostStore::take_moved`): node sync runs
    /// again (`Event::Hub`, with no `Up` if none).
    Moved,
}

/// What a served connection hands node sync.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Up {
    /// The dialer's Hello arrived: what the connection binds. Every other `Up` of it comes after.
    Start(Binding),
    /// A node-kind message (`Message::for_node`): node sync answers each request by `Down`.
    Message(Box<Message>),
    /// A client-port request (Auth, Call, Sub: answered by `Down::Reply`; an Unsub, already
    /// answered).
    Request(Box<Message>),
    /// Whether the session holds something of the hub's own (an open, an answered Auth): sent
    /// when it changes.
    Opened(bool),
    /// Pushes of up to `budget` bytes may go now (after `Down::WantRoom`).
    Room { budget: usize },
    /// The connection is gone (after a `Start`).
    End,
}

/// A served connection's binding (spec/sync.md §10, Connection proofs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The dialer's and this side's Hello challenges, and the static key of the listener that
    /// took the connection.
    pub dialer: [u8; 32],
    pub listener: [u8; 32],
    pub key: [u8; 32],
    pub remote: Remote,
}

/// The dialer of a served connection as the transport tells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Remote {
    /// Who it is (a key it authenticated, or a unix peer's uid).
    pub peer: Peer,
    /// Where it comes from (`osis_transport::Source`; none: unknown).
    pub source: Option<Source>,
    /// A relay carries the connection (`osis_transport::Connection::relayed`).
    pub relayed: bool,
}

impl Remote {
    /// A peer with transport key `key`, from no known source, not relayed.
    pub fn key(key: [u8; 32]) -> Remote {
        Remote { peer: Peer::Key(key), source: None, relayed: false }
    }
}

/// What node sync hands a served connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Down {
    /// A message to send: a request within the session's request window, anything else at once
    /// (a relay-only push without room is dropped).
    Message(Box<Message>),
    /// The answer to an `Up::Request`.
    Reply { id: osis_proto::msg::Id, reply: Result<osis_proto::Outcome, osis_proto::Code> },
    /// Notify pushes, within the room last granted.
    Notify(Vec<(osis_proto::msg::Id, osis_proto::Payload)>),
    /// Pushes wait: `Up::Room` when the session's push rule allows.
    WantRoom,
    /// Whether the connection shares something (node sync's rule over its connections): for the
    /// driver, which keeps its transport slot from being given away; the hub keeps nothing of it.
    Keep(bool),
    /// Close the connection.
    Close,
}

#[derive(Clone)]
enum Conn {
    /// `buffered`: received bytes it holds (`ServingSession::buffered`); `hold`: what it holds
    /// against the output bound (`ServingSession::holding`); `alone`: no output of its own
    /// (`ServingSession::alone`); `need`: the room its first waiting reply, push or request needs
    /// (`ServingSession::need`); `queued`: in `queue` since then; `paused`: received
    /// frames wait for room, so it takes no input (`Hub::waits`); `taken`: the last report
    /// (`Hub::sent`); `moved`: a report took more since the last check; `started`: its
    /// `Up::Start` went; `opened`: the last `Up::Opened`.
    Served { c: Box<ServingSession>, remote: Remote, hello_by: Option<u64>, buffered: usize, hold: usize, alone: bool, need: Option<usize>, queued: Option<u64>, paused: bool, taken: u64, moved: bool, started: bool, opened: bool },
    Peer { r: Box<Replicator>, timer: Option<u64> },
}

pub struct Hub {
    /// The node's one store, beside its engine: locked for each call (a batch's writes are one
    /// transaction no other holder interleaves with).
    store: Arc<Mutex<HostStore>>,
    rng: Box<dyn osis_crypto::NodeRng>,
    conns: BTreeMap<ConnId, Conn>,
    /// Sweeps wait until then (after a failure).
    sweep_hold: u64,
    /// The last sweep ran out of budget.
    sweep_more: bool,
    /// Received bytes held for all served connections (`ServingSession::buffered`).
    buffered: usize,
    /// What all served connections hold against `max_buffered_bytes`: bytes written and not
    /// taken by the transport (as reported), and reply allowances handed up and not answered.
    hold: usize,
    /// Served connections holding something or needing room: each one's share of the bound is
    /// the bound over their number.
    active: usize,
    /// Connections with no output of their own whose need waits for the node's room, in arrival
    /// order: the first one's need is kept free of the others (it reserves it), so each gets its
    /// turn.
    queue: VecDeque<ConnId>,
    /// Connections that take input again since `take_resumed`.
    resumed: Vec<ConnId>,
    /// While the queue's first waits: when connections whose output did not move are next
    /// closed (`tick`).
    check_at: Option<u64>,
    /// The latest time any call carried.
    now: u64,
    /// Relay-only entries handed to connections so far (`relays_delivered`).
    relays_delivered: u64,
    /// Started connections removed since the last batch ended (`Up::End`).
    ended: Vec<ConnId>,
}

impl Hub {
    pub fn new(store: Arc<Mutex<HostStore>>, rng: Box<dyn osis_crypto::NodeRng>) -> Hub {
        Hub { store, rng, conns: BTreeMap::new(), sweep_hold: 0, sweep_more: false, buffered: 0, hold: 0, active: 0, queue: VecDeque::new(), resumed: Vec::new(), check_at: None, now: 0, relays_delivered: 0, ended: Vec::new() }
    }

    /// Tests only: an exact copy of this hub as it stands, on `clock`, sharing no mutable state
    /// with it: its store (`HostStore::test_copy`), connections and their sessions, its rng going
    /// on with the same stream. Never in a product: two hubs with one key and rng stream.
    #[doc(hidden)]
    pub fn test_copy(&self, clock: std::sync::Arc<dyn osis_base::Clock>) -> Result<Hub, osis_store::Error> {
        let store = Arc::new(Mutex::new(self.store().test_copy(clock)?));
        Ok(self.test_copy_over(store))
    }

    /// Tests only: `test_copy` over `store`, a copy of this hub's store already made (a node's
    /// copy: its sync engine's copy of the store it shares with this hub, `SyncEngine::test_copy`),
    /// so the copied engine and hub share one store as these two do.
    #[doc(hidden)]
    pub fn test_copy_over(&self, store: Arc<Mutex<HostStore>>) -> Hub {
        osis_base::copying::copying(|| {
            Hub {
                store,
                rng: self.rng.test_copy(),
                conns: self.conns.clone(),
                sweep_hold: self.sweep_hold,
                sweep_more: self.sweep_more,
                buffered: self.buffered,
                hold: self.hold,
                active: self.active,
                queue: self.queue.clone(),
                resumed: self.resumed.clone(),
                check_at: self.check_at,
                now: self.now,
                relays_delivered: self.relays_delivered,
                ended: self.ended.clone(),
            }
        })
    }

    /// The store, locked: hold the guard for one statement, never across another call of this
    /// hub's (each locks it) or a second `store()` (the lock is not re-entrant).
    pub fn store(&self) -> MutexGuard<'_, HostStore> {
        self.store.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Hosting stopped: the labels `drop` names go from the store (`HostStore::drop_labels`),
    /// and served connections that opened something, and replication sessions, close.
    pub fn stop_hosting(&mut self, drop: &dyn Fn(&osis_base::LabelId) -> bool) -> Vec<HubOutput> {
        self.sweep_more = false;
        self.sweep_hold = 0;
        let mut out = Vec::new();
        if let Err(e) = self.store().drop_labels(drop) {
            out.push(HubOutput::Diagnostic(format!("hosting stopped: dropping its labels: {e}")));
        }
        out.extend(self.batch(|h, _, out| {
            let gone: Vec<ConnId> = h.conns.iter().filter(|(_, c)| match c {
                Conn::Served { c, .. } => c.opened().next().is_some(),
                Conn::Peer { .. } => true,
            }).map(|(id, _)| *id).collect();
            for id in gone {
                h.remove(id);
                out.push(HubOutput::Close(id));
            }
        }));
        out
    }

    pub fn connections(&self) -> usize {
        self.conns.len()
    }

    /// Relay-only entries handed to connections so far: one per subscriber of the label on
    /// another connection, whatever the number of connections.
    pub fn relays_delivered(&self) -> u64 {
        self.relays_delivered
    }

    fn challenge(&mut self) -> [u8; 32] {
        let mut c = [0u8; 32];
        self.rng.fill_bytes(&mut c);
        c
    }

    /// A connection from `remote` on the listener of static key `key` (bound by open signatures
    /// and connection proofs; spec/sync.md §10): start its session (sends Hello). How many
    /// connections a node serves is node sync's rule (it closes by `Down::Close`); the hub caps
    /// none.
    pub fn accept(&mut self, now: u64, id: ConnId, key: [u8; 32], remote: Remote) -> Vec<HubOutput> {
        self.now = now;
        let cfg = ServingConfig { static_key: key, challenge: self.challenge() };
        let hello_by = Some(now.saturating_add(self.store().policy().hello_ms));
        self.conns.insert(id, Conn::Served { c: Box::new(ServingSession::new(cfg)), remote, hello_by, buffered: 0, hold: 0, alone: true, need: None, queued: None, paused: false, taken: 0, moved: false, started: false, opened: false });
        self.batch(|h, st, out| h.serve(st, now, id, ServingInput::Start, out))
    }

    /// A connection this node dialed to peer host `peer_key` is up: replicate to it.
    pub fn peer_up(&mut self, now: u64, id: ConnId, peer_key: [u8; 32]) -> Vec<HubOutput> {
        self.now = now;
        let challenge = self.challenge();
        self.conns.insert(id, Conn::Peer { r: Box::new(Replicator::new(peer_key, challenge)), timer: None });
        self.batch(|h, st, out| h.replicate(st, now, id, Some(ClientInput::Start), out))
    }

    /// Runs `f` in one store transaction committed at its end (one commit, at most one shredding
    /// root write, for a whole message of entries, spec/requirements.md: peer input never causes
    /// unbounded work), before any output leaves. If that fails, nothing the batch would send goes: the connections it
    /// would have written to are closed (their peers retry what went unanswered).
    fn batch(&mut self, f: impl FnOnce(&mut Hub, &mut HostStore, &mut Vec<HubOutput>)) -> Vec<HubOutput> {
        let arc = self.store.clone();
        let mut st = arc.lock().unwrap_or_else(|p| p.into_inner());
        st.defer_durability();
        let mut out = Vec::new();
        f(self, &mut st, &mut out);
        self.pressure(&mut st, &mut out);
        if let Err(e) = st.durable() {
            let mut dead = std::collections::BTreeSet::new();
            out.retain(|o| match o {
                HubOutput::Send(id, _) => {
                    dead.insert(*id);
                    false
                }
                _ => true,
            });
            out.push(HubOutput::Diagnostic(format!("storage sync: {e}")));
            for id in dead {
                if self.conns.contains_key(&id) {
                    self.remove(id);
                    out.push(HubOutput::Close(id));
                }
            }
        }
        out.extend(self.ended.drain(..).map(|id| HubOutput::Up(id, Up::End)));
        if st.moved() {
            out.push(HubOutput::Moved);
        }
        out
    }

    /// Bytes arrived on a connection.
    pub fn input(&mut self, now: u64, id: ConnId, bytes: Vec<u8>) -> Vec<HubOutput> {
        self.now = now;
        self.batch(|h, st, out| match h.conns.get(&id) {
            Some(Conn::Served { .. }) => {
                h.serve(st, now, id, ServingInput::Bytes(bytes), out);
                h.limit_buffered(st, out);
            }
            Some(Conn::Peer { .. }) => h.replicate(st, now, id, Some(ClientInput::Bytes(bytes)), out),
            None => {}
        })
    }

    /// The transport took bytes sent on these connections since the last report, with how many
    /// it took in all: progress for a replication session's stall timeout, room for a served
    /// connection's pushes (`ServingInput::Taken`). The driver reports it before `tick`, before
    /// a connection's input bytes, and at `PUSH_POLL_MS` while one holds pushes (`next_due`).
    pub fn sent(&mut self, now: u64, ids: &[(ConnId, u64)]) -> Vec<HubOutput> {
        self.now = now;
        self.batch(|h, st, out| {
            for (id, n) in ids {
                match h.conns.get_mut(id) {
                    Some(Conn::Peer { .. }) => h.replicate(st, now, *id, Some(ClientInput::Taken(*n)), out),
                    Some(Conn::Served { taken, moved, .. }) => {
                        if *n > *taken {
                            *taken = *n;
                            *moved = true;
                        }
                        h.serve(st, now, *id, ServingInput::Taken(*n), out);
                    }
                    None => {}
                }
            }
        })
    }

    /// The connection is gone (either side closed it). Runs as a batch (it commits nothing of
    /// its own).
    pub fn closed(&mut self, id: ConnId) -> Vec<HubOutput> {
        self.batch(|h, _, _| h.remove(id))
    }

    /// Node sync's messages, answers, Notifies, push room requests and closes for served
    /// connections, in order (one batch). Those of a connection gone are dropped.
    pub fn down(&mut self, now: u64, downs: Vec<(ConnId, Down)>) -> Vec<HubOutput> {
        self.now = now;
        self.batch(|h, st, out| {
            for (id, d) in downs {
                if !matches!(h.conns.get(&id), Some(Conn::Served { .. })) {
                    continue;
                }
                match d {
                    Down::Message(m) => h.serve(st, now, id, ServingInput::Peer(m), out),
                    Down::Reply { id: r, reply } => h.serve(st, now, id, ServingInput::Reply { id: r, reply }, out),
                    Down::Notify(n) => h.serve(st, now, id, ServingInput::Notify(n), out),
                    Down::WantRoom => h.serve(st, now, id, ServingInput::WantRoom, out),
                    Down::Keep(_) => {}
                    Down::Close => {
                        h.remove(id);
                        out.push(HubOutput::Close(id));
                    }
                }
            }
        })
    }

    /// Forgets a connection and what it holds (`Up::End` once the batch ends).
    fn remove(&mut self, id: ConnId) {
        let Some(Conn::Served { buffered, hold, need, started, .. }) = self.conns.remove(&id) else { return };
        self.buffered = self.buffered.saturating_sub(buffered);
        self.hold = self.hold.saturating_sub(hold);
        if hold > 0 || need.is_some() {
            self.active = self.active.saturating_sub(1);
        }
        if started {
            self.ended.push(id);
        }
    }

    /// What all served connections hold against `max_buffered_bytes` (bytes written and not
    /// taken, reply allowances handed up and not answered): never more than it.
    pub fn held(&self) -> usize {
        self.hold
    }

    /// Whether connection `id`'s received frames wait for room: its driver hands the hub none of
    /// its input until it takes input again (`take_resumed`). Others are served meanwhile.
    pub fn waits(&self, id: ConnId) -> bool {
        matches!(self.conns.get(&id), Some(Conn::Served { paused: true, .. }))
    }

    /// Connections that take input again since the last call.
    pub fn take_resumed(&mut self) -> Vec<ConnId> {
        std::mem::take(&mut self.resumed)
    }

    /// Each active connection's share of the output bound.
    fn share(&self, st: &HostStore) -> usize {
        st.policy().max_buffered_bytes / self.active.max(1)
    }

    /// The bound's bytes left for connection `id`: those the queue's first reserves are not
    /// left for the others.
    fn slack(&self, st: &HostStore, id: ConnId) -> usize {
        let left = st.policy().max_buffered_bytes.saturating_sub(self.hold);
        match self.queue.front() {
            Some(f) if *f != id => left.saturating_sub(self.need_of(*f)),
            _ => left,
        }
    }

    fn need_of(&self, id: ConnId) -> usize {
        match self.conns.get(&id) {
            Some(Conn::Served { need: Some(n), alone: true, .. }) => *n,
            _ => 0,
        }
    }

    /// Back-pressure on the output (spec/sync.md §10 Served connections): each served
    /// connection's replies, pushes and own requests go only within its share of
    /// `max_buffered_bytes` (the bound over the active connections) and the bytes the bound has
    /// left; its received requests wait for room in order, and it takes no input meanwhile. One
    /// holding nothing may take one reply past its share when the bound has room: those wait in
    /// a queue, the first one's need reserved, run here once it fits. Nothing passes the bound;
    /// a slow reader slows only itself; only output that does not move while the queue waits is
    /// closed for (`tick`).
    fn pressure(&mut self, st: &mut HostStore, out: &mut Vec<HubOutput>) {
        let max = st.policy().max_buffered_bytes;
        let mut kicks = self.queue.len();
        while let Some(&id) = self.queue.front() {
            let need = match self.conns.get(&id) {
                Some(Conn::Served { need: Some(n), alone: true, .. }) => *n,
                _ => {
                    self.queue.pop_front();
                    if let Some(Conn::Served { queued, .. }) = self.conns.get_mut(&id) {
                        *queued = None;
                    }
                    continue;
                }
            };
            if need > max.saturating_sub(self.hold) || kicks == 0 {
                if self.check_at.is_none() {
                    self.check_at = Some(self.now.saturating_add(osis_proto::serving::PUSH_POLL_MS));
                    self.unmove();
                }
                return;
            }
            kicks -= 1;
            // run while still first, so the room kept for it is its own; it leaves the queue
            // once it needs nothing more of the bound (the loop above), else stays first
            self.serve(st, self.now, id, ServingInput::Resume, out);
        }
        self.check_at = None;
    }

    fn unmove(&mut self) {
        for c in self.conns.values_mut() {
            if let Conn::Served { moved, .. } = c {
                *moved = false;
            }
        }
    }

    /// When the queue's first has waited half the stall time (`STALL_TIMEOUT_MS`, the most its
    /// peer waits on a request): then the bound's room is taken for it from the biggest
    /// holders, moving or not, before its peer's own stall rule closes it.
    fn first_due(&self) -> Option<u64> {
        let f = self.queue.front()?;
        match self.conns.get(f) {
            Some(Conn::Served { queued: Some(t), .. }) => Some(t.saturating_add(osis_proto::client::STALL_TIMEOUT_MS / 2)),
            _ => None,
        }
    }

    /// While the queue's first waits for the bound's room, once per `PUSH_POLL_MS` (the period
    /// the driver reports takes in, so a reader's progress shows in each): closes, most held
    /// first until the whole queue's needs fit, the connections holding output that the
    /// transport took none of since the last check (each peer that stops reading could
    /// otherwise hold its share for good, and anyone who shares one group can open
    /// `max_connections` of them; making room for the first alone would let the queue move one
    /// request a period). Once the first has waited half the stall time (`first_due`: readers
    /// draining too slowly to make its room in time), the connections holding the most,
    /// whatever they read, until it fits.
    fn close_stuck(&mut self, st: &HostStore, now: u64, out: &mut Vec<HubOutput>) {
        let Some(&first) = self.queue.front() else { return };
        let max = st.policy().max_buffered_bytes;
        if self.check_at.is_some_and(|t| t <= now) {
            let needs = self.queue.iter().fold(0usize, |n, q| n.saturating_add(self.need_of(*q))).min(max);
            // output of its own that did not move: a reservation alone (a reply to come) has no
            // bytes to move
            self.close_biggest(st, needs, |id, c| matches!(c, Conn::Served { moved: false, alone: false, queued: None, .. }) && id != first, "not moving", out);
            self.check_at = Some(now.saturating_add(osis_proto::serving::PUSH_POLL_MS));
            self.unmove();
        }
        if self.first_due().is_some_and(|t| t <= now) {
            let need = self.need_of(first);
            self.close_biggest(st, need, |id, _| id != first, "draining too slowly", out);
        }
    }

    /// Closes the connections `which` picks, most held first, until `need` fits the bound.
    fn close_biggest(&mut self, st: &HostStore, need: usize, which: impl Fn(ConnId, &Conn) -> bool, why: &str, out: &mut Vec<HubOutput>) {
        let max = st.policy().max_buffered_bytes;
        if need <= max.saturating_sub(self.hold) {
            return;
        }
        let mut picked: Vec<(usize, ConnId)> = self.conns.iter().filter_map(|(id, c)| match c {
            Conn::Served { hold, .. } if *hold > 0 && which(*id, c) => Some((*hold, *id)),
            _ => None,
        }).collect();
        picked.sort_unstable();
        while need > max.saturating_sub(self.hold) {
            let Some((_, id)) = picked.pop() else { break };
            self.remove(id);
            out.push(HubOutput::Close(id));
            out.push(HubOutput::Diagnostic(format!("connection {id}: closed, output {why} while others wait for room")));
        }
    }

    /// Received bytes held for all served connections: partial frames, frames waiting to run,
    /// requests handed up and not answered.
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// Over `max_buffered_bytes` received and held: closes the connections holding the largest
    /// until under it (anyone who can connect could otherwise hold `MAX_MESSAGE` per connection).
    fn limit_buffered(&mut self, st: &HostStore, out: &mut Vec<HubOutput>) {
        while self.buffered > st.policy().max_buffered_bytes {
            let Some(id) = self.conns.iter().filter_map(|(id, c)| if let Conn::Served { buffered, .. } = c { Some((*buffered, *id)) } else { None }).max().map(|(_, id)| id) else { break };
            self.remove(id);
            out.push(HubOutput::Close(id));
            out.push(HubOutput::Diagnostic(format!("connection {id}: closed, received frames over the budget")));
        }
    }

    /// Runs what is due: a bounded sweep (expiry, tombstones, claim sets), Hello
    /// deadlines, stalls of node sync's requests (spec/sync.md §6 Stall), replication work and
    /// timers.
    pub fn tick(&mut self, now: u64) -> Vec<HubOutput> {
        self.now = now;
        self.batch(|h, st, out| h.tick_in(st, now, out))
    }

    fn tick_in(&mut self, st: &mut HostStore, now: u64, out: &mut Vec<HubOutput>) {
        self.close_stuck(st, now, out);
        if now >= self.sweep_hold && (self.sweep_more || st.next_due().ok().flatten().is_some_and(|t| t <= now)) {
            match st.sweep(now, SWEEP_BUDGET).and_then(|s| st.commit().map(|()| s)) {
                Ok(s) => self.sweep_more = s.more,
                Err(e) => {
                    self.sweep_more = false;
                    self.sweep_hold = now.saturating_add(SWEEP_BACKOFF_MS);
                    out.push(HubOutput::Diagnostic(format!("sweep: {e}")));
                }
            }
        }
        let late: Vec<ConnId> = self.conns.iter().filter(|(_, c)| matches!(c, Conn::Served { hello_by: Some(t), .. } if *t <= now)).map(|(id, _)| *id).collect();
        for id in late {
            self.remove(id);
            out.push(HubOutput::Close(id));
        }
        let stalled: Vec<ConnId> = self.conns.iter().filter(|(_, c)| matches!(c, Conn::Served { c, .. } if c.stall_at().is_some_and(|t| t <= now))).map(|(id, _)| *id).collect();
        for id in stalled {
            self.remove(id);
            out.push(HubOutput::Close(id));
            out.push(HubOutput::Diagnostic(format!("connection {id}: closed, a request stalled")));
        }
        let due: Vec<(ConnId, bool)> = self
            .conns
            .iter()
            .filter_map(|(id, c)| match c {
                Conn::Peer { r, timer } => {
                    let fired = timer.is_some_and(|t| t <= now);
                    (fired || r.next_due(now).is_some_and(|t| t <= now)).then_some((*id, fired))
                }
                Conn::Served { .. } => None,
            })
            .collect();
        for (id, fired) in due {
            if fired && let Some(Conn::Peer { timer, .. }) = self.conns.get_mut(&id) {
                *timer = None;
            }
            self.replicate(st, now, id, fired.then_some(ClientInput::Timer), out);
        }
    }

    /// When `tick` next has work.
    pub fn next_due(&self, now: u64) -> Option<u64> {
        let sweep = if self.sweep_more { Some(now) } else { self.store().next_due().ok().flatten() }.map(|t| t.max(self.sweep_hold));
        // bytes not yet reported taken: the driver reports at the next tick (shares count them)
        let unread = (self.hold > 0).then(|| now.saturating_add(osis_proto::serving::PUSH_POLL_MS)).into_iter().chain(self.check_at).chain(self.first_due());
        let conns = self.conns.values().filter_map(|c| match c {
            Conn::Served { c, hello_by, .. } => [c.held().then(|| now.saturating_add(osis_proto::serving::PUSH_POLL_MS)), *hello_by, c.stall_at()].into_iter().flatten().min(),
            Conn::Peer { r, timer } => [*timer, r.next_due(now)].into_iter().flatten().min(),
        });
        sweep.into_iter().chain(unread).chain(conns).min()
    }

    fn serve(&mut self, st: &mut HostStore, now: u64, id: ConnId, input: ServingInput, out: &mut Vec<HubOutput>) {
        let (share, slack) = (self.share(st), self.slack(st, id));
        let Some(Conn::Served { c, remote, hello_by, buffered, hold, alone, need, queued, paused, started, opened, .. }) = self.conns.get_mut(&id) else { return };
        c.set_room(share, slack);
        // whose entries these are (echo suppression): a keyed peer's
        st.set_origin(match &remote.peer {
            Peer::Key(k) => Some(*k),
            Peer::Unix { .. } => None,
        });
        let outputs = c.handle(now, st, input);
        st.set_origin(None);
        if c.version().is_some() {
            *hello_by = None;
        }
        // node sync learns the connection once its Hello binds it, before anything of it
        if !*started && let Some((dialer, listener, key)) = c.binding() {
            *started = true;
            out.push(HubOutput::Up(id, Up::Start(Binding { dialer, listener, key, remote: *remote })));
        }
        let now_opened = !c.none_opened();
        let opened_moved = *started && now_opened != *opened;
        *opened = now_opened;
        let now_buffered = c.buffered();
        self.buffered = self.buffered.saturating_sub(*buffered).saturating_add(now_buffered);
        *buffered = now_buffered;
        let was_active = *hold > 0 || need.is_some();
        let now_hold = c.holding(&[]);
        self.hold = self.hold.saturating_sub(*hold).saturating_add(now_hold);
        *hold = now_hold;
        *alone = c.alone();
        *need = c.need();
        let is_active = *hold > 0 || need.is_some();
        self.active = (self.active + usize::from(is_active)).saturating_sub(usize::from(was_active));
        if need.is_some() && *alone && queued.is_none() {
            *queued = Some(now);
            self.queue.push_back(id);
        }
        let now_paused = !c.takes_input();
        if *paused && !now_paused {
            self.resumed.push(id);
        }
        *paused = now_paused;
        if opened_moved {
            out.push(HubOutput::Up(id, Up::Opened(now_opened)));
        }
        for o in outputs {
            match o {
                ServingOutput::Send(b) => out.push(HubOutput::Send(id, b)),
                ServingOutput::Close => {
                    self.remove(id);
                    out.push(HubOutput::Close(id));
                }
                ServingOutput::Changed(l) => self.changed(st, now, l, out),
                // only to the label's subscribers on other connections, the bytes shared
                ServingOutput::Relay(r) => {
                    let others: Vec<ConnId> = self.conns.iter().filter(|(k, c)| **k != id && matches!(c, Conn::Served { c, .. } if c.subscribed(&r.label))).map(|(k, _)| *k).collect();
                    for j in others {
                        self.relays_delivered += 1;
                        self.serve(st, now, j, ServingInput::Relay(r.clone()), out);
                    }
                }
                ServingOutput::PeerError(e) => out.push(HubOutput::Diagnostic(format!("connection {id}: {e}"))),
                ServingOutput::StoreError(e) => out.push(HubOutput::Diagnostic(e.to_string())),
                // node sync's, judged there (proofs, records, the shared set, the stream, the port)
                ServingOutput::Peer(m) => out.push(HubOutput::Up(id, Up::Message(m))),
                ServingOutput::Request(m) => out.push(HubOutput::Up(id, Up::Request(m))),
                ServingOutput::Room { budget } => out.push(HubOutput::Up(id, Up::Room { budget })),
            }
        }
    }

    /// A label's log grew: push to subscriptions, queue replication.
    fn changed(&mut self, st: &mut HostStore, now: u64, label: LabelId, out: &mut Vec<HubOutput>) {
        let ids: Vec<ConnId> = self.conns.keys().copied().collect();
        for j in ids {
            match self.conns.get_mut(&j) {
                Some(Conn::Served { .. }) => self.serve(st, now, j, ServingInput::Changed(label), out),
                Some(Conn::Peer { r, .. }) => {
                    r.mark([label]);
                    self.replicate(st, now, j, None, out);
                }
                None => {}
            }
        }
    }

    fn replicate(&mut self, st: &mut HostStore, now: u64, id: ConnId, input: Option<ClientInput>, out: &mut Vec<HubOutput>) {
        let Some(Conn::Peer { r, timer }) = self.conns.get_mut(&id) else { return };
        let outputs = r.handle(now, st, input);
        let mut close = false;
        for o in outputs {
            match o {
                ClientOutput::Send(b) => out.push(HubOutput::Send(id, b)),
                ClientOutput::Close => close = true,
                ClientOutput::SetTimer(t) => *timer = Some(t),
                ClientOutput::Event(e) => {
                    if let Some(d) = Replicator::diagnostic(&e) {
                        out.push(HubOutput::Diagnostic(format!("peer {id}: {d}")));
                    }
                }
            }
        }
        for d in r.take_diagnostics() {
            out.push(HubOutput::Diagnostic(format!("peer {id}: {d}")));
        }
        if close {
            self.conns.remove(&id);
            out.push(HubOutput::Close(id));
        }
    }
}

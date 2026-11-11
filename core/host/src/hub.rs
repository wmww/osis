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
use osis_base::LabelId;
use osis_proto::{ClientInput, ClientOutput, Message, ServingConfig, ServingSession, ServingInput, ServingOutput};
use osis_transport::{Peer, Source};
use std::collections::{BTreeMap, BTreeSet};

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
    /// `buffered`: partial frame bytes after the last input; `unread`: bytes written and not
    /// taken by the transport (as reported); `taken`: the last report (`Hub::sent`); `moved`:
    /// a report took more since the last check while the node was over its bound; `waits`: it
    /// holds more than its share (`Hub::waits`); `started`: its `Up::Start` went; `opened`: the
    /// last `Up::Opened`.
    Served { c: Box<ServingSession>, remote: Remote, hello_by: Option<u64>, buffered: usize, unread: usize, taken: u64, moved: bool, waits: bool, started: bool, opened: bool },
    Peer { r: Box<Replicator>, timer: Option<u64> },
}

pub struct Hub {
    store: HostStore,
    rng: Box<dyn osis_crypto::NodeRng>,
    conns: BTreeMap<ConnId, Conn>,
    /// Sweeps wait until then (after a failure).
    sweep_hold: u64,
    /// The last sweep ran out of budget.
    sweep_more: bool,
    /// Partial frame bytes over all served connections.
    buffered: usize,
    /// Bytes written to all served connections and not taken by the transport (as reported).
    unread: usize,
    /// Served connections holding unread output, by how much: each one's share of
    /// `max_buffered_bytes` is that over their number.
    holders: BTreeSet<(usize, ConnId)>,
    /// Those holding more than their share (`waits`), by how much.
    waiting: BTreeSet<(usize, ConnId)>,
    /// The share as of the last batch's end.
    share: usize,
    /// Served connections whose unread changed in this batch.
    touched: Vec<ConnId>,
    /// Connections back under their share since `take_resumed`.
    resumed: Vec<ConnId>,
    /// While `unread` is over `max_buffered_bytes`: when connections whose output did not move
    /// are next closed (`tick`).
    check_at: Option<u64>,
    /// The latest time any call carried.
    now: u64,
    /// Relay-only entries handed to connections so far (`relays_delivered`).
    relays_delivered: u64,
    /// Started connections removed since the last batch ended (`Up::End`).
    ended: Vec<ConnId>,
}

impl Hub {
    pub fn new(store: HostStore, rng: Box<dyn osis_crypto::NodeRng>) -> Hub {
        Hub { store, rng, conns: BTreeMap::new(), sweep_hold: 0, sweep_more: false, buffered: 0, unread: 0, holders: BTreeSet::new(), waiting: BTreeSet::new(), share: usize::MAX, touched: Vec::new(), resumed: Vec::new(), check_at: None, now: 0, relays_delivered: 0, ended: Vec::new() }
    }

    /// Tests only: an exact copy of this hub as it stands, on `clock`, sharing no mutable state
    /// with it: its store (`HostStore::test_copy`), connections and their sessions, its rng going
    /// on with the same stream. Never in a product: two hubs with one key and rng stream.
    #[doc(hidden)]
    pub fn test_copy(&self, clock: std::sync::Arc<dyn osis_base::Clock>) -> Result<Hub, osis_store::Error> {
        osis_base::copying::copying(|| {
            Ok(Hub {
                store: self.store.test_copy(clock)?,
                rng: self.rng.test_copy(),
                conns: self.conns.clone(),
                sweep_hold: self.sweep_hold,
                sweep_more: self.sweep_more,
                buffered: self.buffered,
                unread: self.unread,
                holders: self.holders.clone(),
                waiting: self.waiting.clone(),
                share: self.share,
                touched: self.touched.clone(),
                resumed: self.resumed.clone(),
                check_at: self.check_at,
                now: self.now,
                relays_delivered: self.relays_delivered,
                ended: self.ended.clone(),
            })
        })
    }

    pub fn store(&self) -> &HostStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut HostStore {
        &mut self.store
    }

    /// Serves `store` from now on and returns the one it served (hosting started or stopped):
    /// served connections that opened something there, and replication sessions, close.
    pub fn replace_store(&mut self, store: HostStore) -> (HostStore, Vec<HubOutput>) {
        let old = std::mem::replace(&mut self.store, store);
        self.sweep_more = false;
        self.sweep_hold = 0;
        let out = self.batch(|h, out| {
            let gone: Vec<ConnId> = h.conns.iter().filter(|(_, c)| match c {
                Conn::Served { c, .. } => c.opened().next().is_some(),
                Conn::Peer { .. } => true,
            }).map(|(id, _)| *id).collect();
            for id in gone {
                h.remove(id);
                out.push(HubOutput::Close(id));
            }
        });
        (old, out)
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
        let hello_by = Some(now.saturating_add(self.store.policy().hello_ms));
        self.conns.insert(id, Conn::Served { c: Box::new(ServingSession::new(cfg)), remote, hello_by, buffered: 0, unread: 0, taken: 0, moved: false, waits: false, started: false, opened: false });
        self.batch(|h, out| h.serve(now, id, ServingInput::Start, out))
    }

    /// A connection this node dialed to peer host `peer_key` is up: replicate to it.
    pub fn peer_up(&mut self, now: u64, id: ConnId, peer_key: [u8; 32]) -> Vec<HubOutput> {
        self.now = now;
        let challenge = self.challenge();
        self.conns.insert(id, Conn::Peer { r: Box::new(Replicator::new(peer_key, challenge)), timer: None });
        self.batch(|h, out| h.replicate(now, id, Some(ClientInput::Start), out))
    }

    /// Runs `f` in one store transaction committed at its end (one commit, at most one shredding
    /// root write, for a whole message of entries, spec/requirements.md: peer input never causes
    /// unbounded work), before any output leaves. If that fails, nothing the batch would send goes: the connections it
    /// would have written to are closed (their peers retry what went unanswered).
    fn batch(&mut self, f: impl FnOnce(&mut Hub, &mut Vec<HubOutput>)) -> Vec<HubOutput> {
        self.store.defer_durability();
        let mut out = Vec::new();
        f(self, &mut out);
        self.pressure(&mut out);
        if let Err(e) = self.store.durable() {
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
        out
    }

    /// Bytes arrived on a connection.
    pub fn input(&mut self, now: u64, id: ConnId, bytes: Vec<u8>) -> Vec<HubOutput> {
        self.now = now;
        self.batch(|h, out| match h.conns.get(&id) {
            Some(Conn::Served { .. }) => {
                h.serve(now, id, ServingInput::Bytes(bytes), out);
                h.limit_buffered(out);
            }
            Some(Conn::Peer { .. }) => h.replicate(now, id, Some(ClientInput::Bytes(bytes)), out),
            None => {}
        })
    }

    /// The transport took bytes sent on these connections since the last report, with how many
    /// it took in all: progress for a replication session's stall timeout, room for a served
    /// connection's pushes (`ServingInput::Taken`). The driver reports it before `tick`, before
    /// a connection's input bytes, and at `PUSH_POLL_MS` while one holds pushes (`next_due`).
    pub fn sent(&mut self, now: u64, ids: &[(ConnId, u64)]) -> Vec<HubOutput> {
        self.now = now;
        self.batch(|h, out| {
            for (id, n) in ids {
                match h.conns.get_mut(id) {
                    Some(Conn::Peer { .. }) => h.replicate(now, *id, Some(ClientInput::Taken(*n)), out),
                    Some(Conn::Served { taken, moved, .. }) => {
                        if *n > *taken {
                            *taken = *n;
                            *moved = true;
                        }
                        h.serve(now, *id, ServingInput::Taken(*n), out);
                    }
                    None => {}
                }
            }
        })
    }

    /// The connection is gone (either side closed it). Runs as a batch (it commits nothing of
    /// its own).
    pub fn closed(&mut self, id: ConnId) -> Vec<HubOutput> {
        self.batch(|h, _| h.remove(id))
    }

    /// Node sync's messages, answers, Notifies, push room requests and closes for served
    /// connections, in order (one batch). Those of a connection gone are dropped.
    pub fn down(&mut self, now: u64, downs: Vec<(ConnId, Down)>) -> Vec<HubOutput> {
        self.now = now;
        self.batch(|h, out| {
            for (id, d) in downs {
                if !matches!(h.conns.get(&id), Some(Conn::Served { .. })) {
                    continue;
                }
                match d {
                    Down::Message(m) => h.serve(now, id, ServingInput::Peer(m), out),
                    Down::Reply { id: r, reply } => h.serve(now, id, ServingInput::Reply { id: r, reply }, out),
                    Down::Notify(n) => h.serve(now, id, ServingInput::Notify(n), out),
                    Down::WantRoom => h.serve(now, id, ServingInput::WantRoom, out),
                    Down::Keep(_) => {}
                    Down::Close => {
                        h.remove(id);
                        out.push(HubOutput::Close(id));
                    }
                }
            }
        })
    }

    /// Forgets a connection and its partial frame bytes (`Up::End` once the batch ends).
    fn remove(&mut self, id: ConnId) {
        let Some(Conn::Served { buffered, unread, started, .. }) = self.conns.remove(&id) else { return };
        self.buffered = self.buffered.saturating_sub(buffered);
        self.unread = self.unread.saturating_sub(unread);
        self.holders.remove(&(unread, id));
        self.waiting.remove(&(unread, id));
        if started {
            self.ended.push(id);
        }
    }

    /// Bytes written to all served connections and not taken by the transport (as reported).
    pub fn unread(&self) -> usize {
        self.unread
    }

    /// Whether connection `id` holds more than its share of `max_buffered_bytes` unread (the
    /// bound over the number of connections holding any): then its driver hands the hub none
    /// of its input and its session pushes nothing and grants no room, until its reader drained
    /// it under its share (`take_resumed`). Others are served meanwhile.
    pub fn waits(&self, id: ConnId) -> bool {
        matches!(self.conns.get(&id), Some(Conn::Served { waits: true, .. }))
    }

    /// Connections back under their share since the last call: their input may go on.
    pub fn take_resumed(&mut self) -> Vec<ConnId> {
        std::mem::take(&mut self.resumed)
    }

    /// A served connection's unread went from `old` to `new`.
    fn account(&mut self, id: ConnId, old: usize, new: usize, waits: bool) {
        if old == new {
            return;
        }
        if old > 0 {
            self.holders.remove(&(old, id));
        }
        if new > 0 {
            self.holders.insert((new, id));
        }
        if waits {
            self.waiting.remove(&(old, id));
            self.waiting.insert((new, id));
        }
        self.touched.push(id);
    }

    /// Back-pressure on the output, per connection (spec/sync.md §10 Served connections): a
    /// connection holding more than its share of `max_buffered_bytes` unread waits (`waits`), so
    /// only it stops making output while its reader drains it; one under its share, holding
    /// nothing included, is served whatever the others hold. Shares follow the number of
    /// holders: one over a smaller share just waits. Below its share again a held session's
    /// pushes go on. Only bytes that do not move are closed for (`tick`).
    fn pressure(&mut self, out: &mut Vec<HubOutput>) {
        let max = self.store.policy().max_buffered_bytes;
        if self.unread <= max {
            self.check_at = None;
        } else if self.check_at.is_none() {
            self.check_at = Some(self.now.saturating_add(osis_proto::serving::PUSH_POLL_MS));
            self.unmove();
        }
        loop {
            let share = max / self.holders.len().max(1);
            // newly over: those whose unread changed, and those between a smaller share and the last
            let mut over = std::mem::take(&mut self.touched);
            if share < self.share {
                over.extend(self.holders.range((share.saturating_add(1), 0)..=(self.share, ConnId::MAX)).map(|(_, id)| *id));
            }
            self.share = share;
            for id in over {
                if let Some(Conn::Served { unread, waits, .. }) = self.conns.get_mut(&id)
                    && !*waits
                    && *unread > share
                {
                    *waits = true;
                    self.waiting.insert((*unread, id));
                }
            }
            let mut kicked = false;
            while let Some(&(u, id)) = self.waiting.first()
                && u <= share
            {
                self.waiting.pop_first();
                let Some(Conn::Served { c, waits, .. }) = self.conns.get_mut(&id) else { continue };
                *waits = false;
                self.resumed.push(id);
                if c.held() {
                    self.serve(self.now, id, ServingInput::Unfull, out);
                    kicked = true;
                }
            }
            // what they pushed may change the shares again
            if !kicked {
                break;
            }
        }
    }

    fn unmove(&mut self) {
        for c in self.conns.values_mut() {
            if let Conn::Served { moved, .. } = c {
                *moved = false;
            }
        }
    }

    /// While the node is over `max_buffered_bytes` unread, once per `PUSH_POLL_MS` (the period
    /// the driver reports takes in, so a reader's progress shows in each): closes, most unread
    /// first until it is no longer over, the connections holding unread output that the
    /// transport took none of since the last check.
    /// Each peer that stops reading could otherwise hold `max_queued_bytes`, and anyone who
    /// shares one group can open `max_connections` of them.
    fn close_stuck(&mut self, now: u64, out: &mut Vec<HubOutput>) {
        if self.check_at.is_none_or(|t| t > now) {
            return;
        }
        let mut stuck: Vec<(usize, ConnId)> = self.conns.iter().filter_map(|(id, c)| match c {
            Conn::Served { unread, moved: false, .. } if *unread > 0 => Some((*unread, *id)),
            _ => None,
        }).collect();
        stuck.sort_unstable();
        while self.unread > self.store.policy().max_buffered_bytes {
            let Some((_, id)) = stuck.pop() else { break };
            self.remove(id);
            out.push(HubOutput::Close(id));
            out.push(HubOutput::Diagnostic(format!("connection {id}: closed, output unread and not moving while the node is over its bound")));
        }
        self.check_at = Some(now.saturating_add(osis_proto::serving::PUSH_POLL_MS));
        self.unmove();
    }

    /// Partial frame bytes held for all served connections.
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// Over `max_buffered_bytes` of partial frames: closes the connections holding the largest
    /// until under it (anyone who can connect could otherwise hold `MAX_MESSAGE` per connection).
    fn limit_buffered(&mut self, out: &mut Vec<HubOutput>) {
        while self.buffered > self.store.policy().max_buffered_bytes {
            let Some(id) = self.conns.iter().filter_map(|(id, c)| if let Conn::Served { buffered, .. } = c { Some((*buffered, *id)) } else { None }).max().map(|(_, id)| id) else { break };
            self.remove(id);
            out.push(HubOutput::Close(id));
            out.push(HubOutput::Diagnostic(format!("connection {id}: closed, partial frames over the budget")));
        }
    }

    /// Runs what is due: a bounded sweep (expiry, tombstones, claim sets), Hello
    /// deadlines, stalls of node sync's requests (spec/sync.md §6 Stall), replication work and
    /// timers.
    pub fn tick(&mut self, now: u64) -> Vec<HubOutput> {
        self.now = now;
        self.batch(|h, out| h.tick_in(now, out))
    }

    fn tick_in(&mut self, now: u64, out: &mut Vec<HubOutput>) {
        self.close_stuck(now, out);
        if now >= self.sweep_hold && (self.sweep_more || self.store.next_due().ok().flatten().is_some_and(|t| t <= now)) {
            match self.store.sweep(now, SWEEP_BUDGET).and_then(|s| self.store.commit().map(|()| s)) {
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
            self.replicate(now, id, fired.then_some(ClientInput::Timer), out);
        }
    }

    /// When `tick` next has work.
    pub fn next_due(&self, now: u64) -> Option<u64> {
        let sweep = if self.sweep_more { Some(now) } else { self.store.next_due().ok().flatten() }.map(|t| t.max(self.sweep_hold));
        // bytes not yet reported taken: the driver reports at the next tick (shares count them)
        let unread = (self.unread > 0).then(|| now.saturating_add(osis_proto::serving::PUSH_POLL_MS)).into_iter().chain(self.check_at);
        let conns = self.conns.values().filter_map(|c| match c {
            Conn::Served { c, hello_by, .. } => [c.held().then(|| now.saturating_add(osis_proto::serving::PUSH_POLL_MS)), *hello_by, c.stall_at()].into_iter().flatten().min(),
            Conn::Peer { r, timer } => [*timer, r.next_due(now)].into_iter().flatten().min(),
        });
        sweep.into_iter().chain(unread).chain(conns).min()
    }

    fn serve(&mut self, now: u64, id: ConnId, input: ServingInput, out: &mut Vec<HubOutput>) {
        let Some(Conn::Served { c, remote, hello_by, buffered, unread, waits, started, opened, .. }) = self.conns.get_mut(&id) else { return };
        c.set_full(*waits);
        // whose entries these are (echo suppression): a keyed peer's
        self.store.set_origin(match &remote.peer {
            Peer::Key(k) => Some(*k),
            Peer::Unix { .. } => None,
        });
        let outputs = c.handle(now, &mut self.store, input);
        self.store.set_origin(None);
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
        let now_unread = c.unread();
        self.unread = self.unread.saturating_sub(*unread).saturating_add(now_unread);
        let (old, w) = (std::mem::replace(unread, now_unread), *waits);
        self.account(id, old, now_unread, w);
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
                ServingOutput::Changed(l) => self.changed(now, l, out),
                // only to the label's subscribers on other connections, the bytes shared
                ServingOutput::Relay(r) => {
                    let others: Vec<ConnId> = self.conns.iter().filter(|(k, c)| **k != id && matches!(c, Conn::Served { c, .. } if c.subscribed(&r.label))).map(|(k, _)| *k).collect();
                    for j in others {
                        self.relays_delivered += 1;
                        self.serve(now, j, ServingInput::Relay(r.clone()), out);
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
    fn changed(&mut self, now: u64, label: LabelId, out: &mut Vec<HubOutput>) {
        let ids: Vec<ConnId> = self.conns.keys().copied().collect();
        for j in ids {
            match self.conns.get_mut(&j) {
                Some(Conn::Served { .. }) => self.serve(now, j, ServingInput::Changed(label), out),
                Some(Conn::Peer { r, .. }) => {
                    r.mark([label]);
                    self.replicate(now, j, None, out);
                }
                None => {}
            }
        }
    }

    fn replicate(&mut self, now: u64, id: ConnId, input: Option<ClientInput>, out: &mut Vec<HubOutput>) {
        let Some(Conn::Peer { r, timer }) = self.conns.get_mut(&id) else { return };
        let outputs = r.handle(now, &mut self.store, input);
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

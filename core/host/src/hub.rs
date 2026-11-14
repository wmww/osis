//! `Hub`: a node's connections over one store, sans-I/O (spec/sync-ids.md §6). One osis-proto
//! `Session` per connection, accepted under the key of the listener that took it or dialed to a
//! key (`dial`); bounded sweeps, Hello deadlines and stalls of the upper layer's requests. Node
//! sync is every session's upper layer: the hub hands it each connection's start, node-kind
//! messages, answers to its requests, client-port requests, push room and end (`HubOutput::Up`)
//! and takes its requests, answers and closes down (`Hub::down`), judging none of them. The node's driver and the simulator only move bytes, pass `Up` and
//! `Down` between the hub and node sync, and call `tick` when `next_due` says.

use crate::store::HostStore;
use std::sync::{Arc, Mutex, MutexGuard};
use osis_proto::{Message, SessionConfig, Session, SessionInput, SessionOutput};
use osis_transport::Peer;
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
    /// Something worth logging (a peer's protocol error, a storage failure).
    Diagnostic(String),
    /// For node sync, the session's upper layer.
    Up(ConnId, Up),
    /// The batch changed a sync ID node sync reads (`HostStore::take_moved`): node sync runs
    /// again (`Event::Hub`, with no `Up` if none).
    Moved,
}

/// What a connection hands node sync.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Up {
    /// The peer's Hello arrived: what the connection binds. Every other `Up` of it but a dialed
    /// connection's `End` comes after.
    Start(Binding),
    /// A node-kind message (`Message::for_node`), which node sync answers by `Down` if a request;
    /// an answer to one of node sync's requests; a Notify.
    Message(Box<Message>),
    /// A client-port request (Auth, Call, Sub: answered by `Down::Reply`; an Unsub, already
    /// answered).
    Request(Box<Message>),
    /// Pushes of up to `budget` bytes may go now (after `Down::WantRoom`).
    Room { budget: usize },
    /// The connection is gone (after a `Start`, or a dialed one at any time).
    End,
}

/// A connection's binding (spec/sync-opens.md §2, connection proofs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The dialer's and the listener's Hello challenges, and the listener's static key (this
    /// side's listener's, or the key dialed).
    pub dialer: [u8; 32],
    pub listener: [u8; 32],
    pub key: [u8; 32],
    pub remote: Remote,
}

/// The peer of a connection as the transport tells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Remote {
    /// Who it is (a key it authenticated, or a unix peer's uid).
    pub peer: Peer,
    /// A relay carries the connection (`osis_transport::Connection::relayed`).
    pub relayed: bool,
}

impl Remote {
    /// A peer with transport key `key`, not relayed.
    pub fn key(key: [u8; 32]) -> Remote {
        Remote { peer: Peer::Key(key), relayed: false }
    }
}

/// What node sync hands a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Down {
    /// A message to send: a request (its id node sync's) within the session's request window,
    /// anything else at once (a relay-only push without room is dropped).
    Message(Box<Message>),
    /// The answer to an `Up::Request`.
    Reply { id: osis_proto::msg::Id, reply: Result<osis_proto::Outcome, osis_proto::Code> },
    /// Notify pushes, within the room last granted.
    Notify(Vec<(osis_proto::msg::Id, osis_proto::Payload)>),
    /// Pushes wait: `Up::Room` when the session's push rule allows.
    WantRoom,
    /// Node sync opened the label here by a sync-key or static-entry Hit: the session takes its
    /// Deletes (`SessionInput::Open`).
    Open(osis_base::LabelId),
    /// That open ended.
    Shut(osis_base::LabelId),
    /// Close the connection.
    Close,
}

/// A connection. `dialed`: this node dialed it (its `Up::End` goes even before a `Start`); `buffered`: received bytes it holds (`Session::buffered`); `hold`:
/// what it holds against the output bound (`Session::holding`); `alone`: no output of its
/// own (`Session::alone`); `need`: the room its first waiting reply, push or request needs
/// (`Session::need`); `queued`: in `queue` since then; `paused`: received frames wait for
/// room, so it takes no input (`Hub::waits`); `taken`: the last report (`Hub::sent`); `moved`: a
/// report took more since the last check; `started`: its `Up::Start` went.
#[derive(Clone)]
struct Conn {
    c: Box<Session>,
    remote: Remote,
    dialed: bool,
    hello_by: Option<u64>,
    buffered: usize,
    hold: usize,
    alone: bool,
    need: Option<usize>,
    queued: Option<u64>,
    paused: bool,
    taken: u64,
    moved: bool,
    started: bool,
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
    /// Received bytes held for all connections (`Session::buffered`).
    buffered: usize,
    /// What all connections hold against `max_buffered_bytes`: bytes written and not
    /// taken by the transport (as reported), and reply allowances handed up and not answered.
    hold: usize,
    /// Connections holding something or needing room: each one's share of the bound is
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
    /// Started connections removed since the last batch ended (`Up::End`).
    ended: Vec<ConnId>,
}

impl Hub {
    pub fn new(store: Arc<Mutex<HostStore>>, rng: Box<dyn osis_crypto::NodeRng>) -> Hub {
        Hub { store, rng, conns: BTreeMap::new(), sweep_hold: 0, sweep_more: false, buffered: 0, hold: 0, active: 0, queue: VecDeque::new(), resumed: Vec::new(), check_at: None, now: 0, ended: Vec::new() }
    }

    /// Tests only: an exact copy of this hub as it stands, on `clock`, sharing no mutable state
    /// with it: its store (`HostStore::test_copy`), connections and their sessions, its rng going
    /// on with the same stream. Never in a product: two hubs with one key and rng stream.
    #[doc(hidden)]
    pub fn test_copy(&self, clock: std::sync::Arc<dyn osis_base::Clock>) -> Result<Hub, osis_store::Error> {
        // inside a world copy, the copy of the store a node's engine shares with this hub
        Ok(self.test_copy_over(osis_store::test_copy_shared(&self.store, clock)?))
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
    /// and connections that opened something close.
    pub fn stop_hosting(&mut self, drop: &dyn Fn(&osis_base::LabelId) -> bool) -> Vec<HubOutput> {
        self.sweep_more = false;
        self.sweep_hold = 0;
        let mut out = Vec::new();
        if let Err(e) = self.store().drop_labels(drop) {
            out.push(HubOutput::Diagnostic(format!("hosting stopped: dropping its labels: {e}")));
        }
        out.extend(self.batch(|h, _, out| {
            let gone: Vec<ConnId> = h.conns.iter().filter(|(_, c)| c.c.opened().next().is_some()).map(|(id, _)| *id).collect();
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


    fn challenge(&mut self) -> [u8; 32] {
        let mut c = [0u8; 32];
        self.rng.fill_bytes(&mut c);
        c
    }

    /// A connection from `remote` on the listener of static key `key` (bound by open signatures
    /// and connection proofs; spec/sync-opens.md §4): start its session (sends Hello). How many
    /// connections a node serves is node sync's rule (it closes by `Down::Close`); the hub caps
    /// none.
    pub fn accept(&mut self, now: u64, id: ConnId, key: [u8; 32], remote: Remote) -> Vec<HubOutput> {
        self.start(now, id, key, remote, false)
    }

    /// A connection node sync dialed to static key `key`, up now (`remote`: the transport's
    /// word on it): start its session (sends Hello). Its `Up::End` goes whenever it ends.
    pub fn dial(&mut self, now: u64, id: ConnId, key: [u8; 32], remote: Remote) -> Vec<HubOutput> {
        self.start(now, id, key, remote, true)
    }

    fn start(&mut self, now: u64, id: ConnId, key: [u8; 32], remote: Remote, dialed: bool) -> Vec<HubOutput> {
        self.now = now;
        let cfg = SessionConfig { listener_key: key, challenge: self.challenge(), dialed };
        let hello_by = Some(now.saturating_add(self.store().policy().hello_ms));
        self.conns.insert(id, Conn { c: Box::new(Session::new(cfg)), remote, dialed, hello_by, buffered: 0, hold: 0, alone: true, need: None, queued: None, paused: false, taken: 0, moved: false, started: false });
        self.batch(|h, st, out| h.serve(st, now, id, SessionInput::Start, out))
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
        self.batch(|h, st, out| {
            if h.conns.contains_key(&id) {
                h.serve(st, now, id, SessionInput::Bytes(bytes), out);
                h.limit_buffered(st, out);
            }
        })
    }

    /// The transport took bytes sent on these connections since the last report, with how many
    /// it took in all: room for a connection's pushes (`SessionInput::Taken`). The driver reports it before `tick`, before
    /// a connection's input bytes, and at `PUSH_POLL_MS` while one holds pushes (`next_due`).
    pub fn sent(&mut self, now: u64, ids: &[(ConnId, u64)]) -> Vec<HubOutput> {
        self.now = now;
        self.batch(|h, st, out| {
            for (id, n) in ids {
                if let Some(c) = h.conns.get_mut(id) {
                    if *n > c.taken {
                        c.taken = *n;
                        c.moved = true;
                    }
                    h.serve(st, now, *id, SessionInput::Taken(*n), out);
                }
            }
        })
    }

    /// The connection is gone (either side closed it). Runs as a batch (it commits nothing of
    /// its own).
    pub fn closed(&mut self, id: ConnId) -> Vec<HubOutput> {
        self.batch(|h, _, _| h.remove(id))
    }

    /// Node sync's messages, answers, Notifies, push room requests and closes for its
    /// connections, in order (one batch). Those of a connection gone are dropped.
    pub fn down(&mut self, now: u64, downs: Vec<(ConnId, Down)>) -> Vec<HubOutput> {
        self.now = now;
        self.batch(|h, st, out| {
            for (id, d) in downs {
                if !h.conns.contains_key(&id) {
                    continue;
                }
                match d {
                    Down::Message(m) => h.serve(st, now, id, SessionInput::Peer(m), out),
                    Down::Reply { id: r, reply } => h.serve(st, now, id, SessionInput::Reply { id: r, reply }, out),
                    Down::Notify(n) => h.serve(st, now, id, SessionInput::Notify(n), out),
                    Down::WantRoom => h.serve(st, now, id, SessionInput::WantRoom, out),
                    Down::Open(l) => h.serve(st, now, id, SessionInput::Open(l), out),
                    Down::Shut(l) => h.serve(st, now, id, SessionInput::Shut(l), out),
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
        let Some(Conn { buffered, hold, need, started, dialed, .. }) = self.conns.remove(&id) else { return };
        self.buffered = self.buffered.saturating_sub(buffered);
        self.hold = self.hold.saturating_sub(hold);
        if hold > 0 || need.is_some() {
            self.active = self.active.saturating_sub(1);
        }
        if started || dialed {
            self.ended.push(id);
        }
    }

    /// What all connections hold against `max_buffered_bytes` (bytes written and not
    /// taken, reply allowances handed up and not answered): never more than it.
    pub fn held(&self) -> usize {
        self.hold
    }

    /// Whether connection `id`'s received frames wait for room: its driver hands the hub none of
    /// its input until it takes input again (`take_resumed`). Others are served meanwhile.
    pub fn waits(&self, id: ConnId) -> bool {
        matches!(self.conns.get(&id), Some(Conn { paused: true, .. }))
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
            Some(Conn { need: Some(n), alone: true, .. }) => *n,
            _ => 0,
        }
    }

    /// Back-pressure on the output (spec/sync-transport.md §5 served connections): each
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
                Some(Conn { need: Some(n), alone: true, .. }) => *n,
                _ => {
                    self.queue.pop_front();
                    if let Some(Conn { queued, .. }) = self.conns.get_mut(&id) {
                        *queued = None;
                    }
                    continue;
                }
            };
            if need > max.saturating_sub(self.hold) || kicks == 0 {
                if self.check_at.is_none() {
                    self.check_at = Some(self.now.saturating_add(osis_proto::session::PUSH_POLL_MS));
                    self.unmove();
                }
                return;
            }
            kicks -= 1;
            // run while still first, so the room kept for it is its own; it leaves the queue
            // once it needs nothing more of the bound (the loop above), else stays first
            self.serve(st, self.now, id, SessionInput::Resume, out);
        }
        self.check_at = None;
    }

    fn unmove(&mut self) {
        for c in self.conns.values_mut() {
            c.moved = false;
        }
    }

    /// When the queue's first has waited half the stall time (`STALL_TIMEOUT_MS`, the most its
    /// peer waits on a request): then the bound's room is taken for it from the biggest
    /// holders, moving or not, before its peer's own stall rule closes it.
    fn first_due(&self) -> Option<u64> {
        let f = self.queue.front()?;
        match self.conns.get(f) {
            Some(Conn { queued: Some(t), .. }) => Some(t.saturating_add(osis_proto::window::STALL_TIMEOUT_MS / 2)),
            _ => None,
        }
    }

    /// While the queue's first waits for the bound's room, once per `PUSH_POLL_MS` (the period
    /// the driver reports takes in, so a reader's progress shows in each): closes, most held
    /// first until the whole queue's needs fit, the connections holding output that the
    /// transport took none of since the last check (each peer that stops reading could
    /// otherwise hold its share for good, and anyone who shares one group can open any
    /// number of them; making room for the first alone would let the queue move one
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
            self.close_biggest(st, needs, |id, c| matches!(c, Conn { moved: false, alone: false, queued: None, .. }) && id != first, "not moving", out);
            self.check_at = Some(now.saturating_add(osis_proto::session::PUSH_POLL_MS));
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
            Conn { hold, .. } if *hold > 0 && which(*id, c) => Some((*hold, *id)),
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

    /// Received bytes held for all connections: partial frames, frames waiting to run,
    /// requests handed up and not answered.
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// Over `max_buffered_bytes` received and held: closes the connections holding the largest
    /// until under it (anyone who can connect could otherwise hold `MAX_MESSAGE` per connection).
    fn limit_buffered(&mut self, st: &HostStore, out: &mut Vec<HubOutput>) {
        while self.buffered > st.policy().max_buffered_bytes {
            let Some(id) = self.conns.iter().map(|(id, c)| (c.buffered, *id)).max().map(|(_, id)| id) else { break };
            self.remove(id);
            out.push(HubOutput::Close(id));
            out.push(HubOutput::Diagnostic(format!("connection {id}: closed, received frames over the budget")));
        }
    }

    /// Runs what is due: a bounded sweep (expiry, tombstones, claim sets), Hello
    /// deadlines and stalls of node sync's requests (spec/sync-streams.md §1 stall).
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
        let late: Vec<ConnId> = self.conns.iter().filter(|(_, c)| matches!(c, Conn { hello_by: Some(t), .. } if *t <= now)).map(|(id, _)| *id).collect();
        for id in late {
            self.remove(id);
            out.push(HubOutput::Close(id));
        }
        let stalled: Vec<ConnId> = self.conns.iter().filter(|(_, c)| matches!(c, Conn { c, .. } if c.stall_at().is_some_and(|t| t <= now))).map(|(id, _)| *id).collect();
        for id in stalled {
            self.remove(id);
            out.push(HubOutput::Close(id));
            out.push(HubOutput::Diagnostic(format!("connection {id}: closed, a request stalled")));
        }
    }

    /// When `tick` next has work.
    pub fn next_due(&self, now: u64) -> Option<u64> {
        let sweep = if self.sweep_more { Some(now) } else { self.store().next_due().ok().flatten() }.map(|t| t.max(self.sweep_hold));
        // bytes not yet reported taken: the driver reports at the next tick (shares count them)
        let unread = (self.hold > 0).then(|| now.saturating_add(osis_proto::session::PUSH_POLL_MS)).into_iter().chain(self.check_at).chain(self.first_due());
        let conns = self.conns.values().filter_map(|Conn { c, hello_by, .. }| [c.held().then(|| now.saturating_add(osis_proto::session::PUSH_POLL_MS)), *hello_by, c.stall_at()].into_iter().flatten().min());
        sweep.into_iter().chain(unread).chain(conns).min()
    }

    fn serve(&mut self, st: &mut HostStore, now: u64, id: ConnId, input: SessionInput, out: &mut Vec<HubOutput>) {
        let (share, slack) = (self.share(st), self.slack(st, id));
        let Some(Conn { c, remote, hello_by, buffered, hold, alone, need, queued, paused, started, .. }) = self.conns.get_mut(&id) else { return };
        c.set_room(share, slack);
        let outputs = c.handle(now, st, input);
        if c.version().is_some() {
            *hello_by = None;
        }
        // node sync learns the connection once its Hello binds it, before anything of it
        if !*started && let Some((dialer, listener, key)) = c.binding() {
            *started = true;
            out.push(HubOutput::Up(id, Up::Start(Binding { dialer, listener, key, remote: *remote })));
        }
        let now_buffered = c.buffered();
        self.buffered = self.buffered.saturating_sub(*buffered).saturating_add(now_buffered);
        *buffered = now_buffered;
        let was_active = *hold > 0 || need.is_some();
        let now_hold = c.holding();
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
        for o in outputs {
            match o {
                SessionOutput::Send(b) => out.push(HubOutput::Send(id, b)),
                SessionOutput::Close => {
                    self.remove(id);
                    out.push(HubOutput::Close(id));
                }
                SessionOutput::PeerError(e) => out.push(HubOutput::Diagnostic(format!("connection {id}: {e}"))),
                SessionOutput::StoreError(e) => out.push(HubOutput::Diagnostic(e.to_string())),
                // node sync's, judged there (proofs, records, the shared set, the stream, the port)
                SessionOutput::Peer(m) => out.push(HubOutput::Up(id, Up::Message(m))),
                SessionOutput::Request(m) => out.push(HubOutput::Up(id, Up::Request(m))),
                SessionOutput::Room { budget } => out.push(HubOutput::Up(id, Up::Room { budget })),
            }
        }
    }

}

//! `Hub`: the blind node's connections over one store, sans-I/O (spec/sync.md §5-§9). One
//! osis-proto `ServerConnection` per accepted connection, one `Replicator` per connection this
//! node dialed to a peer server; cross-connection notices (`Changed` to every connection and
//! replicator, `Relay` to every other connection), bounded sweeps, Hello deadlines, the
//! connection cap and timers. The async driver and the simulator only move bytes and call `tick`
//! when `next_due` says.

use crate::replicate::Replicator;
use crate::store::BackendStore;
use osis_base::LabelId;
use osis_crypto::CryptoRngCore;
use osis_proto::{ClientInput, ClientOutput, ServerConfig, ServerConnection, ServerInput, ServerOutput};
use osis_store::Backend;
use std::collections::BTreeMap;

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
}

enum Conn {
    /// `buffered`: partial frame bytes after the last input.
    Served { c: Box<ServerConnection>, peer: [u8; 32], hello_by: Option<u64>, buffered: usize },
    Peer { r: Box<Replicator>, timer: Option<u64> },
}

pub struct Hub<B: Backend> {
    store: BackendStore<B>,
    static_key: [u8; 32],
    rng: Box<dyn CryptoRngCore + Send>,
    conns: BTreeMap<ConnId, Conn>,
    /// Sweeps wait until then (after a failure).
    sweep_hold: u64,
    /// The last sweep ran out of budget.
    sweep_more: bool,
    /// Partial frame bytes over all served connections.
    buffered: usize,
}

impl<B: Backend> Hub<B> {
    /// `static_key`: this node's transport key (bound by open signatures).
    pub fn new(store: BackendStore<B>, static_key: [u8; 32], rng: Box<dyn CryptoRngCore + Send>) -> Hub<B> {
        Hub { store, static_key, rng, conns: BTreeMap::new(), sweep_hold: 0, sweep_more: false, buffered: 0 }
    }

    pub fn store(&self) -> &BackendStore<B> {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut BackendStore<B> {
        &mut self.store
    }

    pub fn static_key(&self) -> [u8; 32] {
        self.static_key
    }

    pub fn connections(&self) -> usize {
        self.conns.len()
    }

    fn challenge(&mut self) -> [u8; 32] {
        let mut c = [0u8; 32];
        self.rng.fill_bytes(&mut c);
        c
    }

    /// A client connected (`peer`: the key the transport authenticated): start its server engine
    /// (sends Hello), or close it beyond `max_connections`.
    pub fn accept(&mut self, now: u64, id: ConnId, peer: [u8; 32]) -> Vec<HubOutput> {
        let served = self.conns.values().filter(|c| matches!(c, Conn::Served { .. })).count();
        if served >= self.store.policy().max_connections {
            return vec![HubOutput::Close(id)];
        }
        let cfg = ServerConfig { static_key: self.static_key, challenge: self.challenge(), tie: id };
        let hello_by = Some(now.saturating_add(self.store.policy().hello_ms));
        self.conns.insert(id, Conn::Served { c: Box::new(ServerConnection::new(cfg)), peer, hello_by, buffered: 0 });
        self.batch(now, |h, out| h.serve(now, id, ServerInput::Start, out))
    }

    /// A connection this node dialed to peer server `peer_key` is up: replicate to it.
    pub fn peer_up(&mut self, now: u64, id: ConnId, peer_key: [u8; 32]) -> Vec<HubOutput> {
        let challenge = self.challenge();
        self.conns.insert(id, Conn::Peer { r: Box::new(Replicator::new(peer_key, challenge)), timer: None });
        self.batch(now, |h, out| h.replicate(now, id, Some(ClientInput::Start), out))
    }

    /// Runs `f` with the store's commits made durable once at its end (one fsync for a whole
    /// message of entries, spec/requirements.md: peer input never causes unbounded work), before
    /// any output leaves. If that fails, nothing the batch would send goes: the connections it
    /// would have written to are closed (their peers retry what went unanswered).
    fn batch(&mut self, now: u64, f: impl FnOnce(&mut Hub<B>, &mut Vec<HubOutput>)) -> Vec<HubOutput> {
        self.store.defer_durability();
        let mut out = Vec::new();
        f(self, &mut out);
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
                    self.remove(now, id, &mut out);
                    self.conns.remove(&id);
                    out.push(HubOutput::Close(id));
                }
            }
        }
        out
    }

    /// Bytes arrived on a connection.
    pub fn input(&mut self, now: u64, id: ConnId, bytes: Vec<u8>) -> Vec<HubOutput> {
        self.batch(now, |h, out| match h.conns.get(&id) {
            Some(Conn::Served { .. }) => {
                h.serve(now, id, ServerInput::Bytes(bytes), out);
                h.limit_buffered(now, out);
            }
            Some(Conn::Peer { .. }) => h.replicate(now, id, Some(ClientInput::Bytes(bytes)), out),
            None => {}
        })
    }

    /// The transport took bytes sent on these connections since the last report, with how many
    /// it took in all: progress for a replication session's stall timeout, room for a served
    /// connection's pushes (`ServerInput::Taken`). The driver reports it before `tick`, before
    /// a connection's input bytes, and at `PUSH_POLL_MS` while one holds pushes (`next_due`).
    pub fn sent(&mut self, now: u64, ids: &[(ConnId, u64)]) -> Vec<HubOutput> {
        self.batch(now, |h, out| {
            for (id, n) in ids {
                match h.conns.get(id) {
                    Some(Conn::Peer { .. }) => h.replicate(now, *id, Some(ClientInput::Sent), out),
                    Some(Conn::Served { .. }) => h.serve(now, *id, ServerInput::Taken(*n), out),
                    None => {}
                }
            }
        })
    }

    /// The connection is gone (either side closed it): the presence entries it uploaded go
    /// (spec/sync.md §5), pushed to the subscriptions as deletions.
    pub fn closed(&mut self, now: u64, id: ConnId) -> Vec<HubOutput> {
        self.batch(now, |h, out| h.remove(now, id, out))
    }

    /// Forgets a connection and its partial frame bytes; unties it from the presence entries it
    /// uploaded, removing those no other open connection's tie holds (spec/sync.md §5).
    fn remove(&mut self, now: u64, id: ConnId, out: &mut Vec<HubOutput>) {
        let Some(Conn::Served { c, buffered, .. }) = self.conns.remove(&id) else { return };
        self.buffered = self.buffered.saturating_sub(buffered);
        let mut grew = std::collections::BTreeSet::new();
        for (l, b) in c.presence() {
            match osis_proto::LabelStore::untie(&mut self.store, l, b, id) {
                Ok(true) => {
                    grew.insert(*l);
                }
                Ok(false) => {}
                Err(e) => out.push(HubOutput::Diagnostic(format!("presence of connection {id}: {e}"))),
            }
        }
        for l in grew {
            self.changed(now, l, out);
        }
    }

    /// Partial frame bytes held for all served connections.
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// Over `max_buffered_bytes` of partial frames: closes the connections holding the largest
    /// until under it (anyone who can connect could otherwise hold `MAX_MESSAGE` per connection).
    fn limit_buffered(&mut self, now: u64, out: &mut Vec<HubOutput>) {
        while self.buffered > self.store.policy().max_buffered_bytes {
            let Some(id) = self.conns.iter().filter_map(|(id, c)| if let Conn::Served { buffered, .. } = c { Some((*buffered, *id)) } else { None }).max().map(|(_, id)| id) else { break };
            self.remove(now, id, out);
            out.push(HubOutput::Close(id));
            out.push(HubOutput::Diagnostic(format!("connection {id}: closed, partial frames over the budget")));
        }
    }

    /// Runs what is due: a bounded sweep (expiry, timed deletes, tombstones, claim sets), Hello
    /// deadlines, replication work and timers.
    pub fn tick(&mut self, now: u64) -> Vec<HubOutput> {
        self.batch(now, |h, out| h.tick_in(now, out))
    }

    fn tick_in(&mut self, now: u64, out: &mut Vec<HubOutput>) {
        if now >= self.sweep_hold && (self.sweep_more || self.store.next_due().ok().flatten().is_some_and(|t| t <= now)) {
            match self.store.sweep(now, SWEEP_BUDGET) {
                Ok(s) => {
                    self.sweep_more = s.more;
                    for l in s.grew {
                        self.changed(now, l, out);
                    }
                }
                Err(e) => {
                    self.sweep_more = false;
                    self.sweep_hold = now.saturating_add(SWEEP_BACKOFF_MS);
                    out.push(HubOutput::Diagnostic(format!("sweep: {e}")));
                }
            }
        }
        let late: Vec<ConnId> = self.conns.iter().filter(|(_, c)| matches!(c, Conn::Served { hello_by: Some(t), .. } if *t <= now)).map(|(id, _)| *id).collect();
        for id in late {
            self.remove(now, id, out);
            out.push(HubOutput::Close(id));
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
        let conns = self.conns.values().filter_map(|c| match c {
            Conn::Served { c, .. } if c.held() => Some(now.saturating_add(osis_proto::server::PUSH_POLL_MS)),
            Conn::Served { hello_by, .. } => *hello_by,
            Conn::Peer { r, timer } => [*timer, r.next_due(now)].into_iter().flatten().min(),
        });
        sweep.into_iter().chain(conns).min()
    }

    fn serve(&mut self, now: u64, id: ConnId, input: ServerInput, out: &mut Vec<HubOutput>) {
        let Some(Conn::Served { c, peer, hello_by, buffered }) = self.conns.get_mut(&id) else { return };
        self.store.set_origin(Some(*peer));
        let outputs = c.handle(now, &mut self.store, input);
        self.store.set_origin(None);
        if c.version().is_some() {
            *hello_by = None;
        }
        let now_buffered = c.buffered();
        self.buffered = self.buffered.saturating_sub(*buffered).saturating_add(now_buffered);
        *buffered = now_buffered;
        for o in outputs {
            match o {
                ServerOutput::Send(b) => out.push(HubOutput::Send(id, b)),
                ServerOutput::Close => {
                    self.remove(now, id, out);
                    out.push(HubOutput::Close(id));
                }
                ServerOutput::Changed(l) => self.changed(now, l, out),
                ServerOutput::Relay(r) => {
                    let others: Vec<ConnId> = self.conns.iter().filter(|(k, c)| **k != id && matches!(c, Conn::Served { .. })).map(|(k, _)| *k).collect();
                    for j in others {
                        self.serve(now, j, ServerInput::Relay(r.clone()), out);
                    }
                }
                ServerOutput::PeerError(e) => out.push(HubOutput::Diagnostic(format!("connection {id}: {e}"))),
                ServerOutput::StoreError(e) => out.push(HubOutput::Diagnostic(e.to_string())),
            }
        }
    }

    /// A label's log grew: push to subscriptions, queue replication.
    fn changed(&mut self, now: u64, label: LabelId, out: &mut Vec<HubOutput>) {
        let ids: Vec<ConnId> = self.conns.keys().copied().collect();
        for j in ids {
            match self.conns.get_mut(&j) {
                Some(Conn::Served { .. }) => self.serve(now, j, ServerInput::Changed(label), out),
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

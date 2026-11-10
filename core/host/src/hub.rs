//! `Hub`: the host's connections over one store, sans-I/O (spec/sync.md §5-§9). One
//! osis-proto `ServingSession` per accepted connection, one `Replicator` per connection this
//! node dialed to a peer host; cross-connection notices (`Changed` to every connection and
//! replicator, `Relay` to every other connection), bounded sweeps, Hello deadlines, the
//! connection cap and timers. The async driver and the simulator only move bytes and call `tick`
//! when `next_due` says.

use crate::replicate::Replicator;
use crate::store::HostStore;
use osis_base::LabelId;
use osis_crypto::CryptoRngCore;
use osis_proto::{ClientInput, ClientOutput, ServingConfig, ServingSession, ServingInput, ServingOutput};
use osis_transport::Source;
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
    /// `buffered`: partial frame bytes after the last input; `source`: where it comes from
    /// (slots are shared by it).
    Served { c: Box<ServingSession>, peer: [u8; 32], hello_by: Option<u64>, buffered: usize, source: Option<Source> },
    Peer { r: Box<Replicator>, timer: Option<u64> },
}

pub struct Hub {
    store: HostStore,
    static_key: [u8; 32],
    rng: Box<dyn CryptoRngCore + Send>,
    conns: BTreeMap<ConnId, Conn>,
    /// Sweeps wait until then (after a failure).
    sweep_hold: u64,
    /// The last sweep ran out of budget.
    sweep_more: bool,
    /// Partial frame bytes over all served connections.
    buffered: usize,
    /// Relay-only entries handed to connections so far (`relays_delivered`).
    relays_delivered: u64,
}

impl Hub {
    /// `static_key`: this node's transport key (bound by open signatures).
    pub fn new(store: HostStore, static_key: [u8; 32], rng: Box<dyn CryptoRngCore + Send>) -> Hub {
        Hub { store, static_key, rng, conns: BTreeMap::new(), sweep_hold: 0, sweep_more: false, buffered: 0, relays_delivered: 0 }
    }

    pub fn store(&self) -> &HostStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut HostStore {
        &mut self.store
    }

    pub fn static_key(&self) -> [u8; 32] {
        self.static_key
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

    /// A client connected (`peer`: the key the transport authenticated), from no known source.
    pub fn accept(&mut self, now: u64, id: ConnId, peer: [u8; 32]) -> Vec<HubOutput> {
        self.accept_from(now, id, peer, None)
    }

    /// A client connected from `source` (`osis_transport::Source`; none: unknown, all such
    /// connections one source): start its host engine (sends Hello). At `max_connections`
    /// the slots are shared by source (`osis_transport::evict_for`): the newest connection of
    /// the source holding the most is closed for it, or it is closed if that source holds fewer
    /// than two more than its own.
    pub fn accept_from(&mut self, now: u64, id: ConnId, peer: [u8; 32], source: Option<Source>) -> Vec<HubOutput> {
        let mut out = Vec::new();
        let mut held = BTreeMap::new();
        for c in self.conns.values() {
            if let Conn::Served { source, .. } = c {
                *held.entry(*source).or_insert(0usize) += 1;
            }
        }
        if held.values().sum::<usize>() >= self.store.policy().max_connections {
            let victim = osis_transport::evict_for(&held, &source).and_then(|v| self.conns.iter().rev().find(|(_, c)| matches!(c, Conn::Served { source, .. } if *source == v)).map(|(k, _)| *k));
            let Some(v) = victim else { return vec![HubOutput::Close(id)] };
            self.remove(v);
            out.push(HubOutput::Close(v));
            out.push(HubOutput::Diagnostic(format!("connection {v}: closed for a connection from a source holding fewer slots")));
        }
        let cfg = ServingConfig { static_key: self.static_key, challenge: self.challenge() };
        let hello_by = Some(now.saturating_add(self.store.policy().hello_ms));
        self.conns.insert(id, Conn::Served { c: Box::new(ServingSession::new(cfg)), peer, hello_by, buffered: 0, source });
        out.extend(self.batch(|h, out| h.serve(now, id, ServingInput::Start, out)));
        out
    }

    /// A connection this node dialed to peer host `peer_key` is up: replicate to it.
    pub fn peer_up(&mut self, now: u64, id: ConnId, peer_key: [u8; 32]) -> Vec<HubOutput> {
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
                    self.conns.remove(&id);
                    out.push(HubOutput::Close(id));
                }
            }
        }
        out
    }

    /// Bytes arrived on a connection.
    pub fn input(&mut self, now: u64, id: ConnId, bytes: Vec<u8>) -> Vec<HubOutput> {
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
        self.batch(|h, out| {
            for (id, n) in ids {
                match h.conns.get(id) {
                    Some(Conn::Peer { .. }) => h.replicate(now, *id, Some(ClientInput::Taken(*n)), out),
                    Some(Conn::Served { .. }) => h.serve(now, *id, ServingInput::Taken(*n), out),
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

    /// Forgets a connection and its partial frame bytes.
    fn remove(&mut self, id: ConnId) {
        let Some(Conn::Served { buffered, .. }) = self.conns.remove(&id) else { return };
        self.buffered = self.buffered.saturating_sub(buffered);
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
    /// deadlines, replication work and timers.
    pub fn tick(&mut self, now: u64) -> Vec<HubOutput> {
        self.batch(|h, out| h.tick_in(now, out))
    }

    fn tick_in(&mut self, now: u64, out: &mut Vec<HubOutput>) {
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
            Conn::Served { c, .. } if c.held() => Some(now.saturating_add(osis_proto::serving::PUSH_POLL_MS)),
            Conn::Served { hello_by, .. } => *hello_by,
            Conn::Peer { r, timer } => [*timer, r.next_due(now)].into_iter().flatten().min(),
        });
        sweep.into_iter().chain(conns).min()
    }

    fn serve(&mut self, now: u64, id: ConnId, input: ServingInput, out: &mut Vec<HubOutput>) {
        let Some(Conn::Served { c, peer, hello_by, buffered, .. }) = self.conns.get_mut(&id) else { return };
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
                // serving no identity, a host proves nothing and keeps no record (spec/wire.md
                // §11.2); proving no actor, it has no shared set: a request of the shared set or
                // the stream is answered 14 (spec/sync.md §10); Stranded and Suspect are node to
                // node only, 11 (spec/wire.md §11.2)
                ServingOutput::Peer(m) if m.is_request() => {
                    use osis_proto::{Code, Message as M};
                    let reply = match *m {
                        M::Prove { id, .. } => M::Proved { id, proofs: Vec::new() },
                        M::Resume { id, .. } => M::Error { id, code: Code::REFUSED },
                        M::Stranded { id, .. } | M::Suspect { id, .. } => M::Error { id, code: Code::UNSUPPORTED },
                        m => M::Error { id: m.id(), code: Code::NOT_ADMITTED },
                    };
                    self.serve(now, id, ServingInput::Peer(Box::new(reply)), out);
                }
                // a host serves no client port (its sessions answer those kinds Error 11)
                ServingOutput::Request(_) | ServingOutput::Room { .. } | ServingOutput::Peer(_) => {}
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

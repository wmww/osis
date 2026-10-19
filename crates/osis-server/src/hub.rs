//! `Hub`: the blind node's connections over one store, sans-I/O (spec/sync.md §5-§9). One
//! osis-proto `ServerConnection` per accepted connection, one `Replicator` per connection this
//! node dialed to a peer server; cross-connection notices (`Changed` to every connection and
//! replicator, `Signal` to every other connection), sweeps and timers. The async driver
//! (`driver`) and the simulator only move bytes and call `tick`.

use crate::replicate::Replicator;
use crate::store::BackendStore;
use osis_core::LabelId;
use osis_crypto::CryptoRngCore;
use osis_proto::{ClientInput, ClientOutput, ServerConfig, ServerConnection, ServerInput, ServerOutput};
use osis_store::Backend;
use std::collections::BTreeMap;

/// A connection's handle, chosen by the driver.
pub type ConnId = u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HubOutput {
    /// Bytes to write on the connection.
    Send(ConnId, Vec<u8>),
    /// Close the connection.
    Close(ConnId),
    /// Something worth logging (a peer's protocol error, a storage failure, a refused replication).
    Diagnostic(String),
}

enum Conn {
    Served(Box<ServerConnection>),
    Peer { r: Box<Replicator>, timer: Option<u64> },
}

pub struct Hub<B: Backend> {
    store: BackendStore<B>,
    static_key: [u8; 32],
    rng: Box<dyn CryptoRngCore + Send>,
    conns: BTreeMap<ConnId, Conn>,
}

impl<B: Backend> Hub<B> {
    /// `static_key`: this node's transport key (bound by open signatures).
    pub fn new(store: BackendStore<B>, static_key: [u8; 32], rng: Box<dyn CryptoRngCore + Send>) -> Hub<B> {
        Hub { store, static_key, rng, conns: BTreeMap::new() }
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

    /// A client connected: start its server engine (sends Hello).
    pub fn accept(&mut self, now: u64, id: ConnId) -> Vec<HubOutput> {
        let cfg = ServerConfig { static_key: self.static_key, challenge: self.challenge() };
        self.conns.insert(id, Conn::Served(Box::new(ServerConnection::new(cfg))));
        let mut out = Vec::new();
        self.serve(now, id, ServerInput::Start, &mut out);
        out
    }

    /// A connection this node dialed to peer server `peer_key` is up: replicate to it.
    pub fn peer_up(&mut self, now: u64, id: ConnId, peer_key: [u8; 32]) -> Vec<HubOutput> {
        let challenge = self.challenge();
        let mut r = Replicator::new(peer_key, challenge);
        let mut out = Vec::new();
        match self.store.labels() {
            Ok(labels) => r.mark(labels),
            Err(e) => out.push(HubOutput::Diagnostic(e.to_string())),
        }
        self.conns.insert(id, Conn::Peer { r: Box::new(r), timer: None });
        self.replicate(now, id, Some(ClientInput::Start), &mut out);
        out
    }

    /// Bytes arrived on a connection.
    pub fn input(&mut self, now: u64, id: ConnId, bytes: Vec<u8>) -> Vec<HubOutput> {
        let mut out = Vec::new();
        match self.conns.get(&id) {
            Some(Conn::Served(_)) => self.serve(now, id, ServerInput::Bytes(bytes), &mut out),
            Some(Conn::Peer { .. }) => self.replicate(now, id, Some(ClientInput::Bytes(bytes)), &mut out),
            None => {}
        }
        out
    }

    /// The connection is gone (either side closed it).
    pub fn closed(&mut self, id: ConnId) {
        self.conns.remove(&id);
    }

    /// Runs due sweeps (expiry, timed deletes, tombstones, claim sets) and replication timers.
    pub fn tick(&mut self, now: u64) -> Vec<HubOutput> {
        let mut out = Vec::new();
        match self.store.sweep(now) {
            Ok(grew) => {
                for l in grew {
                    self.changed(now, l, &mut out);
                }
            }
            Err(e) => out.push(HubOutput::Diagnostic(e.to_string())),
        }
        let due: Vec<ConnId> = self.conns.iter().filter(|(_, c)| matches!(c, Conn::Peer { timer: Some(t), .. } if *t <= now)).map(|(id, _)| *id).collect();
        for id in due {
            if let Some(Conn::Peer { timer, .. }) = self.conns.get_mut(&id) {
                *timer = None;
            }
            self.replicate(now, id, Some(ClientInput::Timer), &mut out);
        }
        out
    }

    /// When `tick` next has work: the earliest sweep or replication timer.
    pub fn next_due(&self) -> Option<u64> {
        let sweep = self.store.next_due().ok().flatten();
        let timers = self.conns.values().filter_map(|c| if let Conn::Peer { timer, .. } = c { *timer } else { None });
        sweep.into_iter().chain(timers).min()
    }

    fn serve(&mut self, now: u64, id: ConnId, input: ServerInput, out: &mut Vec<HubOutput>) {
        let Some(Conn::Served(c)) = self.conns.get_mut(&id) else { return };
        let outputs = c.handle(now, &mut self.store, input);
        for o in outputs {
            match o {
                ServerOutput::Send(b) => out.push(HubOutput::Send(id, b)),
                ServerOutput::Close => out.push(HubOutput::Close(id)),
                ServerOutput::Changed(l) => self.changed(now, l, out),
                ServerOutput::Signal { label, blob, wrap, auth } => {
                    let others: Vec<ConnId> = self.conns.iter().filter(|(k, c)| **k != id && matches!(c, Conn::Served(_))).map(|(k, _)| *k).collect();
                    for j in others {
                        self.serve(now, j, ServerInput::Signal { label, blob: blob.clone(), wrap, auth: auth.clone() }, out);
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
                Some(Conn::Served(_)) => self.serve(now, j, ServerInput::Changed(label), out),
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
        for o in outputs {
            match o {
                ClientOutput::Send(b) => out.push(HubOutput::Send(id, b)),
                ClientOutput::Close => out.push(HubOutput::Close(id)),
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
    }
}

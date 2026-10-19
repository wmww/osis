//! The sans-I/O sync engine (plans/node-sync.md; notes/architecture.md §2): one synchronous
//! state machine per node, `SyncEngine::handle(Event) -> Vec<Action>`, holding the engine, one
//! osis-proto `ClientSession` per server connection, the labeling decisions and the convergence
//! loop (spec/sync.md §5-§9). Two drivers move its bytes and timers: the tokio driver
//! (`driver`, feature `driver`) and the simulator's step driver. No sync logic lives in a driver.
//!
//! Per server and label: open (sync key of the head, else walk by stale key or claim key),
//! verify the head, download (cursor sync, reconciliation fallback), apply membership commits
//! first, then the pass: re-registration when an admin holds newer epochs (the actor's
//! membership commits the server lacks first, then the step, then the rest), uploads of
//! must-hold bodies, relays, certificates and heartbeats, deletions of must-not-hold bodies.

mod bundle;
mod inbound;
mod local;
mod open;
mod pass;
pub(crate) mod state;

use crate::engine::Engine;
use crate::error::Result;
use crate::events::{Diagnostic, DiagnosticKind, Origin};
use crate::labeling::{GroupLabel, HeadKeys};
use osis_core::{Clock, LabelId, Tid};
use osis_crypto::CryptoRngCore;
use osis_label::{Address, Step};
use osis_proto::{ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Command};
use state::{ServerKey, State};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::mpsc::Receiver;

pub use state::Kind as EntryKind;

/// A connection's handle, chosen by the sync engine.
pub type ConnId = u64;

#[derive(Clone, Debug)]
pub struct SyncConfig {
    /// Servers to keep a connection to besides those the labels name.
    pub servers: Vec<Address>,
    /// Subscribe to every opened label (pushes, spec/sync.md §8).
    pub subscribe: bool,
    /// Blobs above this many bytes are announced without their bytes and fetched when needed
    /// (lazy chunks, spec/sync.md §6).
    pub inline_limit: u64,
    /// Place heartbeats (spec/permissions.md §4; policy, notes/sync.md).
    pub heartbeats: bool,
    /// Heartbeat lifetime (`expires` after the commit's `ts`).
    pub heartbeat_lifetime_ms: u64,
    /// Re-sync interval of opened labels without a subscription.
    pub resync_ms: u64,
    /// Pause before re-dialing a server.
    pub retry_ms: u64,
    /// Deposits skip heartbeats when fewer entries are left in the budget.
    pub tight_budget: u64,
}

impl Default for SyncConfig {
    fn default() -> SyncConfig {
        SyncConfig {
            servers: Vec::new(),
            subscribe: true,
            inline_limit: osis_core::format::MAX_BLOB as u64,
            heartbeats: true,
            heartbeat_lifetime_ms: 2 * osis_core::format::HEARTBEAT_MIN_LIFETIME_MS,
            resync_ms: 60_000,
            retry_ms: 5_000,
            tight_budget: 16,
        }
    }
}

/// Inputs of the sync engine.
#[derive(Clone, Debug)]
pub enum Event {
    /// Time passed (a `Wake` came due, or any time).
    Tick,
    /// The engine changed through local calls (commits): look at its events.
    Local,
    /// A connection asked for by `Dial` is up.
    Up { conn: ConnId },
    /// Bytes arrived on a connection.
    Bytes { conn: ConnId, bytes: Vec<u8> },
    /// A connection is gone, or its dial failed.
    Down { conn: ConnId },
}

/// Outputs for the driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Open a connection to `address` (checking the server's key against it, spec/sync.md §10)
    /// and report `Up` or `Down`.
    Dial { conn: ConnId, address: Address },
    Send { conn: ConnId, bytes: Vec<u8> },
    Close { conn: ConnId },
    /// Deliver `Event::Tick` at this wall ms (the driver's clock; replaces earlier ones).
    Wake { at: u64 },
}

/// Open state of a label on a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Trying open keys in order.
    Opening,
    /// Registering the recorded path at a server that lacks the label.
    Registering,
    /// Waiting for the server's path to verify its head.
    Verifying,
    Open,
    /// No key opens it here.
    Failed,
}

/// One label on one connection.
pub(crate) struct LConn {
    pub group: Tid,
    pub index: Option<u64>,
    pub phase: Phase,
    pub tries: Vec<open::Try>,
    pub tried_claim: bool,
    pub head: Option<Step>,
    pub keys: HeadKeys,
    /// A Sync exchange is running.
    pub syncing: bool,
    /// The log was read to its end at least once on this connection.
    pub synced: bool,
    /// A pass is wanted once the running exchange ends.
    pub dirty: bool,
    /// A child step sent for registration.
    pub registering: Option<(Step, osis_label::ClaimSet)>,
    pub budget: Option<u64>,
    pub last_sync: u64,
    pub path: Vec<Step>,
}

pub(crate) struct Conn {
    pub server: ServerKey,
    pub address: Address,
    pub session: ClientSession,
    pub up: bool,
    pub labels: BTreeMap<LabelId, LConn>,
    pub timer: Option<u64>,
    pub offset: Option<i64>,
}

/// The sync engine of one node.
pub struct SyncEngine {
    pub(crate) engine: Engine,
    events: Receiver<crate::Event>,
    clock: Arc<dyn Clock>,
    pub(crate) rng: Box<dyn CryptoRngCore + Send>,
    pub(crate) cfg: SyncConfig,
    pub(crate) conns: BTreeMap<ConnId, Conn>,
    next_conn: ConnId,
    /// Servers not connected: when to dial again.
    retry: BTreeMap<ServerKey, (Address, u64)>,
    pub(crate) state: State,
    /// Event counter: pass completions and remote membership commits are ordered by it.
    pub(crate) seq: u64,
    pub(crate) passes: BTreeMap<(ServerKey, LabelId), u64>,
    membership_seen: BTreeMap<Tid, u64>,
    wake: Option<u64>,
    /// Signals received (also sent as engine events).
    pub(crate) signals: Vec<osis_label::SignalBody>,
    /// Recent diagnostics (also sent as engine events).
    diagnostics: Vec<String>,
    /// Inbox blobs waiting for a connection to their server.
    pub(crate) outbox: Vec<local::Outgoing>,
}

impl SyncEngine {
    /// Wraps an engine. `clock` is the uncorrected wall clock the engine was built on (Hellos
    /// carry it; the correction goes to the engine).
    pub fn new(mut engine: Engine, clock: Arc<dyn Clock>, rng: Box<dyn CryptoRngCore + Send>, cfg: SyncConfig) -> Result<SyncEngine> {
        let events = engine.subscribe();
        let state = State::load(&mut engine)?;
        Ok(SyncEngine {
            engine,
            events,
            clock,
            rng,
            cfg,
            conns: BTreeMap::new(),
            next_conn: 1,
            retry: BTreeMap::new(),
            state,
            seq: 0,
            passes: BTreeMap::new(),
            membership_seen: BTreeMap::new(),
            wake: None,
            signals: Vec::new(),
            diagnostics: Vec::new(),
            outbox: Vec::new(),
        })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// The engine, for local writes; follow with `handle(Event::Local)`.
    pub fn engine_mut(&mut self) -> &mut Engine {
        &mut self.engine
    }

    pub fn into_engine(self) -> Engine {
        self.engine
    }

    pub fn config(&self) -> &SyncConfig {
        &self.cfg
    }

    /// Raw wall ms (sessions and timers).
    pub(crate) fn raw_now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    /// Corrected wall ms (expiry and bounds).
    pub(crate) fn now(&self) -> u64 {
        self.engine.now().0
    }

    pub(crate) fn diag(&mut self, detail: String) {
        if self.diagnostics.len() < 256 {
            self.diagnostics.push(detail.clone());
        }
        let now = self.engine.now();
        self.engine.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::BadInput, tids: Vec::new(), commit: None, peer: None, detail }, now);
        self.engine.core.events.flush();
    }

    /// Feeds one input; returns what the driver must do.
    pub fn handle(&mut self, ev: Event) -> Vec<Action> {
        let mut out = Vec::new();
        if let Err(e) = self.step(ev, &mut out) {
            self.diag(format!("sync: {e}"));
        }
        if let Err(e) = self.state.flush(&mut self.engine) {
            self.diag(format!("sync state: {e}"));
        }
        if let Some(at) = self.next_wake()
            && self.wake != Some(at)
        {
            self.wake = Some(at);
            out.push(Action::Wake { at });
        }
        out
    }

    fn step(&mut self, ev: Event, out: &mut Vec<Action>) -> Result<()> {
        match ev {
            Event::Tick => {
                self.engine.tick()?;
                self.timers(out)?;
            }
            Event::Local => {}
            Event::Up { conn } => {
                let now = self.raw_now();
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.up = true;
                    let o = c.session.handle(now, ClientInput::Start);
                    self.outputs(conn, o, out)?;
                }
            }
            Event::Bytes { conn, bytes } => {
                let now = self.raw_now();
                if let Some(c) = self.conns.get_mut(&conn) {
                    let o = c.session.handle(now, ClientInput::Bytes(bytes));
                    self.outputs(conn, o, out)?;
                }
            }
            Event::Down { conn } => {
                if let Some(c) = self.conns.remove(&conn) {
                    let at = self.raw_now().saturating_add(self.cfg.retry_ms);
                    self.retry.insert(c.server, (c.address, at));
                }
            }
        }
        self.engine_events()?;
        self.connect(out);
        self.send_outbox(out)?;
        self.run_dirty(out)?;
        Ok(())
    }

    /// Drains engine events: changes mark every open label for a pass; remote membership
    /// commits restart `complete_pass` for the actors they touch.
    fn engine_events(&mut self) -> Result<()> {
        let mut changed = false;
        while let Ok(e) = self.events.try_recv() {
            match e {
                crate::Event::Applied { id, origin, .. } => {
                    changed = true;
                    if origin == Origin::Remote
                        && let Some(h) = self.engine.header(&id)
                        && h.kind.is_membership()
                    {
                        self.seq += 1;
                        for a in &h.aspects {
                            let actor = self.engine.core.secret_actor(&a.tid).unwrap_or(a.tid);
                            self.membership_seen.insert(actor, self.seq);
                        }
                    }
                }
                crate::Event::Changed { .. } | crate::Event::Roster { .. } => changed = true,
                _ => {}
            }
        }
        if changed {
            for c in self.conns.values_mut() {
                for l in c.labels.values_mut() {
                    l.dirty = true;
                }
            }
        }
        Ok(())
    }

    /// Whether every server this node syncs `actor`'s labels with has had a complete pass since
    /// the last membership commit of the actor applied from elsewhere
    /// (issues/keys-established-epochs.md; spec/permissions.md §3 re-seal timing).
    pub fn complete_pass(&mut self, actor: &Tid) -> bool {
        let since = self.membership_seen.get(actor).copied().unwrap_or(0);
        let mut any = false;
        for (g, l) in self.labels() {
            if self.engine.core.secret_actor(&g) != Some(*actor) {
                continue;
            }
            for a in &l.servers {
                any = true;
                if self.passes.get(&(a.key, l.id)).is_none_or(|p| *p <= since) {
                    return false;
                }
            }
        }
        any
    }

    /// Labels this node syncs: every non-replaced label of a labeled group it holds read
    /// secrets of.
    pub fn labels(&mut self) -> Vec<(Tid, GroupLabel)> {
        let mut out = Vec::new();
        for g in self.engine.labeled_groups() {
            if self.engine.epochs(&g).is_none_or(|e| e.read.held().next().is_none()) {
                continue;
            }
            for l in self.engine.group_labels(&g).unwrap_or_default() {
                if !l.replaced {
                    out.push((g, l));
                }
            }
        }
        out
    }

    /// The servers to keep connections to.
    fn wanted_servers(&mut self) -> BTreeMap<ServerKey, Address> {
        let mut m: BTreeMap<ServerKey, Address> = self.cfg.servers.iter().map(|a| (a.key, a.clone())).collect();
        for (_, l) in self.labels() {
            for a in l.servers {
                m.entry(a.key).or_insert(a);
            }
        }
        for h in self.state.hints.values() {
            for a in &h.servers {
                m.entry(a.key).or_insert_with(|| a.clone());
            }
        }
        m
    }

    /// Dials wanted servers without a connection (after their retry time); adds labels to
    /// open connections.
    fn connect(&mut self, out: &mut Vec<Action>) {
        let now = self.raw_now();
        let wanted = self.wanted_servers();
        for (key, addr) in wanted {
            if self.conns.values().any(|c| c.server == key) {
                continue;
            }
            if self.retry.get(&key).is_some_and(|(_, t)| *t > now) {
                continue;
            }
            self.retry.remove(&key);
            let conn = self.next_conn;
            self.next_conn += 1;
            let mut challenge = [0u8; 32];
            self.rng.fill_bytes(&mut challenge);
            let session = ClientSession::new(ClientConfig { peer_static_key: key, challenge });
            self.conns.insert(conn, Conn { server: key, address: addr.clone(), session, up: false, labels: BTreeMap::new(), timer: None, offset: None });
            out.push(Action::Dial { conn, address: addr });
        }
    }

    /// Runs the session's outputs: frames out, timers, events in.
    pub(crate) fn outputs(&mut self, conn: ConnId, outputs: Vec<ClientOutput>, out: &mut Vec<Action>) -> Result<()> {
        for o in outputs {
            match o {
                ClientOutput::Send(bytes) => out.push(Action::Send { conn, bytes }),
                ClientOutput::Close => {
                    out.push(Action::Close { conn });
                    if let Some(c) = self.conns.remove(&conn) {
                        let at = self.raw_now().saturating_add(self.cfg.retry_ms);
                        self.retry.insert(c.server, (c.address, at));
                    }
                }
                ClientOutput::SetTimer(t) => {
                    if let Some(c) = self.conns.get_mut(&conn) {
                        c.timer = Some(t);
                    }
                }
                ClientOutput::Event(e) => self.session_event(conn, e, out)?,
            }
        }
        Ok(())
    }

    /// Sends a command on a connection.
    pub(crate) fn command(&mut self, conn: ConnId, cmd: Command, out: &mut Vec<Action>) -> Result<()> {
        let now = self.raw_now();
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        let o = c.session.handle(now, ClientInput::Command(cmd));
        self.outputs(conn, o, out)
    }

    fn session_event(&mut self, conn: ConnId, e: ClientEvent, out: &mut Vec<Action>) -> Result<()> {
        use ClientEvent as E;
        if std::env::var_os("OSIS_SYNC_TRACE").is_some() {
            eprintln!("[{}] conn {conn}: {}", self.engine.tid(), format!("{e:?}").chars().take(300).collect::<String>());
        }
        match e {
            E::Ready { .. } => self.ready(conn, out)?,
            E::ClockOffset { offset_ms, .. } => {
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.offset = Some(offset_ms);
                }
                let mut v: Vec<i64> = self.conns.values().filter_map(|c| c.offset).collect();
                v.sort_unstable();
                if let Some(m) = v.get(v.len() / 2) {
                    self.engine.set_clock_offset(*m);
                }
            }
            E::Opened { label, head, entry_box } => self.opened(conn, label, head, entry_box, out)?,
            E::Step { label, step } => self.stale_step(conn, label, step, out)?,
            E::Registered { label } => self.registered(conn, label, out)?,
            E::Head { label, head } => self.head_reply(conn, label, head, out)?,
            E::PathSteps { label, steps, more } => self.path_steps(conn, label, steps, more, out)?,
            E::EntryStatus { label, blob_ids, codes, head } => self.entry_status(conn, label, blob_ids, codes, head, out)?,
            E::DeleteStatus { label, blob_ids, codes, head } => self.delete_status(conn, label, blob_ids, codes, head, out)?,
            E::Budget { label, blob_id, code, entries_left, head, .. } => self.budget(conn, label, blob_id, code, entries_left, head, out)?,
            E::Events { label, events, cursor } => self.log_events(Some(conn), label, events, cursor, out)?,
            E::Want { label, ids } => self.want(conn, label, ids, out)?,
            E::Synced { label } => self.synced(conn, label, out)?,
            E::NeedReconcile { label } => {
                let s = self.conns.get(&conn).map(|c| c.server);
                if let Some(s) = s {
                    self.state.set_cursor(s, label, None);
                    let ids = self.state.present_at(&s, &label);
                    self.command(conn, Command::Reconcile { label, ids }, out)?;
                }
            }
            E::Reconciled { label, need, have } => self.reconciled(conn, label, need, have, out)?,
            E::Fetched { label, items } => {
                let evs = items.into_iter().filter_map(|f| f.entry.map(|(blob, wrap, stamp)| osis_proto::Event::Added { blob_id: f.blob_id, blob: Some(blob), wrap, stamp })).collect();
                self.log_events(Some(conn), label, evs, None, out)?;
            }
            E::Subscribed { .. } => {}
            E::Signal { label, blob, wrap, auth } => self.signal_in(label, &blob, &wrap, &auth)?,
            E::Refused { label, kind, code } => self.refused(conn, label, kind, code, out)?,
            E::PeerError(e) => self.diag(format!("server: {e}")),
        }
        Ok(())
    }

    /// Hellos done: every label this server holds (by the labels' server lists, or a hint)
    /// starts opening.
    fn ready(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        let mut want: Vec<(Tid, LabelId)> = Vec::new();
        for (g, l) in self.labels() {
            if l.servers.iter().any(|a| a.key == server) {
                want.push((g, l.id));
            }
        }
        let hints: Vec<(Tid, LabelId)> = self.state.hints.iter().filter(|(_, h)| h.servers.iter().any(|a| a.key == server)).map(|(l, h)| (h.thing, *l)).collect();
        for (g, l) in hints {
            if !want.iter().any(|(_, x)| *x == l) {
                want.push((g, l));
            }
        }
        for (g, l) in want {
            self.start_label(conn, g, l, out)?;
        }
        Ok(())
    }

    /// Adds labels new since the connection came up (a `/label` arrived, a label was created).
    fn add_new_labels(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let conns: Vec<(ConnId, ServerKey)> = self.conns.iter().filter(|(_, c)| c.session.is_ready()).map(|(id, c)| (*id, c.server)).collect();
        if conns.is_empty() {
            return Ok(());
        }
        let labels = self.labels();
        for (conn, server) in conns {
            for (g, l) in &labels {
                let known = self.conns.get(&conn).is_some_and(|c| c.labels.contains_key(&l.id));
                if !known && l.servers.iter().any(|a| a.key == server) {
                    self.start_label(conn, *g, l.id, out)?;
                }
            }
        }
        Ok(())
    }

    /// Runs passes for open, synced labels marked dirty.
    fn run_dirty(&mut self, out: &mut Vec<Action>) -> Result<()> {
        self.add_new_labels(out)?;
        // a hint is done once the thing's `/label` names the label
        let hints: Vec<(LabelId, Tid)> = self.state.hints.iter().map(|(l, h)| (*l, h.thing)).collect();
        for (l, t) in hints {
            if self.engine.group_labels(&t)?.iter().any(|x| x.id == l) {
                self.state.remove_hint(&l);
            }
        }
        let todo: Vec<(ConnId, LabelId)> = self
            .conns
            .iter()
            .flat_map(|(id, c)| c.labels.iter().filter(|(_, l)| l.dirty && l.synced && !l.syncing && l.phase == Phase::Open && l.registering.is_none()).map(move |(lid, _)| (*id, *lid)))
            .collect();
        for (conn, label) in todo {
            if let Some(l) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&label)) {
                l.dirty = false;
            }
            self.pass(conn, label, out)?;
        }
        Ok(())
    }

    /// Session pings, periodic re-syncs, heartbeats and retries.
    fn timers(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let now = self.raw_now();
        let due: Vec<ConnId> = self.conns.iter().filter(|(_, c)| c.timer.is_some_and(|t| t <= now)).map(|(id, _)| *id).collect();
        for conn in due {
            if let Some(c) = self.conns.get_mut(&conn) {
                c.timer = None;
                let o = c.session.handle(now, ClientInput::Timer);
                self.outputs(conn, o, out)?;
            }
        }
        let resync: Vec<(ConnId, LabelId)> = self
            .conns
            .iter()
            .flat_map(|(id, c)| {
                c.labels.iter().filter(|(_, l)| l.phase == Phase::Open && !l.syncing && l.last_sync.saturating_add(self.cfg.resync_ms) <= now).map(move |(lid, _)| (*id, *lid))
            })
            .collect();
        for (conn, label) in resync {
            if !self.cfg.subscribe || self.conns.get(&conn).and_then(|c| c.labels.get(&label)).is_some_and(|l| !l.synced) {
                self.sync_label(conn, label, out)?;
            } else if let Some(l) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&label)) {
                // subscribed: a pass now and then (heartbeats, timed bounds)
                l.last_sync = now;
                l.dirty = true;
            }
        }
        Ok(())
    }

    fn next_wake(&self) -> Option<u64> {
        let mut t: Option<u64> = None;
        let mut at = |x: u64| t = Some(t.map_or(x, |y: u64| y.min(x)));
        for c in self.conns.values() {
            if let Some(x) = c.timer {
                at(x);
            }
            for l in c.labels.values() {
                if l.phase == Phase::Open {
                    at(l.last_sync.saturating_add(self.cfg.resync_ms));
                }
            }
        }
        for (_, x) in self.retry.values() {
            at(*x);
        }
        t
    }

    /// Asks every connection to sync every open label now.
    pub fn sync_now(&mut self) -> Vec<Action> {
        let mut out = Vec::new();
        let todo: Vec<(ConnId, LabelId)> = self.conns.iter().flat_map(|(id, c)| c.labels.iter().filter(|(_, l)| l.phase == Phase::Open && !l.syncing).map(move |(lid, _)| (*id, *lid))).collect();
        for (conn, label) in todo {
            if let Err(e) = self.sync_label(conn, label, &mut out) {
                self.diag(format!("sync: {e}"));
            }
        }
        let _ = self.state.flush(&mut self.engine);
        out
    }

    /// Starts a cursor sync of an open label.
    pub(crate) fn sync_label(&mut self, conn: ConnId, label: LabelId, out: &mut Vec<Action>) -> Result<()> {
        let now = self.raw_now();
        let inline_limit = self.cfg.inline_limit;
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        let server = c.server;
        let Some(l) = c.labels.get_mut(&label) else { return Ok(()) };
        l.syncing = true;
        l.last_sync = now;
        let cursor = self.state.cursors.get(&(server, label)).copied();
        self.command(conn, Command::Sync { label, cursor, inline_limit, entries: Vec::new(), gained: Vec::new() }, out)
    }

    /// Label IDs open on a connection to `server` (tests, diagnostics).
    pub fn open_labels(&self, server: &ServerKey) -> BTreeSet<LabelId> {
        self.conns.values().filter(|c| c.server == *server).flat_map(|c| c.labels.iter().filter(|(_, l)| l.phase == Phase::Open).map(|(id, _)| *id)).collect()
    }

    /// Whether every open label on every connection has completed a pass and nothing is
    /// outstanding (tests, simulator quiescence).
    pub fn is_idle(&self) -> bool {
        self.conns.values().all(|c| c.session.outstanding() == 0 && c.labels.values().all(|l| l.phase != Phase::Open || (l.synced && !l.syncing && !l.dirty && l.registering.is_none())))
    }

    /// Diagnostics since the last call (tests).
    pub fn take_diagnostics(&mut self) -> Vec<String> {
        std::mem::take(&mut self.diagnostics)
    }

    /// Entries this node knows under a label (tests).
    pub fn entries(&self, l: &LabelId) -> Vec<(osis_core::BlobId, EntryKind)> {
        self.state.entries.iter().filter(|((x, _), _)| x == l).map(|((_, b), e)| (*b, e.kind.clone())).collect()
    }

    /// Signals received since the last call.
    pub fn take_signals(&mut self) -> Vec<osis_label::SignalBody> {
        std::mem::take(&mut self.signals)
    }
}

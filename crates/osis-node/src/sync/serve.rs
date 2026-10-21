//! Member-peer serving (spec/sync.md §5 last bullet, §10): a node serves the labels it syncs to
//! the peers that dial it, through osis-proto's server engine over its own label state
//! (`PeerStore`, a `LabelStore` over the sync state's entries and the engine's blobs). Opens,
//! stamps and deposits are checked as a blind node checks them, against the registration path
//! recorded in `/label` (the deepest recorded step is the head). Accepted entries go through the
//! same path as downloaded ones; the log is in memory (`Feed`, a fresh log ID per start, so a
//! peer's old cursor replays). A peer's deletion hides the entry from peers only, a registration
//! extends the served path in memory: this node's own state follows its own rules. Entries this
//! node dropped stay refused for `TOMBSTONE_LIFETIME` (`State::tombs`). What peers upload or
//! deposit is charged to the uploading peer key and to a node-wide total (`SyncConfig`
//! `peer_bytes`, `peer_total_bytes`) until it opens, reaches a server or is dropped; past either,
//! uploads get code 12 and deposits code 5. A member proof by the dialable key of a node that
//! currently reads a label opens it (spec/sync.md §5, member peer); budgets are then charged to
//! that dialable key.

use super::state::Entry;
use super::{Action, ConnId, SyncEngine};
use crate::engine::Engine;
use crate::error::Result;
use osis_core::format::TOMBSTONE_LIFETIME_MS;
use osis_core::{BlobId, LabelId};
use osis_label::{ClaimSet, Step, StepId};
use osis_proto::{Budget, Code, EntryMeta, LabelStore, LogRecord, Put, ServerConfig, ServerConnection, ServerInput, ServerOutput, StoreError};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

/// Log records kept per label; a cursor below them replays.
const LOG_KEEP: usize = 4096;
/// Rounds of "a served change grew a log" per `handle`.
const MAX_NOTIFY: usize = 8;
/// Budget entries reported per this many bytes left (the recommended deposit unit).
const ENTRY_UNIT: u64 = 32 * 1024;
/// Steps peers registered kept per label.
const MAX_PEER_STEPS: usize = 64;

/// The in-memory log of each label as peers see it (spec/sync.md §4).
#[derive(Default)]
pub(crate) struct Feed {
    pub log_id: [u8; 16],
    labels: BTreeMap<LabelId, LabelLog>,
    /// Labels whose log grew since the last notification.
    grown: BTreeSet<LabelId>,
}

impl Feed {
    /// Forgets a label's log (this node no longer reads it).
    pub(crate) fn forget(&mut self, l: &LabelId) {
        self.labels.remove(l);
        self.grown.remove(l);
    }
}

#[derive(Default)]
struct LabelLog {
    recs: VecDeque<(u64, LogRecord)>,
    /// Records at or below this sequence number were dropped.
    horizon: u64,
    seq: u64,
    /// Sequence number of each entry's latest add (entries from before this start: none).
    adds: BTreeMap<BlobId, u64>,
    head: Option<StepId>,
    /// Deleted for peers: when.
    gone: BTreeMap<BlobId, u64>,
    /// Pending deletion times peers set.
    pending: BTreeMap<BlobId, u64>,
}

impl LabelLog {
    fn hidden(&self, b: &BlobId, now: u64) -> bool {
        self.gone.contains_key(b) || self.pending.get(b).is_some_and(|t| *t <= now)
    }
}

impl Feed {
    fn append(&mut self, l: LabelId, r: LogRecord) -> u64 {
        self.grown.insert(l);
        let x = self.labels.entry(l).or_default();
        x.seq += 1;
        x.recs.push_back((x.seq, r));
        if x.recs.len() > LOG_KEEP
            && let Some((s, _)) = x.recs.pop_front()
        {
            x.horizon = s;
        }
        x.seq
    }

    /// An entry was added or its wrap or stamp changed.
    pub fn added(&mut self, l: LabelId, b: BlobId) {
        let s = self.append(l, LogRecord::Added(b));
        if let Some(x) = self.labels.get_mut(&l) {
            x.adds.insert(b, s);
        }
    }

    pub fn deleted(&mut self, l: LabelId, b: BlobId) {
        if let Some(x) = self.labels.get_mut(&l) {
            x.adds.remove(&b);
        }
        self.append(l, LogRecord::Deleted(b));
    }

    /// Forgets peer deletions past the tombstone lifetime.
    pub fn expire(&mut self, now: u64) {
        let live = |t: &u64| t.saturating_add(TOMBSTONE_LIFETIME_MS) > now;
        for x in self.labels.values_mut() {
            x.gone.retain(|_, t| live(t));
            x.pending.retain(|_, t| live(t));
        }
    }

    /// Logs a head record where the served head moved.
    fn heads(&mut self, labels: &BTreeMap<LabelId, ServedLabel>) {
        for (l, s) in labels {
            let Some(h) = s.path.last() else { continue };
            let id = h.id();
            if self.labels.get(l).and_then(|x| x.head) != Some(id) {
                self.append(*l, LogRecord::Head(h.clone()));
                if let Some(x) = self.labels.get_mut(l) {
                    x.head = Some(id);
                }
            }
        }
    }
}

/// A served label: its group, its path to the head and the claim sets held.
pub struct ServedLabel {
    group: osis_core::Tid,
    path: Vec<Step>,
    claims: BTreeMap<StepId, Arc<ClaimSet>>,
}

impl ServedLabel {
    /// The path to the deepest step of `steps` (the lowest ID among equals).
    pub(crate) fn new(group: osis_core::Tid, steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> Option<ServedLabel> {
        let depth = |id: &StepId| {
            let mut n = 0usize;
            let mut cur = Some(*id);
            while let Some(c) = cur {
                let (s, _) = steps.get(&c)?;
                n += 1;
                if n > steps.len() {
                    return None;
                }
                cur = s.prev;
            }
            Some(n)
        };
        let tip = steps.keys().filter_map(|id| depth(id).map(|d| (d, *id))).max_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)))?.1;
        let mut path = Vec::new();
        let mut cur = Some(tip);
        while let Some(c) = cur {
            let (s, _) = steps.get(&c)?;
            path.push(s.clone());
            cur = s.prev;
        }
        path.reverse();
        let claims = steps.iter().filter_map(|(id, (_, c))| c.clone().map(|c| (*id, Arc::new(c)))).collect();
        Some(ServedLabel { group, path, claims })
    }
}

/// An incoming peer session.
pub(crate) struct Served {
    conn: ServerConnection,
    /// The dialer's authenticated key (budgets are charged to it).
    peer: [u8; 32],
    /// Raw ms of the last bytes received (idle sessions are closed).
    pub last: u64,
    /// Raw ms the session started (one that opens nothing is closed).
    since: u64,
}

/// What a served request accepted, carried out after the server engine returns.
#[derive(Default)]
struct Accepted {
    entries: Vec<(LabelId, osis_proto::Event)>,
    steps: Vec<(LabelId, Step, Option<ClaimSet>)>,
    /// Bytes charged per accepted entry.
    charges: Vec<(LabelId, BlobId, u64)>,
    /// A put was refused for the budget.
    full: bool,
}

/// The `LabelStore` a member peer serves from.
struct PeerStore<'a> {
    engine: RefCell<&'a mut Engine>,
    entries: &'a BTreeMap<(LabelId, BlobId), Entry>,
    tombs: &'a BTreeMap<(LabelId, BlobId), u64>,
    feed: &'a mut Feed,
    labels: &'a BTreeMap<LabelId, ServedLabel>,
    /// Node things by dialable key (`reach_nodes`): whose member proofs count.
    reach: &'a BTreeMap<[u8; 32], osis_core::Tid>,
    /// Blob sizes seen (`live` reads a blob only once).
    sizes: RefCell<&'a mut BTreeMap<BlobId, u64>>,
    now: u64,
    /// Corrected wall ms (tombstones of this node's drops).
    wall: u64,
    /// Bytes this peer, and all peers together, may still have charged.
    peer_left: u64,
    total_left: u64,
    acc: Accepted,
}

fn local(e: crate::Error) -> StoreError {
    StoreError(e.to_string())
}

impl PeerStore<'_> {
    fn blob_len(&self, b: &BlobId) -> std::result::Result<Option<u64>, StoreError> {
        if let Some(n) = self.sizes.borrow().get(b) {
            return Ok(Some(*n));
        }
        let n = self.engine.borrow_mut().blob(b).map_err(local)?.map(|x| x.len() as u64);
        if let Some(n) = n {
            self.sizes.borrow_mut().insert(*b, n);
        }
        Ok(n)
    }

    fn live(&self, l: &LabelId, b: &BlobId) -> std::result::Result<Option<EntryMeta>, StoreError> {
        let Some(e) = self.entries.get(&(*l, *b)) else { return Ok(None) };
        let log = self.feed.labels.get(l);
        if log.is_some_and(|x| x.hidden(b, self.now)) {
            return Ok(None);
        }
        let Some(size) = self.blob_len(b)? else { return Ok(None) };
        Ok(Some(EntryMeta {
            wrap: e.wrap,
            stamp: e.stamp,
            size,
            add_seq: log.and_then(|x| x.adds.get(b)).copied().unwrap_or(0),
            pending_delete: log.and_then(|x| x.pending.get(b)).copied(),
        }))
    }
}

impl LabelStore for PeerStore<'_> {
    /// A node of a current reader of the label (spec/sync.md §5).
    fn member_open(&self, dialable: &[u8; 32], label: &LabelId) -> std::result::Result<bool, StoreError> {
        let Some(n) = self.reach.get(dialable).copied() else { return Ok(false) };
        Ok(self.labels.get(label).is_some_and(|s| self.engine.borrow().may_read(&n, &s.group)))
    }

    fn head(&self, label: &LabelId) -> std::result::Result<Option<StepId>, StoreError> {
        Ok(self.labels.get(label).and_then(|s| s.path.last()).map(|s| s.id()))
    }

    fn step(&self, label: &LabelId, id: &StepId) -> std::result::Result<Option<Step>, StoreError> {
        Ok(self.labels.get(label).and_then(|s| s.path.iter().find(|x| x.id() == *id)).cloned())
    }

    fn claim_set(&self, label: &LabelId, id: &StepId) -> std::result::Result<Option<Arc<ClaimSet>>, StoreError> {
        Ok(self.labels.get(label).and_then(|s| s.claims.get(id)).cloned())
    }

    fn path(&self, label: &LabelId) -> std::result::Result<Vec<Step>, StoreError> {
        Ok(self.labels.get(label).map(|s| s.path.clone()).unwrap_or_default())
    }

    /// Only labels this node syncs are served.
    fn admit_label(&self, _label: &LabelId) -> std::result::Result<Code, StoreError> {
        Ok(Code::REFUSED)
    }

    fn push_step(&mut self, label: &LabelId, step: Step, claim_set: Option<ClaimSet>) -> std::result::Result<(), StoreError> {
        self.acc.steps.push((*label, step, claim_set));
        Ok(())
    }

    fn entry(&self, label: &LabelId, blob_id: &BlobId) -> std::result::Result<Option<EntryMeta>, StoreError> {
        self.live(label, blob_id)
    }

    fn tombstoned(&self, label: &LabelId, blob_id: &BlobId) -> std::result::Result<bool, StoreError> {
        // dropped here (a server's deletion, our own delete or drop): never back from a peer
        if self.tombs.get(&(*label, *blob_id)).is_some_and(|t| t.saturating_add(TOMBSTONE_LIFETIME_MS) > self.wall) {
            return Ok(true);
        }
        let Some(x) = self.feed.labels.get(label) else { return Ok(false) };
        let at = x.gone.get(blob_id).copied().or_else(|| x.pending.get(blob_id).copied().filter(|t| *t <= self.now));
        Ok(at.is_some_and(|t| t.saturating_add(TOMBSTONE_LIFETIME_MS) > self.now))
    }

    fn blob(&self, blob_id: &BlobId) -> std::result::Result<Option<Vec<u8>>, StoreError> {
        self.engine.borrow_mut().blob(blob_id).map_err(local)
    }

    fn put(&mut self, label: &LabelId, put: Put<'_>) -> std::result::Result<Code, StoreError> {
        // a held entry costs nothing more (a new wrap or a stamp)
        if !self.entries.contains_key(&(*label, put.blob_id)) {
            let size = put.blob.len() as u64;
            if size > self.peer_left || size > self.total_left {
                self.acc.full = true;
                return Ok(if put.stamp.is_some() { Code::STORAGE_CAP } else { Code::BUDGET_FULL });
            }
            self.peer_left -= size;
            self.total_left -= size;
            self.acc.charges.push((*label, put.blob_id, size));
        }
        if let Some(x) = self.feed.labels.get_mut(label) {
            x.gone.remove(&put.blob_id);
            x.pending.remove(&put.blob_id);
        }
        self.acc.entries.push((*label, osis_proto::Event::Added { blob_id: put.blob_id, blob: Some(put.blob.to_vec()), wrap: put.wrap, stamp: put.stamp }));
        Ok(Code::OK)
    }

    fn budget(&self, _label: &LabelId) -> std::result::Result<Budget, StoreError> {
        let bytes_left = self.peer_left.min(self.total_left);
        Ok(Budget { entries_left: bytes_left / ENTRY_UNIT, bytes_left })
    }

    fn delete(&mut self, label: &LabelId, blob_id: &BlobId, now: u64) -> std::result::Result<Code, StoreError> {
        if self.live(label, blob_id)?.is_some() {
            self.feed.labels.entry(*label).or_default().gone.insert(*blob_id, now);
            self.feed.deleted(*label, *blob_id);
        }
        Ok(Code::OK)
    }

    fn schedule_delete(&mut self, label: &LabelId, blob_id: &BlobId, at: u64) -> std::result::Result<Code, StoreError> {
        let x = self.feed.labels.entry(*label).or_default();
        if x.pending.get(blob_id).is_none_or(|t| at < *t) {
            x.pending.insert(*blob_id, at);
            self.feed.append(*label, LogRecord::Pending(*blob_id, at));
        }
        Ok(Code::OK)
    }

    fn signal(&mut self, _label: &LabelId) -> std::result::Result<Code, StoreError> {
        Ok(Code::OK)
    }

    fn log_head(&self, label: &LabelId) -> std::result::Result<([u8; 16], u64), StoreError> {
        Ok((self.feed.log_id, self.feed.labels.get(label).map_or(0, |x| x.seq)))
    }

    fn log_after(&self, label: &LabelId, after: u64, max: usize) -> std::result::Result<Option<Vec<(u64, LogRecord)>>, StoreError> {
        let Some(x) = self.feed.labels.get(label) else { return Ok((after == 0).then(Vec::new)) };
        if after < x.horizon || after > x.seq {
            return Ok(None);
        }
        Ok(Some(x.recs.iter().filter(|(s, _)| *s > after).take(max).cloned().collect()))
    }

    fn live_by_id(&self, label: &LabelId, after: Option<&BlobId>, max: usize) -> std::result::Result<Vec<(BlobId, EntryMeta)>, StoreError> {
        let start = after.copied().unwrap_or(BlobId([0; 32]));
        let mut out = Vec::new();
        for ((l, b), _) in self.entries.range((*label, start)..) {
            if l != label || out.len() >= max {
                break;
            }
            if after == Some(b) {
                continue;
            }
            if let Some(m) = self.live(label, b)? {
                out.push((*b, m));
            }
        }
        Ok(out)
    }

    fn live_ids(&self, label: &LabelId) -> std::result::Result<Vec<BlobId>, StoreError> {
        let mut out = Vec::new();
        for ((l, b), _) in self.entries.range((*label, BlobId([0; 32]))..) {
            if l != label {
                break;
            }
            if self.live(label, b)?.is_some() {
                out.push(*b);
            }
        }
        Ok(out)
    }
}


impl SyncEngine {
    /// A peer dialed this node: a session on its listener. `local` is the key this node's
    /// listener presented (its dialable key, or a LAN transport key; open signatures bind it),
    /// `peer` the key the transport authenticated for the dialer (budgets are charged to it,
    /// or to the dialable key of its member proof). Returns the session's handle (its bytes come
    /// as `Event::Bytes`, its end as `Event::Down`) and the actions (the Hello; a Close when
    /// `SyncConfig.max_served` sessions run, or `max_served_per_key` for this `peer`). Opens are
    /// checked as a blind node checks them, plus member proofs by the dialable key of a node
    /// thing currently reading the label (spec/sync.md §5).
    pub fn accept(&mut self, local: [u8; 32], peer: [u8; 32]) -> (ConnId, Vec<Action>) {
        let conn = self.next_conn;
        self.next_conn += 1;
        let mut out = Vec::new();
        if self.served.len() >= self.cfg.max_served || self.served.values().filter(|s| s.peer == peer).count() >= self.cfg.max_served_per_key {
            out.push(Action::Close { conn });
            return (conn, out);
        }
        self.state.now = self.now();
        let mut challenge = [0u8; 32];
        self.rng.fill_bytes(&mut challenge);
        let last = self.raw_now();
        self.served.insert(conn, Served { conn: ServerConnection::new(ServerConfig { static_key: local, challenge }), peer, last, since: last });
        if let Err(e) = self.serve(conn, ServerInput::Start, &mut out) {
            self.diag(format!("serve: {e}"));
        }
        let _ = self.state.flush(&mut self.engine);
        (conn, out)
    }

    /// Label IDs opened on each served session (tests, diagnostics).
    pub fn served_opened(&self) -> BTreeMap<ConnId, BTreeSet<LabelId>> {
        self.served.iter().map(|(c, s)| (*c, s.conn.opened().clone())).collect()
    }

    /// The labels this node serves: those it syncs, at the deepest recorded step (and the steps
    /// peers registered here since start). Cached until `/label`, membership or the peer steps
    /// change.
    fn served_labels(&mut self) -> Arc<BTreeMap<LabelId, ServedLabel>> {
        if let Some(c) = &self.served_cache {
            return c.clone();
        }
        let mut m = BTreeMap::new();
        for (_, mut gl) in self.labels() {
            for (s, c) in self.peer_steps.get(&gl.id).into_iter().flatten() {
                gl.steps.entry(s.id()).or_insert_with(|| (s.clone(), c.clone()));
            }
            if let Some(s) = ServedLabel::new(gl.group, &gl.steps) {
                m.insert(gl.id, s);
            }
        }
        let m = Arc::new(m);
        self.served_cache = Some(m.clone());
        m
    }

    /// Drops charges that no longer count: entries no longer held, opened since, or present at
    /// a server or peer.
    pub(crate) fn prune_charges(&mut self) {
        let st = &self.state;
        let stale: Vec<(LabelId, BlobId)> = self.charges.keys().filter(|(l, b)| !(st.entries.get(&(*l, *b)).is_some_and(|e| matches!(e.kind, super::state::Kind::Unknown | super::state::Kind::Bad | super::state::Kind::Parked(_))) && !st.present_anywhere(l, b))).copied().collect();
        for k in stale {
            if let Some((p, n)) = self.charges.remove(&k) {
                self.uncharge(p, n);
            }
        }
        self.charges_pruned = self.raw_now();
        self.charges_full = false;
    }

    fn uncharge(&mut self, p: [u8; 32], n: u64) {
        self.charged_total = self.charged_total.saturating_sub(n);
        if let Some(x) = self.charged_per.get_mut(&p) {
            *x = x.saturating_sub(n);
            if *x == 0 {
                self.charged_per.remove(&p);
            }
        }
    }

    /// Feeds one input to a served session.
    pub(crate) fn serve(&mut self, conn: ConnId, input: ServerInput, out: &mut Vec<Action>) -> Result<()> {
        let labels = self.served_labels();
        self.serve_with(conn, input, &labels, out)
    }

    fn serve_with(&mut self, conn: ConnId, input: ServerInput, labels: &BTreeMap<LabelId, ServedLabel>, out: &mut Vec<Action>) -> Result<()> {
        if !self.served.contains_key(&conn) {
            return Ok(());
        }
        let now = self.raw_now();
        // a budget was reached: charges that no longer count go first (at most once a second)
        if self.charges_full && now >= self.charges_pruned.saturating_add(1000) {
            self.prune_charges();
        }
        let Some(mut s) = self.served.remove(&conn) else { return Ok(()) };
        let used = self.charged_per.get(&s.conn.member().unwrap_or(s.peer)).copied().unwrap_or(0);
        let total = self.charged_total;
        let reach = self.reach_nodes();
        self.state.feed.heads(labels);
        if matches!(input, ServerInput::Bytes(_)) {
            s.last = now;
        }
        let wall = self.state.now;
        let (outputs, acc) = {
            let mut store = PeerStore {
                engine: RefCell::new(&mut self.engine),
                entries: &self.state.entries,
                tombs: &self.state.tombs,
                feed: &mut self.state.feed,
                labels,
                reach: &reach,
                sizes: RefCell::new(&mut self.blob_sizes),
                now,
                wall,
                peer_left: self.cfg.peer_bytes.saturating_sub(used),
                total_left: self.cfg.peer_total_bytes.saturating_sub(total),
                acc: Accepted::default(),
            };
            let o = s.conn.handle(now, &mut store, input);
            (o, store.acc)
        };
        let peer = s.conn.member().unwrap_or(s.peer);
        let member = s.conn.member().is_some_and(|k| reach.contains_key(&k));
        if !s.conn.is_closed() {
            self.served.insert(conn, s);
        }
        self.charges_full |= acc.full;
        for (l, b, n) in acc.charges {
            if let Some((p, old)) = self.charges.insert((l, b), (peer, n)) {
                self.uncharge(p, old);
            }
            *self.charged_per.entry(peer).or_default() += n;
            self.charged_total = self.charged_total.saturating_add(n);
        }
        if !acc.entries.is_empty() && member {
            for (l, _) in &acc.entries {
                self.peer_received.entry(*l).or_default().insert(peer);
            }
        }
        for (l, step, cs) in acc.steps {
            let v = self.peer_steps.entry(l).or_default();
            if !v.iter().any(|(x, _)| x.id() == step.id()) {
                v.push((step, cs));
                if v.len() > MAX_PEER_STEPS {
                    v.remove(0);
                }
            }
            self.served_cache = None;
        }
        let mut by_label: BTreeMap<LabelId, Vec<osis_proto::Event>> = BTreeMap::new();
        for (l, ev) in acc.entries {
            by_label.entry(l).or_default().push(ev);
        }
        for (l, evs) in by_label {
            // stamps were checked against the served head by the server engine
            self.log_events(None, l, evs, None, out)?;
        }
        let mut signals = Vec::new();
        for o in outputs {
            match o {
                ServerOutput::Send(bytes) => out.push(Action::Send { conn, bytes }),
                ServerOutput::Close => out.push(Action::Close { conn }),
                ServerOutput::Changed(l) => {
                    self.state.feed.grown.insert(l);
                }
                ServerOutput::Signal { label, blob, wrap, auth } => signals.push((label, blob, wrap, auth)),
                ServerOutput::PeerError(e) => self.diag(format!("peer: {e}")),
                ServerOutput::StoreError(e) => self.diag(format!("serve: {e}")),
            }
        }
        for (label, blob, wrap, auth) in signals {
            self.signal_in(label, &blob, &wrap, &auth)?;
            let others: Vec<ConnId> = self.served.keys().copied().filter(|c| *c != conn).collect();
            for c in others {
                self.serve_with(c, ServerInput::Signal { label, blob: blob.clone(), wrap, auth: auth.clone() }, labels, out)?;
            }
        }
        Ok(())
    }

    /// After a membership or roster change: co-readers that no longer read a label stop
    /// counting for its complete pass, and served sessions whose member proof's node no longer
    /// reads a label they opened are closed.
    pub(crate) fn members_changed(&mut self, out: &mut Vec<Action>) {
        let peers = self.peers();
        for (l, ks) in self.peer_received.iter_mut() {
            ks.retain(|k| peers.get(k).is_some_and(|p| p.labels.contains(l)));
        }
        self.peer_received.retain(|_, ks| !ks.is_empty());
        let reach = self.reach_nodes();
        let labels = self.served_labels();
        let stale: Vec<ConnId> = self
            .served
            .iter()
            .filter(|(_, s)| {
                let Some(k) = s.conn.member() else { return false };
                let node = reach.get(&k);
                s.conn.opened().iter().any(|l| labels.get(l).is_some_and(|x| node.is_none_or(|n| !self.engine.may_read(n, &x.group))))
            })
            .map(|(c, _)| *c)
            .collect();
        for c in stale {
            self.served.remove(&c);
            out.push(Action::Close { conn: c });
        }
    }

    /// Pushes grown logs to subscribed peer sessions.
    pub(crate) fn notify_served(&mut self, out: &mut Vec<Action>) -> Result<()> {
        if self.served.is_empty() {
            self.state.feed.grown.clear();
            return Ok(());
        }
        for _ in 0..MAX_NOTIFY {
            let grown = std::mem::take(&mut self.state.feed.grown);
            if grown.is_empty() {
                break;
            }
            let labels = self.served_labels();
            let conns: Vec<ConnId> = self.served.keys().copied().collect();
            for c in conns {
                for l in &grown {
                    self.serve_with(c, ServerInput::Changed(*l), &labels, out)?;
                }
            }
        }
        Ok(())
    }

    /// Closes served sessions without bytes for `SyncConfig.serve_idle_ms`, and those that
    /// opened no label within `serve_open_ms`; expires peer deletions and this node's
    /// tombstones; prunes charges and blob sizes.
    pub(crate) fn serve_timers(&mut self, out: &mut Vec<Action>) {
        let now = self.raw_now();
        let (idle, open) = (self.cfg.serve_idle_ms, self.cfg.serve_open_ms);
        let stale: Vec<ConnId> = self.served.iter().filter(|(_, s)| s.last.saturating_add(idle) <= now || s.conn.opened().is_empty() && s.since.saturating_add(open) <= now).map(|(c, _)| *c).collect();
        for c in stale {
            self.served.remove(&c);
            out.push(Action::Close { conn: c });
        }
        let wall = self.state.now;
        self.state.feed.expire(wall);
        self.state.expire_tombs(wall);
        self.prune_charges();
        if self.blob_sizes.len() > self.state.entries.len() {
            let held: BTreeSet<BlobId> = self.state.entries.keys().map(|(_, b)| *b).collect();
            self.blob_sizes.retain(|b, _| held.contains(b));
        }
    }

    /// When the next served session goes idle.
    pub(crate) fn serve_wake(&self) -> Option<u64> {
        self.served.values().map(|s| if s.conn.opened().is_empty() { s.since.saturating_add(self.cfg.serve_open_ms).min(s.last.saturating_add(self.cfg.serve_idle_ms)) } else { s.last.saturating_add(self.cfg.serve_idle_ms) }).min()
    }
}

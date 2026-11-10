//! Co-reader-peer serving (spec/sync.md §5 last bullet, §10): a node serves the labels it syncs to
//! the peers that dial it, through osis-proto's host engine over its own label state
//! (`PeerStore`, a `LabelStore` over the sync state's entries and the engine's blobs). Opens,
//! stamps and deposits are checked as a host checks them, against the registration path
//! recorded in `label.0` (the deepest recorded step is the head). Accepted entries go through the
//! same path as downloaded ones; what peers read of this node goes by its node log stream
//! (`stream`), so Sync, Subscribe and Reconcile are answered Error 11. A peer's deletion or
//! replacement removes nothing, a registration extends the served path in memory: this node's
//! own state follows its own rules. Entries this
//! node dropped stay refused for `TOMBSTONE_LIFETIME` (`State::tombs`). What peers upload or
//! deposit is charged to the label it went under (dialer keys are fresh per connection) and to a node-wide total (`SyncConfig`
//! `peer_bytes`, `peer_total_bytes`) until it opens, reaches a host or is dropped; past either,
//! uploads get code 12 and deposits code 5. A connection's shared set opens a label for a peer
//! (issues/net-shared-set.md); budgets are then charged to the node it proved.

use super::state::{Entry, Tomb};
use super::{Action, ConnId, SyncEngine};
use crate::engine::Engine;
use crate::error::Result;
use osis_base::Tid;
use osis_crypto::Secret32;
use osis_schema::core_types as ct;
use osis_base::format::TOMBSTONE_LIFETIME_MS;

/// How often carriers and certificate placements nothing needs are forgotten (they wait
/// `TOMBSTONE_LIFETIME` anyway): at 0 every tick scans every entry, at infinity they stay.
pub(crate) const RECORD_SWEEP_MS: u64 = 3_600_000;
use osis_base::{BlobId, LabelId};
use osis_label::{ClaimSet, Step, StepId};
use osis_proto::{Budget, Code, EntryMeta, LabelStore, LogRecord, Put, ServingConfig, ServingSession, ServingInput, ServingOutput, StoreError};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Budget entries reported per this many bytes left (the recommended deposit unit).
const ENTRY_UNIT: u64 = 32 * 1024;
/// Steps peers registered kept per label.
const MAX_PEER_STEPS: usize = 64;

/// A served label: its group, its path to the head and the claim sets held, with the path
/// indexes an Open or a Path page reads (step ID → position, sync key → newest position) and the
/// head keys, so a peer's request costs no scan of the path.
pub struct ServedLabel {
    path: Vec<Step>,
    claims: BTreeMap<StepId, Arc<ClaimSet>>,
    pos: BTreeMap<StepId, usize>,
    by_sync: BTreeMap<[u8; 32], usize>,
    keys: Option<osis_proto::HeadKeys>,
}

impl ServedLabel {
    /// The served head.
    pub(crate) fn head(&self) -> Option<&Step> {
        self.path.last()
    }

    /// What a holder of static entry `entry` needs to read the label (spec/sync.md §10, Shared
    /// set): the head's entry box for it and the path to the head.
    pub(crate) fn grant(&self, entry: &[u8; 32]) -> Option<osis_proto::msg::EntryGrant> {
        let head = self.path.last()?;
        let entry_box = self.claims.get(&head.id())?.entries.get(entry)?.clone();
        Some(osis_proto::msg::EntryGrant { entry_box, path: self.path.clone() })
    }

    /// The path to the deepest step of `steps` (the lowest ID among equals).
    pub(crate) fn new(steps: &super::open::Steps) -> Option<ServedLabel> {
        let path: Vec<Step> = super::open::deepest_path(steps)?.into_iter().map(|(s, _)| s.clone()).collect();
        let claims = steps.iter().filter_map(|(id, (_, c))| c.clone().map(|c| (*id, Arc::new(c)))).collect();
        let pos = path.iter().enumerate().map(|(i, s)| (s.id(), i)).collect();
        // later positions overwrite: the newest step per sync key
        let by_sync = path.iter().enumerate().map(|(i, s)| (s.keys.sync.to_bytes(), i)).collect();
        let keys = osis_proto::HeadKeys::of_path(&path);
        Some(ServedLabel { path, claims, pos, by_sync, keys })
    }
}

/// An incoming peer session.
pub(crate) struct Served {
    conn: ServingSession,
    tier: super::Tier,
    /// It made a client-port request (`Action::Ended` when it goes).
    ported: bool,
    /// On the client listener (its unauthenticated sessions are a pool of their own).
    public: bool,
    /// What this connection's dialer proved (spec/sync.md §10), read by `SyncEngine::proven`.
    proven: super::proofs::Proven,
    /// Raw ms of the last bytes received (idle sessions are closed).
    pub last: u64,
    /// Raw ms the session started (one that opens nothing is closed).
    since: u64,
    /// A thin client's: the hash of the secret it authenticated with and its entry's end
    /// (corrected wall ms). The session ends with the entry, with that hash, at that end.
    client: Option<ClientBinding>,
}

#[derive(Clone, Copy)]
struct ClientBinding {
    hash: [u8; 32],
    until: Option<u64>,
}

impl ClientBinding {
    /// Entry `e` still stands for this session at `now`: the same secret, not past its `until`.
    fn holds(&self, e: &ct::Client, now: u64) -> bool {
        Secret32::from_bytes(e.secret_hash) == Secret32::from_bytes(self.hash) && e.until.is_none_or(|u| u.0 > now)
    }
}

/// Bytes peers uploaded or deposited here, per entry: (peer key, bytes), with running sums per
/// peer key and in all (stale charges pruned at ticks and when a budget is reached).
#[derive(Default)]
pub(crate) struct Charges {
    by_entry: BTreeMap<(LabelId, BlobId), ([u8; 32], u64)>,
    per: BTreeMap<[u8; 32], u64>,
    total: u64,
    /// When charges were last pruned (raw ms), and whether a budget was reached since.
    pruned: u64,
    full: bool,
}

impl Charges {
    fn charge(&mut self, l: LabelId, b: BlobId, key: [u8; 32], n: u64) {
        if let Some((p, old)) = self.by_entry.insert((l, b), (key, n)) {
            self.uncharge(p, old);
        }
        *self.per.entry(key).or_default() += n;
        self.total = self.total.saturating_add(n);
    }

    fn uncharge(&mut self, p: [u8; 32], n: u64) {
        self.total = self.total.saturating_sub(n);
        if let Some(x) = self.per.get_mut(&p) {
            *x = x.saturating_sub(n);
            if *x == 0 {
                self.per.remove(&p);
            }
        }
    }
}

/// What a served request accepted, carried out after the host engine returns.
#[derive(Default)]
struct Accepted {
    entries: Vec<(LabelId, osis_proto::Event)>,
    steps: Vec<(LabelId, Step, Option<ClaimSet>)>,
    /// Bytes charged per accepted entry.
    charges: Vec<(LabelId, BlobId, u64)>,
    /// A put was refused for the budget.
    full: bool,
    /// What the dialer proved by its Prove (`proofs`).
    proven: super::proofs::Proven,
    /// The record this connection's Resume found or made, and records read for it.
    bound: Option<(osis_store::RecordId, bool)>,
    lookups: u64,
}

/// The `LabelStore` a co-reader peer serves from.
struct PeerStore<'a> {
    engine: RefCell<&'a mut Engine>,
    entries: &'a BTreeMap<(LabelId, BlobId), Entry>,
    tombs: &'a BTreeMap<(LabelId, BlobId), Tomb>,
    labels: &'a BTreeMap<LabelId, ServedLabel>,
    /// What this session proved so far (`Accepted.proven` for a Prove in the same input).
    proven_before: &'a super::proofs::Proven,
    /// Records in use by a connection: not evicted.
    in_use: BTreeSet<osis_store::RecordId>,
    /// Blob sizes seen (`live` reads a blob only once).
    sizes: RefCell<&'a mut BTreeMap<BlobId, u64>>,
    /// Corrected wall ms (tombstones of this node's drops).
    wall: u64,
    /// What is charged so far per charge key (`charge_key`), its limit, this session's proven
    /// node, and this request's charges per key; all peers together may still have `total_left`.
    charged: &'a BTreeMap<[u8; 32], u64>,
    limit: u64,
    node: Option<Tid>,
    used_here: BTreeMap<[u8; 32], u64>,
    total_left: u64,
    acc: Accepted,
    relays: &'a mut osis_proto::RelayGate,
}

/// Whom bytes a peer session put here are charged to: the node it proved, else the label they
/// went under (a dialer key is fresh per connection, so charging it would bound nothing: a link
/// holder's sessions share its K label's budget).
fn charge_key(node: Option<Tid>, label: &LabelId) -> [u8; 32] {
    node.map(|t| {
        let mut k = [0u8; 32];
        if let Some(d) = k.get_mut(..15) {
            d.copy_from_slice(t.as_bytes());
        }
        k
    }).unwrap_or_else(|| {        let mut k = [0xff; 32];
        if let Some(d) = k.get_mut(16..) {
            d.copy_from_slice(&label.0);
        }
        k
    })
}

fn local(e: crate::Error) -> StoreError {
    StoreError(e.to_string())
}

impl PeerStore<'_> {
    /// Bytes charged to `key` so far, this request's included.
    fn used(&self, key: &[u8; 32]) -> u64 {
        self.charged.get(key).copied().unwrap_or(0).saturating_add(self.used_here.get(key).copied().unwrap_or(0))
    }

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
        let Some(size) = self.blob_len(b)? else { return Ok(None) };
        Ok(Some(EntryMeta {
            wrap: e.wrap,
            stamp: e.stamp,
            size,
            add_seq: 0,
        }))
    }
}

impl LabelStore for PeerStore<'_> {
    fn prove(&mut self, proofs: Vec<osis_proto::ActorProof>, challenge: &[u8; 32], listener_key: &[u8; 32]) -> std::result::Result<Vec<osis_proto::ActorProof>, StoreError> {
        let engine = self.engine.get_mut();
        let proven = super::proofs::proven_actors(engine, &proofs).map_err(|e| StoreError(e.to_string()))?;
        // this side proves only to a dialer that proved an actor it knows (spec/sync.md §10)
        let known = engine.core.judge(proven.all()).known();
        let mine = if known { super::proofs::provers(engine).map_err(|e| StoreError(e.to_string()))?.iter().map(|p| p.sign(true, challenge, listener_key)).collect() } else { Vec::new() };
        self.acc.proven = proven;
        Ok(mine)
    }

    fn resume(&mut self, nonce: &[u8; 32], tags: &[[u8; 32]], binding: (&[u8; 32], &[u8; 32], &[u8; 32])) -> std::result::Result<Option<osis_proto::ResumeAnswer>, StoreError> {
        let proven = if self.acc.proven.is_empty() { self.proven_before } else { &self.acc.proven };
        let engine = self.engine.get_mut();
        let actors = super::records::counted_actors(engine, proven);
        if actors.is_empty() {
            return Ok(None);
        }
        let (answer, id, looked) = super::records::answer_resume(engine, &actors, &self.in_use, nonce, tags, binding).map_err(|e| StoreError(e.to_string()))?;
        self.acc.bound = Some(id);
        self.acc.lookups += looked;
        Ok(Some(answer))
    }

    fn head(&self, label: &LabelId) -> std::result::Result<Option<StepId>, StoreError> {
        Ok(self.labels.get(label).and_then(|s| s.path.last()).map(|s| s.id()))
    }

    fn step(&self, label: &LabelId, id: &StepId) -> std::result::Result<Option<Step>, StoreError> {
        Ok(self.labels.get(label).and_then(|s| s.pos.get(id).and_then(|i| s.path.get(*i))).cloned())
    }

    fn claim_set(&self, label: &LabelId, id: &StepId) -> std::result::Result<Option<Arc<ClaimSet>>, StoreError> {
        Ok(self.labels.get(label).and_then(|s| s.claims.get(id)).cloned())
    }

    fn step_with_sync(&self, label: &LabelId, pk: &osis_crypto::VerifyingKey) -> std::result::Result<Option<StepId>, StoreError> {
        Ok(self.labels.get(label).and_then(|s| s.by_sync.get(&pk.to_bytes()).and_then(|i| s.path.get(*i))).map(|x| x.id()))
    }

    fn child(&self, label: &LabelId, step: Option<&StepId>) -> std::result::Result<Option<StepId>, StoreError> {
        let Some(s) = self.labels.get(label) else { return Ok(None) };
        let next = match step {
            None => s.path.first(),
            Some(id) => s.pos.get(id).and_then(|i| s.path.get(i + 1)),
        };
        Ok(next.map(|x| x.id()))
    }

    fn path(&self, label: &LabelId) -> std::result::Result<Vec<Step>, StoreError> {
        Ok(self.labels.get(label).map(|s| s.path.clone()).unwrap_or_default())
    }

    fn head_keys(&self, label: &LabelId) -> std::result::Result<Option<osis_proto::HeadKeys>, StoreError> {
        Ok(self.labels.get(label).and_then(|s| s.keys.clone()))
    }

    /// Only labels this node syncs are served.
    fn admit_label(&self, _label: &LabelId) -> std::result::Result<Code, StoreError> {
        Ok(Code::REFUSED)
    }

    fn push_step(&mut self, label: &LabelId, step: Step, claim_set: Option<ClaimSet>) -> std::result::Result<Code, StoreError> {
        self.acc.steps.push((*label, step, claim_set));
        Ok(Code::OK)
    }

    fn entry(&self, label: &LabelId, blob_id: &BlobId) -> std::result::Result<Option<EntryMeta>, StoreError> {
        self.live(label, blob_id)
    }

    fn tombstoned(&self, label: &LabelId, blob_id: &BlobId) -> std::result::Result<bool, StoreError> {
        // dropped here (a host's deletion, our own delete or drop): never back from a peer
        Ok(self.tombs.get(&(*label, *blob_id)).is_some_and(|t| t.at.saturating_add(TOMBSTONE_LIFETIME_MS) > self.wall))
    }

    fn blob(&self, blob_id: &BlobId) -> std::result::Result<Option<Vec<u8>>, StoreError> {
        self.engine.borrow_mut().blob(blob_id).map_err(local)
    }

    fn put(&mut self, label: &LabelId, put: Put<'_>) -> std::result::Result<Code, StoreError> {
        // what an upload replaces stays: this node's own rules judge what it holds
        // a held entry costs nothing more (a stamp; which wrap stays: `take_wrap`)
        if !self.entries.contains_key(&(*label, put.blob_id)) {
            let size = put.blob.len() as u64;
            let key = charge_key(self.node, label);
            if size > self.limit.saturating_sub(self.used(&key)) || size > self.total_left {
                self.acc.full = true;
                return Ok(if put.stamp.is_some() { Code::STORAGE_CAP } else { Code::BUDGET_FULL });
            }
            *self.used_here.entry(key).or_default() += size;
            self.total_left -= size;
            self.acc.charges.push((*label, put.blob_id, size));
        }
        self.acc.entries.push((*label, osis_proto::Event::Added { blob_id: put.blob_id, blob: Some(put.blob.to_vec()), wrap: put.wrap, stamp: put.stamp }));
        Ok(Code::OK)
    }

    fn budget(&self, label: &LabelId) -> std::result::Result<Budget, StoreError> {
        let bytes_left = self.limit.saturating_sub(self.used(&charge_key(self.node, label))).min(self.total_left);
        Ok(Budget { entries_left: bytes_left / ENTRY_UNIT, bytes_left })
    }

    /// A reader's Delete changes nothing here: what this node holds follows its own rules, and
    /// a deletion reaches other readers by the deleter's own stream.
    fn delete(&mut self, _label: &LabelId, _blob_id: &BlobId, _now: u64) -> std::result::Result<Code, StoreError> {
        Ok(Code::OK)
    }

    /// Readers serve the node log stream (`stream`), never a per-label log.
    fn serves_log(&self) -> bool {
        false
    }

    fn log_head(&self, _label: &LabelId) -> std::result::Result<([u8; 16], u64), StoreError> {
        Ok(([0; 16], 0))
    }

    fn log_after(&self, _label: &LabelId, _after: u64, _max: usize) -> std::result::Result<Option<Vec<(u64, LogRecord)>>, StoreError> {
        Ok(None)
    }

    fn live_by_id(&self, _label: &LabelId, _after: Option<&BlobId>, _max: usize) -> std::result::Result<Vec<(BlobId, EntryMeta)>, StoreError> {
        Ok(Vec::new())
    }

    fn relay(&mut self, label: &LabelId, blob_id: &BlobId, size: usize, expiry: Option<u64>, _now: u64) -> std::result::Result<osis_proto::RelayVerdict, StoreError> {
        // expiry is wall time: the corrected clock
        Ok(self.relays.admit(label, blob_id, size, expiry, self.wall))
    }

    fn live_ids_in(&self, _label: &LabelId, _lower: &BlobId, _upper: Option<&BlobId>) -> std::result::Result<Vec<BlobId>, StoreError> {
        Ok(Vec::new())
    }
}

impl SyncEngine {
    /// A peer dialed this node: a session on its listener. `local` is the key this node's
    /// listener presented (its dialable key, or a LAN transport key; open signatures bind it),
    /// `peer` the key the transport authenticated for the dialer (ephemeral; budgets go to the
    /// node the session proved, else the label: `charge_key`). Returns the session's handle (its bytes come
    /// as `Event::Bytes`, its end as `Event::Down`) and the actions (the Hello). With
    /// `SyncConfig.max_served` sessions running, the oldest one that serves nothing is closed
    /// to make room (a dialer chooses its key, so a per-key cap would bind nothing); when every
    /// one serves something, this one is closed. Opens are checked as a host checks them
    /// (spec/sync.md §5); a reader's sync IDs are its shared set's (spec/sync.md §10).
    pub fn accept(&mut self, local: [u8; 32], peer: [u8; 32]) -> (ConnId, Vec<Action>) {
        self.accept_peer(local, osis_transport::Peer::Key(peer))
    }

    /// `accept` with the peer as the transport type reported it: a `Peer::Unix` session of this
    /// process's uid is a client in the main tier (notes/client-port.md §0, §5), in its own
    /// pool of `SyncConfig.max_clients` (an authenticated one counts as opened); every other
    /// session is keyed, in `max_served` (another uid's too, whatever its listener let in), but
    /// one on the client listener, in `client_pending`, so a flood there costs co-readers nothing.
    pub fn accept_peer(&mut self, local: [u8; 32], peer: osis_transport::Peer) -> (ConnId, Vec<Action>) {
        let (tier, cap) = match peer {
            osis_transport::Peer::Unix { uid } if osis_transport::unix::own_uid().is_ok_and(|o| o == uid) => (super::Tier::Main, self.cfg.max_clients),
            osis_transport::Peer::Unix { .. } | osis_transport::Peer::Key(_) => (super::Tier::Keyed, self.cfg.max_served),
        };
        let public = tier == super::Tier::Keyed && self.client_listen_key() == Some(local);
        let cap = if public { self.cfg.client_pending } else { cap };
        let conn = self.next_conn;
        self.next_conn += 1;
        let mut out = Vec::new();
        if self.served.values().filter(|s| s.tier == tier && s.public == public).count() >= cap {
            let idle = self.served.iter().filter(|(c, s)| s.tier == tier && s.public == public && self.serves_nothing(**c, s)).min_by_key(|(c, s)| (s.since, **c)).map(|(c, _)| *c);
            match idle {
                Some(old) => self.close_served(old, &mut out),
                None => {
                    out.push(Action::Close { conn });
                    return (conn, out);
                }
            }
        }
        self.state.now = self.now();
        let mut challenge = [0u8; 32];
        self.rng.fill_bytes(&mut challenge);
        let last = self.raw_now();
        let session = ServingSession::new(ServingConfig { static_key: local, challenge });
        self.served.insert(conn, Served { conn: if public { session.port_only() } else { session.with_port() }, tier, public, ported: false, proven: super::proofs::Proven::default(), last, since: last, client: None });
        if let Err(e) = self.serve(conn, ServingInput::Start, &mut out) {
            self.diag(format!("serve: {e}"));
        }
        let _ = self.state.flush(&mut self.engine);
        (conn, out)
    }

    /// Label IDs each served session serves: those it opened and its shared set's members
    /// (tests, diagnostics).
    pub fn served_opened(&self) -> BTreeMap<ConnId, BTreeSet<LabelId>> {
        self.served.iter().map(|(c, s)| (*c, s.conn.opened().copied().chain(self.shared_members(*c)).collect())).collect()
    }

    /// Whether served session `c` is exempt from the idle bound while its connection is up: an
    /// authenticated client (notes/client-port.md §3), or a reader sharing a sync ID here, whose
    /// stream is silent while nothing changes (the transport ends a dead connection).
    fn kept_while_up(&self, c: ConnId, s: &Served) -> bool {
        s.conn.authed() || self.records.shared.get(&c).is_some_and(|x| !x.is_empty())
    }

    /// Whether served session `c` serves nothing: no open and no member of its shared set.
    fn serves_nothing(&self, c: ConnId, s: &Served) -> bool {
        s.conn.none_opened() && self.records.shared.get(&c).is_none_or(|x| x.is_empty())
    }

    pub(super) fn served_proven_all(&self) -> Vec<(ConnId, BTreeSet<Tid>)> {
        self.served.iter().map(|(c, s)| (*c, s.proven.all())).collect()
    }

    /// The actors served session `conn` proved (`SyncEngine::proven`).
    pub(super) fn served_proven(&self, conn: ConnId) -> Option<&super::proofs::Proven> {
        self.served.get(&conn).map(|s| &s.proven)
    }

    /// The labels this node serves: those it syncs, at the deepest recorded step (and the steps
    /// peers registered here since start). Cached until `label.0`, role or the peer steps
    /// change.
    pub(crate) fn served_labels(&mut self) -> Arc<BTreeMap<LabelId, ServedLabel>> {
        if let Some(c) = &self.served_cache {
            return c.clone();
        }
        let mut m = BTreeMap::new();
        for (_, gl) in self.labels() {
            // borrowed unless a peer's step adds to it
            let mut steps = std::borrow::Cow::Borrowed(&gl.steps);
            for (s, c) in self.peer_steps.get(&gl.id).into_iter().flatten() {
                steps.to_mut().entry(s.id()).or_insert_with(|| (s.clone(), c.clone()));
            }
            if let Some(s) = ServedLabel::new(&steps) {
                if let Some(h) = s.path.last() {
                    self.state.note_head(gl.id, h.id().0);
                }
                m.insert(gl.id, s);
            }
        }
        let m = Arc::new(m);
        self.served_cache = Some(m.clone());
        m
    }

    /// Bytes new here that reader `conn`'s stream or fetches brought for entries of `l` with no
    /// stamp under the served head: those still unopened count against the peer budgets as an
    /// upload's did (`charge_key`), and past either the entry is not kept (spec/requirements.md:
    /// peer input never grows storage unbounded).
    pub(crate) fn charge_reader(&mut self, conn: ConnId, l: LabelId, fresh: &[BlobId]) -> Result<()> {
        if fresh.is_empty() {
            return Ok(());
        }
        let node = self.connection_proven(conn).and_then(|p| p.node).filter(|_| self.connection_proven(conn).is_some_and(|p| self.engine.core.judge(p.all()).known()));
        let key = charge_key(node, &l);
        let mut gone = Vec::new();
        for b in fresh {
            let unopened = self.state.entries.get(&(l, *b)).is_some_and(|e| matches!(e.kind, super::state::Kind::Unknown | super::state::Kind::Bad) && e.stamp.is_none());
            if !unopened {
                continue;
            }
            let size = match self.engine.blob(b)? {
                Some(x) => x.len() as u64,
                None => 0,
            };
            let used = self.charges.per.get(&key).copied().unwrap_or(0);
            if size > self.cfg.peer_bytes.saturating_sub(used) || size > self.cfg.peer_total_bytes.saturating_sub(self.charges.total) {
                self.charges.full = true;
                self.state.drop_entry(l, *b);
                self.fetched(b);
                if !self.state.blobs.contains_key(b) {
                    gone.push(*b);
                }
                continue;
            }
            self.charges.charge(l, *b, key, size);
        }
        self.delete_blobs(&gone)
    }

    /// Drops charges that no longer count: entries no longer held, opened since, or present at
    /// a host or peer.
    pub(crate) fn prune_charges(&mut self) {
        let st = &self.state;
        let stale: Vec<(LabelId, BlobId)> = self.charges.by_entry.keys().filter(|(l, b)| !(st.entries.get(&(*l, *b)).is_some_and(|e| matches!(e.kind, super::state::Kind::Unknown | super::state::Kind::Bad | super::state::Kind::Parked(_))) && !st.present_anywhere(l, b))).copied().collect();
        for k in stale {
            if let Some((p, n)) = self.charges.by_entry.remove(&k) {
                self.charges.uncharge(p, n);
            }
        }
        self.charges.pruned = self.raw_now();
        self.charges.full = false;
    }

    /// Feeds one input to a served session.
    pub(crate) fn serve(&mut self, conn: ConnId, input: ServingInput, out: &mut Vec<Action>) -> Result<()> {
        let labels = self.served_labels();
        self.serve_with(conn, input, &labels, out)
    }

    pub(crate) fn serve_with(&mut self, conn: ConnId, input: ServingInput, labels: &BTreeMap<LabelId, ServedLabel>, out: &mut Vec<Action>) -> Result<()> {
        if !self.served.contains_key(&conn) {
            return Ok(());
        }
        let now = self.raw_now();
        // a budget was reached: charges that no longer count go first (at most once a second)
        if self.charges.full && now >= self.charges.pruned.saturating_add(1000) {
            self.prune_charges();
        }
        let Some(mut s) = self.served.remove(&conn) else { return Ok(()) };
        let total = self.charges.total;
        // charged to the proved node only if known here: a fresh key per connection would bound nothing
        let node = s.proven.node.filter(|_| self.engine.core.judge(s.proven.all()).known());
        if matches!(input, ServingInput::Bytes(_)) {
            s.last = now;
        }
        let wall = self.state.now;
        let (outputs, mut acc) = {
            let mut store = PeerStore {
                engine: RefCell::new(&mut self.engine),
                proven_before: &s.proven,
                in_use: self.records.live(),
                entries: &self.state.entries,
                tombs: &self.state.tombs,
                labels,
                sizes: RefCell::new(&mut self.blob_sizes),
                wall,
                charged: &self.charges.per,
                limit: self.cfg.peer_bytes,
                node,
                used_here: BTreeMap::new(),
                total_left: self.cfg.peer_total_bytes.saturating_sub(total),
                acc: Accepted::default(),
                relays: &mut self.relay_gate,
            };
            let o = s.conn.handle(now, &mut store, input);
            (o, store.acc)
        };
        if !acc.proven.is_empty() {
            s.proven = std::mem::take(&mut acc.proven);
        }
        let closed = s.conn.is_closed();
        if outputs.iter().any(|o| matches!(o, ServingOutput::Request(_))) {
            s.ported = true;
        }
        if closed {
            self.records.conn_gone(conn);
            self.streams.remove(&conn);
            if s.ported {
                out.push(Action::Ended { conn });
            }
        } else {
            self.served.insert(conn, s);
        }
        self.records.lookups += acc.lookups;
        let bound = acc.bound.take().filter(|_| !closed);
        self.charges.full |= acc.full;
        for (l, b, n) in acc.charges {
            self.charges.charge(l, b, charge_key(node, &l), n);
        }
        // entries from a node known by its `reach.0`: its dialable key counts for the pass wait
        if !acc.entries.is_empty()
            && let Some(t) = node
            && let Some(k) = self.reach_nodes().iter().find(|(_, x)| **x == t).map(|(k, _)| *k)
        {
            for (l, _) in &acc.entries {
                self.peer_received.entry(*l).or_default().insert(k);
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
        let uploaded: Vec<BlobId> = acc.entries.iter().filter_map(|(_, e)| if let osis_proto::Event::Added { blob_id, .. } = e { Some(*blob_id) } else { None }).collect();
        let mut by_label: BTreeMap<LabelId, Vec<osis_proto::Event>> = BTreeMap::new();
        for (l, ev) in acc.entries {
            by_label.entry(l).or_default().push(ev);
        }
        for (l, evs) in by_label {
            // stamps were checked against the served head by the host engine
            self.log_events_from(super::inbound::Src::Served(conn), l, evs, None, out)?;
        }
        // bytes uploaded here are announced back without them (spec/wire.md §11.2, Inline bytes)
        if !uploaded.is_empty() {
            self.stream_crossed(conn, uploaded);
        }
        let mut relays = Vec::new();
        let mut refused = Vec::new();
        for o in outputs {
            match o {
                ServingOutput::Send(bytes) => out.push(Action::Send { conn, bytes }),
                ServingOutput::Close => out.push(Action::Close { conn }),
                ServingOutput::Changed(_) => {}
                ServingOutput::Relay(r) => relays.push(r),
                ServingOutput::PeerError(e) => self.diag(format!("peer: {e}")),
                ServingOutput::StoreError(e) => self.diag(format!("serve: {e}")),
                // nothing of an unauthenticated keyed session goes up, and no secret ever does
                ServingOutput::Request(msg) => match self.admit(conn, *msg) {
                    Ok((tier, msg)) => {
                        if matches!(tier, super::Tier::Client(_)) && matches!(msg, osis_proto::Message::Auth { .. }) {
                            out.push(Action::Authed { conn });
                        }
                        out.push(Action::Request { conn, tier, msg: Box::new(msg) });
                    }
                    Err(r) => refused.push(r),
                },
                ServingOutput::Room { budget } => out.push(Action::Room { conn, budget }),
                ServingOutput::Peer(m) => self.peer_message(conn, *m, out)?,
            }
        }
        // after the answer to the Resume: the shared set's first messages follow it on the wire,
        // so the dialer has begun its own set when they arrive
        if let Some(id) = bound {
            self.bind_record(conn, id, out)?;
        }
        // a relay-only entry: delivered here and passed on (the other served sessions, the
        // hosts of the label), held by nobody (spec/sync.md §5)
        for r in relays {
            self.relay_in(super::memory::RelayFrom::Served(conn), r.label, r.blob_id, r.blob.to_vec(), r.wrap, Some(r.stamp), out)?;
        }
        for (id, code) in refused {
            self.serve_with(conn, ServingInput::Reply { id, reply: Err(code) }, labels, out)?;
        }
        Ok(())
    }

    /// Decides what a served session's client-port request goes up as (notes/client-port.md §3).
    /// A main session's Auth without a secret; a keyed session's with a secret matching a current
    /// `clients^.0` entry, which binds the session to that client actor, its secret stripped;
    /// any other Auth (a second one too) is Error 1. Proto refuses Call, Sub and Unsub before an
    /// answered Auth, so a keyed session never gets further unauthenticated.
    fn admit(&mut self, conn: ConnId, msg: osis_proto::Message) -> std::result::Result<(super::Tier, osis_proto::Message), (osis_proto::msg::Id, osis_proto::Code)> {
        use super::Tier;
        use osis_proto::{Code, Message};
        let tier = self.served.get(&conn).map_or(Tier::Keyed, |s| s.tier);
        let id = msg.id();
        let Message::Auth { secret, session, .. } = msg else {
            return if tier == Tier::Keyed { Err((id, Code::REFUSED)) } else { Ok((tier, msg)) };
        };
        match (tier, secret) {
            (Tier::Main, None) => Ok((tier, Message::Auth { id, secret: None, session })),
            (Tier::Keyed, Some(secret)) => {
                let hash = osis_base::hash::hash(secret.expose());
                let Some((actor, until)) = self.client_entry_by_hash(&hash) else { return Err((id, Code::REFUSED)) };
                let of_it = self.served.values().filter(|s| s.tier == Tier::Client(actor)).count();
                let all = self.served.values().filter(|s| matches!(s.tier, Tier::Client(_))).count();
                if of_it >= super::MAX_CONNS_PER_CLIENT || all >= self.cfg.max_clients {
                    return Err((id, Code::RATE_LIMITED));
                }
                let Some(s) = self.served.get_mut(&conn) else { return Err((id, Code::REFUSED)) };
                s.tier = Tier::Client(actor);
                s.client = Some(ClientBinding { hash, until });
                Ok((s.tier, Message::Auth { id, secret: None, session }))
            }
            _ => Err((id, Code::REFUSED)),
        }
    }

    /// The client listener's key (every transport's key is the Ed25519 key of its secret), while
    /// it has one. Independent of the dialable key, LAN keys and the signing key: nothing links
    /// them (notes/client-port.md §5).
    pub fn client_listen_key(&self) -> Option<[u8; 32]> {
        self.state.client_listen.as_ref().map(|s| osis_crypto::SigningSecret::from_seed(s).verifying_key().to_bytes())
    }

    /// The secret the client listener listens with, made on first use, drawn afresh: it derives
    /// from nothing else. `rotate`: a new one replaces it (the old shredded).
    pub fn client_listen_secret(&mut self, rotate: bool) -> Secret32 {
        if !rotate && let Some(s) = &self.state.client_listen {
            return s.clone();
        }
        let mut b = [0u8; 32];
        self.rng.fill_bytes(&mut b);
        let s = Secret32::from_bytes(b);
        self.state.set_client_listen(Some(s.clone()));
        if let Err(e) = self.state.flush(&mut self.engine) {
            self.diag(format!("sync state: {e}"));
        }
        s
    }

    /// Shreds the client listener's secret: its address is gone for good.
    pub fn drop_client_listen_secret(&mut self) {
        self.state.set_client_listen(None);
        if let Err(e) = self.state.flush(&mut self.engine) {
            self.diag(format!("sync state: {e}"));
        }
    }

    /// This node's `clients^.0`.
    fn client_entries(&mut self) -> BTreeMap<Tid, ct::Client> {
        let me = self.engine.tid();
        self.engine.get_typed(&me, &ct::CLIENTS).ok().flatten().unwrap_or_default()
    }

    /// The current entry (actor, end) whose secret hash is `hash`: every entry compared in
    /// constant time, none skipped.
    fn client_entry_by_hash(&mut self, hash: &[u8; 32]) -> Option<(Tid, Option<u64>)> {
        let now = self.now();
        let probe = Secret32::from_bytes(*hash);
        let mut hit = None;
        for (t, c) in self.client_entries() {
            if Secret32::from_bytes(c.secret_hash) == probe {
                hit = Some((t, c.until.map(|u| u.0)));
            }
        }
        hit.filter(|(_, until)| until.is_none_or(|u| u > now))
    }

    /// The client actor served session `conn` runs as now: none unless the session is bound to
    /// a client whose entry is still there, under the same secret, and not past its `until`.
    /// The port asks at every request and every send, so no answer outlives the entry.
    pub fn client_of(&mut self, conn: ConnId) -> Option<Tid> {
        let now = self.now();
        let (super::Tier::Client(actor), Some(b)) = self.served.get(&conn).map(|s| (s.tier, s.client))? else { return None };
        let e = self.client_entries().remove(&actor)?;
        b.holds(&e, now).then_some(actor)
    }

    /// After a `clients^.0` change: sessions of a client removed, rotated or past its `until` end;
    /// the others take their entry's `until` (the timer `serve_timers` closes them by).
    pub(crate) fn clients_changed(&mut self, out: &mut Vec<Action>) {
        if !self.served.values().any(|s| s.client.is_some()) {
            return;
        }
        let entries = self.client_entries();
        let now = self.now();
        let mut stale = Vec::new();
        for (c, s) in self.served.iter_mut() {
            let (super::Tier::Client(actor), Some(b)) = (s.tier, s.client.as_mut()) else { continue };
            match entries.get(&actor) {
                Some(e) if b.holds(e, now) => b.until = e.until.map(|u| u.0),
                _ => stale.push(*c),
            }
        }
        for c in stale {
            self.close_served(c, out);
        }
    }

    /// After a role or roster change: co-readers that no longer read a label stop counting for
    /// its complete pass (what a session keeps open is the shared set's, `shared_changed`).
    pub(crate) fn holders_changed(&mut self) {
        let peers = self.peers();
        for (l, ks) in self.peer_received.iter_mut() {
            ks.retain(|k| peers.get(k).is_some_and(|p| p.labels.contains(l)));
        }
        self.peer_received.retain(|_, ks| !ks.is_empty());
    }

    /// A served session's `(dialer challenge, listener challenge, listener key)`, once its
    /// Hello arrived.
    pub(crate) fn served_binding(&self, conn: ConnId) -> Option<([u8; 32], [u8; 32], [u8; 32])> {
        self.served.get(&conn).and_then(|s| s.conn.binding())
    }

    pub(crate) fn served_has(&self, conn: ConnId) -> bool {
        self.served.contains_key(&conn)
    }

    pub(crate) fn end_served(&mut self, conn: ConnId, out: &mut Vec<Action>) {
        self.records.conn_gone(conn);
        self.streams.remove(&conn);
        if self.served.remove(&conn).is_some_and(|s| s.ported) {
            out.push(Action::Ended { conn });
        }
    }

    /// Ends served session `conn` from this side.
    pub(crate) fn close_served(&mut self, conn: ConnId, out: &mut Vec<Action>) {
        self.end_served(conn, out);
        out.push(Action::Close { conn });
    }

    /// Closes served sessions without bytes for `SyncConfig.serve_idle_ms` (but those kept while
    /// up), those that serve nothing within `serve_open_ms`, and those whose oldest request of
    /// this node's stalled (`ServingSession::stall_at`); expires the memory log's deletions and this node's
    /// tombstones; forgets carriers and certificate placements nothing needs; prunes charges
    /// and blob sizes.
    pub(crate) fn serve_timers(&mut self, out: &mut Vec<Action>) {
        let now = self.raw_now();
        let (idle, open) = (self.cfg.serve_idle_ms, self.cfg.serve_open_ms);
        let corrected = self.now();
        let stale: Vec<ConnId> = self
            .served
            .iter()
            .filter(|(c, s)| {
                let idled = !self.kept_while_up(**c, s) && s.last.saturating_add(idle) <= now;
                let opened_nothing = self.serves_nothing(**c, s) && s.since.saturating_add(open) <= now;
                // a thin client's `until` passed: no other change is needed to end it
                let ended = s.client.is_some_and(|b| b.until.is_some_and(|u| u <= corrected));
                let stalled = s.conn.stall_at().is_some_and(|t| t <= now);
                idled || opened_nothing || ended || stalled
            })
            .map(|(c, _)| *c)
            .collect();
        for c in stale {
            self.close_served(c, out);
        }
        let wall = self.state.now;
        self.state.mem_log.expire(wall);
        self.state.expire_tombs(wall);
        self.sweep_forgotten();
        // these scan every entry and placement: at most once per `RECORD_SWEEP_MS`
        if wall >= self.swept.saturating_add(RECORD_SWEEP_MS) {
            self.swept = wall;
            self.state.log_sweep_due = true;
            self.state.sweep_carriers(wall);
            let ix = &self.engine.core.ix.commits;
            self.state.sweep_certs(|c| ix.get(c).is_some_and(|m| (0..m.header.aspects.len()).any(|ai| !m.body_gone(ai))));
        }
        if let Err(e) = self.forget_own_covered() {
            self.diag(format!("forget: {e}"));
        }
        self.prune_charges();
        if self.blob_sizes.len() > self.state.entries.len() {
            let held: BTreeSet<BlobId> = self.state.entries.keys().map(|(_, b)| *b).collect();
            self.blob_sizes.retain(|b, _| held.contains(b));
        }
    }

    /// When the next served session goes idle.
    pub(crate) fn serve_wake(&self) -> Option<u64> {
        // a session holding pushes back: `Event::Sent` at the next tick may give them room
        let poll = self.served.values().any(|s| s.conn.held()).then(|| self.raw_now().saturating_add(osis_proto::serving::PUSH_POLL_MS));
        let stall = self.served.values().filter_map(|s| s.conn.stall_at()).min();
        // a thin client's `until`, corrected wall ms, on the raw clock
        let (raw, wall) = (self.raw_now(), self.now());
        let until = self.served.values().filter_map(|s| s.client.and_then(|b| b.until)).map(|u| u.saturating_add(raw).saturating_sub(wall)).min();
        self.served.iter().filter(|(c, s)| !self.kept_while_up(**c, s)).map(|(c, s)| if self.serves_nothing(*c, s) { s.since.saturating_add(self.cfg.serve_open_ms).min(s.last.saturating_add(self.cfg.serve_idle_ms)) } else { s.last.saturating_add(self.cfg.serve_idle_ms) }).chain(poll).chain(until).chain(stall).min()
    }
}

//! Member-peer serving (spec/sync.md §5 last bullet, §10): a node serves the labels it syncs to
//! the peers that dial it, through osis-proto's server engine over its own label state
//! (`PeerStore`, a `LabelStore` over the sync state's entries and the engine's blobs). Opens,
//! stamps and deposits are checked as a blind node checks them, against the registration path
//! recorded in `/label` (the deepest recorded step is the head). Accepted entries go through the
//! same path as downloaded ones; the log is in memory (`Feed`, a fresh log ID per start, so a
//! peer's old cursor replays). A peer's deletion hides the entry from peers only, a registration
//! extends the served path in memory: this node's own state follows its own rules. Entries this
//! node dropped stay refused for `TOMBSTONE_LIFETIME` (`State::tombs`). What peers upload or
//! deposit is charged to the label it went under (dialer keys are fresh per connection) and to a node-wide total (`SyncConfig`
//! `peer_bytes`, `peer_total_bytes`) until it opens, reaches a server or is dropped; past either,
//! uploads get code 12 and deposits code 5. A member proof by the dialable key of a node that
//! currently reads a label opens it (spec/sync.md §5, member peer); budgets are then charged to
//! that dialable key.

use super::state::Entry;
use super::{Action, ConnId, SyncEngine};
use crate::engine::Engine;
use crate::error::Result;
use osis_base::format::TOMBSTONE_LIFETIME_MS;
use osis_base::{BlobId, LabelId};
use osis_label::{ClaimSet, Step, StepId};
use osis_proto::{Budget, Code, EntryMeta, LabelStore, LogRecord, Put, Replaced, ServerConfig, ServerConnection, ServerInput, ServerOutput, StoreError};
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

/// A served label: its group, its path to the head and the claim sets held, with the path
/// indexes an Open or a Path page reads (step ID → position, sync key → newest position) and the
/// head keys, so a peer's request costs no scan of the path.
pub struct ServedLabel {
    group: osis_base::Tid,
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

    /// The path to the deepest step of `steps` (the lowest ID among equals).
    pub(crate) fn new(group: osis_base::Tid, steps: &super::open::Steps) -> Option<ServedLabel> {
        let path: Vec<Step> = super::open::deepest_path(steps)?.into_iter().map(|(s, _)| s.clone()).collect();
        let claims = steps.iter().filter_map(|(id, (_, c))| c.clone().map(|c| (*id, Arc::new(c)))).collect();
        let pos = path.iter().enumerate().map(|(i, s)| (s.id(), i)).collect();
        // later positions overwrite: the newest step per sync key
        let by_sync = path.iter().enumerate().map(|(i, s)| (s.keys.sync.to_bytes(), i)).collect();
        let keys = osis_proto::HeadKeys::of_path(&path);
        Some(ServedLabel { group, path, claims, pos, by_sync, keys })
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

/// What a served request accepted, carried out after the server engine returns.
#[derive(Default)]
struct Accepted {
    entries: Vec<(LabelId, osis_proto::Event)>,
    steps: Vec<(LabelId, Step, Option<ClaimSet>)>,
    /// Bytes charged per accepted entry.
    charges: Vec<(LabelId, BlobId, u64)>,
    /// A put was refused for the budget.
    full: bool,
    /// Entries accepted uploads replaced: hidden from peers (by delete proof), or no longer
    /// sourced by this session (untied), once the uploads are applied.
    removed: Vec<(LabelId, BlobId)>,
    untied: Vec<(LabelId, BlobId)>,
}

/// The `LabelStore` a member peer serves from.
struct PeerStore<'a> {
    engine: RefCell<&'a mut Engine>,
    entries: &'a BTreeMap<(LabelId, BlobId), Entry>,
    tombs: &'a BTreeMap<(LabelId, BlobId), u64>,
    feed: &'a mut Feed,
    labels: &'a BTreeMap<LabelId, ServedLabel>,
    /// Node things by dialable key (`reach_nodes`): whose member proofs count.
    reach: &'a BTreeMap<[u8; 32], osis_base::Tid>,
    /// Blob sizes seen (`live` reads a blob only once).
    sizes: RefCell<&'a mut BTreeMap<BlobId, u64>>,
    now: u64,
    /// Corrected wall ms (tombstones of this node's drops).
    wall: u64,
    /// What is charged so far per charge key (`charge_key`), its limit, the session's member
    /// key, and this request's charges per key; all peers together may still have `total_left`.
    charged: &'a BTreeMap<[u8; 32], u64>,
    limit: u64,
    member: Option<[u8; 32]>,
    used_here: BTreeMap<[u8; 32], u64>,
    total_left: u64,
    acc: Accepted,
    /// Ephemeral entries held in memory (`ephemeral`): served like the others.
    eph: &'a super::ephemeral::Lane,
    relays: &'a mut osis_proto::RelayGate,
    /// The session served (its tie to the presence entries it uploads).
    conn: ConnId,
}

/// Whom bytes a peer session put here are charged to: the dialable key its member proof
/// proved, else the label they went under (a dialer key is fresh per connection, so charging
/// it would bound nothing: a link holder's sessions share its K label's budget).
fn charge_key(member: Option<[u8; 32]>, label: &LabelId) -> [u8; 32] {
    member.unwrap_or_else(|| {
        let mut k = [0xff; 32];
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
        let log = self.feed.labels.get(l);
        if let Some(e) = self.eph.entries.get(&(*l, *b)) {
            if log.is_some_and(|x| x.hidden(b, self.now)) {
                return Ok(None);
            }
            return Ok(Some(EntryMeta { wrap: e.wrap, stamp: e.stamp, size: e.blob.len() as u64, add_seq: log.and_then(|x| x.adds.get(b)).copied().unwrap_or(0), pending_delete: None }));
        }
        let Some(e) = self.entries.get(&(*l, *b)) else { return Ok(None) };
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
        // dropped here (a server's deletion, our own delete or drop): never back from a peer
        if self.tombs.get(&(*label, *blob_id)).is_some_and(|t| t.saturating_add(TOMBSTONE_LIFETIME_MS) > self.wall) {
            return Ok(true);
        }
        let Some(x) = self.feed.labels.get(label) else { return Ok(false) };
        let at = x.gone.get(blob_id).copied().or_else(|| x.pending.get(blob_id).copied().filter(|t| *t <= self.now));
        Ok(at.is_some_and(|t| t.saturating_add(TOMBSTONE_LIFETIME_MS) > self.now))
    }

    fn blob(&self, blob_id: &BlobId) -> std::result::Result<Option<Vec<u8>>, StoreError> {
        if let Some((_, l)) = self.eph.by_blob.range((*blob_id, LabelId([0; 16]))..).next().filter(|(b, _)| b == blob_id)
            && let Some(e) = self.eph.entries.get(&(*l, *blob_id))
        {
            return Ok(Some(e.blob.clone()));
        }
        self.engine.borrow_mut().blob(blob_id).map_err(local)
    }

    fn put(&mut self, label: &LabelId, put: Put<'_>) -> std::result::Result<Code, StoreError> {
        // replacements (spec/sync.md §5): an untie only of a presence entry this session uploaded
        // (any other is skipped)
        let (mut removed, mut untied) = (Vec::new(), Vec::new());
        for r in put.replaces {
            match *r {
                Replaced::Delete(b) if b != put.blob_id && self.live(label, &b)?.is_some() => removed.push((*label, b)),
                Replaced::Untie(b) if b != put.blob_id && self.eph.served_src.get(&(*label, b)).is_some_and(|cs| cs.contains(&self.conn)) => untied.push((*label, b)),
                _ => {}
            }
        }
        // a held entry costs nothing more (a new wrap or a stamp)
        if !self.entries.contains_key(&(*label, put.blob_id)) {
            let size = put.blob.len() as u64;
            let key = charge_key(self.member, label);
            if size > self.limit.saturating_sub(self.used(&key)) || size > self.total_left {
                self.acc.full = true;
                return Ok(if put.stamp.is_some() { Code::STORAGE_CAP } else { Code::BUDGET_FULL });
            }
            *self.used_here.entry(key).or_default() += size;
            self.total_left -= size;
            self.acc.charges.push((*label, put.blob_id, size));
        }
        if let Some(x) = self.feed.labels.get_mut(label) {
            x.gone.remove(&put.blob_id);
            x.pending.remove(&put.blob_id);
        }
        self.acc.entries.push((*label, osis_proto::Event::Added { blob_id: put.blob_id, blob: Some(put.blob.to_vec()), wrap: put.wrap, stamp: put.stamp }));
        self.acc.removed.extend(removed);
        self.acc.untied.extend(untied);
        Ok(Code::OK)
    }

    fn budget(&self, label: &LabelId) -> std::result::Result<Budget, StoreError> {
        let bytes_left = self.limit.saturating_sub(self.used(&charge_key(self.member, label))).min(self.total_left);
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
        let mut ids: BTreeSet<BlobId> = BTreeSet::new();
        for ((l, b), _) in self.entries.range((*label, start)..) {
            if l != label || ids.len() >= max.saturating_add(1) {
                break;
            }
            ids.insert(*b);
        }
        for (b, _) in SyncEngine::eph_entries_of(self.eph, label).filter(|(b, _)| *b >= start).take(max.saturating_add(1)) {
            ids.insert(b);
        }
        let mut out = Vec::new();
        for b in ids {
            if out.len() >= max {
                break;
            }
            if after == Some(&b) {
                continue;
            }
            if let Some(m) = self.live(label, &b)? {
                out.push((b, m));
            }
        }
        Ok(out)
    }

    /// Unused: the sync engine drops a presence entry a session uploaded once no source holds
    /// it (`eph_served_gone`, `eph_presence`).
    fn untie(&mut self, _label: &LabelId, _blob_id: &BlobId, _tie: u64) -> std::result::Result<bool, StoreError> {
        Ok(false)
    }

    fn relay(&mut self, label: &LabelId, blob_id: &BlobId, size: usize, expiry: Option<u64>, _now: u64) -> std::result::Result<osis_proto::RelayVerdict, StoreError> {
        // expiry is wall time: the corrected clock
        Ok(self.relays.admit(label, blob_id, size, expiry, self.wall))
    }

    fn live_ids_in(&self, label: &LabelId, lower: &BlobId, upper: Option<&BlobId>) -> std::result::Result<Vec<BlobId>, StoreError> {
        let below = |b: &BlobId| upper.is_none_or(|u| b < u);
        let mut ids: BTreeSet<BlobId> = self.entries.range((*label, *lower)..).take_while(|((l, b), _)| l == label && below(b)).map(|((_, b), _)| *b).collect();
        ids.extend(self.eph.entries.range((*label, *lower)..).take_while(|((l, b), _)| l == label && below(b)).map(|((_, b), _)| *b));
        let mut out = Vec::new();
        for b in ids {
            if self.live(label, &b)?.is_some() {
                out.push(b);
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
    /// as `Event::Bytes`, its end as `Event::Down`) and the actions (the Hello). With
    /// `SyncConfig.max_served` sessions running, the oldest one that has opened nothing is
    /// closed to make room (dialer keys are ephemeral, so a per-key cap would bind nothing);
    /// when every one has opened a label, this one is closed. Opens are
    /// checked as a blind node checks them, plus member proofs by the dialable key of a node
    /// thing currently reading the label (spec/sync.md §5).
    pub fn accept(&mut self, local: [u8; 32], peer: [u8; 32]) -> (ConnId, Vec<Action>) {
        let conn = self.next_conn;
        self.next_conn += 1;
        let mut out = Vec::new();
        if self.served.len() >= self.cfg.max_served {
            let idle = self.served.iter().filter(|(_, s)| s.conn.none_opened()).min_by_key(|(c, s)| (s.since, **c)).map(|(c, _)| *c);
            match idle {
                Some(old) => {
                    self.served.remove(&old);
                    self.eph_served_gone(old);
                    out.push(Action::Close { conn: old });
                }
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
        self.served.insert(conn, Served { conn: ServerConnection::new(ServerConfig { static_key: local, challenge, tie: conn }), peer, last, since: last });
        if let Err(e) = self.serve(conn, ServerInput::Start, &mut out) {
            self.diag(format!("serve: {e}"));
        }
        let _ = self.state.flush(&mut self.engine);
        (conn, out)
    }

    /// Label IDs opened on each served session (tests, diagnostics).
    pub fn served_opened(&self) -> BTreeMap<ConnId, BTreeSet<LabelId>> {
        self.served.iter().map(|(c, s)| (*c, s.conn.opened().copied().collect())).collect()
    }

    /// The dialable keys member proofs proved on the sessions served now (spec/sync.md §5).
    pub fn served_members(&self) -> BTreeSet<[u8; 32]> {
        self.served.values().filter_map(|s| s.conn.member()).collect()
    }

    /// The labels this node serves: those it syncs, at the deepest recorded step (and the steps
    /// peers registered here since start). Cached until `/label`, membership or the peer steps
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
            if let Some(s) = ServedLabel::new(gl.group, &steps) {
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
    pub(crate) fn serve(&mut self, conn: ConnId, input: ServerInput, out: &mut Vec<Action>) -> Result<()> {
        let labels = self.served_labels();
        self.serve_with(conn, input, &labels, out)
    }

    pub(crate) fn serve_with(&mut self, conn: ConnId, input: ServerInput, labels: &BTreeMap<LabelId, ServedLabel>, out: &mut Vec<Action>) -> Result<()> {
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
                charged: &self.charges.per,
                limit: self.cfg.peer_bytes,
                member: s.conn.member(),
                used_here: BTreeMap::new(),
                total_left: self.cfg.peer_total_bytes.saturating_sub(total),
                acc: Accepted::default(),
                eph: &self.eph,
                relays: &mut self.relay_gate,
                conn,
            };
            let o = s.conn.handle(now, &mut store, input);
            (o, store.acc)
        };
        let peer = s.conn.member().unwrap_or(s.peer);
        let proven = s.conn.member();
        let member = proven.is_some_and(|k| reach.contains_key(&k));
        if s.conn.is_closed() {
            self.eph_served_gone(conn);
        } else {
            self.served.insert(conn, s);
        }
        self.charges.full |= acc.full;
        for (l, b, n) in acc.charges {
            self.charges.charge(l, b, charge_key(proven, &l), n);
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
            self.log_events_from(None, Some(conn), l, evs, None, out)?;
        }
        // what the uploads replaced goes after them (peers see the new entry first)
        for (l, b) in acc.removed {
            let x = self.state.feed.labels.entry(l).or_default();
            if x.gone.insert(b, now).is_none() {
                self.state.feed.deleted(l, b);
            }
        }
        for k in acc.untied {
            if let Some(cs) = self.eph.served_src.get_mut(&k) {
                cs.remove(&conn);
                if cs.is_empty() {
                    self.eph.served_src.remove(&k);
                }
            }
        }
        let mut relays = Vec::new();
        for o in outputs {
            match o {
                ServerOutput::Send(bytes) => out.push(Action::Send { conn, bytes }),
                ServerOutput::Close => out.push(Action::Close { conn }),
                ServerOutput::Changed(l) => {
                    self.state.feed.grown.insert(l);
                }
                ServerOutput::Relay(r) => relays.push(r),
                ServerOutput::PeerError(e) => self.diag(format!("peer: {e}")),
                ServerOutput::StoreError(e) => self.diag(format!("serve: {e}")),
            }
        }
        // a relay-only entry: delivered here and passed on (the other served sessions, the
        // servers of the label), held by nobody (spec/sync.md §5)
        for r in relays {
            self.relay_in(super::ephemeral::RelayFrom::Served(conn), r.label, r.blob_id, r.blob, r.wrap, Some(r.stamp), out)?;
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
                s.conn.opened().any(|l| labels.get(l).is_some_and(|x| node.is_none_or(|n| !self.engine.may_read(n, &x.group))))
            })
            .map(|(c, _)| *c)
            .collect();
        for c in stale {
            self.served.remove(&c);
            self.eph_served_gone(c);
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
        let stale: Vec<ConnId> = self.served.iter().filter(|(_, s)| s.last.saturating_add(idle) <= now || s.conn.none_opened() && s.since.saturating_add(open) <= now).map(|(c, _)| *c).collect();
        for c in stale {
            self.served.remove(&c);
            self.eph_served_gone(c);
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
        // a session holding pushes back: `Event::Sent` at the next tick may give them room
        let poll = self.served.values().any(|s| s.conn.held()).then(|| self.raw_now().saturating_add(osis_proto::server::PUSH_POLL_MS));
        self.served.values().map(|s| if s.conn.none_opened() { s.since.saturating_add(self.cfg.serve_open_ms).min(s.last.saturating_add(self.cfg.serve_idle_ms)) } else { s.last.saturating_add(self.cfg.serve_idle_ms) }).chain(poll).min()
    }
}

//! `BackendStore`: osis-proto's `LabelStore` over an osis-store `Backend` (spec/sync.md §4, §5):
//! registration paths, entries, tombstones, per-label logs, blob bytes stored once with reference
//! counts, timed deletes, expiry, claim-set retention, and the server policy (storage caps,
//! deposit budget, rate limits). Every mutation is one atomic `WriteBatch`.
//!
//! Rows (all cleartext metadata a blind node sees anyway; blobs are ciphertext):
//! `I` seed; `L label` meta; `S label step` step; `C label step` claim set; `E label blob` entry;
//! `T label blob` tombstone time; `G label seq` log record; `R blob` reference count;
//! sweep indexes `X t label blob` (expiry), `P t label blob` (pending deletion),
//! `Y t label blob` (tombstone drop), `Z t label step` (claim-set drop);
//! `Q peer label` replication position; `N` node-wide totals (labels, entries, bytes).
//!
//! Ephemeral entries (blob prefix class ephemeral, spec/sync.md §4) are held in memory only:
//! entry, blob, log records and tombstones; a restart loses them. Their log records take
//! sequence numbers from the label's log, reserved on disk in blocks (`SEQ_BLOCK`, the label
//! meta's `reserved`), so no number handed out before a restart is handed out again.

use osis_base::format::{MAX_DRIFT_MS, MEMBERSHIP_KEEP_MS, TOMBSTONE_LIFETIME_MS};
use osis_base::{BlobId, Clock, LabelId};
use osis_crypto::{CryptoRngCore, Signature};
use osis_proto::msg::{ClaimSet, Code, Step, StepId, WRAP_LEN};
use osis_proto::{Budget, EntryMeta, LabelStore, LogRecord, Put, StoreError};
use osis_store::{Backend, BackendError, KeyValue, WriteBatch};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

/// Deposit budget unit (spec/sync.md §5 recommended minimum).
pub const DEPOSIT_ENTRY_BYTES: u64 = 32 * 1024;

/// Server policy (spec/sync.md §5: caps, budget, rate limits; notes/sync.md Policy defaults).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Live entries per label beyond which new entries get code 12.
    pub cap_entries: u64,
    /// Live entry bytes per label beyond which new entries get code 12.
    pub cap_bytes: u64,
    /// Deposit budget = this × (64 + 4 × head claim slots) entries, × 32 KiB bytes; at least 1.
    pub deposit_factor: u64,
    /// A claim set is kept this long after its step is superseded (at least `MEMBERSHIP_KEEP`).
    pub claim_keep_ms: u64,
    pub tombstone_ms: u64,
    /// Log records kept per label; older ones are dropped (cursors below fall back to reconciliation).
    pub log_keep: u64,
    /// Rate-limit window.
    pub window_ms: u64,
    /// Per label and window.
    pub deletes: u32,
    pub replacements: u32,
    pub deposits: u32,
    /// Ephemeral entry bytes held per label, and over all labels (in memory): ephemeral uploads
    /// beyond either get code 12 (notes/ephemeral.md Bounds).
    pub ephemeral_bytes: u64,
    pub ephemeral_total: u64,
    /// Wrap replacements per entry and window.
    pub entry_replacements: u32,
    /// Relay-only uploads pushed per label and window, and their bytes (`osis_proto::RelayLimits`).
    pub relays: u32,
    pub relay_bytes: u64,
    /// Node-wide caps: new entries beyond them get code 12, new labels Error 12.
    pub max_labels: u64,
    pub max_entries: u64,
    pub max_bytes: u64,
    /// Connections served at once (the driver closes any beyond).
    pub max_connections: usize,
    /// A connection without the peer's Hello this long after accept is closed.
    pub hello_ms: u64,
    /// Bytes queued for one connection beyond which it is dropped (a peer that does not read).
    pub max_queued_bytes: usize,
    /// Partially received frame bytes over all connections beyond which the connection holding
    /// the largest partial frame is closed.
    pub max_buffered_bytes: usize,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            cap_entries: 1 << 20,
            cap_bytes: 16 << 30,
            deposit_factor: 1,
            claim_keep_ms: MEMBERSHIP_KEEP_MS,
            tombstone_ms: TOMBSTONE_LIFETIME_MS,
            log_keep: 1 << 20,
            window_ms: 60_000,
            deletes: 20_000,
            replacements: 20_000,
            deposits: 600,
            ephemeral_bytes: 16 << 20,
            ephemeral_total: 1 << 30,
            entry_replacements: 4,
            relays: osis_proto::RelayLimits::default().count,
            relay_bytes: osis_proto::RelayLimits::default().bytes,
            max_labels: 1 << 20,
            max_entries: 1 << 26,
            max_bytes: 256 << 30,
            max_connections: 10_000,
            hello_ms: 10_000,
            max_queued_bytes: 32 << 20,
            max_buffered_bytes: 512 << 20,
        }
    }
}

impl Policy {
    /// No limits beyond the spec's minimum budget (tests comparing with `MemoryLabelStore`).
    pub fn unlimited() -> Policy {
        Policy {
            cap_entries: u64::MAX,
            cap_bytes: u64::MAX,
            log_keep: u64::MAX,
            deletes: u32::MAX,
            replacements: u32::MAX,
            deposits: u32::MAX,
            ephemeral_bytes: u64::MAX,
            ephemeral_total: u64::MAX,
            entry_replacements: u32::MAX,
            relays: u32::MAX,
            relay_bytes: u64::MAX,
            max_labels: u64::MAX,
            max_entries: u64::MAX,
            max_bytes: u64::MAX,
            ..Policy::default()
        }
    }
}

fn err(e: BackendError) -> StoreError {
    StoreError(e.to_string())
}

fn corrupt(what: &str) -> StoreError {
    StoreError(format!("corrupt {what}"))
}

fn unknown() -> StoreError {
    StoreError("unknown label".into())
}

fn key(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut k = vec![tag];
    for p in parts {
        k.extend_from_slice(p);
    }
    k
}

fn be(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

fn read_u64(b: &[u8], at: usize) -> Result<u64, StoreError> {
    let s: [u8; 8] = b.get(at..at + 8).and_then(|s| s.try_into().ok()).ok_or_else(|| corrupt("row"))?;
    Ok(u64::from_be_bytes(s))
}

fn read_arr<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N], StoreError> {
    b.get(at..at + N).and_then(|s| s.try_into().ok()).ok_or_else(|| corrupt("row"))
}

/// Per-label counters and positions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Meta {
    log_id: [u8; 16],
    head: Option<StepId>,
    next_seq: u64,
    /// Records at or below this sequence number were dropped.
    horizon: u64,
    head_claims: u64,
    entries: u64,
    bytes: u64,
    dep_n: u64,
    dep_bytes: u64,
    /// Sequence numbers up to this one may have gone to ephemeral log records (in memory).
    reserved: u64,
    /// Durable log records held (`G` rows): ephemeral records and reserved numbers take
    /// sequence numbers too, so the span `next_seq - horizon` does not count them.
    records: u64,
}

const META_LEN: usize = 16 + 1 + 32 + 8 * 9;

/// Sequence numbers reserved on disk at a time for ephemeral log records. Performance switch
/// (notes/arbitrary-values.md): 1 writes the label meta per ephemeral upload, a large block skips
/// that many numbers after a restart (harmless: cursors only compare).
const SEQ_BLOCK: u64 = 1024;

impl Meta {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(META_LEN);
        v.extend_from_slice(&self.log_id);
        v.push(u8::from(self.head.is_some()));
        v.extend_from_slice(&self.head.map_or([0; 32], |h| h.0));
        for n in [self.next_seq, self.horizon, self.head_claims, self.entries, self.bytes, self.dep_n, self.dep_bytes, self.reserved, self.records] {
            v.extend_from_slice(&be(n));
        }
        v
    }

    fn decode(b: &[u8]) -> Result<Meta, StoreError> {
        if b.len() != META_LEN {
            return Err(corrupt("label meta"));
        }
        let n = |i: usize| read_u64(b, 49 + 8 * i);
        Ok(Meta {
            log_id: read_arr(b, 0)?,
            head: (b.get(16) == Some(&1)).then(|| read_arr(b, 17).map(StepId)).transpose()?,
            next_seq: n(0)?,
            horizon: n(1)?,
            head_claims: n(2)?,
            entries: n(3)?,
            bytes: n(4)?,
            dep_n: n(5)?,
            dep_bytes: n(6)?,
            reserved: n(7)?,
            records: n(8)?,
        })
    }
}

/// A stored entry: the engine's view plus its expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    meta: EntryMeta,
    expiry: Option<u64>,
}

const ROW_LEN: usize = WRAP_LEN + 1 + 64 + 8 * 4;

impl Row {
    fn encode(&self) -> Vec<u8> {
        let m = &self.meta;
        let mut v = Vec::with_capacity(ROW_LEN);
        v.extend_from_slice(&m.wrap);
        v.push(u8::from(m.stamp.is_some()) | u8::from(m.pending_delete.is_some()) << 1 | u8::from(self.expiry.is_some()) << 2);
        v.extend_from_slice(&m.stamp.map_or([0; 64], |s| s.0));
        for n in [m.size, m.add_seq, m.pending_delete.unwrap_or(0), self.expiry.unwrap_or(0)] {
            v.extend_from_slice(&be(n));
        }
        v
    }

    fn decode(b: &[u8]) -> Result<Row, StoreError> {
        if b.len() != ROW_LEN {
            return Err(corrupt("entry"));
        }
        let flags = b.get(WRAP_LEN).copied().unwrap_or(0);
        let at = WRAP_LEN + 1 + 64;
        let opt = |bit: u8, v: u64| (flags & bit != 0).then_some(v);
        Ok(Row {
            meta: EntryMeta {
                wrap: read_arr(b, 0)?,
                stamp: opt(1, 0).map(|_| read_arr(b, WRAP_LEN + 1).map(Signature)).transpose()?,
                size: read_u64(b, at)?,
                add_seq: read_u64(b, at + 8)?,
                pending_delete: opt(2, read_u64(b, at + 16)?),
            },
            expiry: opt(4, read_u64(b, at + 24)?),
        })
    }
}

fn encode_record(r: &LogRecord) -> Vec<u8> {
    match r {
        LogRecord::Added(b) => key(0, &[&b.0]),
        LogRecord::Deleted(b) => key(1, &[&b.0]),
        LogRecord::Pending(b, at) => key(2, &[&b.0, &be(*at)]),
        LogRecord::Head(s) => key(3, &[&s.to_bytes()]),
    }
}

fn decode_record(b: &[u8]) -> Result<LogRecord, StoreError> {
    let id = || read_arr(b, 1).map(BlobId);
    Ok(match b.first() {
        Some(0) => LogRecord::Added(id()?),
        Some(1) => LogRecord::Deleted(id()?),
        Some(2) => LogRecord::Pending(id()?, read_u64(b, 33)?),
        Some(3) => LogRecord::Head(Step::parse(b.get(1..).unwrap_or(&[])).map_err(|_| corrupt("step"))?),
        _ => return Err(corrupt("log record")),
    })
}

/// Rate-limited operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Rate {
    Delete,
    Replace,
    Deposit,
}

/// One ephemeral entry (in memory).
#[derive(Clone, Debug)]
struct EphEntry {
    meta: EntryMeta,
    expiry: Option<u64>,
}

/// An ephemeral log record (in memory): no head records go here, so no parsed step.
#[derive(Clone, Copy, Debug)]
enum EphRec {
    Added(BlobId),
    Deleted(BlobId),
    Pending(BlobId, u64),
}

impl EphRec {
    fn record(self) -> LogRecord {
        match self {
            EphRec::Added(b) => LogRecord::Added(b),
            EphRec::Deleted(b) => LogRecord::Deleted(b),
            EphRec::Pending(b, t) => LogRecord::Pending(b, t),
        }
    }
}

/// A label's ephemeral entries, tombstones and log records (in memory).
#[derive(Debug, Default)]
struct EphLabel {
    entries: BTreeMap<BlobId, EphEntry>,
    /// Entries by their latest add's sequence number, oldest first (eviction order).
    order: BTreeMap<u64, BlobId>,
    /// Deleted ephemeral entries: when their tombstone goes.
    tombstones: BTreeMap<BlobId, u64>,
    log: std::collections::VecDeque<(u64, EphRec)>,
    /// Ephemeral records at or below this sequence number were dropped.
    horizon: u64,
    /// Memory charged to the label's cap: blobs, per-entry and per-record overhead.
    bytes: u64,
    /// Memory of its tombstones (charged to the node-wide total only).
    tombs: u64,
}

/// Memory charged per ephemeral entry besides its blob bytes: the entry map's key and value
/// (about 170 bytes), the blob map's entry, the eviction order and due-time index entries and an
/// origin entry, each with its map's node overhead (checked against the type sizes by
/// `overheads_cover_the_structures`). Not a tunable: what an entry really costs.
const ENTRY_OVERHEAD: u64 = 768;
/// Memory charged per ephemeral tombstone (map entry and due-time index entry).
const TOMB_OVERHEAD: u64 = 160;
/// Memory charged per ephemeral log record.
const REC_OVERHEAD: u64 = 96;

/// Ephemeral log records kept per label (a cursor below them replays). Resource bound, charged
/// to the label's ephemeral bytes besides (0: every cursor replays; infinity: bounded by the
/// cap alone, and a full label trims its log first).
const EPH_LOG_KEEP: usize = 1 << 16;

/// How long a deleted ephemeral entry stays refused (its tombstone, in memory). Minor
/// consequence: past it a holder that missed the deletion may upload the entry again, and the
/// next writer that finds it covered deletes it again; 0: such re-uploads at once; infinity
/// (the durable `TOMBSTONE_LIFETIME`, 30 days): memory grows with every ephemeral delete.
const EPH_TOMBSTONE_MS: u64 = MAX_DRIFT_MS;

/// The ephemeral side of the store (in memory).
#[derive(Debug, Default)]
struct Ephemeral {
    labels: HashMap<LabelId, EphLabel>,
    blobs: HashMap<BlobId, (Vec<u8>, usize)>,
    /// The log's next sequence number for labels with ephemeral records since start.
    seq: HashMap<LabelId, u64>,
    /// Memory charged over all labels, and the labels by their charge (eviction picks the
    /// largest).
    total: u64,
    by_bytes: BTreeSet<(u64, LabelId)>,
    /// Due times: entry expiries, timed deletes, tombstone drops (stale ones are skipped).
    due: BTreeSet<(u64, LabelId, BlobId)>,
}

impl Ephemeral {
    /// Charges `n` bytes to label `l`: to its cap (`tomb` false) or, for tombstones, to the
    /// node-wide total only (a writer's deletes must not fill the label it compacts: the total
    /// bounds them, the label charged most giving way).
    fn charge(&mut self, l: &LabelId, n: u64, tomb: bool) {
        let e = self.labels.entry(*l).or_default();
        self.by_bytes.remove(&(e.bytes.saturating_add(e.tombs), *l));
        if tomb {
            e.tombs = e.tombs.saturating_add(n);
        } else {
            e.bytes = e.bytes.saturating_add(n);
        }
        self.by_bytes.insert((e.bytes.saturating_add(e.tombs), *l));
        self.total = self.total.saturating_add(n);
    }

    fn release(&mut self, l: &LabelId, n: u64, tomb: bool) {
        let Some(e) = self.labels.get_mut(l) else { return };
        self.by_bytes.remove(&(e.bytes.saturating_add(e.tombs), *l));
        if tomb {
            e.tombs = e.tombs.saturating_sub(n);
        } else {
            e.bytes = e.bytes.saturating_sub(n);
        }
        let all = e.bytes.saturating_add(e.tombs);
        if all > 0 {
            self.by_bytes.insert((all, *l));
        }
        self.total = self.total.saturating_sub(n);
    }

    /// Drops the label's oldest log record (cursors below it replay). Whether one was there.
    fn trim_log(&mut self, l: &LabelId) -> bool {
        let Some(e) = self.labels.get_mut(l) else { return false };
        let Some((s, _)) = e.log.pop_front() else { return false };
        e.horizon = s;
        self.release(l, REC_OVERHEAD, false);
        true
    }
}

/// How an ephemeral entry goes (`BackendStore::eph_remove`).
#[derive(Clone, Copy, Debug)]
enum EphRemove {
    Expire,
    Delete(u64),
    Evict,
}

/// Fixed-window counters, kept in memory only (a restart resets them).
#[derive(Debug, Default)]
struct Rates {
    window: u64,
    labels: HashMap<(LabelId, Rate), u32>,
    entries: HashMap<(LabelId, BlobId), u32>,
}

impl Rates {
    fn roll(&mut self, now: u64, window_ms: u64) {
        let w = now / window_ms.max(1);
        if w != self.window {
            self.window = w;
            self.labels.clear();
            self.entries.clear();
        }
    }

    /// Counts one operation; false when over `limit`.
    fn take(&mut self, label: &LabelId, rate: Rate, limit: u32) -> bool {
        let n = self.labels.entry((*label, rate)).or_insert(0);
        if *n >= limit {
            return false;
        }
        *n += 1;
        true
    }
}

/// One mutation: the label's meta, its row writes and log appends, committed as one batch.
struct Tx {
    label: LabelId,
    meta: Meta,
    /// Entries and bytes before this mutation, and whether the label is new (node totals).
    before: (u64, u64, bool),
    batch: WriteBatch,
    grew: bool,
}

impl Tx {
    fn append(&mut self, r: &LogRecord) -> u64 {
        self.meta.next_seq += 1;
        self.meta.records += 1;
        self.batch.put(key(b'G', &[&self.label.0, &be(self.meta.next_seq)]), encode_record(r));
        self.grew = true;
        self.meta.next_seq
    }
}

/// Node-wide totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub labels: u64,
    pub entries: u64,
    pub bytes: u64,
}

/// What a bounded sweep did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// Labels whose logs grew (timed deletes ran).
    pub grew: BTreeSet<LabelId>,
    /// The budget ran out with due work left.
    pub more: bool,
}

/// Remembered entry origins (in memory) beyond which the map is cleared.
const MAX_ORIGINS: usize = 1 << 20;

/// `LabelStore` over a `Backend`. Holds the backend, the clock for rate windows and supersession
/// times, and the policy.
pub struct BackendStore<B: Backend> {
    backend: B,
    seed: [u8; 32],
    clock: Arc<dyn Clock>,
    policy: Policy,
    rates: Rates,
    /// Peer key of the connection whose request is being handled (set by the hub).
    origin: Option<[u8; 32]>,
    /// Who last added or replaced an entry, when known: replication skips sending it back.
    origins: HashMap<(LabelId, BlobId), [u8; 32]>,
    eph: Ephemeral,
    relays: osis_proto::RelayGate,
}

impl<B: Backend> BackendStore<B> {
    /// Opens the store on `backend`, creating the instance seed (log IDs derive from it) with
    /// `rng` on first use.
    pub fn open(mut backend: B, clock: Arc<dyn Clock>, policy: Policy, rng: &mut dyn CryptoRngCore) -> Result<BackendStore<B>, StoreError> {
        let seed = match backend.get(b"I").map_err(err)? {
            Some(s) => s.as_slice().try_into().map_err(|_| corrupt("seed"))?,
            None => {
                let mut s = [0u8; 32];
                rng.fill_bytes(&mut s);
                let mut b = WriteBatch::new();
                b.put(b"I".to_vec(), s.to_vec());
                backend.commit(b).map_err(err)?;
                s
            }
        };
        let mut policy = policy;
        policy.tombstone_ms = policy.tombstone_ms.max(TOMBSTONE_LIFETIME_MS);
        let relays = osis_proto::RelayGate::new(osis_proto::RelayLimits { count: policy.relays, bytes: policy.relay_bytes, window_ms: policy.window_ms });
        Ok(BackendStore { backend, seed, clock, policy, rates: Rates::default(), origin: None, origins: HashMap::new(), eph: Ephemeral::default(), relays })
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The peer key of the connection whose requests follow (none: unknown).
    pub fn set_origin(&mut self, peer: Option<[u8; 32]>) {
        self.origin = peer;
    }

    /// The peer key an entry's current wrap and stamp came from, if remembered.
    pub fn origin(&self, label: &LabelId, blob: &BlobId) -> Option<[u8; 32]> {
        self.origins.get(&(*label, *blob)).copied()
    }

    pub fn totals(&self) -> Result<Totals, StoreError> {
        let Some(b) = self.backend.get(b"N").map_err(err)? else { return Ok(Totals::default()) };
        Ok(Totals { labels: read_u64(&b, 0)?, entries: read_u64(&b, 8)?, bytes: read_u64(&b, 16)? })
    }

    fn now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    /// The label's meta with its log position past every ephemeral record handed out (this run's,
    /// or reserved before a restart).
    fn meta(&self, label: &LabelId) -> Result<Option<Meta>, StoreError> {
        let Some(mut m) = self.raw_meta(label)? else { return Ok(None) };
        m.next_seq = match self.eph.seq.get(label) {
            Some(s) => m.next_seq.max(*s),
            None => m.next_seq.max(m.reserved),
        };
        Ok(Some(m))
    }

    fn raw_meta(&self, label: &LabelId) -> Result<Option<Meta>, StoreError> {
        self.backend.get(&key(b'L', &[&label.0])).map_err(err)?.map(|b| Meta::decode(&b)).transpose()
    }

    /// Ephemeral memory charged per label: blobs and per-entry, per-tombstone and per-record
    /// overhead (tests, diagnostics).
    pub fn ephemeral_bytes(&self, label: &LabelId) -> u64 {
        self.eph.labels.get(label).map_or(0, |e| e.bytes)
    }

    /// Ephemeral memory charged over all labels (tests, diagnostics).
    pub fn ephemeral_total(&self) -> u64 {
        self.eph.total
    }

    /// Appends an ephemeral log record (in memory), reserving sequence numbers on disk as needed.
    fn eph_append(&mut self, label: &LabelId, r: EphRec) -> Result<u64, StoreError> {
        let m = self.meta(label)?.ok_or_else(unknown)?;
        let seq = m.next_seq.saturating_add(1);
        if seq > m.reserved {
            let mut raw = self.raw_meta(label)?.ok_or_else(unknown)?;
            raw.reserved = seq.saturating_add(SEQ_BLOCK);
            let mut b = WriteBatch::new();
            b.put(key(b'L', &[&label.0]), raw.encode());
            self.backend.commit(b).map_err(err)?;
        }
        self.eph.seq.insert(*label, seq);
        self.eph.labels.entry(*label).or_default().log.push_back((seq, r));
        self.eph.charge(label, REC_OVERHEAD, false);
        if self.eph.labels.get(label).is_some_and(|e| e.log.len() > EPH_LOG_KEEP) {
            self.eph.trim_log(label);
        }
        Ok(seq)
    }

    /// Removes an ephemeral entry: silently (expiry), with a tombstone and a log record (a
    /// delete), or with a log record only (evicted for the node-wide cap: holders may bring it
    /// back).
    fn eph_remove(&mut self, label: &LabelId, blob: &BlobId, how: EphRemove) -> Result<bool, StoreError> {
        let Some(e) = self.eph.labels.get_mut(label) else { return Ok(false) };
        let Some(x) = e.entries.remove(blob) else { return Ok(false) };
        e.order.remove(&x.meta.add_seq);
        for t in [x.expiry, x.meta.pending_delete].into_iter().flatten() {
            self.eph.due.remove(&(t, *label, *blob));
        }
        self.eph.release(label, x.meta.size.saturating_add(ENTRY_OVERHEAD), false);
        if let Some((_, n)) = self.eph.blobs.get_mut(blob) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.eph.blobs.remove(blob);
            }
        }
        match how {
            EphRemove::Expire => {}
            EphRemove::Delete(now) => {
                let drop = now.saturating_add(EPH_TOMBSTONE_MS);
                if let Some(old) = self.eph.labels.entry(*label).or_default().tombstones.insert(*blob, drop) {
                    self.eph.due.remove(&(old, *label, *blob));
                } else {
                    self.eph.charge(label, TOMB_OVERHEAD, true);
                }
                self.eph.due.insert((drop, *label, *blob));
                self.eph_append(label, EphRec::Deleted(*blob))?;
            }
            EphRemove::Evict => {
                self.eph_append(label, EphRec::Deleted(*blob))?;
            }
        }
        Ok(true)
    }

    /// Frees ephemeral memory for the node-wide cap from the label charged most (M4 of the
    /// ephemeral security review: a stranger's labels cannot lock others out): its oldest log
    /// record, else its oldest entry, else its oldest tombstone. Whether anything was freed.
    fn eph_evict(&mut self) -> Result<bool, StoreError> {
        let Some((_, l)) = self.eph.by_bytes.last().copied() else { return Ok(false) };
        if self.eph.trim_log(&l) {
            return Ok(true);
        }
        let Some(e) = self.eph.labels.get(&l) else { return Ok(false) };
        if let Some((_, b)) = e.order.first_key_value().map(|(s, b)| (*s, *b)) {
            return self.eph_remove(&l, &b, EphRemove::Evict);
        }
        let Some((b, t)) = e.tombstones.iter().min_by_key(|(_, t)| **t).map(|(b, t)| (*b, *t)) else { return Ok(false) };
        if let Some(e) = self.eph.labels.get_mut(&l) {
            e.tombstones.remove(&b);
        }
        self.eph.due.remove(&(t, l, b));
        self.eph.release(&l, TOMB_OVERHEAD, true);
        Ok(true)
    }

    /// Adds or replaces an ephemeral entry (spec/sync.md §4, §5): stamped only; past the label's
    /// ephemeral cap (after trimming its log) code 12; past the node's, the label charged most
    /// gives way; a wrap replacement is rate-limited like a durable one.
    fn eph_put(&mut self, label: &LabelId, put: Put<'_>) -> Result<Code, StoreError> {
        let Some(stamp) = put.stamp else { return Ok(Code::REFUSED) };
        let held = self.eph.labels.get(label).and_then(|e| e.entries.get(&put.blob_id)).cloned();
        if let Some(h) = &held
            && h.meta.wrap == put.wrap
            && h.meta.stamp == Some(stamp)
        {
            return Ok(Code::OK);
        }
        let now = self.now();
        self.rates.roll(now, self.policy.window_ms);
        let size = put.blob.len() as u64;
        match &held {
            Some(_) => {
                let p = &self.policy;
                let n = self.rates.entries.get(&(*label, put.blob_id)).copied().unwrap_or(0);
                if n >= p.entry_replacements || !self.rates.take(label, Rate::Replace, p.replacements) {
                    return Ok(Code::RATE_LIMITED);
                }
                self.rates.entries.insert((*label, put.blob_id), n + 1);
            }
            None => {
                let need = size.saturating_add(ENTRY_OVERHEAD).saturating_add(REC_OVERHEAD);
                let used = |s: &Self| s.eph.labels.get(label).map_or(0, |e| e.bytes);
                while used(self).saturating_add(need) > self.policy.ephemeral_bytes && self.eph.trim_log(label) {}
                if used(self).saturating_add(need) > self.policy.ephemeral_bytes {
                    return Ok(Code::STORAGE_CAP);
                }
                while self.eph.total.saturating_add(need) > self.policy.ephemeral_total {
                    if !self.eph_evict()? {
                        return Ok(Code::STORAGE_CAP);
                    }
                }
            }
        }
        let seq = self.eph_append(label, EphRec::Added(put.blob_id))?;
        match held {
            Some(h) => {
                let e = self.eph.labels.entry(*label).or_default();
                e.order.remove(&h.meta.add_seq);
                e.order.insert(seq, put.blob_id);
                e.entries.insert(put.blob_id, EphEntry { meta: EntryMeta { wrap: put.wrap, stamp: Some(stamp), add_seq: seq, ..h.meta }, expiry: h.expiry });
            }
            None => {
                let e = self.eph.labels.entry(*label).or_default();
                e.order.insert(seq, put.blob_id);
                e.entries.insert(put.blob_id, EphEntry { meta: EntryMeta { wrap: put.wrap, stamp: Some(stamp), size, add_seq: seq, pending_delete: None }, expiry: put.expiry });
                if let Some(t) = put.expiry {
                    self.eph.due.insert((t, *label, put.blob_id));
                }
                self.eph.charge(label, size.saturating_add(ENTRY_OVERHEAD), false);
                self.eph.blobs.entry(put.blob_id).or_insert_with(|| (put.blob.to_vec(), 0)).1 += 1;
            }
        }
        match self.origin {
            Some(o) => {
                if self.origins.len() >= MAX_ORIGINS {
                    self.origins.clear();
                }
                self.origins.insert((*label, put.blob_id), o);
            }
            None => {
                self.origins.remove(&(*label, put.blob_id));
            }
        }
        Ok(Code::OK)
    }

    fn eph_entry(&self, label: &LabelId, blob: &BlobId) -> Option<&EphEntry> {
        self.eph.labels.get(label)?.entries.get(blob)
    }

    /// Runs due ephemeral expiries, timed deletes and tombstone drops, at most `budget` of them;
    /// the labels whose logs grew. The number of due items handled.
    fn eph_sweep(&mut self, now: u64, budget: usize, grew: &mut BTreeSet<LabelId>) -> Result<usize, StoreError> {
        let mut n = 0;
        while n < budget {
            let Some((t, l, b)) = self.eph.due.first().copied() else { break };
            if t > now {
                break;
            }
            self.eph.due.pop_first();
            n += 1;
            let Some(e) = self.eph.labels.get(&l) else { continue };
            if let Some(x) = e.entries.get(&b) {
                if x.expiry.is_some_and(|t| t <= now) {
                    self.eph_remove(&l, &b, EphRemove::Expire)?;
                } else if x.meta.pending_delete.is_some_and(|t| t <= now) && self.eph_remove(&l, &b, EphRemove::Delete(now))? {
                    grew.insert(l);
                }
            } else if e.tombstones.get(&b).is_some_and(|d| *d <= now) {
                if let Some(e) = self.eph.labels.get_mut(&l) {
                    e.tombstones.remove(&b);
                }
                self.eph.release(&l, TOMB_OVERHEAD, true);
            }
        }
        Ok(n)
    }

    /// The earliest ephemeral expiry, timed delete or tombstone drop.
    fn eph_next_due(&self) -> Option<u64> {
        self.eph.due.first().map(|(t, _, _)| *t)
    }

    fn row(&self, label: &LabelId, blob: &BlobId) -> Result<Option<Row>, StoreError> {
        self.backend.get(&key(b'E', &[&label.0, &blob.0])).map_err(err)?.map(|b| Row::decode(&b)).transpose()
    }

    fn tx(&self, label: &LabelId) -> Result<Tx, StoreError> {
        let meta = self.meta(label)?.ok_or_else(unknown)?;
        Ok(Tx { label: *label, before: (meta.entries, meta.bytes, false), meta, batch: WriteBatch::new(), grew: false })
    }

    /// Trims the log to `log_keep` durable records (in steps of 1/8 of it: the oldest `G` rows,
    /// scanned, so ephemeral records and reserved numbers in between cost nothing) and commits.
    fn commit(&mut self, mut tx: Tx) -> Result<(), StoreError> {
        let keep = self.policy.log_keep.max(1);
        if tx.meta.records > keep.saturating_add(keep / 8) {
            let drop = usize::try_from(tx.meta.records - keep).unwrap_or(usize::MAX);
            let prefix = key(b'G', &[&tx.label.0]);
            let end = osis_store::prefix_end(&prefix);
            let rows = self.backend.scan(&prefix, end.as_deref(), drop).map_err(err)?;
            for (k, _) in &rows {
                tx.batch.delete(k.clone());
                tx.meta.horizon = tx.meta.horizon.max(read_u64(k, 17)?);
            }
            tx.meta.records = tx.meta.records.saturating_sub(rows.len() as u64);
        }
        tx.batch.put(key(b'L', &[&tx.label.0]), tx.meta.encode());
        if let Some(s) = self.eph.seq.get_mut(&tx.label) {
            *s = (*s).max(tx.meta.next_seq);
        }
        let (entries, bytes, new) = tx.before;
        if new || entries != tx.meta.entries || bytes != tx.meta.bytes {
            let t = self.totals()?;
            let t = Totals {
                labels: t.labels.saturating_add(u64::from(new)),
                entries: t.entries.saturating_add(tx.meta.entries).saturating_sub(entries),
                bytes: t.bytes.saturating_add(tx.meta.bytes).saturating_sub(bytes),
            };
            tx.batch.put(b"N".to_vec(), [be(t.labels), be(t.entries), be(t.bytes)].concat());
        }
        self.backend.commit(tx.batch).map_err(err)
    }

    fn budget_max(&self, m: &Meta) -> u64 {
        self.policy.deposit_factor.max(1).saturating_mul(64u64.saturating_add(m.head_claims.saturating_mul(4)))
    }

    /// Removes a held entry within `tx`: counters, indexes, blob reference; a tombstone when
    /// `tombstone_at` is given.
    fn remove(&self, tx: &mut Tx, blob: &BlobId, row: &Row, tombstone_at: Option<u64>) -> Result<(), StoreError> {
        let l = tx.label.0;
        tx.batch.delete(key(b'E', &[&l, &blob.0]));
        if let Some(t) = row.expiry {
            tx.batch.delete(key(b'X', &[&be(t), &l, &blob.0]));
        }
        if let Some(t) = row.meta.pending_delete {
            tx.batch.delete(key(b'P', &[&be(t), &l, &blob.0]));
        }
        let m = &mut tx.meta;
        m.entries = m.entries.saturating_sub(1);
        m.bytes = m.bytes.saturating_sub(row.meta.size);
        if row.meta.stamp.is_none() {
            m.dep_n = m.dep_n.saturating_sub(1);
            m.dep_bytes = m.dep_bytes.saturating_sub(row.meta.size);
        }
        if let Some(t) = tombstone_at {
            // A tombstone already present keeps its first drop time row; replace it.
            if let Some(old) = self.backend.get(&key(b'T', &[&l, &blob.0])).map_err(err)? {
                tx.batch.delete(key(b'Y', &[&old, &l, &blob.0]));
            }
            let drop = t.saturating_add(self.policy.tombstone_ms);
            tx.batch.put(key(b'T', &[&l, &blob.0]), be(drop).to_vec());
            tx.batch.put(key(b'Y', &[&be(drop), &l, &blob.0]), vec![]);
            tx.append(&LogRecord::Deleted(*blob));
        }
        let refs = self.refs(blob)?;
        if refs <= 1 {
            tx.batch.delete(key(b'R', &[&blob.0]));
            tx.batch.delete_blob(*blob);
        } else {
            tx.batch.put(key(b'R', &[&blob.0]), be(refs - 1).to_vec());
        }
        Ok(())
    }

    fn refs(&self, blob: &BlobId) -> Result<u64, StoreError> {
        self.backend.get(&key(b'R', &[&blob.0])).map_err(err)?.map_or(Ok(0), |b| read_u64(&b, 0))
    }

    /// Up to `limit` due index rows `tag t ...` with `t <= now`: (row key, rest after `t`).
    fn due(&self, tag: u8, now: u64, limit: usize) -> Result<Vec<KeyValue>, StoreError> {
        let end = key(tag, &[&be(now.saturating_add(1))]);
        let start = [tag];
        let end = if now == u64::MAX { osis_store::prefix_end(&start) } else { Some(end) };
        let rows = self.backend.scan(&start, end.as_deref(), limit).map_err(err)?;
        Ok(rows.into_iter().map(|(k, _)| (k.clone(), k.get(9..).unwrap_or(&[]).to_vec())).collect())
    }

    /// Expires entries (no tombstone, no event), executes due timed deletes, drops old tombstones
    /// and claim sets superseded for `claim_keep_ms`; at most `budget` index rows, one commit per
    /// label. An index row that does not parse, or names a label not held, is dropped.
    pub fn sweep(&mut self, now: u64, budget: usize) -> Result<Swept, StoreError> {
        let mut out = Swept::default();
        let mut left = budget.max(1);
        let mut junk = WriteBatch::new();
        let mut by_label: BTreeMap<LabelId, Vec<(Vec<u8>, BlobId, bool)>> = BTreeMap::new();
        for (tag, tomb) in [(b'X', false), (b'P', true)] {
            let due = self.due(tag, now, left)?;
            left -= due.len();
            for (k, rest) in due {
                match (read_arr(&rest, 0).map(LabelId), read_arr(&rest, 16).map(BlobId)) {
                    (Ok(l), Ok(b)) if rest.len() == 48 => by_label.entry(l).or_default().push((k, b, tomb)),
                    _ => junk.delete(k),
                }
            }
        }
        for (label, rows) in by_label {
            let Ok(mut tx) = self.tx(&label) else {
                for (k, _, _) in rows {
                    junk.delete(k);
                }
                continue;
            };
            let mut done = BTreeSet::new();
            for (k, blob, tomb) in rows {
                tx.batch.delete(k);
                if !done.insert(blob) {
                    continue;
                }
                let raw = self.backend.get(&key(b'E', &[&label.0, &blob.0])).map_err(err)?;
                if let Some(Ok(row)) = raw.map(|r| Row::decode(&r)) {
                    self.remove(&mut tx, &blob, &row, tomb.then_some(now))?;
                }
            }
            if tx.grew {
                out.grew.insert(label);
            }
            self.commit(tx)?;
        }
        let mut b = WriteBatch::new();
        let due = self.due(b'Y', now, left)?;
        left -= due.len();
        for (k, rest) in due {
            b.delete(key(b'T', &[&rest]));
            b.delete(k);
        }
        let due = self.due(b'Z', now, left)?;
        left -= due.len();
        for (k, rest) in due {
            b.delete(key(b'C', &[&rest]));
            b.delete(k);
        }
        b.ops.extend(junk.ops);
        if !b.is_empty() {
            self.backend.commit(b).map_err(err)?;
        }
        left -= self.eph_sweep(now, left, &mut out.grew)?;
        out.more = left == 0;
        Ok(out)
    }

    /// Up to `max` labels held above `after` (from the lowest when none), ascending.
    pub fn labels_after(&self, after: Option<&LabelId>, max: usize) -> Result<Vec<LabelId>, StoreError> {
        let start = match after {
            Some(a) => key(b'L', &[&a.0, &[0]]),
            None => b"L".to_vec(),
        };
        let rows = self.backend.scan(&start, Some(b"M"), max).map_err(err)?;
        rows.iter().map(|(k, _)| read_arr(k, 1).map(LabelId)).collect()
    }

    /// Next due sweep time (earliest index row), if any.
    pub fn next_due(&self) -> Result<Option<u64>, StoreError> {
        let mut next: Option<u64> = self.eph_next_due();
        for tag in *b"XPYZ" {
            if let Some((k, _)) = self.backend.scan_prefix(&[tag], 1).map_err(err)?.first() {
                let t = read_u64(k, 1)?;
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        }
        Ok(next)
    }

    /// Log position replicated to `peer` for `label`: (log ID it refers to, sequence number).
    pub fn replica_pos(&self, peer: &[u8; 32], label: &LabelId) -> Result<Option<([u8; 16], u64)>, StoreError> {
        let Some(b) = self.backend.get(&key(b'Q', &[peer, &label.0])).map_err(err)? else { return Ok(None) };
        Ok(Some((read_arr(&b, 0)?, read_u64(&b, 16)?)))
    }

    pub fn set_replica_pos(&mut self, peer: &[u8; 32], label: &LabelId, log_id: [u8; 16], seq: u64) -> Result<(), StoreError> {
        let mut b = WriteBatch::new();
        b.put(key(b'Q', &[peer, &label.0]), [&log_id[..], &be(seq)].concat());
        self.backend.commit(b).map_err(err)
    }
}

impl<B: Backend> LabelStore for BackendStore<B> {
    fn head(&self, label: &LabelId) -> Result<Option<StepId>, StoreError> {
        Ok(self.meta(label)?.and_then(|m| m.head))
    }

    fn step(&self, label: &LabelId, id: &StepId) -> Result<Option<Step>, StoreError> {
        let Some(b) = self.backend.get(&key(b'S', &[&label.0, &id.0])).map_err(err)? else { return Ok(None) };
        Step::parse(&b).map(Some).map_err(|_| corrupt("step"))
    }

    fn claim_set(&self, label: &LabelId, id: &StepId) -> Result<Option<Arc<ClaimSet>>, StoreError> {
        let Some(b) = self.backend.get(&key(b'C', &[&label.0, &id.0])).map_err(err)? else { return Ok(None) };
        ClaimSet::parse(&b).map(|c| Some(Arc::new(c))).map_err(|_| corrupt("claim set"))
    }

    fn admit_label(&self, _label: &LabelId) -> Result<Code, StoreError> {
        let t = self.totals()?;
        let p = &self.policy;
        Ok(if t.labels >= p.max_labels || t.entries >= p.max_entries || t.bytes >= p.max_bytes { Code::STORAGE_CAP } else { Code::OK })
    }

    fn push_step(&mut self, label: &LabelId, step: Step, claim_set: Option<ClaimSet>) -> Result<(), StoreError> {
        let (meta, new) = match self.meta(label)? {
            Some(m) => (m, false),
            None => {
                let h = osis_base::hash::hash(&[&self.seed[..], &label.0[..]].concat());
                (Meta { log_id: read_arr(&h, 0)?, ..Meta::default() }, true)
            }
        };
        let mut tx = Tx { label: *label, before: (meta.entries, meta.bytes, new), meta, batch: WriteBatch::new(), grew: false };
        let id = step.id();
        if let Some(prev) = tx.meta.head {
            let drop = self.now().saturating_add(self.policy.claim_keep_ms.max(MEMBERSHIP_KEEP_MS));
            tx.batch.put(key(b'Z', &[&be(drop), &label.0, &prev.0]), vec![]);
        }
        tx.meta.head = Some(id);
        tx.meta.head_claims = claim_set.as_ref().map_or(0, |c| c.claims.len() as u64);
        tx.batch.put(key(b'S', &[&label.0, &id.0]), step.to_bytes());
        if let Some(c) = &claim_set {
            tx.batch.put(key(b'C', &[&label.0, &id.0]), c.to_bytes());
        }
        tx.append(&LogRecord::Head(step));
        self.commit(tx)
    }

    fn entry(&self, label: &LabelId, blob_id: &BlobId) -> Result<Option<EntryMeta>, StoreError> {
        if let Some(e) = self.eph_entry(label, blob_id) {
            return Ok(Some(e.meta.clone()));
        }
        Ok(self.row(label, blob_id)?.map(|r| r.meta))
    }

    fn tombstoned(&self, label: &LabelId, blob_id: &BlobId) -> Result<bool, StoreError> {
        let now = self.now();
        if self.eph.labels.get(label).is_some_and(|e| e.tombstones.get(blob_id).is_some_and(|t| *t > now)) {
            return Ok(true);
        }
        Ok(self.backend.get(&key(b'T', &[&label.0, &blob_id.0])).map_err(err)?.is_some())
    }

    fn blob(&self, blob_id: &BlobId) -> Result<Option<Vec<u8>>, StoreError> {
        if let Some((b, _)) = self.eph.blobs.get(blob_id) {
            return Ok(Some(b.clone()));
        }
        self.backend.get_blob(blob_id).map_err(err)
    }

    fn put(&mut self, label: &LabelId, put: Put<'_>) -> Result<Code, StoreError> {
        let mut tx = self.tx(label)?;
        let held = self.row(label, &put.blob_id)?;
        // an ephemeral blob (unless the same blob is held as a durable entry) stays in memory
        if (put.ephemeral && held.is_none()) || self.eph_entry(label, &put.blob_id).is_some() {
            return self.eph_put(label, put);
        }
        if let Some(r) = &held
            && (put.stamp.is_none() || (r.meta.wrap == put.wrap && r.meta.stamp == put.stamp))
        {
            return Ok(Code::OK);
        }
        let size = put.blob.len() as u64;
        let now = self.now();
        self.rates.roll(now, self.policy.window_ms);
        let p = &self.policy;
        match &held {
            Some(_) => {
                let n = self.rates.entries.get(&(*label, put.blob_id)).copied().unwrap_or(0);
                if n >= p.entry_replacements || !self.rates.take(label, Rate::Replace, p.replacements) {
                    return Ok(Code::RATE_LIMITED);
                }
                self.rates.entries.insert((*label, put.blob_id), n + 1);
            }
            None => {
                let m = &tx.meta;
                if m.entries.saturating_add(1) > p.cap_entries || m.bytes.saturating_add(size) > p.cap_bytes {
                    return Ok(Code::STORAGE_CAP);
                }
                let t = self.totals()?;
                let p = &self.policy;
                if t.entries.saturating_add(1) > p.max_entries || t.bytes.saturating_add(size) > p.max_bytes {
                    return Ok(Code::STORAGE_CAP);
                }
                if put.stamp.is_none() {
                    let max = self.budget_max(m);
                    if m.dep_n.saturating_add(1) > max || m.dep_bytes.saturating_add(size) > max.saturating_mul(DEPOSIT_ENTRY_BYTES) {
                        return Ok(Code::BUDGET_FULL);
                    }
                    if !self.rates.take(label, Rate::Deposit, p.deposits) {
                        return Ok(Code::RATE_LIMITED);
                    }
                }
            }
        }
        let seq = tx.append(&LogRecord::Added(put.blob_id));
        let l = label.0;
        let row = match held {
            Some(old) => {
                if old.meta.stamp.is_none() {
                    tx.meta.dep_n = tx.meta.dep_n.saturating_sub(1);
                    tx.meta.dep_bytes = tx.meta.dep_bytes.saturating_sub(old.meta.size);
                }
                Row { meta: EntryMeta { wrap: put.wrap, stamp: put.stamp, add_seq: seq, ..old.meta }, expiry: old.expiry }
            }
            None => {
                tx.meta.entries += 1;
                tx.meta.bytes = tx.meta.bytes.saturating_add(size);
                if put.stamp.is_none() {
                    tx.meta.dep_n += 1;
                    tx.meta.dep_bytes = tx.meta.dep_bytes.saturating_add(size);
                }
                if let Some(t) = put.expiry {
                    tx.batch.put(key(b'X', &[&be(t), &l, &put.blob_id.0]), vec![]);
                }
                let refs = self.refs(&put.blob_id)?;
                if refs == 0 {
                    tx.batch.put_blob(put.blob_id, put.blob.to_vec());
                }
                tx.batch.put(key(b'R', &[&put.blob_id.0]), be(refs + 1).to_vec());
                Row { meta: EntryMeta { wrap: put.wrap, stamp: put.stamp, size, add_seq: seq, pending_delete: None }, expiry: put.expiry }
            }
        };
        tx.batch.put(key(b'E', &[&l, &put.blob_id.0]), row.encode());
        self.commit(tx)?;
        match self.origin {
            Some(o) => {
                if self.origins.len() >= MAX_ORIGINS {
                    self.origins.clear();
                }
                self.origins.insert((*label, put.blob_id), o);
            }
            None => {
                self.origins.remove(&(*label, put.blob_id));
            }
        }
        Ok(Code::OK)
    }

    fn budget(&self, label: &LabelId) -> Result<Budget, StoreError> {
        let m = self.meta(label)?.ok_or_else(unknown)?;
        let max = self.budget_max(&m);
        Ok(Budget { entries_left: max.saturating_sub(m.dep_n), bytes_left: max.saturating_mul(DEPOSIT_ENTRY_BYTES).saturating_sub(m.dep_bytes) })
    }

    fn delete(&mut self, label: &LabelId, blob_id: &BlobId, now: u64) -> Result<Code, StoreError> {
        if self.eph_entry(label, blob_id).is_some() {
            self.rates.roll(self.now(), self.policy.window_ms);
            if !self.rates.take(label, Rate::Delete, self.policy.deletes) {
                return Ok(Code::RATE_LIMITED);
            }
            self.eph_remove(label, blob_id, EphRemove::Delete(now))?;
            return Ok(Code::OK);
        }
        let mut tx = self.tx(label)?;
        let Some(row) = self.row(label, blob_id)? else { return Ok(Code::OK) };
        self.rates.roll(self.now(), self.policy.window_ms);
        if !self.rates.take(label, Rate::Delete, self.policy.deletes) {
            return Ok(Code::RATE_LIMITED);
        }
        self.remove(&mut tx, blob_id, &row, Some(now))?;
        self.commit(tx)?;
        Ok(Code::OK)
    }

    fn schedule_delete(&mut self, label: &LabelId, blob_id: &BlobId, at: u64) -> Result<Code, StoreError> {
        if let Some(e) = self.eph_entry(label, blob_id) {
            let old = e.meta.pending_delete;
            if old.is_some_and(|t| t <= at) {
                return Ok(Code::OK);
            }
            self.rates.roll(self.now(), self.policy.window_ms);
            if !self.rates.take(label, Rate::Delete, self.policy.deletes) {
                return Ok(Code::RATE_LIMITED);
            }
            if let Some(t) = old {
                self.eph.due.remove(&(t, *label, *blob_id));
            }
            if let Some(e) = self.eph.labels.get_mut(label).and_then(|e| e.entries.get_mut(blob_id)) {
                e.meta.pending_delete = Some(at);
            }
            self.eph.due.insert((at, *label, *blob_id));
            self.eph_append(label, EphRec::Pending(*blob_id, at))?;
            return Ok(Code::OK);
        }
        let mut tx = self.tx(label)?;
        let Some(mut row) = self.row(label, blob_id)? else { return Ok(Code::OK) };
        if row.meta.pending_delete.is_some_and(|t| t <= at) {
            return Ok(Code::OK);
        }
        self.rates.roll(self.now(), self.policy.window_ms);
        if !self.rates.take(label, Rate::Delete, self.policy.deletes) {
            return Ok(Code::RATE_LIMITED);
        }
        let l = label.0;
        if let Some(old) = row.meta.pending_delete {
            tx.batch.delete(key(b'P', &[&be(old), &l, &blob_id.0]));
        }
        row.meta.pending_delete = Some(at);
        tx.batch.put(key(b'P', &[&be(at), &l, &blob_id.0]), vec![]);
        tx.batch.put(key(b'E', &[&l, &blob_id.0]), row.encode());
        tx.append(&LogRecord::Pending(*blob_id, at));
        self.commit(tx)?;
        Ok(Code::OK)
    }

    fn log_head(&self, label: &LabelId) -> Result<([u8; 16], u64), StoreError> {
        let m = self.meta(label)?.ok_or_else(unknown)?;
        Ok((m.log_id, m.next_seq))
    }

    fn log_after(&self, label: &LabelId, after: u64, max: usize) -> Result<Option<Vec<(u64, LogRecord)>>, StoreError> {
        let m = self.meta(label)?.ok_or_else(unknown)?;
        let eph = self.eph.labels.get(label);
        if after < m.horizon || after > m.next_seq {
            return Ok(None);
        }
        if max == 0 || after == m.next_seq {
            return Ok(Some(Vec::new()));
        }
        let start = key(b'G', &[&label.0, &be(after + 1)]);
        let end = key(b'G', &[&label.0, &be(m.next_seq.saturating_add(1))]);
        let end = if m.next_seq == u64::MAX { osis_store::prefix_end(&key(b'G', &[&label.0])) } else { Some(end) };
        let rows = self.backend.scan(&start, end.as_deref(), max).map_err(err)?;
        let mut out = rows.iter().map(|(k, v)| Ok((read_u64(k, 17)?, decode_record(v)?))).collect::<Result<Vec<_>, StoreError>>()?;
        // the ephemeral records in sequence order among them; where the ephemeral log was trimmed
        // past `after`, the live entries added since stand in for their add records (the
        // deletions and timed deletes trimmed are not repeated), so ephemeral churn never sends a
        // durable cursor back to reconciliation
        if let Some(e) = eph {
            if after < e.horizon {
                out.extend(e.order.range(after + 1..=e.horizon).take(max).map(|(s, b)| (*s, LogRecord::Added(*b))));
            }
            let at = e.log.partition_point(|(s, _)| *s <= after);
            out.extend(e.log.iter().skip(at).take(max).map(|(s, r)| (*s, r.record())));
            out.sort_by_key(|(s, _)| *s);
            out.truncate(max);
        }
        Ok(Some(out))
    }

    fn live_by_id(&self, label: &LabelId, after: Option<&BlobId>, max: usize) -> Result<Vec<(BlobId, EntryMeta)>, StoreError> {
        let prefix = key(b'E', &[&label.0]);
        let start = match after {
            // The least key above `after`.
            Some(a) => key(b'E', &[&label.0, &a.0, &[0]]),
            None => prefix.clone(),
        };
        let end = osis_store::prefix_end(&prefix);
        let rows = self.backend.scan(&start, end.as_deref(), max).map_err(err)?;
        let mut out = rows.iter().map(|(k, v)| Ok((BlobId(read_arr(k, 17)?), Row::decode(v)?.meta))).collect::<Result<Vec<_>, StoreError>>()?;
        if let Some(e) = self.eph.labels.get(label) {
            let range = match after {
                Some(a) => e.entries.range((std::ops::Bound::Excluded(*a), std::ops::Bound::Unbounded)),
                None => e.entries.range(..),
            };
            out.extend(range.take(max).map(|(b, x)| (*b, x.meta.clone())));
            out.sort_by_key(|(b, _)| *b);
            out.truncate(max);
        }
        Ok(out)
    }

    fn live_ids(&self, label: &LabelId) -> Result<Vec<BlobId>, StoreError> {
        Ok(self.live_by_id(label, None, usize::MAX)?.into_iter().map(|(b, _)| b).collect())
    }

    fn relay(&mut self, label: &LabelId, blob_id: &BlobId, size: usize, expiry: Option<u64>, now: u64) -> Result<osis_proto::RelayVerdict, StoreError> {
        Ok(self.relays.admit(label, blob_id, size, expiry, now))
    }
}

#[cfg(test)]
mod tests;

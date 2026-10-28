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

use osis_base::format::{MEMBERSHIP_KEEP_MS, TOMBSTONE_LIFETIME_MS};
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
    pub signals: u32,
    /// Wrap replacements per entry and window.
    pub entry_replacements: u32,
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
            signals: 1_200,
            entry_replacements: 4,
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
            signals: u32::MAX,
            entry_replacements: u32::MAX,
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
}

const META_LEN: usize = 16 + 1 + 32 + 8 * 7;

impl Meta {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(META_LEN);
        v.extend_from_slice(&self.log_id);
        v.push(u8::from(self.head.is_some()));
        v.extend_from_slice(&self.head.map_or([0; 32], |h| h.0));
        for n in [self.next_seq, self.horizon, self.head_claims, self.entries, self.bytes, self.dep_n, self.dep_bytes] {
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
    Signal,
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
        Ok(BackendStore { backend, seed, clock, policy, rates: Rates::default(), origin: None, origins: HashMap::new() })
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn into_backend(self) -> B {
        self.backend
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

    fn meta(&self, label: &LabelId) -> Result<Option<Meta>, StoreError> {
        self.backend.get(&key(b'L', &[&label.0])).map_err(err)?.map(|b| Meta::decode(&b)).transpose()
    }

    fn row(&self, label: &LabelId, blob: &BlobId) -> Result<Option<Row>, StoreError> {
        self.backend.get(&key(b'E', &[&label.0, &blob.0])).map_err(err)?.map(|b| Row::decode(&b)).transpose()
    }

    fn tx(&self, label: &LabelId) -> Result<Tx, StoreError> {
        let meta = self.meta(label)?.ok_or_else(unknown)?;
        Ok(Tx { label: *label, before: (meta.entries, meta.bytes, false), meta, batch: WriteBatch::new(), grew: false })
    }

    /// Trims the log to `log_keep` records (in steps of 1/8 of it) and commits.
    fn commit(&mut self, mut tx: Tx) -> Result<(), StoreError> {
        let keep = self.policy.log_keep.max(1);
        let held = tx.meta.next_seq.checked_sub(tx.meta.horizon).ok_or_else(|| corrupt("log horizon"))?;
        if held > keep.saturating_add(keep / 8) {
            let upto = tx.meta.next_seq.saturating_sub(keep);
            for seq in tx.meta.horizon + 1..=upto {
                tx.batch.delete(key(b'G', &[&tx.label.0, &be(seq)]));
            }
            tx.meta.horizon = upto;
        }
        tx.batch.put(key(b'L', &[&tx.label.0]), tx.meta.encode());
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
            let Some(mut tx) = self.meta(&label).ok().flatten().map(|meta| Tx { label, before: (meta.entries, meta.bytes, false), meta, batch: WriteBatch::new(), grew: false }) else {
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
        let mut next: Option<u64> = None;
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
        Ok(self.row(label, blob_id)?.map(|r| r.meta))
    }

    fn tombstoned(&self, label: &LabelId, blob_id: &BlobId) -> Result<bool, StoreError> {
        Ok(self.backend.get(&key(b'T', &[&label.0, &blob_id.0])).map_err(err)?.is_some())
    }

    fn blob(&self, blob_id: &BlobId) -> Result<Option<Vec<u8>>, StoreError> {
        self.backend.get_blob(blob_id).map_err(err)
    }

    fn put(&mut self, label: &LabelId, put: Put<'_>) -> Result<Code, StoreError> {
        let mut tx = self.tx(label)?;
        let held = self.row(label, &put.blob_id)?;
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

    fn signal(&mut self, label: &LabelId) -> Result<Code, StoreError> {
        self.rates.roll(self.now(), self.policy.window_ms);
        Ok(if self.rates.take(label, Rate::Signal, self.policy.signals) { Code::OK } else { Code::RATE_LIMITED })
    }

    fn log_head(&self, label: &LabelId) -> Result<([u8; 16], u64), StoreError> {
        let m = self.meta(label)?.ok_or_else(unknown)?;
        Ok((m.log_id, m.next_seq))
    }

    fn log_after(&self, label: &LabelId, after: u64, max: usize) -> Result<Option<Vec<(u64, LogRecord)>>, StoreError> {
        let m = self.meta(label)?.ok_or_else(unknown)?;
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
        rows.iter().map(|(k, v)| Ok((read_u64(k, 17)?, decode_record(v)?))).collect::<Result<Vec<_>, _>>().map(Some)
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
        rows.iter().map(|(k, v)| Ok((BlobId(read_arr(k, 17)?), Row::decode(v)?.meta))).collect()
    }

    fn live_ids(&self, label: &LabelId) -> Result<Vec<BlobId>, StoreError> {
        Ok(self.live_by_id(label, None, usize::MAX)?.into_iter().map(|(b, _)| b).collect())
    }
}

#[cfg(test)]
mod tests;

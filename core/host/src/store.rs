//! `HostStore`: osis-proto's `LabelStore` over its own osis-store `Store` (spec/sync.md §4, §5):
//! registration paths, entries, tombstones, per-label logs, blob bytes stored once with reference
//! counts, expiry, claim-set retention, and the host policy (storage caps,
//! deposit budget, rate limits). Every mutation's writes apply together to the open store
//! transaction, committed per mutation or, deferred (`defer_durability`), once per hub batch.
//!
//! Deletion (spec/requirements.md, Deletion): every row removal shreds (`Shred::Yes`), so a
//! deleted entry's wrap is unrecoverable once its transaction commits, even on a node that also
//! reads the label; overwrites do not shred (a promotion wraps the same blob key, and the entry's
//! removal later shreds every earlier version on its path). Blob ciphertexts sit in the store's
//! blob area, deleted for space only: without a wrap they open nowhere.
//!
//! Rows, in one table of the store (encrypted under the host store's own key tree; what a host
//! sees anyway, blobs are ciphertext):
//! `I` seed; `L label` meta; `K label` the head's earlier role keys (`HeadKeys`); `S label step`
//! step; `C label step` claim set, `H label step key` each of its keys (the entry box or empty:
//! an Open looks one key up instead of loading the set); path indexes `V label sync_key` the newest step registering
//! that sync key, `W label` the genesis step and `W label step` its child (an Open or a Path page
//! reads no path); `E label blob` entry;
//! `T label blob` tombstone time; `G label seq` log record; `R blob` reference count and the
//! blob's prefix bytes (`blob_prefix`);
//! sweep indexes `X t label blob` (expiry),
//! `Y t label blob` (a removed entry's log trim, and its tombstone drop after a deletion: the log
//! position it went at, then 1 for a deletion, 0 for an expiry), `Z t label step` (claim-set drop, with its `H` rows);
//! `Q peer label` replication position; `N` host-wide totals (labels, entries, bytes).
//!
//! Ephemeral entries (blob prefix class ephemeral, spec/sync.md §4) are held in memory only:
//! entry, blob, log records and tombstones; a restart loses them. Their log records take
//! sequence numbers from the label's log, reserved on disk in blocks (`SEQ_BLOCK`, the label
//! meta's `reserved`), so no number handed out before a restart is handed out again.

use osis_base::format::{MAX_DRIFT_MS, ROLE_KEEP_MS, TOMBSTONE_LIFETIME_MS};
use osis_base::{BlobId, Clock, LabelId};
use osis_crypto::Signature;
use osis_proto::msg::{ClaimSet, Code, SecretBox, Step, StepId, WRAP_LEN};
use osis_proto::{Budget, EntryMeta, HeadKeys, LabelStore, LogRecord, Put, StoreError};
use osis_store::{KeyValue, Shred, Store, Suspended, Table, Transaction};
use crate::{Admission, LabelCaps};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

/// Deposit budget unit (spec/sync.md §5 recommended minimum).
pub const DEPOSIT_ENTRY_BYTES: u64 = 32 * 1024;

/// Host policy (spec/sync.md §5: caps, budget, rate limits; notes/serving.md Host policy).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPolicy {
    /// Live entries per label beyond which new entries are refused.
    pub cap_entries: u64,
    /// Bytes per label (live entries, steps, held claim sets) beyond which new entries and
    /// steps are refused.
    pub cap_bytes: u64,
    /// Deposit budget = this × (64 + 4 × head claim slots) entries, × 32 KiB bytes; at least 1.
    pub deposit_factor: u64,
    /// A claim set is kept this long after its step is superseded (at least `ROLE_KEEP`).
    pub claim_keep_ms: u64,
    pub tombstone_ms: u64,
    /// Log records kept per label; older ones are dropped (cursors below fall back to reconciliation).
    pub log_keep: u64,
    /// Rate-limit window.
    pub window_ms: u64,
    /// Per label and window.
    pub deletes: u32,
    pub deposits: u32,
    /// Registered steps per label and window (each step and its claim set also count toward
    /// the byte caps): 0 registers nothing, unlimited leaves only the byte caps.
    pub registers: u32,
    /// A child step past a byte cap even without its claim set is taken at most once per this
    /// per label; another in that time is refused (the registrar retries). Resource bound:
    /// growth past the caps is at most `max_labels` steps per this; 0 leaves only `registers`,
    /// infinity takes one such step per label until room appears (a later rotation waits there).
    pub over_cap_step_ms: u64,
    /// Ephemeral memory charged per label, and over all labels: an ephemeral upload beyond the
    /// label's is refused; past the total, the label charged most gives way (notes/ephemeral.md).
    pub ephemeral_bytes: u64,
    pub ephemeral_total: u64,
    /// Relay-only uploads pushed per label and window, and their bytes (`osis_proto::RelayLimits`).
    pub relays: u32,
    pub relay_bytes: u64,
    /// Host-wide caps: new entries, labels and steps beyond them are refused.
    pub max_labels: u64,
    pub max_entries: u64,
    pub max_bytes: u64,
    /// Connections served at once (node sync closes any beyond, by its rule).
    pub max_connections: usize,
    /// A connection without the peer's Hello this long after accept is closed.
    pub hello_ms: u64,
    /// Bytes queued for one connection beyond which it is dropped (a peer that does not read);
    /// at least `osis_proto::serving::SEND_QUEUE` plus `osis_proto::client::WINDOW_QUEUE`
    /// (windowed replies and held pushes, and node sync's own requests, spec/sync.md §6).
    pub max_queued_bytes: usize,
    /// Bytes held for connections in each direction, over all of them: partially received
    /// frames, and bytes written and not yet taken by the transport. Past it the connection
    /// holding the most of that direction is closed. The node's memory bound for its connections,
    /// whatever their count (`max_connections` bounds slots, not bytes).
    pub max_buffered_bytes: usize,
}

impl Default for HostPolicy {
    fn default() -> HostPolicy {
        HostPolicy {
            cap_entries: 1 << 20,
            cap_bytes: 16 << 30,
            deposit_factor: 1,
            claim_keep_ms: ROLE_KEEP_MS,
            tombstone_ms: TOMBSTONE_LIFETIME_MS,
            log_keep: 1 << 20,
            window_ms: 60_000,
            deletes: 20_000,
            deposits: 600,
            registers: 600,
            over_cap_step_ms: 3_600_000,
            ephemeral_bytes: 16 << 20,
            ephemeral_total: 1 << 30,
            relays: osis_proto::RelayLimits::default().count,
            relay_bytes: osis_proto::RelayLimits::default().bytes,
            max_labels: 1 << 20,
            max_entries: 1 << 26,
            max_bytes: 256 << 30,
            max_connections: 10_000,
            hello_ms: 10_000,
            max_queued_bytes: 64 << 20,
            max_buffered_bytes: 512 << 20,
        }
    }
}

const _: () = assert!(64 << 20 >= osis_proto::serving::SEND_QUEUE + osis_proto::client::WINDOW_QUEUE);

impl HostPolicy {
    /// Sets the knob named like its field (the `policy` map of `host^.0`); an unknown name or a
    /// value out of the knob's range is an error, the policy unchanged.
    pub fn set(&mut self, name: &str, v: u64) -> Result<(), String> {
        let n32 = || u32::try_from(v).map_err(|_| format!("{name}: {v} is too large"));
        let nz = || usize::try_from(v).map_err(|_| format!("{name}: {v} is too large"));
        match name {
            "cap_entries" => self.cap_entries = v,
            "cap_bytes" => self.cap_bytes = v,
            "deposit_factor" => self.deposit_factor = v,
            "claim_keep_ms" => self.claim_keep_ms = v,
            "tombstone_ms" => self.tombstone_ms = v,
            "log_keep" => self.log_keep = v,
            "window_ms" => self.window_ms = v,
            "deletes" => self.deletes = n32()?,
            "deposits" => self.deposits = n32()?,
            "registers" => self.registers = n32()?,
            "over_cap_step_ms" => self.over_cap_step_ms = v,
            "ephemeral_bytes" => self.ephemeral_bytes = v,
            "ephemeral_total" => self.ephemeral_total = v,
            "relays" => self.relays = n32()?,
            "relay_bytes" => self.relay_bytes = v,
            "max_labels" => self.max_labels = v,
            "max_entries" => self.max_entries = v,
            "max_bytes" => self.max_bytes = v,
            "max_connections" => self.max_connections = nz()?,
            "hello_ms" => self.hello_ms = v,
            "max_queued_bytes" => {
                let q = nz()?;
                let least = osis_proto::serving::SEND_QUEUE + osis_proto::client::WINDOW_QUEUE;
                if q < least {
                    return Err(format!("{name}: below {least} (a peer's window plus a reply and a push, and this node's own window, spec/sync.md §6)"));
                }
                self.max_queued_bytes = q;
            }
            "max_buffered_bytes" => self.max_buffered_bytes = nz()?,
            _ => return Err(format!("unknown host policy knob {name}")),
        }
        Ok(())
    }

    /// The knobs differing from the defaults, by the names `set` takes: `set` of each over the
    /// defaults gives this policy back.
    pub fn knobs(&self) -> std::collections::BTreeMap<String, u64> {
        let d = HostPolicy::default();
        let mut out = std::collections::BTreeMap::new();
        let mut put = |name: &str, v: u64, was: u64| {
            if v != was {
                out.insert(name.to_string(), v);
            }
        };
        put("cap_entries", self.cap_entries, d.cap_entries);
        put("cap_bytes", self.cap_bytes, d.cap_bytes);
        put("deposit_factor", self.deposit_factor, d.deposit_factor);
        put("claim_keep_ms", self.claim_keep_ms, d.claim_keep_ms);
        put("tombstone_ms", self.tombstone_ms, d.tombstone_ms);
        put("log_keep", self.log_keep, d.log_keep);
        put("window_ms", self.window_ms, d.window_ms);
        put("deletes", self.deletes.into(), d.deletes.into());
        put("deposits", self.deposits.into(), d.deposits.into());
        put("registers", self.registers.into(), d.registers.into());
        put("over_cap_step_ms", self.over_cap_step_ms, d.over_cap_step_ms);
        put("ephemeral_bytes", self.ephemeral_bytes, d.ephemeral_bytes);
        put("ephemeral_total", self.ephemeral_total, d.ephemeral_total);
        put("relays", self.relays.into(), d.relays.into());
        put("relay_bytes", self.relay_bytes, d.relay_bytes);
        put("max_labels", self.max_labels, d.max_labels);
        put("max_entries", self.max_entries, d.max_entries);
        put("max_bytes", self.max_bytes, d.max_bytes);
        put("max_connections", self.max_connections as u64, d.max_connections as u64);
        put("hello_ms", self.hello_ms, d.hello_ms);
        put("max_queued_bytes", self.max_queued_bytes as u64, d.max_queued_bytes as u64);
        put("max_buffered_bytes", self.max_buffered_bytes as u64, d.max_buffered_bytes as u64);
        out
    }

    /// No limits beyond the spec's minimum budget (tests comparing with `MemoryLabelStore`).
    pub fn unlimited() -> HostPolicy {
        HostPolicy {
            cap_entries: u64::MAX,
            cap_bytes: u64::MAX,
            log_keep: u64::MAX,
            deletes: u32::MAX,
            deposits: u32::MAX,
            registers: u32::MAX,
            over_cap_step_ms: 0,
            ephemeral_bytes: u64::MAX,
            ephemeral_total: u64::MAX,
            relays: u32::MAX,
            relay_bytes: u64::MAX,
            max_labels: u64::MAX,
            max_entries: u64::MAX,
            max_bytes: u64::MAX,
            ..HostPolicy::default()
        }
    }
}

fn err(e: osis_store::Error) -> StoreError {
    StoreError(e.to_string())
}

/// One mutation's writes, applied to the open transaction together.
#[derive(Default)]
struct Writes(Vec<Write>);

enum Write {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    PutBlob(BlobId, Vec<u8>),
    DeleteBlob(BlobId),
    /// Node log events (notes/local-store.md, Node log), beside the per-label log.
    LogAdded(LabelId, BlobId),
    LogDeleted(LabelId, BlobId, u64),
    LogHead(LabelId, StepId),
    /// A page of the node log's sweep at a wall time.
    LogSweep(u64),
}

impl Writes {
    fn put(&mut self, k: Vec<u8>, v: Vec<u8>) {
        self.0.push(Write::Put(k, v));
    }
    fn delete(&mut self, k: Vec<u8>) {
        self.0.push(Write::Delete(k));
    }
    fn put_blob(&mut self, id: BlobId, b: Vec<u8>) {
        self.0.push(Write::PutBlob(id, b));
    }
    fn delete_blob(&mut self, id: BlobId) {
        self.0.push(Write::DeleteBlob(id));
    }
    fn log(&mut self, w: Write) {
        self.0.push(w);
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The host's `Store`, its one table, and the transaction open since the last commit.
struct Db {
    store: Store,
    table: Table,
    rng: Box<dyn osis_crypto::NodeRng>,
    open: Option<Suspended>,
}

/// Name of the host's table (`Transaction::index`).
const TABLE: &[u8] = b"host";

impl Db {
    /// Runs `f` in the open transaction (one is started if none is open).
    fn run<R>(&mut self, f: impl FnOnce(&mut Transaction<'_>, Table) -> Result<R, osis_store::Error>) -> Result<R, osis_store::Error> {
        let Db { store, table, rng, open } = self;
        let mut t = match open.take() {
            Some(s) => store.resume(s, &mut **rng),
            None => store.transaction(&mut **rng)?,
        };
        let r = f(&mut t, *table);
        *open = Some(t.suspend()?);
        r
    }

    /// Applies `w` to the open transaction. A failure part way drops it (aborted: every write
    /// since the last commit is lost) and recovers the store in place, as a failed commit does.
    fn apply(&mut self, w: Writes) -> Result<(), osis_store::Error> {
        let Db { store, table, rng, open } = self;
        let r = match open.take() {
            Some(s) => Ok(store.resume(s, &mut **rng)),
            None => store.transaction(&mut **rng),
        }
        .and_then(|mut t| {
            for op in w.0 {
                match op {
                    Write::Put(k, v) => t.table_put(*table, &k, v, Shred::No).map(drop)?,
                    Write::Delete(k) => t.table_remove(*table, &k, Shred::Yes).map(drop)?,
                    Write::PutBlob(id, b) => t.put_blob(&id, b)?,
                    Write::DeleteBlob(id) => t.delete_blob(&id),
                    Write::LogAdded(l, b) => drop(t.log_added(l, b)?),
                    Write::LogDeleted(l, b, at) => drop(t.log_deleted(l, b, at)?),
                    Write::LogHead(l, h) => drop(t.log_head(l, &h.0)?),
                    Write::LogSweep(now) => drop(t.log_sweep(now)?),
                }
            }
            t.suspend()
        });
        match r {
            Ok(s) => {
                *open = Some(s);
                Ok(())
            }
            Err(e) => {
                // a reopen that fails leaves the store broken: every later call fails
                let _ = store.reopen();
                Err(e)
            }
        }
    }

    /// Commits the open transaction. A failed commit leaves the outcome unknown: the store is
    /// recovered in place (`Store::reopen`) and the error returned.
    fn commit(&mut self) -> Result<(), osis_store::Error> {
        let Some(s) = self.open.take() else { return Ok(()) };
        let r = self.store.resume(s, &mut *self.rng).commit();
        if r.is_err() {
            // a reopen that fails leaves the store broken: every later call fails
            let _ = self.store.reopen();
        }
        r
    }
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

/// `K` row: per role a count byte, then that many 32-byte keys.
fn encode_older(older: &[Vec<osis_crypto::VerifyingKey>; 4]) -> Vec<u8> {
    let mut b = Vec::new();
    for keys in older {
        b.push(keys.len() as u8);
        for k in keys {
            b.extend_from_slice(&k.to_bytes());
        }
    }
    b
}

fn decode_older(b: &[u8]) -> Result<[Vec<osis_crypto::VerifyingKey>; 4], StoreError> {
    let mut older: [Vec<osis_crypto::VerifyingKey>; 4] = Default::default();
    let mut at = 0;
    for keys in older.iter_mut() {
        let n = *b.get(at).ok_or_else(|| corrupt("head keys"))? as usize;
        at += 1;
        for _ in 0..n {
            keys.push(osis_crypto::VerifyingKey::from_bytes(&read_arr(b, at)?).map_err(|_| corrupt("head keys"))?);
            at += 32;
        }
    }
    if at != b.len() {
        return Err(corrupt("head keys"));
    }
    Ok(older)
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
    /// Wall ms before which a child step past a byte cap is refused (`HostPolicy::over_cap_step_ms`).
    over_cap_until: u64,
}

const META_LEN: usize = 16 + 1 + 32 + 8 * 10;

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
        for n in [self.next_seq, self.horizon, self.head_claims, self.entries, self.bytes, self.dep_n, self.dep_bytes, self.reserved, self.records, self.over_cap_until] {
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
            over_cap_until: n(9)?,
        })
    }
}

/// A stored entry: the engine's view plus its expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    meta: EntryMeta,
    expiry: Option<u64>,
}

const ROW_LEN: usize = WRAP_LEN + 1 + 64 + 8 * 3;

impl Row {
    fn encode(&self) -> Vec<u8> {
        let m = &self.meta;
        let mut v = Vec::with_capacity(ROW_LEN);
        v.extend_from_slice(&m.wrap);
        v.push(u8::from(m.stamp.is_some()) | u8::from(self.expiry.is_some()) << 2);
        v.extend_from_slice(&m.stamp.map_or([0; 64], |s| s.0));
        for n in [m.size, m.add_seq, self.expiry.unwrap_or(0)] {
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
            },
            expiry: opt(4, read_u64(b, at + 16)?),
        })
    }
}

fn encode_record(r: &LogRecord) -> Vec<u8> {
    match r {
        LogRecord::Added(b) => key(0, &[&b.0]),
        LogRecord::Deleted(b) => key(1, &[&b.0]),
        LogRecord::Head(s) => key(3, &[&s.to_bytes()]),
    }
}

fn decode_record(b: &[u8]) -> Result<LogRecord, StoreError> {
    let id = || read_arr(b, 1).map(BlobId);
    Ok(match b.first() {
        Some(0) => LogRecord::Added(id()?),
        Some(1) => LogRecord::Deleted(id()?),
        Some(3) => LogRecord::Head(Step::parse(b.get(1..).unwrap_or(&[])).map_err(|_| corrupt("step"))?),
        _ => return Err(corrupt("log record")),
    })
}

/// Rate-limited operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Rate {
    Delete,
    Deposit,
    Register,
}

/// One ephemeral entry (in memory).
#[derive(Clone, Debug)]
struct EphEntry {
    meta: EntryMeta,
    expiry: Option<u64>,
}

/// What an upload's replacements remove (spec/sync.md §5, Replace), planned before it is
/// admitted, and the room they free per cap.
#[derive(Default)]
struct Plan {
    /// Entries removed (durable rows or ephemeral entries), in request order.
    gone: Vec<BlobId>,
    /// Durable entries and bytes freed.
    entries: u64,
    bytes: u64,
    /// Ephemeral memory freed in the label's charge.
    eph_label: u64,
    /// Removals counted against the delete rate.
    counted: u32,
}

/// An ephemeral log record (in memory): no head records go here, so no parsed step.
#[derive(Clone, Copy, Debug)]
enum EphRec {
    Added(BlobId),
    Deleted(BlobId),
}

impl EphRec {
    fn record(self) -> LogRecord {
        match self {
            EphRec::Added(b) => LogRecord::Added(b),
            EphRec::Deleted(b) => LogRecord::Deleted(b),
        }
    }
}

/// A label's ephemeral entries, tombstones and log records (in memory).
#[derive(Clone, Debug, Default)]
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
    /// Memory of its tombstones (charged to the host-wide total only).
    tombs: u64,
}

impl EphLabel {
    /// Everything charged to the label (the host-wide cap's eviction order).
    fn all(&self) -> u64 {
        self.bytes.saturating_add(self.tombs)
    }
}

/// What a charge counts toward (`Ephemeral::charge`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Charge {
    Label,
    Tomb,
}

/// Memory charged per ephemeral entry besides its blob bytes: the entry map's key and value
/// (about 170 bytes), the blob map's entry, the eviction order and due-time index entries and an
/// origin entry, each with its map's node overhead (checked against the
/// type sizes by `overheads_cover_the_structures`). Not a tunable: what an entry really costs.
const ENTRY_OVERHEAD: u64 = 896;
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
#[derive(Clone, Debug, Default)]
struct Ephemeral {
    labels: HashMap<LabelId, EphLabel>,
    blobs: HashMap<BlobId, (Vec<u8>, usize)>,
    /// The log's next sequence number for labels with ephemeral records since start.
    seq: HashMap<LabelId, u64>,
    /// Memory charged over all labels, and the labels by their charge (eviction picks the
    /// largest).
    total: u64,
    by_bytes: BTreeSet<(u64, LabelId)>,
    /// Due times: entry expiries, tombstone drops (stale ones are skipped).
    due: BTreeSet<(u64, LabelId, BlobId)>,
}

impl Ephemeral {
    /// Charges `n` bytes to label `l`: to its cap, or for tombstones to the host-wide total only
    /// (a writer's deletes must not fill the label it compacts: the total bounds them, the label
    /// charged most giving way).
    fn charge(&mut self, l: &LabelId, n: u64, kind: Charge) {
        let e = self.labels.entry(*l).or_default();
        self.by_bytes.remove(&(e.all(), *l));
        match kind {
            Charge::Label => e.bytes = e.bytes.saturating_add(n),
            Charge::Tomb => e.tombs = e.tombs.saturating_add(n),
        }
        self.by_bytes.insert((e.all(), *l));
        self.total = self.total.saturating_add(n);
    }

    fn release(&mut self, l: &LabelId, n: u64, kind: Charge) {
        let Some(e) = self.labels.get_mut(l) else { return };
        self.by_bytes.remove(&(e.all(), *l));
        match kind {
            Charge::Label => e.bytes = e.bytes.saturating_sub(n),
            Charge::Tomb => e.tombs = e.tombs.saturating_sub(n),
        }
        let all = e.all();
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
        self.release(l, REC_OVERHEAD, Charge::Label);
        true
    }
}

/// How an ephemeral entry goes (`HostStore::eph_remove`).
#[derive(Clone, Copy, Debug)]
enum EphRemove {
    Expire,
    Delete(u64),
    Evict,
}

/// Fixed-window counters, kept in memory only (a restart resets them).
#[derive(Clone, Debug, Default)]
struct Rates {
    window: u64,
    labels: HashMap<(LabelId, Rate), u32>,
}

impl Rates {
    fn roll(&mut self, now: u64, window_ms: u64) {
        let w = now / window_ms.max(1);
        if w != self.window {
            self.window = w;
            self.labels.clear();
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
    /// Entries and bytes before this mutation, and whether the label is new (host totals).
    before: (u64, u64, bool),
    batch: Writes,
}

impl Tx {
    fn append(&mut self, r: &LogRecord) -> u64 {
        self.meta.next_seq += 1;
        self.meta.records += 1;
        self.batch.put(key(b'G', &[&self.label.0, &be(self.meta.next_seq)]), encode_record(r));
        self.meta.next_seq
    }
}

/// A due index row: (row key, rest after `t`, value).
type Due = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Host-wide totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub labels: u64,
    pub entries: u64,
    pub bytes: u64,
}

/// What a bounded sweep did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// The budget ran out with due work left.
    pub more: bool,
}

/// A held claim set's rows: the set (`C`) and its index (`H`, a key and its entry box or empty),
/// one row per distinct key (a set may list a key more than once; counting each listing would
/// leave bytes in the totals the sweep never frees).
fn set_rows(label: &LabelId, id: &StepId, c: &ClaimSet) -> (Vec<u8>, Vec<KeyValue>) {
    let index = c.claims.iter().collect::<BTreeSet<_>>().into_iter().map(|k| (key(b'H', &[&label.0, &id.0, k]), c.entries.get(k).map(osis_label::step::entry_box_bytes).unwrap_or_default())).collect();
    (c.to_bytes(), index)
}

fn rows_bytes((set, index): &(Vec<u8>, Vec<KeyValue>)) -> u64 {
    (set.len() + index.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()) as u64
}

/// The bytes step `id`'s claim set `c` counts toward the byte caps while held: the set and its
/// index rows.
pub fn claim_set_bytes(label: &LabelId, id: &StepId, c: &ClaimSet) -> u64 {
    rows_bytes(&set_rows(label, id, c))
}

/// Remembered entry origins (in memory) beyond which the map is cleared.
const MAX_ORIGINS: usize = 1 << 20;

/// `LabelStore` over a `Store`. Holds the store, the clock for rate windows and supersession
/// times, and the policy.
pub struct HostStore {
    /// Reads need the store mutably (`LabelStore` reads take `&self`).
    db: RefCell<Db>,
    /// A write failed since the last `durable`: its transaction was aborted.
    failed: Option<osis_store::Error>,
    seed: [u8; 32],
    clock: Arc<dyn Clock>,
    policy: HostPolicy,
    rates: Rates,
    /// Peer key of the connection whose request is being handled (set by the hub).
    origin: Option<[u8; 32]>,
    /// Who last added or replaced an entry, when known: replication skips sending it back.
    origins: HashMap<(LabelId, BlobId), [u8; 32]>,
    eph: Ephemeral,
    relays: osis_proto::RelayGate,
    /// Commits wait for `durable` (`defer_durability`).
    lazy: bool,
    admission: Admission,
    caps: BTreeMap<LabelId, LabelCaps>,
}

impl HostStore {
    /// Tests only: an exact copy of this host store as it stands, on `clock`, sharing no mutable
    /// state with it: its store and open transaction (`Store::test_copy`), rates, ephemeral
    /// entries and gates, its rng going on with the same stream. Never in a product: two hosts
    /// with one instance seed and rng stream.
    #[doc(hidden)]
    pub fn test_copy(&self, clock: Arc<dyn Clock>) -> Result<HostStore, osis_store::Error> {
        let db = self.db.borrow();
        let db = Db { store: db.store.test_copy()?, table: db.table, rng: db.rng.test_copy(), open: db.open.as_ref().map(Suspended::test_copy) };
        Ok(HostStore {
            db: RefCell::new(db),
            failed: self.failed.clone(),
            seed: self.seed,
            clock,
            policy: self.policy.clone(),
            rates: self.rates.clone(),
            origin: self.origin,
            origins: self.origins.clone(),
            eph: self.eph.clone(),
            relays: self.relays.clone(),
            lazy: self.lazy,
            admission: self.admission.clone(),
            caps: self.caps.clone(),
        })
    }

    /// Opens the host store over `store` (the host's own, never the node's), creating its table
    /// and the instance seed (log IDs derive from it) on first use. `rng` keys the store's units.
    pub fn open(mut store: Store, clock: Arc<dyn Clock>, policy: HostPolicy, mut rng: Box<dyn osis_crypto::NodeRng>) -> Result<HostStore, StoreError> {
        let mut fresh = [0u8; 32];
        rng.fill_bytes(&mut fresh);
        let mut t = store.transaction(&mut *rng).map_err(err)?;
        let table = t.index(TABLE).map_err(err)?;
        let seed = match t.table_get(table, b"I").map_err(err)? {
            Some(s) => s.as_slice().try_into().map_err(|_| corrupt("seed"))?,
            None => {
                t.table_put(table, b"I", fresh.to_vec(), Shred::No).map_err(err)?;
                fresh
            }
        };
        t.commit().map_err(err)?;
        let relays = osis_proto::RelayGate::default();
        let db = RefCell::new(Db { store, table, rng, open: None });
        let mut s = HostStore { db, failed: None, seed, clock, policy: HostPolicy::default(), rates: Rates::default(), origin: None, origins: HashMap::new(), eph: Ephemeral::default(), relays, lazy: false, admission: Admission::Open, caps: BTreeMap::new() };
        s.set_policy(policy);
        Ok(s)
    }

    /// Replaces the policy (rate windows restart).
    pub fn set_policy(&mut self, policy: HostPolicy) {
        let mut policy = policy;
        policy.tombstone_ms = policy.tombstone_ms.max(TOMBSTONE_LIFETIME_MS);
        self.relays = osis_proto::RelayGate::new(osis_proto::RelayLimits { count: policy.relays, bytes: policy.relay_bytes, window_ms: policy.window_ms });
        self.policy = policy;
    }

    /// Which labels new registrations are taken for, and per-label caps in place of the
    /// policy's (`HostConfig`).
    pub fn set_admission(&mut self, admission: Admission, caps: BTreeMap<LabelId, LabelCaps>) {
        self.admission = admission;
        self.caps = caps;
    }

    /// `label`'s entry and byte caps.
    fn label_caps(&self, label: &LabelId) -> (u64, u64) {
        self.caps.get(label).map_or((self.policy.cap_entries, self.policy.cap_bytes), |c| (c.entries, c.bytes))
    }

    /// The underlying store, its open transaction committed first (tests: forensic checks of
    /// what it holds).
    #[doc(hidden)]
    pub fn store_mut(&mut self) -> Result<&mut Store, StoreError> {
        let db = self.db.get_mut();
        db.commit().map_err(err)?;
        Ok(&mut db.store)
    }

    /// Mutations from now on are visible at once and committed together at the next `durable`
    /// (the hub's batch: one store commit, one shredding root write at most, per handled input
    /// instead of per entry).
    pub fn defer_durability(&mut self) {
        self.lazy = true;
    }

    /// Commits every mutation since `defer_durability` and commits per mutation again. Nothing
    /// is acknowledged to a peer before it returns `Ok`. A write that failed in between fails
    /// it (its transaction, with every mutation since the last commit, was aborted).
    pub fn durable(&mut self) -> Result<(), StoreError> {
        self.lazy = false;
        self.commit()
    }

    /// Commits the open transaction now, deferred or not (a sweep's own failure is the sweep's).
    /// A write that failed since the last commit fails it.
    pub fn commit(&mut self) -> Result<(), StoreError> {
        if let Some(e) = self.failed.take() {
            // what was written after the failure goes with it
            self.db.get_mut().open = None;
            return Err(err(e));
        }
        self.db.get_mut().commit().map_err(err)
    }

    fn write(&mut self, w: Writes) -> Result<(), StoreError> {
        let db = self.db.get_mut();
        let r = db.apply(w).and_then(|()| if self.lazy { Ok(()) } else { db.commit() });
        if let Err(e) = &r
            && self.lazy
        {
            self.failed = Some(e.clone());
        }
        r.map_err(err)
    }

    /// Rows the store holds (tests, diagnostics).
    pub fn rows(&self) -> Result<u64, StoreError> {
        self.db.borrow_mut().run(|t, table| t.table_len(table)).map_err(err)
    }

    /// Every row, key and value (tests counting what grows).
    #[doc(hidden)]
    pub fn all_rows(&self) -> Result<Vec<KeyValue>, StoreError> {
        self.scan(b"", None, usize::MAX)
    }

    fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.db.borrow_mut().run(|t, table| t.table_get(table, k)).map_err(err)
    }

    /// Up to `limit` rows with `start <= key < end` (`None`: unbounded), ascending.
    fn scan(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<KeyValue>, StoreError> {
        self.db.borrow_mut().run(|t, table| t.table_range(table, start, end, limit)).map_err(err)
    }

    fn scan_prefix(&self, prefix: &[u8], limit: usize) -> Result<Vec<KeyValue>, StoreError> {
        self.scan(prefix, osis_store::prefix_end(prefix).as_deref(), limit)
    }

    pub fn policy(&self) -> &HostPolicy {
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
        let Some(b) = self.get(b"N")? else { return Ok(Totals::default()) };
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
        self.get(&key(b'L', &[&label.0]))?.map(|b| Meta::decode(&b)).transpose()
    }

    /// Ephemeral memory charged per label: blobs and per-entry, per-tombstone and per-record
    /// overhead (tests, diagnostics).
    pub fn ephemeral_bytes(&self, label: &LabelId) -> u64 {
        self.eph.labels.get(label).map_or(0, |e| e.bytes)
    }

    /// Whether a new plain ephemeral entry of `size` blob bytes would fit under `label`'s cap,
    /// every log record trimmed as an upload would (tests: a refusal is genuine).
    pub fn ephemeral_fits(&self, label: &LabelId, size: u64) -> bool {
        let used = self.eph.labels.get(label).map_or(0, |e| e.bytes.saturating_sub(REC_OVERHEAD.saturating_mul(e.log.len() as u64)));
        used.saturating_add(size).saturating_add(ENTRY_OVERHEAD).saturating_add(REC_OVERHEAD) <= self.policy.ephemeral_bytes
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
            let mut b = Writes::default();
            b.put(key(b'L', &[&label.0]), raw.encode());
            self.write(b)?;
        }
        self.eph.seq.insert(*label, seq);
        self.eph.labels.entry(*label).or_default().log.push_back((seq, r));
        self.eph.charge(label, REC_OVERHEAD, Charge::Label);
        if self.eph.labels.get(label).is_some_and(|e| e.log.len() > EPH_LOG_KEEP) {
            self.eph.trim_log(label);
        }
        // a record no upload made room for (a deletion's) stays within the cap: older records go
        while self.eph.labels.get(label).is_some_and(|e| e.bytes > self.policy.ephemeral_bytes) && self.eph.trim_log(label) {}
        Ok(seq)
    }

    /// Removes an ephemeral entry: silently (expiry), with a tombstone and a log record (a
    /// delete), or with a log record only (evicted for the host-wide cap: holders may bring it
    /// back).
    fn eph_remove(&mut self, label: &LabelId, blob: &BlobId, how: EphRemove) -> Result<bool, StoreError> {
        let Some(e) = self.eph.labels.get_mut(label) else { return Ok(false) };
        let Some(x) = e.entries.remove(blob) else { return Ok(false) };
        e.order.remove(&x.meta.add_seq);
        if let Some(t) = x.expiry {
            self.eph.due.remove(&(t, *label, *blob));
        }
        self.eph.release(label, x.meta.size.saturating_add(ENTRY_OVERHEAD), Charge::Label);
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
                    self.eph.charge(label, TOMB_OVERHEAD, Charge::Tomb);
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

    /// Frees ephemeral memory for the host-wide cap from the label charged most (M4 of the
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
        self.eph.release(&l, TOMB_OVERHEAD, Charge::Tomb);
        Ok(true)
    }

    /// Adds an ephemeral entry (spec/sync.md §4, §5): stamped only; past the label's ephemeral
    /// cap (after trimming its log) code 12; past the node's, the label charged most gives way.
    fn eph_put(&mut self, label: &LabelId, put: Put<'_>, plan: &Plan) -> Result<Code, StoreError> {
        let Some(stamp) = put.stamp else { return Ok(Code::REFUSED) };
        // always stamped: a held one never changes (`LabelStore::put`)
        if self.eph.labels.get(label).is_some_and(|e| e.entries.contains_key(&put.blob_id)) {
            return Ok(Code::OK);
        }
        // the planned removals' memory still held (an eviction below may take one first)
        let freed = |s: &Self| plan.gone.iter().filter_map(|b| s.eph_entry(label, b)).map(|e| e.meta.size.saturating_add(ENTRY_OVERHEAD)).fold(0u64, u64::saturating_add);
        let now = self.now();
        self.rates.roll(now, self.policy.window_ms);
        let size = put.blob.len() as u64;
        let need = size.saturating_add(ENTRY_OVERHEAD).saturating_add(REC_OVERHEAD);
        let used = |s: &Self| s.eph.labels.get(label).map_or(0, |e| e.bytes).saturating_sub(plan.eph_label);
        while used(self).saturating_add(need) > self.policy.ephemeral_bytes && self.eph.trim_log(label) {}
        if used(self).saturating_add(need) > self.policy.ephemeral_bytes {
            return Ok(Code::STORAGE_CAP);
        }
        while self.eph.total.saturating_sub(freed(self)).saturating_add(need) > self.policy.ephemeral_total {
            if !self.eph_evict()? {
                return Ok(Code::STORAGE_CAP);
            }
        }
        let seq = self.eph_append(label, EphRec::Added(put.blob_id))?;
        let e = self.eph.labels.entry(*label).or_default();
        e.order.insert(seq, put.blob_id);
        e.entries.insert(put.blob_id, EphEntry { meta: EntryMeta { wrap: put.wrap, stamp: Some(stamp), size, add_seq: seq }, expiry: put.expiry });
        if let Some(t) = put.expiry {
            self.eph.due.insert((t, *label, put.blob_id));
        }
        self.eph.charge(label, size.saturating_add(ENTRY_OVERHEAD), Charge::Label);
        self.eph.blobs.entry(put.blob_id).or_insert_with(|| (put.blob.to_vec(), 0)).1 += 1;
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

    /// Adds a durable entry or promotes a deposited one (spec/sync.md §4, §5): past the label's
    /// or the node's cap, the room `plan`'s removals free counted, code 12.
    fn durable_put(&mut self, label: &LabelId, put: Put<'_>, held: Option<Row>, plan: &Plan) -> Result<Code, StoreError> {
        let mut tx = self.tx(label)?;
        if let Some(r) = &held
            && (put.stamp.is_none() || r.meta.stamp.is_some())
        {
            return Ok(Code::OK);
        }
        let size = put.blob.len() as u64;
        let now = self.now();
        self.rates.roll(now, self.policy.window_ms);
        match &held {
            // a promotion: once per entry
            Some(_) => {}
            None => {
                let m = &tx.meta;
                let (entries, bytes) = (m.entries.saturating_sub(plan.entries), m.bytes.saturating_sub(plan.bytes));
                let (cap_entries, cap_bytes) = self.label_caps(label);
                if entries.saturating_add(1) > cap_entries || bytes.saturating_add(size) > cap_bytes {
                    return Ok(Code::STORAGE_CAP);
                }
                let t = self.totals()?;
                let p = &self.policy;
                let (entries, bytes) = (t.entries.saturating_sub(plan.entries), t.bytes.saturating_sub(plan.bytes));
                if entries.saturating_add(1) > p.max_entries || bytes.saturating_add(size) > p.max_bytes {
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
                let (refs, _) = self.refs(&put.blob_id)?;
                if refs == 0 {
                    tx.batch.put_blob(put.blob_id, put.blob.to_vec());
                }
                let prefix = osis_label::prefix_bytes(put.blob);
                tx.batch.put(key(b'R', &[&put.blob_id.0]), [&be(refs + 1)[..], prefix].concat());
                Row { meta: EntryMeta { wrap: put.wrap, stamp: put.stamp, size, add_seq: seq }, expiry: put.expiry }
            }
        };
        tx.batch.put(key(b'E', &[&l, &put.blob_id.0]), row.encode());
        tx.batch.log(Write::LogAdded(*label, put.blob_id));
        self.finish(tx)?;
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

    /// Plans `put`'s replacements (spec/sync.md §5, Replace): what goes, the room freed.
    fn plan(&self, label: &LabelId, put: &Put<'_>) -> Result<Plan, StoreError> {
        let mut plan = Plan::default();
        let mut seen = BTreeSet::new();
        for &b in put.replaces {
            if b == put.blob_id || seen.contains(&b) {
                continue;
            }
            if let Some(e) = self.eph_entry(label, &b) {
                seen.insert(b);
                plan.eph_label = plan.eph_label.saturating_add(e.meta.size.saturating_add(ENTRY_OVERHEAD));
                plan.counted += 1;
                plan.gone.push(b);
            } else if let Some(row) = self.row(label, &b)? {
                seen.insert(b);
                plan.entries += 1;
                plan.bytes = plan.bytes.saturating_add(row.meta.size);
                plan.counted += 1;
                plan.gone.push(b);
            }
        }
        Ok(plan)
    }

    /// Carries out a planned replacement once its upload was admitted (logged after the add):
    /// each entry removed as a Delete removes it.
    fn replace(&mut self, label: &LabelId, plan: &Plan, now: u64) -> Result<(), StoreError> {
        if plan.gone.is_empty() {
            return Ok(());
        }
        let mut tx = self.tx(label)?;
        let mut durable = false;
        for b in &plan.gone {
            if self.eph_entry(label, b).is_some() {
                self.eph_remove(label, b, EphRemove::Delete(now))?;
            } else if let Some(row) = self.row(label, b)? {
                self.remove(&mut tx, b, &row, now, true)?;
                durable = true;
            }
        }
        if durable {
            self.finish(tx)?;
        }
        Ok(())
    }

    fn eph_entry(&self, label: &LabelId, blob: &BlobId) -> Option<&EphEntry> {
        self.eph.labels.get(label)?.entries.get(blob)
    }

    /// Runs due ephemeral expiries and tombstone drops, at most `budget` of them; the number of
    /// due items handled.
    fn eph_sweep(&mut self, now: u64, budget: usize) -> Result<usize, StoreError> {
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
                }
            } else if e.tombstones.get(&b).is_some_and(|d| *d <= now) {
                if let Some(e) = self.eph.labels.get_mut(&l) {
                    e.tombstones.remove(&b);
                }
                self.eph.release(&l, TOMB_OVERHEAD, Charge::Tomb);
            }
        }
        Ok(n)
    }

    /// The earliest ephemeral expiry or tombstone drop.
    fn eph_next_due(&self) -> Option<u64> {
        self.eph.due.first().map(|(t, _, _)| *t)
    }

    /// A `V` or `W` row: a step ID.
    fn step_row(&self, k: Vec<u8>) -> Result<Option<StepId>, StoreError> {
        self.get(&k)?.map(|b| read_arr(&b, 0).map(StepId)).transpose()
    }

    fn row(&self, label: &LabelId, blob: &BlobId) -> Result<Option<Row>, StoreError> {
        self.get(&key(b'E', &[&label.0, &blob.0]))?.map(|b| Row::decode(&b)).transpose()
    }

    fn tx(&self, label: &LabelId) -> Result<Tx, StoreError> {
        let meta = self.meta(label)?.ok_or_else(unknown)?;
        Ok(Tx { label: *label, before: (meta.entries, meta.bytes, false), meta, batch: Writes::default() })
    }

    /// Trims the log to `log_keep` durable records (in steps of 1/8 of it: the oldest `G` rows,
    /// scanned, so ephemeral records and reserved numbers in between cost nothing) and commits.
    fn finish(&mut self, mut tx: Tx) -> Result<(), StoreError> {
        let keep = self.policy.log_keep.max(1);
        if tx.meta.records > keep.saturating_add(keep / 8) {
            let drop = usize::try_from(tx.meta.records - keep).unwrap_or(usize::MAX);
            let prefix = key(b'G', &[&tx.label.0]);
            let end = osis_store::prefix_end(&prefix);
            let rows = self.scan(&prefix, end.as_deref(), drop)?;
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
        self.write(tx.batch)
    }

    fn budget_max(&self, m: &Meta) -> u64 {
        self.policy.deposit_factor.max(1).saturating_mul(64u64.saturating_add(m.head_claims.saturating_mul(4)))
    }

    /// Removes a held entry at `now` within `tx`: counters, indexes, blob reference; a tombstone
    /// and a deletion record when `tombstone`. Either way a `Y` row due `tombstone_ms` later
    /// holds the log position the entry is gone at: the sweep then drops the log up to it
    /// (spec/sync.md §4; a cursor below falls back to range reconciliation, §6).
    fn remove(&self, tx: &mut Tx, blob: &BlobId, row: &Row, now: u64, tombstone: bool) -> Result<(), StoreError> {
        let l = tx.label.0;
        tx.batch.delete(key(b'E', &[&l, &blob.0]));
        if let Some(t) = row.expiry {
            tx.batch.delete(key(b'X', &[&be(t), &l, &blob.0]));
        }
        let m = &mut tx.meta;
        m.entries = m.entries.saturating_sub(1);
        m.bytes = m.bytes.saturating_sub(row.meta.size);
        if row.meta.stamp.is_none() {
            m.dep_n = m.dep_n.saturating_sub(1);
            m.dep_bytes = m.dep_bytes.saturating_sub(row.meta.size);
        }
        let drop = now.saturating_add(self.policy.tombstone_ms);
        let seq = if tombstone {
            // A tombstone already present keeps its first drop time row; replace it.
            if let Some(old) = self.get(&key(b'T', &[&l, &blob.0]))? {
                tx.batch.delete(key(b'Y', &[&old, &l, &blob.0]));
            }
            tx.batch.put(key(b'T', &[&l, &blob.0]), be(drop).to_vec());
            tx.append(&LogRecord::Deleted(*blob))
        } else {
            tx.meta.next_seq
        };
        tx.batch.put(key(b'Y', &[&be(drop), &l, &blob.0]), [be(seq).as_slice(), &[u8::from(tombstone)]].concat());
        // the node log takes every removal, an expiry too: the entry left the node
        tx.batch.log(Write::LogDeleted(tx.label, *blob, now));
        let (refs, prefix) = self.refs(blob)?;
        if refs <= 1 {
            tx.batch.delete(key(b'R', &[&blob.0]));
            tx.batch.delete_blob(*blob);
        } else {
            tx.batch.put(key(b'R', &[&blob.0]), [&be(refs - 1)[..], &prefix].concat());
        }
        Ok(())
    }

    /// A blob's reference count and its prefix bytes (`R` row; 0 and none when not held).
    fn refs(&self, blob: &BlobId) -> Result<(u64, Vec<u8>), StoreError> {
        let Some(b) = self.get(&key(b'R', &[&blob.0]))? else { return Ok((0, Vec::new())) };
        Ok((read_u64(&b, 0)?, b.get(8..).unwrap_or_default().to_vec()))
    }

    /// Up to `limit` due index rows `tag t ...` with `t <= now`.
    fn due(&self, tag: u8, now: u64, limit: usize) -> Result<Vec<Due>, StoreError> {
        let end = key(tag, &[&be(now.saturating_add(1))]);
        let start = [tag];
        let end = if now == u64::MAX { osis_store::prefix_end(&start) } else { Some(end) };
        let rows = self.scan(&start, end.as_deref(), limit)?;
        Ok(rows.into_iter().map(|(k, v)| (k.clone(), k.get(9..).unwrap_or(&[]).to_vec(), v)).collect())
    }

    /// Expires entries (no tombstone, no per-label record; a node log deletion), drops old
    /// tombstones and the log up to removals that old, and claim sets superseded for
    /// `claim_keep_ms`; at most `budget` index and log rows, one commit per label; then a page of
    /// the node log's sweep. An index row that does not parse, or names a label not held, is dropped.
    pub fn sweep(&mut self, now: u64, budget: usize) -> Result<Swept, StoreError> {
        let mut out = Swept::default();
        let mut left = budget.max(1);
        let mut junk = Writes::default();
        let mut by_label: BTreeMap<LabelId, Vec<(Vec<u8>, BlobId)>> = BTreeMap::new();
        let due = self.due(b'X', now, left)?;
        left -= due.len();
        for (k, rest, _) in due {
            match (read_arr(&rest, 0).map(LabelId), read_arr(&rest, 16).map(BlobId)) {
                (Ok(l), Ok(b)) if rest.len() == 48 => by_label.entry(l).or_default().push((k, b)),
                _ => junk.delete(k),
            }
        }
        for (label, rows) in by_label {
            let Ok(mut tx) = self.tx(&label) else {
                for (k, _) in rows {
                    junk.delete(k);
                }
                continue;
            };
            let mut done = BTreeSet::new();
            for (k, blob) in rows {
                tx.batch.delete(k);
                if !done.insert(blob) {
                    continue;
                }
                let raw = self.get(&key(b'E', &[&label.0, &blob.0]))?;
                if let Some(Ok(row)) = raw.map(|r| Row::decode(&r)) {
                    self.remove(&mut tx, &blob, &row, now, false)?;
                }
            }
            self.finish(tx)?;
        }
        // removals past their lifetime: a deletion's tombstone goes, and the label's log up to
        // the highest position an entry went at (spec/sync.md §4; each record once over the log's
        // life); the `Y` and `G` rows dropped count against the budget, so a sweep whose budget
        // the due `Y` rows fill still drops some; a trim the budget cuts short keeps that highest
        // `Y` row (and its tombstone) for the next sweep
        let mut b = Writes::default();
        let drop_y = |b: &mut Writes, (k, rest, v): Due| {
            if v.get(8) == Some(&1) {
                b.delete(key(b'T', &[&rest]));
            }
            b.delete(k);
        };
        let mut trim: BTreeMap<LabelId, (u64, Due)> = BTreeMap::new();
        for row in self.due(b'Y', now, left)? {
            let gone = match (read_arr(&row.1, 0).map(LabelId), read_u64(&row.2, 0)) {
                (Ok(l), Ok(seq)) if row.1.len() == 48 && trim.get(&l).is_none_or(|t| t.0 <= seq) => trim.insert(l, (seq, row)).map(|t| t.1),
                _ => Some(row),
            };
            if let Some(row) = gone {
                drop_y(&mut b, row);
                left -= 1;
            }
        }
        for (label, (seq, row)) in trim {
            let mut done = true;
            if let Ok(mut tx) = self.tx(&label)
                && seq > tx.meta.horizon
            {
                let prefix = key(b'G', &[&label.0]);
                let rows = self.scan(&prefix, Some(&key(b'G', &[&label.0, &be(seq.saturating_add(1))])), left)?;
                done = rows.len() < left;
                left -= rows.len();
                for (k, _) in &rows {
                    tx.batch.delete(k.clone());
                }
                tx.meta.records = tx.meta.records.saturating_sub(rows.len() as u64);
                tx.meta.horizon = match rows.last() {
                    _ if done => seq,
                    Some((k, _)) => read_u64(k, 17)?,
                    None => tx.meta.horizon,
                };
                self.finish(tx)?;
            }
            if done {
                drop_y(&mut b, row);
                left = left.saturating_sub(1);
            }
        }
        // a dropped claim set's bytes, its index rows' included, leave the label's and the
        // host's totals; each index row counts against the budget (a set has up to `MAX_CLAIMS`
        // keys), so a set may go over several sweeps, its `Z` row kept until the last
        for (k, rest, _) in self.due(b'Z', now, left)? {
            if left == 0 {
                break;
            }
            left -= 1;
            let label = match read_arr(&rest, 0).map(LabelId) {
                Ok(l) if rest.len() == 48 => l,
                _ => {
                    b.delete(k);
                    continue;
                }
            };
            let index = self.scan_prefix(&key(b'H', &[&rest]), left)?;
            let all = index.len() < left;
            left -= index.len();
            let mut freed: usize = index.iter().map(|(k, v)| k.len() + v.len()).sum();
            let mut batch = Writes::default();
            for (h, _) in index {
                batch.delete(h);
            }
            if all {
                let c = key(b'C', &[&rest]);
                freed += self.get(&c)?.map_or(0, |set| set.len());
                batch.delete(c);
                batch.delete(k);
            }
            match self.tx(&label) {
                Ok(mut tx) => {
                    tx.meta.bytes = tx.meta.bytes.saturating_sub(freed as u64);
                    tx.batch = batch;
                    self.finish(tx)?;
                }
                Err(_) => b.0.extend(batch.0),
            }
        }
        b.0.extend(junk.0);
        if !b.is_empty() {
            self.write(b)?;
        }
        left -= self.eph_sweep(now, left)?;
        // the node log's deletion events past their lifetime, a page a sweep
        let log_due = |s: &mut Self| s.db.get_mut().run(|t, _| t.log_next_due()).map(|d| d.is_some_and(|t| t <= now)).map_err(err);
        if log_due(self)? {
            let mut log = Writes::default();
            log.log(Write::LogSweep(now));
            self.write(log)?;
        }
        out.more = left == 0 || log_due(self)?;
        Ok(out)
    }

    /// Up to `max` labels held above `after` (from the lowest when none), ascending.
    pub fn labels_after(&self, after: Option<&LabelId>, max: usize) -> Result<Vec<LabelId>, StoreError> {
        let start = match after {
            Some(a) => key(b'L', &[&a.0, &[0]]),
            None => b"L".to_vec(),
        };
        let rows = self.scan(&start, Some(b"M"), max)?;
        rows.iter().map(|(k, _)| read_arr(k, 1).map(LabelId)).collect()
    }

    /// Next due sweep time (earliest index row), if any.
    pub fn next_due(&self) -> Result<Option<u64>, StoreError> {
        let mut next = self.eph_next_due();
        if let Some(t) = self.db.borrow_mut().run(|t, _| t.log_next_due()).map_err(err)? {
            next = Some(next.map_or(t, |n| n.min(t)));
        }
        for tag in *b"XPYZ" {
            if let Some((k, _)) = self.scan_prefix(&[tag], 1)?.first() {
                let t = read_u64(k, 1)?;
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        }
        Ok(next)
    }

    /// Log position replicated to `peer` for `label`: (log ID it refers to, sequence number).
    pub fn replica_pos(&self, peer: &[u8; 32], label: &LabelId) -> Result<Option<([u8; 16], u64)>, StoreError> {
        let Some(b) = self.get(&key(b'Q', &[peer, &label.0]))? else { return Ok(None) };
        Ok(Some((read_arr(&b, 0)?, read_u64(&b, 16)?)))
    }

    pub fn set_replica_pos(&mut self, peer: &[u8; 32], label: &LabelId, log_id: [u8; 16], seq: u64) -> Result<(), StoreError> {
        let mut b = Writes::default();
        b.put(key(b'Q', &[peer, &label.0]), [&log_id[..], &be(seq)].concat());
        self.write(b)
    }
}

impl LabelStore for HostStore {
    fn head(&self, label: &LabelId) -> Result<Option<StepId>, StoreError> {
        Ok(self.meta(label)?.and_then(|m| m.head))
    }

    fn step(&self, label: &LabelId, id: &StepId) -> Result<Option<Step>, StoreError> {
        let Some(b) = self.get(&key(b'S', &[&label.0, &id.0]))? else { return Ok(None) };
        Step::parse(&b).map(Some).map_err(|_| corrupt("step"))
    }

    fn claim_set(&self, label: &LabelId, id: &StepId) -> Result<Option<Arc<ClaimSet>>, StoreError> {
        let Some(b) = self.get(&key(b'C', &[&label.0, &id.0]))? else { return Ok(None) };
        ClaimSet::parse(&b).map(|c| Some(Arc::new(c))).map_err(|_| corrupt("claim set"))
    }

    /// One `H` row read: an Open by claim or static entry costs a lookup, not the set's size.
    fn claim(&self, label: &LabelId, id: &StepId, k: &[u8; 32]) -> Result<Option<Option<SecretBox>>, StoreError> {
        let Some(b) = self.get(&key(b'H', &[&label.0, &id.0, k]))? else { return Ok(None) };
        if b.is_empty() {
            return Ok(Some(None));
        }
        osis_label::step::parse_entry_box(&b).map(|e| Some(Some(e))).map_err(|_| corrupt("entry box"))
    }

    fn head_keys(&self, label: &LabelId) -> Result<Option<HeadKeys>, StoreError> {
        let Some(head) = self.head(label)? else { return Ok(None) };
        let step = self.step(label, &head)?.ok_or_else(|| corrupt("head step"))?;
        let b = self.get(&key(b'K', &[&label.0]))?.ok_or_else(|| corrupt("head keys"))?;
        Ok(Some(HeadKeys { head: step, older: decode_older(&b)? }))
    }

    fn step_with_sync(&self, label: &LabelId, pk: &osis_crypto::VerifyingKey) -> Result<Option<StepId>, StoreError> {
        self.step_row(key(b'V', &[&label.0, &pk.to_bytes()]))
    }

    fn child(&self, label: &LabelId, step: Option<&StepId>) -> Result<Option<StepId>, StoreError> {
        self.step_row(key(b'W', &[&label.0, step.map_or(&[][..], |s| &s.0[..])]))
    }

    fn admit_label(&self, label: &LabelId) -> Result<Code, StoreError> {
        if !self.admission.admits(label) {
            return Ok(Code::NOT_ADMITTED);
        }
        let t = self.totals()?;
        let p = &self.policy;
        Ok(if t.labels >= p.max_labels || t.entries >= p.max_entries || t.bytes >= p.max_bytes { Code::STORAGE_CAP } else { Code::OK })
    }

    /// The step's and its claim set's bytes count toward the label's and the host's byte caps
    /// (the claim set's until the sweep drops it): past them a genesis step is refused, a child
    /// step kept without its set (past them even so: once per `over_cap_step_ms`);
    /// registrations are rate-limited per label.
    fn push_step(&mut self, label: &LabelId, step: Step, claim_set: Option<ClaimSet>) -> Result<Code, StoreError> {
        let (meta, new) = match self.meta(label)? {
            Some(m) => (m, false),
            None => {
                let h = osis_base::hash::hash(&[&self.seed[..], &label.0[..]].concat());
                (Meta { log_id: read_arr(&h, 0)?, ..Meta::default() }, true)
            }
        };
        let keys = match meta.head {
            Some(_) => self.head_keys(label)?.ok_or_else(|| corrupt("head keys"))?.child(step.clone()),
            None => HeadKeys::genesis(step.clone()),
        };
        let step_bytes = step.to_bytes();
        let id = step.id();
        let mut set_rows = claim_set.as_ref().map(|c| set_rows(label, &id, c));
        let cap_bytes = self.label_caps(label).1;
        let fits = |n: u64, total: u64| meta.bytes.saturating_add(n) <= cap_bytes && total.saturating_add(n) <= self.policy.max_bytes;
        let total = self.totals()?.bytes;
        let mut size = step_bytes.len() as u64 + set_rows.as_ref().map_or(0, rows_bytes);
        let mut over = false;
        if !fits(size, total) {
            // a new label is refused; a child step is taken without its claim set (a refused
            // rotation keeps a removed holder's open and write keys valid here), even past the
            // cap once per `over_cap_step_ms`, so the label's own admin alone spends that room
            if new {
                return Ok(Code::STORAGE_CAP);
            }
            set_rows = None;
            size = step_bytes.len() as u64;
            over = !fits(size, total);
            // a wait longer than the interval (a clock set back, a shorter interval configured)
            // is over: a label never waits more than one interval
            let wait = meta.over_cap_until.saturating_sub(self.now());
            if over && wait > 0 && wait <= self.policy.over_cap_step_ms {
                return Ok(Code::STORAGE_CAP);
            }
        }
        self.rates.roll(self.now(), self.policy.window_ms);
        if !self.rates.take(label, Rate::Register, self.policy.registers) {
            return Ok(Code::RATE_LIMITED);
        }
        let mut tx = Tx { label: *label, before: (meta.entries, meta.bytes, new), meta, batch: Writes::default() };
        tx.meta.bytes = tx.meta.bytes.saturating_add(size);
        if over {
            tx.meta.over_cap_until = self.now().saturating_add(self.policy.over_cap_step_ms);
        }
        tx.batch.put(key(b'K', &[&label.0]), encode_older(&keys.older));
        if let Some(prev) = tx.meta.head {
            let drop = self.now().saturating_add(self.policy.claim_keep_ms.max(ROLE_KEEP_MS));
            tx.batch.put(key(b'Z', &[&be(drop), &label.0, &prev.0]), vec![]);
        }
        tx.meta.head = Some(id);
        tx.meta.head_claims = claim_set.as_ref().map_or(0, |c| c.claims.len() as u64);
        tx.batch.put(key(b'S', &[&label.0, &id.0]), step_bytes);
        tx.batch.put(key(b'V', &[&label.0, &step.keys.sync.to_bytes()]), id.0.to_vec());
        tx.batch.put(key(b'W', &[&label.0, step.prev.as_ref().map_or(&[][..], |p| &p.0[..])]), id.0.to_vec());
        if let Some((c, index)) = set_rows {
            tx.batch.put(key(b'C', &[&label.0, &id.0]), c);
            for (k, v) in index {
                tx.batch.put(k, v);
            }
        }
        tx.append(&LogRecord::Head(step));
        tx.batch.log(Write::LogHead(*label, id));
        self.finish(tx)?;
        Ok(Code::OK)
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
        Ok(self.get(&key(b'T', &[&label.0, &blob_id.0]))?.is_some())
    }

    fn blob(&self, blob_id: &BlobId) -> Result<Option<Vec<u8>>, StoreError> {
        if let Some((b, _)) = self.eph.blobs.get(blob_id) {
            return Ok(Some(b.clone()));
        }
        self.db.borrow_mut().run(|t, _| t.get_blob(blob_id)).map_err(err)
    }

    fn blob_prefix(&self, blob_id: &BlobId) -> Result<Option<Vec<u8>>, StoreError> {
        if let Some((b, _)) = self.eph.blobs.get(blob_id) {
            return Ok(Some(osis_label::prefix_bytes(b).to_vec()));
        }
        let (refs, prefix) = self.refs(blob_id)?;
        Ok((refs > 0).then_some(prefix))
    }

    fn put(&mut self, label: &LabelId, put: Put<'_>) -> Result<Code, StoreError> {
        let plan = self.plan(label, &put)?;
        // the removals count against the delete rate (taken even if the upload is then refused
        // for its cap: a minor overcount)
        if plan.counted > 0 {
            self.rates.roll(self.now(), self.policy.window_ms);
            for _ in 0..plan.counted {
                if !self.rates.take(label, Rate::Delete, self.policy.deletes) {
                    return Ok(Code::RATE_LIMITED);
                }
            }
        }
        let held = self.row(label, &put.blob_id)?;
        // an ephemeral blob (unless the same blob is held as a durable entry) stays in memory
        let code = if (put.ephemeral && held.is_none()) || self.eph_entry(label, &put.blob_id).is_some() {
            self.eph_put(label, put, &plan)?
        } else {
            self.durable_put(label, put, held, &plan)?
        };
        if code == Code::OK {
            self.replace(label, &plan, put.now)?;
        }
        Ok(code)
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
        self.remove(&mut tx, blob_id, &row, now, true)?;
        self.finish(tx)?;
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
        let rows = self.scan(&start, end.as_deref(), max)?;
        let mut out = rows.iter().map(|(k, v)| Ok((read_u64(k, 17)?, decode_record(v)?))).collect::<Result<Vec<_>, StoreError>>()?;
        // the ephemeral records in sequence order among them; where the ephemeral log was trimmed
        // past `after`, the live entries added since stand in for their add records (the
        // deletions trimmed are not repeated), so ephemeral churn never sends a
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
        let rows = self.scan(&start, end.as_deref(), max)?;
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

    fn live_ids_in(&self, label: &LabelId, lower: &BlobId, upper: Option<&BlobId>) -> Result<Vec<BlobId>, StoreError> {
        if upper.is_some_and(|u| u <= lower) {
            return Ok(Vec::new());
        }
        let start = key(b'E', &[&label.0, &lower.0]);
        let end = match upper {
            Some(u) => Some(key(b'E', &[&label.0, &u.0])),
            None => osis_store::prefix_end(&key(b'E', &[&label.0])),
        };
        let rows = self.scan(&start, end.as_deref(), usize::MAX)?;
        let mut out = rows.iter().map(|(k, _)| Ok(BlobId(read_arr(k, 17)?))).collect::<Result<Vec<_>, StoreError>>()?;
        if let Some(e) = self.eph.labels.get(label) {
            let eph = match upper {
                Some(u) => e.entries.range(*lower..*u),
                None => e.entries.range(*lower..),
            };
            out.extend(eph.map(|(b, _)| *b));
            out.sort();
        }
        Ok(out)
    }

    fn relay(&mut self, label: &LabelId, blob_id: &BlobId, size: usize, expiry: Option<u64>, now: u64) -> Result<osis_proto::RelayVerdict, StoreError> {
        Ok(self.relays.admit(label, blob_id, size, expiry, now))
    }
}

#[cfg(test)]
mod tests;

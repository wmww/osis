//! `HostStore`: osis-proto's `LabelStore` over its own osis-store `Store` (spec/sync.md §4, §5):
//! registration paths, entries, tombstones, blob bytes stored once with reference counts, expiry,
//! claim-set retention, the node log (notes/local-store.md, Node log), and the host policy
//! (storage caps, deposit budget, rate limits). Every mutation's writes apply together to the open store
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
//! `L label` meta; `K label` the head's earlier role keys (`HeadKeys`); `S label step`
//! step; `C label step` claim set; path indexes `V label sync_key` the newest step registering
//! that sync key, `W label` the genesis step and `W label step` its child (a Behind item reads no
//! path); `E label blob` entry;
//! `T label blob` tombstone time; `R blob` reference count and the blob's prefix bytes
//! (`blob_prefix`); sweep indexes `X t label blob` (expiry), `Y t label blob` (tombstone drop),
//! `Z t label step` (claim-set drop); `N` host-wide totals (labels, entries,
//! bytes); `B blob` the engine's hold (`engine.rs`), `n label` node sync's (`reader.rs`).
//!
//! Ephemeral entries (blob prefix class ephemeral, spec/sync.md §4) are held in memory only:
//! entry, blob and tombstone; a restart loses them.

use osis_base::format::{MAX_DRIFT_MS, ROLE_KEEP_MS, TOMBSTONE_LIFETIME_MS};
use osis_base::{BlobId, Clock, LabelId};
use osis_crypto::Signature;
use osis_proto::msg::{ClaimSet, Code, Step, StepId, WRAP_LEN};
use osis_proto::{EntryMeta, HeadKeys, LabelStore, Put, StoreError};
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
    /// Ephemeral memory charged per label, and over all labels: an ephemeral entry beyond the
    /// label's is refused; past the total, the label charged most gives way (notes/ephemeral.md).
    pub ephemeral_bytes: u64,
    pub ephemeral_total: u64,
    /// Relay-only entries passed on per label and window, and their bytes (`osis_proto::RelayLimits`).
    pub relays: u32,
    pub relay_bytes: u64,
    /// Host-wide caps: new entries, labels and steps beyond them are refused.
    pub max_labels: u64,
    pub max_entries: u64,
    pub max_bytes: u64,
    /// A connection without the peer's Hello this long after accept is closed.
    pub hello_ms: u64,
    /// Bytes queued for one connection beyond which it is dropped (a peer that does not read);
    /// at least `osis_proto::serving::SEND_QUEUE` plus `osis_proto::client::WINDOW_QUEUE`
    /// (windowed replies and held pushes, and node sync's own requests, spec/sync.md §6).
    pub max_queued_bytes: usize,
    /// Bytes the hub holds for connections in each direction, over all of them: partially
    /// received frames (past it the connection holding the most is closed), and bytes written
    /// and not yet taken by the transport with the reply allowances reserved (never passed:
    /// output waits for room, `Hub::held`). The transport's own buffers, up to
    /// `osis_transport::link::CONN_MEMORY` per connection, are outside it: connections are not
    /// counted (spec/sync.md §10 Served connections).
    pub max_buffered_bytes: usize,
}

/// Default `max_buffered_bytes` (resource bound: 0 closes every connection at its first partial
/// frame and stops all output; infinity leaves memory unbounded).
const BUFFERED: usize = 512 << 20;

impl Default for HostPolicy {
    fn default() -> HostPolicy {
        HostPolicy {
            cap_entries: 1 << 20,
            cap_bytes: 16 << 30,
            deposit_factor: 1,
            claim_keep_ms: ROLE_KEEP_MS,
            tombstone_ms: TOMBSTONE_LIFETIME_MS,
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
            hello_ms: 10_000,
            max_queued_bytes: 64 << 20,
            max_buffered_bytes: BUFFERED,
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
    /// A removal that shreds nothing (a row holding no secret: the engine's hold, `B`).
    Unmark(Vec<u8>),
    /// Stored unless held already.
    PutBlob(BlobId, Vec<u8>),
    /// Deleted unless the engine holds it (`B`).
    DeleteBlob(BlobId),
    /// Node log events (notes/local-store.md, Node log).
    LogAdded(LabelId, BlobId),
    LogDeleted(LabelId, BlobId, u64),
    LogHead(LabelId, StepId),
    /// A page of the node log's sweep at a wall time.
    LogSweep(u64),
    /// A label's every node log event and slot, with no deletion event.
    LogForget(LabelId),
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
    /// since the last commit is lost; the next transaction recovers the store after a failed write).
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
                    Write::Unmark(k) => t.table_remove(*table, &k, Shred::No).map(drop)?,
                    Write::PutBlob(id, b) => {
                        if t.read_blob(&id, 0, 0)?.is_none() {
                            t.put_blob(&id, b)?;
                        }
                    }
                    Write::DeleteBlob(id) => {
                        if t.table_get(*table, &key(b'B', &[&id.0]))?.is_none() {
                            t.delete_blob(&id);
                        }
                    }
                    Write::LogAdded(l, b) => drop(t.log_added(l, b)?),
                    Write::LogDeleted(l, b, at) => drop(t.log_deleted(l, b, at)?),
                    Write::LogHead(l, h) => drop(t.log_head(l, &h.0)?),
                    Write::LogSweep(now) => drop(t.log_sweep(now)?),
                    Write::LogForget(l) => t.log_forget(l)?,
                }
            }
            t.suspend()
        });
        *open = Some(r?);
        Ok(())
    }

    /// Commits the open transaction; the result is its outcome (`Transaction::commit`).
    fn commit(&mut self) -> Result<(), osis_store::Error> {
        let Some(s) = self.open.take() else { return Ok(()) };
        self.store.resume(s, &mut *self.rng).commit()
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

/// Per-label counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Meta {
    head: Option<StepId>,
    head_claims: u64,
    entries: u64,
    bytes: u64,
    dep_n: u64,
    dep_bytes: u64,
    /// Wall ms before which a child step past a byte cap is refused (`HostPolicy::over_cap_step_ms`).
    over_cap_until: u64,
    /// Role entries (`Put::role`) among `entries` and their bytes: outside the label's caps.
    role_n: u64,
    role_bytes: u64,
}

impl Meta {
    /// The entries and bytes the label's and the host's caps count (role entries are outside them).
    fn capped(&self) -> (u64, u64) {
        (self.entries.saturating_sub(self.role_n), self.bytes.saturating_sub(self.role_bytes))
    }
}

const META_LEN: usize = 1 + 32 + 8 * 8;

impl Meta {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(META_LEN);
        v.push(u8::from(self.head.is_some()));
        v.extend_from_slice(&self.head.map_or([0; 32], |h| h.0));
        for n in [self.head_claims, self.entries, self.bytes, self.dep_n, self.dep_bytes, self.over_cap_until, self.role_n, self.role_bytes] {
            v.extend_from_slice(&be(n));
        }
        v
    }

    fn decode(b: &[u8]) -> Result<Meta, StoreError> {
        if b.len() != META_LEN {
            return Err(corrupt("label meta"));
        }
        let n = |i: usize| read_u64(b, 33 + 8 * i);
        Ok(Meta {
            head: (b.first() == Some(&1)).then(|| read_arr(b, 1).map(StepId)).transpose()?,
            head_claims: n(0)?,
            entries: n(1)?,
            bytes: n(2)?,
            dep_n: n(3)?,
            dep_bytes: n(4)?,
            over_cap_until: n(5)?,
            role_n: n(6)?,
            role_bytes: n(7)?,
        })
    }
}

/// A stored entry: the engine's view plus its expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    meta: EntryMeta,
    expiry: Option<u64>,
    /// Taken as a role entry (`Put::role`): counted in `Meta::role_n`.
    role: bool,
}

const ROW_LEN: usize = WRAP_LEN + 1 + 64 + 8 * 2;

impl Row {
    fn encode(&self) -> Vec<u8> {
        let m = &self.meta;
        let mut v = Vec::with_capacity(ROW_LEN);
        v.extend_from_slice(&m.wrap);
        v.push(u8::from(m.stamp.is_some()) | u8::from(self.role) << 1 | u8::from(self.expiry.is_some()) << 2);
        v.extend_from_slice(&m.stamp.map_or([0; 64], |s| s.0));
        for n in [m.size, self.expiry.unwrap_or(0)] {
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
            },
            expiry: opt(4, read_u64(b, at + 8)?),
            role: flags & 2 != 0,
        })
    }
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
    /// Its place in the label's eviction order (`EphLabel::order`).
    age: u64,
}

/// A label's ephemeral entries and tombstones (in memory).
#[derive(Clone, Debug, Default)]
struct EphLabel {
    entries: BTreeMap<BlobId, EphEntry>,
    /// Entries by age, oldest first (eviction order).
    order: BTreeMap<u64, BlobId>,
    /// Deleted ephemeral entries: when their tombstone goes.
    tombstones: BTreeMap<BlobId, u64>,
    /// Memory charged to the label's cap: blobs and per-entry overhead.
    bytes: u64,
    /// Memory of its tombstones (charged to the host-wide total only).
    tombs: u64,
    /// Deposited (unstamped) entries and their blob bytes: the deposit budget's ephemeral part.
    dep_n: u64,
    dep_bytes: u64,
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
/// (about 150 bytes), the blob map's entry, the eviction order and due-time index entries, each
/// with its map's node overhead (checked against the type sizes by
/// `overheads_cover_the_structures`). Not a tunable: what an entry really costs.
const ENTRY_OVERHEAD: u64 = 896;
/// Memory charged per ephemeral tombstone (map entry and due-time index entry).
const TOMB_OVERHEAD: u64 = 160;

/// How long a deleted ephemeral entry stays refused (its tombstone, in memory). Minor
/// consequence: past it a holder that missed the deletion may bring the entry back, and the
/// next writer that finds it covered deletes it again; 0: it comes back at once; infinity
/// (the durable `TOMBSTONE_LIFETIME`, 30 days): memory grows with every ephemeral delete.
const EPH_TOMBSTONE_MS: u64 = MAX_DRIFT_MS;

/// The ephemeral side of the store (in memory).
#[derive(Clone, Debug, Default)]
struct Ephemeral {
    labels: HashMap<LabelId, EphLabel>,
    blobs: HashMap<BlobId, (Vec<u8>, usize)>,
    /// The next entry's age (`EphEntry::age`).
    next_age: u64,
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

/// One mutation: the label's meta and its row writes, committed as one batch.
struct Tx {
    label: LabelId,
    meta: Meta,
    /// Entries and bytes before this mutation, and whether the label is new (host totals).
    before: (u64, u64, bool),
    batch: Writes,
}

/// A due index row: (row key, rest after `t`, value).
type Due = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Host-wide totals; entries and bytes as the caps count them (role entries outside).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub labels: u64,
    pub entries: u64,
    pub bytes: u64,
}

/// Room of one kind as used at a reading (`HostStore::room`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Room {
    pub memory: bool,
    used: [u64; 4],
}

impl Room {
    /// Whether any count is below `earlier`'s: something left since.
    pub fn below(&self, earlier: &Room) -> bool {
        self.used.iter().zip(earlier.used.iter()).any(|(a, b)| a < b)
    }
}

/// What a bounded sweep did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// The budget ran out with due work left.
    pub more: bool,
}

/// The bytes a held claim set counts toward the byte caps: its one row (`C`).
pub fn claim_set_bytes(c: &ClaimSet) -> u64 {
    c.to_bytes().len() as u64
}

/// `LabelStore` over a `Store`. Holds the store, the clock for rate windows and supersession
/// times, and the policy.
pub struct HostStore {
    /// Reads need the store mutably (`LabelStore` reads take `&self`).
    db: RefCell<Db>,
    /// A write failed since the last `durable`: its transaction was aborted.
    failed: Option<osis_store::Error>,
    clock: Arc<dyn Clock>,
    policy: HostPolicy,
    rates: Rates,
    eph: Ephemeral,
    relays: osis_proto::RelayGate,
    /// Commits wait for `durable` (`defer_durability`).
    lazy: bool,
    admission: Admission,
    caps: BTreeMap<LabelId, LabelCaps>,
    /// The sync IDs node sync reads (`reader.rs`).
    read: BTreeSet<LabelId>,
    /// Something other than node sync changed what it reads or streams, or a head (`take_moved`).
    moved: bool,
    /// Moves with any head, a label dropped, or the read set (`heads_generation`).
    heads_gen: u64,
    /// The unread sync IDs node sync's shared sets serve, and their ephemeral events since it
    /// last took them (`unread.rs`).
    streamed: BTreeSet<LabelId>,
    mem: Vec<unread::MemEvent>,
    /// Memory blobs the engine holds (`osis_store::CipherTx::hold` in memory): gone at a restart.
    engine_mem: HashMap<BlobId, Vec<u8>>,
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
            clock,
            policy: self.policy.clone(),
            rates: self.rates.clone(),
            eph: self.eph.clone(),
            relays: self.relays.clone(),
            lazy: self.lazy,
            admission: self.admission.clone(),
            caps: self.caps.clone(),
            engine_mem: self.engine_mem.clone(),
            read: self.read.clone(),
            moved: self.moved,
            heads_gen: self.heads_gen,
            streamed: self.streamed.clone(),
            mem: self.mem.clone(),
        })
    }

    /// Opens the host store over `store` (the host's own, never the node's), creating its table
    /// on first use. `rng` keys the store's units.
    pub fn open(mut store: Store, clock: Arc<dyn Clock>, policy: HostPolicy, mut rng: Box<dyn osis_crypto::NodeRng>) -> Result<HostStore, StoreError> {
        let mut t = store.transaction(&mut *rng).map_err(err)?;
        let table = t.index(TABLE).map_err(err)?;
        t.commit().map_err(err)?;
        let relays = osis_proto::RelayGate::default();
        let db = RefCell::new(Db { store, table, rng, open: None });
        let mut s = HostStore { db, failed: None, clock, policy: HostPolicy::default(), rates: Rates::default(), eph: Ephemeral::default(), relays, lazy: false, admission: Admission::Open, caps: BTreeMap::new(), engine_mem: HashMap::new(), read: BTreeSet::new(), moved: false, heads_gen: 0, streamed: BTreeSet::new(), mem: Vec::new() };
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

    /// Label `label`'s meta, or a fresh one and true.
    fn meta_or_new(&self, label: &LabelId) -> Result<(Meta, bool), StoreError> {
        Ok(match self.meta(label)? {
            Some(m) => (m, false),
            None => (Meta::default(), true),
        })
    }

    /// Writes `step` as `label`'s new head with its claim set (`over`: taken past the cap, the
    /// next such step waits `over_cap_step_ms`), into the open transaction.
    fn put_step(&mut self, label: &LabelId, step: Step, claim_set: Option<ClaimSet>, over: bool) -> Result<(), StoreError> {
        let (meta, new) = self.meta_or_new(label)?;
        let keys = match meta.head {
            Some(_) => self.head_keys(label)?.ok_or_else(|| corrupt("head keys"))?.child(step.clone()),
            None => HeadKeys::genesis(step.clone()),
        };
        let step_bytes = step.to_bytes();
        let id = step.id();
        let set = claim_set.as_ref().map(ClaimSet::to_bytes);
        let size = (step_bytes.len() + set.as_ref().map_or(0, Vec::len)) as u64;
        let (entries, bytes) = meta.capped();
        let mut tx = Tx { label: *label, before: (entries, bytes, new), meta, batch: Writes::default() };
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
        if let Some(c) = set {
            tx.batch.put(key(b'C', &[&label.0, &id.0]), c);
        }
        tx.batch.log(Write::LogHead(*label, id));
        // any head: the unread ones' credentials are in node sync's filters
        self.heads_gen += 1;
        self.moved = true;
        self.finish(tx)
    }

    /// Whether this store would take `label`'s registration (`admit_label`, caps aside): one
    /// node sync reads comes from `label.0` instead.
    pub fn admits(&self, label: &LabelId) -> bool {
        !self.reads(label) && self.admission.admits(label)
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

    /// `Store::writes` of the host's store.
    pub fn store_writes(&self) -> osis_store::Writes {
        self.db.borrow().store.writes()
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

    pub fn totals(&self) -> Result<Totals, StoreError> {
        let Some(b) = self.get(b"N")? else { return Ok(Totals::default()) };
        Ok(Totals { labels: read_u64(&b, 0)?, entries: read_u64(&b, 8)?, bytes: read_u64(&b, 16)? })
    }

    fn now(&self) -> u64 {
        self.clock.now_wall_ms().0
    }

    fn meta(&self, label: &LabelId) -> Result<Option<Meta>, StoreError> {
        self.get(&key(b'L', &[&label.0]))?.map(|b| Meta::decode(&b)).transpose()
    }

    /// Ephemeral memory charged to `label`'s cap: blobs and per-entry overhead (tests,
    /// diagnostics).
    pub fn ephemeral_bytes(&self, label: &LabelId) -> u64 {
        self.eph.labels.get(label).map_or(0, |e| e.bytes)
    }

    /// The ephemeral entries held under `label` (tests, diagnostics).
    #[doc(hidden)]
    pub fn ephemeral_ids(&self, label: &LabelId) -> Vec<BlobId> {
        self.eph.labels.get(label).map(|e| e.entries.keys().copied().collect()).unwrap_or_default()
    }

    /// Whether a new plain ephemeral entry of `size` blob bytes would fit under `label`'s cap
    /// (tests: a refusal is genuine).
    pub fn ephemeral_fits(&self, label: &LabelId, size: u64) -> bool {
        self.ephemeral_bytes(label).saturating_add(size).saturating_add(ENTRY_OVERHEAD) <= self.policy.ephemeral_bytes
    }

    /// The entries and bytes of `label` its caps count (role entries are outside them).
    pub fn capped(&self, label: &LabelId) -> Result<(u64, u64), StoreError> {
        Ok(self.meta(label)?.map_or((0, 0), |m| m.capped()))
    }

    /// What `label`'s room of one kind (durable, or `memory`) found used: the label's and the
    /// store's, entries and bytes (memory: bytes charged). Room grew when any is below an
    /// earlier reading's (`Room::below`).
    pub fn room(&self, label: &LabelId, memory: bool) -> Result<Room, StoreError> {
        let used = if memory {
            [self.ephemeral_bytes(label), self.eph.total, 0, 0]
        } else {
            let m = self.meta(label)?;
            let t = self.totals()?;
            let (entries, bytes) = m.as_ref().map_or((0, 0), Meta::capped);
            [entries, bytes, t.entries, t.bytes]
        };
        Ok(Room { memory, used })
    }

    /// Ephemeral memory charged over all labels (tests, diagnostics).
    pub fn ephemeral_total(&self) -> u64 {
        self.eph.total
    }

    /// Removes an ephemeral entry: silently (expiry), with a tombstone (a delete), or without one
    /// (evicted for the host-wide cap: holders may bring it back). Whether it was held.
    fn eph_remove(&mut self, label: &LabelId, blob: &BlobId, how: EphRemove) -> bool {
        let Some(e) = self.eph.labels.get_mut(label) else { return false };
        let Some(x) = e.entries.remove(blob) else { return false };
        e.order.remove(&x.age);
        if x.meta.stamp.is_none() {
            e.dep_n = e.dep_n.saturating_sub(1);
            e.dep_bytes = e.dep_bytes.saturating_sub(x.meta.size);
        }
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
        if let EphRemove::Delete(now) = how {
            let drop = now.saturating_add(EPH_TOMBSTONE_MS);
            if let Some(old) = self.eph.labels.entry(*label).or_default().tombstones.insert(*blob, drop) {
                self.eph.due.remove(&(old, *label, *blob));
            } else {
                self.eph.charge(label, TOMB_OVERHEAD, Charge::Tomb);
            }
            self.eph.due.insert((drop, *label, *blob));
        }
        self.note_memory(label, HostStore::memory_removed(*label, *blob, how));
        true
    }

    /// Frees ephemeral memory for the host-wide cap from the label charged most (M4 of the
    /// ephemeral security review: a stranger's labels cannot lock others out): its oldest entry,
    /// else its oldest tombstone. Whether anything was freed.
    fn eph_evict(&mut self) -> bool {
        let Some((_, l)) = self.eph.by_bytes.last().copied() else { return false };
        let Some(e) = self.eph.labels.get(&l) else { return false };
        if let Some(b) = e.order.first_key_value().map(|(_, b)| *b) {
            return self.eph_remove(&l, &b, EphRemove::Evict);
        }
        let Some((b, t)) = e.tombstones.iter().min_by_key(|(_, t)| **t).map(|(b, t)| (*b, *t)) else { return false };
        if let Some(e) = self.eph.labels.get_mut(&l) {
            e.tombstones.remove(&b);
        }
        self.eph.due.remove(&(t, l, b));
        self.eph.release(&l, TOMB_OVERHEAD, Charge::Tomb);
        true
    }

    /// Adds an ephemeral entry or promotes a deposited one (spec/sync.md §4, §5): past the
    /// label's ephemeral cap code 12; past the node's, the label charged most gives way; a
    /// deposit within the deposit budget, as a durable one.
    fn eph_put(&mut self, label: &LabelId, put: Put<'_>) -> Result<Code, StoreError> {
        let m = self.meta(label)?.ok_or_else(unknown)?;
        let now = self.now();
        self.rates.roll(now, self.policy.window_ms);
        let size = put.blob.len() as u64;
        // a held one never changes but by its promotion (`LabelStore::put`)
        if let Some(held) = self.eph_entry(label, &put.blob_id).map(|e| e.meta.clone()) {
            if put.stamp.is_none() || held.stamp.is_some() {
                return Ok(Code::OK);
            }
            if let Some(e) = self.eph.labels.get_mut(label) {
                e.dep_n = e.dep_n.saturating_sub(1);
                e.dep_bytes = e.dep_bytes.saturating_sub(held.size);
                if let Some(x) = e.entries.get_mut(&put.blob_id) {
                    x.meta = EntryMeta { wrap: put.wrap, stamp: put.stamp, ..held };
                }
            }
            self.note_memory(label, MemEvent::Added(*label, put.blob_id));
            return Ok(Code::OK);
        }
        if put.stamp.is_none() && !self.deposit_fits(label, &m, size) {
            return Ok(Code::BUDGET_FULL);
        }
        if put.stamp.is_none() && !self.rates.take(label, Rate::Deposit, self.policy.deposits) {
            return Ok(Code::RATE_LIMITED);
        }
        let need = size.saturating_add(ENTRY_OVERHEAD);
        if self.ephemeral_bytes(label).saturating_add(need) > self.policy.ephemeral_bytes {
            return Ok(Code::STORAGE_CAP);
        }
        while self.eph.total.saturating_add(need) > self.policy.ephemeral_total {
            if !self.eph_evict() {
                return Ok(Code::STORAGE_CAP);
            }
        }
        let age = self.eph.next_age;
        self.eph.next_age += 1;
        let e = self.eph.labels.entry(*label).or_default();
        e.order.insert(age, put.blob_id);
        if put.stamp.is_none() {
            e.dep_n += 1;
            e.dep_bytes = e.dep_bytes.saturating_add(size);
        }
        e.entries.insert(put.blob_id, EphEntry { meta: EntryMeta { wrap: put.wrap, stamp: put.stamp, size }, expiry: put.expiry, age });
        if let Some(t) = put.expiry {
            self.eph.due.insert((t, *label, put.blob_id));
        }
        self.eph.charge(label, need, Charge::Label);
        self.eph.blobs.entry(put.blob_id).or_insert_with(|| (put.blob.to_vec(), 0)).1 += 1;
        self.note_memory(label, MemEvent::Added(*label, put.blob_id));
        Ok(Code::OK)
    }

    /// Adds a durable entry or promotes a deposited one (spec/sync.md §4, §5): past the label's
    /// or the node's cap, code 12.
    fn durable_put(&mut self, label: &LabelId, put: Put<'_>, held: Option<Row>) -> Result<Code, StoreError> {
        let mut tx = self.tx(label)?;
        if let Some(r) = &held
            && (put.stamp.is_none() || r.meta.stamp.is_some())
        {
            return Ok(Code::OK);
        }
        let size = put.blob.len() as u64;
        let now = self.now();
        self.rates.roll(now, self.policy.window_ms);
        // a promotion: once per entry, no cap or budget
        if held.is_none() {
            let m = &tx.meta;
            let p = &self.policy;
            // an entry deletes are judged by is outside the storage caps, else no purge or
            // compaction frees room here; a stamped one is a writer's, bounded by nothing
            // more, a deposited one by the deposit budget below (spec/sync.md §5, Role entries)
            if !put.role {
                let (entries, bytes) = m.capped();
                let (cap_entries, cap_bytes) = self.label_caps(label);
                if entries.saturating_add(1) > cap_entries || bytes.saturating_add(size) > cap_bytes {
                    return Ok(Code::STORAGE_CAP);
                }
                let t = self.totals()?;
                if t.entries.saturating_add(1) > p.max_entries || t.bytes.saturating_add(size) > p.max_bytes {
                    return Ok(Code::STORAGE_CAP);
                }
            }
            if put.stamp.is_none() && !self.deposit_fits(label, m, size) {
                return Ok(Code::BUDGET_FULL);
            }
            if put.stamp.is_none() && !self.rates.take(label, Rate::Deposit, p.deposits) {
                return Ok(Code::RATE_LIMITED);
            }
        }
        let l = label.0;
        // node sync alone expires an entry of a sync ID it reads (its pass removes the row)
        let expiry = put.expiry.filter(|_| !self.reads(label));
        let row = match held {
            Some(old) => {
                if old.meta.stamp.is_none() {
                    tx.meta.dep_n = tx.meta.dep_n.saturating_sub(1);
                    tx.meta.dep_bytes = tx.meta.dep_bytes.saturating_sub(old.meta.size);
                }
                Row { meta: EntryMeta { wrap: put.wrap, stamp: put.stamp, ..old.meta }, expiry: old.expiry, role: old.role }
            }
            None => {
                tx.meta.entries += 1;
                tx.meta.bytes = tx.meta.bytes.saturating_add(size);
                if put.role {
                    tx.meta.role_n += 1;
                    tx.meta.role_bytes = tx.meta.role_bytes.saturating_add(size);
                }
                if put.stamp.is_none() {
                    tx.meta.dep_n += 1;
                    tx.meta.dep_bytes = tx.meta.dep_bytes.saturating_add(size);
                }
                if let Some(t) = expiry {
                    tx.batch.put(key(b'X', &[&be(t), &l, &put.blob_id.0]), vec![]);
                }
                let (refs, _) = self.refs(&put.blob_id)?;
                if refs == 0 {
                    tx.batch.put_blob(put.blob_id, put.blob.to_vec());
                }
                let prefix = osis_label::prefix_bytes(put.blob);
                tx.batch.put(key(b'R', &[&put.blob_id.0]), [&be(refs + 1)[..], prefix].concat());
                Row { meta: EntryMeta { wrap: put.wrap, stamp: put.stamp, size }, expiry, role: put.role }
            }
        };
        tx.batch.put(key(b'E', &[&l, &put.blob_id.0]), row.encode());
        tx.batch.log(Write::LogAdded(*label, put.blob_id));
        self.finish(tx)?;
        Ok(Code::OK)
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
                    self.eph_remove(&l, &b, EphRemove::Expire);
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
        let (entries, bytes) = meta.capped();
        Ok(Tx { label: *label, before: (entries, bytes, false), meta, batch: Writes::default() })
    }

    /// Writes the label's meta and the host totals with `tx`'s rows, and commits.
    fn finish(&mut self, mut tx: Tx) -> Result<(), StoreError> {
        tx.batch.put(key(b'L', &[&tx.label.0]), tx.meta.encode());
        // node sync wakes for what it holds as its own (`reads`: it alone expires those, a sync ID
        // it no longer syncs included) and what its shared sets stream
        self.moved |= self.reads(&tx.label) || self.streamed.contains(&tx.label);
        let (entries, bytes, new) = tx.before;
        let (now_entries, now_bytes) = tx.meta.capped();
        if new || entries != now_entries || bytes != now_bytes {
            let t = self.totals()?;
            let t = Totals {
                labels: t.labels.saturating_add(u64::from(new)),
                entries: t.entries.saturating_add(now_entries).saturating_sub(entries),
                bytes: t.bytes.saturating_add(now_bytes).saturating_sub(bytes),
            };
            tx.batch.put(b"N".to_vec(), [be(t.labels), be(t.entries), be(t.bytes)].concat());
        }
        self.write(tx.batch)
    }

    /// Whether one more deposited entry of `size` bytes fits `label`'s deposit budget (spec/sync.md
    /// §5): `deposit_factor` × (64 + 4 × head claim slots) entries, × `DEPOSIT_ENTRY_BYTES` bytes,
    /// over its deposited entries durable (`m`) and ephemeral.
    fn deposit_fits(&self, label: &LabelId, m: &Meta, size: u64) -> bool {
        let max = self.policy.deposit_factor.max(1).saturating_mul(64u64.saturating_add(m.head_claims.saturating_mul(4)));
        let (n, b) = self.eph.labels.get(label).map_or((0, 0), |e| (e.dep_n, e.dep_bytes));
        let (n, bytes) = (m.dep_n.saturating_add(n), m.dep_bytes.saturating_add(b));
        n.saturating_add(1) <= max && bytes.saturating_add(size) <= max.saturating_mul(DEPOSIT_ENTRY_BYTES)
    }

    /// Removes a held entry at `now` within `tx`: counters, indexes, blob reference, a node log
    /// deletion event; when `tombstone`, a tombstone the sweep drops `tombstone_ms` later (its
    /// `Y` row).
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
        if row.role {
            m.role_n = m.role_n.saturating_sub(1);
            m.role_bytes = m.role_bytes.saturating_sub(row.meta.size);
        }
        if tombstone {
            let drop = now.saturating_add(self.policy.tombstone_ms);
            // a tombstone already present has its own drop row: it moves to the new time
            if let Some(old) = self.get(&key(b'T', &[&l, &blob.0]))? {
                tx.batch.delete(key(b'Y', &[&old, &l, &blob.0]));
            }
            tx.batch.put(key(b'T', &[&l, &blob.0]), be(drop).to_vec());
            tx.batch.put(key(b'Y', &[&be(drop), &l, &blob.0]), vec![]);
        }
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

    /// Drops every label `drop` names, whole and shredded (hosting stopped: the store keeps no
    /// sync ID for others), with no tombstone or deletion event: nobody deleted its
    /// entries, the store stopped holding them. Its blobs go once no other label references them.
    /// Commits. The labels dropped.
    pub fn drop_labels(&mut self, drop: &dyn Fn(&LabelId) -> bool) -> Result<Vec<LabelId>, StoreError> {
        let mut gone = Vec::new();
        let mut after = None;
        loop {
            let page = self.labels_after(after.as_ref(), 256)?;
            let Some(last) = page.last().copied() else { break };
            // node sync's sync IDs are its own, kept whatever is kept for others
            gone.extend(page.into_iter().filter(|l| drop(l) && !self.reads(l)));
            after = Some(last);
        }
        for l in &gone {
            self.drop_label(l)?;
        }
        // the sweep indexes naming a dropped label after their time (`X`/`Y`/`Z t label …`), in
        // one pass
        let set: BTreeSet<&LabelId> = gone.iter().collect();
        for tag in *b"XYZ" {
            let at = 9;
            let mut from = vec![tag];
            let end = osis_store::prefix_end(&from);
            loop {
                let rows = self.scan(&from, end.as_deref(), 1024)?;
                let n = rows.len();
                let mut page = Writes::default();
                for (k, _) in &rows {
                    if k.get(at..at + 16).and_then(|x| <[u8; 16]>::try_from(x).ok()).is_some_and(|x| set.contains(&LabelId(x))) {
                        page.delete(k.clone());
                    }
                }
                self.write_open(page)?;
                match rows.last() {
                    Some((k, _)) if n == 1024 => from = [k.as_slice(), &[0]].concat(),
                    _ => break,
                }
            }
        }
        if let Some(e) = self.failed.take() {
            self.db.get_mut().open = None;
            return Err(err(e));
        }
        self.db.get_mut().commit().map_err(err)?;
        Ok(gone)
    }

    fn drop_label(&mut self, l: &LabelId) -> Result<(), StoreError> {
        let Some(meta) = self.meta(l)? else { return Ok(()) };
        self.heads_gen += 1;
        let mut w = Writes::default();
        // blob references, one per entry (`R` counts labels holding the blob)
        let mut refs: BTreeMap<BlobId, u64> = BTreeMap::new();
        let prefix = key(b'E', &[&l.0]);
        let mut from = prefix.clone();
        let end = osis_store::prefix_end(&prefix);
        loop {
            let rows = self.scan(&from, end.as_deref(), 1024)?;
            let n = rows.len();
            for (k, _) in &rows {
                *refs.entry(BlobId(read_arr(k, 17)?)).or_default() += 1;
            }
            match rows.last() {
                Some((k, _)) if n == 1024 => from = [k.as_slice(), &[0]].concat(),
                _ => break,
            }
        }
        for (b, n) in refs {
            let (have, pre) = self.refs(&b)?;
            if have <= n {
                w.delete(key(b'R', &[&b.0]));
                w.delete_blob(b);
            } else {
                w.put(key(b'R', &[&b.0]), [&be(have - n)[..], &pre].concat());
            }
        }
        for tag in *b"LKSCHVWET" {
            let prefix = key(tag, &[&l.0]);
            let end = osis_store::prefix_end(&prefix);
            loop {
                let rows = self.scan(&prefix, end.as_deref(), 1024)?;
                let n = rows.len();
                // deletes apply to the open transaction at once, so the next scan moves on
                let mut page = Writes::default();
                for (k, _) in rows {
                    page.delete(k);
                }
                self.write_open(page)?;
                if n < 1024 {
                    break;
                }
            }
        }
        let t = self.totals()?;
        let (entries, bytes) = meta.capped();
        let t = Totals { labels: t.labels.saturating_sub(1), entries: t.entries.saturating_sub(entries), bytes: t.bytes.saturating_sub(bytes) };
        w.put(b"N".to_vec(), [be(t.labels), be(t.entries), be(t.bytes)].concat());
        w.log(Write::LogForget(*l));
        self.write_open(w)?;
        // its ephemeral side
        if let Some(e) = self.eph.labels.remove(l) {
            self.eph.by_bytes.remove(&(e.all(), *l));
            self.eph.total = self.eph.total.saturating_sub(e.all());
            for x in e.entries.keys() {
                if let Some((_, n)) = self.eph.blobs.get_mut(x) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        self.eph.blobs.remove(x);
                    }
                }
            }
        }
        Ok(())
    }

    /// Applies `w` to the open transaction without committing it (`drop_labels` commits once).
    fn write_open(&mut self, w: Writes) -> Result<(), StoreError> {
        let r = self.db.get_mut().apply(w);
        if let Err(e) = &r {
            self.failed = Some(e.clone());
        }
        r.map_err(err)
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

    /// Expires entries (no tombstone; a node log deletion), drops old tombstones and claim sets
    /// superseded for `claim_keep_ms`; at most `budget` index rows, one commit per label; then a
    /// page of the node log's sweep. An index row that does not parse, or names a label not held, is dropped.
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
        // tombstones past their lifetime
        let mut b = Writes::default();
        for (k, rest, _) in self.due(b'Y', now, left)? {
            left -= 1;
            if rest.len() == 48 {
                b.delete(key(b'T', &[&rest]));
            }
            b.delete(k);
        }
        // a dropped claim set's bytes leave the label's and the host's totals
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
            let mut batch = Writes::default();
            let c = key(b'C', &[&rest]);
            let freed = self.get(&c)?.map_or(0, |set| set.len());
            batch.delete(c);
            batch.delete(k);
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
        for tag in *b"XYZ" {
            if let Some((k, _)) = self.scan_prefix(&[tag], 1)?.first() {
                let t = read_u64(k, 1)?;
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        }
        Ok(next)
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
        // node sync's sync ID: its genesis comes from `label.0`, never first come (refused for
        // now: node sync puts it)
        if self.reads(label) {
            return Ok(Code::RATE_LIMITED);
        }
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
        // node sync's sync IDs: no cap or rate (their steps come from `label.0`, a peer's
        // registration only as a valid child of the head, `admit_label`)
        if self.reads(label) {
            self.put_step(label, step, claim_set, false)?;
            return Ok(Code::OK);
        }
        let (meta, new) = self.meta_or_new(label)?;
        let set_bytes = claim_set.as_ref().map_or(0, claim_set_bytes);
        let step_bytes = step.to_bytes().len() as u64;
        let cap_bytes = self.label_caps(label).1;
        let fits = |n: u64, total: u64| meta.capped().1.saturating_add(n) <= cap_bytes && total.saturating_add(n) <= self.policy.max_bytes;
        let total = self.totals()?.bytes;
        let mut claim_set = claim_set;
        let mut over = false;
        if !fits(step_bytes + set_bytes, total) {
            // a new label is refused; a child step is taken without its claim set (a refused
            // rotation keeps a removed holder's open and write keys valid here), even past the
            // cap once per `over_cap_step_ms`, so the label's own admin alone spends that room
            if new {
                return Ok(Code::STORAGE_CAP);
            }
            claim_set = None;
            over = !fits(step_bytes, total);
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
        self.put_step(label, step, claim_set, over)?;
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
        let held = self.row(label, &put.blob_id)?;
        // an ephemeral blob (unless the same blob is held as a durable entry) stays in memory
        if (put.ephemeral && held.is_none()) || self.eph_entry(label, &put.blob_id).is_some() {
            self.eph_put(label, put)
        } else {
            self.durable_put(label, put, held)
        }
    }

    fn delete(&mut self, label: &LabelId, blob_id: &BlobId, now: u64) -> Result<Code, StoreError> {
        if self.eph_entry(label, blob_id).is_some() {
            self.rates.roll(self.now(), self.policy.window_ms);
            if !self.rates.take(label, Rate::Delete, self.policy.deletes) {
                return Ok(Code::RATE_LIMITED);
            }
            self.eph_remove(label, blob_id, EphRemove::Delete(now));
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

    fn live_ids(&self, label: &LabelId) -> Result<Vec<BlobId>, StoreError> {
        let prefix = key(b'E', &[&label.0]);
        let rows = self.scan_prefix(&prefix, usize::MAX)?;
        let mut out = rows.iter().map(|(k, _)| Ok(BlobId(read_arr(k, 17)?))).collect::<Result<Vec<_>, StoreError>>()?;
        if let Some(e) = self.eph.labels.get(label) {
            out.extend(e.entries.keys().copied());
            out.sort();
        }
        Ok(out)
    }

    fn relay(&mut self, label: &LabelId, blob_id: &BlobId, size: usize, expiry: Option<u64>, now: u64) -> Result<osis_proto::RelayVerdict, StoreError> {
        Ok(self.relays.admit(label, blob_id, size, expiry, now))
    }
}

mod engine;
mod reader;
mod unread;
pub use unread::MemEvent;
#[cfg(test)]
mod tests;

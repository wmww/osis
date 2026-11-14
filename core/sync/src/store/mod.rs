//! The store per sync ID (spec/sync-ids.md §5-§6, spec/sync-streams.md §3, spec/sync-inbox.md
//! §3, spec/sync-judgement.md §4 stand state).
//!
//! One store of ciphertext per node for every sync ID it holds, read and kept unread alike:
//! entries (wrap or filler, stamp, deposited flag), tombstones, blob bytes once per node, the
//! path each sync ID serves, the node log with its per-sync-ID index, usage against the caps and
//! the deposit budget, charges against each peer's budget, and the rows a source's record keeps
//! of what this node logged again there. Ephemeral entries, their tombstones and the memory part
//! of the log live in memory (`memory`). It is the engine's ciphertext door
//! (`osis_store::CipherHost`, `cipher`): `Store` is a cheap handle over one locked store, held by
//! the engine's door and by `Cx`; the engine locks it only inside its own transactions, sync only
//! between engine calls, so one step never holds both.
//!
//! Every operation is one transaction of the underlying store, so a crash keeps all of its rows
//! or none (an entry and its log event, a removal and its tombstone). Every row change stamps
//! (osis-store `Stamping`; the memory part its own `Stamps`), so memos may read it. Expiry,
//! tombstone ends, claim sets' `ROLE_KEEP` and the caps giving way run in `settle`. It decrypts
//! nothing and judges no open: every secret lives above it. It learns which sync IDs the node
//! holds, and how, from the engine's sync set, and its caps from the engine's `caps^.0`.

mod cipher;
mod entries;
mod memory;
mod path;
mod rows;

pub use path::{Behind, Cred};
pub use rows::{Source, Tombstone, Usage};

/// The members a log read serves: each with its `until` (none: not served).
pub trait Members {
    fn until(&self, s: &SyncId) -> Option<Option<Position>>;
    fn is_empty(&self) -> bool;
}

impl Members for BTreeMap<SyncId, Option<Position>> {
    fn until(&self, s: &SyncId) -> Option<Option<Position>> {
        self.get(s).copied()
    }
    fn is_empty(&self) -> bool {
        BTreeMap::is_empty(self)
    }
}

use crate::types::{Cursor, Entry, Position, Result};
use entries::Removal;
use memory::Memory;
use osis_base::format::{MAX_BLOB, TOMBSTONE_LIFETIME_MS};
use osis_base::{BlobId, SyncId, Tid, WallMs};
use osis_engine::Engine;
use osis_engine::sync::{Caps, Holding, Path, SyncSet};
use osis_label::{Class, ClaimSet, DeleteItem, Prefix, Step, StepId};
use osis_proto::{Code, DepositItem};
use osis_store::{Ciphertext, LogRead, LoggedEvent, NodeEvent, Shred, Suspended, Transaction};
use rows::{EntryRow, R, W};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

/// Bytes an entry counts toward the caps beside its blob: its row, index rows and log record.
/// Minor consequence: the caps are approximate by this much per entry (0: rows count nothing;
/// infinity: no entry fits).
pub(crate) const ENTRY_OVERHEAD: u64 = 256;
/// Bytes a tombstone counts toward the caps (minor consequence, as `ENTRY_OVERHEAD`).
pub(crate) const TOMB_OVERHEAD: u64 = 128;
/// Rows a sweep or a give-way pass reads at a time (performance switch: each settle round does
/// at most this much per kind and says it acted while more is due).
const PAGE: usize = 256;

/// The record row tags this module owns (notes/sync-boundary.md U3): a source's stand of
/// "logged again once", and the deletes seen there (spec/sync-judgement.md §4).
const STAND: u8 = b's';
const SEEN: u8 = b'd';

/// The local policy the caps apply (`caps^.0`, spec/data-model.md §9; spec/sync-ids.md §5-§6):
/// every value a resource bound against peers filling this node's store. Each is read from
/// `caps^.0`'s `policy` under its field name; per-thing caps replace `entries` and `bytes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Entries of one sync ID kept unread (0: it takes no entry but role entries; infinity: disk).
    pub entries: u64,
    /// Bytes of one sync ID kept unread: blobs, entry and tombstone overheads, path.
    pub bytes: u64,
    /// Bytes of every sync ID kept unread; past it the one using most gives way.
    pub total_bytes: u64,
    /// Ephemeral bytes held in memory per sync ID kept unread, and in total.
    pub memory_bytes: u64,
    pub memory_total: u64,
    /// Bytes of unstamped entries giving nothing held one peer may charge (spec/sync-ids.md §5
    /// Peer budget; 0: no such entry is kept; infinity: one peer fills the store).
    pub peer_bytes: u64,
    /// The deposit budget per sync ID, raised to the spec's recommended minimum.
    pub deposit_entries: u64,
    pub deposit_bytes: u64,
    /// A child step past the caps even without its claim set is taken at most once per sync ID
    /// per this many ms (spec/sync-ids.md §6 Storage caps; 0: always; infinity: once).
    pub register_every_ms: u64,
}

impl Default for Policy {
    fn default() -> Policy {
        const MIB: u64 = 1024 * 1024;
        Policy {
            entries: 1 << 20,
            bytes: 1024 * MIB,
            total_bytes: 8 * 1024 * MIB,
            memory_bytes: 16 * MIB,
            memory_total: 256 * MIB,
            peer_bytes: 64 * MIB,
            deposit_entries: 0,
            deposit_bytes: 0,
            register_every_ms: 3_600_000,
        }
    }
}

impl Policy {
    /// The policy `caps^.0` states, defaults where it names nothing.
    pub fn from_caps(caps: &Caps) -> Policy {
        let d = Policy::default();
        let get = |k: &str, v: u64| caps.policy.get(k).copied().unwrap_or(v);
        Policy {
            entries: get("entries", d.entries),
            bytes: get("bytes", d.bytes),
            total_bytes: get("total_bytes", d.total_bytes),
            memory_bytes: get("memory_bytes", d.memory_bytes),
            memory_total: get("memory_total", d.memory_total),
            peer_bytes: get("peer_bytes", d.peer_bytes),
            deposit_entries: get("deposit_entries", d.deposit_entries),
            deposit_bytes: get("deposit_bytes", d.deposit_bytes),
            register_every_ms: get("register_every_ms", d.register_every_ms),
        }
    }
}

/// A source's stand of "logged again once" for one body (spec/sync-judgement.md §4): the
/// encryption logged again and the ground it was logged at: the source's head and the body's fall
/// mark (`Engine::fall_mark`, summed over its aspects). Kept in the source's record,
/// durably, until `at` is `TOMBSTONE_LIFETIME` old; toward a peer with no record, in memory
/// while the connection lasts and no longer than that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stand {
    pub at: WallMs,
    pub logged: BlobId,
    pub head: StepId,
    pub fall: u64,
}

impl Stand {
    fn encode(&self) -> Vec<u8> {
        W::default().u64(self.at.0).raw(&self.logged.0).raw(&self.head.0).u64(self.fall).take()
    }
    fn decode(v: &[u8]) -> Result<Stand> {
        let mut r = R::new(v);
        Ok(Stand { at: WallMs(r.u64()?), logged: BlobId(r.array()?), head: StepId(r.array()?), fall: r.u64()? })
    }
}

/// What the operations of one transaction see and change beside its rows.
pub(crate) struct Env<'a> {
    pub now: WallMs,
    pub holdings: &'a BTreeMap<SyncId, (Tid, Holding)>,
    pub caps: &'a Caps,
    pub policy: &'a Policy,
    pub mem: &'a Memory,
    /// Bytes used by every sync ID kept unread; `None` until counted.
    pub total: Option<u64>,
}

impl Env<'_> {
    pub(crate) fn holding(&self, s: &SyncId) -> Option<Holding> {
        self.holdings.get(s).map(|(_, h)| *h)
    }

    /// The caps of S: its thing's own, else the policy's.
    fn caps_of(&self, s: &SyncId) -> (u64, u64) {
        match self.holdings.get(s).and_then(|(t, _)| self.caps.things.get(t)) {
            Some(c) => (c.entries, c.bytes),
            None => (self.policy.entries, self.policy.bytes),
        }
    }

    fn total(&mut self, t: &mut Transaction<'_>) -> Result<u64> {
        if let Some(n) = self.total {
            return Ok(n);
        }
        let mut n = 0u64;
        for (s, (_, h)) in self.holdings {
            if *h == Holding::Unread {
                n = n.saturating_add(entries::usage(t, s)?.bytes);
            }
        }
        self.total = Some(n);
        Ok(n)
    }

    /// Whether S, kept unread, has room for `add_entries` entries of `add_bytes` bytes in all
    /// under its own caps and the total (no give-way). A sync ID read takes nothing from the room.
    pub(crate) fn room(&mut self, t: &mut Transaction<'_>, s: &SyncId, add_entries: u64, add_bytes: u64) -> Result<bool> {
        if self.holding(s) != Some(Holding::Unread) {
            return Ok(true);
        }
        let u = entries::usage(t, s)?;
        let (ce, cb) = self.caps_of(s);
        if u.entries.saturating_add(add_entries) > ce || u.bytes.saturating_add(add_bytes) > cb {
            return Ok(false);
        }
        Ok(self.total(t)?.saturating_add(add_bytes) <= self.policy.total_bytes)
    }
}

/// The store's state behind its lock.
pub(crate) struct Inner {
    store: osis_store::Store,
    rng: Box<dyn osis_crypto::NodeRng>,
    /// The engine's transaction, open between its blob calls.
    open: Option<Suspended>,
    now: WallMs,
    holdings: BTreeMap<SyncId, (Tid, Holding)>,
    caps: Caps,
    policy: Policy,
    mem: Memory,
    total: Option<u64>,
    /// When each sync ID last took a child step past its caps (spec/sync-ids.md §6).
    past_cap: HashMap<SyncId, WallMs>,
}

impl Inner {
    /// Runs `f` in a transaction of its own and commits it; nothing of it stays on an error.
    fn write<T>(&mut self, f: impl FnOnce(&mut Transaction<'_>, &mut Env<'_>) -> Result<T>) -> Result<T> {
        debug_assert!(self.open.is_none(), "sync wrote inside the engine's transaction");
        let Inner { store, rng, now, holdings, caps, policy, mem, total, .. } = self;
        let mut env = Env { now: *now, holdings, caps, policy, mem, total: *total };
        let mut t = store.transaction(&mut **rng)?;
        let r = f(&mut t, &mut env)?;
        t.commit()?;
        *total = env.total;
        Ok(r)
    }

    /// Runs `f` over a transaction that writes nothing (dropped).
    fn read<T>(&mut self, f: impl FnOnce(&mut Transaction<'_>, &mut Env<'_>) -> Result<T>) -> Result<T> {
        let Inner { store, rng, now, holdings, caps, policy, mem, total, .. } = self;
        let mut env = Env { now: *now, holdings, caps, policy, mem, total: *total };
        let mut t = store.transaction(&mut **rng)?;
        f(&mut t, &mut env)
    }

    fn holding(&self, s: &SyncId) -> Option<Holding> {
        self.mem.stamps.read(&("holding", s));
        self.holdings.get(s).map(|(_, h)| *h)
    }
}

/// What a blob's bytes say of it, or the code refusing them.
fn check_blob(bytes: &[u8], b: &BlobId) -> std::result::Result<(Class, Option<WallMs>), Code> {
    if bytes.len() > MAX_BLOB {
        return Err(Code::TOO_LARGE);
    }
    if osis_label::blob_id(bytes) != *b {
        return Err(Code::MALFORMED);
    }
    match Prefix::parse(bytes) {
        Ok(p) => Ok((p.class(), p.expiry())),
        // a framing this build does not know: parked, no expiry, no commitments
        Err(osis_label::Error::UnknownFraming(_)) => Ok((Class::Durable, None)),
        Err(_) => Err(Code::MALFORMED),
    }
}

/// The clear prefix of held blob `b`, read alone (never the ciphertext): reads twice as much
/// while the prefix runs past what was read, so at most twice its length. `None`: not held, or
/// no prefix this build parses (no commitments).
fn read_prefix(t: &mut Transaction<'_>, b: &BlobId) -> Result<Option<Prefix>> {
    let mut n = 256usize;
    loop {
        let Some(v) = t.read_blob(b, 0, n)? else { return Ok(None) };
        match Prefix::parse(&v) {
            Ok(p) => return Ok(Some(p)),
            Err(osis_label::Error::Malformed(_)) if v.len() == n && n < MAX_BLOB => n = n.saturating_mul(2),
            Err(_) => return Ok(None),
        }
    }
}

fn expired(at: Option<WallMs>, now: WallMs) -> bool {
    at.is_some_and(|t| t.0 <= now.0)
}

/// The deposit budget of S (spec/sync-inbox.md §3 Budget): entries and bytes, the policy's
/// raised to the recommended minimum for the head's claim-set size.
fn deposit_budget(policy: &Policy, claims: usize) -> (u64, u64) {
    let (e, b) = osis_proto::limits::deposit_budget(claims);
    (policy.deposit_entries.max(e as u64), policy.deposit_bytes.max(b as u64))
}

/// One node's store.
#[derive(Clone)]
pub struct Store(Arc<Mutex<Inner>>);

impl Store {
    /// A store over `backend` and `root`, created there if none is. Entries a connection with no
    /// record brought that still gave nothing held go: every connection ended with the last start.
    pub fn open(backend: Box<dyn osis_store::Backend>, root: Box<dyn osis_store::RootStorage>, mut rng: Box<dyn osis_crypto::NodeRng>) -> Result<Store> {
        let store = osis_store::Store::open_or_create(backend, root, osis_store::StoreConfig::default(), &mut *rng)?;
        let mut inner = Inner { store, rng, open: None, now: WallMs(0), holdings: BTreeMap::new(), caps: Caps::default(), policy: Policy::default(), mem: Memory::default(), total: None, past_cap: HashMap::new() };
        inner.write(|t, env| {
            for (k, _) in t.scan_local(&[rows::CHARGED, &[0]].concat(), b"", usize::MAX)? {
                let (s, b) = rows::tail_ids(&k)?;
                t.remove_local(&k, Shred::No)?;
                entries::remove(t, env, &s, &b, Removal::Untombed)?;
            }
            Ok(())
        })?;
        Ok(Store(Arc::new(Mutex::new(inner))))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Durable writes committed since the open (a store failure's stretch ends at the next).
    pub fn committed(&self) -> u64 {
        self.lock().store.writes().committed
    }

    /// The engine's ciphertext door (its `Engine::create`/`open` argument).
    pub fn cipher(&self) -> Arc<dyn Ciphertext> {
        self.0.clone()
    }

    /// Runs `f` in a transaction of the node's store, committed: the door through which the
    /// modules owning other rows of it (peer records: opens, streams; `changed_at`) write them,
    /// each beside what makes it true. Not inside an engine call.
    pub fn with_tx<T>(&mut self, f: impl FnOnce(&mut Transaction<'_>) -> std::result::Result<T, osis_store::Error>) -> Result<T> {
        self.lock().write(|t, _| Ok(f(t)?))
    }

    // Holdings and caps

    /// The node's sync set (`Engine::sync_set`): which sync IDs it holds, of which thing, read or
    /// kept unread. A sync ID moving between read and kept unread is counted again in the unread
    /// total (spec/sync-ids.md §5 Caps); only the sync IDs whose holding moved stamp.
    pub fn set_sync_set(&mut self, set: &SyncSet) {
        let mut g = self.lock();
        if g.holdings == set.ids {
            return;
        }
        let unread = |m: &BTreeMap<SyncId, (Tid, Holding)>, s: &SyncId| m.get(s).is_some_and(|(_, h)| *h == Holding::Unread);
        let moved: std::collections::BTreeSet<SyncId> = g.holdings.keys().chain(set.ids.keys()).filter(|s| g.holdings.get(s) != set.ids.get(s)).copied().collect();
        let recount: Vec<(SyncId, bool)> = moved.iter().filter(|s| unread(&g.holdings, s) != unread(&set.ids, s)).map(|s| (*s, unread(&set.ids, s))).collect();
        for s in &moved {
            g.mem.stamps.wrote(&("holding", s), true);
        }
        g.holdings = set.ids.clone();
        if let Some(total) = g.total {
            let counted = g.read(|t, _| {
                let mut n = total;
                for (s, now) in &recount {
                    let b = entries::usage(t, s)?.bytes;
                    n = if *now { n.saturating_add(b) } else { n.saturating_sub(b) };
                }
                Ok(n)
            });
            g.total = counted.ok();
        }
    }

    /// The node's `caps^.0` (`Engine::caps`).
    pub fn set_caps(&mut self, caps: &Caps) {
        let mut g = self.lock();
        g.policy = Policy::from_caps(caps);
        g.caps = caps.clone();
    }

    pub fn holding(&self, s: &SyncId) -> Option<Holding> {
        self.lock().holding(s)
    }

    // Reads

    pub fn entry(&self, s: &SyncId, b: &BlobId) -> Result<Option<Entry>> {
        let mut g = self.lock();
        if let Some(r) = g.mem.read(s, b) {
            return Ok(Some(entries::to_entry(*b, r)));
        }
        g.read(|t, _| Ok(entries::get(t, s, b)?.map(|r| entries::to_entry(*b, &r))))
    }

    /// Every entry of S, durable then ephemeral (stamped reads: memo-safe). O(entries of S).
    pub fn entries(&self, s: &SyncId) -> Result<Vec<Entry>> {
        let mut g = self.lock();
        let mut out = g.read(|t, _| {
            let mut out = Vec::new();
            for (k, v) in t.scan_local(&[rows::ENTRY, &s.0].concat(), b"", usize::MAX)? {
                let (_, b) = rows::tail_ids(&k)?;
                out.push(entries::to_entry(b, &EntryRow::decode(&v)?));
            }
            Ok(out)
        })?;
        out.extend(g.mem.list(s).iter().map(|(b, r)| entries::to_entry(*b, r)));
        Ok(out)
    }

    /// The deposited (unstamped) entries of S, durable then ephemeral (stamped reads). O(S's
    /// deposits), which its deposit budget and the peer budgets bound.
    pub fn deposits(&self, s: &SyncId) -> Result<Vec<Entry>> {
        let mut g = self.lock();
        let mut out = g.read(|t, _| {
            let mut out = Vec::new();
            for (k, _) in t.scan_local(&[rows::DEPOSITED, &s.0].concat(), b"", usize::MAX)? {
                let (_, b) = rows::tail_ids(&k)?;
                if let Some(r) = entries::get(t, s, &b)? {
                    out.push(entries::to_entry(b, &r));
                }
            }
            Ok(out)
        })?;
        out.extend(g.mem.list(s).iter().filter(|(_, r)| r.deposited).map(|(b, r)| entries::to_entry(*b, r)));
        Ok(out)
    }

    /// Every deposited entry held, with its sync ID (a start's listing). O(deposits held).
    pub fn all_deposits(&self) -> Result<Vec<(SyncId, Entry)>> {
        let mut g = self.lock();
        let mut out = g.read(|t, _| {
            let mut out = Vec::new();
            for (k, _) in t.scan_local(rows::DEPOSITED, b"", usize::MAX)? {
                let (s, b) = rows::tail_ids(&k)?;
                if let Some(r) = entries::get(t, &s, &b)? {
                    out.push((s, entries::to_entry(b, &r)));
                }
            }
            Ok(out)
        })?;
        let mut mem: Vec<(SyncId, Entry)> = g.mem.entries.iter().filter(|(_, r)| r.deposited).map(|((s, b), r)| (*s, entries::to_entry(*b, r))).collect();
        mem.sort_by_key(|(s, e)| (*s, e.blob));
        out.extend(mem);
        Ok(out)
    }

    /// The length of blob `b`'s bytes held, if any (sizing deposits, spec/sync-inbox.md §4).
    pub fn blob_len(&self, b: &BlobId) -> Result<Option<u64>> {
        self.lock().read(|t, env| entries::bytes_len(t, env, b))
    }

    /// A reader's cursor over the entries added from now on, or whose wrap, stamp or deposited
    /// flag changed (`(S, blob)`, in order; one undone comes too and reads absent).
    pub fn entry_feed(&self) -> osis_base::memo::Feed<(SyncId, BlobId)> {
        self.lock().mem.fed.feed()
    }

    /// Blob `b`'s bytes, whoever holds them.
    pub fn bytes(&self, b: &BlobId) -> Result<Option<Vec<u8>>> {
        let mut g = self.lock();
        if let Some(v) = g.mem.blobs.get(b) {
            return Ok(Some(v.clone()));
        }
        g.read(|t, _| Ok(t.get_blob(b)?))
    }

    pub fn tombstone(&self, s: &SyncId, b: &BlobId) -> Result<Option<Tombstone>> {
        let mut g = self.lock();
        if g.mem.tombstoned(s, b) {
            let at = g.mem.tombs.get(&(*s, *b)).copied().unwrap_or_default();
            return Ok(Some(Tombstone { at, deleted: false, note: Vec::new() }));
        }
        g.read(|t, _| entries::tombstone(t, s, b))
    }

    /// What S uses: durable and in memory.
    pub fn usage(&self, s: &SyncId) -> Result<(Usage, Usage)> {
        let mut g = self.lock();
        let m = g.mem.usage(s);
        Ok((g.read(|t, _| entries::usage(t, s))?, m))
    }

    /// The head S's path ends at.
    pub fn head(&self, s: &SyncId) -> Result<Option<Step>> {
        self.lock().read(|t, _| Ok(path::head(t, s)?.map(|(_, st)| st)))
    }

    /// S's path from genesis: a kept-unread S's registered one, a read S's served one.
    pub fn path(&self, s: &SyncId) -> Result<Option<Arc<Path>>> {
        self.lock().read(|t, _| Ok(path::read(t, s)?.map(Arc::new)))
    }

    // Writes by this node's own judgement

    /// Logs entry `e` under S in this node's own store (a reader's judgement or an own entry),
    /// with `bytes` unless held already; replaces the wrap, stamp and flags of one held. An
    /// unstamped one is charged to `from` (spec/sync-ids.md §5 Peer budget) until stamped or
    /// `uncharge`d; a new one past `from`'s peer budget is not kept (5). Refused: a tombstoned
    /// blob ID (never logged again under it), an expired or malformed blob, a relay-only one
    /// (never held).
    pub fn log(&mut self, s: &SyncId, e: Entry, bytes: Option<Vec<u8>>, from: Option<Source>) -> Result<Code> {
        let mut g = self.lock();
        let b = e.blob;
        let (class, expires) = match &bytes {
            Some(v) => match check_blob(v, &b) {
                Ok(x) => x,
                Err(c) => return Ok(c),
            },
            None => (e.class, e.expires),
        };
        if class == Class::Relay {
            return Ok(Code::DECLINED);
        }
        if expired(expires, g.now) {
            return Ok(Code::EXPIRED);
        }
        let charged = if e.stamp.is_none() { from } else { None };
        let row = EntryRow { wrap: e.wrap, stamp: e.stamp, deposited: e.deposited, own: e.own, role: e.role, class, expires, size: 0, charged, elsewhere: false };
        if class == Class::Ephemeral {
            if g.mem.tombstoned(s, &b) {
                return Ok(Code::TOMBSTONED);
            }
            if let Some(old) = g.mem.read(s, &b).cloned() {
                let new = EntryRow { size: old.size, charged: if e.stamp.is_some() { None } else { old.charged }, own: old.own || e.own, role: old.role || e.role, elsewhere: old.elsewhere, ..row };
                g.mem.change(s, &b, new);
                return Ok(Code::OK);
            }
            let Some(bytes) = bytes.or_else(|| g.mem.blobs.get(&b).cloned()) else { return Ok(Code::MALFORMED) };
            if let Some(src) = charged {
                let size = bytes.len() as u64;
                if g.read(|t, env| over_peer_budget(t, env, src, size))? {
                    return Ok(Code::DEPOSIT_BUDGET_FULL);
                }
            }
            g.mem.insert(s, &b, row, bytes);
            return Ok(Code::OK);
        }
        g.write(|t, env| {
            if entries::tombstone(t, s, &b)?.is_some() {
                return Ok(Code::TOMBSTONED);
            }
            if let Some(src) = charged
                && entries::get(t, s, &b)?.is_none()
            {
                let size = match &bytes {
                    Some(v) => Some(v.len() as u64),
                    None => entries::bytes_len(t, env, &b)?,
                };
                if over_peer_budget(t, env, src, size.unwrap_or(0))? {
                    return Ok(Code::DEPOSIT_BUDGET_FULL);
                }
            }
            match entries::get(t, s, &b)? {
                Some(old) => {
                    if let Some(v) = bytes
                        && entries::bytes_len(t, env, &b)?.is_none()
                    {
                        t.put_blob(&b, v)?;
                        entries::bytes_arrived(t, env, &b)?;
                    }
                    let old = entries::get(t, s, &b)?.unwrap_or(old);
                    let new = EntryRow { size: old.size, role: old.role || e.role, charged: if e.stamp.is_some() { None } else { old.charged }, own: old.own || e.own, elsewhere: old.elsewhere, ..row };
                    entries::change(t, env, s, &b, &old, new)?;
                }
                None => entries::insert(t, env, s, &b, row, bytes)?,
            }
            Ok(Code::OK)
        })
    }

    /// Drops entry `b` of S by this node's own judgement (spec/sync-judgement.md §3 Own store),
    /// leaving a tombstone with `note` (what the entry was). Whether it was held.
    pub fn drop_entry(&mut self, s: &SyncId, b: &BlobId, note: Vec<u8>) -> Result<bool> {
        let mut g = self.lock();
        let now = g.now;
        if g.mem.read(s, b).is_some() {
            return Ok(g.mem.remove(s, b, now, true, false));
        }
        g.write(|t, env| entries::remove(t, env, s, b, Removal::Tomb(Tombstone { at: now, deleted: false, note })))
    }

    /// Ends S's tombstone of `b` (spec/sync-judgement.md §4: a part counting missing again lifts
    /// this node's own tombstones). Whether there was one.
    pub fn lift_tombstone(&mut self, s: &SyncId, b: &BlobId) -> Result<bool> {
        let mut g = self.lock();
        if g.mem.tombs.remove(&(*s, *b)).is_some() {
            return Ok(true);
        }
        g.write(|t, env| entries::lift(t, env, s, b))
    }

    /// Entry `b` of S gives this node something held: its charge to the peer that brought it ends.
    pub fn uncharge(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let mut g = self.lock();
        if let Some(old) = g.mem.read(s, b).cloned() {
            g.mem.change(s, b, EntryRow { charged: None, ..old });
            return Ok(());
        }
        g.write(|t, env| match entries::get(t, s, b)? {
            Some(old) => entries::change(t, env, s, b, &old.clone(), EntryRow { charged: None, ..old }),
            None => Ok(()),
        })
    }

    /// Whether a source was recorded holding entry `b` of S (`set_elsewhere`).
    pub fn elsewhere(&self, s: &SyncId, b: &BlobId) -> Result<bool> {
        let mut g = self.lock();
        if let Some(r) = g.mem.read(s, b) {
            return Ok(r.elsewhere);
        }
        g.read(|t, _| Ok(entries::get(t, s, b)?.is_some_and(|r| r.elsewhere)))
    }

    /// Records that a source holds entry `b` of S (spec/sync-status.md §2: durable, kept while the
    /// entry is). Nothing for an entry not held.
    pub fn set_elsewhere(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let mut g = self.lock();
        if let Some(old) = g.mem.read(s, b).cloned() {
            if !old.elsewhere {
                g.mem.change(s, b, EntryRow { elsewhere: true, ..old });
            }
            return Ok(());
        }
        g.write(|t, env| match entries::get(t, s, b)? {
            Some(old) if !old.elsewhere => entries::change(t, env, s, b, &old.clone(), EntryRow { elsewhere: true, ..old }),
            _ => Ok(()),
        })
    }

    /// A read S's served path, as its `sync.0` records it; a head move logs a head event.
    pub fn serve_path(&mut self, s: &SyncId, p: &Path) -> Result<()> {
        self.lock().write(|t, env| path::serve(t, env, s, p))
    }

    // Writes a peer brings

    /// A stamped entry a node keeping S unread pulled (spec/sync-ids.md §6 Taking a stamped
    /// entry), with its bytes. Refused: S not kept unread (14); an oversized (3) or malformed (2)
    /// blob; a relay-only one (14: relay-only rules); its prefix expiry passed (7); its blob ID
    /// tombstoned (6); no stamp or a bad one (1); a stamp under an earlier write key of the path
    /// (9); past S's caps (12) unless a role entry. A deposited entry of its blob ID takes the
    /// stamp; a stamped one changes nothing.
    pub fn take_stamped(&mut self, s: &SyncId, e: &Entry, bytes: Vec<u8>) -> Result<Code> {
        let mut g = self.lock();
        if g.holding(s) != Some(Holding::Unread) {
            return Ok(Code::DECLINED);
        }
        let b = e.blob;
        let (class, expires) = match check_blob(&bytes, &b) {
            Ok(x) => x,
            Err(c) => return Ok(c),
        };
        if class == Class::Relay {
            return Ok(Code::DECLINED);
        }
        if expired(expires, g.now) {
            return Ok(Code::EXPIRED);
        }
        let now = g.now;
        let size = bytes.len() as u64;
        let verdict = g.read(|t, _| {
            if entries::tombstone(t, s, &b)?.is_some() {
                return Ok(Err(Code::TOMBSTONED));
            }
            let Some(stamp) = e.stamp else { return Ok(Err(Code::REFUSED)) };
            let Some((_, head)) = path::head(t, s)? else { return Ok(Err(Code::REFUSED)) };
            match osis_label::verify_stamp(&head.keys.write, s, &b, &e.wrap, &stamp) {
                Ok(role) => Ok(Ok(role)),
                Err(_) if path::earlier_write(t, s, |k| osis_label::verify_stamp(k, s, &b, &e.wrap, &stamp).is_ok())? => Ok(Err(Code::NOT_HEAD_KEY)),
                Err(_) => Ok(Err(Code::REFUSED)),
            }
        })?;
        let role = match verdict {
            Ok(r) => r,
            Err(c) => return Ok(c),
        };
        let row = EntryRow { wrap: e.wrap, stamp: e.stamp, deposited: false, own: false, role, class, expires, size: 0, charged: None, elsewhere: false };
        if class == Class::Ephemeral {
            if g.mem.tombstoned(s, &b) {
                return Ok(Code::TOMBSTONED);
            }
            if let Some(old) = g.mem.read(s, &b).cloned() {
                if old.stamp.is_none() {
                    g.mem.change(s, &b, EntryRow { size: old.size, own: old.own, elsewhere: old.elsewhere, ..row });
                }
                return Ok(Code::OK);
            }
            if !role && !mem_room(&mut g, s, size, now) {
                return Ok(Code::STORAGE_CAP);
            }
            g.mem.insert(s, &b, row, bytes);
            return Ok(Code::OK);
        }
        g.write(|t, env| {
            if let Some(old) = entries::get(t, s, &b)? {
                if old.stamp.is_none() {
                    entries::change(t, env, s, &b, &old.clone(), EntryRow { size: old.size, own: old.own, elsewhere: old.elsewhere, ..row })?;
                }
                return Ok(Code::OK);
            }
            if !role && !make_room(t, env, s, size + ENTRY_OVERHEAD)? {
                return Ok(Code::STORAGE_CAP);
            }
            entries::insert(t, env, s, &b, row, Some(bytes))?;
            Ok(Code::OK)
        })
    }

    /// A Deposit item (spec/sync-inbox.md §3), taken by one rule at every node holding its sync
    /// ID, whoever offers it (`from`: where its charge lives). Answers: 0 taken, or held or
    /// dropped already (nothing changes); 4 for a sync ID in the sync set whose head this node
    /// does not hold yet; 5 past the deposit budget or the peer's; 12 past S's caps; 14 a bad
    /// signature, a relay-only, oversized, malformed or expired blob, a sync ID not synced.
    pub fn take_deposit(&mut self, d: &DepositItem, from: Option<Source>) -> Result<Code> {
        let mut g = self.lock();
        let s = d.sync_id;
        let Some(holding) = g.holding(&s) else { return Ok(Code::DECLINED) };
        let b = osis_label::blob_id(&d.blob);
        let (class, expires) = match check_blob(&d.blob, &b) {
            Ok(x) => x,
            Err(_) => return Ok(Code::DECLINED),
        };
        if class == Class::Relay || expired(expires, g.now) {
            return Ok(Code::DECLINED);
        }
        let now = g.now;
        let size = d.blob.len() as u64;
        let policy = g.policy.clone();
        let mem_usage = g.mem.usage(&s);
        let mem_held = g.mem.read(&s, &b).is_some() || g.mem.tombstoned(&s, &b);
        let checked = g.read(|t, env| {
            let Some((hi, head)) = path::head(t, &s)? else { return Ok(Err(Code::RATE_LIMITED)) };
            if mem_held || entries::get(t, &s, &b)?.is_some() || entries::tombstone(t, &s, &b)?.is_some() {
                return Ok(Err(Code::OK));
            }
            let Ok(role) = osis_label::verify_deposit(&head.keys.deposit, &s, &b, &d.wrap, &d.sig) else { return Ok(Err(Code::DECLINED)) };
            let claims = path::claims(t, &s, hi)?.map_or(0, |c| c.claims.len());
            let (be, bb) = deposit_budget(&policy, claims);
            let u = entries::usage(t, &s)?;
            if u.deposits + mem_usage.deposits + 1 > be || u.deposit_bytes + mem_usage.deposit_bytes + size > bb {
                return Ok(Err(Code::DEPOSIT_BUDGET_FULL));
            }
            if let Some(src) = from
                && over_peer_budget(t, env, src, size)?
            {
                return Ok(Err(Code::DEPOSIT_BUDGET_FULL));
            }
            Ok(Ok(role))
        })?;
        let role = match checked {
            Ok(r) => r,
            Err(c) => return Ok(c),
        };
        let row = EntryRow { wrap: d.wrap, stamp: None, deposited: true, own: false, role, class, expires, size: 0, charged: from, elsewhere: false };
        let caps = holding == Holding::Unread && !role;
        if class == Class::Ephemeral {
            if caps && !mem_room(&mut g, &s, size, now) {
                return Ok(Code::STORAGE_CAP);
            }
            g.mem.insert(&s, &b, row, d.blob.clone());
            return Ok(Code::OK);
        }
        g.write(|t, env| {
            if caps && !make_room(t, env, &s, size + ENTRY_OVERHEAD)? {
                return Ok(Code::STORAGE_CAP);
            }
            entries::insert(t, env, &s, &b, row, Some(d.blob.clone()))?;
            Ok(Code::OK)
        })
    }

    /// Delete items for S (spec/sync-ids.md §6 Delete, spec/wire.md §11.2 Delete): taken only at
    /// a node keeping S unread, on a connection where S is open by a store credential (else every
    /// item 8); each by the head's delete key, or by delete keys of levels covering every
    /// commitment group of the blob's prefix with the head's write or sync key. A verified one
    /// removes the entry, leaving a tombstone (0); for an entry not held it changes nothing: 0 by
    /// the delete key where a tombstone of the blob exists (a repeat), else 1 (by levels always:
    /// the prefix is gone), so no peer adds a row for a blob this node does not hold. One
    /// verifying under an earlier step's keys only is 9, any other 1. 13: S not held; 14: S read.
    /// One transaction for the durable items; each reads only its blob's prefix.
    pub fn take_delete(&mut self, s: &SyncId, items: &[DeleteItem], by_store_credential: bool) -> Result<Vec<Code>> {
        let mut g = self.lock();
        let all = |c: Code| Ok(vec![c; items.len()]);
        match g.holding(s) {
            None => return all(Code::UNKNOWN_SYNC_ID),
            Some(Holding::Read) => return all(Code::DECLINED),
            Some(Holding::Unread) => {}
        }
        if !by_store_credential {
            return all(Code::NOT_OPEN);
        }
        let now = g.now;
        // ephemeral entries are judged and removed in memory, the rest in one transaction
        let mut ephemeral = Vec::new();
        let out = g.write(|t, env| {
            let Some((hi, head)) = path::head(t, s)? else { return Ok(vec![Code::UNKNOWN_SYNC_ID; items.len()]) };
            let mut out = Vec::with_capacity(items.len());
            for d in items {
                let b = d.blob;
                let in_mem = env.mem.read(s, &b).is_some();
                let prefix = match env.mem.blobs.get(&b) {
                    Some(v) => Prefix::parse(v).ok(),
                    None => read_prefix(t, &b)?,
                };
                let held = in_mem || entries::get(t, s, &b)?.is_some();
                let code = if d.verify(&head, prefix.as_ref()).is_ok() {
                    if in_mem {
                        ephemeral.push(b);
                        Code::OK
                    } else if held {
                        entries::remove(t, env, s, &b, Removal::Tomb(Tombstone { at: now, deleted: true, note: Vec::new() }))?;
                        Code::OK
                    } else if d.by.is_empty() && (env.mem.tombstoned(s, &b) || entries::tombstone(t, s, &b)?.is_some()) {
                        Code::OK
                    } else {
                        Code::REFUSED
                    }
                } else {
                    let mut earlier = false;
                    for i in (0..hi).rev() {
                        if let Some(st) = path::step(t, s, i)?
                            && d.verify(&st, prefix.as_ref()).is_ok()
                        {
                            earlier = true;
                            break;
                        }
                    }
                    if earlier { Code::NOT_HEAD_KEY } else { Code::REFUSED }
                };
                out.push(code);
            }
            Ok(out)
        })?;
        for b in ephemeral {
            g.mem.remove(s, &b, now, true, false);
        }
        Ok(out)
    }

    /// A Register of `step` with its claim set (spec/sync-ids.md §6 Register, spec/wire.md §11.2).
    /// 14: S not kept unread here (a reader's path comes from `sync.0` alone); 2: a step of
    /// another sync ID or a claim set not hashing to the step's; into an empty path 1 for a
    /// genesis that does not verify, 13 for a child; 0 for the head again; 9: not a child of the
    /// head; 12: past the caps (a genesis; a child past them even without its set, more than once
    /// per interval).
    pub fn take_register(&mut self, s: &SyncId, step: &Step, claims: Option<&ClaimSet>) -> Result<Code> {
        let mut g = self.lock();
        let last = g.past_cap.get(s).copied();
        let policy = g.policy.clone();
        let (code, past) = g.write(|t, env| path::register(t, env, &policy, s, step, claims, last))?;
        if past {
            let now = g.now;
            g.past_cap.insert(*s, now);
        }
        Ok(code)
    }

    /// A Behind item's answer (spec/sync-ids.md §6 Behind), its open signature by `cred`
    /// verified by the caller; at most `max_steps` steps.
    pub fn behind(&self, s: &SyncId, named: Option<&StepId>, cred: &Cred, max_steps: usize) -> Result<Behind> {
        self.lock().read(|t, env| path::behind(t, env, s, named, cred, max_steps))
    }

    // The node log

    /// Up to `max` events of `members` after `from` (from the start with none, or one that names
    /// no position: `whole`), in log order (spec/sync-streams.md §4 Reading). A member with an
    /// `until` is served only its events up to it and the later events of entries first logged
    /// at or below it. The cursor covers what was scanned. Costs the events after `from`.
    pub fn read_log(&self, members: &impl Members, from: Option<&Cursor>, max: usize) -> Result<LogRead> {
        self.lock().read(|t, _| {
            let mut out = LogRead { events: Vec::new(), cursor: from.cloned(), whole: false, more: true };
            let mut first = true;
            while out.events.len() < max && out.more {
                let r = t.log_read(out.cursor.as_deref(), max - out.events.len())?;
                if first {
                    out.whole = r.whole;
                    first = false;
                }
                for e in r.events {
                    let s = e.event.sync_id();
                    if let Some(until) = members.until(&s)
                        && served(t, &e, until)?
                    {
                        out.events.push(e);
                    }
                }
                out.cursor = r.cursor;
                out.more = r.more;
            }
            Ok(out)
        })
    }

    /// Up to `max` events of S alone after `from` (a join: from the start with none), `until` as
    /// in `read_log`. Costs S's events after `from`, however many other sync IDs hold.
    pub fn read_sync(&self, s: &SyncId, until: Option<Position>, from: Option<&Cursor>, max: usize) -> Result<LogRead> {
        self.lock().read(|t, _| {
            let mut r = t.log_read_sync(s, from.map(Vec::as_slice), max)?;
            let mut keep = Vec::with_capacity(r.events.len());
            for e in std::mem::take(&mut r.events) {
                if served(t, &e, until)? {
                    keep.push(e);
                }
            }
            r.events = keep;
            Ok(r)
        })
    }

    /// The memory part of the log of S after counter `after`: each ephemeral entry's latest event
    /// (`true`: present), and the counter read to.
    pub fn read_memory(&self, s: &SyncId, after: u64, max: usize) -> (Vec<(u64, BlobId, bool)>, u64) {
        self.lock().mem.events(s, after, max)
    }

    /// The memory part's counter: it moves at each ephemeral event of any sync ID.
    pub fn memory_mark(&self) -> u64 {
        self.lock().mem.next
    }

    /// The position cursor `c` names on this store's history (spec/sync-streams.md §3): none for
    /// one that does not open, is past the log's end or names an incarnation not held there.
    pub fn position(&self, c: &[u8]) -> Result<Option<Position>> {
        self.lock().read(|t, _| Ok(t.log_position(c)?))
    }

    /// A cursor at position `pos` of this store's log (none past its end).
    pub fn cursor_at(&self, pos: Position) -> Result<Option<Cursor>> {
        self.lock().read(|t, _| Ok(t.log_cursor(pos)?))
    }

    /// The position entry `b` of S was first logged at, while the log holds it: what a member
    /// ended at `until` may still fetch (spec/sync-streams.md §4).
    pub fn first_logged(&self, s: &SyncId, b: &BlobId) -> Result<Option<Position>> {
        self.lock().read(|t, _| Ok(t.log_entry_first(s, b)?))
    }

    /// The log's last position and its deletion horizon (spec/sync-streams.md §3).
    pub fn log_bounds(&self) -> Result<(Position, Position)> {
        self.lock().read(|t, _| Ok((t.log_end()?, t.log_horizon()?)))
    }

    // Leaving and closing

    /// Leaving S (spec/sync-set.md §3): every row of S goes, wraps and keys shredded, with S's
    /// log events, its usage, and S in every peer record (the one transaction that stops it).
    pub fn shred(&mut self, s: &SyncId) -> Result<()> {
        let mut g = self.lock();
        let now = g.now;
        g.write(|t, env| {
            for (k, _) in t.scan_local(&[rows::ENTRY, &s.0].concat(), b"", usize::MAX)? {
                let (_, b) = rows::tail_ids(&k)?;
                entries::remove(t, env, s, &b, Removal::Expired)?;
            }
            for (k, _) in t.scan_local(&[rows::TOMB, &s.0].concat(), b"", usize::MAX)? {
                let (_, b) = rows::tail_ids(&k)?;
                entries::lift(t, env, s, &b)?;
            }
            path::erase(t, env, s)?;
            let u = entries::usage(t, s)?;
            entries::put_usage(t, env, s, u, Usage::default())?;
            t.log_forget(*s)?;
            t.changed_forget(s)?;
            Ok(())
        })?;
        g.mem.forget(s, now);
        g.past_cap.remove(s);
        Ok(())
    }

    /// A source went: a connection closed, or a peer's record was dropped (spec/sync-ids.md §5
    /// Peer budget: a lost record is a first contact). The entries charged to it, those that
    /// still give nothing held, go (fetched again where present), and what was kept for a
    /// connection alone. One transaction.
    pub fn gone(&mut self, src: Source) -> Result<()> {
        let mut g = self.lock();
        let now = g.now;
        for (s, b) in g.mem.charged_to(src) {
            g.mem.remove(&s, &b, now, false, false);
        }
        g.mem.charges.remove(&src);
        if let Source::Conn(conn) = src {
            g.mem.conn_forget(|(c, ..)| *c != conn);
        }
        g.write(|t, env| {
            for (k, _) in t.scan_local(&[rows::CHARGED, &rows::source_bytes(src)].concat(), b"", usize::MAX)? {
                let (s, b) = rows::tail_ids(&k)?;
                entries::remove(t, env, &s, &b, Removal::Untombed)?;
            }
            Ok(())
        })
    }

    // What a source's record keeps for `read` (spec/sync-judgement.md §4)

    fn source_put(&mut self, src: Source, s: &SyncId, tag: u8, key: &[u8], val: Option<(WallMs, Vec<u8>)>) -> Result<()> {
        let mut g = self.lock();
        match src {
            Source::Conn(c) => {
                g.mem.conn_put((c, *s, tag, key.to_vec()), val);
                Ok(())
            }
            Source::Record(rec) => g.write(|t, _| {
                match val {
                    Some((at, v)) => {
                        t.record_put_row(&rec, tag, s, key, v)?;
                        t.put_local(&rows::aging_key(at, s, tag, key, &rec), &[], Shred::No)?;
                    }
                    None => drop(t.record_remove_row(&rec, tag, s, key)?),
                }
                Ok(())
            }),
        }
    }

    fn source_get(&self, src: Source, s: &SyncId, tag: u8, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut g = self.lock();
        match src {
            Source::Conn(c) => Ok(g.mem.conn_get(&(c, *s, tag, key.to_vec()))),
            Source::Record(rec) => g.read(|t, _| Ok(t.record_get_row(&rec, tag, s, key)?)),
        }
    }

    /// The stand of "logged again once" for `body` at `src` (spec/sync-judgement.md §4).
    pub fn stand(&self, src: Source, s: &SyncId, body: &[u8]) -> Result<Option<Stand>> {
        self.source_get(src, s, STAND, body)?.map(|v| Stand::decode(&v)).transpose()
    }

    pub fn set_stand(&mut self, src: Source, s: &SyncId, body: &[u8], stand: Option<&Stand>) -> Result<()> {
        self.source_put(src, s, STAND, body, stand.map(|x| (x.at, x.encode())))
    }

    /// This node saw entry `b` of S deleted at `src`, now (spec/sync-judgement.md §3 Neither).
    pub fn saw_deleted(&mut self, src: Source, s: &SyncId, b: &BlobId) -> Result<()> {
        let now = self.lock().now;
        self.source_put(src, s, SEEN, &b.0, Some((now, now.0.to_be_bytes().to_vec())))
    }

    /// Whether this node saw entry `b` of S deleted at `src` within `TOMBSTONE_LIFETIME`.
    pub fn seen_deleted(&self, src: Source, s: &SyncId, b: &BlobId) -> Result<bool> {
        Ok(self.source_get(src, s, SEEN, &b.0)?.is_some())
    }

    // Time

    /// Reads the engine's sync set and caps (a part the engine has not built leaves them as
    /// they are), then `settle_at`.
    pub fn settle(&mut self, engine: &mut Engine, now: WallMs) -> Result<bool> {
        match engine.sync_set() {
            Ok(set) => self.set_sync_set(&set),
            Err(osis_engine::Error::NotBuilt(_)) => {}
            Err(e) => return Err(e.into()),
        }
        match engine.caps() {
            Ok(c) => self.set_caps(&c),
            Err(osis_engine::Error::NotBuilt(_)) => {}
            Err(e) => return Err(e.into()),
        }
        self.settle_at(now)
    }

    /// Time is `now`: entries past their expiry go (no tombstone, no event), tombstones and the
    /// rows of deletes seen and stands end after `TOMBSTONE_LIFETIME`, claim sets after
    /// `ROLE_KEEP` superseded, deletion events leave the log, and the caps give way if the total
    /// is past them. At most `PAGE` of each a call; whether anything acted.
    pub fn settle_at(&mut self, now: WallMs) -> Result<bool> {
        let mut g = self.lock();
        g.now = WallMs(g.now.0.max(now.0));
        let now = g.now;
        let mut acted = g.mem.sweep(now);
        acted |= g.write(|t, env| {
            let mut acted = false;
            for (k, _) in t.scan_local(rows::EXPIRY, b"", PAGE)? {
                if time_of(&k)? > now.0 {
                    break;
                }
                let (s, b) = rows::tail_ids(&k)?;
                t.remove_local(&k, Shred::No)?;
                entries::remove(t, env, &s, &b, Removal::Expired)?;
                acted = true;
            }
            for (k, _) in t.scan_local(rows::TOMB_AT, b"", PAGE)? {
                if time_of(&k)?.saturating_add(TOMBSTONE_LIFETIME_MS) > now.0 {
                    break;
                }
                let (s, b) = rows::tail_ids(&k)?;
                t.remove_local(&k, Shred::No)?;
                entries::lift(t, env, &s, &b)?;
                acted = true;
            }
            for (k, _) in t.scan_local(rows::CLAIMS_DUE, b"", PAGE)? {
                if time_of(&k)? > now.0 {
                    break;
                }
                let mut r = R::new(k.get(rows::CLAIMS_DUE.len() + 8..).unwrap_or_default());
                let (s, i) = (SyncId(r.array()?), r.u32()?);
                t.remove_local(&k, Shred::No)?;
                path::drop_claims(t, env, &s, i)?;
                acted = true;
            }
            for (k, _) in t.scan_local(rows::AGING, b"", PAGE)? {
                let at = time_of(&k)?;
                if at.saturating_add(TOMBSTONE_LIFETIME_MS) > now.0 {
                    break;
                }
                let mut r = R::new(k.get(rows::AGING.len() + 8..).unwrap_or_default());
                let (s, tag) = (SyncId(r.array()?), r.u8()?);
                let key = r.bytes()?.to_vec();
                let rec: osis_store::RecordId = r.array()?;
                t.remove_local(&k, Shred::No)?;
                // a row written again since ages from its new time
                if t.record_get_row(&rec, tag, &s, &key)?.is_some_and(|v| v.get(..8) == Some(&at.to_be_bytes()[..])) {
                    t.record_remove_row(&rec, tag, &s, &key)?;
                }
                acted = true;
            }
            acted |= t.log_sweep(now.0)?;
            let total = env.total(t)?;
            if total > env.policy.total_bytes {
                acted |= give_way(t, env, total - env.policy.total_bytes)?;
            }
            Ok(acted)
        })?;
        Ok(acted)
    }

    /// When `settle_at` next has something to do.
    pub fn next_wake(&self) -> Option<WallMs> {
        let mut g = self.lock();
        let m = g.mem.next_due();
        let d = g
            .read(|t, _| {
                let first = |t: &mut Transaction<'_>, p: &[u8], add: u64| -> Result<Option<u64>> { Ok(t.scan_local(p, b"", 1)?.first().map(|(k, _)| time_of(k)).transpose()?.map(|x| x.saturating_add(add))) };
                let all = [
                    first(t, rows::EXPIRY, 0)?,
                    first(t, rows::TOMB_AT, TOMBSTONE_LIFETIME_MS)?,
                    first(t, rows::CLAIMS_DUE, 0)?,
                    first(t, rows::AGING, TOMBSTONE_LIFETIME_MS)?,
                    t.log_next_due()?,
                ];
                Ok(all.into_iter().flatten().min().map(WallMs))
            })
            .ok()
            .flatten();
        m.into_iter().chain(d).min()
    }

    /// Tests only: this store's copy inside a world copy (`osis_base::copying`), the one the
    /// engine's copy holds.
    #[doc(hidden)]
    pub fn test_copy(&self, clock: Arc<dyn osis_base::Clock>) -> Result<Store> {
        Ok(Store(osis_store::test_copy_shared(&self.0, clock)?))
    }
}

/// The time a time-keyed sweep row starts with.
fn time_of(k: &[u8]) -> Result<u64> {
    let mut r = R::new(k.get(2..).unwrap_or_default());
    r.u64()
}

/// Whether event `e` is served to a member ended at `until` (spec/sync-streams.md §4: its events
/// up to `until` and later events of entries the log first held at or below it).
fn served(t: &mut Transaction<'_>, e: &LoggedEvent, until: Option<Position>) -> Result<bool> {
    let Some(until) = until else { return Ok(true) };
    if e.pos <= until {
        return Ok(true);
    }
    Ok(match e.event {
        NodeEvent::Added(s, b) | NodeEvent::Deleted { label: s, blob: b, .. } => t.log_entry_first(&s, &b)?.is_some_and(|f| f <= until),
        NodeEvent::Head(_) => false,
    })
}

/// Whether `size` more bytes charged to `src` pass its peer budget (spec/sync-ids.md §5 Peer
/// budget): what its durable and ephemeral entries giving nothing held are charged so far.
fn over_peer_budget(t: &mut Transaction<'_>, env: &Env<'_>, src: Source, size: u64) -> Result<bool> {
    let mem = env.mem.charges.get(&src).copied().unwrap_or(0);
    Ok(source_charge(t, src)?.saturating_add(mem).saturating_add(size) > env.policy.peer_bytes)
}

/// Bytes charged to a source by durable entries.
fn source_charge(t: &mut Transaction<'_>, src: Source) -> Result<u64> {
    match src {
        Source::Record(rec) => entries::record_charge(t, &rec),
        Source::Conn(c) => entries::conn_charge(t, c),
    }
}

/// Room for `add` bytes of a new entry of S kept unread (spec/sync-ids.md §6 Caps): within S's
/// own caps, else none; past the total, the sync ID using most gives way (its oldest entries, no
/// tombstone) until it fits. A sync ID read takes nothing from the room.
fn make_room(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, add: u64) -> Result<bool> {
    if env.holding(s) != Some(Holding::Unread) {
        return Ok(true);
    }
    let u = entries::usage(t, s)?;
    let (ce, cb) = env.caps_of(s);
    if u.entries.saturating_add(1) > ce || u.bytes.saturating_add(add) > cb {
        return Ok(false);
    }
    let total = env.total(t)?.saturating_add(add);
    if total > env.policy.total_bytes {
        give_way(t, env, total - env.policy.total_bytes)?;
        return Ok(env.total(t)?.saturating_add(add) <= env.policy.total_bytes);
    }
    Ok(true)
}

/// The sync IDs kept unread using most give way, oldest entries first (by the node log), until
/// `need` bytes are freed or nothing gives. Whether anything went.
fn give_way(t: &mut Transaction<'_>, env: &mut Env<'_>, need: u64) -> Result<bool> {
    let goal = env.total(t)?.saturating_sub(need);
    let mut acted = false;
    let mut from: Vec<u8> = Vec::new();
    'sync_ids: while env.total(t)? > goal {
        let Some((k, _)) = t.scan_local(rows::BY_USE, &from, PAGE)?.into_iter().find(|(k, _)| {
            let s = SyncId(k.get(k.len() - 16..).and_then(|x| x.try_into().ok()).unwrap_or_default());
            env.holding(&s) == Some(Holding::Unread)
        }) else {
            break;
        };
        let s = SyncId(k.get(k.len() - 16..).and_then(|x| x.try_into().ok()).unwrap_or_default());
        from = [k.get(rows::BY_USE.len()..).unwrap_or_default(), &[0]].concat();
        let mut cursor: Option<Vec<u8>> = None;
        loop {
            let r = t.log_read_sync(&s, cursor.as_deref(), PAGE)?;
            for e in &r.events {
                if let NodeEvent::Added(_, b) = e.event
                    && entries::get(t, &s, &b)?.is_some_and(|row| !row.role)
                {
                    entries::remove(t, env, &s, &b, Removal::Untombed)?;
                    acted = true;
                    if env.total(t)? <= goal {
                        break 'sync_ids;
                    }
                }
            }
            if !r.more {
                break;
            }
            cursor = r.cursor;
        }
    }
    Ok(acted)
}

/// Room in memory for an ephemeral entry of `size` bytes of S (spec/sync-ids.md §6 Caps): within
/// S's memory cap, else none; past the total, the sync ID using most memory gives way.
fn mem_room(g: &mut Inner, s: &SyncId, size: u64, now: WallMs) -> bool {
    if g.holding(s) != Some(Holding::Unread) {
        return true;
    }
    let add = size + ENTRY_OVERHEAD;
    if g.mem.usage(s).bytes.saturating_add(add) > g.policy.memory_bytes {
        return false;
    }
    let unread = |g: &Inner, x: &SyncId| g.holdings.get(x).is_some_and(|(_, h)| *h == Holding::Unread);
    loop {
        let total: u64 = g.mem.usage.iter().filter(|(x, _)| unread(g, x)).map(|(_, u)| u.bytes).sum();
        if total.saturating_add(add) <= g.policy.memory_total {
            return true;
        }
        let Some(most) = g.mem.usage.iter().filter(|(x, _)| unread(g, x)).max_by_key(|(_, u)| u.bytes).map(|(x, _)| *x) else { return false };
        let oldest = g.mem.list(&most).into_iter().find(|(_, r)| !r.role).map(|(b, _)| b);
        let Some(b) = oldest else { return false };
        g.mem.remove(&most, &b, now, false, false);
    }
}

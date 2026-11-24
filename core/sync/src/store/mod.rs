//! The store per sync ID (spec/sync-ids.md §5-§6, spec/sync-streams.md §3, spec/sync-inbox.md
//! §3, spec/sync-judgement.md §4 stand state).
//!
//! One store of ciphertext per node for every sync ID it holds, read and kept unread alike:
//! entries (wrap or filler, stamp, deposited flag), tombstones, blob bytes once per node, the
//! path each sync ID serves, the node log with its per-sync-ID index, usage against the caps and
//! the deposit budget, charges against each peer's budget, and the rows a source's record keeps
//! of what this node logged again there. Ephemeral entries, their tombstones and bytes live in a
//! second store kept in memory (`Inner::ram`), with the same rows and the same rules
//! (`entries`), beside the memory part of the log (`memory`). It is the engine's ciphertext door
//! (`osis_store::CipherStore`, `cipher`): `Store` is a cheap handle over one locked store, held by
//! the engine's door and by `Cx`; the engine locks it only inside its own transactions, sync only
//! between engine calls, so one step never holds both.
//!
//! Every operation is one transaction of the underlying store, so a crash keeps all of its rows
//! or none (an entry and its log event, a removal and its tombstone). Every row change stamps
//! (osis-store `Stamping`; the memory log and feeds their own `Stamps`), so memos may read it. Expiry,
//! tombstone ends, claim sets' `ROLE_KEEP` and the caps giving way run in `settle`. It decrypts
//! nothing and judges no open: every secret lives above it. It learns which sync IDs the node
//! holds, and how, from the engine's sync set, and its caps from the engine's `caps^.0`.

mod cipher;
mod entries;
mod memory;
mod path;
pub(crate) mod rows;
pub(crate) mod source;
mod follow;

pub use follow::Follow;
pub(crate) use follow::{open_entry, pends, release};
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

use crate::types::{ConnId, Cursor, Entry, Position, RecordId, Result};
use entries::Removal;
use memory::Memory;
use osis_base::format::{MAX_BLOB, TOMBSTONE_LIFETIME_MS};
use osis_base::memo::{Clock, Effects};
use osis_base::{BlobId, Mono, SyncId, WallMs};
use osis_engine::sync::{Caps, Held, Holding, Path, SyncSet};
use osis_blob::{Class, ClaimSet, DeleteItem, Prefix, Step, StepId};
use osis_proto::{Code, DepositItem};
use osis_store::{Ciphertext, LogRead, LoggedEvent, NodeEvent, Shred, Suspended, Transaction};
use rows::{EntryRow, R, Vouch, W};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

/// Bytes a durable entry counts toward the caps beside its blob: its row, index rows and log
/// record on disk (an entry in memory counts what it holds there: `entries::overhead`). Minor
/// consequence: the durable caps are approximate by this much per entry (0: rows count nothing;
/// infinity: no entry fits).
pub(crate) const ENTRY_OVERHEAD: u64 = 256;
/// Bytes a durable tombstone counts toward the caps (minor consequence, as `ENTRY_OVERHEAD`).
pub(crate) const TOMB_OVERHEAD: u64 = 128;
/// Rows a sweep or a give-way pass reads at a time (performance switch: each settle round does
/// at most this much per kind and says it acted while more is due).
const PAGE: usize = 256;

/// The record row tags this module owns: a source's stand of "logged again once", and the
/// deletes seen there (spec/sync-judgement.md §4).
use rows::tag::{ROOM_AT, SEEN, STAND};

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
    pub holdings: &'a BTreeMap<SyncId, Held>,
    pub caps: &'a Caps,
    pub policy: &'a Policy,
    pub mem: &'a mut Memory,
    /// Bytes used by every sync ID kept unread; `None` until counted.
    pub total: Option<Total>,
}

/// The usage of every sync ID kept unread (`Env::total`): its bytes, and of those the bytes no
/// give-way frees.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Total {
    pub bytes: u64,
    pub fixed: u64,
}

impl Total {
    pub(crate) fn add(&mut self, u: &Usage, sign: bool) {
        let op = |x: &mut u64, n: u64| *x = if sign { x.saturating_add(n) } else { x.saturating_sub(n) };
        op(&mut self.bytes, u.bytes);
        op(&mut self.fixed, u.fixed());
    }
}

/// Whether S moving from `was` to `now` is raised (spec/sync-judgement.md §6 Read and unread
/// move): it takes entries its sources showed it before and it did not take, so they are pulled
/// from the start: from kept unread to opened (read or for keys), or from held for keys (role
/// entries alone) to read.
fn raised(was: Option<&Held>, now: Option<&Held>) -> bool {
    match (was.map(|(_, h)| *h), now.map(|(_, h)| *h)) {
        (Some(Holding::Unread), Some(h)) => h.opens(),
        (Some(Holding::Keys), Some(Holding::Read)) => true,
        _ => false,
    }
}

impl Env<'_> {
    pub(crate) fn holding(&self, s: &SyncId) -> Option<Holding> {
        self.holdings.get(s).map(|(_, h)| *h)
    }

    /// The caps of S: per thing of S its own, else the policy's; S kept for several things keeps
    /// what the largest allows (it serves each).
    fn caps_of(&self, s: &SyncId) -> (u64, u64) {
        let policy = (self.policy.entries, self.policy.bytes);
        let Some((things, _)) = self.holdings.get(s) else { return policy };
        things.iter().map(|t| self.caps.things.get(t).map_or(policy, |c| (c.entries, c.bytes))).reduce(|a, b| (a.0.max(b.0), a.1.max(b.1))).unwrap_or(policy)
    }

    fn total(&mut self, t: &mut Transaction<'_>) -> Result<u64> {
        Ok(self.totals(t)?.bytes)
    }

    fn totals(&mut self, t: &mut Transaction<'_>) -> Result<Total> {
        if let Some(n) = self.total {
            return Ok(n);
        }
        let mut n = Total::default();
        for (s, (_, h)) in self.holdings {
            if *h == Holding::Unread {
                n.add(&entries::usage(t, s)?, true);
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
    /// The memory part's rows: ephemeral entries, their tombstones and bytes, the engine's memory
    /// holds. A store over memory whose transactions run in memory mode (rows in its overlay,
    /// never written to its backend), lost at a restart. Not the durable store's own overlay: the
    /// engine's transaction, suspended between its calls, may hold no memory rows, and that
    /// store's node log and records write durably in memory mode too.
    ram: osis_store::Store,
    rng: Box<dyn osis_crypto::NodeRng>,
    /// The engine's transaction, open between its blob calls.
    open: Option<Suspended>,
    now: WallMs,
    holdings: BTreeMap<SyncId, Held>,
    caps: Caps,
    policy: Policy,
    mem: Memory,
    total: Option<Total>,
    /// When each sync ID last took a child step past its caps (spec/sync-ids.md §6).
    past_cap: BTreeMap<SyncId, Mono>,
    /// The sync IDs kept unread at a head whose sync key this node holds no box for
    /// (spec/sync-judgement.md §6): they take no entry, as with no head (`unread` sets them).
    unheld: BTreeSet<SyncId>,
    /// The sync IDs kept unread that are full (spec/sync-streams.md §4 Full): per cap that
    /// refused, what it refused (rows `R/`, loaded at open).
    room: BTreeMap<(SyncId, Cap), Refused>,
    /// Each key of `room` followed: whether the cap now has room for that least entry, every
    /// entry it refused expired, or S is no longer kept unread; due only once what that reads
    /// moves (`room_fits`).
    room_fx: Effects<(SyncId, Cap), bool>,
    /// The full sync IDs ended since the last `room_grew` by their last room mark going
    /// (`unmark`): their rows went then, `room_grew` reports them.
    room_gone: BTreeSet<SyncId>,
    /// The room marks of sources that are connections (spec/sync-streams.md §4 Full; a record's
    /// are its rows, `tag::ROOM_AT`): per S, each connection's, whether owed. Gone with the
    /// connection (`gone`).
    room_conn: BTreeMap<SyncId, BTreeMap<ConnId, bool>>,
    /// `now` as read by `room_fits` (an expiry it waits for is a wake, `next_wake`).
    clock: Clock,
}

/// What a cap refused of a sync ID kept unread (spec/sync-streams.md §4 Full, row `R/`): the
/// bytes the least entry it refused needs under it, and the latest expiry of one (`u64::MAX`:
/// one has none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Refused {
    need: u64,
    expires: u64,
}

impl Inner {
    /// S kept unread refused an entry needing `need` bytes under `cap` for room, expiring at
    /// `expires`, whose place passes it at each of `from`: S is full, durably, keeping the least
    /// need and the latest expiry that cap refused (`Store::room_grew`), and each of `from` with
    /// no room mark of S gets one standing (an owed one stays owed: its pull from the start shows
    /// the entry again), in the same transaction.
    fn wait_room(&mut self, s: &SyncId, cap: Cap, need: u64, expires: Option<WallMs>, from: &[Source]) -> Result<()> {
        let expires = expires.map_or(u64::MAX, |t| t.0);
        let r = match self.room.get(&(*s, cap)) {
            Some(r) => Refused { need: r.need.min(need), expires: r.expires.max(expires) },
            None => Refused { need, expires },
        };
        let moved = self.room.get(&(*s, cap)) != Some(&r);
        let conns: Vec<ConnId> = from.iter().filter_map(|x| if let Source::Conn(c) = x { Some(*c) } else { None }).filter(|c| !self.room_conn.get(s).is_some_and(|m| m.contains_key(c))).collect();
        let recs: Vec<RecordId> = from.iter().filter_map(|x| if let Source::Record(r) = x { Some(*r) } else { None }).collect();
        let recs: Vec<RecordId> = self.read(|t, _| {
            let mut out = Vec::new();
            for rec in recs {
                if t.record_get_row(&rec, ROOM_AT, s, b"")?.is_none() {
                    out.push(rec);
                }
            }
            Ok(out)
        })?;
        if !moved && conns.is_empty() && recs.is_empty() {
            return Ok(());
        }
        self.write(|t, _| {
            if moved {
                t.put_local(&room_key(s, cap), &[r.need.to_be_bytes(), r.expires.to_be_bytes()].concat(), Shred::No)?;
            }
            for rec in &recs {
                t.record_put_row(rec, ROOM_AT, s, b"", vec![rows::ROOM_STANDS])?;
            }
            Ok(())
        })?;
        for c in conns {
            self.room_conn.entry(*s).or_default().insert(c, false);
        }
        if moved {
            self.room.insert((*s, cap), r);
            self.mem.stamps.wrote(&RoomNeed(s, cap), true);
            self.room_fx.want((*s, cap));
        }
        Ok(())
    }

    /// Whether S is full (rows `R/`).
    fn full(&self, s: &SyncId) -> bool {
        self.room.range((*s, Cap::Own)..=(*s, Cap::MemoryTotal)).next().is_some()
    }

    /// In one transaction: `f`, then the room marks of S at each of `srcs` go; S full with no
    /// room mark left (none passed what it refused) is full no longer, its `R/` rows going in it
    /// too (spec/sync-streams.md §4 Full), reported at the next `room_grew`. O(S's room marks
    /// read: one).
    fn unmark(&mut self, s: &SyncId, srcs: &[Source], f: impl FnOnce(&mut Transaction<'_>) -> std::result::Result<(), osis_store::Error>) -> Result<()> {
        let conns_left = self.room_conn.get(s).is_some_and(|m| m.keys().any(|c| !srcs.contains(&Source::Conn(*c))));
        let full = self.full(s);
        let ended = self.write(|t, _| {
            f(t)?;
            for src in srcs {
                if let Source::Record(rec) = src {
                    t.record_remove_row(rec, ROOM_AT, s, b"")?;
                }
            }
            let ended = full && !conns_left && !t.records_any_row(s, ROOM_AT, b"")?;
            if ended {
                remove_room_rows(t, s)?;
            }
            Ok(ended)
        })?;
        if let Some(m) = self.room_conn.get_mut(s) {
            m.retain(|c, _| !srcs.contains(&Source::Conn(*c)));
            if m.is_empty() {
                self.room_conn.remove(s);
            }
        }
        if ended {
            self.forget_room(s);
            self.room_gone.insert(*s);
        }
        Ok(())
    }

    /// S full under no cap, in memory (its `R/` rows go with `remove_room_rows`).
    fn forget_room(&mut self, s: &SyncId) {
        let keys: Vec<(SyncId, Cap)> = self.room.range((*s, Cap::Own)..=(*s, Cap::MemoryTotal)).map(|(k, _)| *k).collect();
        for k in &keys {
            self.room.remove(k);
            self.room_fx.unwant(k);
        }
    }

    /// Runs `f` in a transaction of its own of the durable store, or of the memory part's
    /// (`memory`), and commits it; nothing of it stays on an error, but what it fed or logged in
    /// memory.
    fn write_in<T>(&mut self, memory: bool, f: impl FnOnce(&mut Transaction<'_>, &mut Env<'_>) -> Result<T>) -> Result<T> {
        debug_assert!(memory || self.open.is_none(), "sync wrote inside the engine's transaction");
        self.tx(memory, true, f)
    }

    /// Runs `f` over a transaction of either part that writes nothing (dropped).
    fn read_in<T>(&mut self, memory: bool, f: impl FnOnce(&mut Transaction<'_>, &mut Env<'_>) -> Result<T>) -> Result<T> {
        self.tx(memory, false, f)
    }

    fn tx<T>(&mut self, memory: bool, commit: bool, f: impl FnOnce(&mut Transaction<'_>, &mut Env<'_>) -> Result<T>) -> Result<T> {
        let Inner { store, ram, rng, now, holdings, caps, policy, mem, total, .. } = self;
        let mut env = Env { now: *now, holdings, caps, policy, mem, total: *total };
        let mut t = if memory { ram.transaction(&mut **rng)? } else { store.transaction(&mut **rng)? };
        t.set_memory(memory);
        let r = f(&mut t, &mut env)?;
        if commit {
            t.commit()?;
            *total = env.total;
        }
        Ok(r)
    }

    fn write<T>(&mut self, f: impl FnOnce(&mut Transaction<'_>, &mut Env<'_>) -> Result<T>) -> Result<T> {
        self.write_in(false, f)
    }

    fn read<T>(&mut self, f: impl FnOnce(&mut Transaction<'_>, &mut Env<'_>) -> Result<T>) -> Result<T> {
        self.read_in(false, f)
    }

    /// Entry `b` of S, with whether the memory part holds it.
    fn find(&mut self, s: &SyncId, b: &BlobId) -> Result<Option<(bool, EntryRow)>> {
        for memory in [true, false] {
            if let Some(r) = self.read_in(memory, |t, _| entries::get(t, s, b))? {
                return Ok(Some((memory, r)));
            }
        }
        Ok(None)
    }

    /// `f` over each part, the durable store's first, and what each gave.
    fn each<T>(&mut self, mut f: impl FnMut(&mut Transaction<'_>, &mut Env<'_>) -> Result<T>) -> Result<[T; 2]> {
        Ok([self.read_in(false, &mut f)?, self.read_in(true, &mut f)?])
    }

    fn holding(&self, s: &SyncId) -> Option<Holding> {
        self.mem.syncs.read(s);
        self.holdings.get(s).map(|(_, h)| *h)
    }
}

/// What a blob's bytes say of it, or the code refusing them.
fn check_blob(bytes: &[u8], b: &BlobId) -> std::result::Result<(Class, Option<WallMs>), Code> {
    if bytes.len() > MAX_BLOB {
        return Err(Code::TOO_LARGE);
    }
    if osis_blob::blob_id(bytes) != *b {
        return Err(Code::MALFORMED);
    }
    match Prefix::parse(bytes) {
        Ok(p) => Ok((p.class(), p.expiry())),
        // a framing this build does not know: parked, no expiry, no commitments
        Err(osis_blob::Error::UnknownFraming(_)) => Ok((Class::Durable, None)),
        Err(_) => Err(Code::MALFORMED),
    }
}

/// A blob of `class` expiring at `expires` as a store keeps one now, or the code refusing it: a
/// relay-only blob is never held (14), an expired one never taken (7).
fn kept((class, expires): (Class, Option<WallMs>), now: WallMs) -> std::result::Result<(Class, Option<WallMs>), Code> {
    match class {
        Class::Relay => Err(Code::DECLINED),
        _ if expired(expires, now) => Err(Code::EXPIRED),
        _ => Ok((class, expires)),
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
            Err(osis_blob::Error::Malformed(_)) if v.len() == n && n < MAX_BLOB => n = n.saturating_mul(2),
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

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Store")
    }
}

impl Store {
    /// A store over `backend` and `root`, created there if none is. Entries a connection with no
    /// record brought that still gave nothing held go: every connection ended with the last start.
    pub fn open(backend: Box<dyn osis_store::Backend>, root: Box<dyn osis_store::RootStorage>, mut rng: Box<dyn osis_crypto::NodeRng>) -> Result<Store> {
        let store = osis_store::Store::open_or_create(backend, root, osis_store::StoreConfig::default(), &mut *rng)?;
        let ram = osis_store::Store::create(Box::new(osis_store::MemoryBackend::new()), Box::new(osis_store::MemoryRoot::new()), osis_store::StoreConfig::default(), &mut *rng)?;
        let mut inner = Inner { store, ram, rng, open: None, now: WallMs(0), holdings: BTreeMap::new(), caps: Caps::default(), policy: Policy::default(), mem: Memory::default(), total: None, past_cap: BTreeMap::new(), unheld: BTreeSet::new(), room: BTreeMap::new(), room_fx: Effects::new(ROOM_JUDGED), room_gone: BTreeSet::new(), room_conn: BTreeMap::new(), clock: Clock::default() };
        inner.write(|t, env| {
            // a start ends every connection: each one charged or bringing goes (connection
            // numbers start again, so none may name the next one given it)
            let mut conns = BTreeSet::new();
            for prefix in [rows::CHARGED, rows::BROUGHT] {
                for (k, _) in t.scan_local(&[prefix, &[rows::CONN]].concat(), b"", usize::MAX)? {
                    let id = k.get(prefix.len() + 1..prefix.len() + 9).and_then(|x| x.try_into().ok()).ok_or(crate::types::Error::Store(osis_store::Error::Corrupt("charged row")))?;
                    conns.insert(crate::types::ConnId(u64::from_be_bytes(id)));
                }
            }
            for c in conns {
                Self::gone_from(t, env, Source::Conn(c))?;
            }
            Ok(())
        })?;
        // a copy dropped before the start takes nothing until judged again (`set_unheld`); one
        // raised to read is fetched anew (`anew_feed`)
        inner.unheld = inner.read(|t, _| anew_marks(t, false))?;
        // a full S whose room marks were all connections' (in memory) is full no longer
        let room = inner.read(|t, _| room_rows(t))?;
        inner.room = inner.write(|t, _| {
            let mut kept = BTreeMap::new();
            for (k, r) in room {
                if !t.records_any_row(&k.0, ROOM_AT, b"")? {
                    t.remove_local(&room_key(&k.0, k.1), Shred::No)?;
                } else {
                    kept.insert(k, r);
                }
            }
            Ok(kept)
        })?;
        for k in inner.room.keys() {
            inner.room_fx.want(*k);
        }
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

    /// Runs `f` over a transaction of the node's store that writes nothing: the door through
    /// which the modules owning other rows of it read them. Not inside an engine call.
    pub fn with_read<T>(&self, f: impl FnOnce(&mut Transaction<'_>) -> std::result::Result<T, osis_store::Error>) -> Result<T> {
        self.lock().read(|t, _| Ok(f(t)?))
    }

    /// `with_tx` in either part (`memory`): the memory part's for a source's memory rows
    /// (`source`).
    pub(crate) fn with_tx_in<T>(&mut self, memory: bool, f: impl FnOnce(&mut Transaction<'_>) -> std::result::Result<T, osis_store::Error>) -> Result<T> {
        self.lock().write_in(memory, |t, _| Ok(f(t)?))
    }

    /// `with_read` in either part (`memory`).
    pub(crate) fn with_read_in<T>(&self, memory: bool, f: impl FnOnce(&mut Transaction<'_>) -> std::result::Result<T, osis_store::Error>) -> Result<T> {
        self.lock().read_in(memory, |t, _| Ok(f(t)?))
    }

    // Holdings and caps

    /// Tests: the sync IDs this node syncs, whole (`set_holdings` of what differs).
    pub fn set_sync_set(&mut self, set: &SyncSet) -> Result<()> {
        let moved: Vec<(SyncId, Option<Held>)> = {
            let g = self.lock();
            g.holdings.keys().chain(set.ids.keys()).filter(|s| g.holdings.get(s) != set.ids.get(s)).map(|s| (*s, set.ids.get(s).cloned())).collect()
        };
        self.set_holdings(&moved)
    }

    /// The sync IDs this node syncs (spec/sync-set.md §3: the sync set, and each sync ID that
    /// left it while it waits to stop; `leave` writes them): those whose entry moved, each with its
    /// entry now (`None`: no longer synced), of which thing, read or kept unread. A sync ID moving
    /// between read and kept unread is counted again in the unread total (spec/sync-ids.md §5
    /// Caps); only the sync IDs whose entry moved stamp. One raised (`raised`) is
    /// fetched anew (spec/sync-judgement.md §6 Read and unread move), marked durably (`N/`) until
    /// streams moved every source's place of S back to the start (`reset_anew`), so a restart
    /// between still fetches it (`anew_feed`).
    pub fn set_holdings(&mut self, moved: &[(SyncId, Option<Held>)]) -> Result<()> {
        let mut g = self.lock();
        let unread = |h: Option<&Held>| h.is_some_and(|(_, h)| *h == Holding::Unread);
        let anew: Vec<SyncId> = moved.iter().filter(|(s, now)| raised(g.holdings.get(s), now.as_ref()) && !g.unheld.contains(s)).map(|(s, _)| *s).collect();
        if !anew.is_empty() {
            // a dropped copy's mark stands as it is: it is fetched anew once judged (`set_unheld`)
            g.write(|t, _| {
                for s in &anew {
                    t.put_local(&rows::anew_key(s), rows::ANEW_RAISED, Shred::No)?;
                }
                Ok(())
            })?;
        }
        let mut recount = Vec::new();
        for (s, now) in moved {
            let was = g.holdings.get(s).cloned();
            if was == *now {
                continue;
            }
            if unread(was.as_ref()) != unread(now.as_ref()) {
                recount.push((*s, unread(now.as_ref())));
            }
            g.mem.syncs.wrote_added(s, true, true);
            // raised: what it refused kept unread (a stamp under no key of its head then), or
            // was not shown held for keys (all but role entries), its sources show no more, so S
            // is pulled anew (`anew_feed`)
            if raised(was.as_ref(), now.as_ref()) {
                g.mem.anew.wrote_added(s, true, true);
            }
            match now {
                Some(h) => g.holdings.insert(*s, h.clone()),
                None => g.holdings.remove(s),
            };
        }
        if !recount.is_empty() {
            g.mem.stamps.wrote(&UNREAD_FIXED, true);
        }
        if let Some(total) = g.total
            && !recount.is_empty()
        {
            let counted = g.read(|t, _| {
                let mut n = total;
                for (s, now) in &recount {
                    n.add(&entries::usage(t, s)?, *now);
                }
                Ok(n)
            });
            g.total = counted.ok();
        }
        Ok(())
    }

    /// The node's `caps^.0` (`Engine::caps`).
    pub fn set_caps(&mut self, caps: &Caps) {
        let mut g = self.lock();
        g.policy = Policy::from_caps(caps);
        g.caps = caps.clone();
        g.mem.stamps.wrote(&CAPS, true);
    }

    /// How this node syncs S (stamped read).
    pub fn holding(&self, s: &SyncId) -> Option<Holding> {
        self.lock().holding(s)
    }

    /// S's entry in the sync IDs this node syncs: its things and how it is held (stamped read).
    pub fn synced(&self, s: &SyncId) -> Option<Held> {
        let g = self.lock();
        g.mem.syncs.read(s);
        g.holdings.get(s).cloned()
    }

    /// The sync IDs this node syncs, whole (a stamped read of all of them).
    pub fn syncs(&self) -> BTreeMap<SyncId, Held> {
        let g = self.lock();
        g.mem.syncs.read_all();
        g.holdings.clone()
    }

    /// A cursor over the sync IDs whose entry moves from now on (`set_holdings`).
    pub fn syncs_feed(&self) -> osis_base::memo::Feed<SyncId> {
        self.lock().mem.syncs.feed()
    }

    // Reads

    pub fn entry(&self, s: &SyncId, b: &BlobId) -> Result<Option<Entry>> {
        Ok(self.lock().find(s, b)?.map(|(_, r)| entries::to_entry(*b, &r)))
    }

    /// Whether held entry `b` of S carries a stamp that verifies under one of `keys`, in either
    /// domain: the one door for checking a held entry's stamp. The verdict kept where it entered
    /// (`rows::Vouch`) answers when it is one of these checks'; else the stamp is checked, and
    /// nothing is kept (a read writes nothing, so moves no reader).
    pub fn stamp_under(&self, s: &SyncId, b: &BlobId, keys: &[osis_crypto::VerifyingKey]) -> Result<bool> {
        let Some((_, row)) = self.lock().find(s, b)? else { return Ok(false) };
        let Some(stamp) = row.stamp else { return Ok(false) };
        Ok(keys.iter().any(|k| rows::kept_answers(k, s, b, &row.wrap, &stamp, row.vouch)) || keys.iter().any(|k| rows::check_stamp(k, s, b, &row.wrap, &stamp, None).is_some()))
    }

    /// Every entry of S, durable then ephemeral (stamped reads: memo-safe). O(entries of S).
    pub fn entries(&self, s: &SyncId) -> Result<Vec<Entry>> {
        let parts = self.lock().each(|t, _| {
            let mut out = Vec::new();
            for (k, v) in t.scan_local(&[rows::ENTRY, &s.0].concat(), b"", usize::MAX)? {
                let (_, b) = rows::tail_ids(&k)?;
                out.push(entries::to_entry(b, &EntryRow::decode(&v)?));
            }
            Ok(out)
        })?;
        Ok(parts.concat())
    }

    /// The deposited (unstamped) entries of S, durable then ephemeral (stamped reads). O(S's
    /// deposits), which its deposit budget and the peer budgets bound.
    pub fn deposits(&self, s: &SyncId) -> Result<Vec<Entry>> {
        Ok(self.all_of(&[rows::DEPOSITED, &s.0].concat())?.into_iter().map(|(_, e)| e).collect())
    }

    /// Every deposited entry held, with its sync ID (a start's listing). O(deposits held).
    pub fn all_deposits(&self) -> Result<Vec<(SyncId, Entry)>> {
        self.all_of(rows::DEPOSITED)
    }

    /// The entries an index under `prefix` (keys `prefix s b`) lists, durable then ephemeral.
    fn all_of(&self, prefix: &[u8]) -> Result<Vec<(SyncId, Entry)>> {
        let parts = self.lock().each(|t, _| {
            let mut out = Vec::new();
            for (k, _) in t.scan_local(prefix, b"", usize::MAX)? {
                let (s, b) = rows::tail_ids(&k)?;
                if let Some(r) = entries::get(t, &s, &b)? {
                    out.push((s, entries::to_entry(b, &r)));
                }
            }
            Ok(out)
        })?;
        Ok(parts.concat())
    }

    /// The length of blob `b`'s bytes held, if any (sizing deposits, spec/sync-inbox.md §4).
    pub fn blob_len(&self, b: &BlobId) -> Result<Option<u64>> {
        let [d, m] = self.lock().each(|t, _| Ok(t.blob_len(b)?))?;
        Ok(d.or(m))
    }

    /// A reader's cursor over the entries added, removed (reading absent) or whose wrap, stamp
    /// or deposited flag changed from now on (`(S, blob)`, in order).
    pub fn entry_feed(&self) -> osis_base::memo::Feed<(SyncId, BlobId)> {
        self.lock().mem.fed.feed()
    }

    /// A cursor over the blobs no entry names any more, from now on (an entry removed, expired or
    /// shredded; one named again since comes too: the reader checks `named`).
    pub fn unnamed_feed(&self) -> osis_base::memo::Feed<BlobId> {
        self.lock().mem.unnamed.feed()
    }

    /// The blobs an entry or tombstone of S names and no entry or tombstone of another sync ID
    /// does (durable or in memory): what S's shred takes from this node whole (`Engine::shredding`).
    pub fn alone_under(&self, s: &SyncId) -> Result<Vec<BlobId>> {
        let mut g = self.lock();
        let [of_d, of_m] = g.each(|t, _| {
            let mut of_s = BTreeSet::new();
            for p in [rows::ENTRY, rows::TOMB] {
                for (k, _) in t.scan_local(&[p, &s.0[..]].concat(), b"", usize::MAX)? {
                    of_s.insert(rows::tail_ids(&k)?.1);
                }
            }
            Ok(of_s)
        })?;
        let of_s: BTreeSet<BlobId> = of_d.union(&of_m).copied().collect();
        let [d, m] = g.each(|t, _| {
            let mut alone = BTreeSet::new();
            for b in &of_s {
                if entries::naming(t, b)?.iter().chain(&entries::tombed(t, b)?).all(|x| x == s) {
                    alone.insert(*b);
                }
            }
            Ok(alone)
        })?;
        Ok(d.intersection(&m).copied().collect())
    }

    /// Whether an entry under any sync ID names blob `b` (durable or in memory).
    pub fn named(&self, b: &BlobId) -> Result<bool> {
        Ok(!self.naming(b)?.is_empty())
    }

    /// The sync IDs whose entries name blob `b` (durable or in memory).
    pub fn naming(&self, b: &BlobId) -> Result<Vec<SyncId>> {
        let mut out = self.lock().each(|t, _| entries::naming(t, b))?.concat();
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// The sync IDs holding a durable tombstone of blob `b` (each within `TOMBSTONE_LIFETIME`:
    /// the sweep lifts it then).
    pub fn tombstoned_under(&self, b: &BlobId) -> Result<Vec<SyncId>> {
        self.lock().read(|t, _| entries::tombed(t, b))
    }

    /// A cursor over the sync IDs shredded from now on (`shred`).
    pub fn shred_feed(&self) -> osis_base::memo::Feed<SyncId> {
        self.lock().mem.shreds.feed()
    }

    /// A cursor over the sync IDs to fetch anew: those raised to read or owed a pull from the
    /// start at some sources (a head move, a room mark owed) whose pull anew is still owed (`N/`
    /// `ANEW_RAISED`, `ANEW_SOME`, a restart's or a module restart's before it included), then
    /// each one owed from now on (`set_unheld`, `set_holdings`, `take_register`, `room_grew`,
    /// `refused_may_be_gone`), with whether the marks were
    /// read (a failure: the caller fails its step). O(the marks) to make.
    pub fn anew_feed(&self) -> (osis_base::memo::Feed<SyncId>, Result<()>) {
        let mut g = self.lock();
        let feed = g.mem.anew.feed();
        let owed = g.read(|t, _| anew_marks(t, true)).map(|owed| {
            for s in &owed {
                g.mem.anew.wrote_added(s, true, true);
            }
        });
        (feed, owed)
    }

    /// Blob `b`'s bytes, whoever holds them.
    pub fn bytes(&self, b: &BlobId) -> Result<Option<Vec<u8>>> {
        let [d, m] = self.lock().each(|t, _| Ok(t.get_blob(b)?))?;
        Ok(d.or(m))
    }

    pub fn tombstone(&self, s: &SyncId, b: &BlobId) -> Result<Option<Tombstone>> {
        let [d, m] = self.lock().each(|t, _| entries::tombstone(t, s, b))?;
        Ok(d.or(m))
    }

    /// What S uses: durable and in memory.
    pub fn usage(&self, s: &SyncId) -> Result<(Usage, Usage)> {
        let [d, m] = self.lock().each(|t, _| entries::usage(t, s))?;
        Ok((d, m))
    }

    /// Bytes the memory part holds: its store's rows and blobs and the memory log, at an estimate
    /// of their cost held (`osis_store::Store::memory_held`, `Memory::held`). O(rows); tests
    /// check the caps' charges against it.
    #[doc(hidden)]
    pub fn memory_held(&self) -> u64 {
        let g = self.lock();
        g.ram.memory_held() + g.mem.held()
    }

    /// What entry `b` of S counts toward its part's caps (`entries::count`): none for a role
    /// entry or none held.
    pub(crate) fn counted(&self, s: &SyncId, b: &BlobId) -> Result<u64> {
        let mut g = self.lock();
        let Some((memory, r)) = g.find(s, b)? else { return Ok(0) };
        let add = g.read_in(memory, |_, env| Ok(entries::count(memory, env, b, &r, true)))?;
        let mut u = Usage::default();
        add(&mut u);
        Ok(u.bytes)
    }

    /// What holding one more ephemeral commit under read S may cost now (spec/sync-compaction.md
    /// §2 Caps, at a node for what it reads): S's memory cap less what S's ephemeral entries
    /// count, each at least its bytes and an entry of a commit from another node at what it
    /// costs held (`set_memory_charge`). Own entries count their bytes too (local policy).
    pub fn memory_room(&self, s: &SyncId) -> Result<u64> {
        let mut g = self.lock();
        let used = g.read_in(true, |t, _| entries::usage(t, s))?.bytes;
        Ok(g.policy.memory_bytes.saturating_sub(used))
    }

    /// Blob `b`, named by ephemeral entries, is of a held commit from another node costing `n`
    /// held here (`Engine::memory_charge`): the memory usage of every sync ID an entry of it is
    /// under counts it at that, or at its bytes if more (spec/sync-compaction.md §2 Caps: each
    /// body counts at what it takes held, under each sync ID).
    pub fn set_memory_charge(&self, b: &BlobId, n: u64) -> Result<()> {
        self.lock().write_in(true, |t, env| entries::set_estimate(t, env, b, n))
    }

    /// Whether entry `e`'s stamp verifies under S's head write key (a relay-only entry at a
    /// node keeping S unread, spec/sync-ids.md §6 Relay-only).
    pub fn stamp_vouches(&self, s: &SyncId, e: &Entry) -> Result<bool> {
        let Some(stamp) = e.stamp else { return Ok(false) };
        self.lock().read(|t, _| Ok(head_vouch(t, s, &e.blob, &e.wrap, &stamp, None)?.is_some()))
    }

    /// The head S's path ends at.
    pub fn head(&self, s: &SyncId) -> Result<Option<Step>> {
        self.lock().read(|t, _| Ok(path::head(t, s)?.map(|(_, st)| st)))
    }

    /// The head's ID (`head`'s `Step::id`, without parsing it).
    pub fn head_id(&self, s: &SyncId) -> Result<Option<StepId>> {
        self.lock().read(|t, _| path::head_id(t, s))
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
        self.log_checked(s, e, bytes, from, None)
    }

    /// A peer's stamp `stamp` for held entry `b` of S under the same wrap, applied in stream
    /// order (spec/sync-streams.md §4 Applying): logged on an entry held unstamped, judged as any
    /// peer's stamp (charged to `from` unless it vouches); one under `head` (the write key of the
    /// head S's `sync.0` records, which the served path may not follow yet) replaces a held one
    /// that is not (stamped in place on a head move), vouched by that head. A held stamp's kept
    /// verdict answers for it, and the new one is checked once.
    pub fn take_stamp(&mut self, s: &SyncId, b: &BlobId, wrap: &crate::types::Wrap, stamp: &osis_crypto::Signature, head: Option<osis_crypto::VerifyingKey>, from: Source) -> Result<()> {
        let Some(e) = self.entry(s, b)? else { return Ok(()) };
        if e.stamp == Some(*stamp) || e.wrap != *wrap || self.bytes(b)?.is_none() {
            return Ok(());
        }
        let at_head = match head {
            Some(k) if e.stamp.is_some() && self.stamp_under(s, b, &[k])? => return Ok(()),
            Some(k) => rows::check_stamp(&k, s, b, wrap, stamp, None),
            None => None,
        };
        let e = Entry { stamp: Some(*stamp), deposited: false, ..e };
        match at_head {
            Some(v) => self.log_checked(s, e, None, None, Some(Some(v))).map(drop),
            // a held stamp stays (`log`: one that does not vouch replaces none)
            None => {
                // checked under the served head as any peer's stamp: once, where that is `head`
                let served = self.lock().read(|t, _| path::head(t, s))?.map(|(_, st)| st.keys.write);
                let checked = (head.is_some() && served == head).then_some(None);
                self.log_checked(s, e, None, Some(from), checked).map(drop)
            }
        }
    }

    /// `log`, with the verdict on `e`'s stamp under S's head already checked (`checked`), else
    /// checked here for a peer's stamp.
    fn log_checked(&mut self, s: &SyncId, e: Entry, bytes: Option<Vec<u8>>, from: Option<Source>, checked: Option<Option<Vouch>>) -> Result<Code> {
        let mut g = self.lock();
        let b = e.blob;
        let found = match &bytes {
            Some(v) => check_blob(v, &b),
            None => Ok((e.class, e.expires)),
        };
        let (class, expires) = match found.and_then(|x| kept(x, g.now)) {
            Ok(x) => x,
            Err(c) => return Ok(c),
        };
        // a peer's stamp vouches only under S's head write key (spec/sync-ids.md §5 Peer budget):
        // one that does not verify there is charged as unstamped, and replaces no stamp held
        // checked once where it enters, its verdict kept with the entry: one kept with a held copy
        // of exactly these bytes answers (`Vouch`)
        let vouch = match (&e.stamp, from, checked) {
            (_, _, Some(v)) => v,
            (Some(stamp), _, None) => {
                let kept = g.find(s, &b)?.and_then(|(_, r)| r.vouch);
                g.read(|t, _| head_vouch(t, s, &b, &e.wrap, stamp, kept))?
            }
            _ => None,
        };
        let vouched = match (&e.stamp, from) {
            (None, _) => false,
            (Some(_), None) => true,
            (Some(_), Some(_)) => vouch.is_some(),
        };
        let charged = if vouched { None } else { from };
        let row = EntryRow { wrap: e.wrap, stamp: e.stamp, deposited: e.deposited, own: e.own, role: e.role, class, expires, size: 0, charged, brought: if vouched { from } else { None }, vouch };
        // a vouched copy of a held one: off any charge, its bringer kept for when it stops vouching
        let brought = |old: &EntryRow| if vouched { from.or(old.charged).or(old.brought) } else { old.brought };
        let stamp = |old: &EntryRow| if vouched || old.stamp.is_none() { e.stamp } else { old.stamp };
        // a held one keeps its size and gains what this copy brings
        let merged = |old: &EntryRow| EntryRow { size: old.size, stamp: stamp(old), charged: if vouched { None } else { old.charged }, brought: brought(old), own: old.own || e.own, role: old.role || e.role, vouch: row.vouch.or(old.vouch), ..row.clone() };
        let memory = class == Class::Ephemeral;
        let durable = match charged {
            Some(src) => g.read(|t, _| source_charge(t, src))?,
            None => 0,
        };
        g.write_in(memory, |t, env| {
            if entries::tombstone(t, s, &b)?.is_some() {
                return Ok(Code::TOMBSTONED);
            }
            let Some(old) = entries::get(t, s, &b)? else {
                let size = match &bytes {
                    Some(v) => Some(v.len() as u64),
                    None => t.blob_len(&b)?,
                };
                // an ephemeral entry is held with its bytes alone (it has no time to wait for them)
                if memory && size.is_none() {
                    return Ok(Code::MALFORMED);
                }
                if let Some(src) = charged
                    && over_peer_budget(env, src, size.unwrap_or(0), durable)
                {
                    return Ok(Code::DEPOSIT_BUDGET_FULL);
                }
                entries::insert(t, env, s, &b, row.clone(), bytes)?;
                return Ok(Code::OK);
            };
            if let Some(v) = bytes
                && t.blob_len(&b)?.is_none()
            {
                t.put_blob(&b, v)?;
                entries::bytes_arrived(t, env, &b)?;
            }
            let old = entries::get(t, s, &b)?.unwrap_or(old);
            entries::change(t, env, s, &b, &old, merged(&old))?;
            Ok(Code::OK)
        })
    }

    /// Drops entry `b` of S by this node's own judgement (spec/sync-judgement.md §3 Own store),
    /// leaving a tombstone with `note` (what the entry was). Whether it was held.
    pub fn drop_entry(&mut self, s: &SyncId, b: &BlobId, note: Vec<u8>) -> Result<bool> {
        let mut g = self.lock();
        let tomb = Tombstone { at: g.now, deleted: false, note };
        let memory = g.find(s, b)?.is_some_and(|(m, _)| m);
        g.write_in(memory, |t, env| entries::remove(t, env, s, b, Removal::Tomb(tomb)))
    }

    /// Drops entry `b` of S, judged outside S's required set here, with no tombstone: judged so
    /// wrongly, it is logged or pulled again once required. Whether it was held.
    pub fn unlog_entry(&mut self, s: &SyncId, b: &BlobId) -> Result<bool> {
        let mut g = self.lock();
        let Some((memory, _)) = g.find(s, b)? else { return Ok(false) };
        g.write_in(memory, |t, env| entries::remove(t, env, s, b, Removal::Untombed))
    }

    /// Ends S's tombstone of `b` (spec/sync-judgement.md §4: a part counting missing again lifts
    /// this node's own tombstones). Whether there was one.
    pub fn lift_tombstone(&mut self, s: &SyncId, b: &BlobId) -> Result<bool> {
        let mut g = self.lock();
        Ok(g.write_in(true, |t, env| entries::lift(t, env, s, b))? | g.write(|t, env| entries::lift(t, env, s, b))?)
    }

    /// Entry `b` of S, a peer's kept uncharged, whose stamp no longer vouches (it does not verify
    /// under S's head write key, spec/sync-ids.md §5 Peer budget): charged to the peer that
    /// brought it, as an unstamped one. Past that peer's budget, or with its peer gone, it is not
    /// kept (no tombstone: fetched again where present). Whether it was kept.
    pub fn charge_unvouched(&mut self, s: &SyncId, b: &BlobId) -> Result<bool> {
        let mut g = self.lock();
        let Some((memory, old)) = g.find(s, b)? else { return Ok(false) };
        let next = g.read(|t, env| unvouched(t, env, s, b, &old))?;
        g.write_in(memory, |t, env| match &next {
            Some(Some(new)) => entries::change(t, env, s, b, &old, new.clone()),
            Some(None) => Ok(()),
            None => entries::remove(t, env, s, b, Removal::Untombed).map(drop),
        })?;
        Ok(next.is_some())
    }

    /// Entry `b` of S gives this node something held: its charge to the peer that brought it ends.
    pub fn uncharge(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let mut g = self.lock();
        let Some((memory, old)) = g.find(s, b)? else { return Ok(()) };
        if old.charged.is_none() {
            return Ok(());
        }
        g.write_in(memory, |t, env| entries::change(t, env, s, b, &old, EntryRow { charged: None, brought: old.charged, ..old.clone() }))
    }

    /// Whether a source was recorded holding entry `b` of S (`set_elsewhere`).
    pub fn elsewhere(&self, s: &SyncId, b: &BlobId) -> Result<bool> {
        let [d, m] = self.lock().each(|t, _| Ok(t.get_local(&rows::elsewhere_key(s, b))?.is_some()))?;
        Ok(d || m)
    }

    /// Records that a source holds entry `b` of S (spec/sync-status.md §2: kept while the entry
    /// is), in a row of its own: no reader of the entry moves. Nothing for an entry not held.
    pub fn set_elsewhere(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let mut g = self.lock();
        let Some((memory, _)) = g.find(s, b)? else { return Ok(()) };
        g.write_in(memory, |t, _| Ok(t.put_local(&rows::elsewhere_key(s, b), &[], Shred::No)?))
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
    /// (9); past S's caps (12) unless a role entry: S full, a room mark at each of `from` (the
    /// sources whose place passes the entry once it settles, `wait_room`). A deposited entry of its blob ID takes the
    /// stamp; a stamped one changes nothing, and one held with this wrap and stamp is taken (0) unjudged:
    /// shown again (a pull from the start), it is no refusal under a head that moved since.
    pub fn take_stamped(&mut self, s: &SyncId, e: &Entry, bytes: Vec<u8>, from: &[Source]) -> Result<Code> {
        let mut g = self.lock();
        if g.holding(s) != Some(Holding::Unread) {
            return Ok(Code::DECLINED);
        }
        let b = e.blob;
        let (class, expires) = match check_blob(&bytes, &b).and_then(|x| kept(x, g.now)) {
            Ok(x) => x,
            Err(c) => return Ok(c),
        };
        let size = bytes.len() as u64;
        let unheld = g.unheld.contains(s);
        let held = g.find(s, &b)?.map(|(_, r)| (r.wrap, r.stamp));
        // held as it comes (blob, wrap and stamp): judged when it was taken
        if e.stamp.is_some() && held == Some((e.wrap, e.stamp)) {
            return Ok(Code::OK);
        }
        let verdict = g.read(|t, _| {
            if entries::tombstone(t, s, &b)?.is_some() {
                return Ok(Err(Code::TOMBSTONED));
            }
            let Some(stamp) = e.stamp else { return Ok(Err(Code::REFUSED)) };
            let Some((_, head)) = path::head(t, s)?.filter(|_| !unheld) else { return Ok(Err(Code::REFUSED)) };
            match rows::verify_stamp(&head.keys.write, s, &b, &e.wrap, &stamp) {
                Some((signed, vouch)) => Ok(Ok((signed == osis_blob::Signed::RoleEntry, vouch))),
                None if path::earlier(t, s, |st| osis_blob::verify_stamp(&st.keys.write, s, &b, &e.wrap, &stamp).is_ok())? => Ok(Err(Code::NOT_HEAD_KEY)),
                None => Ok(Err(Code::REFUSED)),
            }
        })?;
        let (role, vouch) = match verdict {
            Ok(r) => r,
            Err(c) => return Ok(c),
        };
        let row = EntryRow { wrap: e.wrap, stamp: e.stamp, deposited: false, own: false, role, class, expires, size: 0, charged: None, brought: None, vouch: Some(vouch) };
        let short = g.write_in(class == Class::Ephemeral, |t, env| {
            if entries::tombstone(t, s, &b)?.is_some() {
                return Ok(Ok(Code::TOMBSTONED));
            }
            if let Some(old) = entries::get(t, s, &b)? {
                if old.stamp.is_none() {
                    entries::change(t, env, s, &b, &old.clone(), EntryRow { size: old.size, own: old.own, ..row })?;
                }
                return Ok(Ok(Code::OK));
            }
            let need = size + entries::overhead(t.is_memory(), &row);
            if !role && let Some(cap) = make_room(t, env, s, need)? {
                return Ok(Err((cap, need)));
            }
            entries::insert(t, env, s, &b, row, Some(bytes))?;
            Ok(Ok(Code::OK))
        })?;
        match short {
            Ok(code) => Ok(code),
            Err((cap, need)) => {
                g.wait_room(s, cap, need, expires, from)?;
                Ok(Code::STORAGE_CAP)
            }
        }
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
        let b = osis_blob::blob_id(&d.blob);
        let Ok((class, expires)) = check_blob(&d.blob, &b).and_then(|x| kept(x, g.now)) else { return Ok(Code::DECLINED) };
        let size = d.blob.len() as u64;
        let policy = g.policy.clone();
        let memory = class == Class::Ephemeral;
        let held = g.read_in(memory, |t, _| Ok(entries::get(t, &s, &b)?.is_some() || entries::tombstone(t, &s, &b)?.is_some()))?;
        let mem_usage = g.read_in(true, |t, _| entries::usage(t, &s))?;
        let unheld = g.unheld.contains(&s);
        let checked = g.read(|t, env| {
            let Some((hi, head)) = path::head(t, &s)?.filter(|_| !unheld) else { return Ok(Err(Code::RATE_LIMITED)) };
            if held {
                return Ok(Err(Code::OK));
            }
            let Ok(signed) = osis_blob::verify_deposit(&head.keys.deposit, &s, &b, &d.wrap, &d.sig) else { return Ok(Err(Code::DECLINED)) };
            let role = signed == osis_blob::Signed::RoleEntry;
            let claims = path::claims(t, &s, hi)?.map_or(0, |c| c.claims.len());
            let (be, bb) = deposit_budget(&policy, claims);
            let u = entries::usage(t, &s)?;
            if u.deposits + mem_usage.deposits + 1 > be || u.deposit_bytes + mem_usage.deposit_bytes + size > bb {
                return Ok(Err(Code::DEPOSIT_BUDGET_FULL));
            }
            if let Some(src) = from
                && over_peer_budget(env, src, size, source_charge(t, src)?)
            {
                return Ok(Err(Code::DEPOSIT_BUDGET_FULL));
            }
            Ok(Ok(role))
        })?;
        let role = match checked {
            Ok(r) => r,
            Err(c) => return Ok(c),
        };
        let row = EntryRow { wrap: d.wrap, stamp: None, deposited: true, own: false, role, class, expires, size: 0, charged: from, brought: None, vouch: None };
        let caps = holding == Holding::Unread && !role;
        g.write_in(memory, |t, env| {
            if caps && make_room(t, env, &s, size + entries::overhead(t.is_memory(), &row))?.is_some() {
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
            Some(Holding::Read | Holding::Keys) => return all(Code::DECLINED),
            Some(Holding::Unread) => {}
        }
        if !by_store_credential {
            return all(Code::NOT_OPEN);
        }
        let now = g.now;
        let unheld = g.unheld.contains(s);
        // what the memory part holds of each blob: entry, tombstone, prefix
        let in_mem = g.read_in(true, |t, _| {
            let mut m = BTreeMap::new();
            for d in items {
                m.insert(d.blob, (entries::get(t, s, &d.blob)?.is_some(), entries::tombstone(t, s, &d.blob)?.is_some(), read_prefix(t, &d.blob)?));
            }
            Ok(m)
        })?;
        // a verified Delete of an ephemeral entry removes it in the memory part, after
        let mut ephemeral = Vec::new();
        let tomb = || Removal::Tomb(Tombstone { at: now, deleted: true, note: Vec::new() });
        let out = g.write(|t, env| {
            let Some((_, head)) = path::head(t, s)?.filter(|_| !unheld) else { return Ok(vec![Code::UNKNOWN_SYNC_ID; items.len()]) };
            let mut out = Vec::with_capacity(items.len());
            for d in items {
                let b = d.blob;
                let (mem_held, mem_tomb, mem_prefix) = in_mem.get(&b).cloned().unwrap_or_default();
                let prefix = match mem_prefix {
                    Some(p) => Some(p),
                    None => read_prefix(t, &b)?,
                };
                let code = if d.verify(&head, prefix.as_ref()).is_ok() {
                    if mem_held {
                        ephemeral.push(b);
                        Code::OK
                    } else if entries::get(t, s, &b)?.is_some() {
                        entries::remove(t, env, s, &b, tomb())?;
                        Code::OK
                    } else if d.by.is_empty() && (mem_tomb || entries::tombstone(t, s, &b)?.is_some()) {
                        Code::OK
                    } else {
                        Code::REFUSED
                    }
                } else if path::earlier(t, s, |st| d.verify(st, prefix.as_ref()).is_ok())? {
                    Code::NOT_HEAD_KEY
                } else {
                    Code::REFUSED
                };
                out.push(code);
            }
            Ok(out)
        })?;
        g.write_in(true, |t, env| {
            for b in &ephemeral {
                entries::remove(t, env, s, b, tomb())?;
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// A Register of `steps`, each with its claim set when carried (spec/sync-ids.md §6 Register,
    /// spec/wire.md §11.2; `path::register`). 14: S not kept unread here (a reader's path comes
    /// from `sync.0` alone); 2: a step of another sync ID or a claim set not hashing to its
    /// step's; into an empty path 1 for a genesis that does not verify, 13 for a list from a child;
    /// 0 for a list ending at the head; 9: not a deeper branch off a step bearing the head's delete
    /// key nor ending at a step `endorsement` endorses under it; 12: past the caps (into an empty path; else past them even without the claim sets,
    /// more than once per interval, on the monotonic clock: `mono` is its reading now).
    pub fn take_register(&mut self, s: &SyncId, steps: &[(&Step, Option<&ClaimSet>)], endorsement: Option<&osis_crypto::Signature>, mono: Mono) -> Result<Code> {
        let mut g = self.lock();
        let last = g.past_cap.get(s).copied();
        let policy = g.policy.clone();
        let due = last.is_none_or(|at| mono >= at.after(policy.register_every_ms));
        let (code, past, moved) = g.write(|t, env| path::register(t, env, s, steps, endorsement, due))?;
        // refusals told under the old head are shown again (`anew_feed`), a record's marked durably
        // (`path::register`)
        if moved {
            g.mem.anew.wrote_added(s, true, true);
        }
        if past {
            g.past_cap.insert(*s, mono);
        }
        Ok(code)
    }

    /// A Behind item's answer (spec/sync-ids.md §6 Behind), its open signature by `cred`
    /// verified by the caller; at most `max_steps` steps.
    pub fn behind(&self, s: &SyncId, named: Option<&StepId>, cred: &Cred, max_steps: usize) -> Result<Behind> {
        self.lock().read(|t, env| path::behind(t, env, s, named, cred, max_steps))
    }

    /// The code a Behind of S carrying nothing is answered with (one whose open signature did
    /// not verify): 13 where this node does not keep S, else 14.
    pub fn behind_refusal(&self, s: &SyncId) -> Result<Code> {
        self.lock().read(|t, env| path::behind_refusal(t, env, s))
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

    /// The memory log's events after counter `after` (`memory_mark`), each with its sync ID.
    pub fn memory_since(&self, after: u64) -> Vec<(u64, SyncId)> {
        self.lock().mem.since(after)
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

    /// The position of S's head event in the log (none: no head logged).
    pub fn head_at(&self, s: &SyncId) -> Result<Option<Position>> {
        self.lock().read(|t, _| Ok(t.log_head_at(s)?))
    }

    /// The log's last position and its deletion horizon (spec/sync-streams.md §3).
    pub fn log_bounds(&self) -> Result<(Position, Position)> {
        self.lock().read(|t, _| Ok((t.log_end()?, t.log_horizon()?)))
    }

    // Leaving

    /// The sync IDs with a usage or a path here (`U/`, `H/`): every one whose store holds
    /// something. O(those); read at a start (spec/sync-set.md §3: what left while the node was
    /// down still holds its rows).
    pub fn held_ids(&self) -> Result<BTreeSet<SyncId>> {
        self.lock().read(|t, _| {
            let mut out = BTreeSet::new();
            for p in [rows::USAGE, rows::HEAD] {
                for (k, _) in t.scan_local(p, b"", usize::MAX)? {
                    out.insert(rows::tail_sync(&k)?);
                }
            }
            Ok(out)
        })
    }

    /// Leaving S (spec/sync-set.md §3): every row of S goes, wraps and keys shredded, with S's
    /// log events, its usage, and S in every peer record (the one transaction that stops it).
    pub fn shred(&mut self, s: &SyncId) -> Result<()> {
        let mut g = self.lock();
        let empty = |t: &mut Transaction<'_>, env: &mut Env<'_>| -> Result<()> {
            drop_entries(t, env, s)?;
            for (k, _) in t.scan_local(&[rows::TOMB, &s.0].concat(), b"", usize::MAX)? {
                let (_, b) = rows::tail_ids(&k)?;
                entries::lift(t, env, s, &b)?;
            }
            let u = entries::usage(t, s)?;
            entries::put_usage(t, env, s, u, Usage::default())
        };
        g.write_in(true, |t, env| {
            empty(t, env)?;
            // every source's memory rows of S
            Ok(source::forget_sync(t, s)?)
        })?;
        g.write(|t, env| {
            path::erase(t, env, s)?;
            empty(t, env)?;
            t.log_forget(*s)?;
            // S's rows in every record go with its `changed_at` (spec/sync-opens.md §3)
            t.changed_forget(s)?;
            t.remove_local(&rows::anew_key(s), Shred::No)?;
            t.remove_local(&rows::first_key(s), Shred::No)?;
            remove_room_rows(t, s)
        })?;
        g.forget_room(s);
        g.room_gone.remove(s);
        g.room_conn.remove(s);
        g.mem.forget(s);
        g.mem.shreds.wrote_added(s, true, true);
        g.past_cap.remove(s);
        g.unheld.remove(s);
        Ok(())
    }

    /// Whether S's first sync here ended (spec/sync-streams.md §5): a source's stream of S stood
    /// at the end of a listing from the start since S was last shredded here. Stamped (row `F/`).
    pub fn first_synced(&self, s: &SyncId) -> Result<bool> {
        self.lock().read(|t, _| Ok(t.get_local(&rows::first_key(s))?.is_some()))
    }

    /// S's first sync here ended: kept until S is shredded (`first_synced`).
    pub fn set_first_synced(&mut self, s: &SyncId) -> Result<()> {
        let k = rows::first_key(s);
        let mut g = self.lock();
        if g.read(|t, _| Ok(t.get_local(&k)?.is_some()))? {
            return Ok(());
        }
        g.write(|t, _| {
            t.put_local(&k, &[], Shred::No)?;
            Ok(())
        })
    }

    /// Streams moved the places of S at `srcs` back to the start (`f`, its writes): in one
    /// transaction the `N/` mark goes and so do those sources' room marks (`unmark`: S full with
    /// none left is full no longer).
    pub(crate) fn reset_anew(&mut self, s: &SyncId, srcs: &[Source], f: impl FnOnce(&mut Transaction<'_>) -> std::result::Result<(), osis_store::Error>) -> Result<()> {
        self.lock().unmark(s, srcs, |t| {
            f(t)?;
            t.remove_local(&rows::anew_key(s), Shred::No).map(drop)
        })
    }

    /// In `t`: whether S's pull anew is owed at every source (a dropped copy, a raise to read)
    /// rather than only at those whose rows say so (`ANEW_SOME`, or no mark).
    pub(crate) fn anew_everywhere(t: &mut Transaction<'_>, s: &SyncId) -> std::result::Result<bool, osis_store::Error> {
        Ok(t.get_local(&rows::anew_key(s))?.is_some_and(|v| v != rows::ANEW_SOME))
    }

    /// The room marks of S (spec/sync-streams.md §4 Full): each source whose place passed an
    /// entry of S refused for room, and whether S is owed a pull from the start there. O(S's
    /// marks).
    pub fn room_marks(&self, s: &SyncId) -> Result<Vec<(Source, bool)>> {
        let mut g = self.lock();
        let mut out: Vec<(Source, bool)> = g.room_conn.get(s).into_iter().flatten().map(|(c, o)| (Source::Conn(*c), *o)).collect();
        g.read(|t, _| {
            for rec in t.records_with_row(s, ROOM_AT, b"", usize::MAX)? {
                let v = t.record_get_row(&rec, ROOM_AT, s, b"")?;
                out.push((Source::Record(rec), v.as_deref() == Some(&[rows::ROOM_OWED][..])));
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Whether S is full: kept unread, it refused an entry for room that has not grown since,
    /// and some source's room mark of S stands (spec/sync-streams.md §4 Full).
    pub fn waits_room(&self, s: &SyncId) -> bool {
        self.lock().full(s)
    }

    /// Whether S takes nothing until judged again: its copy dropped past its keys (`set_unheld`).
    pub fn unheld(&self, s: &SyncId) -> bool {
        self.lock().unheld.contains(s)
    }

    /// Each full S that a refusing cap has room for again (`room_fits`: the least entry it
    /// refused fits), or whose refused entries all expired, is full no longer and is fetched
    /// anew at every source with a room mark of S (`end_full`). S no longer kept unread is full
    /// no longer. O(the full keys whose reads moved since the last call: S's usage, the totals a
    /// cap counts, the caps, S's holding, the clock past a latest expiry). The sync IDs full no
    /// longer, those whose last room mark went since the last call (`unmark`) included, each not
    /// full again since.
    pub fn room_grew(&mut self) -> Result<Vec<SyncId>> {
        let mut g = self.lock();
        let mut fx = std::mem::replace(&mut g.room_fx, Effects::new(ROOM_JUDGED));
        let judged = judge_rooms(&mut g, &mut fx);
        g.room_fx = fx;
        let ended = judged?;
        end_full(&mut g, &ended)?;
        let mut out = std::mem::take(&mut g.room_gone);
        out.extend(ended);
        Ok(out.into_iter().filter(|s| !g.full(s)).collect())
    }

    /// What S refused for room may be gone at `src` (spec/sync-streams.md §4 Full: its stream
    /// showed the deletion of an entry neither held nor tombstoned here outside a listing from
    /// the start): its standing room mark of S becomes owed, and S is marked to be pulled from
    /// the start there (`N/` `ANEW_SOME` over none, the `anew` feed), in one transaction before
    /// that source's place passes what showed it. Nothing where `src` holds no standing mark of
    /// S: a source whose place passed nothing refused shows nothing of it.
    pub fn refused_may_be_gone(&mut self, s: &SyncId, src: Source) -> Result<()> {
        let mut g = self.lock();
        let mark = match src {
            Source::Conn(c) => g.room_conn.get(s).and_then(|m| m.get(&c)).copied(),
            Source::Record(rec) => g.read(|t, _| Ok(t.record_get_row(&rec, ROOM_AT, s, b"")?.map(|v| v == [rows::ROOM_OWED])))?,
        };
        if mark != Some(false) {
            return Ok(());
        }
        let feed = g.write(|t, env| {
            if let Source::Record(rec) = src {
                t.record_put_row(&rec, ROOM_AT, s, b"", vec![rows::ROOM_OWED])?;
            }
            mark_some(t, env, s)
        })?;
        if let Source::Conn(c) = src
            && let Some(o) = g.room_conn.get_mut(s).and_then(|m| m.get_mut(&c))
        {
            *o = true;
        }
        if feed {
            g.mem.anew.wrote_added(s, true, true);
        }
        Ok(())
    }

    /// `src` lists S from the start (spec/sync-streams.md §4 Full): what it shows of S is shown
    /// again, so its room mark of S goes (`unmark`), before any of the listing is judged; what it
    /// refuses again marks it again.
    pub fn listed_from_start(&mut self, s: &SyncId, src: Source) -> Result<()> {
        let mut g = self.lock();
        let marked = match src {
            Source::Conn(c) => g.room_conn.get(s).is_some_and(|m| m.contains_key(&c)),
            Source::Record(rec) => g.read(|t, _| Ok(t.record_get_row(&rec, ROOM_AT, s, b"")?.is_some()))?,
        };
        if !marked {
            return Ok(());
        }
        g.unmark(s, &[src], |_| Ok(()))
    }

    /// S kept unread moved to (`true`) or off (`false`) a head whose sync key this node holds no
    /// box for (spec/sync-judgement.md §6): moving there drops its copy of S (every entry, with
    /// no deletion event: it was no delete; its path and tombstones stay), and while there it
    /// takes no entry, deposit or Delete, as with no head. Moving off it (or read), S is fetched
    /// anew (`anew_feed`): its sources' positions passed the entries dropped. The drop is marked
    /// durably (`N/`) until streams moved every source's place of S back to the start
    /// (`reset_anew`), so a restart between finds S unheld, to be judged again.
    pub fn set_unheld(&mut self, s: &SyncId, unheld: bool) -> Result<()> {
        let mut g = self.lock();
        if !unheld {
            if g.unheld.remove(s) {
                g.mem.anew.wrote_added(s, true, true);
            }
            return Ok(());
        }
        if !g.unheld.insert(*s) {
            return Ok(());
        }
        g.write(|t, env| {
            drop_entries(t, env, s)?;
            t.put_local(&rows::anew_key(s), &[], Shred::No)?;
            Ok(())
        })?;
        g.write_in(true, |t, env| drop_entries(t, env, s))
    }

    /// A source went: a connection closed, or a peer's record was dropped (spec/sync-ids.md §5
    /// Peer budget: a lost record is a first contact). Each entry charged to it that still gives
    /// nothing held moves to a record whose stream showed it present (`heir`), else goes (fetched
    /// again where present), and what was kept for a connection alone goes. One transaction.
    pub fn gone(&mut self, src: Source) -> Result<()> {
        let mut g = self.lock();
        Self::gone_memory(&mut g, src)?;
        g.write(|t, env| Self::gone_from(t, env, src))?;
        // a connection's room marks go with it
        if let Source::Conn(c) = src {
            let marked: Vec<SyncId> = g.room_conn.iter().filter(|(_, m)| m.contains_key(&c)).map(|(s, _)| *s).collect();
            for s in marked {
                g.unmark(&s, &[src], |_| Ok(()))?;
            }
        }
        Ok(())
    }

    /// Writes `f` (opens' rows of the records in use), then drops the records `dropped` (others
    /// of a pair, spec/sync-opens.md §3 One record per pair) and those past `budget` that are not
    /// `in_use` (`osis_store::Transaction::records_evict`), each passing what was charged to it
    /// on or dropping it (as `gone`), all in one transaction: a record never goes leaving its
    /// peer's entries charged to nobody. The records that went.
    pub fn write_records(&mut self, budget: u64, in_use: &BTreeSet<RecordId>, dropped: &BTreeSet<RecordId>, f: impl FnOnce(&mut Transaction<'_>) -> std::result::Result<(), osis_store::Error>) -> Result<Vec<RecordId>> {
        let mut g = self.lock();
        let evicted = g.write(|t, env| {
            f(t)?;
            let mut evicted = Vec::new();
            for id in dropped {
                if t.record_remove(id)? {
                    evicted.push(*id);
                }
            }
            evicted.extend(t.records_evict(budget, in_use)?);
            for id in &evicted {
                Self::gone_from(t, env, Source::Record(*id))?;
            }
            Ok(evicted)
        })?;
        for id in &evicted {
            Self::gone_memory(&mut g, Source::Record(*id))?;
        }
        // a record's room marks went with it: each full S is judged again (rare: brute force)
        if !evicted.is_empty() {
            let full: BTreeSet<SyncId> = g.room.keys().map(|(s, _)| *s).collect();
            for s in full {
                g.unmark(&s, &[], |_| Ok(()))?;
            }
        }
        Ok(evicted)
    }

    /// `gone_from` in the memory part, and the source's memory rows go.
    fn gone_memory(g: &mut Inner, src: Source) -> Result<()> {
        g.write_in(true, |t, env| {
            Self::gone_from(t, env, src)?;
            Ok(source::forget_source(t, src)?)
        })
    }

    /// `src` went, in `t`'s part: each entry charged to it passes to its `heir`, else goes; each
    /// it brought uncharged names its heir as bringer, or none. An ephemeral entry has no heir:
    /// a peer's record keeps no presence of it, and it is relisted at the next join, living at
    /// most its drift window.
    fn gone_from(t: &mut Transaction<'_>, env: &mut Env<'_>, src: Source) -> Result<()> {
        let heir = |t: &mut Transaction<'_>, env: &Env<'_>, s: &SyncId, b: &BlobId, size: Option<u64>| if t.is_memory() { Ok(None) } else { heir(t, env, src, s, b, size) };
        for (k, _) in t.scan_local(&[rows::CHARGED, &rows::source_bytes(src)].concat(), b"", usize::MAX)? {
            let (s, b) = rows::tail_ids(&k)?;
            let Some(old) = entries::get(t, &s, &b)? else { continue };
            match heir(t, env, &s, &b, Some(old.size))? {
                Some(to) => entries::change(t, env, &s, &b, &old.clone(), EntryRow { charged: Some(to), ..old })?,
                None => drop(entries::remove(t, env, &s, &b, Removal::Untombed)?),
            }
        }
        // what it brought uncharged names another bringer that showed it, or none
        for (k, _) in t.scan_local(&[rows::BROUGHT, &rows::source_bytes(src)].concat(), b"", usize::MAX)? {
            let (s, b) = rows::tail_ids(&k)?;
            if let Some(old) = entries::get(t, &s, &b)? {
                let brought = heir(t, env, &s, &b, None)?;
                entries::change(t, env, &s, &b, &old.clone(), EntryRow { brought, ..old })?;
            }
        }
        Ok(())
    }

    // What a source's record keeps for `read` (spec/sync-judgement.md §4)

    /// Writes (or with `None` removes) the row `src` keeps of S in its own part, written at `at`:
    /// it ages out after `TOMBSTONE_LIFETIME` (`settle_at`).
    fn source_put(&mut self, src: Source, s: &SyncId, tag: u8, key: &[u8], val: Option<(WallMs, Vec<u8>)>) -> Result<()> {
        self.lock().write_in(source::home(src), |t, _| {
            match val {
                Some((at, v)) => source::put_aging(t, src, tag, s, key, at, v)?,
                None => source::drop_row(t, src, tag, s, key)?,
            }
            Ok(())
        })
    }

    fn source_get(&self, src: Source, s: &SyncId, tag: u8, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.lock().read_in(source::home(src), |t, _| Ok(source::get(t, src, tag, s, key)?))
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
        self.source_put(src, s, SEEN, &b.0, Some((now, now.0.to_be_bytes().to_vec())))?;
        Ok(())
    }

    /// Every delete this node saw at a source within `TOMBSTONE_LIFETIME`, of every source: a
    /// start judges what each showed deleted as what each shows present. O(rows).
    pub fn deletes_seen_all(&self) -> Result<Vec<(Source, SyncId, BlobId)>> {
        let rows = self.lock().each(|t, _| Ok(source::tag_rows(t, SEEN)?))?;
        Ok(rows.into_iter().flatten().filter_map(|(src, s, k)| Some((src, s, BlobId(k.try_into().ok()?)))).collect())
    }

    /// Whether this node saw entry `b` of S deleted at `src` within `TOMBSTONE_LIFETIME`.
    pub fn seen_deleted(&self, src: Source, s: &SyncId, b: &BlobId) -> Result<bool> {
        Ok(self.source_get(src, s, SEEN, &b.0)?.is_some())
    }

    // Time

    /// Time is `now`: entries past their expiry go (no tombstone, no event), tombstones and the
    /// rows of deletes seen and stands end after `TOMBSTONE_LIFETIME`, claim sets after
    /// `ROLE_KEEP` superseded, deletion events leave the log, and the caps give way if the total
    /// is past them. At most `PAGE` of each a call; whether anything acted.
    pub fn settle_at(&mut self, now: WallMs) -> Result<bool> {
        let mut g = self.lock();
        g.now = WallMs(g.now.0.max(now.0));
        let at = g.now.0;
        g.clock.set(at);
        let now = g.now;
        let mut acted = g.mem.sweep(now);
        // in either part: expiries, tombstone ends, a source's aged rows
        let entry_sweep = |t: &mut Transaction<'_>, env: &mut Env<'_>| -> Result<bool> {
            let mut acted = false;
            for (k, _) in due(t, rows::EXPIRY, Some(now.0))? {
                let (s, b) = rows::tail_ids(&k)?;
                t.remove_local(&k, Shred::No)?;
                entries::remove(t, env, &s, &b, Removal::Expired)?;
                acted = true;
            }
            for (k, _) in due(t, rows::TOMB_AT, Some(now.0))? {
                let (s, b) = rows::tail_ids(&k)?;
                t.remove_local(&k, Shred::No)?;
                entries::lift(t, env, &s, &b)?;
                acted = true;
            }
            for (k, _) in due(t, rows::AGING, now.0.checked_sub(TOMBSTONE_LIFETIME_MS))? {
                let at = time_of(&k)?;
                let mut r = R::new(k.get(rows::AGING.len() + 8..).unwrap_or_default());
                let (s, tag, key) = (SyncId(r.array()?), r.u8()?, r.bytes()?.to_vec());
                let src = r.source()?.ok_or(crate::types::Error::Store(osis_store::Error::Corrupt("sync store aging row")))?;
                t.remove_local(&k, Shred::No)?;
                // a row written again since ages from its new time
                if source::get(t, src, tag, &s, &key)?.is_some_and(|v| v.get(..8) == Some(&at.to_be_bytes()[..])) {
                    source::drop_row(t, src, tag, &s, &key)?;
                }
                acted = true;
            }
            Ok(acted)
        };
        acted |= g.write_in(true, entry_sweep)?;
        acted |= g.write(|t, env| {
            let mut acted = entry_sweep(t, env)?;
            for (k, _) in due(t, rows::CLAIMS_DUE, Some(now.0))? {
                let mut r = R::new(k.get(rows::CLAIMS_DUE.len() + 8..).unwrap_or_default());
                let (s, i) = (SyncId(r.array()?), r.u32()?);
                t.remove_local(&k, Shred::No)?;
                path::drop_claims(t, env, &s, i)?;
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
            .each(|t, _| {
                let first = |t: &mut Transaction<'_>, p: &[u8], add: u64| -> Result<Option<u64>> { Ok(t.scan_local(p, b"", 1)?.first().map(|(k, _)| time_of(k)).transpose()?.map(|x| x.saturating_add(add))) };
                let all = [first(t, rows::EXPIRY, 0)?, first(t, rows::TOMB_AT, 0)?, first(t, rows::CLAIMS_DUE, 0)?, first(t, rows::AGING, TOMBSTONE_LIFETIME_MS)?, if t.is_memory() { None } else { t.log_next_due()? }];
                Ok(all.into_iter().flatten().min().map(WallMs))
            })
            .ok()
            .into_iter()
            .flatten()
            .flatten();
        m.into_iter().chain(d).chain(g.clock.next().map(WallMs)).min()
    }

    /// Tests only: this store's copy inside a world copy (`osis_base::copying`), the one the
    /// engine's copy holds.
    #[doc(hidden)]
    pub fn test_copy(&self, clock: Arc<dyn osis_base::Clock>) -> Result<Store> {
        Ok(Store(osis_store::test_copy_shared(&self.0, clock)?))
    }
}

/// A page of the rows of time-ordered index `prefix` (keys `prefix || time || ...`) whose time
/// is at most `through` (none: nothing is due): only those are read.
fn due(t: &mut Transaction<'_>, prefix: &[u8], through: Option<u64>) -> Result<Vec<osis_store::KeyValue>> {
    let Some(end) = through.and_then(|x| x.checked_add(1)) else { return Ok(Vec::new()) };
    Ok(t.scan_local_before(prefix, &end.to_be_bytes(), PAGE)?)
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
        NodeEvent::Added(s, b) | NodeEvent::Deleted { sync_id: s, blob: b, .. } => t.log_entry_first(&s, &b)?.is_some_and(|f| f <= until),
        NodeEvent::Head(_) => false,
    })
}

/// The verdict on `stamp` of entry `b` of S under `wrap` by S's head write key, in either domain
/// (`kept` answering when it is this check's, `rows::check_stamp`): none when it does not verify.
fn head_vouch(t: &mut Transaction<'_>, s: &SyncId, b: &BlobId, wrap: &[u8], stamp: &osis_crypto::Signature, kept: Option<Vouch>) -> Result<Option<Vouch>> {
    let Some((_, head)) = path::head(t, s)? else { return Ok(None) };
    Ok(rows::check_stamp(&head.keys.write, s, b, wrap, stamp, kept))
}

/// Removes every entry of S in `t`'s part, as expired (no event). O(S's entries).
fn drop_entries(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId) -> Result<()> {
    for (k, _) in t.scan_local(&[rows::ENTRY, &s.0].concat(), b"", usize::MAX)? {
        entries::remove(t, env, s, &rows::tail_ids(&k)?.1, Removal::Expired)?;
    }
    Ok(())
}

/// Where entry `b` of S that `src` brought goes when `src` does (spec/sync-ids.md §5 Peer budget):
/// a peer's record, not `src`, whose stream showed it present, with room for its `size` when it
/// is charged. Else nobody: the entry goes, and a stream that passed it would not bring it
/// again. O(records that showed it).
fn heir(t: &mut Transaction<'_>, env: &Env<'_>, src: Source, s: &SyncId, b: &BlobId, size: Option<u64>) -> Result<Option<Source>> {
    for rec in t.records_with_row(s, rows::tag::PRESENT, &b.0, usize::MAX)? {
        let to = Source::Record(rec);
        if to == src {
            continue;
        }
        if let Some(n) = size
            && over_peer_budget(env, to, n, source_charge(t, to)?)
        {
            continue;
        }
        return Ok(Some(to));
    }
    Ok(None)
}

/// Whether `size` more bytes charged to `src` pass its peer budget (spec/sync-ids.md §5 Peer
/// budget): what its durable and ephemeral entries giving nothing held are charged so far.
/// What `Store::charge_unvouched` makes of entry row `old`: kept as it is (`Some(None)`: its own,
/// charged, unstamped or still vouching), kept charged to the peer that brought it
/// (`Some(Some(row))`), or not kept (`None`).
fn unvouched(t: &mut Transaction<'_>, env: &Env<'_>, s: &SyncId, b: &BlobId, old: &EntryRow) -> Result<Option<Option<EntryRow>>> {
    let Some(stamp) = old.stamp.filter(|_| !old.own && old.charged.is_none()) else { return Ok(Some(None)) };
    if head_vouch(t, s, b, &old.wrap, &stamp, old.vouch)?.is_some() {
        return Ok(Some(None));
    }
    Ok(match old.brought {
        Some(src) if !over_peer_budget(env, src, old.size, source_charge(t, src)?) => Some(Some(EntryRow { charged: Some(src), brought: None, ..old.clone() })),
        _ => None,
    })
}

/// `durable`: what it is charged durably (`source_charge`, read in the durable store).
fn over_peer_budget(env: &Env<'_>, src: Source, size: u64, durable: u64) -> bool {
    let mem = env.mem.charges.get(&src).copied().unwrap_or(0);
    durable.saturating_add(mem).saturating_add(size) > env.policy.peer_bytes
}

/// Bytes charged to a source by durable entries.
fn source_charge(t: &mut Transaction<'_>, src: Source) -> Result<u64> {
    match src {
        Source::Record(rec) => entries::record_charge(t, &rec),
        Source::Conn(c) => entries::conn_charge(t, c),
    }
}

/// Room for `add` bytes of a new entry of S kept unread in `t`'s part (spec/sync-ids.md §6 Caps):
/// within S's own caps, else none; past the total, the sync ID using most gives way (its oldest
/// entries, no tombstone) until it fits. A sync ID read takes nothing from the room. The caps
/// differ by part: S's entries and bytes (per thing) and the total of bytes durably, S's bytes and
/// the memory total in memory.
fn make_room(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, add: u64) -> Result<Option<Cap>> {
    if env.holding(s) != Some(Holding::Unread) {
        return Ok(None);
    }
    let ((ce, cb), total_cap, (own, all)) = match t.is_memory() {
        false => (env.caps_of(s), env.policy.total_bytes, (Cap::Own, Cap::Total)),
        true => ((u64::MAX, env.policy.memory_bytes), env.policy.memory_total, (Cap::Memory, Cap::MemoryTotal)),
    };
    let u = entries::usage(t, s)?;
    if u.entries.saturating_add(1) > ce || u.bytes.saturating_add(add) > cb {
        return Ok(Some(own));
    }
    let total = part_total(t, env)?.saturating_add(add);
    if total > total_cap {
        give_way(t, env, total - total_cap)?;
        if part_total(t, env)?.saturating_add(add) > total_cap {
            return Ok(Some(all));
        }
    }
    Ok(None)
}

/// The bytes every sync ID kept unread uses in `t`'s part (`Env::total` durably, kept counted).
fn part_total(t: &mut Transaction<'_>, env: &mut Env<'_>) -> Result<u64> {
    if !t.is_memory() {
        return env.total(t);
    }
    let mut n = 0u64;
    for (k, v) in t.scan_local(rows::USAGE, b"", usize::MAX)? {
        if env.holding(&rows::tail_sync(&k)?) == Some(Holding::Unread) {
            n = n.saturating_add(Usage::decode(&v)?.bytes);
        }
    }
    Ok(n)
}

/// The sync IDs kept unread using most in `t`'s part give way, oldest entries first (by the node
/// log, or the memory log), until `need` bytes are freed or nothing gives. Whether anything went.
fn give_way(t: &mut Transaction<'_>, env: &mut Env<'_>, need: u64) -> Result<bool> {
    let goal = part_total(t, env)?.saturating_sub(need);
    let mut acted = false;
    let mut from: Vec<u8> = Vec::new();
    'sync_ids: while part_total(t, env)? > goal {
        let Some((k, _)) = t.scan_local(rows::BY_USE, &from, PAGE)?.into_iter().find(|(k, _)| rows::tail_sync(k).is_ok_and(|s| env.holding(&s) == Some(Holding::Unread))) else {
            break;
        };
        let s = rows::tail_sync(&k)?;
        from = [k.get(rows::BY_USE.len()..).unwrap_or_default(), &[0]].concat();
        let mut cursor: Option<Vec<u8>> = None;
        loop {
            let (page, more) = match t.is_memory() {
                true => (env.mem.present(&s).collect(), false),
                false => {
                    let r = t.log_read_sync(&s, cursor.as_deref(), PAGE)?;
                    cursor = r.cursor;
                    (r.events.iter().filter_map(|e| if let NodeEvent::Added(_, b) = e.event { Some(b) } else { None }).collect::<Vec<_>>(), r.more)
                }
            };
            for b in page {
                if entries::get(t, &s, &b)?.is_some_and(|row| !row.role) {
                    entries::remove(t, env, &s, &b, Removal::Untombed)?;
                    acted = true;
                    if part_total(t, env)? <= goal {
                        break 'sync_ids;
                    }
                }
            }
            if !more {
                break;
            }
        }
    }
    Ok(acted)
}

/// A cap that refused an entry of a sync ID kept unread for room (spec/sync-streams.md §4 Full):
/// S's own (entries and bytes), the store's durable total, S's memory part, the memory total.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Cap {
    Own = 0,
    Total = 1,
    Memory = 2,
    MemoryTotal = 3,
}

impl Cap {
    fn of(b: u8) -> Option<Cap> {
        [Cap::Own, Cap::Total, Cap::Memory, Cap::MemoryTotal].into_iter().find(|c| *c as u8 == b)
    }
}

/// The full keys judged (`Effects` name, `costs`).
const ROOM_JUDGED: &str = "store: room judged";
/// The stamp key of the caps and policy (`set_caps`).
const CAPS: &str = "caps";
/// The stamp key of the bytes no give-way frees of every sync ID kept unread
/// (`entries::put_usage`, `set_holdings`): what the durable total's room reads.
pub(crate) const UNREAD_FIXED: &str = "unread fixed";

/// The stamp key of a full key's least need (`Inner::wait_room`).
#[derive(Hash)]
struct RoomNeed<'a>(&'a SyncId, Cap);

/// Each of `ended` full no longer (spec/sync-streams.md §4 Full): its `R/` rows go in one
/// transaction with each room mark of it becoming owed and a `N/` mark (`ANEW_SOME`, over none:
/// another pulls from every source) while kept unread, so it is pulled from the start at each
/// source whose place passed what it refused (`anew_feed`); S no longer kept unread loses its
/// marks (a raise pulls it from every source). On a failure nothing changes and each key is
/// judged again.
fn end_full(g: &mut Inner, ended: &BTreeSet<SyncId>) -> Result<()> {
    if ended.is_empty() {
        return Ok(());
    }
    let keys: Vec<(SyncId, Cap)> = ended.iter().flat_map(|s| g.room.range((*s, Cap::Own)..=(*s, Cap::MemoryTotal)).map(|(k, _)| *k).collect::<Vec<_>>()).collect();
    let wrote = g.write(|t, env| {
        let mut anew = Vec::new();
        for k in &keys {
            t.remove_local(&room_key(&k.0, k.1), Shred::No)?;
        }
        for s in ended {
            let unread = env.holding(s) == Some(Holding::Unread);
            for rec in t.records_with_row(s, ROOM_AT, b"", usize::MAX)? {
                match unread {
                    true => t.record_put_row(&rec, ROOM_AT, s, b"", vec![rows::ROOM_OWED])?,
                    false => drop(t.record_remove_row(&rec, ROOM_AT, s, b"")?),
                }
            }
            if mark_some(t, env, s)? {
                anew.push(*s);
            }
        }
        Ok(anew)
    });
    let anew = match wrote {
        Ok(a) => a,
        Err(e) => {
            for k in &keys {
                g.room_fx.unwant(k);
                g.room_fx.want(*k);
            }
            return Err(e);
        }
    };
    for k in &keys {
        g.room.remove(k);
        g.room_fx.unwant(k);
    }
    for s in ended {
        if !anew.contains(s) {
            g.room_conn.remove(s);
        }
        for o in g.room_conn.get_mut(s).into_iter().flat_map(|m| m.values_mut()) {
            *o = true;
        }
    }
    for s in &anew {
        g.mem.anew.wrote_added(s, true, true);
    }
    Ok(())
}

/// In `t`: S kept unread is owed a pull from the start at the sources whose rows say so (`N/`
/// `ANEW_SOME`, written over no mark: another covers it). Whether S is kept unread (it is pulled
/// anew then, by this mark or the one standing).
fn mark_some(t: &mut Transaction<'_>, env: &Env<'_>, s: &SyncId) -> Result<bool> {
    if env.holding(s) != Some(Holding::Unread) {
        return Ok(false);
    }
    let mark = rows::anew_key(s);
    if t.get_local(&mark)?.is_none() {
        t.put_local(&mark, rows::ANEW_SOME, Shred::No)?;
    }
    Ok(true)
}

/// Settles each due full key (`room_fits`); the sync IDs one of whose keys fits now.
fn judge_rooms(g: &mut Inner, fx: &mut Effects<(SyncId, Cap), bool>) -> Result<BTreeSet<SyncId>> {
    let mut ended = BTreeSet::new();
    for k in fx.due() {
        let Some(r) = g.room.get(&k).copied() else {
            fx.unwant(&k);
            continue;
        };
        let fits = || {
            // every entry it refused expired: none of them is left anywhere to take
            if r.expires != u64::MAX && g.clock.until(Some(r.expires)) >= r.expires {
                return Ok(true);
            }
            g.read_in(matches!(k.1, Cap::Memory | Cap::MemoryTotal), |t, env| room_fits(t, env, &k.0, k.1, r.need))
        };
        if let Some((_, true)) = fx.try_settle(&k, fits)? {
            ended.insert(k.0);
        }
    }
    Ok(ended)
}

/// Whether S is full by `cap` no longer (spec/sync-streams.md §4 Full): no longer kept unread, or
/// the cap has room for one more entry of `need` bytes, the least it refused. Stamped reads only:
/// S's holding, the need, the caps and what the cap counts.
fn room_fits(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, cap: Cap, need: u64) -> Result<bool> {
    env.mem.syncs.read(s);
    env.mem.stamps.read(&RoomNeed(s, cap));
    env.mem.stamps.read(&CAPS);
    if env.holding(s) != Some(Holding::Unread) {
        return Ok(true);
    }
    let (entries, bytes) = room_now(t, env, s, cap)?;
    Ok(entries >= 1 && bytes >= need)
}

/// The room `cap` has for S now, as the take judges it (`make_room`, `room_fits`): entries and
/// bytes left under it (`u64::MAX` entries for a cap of bytes alone). A total's room counts what
/// give-way frees: the durable total less the bytes no give-way frees (read by its stamp, the
/// count kept, not read by key); the memory total whole (every byte in memory gives way).
fn room_now(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, cap: Cap) -> Result<(u64, u64)> {
    Ok(match cap {
        // `t` is the part the cap counts
        Cap::Own => {
            let u = entries::usage(t, s)?;
            let (ce, cb) = env.caps_of(s);
            (ce.saturating_sub(u.entries), cb.saturating_sub(u.bytes))
        }
        Cap::Total => {
            env.mem.stamps.read(&UNREAD_FIXED);
            (u64::MAX, env.policy.total_bytes.saturating_sub(env.totals(t)?.fixed))
        }
        Cap::Memory => (u64::MAX, env.policy.memory_bytes.saturating_sub(entries::usage(t, s)?.bytes)),
        Cap::MemoryTotal => (u64::MAX, env.policy.memory_total),
    })
}

fn room_key(s: &SyncId, cap: Cap) -> Vec<u8> {
    [rows::ROOM, &s.0, &[cap as u8]].concat()
}

/// S's `R/` rows go.
fn remove_room_rows(t: &mut Transaction<'_>, s: &SyncId) -> Result<()> {
    for (k, _) in t.scan_local(&[rows::ROOM, &s.0].concat(), b"", usize::MAX)? {
        t.remove_local(&k, Shred::No)?;
    }
    Ok(())
}

/// The full sync IDs' least needs (`R/`).
fn room_rows(t: &mut Transaction<'_>) -> Result<BTreeMap<(SyncId, Cap), Refused>> {
    let bad = || crate::types::Error::Store(osis_store::Error::Corrupt("sync store room mark"));
    let mut out = BTreeMap::new();
    for (k, v) in t.scan_local(rows::ROOM, b"", usize::MAX)? {
        let k = k.get(rows::ROOM.len()..).ok_or_else(bad)?;
        let (id, cap) = k.split_first_chunk::<16>().ok_or_else(bad)?;
        let cap = cap.first().and_then(|c| Cap::of(*c)).ok_or_else(bad)?;
        let mut r = R::new(&v);
        let (need, expires) = (r.u64()?, r.u64()?);
        r.end()?;
        out.insert((SyncId(*id), cap), Refused { need, expires });
    }
    Ok(out)
}

/// The sync IDs whose `N/` mark is a raise to read or a head move (`raised`), or a dropped copy
/// (`!raised`).
fn anew_marks(t: &mut Transaction<'_>, raised: bool) -> Result<BTreeSet<SyncId>> {
    let mut out = BTreeSet::new();
    for (k, v) in t.scan_local(rows::ANEW, b"", usize::MAX)? {
        if v.is_empty() != raised {
            out.insert(rows::tail_sync(&k)?);
        }
    }
    Ok(out)
}

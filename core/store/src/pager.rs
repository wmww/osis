//! Encrypted units on a key tree (notes/local-store.md, Key tree; layout in its Implementation
//! section).
//!
//! A unit is a byte string addressed by a slot number. Each version of a unit is a backend row
//! `u slot ver` encrypted under its own random key. Unit keys sit in the leaves of a fixed-depth
//! `arity`-ary tree; a tree node lists its present children as `(index, key, ver)` and is a row
//! `n level index ver` encrypted under its own key, held by its parent; the top node also holds
//! the store's meta and is encrypted under the root key from `RootStorage`.
//!
//! A transaction writes new row versions (`ver` = its number), so the committed tree stays
//! readable until the commit point. Without erasure the commit point is one backend batch that
//! writes the new top node and the pointer row `r` and deletes the superseded rows. With erasure
//! (a shredded write or delete) every touched node on a shredded path, the top included, gets a
//! fresh key: batch A writes the new rows, a journal and the pending pointer `p`; the new root
//! record is stored (the commit point, and the moment the old keys become unrecoverable); batch B
//! moves `r`, deletes old rows and the journal. Open finishes or rolls back from the journal.
//! Large transactions spill unit rows early under journal rows; their keys stay in memory.

use crate::backend::{Backend, WriteBatch};
use crate::codec::{R, W};
use crate::root::{RootRecord, RootStorage};
use crate::Error;
use osis_base::BlobId;
use osis_crypto::aead::{self, NONCE_LEN};
use osis_crypto::{CryptoRngCore, Secret32, Zeroizing, padme};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Shape and budgets. `arity`, `depth` and `page_max` are fixed when the store is created
/// (stored in the meta); the rest are per open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreConfig {
    /// Children per key tree node (256: a full node is about 11 KB).
    pub arity: u32,
    /// Key tree levels; capacity is `arity^depth` unit slots, never reused.
    pub depth: u32,
    /// Target maximum encoded size of a table page (B-tree node).
    pub page_max: usize,
    /// Unspilled bytes a transaction holds in memory before writing rows early.
    pub spill_bytes: usize,
    /// Decrypted tree nodes kept in memory before the cache is emptied.
    pub node_cache: usize,
    /// Decrypted unit bytes kept in memory before the cache is emptied.
    pub unit_cache_bytes: usize,
}

impl Default for StoreConfig {
    fn default() -> StoreConfig {
        StoreConfig { arity: 256, depth: 5, page_max: 8 * 1024, spill_bytes: 16 << 20, node_cache: 4096, unit_cache_bytes: 16 << 20 }
    }
}

impl StoreConfig {
    /// Slots available, or an error for a shape outside 2..=65536 children, 1..=8 levels.
    fn capacity(&self) -> Result<u64, Error> {
        if !(2..=65536).contains(&self.arity) || !(1..=8).contains(&self.depth) || self.page_max < 64 {
            return Err(Error::Misuse("config"));
        }
        u64::from(self.arity).checked_pow(self.depth).ok_or(Error::Misuse("config"))
    }
}

const ROW_R: &[u8] = b"r";
const ROW_P: &[u8] = b"p";
const JOURNAL: u8 = b'j';
/// Journal index of a rotation's final record (spill records count up from 0).
const FINAL: u32 = u32::MAX;

fn unit_row(slot: u64, ver: u64) -> Vec<u8> {
    W::new().u8(b'u').u64(slot).u64(ver).take()
}
fn node_row(level: u32, idx: u64, ver: u64) -> Vec<u8> {
    W::new().u8(b'n').u8(level as u8).u64(idx).u64(ver).take()
}
fn top_row(ver: u64) -> Vec<u8> {
    W::new().u8(b't').u64(ver).take()
}
fn journal_row(ver: u64, k: u32) -> Vec<u8> {
    W::new().u8(JOURNAL).u64(ver).u32(k).take()
}

#[derive(Clone)]
struct Entry {
    key: Secret32,
    ver: u64,
}

#[derive(Clone, Default)]
struct Node {
    entries: BTreeMap<u32, Entry>,
}

impl Node {
    fn encode(&self, w: &mut W) {
        w.u32(self.entries.len() as u32);
        for (i, e) in &self.entries {
            w.u32(*i).raw(e.key.expose()).u64(e.ver);
        }
    }
    fn decode(r: &mut R, arity: u32) -> Result<Node, Error> {
        let n = r.u32()?;
        let mut entries = BTreeMap::new();
        for _ in 0..n {
            let i = r.u32()?;
            let key = Secret32::from_bytes(r.array()?);
            let ver = r.u64()?;
            if i >= arity || entries.insert(i, Entry { key, ver }).is_some() {
                return Err(Error::Corrupt("tree node"));
            }
        }
        Ok(Node { entries })
    }
}

/// Store-wide state kept in the top node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Meta {
    pub arity: u32,
    pub depth: u32,
    pub page_max: u32,
    pub next_slot: u64,
    pub next_ver: u64,
    /// Slot of the catalog table's root page (`u64::MAX` before the store layer sets it).
    pub catalog: u64,
}

impl Meta {
    fn encode(&self, w: &mut W) {
        w.u32(self.arity).u32(self.depth).u32(self.page_max).u64(self.next_slot).u64(self.next_ver).u64(self.catalog);
    }
    fn decode(r: &mut R) -> Result<Meta, Error> {
        Ok(Meta { arity: r.u32()?, depth: r.u32()?, page_max: r.u32()?, next_slot: r.u64()?, next_ver: r.u64()?, catalog: r.u64()? })
    }
}

/// Least padded plaintext of a unit row (class M): units below it all show this one length, so
/// a small page's version lengths say nothing; Padmé's class width reaches 32 bytes here. 0:
/// small units leak their length to within Padmé's few bytes; infinity: every unit this big.
const UNIT_MIN: usize = 512;

/// Padded plaintext length of a row: Padmé of `len + 1` (spec/wire.md §5), units at least
/// `UNIT_MIN`. Tree, top and journal rows hold keys and row names only: their lengths count
/// entries, which the row names show anyway.
fn padded_len(row: &[u8], len: usize) -> usize {
    let p = padme(len.saturating_add(1));
    if row.first() == Some(&b'u') { p.max(UNIT_MIN) } else { p }
}

/// `nonce || AEAD(key, AD row, plaintext || 0x80 || zeros)` up to `padded_len`.
fn seal(key: &Secret32, row: &[u8], plaintext: &[u8], rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let mut padded = Zeroizing::new(Vec::with_capacity(padded_len(row, plaintext.len())));
    padded.extend_from_slice(plaintext);
    padded.push(0x80);
    padded.resize(padded_len(row, plaintext.len()), 0);
    let ct = aead::seal(key.expose(), &nonce, row, &padded).map_err(|_| Error::Misuse("unit too large"))?;
    Ok([&nonce[..], &ct].concat())
}

/// Opens and unpads a row; the padded length must be `padded_len`'s.
fn open(key: &Secret32, row: &[u8], value: &[u8]) -> Result<Vec<u8>, Error> {
    let (nonce, ct) = value.split_at_checked(NONCE_LEN).ok_or(Error::Corrupt("row"))?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Corrupt("row"))?;
    let mut plain = aead::open(key.expose(), &nonce, row, ct).map_err(|_| Error::Corrupt("row decryption"))?;
    let end = plain.iter().rposition(|&b| b != 0).ok_or(Error::Corrupt("row padding"))?;
    if plain.get(end) != Some(&0x80) || padded_len(row, end) != plain.len() {
        return Err(Error::Corrupt("row padding"));
    }
    plain.truncate(end);
    Ok(plain)
}

/// A journal record: rows and blobs a transaction wrote (deleted on rollback) and, for the
/// final record, rows and blobs to delete once committed.
#[derive(Default)]
struct Journal {
    new_rows: Vec<Vec<u8>>,
    new_blobs: Vec<BlobId>,
    old_rows: Vec<Vec<u8>>,
    old_blobs: Vec<BlobId>,
}

impl Journal {
    fn encode(&self) -> Vec<u8> {
        let mut w = W::new();
        for list in [&self.new_rows, &self.old_rows] {
            w.u32(list.len() as u32);
            for r in list {
                w.bytes(r);
            }
        }
        for list in [&self.new_blobs, &self.old_blobs] {
            w.u32(list.len() as u32);
            for b in list {
                w.raw(&b.0);
            }
        }
        w.0
    }
    fn decode(b: &[u8]) -> Result<Journal, Error> {
        let mut r = R::new(b);
        let rows = |r: &mut R| -> Result<Vec<Vec<u8>>, Error> { (0..r.u32()?).map(|_| r.bytes().map(<[u8]>::to_vec)).collect() };
        let new_rows = rows(&mut r)?;
        let old_rows = rows(&mut r)?;
        let blobs = |r: &mut R| -> Result<Vec<BlobId>, Error> { (0..r.u32()?).map(|_| r.array().map(BlobId)).collect() };
        let new_blobs = blobs(&mut r)?;
        let old_blobs = blobs(&mut r)?;
        r.end()?;
        Ok(Journal { new_rows, new_blobs, old_rows, old_blobs })
    }
}

/// Deletes what the journal records under `prefix` say was written, and the records.
fn rollback(backend: &mut dyn Backend, prefix: &[u8]) -> Result<(), Error> {
    loop {
        let journals = backend.scan_prefix(prefix, 256)?;
        if journals.is_empty() {
            return Ok(());
        }
        let mut batch = WriteBatch::new();
        for (k, v) in journals {
            let j = Journal::decode(&v)?;
            j.new_rows.into_iter().for_each(|r| batch.delete(r));
            j.new_blobs.into_iter().for_each(|b| batch.delete_blob(b));
            batch.delete(k);
        }
        backend.commit(batch)?;
    }
}

fn pointer(epoch: u64, ver: u64) -> Vec<u8> {
    W::new().u64(epoch).u64(ver).take()
}
fn read_pointer(b: &[u8]) -> Result<(u64, u64), Error> {
    let mut r = R::new(b);
    let p = (r.u64()?, r.u64()?);
    r.end()?;
    Ok(p)
}

/// A unit's state inside a transaction.
enum DirtyUnit {
    Plain { data: Vec<u8>, shred: bool },
    /// Written early as row `u slot ver` under `key` (memory only until commit).
    Spilled { key: Secret32, shred: bool },
    Deleted { shred: bool },
}

impl DirtyUnit {
    fn shred(&self) -> bool {
        match self {
            DirtyUnit::Plain { shred, .. } | DirtyUnit::Spilled { shred, .. } | DirtyUnit::Deleted { shred } => *shred,
        }
    }
}

/// A transaction's uncommitted changes.
pub(crate) struct Dirty {
    ver: u64,
    pub meta: Meta,
    units: HashMap<u64, DirtyUnit>,
    plain_bytes: usize,
    /// Blobs written (`Some`) or deleted (`None`), the last change of each.
    blobs: HashMap<BlobId, Option<Vec<u8>>>,
    /// Spill journal records written (`0..spills`).
    spills: u32,
    /// Slots whose spilled row must go at commit (deleted after spilling).
    dead_spills: BTreeSet<u64>,
    /// What the first change of each slot and blob under each open savepoint replaced, oldest
    /// first (`DirtyMark`): bounded by what the savepoint touched, not by how often.
    undo: Vec<DirtyUndo>,
    /// The open savepoints, innermost last, each with the slots and blobs it has an `undo` entry
    /// for. While any is open nothing spills (a rollback to one restores memory only).
    open: Vec<(HashSet<u64>, HashSet<BlobId>)>,
}

/// A change undone by a rollback to a savepoint: what it replaced.
enum DirtyUndo {
    /// The slot's previous state, and whether it was in `dead_spills`.
    Unit(u64, Option<DirtyUnit>, bool),
    Blob(BlobId, Option<Option<Vec<u8>>>),
}

/// A savepoint of a transaction's changes (`Pager::mark`).
pub(crate) struct DirtyMark {
    undo: usize,
    open: usize,
    meta: Meta,
    plain_bytes: usize,
}

impl Dirty {
    pub fn is_empty(&self) -> bool {
        self.units.is_empty() && self.blobs.is_empty() && self.spills == 0
    }

    /// Sets a slot's state, keeping `plain_bytes` and `dead_spills`.
    fn set_unit(&mut self, slot: u64, u: DirtyUnit) {
        let dead = self.dead_spills.contains(&slot);
        let plain = matches!(u, DirtyUnit::Plain { .. });
        if let DirtyUnit::Plain { data, .. } = &u {
            self.plain_bytes = self.plain_bytes.saturating_add(data.len());
        }
        let old = self.units.insert(slot, u);
        match &old {
            Some(DirtyUnit::Plain { data, .. }) => self.plain_bytes = self.plain_bytes.saturating_sub(data.len()),
            Some(DirtyUnit::Spilled { .. }) if !plain => {
                self.dead_spills.insert(slot);
            }
            _ => {}
        }
        if plain {
            self.dead_spills.remove(&slot);
        }
        if self.open.last_mut().is_some_and(|l| l.0.insert(slot)) {
            self.undo.push(DirtyUndo::Unit(slot, old, dead));
        }
    }

    fn set_blob(&mut self, id: BlobId, b: Option<Vec<u8>>) {
        let old = self.blobs.insert(id, b);
        if self.open.last_mut().is_some_and(|l| l.1.insert(id)) {
            self.undo.push(DirtyUndo::Blob(id, old));
        }
    }

    /// Opens a savepoint.
    pub fn mark(&mut self) -> DirtyMark {
        self.open.push(Default::default());
        DirtyMark { undo: self.undo.len(), open: self.open.len(), meta: self.meta, plain_bytes: self.plain_bytes }
    }

    /// Closes savepoint `m` keeping its changes (an outer savepoint may still undo them).
    pub fn release(&mut self, m: DirtyMark) {
        debug_assert_eq!(m.open, self.open.len(), "savepoints release innermost first");
        let inner = self.open.pop().unwrap_or_default();
        match self.open.last_mut() {
            // its entries restore the outer one's values too: a slot unchanged since that mark
            Some(outer) => {
                outer.0.extend(inner.0);
                outer.1.extend(inner.1);
            }
            None => self.undo.clear(),
        }
    }

    /// Undoes every change since savepoint `m` and closes it.
    pub fn rollback_to(&mut self, m: DirtyMark) {
        debug_assert_eq!(m.open, self.open.len(), "savepoints roll back innermost first");
        while self.undo.len() > m.undo {
            match self.undo.pop() {
                Some(DirtyUndo::Unit(slot, old, dead)) => {
                    match old {
                        Some(u) => self.units.insert(slot, u),
                        None => self.units.remove(&slot),
                    };
                    if dead {
                        self.dead_spills.insert(slot);
                    } else {
                        self.dead_spills.remove(&slot);
                    }
                }
                Some(DirtyUndo::Blob(id, old)) => {
                    match old {
                        Some(b) => self.blobs.insert(id, b),
                        None => self.blobs.remove(&id),
                    };
                }
                None => break,
            }
        }
        self.meta = m.meta;
        self.plain_bytes = m.plain_bytes;
        self.open.pop();
        if self.open.is_empty() {
            self.undo.clear();
        }
    }

    pub fn open_savepoints(&self) -> usize {
        self.open.len()
    }
}

/// Finishes or rolls back an interrupted commit and loads the committed top: (epoch, root key,
/// top version, meta, top node). The stored shape overrides `cfg`'s.
fn recover(backend: &mut dyn Backend, root: &mut dyn RootStorage, cfg: &mut StoreConfig) -> Result<(u64, Secret32, u64, Meta, Node), Error> {
    root.repair().map_err(Error::Root)?;
    let rec = root.load().map_err(Error::Root)?.ok_or(Error::NoStore)?;
    if let Some(p) = backend.get(ROW_P)? {
        let (p_epoch, p_ver) = read_pointer(&p)?;
        let journals = backend.scan_prefix(&W::new().u8(JOURNAL).u64(p_ver).0, usize::MAX)?;
        let mut batch = WriteBatch::new();
        for (k, v) in &journals {
            let j = Journal::decode(v)?;
            let finish = p_epoch == rec.epoch;
            let (rows, blobs) = if finish { (j.old_rows, j.old_blobs) } else { (j.new_rows, j.new_blobs) };
            rows.into_iter().for_each(|r| batch.delete(r));
            blobs.into_iter().for_each(|b| batch.delete_blob(b));
            batch.delete(k.clone());
        }
        if p_epoch == rec.epoch {
            batch.put(ROW_R.to_vec(), pointer(p_epoch, p_ver));
        }
        batch.delete(ROW_P.to_vec());
        backend.commit(batch)?;
    }
    // Journals left by spills of transactions that never committed.
    rollback(backend, &[JOURNAL])?;
    let (epoch, ver) = read_pointer(&backend.get(ROW_R)?.ok_or(Error::NoStore)?)?;
    if epoch != rec.epoch {
        return Err(Error::Corrupt("root epoch"));
    }
    let row = top_row(ver);
    let v = backend.get(&row)?.ok_or(Error::Corrupt("top node missing"))?;
    let plain = Zeroizing::new(open(&rec.key, &row, &v)?);
    let mut r = R::new(&plain);
    let meta = Meta::decode(&mut r)?;
    let top = Node::decode(&mut r, meta.arity)?;
    r.end()?;
    cfg.arity = meta.arity;
    cfg.depth = meta.depth;
    cfg.page_max = meta.page_max as usize;
    cfg.capacity()?;
    Ok((epoch, rec.key, ver, meta, top))
}

pub(crate) struct Pager {
    backend: Box<dyn Backend>,
    root: Box<dyn RootStorage>,
    cfg: StoreConfig,
    epoch: u64,
    root_key: Secret32,
    top_ver: u64,
    /// Next transaction version: never repeats within a session, aborted ones included.
    next_ver: u64,
    /// Versions of transactions that spilled and have not committed (aborted unless running).
    open_spills: BTreeSet<u64>,
    meta: Meta,
    top: Node,
    /// Committed tree nodes below the top by (level, index); `None`: absent.
    nodes: HashMap<(u32, u64), Option<Node>>,
    units: HashMap<u64, Vec<u8>>,
    unit_bytes: usize,
    broken: bool,
    /// `Store::changes`.
    changes: u64,
}

/// `Store::changes` stamps: one sequence for the process, so no two stores or opens share one.
static CHANGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn next_change() -> u64 {
    CHANGES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

impl Pager {
    /// Creates an empty store. Refuses if the root storage already holds a root.
    /// Creates a store whose catalog root (slot 0) holds `catalog`, in one batch, then stores
    /// the root record: a crash before that leaves no root, and `create` can run again.
    /// Refuses if the root storage already holds a root.
    pub fn create(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, cfg: StoreConfig, catalog: Vec<u8>, rng: &mut dyn CryptoRngCore) -> Result<Pager, Error> {
        cfg.capacity()?;
        if root.load().map_err(Error::Root)?.is_some() {
            return Err(Error::Exists);
        }
        let root_key = Secret32::random(rng);
        let page_max = u32::try_from(cfg.page_max).map_err(|_| Error::Misuse("config"))?;
        let meta = Meta { arity: cfg.arity, depth: cfg.depth, page_max, next_slot: 0, next_ver: 1, catalog: u64::MAX };
        let mut p = Pager::new(backend, root, cfg, 1, root_key, 0, meta, Node::default());
        let mut d = p.begin()?;
        let slot = p.alloc(&mut d)?;
        p.txn_write(&mut d, slot, catalog, false, rng)?;
        d.meta.catalog = slot;
        p.commit(d, rng)?;
        let record = RootRecord { epoch: 1, key: p.root_key.clone() };
        p.root.store(&record).map_err(Error::Root)?;
        Ok(p)
    }

    #[allow(clippy::too_many_arguments)]
    fn new(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, cfg: StoreConfig, epoch: u64, root_key: Secret32, top_ver: u64, meta: Meta, top: Node) -> Pager {
        Pager { backend, root, cfg, epoch, root_key, top_ver, next_ver: meta.next_ver, open_spills: BTreeSet::new(), meta, top, nodes: HashMap::new(), units: HashMap::new(), unit_bytes: 0, broken: false, changes: next_change() }
    }

    /// Opens a store, finishing or rolling back an interrupted commit. The stored shape wins
    /// over `cfg.arity` and `cfg.depth`.
    pub fn open(mut backend: Box<dyn Backend>, mut root: Box<dyn RootStorage>, mut cfg: StoreConfig) -> Result<Pager, Error> {
        let (epoch, key, ver, meta, top) = recover(&mut *backend, &mut *root, &mut cfg)?;
        Ok(Pager::new(backend, root, cfg, epoch, key, ver, meta, top))
    }

    /// Recovers in place as `open` would (after a failed commit left the pager broken): caches
    /// emptied, versions not reused.
    pub fn reopen(&mut self) -> Result<(), Error> {
        let mut cfg = self.cfg;
        let (epoch, key, ver, meta, top) = recover(&mut *self.backend, &mut *self.root, &mut cfg)?;
        self.next_ver = self.next_ver.max(meta.next_ver);
        (self.cfg, self.epoch, self.root_key, self.top_ver, self.meta, self.top) = (cfg, epoch, key, ver, meta, top);
        self.open_spills.clear();
        self.nodes.clear();
        self.units.clear();
        self.unit_bytes = 0;
        self.broken = false;
        self.changes = next_change();
        Ok(())
    }

    pub fn changes(&self) -> u64 {
        self.changes
    }

    /// The memory overlay changed in a commit (`Store::changes`).
    pub fn note_change(&mut self) {
        self.changes = next_change();
    }

    pub fn cfg(&self) -> &StoreConfig {
        &self.cfg
    }
    pub fn meta(&self) -> Meta {
        self.meta
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn root_tier(&self) -> crate::RootTier {
        self.root.tier()
    }
    pub fn backend(&self) -> &dyn Backend {
        &*self.backend
    }
    fn check(&self) -> Result<(), Error> {
        if self.broken { Err(Error::Broken) } else { Ok(()) }
    }

    fn arity(&self) -> u64 {
        u64::from(self.meta.arity)
    }
    fn top_level(&self) -> u32 {
        self.meta.depth - 1
    }

    /// Loads the committed node (level, idx) into the cache; false if absent.
    fn ensure(&mut self, level: u32, idx: u64) -> Result<bool, Error> {
        if level >= self.top_level() {
            return Ok(true);
        }
        if let Some(n) = self.nodes.get(&(level, idx)) {
            return Ok(n.is_some());
        }
        let entry = self.child_entry(level + 1, idx / self.arity(), (idx % self.arity()) as u32)?;
        let node = match entry {
            None => None,
            Some(e) => {
                let row = node_row(level, idx, e.ver);
                let v = self.backend.get(&row)?.ok_or(Error::Corrupt("tree node missing"))?;
                let plain = Zeroizing::new(open(&e.key, &row, &v)?);
                let mut r = R::new(&plain);
                let n = Node::decode(&mut r, self.meta.arity)?;
                r.end()?;
                Some(n)
            }
        };
        if self.nodes.len() >= self.cfg.node_cache {
            self.nodes.clear();
        }
        let present = node.is_some();
        self.nodes.insert((level, idx), node);
        Ok(present)
    }

    fn node(&self, level: u32, idx: u64) -> Option<&Node> {
        if level >= self.top_level() { Some(&self.top) } else { self.nodes.get(&(level, idx)).and_then(Option::as_ref) }
    }

    /// The committed entry for child `child` of node (level, idx).
    fn child_entry(&mut self, level: u32, idx: u64, child: u32) -> Result<Option<Entry>, Error> {
        if !self.ensure(level, idx)? {
            return Ok(None);
        }
        Ok(self.node(level, idx).and_then(|n| n.entries.get(&child)).cloned())
    }

    fn unit_entry(&mut self, slot: u64) -> Result<Option<Entry>, Error> {
        self.child_entry(0, slot / self.arity(), (slot % self.arity()) as u32)
    }

    /// Committed bytes of unit `slot`.
    pub fn read(&mut self, slot: u64) -> Result<Option<Vec<u8>>, Error> {
        self.check()?;
        if let Some(u) = self.units.get(&slot) {
            return Ok(Some(u.clone()));
        }
        let Some(e) = self.unit_entry(slot)? else { return Ok(None) };
        let row = unit_row(slot, e.ver);
        let v = self.backend.get(&row)?.ok_or(Error::Corrupt("unit missing"))?;
        let plain = open(&e.key, &row, &v)?;
        self.cache_unit(slot, plain.clone());
        Ok(Some(plain))
    }

    fn cache_unit(&mut self, slot: u64, data: Vec<u8>) {
        if data.len() > self.cfg.unit_cache_bytes / 4 {
            self.units.remove(&slot);
            return;
        }
        if self.unit_bytes.saturating_add(data.len()) > self.cfg.unit_cache_bytes {
            self.units.clear();
            self.unit_bytes = 0;
        }
        self.unit_bytes = self.unit_bytes.saturating_add(data.len());
        self.units.insert(slot, data);
    }

    /// Starts a transaction, first rolling back the spills of aborted ones.
    pub fn begin(&mut self) -> Result<Dirty, Error> {
        self.check()?;
        for ver in std::mem::take(&mut self.open_spills) {
            rollback(&mut *self.backend, &W::new().u8(JOURNAL).u64(ver).take()).inspect_err(|_| self.broken = true)?;
        }
        let ver = self.next_ver;
        self.next_ver += 1;
        Ok(Dirty {
            ver,
            meta: self.meta,
            units: HashMap::new(),
            plain_bytes: 0,
            blobs: HashMap::new(),
            spills: 0,
            dead_spills: BTreeSet::new(),
            undo: Vec::new(),
            open: Vec::new(),
        })
    }

    pub fn alloc(&self, d: &mut Dirty) -> Result<u64, Error> {
        let slot = d.meta.next_slot;
        if slot >= self.cfg.capacity()? {
            return Err(Error::Misuse("unit slots exhausted"));
        }
        d.meta.next_slot = slot + 1;
        Ok(slot)
    }

    /// A unit's bytes as the transaction sees them.
    pub fn txn_read(&mut self, d: &Dirty, slot: u64) -> Result<Option<Vec<u8>>, Error> {
        match d.units.get(&slot) {
            Some(DirtyUnit::Plain { data, .. }) => Ok(Some(data.clone())),
            Some(DirtyUnit::Deleted { .. }) => Ok(None),
            Some(DirtyUnit::Spilled { key, .. }) => {
                let row = unit_row(slot, d.ver);
                let v = self.backend.get(&row)?.ok_or(Error::Corrupt("spilled unit missing"))?;
                open(key, &row, &v).map(Some)
            }
            None => self.read(slot),
        }
    }

    /// Writes unit `slot`. `shred`: the previous content must become unrecoverable at commit.
    pub fn txn_write(&mut self, d: &mut Dirty, slot: u64, data: Vec<u8>, shred: bool, rng: &mut dyn CryptoRngCore) -> Result<(), Error> {
        self.check()?;
        let shred = shred || d.units.get(&slot).is_some_and(DirtyUnit::shred);
        d.set_unit(slot, DirtyUnit::Plain { data, shred });
        self.spill_if_due(d, rng)
    }

    /// Deletes unit `slot`; with `shred` its content becomes unrecoverable at commit.
    pub fn txn_delete(&mut self, d: &mut Dirty, slot: u64, shred: bool) {
        let shred = shred || d.units.get(&slot).is_some_and(DirtyUnit::shred);
        d.set_unit(slot, DirtyUnit::Deleted { shred });
    }

    pub fn txn_put_blob(&mut self, d: &mut Dirty, id: BlobId, bytes: Vec<u8>, rng: &mut dyn CryptoRngCore) -> Result<(), Error> {
        self.check()?;
        d.plain_bytes = d.plain_bytes.saturating_add(bytes.len());
        d.set_blob(id, Some(bytes));
        self.spill_if_due(d, rng)
    }

    pub fn txn_delete_blob(&mut self, d: &mut Dirty, id: BlobId) {
        d.set_blob(id, None);
    }

    /// Spills when the unspilled bytes passed `spill_bytes` and no savepoint is open (spilled rows
    /// are on the backend, out of a rollback's reach); a savepoint's release spills what waited.
    pub fn spill_if_due(&mut self, d: &mut Dirty, rng: &mut dyn CryptoRngCore) -> Result<(), Error> {
        if d.plain_bytes > self.cfg.spill_bytes && d.open.is_empty() {
            self.spill(d, rng)?;
        }
        Ok(())
    }

    /// Bytes `offset..offset+len` of a blob as the transaction sees it.
    pub fn txn_get_blob(&self, d: &Dirty, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, Error> {
        self.check()?;
        match d.blobs.get(id) {
            Some(None) => return Ok(None),
            Some(Some(b)) => return Ok(Some(crate::backend::blob_slice(b, offset, len))),
            None => {}
        }
        Ok(self.backend.read_blob(id, offset, len)?)
    }

    /// Writes plain units and blobs early, under a journal record.
    fn spill(&mut self, d: &mut Dirty, rng: &mut dyn CryptoRngCore) -> Result<(), Error> {
        let mut batch = WriteBatch::new();
        let mut j = Journal::default();
        for (slot, u) in d.units.iter_mut() {
            if let DirtyUnit::Plain { data, shred } = u {
                let key = Secret32::random(rng);
                let row = unit_row(*slot, d.ver);
                batch.put(row.clone(), seal(&key, &row, data, rng)?);
                j.new_rows.push(row);
                *u = DirtyUnit::Spilled { key, shred: *shred };
            }
        }
        debug_assert!(d.open.is_empty(), "a spill under a savepoint");
        let puts: Vec<BlobId> = d.blobs.iter().filter(|(_, b)| b.is_some()).map(|(id, _)| *id).collect();
        for id in puts {
            let Some(Some(bytes)) = d.blobs.remove(&id) else { continue };
            // A blob already there (content-addressed re-put) survives a rollback.
            if self.backend.blob_len(&id)?.is_none() {
                j.new_blobs.push(id);
            }
            batch.put_blob(id, bytes);
        }
        batch.put(journal_row(d.ver, d.spills), j.encode());
        self.open_spills.insert(d.ver);
        d.spills += 1;
        d.plain_bytes = 0;
        self.backend.commit(batch).inspect_err(|_| self.broken = true)?;
        Ok(())
    }

    /// Commits a transaction (module doc for the protocol). After an error the pager is broken
    /// and the store must be reopened; a rotation whose root record was stored is committed.
    pub fn commit(&mut self, d: Dirty, rng: &mut dyn CryptoRngCore) -> Result<(), Error> {
        self.check()?;
        if d.is_empty() && d.meta == self.meta {
            return Ok(());
        }
        self.changes = next_change();
        let r = self.commit_inner(d, rng);
        if r.is_err() {
            self.broken = true;
        }
        r
    }

    fn commit_inner(&mut self, mut d: Dirty, rng: &mut dyn CryptoRngCore) -> Result<(), Error> {
        let ver = d.ver;
        let arity = self.arity();
        let mut batch = WriteBatch::new();
        let mut j = Journal::default();
        let mut changes: BTreeMap<u64, BTreeMap<u32, Option<Entry>>> = BTreeMap::new();
        let mut rotate: BTreeSet<u64> = BTreeSet::new();
        let mut cached: Vec<(u64, Option<Vec<u8>>)> = Vec::new();
        let mut units: Vec<(u64, DirtyUnit)> = d.units.drain().collect();
        units.sort_by_key(|(s, _)| *s);
        for (slot, u) in units {
            let old = self.unit_entry(slot)?;
            let row = unit_row(slot, ver);
            let shred = u.shred();
            let entry = match u {
                DirtyUnit::Plain { data, .. } => {
                    let key = Secret32::random(rng);
                    batch.put(row.clone(), seal(&key, &row, &data, rng)?);
                    j.new_rows.push(row);
                    cached.push((slot, Some(data)));
                    Some(Entry { key, ver })
                }
                DirtyUnit::Spilled { key, .. } => {
                    cached.push((slot, None));
                    Some(Entry { key, ver })
                }
                DirtyUnit::Deleted { .. } => {
                    if d.dead_spills.contains(&slot) {
                        j.old_rows.push(row);
                    }
                    cached.push((slot, None));
                    None
                }
            };
            if let Some(o) = &old {
                j.old_rows.push(unit_row(slot, o.ver));
                rotate.extend(shred.then_some(slot / arity));
            } else if entry.is_none() {
                continue;
            }
            changes.entry(slot / arity).or_default().insert((slot % arity) as u32, entry);
        }
        let top_level = self.top_level();
        let mut new_nodes: Vec<((u32, u64), Option<Node>)> = Vec::new();
        for level in 0..top_level {
            let mut next: BTreeMap<u64, BTreeMap<u32, Option<Entry>>> = BTreeMap::new();
            let mut next_rotate = BTreeSet::new();
            for (idx, ch) in changes {
                let old = self.child_entry(level + 1, idx / arity, (idx % arity) as u32)?;
                let mut node = if old.is_some() && self.ensure(level, idx)? { self.node(level, idx).cloned().unwrap_or_default() } else { Node::default() };
                for (i, e) in ch {
                    match e {
                        Some(e) => node.entries.insert(i, e),
                        None => node.entries.remove(&i),
                    };
                }
                let rot = rotate.contains(&idx);
                if let Some(o) = &old {
                    j.old_rows.push(node_row(level, idx, o.ver));
                }
                let entry = if node.entries.is_empty() {
                    new_nodes.push(((level, idx), None));
                    None
                } else {
                    let key = match &old {
                        Some(o) if !rot => o.key.clone(),
                        _ => Secret32::random(rng),
                    };
                    let row = node_row(level, idx, ver);
                    let mut w = W::new();
                    node.encode(&mut w);
                    let plain = Zeroizing::new(w.0);
                    batch.put(row.clone(), seal(&key, &row, &plain, rng)?);
                    j.new_rows.push(row);
                    new_nodes.push(((level, idx), Some(node)));
                    Some(Entry { key, ver })
                };
                if old.is_some() || entry.is_some() {
                    next.entry(idx / arity).or_default().insert((idx % arity) as u32, entry);
                }
                if rot {
                    next_rotate.insert(idx / arity);
                }
            }
            changes = next;
            rotate = next_rotate;
        }
        let mut top = self.top.clone();
        for (i, e) in changes.into_values().flatten() {
            match e {
                Some(e) => top.entries.insert(i, e),
                None => top.entries.remove(&i),
            };
        }
        let rotating = !rotate.is_empty();
        let meta = Meta { next_ver: ver + 1, ..d.meta };
        let top_key = if rotating { Secret32::random(rng) } else { self.root_key.clone() };
        let top_row = top_row(ver);
        let mut w = W::new();
        meta.encode(&mut w);
        top.encode(&mut w);
        let plain = Zeroizing::new(w.0);
        batch.put(top_row.clone(), seal(&top_key, &top_row, &plain, rng)?);
        j.new_rows.push(top_row);
        j.old_rows.push(self::top_row(self.top_ver));
        for (id, b) in d.blobs.drain() {
            match b {
                Some(bytes) => {
                    if self.backend.blob_len(&id)?.is_none() {
                        j.new_blobs.push(id);
                    }
                    batch.put_blob(id, bytes);
                }
                None => j.old_blobs.push(id),
            }
        }
        let journals: Vec<Vec<u8>> = (0..d.spills).map(|k| journal_row(ver, k)).collect();

        let mut epoch = self.epoch;
        if !rotating {
            j.old_rows.iter().for_each(|r| batch.delete(r.clone()));
            j.old_blobs.iter().for_each(|b| batch.delete_blob(*b));
            journals.iter().for_each(|r| batch.delete(r.clone()));
            batch.put(ROW_R.to_vec(), pointer(epoch, ver));
            self.backend.commit(batch)?;
        } else {
            epoch += 1;
            batch.put(journal_row(ver, FINAL), j.encode());
            batch.put(ROW_P.to_vec(), pointer(epoch, ver));
            self.backend.commit(batch)?;
            self.root.store(&RootRecord { epoch, key: top_key.clone() }).map_err(Error::Root)?;
            // Committed: the old root is gone. Clean up.
            self.root_key = top_key.clone();
            self.epoch = epoch;
            let mut b = WriteBatch::new();
            j.old_rows.iter().for_each(|r| b.delete(r.clone()));
            j.old_blobs.iter().for_each(|id| b.delete_blob(*id));
            journals.iter().for_each(|r| b.delete(r.clone()));
            b.delete(journal_row(ver, FINAL));
            b.delete(ROW_P.to_vec());
            b.put(ROW_R.to_vec(), pointer(epoch, ver));
            self.backend.commit(b)?;
        }
        self.root_key = top_key;
        self.epoch = epoch;
        self.top = top;
        self.top_ver = ver;
        self.meta = meta;
        self.open_spills.remove(&ver);
        for (k, n) in new_nodes {
            self.nodes.insert(k, n);
        }
        for (slot, data) in cached {
            match data {
                Some(data) => self.cache_unit(slot, data),
                None => {
                    self.units.remove(&slot);
                }
            }
        }
        Ok(())
    }

    /// Every key the current tree yields (root, nodes, units): what an attacker holding the
    /// device now could start from. O(store); shredding tests only.
    pub fn forensic_keys(&mut self) -> Result<Vec<[u8; 32]>, Error> {
        let mut out = vec![*self.root_key.expose()];
        let mut stack = vec![(self.top_level(), 0u64)];
        while let Some((level, idx)) = stack.pop() {
            if !self.ensure(level, idx)? {
                continue;
            }
            let entries: Vec<(u32, [u8; 32])> = self.node(level, idx).map(|n| n.entries.iter().map(|(i, e)| (*i, *e.key.expose())).collect()).unwrap_or_default();
            for (i, k) in entries {
                out.push(k);
                if level > 0 {
                    stack.push((level - 1, idx * self.arity() + u64::from(i)));
                }
            }
        }
        Ok(out)
    }
}

/// Opens a stored row with a candidate key: the plaintext, or `None`. Shredding tests only.
pub fn forensic_open(row: &[u8], value: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    // a padded row ends in 0x80 or 0x00 (`open`): another last byte rules the key out without
    // the whole AEAD pass (an attack tries every key on every row)
    let (nonce, ct) = value.split_at_checked(NONCE_LEN)?;
    if !matches!(aead::last_plain_byte(key, nonce.try_into().ok()?, ct), Some(0 | 0x80)) {
        return None;
    }
    open(&Secret32::from_bytes(*key), row, value).ok()
}

/// The slot of a unit row (`u slot ver`). Shredding tests only.
pub(crate) fn forensic_unit_slot(row: &[u8]) -> Option<u64> {
    let mut r = R::new(row);
    (r.u8().ok()? == b'u').then(|| r.u64().ok()).flatten()
}

/// Whether a row is stored in the clear: the pointers `r`, `p` and journals `j`. Shredding
/// tests only.
pub(crate) fn forensic_clear_row(row: &[u8]) -> bool {
    row == ROW_R || row == ROW_P || row.first() == Some(&JOURNAL)
}

/// The keys a decrypted tree-node row lists (top node: after the meta). Shredding tests only.
pub fn forensic_node_keys(row: &[u8], plaintext: &[u8]) -> Vec<[u8; 32]> {
    let mut r = R::new(plaintext);
    let top = match row.first() {
        Some(b't') => true,
        Some(b'n') => false,
        _ => return Vec::new(),
    };
    if top && Meta::decode(&mut r).is_err() {
        return Vec::new();
    }
    let node = Node::decode(&mut r, 65536).ok().filter(|_| r.is_empty());
    node.map(|n| n.entries.values().map(|e| *e.key.expose()).collect()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryBackend, MemoryRoot};
    use osis_crypto::SeededRng;

    fn small() -> StoreConfig {
        StoreConfig { arity: 4, depth: 3, ..StoreConfig::default() }
    }

    fn fresh(cfg: StoreConfig) -> (Pager, MemoryBackend, MemoryRoot, SeededRng) {
        let (b, r) = (MemoryBackend::new(), MemoryRoot::new());
        let mut rng = SeededRng::from_u64(1);
        let mut p = Pager::create(Box::new(b.clone()), Box::new(r.clone()), cfg, Vec::new(), &mut rng).unwrap();
        // Free the catalog slot: these tests use units only (slots from 1).
        let mut d = p.begin().unwrap();
        p.txn_delete(&mut d, 0, false);
        p.commit(d, &mut rng).unwrap();
        (p, b, r, rng)
    }

    fn rows(b: &MemoryBackend, prefix: u8) -> usize {
        b.dump().iter().filter(|(k, _)| k.first() == Some(&prefix)).count()
    }

    // spec/commits.md §5: dropping destroys every local copy; notes/local-store.md, Key tree: units round-trip and survive reopen; rows hold ciphertext.
    #[test]
    fn units_roundtrip_and_reopen() {
        let (mut p, b, r, mut rng) = fresh(small());
        let mut d = p.begin().unwrap();
        let slots: Vec<u64> = (0..20).map(|_| p.alloc(&mut d).unwrap()).collect();
        assert_eq!(slots.first(), Some(&1), "slot 0 is the catalog's");
        for &s in &slots {
            p.txn_write(&mut d, s, format!("unit {s}").into_bytes(), false, &mut rng).unwrap();
        }
        assert_eq!(p.txn_read(&d, 3).unwrap(), Some(b"unit 3".to_vec()));
        p.commit(d, &mut rng).unwrap();
        assert_eq!(p.epoch(), 1, "no rotation without erasure");
        assert_eq!(rows(&b, b'u'), 20);
        assert!(b.dump().iter().all(|(_, v)| !v.windows(4).any(|w| w == b"unit")));
        let mut p = Pager::open(Box::new(b.clone()), Box::new(r.clone()), StoreConfig::default()).unwrap();
        assert_eq!(p.cfg().arity, 4, "stored shape wins");
        for &s in &slots {
            assert_eq!(p.read(s).unwrap(), Some(format!("unit {s}").into_bytes()));
        }
        assert_eq!(p.read(99).unwrap(), None);
    }

    // spec/commits.md §5: dropping destroys every local copy; notes/local-store.md, Key tree: a shredded rewrite or delete rotates the path and the root
    // (one root write per transaction); others keep the root; old rows are deleted.
    #[test]
    fn rotation() {
        let (mut p, b, r, mut rng) = fresh(small());
        let mut d = p.begin().unwrap();
        for _ in 0..16 {
            let slot = p.alloc(&mut d).unwrap();
            p.txn_write(&mut d, slot, vec![slot as u8; 10], false, &mut rng).unwrap();
        }
        p.commit(d, &mut rng).unwrap();
        let key1 = r.load().unwrap().unwrap();
        let mut d = p.begin().unwrap();
        p.txn_write(&mut d, 5, b"new".to_vec(), false, &mut rng).unwrap();
        p.commit(d, &mut rng).unwrap();
        assert_eq!(r.load().unwrap().unwrap(), key1);
        let mut d = p.begin().unwrap();
        p.txn_write(&mut d, 5, b"newer".to_vec(), true, &mut rng).unwrap();
        p.txn_delete(&mut d, 9, true);
        p.commit(d, &mut rng).unwrap();
        let key2 = r.load().unwrap().unwrap();
        assert_eq!(key2.epoch, 2);
        assert_ne!(key2.key, key1.key);
        assert_eq!(rows(&b, b'u'), 15);
        assert_eq!(rows(&b, b't'), 1);
        assert_eq!(rows(&b, b'j'), 0);
        assert!(b.get(ROW_P).unwrap().is_none());
        let mut p = Pager::open(Box::new(b.clone()), Box::new(r), small()).unwrap();
        assert_eq!(p.read(5).unwrap(), Some(b"newer".to_vec()));
        assert_eq!(p.read(9).unwrap(), None);
        assert_eq!(p.read(10).unwrap(), Some(vec![10; 10]));
    }

    // spec/commits.md §5: dropping destroys every local copy; notes/local-store.md, Key tree: capacity is arity^depth; slots are never reused; empty
    // nodes disappear.
    #[test]
    fn full_tree() {
        let cfg = StoreConfig { arity: 2, depth: 3, ..StoreConfig::default() };
        let (mut p, b, _r, mut rng) = fresh(cfg);
        let mut d = p.begin().unwrap();
        for _ in 1..8 {
            let s = p.alloc(&mut d).unwrap();
            p.txn_write(&mut d, s, vec![1], false, &mut rng).unwrap();
        }
        assert_eq!(p.alloc(&mut d), Err(Error::Misuse("unit slots exhausted")));
        p.commit(d, &mut rng).unwrap();
        // Levels 0 and 1 below the top: 4 + 2 nodes.
        assert_eq!(rows(&b, b'n'), 6);
        let mut d = p.begin().unwrap();
        for s in 1..8 {
            p.txn_delete(&mut d, s, false);
        }
        p.commit(d, &mut rng).unwrap();
        assert_eq!(rows(&b, b'n'), 0);
        assert_eq!(rows(&b, b'u'), 0);
    }

    // spec/commits.md §4: one storage transaction per commit applied; spilled rows are invisible until commit, readable inside
    // the transaction, and gone after abort and reopen.
    #[test]
    fn spill() {
        let cfg = StoreConfig { spill_bytes: 100, ..small() };
        let (mut p, b, r, mut rng) = fresh(cfg);
        let mut d = p.begin().unwrap();
        for _ in 0..10 {
            let s = p.alloc(&mut d).unwrap();
            p.txn_write(&mut d, s, vec![s as u8; 40], false, &mut rng).unwrap();
        }
        assert!(rows(&b, b'j') > 0);
        assert_eq!(p.txn_read(&d, 1).unwrap(), Some(vec![1; 40]));
        p.txn_delete(&mut d, 1, false);
        p.commit(d, &mut rng).unwrap();
        assert_eq!(rows(&b, b'j'), 0);
        assert_eq!(rows(&b, b'u'), 9);
        assert_eq!(p.read(2).unwrap(), Some(vec![2; 40]));
        // Abandoned spilled transaction: rolled back on open.
        let mut d = p.begin().unwrap();
        for _ in 0..5 {
            let s = p.alloc(&mut d).unwrap();
            p.txn_write(&mut d, s, vec![7; 40], false, &mut rng).unwrap();
        }
        drop(d);
        assert!(rows(&b, b'u') > 9);
        let mut p = Pager::open(Box::new(b.clone()), Box::new(r), cfg).unwrap();
        assert_eq!(rows(&b, b'u'), 9);
        assert_eq!(rows(&b, b'j'), 0);
        assert_eq!(p.read(2).unwrap(), Some(vec![2; 40]));
    }

    // spec: none (internal: notes/local-store.md, Savepoints). A savepoint's undo log holds one entry per slot and blob it touched, however often (a step
    // rewriting one page per op keeps one old copy, not one per op), and nested ones still
    // restore their own marks.
    #[test]
    fn savepoint_undo_per_touched_unit() {
        let (mut p, _b, _r, mut rng) = fresh(small());
        let mut d = p.begin().unwrap();
        let s = p.alloc(&mut d).unwrap();
        p.txn_write(&mut d, s, vec![1], false, &mut rng).unwrap();
        let outer = d.mark();
        for i in 0..100u8 {
            p.txn_write(&mut d, s, vec![2, i], false, &mut rng).unwrap();
            p.txn_put_blob(&mut d, BlobId([9; 32]), vec![i], &mut rng).unwrap();
        }
        assert_eq!(d.undo.len(), 2);
        let inner = d.mark();
        p.txn_write(&mut d, s, vec![3], false, &mut rng).unwrap();
        p.txn_write(&mut d, s, vec![4], false, &mut rng).unwrap();
        d.release(inner);
        let inner = d.mark();
        p.txn_write(&mut d, s, vec![5], false, &mut rng).unwrap();
        d.rollback_to(inner);
        assert_eq!(p.txn_read(&d, s).unwrap(), Some(vec![4]));
        assert_eq!(d.undo.len(), 3);
        d.rollback_to(outer);
        assert_eq!(p.txn_read(&d, s).unwrap(), Some(vec![1]));
        assert_eq!(p.txn_get_blob(&d, &BlobId([9; 32]), 0, 1).unwrap(), None);
    }

    // spec/commits.md §5: dropping destroys every local copy; notes/local-store.md, Key tree: three levels of 256 cover 16M units. Same shape at arity 16:
    // a rotation rewrites exactly one node per level, whatever the store size.
    #[test]
    #[ignore = "by hand"]
    fn shape_reduced_arity() {
        let cfg = StoreConfig { arity: 16, depth: 6, ..StoreConfig::default() };
        let (mut p, b, _r, mut rng) = fresh(cfg);
        let n = 200_000u64;
        for _ in 0..n / 10_000 {
            let mut d = p.begin().unwrap();
            for _ in 0..10_000 {
                let s = p.alloc(&mut d).unwrap();
                p.txn_write(&mut d, s, s.to_be_bytes().to_vec(), false, &mut rng).unwrap();
            }
            p.commit(d, &mut rng).unwrap();
        }
        let before: std::collections::HashSet<_> = b.dump().into_iter().collect();
        let mut d = p.begin().unwrap();
        p.txn_write(&mut d, 123_456, b"x".to_vec(), true, &mut rng).unwrap();
        p.commit(d, &mut rng).unwrap();
        let changed: Vec<u8> = b.dump().into_iter().filter(|kv| !before.contains(kv)).map(|(k, _)| k[0]).collect();
        // One unit row, depth-1 nodes, the top node, the pointer row.
        assert_eq!(changed.len(), 1 + 5 + 1 + 1, "{changed:?}");
        assert_eq!(p.read(123_456).unwrap(), Some(b"x".to_vec()));
        assert_eq!(p.read(7).unwrap(), Some(7u64.to_be_bytes().to_vec()));
    }

    // spec/commits.md §5: dropping destroys every local copy, no fingerprint left; spec/wire.md §5:
    // Padmé; notes/local-store.md, Row padding: a row's length shows only its Padmé class, at least `UNIT_MIN` for units, and
    // the plaintext round-trips at every length around the class boundaries.
    #[test]
    fn row_lengths_show_only_the_class() {
        let key = Secret32::from_bytes([7; 32]);
        let mut rng = SeededRng::from_u64(2);
        let (unit, node) = (unit_row(5, 9), node_row(1, 3, 9));
        let sealed = |row: &[u8], len: usize, rng: &mut SeededRng| seal(&key, row, &vec![0xa5; len], rng).unwrap();
        assert_eq!(sealed(&unit, 0, &mut rng).len(), sealed(&unit, UNIT_MIN - 1, &mut rng).len(), "below the floor: one length");
        assert_eq!(sealed(&unit, 4200, &mut rng).len(), sealed(&unit, 4220, &mut rng).len(), "one class at 4 KB");
        assert!(sealed(&node, 1, &mut rng).len() < sealed(&unit, 1, &mut rng).len(), "no floor for tree nodes");
        for row in [&unit, &node] {
            let mut lens: Vec<usize> = (0..=16).collect();
            for len in 0..9000 {
                if padded_len(row, len) != padded_len(row, len + 1) {
                    lens.extend([len, len + 1]);
                }
            }
            for len in lens {
                let plain: Vec<u8> = (0..len).map(|i| i as u8 | 1).collect();
                let v = seal(&key, row, &plain, &mut rng).unwrap();
                assert_eq!(v.len(), NONCE_LEN + padded_len(row, len) + aead::TAG_LEN);
                assert_eq!(open(&key, row, &v).unwrap(), plain, "len {len}");
            }
        }
        // A trailing zero in the plaintext survives (the marker ends the scan).
        let v = seal(&key, &unit, &[0, 0x80, 0], &mut rng).unwrap();
        assert_eq!(open(&key, &unit, &v).unwrap(), vec![0, 0x80, 0]);
    }

    // spec/wire.md §5: `P || 0x80 || zeros`; notes/local-store.md, Row padding: open accepts only that, at exactly the class length.
    #[test]
    fn row_padding_rejects_other_shapes() {
        let key = Secret32::from_bytes([5; 32]);
        let (unit, node) = (unit_row(3, 1), node_row(0, 2, 1));
        let raw = |row: &[u8], padded: &[u8]| [&[0u8; NONCE_LEN][..], &aead::seal(key.expose(), &[0; NONCE_LEN], row, padded).unwrap()].concat();
        let mut marker_then_byte = vec![0x80; 1];
        marker_then_byte.resize(UNIT_MIN, 0);
        marker_then_byte[UNIT_MIN - 1] = 1;
        let mut short = vec![9u8; 10];
        short.push(0x80);
        for (row, padded) in [(&unit, vec![]), (&unit, vec![0; UNIT_MIN]), (&unit, marker_then_byte), (&unit, short.clone()), (&node, vec![0x80, 0])] {
            assert_eq!(open(&key, row, &raw(row, &padded)), Err(Error::Corrupt("row padding")), "{padded:?}");
        }
        short.resize(padme(11), 0);
        assert_eq!(open(&key, &node, &raw(&node, &short)).unwrap(), vec![9; 10], "the same bytes are a valid node row");
    }

    // spec/wire.md §5: Padmé; notes/local-store.md, Row padding: overhead measurement (no timing). Units above the floor
    // pay under 1/16 of their length; prints the mean over every length up to 16 KiB.
    #[test]
    fn row_padding_overhead() {
        let unit = unit_row(1, 1);
        let (mut plain, mut padded) = (0usize, 0usize);
        for len in UNIT_MIN..16 << 10 {
            let p = padded_len(&unit, len);
            assert!(p > len && p <= (len + 1) * 17 / 16, "len {len} pads to {p}");
            plain += len;
            padded += p;
        }
        println!("unit padding over {UNIT_MIN}..16 KiB: {:.2}% mean", 100.0 * (padded - plain) as f64 / plain as f64);
    }

    proptest::proptest! {
        // spec/commits.md §5, spec/wire.md §5; notes/local-store.md, Row padding: a sealed row's length is
        // its Padmé class (units at least `UNIT_MIN`), nothing finer; every length round-trips.
        #[test]
        fn row_padding_classes(a in 0usize..6000, b in 0usize..6000, unit in proptest::bool::ANY) {
            let key = Secret32::from_bytes([3; 32]);
            let mut rng = SeededRng::from_u64(a as u64);
            let row = if unit { unit_row(2, 4) } else { node_row(0, 1, 4) };
            let (pa, pb): (Vec<u8>, Vec<u8>) = (vec![0x11; a], vec![0; b]);
            let (va, vb) = (seal(&key, &row, &pa, &mut rng).unwrap(), seal(&key, &row, &pb, &mut rng).unwrap());
            let class = |len: usize| NONCE_LEN + padme(len + 1).max(if unit { UNIT_MIN } else { 0 }) + aead::TAG_LEN;
            proptest::prop_assert_eq!((va.len(), vb.len()), (class(a), class(b)));
            proptest::prop_assert_eq!(open(&key, &row, &va).unwrap(), pa);
            proptest::prop_assert_eq!(open(&key, &row, &vb).unwrap(), pb);
        }
    }
}

//! `Store` and `Transaction`: the typed unit API node uses (notes/local-store.md, Units). One
//! catalog table maps typed keys to small records and to the roots of further tables; every
//! table page is an encrypted unit. All writes of a transaction commit together or not at all
//! (spec/commits.md §4); drop a transaction to abort it.

use crate::backend::Backend;
use crate::btree::{self, Units};
use crate::codec::{R, W};
use crate::overlay::{MEM_TABLE, MemTxn, Overlay};
use crate::pager::{Dirty, Pager, StoreConfig};
use crate::root::{RootStorage, RootTier};
use crate::{Error, KeyValue};
use osis_base::{Ak, BlobId, CommitId, LabelId, Tid, Ts};
use osis_crypto::CryptoRngCore;

/// Whether an overwrite or removal must make the previous bytes unrecoverable once committed
/// (spec/commits.md §5). `Yes` rotates the key path to a fresh root at commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shred {
    No,
    Yes,
}

impl Shred {
    fn on(self) -> bool {
        self == Shred::Yes
    }
}

/// A table: an ordered byte map paged into units (a large aspect state, its indexes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Table(u64);

/// A small aspect's state, undo buffer and pre-reset snapshots: one record, encodings the
/// node's. A large state keeps its elements and indexes in the aspect's tables.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AspectUnit {
    pub state: Vec<u8>,
    pub undo: Vec<u8>,
    pub snapshots: Vec<u8>,
}

/// First and last death so far of a body's writes in one aspect (spec/commits.md §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deaths {
    pub first: Ts,
    pub last: Ts,
}

/// A commit not applied yet (spec/commits.md §4) or parked (spec/versioning.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingKind {
    Pending,
    Parked,
}

/// Catalog key kinds.
mod kind {
    pub const ASPECT: u8 = 1;
    pub const DEATH: u8 = 2;
    pub const TABLE: u8 = 3;
    pub const WRAP: u8 = 4;
    pub const SECRETS: u8 = 5;
    pub const CURSOR: u8 = 6;
    pub const LOG: u8 = 7;
    pub const LOG_HEAD: u8 = 8;
    pub const COUNTER: u8 = 9;
    pub const PENDING: u8 = 10;
    pub const INDEX: u8 = 11;
    pub const LOCAL: u8 = 12;
}

fn aspect_key(k: u8, tid: &Tid, ak: &Ak) -> Vec<u8> {
    let a = ak.as_str().as_bytes();
    W::new().u8(k).raw(tid.as_bytes()).u32(a.len() as u32).raw(a).take()
}

fn named_key(k: u8, name: &[u8]) -> Vec<u8> {
    W::new().u8(k).bytes(name).take()
}

fn u64_value(v: Option<Vec<u8>>) -> Result<Option<u64>, Error> {
    v.map(|b| {
        let mut r = R::new(&b);
        let n = r.u64()?;
        r.end()?;
        Ok(n)
    })
    .transpose()
}

fn tail<const N: usize>(key: &[u8]) -> Result<[u8; N], Error> {
    key.get(key.len().saturating_sub(N)..).and_then(|t| t.try_into().ok()).ok_or(Error::Corrupt("catalog key"))
}

/// The encrypted local store, with its memory overlay (`crate::overlay`): rows of the memory
/// class, lost when the store is dropped.
pub struct Store {
    pager: Pager,
    mem: Overlay,
}

impl Store {
    /// Creates an empty store over an empty backend and an empty root storage.
    pub fn create(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, cfg: StoreConfig, rng: &mut dyn CryptoRngCore) -> Result<Store, Error> {
        Ok(Store { pager: Pager::create(backend, root, cfg, btree::empty_page(), rng)?, mem: Overlay::default() })
    }

    /// Opens a store, finishing or rolling back a commit a crash interrupted.
    pub fn open(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, cfg: StoreConfig) -> Result<Store, Error> {
        let pager = Pager::open(backend, root, cfg)?;
        if pager.meta().catalog == u64::MAX {
            return Err(Error::NoStore);
        }
        Ok(Store { pager, mem: Overlay::default() })
    }

    /// Starts a transaction; reads see its own writes. Drop it to abort.
    pub fn transaction<'a>(&'a mut self, rng: &'a mut dyn CryptoRngCore) -> Result<Transaction<'a>, Error> {
        let d = self.pager.begin()?;
        Ok(Transaction { pager: &mut self.pager, d, rng, mem: MemTxn { o: &mut self.mem, undo: Vec::new(), done: false }, memory: false })
    }

    pub fn root_tier(&self) -> RootTier {
        self.pager.root_tier()
    }
    /// Rotations so far (one per committed transaction that shredded).
    pub fn epoch(&self) -> u64 {
        self.pager.epoch()
    }
    pub fn config(&self) -> &StoreConfig {
        self.pager.cfg()
    }
    /// The raw backend: ciphertext only. Tests.
    #[doc(hidden)]
    pub fn backend(&self) -> &dyn Backend {
        self.pager.backend()
    }
    /// Every key the current tree yields. Shredding tests.
    #[doc(hidden)]
    pub fn forensic_keys(&mut self) -> Result<Vec<[u8; 32]>, Error> {
        self.pager.forensic_keys()
    }
}

/// A set of writes committed atomically. Every method fails with `Error::Broken` after a failed
/// commit until the store is reopened.
///
/// Rows go to the memory overlay or the durable store by class (notes/local-store.md, Memory
/// overlay): in memory mode (`set_memory`) every new row is memory; a row already held in memory
/// stays there; every row of a memory-class aspect (`is_memory_aspect`) is memory. Reads see
/// both, memory first; removals remove from both.
pub struct Transaction<'a> {
    pager: &'a mut Pager,
    d: Dirty,
    rng: &'a mut dyn CryptoRngCore,
    mem: MemTxn<'a>,
    memory: bool,
}

impl Units for Transaction<'_> {
    fn read(&mut self, slot: u64) -> Result<Option<Vec<u8>>, Error> {
        self.pager.txn_read(&self.d, slot)
    }
    fn write(&mut self, slot: u64, data: Vec<u8>, shred: bool) -> Result<(), Error> {
        self.pager.txn_write(&mut self.d, slot, data, shred, &mut *self.rng)
    }
    fn delete(&mut self, slot: u64, shred: bool) {
        self.pager.txn_delete(&mut self.d, slot, shred);
    }
    fn alloc(&mut self) -> Result<u64, Error> {
        self.pager.alloc(&mut self.d)
    }
    fn page_max(&self) -> usize {
        self.pager.cfg().page_max
    }
}

impl Transaction<'_> {
    /// Commits durably. With any `Shred::Yes` in it, returns only after the new root record is
    /// durable: from then on the shredded bytes are unrecoverable.
    ///
    /// `Err` means the outcome is unknown: a shredding commit whose root record landed is
    /// committed even if a later cleanup write failed. The store refuses further use; reopen it
    /// (recovery finishes or rolls back, and may be repeated after another crash) and read back.
    pub fn commit(self) -> Result<(), Error> {
        let Transaction { pager, d, rng, mut mem, .. } = self;
        pager.commit(d, rng)?;
        mem.done = true;
        Ok(())
    }

    /// Memory mode: new rows go to the memory overlay (a memory commit's application).
    pub fn set_memory(&mut self, on: bool) {
        self.memory = on;
    }
    pub fn is_memory(&self) -> bool {
        self.memory
    }
    /// Whether the aspect's rows are of the memory class.
    pub fn is_memory_aspect(&self, tid: &Tid, ak: &Ak) -> bool {
        self.mem.o.aspects.contains(&(*tid, ak.clone()))
    }
    /// Whether rows of this aspect written now go to memory (marking it memory-class if so).
    fn aspect_mem(&mut self, tid: &Tid, ak: &Ak) -> bool {
        let on = self.memory || self.is_memory_aspect(tid, ak);
        if on {
            self.mem.mark_aspect(tid, ak);
        }
        on
    }

    fn catalog(&self) -> u64 {
        self.d.meta.catalog
    }
    fn cat_get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if let Some(v) = self.mem.o.cat.get(key) {
            return Ok(Some(v.clone()));
        }
        let c = self.catalog();
        btree::get(self, c, key)
    }
    fn cat_put(&mut self, key: &[u8], val: Vec<u8>, shred: Shred) -> Result<(), Error> {
        let m = self.memory;
        self.cat_put_to(key, val, shred, m)
    }
    /// A catalog row to memory when `mem` or already there, else to the durable store.
    fn cat_put_to(&mut self, key: &[u8], val: Vec<u8>, shred: Shred, mem: bool) -> Result<(), Error> {
        if mem || self.mem.o.cat.contains_key(key) {
            debug_assert!(self.durable_get(key)?.is_none(), "a memory row over a durable one");
            self.mem.cat_put(key, val);
            return Ok(());
        }
        let c = self.catalog();
        btree::put(self, c, key, val, shred.on()).map(|_| ())
    }
    fn durable_get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let c = self.catalog();
        btree::get(self, c, key)
    }
    fn cat_remove(&mut self, key: &[u8], shred: Shred) -> Result<bool, Error> {
        let removed = self.mem.cat_remove(key);
        let c = self.catalog();
        Ok(btree::remove(self, c, key, shred.on())? || removed)
    }
    /// Catalog entries under `prefix`, from `prefix || from` on.
    fn cat_scan(&mut self, prefix: &[u8], from: &[u8], limit: usize) -> Result<Vec<KeyValue>, Error> {
        let c = self.catalog();
        let start = [prefix, from].concat();
        let end = crate::backend::prefix_end(prefix);
        let mem = crate::overlay::range(Some(&self.mem.o.cat), &start, end.as_deref(), limit);
        let durable = btree::range(self, c, &start, end.as_deref(), limit)?;
        Ok(if mem.is_empty() { durable } else { crate::overlay::merge(mem, durable, limit) })
    }
    /// Removes and returns the first catalog entry under `prefix`.
    fn cat_pop_prefix(&mut self, prefix: &[u8], shred: Shred) -> Result<Option<KeyValue>, Error> {
        let Some((k, v)) = self.cat_scan(prefix, b"", 1)?.pop() else { return Ok(None) };
        self.cat_remove(&k, shred)?;
        Ok(Some((k, v)))
    }

    // Aspects.

    pub fn get_aspect(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<AspectUnit>, Error> {
        let Some(b) = self.cat_get(&aspect_key(kind::ASPECT, tid, ak))? else { return Ok(None) };
        let mut r = R::new(&b);
        let u = AspectUnit { state: r.bytes()?.to_vec(), undo: r.bytes()?.to_vec(), snapshots: r.bytes()?.to_vec() };
        r.end()?;
        Ok(Some(u))
    }

    /// Writes an aspect's unit. `Shred::Yes` when the rewrite drops content that must not be
    /// recoverable (a dropped body's writes, undo entries, snapshots).
    pub fn put_aspect(&mut self, tid: &Tid, ak: &Ak, unit: &AspectUnit, shred: Shred) -> Result<(), Error> {
        if [&unit.state, &unit.undo, &unit.snapshots].iter().any(|b| u32::try_from(b.len()).is_err()) {
            return Err(Error::Misuse("aspect unit field above 4 GiB"));
        }
        let v = W::new().bytes(&unit.state).bytes(&unit.undo).bytes(&unit.snapshots).take();
        let m = self.aspect_mem(tid, ak);
        self.cat_put_to(&aspect_key(kind::ASPECT, tid, ak), v, shred, m)
    }

    /// Records a death of a write of `body` in this aspect at `ts`: first and last so far.
    pub fn note_death(&mut self, tid: &Tid, ak: &Ak, body: &BlobId, ts: Ts) -> Result<Deaths, Error> {
        let d = match self.death(tid, ak, body)? {
            Some(d) => Deaths { first: d.first.min(ts), last: d.last.max(ts) },
            None => Deaths { first: ts, last: ts },
        };
        let key = [aspect_key(kind::DEATH, tid, ak), body.0.to_vec()].concat();
        let m = self.aspect_mem(tid, ak);
        self.cat_put_to(&key, W::new().u64(d.first.to_u64()).u64(d.last.to_u64()).take(), Shred::No, m)?;
        Ok(d)
    }

    /// Replaces the death record of `body` in this aspect (`None` removes it).
    pub fn set_death(&mut self, tid: &Tid, ak: &Ak, body: &BlobId, d: Option<Deaths>) -> Result<(), Error> {
        let key = [aspect_key(kind::DEATH, tid, ak), body.0.to_vec()].concat();
        match d {
            Some(d) => {
                let m = self.aspect_mem(tid, ak);
                self.cat_put_to(&key, W::new().u64(d.first.to_u64()).u64(d.last.to_u64()).take(), Shred::No, m)
            }
            None => self.cat_remove(&key, Shred::No).map(|_| ()),
        }
    }

    pub fn death(&mut self, tid: &Tid, ak: &Ak, body: &BlobId) -> Result<Option<Deaths>, Error> {
        let key = [aspect_key(kind::DEATH, tid, ak), body.0.to_vec()].concat();
        self.cat_get(&key)?.map(|b| decode_deaths(&b)).transpose()
    }

    /// Death records of an aspect, by body ID, after `after` (exclusive).
    pub fn deaths(&mut self, tid: &Tid, ak: &Ak, after: Option<&BlobId>, limit: usize) -> Result<Vec<(BlobId, Deaths)>, Error> {
        let from = after.map(|b| [&b.0[..], &[0]].concat()).unwrap_or_default();
        self.cat_scan(&aspect_key(kind::DEATH, tid, ak), &from, limit)?
            .into_iter()
            .map(|(k, v)| Ok((BlobId(tail(&k)?), decode_deaths(&v)?)))
            .collect()
    }

    /// Drops a body locally (spec/commits.md §5): shreds its death records in `aspects` and
    /// deletes its ciphertext. The caller rewrites those aspects' state, undo buffers and
    /// snapshots without the body's content, with `Shred::Yes`, in the same transaction, and
    /// drops its wraps (`drop_wrap`) where the body leaves a label.
    pub fn drop_body(&mut self, body: &BlobId, aspects: &[(Tid, Ak)]) -> Result<(), Error> {
        for (tid, ak) in aspects {
            self.cat_remove(&[aspect_key(kind::DEATH, tid, ak), body.0.to_vec()].concat(), Shred::Yes)?;
        }
        self.delete_blob(body);
        Ok(())
    }


    /// Drops an aspect's unit, tables and death records, shredded (a whole-aspect purge). Its
    /// counters stay: node-form counters never repeat.
    pub fn drop_aspect(&mut self, tid: &Tid, ak: &Ak) -> Result<(), Error> {
        self.cat_remove(&aspect_key(kind::ASPECT, tid, ak), Shred::Yes)?;
        while self.cat_pop_prefix(&aspect_key(kind::DEATH, tid, ak), Shred::Yes)?.is_some() {}
        while let Some((_, v)) = self.cat_pop_prefix(&aspect_key(kind::TABLE, tid, ak), Shred::Yes)? {
            let root = u64_value(Some(v))?.ok_or(Error::Corrupt("table"))?;
            self.drop_root(root)?;
        }
        Ok(())
    }

    /// Drops every row of the table rooted at `root`, in memory and durable.
    fn drop_root(&mut self, root: u64) -> Result<(), Error> {
        self.mem.drop_rows(root);
        if root & MEM_TABLE == 0 {
            btree::drop_all(self, root, true)?;
        }
        Ok(())
    }

    // Tables (paged large state and its indexes).

    /// Table `idx` of an aspect, if created.
    pub fn table(&mut self, tid: &Tid, ak: &Ak, idx: u8) -> Result<Option<Table>, Error> {
        let key = [aspect_key(kind::TABLE, tid, ak), vec![idx]].concat();
        Ok(u64_value(self.cat_get(&key)?)?.map(Table))
    }

    /// Table `idx` of an aspect, created empty if absent.
    pub fn create_table(&mut self, tid: &Tid, ak: &Ak, idx: u8) -> Result<Table, Error> {
        if let Some(t) = self.table(tid, ak, idx)? {
            return Ok(t);
        }
        let m = self.aspect_mem(tid, ak);
        let root = if m { self.mem.new_table() } else { btree::create(self)? };
        let key = [aspect_key(kind::TABLE, tid, ak), vec![idx]].concat();
        self.cat_put_to(&key, W::new().u64(root).take(), Shred::No, m)?;
        Ok(Table(root))
    }

    /// Drops one table of an aspect, shredded.
    pub fn drop_table(&mut self, tid: &Tid, ak: &Ak, idx: u8) -> Result<(), Error> {
        let Some(t) = self.table(tid, ak, idx)? else { return Ok(()) };
        self.cat_remove(&[aspect_key(kind::TABLE, tid, ak), vec![idx]].concat(), Shred::Yes)?;
        self.drop_root(t.0)
    }

    /// A memory-only table, or a durable one holding no memory rows.
    fn pure(&self, t: Table) -> Option<bool> {
        if t.0 & MEM_TABLE != 0 {
            Some(true)
        } else if self.mem.o.tables.contains_key(&t.0) {
            None
        } else {
            Some(false)
        }
    }

    pub fn table_get(&mut self, t: Table, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if let Some(v) = self.mem.row_get(t.0, key) {
            return Ok(Some(v.clone()));
        }
        if t.0 & MEM_TABLE != 0 {
            return Ok(None);
        }
        btree::get(self, t.0, key)
    }
    /// Inserts or replaces; true if the key was new. Keys are at most a quarter page. A row goes
    /// to memory in a memory table, in memory mode or when held there already.
    pub fn table_put(&mut self, t: Table, key: &[u8], val: Vec<u8>, shred: Shred) -> Result<bool, Error> {
        if t.0 & MEM_TABLE != 0 || self.memory || self.mem.row_get(t.0, key).is_some() {
            debug_assert!(t.0 & MEM_TABLE != 0 || btree::get(self, t.0, key)?.is_none(), "a memory row over a durable one");
            return Ok(self.mem.row_put(t.0, key, val));
        }
        btree::put(self, t.0, key, val, shred.on())
    }
    /// Removes; true if the key was present.
    pub fn table_remove(&mut self, t: Table, key: &[u8], shred: Shred) -> Result<bool, Error> {
        let removed = self.mem.row_remove(t.0, key);
        if t.0 & MEM_TABLE != 0 {
            return Ok(removed);
        }
        Ok(btree::remove(self, t.0, key, shred.on())? || removed)
    }
    /// Up to `limit` entries with `start <= key < end` in key order: a page of a stream (continue
    /// from the last key with a 0 byte appended).
    pub fn table_range(&mut self, t: Table, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<KeyValue>, Error> {
        let mem = crate::overlay::range(self.mem.o.tables.get(&t.0), start, end, limit);
        if t.0 & MEM_TABLE != 0 {
            return Ok(mem);
        }
        let durable = btree::range(self, t.0, start, end, limit)?;
        Ok(if mem.is_empty() { durable } else { crate::overlay::merge(mem, durable, limit) })
    }
    /// Every entry of a table holding rows in both layers.
    fn merged_all(&mut self, t: Table) -> Result<Vec<KeyValue>, Error> {
        self.table_range(t, b"", None, usize::MAX)
    }
    pub fn table_len(&mut self, t: Table) -> Result<u64, Error> {
        match self.pure(t) {
            Some(true) => Ok(self.mem.o.tables.get(&t.0).map_or(0, |r| r.len() as u64)),
            Some(false) => btree::len(self, t.0),
            None => Ok(self.merged_all(t)?.len() as u64),
        }
    }
    /// Number of keys below `key` (a position).
    pub fn table_rank(&mut self, t: Table, key: &[u8]) -> Result<u64, Error> {
        match self.pure(t) {
            Some(true) => Ok(self.mem.o.tables.get(&t.0).map_or(0, |r| r.range(..key.to_vec()).count() as u64)),
            Some(false) => btree::rank(self, t.0, key),
            None => Ok(self.merged_all(t)?.iter().filter(|(k, _)| k.as_slice() < key).count() as u64),
        }
    }
    /// The entry at position `i`.
    pub fn table_nth(&mut self, t: Table, i: u64) -> Result<Option<KeyValue>, Error> {
        match self.pure(t) {
            Some(true) => Ok(self.mem.o.tables.get(&t.0).and_then(|r| r.iter().nth(i as usize)).map(|(k, v)| (k.clone(), v.clone()))),
            Some(false) => btree::nth(self, t.0, i),
            None => Ok(self.merged_all(t)?.into_iter().nth(i as usize)),
        }
    }

    /// A rebuildable index table spanning aspects, created empty if absent (always durable: its
    /// memory rows are kept per row).
    pub fn index(&mut self, name: &[u8]) -> Result<Table, Error> {
        let key = named_key(kind::INDEX, name);
        if let Some(root) = u64_value(self.cat_get(&key)?)? {
            return Ok(Table(root));
        }
        let root = btree::create(self)?;
        self.cat_put_to(&key, W::new().u64(root).take(), Shred::No, false)?;
        Ok(Table(root))
    }

    /// Shreds every rebuildable index (a purge of anything they cover); returns their names.
    pub fn drop_indexes(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        let mut names = Vec::new();
        while let Some((k, v)) = self.cat_pop_prefix(&[kind::INDEX], Shred::Yes)? {
            let root = u64_value(Some(v))?.ok_or(Error::Corrupt("index"))?;
            self.drop_root(root)?;
            names.push(R::new(k.get(1..).unwrap_or_default()).bytes()?.to_vec());
        }
        Ok(names)
    }

    // Label wraps.

    pub fn put_wrap(&mut self, label: &LabelId, blob: &BlobId, wrap: &[u8]) -> Result<(), Error> {
        let key = W::new().u8(kind::WRAP).raw(&label.0).raw(&blob.0).take();
        self.cat_put(&key, wrap.to_vec(), Shred::No)
    }
    pub fn get_wrap(&mut self, label: &LabelId, blob: &BlobId) -> Result<Option<Vec<u8>>, Error> {
        self.cat_get(&W::new().u8(kind::WRAP).raw(&label.0).raw(&blob.0).take())
    }
    /// A label's wraps by blob ID, after `after` (exclusive).
    pub fn wraps(&mut self, label: &LabelId, after: Option<&BlobId>, limit: usize) -> Result<Vec<(BlobId, Vec<u8>)>, Error> {
        let prefix = W::new().u8(kind::WRAP).raw(&label.0).take();
        let from = after.map(|b| [&b.0[..], &[0]].concat()).unwrap_or_default();
        self.cat_scan(&prefix, &from, limit)?.into_iter().map(|(k, v)| Ok((BlobId(tail(&k)?), v))).collect()
    }
    /// Removes a wrap, shredded: its page is rewritten under a fresh key.
    pub fn drop_wrap(&mut self, label: &LabelId, blob: &BlobId) -> Result<bool, Error> {
        self.cat_remove(&W::new().u8(kind::WRAP).raw(&label.0).raw(&blob.0).take(), Shred::Yes)
    }

    // Actor secrets.

    pub fn put_secrets(&mut self, actor: &Tid, bytes: &[u8], shred: Shred) -> Result<(), Error> {
        self.cat_put(&W::new().u8(kind::SECRETS).raw(actor.as_bytes()).take(), bytes.to_vec(), shred)
    }
    pub fn get_secrets(&mut self, actor: &Tid) -> Result<Option<Vec<u8>>, Error> {
        self.cat_get(&W::new().u8(kind::SECRETS).raw(actor.as_bytes()).take())
    }
    /// Drops an actor's secrets, shredded.
    pub fn drop_actor_secrets(&mut self, actor: &Tid) -> Result<bool, Error> {
        self.cat_remove(&W::new().u8(kind::SECRETS).raw(actor.as_bytes()).take(), Shred::Yes)
    }

    // Cursors and logs (blob IDs gained, diagnostics).

    pub fn put_cursor(&mut self, name: &[u8], bytes: &[u8]) -> Result<(), Error> {
        self.cat_put(&named_key(kind::CURSOR, name), bytes.to_vec(), Shred::No)
    }
    pub fn get_cursor(&mut self, name: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.cat_get(&named_key(kind::CURSOR, name))
    }
    pub fn remove_cursor(&mut self, name: &[u8]) -> Result<bool, Error> {
        self.cat_remove(&named_key(kind::CURSOR, name), Shred::No)
    }

    /// Appends to log `name`; returns the entry's sequence number (from 0).
    pub fn log_append(&mut self, name: &[u8], bytes: &[u8]) -> Result<u64, Error> {
        let head = named_key(kind::LOG_HEAD, name);
        let seq = u64_value(self.cat_get(&head)?)?.unwrap_or(0);
        self.cat_put(&head, W::new().u64(seq + 1).take(), Shred::No)?;
        let key = [named_key(kind::LOG, name), seq.to_be_bytes().to_vec()].concat();
        self.cat_put(&key, bytes.to_vec(), Shred::No)?;
        Ok(seq)
    }
    /// Entries of log `name` from sequence `from` on.
    pub fn log_scan(&mut self, name: &[u8], from: u64, limit: usize) -> Result<Vec<(u64, Vec<u8>)>, Error> {
        self.cat_scan(&named_key(kind::LOG, name), &from.to_be_bytes(), limit)?
            .into_iter()
            .map(|(k, v)| Ok((u64::from_be_bytes(tail(&k)?), v)))
            .collect()
    }
    /// Removes entries below sequence `before`.
    pub fn log_truncate(&mut self, name: &[u8], before: u64) -> Result<(), Error> {
        let prefix = named_key(kind::LOG, name);
        loop {
            let page = self.cat_scan(&prefix, b"", 256)?;
            let mut done = page.is_empty();
            for (k, _) in page {
                if u64::from_be_bytes(tail(&k)?) >= before {
                    done = true;
                    break;
                }
                self.cat_remove(&k, Shred::No)?;
            }
            if done {
                return Ok(());
            }
        }
    }

    // Counters per (aspect, this node).

    /// The next unused node-form counter of this node in the aspect (from 1).
    pub fn counter(&mut self, tid: &Tid, ak: &Ak) -> Result<u64, Error> {
        Ok(u64_value(self.cat_get(&aspect_key(kind::COUNTER, tid, ak))?)?.unwrap_or(1))
    }
    /// Reserves `n` counters; returns the first. Commit this transaction before signing a commit
    /// that uses them (spec/crdt.md §2.3).
    pub fn reserve_counters(&mut self, tid: &Tid, ak: &Ak, n: u64) -> Result<u64, Error> {
        let first = self.counter(tid, ak)?;
        let next = first.checked_add(n).ok_or(Error::Misuse("counter overflow"))?;
        let m = self.aspect_mem(tid, ak);
        self.cat_put_to(&aspect_key(kind::COUNTER, tid, ak), W::new().u64(next).take(), Shred::No, m)?;
        Ok(first)
    }

    // Pending and parked commits.

    /// Stores a commit not yet applied, as bytes (header and blob).
    pub fn put_pending(&mut self, id: &CommitId, k: PendingKind, bytes: &[u8]) -> Result<(), Error> {
        let tag = match k {
            PendingKind::Pending => 0,
            PendingKind::Parked => 1,
        };
        let v = W::new().u8(tag).raw(bytes).take();
        self.cat_put(&W::new().u8(kind::PENDING).raw(&id.0).take(), v, Shred::No)
    }
    pub fn get_pending(&mut self, id: &CommitId) -> Result<Option<(PendingKind, Vec<u8>)>, Error> {
        self.cat_get(&W::new().u8(kind::PENDING).raw(&id.0).take())?.map(|v| decode_pending(&v)).transpose()
    }
    /// Pending and parked commits by ID, after `after` (exclusive).
    pub fn pending(&mut self, after: Option<&CommitId>, limit: usize) -> Result<Vec<(CommitId, PendingKind, Vec<u8>)>, Error> {
        let from = after.map(|c| [&c.0[..], &[0]].concat()).unwrap_or_default();
        self.cat_scan(&[kind::PENDING], &from, limit)?
            .into_iter()
            .map(|(k, v)| {
                let (pk, b) = decode_pending(&v)?;
                Ok((CommitId(tail(&k)?), pk, b))
            })
            .collect()
    }
    /// Removes a pending commit; `Shred::Yes` when its content is being purged rather than applied.
    pub fn remove_pending(&mut self, id: &CommitId, shred: Shred) -> Result<bool, Error> {
        self.cat_remove(&W::new().u8(kind::PENDING).raw(&id.0).take(), shred)
    }

    // Node-local records with no dedicated kind.

    pub fn put_local(&mut self, key: &[u8], val: &[u8], shred: Shred) -> Result<(), Error> {
        self.cat_put(&[&[kind::LOCAL], key].concat(), val.to_vec(), shred)
    }
    pub fn get_local(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.cat_get(&[&[kind::LOCAL], key].concat())
    }
    pub fn remove_local(&mut self, key: &[u8], shred: Shred) -> Result<bool, Error> {
        self.cat_remove(&[&[kind::LOCAL], key].concat(), shred)
    }
    /// Local records with keys starting with `prefix`, from `prefix || from` on.
    pub fn scan_local(&mut self, prefix: &[u8], from: &[u8], limit: usize) -> Result<Vec<KeyValue>, Error> {
        let p = [&[kind::LOCAL], prefix].concat();
        Ok(self.cat_scan(&p, from, limit)?.into_iter().map(|(k, v)| (k.get(1..).unwrap_or_default().to_vec(), v)).collect())
    }

    // Blob ciphertexts (already opaque; deleted for space).

    /// Stores a blob: in memory in memory mode.
    pub fn put_blob(&mut self, id: &BlobId, ciphertext: Vec<u8>) -> Result<(), Error> {
        if self.memory {
            self.mem.blob_put(*id, ciphertext);
            return Ok(());
        }
        self.pager.txn_put_blob(&mut self.d, *id, ciphertext, &mut *self.rng)
    }
    pub fn delete_blob(&mut self, id: &BlobId) {
        self.mem.blob_remove(id);
        self.pager.txn_delete_blob(&mut self.d, *id);
    }
    pub fn get_blob(&mut self, id: &BlobId) -> Result<Option<Vec<u8>>, Error> {
        self.read_blob(id, 0, usize::MAX)
    }
    /// Bytes `offset..offset+len` of a blob (streaming reads of large blobs).
    pub fn read_blob(&mut self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, Error> {
        if let Some(b) = self.mem.o.blobs.get(id) {
            let start = usize::try_from(offset).unwrap_or(usize::MAX).min(b.len());
            return Ok(b.get(start..start.saturating_add(len).min(b.len())).map(<[u8]>::to_vec));
        }
        self.pager.txn_get_blob(&self.d, id, offset, len)
    }
}

fn decode_deaths(b: &[u8]) -> Result<Deaths, Error> {
    let mut r = R::new(b);
    let ts = |n: u64| Ts::from_u64(n).ok_or(Error::Corrupt("death"));
    let d = Deaths { first: ts(r.u64()?)?, last: ts(r.u64()?)? };
    r.end()?;
    Ok(d)
}

fn decode_pending(v: &[u8]) -> Result<(PendingKind, Vec<u8>), Error> {
    let (tag, b) = v.split_first().ok_or(Error::Corrupt("pending"))?;
    let k = match tag {
        0 => PendingKind::Pending,
        1 => PendingKind::Parked,
        _ => return Err(Error::Corrupt("pending")),
    };
    Ok((k, b.to_vec()))
}

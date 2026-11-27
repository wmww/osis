//! `Store` and `Transaction`: the typed unit API node uses (notes/local-store.md, Units). One
//! catalog table maps typed keys to small records and to the roots of further tables; every
//! table page is an encrypted unit. All writes of a transaction commit together or not at all
//! (spec/commits.md §4); drop a transaction to abort it. A savepoint (`Transaction::savepoint`)
//! lets a caller undo part of a transaction and go on.

use crate::backend::Backend;
use crate::btree::{self, Units};
use crate::codec::{R, W};
use crate::overlay::{MEM_TABLE, MemTxn, Overlay};
use crate::pager::{Dirty, DirtyMark, Pager, StoreConfig};
use crate::root::RootStorage;
use crate::{Error, KeyValue};
use osis_base::memo::{StampKey, Stamps};
use osis_base::{Ak, BlobId, CommitId, Tid};
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

thread_local! {
    static HANDED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Counts `n` bytes of durable rows (key and value; a removal its key) or blobs handed to a
/// store on this thread (`bytes_handed`).
fn written(n: usize) {
    HANDED.with(|h| h.set(h.get() + n as u64));
}

/// Bytes of durable rows (key and value; a removal its key) and blobs handed to stores on this
/// thread so far: what operations asked them to write, before paging into units, whose bytes move
/// by a whole unit wherever a key lands (scale tests count this at two sizes).
pub fn bytes_handed() -> u64 {
    HANDED.with(std::cell::Cell::get)
}

/// A table: an ordered byte map paged into units (a large aspect state, its indexes), and the
/// catalog row it belongs to (its aspect's unit, an index's name), whose stamp its rows share
/// (`Stamping`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Table(u64, Owner);

/// A small aspect's state: one record, encodings the node's. A large state keeps its elements
/// and indexes in the aspect's tables.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AspectUnit {
    pub state: Vec<u8>,
}

/// A commit not applied yet (spec/commits.md §4) or parked (spec/versioning.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingKind {
    Pending,
    Parked,
}

/// A stored pending or parked commit: its bytes (header and blob) and the kept verdict on their
/// signature, if one was reached (the engine's `osis_commit::Signed`): this node's own, never a peer's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub kind: PendingKind,
    pub verdict: Option<[u8; 32]>,
    /// When the commit first arrived (ms): its receipt (spec/permissions.md §5.1 Received).
    pub received: u64,
    pub bytes: Vec<u8>,
}

/// Catalog rows a paged scan reads at a time.
pub(crate) const PAGE: usize = 256;

/// Catalog key kinds.
pub(crate) mod kind {
    pub const ASPECT: u8 = 1;
    pub const TABLE: u8 = 3;
    pub const LOG: u8 = 7;
    pub const RECORD: u8 = 8;
    pub const COUNTER: u8 = 9;
    pub const PENDING: u8 = 10;
    pub const INDEX: u8 = 11;
    pub const LOCAL: u8 = 12;
    pub const CHANGED: u8 = 13;
    /// No catalog row: the stamps of blob ciphertexts' presence (`blob_key`).
    pub const BLOB: u8 = 14;
}

/// The stamp key of blob `id`'s presence: a blob held or not moves what read it (its length,
/// its bytes) as a row does.
fn blob_key(id: &BlobId) -> [u8; 33] {
    let mut k = [kind::BLOB; 33];
    k[1..].copy_from_slice(&id.0);
    k
}

fn aspect_key(k: u8, tid: &Tid, ak: &Ak) -> Vec<u8> {
    let a = ak.as_str().as_bytes();
    W::new().u8(k).raw(tid.as_bytes()).u32(a.len() as u32).raw(a).take()
}

/// The `(tid, ak)` of an `aspect_key`.
fn aspect_of_key(k: &[u8]) -> Result<(Tid, Ak), Error> {
    let mut r = R::new(k.get(1..).unwrap_or_default());
    let tid = Tid::from_bytes(r.array()?);
    let n = r.u32()? as usize;
    let ak = std::str::from_utf8(r.raw(n)?).ok().and_then(|a| Ak::new(a).ok()).ok_or(Error::Corrupt("aspect key"))?;
    r.end()?;
    Ok((tid, ak))
}

/// A session's counter row: the aspect key with the session's nonce (an open's sessions share
/// an aspect without sharing counters).
fn counter_key(tid: &Tid, ak: &Ak, nonce: &[u8]) -> Vec<u8> {
    let mut k = aspect_key(kind::COUNTER, tid, ak);
    k.extend_from_slice(nonce);
    k
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

pub(crate) fn tail<const N: usize>(key: &[u8]) -> Result<[u8; N], Error> {
    key.last_chunk().copied().ok_or(Error::Corrupt("catalog key"))
}

/// The encrypted local store, with its memory overlay (`crate::overlay`): rows of the memory
/// class, lost when the store is dropped.
pub struct Store {
    pager: Pager,
    mem: Overlay,
    stamping: Stamping,
}

/// The store's change stamps (`osis_base::memo`): what a memo reading the store depends on.
/// A catalog row is stamped by its key (a scan by its prefix), a table's rows as the catalog row
/// owning the table (`Table`). A transaction stamps each row it writes, and again each it undoes
/// (a savepoint rolled back, an abort), so a memo that read a row written and then undone moves.
/// The rows are stamped in families, a stamp table each (by catalog kind; a local or peer record
/// row by its key's next byte as well): a memo's debug comparison runs again when a table it read changed
/// (`osis_base::memo`, Checks), so one table for the whole store would compare every memo reading
/// it at nearly every transaction.
#[derive(Clone)]
struct Stamping {
    families: Vec<Stamps>,
    /// Moved by every change of a row: counts them (`Store::row_changes`). Read by no memo.
    all: Stamps,
    /// What the open or suspended transaction wrote, in order: stamped again if it is undone.
    log: Vec<Logged>,
}

/// Stamp tables: one per catalog kind (kinds are below `KINDS`), then one per byte after the kind
/// of a local row's key, then of a peer record row's (`record.rs`: its LRU rows move at every use
/// of a record, and a removal moves what read an absent row of the same table, so they share no
/// table with the module rows sync judges by).
const KINDS: usize = 16;

/// The kinds stamped per their key's next byte, each with the first of its 256 tables.
fn split(k: u8) -> Option<usize> {
    match k {
        kind::LOCAL => Some(KINDS),
        kind::RECORD => Some(KINDS + 256),
        _ => None,
    }
}

impl Default for Stamping {
    fn default() -> Stamping {
        // each family named by its kind and key byte (`Effects` causes), made once per process
        static NAMES: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
        let names = NAMES.get_or_init(|| {
            let name = |i: usize| match i {
                i if i == usize::from(kind::BLOB) => "store: blobs".to_string(),
                i if i < KINDS => format!("store: catalog kind {i}"),
                i if i < KINDS + 256 => format!("store: local rows {:#04x}", i - KINDS),
                i => format!("store: record rows {:#04x}", i - KINDS - 256),
            };
            (0..KINDS + 512).map(|i| &*Box::leak(name(i).into_boxed_str())).collect()
        });
        Stamping { families: names.iter().map(|n| Stamps::named(n)).collect(), all: Stamps::named("store: catalog"), log: Vec::new() }
    }
}

/// The family of catalog key (or prefix) `key`: `None` for a prefix naming no single family (a
/// split kind alone, `split`).
fn family(key: &[u8]) -> Option<usize> {
    match key {
        [k, rest @ ..] => match split(*k) {
            Some(first) => rest.first().map(|b| first + usize::from(*b)),
            None => Some(usize::from(*k) % KINDS),
        },
        [] => None,
    }
}

/// The catalog row owning a table: its family and stamp key. A table's rows are stamped in its
/// owner's family as the owner's key bytes then the row's key (`row_key`), so a read of a row, or
/// of a range sharing a prefix, moves with the writes there alone; a read of the table whole (its
/// length, a rank, an open range) reads the owner, which every write of a row moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Owner(usize, StampKey);

impl Owner {
    /// The stamp bytes of row `key` of the table.
    fn row_key(&self, key: &[u8]) -> Vec<u8> {
        [self.1.bytes().as_slice(), key].concat()
    }
}

#[derive(Clone)]
enum Logged {
    Row(Vec<u8>),
    TableRow(Owner, Vec<u8>),
}

impl Stamping {
    fn table(&self, f: usize) -> Option<&Stamps> {
        self.families.get(f)
    }
    fn read(&self, key: &[u8]) {
        if let Some(t) = family(key).and_then(|f| self.table(f)) {
            t.read(key);
        }
    }
    fn read_prefix(&self, p: &[u8]) {
        match family(p) {
            Some(f) => {
                if let Some(t) = self.table(f) {
                    t.read_prefix(p);
                }
            }
            // a split kind alone reads its 256 tables; the empty prefix, every table
            None => {
                let (from, n) = p.first().and_then(|k| split(*k)).map_or((0, self.families.len()), |f| (f, 256));
                self.families.iter().skip(from).take(n).for_each(|t| t.read_prefix(p))
            }
        }
    }
    fn stamp(&self, key: &[u8]) -> u64 {
        family(key).and_then(|f| self.table(f)).map_or(0, |t| t.stamp(key))
    }
    /// Row `key` of `o`'s table is read, or (`prefix`) every row starting with it.
    fn read_table_rows(&self, o: Owner, key: &[u8], prefix: bool) {
        if let Some(t) = self.table(o.0) {
            match prefix {
                true => t.read_prefix(&o.row_key(key)),
                false => t.read(&o.row_key(key)[..]),
            }
        }
    }
    fn read_owner(&self, o: Owner) {
        if let Some(t) = self.table(o.0) {
            t.read_key(o.1);
        }
    }
    fn stamp_row(&self, key: &[u8], present: bool) {
        if let Some(t) = family(key).and_then(|f| self.table(f)) {
            t.wrote_bytes(key, present);
        }
        self.all.moved();
    }
    fn stamp_owner(&self, o: Owner, present: bool) {
        if let Some(t) = self.table(o.0) {
            t.wrote_key(o.1, present);
        }
        self.all.moved();
    }
    fn row(&mut self, key: &[u8], present: bool) {
        self.stamp_row(key, present);
        self.log.push(Logged::Row(key.to_vec()));
    }
    /// Row `key` of `o`'s table was written: moves what read it, a prefix of it or the table whole.
    fn table_row(&mut self, o: Owner, key: &[u8], present: bool) {
        self.stamp_table_row(o, key, present);
        self.log.push(Logged::TableRow(o, key.to_vec()));
    }
    fn stamp_table_row(&self, o: Owner, key: &[u8], present: bool) {
        if let Some(t) = self.table(o.0) {
            t.wrote_bytes(&o.row_key(key), present);
        }
        self.stamp_owner(o, true);
    }
    /// Stamps again what was written after the first `len` of the log, and forgets it. Each is
    /// stamped as removed, whether the undo leaves it there or not: a removal moves the key and
    /// keeps no stamp of its own for it (a row there reads at its bucket's), so a row created and
    /// undone leaves no stamp behind.
    fn undo_to(&mut self, len: usize) {
        osis_base::memo::undoing(|| {
            let undone = self.log.split_off(len.min(self.log.len()));
            for l in undone {
                match l {
                    Logged::Row(k) => self.stamp_row(&k, false),
                    Logged::TableRow(o, k) => {
                        self.stamp_table_row(o, &k, false);
                        self.stamp_owner(o, false);
                    }
                }
            }
        })
    }
}

/// A transaction's hold on `Stamping`: undone on drop unless done (committed, or suspended with
/// its log kept in the store for the transaction that resumes it).
struct StampTxn<'a> {
    s: &'a mut Stamping,
    done: bool,
}

impl Drop for StampTxn<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.s.undo_to(0);
        }
    }
}

/// The stamps of a table owned by catalog row `key`: in its family, apart from the row's own
/// stamp, so a write of a table row moves no read of the catalog row (a table's handle).
fn owner(key: &[u8]) -> Owner {
    Owner(family(key).unwrap_or(0), Stamps::key(&(b"table", key)))
}

impl Store {
    /// Creates an empty store over an empty backend and an empty root storage.
    pub fn create(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, cfg: StoreConfig, rng: &mut dyn CryptoRngCore) -> Result<Store, Error> {
        Ok(Store { pager: Pager::create(backend, root, cfg, btree::empty_page(), rng)?, mem: Overlay::default(), stamping: Stamping::default() })
    }

    /// Opens a store, finishing or rolling back a commit a crash interrupted.
    pub fn open(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, cfg: StoreConfig) -> Result<Store, Error> {
        let pager = Pager::open(backend, root, cfg)?;
        if pager.meta().catalog == u64::MAX {
            return Err(Error::NoStore);
        }
        Ok(Store { pager, mem: Overlay::default(), stamping: Stamping::default() })
    }

    /// Opens the store held by `root`, or creates one when `root` holds none.
    pub fn open_or_create(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, cfg: StoreConfig, rng: &mut dyn CryptoRngCore) -> Result<Store, Error> {
        match root.load().map_err(Error::Root)? {
            Some(_) => Store::open(backend, root, cfg),
            None => Store::create(backend, root, cfg, rng),
        }
    }

    /// Tests only: an exact copy of this store, its caches, memory overlay and versions as they
    /// stand, over test copies of its backend and root (`Backend::test_copy_boxed`), inside a
    /// world copy (`osis_base::copying`). Never in a product: the copy continues this store's key
    /// versions and its node's session, so two live copies reuse them.
    #[doc(hidden)]
    pub fn test_copy(&self) -> Result<Store, Error> {
        osis_base::copying::copying(|| Ok(Store { pager: self.pager.test_copy()?, mem: self.mem.clone(), stamping: self.stamping.clone() }))
    }

    /// Bytes the memory overlay holds (its rows and blobs, at an estimate of their cost held:
    /// `MEM_ROW_COST`): O(rows).
    pub fn memory_held(&self) -> u64 {
        self.mem.held()
    }

    /// The store with its rows' stamps undoable (`memo::Stamps::undoable`): for a store whose
    /// writes inside a `memo::Undoable` stretch all go to one transaction of it, aborted when the
    /// stretch is undone (the engine's own store, `Engine::run`). Not the sync store: the
    /// engine's memory holds commit to its memory part at once.
    pub fn undoable(mut self) -> Store {
        self.stamping.families = std::mem::take(&mut self.stamping.families).into_iter().map(Stamps::undoable).collect();
        self
    }

    /// Counts the changes of the store's rows, each write and each undo (`Stamping`): equal at
    /// two times, no row changed between.
    pub fn row_changes(&self) -> osis_base::memo::Changes {
        self.stamping.all.counter()
    }

    /// Durable writes since the open (`Writes`).
    pub fn writes(&self) -> Writes {
        self.pager.writes()
    }

    /// Table pages decoded since the open (tests count work): a page is decoded once per write
    /// of its unit while the unit stays cached.
    pub fn pages_decoded(&self) -> u64 {
        self.pager.pages_decoded()
    }

    /// Starts a transaction; reads see its own writes. Drop it to abort. After a failed write the
    /// store first recovers in place as `open` would; after one whose outcome is unknown, at once
    /// and then after waits of 1 s doubling to 60 s while that fails (`Error::Broken` between).
    pub fn transaction<'a>(&'a mut self, rng: &'a mut dyn CryptoRngCore) -> Result<Transaction<'a>, Error> {
        // a suspended transaction not resumed is dropped: what it wrote is undone
        self.stamping.undo_to(0);
        let d = self.pager.begin()?;
        Ok(self.resume(Suspended { d }, rng))
    }

    /// Continues a transaction set aside by `Transaction::suspend`. No other transaction may
    /// start in between: `transaction` rolls back the spills of every uncommitted one.
    pub fn resume<'a>(&'a mut self, s: Suspended, rng: &'a mut dyn CryptoRngCore) -> Transaction<'a> {
        Transaction { pager: &mut self.pager, d: s.d, rng, mem: MemTxn { o: &mut self.mem, undo: Vec::new(), done: false }, memory: false, st: StampTxn { s: &mut self.stamping, done: false } }
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
    /// What the store holds, decrypted: every committed unit by slot and every memory-overlay
    /// row. Tests compare two stores with it.
    #[doc(hidden)]
    pub fn dump(&mut self) -> Result<Vec<(String, Vec<u8>)>, Error> {
        let mut out = Vec::new();
        for slot in 0..self.pager.meta().next_slot {
            if let Some(u) = self.pager.read(slot)? {
                out.push((format!("unit {slot}"), u));
            }
        }
        out.extend(self.mem.cat.iter().map(|(k, v)| (format!("memory catalog {k:02x?}"), v.clone())));
        for (t, rows) in &self.mem.tables {
            out.extend(rows.iter().map(|(k, v)| (format!("memory table {t} {k:02x?}"), v.clone())));
        }
        let mut blobs: Vec<_> = self.mem.blobs.iter().map(|(id, b)| (format!("memory blob {:02x?}", id.0), b.clone())).collect();
        blobs.sort();
        out.extend(blobs);
        Ok(out)
    }
    /// Every key the current tree yields. Shredding tests.
    #[doc(hidden)]
    pub fn forensic_keys(&mut self) -> Result<Vec<[u8; 32]>, Error> {
        self.pager.forensic_keys()
    }
}

/// A transaction set aside between calls (`Transaction::suspend`, `Store::resume`): the
/// blob area keeps one open across a batch of requests and commits it once. Dropped without
/// resuming, it aborts. It holds no memory-overlay rows (`suspend` refuses them).
pub struct Suspended {
    d: Dirty,
}

impl Suspended {
    /// Tests only: this transaction set aside, for the test copy of its store
    /// (`Store::test_copy`); resumed only on that copy.
    #[doc(hidden)]
    pub fn test_copy(&self) -> Suspended {
        Suspended { d: self.d.clone() }
    }
}

/// Durable writes of one open of a store: commits that landed, and failed writes (a commit, a
/// spill, a rollback), each of which the store recovered from, so an owner holding state beside
/// it in memory knows to read it again; a store taking commits again after one is working.
/// `unknown` counts the failures whose outcome was unknown (a sync failed): a commit answered
/// `Err` may then have landed after all, as the store reads it once it works again, so an owner
/// reads everything again, as an open does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Writes {
    pub committed: u64,
    pub failed: u64,
    pub unknown: u64,
}

/// A point in a transaction to undo back to (`Transaction::rollback_to`) or keep
/// (`Transaction::release`). Savepoints nest: the innermost open one goes first.
#[must_use = "a savepoint is released or rolled back"]
pub struct Savepoint {
    dirty: DirtyMark,
    mem: usize,
    stamped: usize,
    memory: bool,
}

/// A set of writes committed atomically. After one of its writes failed every method fails
/// `Error::Broken`; the next transaction recovers the store in place.
///
/// Rows go to the memory overlay or the durable store by class (notes/local-store.md, Memory
/// overlay): in memory mode (`set_memory`) every new row is memory; a row already held in memory
/// stays there; every row of a memory-class aspect (its key's `+` marker, spec/commits.md §2) is
/// memory. Reads see both, memory first; removals remove from both.
pub struct Transaction<'a> {
    pager: &'a mut Pager,
    d: Dirty,
    rng: &'a mut dyn CryptoRngCore,
    mem: MemTxn<'a>,
    memory: bool,
    st: StampTxn<'a>,
}

impl Units for Transaction<'_> {
    fn read(&mut self, slot: u64) -> Result<Option<Vec<u8>>, Error> {
        self.pager.txn_read(&self.d, slot)
    }
    fn write(&mut self, slot: u64, data: Vec<u8>, shred: bool) -> Result<(), Error> {
        self.pager.txn_write(&mut self.d, slot, data, shred, &mut *self.rng)
    }
    fn page(&mut self, slot: u64) -> Result<std::sync::Arc<crate::btree::Page>, Error> {
        self.pager.txn_page(&mut self.d, slot)
    }
    fn take_page(&mut self, slot: u64) -> Result<crate::btree::Page, Error> {
        self.pager.txn_take_page(&mut self.d, slot)
    }
    fn put_page(&mut self, slot: u64, page: crate::btree::Page, shred: bool) -> Result<(), Error> {
        self.pager.txn_put_page(&mut self.d, slot, page, shred, &mut *self.rng)
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
    /// The result is the outcome: a failed commit recovers the store in place as `open` would
    /// (finishing or rolling back) and reads whether it landed (a shredding commit whose root
    /// record was stored did: `Ok`); `Ok` is always durable. `Err` leaves the store as before the
    /// transaction and takes the next one; only if a backend sync failed, or recovering fails
    /// too, is the outcome unknown (`Writes::unknown`), and every call fails `Error::Broken`
    /// until the store recovers in place on its own (`Store::transaction`).
    pub fn commit(self) -> Result<(), Error> {
        if self.d.open_savepoints() > 0 {
            return Err(Error::Misuse("commit with a savepoint open"));
        }
        let Transaction { pager, d, rng, mut mem, mut st, .. } = self;
        // a failed commit leaves the store as before the transaction: its rows are undone
        pager.commit(d, rng)?;
        mem.done = true;
        st.done = true;
        st.s.log.clear();
        Ok(())
    }

    /// Whether this open of the store has drawn its node log incarnation (`pager::Meta`).
    pub(crate) fn log_drawn(&self) -> bool {
        self.d.meta.log_drawn
    }
    pub(crate) fn cfg(&self) -> &StoreConfig {
        self.pager.cfg()
    }

    pub(crate) fn set_log_drawn(&mut self) {
        self.d.meta.log_drawn = true;
    }

    /// Sets the transaction aside, uncommitted (`Store::resume`). In memory mode or holding
    /// memory-overlay rows it fails `Misuse` and aborts (a dropped `Suspended` could not undo them).
    pub fn suspend(self) -> Result<Suspended, Error> {
        if self.memory || !self.mem.undo.is_empty() {
            return Err(Error::Misuse("suspend with memory rows"));
        }
        if self.d.open_savepoints() > 0 {
            return Err(Error::Misuse("suspend with a savepoint open"));
        }
        let Transaction { d, mut mem, mut st, .. } = self;
        mem.done = true;
        st.done = true;
        Ok(Suspended { d })
    }

    /// Opens a savepoint: `rollback_to` it undoes every change made after this call (rows in
    /// both layers, blobs, memory mode) and nothing before it. Nothing spills to the backend while
    /// one is open, so a rollback is a memory operation that cannot fail.
    pub fn savepoint(&mut self) -> Savepoint {
        Savepoint { dirty: self.d.mark(), mem: self.mem.undo.len(), stamped: self.st.s.log.len(), memory: self.memory }
    }

    /// Closes `sp` keeping its changes (an outer savepoint can still undo them). The outermost
    /// release spills what waited, so it may fail as a write does.
    pub fn release(&mut self, sp: Savepoint) -> Result<(), Error> {
        self.d.release(sp.dirty);
        self.pager.spill_if_due(&mut self.d, &mut *self.rng)
    }

    /// Undoes every change made since `sp` was opened, and closes it.
    pub fn rollback_to(&mut self, sp: Savepoint) {
        self.d.rollback_to(sp.dirty);
        self.mem.rollback_to(sp.mem);
        self.st.s.undo_to(sp.stamped);
        self.memory = sp.memory;
    }

    /// A read of the unit and tables of aspect `(tid, ak)` answered from a copy the caller keeps
    /// of them (the engine's decoded states): a memo computing depends on them as on a read here.
    pub fn noted_aspect(&self, tid: &Tid, ak: &Ak) {
        let key = aspect_key(kind::ASPECT, tid, ak);
        self.st.s.read(&key[..]);
        self.st.s.read_owner(owner(&key));
    }

    /// `noted_aspect` of local record `key` (the engine's decoded commit records).
    pub fn noted_local(&self, key: &[u8]) {
        self.st.s.read(&[&[kind::LOCAL], key].concat()[..]);
    }

    /// Local record `key`'s change stamp (`osis_base::memo::Stamps::stamp`), read by no memo:
    /// equal at two times, the record was not written, removed or undone between (the engine's
    /// decoded commit records check themselves by it).
    pub fn local_stamp(&self, key: &[u8]) -> u64 {
        self.st.s.stamp(&[&[kind::LOCAL], key].concat()[..])
    }

    /// Whether this transaction changed anything (rows in either layer, blobs).
    pub fn wrote(&self) -> bool {
        !self.d.is_empty() || !self.mem.undo.is_empty()
    }

    /// Memory mode: new rows go to the memory overlay (a memory commit's application).
    pub fn set_memory(&mut self, on: bool) {
        self.memory = on;
    }
    pub fn is_memory(&self) -> bool {
        self.memory
    }
    /// Whether rows of aspect `ak` written now go to memory. In memory mode an unmarked key's
    /// rows go there too: only a writer breaking the marker rule (tests) makes one.
    fn aspect_mem(&self, ak: &Ak) -> bool {
        self.memory || ak.ephemeral()
    }

    pub(crate) fn rng(&mut self) -> &mut dyn CryptoRngCore {
        &mut *self.rng
    }

    fn catalog(&self) -> u64 {
        self.d.meta.catalog
    }
    pub(crate) fn cat_get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        osis_base::costs::count_scoped("store rows read", 1);
        self.st.s.read(key);
        if let Some(v) = self.mem.o.cat.get(key) {
            return Ok(Some(v.clone()));
        }
        self.durable_get(key)
    }
    /// A catalog row to memory when `mem` or already there, else to the durable store.
    pub(crate) fn cat_put_to(&mut self, key: &[u8], val: Vec<u8>, shred: Shred, mem: bool) -> Result<(), Error> {
        // the same bytes again change nothing: no reader moves
        let same = match self.mem.o.cat.get(key) {
            Some(v) => *v == val,
            None => self.durable_get(key)?.is_some_and(|v| v == val),
        };
        if same {
            return Ok(());
        }
        osis_base::costs::count_scoped("store rows written", 1);
        self.st.s.row(key, true);
        if mem || self.mem.o.cat.contains_key(key) {
            debug_assert!(self.durable_get(key)?.is_none(), "a memory row over a durable one");
            self.mem.cat_put(key, val);
            return Ok(());
        }
        let c = self.catalog();
        written(key.len() + val.len());
        btree::put(self, c, key, val, shred.on()).map(|_| ())
    }
    fn durable_get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let c = self.catalog();
        btree::get(self, c, key)
    }
    pub(crate) fn cat_remove(&mut self, key: &[u8], shred: Shred) -> Result<bool, Error> {
        let removed = self.mem.cat_remove(key);
        let c = self.catalog();
        let durable = btree::remove(self, c, key, shred.on())?;
        if durable {
            written(key.len());
        }
        let removed = durable || removed;
        // removing an absent row changes nothing: no reader moves
        if removed {
            osis_base::costs::count_scoped("store rows written", 1);
            self.st.s.row(key, false);
        }
        Ok(removed)
    }
    /// The catalog keys under `prefix`, in order: no value is read.
    fn cat_keys(&mut self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        self.st.s.read_prefix(prefix);
        let mem: Vec<KeyValue> = self.mem.o.cat.range(prefix.to_vec()..).take_while(|(k, _)| k.starts_with(prefix)).map(|(k, _)| (k.clone(), Vec::new())).collect();
        let c = self.catalog();
        let durable = btree::keys(self, c, prefix, crate::backend::prefix_end(prefix).as_deref(), usize::MAX)?;
        let rows = crate::overlay::merge(mem, durable, usize::MAX, false);
        osis_base::costs::count_scoped("store rows read", rows.len() as u64 + 1);
        Ok(rows.into_iter().map(|r| r.0).collect())
    }
    /// Catalog entries under `prefix`, from `prefix || from` on.
    pub(crate) fn cat_scan(&mut self, prefix: &[u8], from: &[u8], limit: usize) -> Result<Vec<KeyValue>, Error> {
        self.st.s.read_prefix(prefix);
        self.cat_range(prefix, from, crate::backend::prefix_end(prefix), limit)
    }
    /// Whether some catalog key under `prefix` passes `exact` (given the key after the prefix).
    /// Read by its witness: the first such key alone, so another coming or going moves nothing
    /// while it stands; with none, the prefix (anything coming under it).
    pub(crate) fn cat_any(&mut self, prefix: &[u8], exact: impl Fn(&[u8]) -> bool) -> Result<bool, Error> {
        let mut from = Vec::new();
        loop {
            let rows = self.cat_range(prefix, &from, crate::backend::prefix_end(prefix), PAGE)?;
            let n = rows.len();
            for (k, _) in rows {
                let rest = k.get(prefix.len()..).unwrap_or_default();
                if exact(rest) {
                    self.st.s.read(&k);
                    return Ok(true);
                }
                from = [rest, &[0]].concat();
            }
            if n < PAGE {
                self.st.s.read_prefix(prefix);
                return Ok(false);
            }
        }
    }
    /// Catalog entries under `prefix` below `end`, read as a scan of the prefix.
    pub(crate) fn cat_scan_to(&mut self, prefix: &[u8], end: Vec<u8>, limit: usize) -> Result<Vec<KeyValue>, Error> {
        self.st.s.read_prefix(prefix);
        self.cat_range(prefix, b"", Some(end), limit)
    }
    /// Catalog entries under `prefix` from `prefix || from` up to `end` (exclusive; none: the
    /// catalog's end), read by no memo.
    fn cat_range(&mut self, prefix: &[u8], from: &[u8], end: Option<Vec<u8>>, limit: usize) -> Result<Vec<KeyValue>, Error> {
        let c = self.catalog();
        let start = [prefix, from].concat();
        let mem = crate::overlay::range(Some(&self.mem.o.cat), &start, end.as_deref(), limit, false);
        let durable = btree::range(self, c, &start, end.as_deref(), limit, false)?;
        let rows = crate::overlay::merge(mem, durable, limit, false);
        // a scan costs a seek and its rows: what scale tests count (`osis_base::costs`)
        osis_base::costs::count_scoped("store rows read", rows.len() as u64 + 1);
        Ok(rows)
    }
    /// Runs `f` on every catalog entry under `prefix` in key order, reading a page at a time;
    /// `f` may remove the entry it is given.
    pub(crate) fn cat_each(&mut self, prefix: &[u8], mut f: impl FnMut(&mut Self, Vec<u8>, Vec<u8>) -> Result<(), Error>) -> Result<(), Error> {
        let mut from = Vec::new();
        loop {
            let rows = self.cat_scan(prefix, &from, PAGE)?;
            let n = rows.len();
            for (k, v) in rows {
                from = [k.get(prefix.len()..).unwrap_or_default(), &[0]].concat();
                f(self, k, v)?;
            }
            if n < PAGE {
                return Ok(());
            }
        }
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
        let u = AspectUnit { state: r.bytes()?.to_vec() };
        r.end()?;
        Ok(Some(u))
    }

    /// Writes an aspect's unit. `Shred::Yes` when the rewrite drops content that must not be
    /// recoverable (a dropped body's writes).
    pub fn put_aspect(&mut self, tid: &Tid, ak: &Ak, unit: &AspectUnit, shred: Shred) -> Result<(), Error> {
        if u32::try_from(unit.state.len()).is_err() {
            return Err(Error::Misuse("aspect unit field above 4 GiB"));
        }
        let v = W::new().bytes(&unit.state).take();
        let m = self.aspect_mem(ak);
        self.cat_put_to(&aspect_key(kind::ASPECT, tid, ak), v, shred, m)
    }

    /// Removes an aspect's unit (its state went); its tables and counters stay.
    pub fn remove_aspect(&mut self, tid: &Tid, ak: &Ak, shred: Shred) -> Result<(), Error> {
        self.cat_remove(&aspect_key(kind::ASPECT, tid, ak), shred).map(drop)
    }

    /// The AKs of `tid`'s aspect units, in key order: keys alone are read, no state.
    pub fn aspects_of(&mut self, tid: &Tid) -> Result<Vec<Ak>, Error> {
        let p = W::new().u8(kind::ASPECT).raw(tid.as_bytes()).take();
        self.cat_keys(&p)?.iter().map(|k| Ok(aspect_of_key(k)?.1)).collect()
    }

    /// Every aspect unit as `(tid, ak)`, in key order: keys alone are read, no state.
    pub fn all_aspects(&mut self) -> Result<Vec<(Tid, Ak)>, Error> {
        self.cat_keys(&[kind::ASPECT])?.iter().map(|k| aspect_of_key(k)).collect()
    }

    /// Drops an aspect's unit and tables, shredded (a whole-aspect purge). Its
    /// counters stay: a session never takes a counter twice.
    pub fn drop_aspect(&mut self, tid: &Tid, ak: &Ak) -> Result<(), Error> {
        self.cat_remove(&aspect_key(kind::ASPECT, tid, ak), Shred::Yes)?;
        let o = owner(&aspect_key(kind::ASPECT, tid, ak));
        while let Some((_, v)) = self.cat_pop_prefix(&aspect_key(kind::TABLE, tid, ak), Shred::Yes)? {
            let root = u64_value(Some(v))?.ok_or(Error::Corrupt("table"))?;
            self.drop_rows(Table(root, o))?;
        }

        Ok(())
    }

    /// Drops table `t` whole, each row stamped as removed: what read a row, a range or the table
    /// moves, as at the row's own removal (work in proportion to what is dropped).
    fn drop_rows(&mut self, t: Table) -> Result<(), Error> {
        for (k, _) in self.table_range(t, b"", None, usize::MAX)? {
            self.st.s.table_row(t.1, &k, false);
        }
        self.mem.drop_rows(t.0);
        if t.0 & MEM_TABLE == 0 {
            btree::drop_all(self, t.0, true)?;
        }
        Ok(())
    }

    // Tables (paged large state and its indexes).

    /// Table `idx` of an aspect, if created.
    pub fn table(&mut self, tid: &Tid, ak: &Ak, idx: u8) -> Result<Option<Table>, Error> {
        let key = [aspect_key(kind::TABLE, tid, ak), vec![idx]].concat();
        let of = owner(&aspect_key(kind::ASPECT, tid, ak));
        Ok(u64_value(self.cat_get(&key)?)?.map(|root| Table(root, of)))
    }

    /// Table `idx` of an aspect, created empty if absent.
    pub fn create_table(&mut self, tid: &Tid, ak: &Ak, idx: u8) -> Result<Table, Error> {
        if let Some(t) = self.table(tid, ak, idx)? {
            return Ok(t);
        }
        let m = self.aspect_mem(ak);
        let root = if m { self.mem.new_table() } else { btree::create(self)? };
        let key = [aspect_key(kind::TABLE, tid, ak), vec![idx]].concat();
        self.cat_put_to(&key, W::new().u64(root).take(), Shred::No, m)?;
        Ok(Table(root, owner(&aspect_key(kind::ASPECT, tid, ak))))
    }

    /// Drops one table of an aspect, shredded.
    pub fn drop_table(&mut self, tid: &Tid, ak: &Ak, idx: u8) -> Result<(), Error> {
        let Some(t) = self.table(tid, ak, idx)? else { return Ok(()) };
        self.cat_remove(&[aspect_key(kind::TABLE, tid, ak), vec![idx]].concat(), Shred::Yes)?;
        self.drop_rows(t)
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
        self.st.s.read_table_rows(t.1, key, false);
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
        self.st.s.table_row(t.1, key, true);
        if t.0 & MEM_TABLE != 0 || self.memory || self.mem.row_get(t.0, key).is_some() {
            debug_assert!(t.0 & MEM_TABLE != 0 || btree::get(self, t.0, key)?.is_none(), "a memory row over a durable one");
            return Ok(self.mem.row_put(t.0, key, val));
        }
        written(key.len() + val.len());
        btree::put(self, t.0, key, val, shred.on())
    }
    /// Removes; true if the key was present.
    pub fn table_remove(&mut self, t: Table, key: &[u8], shred: Shred) -> Result<bool, Error> {
        self.st.s.table_row(t.1, key, false);
        let removed = self.mem.row_remove(t.0, key);
        if t.0 & MEM_TABLE != 0 {
            return Ok(removed);
        }
        let gone = btree::remove(self, t.0, key, shred.on())?;
        if gone {
            written(key.len());
        }
        Ok(gone || removed)
    }
    /// Up to `limit` entries with `start <= key < end` in key order: a page of a stream (continue
    /// from the last key with a 0 byte appended).
    pub fn table_range(&mut self, t: Table, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<KeyValue>, Error> {
        self.table_rows(t, start, end, limit, false)
    }
    /// Up to `limit` entries with `start <= key < end`, greatest key first.
    pub fn table_range_rev(&mut self, t: Table, start: &[u8], end: &[u8], limit: usize) -> Result<Vec<KeyValue>, Error> {
        self.table_rows(t, start, Some(end), limit, true)
    }
    fn table_rows(&mut self, t: Table, start: &[u8], end: Option<&[u8]>, limit: usize, rev: bool) -> Result<Vec<KeyValue>, Error> {
        // every key in [start, end) starts with what start and end share
        match end {
            Some(end) => {
                let n = start.iter().zip(end).take_while(|(a, b)| a == b).count();
                self.st.s.read_table_rows(t.1, start.get(..n).unwrap_or_default(), true);
            }
            None => self.st.s.read_owner(t.1),
        }
        let mem = crate::overlay::range(self.mem.o.tables.get(&t.0), start, end, limit, rev);
        if t.0 & MEM_TABLE != 0 || end.is_some_and(|e| start >= e) {
            return Ok(mem);
        }
        let durable = btree::range(self, t.0, start, end, limit, rev)?;
        Ok(crate::overlay::merge(mem, durable, limit, rev))
    }
    pub fn table_len(&mut self, t: Table) -> Result<u64, Error> {
        self.st.s.read_owner(t.1);
        match self.pure(t) {
            Some(true) => Ok(self.mem.o.tables.get(&t.0).map_or(0, |r| r.len() as u64)),
            Some(false) => btree::len(self, t.0),
            None => Ok(self.table_range(t, b"", None, usize::MAX)?.len() as u64),
        }
    }
    /// Number of keys below `key` (a position).
    pub fn table_rank(&mut self, t: Table, key: &[u8]) -> Result<u64, Error> {
        self.st.s.read_owner(t.1);
        match self.pure(t) {
            Some(true) => Ok(self.mem.o.tables.get(&t.0).map_or(0, |r| r.range(..key.to_vec()).count() as u64)),
            Some(false) => btree::rank(self, t.0, key),
            None => Ok(self.table_range(t, b"", None, usize::MAX)?.iter().filter(|(k, _)| k.as_slice() < key).count() as u64),
        }
    }
    /// The entry at position `i`.
    pub fn table_nth(&mut self, t: Table, i: u64) -> Result<Option<KeyValue>, Error> {
        self.st.s.read_owner(t.1);
        match self.pure(t) {
            Some(true) => Ok(self.mem.o.tables.get(&t.0).and_then(|r| r.iter().nth(i as usize)).map(|(k, v)| (k.clone(), v.clone()))),
            Some(false) => btree::nth(self, t.0, i),
            None => Ok(self.table_range(t, b"", None, usize::MAX)?.into_iter().nth(i as usize)),
        }
    }

    /// A rebuildable index table spanning aspects, created empty if absent (always durable: its
    /// memory rows are kept per row).
    pub fn index(&mut self, name: &[u8]) -> Result<Table, Error> {
        let key = named_key(kind::INDEX, name);
        if let Some(root) = u64_value(self.cat_get(&key)?)? {
            return Ok(Table(root, owner(&key)));
        }
        let root = btree::create(self)?;
        self.cat_put_to(&key, W::new().u64(root).take(), Shred::No, false)?;
        Ok(Table(root, owner(&key)))
    }

    /// Shreds every rebuildable index (a purge of anything they cover); returns their names.
    pub fn drop_indexes(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        let mut names = Vec::new();
        while let Some((k, v)) = self.cat_pop_prefix(&[kind::INDEX], Shred::Yes)? {
            let root = u64_value(Some(v))?.ok_or(Error::Corrupt("index"))?;
            self.drop_rows(Table(root, owner(&k)))?;
            names.push(R::new(k.get(1..).unwrap_or_default()).bytes()?.to_vec());
        }
        Ok(names)
    }

    // Counters per (aspect, this session): memory rows only (spec/crdt.md §2.1: a session's
    // counters start from 1 at each open and never reach the disk), rolled back with an aborted
    // transaction, so a session leaves no gap.

    /// The next unused counter of session `nonce` in the aspect (from 1).
    pub fn counter(&mut self, tid: &Tid, ak: &Ak, nonce: &[u8]) -> Result<u64, Error> {
        let key = counter_key(tid, ak, nonce);
        self.st.s.read(&key[..]);
        Ok(u64_value(self.mem.o.cat.get(&key).cloned())?.unwrap_or(1))
    }
    /// Reserves `n` counters of session `nonce`; returns the first.
    pub fn reserve_counters(&mut self, tid: &Tid, ak: &Ak, nonce: &[u8], n: u64) -> Result<u64, Error> {
        let first = self.counter(tid, ak, nonce)?;
        let next = first.checked_add(n).ok_or(Error::Misuse("counter overflow"))?;
        let key = counter_key(tid, ak, nonce);
        self.st.s.row(&key, true);
        self.mem.cat_put(&key, W::new().u64(next).take());
        Ok(first)
    }

    // Pending and parked commits.

    /// Stores a commit not yet applied, as bytes (header and blob), with its signature's
    /// verdict if one was reached (`Pending`).
    pub fn put_pending(&mut self, id: &CommitId, k: PendingKind, verdict: Option<[u8; 32]>, received: u64, bytes: &[u8]) -> Result<(), Error> {
        let tag = match k {
            PendingKind::Pending => 0,
            PendingKind::Parked => 1,
        } | u8::from(verdict.is_some()) << 1;
        let v = W::new().u8(tag).raw(verdict.as_ref().map_or(&[][..], |v| &v[..])).raw(&received.to_be_bytes()).raw(bytes).take();
        self.cat_put_to(&W::new().u8(kind::PENDING).raw(&id.0).take(), v, Shred::No, self.memory)
    }
    pub fn get_pending(&mut self, id: &CommitId) -> Result<Option<Pending>, Error> {
        self.cat_get(&W::new().u8(kind::PENDING).raw(&id.0).take())?.map(|v| decode_pending(&v)).transpose()
    }
    /// Pending and parked commits by ID, after `after` (exclusive).
    pub fn pending(&mut self, after: Option<&CommitId>, limit: usize) -> Result<Vec<(CommitId, Pending)>, Error> {
        let from = after.map(|c| [&c.0[..], &[0]].concat()).unwrap_or_default();
        self.cat_scan(&[kind::PENDING], &from, limit)?
            .into_iter()
            .map(|(k, v)| Ok((CommitId(tail(&k)?), decode_pending(&v)?)))
            .collect()
    }
    /// Removes a pending commit; `Shred::Yes` when its content is being purged rather than applied.
    pub fn remove_pending(&mut self, id: &CommitId, shred: Shred) -> Result<bool, Error> {
        self.cat_remove(&W::new().u8(kind::PENDING).raw(&id.0).take(), shred)
    }

    /// Every logical row, by family: `aspect <ak>` (units), `table <ak> <idx>` (an aspect's
    /// table rows), `index <name>`, `local <prefix>` (a local key up to its first `/`, else 3
    /// bytes), else the catalog kind: count and key plus value bytes, memory rows included. Tests
    /// counting what a thing costs (notes/thing-cost.md).
    #[doc(hidden)]
    pub fn census(&mut self) -> Result<std::collections::BTreeMap<String, (usize, usize)>, Error> {
        let mut out = std::collections::BTreeMap::<String, (usize, usize)>::new();
        let add = |out: &mut std::collections::BTreeMap<String, (usize, usize)>, f: String, n: usize| {
            let e = out.entry(f).or_default();
            e.0 += 1;
            e.1 += n;
        };
        let ak_of = |k: &[u8]| -> String {
            let n = k.get(16..20).and_then(|b| <[u8; 4]>::try_from(b).ok()).map_or(0, |b| u32::from_be_bytes(b) as usize);
            String::from_utf8_lossy(k.get(20..20 + n).unwrap_or_default()).into_owned()
        };
        for (k, v) in self.cat_scan(b"", b"", usize::MAX)? {
            let size = k.len() + v.len();
            match k.first().copied() {
                Some(kind::ASPECT) => add(&mut out, format!("aspect {}", ak_of(&k)), size),
                Some(t @ (kind::TABLE | kind::INDEX)) => {
                    let name = match t {
                        kind::TABLE => format!("table {} {}", ak_of(&k), k.last().copied().unwrap_or(0)),
                        _ => format!("index {}", String::from_utf8_lossy(k.get(5..).unwrap_or_default())),
                    };
                    let root = u64_value(Some(v))?.unwrap_or(0);
                    for (tk, tv) in self.table_range(Table(root, owner(&k)), b"", None, usize::MAX)? {
                        add(&mut out, name.clone(), tk.len() + tv.len());
                    }
                }
                Some(kind::LOCAL) => {
                    let l = k.get(1..).unwrap_or_default();
                    let end = l.iter().position(|b| *b == b'/').map_or(3.min(l.len()), |p| (p + 1).min(l.len()));
                    add(&mut out, format!("local {}", String::from_utf8_lossy(l.get(..end).unwrap_or(l))), size);
                }
                k => add(&mut out, format!("kind {k:?}"), size),
            }
        }
        let blobs: Vec<usize> = self.mem.o.blobs.values().map(Vec::len).collect();
        for n in blobs {
            add(&mut out, "memory blob".into(), n);
        }
        Ok(out)
    }

    // Node-local records with no dedicated kind.

    pub fn put_local(&mut self, key: &[u8], val: &[u8], shred: Shred) -> Result<(), Error> {
        self.cat_put_to(&[&[kind::LOCAL], key].concat(), val.to_vec(), shred, self.memory)
    }
    pub fn get_local(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.cat_get(&[&[kind::LOCAL], key].concat())
    }
    /// Keys of the local records under `prefix` held in memory (keys returned whole).
    pub fn memory_local_keys(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        let p = [&[kind::LOCAL], prefix].concat();
        self.st.s.read_prefix(&p);
        self.mem.o.cat.range(p.clone()..).take_while(|(k, _)| k.starts_with(&p)).map(|(k, _)| k.get(1..).unwrap_or_default().to_vec()).collect()
    }

    pub fn remove_local(&mut self, key: &[u8], shred: Shred) -> Result<bool, Error> {
        self.cat_remove(&[&[kind::LOCAL], key].concat(), shred)
    }
    /// Local records with keys starting with `prefix`, from `prefix || from` on.
    pub fn scan_local(&mut self, prefix: &[u8], from: &[u8], limit: usize) -> Result<Vec<KeyValue>, Error> {
        let p = [&[kind::LOCAL], prefix].concat();
        Ok(self.cat_scan(&p, from, limit)?.into_iter().map(|(k, v)| (k.get(1..).unwrap_or_default().to_vec(), v)).collect())
    }

    /// Local records with keys starting with `prefix`, below `prefix || before`: a time-ordered
    /// index read up to a time reads only the rows due by then.
    pub fn scan_local_before(&mut self, prefix: &[u8], before: &[u8], limit: usize) -> Result<Vec<KeyValue>, Error> {
        let p = [&[kind::LOCAL], prefix].concat();
        let end = [&p[..], before].concat();
        Ok(self.cat_scan_to(&p, end, limit)?.into_iter().map(|(k, v)| (k.get(1..).unwrap_or_default().to_vec(), v)).collect())
    }

    // Blob ciphertexts (already opaque; deleted for space).

    /// Stores a blob: in memory in memory mode.
    pub fn put_blob(&mut self, id: &BlobId, ciphertext: Vec<u8>) -> Result<(), Error> {
        self.st.s.row(&blob_key(id), true);
        if self.memory {
            self.mem.blob_put(*id, ciphertext);
            return Ok(());
        }
        written(ciphertext.len());
        self.pager.txn_put_blob(&mut self.d, *id, ciphertext, &mut *self.rng)
    }
    /// Deletes a blob. A memory blob never had a durable copy, and memory-mode work touches no
    /// durable blob: neither writes anything durable.
    pub fn delete_blob(&mut self, id: &BlobId) {
        self.st.s.row(&blob_key(id), false);
        if self.mem.blob_remove(id) {
            return;
        }
        // a durable blob deleted in memory mode would be kept on disk: a bug
        debug_assert!(!self.memory || self.pager.txn_get_blob(&self.d, id, 0, 0).ok().flatten().is_none(), "memory-mode delete of a durable blob");
        if !self.memory {
            self.pager.txn_delete_blob(&mut self.d, *id);
        }
    }
    pub fn get_blob(&mut self, id: &BlobId) -> Result<Option<Vec<u8>>, Error> {
        self.read_blob(id, 0, usize::MAX)
    }
    /// Bytes `offset..offset+len` of a blob (streaming reads of large blobs).
    pub fn read_blob(&mut self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, Error> {
        self.st.s.read(&blob_key(id));
        let v = match self.mem.o.blobs.get(id) {
            Some(b) => Some(crate::backend::blob_slice(b, offset, len)),
            None => self.pager.txn_get_blob(&self.d, id, offset, len)?,
        };
        osis_base::costs::count("store blob bytes read", v.as_ref().map_or(0, |v| v.len() as u64));
        Ok(v)
    }
    /// A blob's byte length, without reading it.
    pub fn blob_len(&mut self, id: &BlobId) -> Result<Option<u64>, Error> {
        self.st.s.read(&blob_key(id));
        if let Some(b) = self.mem.o.blobs.get(id) {
            return Ok(Some(b.len() as u64));
        }
        self.pager.txn_blob_len(&self.d, id)
    }
}

fn decode_pending(v: &[u8]) -> Result<Pending, Error> {
    let (tag, b) = v.split_first().ok_or(Error::Corrupt("pending"))?;
    let kind = match tag & 1 {
        0 => PendingKind::Pending,
        _ => PendingKind::Parked,
    };
    let (verdict, bytes) = match tag >> 1 {
        0 => (None, b),
        1 => {
            let (v, rest) = b.split_first_chunk::<32>().ok_or(Error::Corrupt("pending"))?;
            (Some(*v), rest)
        }
        _ => return Err(Error::Corrupt("pending")),
    };
    let (received, bytes) = bytes.split_first_chunk::<8>().ok_or(Error::Corrupt("pending"))?;
    Ok(Pending { kind, verdict, received: u64::from_be_bytes(*received), bytes: bytes.to_vec() })
}

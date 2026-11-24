//! The memory overlay (notes/local-store.md, Memory overlay): rows of the memory class (what
//! ephemeral data derives, notes/ephemeral.md) kept in plain maps beside the encrypted store,
//! never written to the backend. A store opens with an empty overlay. A transaction changes it in
//! place and keeps an undo journal, replayed when the transaction is dropped uncommitted or
//! rolls back to a savepoint.

use osis_base::BlobId;
use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;

/// Table IDs of tables created in memory (never a durable root slot).
pub(crate) const MEM_TABLE: u64 = 1 << 63;

/// What a row or blob held here costs beside its key and value bytes (`Store::memory_held`): a
/// B-tree slot of two `Vec` headers in nodes at worst half full (96), two allocations' headers
/// (32), the stamp of its key (32). Minor consequence: an estimate of this representation, off by
/// a few dozen bytes a row (0: only the bytes count; infinity: nothing seems to fit).
pub const ROW_COST: u64 = 160;

type Rows = BTreeMap<Vec<u8>, Vec<u8>>;

#[derive(Clone, Default)]
pub(crate) struct Overlay {
    /// Catalog rows held in memory.
    pub cat: Rows,
    /// Table rows held in memory, by table ID: a memory table's whole content, or the memory rows
    /// of a durable table (an index naming memory commits).
    pub tables: BTreeMap<u64, Rows>,
    pub blobs: HashMap<BlobId, Vec<u8>>,
    pub next_table: u64,
}

impl Overlay {
    /// Bytes held: each row's and blob's, and `ROW_COST` each. O(rows).
    pub fn held(&self) -> u64 {
        let rows = self.cat.iter().chain(self.tables.values().flatten()).map(|(k, v)| k.len() + v.len());
        rows.chain(self.blobs.values().map(Vec::len)).map(|n| n as u64 + ROW_COST).sum()
    }
}

pub(crate) enum Undo {
    Cat(Vec<u8>, Option<Vec<u8>>),
    Row(u64, Vec<u8>, Option<Vec<u8>>),
    Table(u64, Option<Rows>),
    Blob(BlobId, Option<Vec<u8>>),
    NextTable(u64),
}

/// A transaction's view of the overlay: changes applied in place, undone on drop unless `done`.
pub(crate) struct MemTxn<'a> {
    pub o: &'a mut Overlay,
    pub undo: Vec<Undo>,
    pub done: bool,
}

impl Drop for MemTxn<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.rollback_to(0);
        }
    }
}

fn restore(m: &mut Rows, k: Vec<u8>, v: Option<Vec<u8>>) {
    match v {
        Some(v) => m.insert(k, v),
        None => m.remove(&k),
    };
}

impl MemTxn<'_> {
    /// Undoes the changes after the first `len` of the journal, newest first.
    pub fn rollback_to(&mut self, len: usize) {
        while self.undo.len() > len {
            let Some(u) = self.undo.pop() else { break };
            match u {
                Undo::Cat(k, v) => restore(&mut self.o.cat, k, v),
                Undo::Row(t, k, v) => restore(self.o.tables.entry(t).or_default(), k, v),
                Undo::Table(t, rows) => {
                    match rows {
                        Some(r) => self.o.tables.insert(t, r),
                        None => self.o.tables.remove(&t),
                    };
                }
                Undo::Blob(id, v) => {
                    match v {
                        Some(b) => self.o.blobs.insert(id, b),
                        None => self.o.blobs.remove(&id),
                    };
                }
                Undo::NextTable(n) => self.o.next_table = n,
            }
        }
        self.o.tables.retain(|_, r| !r.is_empty());
    }

    pub fn cat_put(&mut self, key: &[u8], val: Vec<u8>) {
        let old = self.o.cat.insert(key.to_vec(), val);
        self.undo.push(Undo::Cat(key.to_vec(), old));
    }
    pub fn cat_remove(&mut self, key: &[u8]) -> bool {
        let old = self.o.cat.remove(key);
        let was = old.is_some();
        if was {
            self.undo.push(Undo::Cat(key.to_vec(), old));
        }
        was
    }
    pub fn row_get(&self, t: u64, key: &[u8]) -> Option<&Vec<u8>> {
        self.o.tables.get(&t)?.get(key)
    }
    pub fn row_put(&mut self, t: u64, key: &[u8], val: Vec<u8>) -> bool {
        let old = self.o.tables.entry(t).or_default().insert(key.to_vec(), val);
        let new = old.is_none();
        self.undo.push(Undo::Row(t, key.to_vec(), old));
        new
    }
    pub fn row_remove(&mut self, t: u64, key: &[u8]) -> bool {
        let Some(rows) = self.o.tables.get_mut(&t) else { return false };
        let old = rows.remove(key);
        let was = old.is_some();
        if rows.is_empty() {
            self.o.tables.remove(&t);
        }
        if was {
            self.undo.push(Undo::Row(t, key.to_vec(), old));
        }
        was
    }
    pub fn drop_rows(&mut self, t: u64) {
        let old = self.o.tables.remove(&t);
        if old.is_some() {
            self.undo.push(Undo::Table(t, old));
        }
    }
    pub fn new_table(&mut self) -> u64 {
        self.undo.push(Undo::NextTable(self.o.next_table));
        self.o.next_table += 1;
        MEM_TABLE | self.o.next_table
    }
    pub fn blob_put(&mut self, id: BlobId, b: Vec<u8>) {
        let old = self.o.blobs.insert(id, b);
        self.undo.push(Undo::Blob(id, old));
    }
    /// Removes a memory blob; false when it was not one.
    pub fn blob_remove(&mut self, id: &BlobId) -> bool {
        match self.o.blobs.remove(id) {
            Some(old) => {
                self.undo.push(Undo::Blob(*id, Some(old)));
                true
            }
            None => false,
        }
    }
}

/// Merges two key-ordered pages, ascending or (`rev`) descending (memory wins on equal keys), up
/// to `limit` entries.
pub(crate) fn merge(mem: Vec<(Vec<u8>, Vec<u8>)>, durable: Vec<(Vec<u8>, Vec<u8>)>, limit: usize, rev: bool) -> Vec<(Vec<u8>, Vec<u8>)> {
    if mem.is_empty() {
        return durable;
    }
    let mut out = Vec::with_capacity(limit.min(mem.len() + durable.len()));
    let (mut a, mut b) = (mem.into_iter().peekable(), durable.into_iter().peekable());
    while out.len() < limit {
        let next = match (a.peek(), b.peek()) {
            (Some(x), Some(y)) if x.0 == y.0 => {
                b.next();
                a.next()
            }
            (Some(x), Some(y)) if (x.0 < y.0) != rev => a.next(),
            (Some(_), Some(_)) => b.next(),
            (Some(_), None) => a.next(),
            (None, Some(_)) => b.next(),
            (None, None) => None,
        };
        let Some(n) = next else { break };
        out.push(n);
    }
    out
}

/// The rows of `m` with `start <= key < end` (`None`: unbounded), ascending or (`rev`)
/// descending, at most `limit`.
pub(crate) fn range(m: Option<&Rows>, start: &[u8], end: Option<&[u8]>, limit: usize, rev: bool) -> Vec<(Vec<u8>, Vec<u8>)> {
    let Some(m) = m else { return Vec::new() };
    if end.is_some_and(|e| start >= e) {
        return Vec::new();
    }
    let rows = m.range::<[u8], _>((Bound::Included(start), end.map_or(Bound::Unbounded, Bound::Excluded)));
    let pair = |(k, v): (&Vec<u8>, &Vec<u8>)| (k.clone(), v.clone());
    if rev { rows.rev().take(limit).map(pair).collect() } else { rows.take(limit).map(pair).collect() }
}

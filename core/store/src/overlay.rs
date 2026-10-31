//! The memory overlay (notes/local-store.md, Memory overlay): rows of the memory class (what
//! ephemeral data derives, issues/eph-unify.md) kept in plain maps beside the encrypted store,
//! never written to the backend. A store opens with an empty overlay. A transaction changes it in
//! place and keeps an undo journal, replayed when the transaction is dropped uncommitted.

use osis_base::{Ak, BlobId, Tid};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Table IDs of tables created in memory (never a durable root slot).
pub(crate) const MEM_TABLE: u64 = 1 << 63;

type Rows = BTreeMap<Vec<u8>, Vec<u8>>;

#[derive(Default)]
pub(crate) struct Overlay {
    /// Catalog rows held in memory.
    pub cat: Rows,
    /// Table rows held in memory, by table ID: a memory table's whole content, or the memory rows
    /// of a durable table (an index naming memory commits).
    pub tables: BTreeMap<u64, Rows>,
    pub blobs: HashMap<BlobId, Vec<u8>>,
    /// Aspects of the memory class: every aspect-keyed row of theirs is held here.
    pub aspects: HashSet<(Tid, Ak)>,
    pub next_table: u64,
}

pub(crate) enum Undo {
    Cat(Vec<u8>, Option<Vec<u8>>),
    Row(u64, Vec<u8>, Option<Vec<u8>>),
    Table(u64, Option<Rows>),
    Blob(BlobId, Option<Vec<u8>>),
    Aspect((Tid, Ak)),
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
        if self.done {
            return;
        }
        while let Some(u) = self.undo.pop() {
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
                Undo::Aspect(a) => {
                    self.o.aspects.remove(&a);
                }
                Undo::NextTable(n) => self.o.next_table = n,
            }
        }
        self.o.tables.retain(|_, r| !r.is_empty());
    }
}

fn restore(m: &mut Rows, k: Vec<u8>, v: Option<Vec<u8>>) {
    match v {
        Some(v) => m.insert(k, v),
        None => m.remove(&k),
    };
}

impl MemTxn<'_> {
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
    pub fn blob_remove(&mut self, id: &BlobId) {
        if let Some(old) = self.o.blobs.remove(id) {
            self.undo.push(Undo::Blob(*id, Some(old)));
        }
    }
    /// Marks an aspect memory-class (for the rest of the store's life).
    pub fn mark_aspect(&mut self, tid: &Tid, ak: &Ak) {
        let k = (*tid, ak.clone());
        if self.o.aspects.insert(k.clone()) {
            self.undo.push(Undo::Aspect(k));
        }
    }
}

/// Merges two key-ordered pages (memory wins on equal keys) up to `limit` entries.
pub(crate) fn merge(mem: Vec<(Vec<u8>, Vec<u8>)>, durable: Vec<(Vec<u8>, Vec<u8>)>, limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::with_capacity(limit.min(mem.len() + durable.len()));
    let (mut a, mut b) = (mem.into_iter().peekable(), durable.into_iter().peekable());
    while out.len() < limit {
        let next = match (a.peek(), b.peek()) {
            (Some(x), Some(y)) if x.0 == y.0 => {
                b.next();
                a.next()
            }
            (Some(x), Some(y)) if x.0 < y.0 => a.next(),
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

/// The rows of `m` with `start <= key < end`, at most `limit`.
pub(crate) fn range(m: Option<&Rows>, start: &[u8], end: Option<&[u8]>, limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let Some(m) = m else { return Vec::new() };
    m.range(start.to_vec()..).take_while(|(k, _)| end.is_none_or(|e| k.as_slice() < e)).take(limit).map(|(k, v)| (k.clone(), v.clone())).collect()
}

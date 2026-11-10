//! The writes a body holds by origin dot (spec/permissions.md §5.2): which dots a snapshot
//! holds a write or a map record under (`CopyIndex`, what un-merge keeps of an invalid
//! delta's records a valid snapshot vouches for), and stripping what a snapshot gave
//! (`Fragment::remove_writes`). Copies of one write are never compared: they join by the copy order
//! (spec/crdt.md §4.1).

use crate::fragment::{Bag, Enum, Fragment, Map, Set, Slots, Struct};
use crate::seq::SeqContent;
use crate::stamp::{Dot, Source, Stamp};
use std::collections::BTreeSet;

/// Collects the origin dots `keep` accepts of the writes and map records walked. `Derived` writes and the copies of a
/// register's write inside its embeddings (spec/crdt.md §7) are skipped: they repeat the
/// register's.
struct Copies<'a> {
    keep: &'a dyn Fn(&Dot) -> bool,
    out: BTreeSet<Dot>,
    /// A `Slots` register's stamps while its slots are walked.
    embedded: Vec<Stamp>,
    /// The dots of the map records walked (keyed or key-erased, §4.7), with or without a creation.
    records: BTreeSet<Dot>,
}

impl Copies<'_> {
    fn put(&mut self, s: &Stamp) {
        if s.dot.src.is_derived() || self.embedded.contains(s) || !(self.keep)(&s.dot) {
            return;
        }
        self.out.insert(s.dot.clone());
    }
    fn opt(&mut self, s: &Option<Stamp>) {
        if let Some(s) = s {
            self.put(s);
        }
    }
    fn meta(&mut self, m: &crate::fragment::Meta) {
        self.opt(&m.reset);
        self.opt(&m.w);
    }
    fn reg(&mut self, r: &crate::fragment::Register) {
        self.opt(&r.reset);
        if let Some(w) = &r.write {
            self.put(&w.stamp);
        }
    }
    fn frag(&mut self, f: &Fragment) {
        match f {
            Fragment::Register(r) => self.reg(r),
            Fragment::Bag(Bag { meta: m, elems: e, .. }) | Fragment::Set(Set { meta: m, elems: e }) => {
                self.meta(m);
                for x in e.iter().filter(|(d, _)| !d.src.is_derived()).map(|(_, x)| x) {
                    self.opt(&x.reset);
                    if let Some(f) = &x.frag {
                        self.frag(f);
                    }
                }
            }
            Fragment::Struct(Struct { meta: m, fields: xs }) | Fragment::Enum(Enum { meta: m, payloads: xs, .. }) => {
                self.meta(m);
                if let Fragment::Enum(Enum { case: Some(c), .. }) = f {
                    self.put(&c.stamp);
                }
                for x in xs.values() {
                    self.frag(x);
                }
            }
            Fragment::Map(Map { meta: m, entries, .. }) => {
                self.meta(m);
                for (id, e) in entries {
                    if (self.keep)(&id.dot) {
                        self.records.insert(id.dot.clone());
                    }
                    if let Some(c) = &e.created {
                        self.put(c);
                    }
                    self.opt(&e.reset);
                    if let Some(f) = &e.frag {
                        self.frag(f);
                    }
                }
            }
            Fragment::Seq(s) => {
                self.meta(&s.meta);
                for (d, e) in crate::seq_span::expand(s.elems().clone()) {
                    if d.src.is_derived() {
                        continue;
                    }
                    if let Some((st, _)) = &e.created {
                        self.put(st);
                    }
                    for (st, _, _) in e.pos.iter().filter(|p| p.0.dot != d) {
                        self.put(st);
                    }
                    if let Some((st, _)) = &e.deleted {
                        self.put(st);
                    }
                    if let SeqContent::Frag(x) = &e.content {
                        self.frag(x);
                    }
                }
            }
            Fragment::Slots(Slots { reg, slots }) => {
                let n = self.embedded.len();
                if let Some(r) = reg {
                    self.reg(r);
                    self.embedded.extend(r.reset.iter().cloned().chain(r.write.iter().map(|w| w.stamp.clone())));
                }
                for x in slots.values() {
                    self.frag(x);
                }
                self.embedded.truncate(n);
            }
        }
    }
}

impl Fragment {
    /// Its writes by origin dot (`CopyIndex`).
    pub fn copy_index(&self) -> CopyIndex {
        let mut ix = CopyIndex::default();
        ix.add(self);
        ix
    }

    /// `copy_index` of the writes under a dot in `ranges` (sorted), without indexing the rest.
    pub fn copy_index_in(&self, ranges: &[(Source, u64, u64)]) -> CopyIndex {
        let pick = |d: &Dot| {
            // the last range starting at or before the dot, or an earlier one reaching it
            ranges.iter().take(ranges.partition_point(|r| (&r.0, r.1) <= (&d.src, d.ctr))).rev().take_while(|r| r.0 == d.src).any(|r| d.ctr < r.2)
        };
        let mut ix = CopyIndex::default();
        ix.add_picked(self, &pick);
        ix
    }
}

/// A fragment's writes by origin dot (`Fragment::copy_index`), and the dots of its map records
/// (keyed or key-erased).
#[derive(Debug, Default)]
pub struct CopyIndex(BTreeSet<Dot>, BTreeSet<Dot>);

impl CopyIndex {
    /// Adds the writes of `f` (a piece of a streamed fragment: the index of a fragment is the
    /// union of its pieces'; a write two pieces repeat, such as the creation of the entry a
    /// page lies under, counts once).
    pub fn add(&mut self, f: &Fragment) {
        self.add_picked(f, &|_| true);
    }
    fn add_picked(&mut self, f: &Fragment, pick: &dyn Fn(&Dot) -> bool) {
        let mut c = Copies { keep: pick, out: BTreeSet::new(), embedded: Vec::new(), records: BTreeSet::new() };
        c.frag(f);
        self.0.extend(c.out);
        self.1.extend(c.records);
    }
    /// Dots indexed.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Every origin dot indexed.
    pub fn dots(&self) -> impl Iterator<Item = &Dot> {
        self.0.iter()
    }
    /// The dots of `src` with a counter in `lo..hi` under which a write or a map record is
    /// held: a creation's copy, or a record alone (one a reset pruned, kept by a later write
    /// nested in it, hidden, §5.6 Live; a key-erased one, §4.7). The records of a map dot are
    /// one entry, whatever their keys (§5.6).
    pub fn held_in(&self, src: &Source, lo: u64, hi: u64) -> impl Iterator<Item = &Dot> {
        let range = Dot::new(src.clone(), lo)..Dot::new(src.clone(), hi);
        self.0.range(range.clone()).chain(self.1.range(range))
    }
    /// Whether a write is indexed under origin dot `d`.
    pub fn holds(&self, d: &Dot) -> bool {
        self.0.contains(d)
    }
}

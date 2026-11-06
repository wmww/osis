//! The writes a body holds by origin dot (spec/permissions.md §5.2): which dots a snapshot
//! holds a write under and in which map records (`CopyIndex`, what un-merge keeps of an
//! invalid delta's records a valid snapshot vouches for), and stripping what a snapshot gave
//! (`strip_copies`). Copies of one write are never compared: they join by the copy order
//! (spec/crdt.md §4.1).

use crate::fragment::{Bag, Enum, Fragment, Map, Set, Slots, Struct};
use crate::seq::SeqContent;
use crate::stamp::{Dot, Source, Stamp};
use osis_base::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Collects the writes whose origin dot `keep` accepts: per dot, the keys of its map entry
/// creations (`Some`), `None` for any other write. `Derived` writes and the copies of a
/// register's write inside its embeddings (spec/crdt.md §7) are skipped: they repeat the
/// register's.
struct Copies<'a> {
    keep: &'a dyn Fn(&Dot) -> bool,
    out: BTreeMap<Dot, BTreeSet<Option<Value>>>,
    /// A `Slots` register's stamps while its slots are walked.
    embedded: Vec<Stamp>,
    /// The map records walked (dot, key; `None`: key-erased, §4.7), with or without a creation.
    records: BTreeMap<Dot, BTreeSet<Option<Value>>>,
}

impl Copies<'_> {
    fn put(&mut self, s: &Stamp, key: Option<Value>) {
        if s.dot.src.is_derived() || self.embedded.contains(s) || !(self.keep)(&s.dot) {
            return;
        }
        self.out.entry(s.dot.clone()).or_default().insert(key);
    }
    fn opt(&mut self, s: &Option<Stamp>) {
        if let Some(s) = s {
            self.put(s, None);
        }
    }
    fn meta(&mut self, m: &crate::fragment::Meta) {
        self.opt(&m.reset);
        self.opt(&m.w);
    }
    fn reg(&mut self, r: &crate::fragment::Register) {
        self.opt(&r.reset);
        if let Some(w) = &r.write {
            self.put(&w.stamp, None);
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
                    self.put(&c.stamp, None);
                }
                for x in xs.values() {
                    self.frag(x);
                }
            }
            Fragment::Map(Map { meta: m, entries, .. }) => {
                self.meta(m);
                for (id, e) in entries {
                    self.records.entry(id.dot.clone()).or_default().insert(id.key().cloned());
                    if let Some(c) = &e.created {
                        self.put(c, id.key().cloned());
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
                        self.put(st, None);
                    }
                    for (st, _, _) in e.pos.iter().filter(|p| p.0.dot != d) {
                        self.put(st, None);
                    }
                    if let Some((st, _)) = &e.deleted {
                        self.put(st, None);
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

    /// Removes every write whose origin dot `pred` accepts, element and entry creations with
    /// their chars and anchors included, keeping others' writes nested in what they created,
    /// with the entry's key (their records repeat it, spec/crdt.md §3.2): what an invalid
    /// snapshot body or a snapshot turned invalid gave (spec/permissions.md §5.2).
    pub fn strip_copies(&mut self, pred: &dyn Fn(&Dot) -> bool) {
        self.remove_dots_in(pred, &|_, _| true);
        self.drop_creations(pred);
    }

    pub(crate) fn drop_creations(&mut self, pred: &dyn Fn(&Dot) -> bool) {
        match self {
            Fragment::Register(_) => {}
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => {
                for x in elems.values_mut().filter_map(|e| e.frag.as_deref_mut()) {
                    x.drop_creations(pred);
                }
            }
            Fragment::Struct(Struct { fields: m, .. }) | Fragment::Enum(Enum { payloads: m, .. }) => {
                for x in m.values_mut() {
                    x.drop_creations(pred);
                }
            }
            // an entry's creation went with `remove_dots_in`; an entry left holding nothing
            // (its sequence's records gone) goes with it
            Fragment::Map(m) => {
                m.entries.retain(|_, e| {
                    if let Some(x) = e.frag.as_deref_mut() {
                        x.drop_creations(pred);
                        if x.is_empty() {
                            e.frag = None;
                        }
                    }
                    e.reset.is_some() || e.frag.is_some() || e.created.is_some()
                });
            }
            Fragment::Seq(s) => crate::seq::drop_creations(s, pred),
            Fragment::Slots(Slots { slots, .. }) => {
                for x in slots.values_mut() {
                    x.drop_creations(pred);
                }
            }
        }
    }
}

/// A fragment's writes by origin dot (`Fragment::copy_index`): per dot, the keys of its map
/// entry creations (`Some`) and `None` for any other write; and its map records (`None`:
/// key-erased).
#[derive(Debug, Default)]
pub struct CopyIndex(BTreeMap<Dot, BTreeSet<Option<Value>>>, BTreeMap<Dot, BTreeSet<Option<Value>>>);

impl CopyIndex {
    /// Adds the writes of `f` (a piece of a streamed fragment: the index of a fragment is the
    /// union of its pieces'; a write two pieces repeat, such as the creation of the entry a
    /// page lies under, counts once).
    pub fn add(&mut self, f: &Fragment) {
        self.add_picked(f, &|_| true);
    }
    fn add_picked(&mut self, f: &Fragment, pick: &dyn Fn(&Dot) -> bool) {
        let mut c = Copies { keep: pick, out: BTreeMap::new(), embedded: Vec::new(), records: BTreeMap::new() };
        c.frag(f);
        for (d, ks) in c.records {
            self.1.entry(d).or_default().extend(ks);
        }
        for (d, ks) in c.out {
            self.0.entry(d).or_default().extend(ks);
        }
    }
    /// Entries indexed.
    pub fn len(&self) -> usize {
        self.0.values().map(BTreeSet::len).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Every origin dot indexed.
    pub fn dots(&self) -> impl Iterator<Item = &Dot> {
        self.0.keys()
    }
    /// The records holding the writes indexed under origin dots of `src` with a counter in
    /// `lo..hi`, as (dot, key): a map entry creation's copy names its record's key (records of
    /// one dot with different keys are independent, §5.6), any other write `None`; and the
    /// keyed map records of such dots held, a creation's copy or not (one a reset pruned,
    /// kept by a later write nested in it, hidden, §5.6 Live).
    pub fn records_in(&self, src: &Source, lo: u64, hi: u64) -> impl Iterator<Item = (&Dot, Option<&Value>)> {
        let range = Dot::new(src.clone(), lo)..Dot::new(src.clone(), hi);
        let writes = self.0.range(range.clone()).flat_map(|(d, ks)| ks.iter().map(move |k| (d, k.as_ref())));
        let records = self.1.range(range).flat_map(|(d, ks)| ks.iter().flatten().map(move |k| (d, Some(k))));
        writes.chain(records)
    }
    /// The dots of `src` with a counter in `lo..hi` whose map record is held key-erased (its
    /// writer held the dot value-less, §4.7).
    pub fn erased_in(&self, src: &Source, lo: u64, hi: u64) -> impl Iterator<Item = &Dot> {
        self.1.range(Dot::new(src.clone(), lo)..Dot::new(src.clone(), hi)).filter(|(_, ks)| ks.contains(&None)).map(|(d, _)| d)
    }
    /// Whether a write is indexed under origin dot `d`.
    pub fn holds(&self, d: &Dot) -> bool {
        self.0.contains_key(d)
    }
}

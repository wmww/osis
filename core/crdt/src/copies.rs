//! The writes a body holds by origin dot (spec/permissions.md §5.2): which dots a snapshot
//! holds a write under (`CopyIndex`), for stripping what a snapshot gave
//! (`Fragment::remove_writes`). Copies of one write are never compared: they join by the copy order
//! (spec/crdt.md §4.1).

use crate::fragment::{Bag, Enum, Fragment, Map, Set, Slots, Struct};
use crate::seq::SeqContent;
use crate::stamp::{Dot, Stamp};
use std::collections::BTreeSet;

/// Collects the origin dots of the writes walked. `Derived` writes and the copies of a
/// register's write inside its embeddings (spec/crdt.md §7) are skipped: they repeat the
/// register's.
struct Copies {
    out: BTreeSet<Dot>,
    /// A `Slots` register's stamps while its slots are walked.
    embedded: Vec<Stamp>,
}

impl Copies {
    fn put(&mut self, s: &Stamp) {
        if s.dot.src.is_derived() || self.embedded.contains(s) {
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
            Fragment::Bag(Bag { meta: m, elems: e, .. }) | Fragment::Set(Set { meta: m, elems: e, .. }) => {
                self.meta(m);
                for x in e.iter().filter(|(d, _)| !d.src.is_derived()).map(|(_, x)| x) {
                    self.opt(&x.reset);
                    if let Some(g) = &x.gone {
                        self.put(&g.0);
                    }
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
                for e in entries.values() {
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
        let mut c = Copies { out: BTreeSet::new(), embedded: Vec::new() };
        c.frag(self);
        CopyIndex(c.out)
    }
}

/// A fragment's writes by origin dot (`Fragment::copy_index`).
#[derive(Debug, Default)]
pub struct CopyIndex(BTreeSet<Dot>);

impl CopyIndex {
    /// Whether a write is indexed under origin dot `d`.
    pub fn holds(&self, d: &Dot) -> bool {
        self.0.contains(d)
    }
}

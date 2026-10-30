//! Copies of writes held by several bodies (spec/permissions.md §5.2, spec/commits.md §5): a
//! snapshot's record of a write whose own commit is held counts for nothing (`strip_copies`),
//! and a write's copies agree when each holds it at the same position with the same stamp and
//! payload (`copies_within`). Honest copies of one write are identical; a copy that differs was
//! forged.

use crate::fragment::{Bag, Enum, Fragment, Map, Set, Slots, Struct};
use crate::seq::{Anchor, SeqContent};
use crate::stamp::{Dot, Source, Stamp};
use osis_base::Value;
use std::collections::{BTreeMap, BTreeSet};

/// A step from the root to a write: a struct field, an enum payload, an element or entry.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Step {
    Field(u64),
    Case(u64),
    Elem(Dot),
}

/// What a write is, apart from its value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Reset,
    W,
    Reg,
    Case,
    Entry,
    Created(Anchor),
    /// Anchor and sibling key (§5.7).
    Pos(Anchor, Option<Stamp>),
    Flag(bool),
}

/// A write's value; `None` where the copy holds it value-less (§4.7) or without its char (a
/// deleted text element, §3.3 rule 5), which matches any value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Val {
    V(Value),
    Case(u64),
    Char(char),
}

type Key = (Vec<Step>, Kind, Stamp);

/// Collects the writes whose owner dot `keep` accepts, by position, kind and stamp. `Derived`
/// writes and the copies of a register's write inside its embeddings (§7) are skipped: they
/// repeat the register's.
struct Copies<'a> {
    keep: &'a dyn Fn(&Dot) -> bool,
    path: Vec<Step>,
    out: Vec<(Key, Option<Val>)>,
    /// A `Slots` register's stamps while its members are walked.
    embedded: Vec<Stamp>,
}

impl Copies<'_> {
    fn put(&mut self, kind: Kind, s: &Stamp, v: Option<Val>) {
        if s.dot.src.is_derived() || self.embedded.contains(s) || !(self.keep)(&s.dot) {
            return;
        }
        self.out.push(((self.path.clone(), kind, s.clone()), v));
    }
    fn opt(&mut self, kind: Kind, s: &Option<Stamp>) {
        if let Some(s) = s {
            self.put(kind, s, None);
        }
    }
    fn meta(&mut self, m: &crate::fragment::Meta) {
        self.opt(Kind::Reset, &m.reset);
        self.opt(Kind::W, &m.w);
    }
    fn reg(&mut self, r: &crate::fragment::Register) {
        self.opt(Kind::Reset, &r.reset);
        if let Some(w) = &r.write {
            self.put(Kind::Reg, &w.stamp, w.value.clone().map(Val::V));
        }
    }
    fn under(&mut self, s: Step, f: &Fragment) {
        self.path.push(s);
        self.frag(f);
        self.path.pop();
    }
    fn frag(&mut self, f: &Fragment) {
        match f {
            Fragment::Register(r) => self.reg(r),
            Fragment::Bag(Bag { meta: m, elems: e, .. }) | Fragment::Set(Set { meta: m, elems: e }) => {
                self.meta(m);
                for (d, x) in e.iter().filter(|(d, _)| !d.src.is_derived()) {
                    self.path.push(Step::Elem(d.clone()));
                    self.opt(Kind::Reset, &x.reset);
                    if let Some(f) = &x.frag {
                        self.frag(f);
                    }
                    self.path.pop();
                }
            }
            Fragment::Struct(Struct { meta: m, fields }) => {
                self.meta(m);
                for (k, x) in fields {
                    self.under(Step::Field(*k), x);
                }
            }
            Fragment::Enum(Enum { meta: m, case, payloads }) => {
                self.meta(m);
                if let Some(c) = case {
                    self.put(Kind::Case, &c.stamp, c.case.map(Val::Case));
                }
                for (k, x) in payloads {
                    self.under(Step::Case(*k), x);
                }
            }
            Fragment::Map(Map { meta: m, entries, .. }) => {
                self.meta(m);
                for (id, e) in entries {
                    self.path.push(Step::Elem(id.dot.clone()));
                    if let Some(c) = &e.created {
                        self.put(Kind::Entry, c, id.key().cloned().map(Val::V));
                    }
                    self.opt(Kind::Reset, &e.reset);
                    if let Some(f) = &e.frag {
                        self.frag(f);
                    }
                    self.path.pop();
                }
            }
            Fragment::Seq(s) => {
                self.meta(&s.meta);
                for (d, e) in crate::seq_span::expand(s.elems().clone()) {
                    if d.src.is_derived() {
                        continue;
                    }
                    self.path.push(Step::Elem(d.clone()));
                    if let Some((st, a)) = &e.created {
                        let v = match &e.content {
                            SeqContent::Char(c) => Some(Val::Char(*c)),
                            _ => None,
                        };
                        self.put(Kind::Created(a.clone()), st, v);
                    }
                    for (st, a, k) in e.pos.iter().filter(|p| p.0.dot != d) {
                        self.put(Kind::Pos(a.clone(), k.clone()), st, None);
                    }
                    if let Some((st, b)) = &e.deleted {
                        self.put(Kind::Flag(*b), st, None);
                    }
                    if let SeqContent::Frag(x) = &e.content {
                        self.frag(x);
                    }
                    self.path.pop();
                }
            }
            Fragment::Slots(Slots { reg, members }) => {
                let n = self.embedded.len();
                if let Some(r) = reg {
                    self.reg(r);
                    self.embedded.extend(r.reset.iter().cloned().chain(r.write.iter().map(|w| w.stamp.clone())));
                }
                for x in members.values() {
                    self.frag(x);
                }
                self.embedded.truncate(n);
            }
        }
    }
}

impl Fragment {
    fn copies(&self, keep: &dyn Fn(&Dot) -> bool) -> Vec<(Key, Option<Val>)> {
        let mut c = Copies { keep, path: Vec::new(), out: Vec::new(), embedded: Vec::new() };
        c.frag(self);
        c.out
    }

    /// Whether every write of `self` under a dot one of `others` holds a write of, or that
    /// `also` accepts, has a copy in one of `others` at the same position with the same stamp and
    /// payload (a value-less copy on either side matches). `Derived` writes and embeddings are
    /// not compared.
    pub fn copies_within(&self, others: &[&Fragment], also: &dyn Fn(&Dot) -> bool) -> bool {
        self.copies_outside(others, also).is_empty()
    }

    /// The dots of the writes failing `copies_within`.
    pub fn copies_outside(&self, others: &[&Fragment], also: &dyn Fn(&Dot) -> bool) -> BTreeSet<Dot> {
        let theirs: BTreeMap<Key, Option<Val>> = others.iter().flat_map(|o| o.copies(&|_| true)).collect();
        let dots: BTreeSet<&Dot> = theirs.keys().map(|k| &k.2.dot).collect();
        let mine = self.copies(&|d| dots.contains(d) || also(d));
        mine.into_iter()
            .filter(|(k, v)| match theirs.get(k) {
                Some(t) => !(v.is_none() || t.is_none() || v == t),
                None => true,
            })
            .map(|(k, _)| k.2.dot)
            .collect()
    }

    /// Its writes by owner dot, for `CopyIndex::outside` against many deltas in turn.
    pub fn copy_index(&self) -> CopyIndex {
        let mut m: BTreeMap<Dot, Vec<(Key, Option<Val>)>> = BTreeMap::new();
        for (k, v) in self.copies(&|_| true) {
            m.entry(k.2.dot.clone()).or_default().push((k, v));
        }
        CopyIndex(m)
    }

    /// Removes every write whose owner dot `pred` accepts, element and entry creations with
    /// their chars and anchors included, keeping others' writes nested in what they created,
    /// with the entry's key (their records repeat it, spec/crdt.md §3.2): a snapshot's copies
    /// of writes whose own commit supplies them (spec/permissions.md §5.2).
    pub fn strip_copies(&mut self, pred: &dyn Fn(&Dot) -> bool) {
        self.remove_dots_in(pred, true);
        self.drop_creations(pred, false);
    }

    /// `strip_copies`, the keys of the entries `pred` accepts included: copies found to differ
    /// from their delta (`copies_outside`), whose key may be forged too.
    pub fn strip_forged(&mut self, pred: &dyn Fn(&Dot) -> bool) {
        self.remove_dots_in(pred, true);
        self.drop_creations(pred, true);
    }

    pub(crate) fn drop_creations(&mut self, pred: &dyn Fn(&Dot) -> bool, keys: bool) {
        match self {
            Fragment::Register(_) => {}
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => {
                for x in elems.values_mut().filter_map(|e| e.frag.as_deref_mut()) {
                    x.drop_creations(pred, keys);
                }
            }
            Fragment::Struct(Struct { fields: m, .. }) | Fragment::Enum(Enum { payloads: m, .. }) => {
                for x in m.values_mut() {
                    x.drop_creations(pred, keys);
                }
            }
            // an entry's creation went with `remove_dots_in`
            Fragment::Map(m) => {
                if keys {
                    m.erase_keys(&|d| pred(d.owner()));
                }
                for x in m.entries.values_mut().filter_map(|e| e.frag.as_deref_mut()) {
                    x.drop_creations(pred, keys);
                }
            }
            Fragment::Seq(s) => crate::seq::drop_creations(s, pred, keys),
            Fragment::Slots(Slots { members, .. }) => {
                for x in members.values_mut() {
                    x.drop_creations(pred, keys);
                }
            }
        }
    }
}

/// A fragment's writes by owner dot (`Fragment::copy_index`).
#[derive(Debug, Default)]
pub struct CopyIndex(BTreeMap<Dot, Vec<(Key, Option<Val>)>>);

impl CopyIndex {
    /// Writes indexed.
    pub fn len(&self) -> usize {
        self.0.values().map(Vec::len).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// The owner dots indexed of `src` with a counter in `lo..hi`.
    pub fn dots_in(&self, src: &Source, lo: u64, hi: u64) -> impl Iterator<Item = &Dot> {
        self.0.range(Dot::new(src.clone(), lo)..Dot::new(src.clone(), hi)).map(|(d, _)| d)
    }
    /// The dots in `ranges` (source, counters `lo..hi`) whose writes here are not all in
    /// `others` as `Fragment::copies_within` compares them.
    pub fn outside(&self, ranges: &[(Source, u64, u64)], others: &[&Fragment]) -> BTreeSet<Dot> {
        let mut out = BTreeSet::new();
        let mut theirs: Option<BTreeMap<Key, Option<Val>>> = None;
        for (src, lo, hi) in ranges {
            for (d, ws) in self.0.range(Dot::new(src.clone(), *lo)..Dot::new(src.clone(), *hi)) {
                let t = theirs.get_or_insert_with(|| others.iter().flat_map(|o| o.copies(&|_| true)).collect());
                if ws.iter().any(|(k, v)| !t.get(k).is_some_and(|x| v.is_none() || x.is_none() || v == x)) {
                    out.insert(d.clone());
                }
            }
        }
        out
    }
}

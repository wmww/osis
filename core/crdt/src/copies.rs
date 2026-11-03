//! Copies of writes held by several bodies (spec/permissions.md §5.2, spec/commits.md §5): a
//! write's copies agree when each holds it at the same position with the same stamp and
//! payload (`copies_within`). Honest copies of one write are identical; a copy that differs was
//! forged, and a valid snapshot's copy then governs (`misstated`).

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

/// Writes by position, kind and stamp, with their values.
type Writes = Vec<(Key, Option<Val>)>;

/// Collects the writes whose owner dot `keep` accepts, by position, kind and stamp. `Derived`
/// writes and the copies of a register's write inside its embeddings (§7) are skipped: they
/// repeat the register's.
struct Copies<'a> {
    keep: &'a dyn Fn(&Dot) -> bool,
    path: Vec<Step>,
    out: Vec<(Key, Option<Val>)>,
    /// A `Slots` register's stamps while its slots are walked.
    embedded: Vec<Stamp>,
    /// The keyed map records walked (dot, key), with or without a creation.
    records: Vec<(Dot, Value)>,
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
                    if let Some(k) = id.key() {
                        self.records.push((id.dot.clone(), k.clone()));
                    }
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
                        self.put(Kind::Flag(*b), st, e.undel.map(Val::Char));
                    }
                    if let SeqContent::Frag(x) = &e.content {
                        self.frag(x);
                    }
                    self.path.pop();
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
    fn copies(&self, keep: &dyn Fn(&Dot) -> bool) -> Vec<(Key, Option<Val>)> {
        self.copies_and_records(keep).0
    }

    /// `copies`, and the keyed map records walked.
    fn copies_and_records(&self, keep: &dyn Fn(&Dot) -> bool) -> (Writes, Vec<(Dot, Value)>) {
        let mut c = Copies { keep, path: Vec::new(), out: Vec::new(), embedded: Vec::new(), records: Vec::new() };
        c.frag(self);
        (c.out, c.records)
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

    /// The dots `pick` accepts, among those `others` hold writes under, under which `self` holds
    /// a write that `others` do not hold alike (`agrees`; `lax(d)`: a value-less copy in `self`
    /// matches, as for an expiring write's): where `self` is a valid snapshot and `others` a held
    /// delta, a misstatement (spec/permissions.md §5.2).
    pub fn misstated(&self, others: &[&Fragment], pick: &dyn Fn(&Dot) -> bool, lax: &dyn Fn(&Dot) -> bool) -> BTreeSet<Dot> {
        self.misstated_in(&CopySet::of(others), pick, lax)
    }

    /// `misstated` against `others` indexed once (`CopySet::of`): the misstatements of a
    /// fragment are those of its parts (a write's copy is compared at its own position), so a
    /// fragment streamed page by page is judged a page at a time.
    pub fn misstated_in(&self, others: &CopySet, pick: &dyn Fn(&Dot) -> bool, lax: &dyn Fn(&Dot) -> bool) -> BTreeSet<Dot> {
        let mine = self.copies(&|d| others.dots.contains(d) && pick(d));
        mine.into_iter().filter(|(k, v)| !others.copies.get(k).is_some_and(|t| agrees(&k.1, v, t, lax(&k.2.dot)))).map(|(k, _)| k.2.dot).collect()
    }

    /// Its writes by owner dot, for `CopyIndex::outside` against many deltas in turn.
    pub fn copy_index(&self) -> CopyIndex {
        let mut ix = CopyIndex::default();
        ix.add(self);
        ix
    }

    /// Removes every write whose owner dot `pred` accepts, element and entry creations with
    /// their chars and anchors included, keeping others' writes nested in what they created,
    /// with the entry's key (their records repeat it, spec/crdt.md §3.2): what an invalid
    /// snapshot body or a snapshot turned invalid gave (spec/permissions.md §5.2).
    pub fn strip_copies(&mut self, pred: &dyn Fn(&Dot) -> bool) {
        self.remove_dots_in(pred, &|_, _| true);
        self.drop_creations(pred, false);
    }

    /// `strip_copies`, the keys of the entries `pred` accepts included: writes under dots a
    /// snapshot misstates (`misstated`), whose key may be forged too.
    pub fn strip_forged(&mut self, pred: &dyn Fn(&Dot) -> bool) {
        self.remove_dots_in(pred, &|_, _| true);
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
            // an entry's creation went with `remove_dots_in`; an entry left holding nothing
            // (its sequence's records gone) goes with it
            Fragment::Map(m) => {
                if keys {
                    m.erase_keys(&|d| pred(d.owner()), &mut crate::changes::Changes::new());
                }
                m.entries.retain(|_, e| {
                    if let Some(x) = e.frag.as_deref_mut() {
                        x.drop_creations(pred, keys);
                        if x.is_empty() {
                            e.frag = None;
                        }
                    }
                    e.reset.is_some() || e.frag.is_some() || e.created.is_some()
                });
            }
            Fragment::Seq(s) => crate::seq::drop_creations(s, pred, keys),
            Fragment::Slots(Slots { slots, .. }) => {
                for x in slots.values_mut() {
                    x.drop_creations(pred, keys);
                }
            }
        }
    }
}

/// Whether copy `mine` of a write of kind `k` agrees with `theirs`: equal, or `theirs` held
/// value-less (expired or purged there), or `mine` without its value where it may be: a text
/// element's char, the creation's (deleted: §3.3 rule 5) or an undelete's copy (§5.7), or
/// anything when `lax`.
fn agrees(k: &Kind, mine: &Option<Val>, theirs: &Option<Val>, lax: bool) -> bool {
    theirs.is_none() || mine == theirs || mine.is_none() && (lax || matches!(k, Kind::Created(_) | Kind::Flag(_)))
}

/// Fragments' writes by position, kind and stamp, and the dots they hold writes under
/// (`Fragment::misstated_in`).
#[derive(Debug, Default)]
pub struct CopySet {
    copies: BTreeMap<Key, Option<Val>>,
    dots: BTreeSet<Dot>,
}

impl CopySet {
    pub fn of(fs: &[&Fragment]) -> CopySet {
        let mut out = CopySet::default();
        for f in fs {
            out.add(f);
        }
        out
    }
    /// Adds the writes of `f` (a piece of a streamed fragment: the set of a fragment is the
    /// union of its pieces').
    pub fn add(&mut self, f: &Fragment) {
        for (k, v) in f.copies(&|_| true) {
            self.dots.insert(k.2.dot.clone());
            self.copies.insert(k, v);
        }
    }
}

/// A fragment's writes by owner dot (`Fragment::copy_index`), and its keyed map records.
#[derive(Debug, Default)]
pub struct CopyIndex(BTreeMap<Dot, Vec<(Key, Option<Val>)>>, BTreeMap<Dot, BTreeSet<Value>>);

impl CopyIndex {
    /// Adds the writes of `f` (a piece of a streamed fragment: the index of a fragment is the
    /// union of its pieces'; a write two pieces repeat, such as the creation of the entry a
    /// page lies under, counts once).
    pub fn add(&mut self, f: &Fragment) {
        let (copies, records) = f.copies_and_records(&|_| true);
        for (d, k) in records {
            self.1.entry(d).or_default().insert(k);
        }
        for (k, v) in copies {
            let ws = self.0.entry(k.2.dot.clone()).or_default();
            if !ws.iter().any(|w| w.0 == k && w.1 == v) {
                ws.push((k, v));
            }
        }
    }
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
    /// Every owner dot indexed.
    pub fn dots(&self) -> impl Iterator<Item = &Dot> {
        self.0.keys()
    }
    /// The records holding the writes indexed under owner dots of `src` with a counter in
    /// `lo..hi`, as (dot, key): a map entry creation's copy names its record's key (records of
    /// one dot with different keys are independent, §5.6), any other write `None`; and the
    /// keyed map records of such dots held, a creation's copy or not (one a reset pruned,
    /// alive by a later write nested in it, §5.6 Resurrection).
    pub fn records_in(&self, src: &Source, lo: u64, hi: u64) -> impl Iterator<Item = (&Dot, Option<&Value>)> {
        let writes = self.0.range(Dot::new(src.clone(), lo)..Dot::new(src.clone(), hi)).flat_map(|(d, ws)| {
            ws.iter().map(move |(k, v)| match (&k.1, v) {
                (Kind::Entry, Some(Val::V(key))) => (d, Some(key)),
                _ => (d, None),
            })
        });
        let records = self.1.range(Dot::new(src.clone(), lo)..Dot::new(src.clone(), hi)).flat_map(|(d, ks)| ks.iter().map(move |k| (d, Some(k))));
        writes.chain(records)
    }
    /// Whether a write is indexed under owner dot `d`.
    pub fn holds(&self, d: &Dot) -> bool {
        self.0.contains_key(d)
    }
    /// Whether a write is indexed under a dot in `ranges` (source, counters `lo..hi`): else
    /// `misstated` and `outside` find nothing, whatever they compare with.
    pub fn any_in(&self, ranges: &[(Source, u64, u64)]) -> bool {
        ranges.iter().any(|(src, lo, hi)| self.dots_in(src, *lo, *hi).next().is_some())
    }
    /// The dots in `ranges` whose writes here a held delta (its writes `own`) holds otherwise
    /// (`Fragment::misstated`; `lax`: the delta expires, so a value-less copy matches).
    pub fn misstated(&self, ranges: &[(Source, u64, u64)], own: &CopySet, lax: bool) -> BTreeSet<Dot> {
        self.failing(ranges, &|k, v| own.copies.get(k).is_some_and(|x| agrees(&k.1, v, x, lax)))
    }
    /// The dots in `ranges` (source, counters `lo..hi`) whose writes here are not all in
    /// `others` as `Fragment::copies_within` compares them.
    pub fn outside(&self, ranges: &[(Source, u64, u64)], others: &CopySet) -> BTreeSet<Dot> {
        self.failing(ranges, &|k, v| others.copies.get(k).is_some_and(|x| v.is_none() || x.is_none() || v == x))
    }
    /// The dots in `ranges` with a write here that `ok` refuses.
    fn failing(&self, ranges: &[(Source, u64, u64)], ok: &dyn Fn(&Key, &Option<Val>) -> bool) -> BTreeSet<Dot> {
        let mut out = BTreeSet::new();
        for (src, lo, hi) in ranges {
            for (d, ws) in self.0.range(Dot::new(src.clone(), *lo)..Dot::new(src.clone(), *hi)) {
                if ws.iter().any(|(k, v)| !ok(k, v)) {
                    out.insert(d.clone());
                }
            }
        }
        out
    }
}

//! Join, prune, presence and read over fragments (spec/crdt.md §4, §5, §7).
//!
//! `join_into` is delta-driven: it walks what the incoming fragment carries and prunes existing
//! content only where a reset rises, so a small delta costs only the elements it touches. Its
//! result equals the union of writes followed by a whole-state prune (§4.1, §4.2).

use crate::changes::Changes;
use crate::fragment::{Bag, BagKind, CaseWrite, Elem, Encoding, Entry, Enum, Fragment, Map, Meta, RegWrite, Register, Set, Slots, Struct};
use crate::seq::{self, Seq};
use crate::stamp::{Dot, Stamp, max_opt};
use osis_core::{Float, Value};
use std::cmp::Ordering;
use std::collections::BTreeMap;

impl Default for Fragment {
    /// The empty state: a register with nothing in it.
    fn default() -> Fragment {
        Fragment::Register(Register::default())
    }
}

/// Drops `s` if it does not survive `e`, recording its death.
fn prune_stamp(s: &mut Option<Stamp>, e: Option<&Stamp>, ch: &mut Changes) {
    if let (Some(x), Some(e)) = (s.as_ref(), e)
        && x < e
    {
        ch.died(x, e.ts);
        *s = None;
    }
}

/// Joins a reset-like stamp (greatest wins; the loser dies).
fn join_stamp(s: &mut Option<Stamp>, d: Option<Stamp>, ch: &mut Changes) -> bool {
    let Some(d) = d else { return false };
    match s {
        Some(x) if *x == d => false,
        Some(x) if *x > d => {
            ch.died(&d, x.ts);
            false
        }
        _ => {
            if let Some(x) = s.as_ref() {
                ch.died(x, d.ts);
            }
            *s = Some(d);
            ch.touch();
            true
        }
    }
}

/// Register-like join: greater stamp wins; of two copies of one write the valued one (§4.7).
fn join_write<T: PartialEq>(s: &mut Option<(Stamp, Option<T>)>, d: Option<(Stamp, Option<T>)>, ch: &mut Changes) {
    let Some(d) = d else { return };
    match s {
        Some(x) if x.0 == d.0 => {
            if x.1.is_none() && d.1.is_some() {
                x.1 = d.1;
                ch.touch();
            }
        }
        Some(x) if x.0 > d.0 => ch.died(&d.0, x.0.ts),
        _ => {
            if let Some(x) = s.as_ref() {
                ch.died(&x.0, d.0.ts);
            }
            *s = Some(d);
            ch.touch();
        }
    }
}

fn reg_pair(w: Option<RegWrite>) -> Option<(Stamp, Option<Value>)> {
    w.map(|w| (w.stamp, w.value))
}
fn reg_unpair(p: Option<(Stamp, Option<Value>)>) -> Option<RegWrite> {
    p.map(|(stamp, value)| RegWrite { stamp, value })
}
fn case_pair(w: Option<CaseWrite>) -> Option<(Stamp, Option<u64>)> {
    w.map(|w| (w.stamp, w.case))
}
fn case_unpair(p: Option<(Stamp, Option<u64>)>) -> Option<CaseWrite> {
    p.map(|(stamp, case)| CaseWrite { stamp, case })
}

/// Joins a composite's reset and `W` under the parent's effective reset. Returns the effective
/// reset `E` and whether the own reset rose (existing children then need pruning).
fn join_meta(s: &mut Meta, d: Meta, e_parent: Option<&Stamp>, ch: &mut Changes) -> (Option<Stamp>, bool) {
    let raised = join_stamp(&mut s.reset, d.reset, ch);
    prune_stamp(&mut s.reset, e_parent, ch);
    let e = max_opt(e_parent.cloned(), s.reset.clone());
    join_stamp(&mut s.w, d.w, ch);
    prune_stamp(&mut s.w, e.as_ref(), ch);
    (e, raised)
}

/// Prunes a composite's own reset (a nested reset below the parent's is a pruned write, §4.2)
/// and `W`; returns `E`.
fn prune_meta(m: &mut Meta, e_parent: Option<&Stamp>, ch: &mut Changes) -> Option<Stamp> {
    prune_stamp(&mut m.reset, e_parent, ch);
    let e = max_opt(e_parent.cloned(), m.reset.clone());
    prune_stamp(&mut m.w, e.as_ref(), ch);
    e
}

/// Prunes a keyed child map (struct fields, enum payloads), dropping empty children.
fn prune_children(c: &mut BTreeMap<u64, Fragment>, e: Option<&Stamp>, ch: &mut Changes) {
    c.retain(|_, f| {
        f.prune(e, ch);
        !f.is_empty()
    });
}

fn join_children(s: &mut BTreeMap<u64, Fragment>, d: BTreeMap<u64, Fragment>, e: Option<&Stamp>, ch: &mut Changes) {
    for (k, mut df) in d {
        match s.get_mut(&k) {
            Some(sf) => {
                sf.join_into(df, e, ch);
                if sf.is_empty() {
                    s.remove(&k);
                }
            }
            None => {
                df.prune(e, ch);
                if !df.is_empty() {
                    ch.touch();
                    s.insert(k, df);
                }
            }
        }
    }
}

/// Prunes an optional nested fragment under `e`, dropping it when empty.
fn prune_opt(f: &mut Option<Box<Fragment>>, e: Option<&Stamp>, ch: &mut Changes) {
    if let Some(x) = f {
        x.prune(e, ch);
        if x.is_empty() {
            *f = None;
        }
    }
}

fn join_opt(s: &mut Option<Box<Fragment>>, d: Option<Box<Fragment>>, e: Option<&Stamp>, ch: &mut Changes) {
    match (s.as_mut(), d) {
        (_, None) => {}
        (Some(x), Some(y)) => {
            x.join_into(*y, e, ch);
            if x.is_empty() {
                *s = None;
            }
        }
        (None, Some(mut y)) => {
            y.prune(e, ch);
            if !y.is_empty() {
                ch.touch();
                *s = Some(y);
            }
        }
    }
}

/// Prunes a set or bag element; `false` when the record goes (§4.2).
fn prune_elem(el: &mut Elem, e: Option<&Stamp>, ch: &mut Changes) -> bool {
    prune_stamp(&mut el.reset, e, ch);
    let ee = max_opt(e.cloned(), el.reset.clone());
    prune_opt(&mut el.frag, ee.as_ref(), ch);
    el.reset.is_some() || el.frag.is_some()
}

fn prune_elems(elems: &mut BTreeMap<Dot, Elem>, e: Option<&Stamp>, ch: &mut Changes) {
    elems.retain(|_, el| prune_elem(el, e, ch));
}

fn join_elems(s: &mut BTreeMap<Dot, Elem>, d: BTreeMap<Dot, Elem>, e: Option<&Stamp>, ch: &mut Changes) {
    for (dot, mut de) in d {
        match s.get_mut(&dot) {
            Some(se) => {
                let raised = join_stamp(&mut se.reset, de.reset, ch);
                prune_stamp(&mut se.reset, e, ch);
                let ee = max_opt(e.cloned(), se.reset.clone());
                if raised {
                    prune_opt(&mut se.frag, ee.as_ref(), ch);
                }
                join_opt(&mut se.frag, de.frag, ee.as_ref(), ch);
                if se.reset.is_none() && se.frag.is_none() {
                    s.remove(&dot);
                }
            }
            None => {
                if prune_elem(&mut de, e, ch) {
                    ch.touch();
                    s.insert(dot, de);
                }
            }
        }
    }
}

/// Prunes a map entry; the key goes with the content (content-free tombstone, §5.6).
fn prune_entry(en: &mut Entry, e: Option<&Stamp>, ch: &mut Changes) -> bool {
    prune_stamp(&mut en.reset, e, ch);
    let ee = max_opt(e.cloned(), en.reset.clone());
    prune_opt(&mut en.frag, ee.as_ref(), ch);
    if en.frag.is_none() {
        en.key = None;
    }
    en.reset.is_some() || en.frag.is_some()
}

fn join_entries(m: &mut Map, d: BTreeMap<Dot, Entry>, e: Option<&Stamp>, ch: &mut Changes) {
    for (dot, de) in d {
        join_entry(&mut m.entries, dot.clone(), de, e, ch);
        m.index_dot(&dot);
    }
}

fn join_entry(s: &mut BTreeMap<Dot, Entry>, dot: Dot, mut de: Entry, e: Option<&Stamp>, ch: &mut Changes) {
    match s.get_mut(&dot) {
        Some(se) => {
            let raised = join_stamp(&mut se.reset, de.reset, ch);
            prune_stamp(&mut se.reset, e, ch);
            let ee = max_opt(e.cloned(), se.reset.clone());
            if raised {
                prune_opt(&mut se.frag, ee.as_ref(), ch);
            }
            if se.key.is_none() && de.key.is_some() {
                se.key = de.key;
                ch.touch();
            }
            join_opt(&mut se.frag, de.frag, ee.as_ref(), ch);
            if se.frag.is_none() {
                se.key = None;
            }
            if se.reset.is_none() && se.frag.is_none() {
                s.remove(&dot);
            }
        }
        None => {
            if prune_entry(&mut de, e, ch) {
                ch.touch();
                s.insert(dot, de);
            }
        }
    }
}

/// Splits a position into its register slot and non-register slots (§7).
fn parts(f: Fragment) -> (Option<Register>, BTreeMap<Encoding, Fragment>) {
    match f {
        Fragment::Slots(s) => (s.reg, s.members),
        Fragment::Register(r) => (Some(r), BTreeMap::new()),
        f => (None, BTreeMap::from([(f.encoding(), f)])),
    }
}

/// The canonical position from its members: empty members go, a lone member stands alone,
/// nothing is an empty register (§7 Canonical form).
fn assemble(reg: Option<Register>, mut members: BTreeMap<Encoding, Fragment>) -> Fragment {
    let reg = reg.filter(|r| !Fragment::Register(r.clone()).is_empty());
    members.retain(|_, f| !f.is_empty() && !reg.as_ref().is_some_and(|r| below_embedding(f, r)));
    let mut it = members.into_iter();
    match (reg, it.len()) {
        (None, 0) => Fragment::default(),
        (Some(r), 0) => Fragment::Register(r),
        (None, 1) => it.next().map_or_else(Fragment::default, |(_, f)| f),
        (reg, _) => Fragment::Slots(Slots { reg, members: it.collect() }),
    }
}

/// Whether member `f` adds nothing to the embedding of register `r`: `f ⊔ embed(r) = embed(r)`
/// (§7 Canonical form).
pub(crate) fn below_embedding(f: &Fragment, r: &Register) -> bool {
    let Some(mut e) = embed(r, f.encoding()) else { return false };
    let mut ch = Changes::new();
    e.prune(None, &mut ch);
    let mut j = f.clone();
    j.join_into(e.clone(), None, &mut ch);
    j == e
}

/// The embedding of register `r` into encoding `target` (§7); `None` for register and slots.
pub(crate) fn embed(r: &Register, target: Encoding) -> Option<Fragment> {
    let reset = max_opt(r.reset.clone(), r.write.as_ref().map(|w| w.stamp.clone()));
    let meta = Meta { reset, w: None };
    Some(match target {
        Encoding::Register | Encoding::Slots => return None,
        Encoding::Counter | Encoding::Max | Encoding::Min => {
            let mut elems = BTreeMap::new();
            if let Some(w) = &r.write {
                let reg = Register { reset: None, write: Some(w.clone()) };
                elems.insert(w.stamp.dot.clone(), Elem { reset: None, frag: Some(Box::new(Fragment::Register(reg))) });
            }
            Fragment::Bag(Bag { kind: target.bag_kind()?, meta, elems })
        }
        Encoding::Text => Fragment::Seq(Seq { text: true, meta, elems: seq::embed_text(r) }),
        Encoding::List => Fragment::Seq(Seq { text: false, meta, elems: BTreeMap::new() }),
        Encoding::Struct => Fragment::Struct(Struct { meta, fields: BTreeMap::new() }),
        Encoding::Enum => Fragment::Enum(Enum { meta, case: None, payloads: BTreeMap::new() }),
        Encoding::Set => Fragment::Set(Set { meta, elems: BTreeMap::new() }),
        Encoding::Map => Fragment::Map(Map { meta, ..Map::default() }),
    })
}

impl Fragment {
    /// Joins `other` into the state at the root (§4.1).
    pub fn join(&mut self, other: Fragment) -> Changes {
        let mut ch = Changes::new();
        self.join_into(other, None, &mut ch);
        ch
    }

    /// Joins `other` (any encoding) into `self` under the parent's effective reset `e_parent`
    /// (§4.1, §4.2, §7), touching only what `other` carries and what a raised reset prunes.
    /// `self` must already be pruned under `e_parent`.
    pub fn join_into(&mut self, other: Fragment, e_parent: Option<&Stamp>, ch: &mut Changes) {
        if self.is_empty() {
            // nothing to join with: the other side, pruned (no empty register slot appears)
            *self = other;
            self.prune(e_parent, ch);
            if !self.is_empty() {
                ch.touch();
            }
            return;
        }
        let this = std::mem::take(self);
        *self = match (this, other) {
            (Fragment::Register(mut a), Fragment::Register(b)) => {
                join_stamp(&mut a.reset, b.reset, ch);
                prune_stamp(&mut a.reset, e_parent, ch);
                let mut w = reg_pair(a.write.take());
                join_write(&mut w, reg_pair(b.write), ch);
                a.write = reg_unpair(w);
                let e = max_opt(e_parent.cloned(), a.reset.clone());
                prune_write(&mut a.write, e.as_ref(), ch);
                drop_implied_reset(&mut a, ch);
                Fragment::Register(a)
            }
            (Fragment::Bag(mut a), Fragment::Bag(b)) if a.kind == b.kind => {
                let (e, raised) = join_meta(&mut a.meta, b.meta, e_parent, ch);
                if raised {
                    prune_elems(&mut a.elems, e.as_ref(), ch);
                }
                join_elems(&mut a.elems, b.elems, e.as_ref(), ch);
                Fragment::Bag(a)
            }
            (Fragment::Set(mut a), Fragment::Set(b)) => {
                let (e, raised) = join_meta(&mut a.meta, b.meta, e_parent, ch);
                if raised {
                    prune_elems(&mut a.elems, e.as_ref(), ch);
                }
                join_elems(&mut a.elems, b.elems, e.as_ref(), ch);
                Fragment::Set(a)
            }
            (Fragment::Struct(mut a), Fragment::Struct(b)) => {
                let (e, raised) = join_meta(&mut a.meta, b.meta, e_parent, ch);
                if raised {
                    prune_children(&mut a.fields, e.as_ref(), ch);
                }
                join_children(&mut a.fields, b.fields, e.as_ref(), ch);
                Fragment::Struct(a)
            }
            (Fragment::Enum(mut a), Fragment::Enum(b)) => {
                let (e, raised) = join_meta(&mut a.meta, b.meta, e_parent, ch);
                if raised {
                    prune_children(&mut a.payloads, e.as_ref(), ch);
                }
                let mut c = case_pair(a.case.take());
                join_write(&mut c, case_pair(b.case), ch);
                a.case = case_unpair(c);
                prune_case(&mut a.case, e.as_ref(), ch);
                join_children(&mut a.payloads, b.payloads, e.as_ref(), ch);
                Fragment::Enum(a)
            }
            (Fragment::Map(mut a), Fragment::Map(b)) => {
                let (e, raised) = join_meta(&mut a.meta, b.meta, e_parent, ch);
                if raised {
                    a.entries.retain(|_, en| prune_entry(en, e.as_ref(), ch));
                }
                join_entries(&mut a, b.entries, e.as_ref(), ch);
                Fragment::Map(a)
            }
            (Fragment::Seq(mut a), Fragment::Seq(mut b)) if a.text == b.text => {
                let bm = std::mem::take(&mut b.meta);
                let (e, raised) = join_meta(&mut a.meta, bm, e_parent, ch);
                if raised {
                    seq::prune_elems(&mut a, e.as_ref(), ch);
                }
                seq::join_elems(&mut a, b, e.as_ref(), ch);
                Fragment::Seq(a)
            }
            (a, b) => join_slots(a, b, e_parent, ch),
        };
    }

    /// Drops every write below the effective reset `max(e_parent, own reset)` (§4.2). A nested
    /// reset below `e_parent` is itself dropped.
    pub fn prune(&mut self, e_parent: Option<&Stamp>, ch: &mut Changes) {
        match self {
            Fragment::Register(r) => {
                prune_stamp(&mut r.reset, e_parent, ch);
                let e = max_opt(e_parent.cloned(), r.reset.clone());
                prune_write(&mut r.write, e.as_ref(), ch);
                drop_implied_reset(r, ch);
            }
            Fragment::Bag(Bag { meta, elems, .. }) | Fragment::Set(Set { meta, elems }) => {
                let e = prune_meta(meta, e_parent, ch);
                prune_elems(elems, e.as_ref(), ch);
            }
            Fragment::Struct(s) => {
                let e = prune_meta(&mut s.meta, e_parent, ch);
                prune_children(&mut s.fields, e.as_ref(), ch);
            }
            Fragment::Enum(s) => {
                let e = prune_meta(&mut s.meta, e_parent, ch);
                prune_case(&mut s.case, e.as_ref(), ch);
                prune_children(&mut s.payloads, e.as_ref(), ch);
            }
            Fragment::Map(m) => {
                let e = prune_meta(&mut m.meta, e_parent, ch);
                m.entries.retain(|_, en| prune_entry(en, e.as_ref(), ch));
            }
            Fragment::Seq(s) => {
                let e = prune_meta(&mut s.meta, e_parent, ch);
                seq::prune_elems(s, e.as_ref(), ch);
            }
            Fragment::Slots(_) => {
                let (reg, members) = parts(std::mem::take(self));
                *self = prune_slots(reg, members, e_parent, ch);
            }
        }
    }

    /// Own reset; for `Slots` the greatest member reset (§7).
    pub(crate) fn reset(&self) -> Option<Stamp> {
        match self {
            Fragment::Register(r) => r.reset.clone(),
            Fragment::Slots(s) => s.reg.iter().map(|r| r.reset.clone()).chain(s.members.values().map(|f| f.reset())).fold(None, max_opt),
            f => f.meta().and_then(|m| m.reset.clone()),
        }
    }

    pub(crate) fn meta(&self) -> Option<&Meta> {
        match self {
            Fragment::Register(_) | Fragment::Slots(_) => None,
            Fragment::Bag(Bag { meta, .. })
            | Fragment::Set(Set { meta, .. })
            | Fragment::Struct(Struct { meta, .. })
            | Fragment::Enum(Enum { meta, .. })
            | Fragment::Map(Map { meta, .. })
            | Fragment::Seq(Seq { meta, .. }) => Some(meta),
        }
    }

    pub(crate) fn meta_mut(&mut self) -> Option<&mut Meta> {
        match self {
            Fragment::Register(_) | Fragment::Slots(_) => None,
            Fragment::Bag(Bag { meta, .. })
            | Fragment::Set(Set { meta, .. })
            | Fragment::Struct(Struct { meta, .. })
            | Fragment::Enum(Enum { meta, .. })
            | Fragment::Map(Map { meta, .. })
            | Fragment::Seq(Seq { meta, .. }) => Some(meta),
        }
    }

    /// Sets the own reset (a `Slots` member carrying the position's reset, §7).
    pub(crate) fn set_reset(&mut self, r: Option<Stamp>) {
        match self {
            Fragment::Register(x) => x.reset = r,
            Fragment::Slots(_) => {}
            f => {
                if let Some(m) = f.meta_mut() {
                    m.reset = r;
                }
            }
        }
    }

    /// Members of a `Slots` position, or the fragment itself.
    pub(crate) fn members(&self) -> Vec<MemberRef<'_>> {
        match self {
            Fragment::Slots(s) => s.reg.iter().map(MemberRef::Reg).chain(s.members.values().map(MemberRef::Frag)).collect(),
            f => vec![MemberRef::Frag(f)],
        }
    }

    /// The slot of encoding `enc` at this position (§7: ops write into their schema's slot).
    pub fn slot(&self, enc: Encoding) -> Option<MemberRef<'_>> {
        match self {
            Fragment::Slots(s) if enc == Encoding::Register => s.reg.as_ref().map(MemberRef::Reg),
            Fragment::Slots(s) => s.members.get(&enc).map(MemberRef::Frag),
            f if f.encoding() == enc => Some(MemberRef::Frag(f)),
            _ => None,
        }
    }

    /// Presence stamp `written` (§4.3).
    pub fn written(&self) -> Option<Stamp> {
        match self {
            Fragment::Register(r) => reg_written(r),
            Fragment::Slots(_) => self.chosen_member().with(Fragment::written),
            f => max_opt(f.meta().and_then(|m| m.w.clone()), f.inner_max(true)),
        }
    }

    /// Present iff `written` survives (§4.3); a state is pruned, so iff it exists.
    pub fn present(&self) -> bool {
        self.written().is_some()
    }

    /// Greatest stamp inside (children, elements, case), excluding own reset and `W`. With
    /// `valued`, only presence-counting writes (value-less ones are skipped, §4.3, §4.7).
    pub(crate) fn inner_max(&self, valued: bool) -> Option<Stamp> {
        let child = |f: &Fragment| if valued { max_opt(f.written(), f.reset()) } else { f.all_max() };
        let elems_max = |elems: &BTreeMap<Dot, Elem>| elems.values().fold(None, |m, e| max_opt(max_opt(m, e.reset.clone()), e.frag.as_deref().and_then(child)));
        match self {
            Fragment::Register(r) => r.write.as_ref().filter(|w| !valued || w.value.is_some()).map(|w| w.stamp.clone()),
            Fragment::Slots(_) => self.members().into_iter().fold(None, |m, f| max_opt(m, f.with(child))),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => elems_max(elems),
            Fragment::Struct(s) => s.fields.values().fold(None, |m, f| max_opt(m, child(f))),
            Fragment::Enum(s) => {
                let k = s.case.as_ref().filter(|k| !valued || k.case.is_some()).map(|k| k.stamp.clone());
                s.payloads.values().fold(k, |m, f| max_opt(m, child(f)))
            }
            Fragment::Map(m) => m.entries.values().fold(None, |x, e| max_opt(max_opt(x, e.reset.clone()), e.frag.as_deref().and_then(child))),
            Fragment::Seq(s) => seq::inner_max(s, valued),
        }
    }

    /// Greatest stamp of anything inside, own reset, `W` and value-less writes included (§7).
    pub(crate) fn all_max(&self) -> Option<Stamp> {
        let w = self.meta().and_then(|m| m.w.clone());
        max_opt(max_opt(self.inner_max(false), self.reset()), w)
    }

    /// No surviving write and no record at any depth (§4.2 Emptiness).
    pub fn is_empty(&self) -> bool {
        // records are grow-only and children are kept only while non-empty, so any child or
        // record means non-empty; only then do the own stamps decide (cheap at any size)
        let no_children = match self {
            Fragment::Register(r) => return r.reset.is_none() && r.write.is_none(),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => elems.is_empty(),
            Fragment::Struct(s) => s.fields.values().all(Fragment::is_empty),
            Fragment::Enum(s) => s.case.is_none() && s.payloads.values().all(Fragment::is_empty),
            Fragment::Map(m) => m.entries.is_empty(),
            Fragment::Seq(s) => !seq::has_records(s) && seq::inner_max(s, false).is_none(),
            Fragment::Slots(_) => return self.members().iter().all(|m| m.with(|f| f.is_empty())),
        };
        no_children && self.meta().is_none_or(|m| m.reset.is_none() && m.w.is_none())
    }

    /// The member a `Slots` position reads as: greatest stamp inside, ties by greater encoding
    /// id (§7 Read); the fragment itself otherwise.
    pub(crate) fn chosen(&self) -> Fragment {
        self.chosen_member().to_fragment()
    }

    /// `chosen` without cloning the member.
    pub(crate) fn chosen_member(&self) -> MemberRef<'_> {
        match self {
            Fragment::Slots(_) => {
                let key = |m: &MemberRef| (m.with(Fragment::all_max), m.with(Fragment::encoding));
                let mut best: Option<(MemberRef, _)> = None;
                for m in self.members() {
                    let k = key(&m);
                    if best.as_ref().is_none_or(|(_, bk)| k >= *bk) {
                        best = Some((m, k));
                    }
                }
                best.map_or(MemberRef::Frag(self), |(m, _)| m)
            }
            f => MemberRef::Frag(f),
        }
    }

    /// The read (§4.4, §5); `None` is absent.
    pub fn read(&self) -> Option<Value> {
        if !self.present() {
            return None;
        }
        match self {
            Fragment::Slots(_) => self.chosen_member().with(Fragment::read),
            Fragment::Register(r) => r.write.as_ref().and_then(|w| w.value.clone()),
            Fragment::Bag(b) => read_bag(b),
            Fragment::Struct(s) => Some(Value::Map(
                s.fields.iter().filter_map(|(k, f)| Some((Value::Int(i64::try_from(*k).ok()?), f.read()?))).collect(),
            )),
            Fragment::Enum(s) => {
                let id = s.case.as_ref()?.case?;
                Some(Value::Enum(id, s.payloads.get(&id).and_then(|f| f.read()).map(Box::new)))
            }
            Fragment::Set(s) => {
                // `insert` keeps the first of equal values: of equal links, the lowest live dot's
                // (§5.5; `collect` would keep the last).
                let mut out = std::collections::BTreeSet::new();
                for v in s.elems.values().filter_map(|e| e.frag.as_ref()?.read()) {
                    out.insert(v);
                }
                Some(Value::Set(out))
            }
            Fragment::Map(m) => {
                let mut by_key: BTreeMap<&Value, Fragment> = BTreeMap::new();
                for en in m.entries.values() {
                    if let (Some(k), Some(f)) = (&en.key, &en.frag)
                        && f.present()
                    {
                        match by_key.get_mut(k) {
                            None => {
                                by_key.insert(k, (**f).clone());
                            }
                            Some(g) => {
                                // same-key entries read as their join (§5.6)
                                g.join_into((**f).clone(), None, &mut Changes::new());
                            }
                        }
                    }
                }
                Some(Value::Map(by_key.into_iter().filter_map(|(k, f)| Some((k.clone(), f.read()?))).collect()))
            }
            Fragment::Seq(s) => seq::read(s),
        }
    }
}

/// A member of a position: the register slot or another fragment.
#[derive(Clone, Copy, Debug)]
pub enum MemberRef<'a> {
    Reg(&'a Register),
    Frag(&'a Fragment),
}

impl MemberRef<'_> {
    pub(crate) fn with<T>(&self, f: impl Fn(&Fragment) -> T) -> T {
        match self {
            MemberRef::Reg(r) => f(&Fragment::Register((*r).clone())),
            MemberRef::Frag(x) => f(x),
        }
    }
    pub fn to_fragment(self) -> Fragment {
        match self {
            MemberRef::Reg(r) => Fragment::Register((*r).clone()),
            MemberRef::Frag(x) => (*x).clone(),
        }
    }
}

fn reg_written(r: &Register) -> Option<Stamp> {
    r.write.as_ref().filter(|w| w.value.is_some()).map(|w| w.stamp.clone())
}

/// A register's reset below its own write is implied by the write, which resets everything older
/// at the position (§5.1, §7), so it goes.
fn drop_implied_reset(r: &mut Register, ch: &mut Changes) {
    if let (Some(w), Some(x)) = (r.write.as_ref(), r.reset.as_ref())
        && w.stamp > *x
    {
        ch.died(x, w.stamp.ts);
        r.reset = None;
    }
}

fn prune_write(w: &mut Option<RegWrite>, e: Option<&Stamp>, ch: &mut Changes) {
    if let (Some(x), Some(e)) = (w.as_ref(), e)
        && x.stamp < *e
    {
        ch.died(&x.stamp, e.ts);
        *w = None;
    }
}

fn prune_case(c: &mut Option<CaseWrite>, e: Option<&Stamp>, ch: &mut Changes) {
    if let (Some(x), Some(e)) = (c.as_ref(), e)
        && x.stamp < *e
    {
        ch.died(&x.stamp, e.ts);
        *c = None;
    }
}

/// Join across encodings (§7): pointwise per encoding, the register slot embedded into every
/// other slot, then one effective reset for the position.
fn join_slots(a: Fragment, b: Fragment, e_parent: Option<&Stamp>, ch: &mut Changes) -> Fragment {
    let (ra, mut ma) = parts(a);
    let (rb, mb) = parts(b);
    let reg = match (ra, rb) {
        (None, x) | (x, None) => x,
        (Some(x), Some(y)) => {
            let mut f = Fragment::Register(x);
            f.join_into(Fragment::Register(y), None, ch);
            match f {
                Fragment::Register(r) => Some(r),
                _ => None,
            }
        }
    };
    for (k, fb) in mb {
        match ma.get_mut(&k) {
            Some(fa) => fa.join_into(fb, None, ch),
            None => {
                ch.touch();
                ma.insert(k, fb);
            }
        }
    }
    prune_slots(reg, ma, e_parent, ch)
}

/// Prunes a position's members under its one effective reset (an own reset below it goes,
/// §4.2, §7) and assembles the canonical form.
fn prune_slots(reg: Option<Register>, members: BTreeMap<Encoding, Fragment>, e_parent: Option<&Stamp>, ch: &mut Changes) -> Fragment {
    // every member holds the register's embedding, whatever path the members came by (a
    // received snapshot's `Slots` included)
    let mut members = members;
    if let Some(r) = &reg {
        for (k, f) in members.iter_mut() {
            if let Some(e) = embed(r, *k) {
                f.join_into(e, None, ch);
            }
        }
    }
    let resets = reg.iter().map(|r| r.reset.clone()).chain(members.values().map(|f| f.reset()));
    let e = resets.fold(e_parent.cloned(), max_opt);
    let fix = |mut f: Fragment, ch: &mut Changes| {
        f.prune(e.as_ref(), ch);
        f
    };
    let reg = reg.and_then(|r| match fix(Fragment::Register(r), ch) {
        Fragment::Register(r) => Some(r),
        _ => None,
    });
    let members = members.into_iter().map(|(k, f)| (k, fix(f, ch))).collect();
    assemble(reg, members)
}

/// §5.2 order for max/min: ints by value; anything involving a float by IEEE 754 totalOrder.
fn num_cmp(a: &Value, b: &Value) -> Ordering {
    let f = |v: &Value| match v {
        Value::Int(i) => *i as f64,
        Value::Float(x) => x.get(),
        _ => f64::NAN,
    };
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x.cmp(y),
        _ => f(a).total_cmp(&f(b)),
    }
}

/// §5.2 read: counter sums (ints exactly, clamped; floats in dot order), max/min the extreme
/// with the lowest dot among equals. Non-numbers are ignored.
fn read_bag(b: &Bag) -> Option<Value> {
    let vals = b.elems.values().filter_map(|e| e.frag.as_ref()?.read()).filter(|v| matches!(v, Value::Int(_) | Value::Float(_)));
    match b.kind {
        BagKind::Counter => {
            let (mut si, mut sf, mut is_f) = (0i128, 0f64, false);
            for v in vals {
                match v {
                    Value::Int(i) => si = si.saturating_add(i128::from(i)),
                    Value::Float(x) => {
                        is_f = true;
                        sf += x.get();
                    }
                    _ => {}
                }
            }
            let si = si.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
            Some(if is_f { Value::Float(Float::new(sf + si as f64)) } else { Value::Int(si) })
        }
        BagKind::Max | BagKind::Min => {
            let max = b.kind == BagKind::Max;
            vals.reduce(|a, x| {
                let o = num_cmp(&a, &x);
                if (max && o.is_lt()) || (!max && o.is_gt()) { x } else { a }
            })
        }
    }
}

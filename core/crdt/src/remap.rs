//! Re-sourcing for imports (spec/permissions.md §7): every dot of a fragment (write stamps,
//! element identities, anchors, resets) mapped by a function; `ts` is kept. `Derived` dots map
//! through their underlying dot.

use crate::fragment::{Bag, Elem, Entry, Enum, Fragment, Meta, Register, Set, Slots, Struct};
use crate::seq::{Anchor, Seq, SeqContent, SeqElem};
use crate::stamp::{Dot, Source, SourceKind, Stamp};
use std::collections::BTreeMap;

type DotFn<'a> = &'a dyn Fn(&Dot) -> Option<Dot>;

fn dot(d: &Dot, f: DotFn<'_>) -> Dot {
    match d.src.kind() {
        SourceKind::Derived(inner) => match Source::derived(dot(inner, f)) {
            Some(s) => Dot::new(s, d.ctr),
            None => d.clone(),
        },
        _ => f(d).unwrap_or_else(|| d.clone()),
    }
}

fn stamp(s: &mut Stamp, f: DotFn<'_>) {
    s.dot = dot(&s.dot, f);
}

fn opt(s: &mut Option<Stamp>, f: DotFn<'_>) {
    if let Some(s) = s {
        stamp(s, f);
    }
}

fn meta(m: &mut Meta, f: DotFn<'_>) {
    opt(&mut m.reset, f);
    opt(&mut m.w, f);
}

fn register(r: &mut Register, f: DotFn<'_>) {
    opt(&mut r.reset, f);
    if let Some(w) = &mut r.write {
        stamp(&mut w.stamp, f);
    }
}

fn elems(m: &mut BTreeMap<Dot, Elem>, f: DotFn<'_>) {
    *m = std::mem::take(m)
        .into_iter()
        .map(|(d, mut e)| {
            opt(&mut e.reset, f);
            if let Some(x) = &mut e.frag {
                x.map_dots(f);
            }
            (dot(&d, f), e)
        })
        .collect();
}

fn anchor(a: &mut Anchor, f: DotFn<'_>) {
    if let Anchor::Dot(d) = a {
        *d = dot(d, f);
    }
}

fn seq(s: &mut Seq, f: DotFn<'_>) {
    meta(&mut s.meta, f);
    // per element: consecutive dots may map to different commits (imports remap deltas, which
    // the format bounds)
    *s.elems_mut() = crate::seq_span::expand(std::mem::take(s.elems_mut()))
        .into_iter()
        .map(|(d, mut e): (Dot, SeqElem)| {
            if let Some((st, a)) = &mut e.created {
                stamp(st, f);
                anchor(a, f);
            }
            for (st, a) in &mut e.pos {
                stamp(st, f);
                anchor(a, f);
            }
            if let Some((st, _)) = &mut e.deleted {
                stamp(st, f);
            }
            if let SeqContent::Frag(x) = &mut e.content {
                x.map_dots(f);
            }
            (dot(&d, f), e)
        })
        .collect();
}

/// Collects the writes of a fragment: every stamp with its `ts`, every element identity
/// (creation) without one; `Derived` dots as their owner's. Anchors are references, not writes.
struct Writes<'a>(&'a mut Vec<(Dot, Option<osis_base::Ts>)>);

impl Writes<'_> {
    fn stamp(&mut self, s: &Stamp) {
        self.0.push((s.dot.owner().clone(), Some(s.ts)));
    }
    fn opt(&mut self, s: &Option<Stamp>) {
        if let Some(s) = s {
            self.stamp(s);
        }
    }
    /// An element identity, with its creation's `ts` where the record carries it.
    fn elem(&mut self, d: &Dot, ts: Option<osis_base::Ts>) {
        self.0.push((d.owner().clone(), ts));
    }
    fn frag(&mut self, f: &Fragment) {
        match f {
            Fragment::Register(r) => {
                self.opt(&r.reset);
                if let Some(w) = &r.write {
                    self.stamp(&w.stamp);
                }
            }
            Fragment::Bag(Bag { meta: m, elems: e, .. }) | Fragment::Set(Set { meta: m, elems: e }) => {
                self.opt(&m.reset);
                self.opt(&m.w);
                for (d, x) in e {
                    // the value register is written only by the element's creation (§5.5)
                    let ts = match x.frag.as_deref() {
                        Some(Fragment::Register(r)) => r.write.as_ref().filter(|w| w.stamp.dot.src == d.src).map(|w| w.stamp.ts),
                        _ => None,
                    };
                    self.elem(d, ts);
                    self.opt(&x.reset);
                    if let Some(f) = &x.frag {
                        self.frag(f);
                    }
                }
            }
            Fragment::Struct(Struct { meta: m, fields }) => {
                self.opt(&m.reset);
                self.opt(&m.w);
                fields.values().for_each(|f| self.frag(f));
            }
            Fragment::Enum(Enum { meta: m, case, payloads }) => {
                self.opt(&m.reset);
                self.opt(&m.w);
                if let Some(c) = case {
                    self.stamp(&c.stamp);
                }
                payloads.values().for_each(|f| self.frag(f));
            }
            Fragment::Map(mp) => {
                self.opt(&mp.meta.reset);
                self.opt(&mp.meta.w);
                for (d, e) in &mp.entries {
                    self.elem(d, e.created.as_ref().map(|c| c.ts));
                    self.opt(&e.reset);
                    if let Some(f) = &e.frag {
                        self.frag(f);
                    }
                }
            }
            Fragment::Seq(s) => {
                self.opt(&s.meta.reset);
                self.opt(&s.meta.w);
                for (d, e) in crate::seq_span::expand(s.elems().clone()) {
                    self.elem(&d, e.created.as_ref().map(|(st, _)| st.ts));
                    if let Some((st, _)) = &e.created {
                        self.stamp(st);
                    }
                    for (st, _) in &e.pos {
                        self.stamp(st);
                    }
                    if let Some((st, _)) = &e.deleted {
                        self.stamp(st);
                    }
                    if let SeqContent::Frag(x) = &e.content {
                        self.frag(x);
                    }
                }
            }
            Fragment::Slots(Slots { reg, members }) => {
                if let Some(r) = reg {
                    self.opt(&r.reset);
                    if let Some(w) = &r.write {
                        self.stamp(&w.stamp);
                    }
                }
                members.values().for_each(|f| self.frag(f));
            }
        }
    }
}

/// `Fragment::holds_owned`: owner dot ranges against a predicate, stopping at the first hit.
struct Any<'a>(&'a dyn Fn(&Source, u64, u64) -> bool);

impl Any<'_> {
    /// Owner dots of elements `d..d + n` (a `Derived` range has one owner).
    fn range(&self, d: &Dot, n: u64) -> bool {
        match d.src.kind() {
            SourceKind::Derived(o) => (self.0)(&o.src, o.ctr, o.ctr.saturating_add(1)),
            _ => (self.0)(&d.src, d.ctr, d.ctr.saturating_add(n)),
        }
    }
    fn stamp(&self, s: &Stamp) -> bool {
        self.range(&s.dot, 1)
    }
    fn opt(&self, s: &Option<Stamp>) -> bool {
        s.as_ref().is_some_and(|s| self.stamp(s))
    }
    fn frag(&self, f: &Fragment) -> bool {
        match f {
            Fragment::Register(r) => self.opt(&r.reset) || r.write.as_ref().is_some_and(|w| self.stamp(&w.stamp)),
            Fragment::Bag(Bag { meta: m, elems: e, .. }) | Fragment::Set(Set { meta: m, elems: e }) => {
                self.opt(&m.reset) || self.opt(&m.w) || e.iter().any(|(d, x)| self.range(d, 1) || self.opt(&x.reset) || x.frag.as_deref().is_some_and(|f| self.frag(f)))
            }
            Fragment::Struct(Struct { meta: m, fields }) => self.opt(&m.reset) || self.opt(&m.w) || fields.values().any(|f| self.frag(f)),
            Fragment::Enum(Enum { meta: m, case, payloads }) => self.opt(&m.reset) || self.opt(&m.w) || case.as_ref().is_some_and(|c| self.stamp(&c.stamp)) || payloads.values().any(|f| self.frag(f)),
            Fragment::Map(mp) => self.opt(&mp.meta.reset) || self.opt(&mp.meta.w) || mp.entries.iter().any(|(d, e)| self.range(d, 1) || self.opt(&e.reset) || e.frag.as_deref().is_some_and(|f| self.frag(f))),
            Fragment::Seq(s) => {
                // a range record's creations are its elements' dots, its other stamps shared
                self.opt(&s.meta.reset)
                    || self.opt(&s.meta.w)
                    || s.elems().iter().any(|(d, e)| {
                        self.range(d, e.span)
                            || e.pos.iter().any(|(st, _)| st.dot != *d && self.stamp(st))
                            || e.deleted.as_ref().is_some_and(|(st, _)| self.stamp(st))
                            || matches!(&e.content, SeqContent::Frag(x) if self.frag(x))
                    })
            }
            Fragment::Slots(Slots { reg, members }) => reg.as_ref().is_some_and(|r| self.opt(&r.reset) || r.write.as_ref().is_some_and(|w| self.stamp(&w.stamp))) || members.values().any(|f| self.frag(f)),
        }
    }
}

impl Fragment {
    /// Whether some write's owner dot (as `writes` lists them) lies in a range `owned(src, lo,
    /// hi)` accepts (any counter in `lo..hi` owned); stops at the first, and never expands range
    /// records.
    pub fn holds_owned(&self, owned: &dyn Fn(&Source, u64, u64) -> bool) -> bool {
        Any(owned).frag(self)
    }
}

impl Fragment {
    /// Every write in this fragment by its owner dot: stamps with their `ts`, element
    /// creations (map entries, set and bag elements, sequence elements) with their creation's
    /// `ts` where the record carries it (a map entry's creation, a set or bag element's value
    /// register, a sequence element's creation stamp), else without (tombstones, bare anchors). For judging a snapshot's writes as their
    /// authors' (spec/permissions.md §5.2) and ranking them (§7).
    pub fn writes(&self) -> Vec<(Dot, Option<osis_base::Ts>)> {
        let mut out = Vec::new();
        Writes(&mut out).frag(self);
        out
    }

    /// Maps every dot (`f` sees non-`Derived` dots; `None` keeps the dot).
    pub fn map_dots(&mut self, f: &dyn Fn(&Dot) -> Option<Dot>) {
        match self {
            Fragment::Register(r) => register(r, f),
            Fragment::Bag(Bag { meta: m, elems: e, .. }) | Fragment::Set(Set { meta: m, elems: e }) => {
                meta(m, f);
                elems(e, f);
            }
            Fragment::Struct(Struct { meta: m, fields }) => {
                meta(m, f);
                for x in fields.values_mut() {
                    x.map_dots(f);
                }
            }
            Fragment::Enum(Enum { meta: m, case, payloads }) => {
                meta(m, f);
                if let Some(c) = case {
                    stamp(&mut c.stamp, f);
                }
                for x in payloads.values_mut() {
                    x.map_dots(f);
                }
            }
            Fragment::Map(mp) => {
                meta(&mut mp.meta, f);
                mp.entries = std::mem::take(&mut mp.entries)
                    .into_iter()
                    .map(|(d, mut e): (Dot, Entry)| {
                        opt(&mut e.reset, f);
                        opt(&mut e.created, f);
                        if let Some(x) = &mut e.frag {
                            x.map_dots(f);
                        }
                        (dot(&d, f), e)
                    })
                    .collect();
                mp.reindex();
            }
            Fragment::Seq(s) => seq(s, f),
            Fragment::Slots(Slots { reg, members }) => {
                if let Some(r) = reg {
                    register(r, f);
                }
                for x in members.values_mut() {
                    x.map_dots(f);
                }
            }
        }
    }
}

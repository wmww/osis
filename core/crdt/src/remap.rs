//! Re-sourcing for imports (spec/permissions.md §7): every dot of a fragment (write stamps,
//! element identities, anchors, resets) mapped by a function; `ts` is kept. `Derived` dots map
//! through their underlying dot. Also the one read-only walk over a fragment's writes (`walk`).

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
            for (st, a, k) in &mut e.pos {
                stamp(st, f);
                anchor(a, f);
                opt(k, f);
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

/// A record a write walk (`walk`) meets, before its reset and content.
#[derive(Clone, Copy)]
pub(crate) enum Rec<'a> {
    Elem(&'a Dot, &'a Elem),
    Entry(&'a Dot, &'a Entry),
    /// A sequence record (a range one too): its creation, position and flag writes are the
    /// visitor's to look at.
    Seq(&'a Dot, &'a SeqElem),
}

impl Rec<'_> {
    /// A set or bag element or map entry tombstone: it holds the remover's reset, not the
    /// creation, so it is no live write (spec/commits.md §5); a sequence record never is one (an
    /// anchor, spec/crdt.md §5.7).
    fn tomb(self) -> bool {
        match self {
            Rec::Elem(_, x) => x.frag.is_none(),
            Rec::Entry(_, e) => e.created.is_none(),
            Rec::Seq(..) => false,
        }
    }
}

/// What a walk does after a visitor looked at a record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Next {
    On,
    /// Its reset, but not into its content.
    NoContent,
    Stop,
}

/// A read-only walk over a fragment's writes.
pub(crate) trait Visit {
    /// A reset, `W`, register, case or element reset write; `true` stops the walk.
    fn stamp(&mut self, s: &Stamp) -> bool;
    fn rec(&mut self, r: Rec<'_>) -> Next;
}

fn opt_v(v: &mut dyn Visit, s: &Option<Stamp>) -> bool {
    s.as_ref().is_some_and(|s| v.stamp(s))
}

fn reg_v(v: &mut dyn Visit, r: &Register) -> bool {
    opt_v(v, &r.reset) || r.write.as_ref().is_some_and(|w| v.stamp(&w.stamp))
}

fn meta_v(v: &mut dyn Visit, m: &Meta) -> bool {
    opt_v(v, &m.reset) || opt_v(v, &m.w)
}

/// A record, then its reset, then its content.
fn rec_v(v: &mut dyn Visit, r: Rec<'_>, reset: &Option<Stamp>, content: Option<&Fragment>) -> bool {
    match v.rec(r) {
        Next::Stop => true,
        n => opt_v(v, reset) || (n == Next::On && content.is_some_and(|f| walk(v, f))),
    }
}

/// Walks `f`'s writes in fragment order (a position's reset and `W` first, records before their
/// reset and content) until the visitor stops it; `true` if it did. Never expands range records.
pub(crate) fn walk(v: &mut dyn Visit, f: &Fragment) -> bool {
    match f {
        Fragment::Register(r) => reg_v(v, r),
        Fragment::Bag(Bag { meta: m, elems: e, .. }) | Fragment::Set(Set { meta: m, elems: e }) => meta_v(v, m) || e.iter().any(|(d, x)| rec_v(v, Rec::Elem(d, x), &x.reset, x.frag.as_deref())),
        Fragment::Struct(Struct { meta: m, fields }) => meta_v(v, m) || fields.values().any(|f| walk(v, f)),
        Fragment::Enum(Enum { meta: m, case, payloads }) => meta_v(v, m) || case.as_ref().is_some_and(|c| v.stamp(&c.stamp)) || payloads.values().any(|f| walk(v, f)),
        Fragment::Map(mp) => meta_v(v, &mp.meta) || mp.entries.iter().any(|(d, e)| rec_v(v, Rec::Entry(d, e), &e.reset, e.frag.as_deref())),
        Fragment::Seq(s) => {
            meta_v(v, &s.meta)
                || s.elems().iter().any(|(d, e)| match v.rec(Rec::Seq(d, e)) {
                    Next::Stop => true,
                    n => n == Next::On && matches!(&e.content, SeqContent::Frag(x) if walk(v, x)),
                })
        }
        Fragment::Slots(Slots { reg, members }) => reg.as_ref().is_some_and(|r| reg_v(v, r)) || members.values().any(|f| walk(v, f)),
    }
}

/// Collects the writes of a fragment: every stamp with its `ts`, every element identity
/// (creation) without one; `Derived` dots as their owner's. Anchors are references, not writes.
/// `live`: tombstones (`Rec::tomb`) are left out.
struct Writes(Vec<(Dot, Option<osis_base::Ts>)>, bool);

impl Visit for Writes {
    fn stamp(&mut self, s: &Stamp) -> bool {
        self.0.push((s.dot.owner().clone(), Some(s.ts)));
        false
    }
    /// An element identity, with its creation's `ts` where the record carries it; a sequence
    /// element's writes per element.
    fn rec(&mut self, r: Rec<'_>) -> Next {
        match r {
            _ if self.1 && r.tomb() => {}
            Rec::Elem(d, x) => {
                // the value register is written only by the element's creation (§5.5)
                let ts = match x.frag.as_deref() {
                    Some(Fragment::Register(r)) => r.write.as_ref().filter(|w| w.stamp.dot.src == d.src).map(|w| w.stamp.ts),
                    _ => None,
                };
                self.0.push((d.owner().clone(), ts));
            }
            Rec::Entry(d, e) => self.0.push((d.owner().clone(), e.created.as_ref().map(|c| c.ts))),
            Rec::Seq(d, e) => {
                for k in 0..e.span {
                    let piece = (e.span > 1).then(|| crate::seq_span::piece(d, e, k, 1));
                    let (d, e) = piece.as_ref().map_or((d, e), |(d, e)| (d, e));
                    self.0.push((d.owner().clone(), e.created.as_ref().map(|(st, _)| st.ts)));
                    let stamps = e.created.iter().map(|x| &x.0).chain(e.pos.iter().map(|x| &x.0)).chain(e.deleted.iter().map(|x| &x.0));
                    stamps.for_each(|s| _ = self.stamp(s));
                }
            }
        }
        Next::On
    }
}

/// `Fragment::holds_owned`: owner dot ranges against a predicate, stopping at the first hit;
/// `live`: tombstones (`Rec::tomb`) are left out.
struct Any<'a>(&'a dyn Fn(&Source, u64, u64) -> bool, bool);

impl Any<'_> {
    /// Owner dots of elements `d..d + n` (a `Derived` range has one owner).
    fn range(&self, d: &Dot, n: u64) -> bool {
        match d.src.kind() {
            SourceKind::Derived(o) => (self.0)(&o.src, o.ctr, o.ctr.saturating_add(1)),
            _ => (self.0)(&d.src, d.ctr, d.ctr.saturating_add(n)),
        }
    }
}

impl Visit for Any<'_> {
    fn stamp(&mut self, s: &Stamp) -> bool {
        self.range(&s.dot, 1)
    }
    fn rec(&mut self, r: Rec<'_>) -> Next {
        let hit = match r {
            _ if self.1 && r.tomb() => false,
            Rec::Elem(d, _) | Rec::Entry(d, _) => self.range(d, 1),
            // a range record's creations are its elements' dots, its other stamps shared
            Rec::Seq(d, e) => self.range(d, e.span) || e.pos.iter().any(|(st, _, _)| st.dot != *d && self.range(&st.dot, 1)) || e.deleted.as_ref().is_some_and(|(st, _)| self.range(&st.dot, 1)),
        };
        if hit { Next::Stop } else { Next::On }
    }
}

impl Fragment {
    /// Whether some write's owner dot (as `writes` lists them) lies in a range `owned(src, lo,
    /// hi)` accepts (any counter in `lo..hi` owned); stops at the first, and never expands range
    /// records.
    pub fn holds_owned(&self, owned: &dyn Fn(&Source, u64, u64) -> bool) -> bool {
        walk(&mut Any(owned, false), self)
    }

    /// `holds_owned` of the writes the fragment holds (spec/commits.md §5, live writes): an
    /// element or entry tombstone, whose creation is gone, counts for its reset only; a
    /// sequence element's record counts (an anchor, spec/crdt.md §5.7).
    pub fn holds_owned_write(&self, owned: &dyn Fn(&Source, u64, u64) -> bool) -> bool {
        walk(&mut Any(owned, true), self)
    }
}

impl Fragment {
    /// Every write in this fragment by its owner dot: stamps with their `ts`, element
    /// creations (map entries, set and bag elements, sequence elements) with their creation's
    /// `ts` where the record carries it (a map entry's creation, a set or bag element's value
    /// register, a sequence element's creation stamp), else without (tombstones, bare anchors). For judging a snapshot's writes as their
    /// authors' (spec/permissions.md §5.2) and ranking them (§7).
    pub fn writes(&self) -> Vec<(Dot, Option<osis_base::Ts>)> {
        let mut w = Writes(Vec::new(), false);
        walk(&mut w, self);
        w.0
    }

    /// `writes` less element and entry tombstones (spec/commits.md §5, live writes; as
    /// `holds_owned_write` judges them): a tombstone holds the remover's reset, listed as its
    /// own stamp, not the creation.
    pub fn live_writes(&self) -> Vec<(Dot, Option<osis_base::Ts>)> {
        let mut w = Writes(Vec::new(), true);
        walk(&mut w, self);
        w.0
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

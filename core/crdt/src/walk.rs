//! The one read-only walk over a fragment's writes (`walk`).

use crate::fragment::{Bag, Eid, Elem, Entry, Enum, Fragment, Meta, Register, Set, Slots, Struct};
use crate::seq::{SeqContent, SeqElem};
use crate::stamp::{Dot, Source, SourceKind, Stamp};

/// A record a write walk (`walk`) meets, before its reset and content.
#[derive(Clone, Copy)]
pub(crate) enum Rec<'a> {
    Elem(&'a Dot, &'a Elem),
    Entry(&'a Eid, &'a Entry),
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
            Rec::Elem(_, x) => x.frag.is_none() && x.gone.is_none(),
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
        // a value removal's stamp with its record's reset (§5.5)
        Fragment::Bag(Bag { meta: m, elems: e, .. }) | Fragment::Set(Set { meta: m, elems: e, .. }) => meta_v(v, m) || e.iter().any(|(d, x)| rec_v(v, Rec::Elem(d, x), &x.reset, x.frag.as_deref()) || x.gone.as_ref().is_some_and(|g| v.stamp(&g.stamp))),
        Fragment::Struct(Struct { meta: m, fields }) => meta_v(v, m) || fields.values().any(|f| walk(v, f)),
        Fragment::Enum(Enum { meta: m, case, payloads }) => meta_v(v, m) || case.as_ref().is_some_and(|c| v.stamp(&c.stamp)) || payloads.values().any(|f| walk(v, f)),
        Fragment::Map(mp) => meta_v(v, &mp.meta) || mp.entries.iter().any(|(id, e)| rec_v(v, Rec::Entry(id, e), &e.reset, e.frag.as_deref())),
        Fragment::Seq(s) => {
            meta_v(v, &s.meta)
                || s.elems().iter().any(|(d, e)| match v.rec(Rec::Seq(d, e)) {
                    Next::Stop => true,
                    n => n == Next::On && matches!(&e.content, SeqContent::Frag(x) if walk(v, x)),
                })
        }
        Fragment::Slots(Slots { reg, slots }) => reg.as_ref().is_some_and(|r| reg_v(v, r)) || slots.values().any(|f| walk(v, f)),
    }
}

/// Collects the writes of a fragment: every stamp with its `ts`, every element identity
/// (creation) without one; `Derived` dots as their origin's. Anchors are references, not writes.
/// `live`: tombstones (`Rec::tomb`) are left out.
struct Writes(Vec<(Dot, Option<osis_base::Ts>)>, bool);

impl Visit for Writes {
    fn stamp(&mut self, s: &Stamp) -> bool {
        self.0.push((s.dot.origin().clone(), Some(s.ts)));
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
                    _ => x.gone.as_ref().filter(|g| g.stamp.dot.src == d.src).map(|g| g.stamp.ts),
                };
                self.0.push((d.origin().clone(), ts));
            }
            Rec::Entry(id, e) => self.0.push((id.dot.origin().clone(), e.created.as_ref().map(|c| c.ts))),
            Rec::Seq(d, e) => {
                for k in 0..e.span {
                    let piece = (e.span > 1).then(|| crate::seq_span::piece(d, e, k, 1));
                    let (d, e) = piece.as_ref().map_or((d, e), |(d, e)| (d, e));
                    self.0.push((d.origin().clone(), e.created.as_ref().map(|(st, _)| st.ts)));
                    let stamps = e.created.iter().map(|x| &x.0).chain(e.pos.iter().map(|x| &x.0)).chain(e.deleted.iter().map(|x| &x.0));
                    stamps.for_each(|s| _ = self.stamp(s));
                }
            }
        }
        Next::On
    }
}

/// `Fragment::holds_owned`: origin dot ranges against a predicate, stopping at the first hit;
/// `live`: tombstones (`Rec::tomb`) are left out.
struct Any<'a>(&'a dyn Fn(&Source, u64, u64) -> bool, bool);

impl Any<'_> {
    /// Origin dots of elements `d..d + n` (a `Derived` range has one origin).
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
            Rec::Elem(d, _) | Rec::Entry(Eid { dot: d, .. }, _) => self.range(d, 1),
            // a range record's creations are its elements' dots, its other stamps shared
            Rec::Seq(d, e) => self.range(d, e.span) || e.pos.iter().any(|(st, _, _)| st.dot != *d && self.range(&st.dot, 1)) || e.deleted.as_ref().is_some_and(|(st, _)| self.range(&st.dot, 1)),
        };
        if hit { Next::Stop } else { Next::On }
    }
}

impl Fragment {
    /// Whether some write's origin dot (as `writes` lists them) lies in a range `owned(src, lo,
    /// hi)` accepts (any counter in `lo..hi` owned); stops at the first, and never expands range
    /// records.
    #[cfg(test)]
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
    /// Every write in this fragment by its origin dot: stamps with their `ts`, element
    /// creations (map entries, set and bag elements, sequence elements) with their creation's
    /// `ts` where the record carries it (a map entry's creation, a set or bag element's value
    /// register, a sequence element's creation stamp), else without (tombstones, a sequence record
    /// whose creation is gone). For judging a snapshot's writes as their
    /// authors' (spec/permissions.md §5.2).
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
}

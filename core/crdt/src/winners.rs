//! The writes that win in a fragment (spec/crdt.md §4.8): the one definition of supersession. A
//! write of `a` is dead in `a ⊔ b` iff it wins in `a` and not in `a ⊔ b`; retention dates bodies
//! from that set (spec/commits.md §5).

use crate::fragment::{Bag, Elem, Enum, Fragment, Map, Meta, Register, Set, Slots, Struct};
use crate::seq::{Seq, SeqContent, SeqElem};
use crate::stamp::{Dot, Stamp};
use std::collections::{BTreeMap, BTreeSet};

/// A step from a position into one inside it. A `Slots` position adds none: its slots are one
/// position.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Place {
    Field(u64),
    /// An enum payload, by case.
    Case(u64),
    /// A map entry, by dot alone: its records are one entry (§5.6).
    Entry(Dot),
    /// A set or bag element.
    Elem(Dot),
    /// A sequence element (one element of a range record).
    Item(Dot),
    /// The content of the entry or element above: below its own writes (its reset prunes it,
    /// its content's writes supersede none of its own).
    In,
}

/// Which write at a position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// A position's, a map entry's or a set element's reset.
    Reset,
    /// A composite's explicit presence write.
    W,
    /// A register's write.
    Value,
    /// An enum's case write.
    Case,
    /// A map entry's or sequence element's creation.
    Created,
    /// A sequence element's position write (not its creation).
    Pos,
    /// A sequence element's deleted flag (text) or element reset (list).
    Flag,
}

/// A write by position: path, kind and stamp. Values are not part of it (a value-less copy is
/// the same write).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Won {
    pub path: Vec<Place>,
    pub kind: Kind,
    pub stamp: Stamp,
}

/// The writes that win in a fragment (`Fragment::winners`), by position.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Winners(BTreeMap<Vec<Place>, BTreeSet<(Kind, Stamp)>>);

impl Winners {
    pub fn contains(&self, w: &Won) -> bool {
        self.0.get(&w.path).is_some_and(|s| s.contains(&(w.kind, w.stamp.clone())))
    }
    pub fn len(&self) -> usize {
        self.0.values().map(BTreeSet::len).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = Won> + '_ {
        self.0.iter().flat_map(|(p, s)| s.iter().map(move |(k, st)| Won { path: p.clone(), kind: *k, stamp: st.clone() }))
    }
    /// The writes here that do not win in `o`.
    pub fn minus(&self, o: &Winners) -> BTreeSet<Won> {
        self.iter().filter(|w| !o.contains(w)).collect()
    }
    pub fn extend(&mut self, o: Winners) {
        for (p, s) in o.0 {
            self.0.entry(p).or_default().extend(s);
        }
    }
    fn put(&mut self, path: &[Place], kind: Kind, s: &Stamp) {
        self.0.entry(path.to_vec()).or_default().insert((kind, s.clone()));
    }
    /// The earliest write here that supersedes `w` (`supersedes`): at most a few writes per
    /// position on `w`'s path are looked at.
    pub fn superseder(&self, w: &Won) -> Option<Stamp> {
        (0..=w.path.len()).filter_map(|n| self.0.get(w.path.get(..n)?).map(|s| (n, s))).flat_map(|(n, s)| s.iter().filter(move |(k, st)| supersedes(n, *k, st, w))).map(|(_, st)| st.clone()).min()
    }
}

/// Whether the write `kind` stamped `s`, `depth` steps down `w`'s path, supersedes `w` (§4.8), as a
/// winner beside it:
/// - with a greater stamp, the same kind at the same position (beaten as a register, case,
///   flag or position winner; an element's creation is a position write too);
/// - with a greater stamp, a reset or a register write (it implies one, §5.1, §7) at or above
///   `w`, or a flag above it (a list element's reset): pruned;
/// - a flag at `w`'s own element when `w` is its creation, whatever its stamp (a text element
///   deleted; a winning flag beside a dead creation is a delete, or no earlier than the reset
///   that pruned it).
fn supersedes(depth: usize, kind: Kind, s: &Stamp, w: &Won) -> bool {
    let same = depth == w.path.len();
    if same && kind == Kind::Flag && w.kind == Kind::Created {
        return true;
    }
    *s > w.stamp
        && match kind {
            Kind::Reset | Kind::Value => true,
            Kind::Flag => !same || w.kind == Kind::Flag,
            k => same && (k == w.kind || k == Kind::Created && w.kind == Kind::Pos),
        }
}

impl Fragment {
    /// The writes that win here (§4.8), keyed by position (`Won`): every write the fragment
    /// holds, but
    /// - of a sequence element's position writes only the greatest (`cur`; its `prev` is
    ///   beaten), and only when it is not the creation's own (the creation is `Kind::Created`);
    /// - not a text element's creation under a delete (its record keeps it), but for an
    ///   embedded char (§7), which dies with its register's write;
    /// - of a map dot's records, the writes of their join (a write in one beaten at its position
    ///   by a write in another is dead, §5.6), the greatest reset and creation among them.
    ///
    /// Range records count per element. For a fragment in canonical form (a state or delta).
    pub fn winners(&self) -> Winners {
        let mut out = Winners::default();
        collect(self, &mut Vec::new(), &mut out);
        out
    }
}

fn opt(out: &mut Winners, path: &[Place], kind: Kind, s: &Option<Stamp>) {
    if let Some(s) = s {
        out.put(path, kind, s);
    }
}

fn meta(out: &mut Winners, path: &[Place], m: &Meta) {
    opt(out, path, Kind::Reset, &m.reset);
    opt(out, path, Kind::W, &m.w);
}

fn reg(out: &mut Winners, path: &[Place], r: &Register) {
    opt(out, path, Kind::Reset, &r.reset);
    if let Some(w) = &r.write {
        out.put(path, Kind::Value, &w.stamp);
    }
}

fn elems(out: &mut Winners, path: &mut Vec<Place>, m: &Meta, es: &BTreeMap<Dot, Elem>) {
    meta(out, path, m);
    for (d, e) in es {
        path.push(Place::Elem(d.clone()));
        opt(out, path, Kind::Reset, &e.reset);
        if let Some(f) = e.frag.as_deref() {
            inside(f, path, out);
        }
        path.pop();
    }
}

fn collect(f: &Fragment, path: &mut Vec<Place>, out: &mut Winners) {
    match f {
        Fragment::Register(r) => reg(out, path, r),
        Fragment::Slots(Slots { reg: r, slots }) => {
            if let Some(r) = r {
                reg(out, path, r);
            }
            slots.values().for_each(|x| collect(x, path, out));
        }
        Fragment::Bag(Bag { meta: m, elems: es, .. }) | Fragment::Set(Set { meta: m, elems: es }) => elems(out, path, m, es),
        Fragment::Struct(Struct { meta: m, fields }) => {
            meta(out, path, m);
            for (k, x) in fields {
                path.push(Place::Field(*k));
                collect(x, path, out);
                path.pop();
            }
        }
        Fragment::Enum(Enum { meta: m, case, payloads }) => {
            meta(out, path, m);
            if let Some(c) = case {
                out.put(path, Kind::Case, &c.stamp);
            }
            for (k, x) in payloads {
                path.push(Place::Case(*k));
                collect(x, path, out);
                path.pop();
            }
        }
        Fragment::Map(m) => map(out, path, m),
        Fragment::Seq(s) => seq(out, path, s),
    }
}

fn map(out: &mut Winners, path: &mut Vec<Place>, m: &Map) {
    meta(out, path, &m.meta);
    let mut it = m.entries.iter().peekable();
    while let Some((id, first)) = it.next() {
        let mut recs = vec![first];
        while let Some((x, e)) = it.peek()
            && x.dot == id.dot
        {
            recs.push(e);
            it.next();
        }
        path.push(Place::Entry(id.dot.clone()));
        opt(out, path, Kind::Reset, &recs.iter().filter_map(|e| e.reset.clone()).max());
        opt(out, path, Kind::Created, &recs.iter().filter_map(|e| e.created.clone()).max());
        let mut frags = recs.iter().filter_map(|e| e.frag.as_deref());
        if let Some(x) = frags.next() {
            match frags.next() {
                None => inside(x, path, out),
                Some(y) => {
                    let mut j = x.clone();
                    j.join(y.clone());
                    frags.for_each(|z| _ = j.join(z.clone()));
                    inside(&j, path, out);
                }
            }
        }
        path.pop();
    }
}

fn seq(out: &mut Winners, path: &mut Vec<Place>, s: &Seq) {
    meta(out, path, &s.meta);
    for (d, e) in s.elems() {
        for k in 0..e.span {
            let piece = (e.span > 1).then(|| crate::seq_span::piece(d, e, k, 1));
            let (d, e) = piece.as_ref().map_or((d, e), |(d, e)| (d, e));
            path.push(Place::Item(d.clone()));
            item(out, path, s.text, d, e);
            path.pop();
        }
    }
}

fn item(out: &mut Winners, path: &mut Vec<Place>, text: bool, d: &Dot, e: &SeqElem) {
    if let Some((c, _)) = &e.created
        && !(text && !d.src.is_derived() && e.flag())
    {
        out.put(path, Kind::Created, c);
    }
    if let Some(p) = e.pos.first()
        && p.0.dot != *d
    {
        out.put(path, Kind::Pos, &p.0);
    }
    if let Some((f, _)) = &e.deleted {
        out.put(path, Kind::Flag, f);
    }
    if let SeqContent::Frag(x) = &e.content {
        inside(x, path, out);
    }
}

/// A record's content, at `Place::In` below it.
fn inside(f: &Fragment, path: &mut Vec<Place>, out: &mut Winners) {
    path.push(Place::In);
    collect(f, path, out);
    path.pop();
}

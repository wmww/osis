//! The writes that win in a fragment (spec/crdt.md §4.8): the one definition of supersession. A
//! write of `a` is dead in `a ⊔ b` iff it wins in `a` and not in `a ⊔ b`; retention dates bodies
//! from that set (spec/commits.md §5).

use crate::fragment::{Bag, Elem, Enum, Fragment, Map, Meta, Register, Set, Slots, Struct};
use crate::seq::{Seq, SeqContent, SeqElem};
use crate::stamp::{Dot, Stamp};
use osis_base::Ts;
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
    /// A text element's deleted flag set (a delete).
    Delete,
    /// A text element's deleted flag cleared (an undelete): one register with `Delete`.
    Undelete,
    /// A list element's reset.
    ElemReset,
}

impl Kind {
    pub const ALL: [Kind; 9] = [Kind::Reset, Kind::W, Kind::Value, Kind::Case, Kind::Created, Kind::Pos, Kind::Delete, Kind::Undelete, Kind::ElemReset];
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
}

/// The positions on `w`'s path held in `m`, each with its depth (`supersedes`).
fn on_path<'a, V>(m: &'a BTreeMap<Vec<Place>, V>, w: &'a Won) -> impl Iterator<Item = (usize, &'a V)> + 'a {
    (0..=w.path.len()).filter_map(move |n| m.get(w.path.get(..n)?).map(|s| (n, s)))
}

/// Writes by position, each with a note: writes of several fragments (`note`: their winners, or
/// every write they hold, `Fragment::held_writes`), read
/// by write (`get`) or by the earliest of those superseding one (`first_superseding`).
#[derive(Clone, Debug)]
pub struct ByWrite<T>(BTreeMap<Vec<Place>, BTreeMap<(Kind, Stamp), T>>);

impl<T> Default for ByWrite<T> {
    fn default() -> Self {
        ByWrite(BTreeMap::new())
    }
}

impl<T: Default> ByWrite<T> {
    /// Notes each write of `w` (a `winners` or `held_writes` set) with `f`.
    pub fn note(&mut self, w: &Winners, mut f: impl FnMut(&mut T)) {
        for (p, s) in &w.0 {
            let at = self.0.entry(p.clone()).or_default();
            for k in s {
                f(at.entry(k.clone()).or_default());
            }
        }
    }
}

impl<T> ByWrite<T> {
    pub fn get(&self, w: &Won) -> Option<&T> {
        self.0.get(&w.path)?.get(&(w.kind, w.stamp.clone()))
    }
    /// How many writes are noted.
    pub fn len(&self) -> usize {
        self.0.values().map(BTreeMap::len).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// The least `date` among the writes here that supersede `w` (`supersedes`; `None`: that
    /// write is not counted), given that no write dates before its stamp's `ts`: per kind at
    /// each position on `w`'s path, the writes are read in stamp order from `w`'s until one
    /// stamped at or after the least date found, so about as many as supersede `w` earliest.
    pub fn first_superseding(&self, w: &Won, date: impl Fn(&T) -> Option<Ts>) -> Option<Ts> {
        let mut best: Option<Ts> = None;
        for (n, s) in on_path(&self.0, w) {
            for k in Kind::ALL {
                for ((_, st), t) in s.range((k, w.stamp.clone())..).take_while(|x| x.0.0 == k) {
                    if best.is_some_and(|b| st.ts >= b) {
                        break;
                    }
                    if supersedes(n, k, st, w)
                        && let Some(d) = date(t)
                    {
                        best = Some(best.map_or(d, |b| b.min(d)));
                    }
                }
            }
        }
        best
    }
}

/// Whether the write `kind` stamped `s`, `depth` steps down `w`'s path, supersedes `w` (§4.8), as a
/// winner beside it:
/// - with a greater stamp, the same kind at the same position (beaten as a register, case,
///   flag or position winner; a text element's delete and undelete are one flag register; an
///   element's creation is a position write too, and beats a text flag below it, the char
///   being one register over both, §5.7);
/// - with a greater stamp, a reset or a register write (it implies one, §5.1, §7) at or above
///   `w`, or a list element's reset above it: pruned;
/// - a delete at `w`'s own element stamped no earlier than `w` when `w` is its creation (but an
///   embedded char's, which dies with its register's write, §7) or an undelete (a delete wins
///   the flag on a tie).
fn supersedes(depth: usize, kind: Kind, s: &Stamp, w: &Won) -> bool {
    let same = depth == w.path.len();
    let embedded = matches!(w.path.last(), Some(Place::Item(d)) if d.src.is_derived());
    if same && kind == Kind::Delete && (w.kind == Kind::Created && !embedded || w.kind == Kind::Undelete) {
        return *s >= w.stamp;
    }
    let flag = |k: Kind| matches!(k, Kind::Delete | Kind::Undelete);
    *s > w.stamp
        && match kind {
            Kind::Reset | Kind::Value => true,
            Kind::ElemReset => !same || w.kind == Kind::ElemReset,
            k => same && (k == w.kind || flag(k) && flag(w.kind) || k == Kind::Created && (w.kind == Kind::Pos || flag(w.kind))),
        }
}

/// Where the walk puts the writes it finds: the winners (`Winners`), or a count of every copy
/// carried (`Copies`, `ALL`: no write left out).
trait Sink {
    const ALL: bool;
    fn put(&mut self, path: &[Place], kind: Kind, s: &Stamp);
}

impl Sink for Winners {
    const ALL: bool = false;
    fn put(&mut self, path: &[Place], kind: Kind, s: &Stamp) {
        self.0.entry(path.to_vec()).or_default().insert((kind, s.clone()));
    }
}

struct Held(Winners);

impl Sink for Held {
    const ALL: bool = true;
    fn put(&mut self, path: &[Place], kind: Kind, s: &Stamp) {
        self.0.put(path, kind, s);
    }
}

struct Copies(usize);

impl Sink for Copies {
    const ALL: bool = true;
    fn put(&mut self, _: &[Place], _: Kind, _: &Stamp) {
        self.0 += 1;
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

    /// Every write the fragment holds, winning or not (§4.8 When: a write held supersedes
    /// whether or not it wins there): `winners` and the writes it leaves out, a creation's own
    /// position write but as the creation.
    pub fn held_writes(&self) -> Winners {
        let mut out = Held(Winners::default());
        collect(self, &mut Vec::new(), &mut out);
        out.0
    }

    /// How many write copies the fragment carries, winning or not: a sequence element's `prev`
    /// position write, a deleted text element's creation, and a write held in several records
    /// of one map dot once per record. Prune only drops, so a fragment is prune-stable (§3.3
    /// rule 7) iff prune leaves this count as it is.
    pub(crate) fn carried(&self) -> usize {
        let mut out = Copies(0);
        collect(self, &mut Vec::new(), &mut out);
        out.0
    }
}

fn opt<S: Sink>(out: &mut S, path: &[Place], kind: Kind, s: &Option<Stamp>) {
    if let Some(s) = s {
        out.put(path, kind, s);
    }
}

fn meta<S: Sink>(out: &mut S, path: &[Place], m: &Meta) {
    opt(out, path, Kind::Reset, &m.reset);
    opt(out, path, Kind::W, &m.w);
}

fn reg<S: Sink>(out: &mut S, path: &[Place], r: &Register) {
    opt(out, path, Kind::Reset, &r.reset);
    if let Some(w) = &r.write {
        out.put(path, Kind::Value, &w.stamp);
    }
}

fn elems<S: Sink>(out: &mut S, path: &mut Vec<Place>, m: &Meta, es: &BTreeMap<Dot, Elem>) {
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

fn collect<S: Sink>(f: &Fragment, path: &mut Vec<Place>, out: &mut S) {
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

fn map<S: Sink>(out: &mut S, path: &mut Vec<Place>, m: &Map) {
    meta(out, path, &m.meta);
    let mut it = m.entries.iter().peekable();
    while let Some((id, first)) = it.next() {
        // winners: a map dot's records as one, their join; every copy: each record alone
        let mut recs = vec![first];
        while !S::ALL
            && let Some((x, e)) = it.peek()
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

fn seq<S: Sink>(out: &mut S, path: &mut Vec<Place>, s: &Seq) {
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

fn item<S: Sink>(out: &mut S, path: &mut Vec<Place>, text: bool, d: &Dot, e: &SeqElem) {
    if let Some((c, _)) = &e.created
        && (S::ALL || !(text && !d.src.is_derived() && e.flag()))
    {
        out.put(path, Kind::Created, c);
    }
    for p in e.pos.iter().take(if S::ALL { e.pos.len() } else { 1 }).filter(|p| p.0.dot != *d) {
        out.put(path, Kind::Pos, &p.0);
    }
    if let Some((f, del)) = &e.deleted {
        let kind = match (text, del) {
            (false, _) => Kind::ElemReset,
            (true, true) => Kind::Delete,
            (true, false) => Kind::Undelete,
        };
        out.put(path, kind, f);
    }
    if let SeqContent::Frag(x) = &e.content {
        inside(x, path, out);
    }
}

/// A record's content, at `Place::In` below it.
fn inside<S: Sink>(f: &Fragment, path: &mut Vec<Place>, out: &mut S) {
    path.push(Place::In);
    collect(f, path, out);
    path.pop();
}

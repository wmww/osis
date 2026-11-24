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
    /// A set's value removal, beside its elements, by its record's dot (§5.5). Its reference and
    /// parts are payload, decided by copy order like a value (§4.1), never which write it is: so
    /// are a set element's value, so its register sits at `In` whatever it holds. Which elements
    /// a removal hides is read in the copies held as they join (`held::Held`).
    Gone(Dot),
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

/// A write by position: path, kind and stamp. Values are not part of it (copies of one write
/// are one write).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Won {
    pub path: Vec<Place>,
    pub kind: Kind,
    pub stamp: Stamp,
}

/// The writes that win in a fragment (`Fragment::winners`), by position.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Winners(BTreeMap<Vec<Place>, BTreeSet<(Kind, Stamp)>>);

/// Write `w` at position `path`.
fn won(path: &[Place], w: &(Kind, Stamp)) -> Won {
    Won { path: path.to_vec(), kind: w.0, stamp: w.1.clone() }
}

impl Winners {
    pub fn iter(&self) -> impl Iterator<Item = Won> + '_ {
        self.0.iter().flat_map(|(p, s)| s.iter().map(move |w| won(p, w)))
    }
    /// The writes here that do not win in `o`. A register write winning there wins as a reset at
    /// its own stamp too: it implies one (§5.1, §7), so a reset of that stamp (a copy, §4.1, of
    /// another encoding at the position) is no death.
    pub fn minus(&self, o: &Winners) -> BTreeSet<Won> {
        let mut out = BTreeSet::new();
        for (p, s) in &self.0 {
            let theirs = o.0.get(p);
            let wins = |w: &(Kind, Stamp)| theirs.is_some_and(|t| t.contains(w) || w.0 == Kind::Reset && t.contains(&(Kind::Value, w.1.clone())));
            out.extend(s.iter().filter(|w| !wins(w)).map(|w| won(p, w)));
        }
        out
    }
    pub fn contains(&self, w: &Won) -> bool {
        self.0.get(&w.path).is_some_and(|s| s.contains(&(w.kind, w.stamp.clone())))
    }
    pub fn extend(&mut self, o: Winners) {
        for (p, s) in o.0 {
            self.0.entry(p).or_default().extend(s);
        }
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
/// - a delete at `w`'s own element stamped no earlier than `w` when `w` is its creation or an
///   undelete (a delete wins the flag on a tie).
pub(crate) fn supersedes(depth: usize, kind: Kind, s: &Stamp, w: &Won) -> bool {
    let same = depth == w.path.len();
    if same && kind == Kind::Delete && (w.kind == Kind::Created || w.kind == Kind::Undelete) {
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
    /// A set or bag element record at dot `d` of the set at `path`.
    fn elem(&mut self, _path: &[Place], _d: &Dot, _e: &Elem) {}
}

impl Sink for Winners {
    const ALL: bool = false;
    fn put(&mut self, path: &[Place], kind: Kind, s: &Stamp) {
        let w = (kind, s.clone());
        match self.0.get_mut(path) {
            Some(at) => at.insert(w),
            None => self.0.entry(path.to_vec()).or_default().insert(w),
        };
    }
}

struct Held(Winners);

impl Sink for Held {
    const ALL: bool = true;
    fn put(&mut self, path: &[Place], kind: Kind, s: &Stamp) {
        self.0.put(path, kind, s);
    }
}

/// Every set or bag element record, to a callback (`Fragment::each_set_elem`).
struct Elems<'a>(&'a mut dyn FnMut(&[Place], &Dot, &Elem));

impl Sink for Elems<'_> {
    const ALL: bool = true;
    fn put(&mut self, _: &[Place], _: Kind, _: &Stamp) {}
    fn elem(&mut self, path: &[Place], d: &Dot, e: &Elem) {
        (self.0)(path, d, e)
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
    /// - not a text element's creation under a delete (its record keeps it);
    /// - an embedded char's creation (§7: stamped `(s.ts, Derived(s.dot), i)`, with its own
    ///   position write) as register write `s` at the text's position: one write, whichever
    ///   copies hold it, dying with it, never by a delete;
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

    /// Whether every element the fragment holds is found by its dot alone: structs, enums,
    /// registers and sequences all the way down, no map (read by key), set or bag (by value)
    /// nor a position in several encodings. A read of a part at such a fragment's positions
    /// (`positions_at`) holds what any reader of those elements reads.
    pub fn found_by_dot(&self) -> bool {
        match self {
            Fragment::Register(_) => true,
            Fragment::Struct(s) => s.fields.values().all(Fragment::found_by_dot),
            Fragment::Enum(e) => e.payloads.values().all(Fragment::found_by_dot),
            Fragment::Seq(s) => s.elems().iter().all(|(_, e)| match &e.content {
                SeqContent::Frag(x) => x.found_by_dot(),
                _ => true,
            }),
            Fragment::Bag(_) | Fragment::Set(_) | Fragment::Map(_) | Fragment::Slots(_) => false,
        }
    }

    /// Calls `f` with every set or bag element record the fragment holds, hidden or not: its
    /// set's position, its dot and the record.
    pub(crate) fn each_set_elem(&self, f: &mut dyn FnMut(&[Place], &Dot, &Elem)) {
        collect(self, &mut Vec::new(), &mut Elems(f));
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
    // a value removal wins while held; an element it hides does not: it stays hidden (§5.5)
    let gone = if S::ALL { BTreeMap::new() } else { crate::fragment::removed(es) };
    for (d, e) in es {
        out.elem(path, d, e);
        if let Some(g) = &e.gone {
            under(path, Place::Gone(d.clone()), out, |path, out| out.put(path, Kind::Reset, &g.stamp));
        }
        under(path, Place::Elem(d.clone()), out, |path, out| {
            opt(out, path, Kind::Reset, &e.reset);
            if let Some(f) = e.frag.as_deref()
                && !crate::fragment::hidden(d, e, &gone)
            {
                inside(f, path, out);
            }
        });
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
        Fragment::Bag(Bag { meta: m, elems: es, .. }) | Fragment::Set(Set { meta: m, elems: es, .. }) => elems(out, path, m, es),
        Fragment::Struct(Struct { meta: m, fields }) => {
            meta(out, path, m);
            fields.iter().for_each(|(k, x)| under(path, Place::Field(*k), out, |path, out| collect(x, path, out)));
        }
        Fragment::Enum(Enum { meta: m, case, payloads }) => {
            meta(out, path, m);
            if let Some(c) = case {
                out.put(path, Kind::Case, &c.stamp);
            }
            payloads.iter().for_each(|(k, x)| under(path, Place::Case(*k), out, |path, out| collect(x, path, out)));
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
        under(path, Place::Entry(id.dot.clone()), out, |path, out| {
            opt(out, path, Kind::Reset, &recs.iter().filter_map(|e| e.reset.clone()).max());
            opt(out, path, Kind::Created, &recs.iter().filter_map(|e| e.created.clone()).max());
            let mut frags = recs.iter().filter_map(|e| e.frag.as_deref());
            if let Some(x) = frags.next() {
                let mut j = std::borrow::Cow::Borrowed(x);
                frags.for_each(|z| _ = j.to_mut().join(z.clone()));
                inside(&j, path, out);
            }
        });
    }
}

fn seq<S: Sink>(out: &mut S, path: &mut Vec<Place>, s: &Seq) {
    meta(out, path, &s.meta);
    for (d, e) in s.elems() {
        for k in 0..e.span {
            let piece = (e.span > 1).then(|| crate::seq_span::piece(d, e, k, 1));
            let (d, e) = piece.as_ref().map_or((d, e), |(d, e)| (d, e));
            under(path, Place::Item(d.clone()), out, |path, out| item(out, path, s.text, d, e));
        }
    }
}

fn item<S: Sink>(out: &mut S, path: &mut Vec<Place>, text: bool, d: &Dot, e: &SeqElem) {
    match &e.created {
        // a copy of register write `s` (§7 The embedding is the register's)
        Some((c, _)) if text && d.src.is_derived() && c.dot == *d => out.put(path.split_last().map_or(&[][..], |x| x.1), Kind::Value, &Stamp { ts: c.ts, dot: d.origin().clone() }),
        Some((c, _)) if S::ALL || !(text && e.deletes()) => out.put(path, Kind::Created, c),
        _ => {}
    }
    // the position write stamped with the element's dot is the creation's own (a dot is one
    // write, §2.1): no other is ever held, as the wire has no `PosW` for one (§3.3 rule 5)
    for p in e.pos.iter().take(if S::ALL { e.pos.len() } else { 1 }).filter(|p| p.0.dot != *d) {
        out.put(path, Kind::Pos, &p.0);
    }
    // a text flag write below the creation is held, beaten (§5.7), as `prev` is
    if let Some((f, del)) = &e.deleted
        && (S::ALL || !text || e.win_flag().is_some())
    {
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
    under(path, Place::In, out, |path, out| collect(f, path, out));
}

/// `f` at the position `p` below `path`.
fn under<S: Sink>(path: &mut Vec<Place>, p: Place, out: &mut S, f: impl FnOnce(&mut Vec<Place>, &mut S)) {
    path.push(p);
    f(path, out);
    path.pop();
}

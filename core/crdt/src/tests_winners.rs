//! The writes that win (spec/crdt.md §4.8, `Fragment::winners`): against a from-scratch,
//! pairwise definition over every write a fragment holds, and small examples of one write op
//! stamping many writes of which only some die.

use crate::fragment::{Elem, Fragment, Meta, RegWrite};
use crate::ops::{Op, PathOp, Writer};
use crate::seq::{Seq, SeqContent, SeqElem};
use crate::stamp::{Dot, Source, Stamp};
use crate::testutil::{TyView, frag, history, history_honest, joined, node, sink_no_seq, ts};
use crate::winners::{ByWrite, Hiders, Kind, Place, Winners, Won};
use crdt_model::ops::Ty;
use osis_base::{Tid, Ts, Value};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

/// A write as held, whether it wins or not, with what the pairwise rule needs to know.
#[derive(Clone, Debug)]
struct Raw {
    w: Won,
    /// A text element's creation, not an embedded char's (§7).
    text_creation: bool,
    /// A creation's own position write, or a register write's embedded char's creation (§7), as
    /// the copies held embed it: it supersedes, but is the creation's or the register write's,
    /// not a write of its own.
    shadow: bool,
    /// A register write's value (a set element's: the value its copy holds).
    value: Option<Value>,
    /// A set's value removal: its reference and parts.
    removal: Option<(Value, Vec<crate::stamp::DotRange>)>,
    /// A text copy of register write `w` (§7): its embedded char's record. The join applies no
    /// register write's reset from it and it beats only the creations of its record, though it
    /// is the register write (§4.8 When judges it as one).
    copy: Option<Dot>,
}

/// Every write `f` holds, by position as `winners` keys them: every record of a map dot, both
/// position writes of a sequence element, a deleted text element's creation; and the embedded
/// chars' creations of its register writes (`embedded`).
fn raw(f: &Fragment) -> Vec<Raw> {
    embedded(own(f))
}

/// `raw` but the embeddings.
fn own(f: &Fragment) -> Vec<Raw> {
    let mut out = Vec::new();
    walk(f, &mut Vec::new(), &mut out);
    out
}

/// `all` with the embedded chars' creations of its register writes as their copies join (§7):
/// the greatest register copy's string, or with none, the chars its text copies create.
fn embedded(mut all: Vec<Raw>) -> Vec<Raw> {
    let mut emb: BTreeMap<Won, Option<Option<Value>>> = BTreeMap::new();
    let mut texts: BTreeMap<Won, BTreeSet<u64>> = BTreeMap::new();
    for r in all.iter().filter(|r| r.w.kind == Kind::Value) {
        match &r.copy {
            Some(d) => _ = texts.entry(r.w.clone()).or_default().insert(d.ctr),
            None => {
                let v = emb.entry(r.w.clone()).or_default();
                if v.as_ref().is_none_or(|v| crate::state::opt_value_cmp(r.value.as_ref(), v.as_ref()).is_gt()) {
                    *v = Some(r.value.clone());
                }
            }
        }
    }
    let mut chars: BTreeMap<Won, BTreeSet<u64>> = texts;
    for (w, v) in emb {
        let n = match v {
            Some(Some(Value::Str(t))) => t.chars().count() as u64,
            _ => 0,
        };
        chars.insert(w, (1..=n).collect());
    }
    for (w, cs) in chars {
        let Some(src) = Source::derived(w.stamp.dot.clone()) else { continue };
        for i in cs {
            let d = Dot::new(src.clone(), i);
            let c = Won { path: [w.path.as_slice(), &[Place::Item(d.clone())]].concat(), kind: Kind::Created, stamp: Stamp { ts: w.stamp.ts, dot: d } };
            all.push(Raw { w: c, text_creation: false, shadow: true, value: None, removal: None, copy: None });
        }
    }
    all
}

fn put(out: &mut Vec<Raw>, path: &[Place], kind: Kind, s: &Stamp) {
    out.push(Raw { w: Won { path: path.to_vec(), kind, stamp: s.clone() }, text_creation: false, shadow: false, value: None, removal: None, copy: None });
}

fn walk(f: &Fragment, path: &mut Vec<Place>, out: &mut Vec<Raw>) {
    let meta = |out: &mut Vec<Raw>, path: &[Place], m: &Meta| {
        m.reset.iter().for_each(|s| put(out, path, Kind::Reset, s));
        m.w.iter().for_each(|s| put(out, path, Kind::W, s));
    };
    let inside = |f: &Fragment, path: &mut Vec<Place>, out: &mut Vec<Raw>| {
        path.push(Place::In);
        walk(f, path, out);
        path.pop();
    };
    let elems = |es: &BTreeMap<Dot, Elem>, path: &mut Vec<Place>, out: &mut Vec<Raw>| {
        for (d, e) in es {
            path.push(Place::Elem(d.clone()));
            e.reset.iter().for_each(|s| put(out, path, Kind::Reset, s));
            if let Some(x) = e.frag.as_deref() {
                inside(x, path, out);
            }
            path.pop();
        }
    };
    match f {
        Fragment::Register(r) => {
            r.reset.iter().for_each(|s| put(out, path, Kind::Reset, s));
            if let Some(w) = &r.write {
                put(out, path, Kind::Value, &w.stamp);
                out.last_mut().unwrap().value = w.value.clone();
            }
        }
        Fragment::Slots(s) => {
            if let Some(r) = &s.reg {
                walk(&Fragment::Register(r.clone()), path, out);
            }
            s.slots.values().for_each(|x| walk(x, path, out));
        }
        Fragment::Bag(b) => {
            meta(out, path, &b.meta);
            elems(&b.elems, path, out);
        }
        Fragment::Set(b) => {
            meta(out, path, &b.meta);
            for (d, e) in &b.elems {
                if let Some(g) = &e.gone {
                    path.push(Place::Gone(d.clone()));
                    put(out, path, Kind::Reset, &g.stamp);
                    out.last_mut().unwrap().removal = Some((g.value.clone(), g.seen.clone()));
                    path.pop();
                }
                path.push(Place::Elem(d.clone()));
                e.reset.iter().for_each(|s| put(out, path, Kind::Reset, s));
                if let Some(x) = e.frag.as_deref() {
                    let from = out.len();
                    inside(x, path, out);
                    let v = e.written().and_then(|w| w.0.cloned());
                    out[from..].iter_mut().filter(|r| r.w.kind == Kind::Value).for_each(|r| r.value = v.clone());
                }
                path.pop();
            }
        }
        Fragment::Struct(s) => {
            meta(out, path, &s.meta);
            for (k, x) in &s.fields {
                path.push(Place::Field(*k));
                walk(x, path, out);
                path.pop();
            }
        }
        Fragment::Enum(e) => {
            meta(out, path, &e.meta);
            e.case.iter().for_each(|c| put(out, path, Kind::Case, &c.stamp));
            for (k, x) in &e.payloads {
                path.push(Place::Case(*k));
                walk(x, path, out);
                path.pop();
            }
        }
        Fragment::Map(m) => {
            meta(out, path, &m.meta);
            for (id, e) in &m.entries {
                path.push(Place::Entry(id.dot.clone()));
                e.reset.iter().for_each(|s| put(out, path, Kind::Reset, s));
                e.created.iter().for_each(|s| put(out, path, Kind::Created, s));
                if let Some(x) = e.frag.as_deref() {
                    inside(x, path, out);
                }
                path.pop();
            }
        }
        Fragment::Seq(s) => {
            meta(out, path, &s.meta);
            for (d, e) in s.elems() {
                for k in 0..e.span {
                    let (d, e) = crate::seq_span::piece(d, e, k, 1);
                    path.push(Place::Item(d.clone()));
                    match &e.created {
                        // a copy of register write `(c.ts, d's origin)`, its own position write too (§7)
                        Some((c, _)) if s.text && d.src.is_derived() && c.dot == d => {
                            let at = path[..path.len() - 1].to_vec();
                            out.push(Raw { w: Won { path: at, kind: Kind::Value, stamp: Stamp { ts: c.ts, dot: d.origin().clone() } }, text_creation: false, shadow: false, value: None, removal: None, copy: Some(d.clone()) });
                        }
                        Some((c, _)) => out.push(Raw { w: Won { path: path.clone(), kind: Kind::Created, stamp: c.clone() }, text_creation: s.text, shadow: false, value: None, removal: None, copy: None }),
                        None => {}
                    }
                    for p in e.pos.iter().filter(|p| !(s.text && d.src.is_derived() && p.0.dot == d)) {
                        out.push(Raw { w: Won { path: path.clone(), kind: Kind::Pos, stamp: p.0.clone() }, text_creation: false, shadow: p.0.dot == d, value: None, removal: None, copy: None });
                    }
                    if let Some((st, v)) = &e.deleted {
                        let kind = match (s.text, v) {
                            (false, _) => Kind::ElemReset,
                            (true, true) => Kind::Delete,
                            (true, false) => Kind::Undelete,
                        };
                        out.push(Raw { w: Won { path: path.clone(), kind, stamp: st.clone() }, text_creation: false, shadow: false, value: None, removal: None, copy: None });
                    }
                    if let SeqContent::Frag(x) = &e.content {
                        inside(x, path, out);
                    }
                    path.pop();
                }
            }
        }
    }
}

/// Whether a write of `all` with a greater stamp resets `w` from at or above (a reset, or a
/// register write, which implies one) or resets the list element it is inside. In the join
/// (`when` false) a register write's text copy resets nothing; judged alone (§4.8 When) it is
/// the register write.
fn pruned(w: &Raw, all: &[Raw], when: bool) -> bool {
    let prefix = |p: &[Place]| w.w.path.starts_with(p);
    // a value removal of a set: its tid's elements there, hidden (§5.5)
    let removes = |s: &Raw| match (s.w.path.split_last(), w.w.path.as_slice(), &s.removal, &w.value) {
        (Some((Place::Gone(_), at)), [up @ .., Place::Elem(d), Place::In], Some((g, seen)), Some(v)) => at == up && g == v && seen.iter().any(|r| r.covers(d)),
        _ => false,
    };
    all.iter().any(|s| {
        s.w.stamp > w.w.stamp
            && match s.w.kind {
                Kind::Reset if removes(s) => true,
                Kind::Value if s.copy.is_some() && !when => false,
                Kind::Reset | Kind::Value => prefix(&s.w.path),
                Kind::ElemReset => s.w.path.len() < w.w.path.len() && prefix(&s.w.path),
                _ => false,
            }
    })
}

/// A text flag write: a delete or an undelete, one register.
fn is_flag(k: Kind) -> bool {
    matches!(k, Kind::Delete | Kind::Undelete)
}

/// Whether `s` beats `w` at its position: a greater stamp of the same kind (a flag of a flag),
/// a creation above a position write of its element (the creation is one of its position writes,
/// §5.7, held as `created` even once `pos` lets it go), or a text creation above a flag of its
/// element (the char is one register over both); of copies of one flag write, a delete beats an
/// undelete (§4.1 copy order). In the join (`when` false) a register write's text copy beats
/// only another's copy on its record (one creation per dot, §5.7), and is beaten so alone.
fn beats(s: &Raw, w: &Raw, when: bool) -> bool {
    if !when && (s.copy.is_some() || w.copy.is_some()) && s.w.kind == Kind::Value && w.w.kind == Kind::Value {
        return s.copy.is_some() && s.copy == w.copy && s.w.stamp > w.w.stamp;
    }
    let tie = s.w.stamp == w.w.stamp && s.w.kind == Kind::Delete && w.w.kind == Kind::Undelete;
    s.w.path == w.w.path && (tie || s.w.stamp > w.w.stamp && (s.w.kind == w.w.kind || is_flag(s.w.kind) && is_flag(w.w.kind) || s.w.kind == Kind::Created && (is_flag(w.w.kind) || w.w.kind == Kind::Pos)))
}

/// §4.8 from scratch: `w` is superseded among `all` (as joined) when it is pruned there, a write
/// there beats it at its position, or it is a text element's creation whose winning flag (of the
/// flags there at or above it and not pruned) is a delete.
fn superseded(w: &Raw, all: &[Raw]) -> bool {
    let pairwise = pruned(w, all, false) || all.iter().any(|s| beats(s, w, false));
    let deleted = w.text_creation && all.iter().filter(|s| is_flag(s.w.kind) && s.w.path == w.w.path && s.w.stamp >= w.w.stamp && !pruned(s, all, false)).max_by(|a, b| (&a.w.stamp, a.w.kind == Kind::Delete).cmp(&(&b.w.stamp, b.w.kind == Kind::Delete))).is_some_and(|f| f.w.kind == Kind::Delete);
    pairwise || deleted
}

/// §4.8 When, from scratch: whether `s` supersedes `w` alone (pruning it, beating it at its
/// position, or deleting its text element).
fn kills(s: &Raw, w: &Raw) -> bool {
    pruned(w, std::slice::from_ref(s), true) || beats(s, w, true) || w.text_creation && s.w.kind == Kind::Delete && s.w.path == w.w.path && s.w.stamp >= w.w.stamp
}

/// The writes of `all` none of `all` supersedes.
fn unsuperseded(all: &[Raw]) -> BTreeSet<Won> {
    all.iter().filter(|w| !w.shadow && !superseded(w, all)).map(|w| w.w.clone()).collect()
}

/// Random histories of `types`, joins of random subsets of their commits (as snapshots carry
/// them): `winners` is the from-scratch set of each, and the writes of one dead in a join of two
/// are those the other's writes supersede, so one the other holds supersedes each (`ByWrite`
/// of its `held_writes`; any clocks). Every write the bodies (deltas, and joins of them as snapshots) hold, noted by write
/// (`ByWrite`), each dated at its body's latest stamp: the earliest superseding a write is the
/// earliest body holding any write that supersedes it alone.
fn winners_check(seed: u64, types: &[Ty], honest: bool) {
    let mut r = crate::testutil::rng(seed | 1);
    let commits = if honest { history_honest(&mut r, types, 3, 4) } else { history(&mut r, types, 3, 4) };
    let bodies: Vec<Fragment> = commits.iter().map(|c| frag(&c.delta)).collect();
    first_superseding_check(&bodies);
    // bodies and joins of them, as snapshots, leaving and coming
    let mut some = bodies.clone();
    for _ in 0..2 {
        some.push(bodies.iter().filter(|_| r.chance(1, 2)).fold(Fragment::default(), |f, b| joined(&f, b)));
    }
    changes_check(&some, &mut r);
    for _ in 0..6 {
        let mut pick = || bodies.iter().filter(|_| r.chance(1, 2)).fold(Fragment::default(), |f, b| joined(&f, b));
        let (a, b) = (pick(), pick());
        let ab = joined(&a, &b);
        // joined bodies, as snapshots: a deleted text creation still supersedes
        first_superseding_check(&[a.clone(), b.clone()]);
        for x in [&a, &b, &ab] {
            let got: BTreeSet<Won> = x.winners().iter().collect();
            assert_eq!(got, unsuperseded(&raw(x)), "winners are the writes held that none held supersedes: {x:?}");
        }
        let both = unsuperseded(&embedded(own(&a).into_iter().chain(own(&b)).collect()));
        let want: BTreeSet<Won> = a.winners().iter().filter(|w| !both.contains(w)).collect();
        let dead = a.winners().minus(&ab.winners());
        assert_eq!(dead, want, "dead in a join: the winners the other side's writes supersede");
        let mut other: ByWrite<()> = ByWrite::default();
        other.note(&b.held_writes(), |_, _| ());
        // what the engine dates a death by (`Killed::note`): the writes held before and after the
        // join, winning or not (§4.8 When: a creation beats a position write below it though a
        // delete beat the creation)
        let mut held: ByWrite<()> = ByWrite::default();
        for x in [&a, &b, &ab] {
            held.note(&x.held_writes(), |_, _| ());
        }
        let mut hiders = Hiders::default();
        hiders.note(&a);
        hiders.note(&b);
        for w in &dead {
            assert!(held.first_superseding(w, &hiders, |s, _| Some(s.ts)).is_some(), "a dead write dies by a write held before or after the join: {w:?} in {ab:?}");
            assert!(a.holds_stamp(&w.stamp) || a.held_writes().iter().any(|x| x == *w && x.kind == Kind::Value), "a dead write is the side's by exact stamp (a register write's: or its embedding's): {w:?}");
            assert!(other.first_superseding(w, &hiders, |_, _| Some(w.stamp.ts)).is_some(), "a dead write dies by a write the other side holds: {w:?} in {ab:?}");
        }
    }
}

/// Each copy's payload as the copies of `all` join (§4.1 copy order): a set element's value, a
/// removal's reference and parts. Which elements a removal hides is read so (§4.8 Which write).
fn as_joined(all: &mut [Raw]) {
    let mut values: BTreeMap<Won, Option<Value>> = BTreeMap::new();
    let mut removals: BTreeMap<Won, (Value, Vec<crate::stamp::DotRange>)> = BTreeMap::new();
    for r in all.iter() {
        if r.w.kind == Kind::Value {
            let v = values.entry(r.w.clone()).or_default();
            if crate::state::opt_value_cmp(r.value.as_ref(), v.as_ref()).is_gt() {
                *v = r.value.clone();
            }
        }
        if let Some(g) = &r.removal {
            removals.entry(r.w.clone()).and_modify(|x| *x = x.clone().max(g.clone())).or_insert_with(|| g.clone());
        }
    }
    for r in all.iter_mut() {
        if let Some(v) = values.get(&r.w) {
            r.value = v.clone();
        }
        if let Some(g) = removals.get(&r.w) {
            r.removal = Some(g.clone());
        }
    }
}

/// `first_superseding` against the from-scratch earliest: each write's stamp, read from a body
/// holding it, and the bodies' own latest stamps as notes; a text element's creation only by
/// deletes after the latest undelete held (§4.8 When); hiding read in the copies as joined.
fn first_superseding_check(bodies: &[Fragment]) {
    let date = |b: &Fragment| own(b).iter().map(|x| x.w.stamp.ts).max().unwrap_or_default();
    let mut ix: ByWrite<Option<Ts>> = ByWrite::default();
    for b in bodies {
        let d = date(b);
        ix.note(&b.held_writes(), |_, x| *x = Some(x.map_or(d, |y| y.min(d))));
    }
    // each write with its body's date; an embedded char's creation with its register write's
    // earliest (held wherever the write is, §4.8 When)
    let mut all: Vec<Raw> = bodies.iter().flat_map(own).collect();
    let mut dates: Vec<Ts> = bodies.iter().flat_map(|b| std::iter::repeat_n(date(b), own(b).len())).collect();
    as_joined(&mut all);
    let n = all.len();
    let all = embedded(all);
    for r in &all[n..] {
        let Some(Place::Item(d)) = r.w.path.last() else { unreachable!() };
        let of = Won { path: r.w.path[..r.w.path.len() - 1].to_vec(), kind: Kind::Value, stamp: Stamp { ts: r.w.stamp.ts, dot: d.origin().clone() } };
        dates.push(all[..n].iter().zip(&dates).filter(|(x, _)| x.w == of).map(|(_, t)| *t).min().unwrap());
    }
    let mut hiders = Hiders::default();
    bodies.iter().for_each(|b| hiders.note(b));
    for w in all.iter().filter(|w| !w.shadow) {
        let undeleted = all.iter().filter(|s| s.w.kind == Kind::Undelete && s.w.path == w.w.path).map(|s| &s.w.stamp).max();
        let counts = |s: &Raw| kills(s, w) && !(w.text_creation && s.w.kind == Kind::Delete && undeleted.is_some_and(|u| s.w.stamp < *u));
        let want = all.iter().zip(&dates).filter(|(s, _)| counts(s)).map(|(_, d)| *d).min();
        assert_eq!(ix.first_superseding(&w.w, &hiders, |_, x| *x), want, "the earliest body superseding {w:?}");
        let by_stamp = all.iter().filter(|s| counts(s)).map(|s| s.w.stamp.ts).min();
        assert_eq!(ix.first_superseding(&w.w, &hiders, |s, _| Some(s.ts)), by_stamp, "the earliest write superseding {w:?}");
    }
    moved_by_check(bodies);
}

/// `moved_by`: noting the bodies one at a time, every write held before whose earliest
/// superseding write moves is one the new body's writes name.
fn moved_by_check(bodies: &[Fragment]) {
    let mut ix: ByWrite<()> = ByWrite::default();
    let mut hiders = Hiders::default();
    let mut held: BTreeSet<Won> = BTreeSet::new();
    for b in bodies {
        let was: Vec<Option<Ts>> = held.iter().map(|w| ix.first_superseding(w, &hiders, |s, _| Some(s.ts))).collect();
        let hw = b.held_writes();
        ix.note(&hw, |_, _| ());
        hiders.note(b);
        let named: BTreeSet<Won> = hw.iter().flat_map(|s| ix.moved_by(&s)).collect();
        for (w, was) in held.iter().zip(was) {
            let now = ix.first_superseding(w, &hiders, |s, _| Some(s.ts));
            assert!(now == was || named.contains(w), "{w:?} moved from {was:?} to {now:?}, unnamed by {:?}", hw.iter().collect::<Vec<_>>());
        }
        held.extend(hw.iter());
    }
}

/// The held writes and hiders of `bodies`, each body's writes counted (`ByWrite::note`).
fn index_of<'a>(bodies: impl IntoIterator<Item = &'a Fragment>) -> (ByWrite<usize>, Hiders) {
    let (mut ix, mut hiders) = (ByWrite::default(), Hiders::default());
    for b in bodies {
        ix.note(&b.held_writes(), |_, n| *n += 1);
        hiders.note(b);
    }
    (ix, hiders)
}

/// `forget` and `moved_by` over bodies leaving: from a random set of the bodies to another, the
/// leaving ones forgotten (`ByWrite::forget`, `Hiders::forget`) and the new ones noted, the
/// index is what noting the second set gives; and every write held in both whose earliest
/// superseding write moved is one that `moved_by`, on the index after, names for a write of a
/// body that left or came.
fn changes_check(bodies: &[Fragment], r: &mut crate::testutil::SeedRng) {
    for _ in 0..4 {
        let from: Vec<bool> = bodies.iter().map(|_| r.chance(1, 2)).collect();
        let to: Vec<bool> = bodies.iter().map(|_| r.chance(1, 2)).collect();
        let pick = |s: &[bool]| bodies.iter().zip(s.to_vec()).filter(|x| x.1).map(|x| x.0).collect::<Vec<_>>();
        let (was, was_hiders) = index_of(pick(&from));
        let (mut ix, mut hiders) = (was.clone(), was_hiders.clone());
        let mut changed = Winners::default();
        for (i, b) in bodies.iter().enumerate() {
            let hw = b.held_writes();
            if from[i] && !to[i] {
                ix.forget(&hw, |_, n| {
                    *n -= 1;
                    *n > 0
                });
                let mut own = Hiders::default();
                own.note(b);
                hiders.forget(&own);
                changed.extend(hw);
            } else if to[i] && !from[i] {
                ix.note(&hw, |_, n| *n += 1);
                hiders.note(b);
                changed.extend(hw);
            }
        }
        let (want, want_hiders) = index_of(pick(&to));
        assert_eq!(ix, want, "the index after bodies left and came is the one noting those held");
        assert_eq!(hiders, want_hiders, "the hiders after bodies left and came are those noting the copies held");
        let named: BTreeSet<Won> = changed.iter().flat_map(|s| ix.moved_by(&s)).collect();
        let held = |s: &[bool]| -> BTreeSet<Won> { pick(s).into_iter().flat_map(|b| b.held_writes().iter().collect::<Vec<_>>()).collect() };
        for w in held(&from).intersection(&held(&to)) {
            let (a, b) = (was.first_superseding(w, &was_hiders, |s, _| Some(s.ts)), ix.first_superseding(w, &hiders, |s, _| Some(s.ts)));
            assert!(a == b || named.contains(w), "{w:?} moved from {a:?} to {b:?}, unnamed by the writes that left or came");
        }
    }
}

proptest! {
    /// §4.8: `winners` against the pairwise definition, maps, structs, registers and bags.
    #[test]
    fn winners_from_scratch_spec_4_8(seed in any::<u64>()) {
        winners_check(seed, &[sink_no_seq()], seed % 2 == 0);
    }

    /// §4.8, §5.6, §5.7, §7: sequences at any depth, and positions written in several encodings
    /// (the last: composites created empty, so several slots' `W`s meet without a reset). The seed
    /// picks the type and honesty, so each takes a tenth of the cases.
    #[test]
    fn seq_winners_from_scratch_spec_4_8(seed in any::<u64>()) {
        let r = || Box::new(Ty::Register);
        let types = [
            vec![Ty::Text],
            vec![Ty::List(Box::new(Ty::Struct([(1, Ty::Register), (2, Ty::Text)].into_iter().collect())))],
            vec![Ty::Map(Box::new(Ty::Register), Box::new(Ty::Text))],
            vec![Ty::Text, Ty::Register, sink_no_seq()],
            vec![Ty::Set(r()), Ty::Map(r(), r()), Ty::List(r())],
        ];
        winners_check(seed, &types[(seed / 2 % 5) as usize], seed % 2 == 0);
    }
}

fn x() -> Source {
    node(1)
}

fn text_view() -> TyView {
    TyView(Ty::Text)
}

/// The delta of `ops` against `st`, written at `t` from counter `lo`.
fn edit(st: &Fragment, t: u64, lo: u64, ops: Vec<Op>) -> Fragment {
    let ops: Vec<PathOp> = ops.into_iter().map(|op| PathOp { path: vec![], op }).collect();
    crate::testutil::build(st, Writer::new(ts(t), x(), lo), &ops, &text_view()).unwrap().0
}

fn s(v: &str) -> Value {
    Value::Str(v.into())
}

/// The writes of `a` dead in `a ⊔ b`, by kind and stamp.
fn dead(a: &Fragment, b: &Fragment) -> Vec<(Kind, Stamp)> {
    a.winners().minus(&joined(a, b).winners()).into_iter().map(|w| (w.kind, w.stamp)).collect()
}

/// §4.1, §4.8: a register beaten by a greater stamp dies, a late older write dies on arrival,
/// a reset kills the writes below it.
#[test]
fn beaten_and_pruned_die_spec_4_8() {
    use crate::fragment::{RegWrite, Register, Struct};
    let st = |t: u64, c: u64| Stamp::new(ts(t), x(), c);
    let reg = |s: Stamp, v: i64| Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: s, value: Some(Value::Int(v)) }) });
    let field = |s: Stamp, v: i64| Fragment::Struct(Struct { fields: [(1, reg(s, v))].into_iter().collect(), ..Default::default() });
    let (a, b) = (field(st(1, 1), 1), field(st(2, 2), 2));
    assert_eq!(dead(&a, &b), vec![(Kind::Value, st(1, 1))]);
    assert_eq!(dead(&field(st(1, 3), 3), &b), vec![(Kind::Value, st(1, 3))], "a late older write");
    assert!(dead(&b, &a).is_empty());
    let mut reset = Struct::default();
    reset.meta.reset = Some(st(3, 4));
    assert_eq!(dead(&b, &Fragment::Struct(reset)), vec![(Kind::Value, st(2, 2))]);
}

/// §5.7 (the two greatest position writes): `pos` keeps the beaten `cur` as `prev`: one move writes the position of two elements
/// with one stamp; a later move of one of them kills that element's position write alone,
/// though its record keeps it.
#[test]
fn move_beaten_as_cur_dies_kept_as_prev_spec_4_8() {
    let ins = edit(&Fragment::default(), 1, 1, vec![Op::Insert { at: 0, items: vec![s("abc")] }]);
    let mv = edit(&ins, 2, 10, vec![Op::Move { at: 0, len: 2, to: 1 }]);
    let a = joined(&ins, &mv);
    assert_eq!(a.read(), Some(s("cab")));
    let moved: Vec<Won> = mv.winners().iter().filter(|w| w.kind == Kind::Pos).collect();
    assert_eq!(moved.len(), 2, "one move, two position writes");
    let again = edit(&a, 3, 20, vec![Op::Move { at: 1, len: 1, to: 2 }]);
    let ab = joined(&a, &again);
    assert_eq!(ab.read(), Some(s("cba")));
    let gone: Vec<Won> = a.winners().minus(&ab.winners()).into_iter().collect();
    assert_eq!(gone.len(), 1, "only the moved element's write: {gone:?}");
    assert!(moved.contains(&gone[0]));
    assert!(ab.holds_stamp(&gone[0].stamp), "kept as `prev`");
}

/// §4.8, §5.7: a flag write below its element's creation (forged) is beaten by it and held, as
/// `prev` is: it dies when the creation arrives, and the creation wins with its char.
#[test]
fn text_flag_below_creation_dies_kept_in_record_spec_4_8() {
    let d = Dot::new(x(), 5);
    let c = Stamp::new(ts(4), x(), 5);
    let del = Stamp::new(ts(2), node(2), 9);
    let one = |el: SeqElem| Fragment::Seq(Seq::new(true, Meta::default(), BTreeMap::from([(d.clone(), el)])));
    let flag = one(SeqElem { deleted: Some((del.clone(), true)), ..SeqElem::bare() });
    let created = one(SeqElem { created: Some((c.clone(), crate::seq::Anchor::Head)), content: SeqContent::Char('a'), pos: vec![(c, crate::seq::Anchor::Head, None)], ..SeqElem::bare() });
    assert_eq!(dead(&flag, &created), vec![(Kind::Delete, del.clone())]);
    let both = joined(&flag, &created);
    assert_eq!(both.read(), Some(s("a")));
    assert!(both.holds_stamp(&del), "its record keeps it");
    assert!(both.winners().iter().all(|w| w.kind != Kind::Delete));
}

/// §4.8 (its element deleted or tombstoned): deleting one char of an insert kills that element's creation
/// alone, though its record keeps it.
#[test]
fn text_creation_dies_at_delete_kept_in_record_spec_4_8() {
    let a = edit(&Fragment::default(), 1, 1, vec![Op::Insert { at: 0, items: vec![s("abc")] }]);
    let del = edit(&a, 2, 10, vec![Op::Delete { at: 1, len: 1 }]);
    let ab = joined(&a, &del);
    assert_eq!(ab.read(), Some(s("ac")));
    let gone: Vec<Won> = a.winners().minus(&ab.winners()).into_iter().collect();
    assert_eq!(gone.iter().map(|w| w.kind).collect::<Vec<_>>(), vec![Kind::Created], "{gone:?}");
    let created: Vec<Won> = a.winners().iter().filter(|w| w.kind == Kind::Created).collect();
    assert_eq!(created.len(), 3);
    assert_eq!(gone[0], created[1], "the middle char's");
    assert!(ab.holds_stamp(&gone[0].stamp), "its record keeps it");
    // an undelete over the delete: the creation wins again
    let mut un = Seq::empty(true);
    let Place::Item(d) = gone[0].path[0].clone() else { panic!() };
    un.elems_mut().insert(d, SeqElem { deleted: Some((Stamp::new(ts(3), x(), 30), false)), ..SeqElem::bare() });
    assert!(joined(&ab, &Fragment::Seq(un)).winners().iter().any(|x| x == gone[0]));
}

/// §5.6 (the records of a dot are one entry): one put writes k1 and k2 under one stamp; k1's value
/// held value-less in its key-erased record (a snapshot's copy of an expiring put) is beaten by
/// a later write in the keyed record: k1's write is dead, k2's not, though each record keeps
/// its own.
#[test]
fn record_pair_cross_death_spec_5_6() {
    use crate::ops::{create, diff};
    use crate::view::AnyView;
    let map = |k1: &str| Value::Map(osis_base::ValueMap::from([(s("k1"), s(k1)), (s("k2"), s("p"))]));
    let put = create(&mut Writer::new(ts(5), x(), 1), &AnyView, &map("p")).unwrap();
    let later = diff(&mut Writer::new(ts(8), x(), 20), Some(&put), &AnyView, &map("w")).unwrap().unwrap();
    let mut erased = put.clone();
    erased.strip(&|d| d.ctr < 20);
    let pw: BTreeSet<Won> = put.winners().iter().filter(|w| w.kind == Kind::Value).collect();
    assert_eq!(pw.len(), 2, "two values");
    assert_eq!(pw.iter().map(|w| &w.stamp).collect::<BTreeSet<_>>().len(), 1, "under one stamp");
    for (a, b) in [(&erased, &later), (&later, &erased)] {
        let ab = joined(a, b);
        let gone = erased.winners().minus(&ab.winners());
        assert_eq!(gone.len(), 1, "k1's value alone: {gone:?}");
        assert!(pw.contains(gone.iter().next().unwrap()));
        assert!(ab.holds_stamp(&gone.iter().next().unwrap().stamp), "each record keeps its write");
    }
}

/// A set of the given element records (§5.5).
fn set_of(elems: Vec<(Dot, Elem)>) -> Fragment {
    Fragment::Set(crate::fragment::Set { meta: Meta::default(), elems: elems.into_iter().collect() })
}

/// Set element `v` written at `s`.
fn elem_at(s: &Stamp, v: Value) -> Elem {
    use crate::fragment::{RegWrite, Register};
    Elem { reset: None, frag: Some(Box::new(Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: s.clone(), value: Some(v) }) }))), gone: None }
}

/// A value removal of `v` at `s`, naming the parts of `x()` from counter 1 below `hi`.
fn removal_at(s: &Stamp, v: Value, hi: u64) -> Elem {
    let seen = vec![crate::stamp::DotRange { first: Dot::new(x(), 1), hi }];
    Elem { reset: None, frag: None, gone: Some(crate::fragment::Removal { stamp: s.clone(), value: v, seen }) }
}

/// The writes a join of `y` into `st` kills, each dated as the engine dates it (`Killed::note`:
/// the writes held at the reach before and after the join and in `y`, and what hides a write in
/// the join), the reach law checked first.
fn killed(st: &Fragment, y: &Fragment) -> Vec<(Won, Option<Ts>)> {
    let after = joined(st, y);
    crate::tests_model::reach_holds_the_change(st, &after, y);
    let at = st.reach(y);
    let at_after = after.reach_after(y, &at);
    let mut before = at.winners();
    before.extend(y.winners());
    let mut by: ByWrite<()> = ByWrite::default();
    let mut hiders = Hiders::default();
    for f in [&at, y, &at_after] {
        by.note(&f.held_writes(), |_, _| ());
        hiders.note(f);
    }
    before.minus(&at_after.winners()).into_iter().map(|w| { let t = by.first_superseding(&w, &hiders, |s, _| Some(s.ts)); (w, t) }).collect()
}

/// §4.1 Copy order, §4.8 Which write: copies of a set element's write (one stamp) holding a
/// reference and a plain value, or two references, are one write: whichever copy wins the join,
/// nothing dies (a forged copy, as a snapshot carries it; a node finding a death with no
/// superseder there failed the join with a local error).
#[test]
fn set_element_copies_are_one_write_whatever_they_hold_spec_4_1() {
    let (d, s) = (Dot::new(x(), 1), Stamp::new(ts(5), x(), 1));
    let (strong, weak) = (Value::Strong(Tid::from_bytes([0; 15])), Value::Weak(Tid::from_bytes([2; 15])));
    for (a, b) in [(Value::Int(5), strong.clone()), (strong, weak)] {
        let (fa, fb) = (set_of(vec![(d.clone(), elem_at(&s, a.clone()))]), set_of(vec![(d.clone(), elem_at(&s, b.clone()))]));
        assert!(killed(&fa, &fb).is_empty(), "{a:?} then {b:?}");
        assert!(killed(&fb, &fa).is_empty(), "{b:?} then {a:?}");
    }
}

/// §4.1, §4.8 When, §5.5: a copy of a set element's write that wins the join and holds a reference
/// a held value removal names is hidden: the write dies at that removal, the one hiding it in the
/// state as joined, never at an earlier removal of the copy it replaced. And copies of a removal
/// naming other references are one write: the element the losing copy hid shows again (no
/// death), the one the winning copy hides dies at it.
#[test]
fn a_copy_hidden_by_a_removal_dies_at_it_spec_4_8() {
    let (t_a, t_b) = (Value::Strong(Tid::from_bytes([1; 15])), Value::Strong(Tid::from_bytes([2; 15])));
    let (d, s) = (Dot::new(x(), 1), Stamp::new(ts(5), x(), 1));
    let (ra, rb) = (Dot::new(x(), 7), Dot::new(x(), 8));
    // removals of A at t7 and of B at t9, both naming d's part
    let st = set_of(vec![(d.clone(), elem_at(&s, t_a.clone())), (rb.clone(), removal_at(&Stamp::new(ts(9), x(), 8), t_b.clone(), 4))]);
    let y = set_of(vec![(d.clone(), elem_at(&s, t_b.clone())), (ra.clone(), removal_at(&Stamp::new(ts(7), x(), 7), t_a.clone(), 4))]);
    for (a, b) in [(&st, &y), (&y, &st)] {
        let k = killed(a, b);
        assert_eq!(k.iter().map(|(w, t)| (w.kind, w.stamp.clone(), *t)).collect::<Vec<_>>(), vec![(Kind::Value, s.clone(), Some(ts(9)))], "dies at B's removal, never A's");
    }
    first_superseding_check(&[st.clone(), y.clone()]);
    // copies of one removal (t8), naming A in one and B in the other; e holds B
    let (e, se) = (Dot::new(x(), 2), Stamp::new(ts(5), x(), 2));
    let base = set_of(vec![(d.clone(), elem_at(&s, t_a.clone())), (e.clone(), elem_at(&se, t_b.clone())), (rb.clone(), removal_at(&Stamp::new(ts(8), x(), 8), t_a.clone(), 4))]);
    let copy = set_of(vec![(rb.clone(), removal_at(&Stamp::new(ts(8), x(), 8), t_b.clone(), 4))]);
    first_superseding_check(&[base.clone(), copy.clone()]);
    let k = killed(&base, &copy);
    assert_eq!(k.iter().map(|(w, t)| (w.path.clone(), *t)).collect::<Vec<_>>(), vec![(vec![Place::Elem(e.clone()), Place::In], Some(ts(8)))], "e dies at the removal as joined; d shows again");
    assert_eq!(joined(&base, &copy).read(), Some(Value::Set([t_a].into_iter().collect())));
}

/// §4.8 When, §5.5: a value removal hiding a set element's write supersedes it whether or not a
/// later reset of the element prunes it in the join: the write dies at the removal, the earliest
/// superseder, whether the reset arrives with it, after it or before the write (a node holding
/// more dates no later, spec/commits.md §5).
#[test]
fn a_removal_hides_a_write_a_later_reset_prunes_spec_4_8() {
    let b = Value::Strong(Tid::from_bytes([2; 15]));
    let (d, s) = (Dot::new(x(), 1), Stamp::new(ts(3), x(), 1));
    let w = set_of(vec![(d.clone(), elem_at(&s, b.clone()))]);
    let r = set_of(vec![(Dot::new(x(), 7), removal_at(&Stamp::new(ts(15), x(), 7), b, 4))]);
    let tomb = set_of(vec![(d, Elem::tomb(&Stamp::new(ts(29), x(), 9)))]);
    let rt = joined(&r, &tomb);
    let want = vec![(Kind::Value, s, Some(ts(15)))];
    for (st, y) in [(&w, &r), (&w, &rt), (&rt, &w)] {
        let k: Vec<(Kind, Stamp, Option<Ts>)> = killed(st, y).into_iter().map(|(w, t)| (w.kind, w.stamp, t)).collect();
        assert_eq!(k, want, "{st:?} then {y:?}");
    }
    first_superseding_check(&[w.clone(), r.clone(), tomb]);
    first_superseding_check(&[w, rt]);
}

/// What a node holding `held` dates `w` (a write of `held[0]`) at: `None` while the join of
/// `held` keeps it winning, else the earliest superseder by the held writes and the hiders noted
/// from `held` in that order (as `dated_replaced_at` reads the held bodies).
fn held_date(held: &[&Fragment], w: &Won) -> Option<Option<Ts>> {
    let joined = held.iter().fold(Fragment::default(), |f, b| joined(&f, b));
    if joined.winners().iter().any(|x| x == *w) {
        return None;
    }
    let (mut by, mut hiders) = (ByWrite::<()>::default(), Hiders::default());
    for b in held {
        by.note(&b.held_writes(), |_, _| ());
        hiders.note(b);
    }
    Some(by.first_superseding(w, &hiders, |s, _| Some(s.ts)))
}

fn perms(v: &[usize]) -> Vec<Vec<usize>> {
    if v.len() <= 1 {
        return vec![v.to_vec()];
    }
    (0..v.len())
        .flat_map(|i| {
            let mut rest = v.to_vec();
            let x = rest.remove(i);
            perms(&rest).into_iter().map(move |mut p| {
                p.insert(0, x);
                p
            })
        })
        .collect()
}

/// spec/commits.md §5 (nodes holding the same bodies judge alike; one holding more judges no later),
/// §4.8 When: `w`, the write of `bodies[0]`, dated by every held set holding it, in every
/// arrival order: `want` gives each set's date by mask over `bodies[1..]` (`None`: not dead), the
/// same in every order the set's bodies are noted; an apply's kill (`killed`) in every order of
/// every body is never earlier than its held set's date. With `monotone`, a set holding more
/// dates no later.
fn held_set_dates(bodies: &[Fragment], w: &Won, want: &[Option<Option<Ts>>], monotone: bool) {
    let n = bodies.len() - 1;
    let set = |mask: usize| -> Vec<usize> { std::iter::once(0).chain((0..n).filter(|i| mask >> i & 1 == 1).map(|i| i + 1)).collect() };
    let dates: Vec<Option<Option<Ts>>> = (0..1usize << n)
        .map(|mask| {
            let got: Vec<_> = perms(&set(mask)).iter().map(|p| held_date(&p.iter().map(|i| &bodies[*i]).collect::<Vec<_>>(), w)).collect();
            assert!(got.iter().all(|g| *g == got[0]), "set {mask:b}: alike in every order: {got:?}");
            assert_ne!(got[0], Some(None), "set {mask:b}: a dead write dates by a held superseder");
            assert_eq!(got[0], want[mask], "set {mask:b}");
            got[0]
        })
        .collect();
    if monotone {
        for (a, b) in (0..1usize << n).flat_map(|a| (0..1usize << n).map(move |b| (a, b))).filter(|(a, b)| a & b == *a && a != b) {
            if let (Some(Some(da)), Some(Some(db))) = (dates[a], dates[b]) {
                assert!(db <= da, "holding {b:b} dates no later than {a:b}");
            }
        }
    }
    let mut kills = 0;
    for p in perms(&(0..=n).collect::<Vec<_>>()) {
        let (mut st, mut mask, mut has_w) = (Fragment::default(), 0usize, false);
        for i in p {
            let k = killed(&st, &bodies[i]);
            st = joined(&st, &bodies[i]);
            has_w |= bodies[i].held_writes().iter().any(|x| x == *w);
            if i > 0 {
                mask |= 1 << (i - 1);
            }
            for (_, t) in k.into_iter().filter(|(k, _)| k == w) {
                kills += 1;
                assert!(has_w, "only a holder of {w:?} kills it");
                let (Some(Some(want)), Some(t)) = (dates[mask], t) else { panic!("a kill of {w:?} dated {t:?}, the held set {:?}", dates[mask]) };
                assert!(t >= want, "a kill of {w:?} dated {t:?} before its held set's {want:?}");
            }
        }
    }
    assert!(kills > 0, "some order kills {w:?}");
}

/// §4.8 When, §5.5, spec/commits.md §5: a write hidden by a removal (t15) and pruned by a later
/// reset (t29), and one hidden by two removals (t10, t20): every held set dates it alike in any
/// arrival order, holding more no later, by the earliest superseder held.
#[test]
fn hiding_dates_by_the_held_set_in_any_order_spec_4_8() {
    let b = Value::Strong(Tid::from_bytes([2; 15]));
    let (d, s) = (Dot::new(x(), 1), Stamp::new(ts(3), x(), 1));
    let won = Won { path: vec![Place::Elem(d.clone()), Place::In], kind: Kind::Value, stamp: s.clone() };
    let w = set_of(vec![(d.clone(), elem_at(&s, b.clone()))]);
    let r = |c: u64, t: u64| set_of(vec![(Dot::new(x(), c), removal_at(&Stamp::new(ts(t), x(), c), b.clone(), 4))]);
    let tomb = set_of(vec![(d.clone(), Elem::tomb(&Stamp::new(ts(29), x(), 9)))]);
    let at = |t| Some(Some(ts(t)));
    // masks over [R15, X29]
    held_set_dates(&[w.clone(), r(7, 15), tomb.clone()], &won, &[None, at(15), at(29), at(15)], true);
    // masks over [R10, R20, X29]
    held_set_dates(&[w.clone(), r(7, 10), r(8, 20), tomb.clone()], &won, &[None, at(10), at(20), at(10), at(29), at(10), at(20), at(10)], true);
    first_superseding_check(&[w, r(7, 10), r(8, 20), tomb]);
}

/// §4.1 Copy order, §4.8, §5.5: copies of one removal (t15), one naming the part holding the
/// write's dot, the other (greater, so it wins the join) not: the write is hidden only where the
/// covering copy alone is held, the date a function of the copies held, alike in every order. A
/// node holding the forged copy too dates later (t29, by the reset) or not at all: a forged copy
/// un-hides, so holding more dates later here (issues/forged-copy-undetected.md).
#[test]
fn removal_copies_covering_the_dot_in_one_date_by_the_joined_copy_spec_4_8() {
    let b = Value::Strong(Tid::from_bytes([2; 15]));
    let (d, s) = (Dot::new(x(), 1), Stamp::new(ts(3), x(), 1));
    let won = Won { path: vec![Place::Elem(d.clone()), Place::In], kind: Kind::Value, stamp: s.clone() };
    let w = set_of(vec![(d.clone(), elem_at(&s, b.clone()))]);
    let (rd, rs) = (Dot::new(x(), 7), Stamp::new(ts(15), x(), 7));
    let covering = set_of(vec![(rd.clone(), removal_at(&rs, b.clone(), 4))]);
    let seen = vec![crate::stamp::DotRange { first: Dot::new(x(), 2), hi: 4 }];
    let other = set_of(vec![(rd, Elem::removal(crate::fragment::Removal { stamp: rs, value: b, seen }))]);
    let tomb = set_of(vec![(d, Elem::tomb(&Stamp::new(ts(29), x(), 9)))]);
    let at = |t| Some(Some(ts(t)));
    // masks over [covering, other, X29]
    held_set_dates(&[w.clone(), covering.clone(), other.clone(), tomb.clone()], &won, &[None, at(15), None, None, at(29), at(15), at(29), at(29)], false);
    first_superseding_check(&[w, covering, other, tomb]);
}

/// §5.5 Live, §4.8: a removal hides a write only when its value is the removal's, its dot lies in
/// the removal's parts and it is stamped below the removal: at each boundary but the last (one
/// above), the write dies by the later reset alone (t29), never at the removal.
#[test]
fn a_removal_dates_only_writes_it_hides_spec_5_5() {
    let (b, c) = (Value::Strong(Tid::from_bytes([2; 15])), Value::Strong(Tid::from_bytes([3; 15])));
    let (d, s) = (Dot::new(x(), 1), Stamp::new(ts(3), x(), 1));
    let won = Won { path: vec![Place::Elem(d.clone()), Place::In], kind: Kind::Value, stamp: s.clone() };
    let w = set_of(vec![(d.clone(), elem_at(&s, b.clone()))]);
    let tomb = set_of(vec![(d, Elem::tomb(&Stamp::new(ts(29), x(), 9)))]);
    let removal = |rs: Stamp, v: Value, first: u64| {
        let seen = vec![crate::stamp::DotRange { first: Dot::new(x(), first), hi: 4 }];
        set_of(vec![(Dot::new(x(), 7), Elem::removal(crate::fragment::Removal { stamp: rs, value: v, seen }))])
    };
    let cases = [
        ("stamped as the write", removal(s.clone(), b.clone(), 1), None),
        ("stamped below", removal(Stamp::new(ts(2), x(), 7), b.clone(), 1), None),
        ("another value", removal(Stamp::new(ts(15), x(), 7), c, 1), None),
        ("parts not holding the dot", removal(Stamp::new(ts(15), x(), 7), b.clone(), 2), None),
        ("one above", removal(Stamp::new(ts(3), x(), 2), b, 1), Some(ts(3))),
    ];
    for (what, r, hides) in cases {
        assert_eq!(held_date(&[&w, &r], &won), hides.map(Some), "{what}: the removal alone");
        let want = hides.unwrap_or(ts(29));
        assert_eq!(held_date(&[&w, &r, &tomb], &won), Some(Some(want)), "{what}");
        for (st, y) in [(w.clone(), joined(&r, &tomb)), (joined(&w, &r), tomb.clone()), (joined(&r, &tomb), w.clone())] {
            let k: Vec<Option<Ts>> = killed(&st, &y).into_iter().filter(|(k, _)| *k == won).map(|(_, t)| t).collect();
            assert!(k.iter().all(|t| *t == Some(want)), "{what}: the kill {k:?}");
        }
        first_superseding_check(&[w.clone(), r, tomb.clone()]);
    }
}

/// §4.8 When (each superseder judged against the write alone), §5.7: a move of a text element
/// (t17) dies by the element's creation stamped above it (t19), though a delete (t38) beats the
/// creation: a held write that wins nowhere still supersedes. (A from-scratch seed's case.)
#[test]
fn a_move_dies_by_a_deleted_creation_above_it_spec_4_8() {
    let d = Dot::new(x(), 3);
    let mv = Stamp::new(ts(17), node(4), 1);
    let (c, del) = (Stamp::new(ts(19), x(), 3), Stamp::new(ts(38), node(4), 6));
    let one = |el: SeqElem| Fragment::Seq(Seq::new(true, Meta::default(), BTreeMap::from([(d.clone(), el)])));
    let moved = one(SeqElem { pos: vec![(mv.clone(), crate::seq::Anchor::Head, None)], ..SeqElem::bare() });
    let created = one(SeqElem { created: Some((c.clone(), crate::seq::Anchor::Head)), content: SeqContent::Char('a'), pos: vec![(c, crate::seq::Anchor::Head, None)], deleted: Some((del, true)), ..SeqElem::bare() });
    for (st, y) in [(&moved, &created), (&created, &moved)] {
        let k: Vec<(Kind, Stamp, Option<Ts>)> = killed(st, y).into_iter().map(|(w, t)| (w.kind, w.stamp, t)).collect();
        assert_eq!(k, vec![(Kind::Pos, mv.clone(), Some(ts(19)))], "{st:?} then {y:?}");
    }
    first_superseding_check(&[moved, created]);
}

/// §4.1, §5.1, §7: copies of one stamp (a forged copy), one a text's reset (`remove_aspect`), the
/// other a register write at the position: the write implies the reset, so it stands for it and
/// nothing dies, in either order.
#[test]
fn a_register_write_stands_for_a_reset_copy_of_its_stamp_spec_5_1() {
    use crate::fragment::{RegWrite, Register};
    let s = Stamp::new(ts(5), x(), 3);
    let reset = Fragment::Seq(Seq::new(true, Meta { reset: Some(s.clone()), ..Meta::default() }, BTreeMap::new()));
    let write = Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: s, value: Some(Value::Int(2)) }) });
    assert!(killed(&reset, &write).is_empty());
    assert!(killed(&write, &reset).is_empty());
}

/// §4.1, §4.8 When, §5.7: an undelete and a forged copy of its flag write that is a delete (one
/// stamp): the delete wins the tie, so the element's creation dies, at that stamp, as does the
/// undelete.
#[test]
fn a_delete_copy_of_an_undelete_kills_the_creation_at_its_stamp_spec_4_8() {
    let d = Dot::new(x(), 1);
    let (c, f) = (Stamp::new(ts(4), x(), 1), Stamp::new(ts(25), x(), 7));
    let one = |el: SeqElem| Fragment::Seq(Seq::new(true, Meta::default(), BTreeMap::from([(d.clone(), el)])));
    let undeleted = one(SeqElem { created: Some((c.clone(), crate::seq::Anchor::Head)), content: SeqContent::Char('d'), pos: vec![(c.clone(), crate::seq::Anchor::Head, None)], deleted: Some((f.clone(), false)), undel: Some('d'), ..SeqElem::bare() });
    let deleted = one(SeqElem { deleted: Some((f.clone(), true)), ..SeqElem::bare() });
    let k: Vec<(Kind, Stamp, Option<Ts>)> = killed(&undeleted, &deleted).into_iter().map(|(w, t)| (w.kind, w.stamp, t)).collect();
    assert_eq!(k, vec![(Kind::Created, c, Some(ts(25))), (Kind::Undelete, f, Some(ts(25)))]);
}

/// A text holding register write `s`'s embedded chars `(Derived(s.dot), i)` for `i` in `chars`
/// (1-based, with their chars), created at `(ts, Derived(s.dot), i)`, chained from HEAD: a copy
/// of `s`'s embedding (§7) when `ts` is `s.ts`, as a snapshot carries it.
fn embedded_text(s: &Stamp, ts: Ts, chars: &[(u64, char)]) -> Fragment {
    embedded_text_under(s, ts, chars, None)
}

/// `embedded_text` with reset `reset` (an embedding's own is its register write's stamp, §7).
fn embedded_text_under(s: &Stamp, ts: Ts, chars: &[(u64, char)], reset: Option<Stamp>) -> Fragment {
    let src = Source::derived(s.dot.clone()).unwrap();
    let mut prev = crate::seq::Anchor::Head;
    let mut elems = BTreeMap::new();
    for (i, c) in chars {
        let d = Dot::new(src.clone(), *i);
        let st = Stamp { ts, dot: d.clone() };
        elems.insert(d.clone(), SeqElem { created: Some((st.clone(), prev.clone())), content: SeqContent::Char(*c), pos: vec![(st, prev, None)], ..SeqElem::bare() });
        prev = crate::seq::Anchor::Dot(d);
    }
    Fragment::Seq(Seq::new(true, Meta { reset, ..Meta::default() }, elems))
}

/// §3.3 rule 7, §7, §4.8 When: a copy of register write `s`'s embedding carries the reset `s`
/// implies, so in a join it prunes what it supersedes in the held writes. A snapshot of a text
/// holding `s`'s embedded char without that reset is rejected by both decoders; with it, an
/// older char held beside it is dead in the join and its earliest superseder is `s`, alike.
/// Fails with the copy taken without its reset (the join keeps the older char, the held writes
/// date it at `s`).
#[test]
fn an_embedding_copy_carries_its_register_writes_reset_spec_7() {
    use crate::codec::{decode_snapshot, encode_snapshot};
    use crate::wire::Snapshot;
    let st = Stamp::new(ts(5), x(), 3);
    let (bare, under) = (embedded_text(&st, ts(5), &[(1, 'a')]), embedded_text_under(&st, ts(5), &[(1, 'a')], Some(st.clone())));
    for (f, ok) in [(&bare, false), (&under, true)] {
        let snap = Snapshot { absorbed: Default::default(), facts: Default::default(), nonce: [3; 16], fragment: f.clone(), frontiers: Default::default() };
        let b = encode_snapshot(&snap, &crate::testutil::snap_cx(), None).unwrap();
        assert_eq!(decode_snapshot(&b, &crate::testutil::snap_cx(), &mut crate::stamp::Interner::new(), None).is_ok(), ok, "{f:?}");
        let mcx = &mut crdt_model::wire::Ctx::new(1 << 40, crdt_model::stamp::Source::session(250, 0), 1);
        assert_eq!(crdt_model::wire::decode_snapshot(&b, mcx).is_ok(), ok, "the model: {f:?}");
    }
    let empty = Fragment::Seq(Seq::new(true, Meta::default(), BTreeMap::new()));
    let older = edit(&empty, 3, 1, vec![Op::Insert { at: 0, items: vec![s("q")] }]);
    let mut ix: ByWrite<()> = ByWrite::default();
    let mut hiders = Hiders::default();
    for b in [&older, &under] {
        ix.note(&b.held_writes(), |_, _| ());
        hiders.note(b);
    }
    let dead = dead(&older, &under);
    assert!(!dead.is_empty(), "the older char dies in the join");
    for w in older.winners().iter() {
        let first = ix.first_superseding(&w, &hiders, |s, _| Some(s.ts));
        assert_eq!(first.is_some(), dead.contains(&(w.kind, w.stamp.clone())), "{w:?}: superseded in the held writes iff dead in the join");
        assert!(first.is_none_or(|t| t == ts(5)), "{w:?} dies at s: {first:?}");
    }
    first_superseding_check(&[older, under]);
}

/// §7 One presence write per position, §4.8: a position's slots are one position, so an empty
/// map written (`W` at t3) and an empty list written later (`W` at t5) without a reset, unseen
/// by each other, meet as slots where the list's `W` beats the map's: the map's dies in the
/// join, as the held writes say (dated t5), and the joined position is the list alone. A
/// snapshot holding both as slots is refused by both decoders (prune would change it). Fails
/// with each slot keeping its own `W` (the join keeps the map's, the held writes date it).
#[test]
fn a_slots_presence_write_beats_a_lower_one_in_another_slot_spec_7() {
    use crate::codec::{decode_snapshot, encode_snapshot};
    use crate::fragment::{Map, Slots};
    use crate::wire::Snapshot;
    let w = |t: u64| Meta { w: Some(Stamp::new(ts(t), x(), 1)), ..Meta::default() };
    let map = Fragment::Map(Map { meta: w(3), entries: BTreeMap::new(), keys: BTreeMap::new() });
    let list = Fragment::Seq(Seq::new(false, w(5), BTreeMap::new()));
    for (a, b) in [(&map, &list), (&list, &map)] {
        assert_eq!(joined(a, b), list, "the list alone");
    }
    assert_eq!(dead(&map, &list), vec![(Kind::W, Stamp::new(ts(3), x(), 1))], "the map's W dies");
    let mut ix: ByWrite<()> = ByWrite::default();
    for b in [&map, &list] {
        ix.note(&b.held_writes(), |_, _| ());
    }
    for w in map.winners().iter() {
        assert_eq!(ix.first_superseding(&w, &Hiders::default(), |s, _| Some(s.ts)), Some(ts(5)), "{w:?}");
    }
    first_superseding_check(&[map.clone(), list.clone()]);
    let both = Fragment::Slots(Slots { reg: None, slots: [(map.encoding(), map.clone()), (list.encoding(), list.clone())].into_iter().collect() });
    let snap = Snapshot { absorbed: Default::default(), facts: Default::default(), nonce: [3; 16], fragment: both, frontiers: Default::default() };
    let b = encode_snapshot(&snap, &crate::testutil::snap_cx(), None).unwrap();
    assert!(decode_snapshot(&b, &crate::testutil::snap_cx(), &mut crate::stamp::Interner::new(), None).is_err(), "both slots' W refused");
    let mcx = &mut crdt_model::wire::Ctx::new(1 << 40, crdt_model::stamp::Source::session(250, 0), 1);
    assert!(crdt_model::wire::decode_snapshot(&b, mcx).is_err(), "the model refuses both slots' W");
}

/// §7 One presence write per position: a delta writing a text's `W` above a list slot's drops
/// that slot, so the join leaves the text alone; its reach is the whole position, before and
/// after, or the text's chars, outside the delta's footprint, would read as dying at the reach.
#[test]
fn a_presence_write_reaches_the_whole_slots_position_spec_7() {
    let w = |t: u64| Meta { w: Some(Stamp::new(ts(t), x(), t)), ..Meta::default() };
    let list = Fragment::Seq(Seq::new(false, w(1), BTreeMap::new()));
    let before = joined(&list, &edit(&Fragment::default(), 3, 10, vec![Op::Insert { at: 0, items: vec![s("ac")] }]));
    assert!(matches!(before, Fragment::Slots(_)));
    let y = Fragment::Seq(Seq::new(true, w(5), BTreeMap::new()));
    let after = joined(&before, &y);
    assert_eq!(after.read(), Some(s("ac")));
    assert!(matches!(after, Fragment::Seq(_)), "the list slot goes: {after:?}");
    crate::tests_model::reach_holds_the_change(&before, &after, &y);
}

fn string_reg(s: &Stamp, v: &str) -> Fragment {
    Fragment::Register(crate::fragment::Register { reset: None, write: Some(RegWrite { stamp: s.clone(), value: Some(Value::Str(v.into())) }) })
}

/// §7 The embedding is the register's, §4.8 Which write: a text's copies of register write `s`'s
/// embedding are `s` itself, whatever chars they hold. A forged copy creating three chars at the
/// embedding's stamps, beside `s` = "a": the join cuts it to the winning copy's one char, and
/// nothing dies, in either order; `s` dies once, at a later register write (t9), whichever copies
/// hold it. Fails with an embedded char's creation counted as a write of its own.
#[test]
fn an_embedding_copy_cut_to_the_winning_copy_is_no_death_spec_7() {
    let st = Stamp::new(ts(5), x(), 3);
    let reg = string_reg(&st, "a");
    let text = embedded_text(&st, ts(5), &[(1, 'a'), (2, 'b'), (3, 'c')]);
    assert!(killed(&reg, &text).is_empty(), "the copy joins a state holding s");
    assert!(killed(&text, &reg).is_empty(), "s joins a state holding the copy");
    assert_eq!(joined(&reg, &text).read(), Some(s("a")));
    let later = string_reg(&Stamp::new(ts(9), x(), 4), "z");
    let won = Won { path: vec![], kind: Kind::Value, stamp: st.clone() };
    let at = |t| Some(Some(ts(t)));
    // masks over [the register copy, the later write]: the text copy alone holds s
    held_set_dates(&[text.clone(), reg.clone(), later.clone()], &won, &[None, None, at(9), at(9)], true);
    first_superseding_check(&[text, reg, later]);
}

/// §4.1 Copy order, §7: a `Slots` body holding register copy "ab" of `s` with its embedding (and
/// an insert after it, so the text slot stays) beside a register copy "é" of `s`: "é" wins by
/// copy order and the text slot's embedded records follow it, the second char's creation cut:
/// one write, no death, in either order; so with a list copy winning, which embeds no char.
/// Fails with an embedded char's creation counted as a write of its own.
#[test]
fn an_embedding_losing_by_copy_order_is_no_death_spec_4_1() {
    let st = Stamp::new(ts(5), x(), 3);
    let ab = string_reg(&st, "ab");
    let ins = edit(&ab, 6, 10, vec![Op::Insert { at: 2, items: vec![s("z")] }]);
    let slots = joined(&ab, &ins);
    assert!(matches!(slots, Fragment::Slots(_)), "{slots:?}");
    let e = string_reg(&st, "é");
    // a list winning by copy order embeds no char at all
    let list = Fragment::Register(crate::fragment::Register { reset: None, write: Some(RegWrite { stamp: st.clone(), value: Some(Value::List(vec![])) }) });
    for w in [&e, &list] {
        for (a, b) in [(&slots, w), (w, &slots)] {
            assert!(killed(a, b).is_empty(), "{a:?} then {b:?}");
        }
        first_superseding_check(&[slots.clone(), w.clone()]);
    }
    assert_eq!(joined(&slots, &e).read(), Some(s("éz")));
}

/// §7, §5.7 Join (one creation per dot, the greater stamp wins): a text copy of `s`'s embedding
/// and a forged creation of its char under a later `ts` (t7), held with no register copy: the
/// later creation is a copy of register write `(t7, s.dot)`, which beats `s` at its position, so
/// `s` dies at t7; with `s` held as a register write it wins there, and nothing dies.
#[test]
fn an_embedded_char_created_later_beats_the_copy_as_a_register_write_spec_7() {
    let st = Stamp::new(ts(5), x(), 3);
    let (copy, late) = (embedded_text(&st, ts(5), &[(1, 'a')]), embedded_text(&st, ts(7), &[(1, 'q')]));
    let k: Vec<(Kind, Stamp, Option<Ts>)> = killed(&copy, &late).into_iter().map(|(w, t)| (w.kind, w.stamp, t)).collect();
    assert_eq!(k, vec![(Kind::Value, st.clone(), Some(ts(7)))]);
    assert!(killed(&late, &copy).iter().all(|(w, _)| w.stamp != Stamp { ts: ts(7), dot: st.dot.clone() }));
    let reg = string_reg(&st, "a");
    let held = joined(&copy, &reg);
    assert!(killed(&held, &late).is_empty(), "s held as a register write wins");
    first_superseding_check(&[copy, late, reg]);
}

/// §7, §4.8: copies of register write `s`'s embedding are one write across its records. A text
/// holding `s`'s copies on two chars, and a forged creation of the second under a later `ts`
/// (t7): the copy on the first still holds `s`, so nothing of `s` dies, judged at the join's reach
/// as in the whole state (a copy's join reads the whole text). Fails with the reach of a copy
/// read at its own records alone.
#[test]
fn an_embedding_copy_beaten_on_one_char_lives_on_another_spec_7() {
    let st = Stamp::new(ts(5), x(), 3);
    let (copy, late) = (embedded_text(&st, ts(5), &[(1, 'a'), (2, 'b')]), embedded_text(&st, ts(7), &[(2, 'q')]));
    let Fragment::Seq(l) = &late else { unreachable!() };
    let mut second = Seq::empty(true);
    second.elems_mut().extend(l.elems().iter().map(|(d, e)| (Dot::new(d.src.clone(), 2), SeqElem { created: e.created.clone().map(|(c, _)| (Stamp { ts: c.ts, dot: Dot::new(d.src.clone(), 2) }, crate::seq::Anchor::Head)), pos: e.pos.iter().map(|p| (Stamp { ts: p.0.ts, dot: Dot::new(d.src.clone(), 2) }, crate::seq::Anchor::Head, None)).collect(), ..e.clone() })));
    let late = Fragment::Seq(second);
    assert!(killed(&copy, &late).iter().all(|(w, _)| w.stamp != st), "{:?}", killed(&copy, &late));
    first_superseding_check(&[copy, late]);
}

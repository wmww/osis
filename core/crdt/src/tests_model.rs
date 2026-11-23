//! G3, the crdt's property (notes/crdt.md): what the crdt computes equals the reference model
//! (core/test/crdt-model), whose join is lawful (its own law tests). One differential over every
//! encoding: random histories joined in random orders with duplicates (state and read after every
//! join, spec/crdt.md §4, §5, §7), the wire (delta and snapshot bytes, both decoders, §3), strip
//! (§4.7) and un-merge (§4.6), honest and hostile.

use crate::codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot};
use crate::fragment::Fragment;
use crate::seq::SeqContent;
use crate::stamp::{Dot, Interner};
use crate::testutil::{MCommit, check_bound, check_lin, frag, history_twins, history_with, mapply, node, ostate, sink_no_seq, snapshot, source, value};
use crate::tests_seq::{as_carried, map_of_text};
use crate::testutil::{joined, snap_cx, writer_cx};
use crate::wire::{Delta, Frontiers, Snapshot};
use crdt_model::ops::{Ty, Writer as MWriter};
use crdt_model::r#gen::{Rng, kitchen_sink};
use crdt_model::stamp::{Dot as MDot, Source as MSource};
use crdt_model::state::Frag as MFrag;
use crdt_model::wire::Ctx;
use std::collections::{BTreeMap, BTreeSet};

/// How much the differential runs (notes/testing.md, Sizes): `Plain` the quick check,
/// `Small` at the gate, `Large` in release checks. Only the seed count differs, so any seed replays alone at
/// any size.
#[derive(Clone, Copy, Debug)]
enum Size {
    Plain,
    Small,
    Large,
}

impl Size {
    /// `Large` under `OSIS_FULL=1`, else `Small`.
    fn from_env() -> Size {
        if osis_base::testenv::u64_var("OSIS_FULL") == Some(1) { Size::Large } else { Size::Small }
    }
    fn seeds(self) -> std::ops::Range<u64> {
        match self {
            Size::Plain => 0..100,
            Size::Small => 0..1000,
            Size::Large => 0..10_000,
        }
    }
}

/// What a seed's history stresses, by seed index (every mode at every size).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Mode {
    /// The kitchen sink: every encoding, nested.
    Sink,
    /// Writers of different encodings at one position, at the root or below struct fields (§7).
    Slots,
    /// Maps whose entries hold texts and lists; lists of structs (§5.6, §5.7); chains appended
    /// a commit an element.
    Nested,
    /// Writers 0 and 1 share a source and clock: copies of one write with differing payloads
    /// (§4.1 copy order), one dot under two stamps.
    Twins,
    /// Single-record writes on a text or list no honest writer makes: creation chains anchored
    /// anywhere, forged copies, cycles, register writes of strings (§5.7, §6.2, §7).
    Hostile,
}

const MODES: [Mode; 5] = [Mode::Sink, Mode::Slots, Mode::Nested, Mode::Twins, Mode::Hostile];

/// A seed's history: deltas in creation order, each with its writer where it has a wire form.
#[derive(Clone)]
struct Case {
    mode: Mode,
    deltas: Vec<(MFrag, Option<MWriter>)>,
    /// No two copies of one write differ.
    honest: bool,
    /// Un-merged (§4.6) at the end.
    bad: MSource,
    /// Stripped (§4.7) on every snapshot.
    gone: Gone,
}

/// The dots of one source up to a counter, expiring.
#[derive(Clone)]
struct Gone {
    src: MSource,
    upto: u64,
}

impl Gone {
    fn model(&self) -> impl Fn(&MDot) -> bool + '_ {
        |d| d.source == self.src && d.ctr <= self.upto
    }
    fn ours(&self) -> impl Fn(&Dot) -> bool + '_ {
        let src = source(&self.src);
        move |d| d.src == src && d.ctr <= self.upto
    }
}

fn inner() -> Ty {
    Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect())
}

fn pick<T: Clone>(r: &mut Rng, xs: &[T]) -> T {
    xs[r.below(xs.len())].clone()
}

/// Writer sources: nodes' sessions, sessions of one node beside others' (31-byte `Source`, order
/// by tid then nonce, §2.1), or commit form (own source sorting below the other commits, §3.3).
fn sources(r: &mut Rng, n: usize) -> Vec<MSource> {
    match r.below(3) {
        0 => (1..=n as u8).map(|i| MSource::session(i, 0)).collect(),
        1 => [MSource::session(1, 0xf0), MSource::session(2, 0), MSource::session(1, 0x10), MSource::session(3, 0x80)].into_iter().cycle().take(n).collect(),
        _ => [0x80u8, 0x10, 0xf0, 0x40].iter().cycle().take(n).map(|b| MSource::Commit([*b; 32])).collect(),
    }
}

fn case(k: u64) -> (crate::testutil::SeedRng, Case) {
    let mode = MODES[(k % MODES.len() as u64) as usize];
    let mut r = crate::testutil::rng(2 * k + 1);
    let rounds = if r.chance(1, 8) { 10 } else { 3 + r.below(3) };
    let from = |cs: Vec<MCommit>| cs.into_iter().map(|c| (c.delta, Some(c.w))).collect::<Vec<_>>();
    let (deltas, honest) = match mode {
        Mode::Sink => {
            let n = 2 + r.below(2);
            let srcs = sources(&mut r, n);
            (from(history_with(&mut r, &[kitchen_sink()], srcs, rounds)), true)
        }
        Mode::Slots => {
            let a = Ty::Struct([(1, Ty::Register), (2, Ty::Counter), (3, Ty::Text)].into_iter().collect());
            let b = Ty::Struct([(1, Ty::Max), (2, Ty::Set(Box::new(Ty::Register))), (3, Ty::List(Box::new(Ty::Register)))].into_iter().collect());
            let types = if r.chance(1, 3) {
                vec![a, b]
            } else {
                let all = [Ty::Register, Ty::Counter, Ty::Max, Ty::Min, Ty::Text, Ty::List(Box::new(Ty::Register)), Ty::Set(Box::new(Ty::Register)), Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register)), sink_no_seq(), a, b];
                (0..2 + r.below(3)).map(|_| pick(&mut r, &all)).collect()
            };
            let srcs = sources(&mut r, types.len().max(3));
            (from(history_with(&mut r, &types, srcs, rounds)), true)
        }
        Mode::Nested => {
            let types = pick(&mut r, &[map_of_text(), vec![Ty::List(Box::new(inner()))], vec![Ty::Text, Ty::List(Box::new(Ty::Register))]]);
            let srcs = sources(&mut r, 3);
            // half the time the expiring writer first appends alone, a commit an element:
            // value-less ranges whose creations differ in `ts` (`seq_span`)
            let lead = if r.chance(1, 2) { 6 } else { 0 };
            (from(crate::testutil::history_led(&mut r, &types, srcs, lead, rounds)), true)
        }
        Mode::Twins => {
            let types = pick(&mut r, &[vec![kitchen_sink()], vec![Ty::Text], vec![Ty::List(Box::new(Ty::Register))], vec![Ty::Register, Ty::Text, Ty::Counter, Ty::Set(Box::new(Ty::Register))], map_of_text()]);
            let srcs = vec![MSource::session(1, 0), MSource::session(1, 0), MSource::session(2, 0)];
            // a forged copy reaches a node as bytes (a snapshot: a twin's delta may carry its
            // twin's dots): each delta as the wire carries it, one it cannot carry dropped as bad
            // input (a position write stamped with its element's dot, §3.3 rule 5)
            let carried = |d: &MFrag| crdt_model::wire::decode_snapshot(&crdt_model::wire::encode_snapshot(d, &[], [3; 16], &mut snap_mcx()), &mut snap_mcx()).ok().map(|x| x.0);
            (from(history_twins(&mut r, &types, srcs, rounds)).into_iter().filter_map(|(d, w)| Some((carried(&d)?, w))).collect(), false)
        }
        Mode::Hostile => {
            let (list, slots) = pick(&mut r, &[(false, false), (false, true), (true, false)]);
            (crdt_model::r#gen::hostile(&mut r, list, slots).into_iter().map(|d| (d, None)).collect(), false)
        }
    };
    let writers: Vec<MSource> = deltas.iter().filter_map(|(_, w)| w.as_ref().map(|w| w.source.clone())).collect();
    let bad = writers.iter().find(|s| Some(*s) != writers.first()).cloned().unwrap_or(MSource::session(2, 0));
    let gone = match writers.first() {
        Some(s) => Gone { src: s.clone(), upto: u64::MAX },
        None => Gone { src: MSource::session(1, 0), upto: 6 },
    };
    (r, Case { mode, deltas, honest, bad, gone })
}

fn mread(m: &Option<MFrag>) -> Option<osis_base::Value> {
    m.as_ref().and_then(|m| m.read()).map(|v| value(&v))
}

/// What the crdt answers that the model has no counterpart for, on state `x` before joining
/// delta `y` (spec/commits.md §5): the piece at `y`'s positions joins into `x` unchanged, so
/// `contains` is sound (exact for a sequence); an honest holder of `y`'s writes holds them with
/// `y`'s payloads (covering copies); `y`'s writes the piece supersedes are those the whole state
/// does (the engine dates a body's deaths at its positions, `retention::bounds::deaths`).
fn piece_laws(x: &Fragment, y: &Fragment, honest: bool) {
    let part = x.part_at(y);
    assert_eq!(&joined(x, &part), x, "a piece joins in unchanged");
    let mine = y.winners();
    assert_eq!(mine.minus(&joined(&part, y).winners()), mine.minus(&joined(x, y).winners()), "a piece supersedes what the whole does");
    let unchanged = &joined(x, y) == x;
    assert!(!crate::testutil::contains(x, y) || unchanged, "contains only what joins in unchanged");
    if matches!(x, Fragment::Seq(_)) {
        assert_eq!(crate::testutil::contains(x, y), unchanged, "a sequence's piece judges as the whole");
    }
    if honest && unchanged {
        let mut vl = BTreeSet::new();
        y.valueless_dots(&mut vl);
        let ix = y.copy_index();
        let mut p = part.clone();
        p.remove_writes(&|d| ix.holds(d) && !vl.contains(d));
        p.join(y.clone());
        assert_eq!(p, part, "an honest holder's copies are the body's");
    }
}

/// A join of `y` changes the values a state reads only at `y`'s reach (`Fragment::reach`,
/// `reach_after`): `before` and `after` differ as their pieces at the reach do, each set element
/// read apart (`Values::ReadEach`), and the references they read (`each_read_value`, a set's
/// equal values once) likewise, and the links (a link's content may hold references): the
/// engine's reference index counts a join there alone (notes/engine-refs.md), so the reach holds
/// every element equal to a value holding a reference or link it reaches; equal values without
/// one read once as well, which nothing counts, so the reach need not hold them together. The writes it supersedes, read at the reaches as the
/// engine dates them (`Killed::note`), are the whole state's: a range record the join split is
/// reached at each of its elements.
pub(crate) fn reach_holds_the_change(before: &Fragment, after: &Fragment, y: &Fragment) {
    type Counts = BTreeMap<osis_base::Value, i64>;
    type Each<'a> = &'a dyn Fn(&Fragment, &mut dyn FnMut(&osis_base::Value));
    let diff = |a: &Fragment, b: &Fragment, each: Each<'_>| {
        let mut m = Counts::new();
        each(a, &mut |v| *m.entry(v.clone()).or_default() -= 1);
        each(b, &mut |v| *m.entry(v.clone()).or_default() += 1);
        m.retain(|_, n| *n != 0);
        m
    };
    let elems = |f: &Fragment, g: &mut dyn FnMut(&osis_base::Value)| f.values_with(crate::state::Values::ReadEach, g);
    let refs = |f: &Fragment, g: &mut dyn FnMut(&osis_base::Value)| f.each_read_value(&mut |v| v.each_reference_or_link(g));
    let at = before.reach(y);
    let at_after = after.reach_after(y, &at);
    assert_eq!(diff(&at, &at_after, &elems), diff(before, after, &elems), "a join changes read values only at its reach");
    assert_eq!(diff(&at, &at_after, &refs), diff(before, after, &refs), "a join changes read references only at its reach");
    let dead = |b: &Fragment, a: &Fragment| {
        let mut w = b.winners();
        w.extend(y.winners());
        w.minus(&a.winners())
    };
    let killed = dead(&at, &at_after);
    assert_eq!(killed, dead(before, after), "a join supersedes at its reach what it supersedes in the whole state");
    // what the engine dates a death by (`Killed::note`): each write dead at the reach dies by a
    // write held there before or after the join or in the delta, winning or not, or by a value
    // removal hiding it in the copies as joined (`hiders`): every input, forged copies included,
    // since a node that found none would fail the join with a local error
    let mut by = crate::tests_winners::held_of([&at, y, &at_after]);
    for w in killed {
        assert!(by.dies(&w).unwrap().is_some(), "a write dead at the reach dies by a write held there: {w:?}");
    }
}

/// The references and links `each_read_value` names are those of the read (spec/data-model.md
/// §8 What counts): a set's equal values once, a hidden write none.
fn read_references_are_the_reads(st: &Fragment) {
    let mut by_values: BTreeMap<osis_base::Value, u64> = BTreeMap::new();
    st.each_read_value(&mut |v| v.each_reference_or_link(&mut |r| *by_values.entry(r.clone()).or_default() += 1));
    let mut by_read: BTreeMap<osis_base::Value, u64> = BTreeMap::new();
    st.read().iter().for_each(|v| v.each_reference_or_link(&mut |r| *by_read.entry(r.clone()).or_default() += 1));
    assert_eq!(by_values, by_read, "the references read values name are the read's");
}

/// What a node dates a held body by (spec/commits.md §5, `retention::bounds::dated_replaced_at`):
/// each write of a body that the join of `bodies` supersedes dies by a write one of them holds,
/// winning or not, or by a removal hiding it as their copies join (`Held`): every input,
/// forged copies included, since a node that found none would fail its tick with a local error.
fn held_set_supersedes(bodies: &[Fragment]) {
    let all = bodies.iter().fold(Fragment::default(), |f, b| joined(&f, b));
    let mut by = crate::tests_winners::held_of(bodies);
    let won = all.winners();
    for b in bodies {
        for w in b.winners().minus(&won) {
            assert!(by.dies(&w).unwrap().is_some(), "a held body's write the held set supersedes dies by a held write: {w:?}");
        }
    }
}

/// The history joined in creation order, then twice in a random order with duplicates, by the
/// model and the crdt in lockstep: state and read equal after every join, the cached placement a
/// whole pass's (`check_lin`).
fn joins(r: &mut Rng, c: &Case) -> Option<MFrag> {
    let mut reference = None;
    for (d, _) in &c.deltas {
        mapply(&mut reference, d.clone());
    }
    for _ in 0..2 {
        let mut order: Vec<usize> = (0..c.deltas.len()).collect();
        for k in (1..order.len()).rev() {
            order.swap(k, r.below(k + 1));
        }
        let mut model = None;
        let mut ours = Fragment::default();
        for k in order {
            let reps = if r.chance(1, 4) { 2 } else { 1 };
            for _ in 0..reps {
                let (d, _) = &c.deltas[k];
                let fd = frag(d);
                if c.mode == Mode::Hostile {
                    // a placement held in part follows like a whole pass where it follows (a
                    // reset is joined over records loaded whole)
                    if let (Fragment::Seq(st), Fragment::Seq(ds)) = (&ours, &fd)
                        && ds.meta.reset.is_none()
                    {
                        let _ = crate::testutil::partial_follow(st, ds, 1 + r.below(4));
                    }
                } else {
                    piece_laws(&ours, &fd, c.honest);
                }
                crate::tests_seq::part_judges_as_whole(&ours, &fd, r);
                mapply(&mut model, d.clone());
                let before = ours.clone();
                ours.join(fd.clone());
                reach_holds_the_change(&before, &ours, &fd);
                check_lin(&ours);
                assert_eq!(ours, ostate(&model), "state after joining delta {k}");
                assert_eq!(ours.read(), mread(&model), "read after delta {k}");
                read_at_is_read_then_walk(&ours);
                read_references_are_the_reads(&ours);
                assert!(crate::testutil::contains(&ours, &fd), "a join contains its parts");
            }
        }
        assert_eq!(ours, ostate(&reference), "converged to the reference");
    }
    reference
}

/// `read_at` reads what a whole `read` then a walk along the path reads (`value_at`), at every
/// position the state or its read names (removed map keys, struct fields, enum cases current or
/// not, list indices one past the end, inside values written whole), and at a field step on a
/// map and an integer key step on a struct, which read alike.
fn read_at_is_read_then_walk(f: &Fragment) {
    use crate::ops::PathSeg;
    fn steps_of_frag(f: &Fragment, out: &mut Vec<PathSeg>) {
        match f {
            Fragment::Slots(s) => s.slots.values().for_each(|x| steps_of_frag(x, out)),
            Fragment::Struct(s) => s.fields.keys().for_each(|id| out.push(PathSeg::Field(*id))),
            Fragment::Enum(e) => e.payloads.keys().for_each(|id| out.push(PathSeg::Case(*id))),
            Fragment::Map(m) => m.entries.keys().filter_map(|id| id.key()).for_each(|k| out.push(PathSeg::Key(k.clone()))),
            Fragment::Seq(s) => (0..=s.elems().len()).for_each(|i| out.push(PathSeg::Index(i))),
            _ => {}
        }
    }
    fn steps_of_value(v: &osis_base::Value, out: &mut Vec<PathSeg>) {
        use osis_base::Value as V;
        match v {
            V::Map(m) => m.keys().for_each(|k| out.push(PathSeg::Key(k.clone()))),
            V::List(l) => (0..=l.len()).for_each(|i| out.push(PathSeg::Index(i))),
            V::Enum(c, _) => out.push(PathSeg::Case(*c)),
            _ => {}
        }
    }
    // a field step and an integer key step read alike: try both
    fn twins(s: PathSeg) -> Vec<PathSeg> {
        match &s {
            PathSeg::Field(id) => vec![PathSeg::Key(osis_base::Value::Int(*id as i64)), s],
            PathSeg::Key(osis_base::Value::Int(i)) if *i >= 0 => vec![PathSeg::Field(*i as u64), s],
            _ => vec![s],
        }
    }
    fn walk(root: &Fragment, whole: &Option<osis_base::Value>, path: &mut Vec<PathSeg>, here: Option<&Fragment>, depth: usize) {
        let want = whole.as_ref().and_then(|v| crate::access::value_at(v, path)).cloned();
        assert_eq!(root.read_at(path), want, "read_at {path:?} of {root:?}");
        if depth == 0 {
            return;
        }
        let mut steps = Vec::new();
        if let Some(h) = here {
            steps_of_frag(h, &mut steps);
        }
        if let Some(v) = &want {
            steps_of_value(v, &mut steps);
        }
        steps.push(PathSeg::Case(0));
        let mut seen = Vec::new();
        for s in steps.into_iter().flat_map(twins) {
            if seen.contains(&s) {
                continue;
            }
            seen.push(s.clone());
            path.push(s.clone());
            let next = here.and_then(|h| h.at(std::slice::from_ref(&s)));
            walk(root, whole, path, next.as_ref(), depth - 1);
            path.pop();
        }
    }
    walk(f, &f.read(), &mut Vec::new(), Some(f), 4);
}

fn snap_mcx() -> Ctx {
    Ctx::new(1 << 40, MSource::session(250, 0), 1)
}

/// A snapshot of `st` with `mfr` encodes like the model's and decodes alike through both
/// decoders, reading as `st` unless `twins` (a forged state may hold one dot under two stamps,
/// which no snapshot carries: rejected, or decoded with one of them), back to `st` as carried
/// when `honest`; so does one of `st` stripped of `gone`'s
/// dots (§4.7: value-less writes, list creations and `W`, map writes key-erased), whose strip
/// equals the model's.
fn snapshots(st: &MFrag, mfr: &[(MSource, u64)], gone: &Gone, honest: bool, twins: bool) {
    let check = |st: &MFrag, mfr: &[(MSource, u64)], what: &str| {
        let msnap = crdt_model::wire::encode_snapshot(st, mfr, [3; 16], &mut snap_mcx());
        let mut frontiers = Frontiers::default();
        for (s, c) in mfr {
            assert!(frontiers.insert(&source(s), *c), "a session frontier");
        }
        let s = Snapshot { nonce: [3; 16], frontiers, ..snapshot(&frag(st)) };
        let sbytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
        assert_eq!(sbytes, msnap, "{what} snapshot bytes equal the model's");
        let mback = crdt_model::wire::decode_snapshot(&sbytes, &mut snap_mcx()).map(|x| frag(&x.0));
        let back = decode_snapshot(&sbytes, &snap_cx(), &mut Interner::new(), None);
        assert_eq!(back.as_ref().ok().map(|b| &b.fragment), mback.as_ref().ok(), "{what} snapshot decodes as the model's (errors: ours {:?}, model's {:?})", back.as_ref().err(), mback.as_ref().err());
        if !twins {
            let back = back.as_ref().unwrap_or_else(|e| panic!("{what} snapshot decodes: {e:?}"));
            assert_eq!(back.fragment.read(), s.fragment.read(), "{what} snapshot read");
        }
        if honest {
            let mut back = back.unwrap();
            check_bound(&sbytes, &back.fragment);
            back.frontiers = back.frontiers.without_zeros();
            assert_eq!(back, Snapshot { fragment: as_carried(&s.fragment), ..s.clone() }, "{what} snapshot round trip");
        }
    };
    check(st, mfr, "a");
    let mut mst = st.clone();
    mst.strip(&gone.model());
    let mut ours = frag(st);
    ours.strip(&gone.ours());
    assert_eq!(ours, frag(&mst), "strip equals the model");
    ours.compact();
    assert_eq!(ours, frag(&mst), "compacting changes nothing");
    check(&mst, &[], "a stripped");
}

/// Every writer's delta encodes like the model's and decodes back to itself under the writer's
/// header; after each delta, `snapshots` of the state so far (with the writer's frontier where it
/// has one, for the sources in its fragment, §8).
fn wire(c: &Case) {
    let mut state = None;
    for (d, w) in &c.deltas {
        mapply(&mut state, d.clone());
        let st = state.as_ref().unwrap();
        // a twin's delta may carry its twin's dots of their shared source: no writer's delta
        let Some(w) = w.as_ref().filter(|_| c.mode != Mode::Twins) else {
            snapshots(st, &[], &c.gone, c.honest, c.mode == Mode::Twins);
            continue;
        };
        let mbytes = crdt_model::wire::encode_delta(d, [7; 16], &mut Ctx::new(w.ts, w.source.clone(), w.lo));
        let cx = writer_cx(w);
        let ours = Delta { nonce: [7; 16], fragment: frag(d) };
        let bytes = encode_delta(&ours, &cx, None).unwrap();
        assert_eq!(bytes, mbytes, "delta bytes equal the model's");
        let back = decode_delta(&bytes, &cx, &mut Interner::new(), None).unwrap();
        check_bound(&bytes, &back.fragment);
        assert_eq!(back, ours, "delta round trip");
        let mut fr = crdt_model::received::Received::default();
        fr.add(&w.source, 1, w.hi());
        let traced = crate::sources_of(&frag(st), &snap_cx()).unwrap();
        let mfr: Vec<(MSource, u64)> = fr.frontiers().into_iter().filter(|(s, _)| traced.contains(&source(s))).collect();
        snapshots(st, &mfr, &c.gone, c.honest, c.mode == Mode::Twins);
    }
}

/// Un-merge of one author (§4.6): the join of the bodies each without its writes equals the
/// model's, in any order. Expiry of `gone`'s dots (§4.7): stripping each body before its join
/// equals stripping the join, and no expired write's char outlives it.
fn unmerge_and_strip(c: &Case, reference: &MFrag) {
    let bad = source(&c.bad);
    let unmerged = |order: &mut dyn Iterator<Item = &(MFrag, Option<MWriter>)>| {
        let mut out = Fragment::default();
        for (d, _) in order {
            let mut b = frag(d);
            b.remove_writes(&|d| d.src == bad);
            out.join(b);
        }
        out
    };
    let mut model = None;
    for (d, _) in &c.deltas {
        let mut m = d.clone();
        m.unmerge(&|d| d.source == c.bad);
        mapply(&mut model, m);
    }
    let ours = unmerged(&mut c.deltas.iter());
    assert_eq!(ours, ostate(&model), "un-merged bodies equal the model's");
    assert_eq!(ours, unmerged(&mut c.deltas.iter().rev()), "un-merge order-independent");
    // an invalid delta changes nothing (§4.6): where every body is a writer's own delta, holding
    // the invalid author's bodies un-merged equals never holding them
    if c.mode != Mode::Twins && c.deltas.iter().all(|(_, w)| w.is_some()) {
        let mut never = Fragment::default();
        for (d, w) in &c.deltas {
            if w.as_ref().is_some_and(|w| w.source != c.bad) {
                never.join(frag(d));
            }
        }
        assert_eq!(ours, never, "un-merged equals never held");
    }
    let exp = c.gone.ours();
    let mut late = frag(reference);
    late.strip(&exp);
    // held whole, compacted after each strip: joins meet value-less range records
    for (order, compact) in [(c.deltas.iter().collect::<Vec<_>>(), false), (c.deltas.iter().rev().collect(), true), (c.deltas.iter().collect(), true)] {
        let mut early = Fragment::default();
        for (d, _) in order {
            let mut b = frag(d);
            b.strip(&exp);
            early.join(b);
            early.strip(&exp);
            if compact {
                early.compact();
                check_lin(&early);
            }
        }
        assert_eq!(early, late, "expiry commutes with join");
    }
    if let Fragment::Seq(sq) = &late {
        for (d, e) in sq.elems() {
            let own = matches!(e.content, SeqContent::Char(_)) && exp(d.origin());
            let undel = e.undel.is_some() && e.deleted.as_ref().is_some_and(|x| exp(x.0.dot.origin()));
            assert!(!own && !undel, "an expired write's char outlives it: {d:?}");
        }
    }
}

/// The encodings a state holds, for the coverage tally.
fn tally(f: &Fragment, seen: &mut BTreeSet<&'static str>) {
    use crate::fragment::{Bag, BagKind, Set};
    let (name, kids): (&'static str, Vec<&Fragment>) = match f {
        Fragment::Register(_) => ("register", vec![]),
        Fragment::Bag(Bag { kind, elems, .. }) => {
            let name = match kind {
                BagKind::Counter => "counter",
                BagKind::Max => "max",
                BagKind::Min => "min",
            };
            (name, elems.values().filter_map(|e| e.frag.as_deref()).collect())
        }
        Fragment::Set(Set { elems, .. }) => ("set", elems.values().filter_map(|e| e.frag.as_deref()).collect()),
        Fragment::Struct(x) => ("struct", x.fields.values().collect()),
        Fragment::Enum(x) => ("enum", x.payloads.values().collect()),
        Fragment::Map(x) => ("map", x.entries.values().filter_map(|e| e.frag.as_deref()).collect()),
        Fragment::Seq(s) => (if s.text { "text" } else { "list" }, s.elems().values().filter_map(|e| if let SeqContent::Frag(x) = &e.content { Some(&**x) } else { None }).collect()),
        Fragment::Slots(x) => ("slots", x.slots.values().collect()),
    };
    seen.insert(name);
    for k in kids {
        tally(k, seen);
    }
}

/// One seed: the encodings its final state held.
fn check(k: u64) -> BTreeSet<&'static str> {
    let (r, c) = case(k);
    check_case(r, &c)
}

/// The differential over case `c`: the encodings its final state held.
fn check_case(mut r: crate::testutil::SeedRng, c: &Case) -> BTreeSet<&'static str> {
    let c = c.clone();
    let reference = joins(&mut r, &c);
    let bodies: Vec<Fragment> = c.deltas.iter().map(|(d, _)| frag(d)).collect();
    held_set_supersedes(&bodies);
    for _ in 0..2 {
        held_set_supersedes(&bodies.iter().filter(|_| r.chance(1, 2)).cloned().collect::<Vec<_>>());
    }
    wire(&c);
    let mut seen = BTreeSet::new();
    if let Some(st) = &reference {
        unmerge_and_strip(&c, st);
        tally(&frag(st), &mut seen);
    }
    seen
}

fn differential(size: Size) {
    let replay = |k: u64| {
        let env = std::env::var("OSIS_CRDT_SEED").map(|v| format!(" OSIS_CRDT_SEED={v}")).unwrap_or_default();
        format!("OSIS_CRDT_START={k} OSIS_CRDT_SEEDS=1{env} cargo test -p osis-crdt --lib -- --ignored --exact tests_model::crdt_equals_model_large")
    };
    let name = format!("crdt_equals_model ({size:?})");
    // only the property sizes read a range from the environment
    let out = match size {
        Size::Plain => {
            let seeds: Vec<u64> = size.seeds().collect();
            osis_base::testenv::run_seeds(&name, &seeds, false, replay, check)
        }
        Size::Small | Size::Large => {
            let seeds = osis_base::testenv::Seeds::from_env("OSIS_CRDT_START", "OSIS_CRDT_SEEDS", size.seeds());
            seeds.run(&name, replay, check)
        }
    };
    // every encoding reached (the mode is the seed's place mod 5, by construction)
    for w in ["register", "counter", "max", "min", "set", "struct", "enum", "map", "text", "list", "slots"] {
        osis_base::testenv::reach_floor(&format!("{w} encodings"), out.iter().map(|x| usize::from(x.contains(w))), 1, 20);
    }
}

/// G3: the crdt equals the model, `Plain`.
#[test]
#[ignore = "property"]
fn crdt_equals_model_plain() {
    differential(Size::Plain);
}

/// `Small`, or `Large` with `OSIS_FULL=1`; `OSIS_CRDT_START`/`OSIS_CRDT_SEEDS` pick the
/// seeds (one seed replays a failure at any size).
#[test]
#[ignore]
fn crdt_equals_model_large() {
    differential(Size::from_env());
}

/// A map dot whose records' top-2 position writes push a text element's creation out of `pos` in
/// the record holding the creation: its snapshot implies that position write again (§3.3 rule 5),
/// and both decoders take it back to the state, the creation held (§5.6, §5.7).
#[test]
fn implied_creation_pos_decodes_back_spec_3_3() {
    use crate::fragment::{Eid, Entry, Map, Meta};
    use crate::seq::{Anchor, Seq, SeqElem};
    use crate::stamp::Stamp;
    use crate::testutil::ts;
    let (s1, s2) = (node(1), node(2));
    let st = |t: u64, s: &crate::stamp::Source, c: u64| Stamp::new(ts(t << 16), s.clone(), c);
    let d = Dot::new(s1.clone(), 1);
    let e = Dot::new(s1.clone(), 2);
    let text = |el: SeqElem| Some(Box::new(Fragment::Seq(Seq::new(true, Meta::default(), BTreeMap::from([(e.clone(), el)])))));
    // (d, none): e's creation c (t5) and position write p1 (t12); (d, key 0): e's position
    // write p2 (t10), so the dot's top two are p1 and p2
    let mut created = SeqElem::bare();
    created.created = Some((st(5, &s1, 2), Anchor::Head));
    created.content = SeqContent::Char('x');
    created.pos = vec![(st(12, &s1, 10), Anchor::Head, None)];
    let mut moved = SeqElem::bare();
    moved.pos = vec![(st(10, &s2, 2), Anchor::Head, None)];
    let entries = BTreeMap::from([
        (Eid::new(d.clone(), None), Entry { reset: None, frag: text(created), created: Some(st(5, &s1, 1)) }),
        (Eid::new(d, Some(osis_base::Value::Int(0))), Entry { reset: None, frag: text(moved), created: None }),
    ]);
    let f = Fragment::Map(Map::new(Meta::default(), entries));
    let mut pruned = f.clone();
    pruned.prune(None, &mut crate::Changes::new());
    assert_eq!(pruned, f, "canonical");
    let s = Snapshot { nonce: [3; 16], ..snapshot(&f) };
    let bytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
    let back = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap();
    assert_eq!(back.fragment, f, "a canonical state's snapshot decodes back to it");
    let model = crdt_model::wire::decode_snapshot(&bytes, &mut snap_mcx()).unwrap();
    assert_eq!(frag(&model.0), f, "the model's decoder too");
}

/// §3.3 rule 7, §2.1, §7: a position write or a flag write on a register
/// write `s`'s embedded char stamped with `s`'s dot (at `s` itself: the one stamp at or above the
/// register write's reset and below the char's creation, so beaten by it there and lost from the
/// element's top-2 when the join cuts the creation as a losing copy's, an order-dependent join)
/// is bad input to both decoders; stamped otherwise it decodes.
#[test]
fn a_write_stamped_with_its_embedded_chars_register_dot_is_bad_input_spec_3_3() {
    use crdt_model::state::{Anchor as MAnchor, Composite, Content, SeqElem as MSeqElem};
    use crdt_model::stamp::Stamp as MStamp;
    let d = MDot { source: MSource::session(1, 0), ctr: 3 };
    let s = MStamp { ts: 5 << 16, dot: d.clone() };
    let other = MStamp { ts: 6 << 16, dot: MDot { source: MSource::session(1, 0), ctr: 4 } };
    let second = MDot { source: MSource::Derived(Box::new(d)), ctr: 2 };
    let text = |e: MSeqElem| MFrag::Seq { text: true, c: Composite::default(), elems: [(second.clone(), e)].into_iter().collect() };
    let mv = |st: &MStamp| text(MSeqElem::write(Content::None, vec![(st.clone(), MAnchor::Head, None)], None));
    let del = |st: &MStamp| text(MSeqElem::flag(st.clone(), true, None));
    let decodes = |f: &MFrag| {
        let bytes = crdt_model::wire::encode_snapshot(f, &[], [3; 16], &mut snap_mcx());
        let ours = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).is_ok();
        assert_eq!(ours, crdt_model::wire::decode_snapshot(&bytes, &mut snap_mcx()).is_ok(), "both decoders alike: {f:?}");
        ours
    };
    for f in [mv(&s), del(&s), mv(&MStamp { ts: 7 << 16, dot: s.dot.clone() })] {
        assert!(!decodes(&f), "{f:?}");
    }
    for f in [mv(&other), del(&other)] {
        assert!(decodes(&f), "{f:?}");
    }
}

/// A hand-made history on a text or list of `ty`: writer 1 appends an element a commit (a
/// creation chain across commits, each element at its own commit's `ts`), with `interleaved`
/// taking turns with writer 4 (each of its elements anchored at writer 4's); writer 2, holding
/// the first four, inserts after the second, deletes the third and moves the fourth to the
/// front; writer 3 replaces the sequence at a `ts` between the third and fourth. Writer 1's dots
/// up to `upto` expire (a value-less range whose creations differ in `ts` and anchor,
/// `seq_span`, split where expiry stops), writer 2's un-merge.
fn chain_case(ty: &Ty, upto: u64, interleaved: bool) -> Case {
    use crdt_model::ops as mops;
    use crdt_model::state::Content;
    let text = *ty == Ty::Text;
    let shown = |st: &Option<MFrag>| match st {
        Some(MFrag::Seq { elems, .. }) => mops::visible(text, elems).len(),
        _ => 0,
    };
    let (a, b, c) = (MSource::session(1, 0), MSource::session(2, 0), MSource::session(3, 0));
    let mut deltas: Vec<(MFrag, Option<MWriter>)> = Vec::new();
    let mut ws = [MWriter::new(a.clone(), 1 << 16, 0), MWriter::new(MSource::session(4, 0), 1 << 16, 0)];
    let (mut st, mut four) = (None, None);
    for i in 0..6u64 {
        let w = &mut ws[usize::from(interleaved && i % 2 == 1)];
        w.next_commit(((i + 1) * 10) << 16);
        let item = match ty {
            Ty::List(et) => Content::Frag(Box::new(mops::create(w, et, &crdt_model::r#gen::random_value(&mut Rng(i), et, 1)))),
            _ => Content::Char(char::from(b'a' + i as u8)),
        };
        let d = mops::seq_insert(w, st.as_ref(), text, shown(&st), vec![item]);
        mapply(&mut st, d.clone());
        deltas.push((d, Some(w.clone())));
        if i == 3 {
            four = st.clone();
        }
    }
    let mut wb = MWriter::new(b.clone(), 1 << 16, 0);
    let mut sb = four;
    for (k, op) in [0usize, 1, 2].into_iter().enumerate() {
        wb.next_commit((45 + k as u64) << 16);
        let d = match op {
            0 => {
                let item = match ty {
                    Ty::List(et) => Content::Frag(Box::new(mops::create(&mut wb, et, &crdt_model::r#gen::random_value(&mut Rng(9), et, 1)))),
                    _ => Content::Char('x'),
                };
                Some(mops::seq_insert(&mut wb, sb.as_ref(), text, 2, vec![item]))
            }
            1 => mops::seq_delete(&mut wb, sb.as_ref().unwrap(), 3, 1),
            _ => mops::seq_move(&mut wb, sb.as_ref().unwrap(), 3, 1, 0),
        };
        let d = d.expect("writer 2's op applies");
        mapply(&mut sb, d.clone());
        deltas.push((d, Some(wb.clone())));
    }
    let mut wc = MWriter::new(c, 1 << 16, 0);
    wc.next_commit((35 << 16) + 3);
    let v = match ty {
        Ty::List(et) => crdt_model::value::Value::List(vec![crdt_model::r#gen::random_value(&mut Rng(7), et, 1)]),
        _ => crdt_model::value::Value::Str("yz".into()),
    };
    deltas.push((mops::replace(&mut wc, ty, &v), Some(wc.clone())));
    Case { mode: Mode::Nested, deltas, honest: true, bad: b, gone: Gone { src: a, upto } }
}

/// §5.7, `seq_span`: value-less elements of one source made by commits of their own, a chain or
/// anchored at another writer's elements, held as range records (`SeqElem::each`), equal the
/// model under joins in any order, the wire, expiry and un-merge, with inserts among them, a
/// delete, a move and a reset between their creations, for a text and lists of registers and
/// structs, all or the first few expiring.
#[test]
fn value_less_ranges_equal_model_spec_5_7() {
    for (i, ty) in [Ty::Text, Ty::List(Box::new(Ty::Register)), Ty::List(Box::new(inner()))].iter().enumerate() {
        for upto in [3, u64::MAX] {
            for interleaved in [false, true] {
                check_case(crate::testutil::fixed(i as u64), &chain_case(ty, upto, interleaved));
            }
        }
    }
}

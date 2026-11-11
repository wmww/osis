//! G3, the crdt's property (notes/crdt.md): what the crdt computes equals the reference model
//! (core/test/crdt-model), whose join is lawful (its own law tests). One differential over every
//! encoding: random histories joined in random orders with duplicates (state and read after every
//! join, spec/crdt.md §4, §5, §7), the wire (delta and snapshot bytes, both decoders, §3), strip
//! (§4.7) and un-merge (§4.6), honest and hostile.

use crate::codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot};
use crate::fragment::Fragment;
use crate::seq::SeqContent;
use crate::stamp::{Dot, Interner};
use crate::testutil::{MCommit, check_bound, check_lin, frag, history_twins, history_with, mapply, ostate, sink_no_seq, source, value};
use crate::tests_seq::{as_carried, map_of_text};
use crate::tests_wire::{snap_cx, writer_cx};
use crate::wire::{Delta, Frontiers, Snapshot};
use crdt_model::ops::{Ty, Writer as MWriter};
use crdt_model::r#gen::{Rng, kitchen_sink};
use crdt_model::stamp::{Dot as MDot, Source as MSource};
use crdt_model::state::{Content, Frag as MFrag};
use crdt_model::wire::Ctx;
use std::collections::{BTreeMap, BTreeSet};

/// How much the differential runs (notes/testing.md, Sizes): `Quick` in the default tests,
/// `Small` at the gate, `Large` in release checks. Only the seed count differs, so any seed replays alone at
/// any size.
#[derive(Clone, Copy, Debug)]
enum Size {
    Quick,
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
            Size::Quick => 0..100,
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
    /// Maps whose entries hold texts and lists; lists of structs (§5.6, §5.7).
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
            (from(history_with(&mut r, &types, srcs, rounds)), true)
        }
        Mode::Twins => {
            let types = pick(&mut r, &[vec![kitchen_sink()], vec![Ty::Text], vec![Ty::List(Box::new(Ty::Register))], vec![Ty::Register, Ty::Text, Ty::Counter, Ty::Set(Box::new(Ty::Register))], map_of_text()]);
            let srcs = vec![MSource::session(1, 0), MSource::session(1, 0), MSource::session(2, 0)];
            (from(history_twins(&mut r, &types, srcs, rounds)), false)
        }
        Mode::Hostile => {
            let (list, slots) = pick(&mut r, &[(false, false), (false, true), (true, false)]);
            (hostile_deltas(&mut r, list, slots).into_iter().map(|d| (d, None)).collect(), false)
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

/// Hostile single-record deltas on one text or list (§5.7, §6): creation chains anchored at
/// random dots (their own run, unknown dots, later dots), forged copies of one creation or
/// position write with other anchors or keys, moves with random anchors and sibling keys (cycles
/// through chains and range records), deletes, undeletes, resets; with `slots` (text), register
/// writes of strings at the position (§7: embedded chars, `Derived` dots moved, deleted and
/// anchored at, held or not). Joined into deltas of 1..4 writes each.
fn hostile_deltas(r: &mut Rng, list: bool, slots: bool) -> Vec<MFrag> {
    let mut deltas = Vec::new();
    let mut single = hostile_writes(r, list, slots, 48).into_iter().peekable();
    while single.peek().is_some() {
        let mut d = None;
        for w in single.by_ref().take(1 + r.below(4)) {
            mapply(&mut d, w);
        }
        deltas.extend(d);
    }
    // a char without a creation (no wire form: rejected, §3.3 rule 7) joins as none
    for w in &mut deltas {
        if let MFrag::Seq { text: true, elems, .. } = w {
            for e in elems.values_mut().filter(|e| e.created.is_none()) {
                if r.chance(1, 4) {
                    e.content = Content::Char(char::from(b'a' + r.below(4) as u8));
                }
            }
        }
    }
    deltas
}

fn hostile_writes(r: &mut Rng, list: bool, slots: bool, n: usize) -> Vec<MFrag> {
    use crdt_model::stamp::Stamp as MStamp;
    use crdt_model::state::{Anchor as MAnchor, Composite, SeqElem as MElem};
    let srcs = [MSource::session(1, 0), MSource::session(2, 0), MSource::session(3, 0)];
    // the dots of the register writes so far (their embedded chars: `Derived(d)`, 1..)
    let mut regs: Vec<MDot> = Vec::new();
    fn dot(r: &mut Rng, srcs: &[MSource; 3], regs: &[MDot]) -> MDot {
        if !regs.is_empty() && r.chance(1, 4) {
            return MDot { source: MSource::Derived(Box::new(regs[r.below(regs.len())].clone())), ctr: 1 + r.below(4) as u64 };
        }
        MDot { source: srcs[r.below(3)].clone(), ctr: 1 + r.below(12) as u64 }
    }
    fn anchor(r: &mut Rng, srcs: &[MSource; 3], regs: &[MDot]) -> MAnchor {
        if r.chance(1, 6) { MAnchor::Head } else { MAnchor::Dot(dot(r, srcs, regs)) }
    }
    let content = |r: &mut Rng, s: &MStamp| Content::Frag(Box::new(MFrag::Register { reset: None, write: Some((s.clone(), Some(crdt_model::value::Value::Int(r.below(3) as i64)))) }));
    // chars at random: creation copies of one dot and undeletes may carry other chars (forged
    // copies, §4.1 copy order, §5.7)
    let any_char = |r: &mut Rng| char::from(b'a' + r.below(4) as u8);
    let seq = |elems: BTreeMap<MDot, MElem>, reset: Option<MStamp>| MFrag::Seq { text: !list, c: Composite { reset, w: None, w_valueless: false }, elems };
    // stamps: ts in a small range so writes interleave; position write counters apart from dots
    let mut pos_ctr = 100u64;
    let mut out = Vec::new();
    for _ in 0..n {
        let t = (1 + r.below(30) as u64) << 16;
        let k = r.below(20);
        let mut elems = BTreeMap::new();
        if k < 8 {
            // a creation chain of 1..4 elements (never of a `Derived` source: a writer's delta
            // rejects them)
            let d = MDot { source: srcs[r.below(3)].clone(), ctr: 1 + r.below(12) as u64 };
            let len = 1 + r.below(4) as u64;
            let mut a = anchor(r, &srcs, &regs);
            // mostly one creation `ts` per dot (so copies of one stamp meet, differing in char
            // or anchor), sometimes another (a forged copy under another `ts`, §5.7 Join)
            let forged = r.chance(1, 4);
            for i in 0..len {
                let e = MDot { source: d.source.clone(), ctr: d.ctr + i };
                let ct = if forged { t } else { (1 + (srcs.iter().position(|x| *x == e.source).unwrap() as u64 * 7 + e.ctr * 3) % 30) << 16 };
                let s = MStamp { ts: ct, dot: e.clone() };
                let c = if list { content(r, &s) } else { Content::Char(any_char(r)) };
                elems.insert(e.clone(), MElem::new(s, a.clone(), c));
                a = MAnchor::Dot(e);
            }
        } else if k < 15 {
            // a move (or a forged copy of an earlier position write: same counter)
            let d = dot(r, &srcs, &regs);
            if r.chance(1, 4) {
                pos_ctr = pos_ctr.saturating_sub(r.below(3) as u64);
            }
            pos_ctr += 1;
            let src = srcs[r.below(3)].clone();
            let s = MStamp { ts: t, dot: MDot { source: src, ctr: pos_ctr } };
            let key = if r.chance(1, 3) && t > 1 << 16 { Some(MStamp { ts: t - (1 << 16), dot: dot(r, &srcs, &[]) }) } else { None };
            elems.insert(d, MElem::write(Content::None, vec![(s, anchor(r, &srcs, &regs), key)], None));
        } else if k < 19 {
            // a delete or (text) an undelete with a char; a run of 1..3
            let d = dot(r, &srcs, &regs);
            let len = 1 + r.below(3) as u64;
            pos_ctr += 1;
            let s = MStamp { ts: t, dot: MDot { source: srcs[r.below(3)].clone(), ctr: pos_ctr } };
            let undel = !list && r.chance(1, 3);
            for i in 0..len {
                let e = MDot { source: d.source.clone(), ctr: d.ctr + i };
                // an undelete's chars: some elements' missing (the undo buffer lacked them)
                let c = if undel && !r.chance(1, 5) { Some(any_char(r)) } else { None };
                elems.insert(e, MElem::flag(s.clone(), !undel, c));
            }
        } else if slots && r.chance(1, 2) {
            // an old app's save: a register write of a string (a reset of everything older)
            pos_ctr += 1;
            let d = MDot { source: srcs[r.below(3)].clone(), ctr: pos_ctr };
            let v: String = (0..r.below(4)).map(|i| char::from(b'a' + ((d.ctr + i as u64 + 1) % 4) as u8)).collect();
            out.push(MFrag::Register { reset: None, write: Some((MStamp { ts: t, dot: d.clone() }, Some(crdt_model::value::Value::Str(v)))) });
            regs.push(d);
            continue;
        } else {
            pos_ctr += 1;
            let s = MStamp { ts: t / 2, dot: MDot { source: srcs[r.below(3)].clone(), ctr: pos_ctr } };
            out.push(seq(elems, Some(s)));
            continue;
        }
        out.push(seq(elems, None));
    }
    out
}

fn joined(a: &Fragment, b: &Fragment) -> Fragment {
    let mut x = a.clone();
    x.join(b.clone());
    x
}

fn mread(m: &Option<MFrag>) -> Option<osis_base::Value> {
    m.as_ref().and_then(|m| m.read()).map(|v| value(&v))
}

/// What the crdt answers that the model has no counterpart for, on state `x` before joining
/// delta `y` (spec/commits.md §5): the piece at `y`'s positions joins into `x` unchanged, so
/// `contains` is sound (exact for a sequence); an honest holder of `y`'s writes holds them with
/// `y`'s payloads (covering copies).
fn piece_laws(x: &Fragment, y: &Fragment, honest: bool) {
    let part = x.part_at(y);
    assert_eq!(&joined(x, &part), x, "a piece joins in unchanged");
    let unchanged = &joined(x, y) == x;
    assert!(!x.contains(y) || unchanged, "contains only what joins in unchanged");
    if matches!(x, Fragment::Seq(_)) {
        assert_eq!(x.contains(y), unchanged, "a sequence's piece judges as the whole");
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

/// A join of `y` changes the values a state holds (`each_value`) only at `y`'s reach
/// (`Fragment::reach`): `before` and `after` differ as their pieces at the reach do (the engine's
/// reference index counts a join there alone, notes/engine-refs.md).
fn reach_holds_the_change(before: &Fragment, after: &Fragment, y: &Fragment) {
    let diff = |a: &Fragment, b: &Fragment| {
        let mut m: BTreeMap<osis_base::Value, i64> = BTreeMap::new();
        a.each_value(&mut |v| *m.entry(v.clone()).or_default() -= 1);
        b.each_value(&mut |v| *m.entry(v.clone()).or_default() += 1);
        m.retain(|_, n| *n != 0);
        m
    };
    assert_eq!(diff(&before.reach(y), &after.reach(y)), diff(before, after), "a join changes held values only at its reach");
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
                    crate::tests_seq::part_judges_as_whole(&ours, &fd, r);
                } else {
                    piece_laws(&ours, &fd, c.honest);
                }
                mapply(&mut model, d.clone());
                let before = ours.clone();
                ours.join(fd.clone());
                reach_holds_the_change(&before, &ours, &fd);
                check_lin(&ours);
                assert_eq!(ours, ostate(&model), "state after joining delta {k}");
                assert_eq!(ours.read(), mread(&model), "read after delta {k}");
                read_at_is_read_then_walk(&ours);
                assert!(ours.contains(&fd), "a join contains its parts");
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
        let s = Snapshot { absorbed: Default::default(), nonce: [3; 16], fragment: frag(st), frontiers };
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
            b.remove_dots(&|d| d.src == bad);
            out.join(b);
        }
        out
    };
    let mut model = None;
    for (d, _) in &c.deltas {
        let mut m = d.clone();
        m.unmerge(&|d| d.source == c.bad, &|_| false);
        mapply(&mut model, m);
    }
    let ours = unmerged(&mut c.deltas.iter());
    assert_eq!(ours, ostate(&model), "un-merged bodies equal the model's");
    assert_eq!(ours, unmerged(&mut c.deltas.iter().rev()), "un-merge order-independent");
    let exp = c.gone.ours();
    let mut late = frag(reference);
    late.strip(&exp);
    for order in [c.deltas.iter().collect::<Vec<_>>(), c.deltas.iter().rev().collect()] {
        let mut early = Fragment::default();
        for (d, _) in order {
            let mut b = frag(d);
            b.strip(&exp);
            early.join(b);
            early.strip(&exp);
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

/// One seed: its mode and the encodings its final state held.
fn check(k: u64) -> (Mode, BTreeSet<&'static str>) {
    let (mut r, c) = case(k);
    let reference = joins(&mut r, &c);
    wire(&c);
    let mut seen = BTreeSet::new();
    if let Some(st) = &reference {
        unmerge_and_strip(&c, st);
        tally(&frag(st), &mut seen);
    }
    (c.mode, seen)
}

fn differential(size: Size) {
    let replay = |k: u64| {
        let env = std::env::var("OSIS_CRDT_SEED").map(|v| format!(" OSIS_CRDT_SEED={v}")).unwrap_or_default();
        format!("OSIS_CRDT_START={k} OSIS_CRDT_SEEDS=1{env} cargo test -p osis-crdt --lib -- --ignored --exact tests_model::crdt_equals_model_large")
    };
    let name = format!("crdt_equals_model ({size:?})");
    // only the property sizes read a range from the environment
    let (range, out) = match size {
        Size::Quick => {
            let seeds: Vec<u64> = size.seeds().collect();
            (size.seeds(), osis_base::testenv::run_seeds(&name, &seeds, false, replay, check))
        }
        Size::Small | Size::Large => {
            let seeds = osis_base::testenv::Seeds::from_env("OSIS_CRDT_START", "OSIS_CRDT_SEEDS", size.seeds());
            (seeds.range.clone(), seeds.run(&name, replay, check))
        }
    };
    // every mode and every encoding reached, at every size (a run of fewer seeds than modes
    // replays one)
    if range.end - range.start >= 2 * MODES.len() as u64 {
        let modes: BTreeSet<Mode> = out.iter().map(|x| x.0).collect();
        assert_eq!(modes.len(), MODES.len(), "modes reached: {modes:?}");
        let seen: BTreeSet<&str> = out.into_iter().flat_map(|x| x.1).collect();
        let want = ["register", "counter", "max", "min", "set", "struct", "enum", "map", "text", "list", "slots"];
        assert!(want.iter().all(|w| seen.contains(w)), "encodings reached: {seen:?}");
    }
}

/// G3: the crdt equals the model, `Quick`.
#[test]
fn crdt_equals_model() {
    differential(Size::Quick);
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
    use crate::testutil::{sess, ts};
    let (s1, s2) = (sess(osis_base::Tid::from_bytes([1; 15])), sess(osis_base::Tid::from_bytes([2; 15])));
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
    let s = Snapshot { absorbed: Default::default(), nonce: [3; 16], fragment: f.clone(), frontiers: Frontiers::default() };
    let bytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
    let back = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap();
    assert_eq!(back.fragment, f, "a canonical state's snapshot decodes back to it");
    let model = crdt_model::wire::decode_snapshot(&bytes, &mut snap_mcx()).unwrap();
    assert_eq!(frag(&model.0), f, "the model's decoder too");
}

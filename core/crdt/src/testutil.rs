//! Test support: conversion from the reference model (core/test/crdt-model) and random op sequences from
//! its generator (notes/crdt.md, Reference model).

use crate::Changes;
use crate::fragment::{Bag, BagKind, CaseWrite, Elem, Encoding, Entry, Enum, Fragment, Map, Meta, RegWrite, Register, Set, Slots, Struct};
use crate::seq::{Anchor, Seq, SeqContent, SeqElem};
use crate::seq_span::nth;
use crate::stamp::{CounterRange, Dot, Source, Stamp};
use crate::wire::{DeltaCtx, DeltaKind, Snapshot};
use crdt_model::r#gen::Rng;
use crdt_model::ops::{Ty, Writer as MWriter};
use crdt_model::state as m;
use osis_base::{CommitId, Float, Tid, Ts, Value};
use std::collections::BTreeMap;

/// A random test's seed: `seed`, or `seed` xor a hash of `OSIS_CRDT_SEED` (decimal) to sample
/// other runs (`OSIS_CRDT_SEED=7 cargo test -p osis-crdt`); unset, the committed seed. Hashed: a
/// small value xored into a loop's consecutive seeds would only reorder them.
pub fn seeded(seed: u64) -> u64 {
    osis_base::testenv::u64_var("OSIS_CRDT_SEED").map_or(seed, |v| seed ^ splitmix(v))
}

fn splitmix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The generator of a random test from its committed seed (`seeded`); a test that panics while
/// it is alive prints the effective seed.
pub fn rng(seed: u64) -> SeedRng {
    let eff = seeded(seed);
    SeedRng { rng: Rng(eff), seed, eff }
}

/// A crdt property's seeds (notes/testing.md, Sizes): `default`, or what `OSIS_CRDT_START` and
/// `OSIS_CRDT_SEEDS` pick; `f(seed)` for each on the seed runner, results in seed order. `test`
/// is the libtest path, for the replay line.
pub fn crdt_seeds<T: Send>(test: &str, default: std::ops::Range<u64>, f: impl Fn(u64) -> T + Sync) -> Vec<T> {
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_CRDT_START", "OSIS_CRDT_SEEDS", default);
    let replay = |s: u64| format!("OSIS_CRDT_START={s} OSIS_CRDT_SEEDS=1 cargo test -p osis-crdt --lib -- --ignored --exact {test}");
    seeds.run(test, replay, f)
}

/// The generator of a fixed-seed test: `seed` whatever `OSIS_CRDT_SEED` says (thresholds over a
/// committed seed set must not shift with it).
pub fn fixed(seed: u64) -> SeedRng {
    SeedRng { rng: Rng(seed), seed, eff: seed }
}

pub struct SeedRng {
    rng: Rng,
    seed: u64,
    eff: u64,
}

impl std::ops::Deref for SeedRng {
    type Target = Rng;
    fn deref(&self) -> &Rng {
        &self.rng
    }
}

impl std::ops::DerefMut for SeedRng {
    fn deref_mut(&mut self) -> &mut Rng {
        &mut self.rng
    }
}

impl Drop for SeedRng {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let env = std::env::var("OSIS_CRDT_SEED").unwrap_or_default();
            eprintln!("random test failed at effective seed {} (committed {}, OSIS_CRDT_SEED={env:?})", self.eff, self.seed);
        }
    }
}

pub fn value(v: &crdt_model::value::Value) -> Value {
    use crdt_model::value::Value as V;
    match v {
        V::Bool(b) => Value::Bool(*b),
        V::Int(i) => Value::Int(*i),
        V::Float(b) => Value::Float(Float::from_bits(*b).unwrap()),
        V::Str(s) => Value::Str(s.clone()),
        V::Bytes(b) => Value::Bytes(b.clone()),
        V::Strong(t) => Value::Strong(Tid::from_bytes(*t)),
        V::Weak(t) => Value::Weak(Tid::from_bytes(*t)),
        V::List(l) => Value::List(l.iter().map(value).collect()),
        V::Map(kv) => Value::Map(kv.iter().map(|(k, v)| (value(k), value(v))).collect()),
        V::Set(s) => Value::Set(s.iter().map(value).collect()),
        V::Enum(id, p) => Value::Enum(*id, p.as_ref().map(|p| Box::new(value(p)))),
    }
}

/// Whether joining `y` into `x`'s part at `y`'s positions (`part_at`) changes nothing: how the
/// engine judges a delta against a part of a state (spec/commits.md §5).
pub fn contains(x: &Fragment, y: &Fragment) -> bool {
    let part = x.part_at(y);
    let mut j = part.clone();
    j.join(y.clone());
    j == part
}

/// A writer source for tests: session of node `t` with a zero nonce.
pub fn sess(t: Tid) -> Source {
    Source::session(crate::Session { node: t, nonce: [0; crate::SESSION_NONCE_LEN] })
}

/// The `Source` entry of `sess(t)` in a hand-built `Sources` table.
pub fn sess_value(t: Tid) -> Value {
    Value::Bytes(crate::Session { node: t, nonce: [0; crate::SESSION_NONCE_LEN] }.to_bytes().to_vec())
}

pub fn source(s: &crdt_model::stamp::Source) -> Source {
    use crdt_model::stamp::Source as S;
    match s {
        S::Session(b) => Source::session(crate::Session::from_bytes(b)),
        S::Commit(b) => Source::commit(CommitId(*b)),
        S::Derived(d) => Source::derived(dot(d)).unwrap(),
    }
}

pub fn dot(d: &crdt_model::stamp::Dot) -> Dot {
    Dot::new(source(&d.source), d.ctr)
}

pub fn ts(t: u64) -> Ts {
    Ts::from_u64(t).unwrap()
}

pub fn stamp(s: &crdt_model::stamp::Stamp) -> Stamp {
    Stamp { ts: ts(s.ts), dot: dot(&s.dot) }
}

/// Node `n`'s session source.
pub fn node(n: u8) -> Source {
    sess(Tid::from_bytes([n; 15]))
}

/// `a` joined with `b`. Where `a` is a state (pruned, as every join leaves one), the join
/// reports any change of it: a node stores a joined state only then (an empty state of any
/// encoding is none).
pub fn joined(a: &Fragment, b: &Fragment) -> Fragment {
    let mut x = a.clone();
    let ch = x.join(b.clone());
    let state = || {
        let mut p = a.clone();
        p.prune(None, &mut Changes::new());
        p == *a
    };
    assert!(ch.is_changed() || x == *a || x.is_empty() && a.is_empty() || !state(), "a join changing the state reports it:\n{a:?}\n joined with {b:?}\n gives {x:?}");
    x
}

/// `ops` as one commit by `w` on `f`; `None` if an op fails or the commit writes nothing.
pub fn build<V: crate::view::View>(f: &Fragment, w: crate::ops::Writer, ops: &[crate::ops::PathOp], view: &V) -> Option<(Fragment, crate::stamp::CounterRange)> {
    let mut b = crate::delta::DeltaBuilder::new(f, w);
    for o in ops {
        b.apply(o, view).ok()?;
    }
    b.finish()
}

/// The delta of `ops` on `f` by node `[s; 15]` at `t`·2^16 from counter 1; panics if one fails or
/// it writes nothing.
#[track_caller]
pub fn wrote<V: crate::view::View>(f: &Fragment, s: u8, t: u64, ops: &[crate::ops::PathOp], view: &V) -> Fragment {
    build(f, crate::ops::Writer::new(ts(t << 16), sess(Tid::from_bytes([s; 15])), 1), ops, view).expect("a delta").0
}

/// The read of a text, `None` when absent or not a string.
pub fn reads(f: &Fragment) -> Option<String> {
    match f.read() {
        Some(Value::Str(x)) => Some(x),
        _ => None,
    }
}

/// A snapshot's context: node 250 at ts 2^40.
pub fn snap_cx() -> DeltaCtx {
    DeltaCtx { ts: ts(1 << 40), own: source(&crdt_model::stamp::Source::session(250, 0)), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot }
}

/// Model writer `w`'s header as a writer's delta context.
pub fn writer_cx(w: &MWriter) -> DeltaCtx {
    DeltaCtx { ts: ts(w.ts), own: source(&w.source), range: CounterRange { lo: w.lo, hi: w.hi() }, kind: DeltaKind::Writer }
}

/// Writer `w`'s header as a writer's delta context.
pub fn ctx_of(w: &crate::ops::Writer) -> DeltaCtx {
    let s = w.delta_stamp();
    DeltaCtx { ts: s.ts, own: s.dot.src, range: w.range(), kind: DeltaKind::Writer }
}

/// A snapshot of `f` with nothing else in it.
pub fn snapshot(f: &Fragment) -> Snapshot {
    Snapshot { absorbed: Default::default(), facts: Default::default(), nonce: [0; 16], fragment: f.clone(), frontiers: Default::default() }
}

/// The unpaged bytes of `snapshot(f)`.
pub fn snapshot_bytes(f: &Fragment) -> Vec<u8> {
    crate::encode_snapshot(&snapshot(f), &snap_cx(), None).unwrap()
}

/// `f` through a snapshot: deleted chars dropped, uniform stretches as range records (§3.3).
pub fn via_snapshot(f: &Fragment) -> Fragment {
    crate::decode_snapshot(&snapshot_bytes(f), &snap_cx(), &mut crate::stamp::Interner::new(), None).unwrap().fragment
}

/// Delta `d` through the wire under `cx` (deletes come back as range records).
pub fn wired(d: &Fragment, cx: &DeltaCtx) -> Fragment {
    let bytes = crate::encode_delta(&crate::wire::Delta { nonce: [0; 16], fragment: d.clone() }, cx, None).unwrap();
    crate::decode_delta(&bytes, cx, &mut crate::stamp::Interner::new(), None).unwrap().fragment
}

fn ostamp(s: &Option<crdt_model::stamp::Stamp>) -> Option<Stamp> {
    s.as_ref().map(stamp)
}

fn meta(c: &m::Composite) -> Meta {
    Meta { reset: ostamp(&c.reset), w: ostamp(&c.w) }
}

fn elems(e: &BTreeMap<crdt_model::stamp::Dot, m::Elem>) -> BTreeMap<Dot, Elem> {
    e.iter().map(|(d, e)| (dot(d), Elem { reset: ostamp(&e.reset), frag: e.frag.as_ref().map(|f| Box::new(frag(f))), gone: e.gone.as_ref().map(|g| crate::fragment::Removal { stamp: stamp(&g.stamp), value: value(&g.value), seen: g.seen.iter().map(|(d, hi)| crate::stamp::DotRange { first: dot(d), hi: *hi }).collect() }) })).collect()
}

fn anchor(a: &m::Anchor) -> Anchor {
    match a {
        m::Anchor::Head => Anchor::Head,
        m::Anchor::Dot(d) => Anchor::Dot(dot(d)),
    }
}

fn register(reset: &Option<crdt_model::stamp::Stamp>, write: &Option<(crdt_model::stamp::Stamp, crdt_model::value::Value)>) -> Register {
    Register { reset: ostamp(reset), write: write.as_ref().map(|(s, v)| RegWrite { stamp: stamp(s), value: value(v) }) }
}

pub fn frag(f: &m::Frag) -> Fragment {
    match f {
        m::Frag::Register { reset, write } => Fragment::Register(register(reset, write)),
        m::Frag::Bag { kind, c, elems: e } => {
            let kind = match kind {
                m::BagKind::Counter => BagKind::Counter,
                m::BagKind::Max => BagKind::Max,
                m::BagKind::Min => BagKind::Min,
            };
            Fragment::Bag(Bag { kind, meta: meta(c), elems: elems(e) })
        }
        m::Frag::Struct { c, fields } => Fragment::Struct(Struct { meta: meta(c), fields: fields.iter().map(|(k, f)| (*k, frag(f))).collect() }),
        m::Frag::Enum { c, case, payloads } => Fragment::Enum(Enum {
            meta: meta(c),
            case: case.as_ref().map(|(s, k)| CaseWrite { stamp: stamp(s), case: *k }),
            payloads: payloads.iter().map(|(k, f)| (*k, frag(f))).collect(),
        }),
        m::Frag::Set { c, elems: e } => Fragment::Set(Set::new(meta(c), elems(e))),
        m::Frag::Map { c, entries } => Fragment::Map(Map::new(
            meta(c),
            entries
                .iter()
                .map(|((d, k), e)| (crate::fragment::Eid::new(dot(d), k.as_ref().map(value)), Entry { reset: ostamp(&e.reset), frag: e.frag.as_ref().map(|f| Box::new(frag(f))), created: ostamp(&e.created) }))
                .collect(),
        )),
        m::Frag::Seq { text, c, elems } => Fragment::Seq(Seq::new(
            *text,
            meta(c),
            // uniform stretches as range records, so every test meets them
            crate::seq_span::coalesce(elems
                .iter()
                .map(|(d, e)| {
                    let content = match &e.content {
                        m::Content::None => SeqContent::None,
                        m::Content::Char(c) => SeqContent::Char(*c),
                        m::Content::Frag(f) => SeqContent::Frag(Box::new(frag(f))),
                    };
                    let el = SeqElem {
                        created: e.created.as_ref().map(|(s, a)| (stamp(s), anchor(a))),
                        content,
                        pos: e.pos.iter().map(|(s, a, k)| (stamp(s), anchor(a), k.as_ref().map(stamp))).collect(),
                        deleted: e.deleted.as_ref().map(|(s, b)| (stamp(s), *b)),
                        undel: e.undel,
                        span: 1,
                        each: None,
                    };
                    (dot(d), el)
                })
                .collect()),
        )),
        m::Frag::Slots { reg, slots } => Fragment::Slots(Slots {
            reg: reg.as_ref().map(|r| match frag(r) {
                Fragment::Register(r) => r,
                _ => panic!("register slot"),
            }),
            slots: slots.iter().map(|(k, f)| (Encoding::from_id(u64::from(*k)).unwrap(), frag(f))).collect(),
        }),
    }
}

/// Every cached sequence placement inside `f` equals a whole pass (`seq_lin`), and the early-exit
/// presence check agrees with `written` (§4.3); sequences of more than 10^4 records are skipped
/// (timing tests).
pub fn check_lin(f: &Fragment) {
    let all = |it: &mut dyn Iterator<Item = &Fragment>| it.for_each(check_lin);
    let big = |f: &Fragment| matches!(f, Fragment::Seq(s) if s.elems().len() > 10_000);
    if !big(f) && !matches!(f, Fragment::Slots(x) if x.slots.values().any(big)) {
        assert_eq!(f.present(), f.written().is_some(), "presence");
    }
    match f {
        Fragment::Seq(s) => {
            if s.elems().len() > 10_000 {
                return;
            }
            assert_ne!(s.lin_check(), Some(false), "cached placement differs from a whole pass");
            all(&mut s.elems().values().filter_map(|e| if let SeqContent::Frag(x) = &e.content { Some(&**x) } else { None }));
        }
        Fragment::Struct(x) => all(&mut x.fields.values()),
        Fragment::Enum(x) => all(&mut x.payloads.values()),
        Fragment::Map(x) => all(&mut x.entries.values().filter_map(|e| e.frag.as_deref())),
        Fragment::Set(Set { elems, .. }) | Fragment::Bag(Bag { elems, .. }) => all(&mut elems.values().filter_map(|e| e.frag.as_deref())),
        Fragment::Slots(x) => {
            // a lone slot is chosen without a scan (§7 Read): it beats the register
            if let (Some(r), [m]) = (&x.reg, x.slots.values().collect::<Vec<_>>().as_slice())
                && !big(m)
            {
                assert!(Fragment::Register(r.clone()).all_max() <= m.all_max(), "lone slot chosen");
            }
            all(&mut x.slots.values())
        }
        Fragment::Register(_) => {}
    }
}

pub fn ostate(f: &Option<m::Frag>) -> Fragment {
    f.as_ref().map(frag).unwrap_or_default()
}

/// The kitchen-sink type without sequences: every encoding crdt-core implements, nested.
pub fn sink_no_seq() -> Ty {
    // a set of structs: elements are registers holding the whole value (§3.2)
    let pair = Ty::Struct([(1, Ty::Register), (2, Ty::Register)].into_iter().collect());
    let inner = Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(pair)))].into_iter().collect());
    let cases = [(0, None), (1, Some(Ty::Register)), (2, Some(inner.clone()))].into_iter().collect();
    Ty::Struct(
        [
            (1, Ty::Register),
            (2, Ty::Counter),
            (3, Ty::Max),
            (5, Ty::Enum(cases)),
            (6, Ty::Set(Box::new(Ty::Register))),
            (7, Ty::Map(Box::new(Ty::Register), Box::new(inner))),
            (9, Ty::Min),
        ]
        .into_iter()
        .collect(),
    )
}

/// A list of structs holding a register and a set.
pub fn struct_list() -> Ty {
    Ty::List(Box::new(Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect())))
}

pub use crdt_model::r#gen::{Commit as MCommit, apply as mapply};

/// `n` writers make `rounds` rounds of random ops, writer `i` with type `types[i % len]`, seeing
/// a random part of the others' commits. Returns the commits in creation order.
pub fn history(r: &mut Rng, types: &[Ty], n: usize, rounds: usize) -> Vec<MCommit> {
    let sources = (0..n).map(|i| crdt_model::stamp::Source::session(i as u8 + 1, 0)).collect();
    history_with(r, types, sources, rounds)
}

/// `history` with the given writer sources (commit form: a `Commit` source per writer).
pub fn history_with(r: &mut Rng, types: &[Ty], sources: Vec<crdt_model::stamp::Source>, rounds: usize) -> Vec<MCommit> {
    crdt_model::r#gen::history(r, types, sources, rounds, false, false, false)
}

/// `history_with` opened by `lead` rounds of writer 0 alone appending (`gen::history_led`).
pub fn history_led(r: &mut Rng, types: &[Ty], sources: Vec<crdt_model::stamp::Source>, lead: usize, rounds: usize) -> Vec<MCommit> {
    crdt_model::r#gen::history_led(r, types, sources, lead, rounds, false, false, false)
}

/// `history_with` whose writers 0 and 1 share a source (pass it twice) and a clock but choose
/// their ops apart: copies of one write (equal stamps) with differing payloads, and one dot under
/// two stamps, as a forged copy carries (spec/permissions.md §5.2).
pub fn history_twins(r: &mut Rng, types: &[Ty], sources: Vec<crdt_model::stamp::Source>, rounds: usize) -> Vec<MCommit> {
    crdt_model::r#gen::history(r, types, sources, rounds, false, false, true)
}

/// `history` as honest nodes of a non-role-class aspect write it: a clock past every commit seen
/// (a removal is newer than what it removes), keyless removals (§5.6).
pub fn history_honest(r: &mut Rng, types: &[Ty], n: usize, rounds: usize) -> Vec<MCommit> {
    let sources = (0..n).map(|i| crdt_model::stamp::Source::session(i as u8 + 1, 0)).collect();
    crdt_model::r#gen::history(r, types, sources, rounds, false, true, false)
}

/// `history_with` whose writers each end with a large write (`bulk_value`), so states and
/// those deltas page at small page parameters.
pub fn history_bulk(r: &mut Rng, types: &[Ty], sources: Vec<crdt_model::stamp::Source>, rounds: usize) -> Vec<MCommit> {
    crdt_model::r#gen::history(r, types, sources, rounds, true, false, false)
}

/// The model's schema type as a writer's view (identity projection, no defaults).
#[derive(Clone, Debug)]
pub struct TyView(pub Ty);

impl crate::view::View for TyView {
    fn encoding(&self) -> Option<Encoding> {
        Encoding::from_id(u64::from(self.0.enc()))
    }
    fn project<'a>(&self, v: &'a Value) -> Option<std::borrow::Cow<'a, Value>> {
        Some(std::borrow::Cow::Borrowed(v))
    }
    fn field(&self, id: u64) -> Option<TyView> {
        match &self.0 {
            Ty::Struct(f) => f.get(&id).cloned().map(TyView),
            _ => None,
        }
    }
    fn field_default(&self, _: u64) -> Option<Value> {
        None
    }
    fn case(&self, id: u64) -> Option<TyView> {
        match &self.0 {
            Ty::Enum(c) => c.get(&id).cloned().flatten().map(TyView),
            _ => None,
        }
    }
    fn element(&self) -> Option<TyView> {
        match &self.0 {
            Ty::Set(e) | Ty::List(e) | Ty::Map(_, e) => Some(TyView((**e).clone())),
            Ty::Counter | Ty::Max | Ty::Min => Some(TyView(Ty::Register)),
            _ => None,
        }
    }
    fn key(&self) -> Option<TyView> {
        match &self.0 {
            Ty::Map(k, _) => Some(TyView((**k).clone())),
            _ => None,
        }
    }
}

pub fn writer(w: &MWriter) -> crate::ops::Writer {
    crate::ops::Writer::new(ts(w.ts), source(&w.source), w.lo).keyed_removals(w.keyed)
}

/// A sequence held in part as a node holds a paged one: its records in pages of `per` records
/// (by key) loaded on a miss, its placement (`SeqPlace`) from the stored form of a whole one with
/// blocks and dot-map chunks loaded on a miss.
pub struct Pager {
    st: Seq,
    pub whole: crate::seq_place::SeqPlace,
    bounds: Vec<Option<Dot>>,
    pub loaded: std::collections::BTreeSet<usize>,
    pub p: crate::seq_place::SeqPlace,
    /// Whole passes over the records held (`PlaceMisses::whole`): loaded whole for a reason
    /// other than a miss.
    pub whole_passes: usize,
}

impl Pager {
    pub fn new(st: &Seq, per: usize) -> Pager {
        let whole = Fragment::Seq(st.clone()).seq_place().unwrap();
        let keys: Vec<&Dot> = st.elems().keys().collect();
        let bounds = std::iter::once(None).chain(keys.chunks(per.max(1)).skip(1).map(|c| Some(c[0].clone()))).collect();
        let p = crate::seq_place::SeqPlace::from_top(&whole.top()).unwrap();
        Pager { st: st.clone(), whole, bounds, loaded: Default::default(), p, whole_passes: 0 }
    }
    fn page_of(&self, x: &Dot) -> usize {
        self.bounds.partition_point(|b| b.as_ref().is_none_or(|b| b <= x)) - 1
    }
    /// Loads the pages holding `a..=b`.
    pub fn load(&mut self, a: &Dot, b: &Dot) {
        let r = self.page_of(a)..=self.page_of(b);
        self.loaded.extend(r);
    }
    /// The records loaded, with the placement attached (its cover set).
    pub fn part(&self) -> Fragment {
        let elems = self.st.elems().iter().filter(|(k, _)| self.loaded.contains(&self.page_of(k))).map(|(k, v)| (k.clone(), v.clone())).collect();
        self.p.cover(self.loaded.iter().map(|i| (self.bounds[*i].clone(), self.bounds.get(i + 1).cloned().flatten())).collect());
        let mut f = Fragment::Seq(Seq::new(self.st.text, self.st.meta.clone(), elems));
        let mut p = self.p.clone();
        if !p.is_partial() {
            // loaded whole: a text's chars set (`fill_chars`), as a node does
            f.fill_chars(&mut p);
        }
        f.set_seq_place(Some(p));
        f
    }
    /// `f` on the part held, loading what it missed and running it again until it misses nothing.
    pub fn run<T>(&mut self, mut f: impl FnMut(&Fragment) -> T) -> T {
        let mut got = f(&self.part());
        for _ in 1..64 {
            if !self.absorb() {
                break;
            }
            got = f(&self.part());
        }
        got
    }
    /// Loads what the placement missed since the last call; whether it missed anything.
    pub fn absorb(&mut self) -> bool {
        let m = self.p.misses();
        for b in &m.blocks {
            assert!(self.p.fill(*b, self.whole.rows(*b).unwrap()), "block {b} fits its counts");
        }
        for c in &m.chunks {
            assert!(self.p.fill_chunk(c.as_ref(), self.whole.chunk(c.as_ref()).unwrap()), "chunk fits");
        }
        for (a, b) in &m.recs {
            self.load(a, b);
        }
        self.whole_passes += usize::from(m.whole);
        if m.all {
            // as a node does: load whole
            self.loaded.extend(0..self.bounds.len());
            let (bs, cs) = self.p.stubs();
            for b in bs {
                assert!(self.p.fill(b, self.whole.rows(b).unwrap()));
            }
            for c in cs {
                assert!(self.p.fill_chunk(c.as_ref(), self.whole.chunk(c.as_ref()).unwrap()));
            }
            assert!(self.p.complete());
        }
        m.any()
    }
}

/// A placement held in part (`SeqPlace`) followed through joining `d` into the records of
/// `st` held in part (pages of `per` records), loading what it misses (`dry_follow`, then the
/// join itself): where it follows it is a whole pass of the joined state, the join loads
/// nothing more, and what it changed can be written back. Whether it followed, with the blocks
/// it loaded and all blocks.
pub fn partial_follow(st: &Seq, d: &Seq, per: usize) -> Option<(usize, usize)> {
    partial_follow_in(st, d, per, true).map(|x| x.0)
}

/// `partial_follow`, also giving the pages it loaded; without `newest` the stored placement has
/// no newest-stamp bound (`PlaceTop::newest` unknown).
pub fn partial_follow_in(st: &Seq, d: &Seq, per: usize, newest: bool) -> Option<((usize, usize), usize)> {
    use crate::seq_place::SeqPlace;
    let mut pg = Pager::new(st, per);
    if !newest {
        pg.p = SeqPlace::from_top(&crate::seq_place::PlaceTop { newest: None, ..pg.whole.top() }).unwrap();
    }
    for (k, e) in d.elems() {
        pg.load(k, &nth(k, e.span - 1));
    }
    for _ in 0..64 {
        pg.part().dry_follow(&Fragment::Seq(d.clone()), &pg.p);
        if !pg.absorb() {
            break;
        }
    }
    let mut part = pg.part();
    let old = pg.p.clone();
    part.join(Fragment::Seq(d.clone()));
    let after = part.seq_place_cached()?;
    let whole = &pg.whole;
    let counts = (whole.top().blocks.len() - old.stubs().0.len(), whole.top().blocks.len());
    assert!(!old.misses().any(), "the join missed nothing the dry run loaded");
    let mut want = st.clone();
    join_seq(&mut want, d.clone());
    let want = Fragment::Seq(want).seq_place().unwrap();
    // loaded whole from the stored form: blocks and chunks as written back
    let diff = after.diff(&old).expect("descends from what was stored");
    let mut back = SeqPlace::from_top(&after.top()).unwrap();
    let (bs, cs) = back.stubs();
    for b in bs {
        let rows = after.rows(b).or_else(|| (!diff.blocks.contains(&b)).then(|| whole.rows(b)).flatten()).unwrap();
        assert!(back.fill(b, rows));
    }
    for c in cs {
        let e = after.chunk(c.as_ref()).or_else(|| (!diff.chunks.contains(&c)).then(|| whole.chunk(c.as_ref())).flatten()).unwrap();
        assert!(back.fill_chunk(c.as_ref(), e));
    }
    assert!(back.complete());
    assert!(back.same(&want), "a placement held in part, followed and stored, is a whole pass's");
    Some((counts, pg.loaded.len()))
}

/// `s` ⊔ `d` (a fragment join of two sequences).
fn join_seq(s: &mut Seq, d: Seq) {
    let mut f = Fragment::Seq(std::mem::replace(s, Seq::empty(d.text)));
    f.join(Fragment::Seq(d));
    if let Fragment::Seq(x) = f {
        *s = x;
    }
}

/// `decoded_bound` holds for `bytes` decoded to `f` (a memory bound, spec: none).
pub fn check_bound(bytes: &[u8], f: &Fragment) {
    let bound = crate::decoded_bound(bytes).unwrap();
    assert!(f.approx_bytes() <= bound, "{} > bound {bound}", f.approx_bytes());
}

/// A hand-built snapshot's `Facts` (§8): the narrowest, one per entry of `commits` (a
/// `Commits` table value).
pub fn narrowest_facts(commits: &Value) -> Value {
    let n = if let Value::List(entries) = commits { entries.len() } else { 0 };
    Value::List(std::iter::repeat_n(Value::Int(1), n).collect())
}

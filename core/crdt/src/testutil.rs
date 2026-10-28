//! Test support: conversion from the reference model (core/test/crdt-model) and random op sequences from
//! its generator (notes/crdt.md, Reference model).

use crate::fragment::{Bag, BagKind, CaseWrite, Elem, Encoding, Entry, Enum, Fragment, Map, Meta, RegWrite, Register, Set, Slots, Struct};
use crate::seq::{Anchor, Seq, SeqContent, SeqElem};
use crate::seq_span::nth;
use crate::stamp::{Dot, Source, Stamp};
use crdt_model::r#gen::{Rng, random_op};
use crdt_model::ops::{Ty, Writer as MWriter};
use crdt_model::state as m;
use osis_base::{CommitId, Float, Tid, Ts, Value};
use std::collections::BTreeMap;

/// A random test's seed: `seed`, or `seed` xor a hash of `OSIS_CRDT_SEED` (decimal) to sample
/// other runs (`OSIS_CRDT_SEED=7 cargo test --workspace`); unset, the committed seed. Hashed: a
/// small value xored into a loop's consecutive seeds would only reorder them.
pub fn seeded(seed: u64) -> u64 {
    match std::env::var("OSIS_CRDT_SEED").ok().filter(|v| !v.is_empty()) {
        // (a zero xorshift state never leaves zero)
        Some(v) => (seed ^ splitmix(v.parse::<u64>().unwrap_or_else(|_| panic!("OSIS_CRDT_SEED={v:?} is not a decimal u64")))).max(1),
        None => seed,
    }
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
        V::Tid(t) => Value::Tid(Tid::from_bytes(*t)),
        V::List(l) => Value::List(l.iter().map(value).collect()),
        V::Map(kv) => Value::Map(kv.iter().map(|(k, v)| (value(k), value(v))).collect()),
        V::Set(s) => Value::Set(s.iter().map(value).collect()),
        V::Enum(id, p) => Value::Enum(*id, p.as_ref().map(|p| Box::new(value(p)))),
    }
}

pub fn source(s: &crdt_model::stamp::Source) -> Source {
    use crdt_model::stamp::Source as S;
    match s {
        S::Node(b) => Source::node(Tid::from_bytes(*b)),
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

fn ostamp(s: &Option<crdt_model::stamp::Stamp>) -> Option<Stamp> {
    s.as_ref().map(stamp)
}

fn meta(c: &m::Composite) -> Meta {
    Meta { reset: ostamp(&c.reset), w: ostamp(&c.w) }
}

fn elems(e: &BTreeMap<crdt_model::stamp::Dot, m::Elem>) -> BTreeMap<Dot, Elem> {
    e.iter().map(|(d, e)| (dot(d), Elem { reset: ostamp(&e.reset), frag: e.frag.as_ref().map(|f| Box::new(frag(f))) })).collect()
}

fn anchor(a: &m::Anchor) -> Anchor {
    match a {
        m::Anchor::Head => Anchor::Head,
        m::Anchor::Dot(d) => Anchor::Dot(dot(d)),
    }
}

fn register(reset: &Option<crdt_model::stamp::Stamp>, write: &Option<(crdt_model::stamp::Stamp, Option<crdt_model::value::Value>)>) -> Register {
    Register { reset: ostamp(reset), write: write.as_ref().map(|(s, v)| RegWrite { stamp: stamp(s), value: v.as_ref().map(value) }) }
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
        m::Frag::Set { c, elems: e } => Fragment::Set(Set { meta: meta(c), elems: elems(e) }),
        m::Frag::Map { c, entries } => Fragment::Map(Map::new(
            meta(c),
            entries
                .iter()
                .map(|(d, e)| (dot(d), Entry { reset: ostamp(&e.reset), key: e.key.as_ref().map(value), frag: e.frag.as_ref().map(|f| Box::new(frag(f))), created: ostamp(&e.created) }))
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
                        pos: e.pos.iter().map(|(s, a)| (stamp(s), anchor(a))).collect(),
                        deleted: e.deleted.as_ref().map(|(s, b)| (stamp(s), *b)),
                        span: 1,
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
            members: slots.iter().map(|(k, f)| (Encoding::from_id(u64::from(*k)).unwrap(), frag(f))).collect(),
        }),
    }
}

/// Every cached sequence placement inside `f` equals a whole pass (`seq_lin`), and the early-exit
/// presence check agrees with `written` (§4.3); sequences of more than 10^4 records are skipped
/// (timing tests).
pub fn check_lin(f: &Fragment) {
    let all = |it: &mut dyn Iterator<Item = &Fragment>| it.for_each(check_lin);
    let big = |f: &Fragment| matches!(f, Fragment::Seq(s) if s.elems().len() > 10_000);
    if !big(f) && !matches!(f, Fragment::Slots(x) if x.members.values().any(big)) {
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
            // a lone member is chosen without a scan (§7 Read): it beats the register
            if let (Some(r), [m]) = (&x.reg, x.members.values().collect::<Vec<_>>().as_slice())
                && !big(m)
            {
                assert!(Fragment::Register(r.clone()).all_max() <= m.all_max(), "lone member chosen");
            }
            all(&mut x.members.values())
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

/// Model join of a delta into an optional state (core/test/crdt-model/tests/props.rs `apply`).
pub fn mapply(state: &mut Option<m::Frag>, d: m::Frag) {
    match state {
        None => {
            let mut s = d;
            s.prune(None);
            *state = Some(s);
        }
        Some(s) => s.join(d),
    }
}

/// One commit of the random history.
pub struct MCommit {
    pub w: MWriter,
    pub delta: m::Frag,
}

/// `n` writers make `rounds` rounds of random ops, writer `i` with type `types[i % len]`, seeing
/// a random part of the others' commits. Returns the commits in creation order.
pub fn history(r: &mut Rng, types: &[Ty], n: usize, rounds: usize) -> Vec<MCommit> {
    let sources = (0..n).map(|i| crdt_model::stamp::Source::node(i as u8 + 1)).collect();
    history_with(r, types, sources, rounds)
}

/// `history` with the given writer sources (commit form: a `Commit` source per writer).
pub fn history_with(r: &mut Rng, types: &[Ty], sources: Vec<crdt_model::stamp::Source>, rounds: usize) -> Vec<MCommit> {
    let n = sources.len();
    let mut ws: Vec<MWriter> = sources.into_iter().map(|s| MWriter::new(s, 1 << 16, 0)).collect();
    let mut states: Vec<Option<m::Frag>> = vec![None; n];
    let mut seen: Vec<usize> = vec![0; n];
    let mut commits: Vec<MCommit> = Vec::new();
    for round in 0..rounds {
        for i in 0..n {
            // catch up on a random prefix of the others' commits
            let upto = seen[i] + r.below(commits.len() - seen[i] + 1);
            for c in &commits[seen[i]..upto] {
                mapply(&mut states[i], c.delta.clone());
            }
            seen[i] = upto;
            let t = ((round as u64 * 10 + r.below(10) as u64 + 1) << 16) + i as u64;
            let t = t.max(ws[i].ts + 1);
            let before = ws[i].clone();
            ws[i].next_commit(t);
            let ty = &types[i % types.len()];
            match random_op(r, &mut ws[i], ty, states[i].as_ref()) {
                Some(d) => {
                    mapply(&mut states[i], d.clone());
                    commits.push(MCommit { w: ws[i].clone(), delta: d });
                }
                None => ws[i] = before,
            }
        }
    }
    commits
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
    crate::ops::Writer::new(ts(w.ts), source(&w.source), w.lo)
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
/// no newest-stamp bound (a top written before it).
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

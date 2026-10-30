//! Op scripts on one sequence position replayed against the reference model (core/test/crdt-model)
//! and the differentials of the sequence tests (spec/crdt.md §3.3, §4.5, §4.6, §5.7, §6, §8): the
//! `seq_ops` fuzz target (core/test/fuzz/fuzz_targets/seq_ops.rs) and a tier-1 run of random
//! scripts. Built for tests and fuzzing only.
//!
//! Checked on every step: a writer's delta decodes to itself and re-encodes to the same bytes;
//! a model commit encodes to the model's bytes; a commit's ops read like the same ops on a
//! plain sequence, like the same ops committed one by one, and write the same delta on the
//! state held in part (`Pager`) as on the whole; every cached placement equals a whole pass
//! after every join (`check_lin`), and one held in part follows a join as a whole pass does
//! (`partial_follow`); an undo from the delta's footprint equals one from the whole state; a
//! snapshot round trip keeps the read and re-encodes to the same bytes; a replica every commit
//! of which has a model form equals the model's state (read only after a snapshot); and at the
//! end every replica, given every commit, reads the same (never rebooted: holds the same state).
//! The debug comparisons inside the crate
//! (`Batch`'s layered view against state + net effect, the layered placement against a whole
//! pass, incremental slots join against a whole one) run throughout.

use crate::batch::Batch;
use crate::codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot};
use crate::fragment::Fragment;
use crate::ops::{Op, PathOp, PathSeg, Writer};
use crate::seq::SeqContent;
use crate::stamp::{CounterRange, Dot, Interner, Source};
use crate::testutil::{Pager, TyView, check_lin, frag, mapply, partial_follow, source, ts, value};
use crate::undo::{Undone, undo};
use crate::wire::{Delta, DeltaCtx, DeltaKind, Snapshot};
use crdt_model::r#gen::{Rng, random_op, random_text, random_value};
use crdt_model::ops::{self as mops, Ty, Writer as MWriter};
use crdt_model::state::{Content, Frag as MFrag};
use crdt_model::stamp::Source as MSource;
use osis_base::{Tid, Value};
use std::collections::BTreeSet;

/// Replicas of the position.
pub const REPLICAS: usize = 3;
/// Steps of a script replayed (the rest ignored), ops per commit, commits per join step.
const MAX_STEPS: usize = 96;
const MAX_OPS: usize = 4;
const MAX_JOIN: usize = 8;

/// Replicas of one text (or list) position and the steps they take.
#[derive(Clone, Debug)]
pub struct Script {
    pub list: bool,
    pub steps: Vec<Step>,
}

#[derive(Clone, Debug)]
pub enum Step {
    /// One commit of `ops` by replica `r` (indices against its read, wrapped). `skew` > 0: by a
    /// fresh writer whose clock is above the sequence's reset, below the clock and often below
    /// the stamps already there (inserts only, §2.2). `per` > 0: also run on the state held in part in pages of
    /// `per` records.
    Ops { r: u8, ops: Vec<LocalOp>, skew: u8, per: u8 },
    /// A commit the model writes (`random_op` seeded by `seed`) on replica `r`, if its state has
    /// followed the model's so far.
    Model { r: u8, seed: u16 },
    /// Replica `r` undoes its `back`-th last commit (wrapped).
    Undo { r: u8, back: u8 },
    /// Replica `to` joins `n` commits of the log from the `pick`-th on (wrapped; seen ones again
    /// as duplicates); `per` > 0: each also followed by a placement held in part; `merged`: the
    /// commits joined into one delta first (several writes on one element in one delta).
    Join { to: u8, pick: u8, n: u8, per: u8, merged: bool },
    /// Replica `r`'s state through a snapshot round trip (deleted chars dropped, range records).
    Reboot { r: u8 },
    /// Replica `r` starts over from replica `from`'s snapshot, then joins its own commits.
    Bootstrap { r: u8, from: u8 },
}

/// A local op; indices and lengths wrap to the read it applies to.
#[derive(Clone, Debug)]
pub enum LocalOp {
    Insert { at: u16, item: u8 },
    Delete { at: u16, len: u8 },
    Move { at: u16, len: u8, to: u16 },
    /// Text: a paste of the `run`-th run of deleted chars (adjacent in placement order) at `at`;
    /// a list: a nested field set of the item at `run`.
    Paste { run: u8, at: u16 },
    /// An edit (notes/api.md `edit`) from the read, or (`stale`, first op only) from the
    /// replica's read before its last commit, to it with a splice at `at`.
    Edit { at: u16, del: u8, item: u8, stale: bool },
    Set { item: u8 },
}

struct Rep {
    st: Fragment,
    ms: Option<MFrag>,
    /// Every commit joined has a model form: `ms` is the same history.
    tracked: bool,
    /// Never rebooted: `st` equals the model's state, not only its read.
    whole: bool,
    seen: BTreeSet<usize>,
    msrc: MSource,
    lo: u64,
    stale: Option<Value>,
    /// The log index of this replica's last commit, if nothing joined since.
    last: Option<usize>,
}

struct Commit {
    d: Fragment,
    md: Option<MFrag>,
    by: usize,
    src: Source,
    range: CounterRange,
    before: Fragment,
    /// The undo of this commit restores `before`'s read when nothing joined after it (§4.6
    /// Exactness): no list item write, not a model commit.
    restores: bool,
}

/// What a replay checked.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub commits: usize,
    pub partial: usize,
    pub one_by_one: usize,
    pub model_ops: usize,
    pub model_commits: usize,
    pub undos: usize,
    pub restores: usize,
    pub joins: usize,
    pub model_joins: usize,
    /// joins of several commits as one delta
    pub merged: usize,
}

struct World {
    list: bool,
    ty: Ty,
    view: TyView,
    reps: Vec<Rep>,
    log: Vec<Commit>,
    clock: u64,
    fresh: u64,
    /// Dots pasted by the commit being resolved.
    pasted: std::cell::RefCell<BTreeSet<Dot>>,
    stats: Stats,
}

/// Replays `s`; panics on a property that does not hold.
pub fn replay(s: &Script) -> Stats {
    let ty = if s.list { Ty::List(Box::new(Ty::Struct([(1, Ty::Register), (2, Ty::Register)].into_iter().collect()))) } else { Ty::Text };
    let reps = (0..REPLICAS)
        .map(|i| Rep { st: Fragment::default(), ms: None, tracked: true, whole: true, seen: BTreeSet::new(), msrc: MSource::node(i as u8 + 1), lo: 1, stale: None, last: None })
        .collect();
    let mut w = World { list: s.list, view: TyView(ty.clone()), ty, reps, log: Vec::new(), clock: 0, fresh: 0, pasted: Default::default(), stats: Stats::default() };
    for st in s.steps.iter().take(MAX_STEPS) {
        w.step(st);
    }
    w.converge();
    w.stats
}

/// A random script (tier 1, and the shape the fuzz target's inputs take).
pub fn random_script(r: &mut Rng, steps: usize) -> Script {
    let b = |r: &mut Rng| r.below(256) as u8;
    let w = |r: &mut Rng| r.below(1 << 16) as u16;
    let op = |r: &mut Rng| match r.below(8) {
        0 | 1 => LocalOp::Insert { at: w(r), item: b(r) },
        2 => LocalOp::Delete { at: w(r), len: b(r) },
        3 => LocalOp::Move { at: w(r), len: b(r), to: w(r) },
        4 => LocalOp::Paste { run: b(r), at: w(r) },
        5 | 6 => LocalOp::Edit { at: w(r), del: b(r), item: b(r), stale: r.chance(1, 4) },
        _ => LocalOp::Set { item: b(r) },
    };
    // a third of the scripts only what the model writes too: their replicas follow the model
    let modelled = r.chance(1, 3);
    let steps = (0..steps)
        .map(|_| {
            let rr = r.below(REPLICAS) as u8;
            match r.below(12) {
                0..=4 if modelled => {
                    let o = match r.below(3) {
                        0 => LocalOp::Insert { at: w(r), item: b(r) },
                        1 => LocalOp::Delete { at: w(r), len: b(r) },
                        _ => LocalOp::Move { at: w(r), len: b(r), to: w(r) },
                    };
                    Step::Ops { r: rr, ops: vec![o], skew: 0, per: if r.chance(1, 2) { 1 + r.below(8) as u8 } else { 0 } }
                }
                7 | 10 | 11 if modelled => Step::Model { r: rr, seed: w(r) },
                0..=4 => {
                    let ops = (0..1 + r.below(3)).map(|_| op(r)).collect();
                    let skew = if r.chance(1, 5) { 1 + r.below(255) as u8 } else { 0 };
                    let per = if r.chance(1, 2) { 1 + r.below(8) as u8 } else { 0 };
                    Step::Ops { r: rr, ops, skew, per }
                }
                5 | 6 => Step::Model { r: rr, seed: w(r) },
                // half of them the last commit, which an undo restores when nothing joined since
                7 => Step::Undo { r: rr, back: if r.chance(1, 2) { 0 } else { b(r) } },
                8 | 9 => Step::Join { to: rr, pick: b(r), n: 1 + r.below(4) as u8, per: if r.chance(1, 2) { 1 + r.below(8) as u8 } else { 0 }, merged: r.chance(1, 3) },
                10 => Step::Reboot { r: rr },
                _ => Step::Bootstrap { r: rr, from: r.below(REPLICAS) as u8 },
            }
        })
        .collect();
    Script { list: !modelled && r.chance(1, 3), steps }
}

/// The read of a sequence position as items: a text's chars (one-char strings) or a list's items.
fn items(v: Option<Value>) -> Vec<Value> {
    match v {
        Some(Value::Str(s)) => s.chars().map(|c| Value::Str(c.into())).collect(),
        Some(Value::List(l)) => l,
        _ => Vec::new(),
    }
}

fn joined_items(list: bool, it: &[Value]) -> Value {
    if list {
        Value::List(it.to_vec())
    } else {
        Value::Str(it.iter().filter_map(|v| if let Value::Str(s) = v { Some(s.as_str()) } else { None }).collect())
    }
}

/// Runs of deleted chars, adjacent in placement order (what a paste of cut text restores).
fn deleted_runs(st: &Fragment) -> Vec<Vec<Dot>> {
    let Fragment::Seq(sq) = st else { return Vec::new() };
    let mut runs: Vec<Vec<Dot>> = vec![vec![]];
    for d in crate::linearize::place(sq.elems(), sq.text).iter().map(|r| r.dot.clone()) {
        let Some(e) = crate::seq_span::Recs::elem(sq.elems(), &d) else { continue };
        match (e.flag(), &e.content) {
            (true, SeqContent::Char(_)) => runs.last_mut().into_iter().for_each(|x| x.push(d.clone())),
            (true, _) => {}
            _ => runs.push(vec![]),
        }
    }
    runs.retain(|x| !x.is_empty());
    runs
}

fn char_of(st: &Fragment, d: &Dot) -> Option<Value> {
    let Fragment::Seq(sq) = st else { return None };
    match crate::seq_span::Recs::elem(sq.elems(), d)?.content {
        SeqContent::Char(c) => Some(Value::Str(c.into())),
        _ => None,
    }
}

fn wrap(x: usize, n: usize) -> usize {
    if n == 0 { 0 } else { x % n }
}

/// `f` through a snapshot; the bytes re-encode identically (§3.3).
fn rebooted(f: &Fragment) -> Fragment {
    let cx = snap_cx();
    let snap = |f: &Fragment| Snapshot { absorbed: Default::default(), authors: Default::default(), nonce: [0; 16], fragment: f.clone(), frontiers: Default::default() };
    let bytes = encode_snapshot(&snap(f), &cx, None).expect("snapshot encodes");
    let back = decode_snapshot(&bytes, &cx, &mut Interner::new(), None).expect("own snapshot decodes").fragment;
    assert_eq!(encode_snapshot(&snap(&back), &cx, None).expect("snapshot encodes"), bytes, "a decoded snapshot re-encodes to its bytes");
    assert_eq!(back.read(), f.read(), "a snapshot round trip keeps the read");
    back
}

fn snap_cx() -> DeltaCtx {
    DeltaCtx { ts: ts(1 << 50), own: source(&MSource::node(250)), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot }
}

/// A writer's delta through the wire: decodes to itself, re-encodes to the same bytes.
fn wired(d: &Fragment, cx: &DeltaCtx) -> (Fragment, Vec<u8>) {
    let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, cx, None).expect("delta encodes");
    let back = decode_delta(&bytes, cx, &mut Interner::new(), None).expect("own delta decodes").fragment;
    assert_eq!(&back, d, "a writer's delta round-trips");
    assert_eq!(encode_delta(&Delta { nonce: [0; 16], fragment: back.clone() }, cx, None).expect("delta encodes"), bytes, "a decoded delta re-encodes to its bytes");
    (back, bytes)
}

impl World {
    fn now(&mut self) -> u64 {
        self.clock += 1;
        (1000 + self.clock) << 16
    }

    fn item(&self, k: u8) -> Value {
        match &self.ty {
            Ty::List(e) => value(&random_value(&mut Rng(u64::from(k) + 1), e, 1)),
            _ => Value::Str((0..1 + k % 3).map(|i| char::from(b'a' + (k / 3 + i) % 8)).collect()),
        }
    }

    /// `o` as an op on a sequence read `m` (updated as the op reads), base state `st`; `None`
    /// skips it. `known` goes false when the effect is not that of the plain sequence.
    fn resolve(&self, o: &LocalOp, first: bool, m: &mut Vec<Value>, st: &Fragment, stale: Option<&Value>, known: &mut bool) -> Option<PathOp> {
        let n = m.len();
        let plain = |op| Some(PathOp { path: Vec::new(), op });
        match *o {
            LocalOp::Insert { at, item } => {
                let at = wrap(at.into(), n + 1);
                let v = self.item(item);
                let new = if self.list { vec![v.clone()] } else { items(Some(v.clone())) };
                m.splice(at..at, new);
                plain(Op::Insert { at, items: vec![v] })
            }
            LocalOp::Delete { at, len } => {
                let at = wrap(at.into(), n);
                let len = 1 + wrap(len.into(), (n - at).min(6));
                (n > 0).then(|| m.drain(at..at + len)).map(|_| ())?;
                plain(Op::Delete { at, len })
            }
            LocalOp::Move { at, len, to } => {
                let at = wrap(at.into(), n);
                let len = 1 + wrap(len.into(), (n - at).min(6));
                if n == 0 {
                    return None;
                }
                let to = wrap(to.into(), n - len + 1);
                let x: Vec<Value> = m.drain(at..at + len).collect();
                m.splice(to..to, x);
                plain(Op::Move { at, len, to })
            }
            LocalOp::Paste { run, at } if self.list => {
                // a nested field set of an item
                let i = wrap(run.into(), n);
                let x = m.get_mut(i)?;
                let f = 1 + u64::from(at % 2);
                let v = Value::Int(i64::from(at >> 1) % 5);
                match x {
                    Value::Map(kv) => {
                        kv.insert(Value::Int(f as i64), v.clone());
                    }
                    _ => *known = false,
                }
                Some(PathOp { path: vec![PathSeg::Index(i), PathSeg::Field(f)], op: Op::Set(v) })
            }
            LocalOp::Paste { run, at } => {
                // a run pasted once in this commit is visible again: not pasted twice
                let mut runs = deleted_runs(st);
                runs.retain(|x| !x.iter().any(|d| self.pasted.borrow().contains(d)));
                if runs.is_empty() {
                    return None;
                }
                let dots = runs.swap_remove(wrap(run.into(), runs.len()));
                self.pasted.borrow_mut().extend(dots.iter().cloned());
                let at = wrap(at.into(), n + 1);
                let cs: Vec<Value> = dots.iter().filter_map(|d| char_of(st, d)).collect();
                m.splice(at..at, cs);
                plain(Op::Paste { dots, at })
            }
            LocalOp::Edit { at, del, item, stale: s } => {
                let base = match stale {
                    Some(v) if s && first => {
                        *known = false;
                        v.clone()
                    }
                    _ => joined_items(self.list, m),
                };
                let mut b = items(Some(base.clone()));
                let at = wrap(at.into(), b.len() + 1);
                let del = wrap(del.into(), (b.len() - at).min(4) + 1);
                let ins: Vec<Value> = if self.list { (0..item % 2).map(|k| self.item(item.wrapping_add(k))).collect() } else { items(Some(Value::Str("ed".chars().take(usize::from(item % 3)).collect()))) };
                b.splice(at..at + del, ins);
                let new = joined_items(self.list, &b);
                if *known {
                    *m = b;
                }
                plain(Op::Edit { base, new })
            }
            LocalOp::Set { item } => {
                let v = match &self.ty {
                    Ty::List(_) => Value::List((0..item % 4).map(|k| self.item(item.wrapping_add(k))).collect()),
                    _ => Value::Str(random_text(&mut Rng(u64::from(item) + 1), 8)),
                };
                *m = items(Some(v.clone()));
                plain(Op::Set(v))
            }
        }
    }

    fn step(&mut self, s: &Step) {
        match *s {
            Step::Ops { r, ref ops, skew, per } => self.ops(usize::from(r) % REPLICAS, ops, skew, per),
            Step::Model { r, seed } => self.model(usize::from(r) % REPLICAS, seed),
            Step::Undo { r, back } => self.undo(usize::from(r) % REPLICAS, back),
            Step::Join { to, pick, n, per, merged } => {
                let to = usize::from(to) % REPLICAS;
                let len = self.log.len();
                let ks: Vec<usize> = (0..(usize::from(n) % (MAX_JOIN + 1)).min(len)).map(|k| (usize::from(pick) + k) % len).collect();
                if merged {
                    self.deliver_merged(to, &ks, per);
                } else {
                    for k in ks {
                        self.deliver(to, k, per);
                    }
                }
            }
            Step::Reboot { r } => {
                let rep = &mut self.reps[usize::from(r) % REPLICAS];
                rep.st = rebooted(&rep.st);
                rep.whole = false;
                check_lin(&rep.st);
            }
            Step::Bootstrap { r, from } => {
                let (r, from) = (usize::from(r) % REPLICAS, usize::from(from) % REPLICAS);
                if r == from {
                    return;
                }
                let f = &self.reps[from];
                let (st, ms, tracked, seen) = (rebooted(&f.st), f.ms.clone(), f.tracked, f.seen.clone());
                let rep = &mut self.reps[r];
                // its writer's counters go on (a writer never reuses a dot, §2.3)
                *rep = Rep { st, ms, tracked, whole: false, seen, msrc: rep.msrc.clone(), lo: rep.lo, stale: None, last: None };
                check_lin(&rep.st);
                // and keeps its own commits (an undo reads them from its state)
                for k in 0..self.log.len() {
                    if self.log[k].by == r && !self.reps[r].seen.contains(&k) {
                        self.deliver(r, k, 0);
                    }
                }
            }
        }
    }

    /// Joins `d` into replica `i`'s state, a placement held in part following it first when
    /// `per` > 0; every cached placement then equals a whole pass.
    fn join_into(&mut self, i: usize, d: Fragment, per: u8) {
        let st = &mut self.reps[i].st;
        if per > 0
            && let (Fragment::Seq(sq), Fragment::Seq(ds)) = (&*st, &d)
        {
            let _ = st.read();
            let _ = partial_follow(sq, ds, usize::from(per));
        }
        st.join(d);
        check_lin(st);
    }

    /// The model's state and read equal replica `i`'s, while it follows the model.
    fn check_model(&self, i: usize, what: &str) {
        let rep = &self.reps[i];
        if !rep.tracked {
            return;
        }
        if rep.whole {
            assert!(rep.st == rep.ms.as_ref().map(frag).unwrap_or_default(), "replica {i} state equals the model's after {what}");
        }
        assert_eq!(rep.st.read(), rep.ms.as_ref().and_then(|m| m.read()).map(|v| value(&v)), "replica {i} read equals the model's after {what}");
    }

    fn deliver(&mut self, to: usize, k: usize, per: u8) {
        self.deliver_merged(to, &[k], per);
    }

    /// Joins commits `ks` of the log into replica `to` as one delta: more than one is joined into
    /// a copy of its state first (text content needs the creation it lives with, §5.7), as a peer's
    /// state would arrive.
    fn deliver_merged(&mut self, to: usize, ks: &[usize], per: u8) {
        let d = match ks {
            [] => return,
            [k] => self.log[*k].d.clone(),
            _ => {
                self.stats.merged += 1;
                let mut d = self.reps[to].st.clone();
                for &k in ks {
                    d.join(self.log[k].d.clone());
                }
                d
            }
        };
        self.join_into(to, d, per);
        self.stats.joins += ks.len();
        let rep = &mut self.reps[to];
        rep.last = None;
        for &k in ks {
            rep.seen.insert(k);
            match self.log[k].md.clone() {
                Some(md) if rep.tracked => {
                    self.stats.model_joins += 1;
                    mapply(&mut rep.ms, md)
                }
                _ => rep.tracked = false,
            }
        }
        self.check_model(to, "a join");
    }

    fn push(&mut self, i: usize, c: Commit, md_ok: bool) {
        let k = self.log.len();
        let rep = &mut self.reps[i];
        rep.seen.insert(k);
        rep.last = Some(k);
        match &c.md {
            Some(md) if md_ok && rep.tracked => mapply(&mut rep.ms, md.clone()),
            _ => rep.tracked = false,
        }
        self.log.push(c);
        self.check_model(i, "a commit");
    }

    fn ops(&mut self, i: usize, ops: &[LocalOp], skew: u8, per: u8) {
        let st = self.reps[i].st.clone();
        let stale = self.reps[i].stale.clone();
        let before = st.read();
        let mut m = items(before.clone());
        // below newer siblings an insert lands after their subtrees (§6.1), not at its index
        let mut known = skew == 0;
        let mut pops = Vec::new();
        self.pasted.borrow_mut().clear();
        for (j, o) in ops.iter().take(MAX_OPS).enumerate() {
            let o = match o {
                // below stamps already there: inserts only (§2.2's clock rule, checked by `Batch`)
                LocalOp::Insert { .. } => o.clone(),
                LocalOp::Delete { at, len } | LocalOp::Move { at, len, .. } if skew > 0 => LocalOp::Insert { at: *at, item: *len },
                _ if skew > 0 => LocalOp::Insert { at: 0, item: 0 },
                _ => o.clone(),
            };
            pops.extend(self.resolve(&o, j == 0, &mut m, &st, stale.as_ref(), &mut known));
        }
        if pops.is_empty() {
            return;
        }
        // a move where concurrent moves closed cycles (§6.2: broken by demotion) may re-place
        // the elements of a broken cycle too
        if pops.iter().any(|o| matches!(o.op, Op::Move { .. } | Op::Paste { .. })) && st.seq_place().is_some_and(|p| !p.top().cyc.is_empty()) {
            known = false;
        }
        let now = self.now();
        let (t, src, lo) = if skew > 0 {
            self.fresh += 1;
            let mut b = [0xee; 15];
            b[..8].copy_from_slice(&self.fresh.to_le_bytes());
            let floor = st.reset().map_or(0, |x| (x.ts.to_u64() >> 16) + 1);
            // below the clock (a node's clock is above every stamp it holds, §2.2)
            let span = (now >> 16).saturating_sub(floor).max(1);
            ((floor + u64::from(skew) % span) << 16, Source::node(Tid::from_bytes(b)), 1)
        } else {
            (now, source(&self.reps[i].msrc), self.reps[i].lo)
        };
        let w = || Writer::new(ts(t), src.clone(), lo);
        let run = |f: &Fragment, w: Writer| -> Result<Option<(Fragment, CounterRange)>, ()> {
            let mut b = Batch::new(f, w);
            for o in &pops {
                b.apply(o, &self.view).map_err(|_| ())?;
            }
            Ok(b.finish())
        };
        let Ok(want) = run(&st, w()) else { return };
        // held in part: the same delta, loading what it misses
        if per > 0
            && let Fragment::Seq(sq) = &st
        {
            let mut pg = Pager::new(sq, usize::from(per));
            let mut got = Err(());
            for _ in 0..64 {
                got = run(&pg.part(), w());
                if !pg.absorb() {
                    break;
                }
            }
            self.stats.partial += 1;
            assert!(got == Ok(want.clone()), "ops on a state held in part write what they write on the whole: {pops:?}\n got {got:?}\n want {want:?}");
        }
        // one by one: the same read
        let mut one = (pops.len() > 1).then(|| st.clone());
        if let Some(f) = &mut one {
            let mut l = lo;
            for (j, o) in pops.iter().enumerate() {
                let mut b = Batch::new(f, Writer::new(ts(t + j as u64), src.clone(), l));
                if b.apply(o, &self.view).is_err() {
                    one = None;
                    break;
                }
                if let Some((d, range)) = b.finish() {
                    l = range.hi;
                    f.join(d);
                }
            }
        }
        let Some((d, range)) = want else {
            if known {
                assert_eq!(items(before), m, "ops writing nothing leave the read: {pops:?}");
            }
            return;
        };
        let cx = DeltaCtx { ts: ts(t), own: src.clone(), range, kind: DeltaKind::Writer };
        let (back, bytes) = wired(&d, &cx);
        // the model writes the same delta for an insert of chars, a delete, a move (§5.7)
        let mut md = None;
        if skew == 0 && self.reps[i].tracked && pops.len() == 1 {
            let ms = self.reps[i].ms.as_ref();
            let mut mw = MWriter::new(self.reps[i].msrc.clone(), t, lo);
            md = match (&pops[0].op, ms) {
                (Op::Insert { at, items: v }, _) if !self.list => Some(mops::seq_insert(&mut mw, ms, true, *at, items(v.first().cloned()).iter().filter_map(|c| if let Value::Str(c) = c { c.chars().next() } else { None }).map(Content::Char).collect())),
                (Op::Delete { at, len }, Some(ms)) => mops::seq_delete(&mut mw, ms, *at, *len),
                (Op::Move { at, len, to }, Some(ms)) => mops::seq_move(&mut mw, ms, *at, *len, *to),
                _ => None,
            };
            if let Some(x) = &md {
                self.stats.model_ops += 1;
                assert!(frag(x) == d, "the model writes the same delta: {pops:?}\n model {:?}\n ours {d:?}", frag(x));
                let mbytes = crdt_model::wire::encode_delta(x, [0; 16], &mut crdt_model::wire::Ctx::new(t, self.reps[i].msrc.clone(), lo));
                assert_eq!(mbytes, bytes, "delta bytes equal the model's");
            }
        }
        self.join_into(i, back.clone(), per);
        let read = self.reps[i].st.read();
        if known {
            assert_eq!(items(read.clone()), m, "ops read like the same ops on a plain sequence: {pops:?}");
        }
        if let Some(f) = one {
            self.stats.one_by_one += 1;
            assert_eq!(f.read(), read, "ops in one commit read like the same ops one by one: {pops:?}");
        }
        // (a list item's field first written in a present item stays: no nested register reset,
        // §4.6 "Absent before")
        let restores = !pops.iter().any(|o| self.list && !matches!(o.op, Op::Insert { .. } | Op::Delete { .. }));
        if skew == 0 {
            self.reps[i].lo = range.hi;
        }
        self.reps[i].stale = before;
        self.stats.commits += 1;
        let c = Commit { d: back, md, by: i, src, range, before: st, restores };
        self.push(i, c, true);
    }

    fn model(&mut self, i: usize, seed: u16) {
        if !self.reps[i].tracked {
            return;
        }
        let t = self.now();
        let rep = &self.reps[i];
        let mut mw = MWriter::new(rep.msrc.clone(), t, rep.lo);
        let Some(md) = random_op(&mut Rng(u64::from(seed) * 2 + 1), &mut mw, &self.ty, rep.ms.as_ref()) else { return };
        let range = CounterRange { lo: rep.lo, hi: mw.hi() };
        let src = source(&rep.msrc);
        let cx = DeltaCtx { ts: ts(t), own: src.clone(), range, kind: DeltaKind::Writer };
        let d = frag(&md);
        let (back, bytes) = wired(&d, &cx);
        let mbytes = crdt_model::wire::encode_delta(&md, [0; 16], &mut crdt_model::wire::Ctx::new(t, rep.msrc.clone(), rep.lo));
        assert_eq!(mbytes, bytes, "delta bytes equal the model's");
        let before = rep.st.clone();
        let stale = before.read();
        self.join_into(i, back.clone(), 0);
        self.stats.model_commits += 1;
        let rep = &mut self.reps[i];
        rep.lo = range.hi;
        rep.stale = stale;
        self.push(i, Commit { d: back, md: Some(md), by: i, src, range, before, restores: false }, true);
    }

    fn undo(&mut self, i: usize, back: u8) {
        let mine: Vec<usize> = (0..self.log.len()).filter(|k| self.log[*k].by == i).collect();
        if mine.is_empty() {
            return;
        }
        let k = mine[mine.len() - 1 - wrap(back.into(), mine.len())];
        let t = self.now();
        let rep = &self.reps[i];
        let c = &self.log[k];
        let u = Undone { delta: &c.d, source: &c.src, range: c.range, restored: &|_| false };
        let src = source(&rep.msrc);
        let mut w = Writer::new(ts(t), src.clone(), rep.lo);
        let full = undo(&mut w, &u, &rep.st, &c.before, &self.view);
        // a node keeps only the footprint of the delta as its undo buffer
        let mut w2 = Writer::new(ts(t), src.clone(), rep.lo);
        let part = undo(&mut w2, &u, &rep.st, &c.before.footprint(&c.d), &self.view);
        assert!(full.as_ref().ok() == part.as_ref().ok() && full.is_ok() == part.is_ok(), "an undo from the footprint equals one from the whole state");
        let Ok(Some(ud)) = full else { return };
        let range = w.range();
        let restore = (rep.last == Some(k) && c.restores).then(|| c.before.read());
        let before = rep.st.clone();
        let stale = before.read();
        let cx = DeltaCtx { ts: ts(t), own: src.clone(), range, kind: DeltaKind::Writer };
        let (back, _) = wired(&ud, &cx);
        self.join_into(i, back.clone(), 0);
        self.stats.undos += 1;
        if let Some(want) = restore {
            self.stats.restores += 1;
            // exact, absence included (§4.6 "Absent before")
            assert_eq!(self.reps[i].st.read(), want, "undoing the last commit restores the read before it");
        }
        let rep = &mut self.reps[i];
        rep.lo = range.hi;
        rep.stale = stale;
        self.push(i, Commit { d: back, md: None, by: i, src, range, before, restores: false }, false);
    }

    /// Every replica joins every commit; all read the same.
    fn converge(&mut self) {
        for i in 0..REPLICAS {
            for k in (0..self.log.len()).rev() {
                if !self.reps[i].seen.contains(&k) {
                    self.deliver(i, k, 0);
                }
            }
        }
        let reads: Vec<Option<Value>> = self.reps.iter().map(|r| r.st.read()).collect();
        assert!(reads.windows(2).all(|w| w[0] == w[1]), "replicas given every commit read the same: {reads:?}");
        // and, never rebooted (a snapshot drops deleted chars), hold the same state
        let whole: Vec<&Fragment> = self.reps.iter().filter(|r| r.whole).map(|r| &r.st).collect();
        assert!(whole.windows(2).all(|w| w[0] == w[1]), "replicas given every commit hold the same state");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §4.5, §4.6, §5.7, §6, §8: random scripts of local ops, model commits, undos, joins in
    /// any order and snapshot bootstraps on three replicas pass every check of `replay`.
    #[test]
    fn random_scripts_replay_spec_5_7() {
        let mut all = Stats::default();
        for seed in 0..24u64 {
            let mut r = crate::testutil::rng(2 * seed + 1);
            let s = random_script(&mut r, 48);
            let x = replay(&s);
            all.commits += x.commits;
            all.partial += x.partial;
            all.one_by_one += x.one_by_one;
            all.model_ops += x.model_ops;
            all.model_commits += x.model_commits;
            all.undos += x.undos;
            all.restores += x.restores;
            all.joins += x.joins;
            all.model_joins += x.model_joins;
            all.merged += x.merged;
        }
        assert!(all.commits > 150 && all.partial > 40 && all.one_by_one > 40 && all.model_ops > 40 && all.model_joins > 8 && all.undos > 10 && all.restores > 2 && all.joins > 300 && all.merged > 20, "{all:?}");
    }

    /// §6.2: a move on a replica holding a broken cycle (shrunk from a random script) re-places
    /// the cycle's elements, so it reads unlike the same move on a plain sequence; it writes the
    /// model's delta and the replica's state stays the model's.
    #[test]
    fn move_beside_broken_cycle_replays_spec_6_2() {
        let s = Script{list:false,steps:vec![Step::Model{r:2,seed:43984,},Step::Ops{r:1,ops:vec![LocalOp::Insert{at:24797,item:28,},],skew:0,per:0,},Step::Model{r:2,seed:34863,},Step::Ops{r:1,ops:vec![LocalOp::Move{at:8501,len:81,to:16916,},],skew:0,per:0,},Step::Model{r:0,seed:4636,},Step::Ops{r:1,ops:vec![LocalOp::Move{at:56715,len:98,to:39210,},],skew:0,per:0,},Step::Ops{r:1,ops:vec![LocalOp::Move{at:25427,len:172,to:49462,},],skew:0,per:0,},Step::Ops{r:2,ops:vec![LocalOp::Delete{at:24211,len:208,},],skew:0,per:0,},Step::Join{to:0,pick:218,n:1,per:0,merged:false,},Step::Ops{r:1,ops:vec![LocalOp::Delete{at:10145,len:211,},],skew:0,per:0,},Step::Ops{r:1,ops:vec![LocalOp::Delete{at:22635,len:234,},],skew:0,per:0,},Step::Ops{r:2,ops:vec![LocalOp::Move{at:22605,len:77,to:30330,},],skew:0,per:0,},Step::Model{r:2,seed:34675,},Step::Ops{r:2,ops:vec![LocalOp::Insert{at:34823,item:116,},],skew:0,per:0,},Step::Join{to:0,pick:63,n:1,per:0,merged:false,},Step::Ops{r:2,ops:vec![LocalOp::Delete{at:34543,len:138,},],skew:0,per:0,},Step::Ops{r:0,ops:vec![LocalOp::Insert{at:48798,item:233,},],skew:0,per:0,},Step::Ops{r:0,ops:vec![LocalOp::Move{at:4606,len:60,to:40670,},],skew:0,per:0,},Step::Ops{r:0,ops:vec![LocalOp::Delete{at:53482,len:91,},],skew:0,per:0,},Step::Ops{r:0,ops:vec![LocalOp::Insert{at:16555,item:19,},],skew:0,per:0,},Step::Join{to:1,pick:251,n:2,per:0,merged:false,},Step::Join{to:0,pick:106,n:4,per:0,merged:false,},Step::Ops{r:2,ops:vec![LocalOp::Delete{at:57007,len:193,},],skew:0,per:0,},Step::Ops{r:0,ops:vec![LocalOp::Insert{at:43702,item:225,},],skew:0,per:0,},Step::Ops{r:1,ops:vec![LocalOp::Move{at:55088,len:176,to:23293,},],skew:0,per:0,},Step::Join{to:0,pick:60,n:4,per:0,merged:false,},Step::Ops{r:0,ops:vec![LocalOp::Move{at:30935,len:99,to:4073,},],skew:0,per:0,},],};
        replay(&s);
    }

    /// Shrinks the failing script of `OSIS_SHRINK=<seed>` (as `random_scripts_replay_spec_5_7`
    /// makes it) by dropping steps and ops while it still panics; prints the result.
    #[test]
    #[ignore]
    fn shrink_script() {
        let Ok(seed) = std::env::var("OSIS_SHRINK") else { return };
        let mut r = crate::testutil::rng(2 * seed.parse::<u64>().unwrap() + 1);
        let mut s = random_script(&mut r, 48);
        let fails = |s: &Script| std::panic::catch_unwind(|| replay(s)).is_err();
        assert!(fails(&s), "does not fail");
        std::panic::set_hook(Box::new(|_| {}));
        loop {
            let mut changed = false;
            for k in (0..s.steps.len()).rev() {
                let mut t = s.clone();
                t.steps.remove(k);
                if fails(&t) {
                    s = t;
                    changed = true;
                    continue;
                }
                // plainer fields
                let mut t = s.clone();
                match &mut t.steps[k] {
                    Step::Ops { skew, per, .. } if *skew > 0 || *per > 0 => (*skew, *per) = (0, 0),
                    Step::Join { per, merged, .. } if *per > 0 || *merged => (*per, *merged) = (0, false),
                    _ => {}
                }
                if format!("{:?}", t.steps[k]) != format!("{:?}", s.steps[k]) && fails(&t) {
                    s = t;
                    changed = true;
                }
                if let Step::Ops { ops, .. } = &s.steps[k] && ops.len() > 1 {
                    for j in (0..ops.len()).rev() {
                        let mut t = s.clone();
                        if let Step::Ops { ops, .. } = &mut t.steps[k] { ops.remove(j); }
                        if fails(&t) {
                            s = t;
                            changed = true;
                            break;
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
        let _ = std::panic::take_hook();
        eprintln!("{s:#?}");
        replay(&s);
    }
}

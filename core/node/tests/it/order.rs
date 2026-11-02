#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Arrival-order differential (spec/requirements.md Decentralization: a node's state and its
//! judgment of every write are functions of the data it holds, never of arrival order;
//! spec/permissions.md §5, §5.2; spec/crdt.md §4.6). Random histories over three writers
//! (grants, demotions with frontiers before, inside and after the demoted writes, re-grants,
//! self-removals, roster and compaction snapshots, things created under things in later
//! commits, writes inside map entries, struct fields and nested texts, undo, expiry (expiring
//! writes and undos), typed and untyped writes, hostile commits (`Step::Forged`), partial
//! syncs) are delivered, as one held set, to fresh nodes in several arrival orders (two of them
//! also with multi-aspect commits split into a part and late parts), syncing things by seed
//! (`with_syncs`): every
//! order must give the same per-delta verdicts, reads and states of every aspect, rosters,
//! pending set, persisted index and timelines, and a reopen and a rebuild must give them too.
//! Short focused histories (bounded writes, compactions, undo, demotions, late writes) are also
//! checked in every arrival order of a few held sets. Seeds run on a thread per core.

use crate::common;
use common::*;
use osis_base::testenv::{caught, par_map, threads};
use osis_base::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_node::engine::{IndexDigest, IndexField};
use osis_node::local_peer::{LocalPeer, Package, Peer};
use osis_perm::DemotionScope;
use osis_schema::{Bound, Codec, PurgeBy, Retention};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

const HOUR: u64 = 3_600_000;

#[derive(Clone)]
pub(crate) struct Rng(pub(crate) u64);
impl Rng {
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n.max(1)
    }
    pub(crate) fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len() as u64) as usize]
    }
}

/// One step of a history. Thing indexes are taken modulo the things made so far (0 is G, owned
/// by peer 0), so any subsequence of a history is a history (shrinking drops steps).
#[derive(Clone, Debug)]
pub(crate) enum Step {
    /// A content write (`op` picks the aspect and shape) by `by` on thing `t`.
    Write { by: usize, t: usize, op: u8, k: u8, v: u8 },
    /// `Write` plus a write of `t:rec.0` under default retention in the same commit: two bodies
    /// when `op` has a keep bound (`random_step` never draws it, so found histories keep).
    Mixed { by: usize, t: usize, op: u8, k: u8, v: u8 },
    /// `holder`'s edge on `t` set to `role` (a grant, re-grant or demotion without frontier).
    Edge { by: usize, t: usize, holder: usize, role: Option<Role> },
    /// `by` grants `holder` `role` on `t` with an `until` (`ms` after the author's clock) and an
    /// invite level: a bare edge write like `Edge`, or with `flow` through `Engine::grant` (its
    /// authority checks, secrets, boxes, rotations). Scripted only (`random_step` never draws
    /// it): a refusal panics. An invite grant needs the flow, which first gives G (derived
    /// secrets in the setup) secrets of its own, about 12 KB.
    Grant { by: usize, t: usize, holder: usize, role: Role, until: Option<u64>, invite: Option<Role>, flow: bool },
    /// An explicit demotion (removal, or to read) with a frontier as of one of the holder's
    /// writes (`at`: 0 before all of them, backdated; the last: now).
    Demote { by: usize, t: usize, holder: usize, at: u8, to_read: bool },
    /// `by` removes its own edge on `t`.
    Leave { by: usize, t: usize },
    /// A roster snapshot of `t`.
    Roster { by: usize, t: usize },
    /// A compaction snapshot of one aspect (`op` as in `Write`).
    Compact { by: usize, t: usize, op: u8 },
    /// A new thing owned by thing `parent`, with a write in its creation commit or not.
    New { by: usize, parent: usize, write: bool },
    /// `by` puts entry `k` (a struct, or a text when `text`) on `t`, sends that commit to
    /// `other` alone, `other` writes inside the entry and, when `compact`, compacts the aspect:
    /// another's write nested under a creation that may be invalid; `also`: the put's commit
    /// writes the register too (two parts, one may arrive late).
    Nested { by: usize, other: usize, t: usize, k: u8, text: bool, compact: bool, also: bool },
    /// `by` undoes one of its last commits.
    Undo { by: usize, back: u8 },
    /// Every commit `from` holds to `to`.
    Sync { from: usize, to: usize },
    /// One of `from`'s last commits to `to`.
    Send { from: usize, to: usize, back: u8 },
    /// Time passes (`who`: one peer's clock, else every one).
    Advance { who: Option<usize>, ms: u64 },
    /// The step, its author and thing first pointed at what it can write at play time (`aim`),
    /// so that most drawn steps make a commit.
    Aim(Box<Step>),
    /// `Write` with the aspect's schema, its sequence offsets fitted to the writer's view
    /// (`fit`). `Write` is untyped: it cannot write sequences or counters and its puts hold a
    /// map encoding beside a field write's struct encoding (a `Slots` position).
    Typed { by: usize, t: usize, op: u8, k: u8, v: u8 },
    /// `Nested` with the schema's struct encoding (`Nested { text: true }` is typed too: an
    /// untyped sequence op is refused).
    NestedItem { by: usize, other: usize, t: usize, k: u8, compact: bool, also: bool },
    /// A commit past the writer's rules (`Engine::commit_hostile`), `how` % 5: a content write on
    /// `a` (for odd `v` acting for `b`); one on each of `a` and `b`; one role commit setting another peer's edge on both; `by`
    /// raising its own edge on `a`; a roster snapshot of `a` holding what the author likes. The
    /// author is told of a thing it does not know first, so it may hold no chain to it.
    Forged { by: usize, a: usize, b: usize, how: u8, op: u8, k: u8, v: u8 },
    /// A commit past the writer's rules with a part that hashes right and is bad by itself, `how` % 4:
    /// a content write on `a` and `b`, `b`'s part not decoding; an edge write on both, `b`'s not
    /// decoding; a roster snapshot of `a`, its ledger not decoding; one with a ledger entry linking a
    /// frontier outside its chunk list.
    BadPart { by: usize, a: usize, b: usize, how: u8 },
    /// `Demote` to no role with a frontier padded past `CHUNK_THRESHOLD`: a roster snapshot of `t`
    /// after it links its frontier.
    BigDemote { by: usize, t: usize, holder: usize },
    // scripted only (`random_step` never draws these), for the judgment vectors:
    /// A new thing owned by peer `by` itself: no edge of G reaches it.
    NewTop { by: usize },
    /// `by` gives thing `holder` (an actor) `role` on `t`.
    EdgeTo { by: usize, t: usize, holder: usize, role: Role },
    /// A bare edge write past the writer's rules (`Engine::commit_hostile`):
    /// `holder`'s edge on `t` set to `role` with `invite`, or removed.
    Hostile { by: usize, t: usize, holder: usize, role: Option<Role>, invite: Option<Role> },
    /// `by` removes `holder`'s edge on `t` through `Engine::demote` (a removal of an absent edge
    /// writes through it alone), its frontier as of before the history: covering nothing.
    Removal { by: usize, t: usize, holder: usize },
    /// A roster snapshot of `t` by `by` holding exactly `keep`, whatever the timeline says.
    HostileRoster { by: usize, t: usize, keep: Vec<(usize, Role)> },
    /// A register write on `t`, unchecked.
    HostileWrite { by: usize, t: usize, v: u8 },
    /// One content commit of a register write on each of things `a` and `b`, unchecked.
    Two { by: usize, a: usize, b: usize, v: u8 },
    /// `Two` on three things.
    Three { by: usize, a: usize, b: usize, c: usize, v: u8 },
    /// One role commit setting `holder`'s edge on both things `a` and `b`, unchecked.
    TwoEdges { by: usize, a: usize, b: usize, holder: usize, role: Role },
    /// `by` puts `item("v1", 1)` at key `k` of `t:map.0`, sends that commit to `other` alone,
    /// which sets the entry's field 1 to 7 and compacts. `Nested` writes untyped, so its entries
    /// hold a map encoding where a field write holds a struct's.
    NestedTyped { by: usize, other: usize, t: usize, k: u8 },
    /// `by` sets field 1 of entry `k` of `t:map.0` to `v`.
    TypedField { by: usize, t: usize, k: u8, v: u8 },
    /// A write with a paged delta (spec/crdt.md §8).
    Paged { by: usize, t: usize },
    /// A write of a large atomic value (spec/data-model.md §6).
    Large { by: usize, t: usize },
    /// A removal of `holder` on `t` with its frontier as of now, padded past `CHUNK_THRESHOLD`
    /// with things nobody holds, so it goes by link.
    LinkedDemote { by: usize, t: usize, holder: usize },
}

const OPS: u8 = 30;

fn aspect_of(op: u8) -> Ak {
    ak(match op % OPS {
        0 => "t:reg.0",
        1 | 2 => "t:tags.0",
        3..=5 => "t:map.0",
        6 | 7 => "t:book.0",
        8 | 9 => "t:docs.0",
        10 | 11 => "t:text.0",
        12 => "t:brief.0",
        13 => "t:count.0",
        14 => "t:list.0",
        15 => "t:rec.0",
        // with a keep bound (deaths count only there): registers, a map under keep at most 0
        // (bodies drop as they die), a kept set, kept writes into a map (nested, removals), a
        // kept text, a kept text in a map entry
        16 => "t:kept.0",
        17 => "t:short.0",
        18 => "t:gone.0",
        19 | 20 => "t:gonemap.0",
        21 => "t:keptset.0",
        22 | 25 => "t:map.0",
        23 | 24 => "t:text.0",
        // expiring twins (`expiry_of`) of a register set, a map put and a text insert
        27 => "t:reg.0",
        28 => "t:map.0",
        29 => "t:text.0",
        _ => "t:docs.0",
    })
}

/// The retention of `op`'s writes when not the default: keep at least 30 min, or at most 30
/// min or 0.
fn keep_of(op: u8) -> Option<Retention> {
    let d = Some(HOUR / 2);
    let at_least = Some(Retention { by: PurgeBy::AuthorOrAdmin, at_least: Bound { abs: None, rel: d }, at_most: Bound::default() });
    // an author-only class among them: an admin's compaction drops none of another's bodies
    let author = Some(Retention { by: PurgeBy::Author, at_least: Bound { abs: None, rel: d }, at_most: Bound::default() });
    let at_most = |rel| Some(Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs: None, rel: Some(rel) } });
    match op % OPS {
        16 | 21..=23 => at_least,
        24..=26 => author,
        17 => at_most(HOUR / 2),
        18..=20 => at_most(0),
        _ => None,
    }
}

/// The expiry of `op`'s writes after their commit's wall time, if any (spec/crdt.md §4.7): a
/// second (a peer's own clock steps pass it) or half an hour (a global advance does). With
/// `k` 2 the commit also writes `t:rec.0`, without expiry: two parts, so split delivery makes
/// the expiring one a late part, maybe arriving after T.
fn expiry_of(op: u8, v: u8) -> Option<u64> {
    (27..=29).contains(&(op % OPS)).then_some(if v.is_multiple_of(2) { 1_000 } else { HOUR / 2 })
}

/// The op of a `Write`: k and v from small domains, so writers collide.
fn content_op(op: u8, k: u8, v: u8) -> (Ak, PathOp) {
    let key = |k: u8| PathSeg::Key(s(&format!("k{}", k % 3)));
    let val = format!("v{v}");
    let at = (v % 3) as usize;
    let po = match op % OPS {
        0 => PathOp { path: vec![], op: Op::Set(s(&val)) },
        1 => PathOp { path: vec![], op: Op::Add(s(&format!("t{}", v % 4))) },
        2 => PathOp { path: vec![], op: Op::Remove(s(&format!("t{}", v % 4))) },
        3 => PathOp { path: vec![key(k)], op: Op::Set(item(&val, v as i64)) },
        // a write inside an entry, maybe another writer's
        4 => PathOp { path: vec![key(k), PathSeg::Field(1)], op: Op::Set(Value::Int(v as i64)) },
        5 => PathOp { path: vec![], op: Op::Remove(s(&format!("k{}", k % 3))) },
        6 => PathOp { path: vec![PathSeg::Field(0), key(k)], op: Op::Set(s(&val)) },
        7 => PathOp { path: vec![PathSeg::Field(1)], op: Op::Set(s(&val)) },
        // a text inside a map entry
        8 => PathOp { path: vec![key(k)], op: Op::Insert { at: 0, items: vec![s(&val)] } },
        9 => PathOp { path: vec![key(k)], op: Op::Delete { at, len: 1 } },
        10 => PathOp { path: vec![], op: Op::Insert { at, items: vec![s(&val)] } },
        11 => PathOp { path: vec![], op: Op::Delete { at, len: 2 } },
        12 => PathOp { path: vec![], op: Op::Set(s(&val)) },
        13 => PathOp { path: vec![], op: Op::Inc(Value::Int(1 + v as i64)) },
        14 => PathOp { path: vec![], op: Op::Insert { at, items: vec![s(&val)] } },
        15 => PathOp { path: vec![PathSeg::Field(0)], op: Op::Set(s(&val)) },
        19 => PathOp { path: vec![key(k)], op: Op::Set(s(&val)) },
        20 => PathOp { path: vec![], op: Op::Remove(s(&format!("k{}", k % 3))) },
        21 if v.is_multiple_of(2) => PathOp { path: vec![], op: Op::Add(s(&format!("t{}", k % 3))) },
        21 => PathOp { path: vec![], op: Op::Remove(s(&format!("t{}", k % 3))) },
        22 => PathOp { path: vec![key(k), PathSeg::Field(1)], op: Op::Set(Value::Int(v as i64)) },
        // kept twins of text inserts and deletes, map removals, text in a map entry
        23..=26 => return content_op([10, 11, 5, 8][(op % OPS - 23) as usize], k, v),
        27..=29 => return content_op([0, 3, 10][(op % OPS - 27) as usize], k, v),
        _ => PathOp { path: vec![], op: Op::Set(s(&val)) },
    };
    (aspect_of(op), po)
}

/// The ops an untyped `Write` can write: no sequences, counters or removals.
const UNTYPED: [u8; 14] = [0, 1, 3, 4, 6, 7, 15, 16, 17, 18, 19, 22, 27, 28];

/// The schema's key of `op`'s aspect.
fn key_of(op: u8) -> &'static osis_schema::Aspect<Value> {
    match aspect_of(op).as_str() {
        "t:reg.0" => &REG,
        "t:tags.0" => &TAGS,
        "t:map.0" => &MAP,
        "t:book.0" => &BOOK,
        "t:docs.0" => &DOCS,
        "t:text.0" => &TEXT,
        "t:brief.0" => &BRIEF,
        "t:count.0" => &COUNT,
        "t:list.0" => &LIST,
        "t:rec.0" => &REC,
        "t:kept.0" => &KEPT,
        "t:short.0" => &SHORT,
        "t:gone.0" => &GONE,
        "t:gonemap.0" => &GONEMAP,
        "t:keptset.0" => &KEPTSET,
        a => panic!("no key for {a}"),
    }
}

/// `po` made to fit `by`'s view of the aspect: sequence offsets within it (a delete of an empty
/// sequence inserts), a write inside an absent map entry the whole entry.
fn fit(e: &mut osis_node::Engine, t: Tid, a: &Ak, mut po: PathOp) -> PathOp {
    let top = e.get(&t, a).ok().flatten();
    let mut at = top.as_ref();
    let mut entry = true;
    for seg in &po.path {
        let k = match seg {
            PathSeg::Key(k) => k.clone(),
            PathSeg::Field(i) => Value::Int(*i as i64),
            _ => return po,
        };
        at = match at {
            Some(Value::Map(m)) => m.get(&k),
            _ => None,
        };
        entry &= at.is_some() || matches!(seg, PathSeg::Field(_));
    }
    let len = match at {
        Some(Value::Str(x)) => x.chars().count(),
        Some(Value::List(x)) => x.len(),
        _ => 0,
    };
    match &mut po.op {
        Op::Insert { at, .. } => *at = (*at).min(len),
        Op::Delete { .. } if len == 0 => po.op = Op::Insert { at: 0, items: vec![s("x")] },
        Op::Delete { at, len: n } => {
            *at = (*at).min(len - 1);
            *n = (*n).min(len - *at);
        }
        Op::Set(_) if a.as_str() == "t:map.0" && po.path.len() == 2 && !entry => {
            po.path.truncate(1);
            po.op = Op::Set(item("whole", 1));
        }
        _ => {}
    }
    po
}

/// Points an aimed step's author and things at ones that can write it as far as that peer can
/// tell, `t` choosing among them; an author none of which can stays as it is (and is refused).
fn aim(st: &Step, lp: &mut LocalPeer, things: &[Tid], ids: &[Tid], own: &[Vec<CommitId>]) -> Step {
    use Step::*;
    let want = |r: Role| move |lp: &LocalPeer, by: usize, t: &Tid| lp.peers[by].engine.knows(t) && lp.peers[by].engine.role_on(t) >= Some(r);
    // the first of the authors from `by` on with such a thing, and which of its things
    let pick = |lp: &LocalPeer, by: usize, t: usize, ok: &dyn Fn(&LocalPeer, usize, &Tid) -> bool| -> Option<(usize, usize)> {
        (0..3).map(|i| (by + i) % 3).find_map(|b| {
            let c: Vec<usize> = (0..things.len()).filter(|i| ok(lp, b, &things[*i])).collect();
            (!c.is_empty()).then(|| (b, c[t % c.len()]))
        })
    };
    // what each peer holds, for a compaction
    let holding: Vec<BTreeSet<(Tid, Ak)>> = if matches!(st, Compact { .. }) { lp.peers.iter_mut().map(|p| p.engine.all_aspects().unwrap().into_iter().collect()).collect() } else { Vec::new() };
    let lp = &*lp;
    let write = want(Role::Write);
    let admin = want(Role::Admin);
    let aimed = match st.clone() {
        Write { by, t, op, k, v } => pick(lp, by, t, &write).map(|(by, t)| Write { by, t, op, k, v }),
        Typed { by, t, op, k, v } => pick(lp, by, t, &write).map(|(by, t)| Typed { by, t, op, k, v }),
        Edge { by, t, holder, role } => {
            let held = |lp: &LocalPeer, b: usize, x: &Tid| admin(lp, b, x) && (role.is_some() || lp.peers[b].engine.roster(x).contains_key(&ids[holder]));
            pick(lp, by, t, &held).map(|(by, t)| Edge { by, t, holder, role })
        }
        Demote { by, t, holder, at, to_read } => {
            let above = |lp: &LocalPeer, b: usize, x: &Tid| admin(lp, b, x) && lp.peers[b].engine.roster(x).get(&ids[holder]).is_some_and(|e| !to_read || e.role > Role::Read);
            pick(lp, by, t, &above).map(|(by, t)| Demote { by, t, holder, at, to_read })
        }
        Leave { by, t } => pick(lp, by, t, &|lp, b, x| lp.peers[b].engine.roster(x).contains_key(&ids[b])).map(|(by, t)| Leave { by, t }),
        Roster { by, t } => pick(lp, by, t, &admin).map(|(by, t)| Roster { by, t }),
        Compact { by, t, op } => {
            // an op of an aspect the author holds
            let holds = |lp: &LocalPeer, b: usize, x: &Tid| write(lp, b, x) && holding[b].contains(&(*x, aspect_of(op)));
            pick(lp, by, t, &holds).map(|(by, t)| Compact { by, t, op })
        }
        New { by, parent, write: w } => pick(lp, by, parent, &write).map(|(by, parent)| New { by, parent, write: w }),
        Nested { by, other, t, k, text, compact, also } => pick(lp, by, t, &|lp, b, x| write(lp, b, x) && write(lp, other, x)).filter(|x| x.0 != other).map(|(by, t)| Nested { by, other, t, k, text, compact, also }),
        NestedItem { by, other, t, k, compact, also } => pick(lp, by, t, &|lp, b, x| write(lp, b, x) && write(lp, other, x)).filter(|x| x.0 != other).map(|(by, t)| NestedItem { by, other, t, k, compact, also }),
        Undo { by, back } => {
            // one of the author's last content commits
            let content: Vec<usize> = own[by].iter().enumerate().filter(|(_, id)| lp.peers[by].engine.header(id).is_some_and(|h| h.kind == osis_commit::Kind::Content)).map(|(i, _)| i).collect();
            content.iter().rev().nth(back as usize % content.len().max(1)).map(|i| Undo { by, back: (own[by].len() - 1 - i).min(255) as u8 })
        }
        _ => None,
    };
    aimed.unwrap_or_else(|| st.clone())
}

fn random_step(rng: &mut Rng) -> Step {
    let by = rng.below(3) as usize;
    let t = rng.below(8) as usize;
    let aim = |x: Step| Step::Aim(Box::new(x));
    match rng.below(46) {
        0..=7 => aim(Step::Typed { by, t, op: rng.below(OPS as u64) as u8, k: rng.below(3) as u8, v: rng.below(10) as u8 }),
        8..=10 => aim(Step::Write { by, t, op: rng.pick(&UNTYPED), k: rng.below(3) as u8, v: rng.below(10) as u8 }),
        40 | 41 => {
            let other = (by + 1 + rng.below(2) as usize) % 3;
            aim(Step::NestedItem { by, other, t, k: rng.below(3) as u8, compact: rng.below(3) != 0, also: rng.below(2) == 0 })
        }
        42..=44 => Step::Forged { by, a: t, b: rng.below(8) as usize, how: rng.below(5) as u8, op: rng.below(OPS as u64) as u8, k: rng.below(3) as u8, v: rng.below(10) as u8 },
        45 => Step::NewTop { by },
        11..=13 => aim(Step::Edge { by: rng.pick(&[0, 0, 2]), t, holder: rng.pick(&[1, 2]), role: rng.pick(&[None, Some(Role::Read), Some(Role::Write), Some(Role::Write), Some(Role::Admin)]) }),
        14..=17 => aim(Step::Demote { by: rng.pick(&[0, 0, 2]), t, holder: rng.pick(&[1, 2]), at: rng.below(6) as u8, to_read: rng.below(3) == 0 }),
        18 => aim(Step::Leave { by: rng.pick(&[1, 2]), t }),
        19 => aim(Step::Roster { by: rng.pick(&[0, 0, 2]), t }),
        20..=22 => aim(Step::Compact { by, t, op: rng.below(OPS as u64) as u8 }),
        23 | 24 => aim(Step::New { by: rng.pick(&[0, 0, 2]), parent: t, write: rng.below(2) == 0 }),
        25..=28 => {
            let other = (by + 1 + rng.below(2) as usize) % 3;
            // one draw: `compact` as before `also` (x % 6 % 3 == x % 3)
            let (k, text, c) = (rng.below(3) as u8, rng.below(2) == 0, rng.below(6));
            aim(Step::Nested { by, other, t, k, text, compact: c % 3 != 0, also: c >= 3 })
        }
        29 => aim(Step::Undo { by, back: rng.below(3) as u8 }),
        30..=32 => {
            let from = rng.below(3) as usize;
            Step::Sync { from, to: (from + 1 + rng.below(2) as usize) % 3 }
        }
        33..=36 => {
            let from = rng.below(3) as usize;
            Step::Send { from, to: (from + 1 + rng.below(2) as usize) % 3, back: rng.below(3) as u8 }
        }
        37 => Step::Advance { who: None, ms: HOUR + rng.below(HOUR) },
        _ => Step::Advance { who: Some(rng.below(3) as usize), ms: 1 + rng.below(2_000) },
    }
}

/// Puts `po` on `op`'s aspect of `t`, typed (fitted to the author's view) or not.
fn op_on(m: &mut Mutation, e: &mut osis_node::Engine, t: Tid, op: u8, po: PathOp, typed: bool) {
    if typed {
        let po = fit(e, t, &aspect_of(op), po);
        m.op(t, key_of(op), po).unwrap();
    } else {
        m.op(t, &aspect_of(op), po).unwrap();
    }
}

/// `op`'s write on `t` (`Write`), with its retention, expiry and second aspect.
fn write_op(m: &mut Mutation, e: &mut osis_node::Engine, t: Tid, op: u8, k: u8, v: u8, typed: bool) {
    let a = aspect_of(op);
    if let Some(r) = keep_of(op) {
        m.retention(t, &a, r).unwrap();
    }
    if let Some(ms) = expiry_of(op, v) {
        m.expires(t, &a, WallMs(e.now().0 + ms)).unwrap();
        if k == 2 {
            op_on(m, e, t, 15, content_op(15, k, v).1, typed);
        }
    }
    op_on(m, e, t, op, content_op(op, k, v).1, typed);
}

/// `holder`'s edge on `t` as remove + put (`None`: removed), spec/permissions.md §2.
fn edge_write(t: Tid, holder: Tid, e: Option<osis_schema::core_types::Edge>) -> Mutation {
    let mut m = Mutation::new();
    m.op(t, &osis_schema::core_types::ROLES, PathOp { path: vec![], op: Op::Remove(Value::Tid(holder)) }).unwrap();
    if let Some(e) = e {
        m.op(t, &osis_schema::core_types::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(e.to_value()) }).unwrap();
    }
    m
}

/// A history as played: every commit made, in the order made, and the things.
#[derive(Clone)]
pub(crate) struct Played {
    pub(crate) packs: Vec<Package>,
    /// Each commit's author peer (3: none of the three).
    authors: Vec<usize>,
    /// How many of `packs` are the setup (identities, G, the first grants).
    pub(crate) base: usize,
    pub(crate) things: Vec<Tid>,
    pub(crate) now: WallMs,
    /// What each step made.
    tally: Tally,
    /// What the fresh nodes sync (`Syncs`).
    sync: Syncs,
}

/// Per step kind: how many ran and how many made a commit, and why the others made none.
#[derive(Clone, Debug, Default)]
struct Tally {
    kinds: BTreeMap<String, (u64, u64)>,
    refused: BTreeMap<(String, String), u64>,
    commits: u64,
}

impl Tally {
    fn add(&mut self, o: &Tally) {
        for (k, v) in &o.kinds {
            let e = self.kinds.entry(k.clone()).or_default();
            e.0 += v.0;
            e.1 += v.1;
        }
        for (k, v) in &o.refused {
            *self.refused.entry(k.clone()).or_default() += v;
        }
        self.commits += o.commits;
    }

    /// Runs and commit-making runs, over every kind that should commit.
    fn totals(&self) -> (u64, u64) {
        self.kinds.values().fold((0, 0), |a, v| (a.0 + v.0, a.1 + v.1))
    }

    fn show(&self) -> String {
        let (n, m) = self.totals();
        let mut out = format!("{m} of {n} commit steps made commits ({} no commit), {} commits", pct(n - m, n), self.commits);
        for (k, v) in &self.kinds {
            let _ = write!(out, "\n  {k}: {} of {} none", v.0 - v.1, v.0);
            for ((_, why), c) in self.refused.iter().filter(|x| x.0.0 == *k) {
                let _ = write!(out, ", {why} {c}");
            }
        }
        out
    }
}

fn pct(x: u64, of: u64) -> String {
    format!("{:.0}%", 100.0 * x as f64 / of.max(1) as f64)
}

/// A refusal's name, for `Tally`: the error up to its fields, with its message if it has one.
fn why<T, E: std::fmt::Debug>(r: &Result<T, E>) -> Option<String> {
    r.as_ref().err().map(|e| {
        let e = format!("{e:?}");
        let name = e.split(|c: char| !c.is_alphanumeric()).next().unwrap_or("");
        match e.split('"').nth(1) {
            Some(msg) => format!("{name}({msg})"),
            None => name.to_string(),
        }
    })
}

/// Plays `steps` on three peers: 0 owns G and gives 1 write and 2 admin on it.
pub(crate) fn play(seed: u64, steps: &[Step]) -> Played {
    let mut lp = LocalPeer::new(3, seed, T0).unwrap();
    lp.sync_all().unwrap();
    let ids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.tid()).collect();
    let mut m = Mutation::new();
    let g = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    m.set(g, &REG, &s("g")).unwrap();
    lp.peers[0].commit(m).unwrap();
    set_edge(&mut lp.peers[0].engine, g, ids[1], Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, g, ids[2], Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    let mut seen: BTreeSet<CommitId> = BTreeSet::new();
    let mut packs = Vec::new();
    let mut authors = Vec::new();
    let mut own: Vec<Vec<CommitId>> = vec![Vec::new(); 3];
    // collects the commits peer `i` made since the last call
    let collect = |lp: &mut LocalPeer, i: usize, seen: &mut BTreeSet<CommitId>, packs: &mut Vec<Package>, authors: &mut Vec<usize>, own: &mut Vec<Vec<CommitId>>| {
        for id in lp.peers[i].engine.commit_ids() {
            if seen.insert(id) {
                packs.push(lp.peers[i].engine.package(&id).unwrap().unwrap());
                let by = lp.peers[i].engine.header(&id).map(|h| h.author);
                authors.push(ids.iter().position(|x| Some(*x) == by).unwrap_or(3));
                if by == Some(ids[i]) {
                    own[i].push(id);
                }
            }
        }
    };
    for i in 0..3 {
        collect(&mut lp, i, &mut seen, &mut packs, &mut authors, &mut own);
    }
    let base = packs.len();
    let mut things = vec![g];
    let mut parent: BTreeMap<Tid, Tid> = BTreeMap::new();
    // wall times of each peer's commits (frontier points)
    let mut marks: Vec<Vec<WallMs>> = vec![Vec::new(); 3];
    let mut tally = Tally::default();
    // each made thing's creating commit (`Forged` tells of it)
    let mut made_by: BTreeMap<Tid, (usize, CommitId)> = BTreeMap::new();
    // the blobs of `BadPart`, with what their authors' own copies dropped
    let mut forged: BTreeMap<CommitId, Vec<u8>> = BTreeMap::new();
    for st in steps {
        let aimed;
        let st = match st {
            Step::Aim(x) => {
                aimed = aim(x, &mut lp, &things, &ids, &own);
                &aimed
            }
            x => x,
        };
        let before = packs.len();
        // typed twins play in the arm of the untyped step
        let (typed, st_) = match st.clone() {
            Step::Typed { by, t, op, k, v } => (true, Step::Write { by, t, op, k, v }),
            Step::NestedItem { by, other, t, k, compact, also } => (true, Step::Nested { by, other, t, k, text: false, compact, also }),
            x => (matches!(x, Step::Nested { text: true, .. }), x),
        };
        let th = |t: usize| things[t % things.len()];
        // why this step made no commit, when refused
        let mut no: Option<String> = None;
        let acted = match st_ {
            Step::Aim(_) | Step::Typed { .. } | Step::NestedItem { .. } => unreachable!("aimed and twinned above"),
            Step::Write { by, t, op, k, v } => {
                let mut m = Mutation::new();
                write_op(&mut m, &mut lp.peers[by].engine, th(t), op, k, v, typed);
                let r = lp.peers[by].commit(m);
                no = why(&r);
                if r.is_ok_and(|x| x.is_some()) {
                    marks[by].push(lp.peers[by].engine.now());
                }
                Some(by)
            }
            Step::Mixed { by, t, op, k, v } => {
                let (a, po) = content_op(op, k, v);
                let (a2, po2) = content_op(15, k, v);
                let mut m = Mutation::new();
                if let Some(r) = keep_of(op) {
                    let _ = m.retention(th(t), &a, r);
                }
                let _ = m.op(th(t), &a2, po2);
                if m.op(th(t), &a, po).is_ok() && lp.peers[by].commit(m).is_ok_and(|x| x.is_some()) {
                    marks[by].push(lp.peers[by].engine.now());
                }
                Some(by)
            }
            Step::Edge { by, t, holder, role } => {
                no = why(&lp.peers[by].commit(edge_write(th(t), ids[holder], role.map(edge))));
                Some(by)
            }
            Step::Grant { by, t, holder, role, until, invite, flow } => {
                let e = osis_schema::core_types::Edge { until: until.map(|ms| WallMs(lp.peers[by].engine.now().0 + ms)), invite, ..edge(role) };
                if flow {
                    lp.peers[by].engine.grant(&th(t), &ids[holder], &e).unwrap();
                } else {
                    lp.peers[by].commit(edge_write(th(t), ids[holder], Some(e))).unwrap().expect("a grant writes");
                }
                Some(by)
            }
            Step::Demote { by, t, holder, at, to_read } => {
                let t = th(t);
                let mut below = BTreeSet::from([t]);
                loop {
                    let more: Vec<Tid> = parent.iter().filter(|(c, p)| below.contains(p) && !below.contains(c)).map(|(c, _)| *c).collect();
                    if more.is_empty() {
                        break;
                    }
                    below.extend(more);
                }
                let ms = &marks[holder];
                let as_of = match (at as usize).checked_sub(1) {
                    None => WallMs(ms.first().map_or(T0.0, |x| x.0 - 1)),
                    Some(i) => ms.get(i).copied().unwrap_or_else(|| lp.peers[by].engine.now()),
                };
                let scope = DemotionScope { roles: BTreeMap::from([(ids[holder], BTreeSet::from([t]))]), content: BTreeMap::from([(ids[holder], below)]) };
                let f = lp.peers[by].engine.frontier(&scope, as_of);
                no = why(&f);
                if let Ok(f) = f {
                    let mut m = edge_write(t, ids[holder], to_read.then_some(edge(Role::Read)));
                    m.frontier(f.to_value());
                    no = why(&lp.peers[by].commit(m));
                }
                Some(by)
            }
            Step::Leave { by, t } => {
                let d = osis_node::flows::Demotion { holder: ids[by], new: None, presync: osis_node::flows::PreSync::Backdated(T0) };
                no = why(&lp.peers[by].engine.demote(&th(t), &d));
                Some(by)
            }
            Step::Roster { by, t } => {
                no = why(&lp.peers[by].engine.roster_snapshot(&th(t), None));
                Some(by)
            }
            Step::Compact { by, t, op } => {
                no = why(&lp.peers[by].engine.snapshot(&th(t), &aspect_of(op)));
                Some(by)
            }
            Step::New { by, parent: p, write } => {
                let owner = th(p);
                let mut m = Mutation::new();
                let t = lp.peers[by].engine.new_thing(&mut m, owner);
                if write {
                    m.set(t, &REG, &s("n")).unwrap();
                }
                let r = lp.peers[by].commit(m);
                no = why(&r);
                if let Ok(Some(id)) = r {
                    things.push(t);
                    parent.insert(t, owner);
                    made_by.insert(t, (by, id));
                }
                Some(by)
            }
            Step::Nested { by, other, t, k, text, compact, also } => {
                let (put, inner) = if text { (8, 8) } else { (3, 4) };
                let a = aspect_of(put);
                let mut m = Mutation::new();
                if also {
                    let _ = m.set(th(t), &REG, &s("also"));
                }
                op_on(&mut m, &mut lp.peers[by].engine, th(t), put, content_op(put, k, 1).1, typed);
                let r = lp.peers[by].commit(m);
                no = why(&r);
                if let Ok(Some(id)) = r {
                    marks[by].push(lp.peers[by].engine.now());
                    let pk = lp.peers[by].engine.package(&id).unwrap().unwrap();
                    lp.deliver(other, &pk).unwrap();
                    lp.peers[other].clock.advance(1);
                    let mut m = Mutation::new();
                    op_on(&mut m, &mut lp.peers[other].engine, th(t), inner, content_op(inner, k, 7).1, typed);
                    if lp.peers[other].commit(m).is_ok_and(|x| x.is_some()) {
                        marks[other].push(lp.peers[other].engine.now());
                    }
                    if compact {
                        lp.peers[other].clock.advance(1);
                        let _ = lp.peers[other].engine.snapshot(&th(t), &a);
                    }
                }
                collect(&mut lp, by, &mut seen, &mut packs, &mut authors, &mut own);
                Some(other)
            }
            Step::Undo { by, back } => {
                let n = own[by].len();
                if let Some(id) = n.checked_sub(1 + back as usize).and_then(|i| own[by].get(i)).copied() {
                    no = why(&lp.peers[by].engine.revert(&id));
                }
                Some(by)
            }
            Step::Sync { from, to } => {
                lp.sync(from, to).unwrap();
                None
            }
            Step::Send { from, to, back } => {
                let n = own[from].len();
                if let Some(id) = n.checked_sub(1 + back as usize).and_then(|i| own[from].get(i)).copied()
                    && let Some(pk) = lp.peers[from].engine.package(&id).unwrap()
                {
                    lp.deliver(to, &pk).unwrap();
                }
                None
            }
            Step::Forged { by, a, b, how, op, k, v } => {
                let (a, b) = (th(a), th(b));
                for x in [a, b] {
                    if !lp.peers[by].engine.knows(&x)
                        && let Some((from, id)) = made_by.get(&x)
                        && let Some(pk) = lp.peers[*from].engine.package(id).unwrap()
                    {
                        let _ = lp.deliver(by, &pk);
                    }
                }
                let other = ids[(by + 1 + v as usize % 2) % 3];
                let mut m = Mutation::new();
                let edge_on = |m: &mut Mutation, t: Tid, holder: Tid, e: osis_schema::core_types::Edge| {
                    m.op(t, &osis_schema::core_types::ROLES, PathOp { path: vec![], op: Op::Remove(Value::Tid(holder)) }).unwrap();
                    m.op(t, &osis_schema::core_types::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(e.to_value()) }).unwrap();
                };
                match how % 5 {
                    // half of them acting for thing `b` (spec/permissions.md §5.2, Acting): valid
                    // only while `by` holds write on it
                    0 => {
                        write_op(&mut m, &mut lp.peers[by].engine, a, op, k, v, true);
                        if v % 2 == 1 {
                            m.act_as(b);
                        }
                    }
                    1 => {
                        write_op(&mut m, &mut lp.peers[by].engine, a, op, k, v, true);
                        write_op(&mut m, &mut lp.peers[by].engine, b, op / 2, k, v, true);
                    }
                    2 => {
                        edge_on(&mut m, a, other, edge(Role::Write));
                        edge_on(&mut m, b, other, edge(Role::Write));
                    }
                    3 => edge_on(&mut m, a, ids[by], osis_schema::core_types::Edge { invite: (v % 2 == 0).then_some(Role::Admin), ..edge(Role::Admin) }),
                    _ => {
                        let roster: osis_schema::core_types::Holders = [(ids[by], edge(Role::Admin)), (other, edge(Role::Write))].into_iter().take(1 + v as usize % 2).collect();
                        m.replace(a, &osis_schema::core_types::ROLES, &roster).unwrap();
                        m.replace(a, &osis_schema::core_types::TENURES, &osis_schema::core_types::Tenures(Vec::new())).unwrap();
                        m.roster_for_tests();
                    }
                }
                no = why(&lp.peers[by].engine.commit_hostile(m));
                Some(by)
            }
            Step::BadPart { by, a, b, how } => {
                let (a, b) = (th(a), th(b));
                for x in [a, b] {
                    if !lp.peers[by].engine.knows(&x)
                        && let Some((from, id)) = made_by.get(&x)
                        && let Some(pk) = lp.peers[*from].engine.package(id).unwrap()
                    {
                        let _ = lp.deliver(by, &pk);
                    }
                }
                let other = ids[(by + 1) % 3];
                let mut m = Mutation::new();
                let roles = osis_schema::core_types::ROLES;
                let tenures = osis_schema::core_types::TENURES;
                let mut bad = BTreeSet::new();
                let roster = |m: &mut Mutation, ledger: osis_schema::core_types::Tenures| {
                    let holders: osis_schema::core_types::Holders = [(ids[by], edge(Role::Admin))].into_iter().collect();
                    m.replace(a, &roles, &holders).unwrap();
                    m.replace(a, &tenures, &ledger).unwrap();
                    m.roster_for_tests();
                };
                let at = osis_schema::core_types::EdgeKey { ts: osis_base::Ts::make(T0, 0).unwrap(), node: other, commit: CommitId([0; 32]) };
                match how % 4 {
                    0 => {
                        m.set(a, &REG, &s("beside bad")).unwrap();
                        m.set(b, &REG, &s("bad")).unwrap();
                        bad.insert((b, Ak::new("t:reg.0").unwrap()));
                    }
                    1 => {
                        for x in [a, b] {
                            m.op(x, &roles, PathOp { path: vec![PathSeg::Key(Value::Tid(other))], op: Op::Set(edge(Role::Write).to_value()) }).unwrap();
                        }
                        bad.insert((b, Ak::new("roles.0").unwrap()));
                    }
                    2 => {
                        roster(&mut m, osis_schema::core_types::Tenures(vec![osis_schema::core_types::Tenure { holder: other, role: Role::Write, since: None, until: at, frontier: None }]));
                        bad.insert((a, Ak::new("tenures.0").unwrap()));
                    }
                    _ => {
                        let fake = osis_base::Link { hash: [3; 32], blob: osis_base::BlobId([4; 32]), suite: 1, key: [5; 32] };
                        let f = osis_schema::Chunked::Link(fake);
                        roster(&mut m, osis_schema::core_types::Tenures(vec![osis_schema::core_types::Tenure { holder: other, role: Role::Write, since: None, until: at, frontier: Some(f) }]));
                        // a part that decodes: `commit_forged` needs some aspect to keep the blob
                        bad.insert((Tid::from_bytes([0; 15]), Ak::new("roles.0").unwrap()));
                    }
                }
                match lp.peers[by].engine.commit_forged(m, bad) {
                    Ok(Some((id, bytes))) => {
                        forged.insert(id, bytes);
                    }
                    Ok(None) => {}
                    Err(e) => no = why(&Err::<(), _>(e)),
                }
                Some(by)
            }
            Step::BigDemote { by, t, holder } => {
                let t = th(t);
                let now = lp.peers[by].engine.now();
                let scope = DemotionScope { roles: BTreeMap::from([(ids[holder], BTreeSet::from([t]))]), content: BTreeMap::from([(ids[holder], BTreeSet::from([t]))]) };
                let f = lp.peers[by].engine.frontier(&scope, now);
                no = why(&f);
                if let Ok(mut f) = f {
                    for i in 0..4000u32 {
                        let b = i.to_be_bytes();
                        let mut c = [7u8; 32];
                        c[..4].copy_from_slice(&b);
                        f.commits.insert(CommitId(c));
                    }
                    let mut m = edge_write(t, ids[holder], None);
                    m.frontier(f.to_value());
                    no = why(&lp.peers[by].commit(m));
                }
                Some(by)
            }
            Step::Advance { who, ms } => {
                match who {
                    Some(i) => lp.peers[i].clock.advance(ms),
                    None => lp.advance(ms),
                }
                None
            }
            Step::NewTop { by } => {
                let mut m = Mutation::new();
                let t = lp.peers[by].engine.new_thing(&mut m, ids[by]);
                m.set(t, &REG, &s("top")).unwrap();
                let id = lp.peers[by].commit(m).unwrap().expect("a creation writes");
                things.push(t);
                made_by.insert(t, (by, id));
                Some(by)
            }
            Step::EdgeTo { by, t, holder, role } => {
                let holder = th(holder);
                lp.peers[by].commit(edge_write(th(t), holder, Some(edge(role)))).unwrap().expect("a grant writes");
                Some(by)
            }
            Step::Hostile { by, t, holder, role, invite } => {
                let m = edge_write(th(t), ids[holder], role.map(|r| osis_schema::core_types::Edge { invite, ..edge(r) }));
                lp.peers[by].engine.commit_hostile(m).unwrap().expect("an edge write writes");
                Some(by)
            }
            Step::Removal { by, t, holder } => {
                let d = osis_node::flows::Demotion { holder: ids[holder], new: None, presync: osis_node::flows::PreSync::Backdated(T0) };
                lp.peers[by].engine.demote(&th(t), &d).unwrap();
                Some(by)
            }
            Step::HostileRoster { by, t, keep } => {
                let roster: osis_schema::core_types::Holders = keep.iter().map(|(h, r)| (ids[*h], edge(*r))).collect();
                let mut m = Mutation::new();
                m.replace(th(t), &osis_schema::core_types::ROLES, &roster).unwrap();
                m.replace(th(t), &osis_schema::core_types::TENURES, &osis_schema::core_types::Tenures(Vec::new())).unwrap();
                m.roster_for_tests();
                lp.peers[by].engine.commit_hostile(m).unwrap().expect("a snapshot writes");
                Some(by)
            }
            Step::HostileWrite { by, t, v } => {
                let mut m = Mutation::new();
                m.set(th(t), &REG, &s(&format!("v{v}"))).unwrap();
                lp.peers[by].engine.commit_hostile(m).unwrap().expect("a write");
                Some(by)
            }
            Step::Two { by, a, b, v } => {
                let mut m = Mutation::new();
                m.set(th(a), &REG, &s(&format!("v{v}"))).unwrap();
                m.set(th(b), &REG, &s(&format!("v{v}"))).unwrap();
                lp.peers[by].engine.commit_hostile(m).unwrap().expect("two writes");
                Some(by)
            }
            Step::Three { by, a, b, c, v } => {
                let mut m = Mutation::new();
                for x in [th(a), th(b), th(c)] {
                    m.set(x, &REG, &s(&format!("v{v}"))).unwrap();
                }
                lp.peers[by].engine.commit_hostile(m).unwrap().expect("three writes");
                Some(by)
            }
            Step::TwoEdges { by, a, b, holder, role } => {
                let mut m = Mutation::new();
                for x in [th(a), th(b)] {
                    m.op(x, &osis_schema::core_types::ROLES, PathOp { path: vec![], op: Op::Remove(Value::Tid(ids[holder])) }).unwrap();
                    m.op(x, &osis_schema::core_types::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(ids[holder]))], op: Op::Set(edge(role).to_value()) }).unwrap();
                }
                lp.peers[by].engine.commit_hostile(m).unwrap().expect("two edge writes");
                Some(by)
            }
            Step::NestedTyped { by, other, t, k } => {
                let key = PathSeg::Key(s(&format!("k{k}")));
                let mut m = Mutation::new();
                m.op(th(t), &MAP, PathOp { path: vec![key.clone()], op: Op::Set(item("v1", 1)) }).unwrap();
                let id = lp.peers[by].commit(m).unwrap().expect("a put");
                let pk = lp.peers[by].engine.package(&id).unwrap().unwrap();
                lp.deliver(other, &pk).unwrap();
                lp.peers[other].clock.advance(1);
                let mut m = Mutation::new();
                m.op(th(t), &MAP, PathOp { path: vec![key, PathSeg::Field(1)], op: Op::Set(Value::Int(7)) }).unwrap();
                lp.peers[other].commit(m).unwrap().expect("a write");
                lp.peers[other].clock.advance(1);
                lp.peers[other].engine.snapshot(&th(t), &ak("t:map.0")).unwrap();
                collect(&mut lp, by, &mut seen, &mut packs, &mut authors, &mut own);
                Some(other)
            }
            Step::TypedField { by, t, k, v } => {
                let mut m = Mutation::new();
                m.op(th(t), &MAP, PathOp { path: vec![PathSeg::Key(s(&format!("k{k}"))), PathSeg::Field(1)], op: Op::Set(Value::Int(v as i64)) }).unwrap();
                lp.peers[by].commit(m).unwrap().expect("a write");
                Some(by)
            }
            Step::Paged { by, t } => {
                let big: BTreeMap<Value, Value> = (0..1100).map(|i| (s(&format!("key-{i:05}")), s(&"x".repeat(40)))).collect();
                let mut m = Mutation::new();
                m.set(th(t), &BIG, &Value::Map(big)).unwrap();
                let id = lp.peers[by].commit(m).unwrap().expect("a write");
                assert!(!lp.peers[by].engine.header(&id).unwrap().chunks.is_empty(), "paged");
                Some(by)
            }
            Step::Large { by, t } => {
                let mut m = Mutation::new();
                m.set(th(t), &BLOB, &Value::Bytes(vec![7; osis_base::format::CHUNK_THRESHOLD + 1])).unwrap();
                let id = lp.peers[by].commit(m).unwrap().expect("a write");
                assert!(!lp.peers[by].engine.header(&id).unwrap().chunks.is_empty(), "chunked");
                Some(by)
            }
            Step::LinkedDemote { by, t, holder } => {
                let t = th(t);
                let scope = DemotionScope { roles: BTreeMap::from([(ids[holder], BTreeSet::from([t]))]), content: BTreeMap::from([(ids[holder], BTreeSet::from([t]))]) };
                let as_of = lp.peers[by].engine.now();
                let mut f = lp.peers[by].engine.frontier(&scope, as_of).unwrap();
                // padded with IDs no commit has, just past the threshold: these go in the vectors
                let mut i = 0u32;
                while osis_base::encode(&f.to_value()).len() <= osis_base::format::CHUNK_THRESHOLD {
                    for _ in 0..50 {
                        let b = i.to_be_bytes();
                        let mut id = [7; 32];
                        id[..4].copy_from_slice(&b);
                        f.commits.insert(CommitId(id));
                        i += 1;
                    }
                }
                let mut m = edge_write(t, ids[holder], None);
                m.frontier(f.to_value());
                let id = lp.peers[by].commit(m).unwrap().expect("a removal");
                assert!(lp.peers[by].engine.header(&id).unwrap().links.frontier.is_some(), "the frontier goes by link");
                Some(by)
            }
        };
        if let Some(i) = acted {
            collect(&mut lp, i, &mut seen, &mut packs, &mut authors, &mut own);
            let kind = format!("{st:?}");
            let kind = kind.split(' ').next().unwrap().to_string() + if matches!(st, Step::Nested { text: true, .. }) { "(text)" } else { "" };
            let e = tally.kinds.entry(kind.clone()).or_default();
            e.0 += 1;
            if packs.len() > before {
                e.1 += 1;
            } else {
                *tally.refused.entry((kind, no.unwrap_or("no change".into()))).or_default() += 1;
            }
        }
    }
    tally.commits = (packs.len() - base) as u64;
    // the fresh nodes' clock: the latest of the writers' (nothing parks for drift)
    let now = lp.peers.iter().map(|p| p.engine.now()).max().unwrap();
    for pk in &mut packs {
        if let Some(b) = forged.get(&pk.id) {
            pk.bytes = b.clone();
        }
    }
    Played { packs, authors, base, things, now, tally, sync: Syncs::None }
}

/// Per body (commit, thing, aspect): its first and last death (spec/crdt.md §4.8).
type Deaths = BTreeMap<(CommitId, Tid, Ak), Option<(osis_base::Ts, osis_base::Ts)>>;

fn deaths_of(e: &mut osis_node::Engine) -> Deaths {
    let mut out = Deaths::new();
    for id in e.commit_ids() {
        let Some(h) = e.header(&id) else { continue };
        for a in &h.aspects {
            out.insert((id, a.tid, a.ak.clone()), e.deaths(&id, &a.tid, &a.ak).unwrap());
        }
    }
    out
}

/// What a node holding `held` and every body of it judges (`keep_bodies`), its deaths
/// recomputed from them all: each write's earliest superseder (spec/crdt.md §4.8), the oracle
/// `dating` compares nodes' local dates with; and its facts (`facts_text`).
struct Oracle {
    deaths: Deaths,
    facts: String,
    /// Aspects a held snapshot carries writes of whose own commit the oracle does not hold (a
    /// role commit, a creation, or one not played): a recompute plays those at the
    /// snapshot, not at their own `ts`, so the oracle does not judge them.
    carried: BTreeSet<(Tid, Ak)>,
}

fn oracle(played: &Played, held: &[usize]) -> Oracle {
    let mut p = Peer::new(FRESH, played.now).unwrap();
    p.engine.keep_bodies(true);
    for t in played.sync.things() {
        p.engine.set_syncing(*t, true).unwrap();
    }
    for &i in held {
        let pk = &played.packs[i];
        let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    let mut aspects = BTreeSet::new();
    for id in p.engine.commit_ids() {
        aspects.extend(p.engine.header(&id).into_iter().flat_map(|h| h.aspects.iter().map(|a| (a.tid, a.ak.clone())).collect::<Vec<_>>()));
    }
    // carried writes whose own commit is not held: the oracle takes those commits too where
    // they are plain writes (no role part, no creation), so its recompute plays them at
    // their own `ts`; more superseders date no later, so `dating` stays sound
    let want: BTreeSet<(Tid, Ak, osis_crdt::Dot)> = aspects.iter().flat_map(|(t, a)| p.engine.carried_dots(t, a).into_iter().map(|d| (*t, a.clone(), d))).collect();
    if !want.is_empty() {
        let whole = deliver(played, &(0..played.packs.len()).collect::<Vec<_>>());
        for (i, pk) in played.packs.iter().enumerate() {
            let Some(h) = whole.engine.header(&pk.id) else { continue };
            if !held.contains(&i) && common::owns_carried(&h, &pk.id, &want) && !h.kind.is_role() && h.kind.has_own_writes() && h.aspects.iter().all(|a| a.ak.as_str() != "created.0") {
                let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
            }
        }
    }
    let carried: BTreeSet<(Tid, Ak)> = aspects.iter().filter(|(t, a)| !p.engine.carried_dots(t, a).is_empty()).cloned().collect();
    for (t, a) in aspects {
        p.engine.replay_deaths(&t, &a).unwrap();
    }
    Oracle { deaths: deaths_of(&mut p.engine), facts: facts_text(&mut p.engine), carried }
}

/// Whether node `p` dates deaths as spec/commits.md §5 allows against the oracle `o` (`None`),
/// else the first violation: a held body with its own writes has a death iff the oracle's has,
/// never earlier, first or last; a held snapshot or import has a last death no earlier than the
/// oracle's; a body dropped here under a relative keep at most D that the oracle holds died by
/// the oracle at least D before now (never early); a body under keep at most 0 with a death and
/// no live write is dropped (prompt). Aspects the drop-before-flip difference reaches are
/// skipped (`alike`), and those with carried writes whose own commit the oracle does not hold
/// (it would date them late, `Oracle::carried`).
fn dating(p: &mut Peer, o: &Oracle, now: WallMs) -> Option<String> {
    let (mine, _) = facts_of(&facts_text(&mut p.engine));
    let (theirs, inv) = facts_of(&o.facts);
    let mut flipped: BTreeSet<(String, String)> = theirs.keys().filter(|k| mine.get(*k).is_some_and(|m| flip(&theirs, &mine, &inv, k) && m.held != theirs[*k].held)).map(|k| (k.1.clone(), k.2.clone())).collect();
    // a part held pending at its expiry counts as never received here (spec/commits.md §5)
    flipped.extend(expired_pending(&mut p.engine));
    let e = &mut p.engine;
    let mut ids = e.commit_ids();
    ids.sort();
    for id in ids {
        let Some(h) = e.header(&id) else { continue };
        let copies = !h.kind.has_own_writes();
        for a in &h.aspects {
            let (r, k) = (a.retention, (id, a.tid, a.ak.clone()));
            let carried = o.carried.contains(&(a.tid, a.ak.clone()));
            if (r.at_least.rel.is_none() && r.at_most.rel.is_none()) || carried || flipped.contains(&(format!("{:?}", a.tid), a.ak.as_str().to_string())) {
                continue;
            }
            let (x, y) = (e.deaths(&id, &a.tid, &a.ak).unwrap(), o.deaths.get(&k).copied().flatten());
            let what = format!("{id:?} ({:?}) {:?} {}: here {x:?}, earliest superseders {y:?}", h.kind, a.tid, a.ak.as_str());
            if e.body_not_dropped(&id, &a.tid, &a.ak) {
                let ok = match (x, y, copies) {
                    (Some(x), Some(y), false) => x.0 >= y.0 && x.1 >= y.1,
                    (None, None, false) | (_, None, true) => true,
                    (Some(x), Some(y), true) => x.1 >= y.1,
                    _ => false,
                };
                if !ok {
                    return Some(format!("death dated early or missing: {what}"));
                }
                if r.at_most.rel == Some(0) && x.is_some() && !e.body_live(&id, &a.tid, &a.ak).unwrap() {
                    return Some(format!("dead body kept under keep at most 0: {what}"));
                }
            } else if let Some(d) = r.at_most.rel
                && !copies
                && theirs.get(&(format!("{id:?}"), format!("{:?}", a.tid), a.ak.as_str().to_string())).is_some_and(|f| f.held)
                && !y.is_some_and(|y| y.0.wall_ms().0.saturating_add(d) <= now.0)
            {
                return Some(format!("body dropped before its keep-at-most bound: {what}"));
            }
        }
    }
    None
}

/// The facts `alike` reads per body (commit, thing, aspect, under keep at most, held, valid,
/// `ts`, under a relative keep at most) and per aspect its invalid writes (`inv`).
fn facts_text(e: &mut osis_node::Engine) -> String {
    let mut facts = String::new();
    let mut aspects = BTreeSet::new();
    for id in e.commit_ids() {
        let Some(h) = e.header(&id) else { continue };
        for a in &h.aspects {
            let at_most = a.retention.at_most.rel.is_some() || a.retention.at_most.abs.is_some();
            let approx = a.retention.at_most.rel.is_some();
            let valid = e.body_valid(&id, &a.tid, &a.ak).unwrap();
            let held = e.body_not_dropped(&id, &a.tid, &a.ak);
            // the node-form counters its writes own (`-`: commit form, a snapshot)
            let owns = if h.form == osis_commit::Form::Node && a.lo < a.hi { format!("N{:?}:{}-{}", h.author, a.lo, a.hi) } else { "-".into() };
            let copies = !h.kind.has_own_writes();
            // a held copies body's lowest carried `ts` (`-`: dropped, or not copies)
            let low = if copies { e.body_min_ts(&id, &a.tid, &a.ak).unwrap().map_or("-".into(), |t| format!("{t:?}")) } else { "-".to_string() };
            let _ = writeln!(facts, "{id:?}|{:?}|{}|{at_most}|{held}|{valid}|{:?}|{approx}|{owns}|{copies}|{low}", a.tid, a.ak.as_str(), h.ts);
            aspects.insert((a.tid, a.ak.clone()));
        }
    }
    for (tid, ak) in &aspects {
        for (c, ts) in e.invalid_writes(tid, ak) {
            let _ = writeln!(facts, "inv|{tid:?}|{}|{c:?}|{ts:?}", ak.as_str());
        }
    }
    let mut facts: Vec<&str> = facts.lines().collect();
    facts.sort();
    facts.join("\n")
}

/// What a node judged: its index a day later (`judged`; `None` from `judged_now`) and the rest as
/// text, by part.
#[derive(Clone)]
struct Judged {
    index: Option<IndexDigest>,
    parts: Vec<(&'static str, String)>,
    /// Aspects (as `facts_text` prints them) the node flags suspect for a part it held pending
    /// at its expiry (counts as never received, spec/commits.md §5): not compared.
    expired_pending: BTreeSet<(String, String)>,
}

impl Judged {
    fn part(&self, name: &str) -> &str {
        &self.parts.iter().find(|x| x.0 == name).unwrap().1
    }
}

/// A state's text, with what spec/crdt.md §5.7 leaves to the node taken out: a deleted text
/// element's char (a node may drop it locally; a reopen has).
fn plain_state(state: &str) -> String {
    const AT: &str = "SeqElem {";
    let mut parts = state.split(AT);
    let mut out = parts.next().unwrap_or("").to_string();
    for el in parts {
        out.push_str(AT);
        let deleted = el.find("deleted: Some").is_some_and(|i| el[i..].find("span:").is_some_and(|j| el[i..i + j].contains(", true))")));
        match el.find("content: Char(").filter(|_| deleted) {
            Some(i) => {
                let j = i + el[i..].find(", pos:").unwrap();
                out.push_str(&el[..i]);
                out.push_str("content: None");
                out.push_str(&el[j..]);
            }
            None => out.push_str(el),
        }
    }
    out
}

/// The aspects (as `facts_text` prints them) node `e` flags suspect for a part it held pending
/// at its expiry.
fn expired_pending(e: &mut osis_node::Engine) -> BTreeSet<(String, String)> {
    e.suspects().unwrap().into_iter().filter(|x| x.3 & osis_node::retention::suspect::Why::PendingDrop as u8 != 0).map(|(t, a, _, _)| (format!("{t:?}"), a.as_str().to_string())).collect()
}

/// What a node holding `packs` judges and reads now, as text, by part: reads and states of every
/// aspect, rosters, pending set, timelines, body facts. Deaths are the node's own (`dating`).
fn judged_now(p: &mut Peer, things: &[Tid]) -> Judged {
    let e = &mut p.engine;
    let mut reads = String::new();
    let mut states = String::new();
    // every aspect held (fresh nodes share a seed, so their own things agree too)
    let all = e.all_aspects().unwrap();
    for (t, a) in &all {
        let (t, a) = (*t, a.clone());
        let _ = writeln!(reads, "{t:?} {} {:?}", a.as_str(), e.get(&t, &a).unwrap());
        let _ = writeln!(states, "{t:?} {} {}", a.as_str(), plain_state(&format!("{:?}", e.state(&t, &a).unwrap())));
    }
    let mut rosters = String::new();
    let tids: BTreeSet<Tid> = all.iter().map(|x| x.0).chain(things.iter().copied()).collect();
    for t in &tids {
        let _ = writeln!(rosters, "{t:?} {:?}", e.roster(t));
    }
    let mut pending: Vec<String> = e.pending().iter().map(|(id, r)| format!("{id:?} {r:?}")).collect();
    pending.sort();
    let perm = e.perm_digest(false);
    let scratch = e.perm_digest(true);
    let facts = facts_text(e);
    let parts = vec![("reads", reads), ("states", states), ("rosters", rosters), ("pending", pending.join("\n")), ("timelines", perm), ("timelines from scratch", scratch), ("facts", facts)];
    let expired_pending = expired_pending(e);
    Judged { index: None, parts, expired_pending }
}

/// The persisted index as a day after `played.now` (every keep-at-most bound past: which bodies
/// a node dropped before is its own dating, `dating`). Moves the node's clock there.
fn index_later(p: &mut Peer, played: &Played) -> IndexDigest {
    let later = WallMs(played.now.0 + 24 * HOUR);
    if p.engine.now().0 < later.0 {
        p.clock.set(later);
    }
    p.engine.tick().unwrap();
    p.engine.index_digest()
}

/// `judged_now`, then `index_later` (moves the node's clock).
fn judged(p: &mut Peer, played: &Played) -> Judged {
    let mut v = judged_now(p, &played.things);
    v.index = Some(index_later(p, played));
    v
}

/// A body's facts at one node (`judged`'s last part), keyed by (commit, thing, aspect) as the
/// index prints them.
struct Fact {
    at_most: bool,
    held: bool,
    valid: bool,
    ts: u64,
    /// Under a relative keep at most: dropped by the node's own dating (at most 0 with a live
    /// write: at its grace bound; without one `dating` checks it dropped).
    approx: bool,
    /// The node-form counters its writes own: `NTid(author):lo-hi`, or `-`.
    owns: String,
    /// A snapshot or import body (copies): its carried writes die for it at its `ts` when
    /// killed by a lower-stamped write (spec/commits.md §5).
    copies: bool,
    /// Held there, a copies body's lowest carried write `ts` (a killer is stamped after it).
    low: Option<u64>,
}

impl Fact {
    /// Whether a dot as a state prints it (`NTid(..):ctr`) is one of this body's.
    fn owns_dot(&self, dot: &str) -> bool {
        let (Some((src, r)), Some((d, ctr))) = (self.owns.rsplit_once(':'), dot.rsplit_once(':')) else { return false };
        let (Some((lo, hi)), Ok(ctr)) = (r.split_once('-'), ctr.parse::<u64>()) else { return false };
        src == d && lo.parse::<u64>().is_ok_and(|lo| lo <= ctr) && hi.parse::<u64>().is_ok_and(|hi| ctr < hi)
    }
}

/// The dots of the creation stamps in a state's text (`created: Some((ts, dot))`), and the text
/// with every one of them blanked.
fn creations(state: &str) -> (Vec<String>, String) {
    const AT: &str = "created: Some((";
    let (mut dots, mut out, mut rest) = (Vec::new(), String::new(), state);
    while let Some(i) = rest.find(AT) {
        out.push_str(&rest[..i]);
        let tail = &rest[i + AT.len()..];
        let Some(j) = tail.find("))") else { break };
        dots.push(tail[..j].split_once(", ").map_or("", |x| x.1).to_string());
        out.push_str("created: None");
        rest = &tail[j + 2..];
    }
    out.push_str(rest);
    (dots, out)
}

type BodyKey = (String, String, String);

/// A `Ts(n)`'s n.
fn ts_of(t: &str) -> u64 {
    t.trim_start_matches("Ts(").trim_end_matches(')').parse().unwrap()
}

/// The bodies' facts, and per (thing, aspect) its invalid writes: (commit or carrying snapshot, `ts`).
fn facts_of(text: &str) -> (Facts, Invalid) {
    let (mut out, mut inv) = (BTreeMap::new(), BTreeMap::<_, Vec<_>>::new());
    for l in text.lines() {
        let f: Vec<&str> = l.split('|').collect();
        if f[0] == "inv" {
            inv.entry((f[1].into(), f[2].into())).or_default().push((f[3].into(), ts_of(f[4])));
            continue;
        }
        let b = |i: usize| f[i] == "true";
        out.insert((f[0].into(), f[1].into(), f[2].into()), Fact { at_most: b(3), held: b(4), valid: b(5), ts: ts_of(f[6]), approx: b(7), owns: f[8].into(), copies: b(9), low: (f[10] != "-").then(|| ts_of(f[10])) });
    }
    (out, inv)
}

/// Facts per body and invalid writes per aspect (`facts_of`).
type Facts = BTreeMap<BodyKey, Fact>;
type Invalid = BTreeMap<(String, String), Vec<(String, u64)>>;

/// The drop-before-flip difference on body `k` between nodes with facts `w` and `g`: held at
/// one node only, under keep at most, with its own write invalid (its delta, or a write it
/// carries) or an invalid write of its aspect that may have killed it: stamped at or after it,
/// or for a snapshot or import at or after the lowest write it carries (a lower-stamped kill of
/// a carried write kills it at its own `ts`; the node holding it reads that bound).
fn flip(w: &Facts, g: &Facts, inv: &Invalid, k: &BodyKey) -> bool {
    let (w, g) = (&w[k], &g[k]);
    let own = !w.valid || inv.get(&(k.1.clone(), k.2.clone())).is_some_and(|v| v.iter().any(|(c, _)| *c == k.0));
    let after = if w.copies { w.low.or(g.low).unwrap_or(w.ts) } else { w.ts };
    let killer = inv.get(&(k.1.clone(), k.2.clone())).is_some_and(|v| v.iter().any(|(c, ts)| *c != k.0 && *ts >= after));
    w.held != g.held && w.at_most && (own || killer)
}

/// The commits with a body held at one node and dropped at the other where that is a drop
/// before a validity flip (`flip`), as `facts_text` prints their IDs: a body dropped for its keep
/// bounds counts as never received (spec/commits.md §5), so the two nodes hold the same bodies
/// once each is given these again (`alike_exchanged`).
fn drop_flips(want: &Judged, got: &Judged) -> BTreeSet<String> {
    let ((wf, inv), (gf, _)) = (facts_of(want.part("facts")), facts_of(got.part("facts")));
    if wf.keys().ne(gf.keys()) {
        return BTreeSet::new();
    }
    wf.keys().filter(|k| flip(&wf, &gf, &inv, k)).map(|k| k.0.clone()).collect()
}

/// Whether two nodes holding the same commits judged alike (`None`), else the first difference.
/// Values, validity, rosters, pending sets, timelines and the index a day later are compared
/// exactly; held bodies too, except under a relative keep at most (deaths are dated per node;
/// `dating` checks them, and that a dead body under at most 0 with no live write is dropped).
/// A body dropped before a validity flip is no exception: callers give both nodes such bodies
/// again first (`alike_exchanged`). Also a drop, then a validity flip and back (`flips`: one of
/// the two orders judged a body of the aspect valid and invalid on the way, `flipped`): the
/// states may then differ in the creation stamps of map entries whose body (keep at most) the
/// node lacking the stamp dropped (an un-merge leaving the entry with no content took the
/// creation; the flip back gave the content alone), reads alike. Anything else is a failure.
fn alike(want: &Judged, got: &Judged, flips: &dyn Fn(&str, &str) -> bool) -> Option<String> {
    // a part held pending at its expiry counts as never received at that node (spec/commits.md
    // §5; owner: nodes may read differently when a part expired before a node could apply it):
    // what such an aspect reads, its bodies, and the index lines of its commits (that part is
    // dropped at a node that applied it, missing at one that did not) may differ, repaired by a
    // writer's snapshot (spec/sync.md §7). Nothing else: whether a commit is applied or pending,
    // and every other aspect and commit, must agree.
    let expired: BTreeSet<(String, String)> = want.expired_pending.union(&got.expired_pending).cloned().collect();
    let ((mut wf, _), (mut gf, _)) = (facts_of(want.part("facts")), facts_of(got.part("facts")));
    let all: BTreeSet<BodyKey> = wf.keys().chain(gf.keys()).cloned().collect();
    wf.retain(|k, _| !expired.contains(&(k.1.clone(), k.2.clone())));
    gf.retain(|k, _| !expired.contains(&(k.1.clone(), k.2.clone())));
    if wf.keys().ne(gf.keys()) {
        let k = wf.keys().find(|k| !gf.contains_key(*k)).or_else(|| gf.keys().find(|k| !wf.contains_key(*k)));
        return Some(format!("body {k:?} known at one node only"));
    }
    if let Some(k) = wf.keys().find(|k| wf[*k].held != gf[*k].held && !wf[*k].approx) {
        return Some(format!("body {k:?} held {} vs {}", wf[k].held, gf[k].held));
    }
    let on_expired = |c: &CommitId| {
        let id = format!("{c:?}");
        all.iter().any(|k| k.0 == id && expired.contains(&(k.1.clone(), k.2.clone())))
    };
    match (&want.index, &got.index) {
        (Some(w), Some(g)) => {
            let exempt = |f: &IndexField| match f {
                IndexField::Commit(c) | IndexField::Snapshots(c) | IndexField::DroppedSnapshots(c) | IndexField::Carried(c) => on_expired(c),
                IndexField::Held(_) | IndexField::ByChunk | IndexField::Table(_) => false,
            };
            if let Some(f) = w.diff(g).into_iter().find(|f| !exempt(f)) {
                return Some(format!("index {f:?}:\n  want {}\n  got  {}", w.show(&f).unwrap_or("<none>".into()), g.show(&f).unwrap_or("<none>".into())));
            }
        }
        (None, None) => {}
        _ => return Some("index judged at one node only".into()),
    }
    for ((name, x), (_, y)) in want.parts.iter().zip(&got.parts) {
        if x == y || *name == "facts" {
            continue;
        }
        let (xl, yl): (Vec<&str>, Vec<&str>) = (x.lines().collect(), y.lines().collect());
        if *name == "reads" || *name == "states" {
            // keyed by thing and aspect: one may lack an aspect the other shows
            let keyed = |ls: &[&str]| -> BTreeMap<(String, String), String> {
                ls.iter().map(|l| {
                    let f: Vec<&str> = l.splitn(3, ' ').collect();
                    ((f[0].into(), f.get(1).copied().unwrap_or("").into()), f.get(2).copied().unwrap_or("").into())
                }).collect()
            };
            let (a, b) = (keyed(&xl), keyed(&yl));
            // only creation stamps of bodies dropped where they are missing, after a flip
            let stamps_only = |k: &(String, String)| -> bool {
                let (Some(x), Some(y)) = (a.get(k), b.get(k)) else { return false };
                let ((xd, xs), (yd, ys)) = (creations(x), creations(y));
                let dropped = |dot: &String, facts: &Facts| facts.iter().any(|(b, f)| b.1 == k.0 && b.2 == k.1 && f.at_most && !f.held && f.owns_dot(dot));
                *name == "states" && xs == ys && xd.iter().filter(|d| !yd.contains(d)).all(|d| dropped(d, &gf)) && yd.iter().filter(|d| !xd.contains(d)).all(|d| dropped(d, &wf)) && flips(&k.0, &k.1)
            };
            for k in a.keys().chain(b.keys()) {
                if a.get(k) != b.get(k) && !stamps_only(k) && !expired.contains(k) {
                    return Some(format!("{name} on {k:?}:\n  want {:?}\n  got  {:?}", a.get(k), b.get(k)));
                }
            }
            continue;
        }
        return first_diff_parts(&[(name, x.clone())], &[(name, y.clone())]);
    }
    None
}

/// The packs of the commits `ids` (as `facts_text` prints them).
fn packs_of(played: &Played, ids: &BTreeSet<String>) -> Vec<usize> {
    (0..played.packs.len()).filter(|&i| ids.contains(&format!("{:?}", played.packs[i].id))).collect()
}

/// `alike` of the judgements `want` (a node given `want_order`) and `got` (one given `got_order`,
/// split by `rng` as `deliver_split`), after both nodes are given once more the commits of
/// every body one dropped before a validity flip and the other holds (`drop_flips`): a copy that
/// arrives again joins (spec/commits.md §5), so they then hold the same bodies and judge alike
/// with no exception for the drop.
fn alike_exchanged(played: &Played, want: &Judged, want_order: &[usize], got: &Judged, got_order: &[usize], rng: Option<Rng>, flips: &dyn Fn(&str, &str) -> bool) -> Option<String> {
    let apart = drop_flips(want, got);
    if apart.is_empty() {
        return alike(want, got, flips);
    }
    let again = packs_of(played, &apart);
    let mut rng = rng;
    let mut w = deliver_with(played, want_order, None, &mut |_| {});
    let mut g = deliver_with(played, got_order, rng.as_mut(), &mut |_| {});
    for p in [&mut w, &mut g] {
        for &i in &again {
            let pk = &played.packs[i];
            let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
        }
        p.engine.reexamine().unwrap();
    }
    let (wj, gj) = (judged(&mut w, played), judged(&mut g, played));
    alike(&wj, &gj, flips).map(|d| format!("after the bodies dropped before a flip ({apart:?}) were given again: {d}"))
}

const FRESH: u64 = 0x5eed_f00d;

/// What the fresh nodes sync, and when they learn it (spec/commits.md §4: atomic apply waits for
/// deltas of things a node syncs, which `deliver` reaches only with a thing synced and a delta
/// missing). Both end at one set, so every order must judge alike.
#[derive(Clone, Debug)]
enum Syncs {
    None,
    /// `on` from before the first commit, some commits' other parts never held (`withhold`);
    /// `prefix` synced only for a stretch of each delivery: a wait it causes ends when it stops.
    Early { on: Vec<Tid>, prefix: Vec<Tid> },
    /// Nothing at first, `on` from a point of each delivery, some stopping and starting again;
    /// some commits' other parts never held. A held set with a commit waiting across things goes
    /// without syncs (`learned_late_wait`).
    Late { on: Vec<Tid> },
}

/// Toggles in delivery order: before the `.0`th ingest, thing `.1` on or off.
struct SyncPlan(Vec<(usize, Tid, bool)>);

impl Syncs {
    fn things(&self) -> &[Tid] {
        match self {
            Syncs::None => &[],
            Syncs::Early { on, .. } | Syncs::Late { on } => on,
        }
    }

    /// The toggles of a delivery of `order`: their points depend on the order alone.
    fn plan(&self, order: &[usize]) -> SyncPlan {
        let mut h = order.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, x| (h ^ *x as u64).wrapping_mul(0x0100_0000_01b3));
        let mut at = move |t: &Tid| {
            h = t.as_bytes().iter().fold(h, |h, x| (h ^ *x as u64).wrapping_mul(0x0100_0000_01b3));
            let mut r = Rng(h | 1);
            r.below(order.len() as u64 + 1) as usize
        };
        let mut out = Vec::new();
        match self {
            Syncs::None => {}
            Syncs::Early { on, prefix } => {
                out.extend(on.iter().chain(prefix).map(|t| (0, *t, true)));
                out.extend(prefix.iter().map(|t| (at(t), *t, false)));
            }
            Syncs::Late { on } => {
                for (i, t) in on.iter().enumerate() {
                    let a = at(t);
                    out.push((a, *t, true));
                    if i % 3 == 0 {
                        let (b, c) = (a.max(at(t)), at(t));
                        out.push((b, *t, false));
                        out.push((b.max(c), *t, true));
                    }
                }
            }
        }
        // stable: a thing's own toggles stay in order
        out.sort_by_key(|x| x.0);
        SyncPlan(out)
    }
}

impl SyncPlan {
    /// Applies the toggles due before ingest number `done` (`usize::MAX`: all that are left).
    fn upto(&mut self, p: &mut Peer, done: usize) {
        while let Some(&(at, t, on)) = self.0.first()
            && at <= done
        {
            p.engine.set_syncing(t, on).unwrap();
            self.0.remove(0);
        }
    }
}

/// The history as the seed's fresh nodes get it, by `seed % 3`: as made; each thing synced from
/// the start with probability one half and half of the commits with parts on several aspects
/// held in part for good (`Syncs::Early`); or things synced at varying points, with such parts
/// withheld too (`Syncs::Late`).
fn with_syncs(mut played: Played, seed: u64) -> Played {
    let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d) | 1);
    let mut half = |ts: &[Tid]| ts.iter().copied().filter(|_| rng.below(2) == 0).collect::<Vec<_>>();
    let things = played.things.clone();
    let (on, other) = (half(&things), half(&things));
    let prefix: Vec<Tid> = other.into_iter().filter(|t| !on.contains(t)).collect();
    match seed % 3 {
        0 => {}
        _ => {
            for i in played.base..played.packs.len() {
                let mut b = osis_commit::CommitBlob::decode(&played.packs[i].bytes).unwrap();
                let ais: BTreeSet<usize> = b.parts.iter().map(|x| x.ai).collect();
                if ais.len() > 1 && rng.below(2) == 0 {
                    let keep = ais.iter().copied().nth(rng.below(ais.len() as u64) as usize).unwrap();
                    b.parts.retain(|x| x.ai == keep);
                    played.packs[i].bytes = b.encode();
                }
            }
            played.sync = if seed % 3 == 1 { Syncs::Early { on, prefix } } else { Syncs::Late { on } };
        }
    }
    played
}

/// A fresh node given `packs` in `order`.
fn deliver(played: &Played, order: &[usize]) -> Peer {
    deliver_with(played, order, None, &mut |_| {})
}

/// A fresh node given `packs` in `order`, each commit with parts on several aspects first with
/// those of one of them only (a seeded pick), the rest of it as late parts at the end, in
/// reverse (spec/commits.md §4: a late delta joins on arrival).
fn deliver_split(played: &Played, order: &[usize], rng: &mut Rng) -> Peer {
    deliver_with(played, order, Some(rng), &mut |_| {})
}

/// `deliver` (no `rng`) or `deliver_split`, calling `each` after every ingest.
fn deliver_with(played: &Played, order: &[usize], mut rng: Option<&mut Rng>, each: &mut dyn FnMut(&mut Peer)) -> Peer {
    let mut p = Peer::new(FRESH, played.now).unwrap();
    // every component's walk saved, so reopens restore them
    p.engine.set_walk_cache_min(1);
    let mut late = Vec::new();
    let mut plan = played.sync.plan(order);
    let mut done = 0;
    for &i in order {
        plan.upto(&mut p, done);
        done += 1;
        let pk = &played.packs[i];
        let bytes = match rng.as_deref_mut() {
            None => pk.bytes.clone(),
            Some(rng) => {
                let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
                let ais: BTreeSet<usize> = b.parts.iter().map(|x| x.ai).collect();
                if ais.len() > 1 {
                    let keep = ais.iter().copied().nth(rng.below(ais.len() as u64) as usize).unwrap();
                    b.parts.retain(|x| x.ai == keep);
                    late.push(i);
                }
                b.encode()
            }
        };
        let _ = p.engine.ingest(&bytes, pk.blobs.clone());
        each(&mut p);
    }
    for &i in late.iter().rev() {
        plan.upto(&mut p, done);
        done += 1;
        let pk = &played.packs[i];
        let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
        each(&mut p);
    }
    plan.upto(&mut p, usize::MAX);
    each(&mut p);
    if rng.is_some() {
        let _ = p.engine.reexamine();
        each(&mut p);
    }
    p
}

/// Whether delivering `order` (split as `deliver_split` with `rng`) judged a body of `(tid, ak)`
/// (as `facts_text` prints them) both valid and invalid on the way: a validity flip in that
/// order. A delivery with facts at every step: asked only about a difference found.
fn flipped(played: &Played, order: &[usize], rng: Option<Rng>, tid: &str, ak: &str) -> bool {
    let mut seen: BTreeMap<BodyKey, BTreeSet<bool>> = BTreeMap::new();
    let mut rng = rng;
    deliver_with(played, order, rng.as_mut(), &mut |p| {
        for (k, f) in facts_of(&facts_text(&mut p.engine)).0 {
            if k.1 == tid && k.2 == ak {
                seen.entry(k).or_default().insert(f.valid);
            }
        }
    });
    seen.values().any(|v| v.len() > 1)
}

/// The first difference between two judgements, index first, described.
fn first_diff(a: &Judged, b: &Judged) -> Option<String> {
    match (&a.index, &b.index) {
        (Some(x), Some(y)) => x.first_diff(y),
        (None, None) => None,
        _ => Some("index judged at one node only".into()),
    }
    .or_else(|| first_diff_parts(&a.parts, &b.parts))
}

fn first_diff_parts(a: &[(&'static str, String)], b: &[(&'static str, String)]) -> Option<String> {
    for ((name, x), (_, y)) in a.iter().zip(b) {
        if x != y {
            let (xl, yl): (Vec<&str>, Vec<&str>) = (x.lines().collect(), y.lines().collect());
            let i = xl.iter().zip(&yl).position(|(p, q)| p != q).unwrap_or(xl.len().min(yl.len()));
            return Some(format!("{name} line {i}:\n  want {}\n  got  {}", xl.get(i).unwrap_or(&"<end>"), yl.get(i).unwrap_or(&"<end>")));
        }
    }
    None
}

/// Every permutation of `0..n` (n small).
fn perms(n: usize) -> Vec<Vec<usize>> {
    if n == 0 {
        return vec![Vec::new()];
    }
    let mut out = Vec::new();
    for p in perms(n - 1) {
        for i in 0..=p.len() {
            let mut q = p.clone();
            q.insert(i, n - 1);
            out.push(q);
        }
    }
    out
}

/// How much of the order space a check covers.
#[derive(Clone, Copy, Debug)]
struct Cfg {
    /// Every order of the held commits after the setup when there are at most this many.
    all_up_to: usize,
    /// `all_up_to` applies to partial held sets too (else to the whole set only).
    every_held: bool,
    /// Random shuffles of each held set.
    random: usize,
    /// Partial held sets.
    subsets: usize,
    /// How many of each held set's orders are tried again with late parts.
    split: usize,
    /// A seed's orders are independent tasks (each late-parts order split by its own rng), run
    /// on `threads` threads; else they run in turn, split by one rng.
    par_orders: bool,
    /// Set by `run`: the threads a seed's orders share (cores over the seeds run at once).
    threads: usize,
    /// Set by `run`: fresh nodes sync things, by seed (`with_syncs`). Pinned histories do not.
    sync: bool,
}

const SMALL: Cfg = Cfg { all_up_to: 4, every_held: false, random: 2, subsets: 1, split: 2, par_orders: false, threads: 1, sync: false };
const LARGE: Cfg = Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, par_orders: false, threads: 1, sync: false };
/// Every order of the whole set and 2 partial sets (`OSIS_ORDER_ALL_HELD`: of every held set),
/// every order with late parts too (6 commits: up to 720 orders).
const EXHAUST: Cfg = Cfg { all_up_to: 6, every_held: true, random: 0, subsets: 2, split: usize::MAX, par_orders: true, threads: 1, sync: false };
/// The same up to 5 commits (120 orders), for tier 1.
const EXHAUST_SMALL: Cfg = Cfg { all_up_to: 5, subsets: 1, ..EXHAUST };

/// The arrival orders of `held` tried: as made (the reference), reversed, every order of the
/// held commits after the setup when there are at most `all_up_to` (and the whole set is held,
/// unless `every_held`), and `random` shuffles of everything.
fn orders(played: &Played, held: &[usize], cfg: Cfg, rng: &mut Rng) -> Vec<Vec<usize>> {
    let n = held.len();
    let mut out = vec![held.to_vec(), held.iter().rev().copied().collect()];
    let rest: Vec<usize> = held.iter().copied().filter(|&i| i >= played.base).collect();
    if (n == played.packs.len() || cfg.every_held) && rest.len() <= cfg.all_up_to {
        for p in perms(rest.len()) {
            out.push((0..played.base).chain(p.into_iter().map(|i| rest[i])).collect());
        }
    }
    for _ in 0..cfg.random {
        let mut o = held.to_vec();
        for i in (1..n).rev() {
            o.swap(i, rng.below(i as u64 + 1) as usize);
        }
        out.push(o);
    }
    out
}

/// The held sets tried: everything, then `subsets` partial ones (alternately without one
/// writer's commits after the setup, as a node that never heard from it, and without a random
/// third of them); `usize::MAX`: every held set (all of the setup, any of the rest).
fn held_sets(played: &Played, subsets: usize, rng: &mut Rng) -> Vec<Vec<usize>> {
    let n = played.packs.len();
    let mut out = vec![(0..n).collect::<Vec<_>>()];
    if subsets == usize::MAX {
        // every subset of what follows the setup
        let rest = n - played.base;
        for m in (0..(1u64 << rest) - 1).rev() {
            out.push((0..n).filter(|&i| i < played.base || m >> (i - played.base) & 1 == 1).collect());
        }
        return out;
    }
    for j in 0..subsets {
        let peer = rng.below(3) as usize;
        let keep: Vec<usize> = (0..n).filter(|&i| i < played.base || if j % 2 == 0 { played.authors[i] != peer } else { rng.below(3) != 0 }).collect();
        if !out.contains(&keep) {
            out.push(keep);
        }
    }
    out
}

/// What a passing history reached.
#[derive(Clone, Debug, Default)]
struct Seen {
    orders: usize,
    /// Its steps' outcomes.
    tally: Tally,
    /// The reference node's pending commits, by reason, over the held sets.
    pending: BTreeMap<String, u64>,
    /// The reference node's commits with an invalid part, over the held sets.
    invalid: u64,
    /// Commits with a part on each aspect, the whole set held.
    aspects: BTreeMap<String, u64>,
    /// Commits the reference node held for missing deltas while it learned its syncs late.
    late_waits: u64,
}

impl Seen {
    fn add(&mut self, o: &Seen) {
        self.orders += o.orders;
        self.tally.add(&o.tally);
        self.invalid += o.invalid;
        self.late_waits += o.late_waits;
        for (k, v) in &o.pending {
            *self.pending.entry(k.clone()).or_default() += v;
        }
        for (k, v) in &o.aspects {
            *self.aspects.entry(k.clone()).or_default() += v;
        }
    }

    /// A run of many seeds that did not reach what the generators are for is a harness bug: the
    /// oracle would pass while testing nothing. Most steps commit, over 20 or more of them (one
    /// short history, a replay, may be mostly refused); 20 seeds or more reach an invalid part
    /// (no window of 2000 focused or 1000 short histories lacked one). `broad`: long `history`s
    /// reach every shape too (over 500 such seeds, no window lacked one; `focused_history` reaches
    /// `WaitDeltas` on 3% of seeds, none in 22% of 40-seed windows; 8-step histories rarely reach any).
    fn floors(&self, name: &str, seeds: usize, broad: bool) {
        let (n, m) = self.tally.totals();
        assert!(n < 20 || m * 2 >= n, "order::{name}: {m} of {n} commit steps made a commit:\n{}", self.tally.show());
        if seeds < 20 {
            return;
        }
        // a history with no role change or hostile commit (`seq_compact_history`) has none to reach
        let can_fall = ["Forged", "Demote", "Edge"].iter().any(|k| self.tally.kinds.contains_key(*k));
        assert!(!can_fall || self.invalid > 0, "order::{name}: no invalid part: {self:?}");
        if broad {
            assert!(self.pending.contains_key("WaitDeltas"), "order::{name}: nothing waited for deltas: {self:?}");
            assert!(self.late_waits > 0, "order::{name}: nothing waited for deltas with syncs learned late: {self:?}");
            for a in ["t:text.0", "t:docs.0", "t:list.0", "t:count.0", "t:map.0"] {
                assert!(self.aspects.contains_key(a), "order::{name}: no write on {a}: {self:?}");
            }
            assert!(self.pending.contains_key("MissingChain"), "order::{name}: no commit without its chain: {self:?}");
        }
    }
}

/// Whether this held set leaves, with every `Late` thing synced from the start, a commit on several
/// things or a role-class snapshot waiting whole: the cases where when the node learned it syncs a
/// thing still decides the read (issues/sync-learned-after-apply.md).
fn learned_late_wait(played: &Played, held: &[usize]) -> bool {
    let mut p = Peer::new(FRESH, played.now).unwrap();
    for t in played.sync.things() {
        p.engine.set_syncing(*t, true).unwrap();
    }
    for &i in held {
        let pk = &played.packs[i];
        let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    p.engine.pending().iter().any(|(id, _)| {
        played.packs.iter().find(|x| x.id == *id).is_some_and(|pk| {
            let h = osis_commit::CommitBlob::decode(&pk.bytes).unwrap().header;
            let several = h.aspects.iter().any(|a| a.tid != h.aspects[0].tid);
            (h.kind != osis_commit::Kind::Role && several) || matches!(h.kind, osis_commit::Kind::RosterSnapshot | osis_commit::Kind::RoleSnapshot)
        })
    })
}

/// Checks one history: what it reached, or the first mismatch found, described (a panic counts,
/// so it shrinks).
fn check(seed: u64, steps: &[Step], cfg: Cfg) -> Result<Seen, String> {
    caught(|| check_orders(seed, steps, cfg))
}

fn check_orders(seed: u64, steps: &[Step], cfg: Cfg) -> Result<Seen, String> {
    let played = play(seed, steps);
    let played = if cfg.sync { with_syncs(played, seed) } else { played };
    let mut rng = Rng(seed ^ 0x0de5_ab1e | 1);
    let mut seen = Seen { tally: played.tally.clone(), ..Seen::default() };
    let mut full: Option<Judged> = None;
    let n = played.packs.len();
    let split = played.packs.iter().any(|pk| osis_commit::CommitBlob::decode(&pk.bytes).is_ok_and(|b| b.parts.iter().any(|x| x.ai != b.parts[0].ai)));
    // `OSIS_ORDER_ALL_HELD`: every held set in exhaustive mode (about 2.3x the time)
    let subsets = if cfg.every_held && std::env::var("OSIS_ORDER_ALL_HELD").is_ok() { usize::MAX } else { cfg.subsets };
    let unsynced = Played { sync: Syncs::None, ..played.clone() };
    let synced = played;
    // which of the two the whole set was judged under: only that one's held sets are compared to it
    let mut full_of: Option<&Played> = None;
    for held in held_sets(&synced, subsets, &mut rng) {
        let played = if matches!(synced.sync, Syncs::Late { .. }) && learned_late_wait(&synced, &held) { &unsynced } else { &synced };
        let of = format!("held {held:?} of {n} commits (base {})", played.base);
        let o = oracle(played, &held);
        // a partial set, then the rest (both ways), ends where the whole set does
        if let Some(f) = full.as_ref().filter(|_| std::ptr::eq(played, full_of.unwrap_or(played))) {
            let rest: Vec<usize> = (0..n).filter(|i| !held.contains(i)).collect();
            for order in [held.iter().chain(&rest).copied().collect::<Vec<_>>(), held.iter().chain(rest.iter().rev()).copied().collect()] {
                let mut p = deliver(played, &order);
                let flips = |t: &str, a: &str| flipped(played, &(0..n).collect::<Vec<_>>(), None, t, a) || flipped(played, &order, None, t, a);
                let whole: Vec<usize> = (0..n).collect();
                if let Some(d) = alike_exchanged(played, f, &whole, &judged(&mut p, played), &order, None, &flips) {
                    return Err(format!("{of}, then the rest: order {order:?} vs the whole set as made: {d}"));
                }
            }
        }
        let orders = orders(played, &held, cfg, &mut rng);
        seen.orders += orders.len();
        // the reference, as made: its deaths dated as the spec allows, a reopen from the
        // persisted index and a rebuild judge alike (an open re-examines what pends)
        let mut p = deliver(played, &orders[0]);
        if let Some(d) = dating(&mut p, &o, played.now) {
            return Err(format!("{of}, as made: {d}"));
        }
        let now = judged_now(&mut p, &played.things);
        for l in now.part("pending").lines() {
            let why = l.split(' ').nth(1).unwrap_or(l).split('(').next().unwrap_or("");
            *seen.pending.entry(why.to_string()).or_default() += 1;
            seen.late_waits += u64::from(why == "WaitDeltas" && matches!(played.sync, Syncs::Late { .. }));
        }
        if full.is_none() {
            for id in p.engine.commit_ids() {
                for a in p.engine.header(&id).into_iter().flat_map(|h| h.aspects.clone()) {
                    *seen.aspects.entry(a.ak.as_str().to_string()).or_default() += 1;
                }
            }
        }
        p.engine.reload().unwrap();
        p.engine.reexamine().unwrap();
        if let Some(d) = first_diff(&now, &judged_now(&mut p, &played.things)) {
            return Err(format!("{of}, as made: reopen differs: {d}"));
        }
        p.engine.rebuild_index().unwrap();
        p.engine.reexamine().unwrap();
        // a rebuild recomputes deaths from the held bodies: dated otherwise, never earlier
        if let Some(d) = alike(&now, &judged_now(&mut p, &played.things), &|_, _| false).or_else(|| dating(&mut p, &o, played.now)) {
            return Err(format!("{of}, as made: rebuild differs: {d}"));
        }
        let mut want = now;
        let idx = index_later(&mut p, played);
        let invalid = idx.commits.values().filter(|c| c.valid.contains(&false)).count();
        seen.invalid += invalid as u64;
        if std::env::var("OSIS_ORDER_STATS").is_ok() {
            let carried: usize = idx.carried.values().map(Vec::len).sum();
            eprintln!("seed {seed}: {} of {} commits held ({} base), {} with an invalid part, {} carried groups, {} pending, {} things", held.len(), n, played.base, invalid, carried, want.part("pending").lines().count(), played.things.len());
        }
        want.index = Some(idx);
        if full.is_none() {
            full = Some(want.clone());
            full_of = Some(played);
        }
        // order `k` alike (and alike after a reopen), or with late parts (split by `rng`) alike
        let one = |k: usize, split_rng: Option<&mut Rng>| -> Result<(), String> {
            let order = &orders[k];
            let vs = format!("{of}: order #0 (as made, want) {held:?} vs order #{k}");
            if let Some(rng) = split_rng {
                let copy = rng.clone();
                let mut p = deliver_split(played, order, rng);
                let flips = |t: &str, a: &str| flipped(played, &orders[0], None, t, a) || flipped(played, order, Some(copy.clone()), t, a);
                return match dating(&mut p, &o, played.now).or_else(|| alike_exchanged(played, &want, &orders[0], &judged(&mut p, played), order, Some(copy.clone()), &flips)) {
                    Some(d) => Err(format!("{vs} with late parts (got) {order:?}: {d}")),
                    None => Ok(()),
                };
            }
            let mut p = deliver(played, order);
            if let Some(d) = dating(&mut p, &o, played.now) {
                return Err(format!("{of}, order #{k} {order:?}: {d}"));
            }
            let mut got = judged_now(&mut p, &played.things);
            p.engine.reload().unwrap();
            p.engine.reexamine().unwrap();
            if let Some(d) = first_diff(&got, &judged_now(&mut p, &played.things)) {
                return Err(format!("{of}, order #{k} {order:?}: reopen differs: {d}"));
            }
            got.index = Some(index_later(&mut p, played));
            match alike_exchanged(played, &want, &orders[0], &got, order, None, &|t, a| flipped(played, &orders[0], None, t, a) || flipped(played, order, None, t, a)) {
                Some(d) => Err(format!("{vs} (got) {order:?}: {d}")),
                None => Ok(()),
            }
        };
        // late parts only matter when a commit has parts on several aspects; without one the
        // sequential modes still deliver the first two again and re-examine (as before)
        let splits = if split || !cfg.par_orders { cfg.split.min(orders.len()) } else { 0 };
        if cfg.par_orders {
            // tasks: orders 1.. as they are, then 0.. with late parts, each split by its own rng
            let tasks: Vec<u64> = (1..orders.len() + splits).map(|x| x as u64).collect();
            let base = rng.0;
            let errs = par_map(&tasks, cfg.threads, |x| {
                let x = x as usize;
                caught(|| if x < orders.len() { one(x, None) } else { one(x - orders.len(), Some(&mut Rng(base ^ (x as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1))) })
            });
            if let Some(e) = errs.into_iter().find_map(Result::err) {
                return Err(e);
            }
        } else {
            for k in 1..orders.len() {
                one(k, None)?;
            }
            for k in 0..splits {
                one(k, Some(&mut rng))?;
            }
        }
    }
    Ok(seen)
}

/// Drops steps while the history still fails; the shortest failing history found.
fn shrink(seed: u64, mut steps: Vec<Step>, cfg: Cfg) -> (Vec<Step>, String) {
    let mut err = check(seed, &steps, cfg).unwrap_err();
    let mut i = 0;
    while i < steps.len() {
        let mut fewer = steps.clone();
        fewer.remove(i);
        match check(seed, &fewer, cfg) {
            Err(e) => {
                steps = fewer;
                err = e;
            }
            Ok(_) => i += 1,
        }
    }
    (steps, err)
}

fn history(seed: u64, len: usize, _: Cfg) -> Vec<Step> {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    (0..len).map(|_| random_step(&mut rng)).collect()
}

/// A short history aimed at deaths and validity together: writes of two bounded aspects
/// (keep-at-most ones by the owner, keep-at-least ones mostly by the others), their compactions, undo, demotions
/// and grants, nested writes under others' entries, one clock pulled ahead (a write made later
/// by a peer behind sorts earlier), sends and syncs. Cut to the longest prefix making at most
/// `cfg.all_up_to` commits after the setup (a prefix of a history plays as its start).
fn focused_history(seed: u64, len: usize, cfg: Cfg) -> Vec<Step> {
    let mut rng = Rng(seed.wrapping_mul(0xa076_1d64_78bd_642f) | 1);
    // two bounded aspects per history, so writes, compactions and undos meet
    const BOUNDED: [u8; 10] = [16, 17, 18, 19, 20, 21, 22, 23, 24, 26];
    let ops = [rng.pick(&BOUNDED), rng.pick(&BOUNDED)];
    let steps: Vec<Step> = (0..len)
        .map(|_| {
            let by = rng.below(3) as usize;
            let t = rng.below(2) as usize;
            let op = rng.pick(&ops);
            match rng.below(22) {
                // a hostile commit among the rest: its parts wait, or judge invalid, in every order
                20 | 21 => Step::Forged { by, a: t, b: rng.below(2) as usize, how: rng.below(5) as u8, op, k: rng.below(2) as u8, v: rng.below(10) as u8 },
                0..=6 => Step::Aim(Box::new(Step::Typed { by: if (17..=20).contains(&op) || rng.below(3) == 0 { 0 } else { 1 + rng.below(2) as usize }, t, op, k: rng.below(2) as u8, v: rng.below(10) as u8 })),
                7 | 8 => Step::Aim(Box::new(Step::Compact { by: rng.pick(&[0, 0, by]), t, op })),
                9 | 10 => Step::Aim(Box::new(Step::Undo { by: rng.pick(&[0, by]), back: rng.below(3) as u8 })),
                11 | 12 => Step::Aim(Box::new(Step::Demote { by: rng.pick(&[0, 0, 2]), t, holder: rng.pick(&[1, 2]), at: rng.below(4) as u8, to_read: rng.below(3) == 0 })),
                13 => Step::Edge { by: 0, t, holder: rng.pick(&[1, 2]), role: rng.pick(&[None, Some(Role::Read), Some(Role::Write)]) },
                14 => Step::Aim(Box::new(Step::Nested { by, other: (by + 1 + rng.below(2) as usize) % 3, t, k: rng.below(2) as u8, text: rng.below(2) == 0, compact: rng.below(2) == 0, also: rng.below(3) == 0 })),
                15 | 16 => Step::Advance { who: Some(rng.below(3) as usize), ms: 1 + rng.below(3_000) },
                17 => Step::Advance { who: None, ms: HOUR / 4 + rng.below(HOUR) },
                18 => {
                    let from = rng.below(3) as usize;
                    Step::Send { from, to: (from + 1 + rng.below(2) as usize) % 3, back: rng.below(2) as u8 }
                }
                _ => {
                    let from = rng.below(3) as usize;
                    Step::Sync { from, to: (from + 1 + rng.below(2) as usize) % 3 }
                }
            }
        })
        .collect();
    // commits made grow with the prefix: the longest prefix within the bound
    let fits = |k: usize| {
        // a play that panics is one `check` reports
        caught(|| {
            let p = play(seed, &steps[..k]);
            Ok::<_, String>(p.packs.len() - p.base <= cfg.all_up_to)
        })
        .unwrap_or(true)
    };
    let (mut lo, mut hi) = (0, steps.len());
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if fits(mid) { lo = mid } else { hi = mid - 1 }
    }
    steps[..lo].to_vec()
}

/// Sequence writes by every peer, undo, sends and syncs and compactions of those sequences: no
/// role change, no hostile commit, so nothing falls. Three ops per history, so they meet.
fn seq_compact_history(seed: u64, len: usize, _: Cfg) -> Vec<Step> {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    const SEQ: [u8; 8] = [8, 9, 10, 11, 14, 23, 24, 26];
    let ops = [rng.pick(&SEQ), rng.pick(&SEQ), rng.pick(&SEQ)];
    (0..len)
        .map(|_| {
            let by = rng.below(3) as usize;
            let op = rng.pick(&ops);
            let to = (by + 1 + rng.below(2) as usize) % 3;
            match rng.below(10) {
                0..=4 => Step::Aim(Box::new(Step::Typed { by, t: 0, op, k: rng.below(2) as u8, v: rng.below(10) as u8 })),
                5 | 6 => Step::Compact { by, t: 0, op },
                7 => Step::Aim(Box::new(Step::Undo { by, back: rng.below(3) as u8 })),
                8 => Step::Send { from: by, to, back: rng.below(2) as u8 },
                _ => Step::Sync { from: by, to },
            }
        })
        .collect()
}

/// Checks the histories `gen` makes from `seeds` (one seed per task, a thread per core), shrinks
/// every failing one and reports them all, each with the command that replays it.
/// `OSIS_ORDER_SEED=n` runs only seed n; `OSIS_ORDER_START=n`, `OSIS_ORDER_SEEDS=n` and
/// `OSIS_ORDER_LEN=n` set the first seed, how many seeds and steps; a seed's history and orders
/// depend on the seed, the length and the test alone.
fn run(name: &str, seeds: std::ops::Range<u64>, len: usize, cfg: Cfg, generate: fn(u64, usize, Cfg) -> Vec<Step>) {
    use osis_base::testenv::{Seeds, u64_var};
    let only = u64_var("OSIS_ORDER_SEED");
    let range = Seeds::from_env("OSIS_ORDER_START", "OSIS_ORDER_SEEDS", seeds);
    let len = u64_var("OSIS_ORDER_LEN").map_or(len, |n| n as usize);
    let seeds: Vec<u64> = match only {
        Some(o) => vec![o],
        None => range.range.clone().collect(),
    };
    let settings: Vec<String> = std::env::vars().filter(|(k, _)| k.starts_with("OSIS_ORDER_")).map(|(k, v)| format!("{k}={v}")).collect();
    let t0 = std::time::Instant::now();
    // seeds on a thread per core; with fewer seeds than cores, a seed's orders share the rest
    let outer = threads("OSIS_ORDER_THREADS").min(seeds.len()).max(1);
    let cfg = Cfg { threads: if cfg.par_orders { threads("OSIS_ORDER_THREADS").div_ceil(outer) } else { 1 }, sync: true, ..cfg };
    let results = par_map(&seeds, outer, |seed| {
        let steps = generate(seed, len, cfg);
        if std::env::var("OSIS_ORDER_STATS").is_ok() {
            eprintln!("seed {seed}: vec!{steps:?}");
        }
        let r = check(seed, &steps, cfg);
        let fail = r.as_ref().is_err().then(|| {
            let (steps, err) = shrink(seed, steps, cfg);
            let msg = format!("seed {seed} (replay: OSIS_ORDER_SEED={seed} OSIS_ORDER_LEN={len} cargo test --workspace --test it order::{name} -- --include-ignored; shrunk for check({seed}, &h, {cfg:?})): h = vec!{steps:?}\n{err}");
            eprintln!("{msg}\n");
            msg
        });
        (r.unwrap_or_default(), fail)
    });
    let mut seen = Seen::default();
    for r in &results {
        seen.add(&r.0);
    }
    let tried = seen.orders;
    let fails: Vec<String> = results.into_iter().filter_map(|x| x.1).collect();
    let summary = format!("order::{name}: {} seeds from {}, {len} steps, {tried} orders in the passing ones, {} failing, {:.1} s (settings: {settings:?})", seeds.len(), seeds.first().copied().unwrap_or(0), fails.len(), t0.elapsed().as_secs_f64());
    // always shown: the order counts are what a passing run is read for
    osis_base::testenv::visible(true, &summary);
    if std::env::var("OSIS_ORDER_STATS").is_ok() {
        eprintln!("{}\npending {:?}, invalid {}, aspects {:?}", seen.tally.show(), seen.pending, seen.invalid, seen.aspects);
    }
    assert!(fails.is_empty(), "{summary}\n{} of {} histories judged differently by arrival order:\n{}", fails.len(), seeds.len(), fails.join("\n\n"));
    seen.floors(name, seeds.len(), !cfg.par_orders && len >= 60);
}

// spec/permissions.md §5.2, spec/crdt.md §4.6: 2's snapshot, invalid once 0 lowers 2 to read,
// gave 1's text creations (1's put not held); stripping them leaves no record of them, as at a
// node that never joined the snapshot. Seed 1028 (was issues/seq-bare-records-order.md).
#[test]
fn seq_stripped_copies_leave_no_records_spec_crdt_4_6() {
    use Step::*;
    let h = vec![Nested { by: 1, other: 2, t: 0, k: 1, text: true, compact: true, also: false }, Edge { by: 0, t: 0, holder: 2, role: Some(Role::Read) }];
    let played = play(1028, &h);
    // without 1's put: the entry's creation is held only through 2's snapshot
    let held: Vec<usize> = (0..played.packs.len()).filter(|i| *i != played.base).collect();
    let state = |order: &[usize]| {
        let mut p = deliver(&played, order);
        format!("{:?}", p.engine.state(&played.things[0], &ak("t:docs.0")).unwrap())
    };
    let as_made = state(&held);
    assert_eq!(as_made, state(&held.iter().rev().copied().collect::<Vec<_>>()));
    assert!(!as_made.contains("created: None, content: None, pos: [], deleted: None"), "no bare record: {as_made}");
}

// spec/crdt.md §4.8, spec/commits.md §5: a kept text's insert dies at its delete's `ts` whether
// the delete is held after it or before it. Seed 1054 (was issues/seq-death-delete-first.md).
#[test]
fn seq_death_delete_first_spec_crdt_4_8() {
    use Step::*;
    // on an empty text the first inserts (`fit`), the second deletes it
    let h = vec![Typed { by: 0, t: 0, op: 24, k: 0, v: 6 }, Typed { by: 0, t: 0, op: 24, k: 0, v: 9 }];
    let played = play(1054, &h);
    let b = played.base;
    let insert = played.packs[b].id;
    let death = |order: Vec<usize>| deliver(&played, &order).engine.deaths(&insert, &played.things[0], &ak("t:text.0")).unwrap();
    let after = death((0..b + 2).collect());
    assert!(after.is_some(), "the delete held last dates it");
    assert_eq!(death((0..b).chain([b + 1, b]).collect()), after, "the delete held first dates it alike");
}

// spec/crdt.md §5.6 (the records of one dot are one entry for superseding), spec/commits.md §5:
// order seed 338806. An expiring put of k0, a kept write of k1, a snapshot (k0's records
// key-erased, value-less), then a put into k0's entry (nested writes, keyed). A node holding the
// snapshot and the later put, not the expiring put, dates the snapshot's body at the later put: its
// value-less copies in the key-erased record are beaten by the keyed record's writes (was: no
// death, the records never met in the state; `dating` skipped `t:map.0` snapshots).
#[test]
fn map_death_across_key_erased_record_spec_crdt_5_6() {
    use Step::*;
    let h = vec![Write { by: 0, t: 0, op: 28, k: 0, v: 3 }, Typed { by: 0, t: 0, op: 22, k: 1, v: 2 }, Compact { by: 0, t: 0, op: 28 }, Nested { by: 0, other: 2, t: 0, k: 0, text: false, compact: false, also: false }];
    let played = play(338806, &h);
    let snap = played.base + 2;
    let held: Vec<usize> = (0..played.base).chain([snap, snap + 1]).collect();
    let o = oracle(&played, &held);
    let mut p = deliver(&played, &held);
    let (id, t, a) = (played.packs[snap].id, played.things[0], ak("t:map.0"));
    let want = o.deaths[&(id, t, a.clone())];
    assert!(want.is_some(), "the oracle dates it");
    assert_eq!(p.engine.deaths(&id, &t, &a).unwrap(), want);
    check(338806, &h, LARGE).unwrap();
}

// spec/commits.md §4: not only hostile, not only chains: one commit on G and H, at a node lacking
// H's creation record. Whichever part comes first, H's waits alone and G's applies.
#[test]
fn chainless_part_creation_missing_spec_commits_4() {
    use Step::*;
    let h = vec![New { by: 0, parent: 0, write: true }, Two { by: 0, a: 0, b: 1, v: 7 }];
    let played = play(1054, &h);
    let last = played.packs.last().unwrap();
    let part = |tid: Tid| {
        let mut b = osis_commit::CommitBlob::decode(&last.bytes).unwrap();
        let hd = b.header.clone();
        b.parts.retain(|x| hd.aspects[x.ai].tid == tid);
        b.encode()
    };
    let read = |first: Tid, second: Tid| {
        let mut p = Peer::new(FRESH, played.now).unwrap();
        for pk in &played.packs[..played.base] {
            p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
        }
        for t in [first, second] {
            let _ = p.engine.ingest(&part(t), last.blobs.clone());
        }
        p.engine.reexamine().unwrap();
        (p.engine.get(&played.things[0], &ak("t:reg.0")).unwrap(), p.engine.pending().len())
    };
    let (g, t) = (played.things[0], played.things[1]);
    assert_eq!(read(g, t), read(t, g));
}

// spec/commits.md §4: one commit on two aspects of G, one part held. A node syncing G first and one
// syncing G after the part came read alike: the part waits for its thing's other part in both.
#[test]
fn sync_learned_after_part_reads_alike_spec_commits_4() {
    use Step::*;
    let h = vec![Nested { by: 0, other: 1, t: 0, k: 0, text: false, compact: false, also: true }];
    let played = play(5, &h);
    let pk = &played.packs[played.base];
    let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    assert!(b.parts.iter().any(|x| x.ai != b.parts[0].ai), "two aspects");
    let keep = b.parts[0].ai;
    b.parts.retain(|x| x.ai == keep);
    let part = b.encode();
    let g = played.things[0];
    let node = |sync_first: bool| {
        let mut p = Peer::new(FRESH, played.now).unwrap();
        for pk in &played.packs[..played.base] {
            p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
        }
        if sync_first {
            p.engine.set_syncing(g, true).unwrap();
        }
        let _ = p.engine.ingest(&part, pk.blobs.clone());
        p.engine.set_syncing(g, true).unwrap();
        judged_now(&mut p, &played.things).parts
    };
    assert_eq!(node(true), node(false));
}


// spec/requirements.md Decentralization, spec/permissions.md §5 and §5.2, spec/crdt.md §4.6:
// small histories, every arrival order of what follows the setup, plus shuffles of everything.
#[test]
fn arrival_order_alike_small_spec_permissions_5_2() {
    run("arrival_order_alike_small_spec_permissions_5_2", 0..4, 8, SMALL, history);
}

// The same at size: long histories, random orders.
#[test]
#[ignore = "tier 2"]
fn arrival_order_alike_large_spec_permissions_5_2() {
    run("arrival_order_alike_large_spec_permissions_5_2", 1000..1060, 60, LARGE, history);
}

// spec/requirements.md Decentralization, spec/crdt.md §4.8: short histories mixing bounded
// writes, compactions, undo, demotions and late writes, every arrival order (the setup first)
// of the whole set and a partial one, each with late parts too.
#[test]
fn arrival_order_exhaustive_small_spec_crdt_4_8() {
    run("arrival_order_exhaustive_small_spec_crdt_4_8", 0..3, 30, EXHAUST_SMALL, focused_history);
}

// The same over more histories, up to 6 commits.
#[test]
#[ignore = "tier 2"]
fn arrival_order_exhaustive_large_spec_crdt_4_8() {
    run("arrival_order_exhaustive_large_spec_crdt_4_8", 2023..2063, 30, EXHAUST, focused_history);
}

/// A history of writes under keep at most, some with a part under default retention, on G.
fn carrierless_history(seed: u64, len: usize) -> Vec<Step> {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut steps = vec![Step::Sync { from: 0, to: 1 }];
    for _ in 0..len {
        let (by, op, k, v) = (rng.below(2) as usize, rng.pick(&[17, 18, 19, 19, 20]), rng.below(3) as u8, rng.below(10) as u8);
        steps.push(match rng.below(8) {
            0..=2 => Step::Mixed { by, t: 0, op, k, v },
            3..=5 => Step::Write { by, t: 0, op, k, v },
            6 => Step::Sync { from: by, to: 1 - by },
            _ => Step::Advance { who: None, ms: 1 + rng.below(1_000) },
        });
    }
    steps
}

/// `pk` without the parts `gone` of it holds: `None` when that leaves no part.
fn without(pk: &Package, gone: &BTreeSet<(CommitId, usize)>) -> Option<Vec<u8>> {
    let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let had = !b.parts.is_empty();
    b.parts.retain(|p| !gone.contains(&(pk.id, p.ai)));
    (b.parts.len() + usize::from(!had) > 0).then(|| b.encode())
}

/// The invariant `apply::at_most_bound` relies on (spec/commits.md §4): whether a part under keep
/// at most arrives never, or after its commit applied, or with the rest, in any order, the node
/// ends alike and nothing pends, for every part a holder dropped with no live write (what hosts
/// delete with no carrier). A part with no commit on its aspect stamped as late keeps its commit
/// waiting at any clock.
fn carrierless_check(seed: u64, len: usize) -> Result<usize, String> {
    let played = play(seed, &carrierless_history(seed, len));
    let n = played.packs.len();
    let mut rng = Rng(seed ^ 0x0de5_ab1e | 1);
    let later = WallMs(played.now.0 + 24 * HOUR);
    let dump = |p: &mut Peer| judged_now(p, &played.things);
    let settle = |p: &mut Peer| {
        p.clock.set(later);
        p.engine.tick().unwrap();
    };
    // only a synced thing's missing part makes its commit wait
    let syncing_node = || {
        let mut p = Peer::new(FRESH, played.now).unwrap();
        p.engine.set_syncing(played.things[0], true).unwrap();
        p
    };
    let mut full = deliver(&played, &(0..n).collect::<Vec<_>>());
    settle(&mut full);
    let want = dump(&mut full);
    if !want.part("pending").is_empty() {
        return Err(format!("the whole set pends: {}", want.part("pending")));
    }
    // what a holder dropped with no live write, and the parts nothing on their aspect is as late as
    let headers: Vec<osis_commit::Header> = played.packs.iter().map(|pk| osis_commit::CommitBlob::decode(&pk.bytes).unwrap().header).collect();
    let (mut gone, mut last) = (BTreeSet::new(), Vec::new());
    for (i, h) in headers.iter().enumerate().skip(played.base) {
        for (ai, a) in h.aspects.iter().enumerate() {
            if a.retention.at_most.rel.is_none() {
                continue;
            }
            if !full.engine.body_not_dropped(&played.packs[i].id, &a.tid, &a.ak) && !full.engine.body_live(&played.packs[i].id, &a.tid, &a.ak).unwrap() {
                gone.insert((played.packs[i].id, ai));
            }
            let on = |o: &osis_commit::Header| o.aspects.iter().any(|x| x.tid == a.tid && x.ak == a.ak);
            if h.aspects.len() > 1 && !headers.iter().enumerate().any(|(j, o)| j != i && o.ts >= h.ts && on(o)) {
                last.push((played.packs[i].id, ai));
            }
        }
    }
    let shuffled = |rng: &mut Rng| {
        let mut o: Vec<usize> = (played.base..n).collect();
        for x in (1..o.len()).rev() {
            o.swap(x, rng.below(x as u64 + 1) as usize);
        }
        (0..played.base).chain(o).collect::<Vec<usize>>()
    };
    let mut tried = 0;
    for _ in 0..4 {
        tried += 1;
        // never: the bodies are gone
        let order = shuffled(&mut rng);
        let mut p = syncing_node();
        for &i in &order {
            if let Some(b) = without(&played.packs[i], &gone) {
                let _ = p.engine.ingest(&b, played.packs[i].blobs.clone());
            }
        }
        let _ = p.engine.reexamine();
        settle(&mut p);
        let got = dump(&mut p);
        let vs = format!("order {order:?}, withheld {gone:?}");
        if !got.part("pending").is_empty() {
            return Err(format!("{vs}: pends: {}", got.part("pending")));
        }
        for part in ["reads", "states"] {
            if got.part(part) != want.part(part) {
                return Err(format!("{vs}: {part} differ:\n{}\nvs\n{}", want.part(part), got.part(part)));
            }
        }
        // late: a copy still comes, in another order
        let order = shuffled(&mut rng);
        for &i in &order {
            let _ = p.engine.ingest(&played.packs[i].bytes, played.packs[i].blobs.clone());
        }
        let _ = p.engine.reexamine();
        let got = dump(&mut p);
        for part in ["reads", "states", "pending"] {
            if got.part(part) != want.part(part) {
                return Err(format!("{vs}, then late in {order:?}: {part} differ:\n{}\nvs\n{}", want.part(part), got.part(part)));
            }
        }
    }
    for (id, ai) in last {
        let mut p = syncing_node();
        let held = BTreeSet::from([(id, ai)]);
        for pk in &played.packs {
            if let Some(b) = without(pk, &held) {
                let _ = p.engine.ingest(&b, pk.blobs.clone());
            }
        }
        settle(&mut p);
        if !p.engine.pending().iter().any(|(c, r)| *c == id && *r == osis_node::Reason::WaitDeltas) {
            return Err(format!("{id:?} part {ai} is live or may be, nothing on its aspect as late, and did not wait: {:?}", p.engine.pending()));
        }
    }
    Ok(tried)
}

fn carrierless_run(name: &str, seeds: std::ops::Range<u64>, len: usize) {
    use osis_base::testenv::{Seeds, u64_var};
    let seeds: Vec<u64> = match u64_var("OSIS_ORDER_SEED") {
        Some(o) => vec![o],
        None => Seeds::from_env("OSIS_ORDER_START", "OSIS_ORDER_SEEDS", seeds).range.collect(),
    };
    let results = par_map(&seeds, threads("OSIS_ORDER_THREADS").min(seeds.len()).max(1), |seed| caught(|| carrierless_check(seed, len)).map_err(|e| format!("seed {seed} (replay: OSIS_ORDER_SEED={seed}, order::{name}): {e}")));
    let fails: Vec<String> = results.into_iter().filter_map(Result::err).collect();
    assert!(fails.is_empty(), "{} of {} failing:\n{}", fails.len(), seeds.len(), fails.join("\n\n"));
}

// spec/commits.md §4 (a delta past its keep-at-most bound counts as held), §5: `carrierless_check`.
#[test]
fn carrierless_part_alike_small_spec_commits_4() {
    carrierless_run("carrierless_part_alike_small_spec_commits_4", 0..12, 14);
}

// The same over more histories, longer.
#[test]
#[ignore = "tier 2"]
fn carrierless_part_alike_large_spec_commits_4() {
    carrierless_run("carrierless_part_alike_large_spec_commits_4", 1000..1200, 30);
}

/// A history for `new_device_alike`: a random one with, in its middle, writer 1's commits
/// synced to the owner and compacted there, and at its end the owner's demotion of writer 1
/// (its frontier as of a random point among 1's writes).
fn device_history(seed: u64, len: usize, cfg: Cfg) -> Vec<Step> {
    let mut steps = history(seed, len, cfg);
    let mut rng = Rng(seed.wrapping_mul(0xd1b5_4a32_d192_ed03) | 1);
    let at = steps.len() / 2;
    let op = rng.below(OPS as u64) as u8;
    steps.splice(at..at, [Step::Write { by: 1, t: 0, op, k: rng.below(3) as u8, v: rng.below(10) as u8 }, Step::Sync { from: 1, to: 0 }, Step::Advance { who: None, ms: 1_000 }, Step::Compact { by: 0, t: 0, op }]);
    steps.push(Step::Advance { who: None, ms: 1_000 });
    steps.push(Step::Demote { by: 0, t: 0, holder: 1, at: rng.below(6) as u8, to_read: false });
    steps
}

/// Checks owner decision (a)'s new-device equivalence (spec/permissions.md §5.1: a frontier lists
/// commit IDs, leaving out commits covered at the demoter; §5.2: a valid snapshot vouches for
/// what it carries): a node holding every body and a fresh node holding only what hosts keep
/// once covered bodies go (every role commit and snapshot whole; each other commit without its
/// parts the first node finds covered by a held snapshot, or not at all when none is left) read
/// every aspect and roster alike. Both keep every body past its keep-at-most bound, so only
/// coverage tells them apart.
fn check_new_device(seed: u64, steps: &[Step]) -> Result<(usize, usize), String> {
    let played = play(seed, steps);
    let ingest = |p: &mut Peer, bytes: &[u8], pk: &Package| {
        let _ = p.engine.ingest(bytes, pk.blobs.clone());
    };
    let mut full = Peer::new(FRESH, played.now).unwrap();
    full.engine.keep_bodies(true);
    for pk in &played.packs {
        ingest(&mut full, &pk.bytes, pk);
    }
    full.engine.reexamine().unwrap();
    let ids = full.engine.commit_ids();
    let snaps: Vec<(CommitId, Tid, Ak)> = ids.iter().filter_map(|c| full.engine.header(c).filter(|h| h.kind.is_compaction()).map(|h| h.aspects.iter().map(|a| (*c, a.tid, a.ak.clone())).collect::<Vec<_>>())).flatten().collect();
    let mut fresh = Peer::new(FRESH, played.now).unwrap();
    fresh.engine.keep_bodies(true);
    let mut left_out = (0, 0);
    for pk in &played.packs {
        let Some(h) = full.engine.header(&pk.id) else {
            ingest(&mut fresh, &pk.bytes, pk);
            continue;
        };
        if h.kind.is_role() || h.kind.is_compaction() {
            ingest(&mut fresh, &pk.bytes, pk);
            continue;
        }
        let covered: BTreeSet<usize> = (0..h.aspects.len())
            .filter(|ai| {
                let a = &h.aspects[*ai];
                snaps.iter().any(|(s, t, k)| *t == a.tid && *k == a.ak && full.engine.covered(s, &pk.id, t, k).unwrap() == Some(true))
            })
            .collect();
        let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        let had = !b.parts.is_empty();
        b.parts.retain(|p| !covered.contains(&p.ai));
        // the parts left out, and those of them invalid here (their writes only vouched for)
        left_out.0 += covered.len();
        left_out.1 += covered.iter().filter(|ai| full.engine.body_valid(&pk.id, &h.aspects[**ai].tid, &h.aspects[**ai].ak) == Some(false)).count();
        if had && b.parts.is_empty() {
            continue;
        }
        ingest(&mut fresh, &b.encode(), pk);
    }
    fresh.engine.reexamine().unwrap();
    for (t, a) in full.engine.all_aspects().unwrap() {
        let (want, got) = (full.engine.get(&t, &a).unwrap(), fresh.engine.get(&t, &a).unwrap());
        if want != got {
            return Err(format!("{t:?} {}: every body {want:?}, after covered drops {got:?}", a.as_str()));
        }
    }
    for t in &played.things {
        if full.engine.roster(t) != fresh.engine.roster(t) {
            return Err(format!("roster of {t:?}: {:?} vs {:?}", full.engine.roster(t), fresh.engine.roster(t)));
        }
    }
    Ok(left_out)
}

/// Runs `check_new_device` over `seeds` (`OSIS_ORDER_START`, `OSIS_ORDER_SEEDS`, `OSIS_ORDER_SEED`
/// and `OSIS_ORDER_LEN` as for `run`), shrinking each failing history.
fn run_new_device(name: &str, seeds: std::ops::Range<u64>, len: usize) {
    use osis_base::testenv::{Seeds, u64_var};
    let range = Seeds::from_env("OSIS_ORDER_START", "OSIS_ORDER_SEEDS", seeds);
    let seeds: Vec<u64> = match u64_var("OSIS_ORDER_SEED") {
        Some(o) => vec![o],
        None => range.range.clone().collect(),
    };
    let len = u64_var("OSIS_ORDER_LEN").map_or(len, |n| n as usize);
    let check = |seed: u64, steps: &[Step]| caught(|| check_new_device(seed, steps));
    let results = par_map(&seeds, threads("OSIS_ORDER_THREADS"), |seed| {
        let mut steps = device_history(seed, len, SMALL);
        match check(seed, &steps) {
            Ok(n) => (n, None),
            Err(mut err) => {
                let mut i = 0;
                while i < steps.len() {
                    let mut fewer = steps.clone();
                    fewer.remove(i);
                    match check(seed, &fewer) {
                        Err(e) => (steps, err) = (fewer, e),
                        Ok(_) => i += 1,
                    }
                }
                ((0, 0), Some(format!("seed {seed}: h = vec!{steps:?}\n{err}")))
            }
        }
    });
    let left_out: usize = results.iter().map(|x| x.0.0).sum();
    let invalid: usize = results.iter().map(|x| x.0.1).sum();
    let fails: Vec<String> = results.into_iter().filter_map(|x| x.1).collect();
    let summary = format!("order::{name}: {} seeds from {}, {len} steps, {left_out} covered parts left out ({invalid} invalid), {} failing", seeds.len(), seeds.first().copied().unwrap_or(0), fails.len());
    osis_base::testenv::visible(true, &summary);
    assert!(fails.is_empty(), "{summary}\n{}", fails.join("\n\n"));
}

// spec/permissions.md §5.1 (frontier by commit ID), §5.2 (snapshots vouch), owner decision (a)
// (issues/session-sources.md rule 7): a fresh node holding the demotion, the snapshots and the
// uncovered bodies reads as a node holding every body.
#[test]
fn new_device_alike_spec_permissions_5_1() {
    run_new_device("new_device_alike_spec_permissions_5_1", 0..16, 20);
}

// The same at size.
#[test]
#[ignore = "tier 2"]
fn new_device_alike_large_spec_permissions_5_1() {
    run_new_device("new_device_alike_large_spec_permissions_5_1", 0..256, 40);
}

// spec/requirements.md Decentralization, spec/crdt.md §5.7: the same for sequences compacted with
// nothing fallen (no role change, no hostile commit): several writers, undo, partial holders.
#[test]
#[ignore = "tier 2"]
fn arrival_order_seq_compact_large_spec_crdt_5_7() {
    run("arrival_order_seq_compact_large_spec_crdt_5_7", 3000..3020, 40, LARGE, seq_compact_history);
}

// spec/crdt.md §5.7: 0 inserts `v5` and deletes the `5`, 1 compacts (its snapshot has no char for
// the `5`), 0 undoes the delete. Held, the snapshot and the undelete: both orders read `v5`.
#[test]
fn undelete_with_snapshot_of_deleted_spec_crdt_5_7() {
    use Step::*;
    let tick = Advance { who: None, ms: 1 };
    let h = vec![Typed { by: 0, t: 0, op: 10, k: 0, v: 5 }, tick.clone(), Typed { by: 0, t: 0, op: 11, k: 0, v: 1 }, Sync { from: 0, to: 1 }, tick.clone(), Compact { by: 1, t: 0, op: 11 }, tick, Undo { by: 0, back: 0 }];
    let played = play(5, &h);
    let (b, n) = (played.base, played.packs.len());
    let read = |rest: [usize; 2]| deliver(&played, &(0..b).chain(rest).collect::<Vec<_>>()).engine.get(&played.things[0], &ak("t:text.0")).unwrap();
    assert_eq!(read([n - 2, n - 1]), read([n - 1, n - 2]));
}

// spec/commits.md §5, spec/crdt.md §4.8 (deaths dated per node, never early): three writes of a
// kept register, X < Y < Z; delivered Z first, X dies at Z (the first superseder held there),
// as made at Y; both no earlier than the earliest superseder.
#[test]
fn deaths_dated_per_node_spec_commits_5() {
    use Step::*;
    let h: Vec<Step> = (0..3).flat_map(|by| [Write { by, t: 0, op: 16, k: 0, v: by as u8 }, Advance { who: None, ms: 1000 }]).collect();
    let played = play(16, &h);
    let n = played.packs.len();
    let o = oracle(&played, &(0..n).collect::<Vec<_>>());
    let mut seen = Vec::new();
    for order in [(0..n).collect::<Vec<_>>(), (0..played.base).chain((played.base..n).rev()).collect()] {
        let mut p = deliver(&played, &order);
        assert_eq!(dating(&mut p, &o, played.now), None, "order {order:?}");
        seen.push(deaths_of(&mut p.engine).into_iter().filter(|x| x.1.is_some()).collect::<Vec<_>>());
    }
    // X: Y's `ts` as made, Z's reversed; Y: Z's both ways (by commit, not by ID order)
    let (x, y) = (played.packs[played.base].id, played.packs[played.base + 1].id);
    let at = |i: usize, c: CommitId| seen[i].iter().find(|e| e.0.0 == c).and_then(|e| e.1);
    assert!(seen[0].len() == 2 && at(0, x).zip(at(1, x)).is_some_and(|(a, b)| a.0 < b.0) && at(0, y).is_some() && at(0, y) == at(1, y), "{seen:?}");
}

// spec/crdt.md §4.8, order seed 7855 (exhaustive, shrunk): W1 and W2 put one `t:gonemap.0` key, U
// undoes W1 (removes the entry), W3 puts it again, S compacts. A recompute holding every body
// dates W1 (W2, U): S's copy of U's removal kills W1's entry creation, which a recompute skipped
// as a snapshot's copy re-dying (W1's value, dead at W2, shares its stamp). Delivered W1, W2,
// S, U, W3 or in order, the dates are never earlier.
#[test]
fn copy_kills_write_sharing_a_dead_stamp_spec_crdt_4_8() {
    use Step::*;
    let h = vec![Write { by: 0, t: 1, op: 19, k: 1, v: 1 }, Write { by: 0, t: 1, op: 19, k: 1, v: 0 }, Undo { by: 0, back: 1 }, Write { by: 0, t: 1, op: 19, k: 1, v: 2 }, Compact { by: 0, t: 0, op: 19 }];
    let played = play(7855, &h);
    let b = played.base;
    let o = oracle(&played, &(0..played.packs.len()).collect::<Vec<_>>());
    assert!(o.deaths.values().any(|d| d.is_some_and(|d| d.0 < d.1)), "{:?}", o.deaths);
    for rel in [[0, 1, 2, 3, 4], [0, 1, 4, 2, 3]] {
        let mut p = deliver(&played, &(0..b).chain(rel.iter().map(|i| b + i)).collect::<Vec<_>>());
        assert_eq!(dating(&mut p, &o, played.now), None, "order {rel:?}");
    }
}

// spec/crdt.md §4.6, spec/permissions.md §5.2: histories the harness found, shrunk (each
// fixed). Seed 1038: C puts an entry, B (sent it alone) writes inside it and compacts, A lowers
// C to read (an audit with no frontier): a node holding B's write and snapshot but not C's
// creation kept the entry when B's write came first (was issues/unmerge-nested-write-order.md).
#[test]
fn arrival_order_found_histories_spec_crdt_4_6() {
    use Step::*;
    let mut cases = Vec::new();
    // seed 83156 (spec/commits.md §5): a role commit's part applied while its other thing's record
    // was away, so its body's class changed when the record came; the death recorded under the
    // old class was lost
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![aim(Nested { by: 0, other: 2, t: 2, k: 2, text: true, compact: true, also: false }), aim(Demote { by: 0, t: 6, holder: 1, at: 3, to_read: true }), aim(Demote { by: 0, t: 5, holder: 2, at: 4, to_read: true }), aim(Typed { by: 0, t: 6, op: 11, k: 0, v: 4 }), aim(NestedItem { by: 1, other: 0, t: 6, k: 0, compact: true, also: false }), NewTop { by: 0 }, Forged { by: 0, a: 7, b: 4, how: 2, op: 5, k: 2, v: 0 }, aim(Nested { by: 1, other: 0, t: 0, k: 1, text: true, compact: true, also: true }), aim(New { by: 0, parent: 7, write: true }), aim(Roster { by: 0, t: 3 })];
    cases.push((83156, h, LARGE));
    let h = vec![Nested { by: 2, other: 1, t: 6, k: 0, text: false, compact: true, also: false }, New { by: 2, parent: 1, write: true }, Send { from: 1, to: 0, back: 1 }, Edge { by: 0, t: 2, holder: 2, role: Some(Role::Read) }];
    cases.push((1038, h, LARGE));
    // seed 1558: C lowers its own edge (a nested write into the roster snapshot's entry) with a
    // clock behind A's, so it sorts before that snapshot: an open read it first and left it
    // waiting for the entry's creation, which a fresh apply had resolved
    let h = vec![Demote { by: 0, t: 5, holder: 1, at: 4, to_read: false }, Roster { by: 0, t: 4 }, Sync { from: 0, to: 1 }, Demote { by: 0, t: 6, holder: 2, at: 1, to_read: false }, Sync { from: 1, to: 2 }, Write { by: 0, t: 7, op: 7, k: 0, v: 4 }, Send { from: 0, to: 2, back: 0 }, Edge { by: 2, t: 4, holder: 2, role: Some(Role::Read) }];
    cases.push((1558, h, LARGE));
    // seed 1053 (spec/crdt.md §4.8): two writes of a keep-at-most-0 register with one `ts`; the
    // later by commit ID lost by dot and died on arrival, and its drop went before its own
    // record was written, which then held it undropped (a reopen disagreed)
    let h = vec![Write { by: 2, t: 4, op: 18, k: 2, v: 4 }, Write { by: 1, t: 6, op: 18, k: 1, v: 4 }];
    cases.push((1053, h, LARGE));
    // seed 1173 (spec/crdt.md §4.8): peer 0's kept write inside peer 1's entry dies at peer 2's;
    // peer 1's creation arriving invalid un-merged both, and nothing replayed the deaths
    let h = vec![Nested { by: 1, other: 2, t: 7, k: 1, text: false, compact: false, also: false }, Send { from: 1, to: 0, back: 0 }, Edge { by: 2, t: 2, holder: 1, role: Some(Role::Read) }, Write { by: 0, t: 0, op: 22, k: 1, v: 9 }];
    cases.push((1173, h, SMALL));
    // seed 93004 (spec/permissions.md §5.2): C's slot reset prunes its own nested entries'
    // creations; B's write inside them survives, held only in B's snapshot. Stripping the
    // snapshot's copies of C's writes also took the entries' keys, which B's records repeat:
    // with C held first the entries lost their keys, with the snapshot first they kept them
    let h = vec![Write { by: 1, t: 5, op: 3, k: 2, v: 6 }, Write { by: 1, t: 1, op: 5, k: 2, v: 7 }, Write { by: 1, t: 5, op: 0, k: 1, v: 9 }, Send { from: 1, to: 2, back: 2 }, Sync { from: 2, to: 0 }, Nested { by: 0, other: 2, t: 4, k: 2, text: false, compact: true, also: true }, New { by: 0, parent: 5, write: false }];
    cases.push((93004, h, LARGE));
    // seeds 12161, 12236 (spec/crdt.md §4.6): B's entry creation is held only through C's
    // snapshot, invalid after C's demotion, so A's write nested in the entry was un-merged; A's
    // valid snapshot carrying the creation, held later, made it valid again, but the join
    // stripped its copy of A's write (A's delta held) and nothing re-merged it (was: the next
    // in-place un-merge differed from a rebuild)
    let h = vec![Nested { by: 1, other: 2, t: 0, k: 2, text: false, compact: true, also: true }, Sync { from: 2, to: 0 }, Write { by: 0, t: 1, op: 22, k: 2, v: 1 }, Compact { by: 0, t: 1, op: 25 }, Edge { by: 0, t: 3, holder: 2, role: Some(Role::Read) }, New { by: 0, parent: 5, write: false }, New { by: 0, parent: 6, write: true }];
    cases.push((12161, h, LARGE));
    let h = vec![Edge { by: 0, t: 5, holder: 1, role: Some(Role::Write) }, Nested { by: 0, other: 2, t: 2, k: 1, text: false, compact: true, also: true }, Edge { by: 0, t: 1, holder: 2, role: None }, Write { by: 1, t: 5, op: 6, k: 1, v: 4 }, Edge { by: 2, t: 3, holder: 1, role: Some(Role::Write) }, Write { by: 1, t: 4, op: 16, k: 0, v: 7 }, Nested { by: 1, other: 0, t: 0, k: 1, text: false, compact: true, also: true }];
    cases.push((12236, h, LARGE));
    // seed 61165 (spec/permissions.md §5.2, spec/crdt.md §7): A's entry, its creation held only
    // through C's snapshot, holds two encodings (a `Slots` position) with A's later writes in
    // its inner entries. Stripping the snapshot's copies of those writes re-joined the slots and
    // pruned the inner creations it keeps for the join; removing an invalid delta's dots from
    // the stripped snapshot (a rebuild after a flip) pruned them too: one held set, two states
    let h = vec![New { by: 0, parent: 0, write: false }, Write { by: 0, t: 5, op: 15, k: 0, v: 5 }, Write { by: 0, t: 5, op: 1, k: 1, v: 3 }, Roster { by: 0, t: 2 }, Demote { by: 2, t: 4, holder: 1, at: 2, to_read: true }, Nested { by: 0, other: 1, t: 6, k: 2, text: false, compact: true, also: true }, Write { by: 0, t: 6, op: 3, k: 0, v: 5 }, Send { from: 0, to: 2, back: 0 }, Write { by: 0, t: 3, op: 19, k: 1, v: 8 }, Write { by: 0, t: 4, op: 16, k: 0, v: 2 }, Demote { by: 0, t: 2, holder: 1, at: 5, to_read: false }, Write { by: 2, t: 6, op: 7, k: 2, v: 0 }, Edge { by: 0, t: 4, holder: 1, role: Some(Role::Write) }, Nested { by: 0, other: 2, t: 2, k: 0, text: false, compact: true, also: false }];
    cases.push((61165, h, LARGE));
    // seed 583175 (spec/permissions.md §5.2): B's snapshot, invalid, carries A's removal that is
    // not held; the oracle took A's commit as if a valid snapshot carried it and dated C's
    // removal dead at it (an invalid snapshot gives nothing: `carried_dots` skips it)
    let h = vec![Demote { by: 2, t: 3, holder: 1, at: 3, to_read: false }, Nested { by: 1, other: 2, t: 4, k: 1, text: false, compact: true, also: false }, Edge { by: 0, t: 3, holder: 2, role: Some(Role::Write) }, Sync { from: 2, to: 1 }, Demote { by: 0, t: 5, holder: 2, at: 4, to_read: false }, Advance { who: Some(0), ms: 1093 }, Sync { from: 1, to: 0 }, Write { by: 0, t: 3, op: 25, k: 1, v: 5 }, Send { from: 0, to: 1, back: 2 }, Edge { by: 0, t: 2, holder: 2, role: Some(Role::Admin) }, Edge { by: 0, t: 2, holder: 2, role: None }, Sync { from: 1, to: 2 }, Send { from: 0, to: 1, back: 2 }, Compact { by: 1, t: 2, op: 22 }, Write { by: 2, t: 0, op: 25, k: 1, v: 9 }];
    cases.push((583175, h, LARGE));
    // seed 15085 (spec/permissions.md §5.2, spec/crdt.md §5.6): two demotions of 1 and 2's
    // compacted `Nested` write: an un-merge pruned an entry's creation whose own dot stayed (a
    // rebuild kept it for the join), so the orders' states differed
    let h = vec![Nested { by: 2, other: 0, t: 5, k: 2, text: false, compact: false, also: false }, Write { by: 0, t: 6, op: 3, k: 2, v: 9 }, Nested { by: 2, other: 0, t: 0, k: 2, text: false, compact: true, also: true }, Write { by: 1, t: 2, op: 0, k: 1, v: 0 }, Write { by: 1, t: 6, op: 16, k: 1, v: 2 }, Edge { by: 0, t: 2, holder: 1, role: Some(Role::Write) }, Edge { by: 0, t: 7, holder: 1, role: Some(Role::Write) }, Demote { by: 0, t: 4, holder: 1, at: 1, to_read: true }, Edge { by: 0, t: 4, holder: 2, role: Some(Role::Write) }, Demote { by: 0, t: 6, holder: 1, at: 5, to_read: true }];
    cases.push((15085, h, LARGE));
    // seed 2700027 (spec/commits.md §5): B's snapshot of a keep-at-most-0 register carries A's
    // write that A's undo (`ts` below the snapshot's) already killed: held after the undo, the
    // snapshot got no death and kept the undone value with no bound
    cases.push((2700027, snapshot_of_undone(), LARGE));
    // seeds 1007, 1018, 1045 (spec/permissions.md §5.2, spec/crdt.md §4.6): a text insert fallen
    // under a demotion, and a valid snapshot taken after the un-merge, carrying its creation
    // without the char. Un-merge kept any write of the fallen delta under a dot a valid snapshot
    // held a write of, the delta's char included: held after the snapshot it read, held before
    // it did not (`x` vs `v2x`; in a map entry's text `v7v1` vs `v7v1v1`); and an in-place
    // un-merge differed from a rebuild. Now the snapshot's copy alone stays (was
    // issues/seq-snapshot-unmerge-order.md)
    let h = vec![Typed { by: 1, t: 0, op: 24, k: 2, v: 2 }, Typed { by: 2, t: 0, op: 10, k: 1, v: 2 }, Demote { by: 0, t: 0, holder: 2, at: 1, to_read: false }, Sync { from: 2, to: 0 }, Compact { by: 0, t: 0, op: 24 }];
    cases.push((1007, h, LARGE));
    let h = vec![Nested { by: 0, other: 2, t: 0, k: 0, text: true, compact: true, also: true }, Edge { by: 0, t: 0, holder: 2, role: Some(Role::Read) }, Nested { by: 2, other: 0, t: 0, k: 0, text: true, compact: false, also: false }, Compact { by: 0, t: 0, op: 26 }];
    cases.push((1018, h, LARGE));
    let h = vec![Nested { by: 0, other: 1, t: 0, k: 0, text: true, compact: false, also: false }, Sync { from: 1, to: 2 }, Demote { by: 0, t: 0, holder: 1, at: 5, to_read: true }, Sync { from: 0, to: 2 }, Nested { by: 0, other: 2, t: 0, k: 0, text: true, compact: true, also: true }, Nested { by: 2, other: 1, t: 0, k: 2, text: true, compact: false, also: false }];
    cases.push((1045, h, LARGE));
    // seed 4123 (spec/permissions.md §5.2): B's snapshot carries the shell of B's own text entry
    // (its creation and chars pruned by a later reset: an entry with bare anchors only), B's
    // put not held; the snapshot turned invalid after B's demotion, and what it gave went by
    // writes, so the shell stayed: now its records carrying no write go too
    let h = vec![Leave { by: 2, t: 3 }, Edge { by: 2, t: 7, holder: 2, role: Some(Role::Read) }, Typed { by: 1, t: 4, op: 26, k: 1, v: 5 }, Undo { by: 1, back: 0 }, Nested { by: 0, other: 1, t: 3, k: 2, text: true, compact: false, also: true }, NewTop { by: 0 }, Nested { by: 0, other: 1, t: 0, k: 2, text: true, compact: true, also: false }, New { by: 0, parent: 5, write: false }, Demote { by: 0, t: 3, holder: 1, at: 1, to_read: true }, Typed { by: 1, t: 1, op: 1, k: 1, v: 3 }, Typed { by: 0, t: 1, op: 10, k: 2, v: 9 }, Roster { by: 2, t: 3 }];
    cases.push((4123, h.into_iter().map(|s| if matches!(s, NewTop { .. }) { s } else { Aim(Box::new(s)) }).collect(), LARGE));
    // seed 8026 (spec/crdt.md §4.8, spec/commits.md §5): B inserts, deletes, undoes the delete
    // and undoes the undo; a kept text insert held after its undelete and before its delete got
    // no death (the delete arriving lost to the undelete without killing anything in the state),
    // and one held after both had its killer gone from the state (a recompute from the bodies)
    let h = vec![Typed { by: 1, t: 0, op: 24, k: 1, v: 8 }, Typed { by: 1, t: 0, op: 24, k: 1, v: 6 }, Undo { by: 1, back: 0 }, Typed { by: 1, t: 0, op: 24, k: 1, v: 8 }, Typed { by: 2, t: 0, op: 10, k: 1, v: 0 }, Undo { by: 1, back: 1 }];
    cases.push((8026, h.into_iter().map(|s| Aim(Box::new(s))).collect(), Cfg { sync: true, ..LARGE }));
    // seed 64303 (spec/crdt.md §5.6, spec/commits.md §5): an expiring put of k0 expired, a kept
    // write into k0 and a later one, a snapshot: the kept write's death was lost where the
    // expiry merged the entry's records after the snapshot's key-erased copy had joined (was
    // issues/map-death-missing-partial-held.md)
    let h = vec![Write { by: 2, t: 7, op: 19, k: 1, v: 6 }, Demote { by: 0, t: 4, holder: 2, at: 5, to_read: false }, Edge { by: 2, t: 5, holder: 2, role: None }, Typed { by: 0, t: 0, op: 1, k: 1, v: 1 }, Edge { by: 2, t: 3, holder: 2, role: Some(Role::Read) }, Write { by: 2, t: 4, op: 28, k: 0, v: 4 }, Demote { by: 0, t: 2, holder: 1, at: 3, to_read: false }, Edge { by: 0, t: 0, holder: 2, role: Some(Role::Write) }];
    let mut h: Vec<Step> = h.into_iter().map(|s| Aim(Box::new(s))).collect();
    h.push(Forged { by: 0, a: 0, b: 6, how: 3, op: 6, k: 1, v: 2 });
    h.extend([Write { by: 2, t: 4, op: 22, k: 0, v: 0 }, Typed { by: 1, t: 6, op: 15, k: 0, v: 7 }].map(|s| Aim(Box::new(s))));
    h.push(Advance { who: None, ms: 6569444 });
    h.extend([Nested { by: 1, other: 0, t: 3, k: 0, text: false, compact: true, also: true }, Undo { by: 1, back: 0 }, Typed { by: 0, t: 1, op: 9, k: 0, v: 4 }, Typed { by: 2, t: 1, op: 8, k: 1, v: 6 }].map(|s| Aim(Box::new(s))));
    h.push(Sync { from: 0, to: 2 });
    cases.push((64303, h, Cfg { sync: true, ..LARGE }));
    // seed 7714 (spec/commits.md §5, spec/permissions.md §5.2): a kept write invalid here whose
    // entry a valid snapshot vouches for, the entry removed later: the live join dated the body
    // at the removal (the copy it is live by died), the recompute never (it left the copy out
    // as "held elsewhere" though its own delta is un-merged); and a superseder expired since
    // dated nothing in the recompute (its residue did not play)
    let h = vec![Nested { by: 2, other: 0, t: 6, k: 0, text: true, compact: true, also: true }, Typed { by: 2, t: 7, op: 22, k: 1, v: 7 }, Write { by: 2, t: 2, op: 1, k: 2, v: 8 }, Nested { by: 2, other: 0, t: 3, k: 2, text: false, compact: true, also: true }];
    let mut h: Vec<Step> = h.into_iter().map(|s| Aim(Box::new(s))).collect();
    h.push(Send { from: 2, to: 0, back: 2 });
    h.extend([Typed { by: 2, t: 5, op: 28, k: 1, v: 2 }, Nested { by: 0, other: 1, t: 4, k: 2, text: true, compact: false, also: false }, Typed { by: 2, t: 4, op: 11, k: 1, v: 9 }, NestedItem { by: 2, other: 0, t: 1, k: 0, compact: true, also: true }].map(|s| Aim(Box::new(s))));
    h.extend([NewTop { by: 0 }, Send { from: 0, to: 2, back: 0 }]);
    h.extend([Nested { by: 2, other: 0, t: 5, k: 0, text: true, compact: true, also: true }, Nested { by: 2, other: 1, t: 4, k: 2, text: true, compact: true, also: true }, Edge { by: 0, t: 6, holder: 1, role: Some(Role::Write) }, NestedItem { by: 0, other: 2, t: 4, k: 2, compact: true, also: true }, Demote { by: 0, t: 5, holder: 2, at: 4, to_read: false }, New { by: 0, parent: 0, write: true }, Demote { by: 0, t: 6, holder: 2, at: 5, to_read: false }, New { by: 0, parent: 7, write: false }, Typed { by: 2, t: 4, op: 25, k: 1, v: 4 }].map(|s| Aim(Box::new(s))));
    cases.push((7714, h, Cfg { sync: true, ..LARGE }));
    // in parallel: the slowest test of the module otherwise
    let idx: Vec<u64> = (0..cases.len() as u64).collect();
    let results = par_map(&idx, threads("OSIS_ORDER_THREADS"), |i| {
        let (seed, h, cfg) = &cases[i as usize];
        check(*seed, h, *cfg)
    });
    for (r, (seed, ..)) in results.into_iter().zip(&cases) {
        if let Err(e) = r {
            panic!("seed {seed}: {e}");
        }
    }
}

// spec/crdt.md §4.8 (a write dies once, at its earliest superseder), spec/commits.md §5: order
// seed 4900, shrunk. Two deletes of one text element: the replay dated the creation's death at
// both, so a node meeting only the first had a last death earlier than the oracle's.
#[test]
fn text_creation_dies_once_seed_4900_spec_crdt_4_8() {
    use Step::*;
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![aim(Typed { by: 2, t: 0, op: 24, k: 0, v: 2 }), aim(Typed { by: 2, t: 0, op: 26, k: 1, v: 5 }), Sync { from: 2, to: 0 }, aim(Typed { by: 2, t: 0, op: 26, k: 0, v: 4 }), aim(Typed { by: 0, t: 0, op: 24, k: 1, v: 0 }), aim(Typed { by: 2, t: 0, op: 11, k: 1, v: 2 }), aim(Typed { by: 0, t: 0, op: 24, k: 1, v: 8 }), Compact { by: 2, t: 0, op: 26 }, Send { from: 2, to: 1, back: 0 }, Compact { by: 1, t: 0, op: 26 }, Send { from: 2, to: 0, back: 1 }, Compact { by: 0, t: 0, op: 11 }];
    check(4900, &h, Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, par_orders: false, threads: 1, sync: true }).unwrap();
}

// spec/crdt.md §4.8 (a write dies once, at its earliest superseder): a kept text inserted,
// deleted, the delete undone and the text deleted again. The insert's body dies at the first
// delete, live and recomputed; the re-delete over the undelete does not move its last death.
#[test]
fn text_redelete_dies_at_first_delete_spec_crdt_4_8() {
    use Step::*;
    let tick = Advance { who: None, ms: 1 };
    let h = vec![Typed { by: 0, t: 0, op: 23, k: 0, v: 0 }, tick.clone(), Typed { by: 0, t: 0, op: 24, k: 0, v: 0 }, tick.clone(), Undo { by: 0, back: 0 }, tick, Typed { by: 0, t: 0, op: 24, k: 0, v: 0 }];
    let played = play(7, &h);
    let mut p = deliver(&played, &(0..played.packs.len()).collect::<Vec<_>>());
    let text = osis_base::Ak::new("t:text.0").unwrap();
    let mut ids: Vec<(osis_base::Ts, CommitId, Tid)> = p.engine.commit_ids().into_iter().filter_map(|id| p.engine.header(&id).and_then(|h| h.aspects.iter().find(|a| a.ak == text).map(|a| (h.ts, id, a.tid)))).collect();
    ids.sort();
    let [(_, ins, t), (del, ..), _, (redel, ..)] = ids[..] else { panic!("{ids:?}") };
    assert!(del < redel);
    assert_eq!(p.engine.deaths(&ins, &t, &text).unwrap(), Some((del, del)), "live");
    p.engine.replay_deaths(&t, &text).unwrap();
    assert_eq!(p.engine.deaths(&ins, &t, &text).unwrap(), Some((del, del)), "recomputed");
}

// spec/crdt.md §4.8, spec/commits.md §5 (a snapshot's writes die for it no earlier than its
// `ts`): order seed 5016, shrunk. A text element's creation and its delete reach a node only
// through a snapshot, as a new record already deleted: the join reported no death, so a later
// snapshot whose author had not seen the delete (it carries the char) was never dated.
#[test]
fn text_creation_arriving_deleted_dies_seed_5016_spec_crdt_4_8() {
    use Step::*;
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![aim(Typed { by: 0, t: 0, op: 8, k: 0, v: 2 }), aim(Typed { by: 0, t: 0, op: 8, k: 0, v: 9 }), aim(Typed { by: 0, t: 0, op: 26, k: 0, v: 3 }), aim(Typed { by: 0, t: 0, op: 9, k: 1, v: 8 }), aim(Undo { by: 0, back: 2 }), aim(Typed { by: 0, t: 0, op: 26, k: 1, v: 6 }), aim(Typed { by: 1, t: 0, op: 8, k: 1, v: 2 }), aim(Typed { by: 2, t: 0, op: 9, k: 0, v: 0 }), aim(Typed { by: 1, t: 0, op: 26, k: 1, v: 3 }), Sync { from: 0, to: 2 }, aim(Typed { by: 0, t: 0, op: 9, k: 0, v: 8 }), aim(Typed { by: 1, t: 0, op: 26, k: 0, v: 7 }), aim(Typed { by: 2, t: 0, op: 8, k: 0, v: 8 }), aim(Typed { by: 2, t: 0, op: 26, k: 1, v: 1 }), aim(Typed { by: 0, t: 0, op: 26, k: 1, v: 6 }), aim(Typed { by: 2, t: 0, op: 9, k: 0, v: 6 }), Sync { from: 1, to: 0 }, Compact { by: 1, t: 0, op: 9 }, Compact { by: 1, t: 0, op: 9 }, aim(Typed { by: 2, t: 0, op: 26, k: 1, v: 1 }), aim(Typed { by: 2, t: 0, op: 26, k: 0, v: 4 }), aim(Typed { by: 0, t: 0, op: 26, k: 1, v: 3 }), aim(Typed { by: 0, t: 0, op: 9, k: 0, v: 3 }), aim(Typed { by: 2, t: 0, op: 26, k: 0, v: 9 }), aim(Undo { by: 2, back: 1 }), Compact { by: 2, t: 0, op: 26 }, Compact { by: 0, t: 0, op: 26 }];
    check(5016, &h, Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, par_orders: false, threads: 1, sync: true }).unwrap();
}

// spec/crdt.md §4.8: exhaustive order seed 9605, shrunk. A commit inserts a char and deletes it;
// arriving first, into an empty state, the join took it whole and reported no death, which a
// join into a held text and the replay did.
#[test]
fn text_creation_deleted_into_empty_state_dies_seed_9605_spec_crdt_4_8() {
    use Step::*;
    let h = vec![Aim(Box::new(Typed { by: 2, t: 1, op: 23, k: 1, v: 3 })), Forged { by: 2, a: 1, b: 1, how: 1, op: 23, k: 0, v: 7 }];
    check(9605, &h, Cfg { all_up_to: 6, every_held: true, random: 0, subsets: 2, split: usize::MAX, par_orders: false, threads: 1, sync: true }).unwrap();
}

// spec/commits.md §5 (dropping a body destroys every local index entry derived from it),
// spec/requirements.md Decentralization (a rebuild judges alike): seed 1291, a keep-at-most-0
// write, its compaction snapshot, the write undone: both bodies drop dead, and the snapshot's
// frontier stayed in `Core::snapshots` incrementally but not after a rebuild of the index.
#[test]
fn dropped_snapshot_rebuilds_alike_spec_commits_5() {
    use Step::*;
    let h = vec![Write { by: 0, t: 2, op: 18, k: 2, v: 3 }, Compact { by: 0, t: 3, op: 18 }, Demote { by: 0, t: 3, holder: 1, at: 3, to_read: false }, Undo { by: 0, back: 2 }];
    check(1291, &h, LARGE).unwrap();
    // the dropped snapshot keeps no frontier: it dropped dead, so it stays dead
    let played = play(1291, &h);
    let mut p = deliver(&played, &(0..played.packs.len()).collect::<Vec<_>>());
    let snap = p.engine.commit_ids().into_iter().find(|id| p.engine.header(id).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot)).unwrap();
    let a = p.engine.header(&snap).unwrap().aspects[0].clone();
    assert!(!p.engine.body_not_dropped(&snap, &a.tid, &a.ak), "the snapshot dropped dead");
    assert!(!p.engine.body_live(&snap, &a.tid, &a.ak).unwrap(), "the undo reset it");
}

// spec/permissions.md §5.2 (an invalid snapshot gives none of its writes), spec/crdt.md §4.6:
// order seed 1006, shrunk. Bob's snapshot (invalid after his demotion) carries Alice's entry
// creation, held before her commit: the un-merge of its dots strips Alice's later write nested in
// that entry; her creating commit arriving last must give it back (`refill` rebuilds).
#[test]
fn invalid_snapshot_owner_late_seed_1006() {
    let h = vec![Step::Edge { by: 0, t: 0, holder: 2, role: None }, Step::Nested { by: 0, other: 1, t: 4, k: 2, text: false, compact: true, also: true }, Step::Write { by: 2, t: 6, op: 12, k: 1, v: 2 }, Step::Write { by: 0, t: 1, op: 18, k: 2, v: 6 }, Step::Demote { by: 0, t: 2, holder: 1, at: 5, to_read: true }, Step::Write { by: 0, t: 0, op: 3, k: 2, v: 9 }];
    check(1006, &h, Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, par_orders: false, threads: 1, sync: false }).unwrap();
}

// as above, order seed 1042, shrunk (an in-place un-merge differed from a rebuild).
#[test]
fn invalid_snapshot_owner_late_seed_1042() {
    let h = vec![Step::Nested { by: 0, other: 2, t: 1, k: 0, text: false, compact: true, also: true }, Step::New { by: 0, parent: 3, write: false }, Step::New { by: 0, parent: 6, write: false }, Step::Sync { from: 2, to: 1 }, Step::Demote { by: 2, t: 3, holder: 1, at: 3, to_read: true }, Step::Nested { by: 2, other: 1, t: 0, k: 1, text: false, compact: true, also: true }];
    check(1042, &h, Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, par_orders: false, threads: 1, sync: false }).unwrap();
}

// spec/commits.md §5 (a body dropped for its keep bounds counts as never received: a copy that
// arrives again joins): histories the harness found with holders writing keep-at-most ops
// (shrunk), where a body is dropped at one node and held at another: seeds 1053, 1024 (its
// killer turned invalid), 1085, 1200 (its own write turned invalid, the op 17 bound passed).
// Given those bodies again, both nodes judge alike with no exception for the drop.
#[test]
fn drop_before_flip_joins_again_spec_commits_5() {
    use Step::*;
    let flips = vec![
        (1053, vec![Write { by: 2, t: 4, op: 18, k: 2, v: 4 }, Write { by: 1, t: 6, op: 18, k: 1, v: 4 }, Demote { by: 0, t: 4, holder: 2, at: 3, to_read: false }]),
        (1024, vec![Write { by: 0, t: 7, op: 18, k: 0, v: 9 }, Edge { by: 0, t: 0, holder: 2, role: Some(Role::Read) }, Write { by: 2, t: 4, op: 18, k: 2, v: 4 }]),
        (1085, vec![Write { by: 2, t: 6, op: 17, k: 2, v: 7 }, Write { by: 0, t: 6, op: 17, k: 1, v: 4 }, Demote { by: 0, t: 0, holder: 2, at: 0, to_read: false }, Advance { who: None, ms: 5203966 }]),
        (1200, vec![Demote { by: 0, t: 7, holder: 1, at: 5, to_read: true }, Write { by: 1, t: 5, op: 17, k: 0, v: 1 }, Write { by: 0, t: 5, op: 17, k: 0, v: 5 }, Advance { who: None, ms: 5183786 }]),
    ];
    for (seed, h) in &flips {
        check(*seed, h, LARGE).unwrap_or_else(|e| panic!("seed {seed}: {e}"));
    }
}

// The owner's example (notes/convergence-study.md §1 hole 1), seed 1053: C writes a keep-at-most-0
// register, B's later write kills it, then A's demotion of B (its frontier not covering that
// write) makes B's write invalid. As made, a node drops C's body when B's write lands and then
// un-merges B's write: the register reads empty. In reverse, B's write is invalid on arrival
// and C's value stays. Given C's commit again, the first node joins it (it counts as never
// received) and both read C's value.
#[test]
fn keep_at_most_drop_joins_again_after_flip_spec_commits_5() {
    use Step::*;
    let h = vec![Write { by: 2, t: 4, op: 18, k: 2, v: 4 }, Write { by: 1, t: 6, op: 18, k: 1, v: 4 }, Demote { by: 0, t: 4, holder: 2, at: 3, to_read: false }];
    let played = play(1053, &h);
    let made: Vec<usize> = (0..played.packs.len()).collect();
    let rev: Vec<usize> = made.iter().rev().copied().collect();
    let (want, got) = (judged(&mut deliver(&played, &made), &played), judged(&mut deliver(&played, &rev), &played));
    assert!(alike(&want, &got, &|_, _| false).is_some(), "the orders differ until the body is given again");
    let apart = drop_flips(&want, &got);
    assert_eq!(apart.len(), 1, "one body dropped before the flip: {apart:?}");
    assert_eq!(alike_exchanged(&played, &want, &made, &got, &rev, None, &|_, _| false), None);
    // the node that dropped it holds it again once a copy arrives
    let mut p = deliver(&played, &made);
    let again = packs_of(&played, &apart);
    let c = played.packs[again[0]].id;
    let a = p.engine.header(&c).unwrap().aspects[0].clone();
    assert!(!p.engine.body_not_dropped(&c, &a.tid, &a.ak), "dropped as made");
    let pk = &played.packs[again[0]];
    p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
    assert!(p.engine.body_not_dropped(&c, &a.tid, &a.ak), "held again: its write is live");
}

// spec/commits.md §5 (under at most 0 the kill that leaves a body no live write drops it in that
// transaction): order seed 64197. A's write of a keep-at-most-0 map entry, undone (a reset of the
// entry): the tombstone left, keyed by the entry's dot, counted as a live write of the body, so
// it was kept to its grace bound; a later reset of the whole map (undoing A's first write,
// absent before) pruned the tombstone and left a dead body held.
#[test]
fn undone_entry_body_dropped_at_once_spec_commits_5() {
    use Step::*;
    let h = vec![Write { by: 0, t: 1, op: 19, k: 0, v: 3 }, Write { by: 0, t: 1, op: 19, k: 1, v: 6 }, Undo { by: 0, back: 0 }, Undo { by: 0, back: 2 }];
    check(64197, &h, LARGE).unwrap();
    // the write and its undo alone: the body drops with the undo
    let played = play(64197, &h);
    let b = played.base;
    let p = deliver(&played, &(0..b + 3).collect::<Vec<_>>());
    let w = &played.packs[b + 1].id;
    let a = p.engine.header(w).unwrap().aspects[0].clone();
    assert!(!p.engine.body_not_dropped(w, &a.tid, &a.ak), "an entry's tombstone is no write of its creator");
}

fn snapshot_of_undone() -> Vec<Step> {
    use Step::*;
    vec![Write { by: 0, t: 1, op: 18, k: 1, v: 6 }, Send { from: 0, to: 1, back: 0 }, Undo { by: 0, back: 0 }, Compact { by: 1, t: 0, op: 18 }, Write { by: 0, t: 0, op: 18, k: 0, v: 5 }]
}

// spec/commits.md §5 (a snapshot's writes die for it no earlier than its `ts`; under at most 0
// a body with no live write goes): order seed 2700027 reduced. B's keep-at-most-0 snapshot
// carries A's write, which A's undo with a lower `ts` killed unseen by B: in every arrival
// order the snapshot dies (at its own `ts` at the latest) and drops, whether the undo is held
// before it (`note_copies`), after it (`note_deaths`) or the aspect's deaths are recomputed.
#[test]
fn snapshot_of_undone_write_dropped_any_order_spec_commits_5() {
    let h = snapshot_of_undone();
    let played = play(2700027, &h);
    let b = played.base;
    let n = played.packs.len() - b;
    let mut orders = vec![(b..b + n).collect::<Vec<_>>()];
    // every order of the history's commits, the setup first
    while let Some(o) = next_perm(orders.last().unwrap()) {
        orders.push(o);
    }
    for rel in orders {
        let order: Vec<usize> = (0..b).chain(rel.iter().copied()).collect();
        let p = deliver(&played, &order);
        let snap = p.engine.commit_ids().into_iter().find(|id| p.engine.header(id).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot)).expect("a snapshot");
        let a = p.engine.header(&snap).unwrap().aspects[0].clone();
        assert!(!p.engine.body_not_dropped(&snap, &a.tid, &a.ak), "order {rel:?}: the snapshot of an undone write dropped");
        // a node keeping every body dates its death (at a superseder it met), a recompute at its
        // `ts` at the latest (the undo is the first superseder held)
        let mut k = Peer::new(FRESH, played.now).unwrap();
        k.engine.keep_bodies(true);
        for &i in &order {
            let pk = &played.packs[i];
            let _ = k.engine.ingest(&pk.bytes, pk.blobs.clone());
        }
        let ts = k.engine.header(&snap).unwrap().ts;
        let first = |k: &mut Peer| k.engine.deaths(&snap, &a.tid, &a.ak).unwrap().map(|d| d.0);
        assert!(first(&mut k).is_some(), "order {rel:?}: no death");
        k.engine.replay_deaths(&a.tid, &a.ak).unwrap();
        assert!(first(&mut k).is_some_and(|f| f <= ts), "order {rel:?}: recomputed {:?}, snapshot at {ts:?}", first(&mut k));
    }
}

/// The next permutation of `v` in lexicographic order, if any.
fn next_perm(v: &[usize]) -> Option<Vec<usize>> {
    let mut v = v.to_vec();
    let i = (1..v.len()).rev().find(|&i| v[i - 1] < v[i])?;
    let j = (i..v.len()).rev().find(|&j| v[j] > v[i - 1])?;
    v.swap(i - 1, j);
    v[i..].reverse();
    Some(v)
}

// spec/commits.md §5 (a body dropped at both nodes, no copy left to join again: their states
// may differ in a dropped body's creation stamp, reads alike), order seeds 47289, 583188 and
// 845143. B's entry in a
// keep-at-most-0 map (its body dropped once B's own later write inside it killed the value, the
// bound passed); B's later write is valid with every commit held, invalid before the re-grant:
// where it arrived valid, then turned invalid and valid again, the un-merge left the entry no
// content and so took its creation, and the write came back alone. Reads agree; `alike`
// accepts the states' creation stamps only where one of the two orders flipped a body.
#[test]
fn creation_lost_by_drop_then_flip_tolerated_spec_commits_5() {
    use Step::*;
    let h = vec![Write { by: 1, t: 6, op: 19, k: 0, v: 3 }, Demote { by: 0, t: 4, holder: 1, at: 5, to_read: false }, Write { by: 1, t: 4, op: 19, k: 0, v: 1 }, Advance { who: None, ms: 4484944 }, Edge { by: 0, t: 6, holder: 1, role: Some(Role::Admin) }];
    let h2 = vec![Demote { by: 0, t: 5, holder: 2, at: 3, to_read: true }, Edge { by: 2, t: 3, holder: 1, role: Some(Role::Write) }, Roster { by: 0, t: 0 }, Roster { by: 0, t: 5 }, Write { by: 2, t: 0, op: 19, k: 2, v: 1 }, New { by: 2, parent: 6, write: false }, Roster { by: 2, t: 1 }, Edge { by: 0, t: 0, holder: 1, role: Some(Role::Admin) }, Compact { by: 1, t: 0, op: 0 }, Sync { from: 2, to: 0 }, Edge { by: 0, t: 1, holder: 2, role: Some(Role::Admin) }, Write { by: 2, t: 1, op: 6, k: 0, v: 5 }, Send { from: 2, to: 1, back: 2 }, Write { by: 1, t: 3, op: 6, k: 1, v: 0 }, Write { by: 1, t: 6, op: 6, k: 2, v: 7 }, Edge { by: 0, t: 6, holder: 2, role: Some(Role::Admin) }, Edge { by: 2, t: 3, holder: 1, role: Some(Role::Write) }, Sync { from: 0, to: 1 }, Write { by: 1, t: 4, op: 19, k: 2, v: 6 }, Advance { who: None, ms: 5488242 }];
    // seed 845143: B's two writes, lowered to read and raised by two grants; B's own creation
    // (the dropped body's) turns invalid and valid again (no single grant missing flips it)
    let h3 = vec![Edge { by: 0, t: 2, holder: 1, role: Some(Role::Read) }, Demote { by: 0, t: 0, holder: 2, at: 2, to_read: false }, Edge { by: 0, t: 6, holder: 1, role: Some(Role::Write) }, Edge { by: 0, t: 4, holder: 1, role: Some(Role::Write) }, Write { by: 1, t: 6, op: 19, k: 0, v: 3 }, Write { by: 1, t: 6, op: 19, k: 0, v: 8 }, Advance { who: None, ms: 6234602 }, New { by: 0, parent: 2, write: true }];
    let cases = [(47289, h.clone()), (583188, h2), (845143, h3)];
    let idx: Vec<u64> = (0..cases.len() as u64).collect();
    for (r, (seed, _)) in par_map(&idx, threads("OSIS_ORDER_THREADS"), |i| check(cases[i as usize].0, &cases[i as usize].1, LARGE)).into_iter().zip(&cases) {
        if let Err(e) = r {
            panic!("seed {seed}: {e}");
        }
    }
    // B's later write first, the demotion, the re-grant: only the creation stamp differs, and
    // only a reachable flip excuses it
    let played = play(47289, &h);
    let b = played.base;
    let made: Vec<usize> = (0..played.packs.len()).collect();
    let mut order: Vec<usize> = (0..b).collect();
    order.extend([b, b + 2, b + 1, b + 3]);
    let want = judged(&mut deliver(&played, &made), &played);
    let got = judged(&mut deliver(&played, &order), &played);
    let differs = alike(&want, &got, &|_, _| false).expect("the creation stamp differs");
    assert!(differs.contains("states on") && differs.contains("created: None"), "{differs}");
    assert!(played.things.iter().any(|t| flipped(&played, &order, None, &format!("{t:?}"), "t:gonemap.0")), "the order flips");
    assert_eq!(alike(&want, &got, &|t, a| flipped(&played, &order, None, t, a)), None);
}

// spec/commits.md §5, the shape of seed 2700027 in a map: B's snapshot of a keep-at-most-0 map
// carries A's entry value, which A's overwrite (`ts` not above the snapshot's) killed unseen by
// B; the value shares its stamp with the entry's creation, still live. In every arrival order,
// and on a recompute, the snapshot dies for it at its `ts` (it had no death and kept the value).
#[test]
fn snapshot_of_overwritten_entry_value_dies_any_order_spec_commits_5() {
    use Step::*;
    let h = vec![Write { by: 0, t: 0, op: 19, k: 0, v: 6 }, Send { from: 0, to: 1, back: 0 }, Write { by: 0, t: 0, op: 19, k: 0, v: 7 }, Compact { by: 1, t: 0, op: 19 }, Write { by: 0, t: 0, op: 19, k: 1, v: 5 }];
    let played = play(2700027, &h);
    let b = played.base;
    let n = played.packs.len() - b;
    let mut orders = vec![(b..b + n).collect::<Vec<_>>()];
    while let Some(o) = next_perm(orders.last().unwrap()) {
        orders.push(o);
    }
    for rel in orders {
        let mut k = Peer::new(FRESH, played.now).unwrap();
        k.engine.keep_bodies(true);
        for &i in (0..b).chain(rel.iter().copied()).collect::<Vec<_>>().iter() {
            let pk = &played.packs[i];
            let _ = k.engine.ingest(&pk.bytes, pk.blobs.clone());
        }
        let snap = k.engine.commit_ids().into_iter().find(|id| k.engine.header(id).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot)).expect("a snapshot");
        let a = k.engine.header(&snap).unwrap().aspects[0].clone();
        let ts = k.engine.header(&snap).unwrap().ts;
        let first = |k: &mut Peer| k.engine.deaths(&snap, &a.tid, &a.ak).unwrap().map(|d| d.0);
        assert_eq!(first(&mut k), Some(ts), "order {rel:?}");
        k.engine.replay_deaths(&a.tid, &a.ak).unwrap();
        assert_eq!(first(&mut k), Some(ts), "order {rel:?}: recomputed");
    }
}

// spec/commits.md §5 (a date is never earlier than the death): B's snapshot carries A's entry
// creation and B's own value write, which overwrote A's (B saw A's first value, not A's second,
// lower `ts` than the snapshot's: that one kills A's first value, a write the snapshot does not
// carry but whose stamp its creation shares); A's removal after the snapshot kills both. The
// snapshot's first death is the removal's `ts`, never its own (dated there by the shared stamp).
#[test]
fn snapshot_sharing_stamp_of_unseen_death_not_dated_early_spec_commits_5() {
    use Step::*;
    let h = vec![
        Write { by: 0, t: 0, op: 19, k: 0, v: 6 },
        Send { from: 0, to: 1, back: 0 },
        Advance { who: None, ms: 1 },
        Write { by: 0, t: 0, op: 19, k: 0, v: 7 },
        Advance { who: None, ms: 1 },
        Write { by: 1, t: 0, op: 19, k: 0, v: 8 },
        Send { from: 1, to: 0, back: 0 },
        Advance { who: None, ms: 1 },
        Compact { by: 1, t: 0, op: 19 },
        Advance { who: None, ms: 1 },
        Write { by: 0, t: 0, op: 20, k: 0, v: 0 },
    ];
    let played = play(2700027, &h);
    let b = played.base;
    let n = played.packs.len() - b;
    let mut orders = vec![(b..b + n).collect::<Vec<_>>()];
    while let Some(o) = next_perm(orders.last().unwrap()) {
        orders.push(o);
    }
    for rel in orders {
        let mut k = Peer::new(FRESH, played.now).unwrap();
        k.engine.keep_bodies(true);
        for &i in (0..b).chain(rel.iter().copied()).collect::<Vec<_>>().iter() {
            let pk = &played.packs[i];
            let _ = k.engine.ingest(&pk.bytes, pk.blobs.clone());
        }
        let snap = k.engine.commit_ids().into_iter().find(|id| k.engine.header(id).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot)).expect("a snapshot");
        let a = k.engine.header(&snap).unwrap().aspects[0].clone();
        let ts = k.engine.header(&snap).unwrap().ts;
        let first = |k: &mut Peer| k.engine.deaths(&snap, &a.tid, &a.ak).unwrap().map(|d| d.0);
        assert!(first(&mut k).is_some_and(|f| f > ts), "order {rel:?}: {:?}, snapshot at {ts:?}", first(&mut k));
        k.engine.replay_deaths(&a.tid, &a.ak).unwrap();
        assert!(first(&mut k).is_some_and(|f| f > ts), "order {rel:?}: recomputed {:?}, snapshot at {ts:?}", first(&mut k));
    }
}

// spec/commits.md §5 (a body dropped for its keep bounds counts as never received; a snapshot
// dropped other than as covered keeps its frontiers), order seed 3401073: B's write kills A's
// keep-at-most-0 write (and so A's snapshot of it) where it arrives before B's demotion, which
// makes it invalid; the snapshot dropped there keeps its frontiers (`gives`) and leaves the
// snapshot indexes until a copy arrives again and joins.
#[test]
fn snapshot_dropped_before_flip_joins_again_spec_commits_5() {
    use Step::*;
    let h = vec![Write { by: 0, t: 3, op: 18, k: 0, v: 2 }, Compact { by: 0, t: 4, op: 18 }, Edge { by: 0, t: 6, holder: 1, role: Some(Role::Admin) }, Roster { by: 0, t: 6 }, Write { by: 1, t: 7, op: 15, k: 2, v: 7 }, Nested { by: 0, other: 2, t: 4, k: 0, text: false, compact: true, also: true }, Demote { by: 0, t: 0, holder: 1, at: 4, to_read: false }, Edge { by: 2, t: 2, holder: 2, role: Some(Role::Admin) }, Write { by: 2, t: 4, op: 0, k: 1, v: 8 }, Demote { by: 0, t: 4, holder: 2, at: 1, to_read: true }, Write { by: 1, t: 0, op: 18, k: 2, v: 5 }];
    let played = play(3401073, &h);
    let made: Vec<usize> = (0..played.packs.len()).collect();
    let order = [16, 7, 20, 13, 12, 5, 8, 21, 1, 10, 0, 18, 19, 9, 15, 3, 14, 6, 2, 17, 11, 4];
    let want = judged(&mut deliver(&played, &made), &played);
    let got = judged(&mut deliver(&played, &order), &played);
    let snap = |j: &Judged| j.index.as_ref().unwrap().commits.values().find(|c| c.kind == osis_commit::Kind::ContentSnapshot && c.rest.contains("t:gone.0")).unwrap().clone();
    assert!(snap(&want).gives.is_empty() && !snap(&got).gives.is_empty(), "dropped in one order only, keeping its frontiers");
    assert_eq!(alike_exchanged(&played, &want, &made, &got, &order, None, &|_, _| false), None);
    check(3401073, &h, LARGE).unwrap();
    // the seed's longer shrink: the dropped snapshot leaves the carried-writes index too
    let h2 = vec![Roster { by: 0, t: 2 }, Nested { by: 1, other: 2, t: 0, k: 1, text: false, compact: false, also: false }, Demote { by: 2, t: 6, holder: 2, at: 4, to_read: true }, Roster { by: 0, t: 0 }, Demote { by: 0, t: 6, holder: 2, at: 1, to_read: false }, Write { by: 0, t: 3, op: 18, k: 0, v: 2 }, Compact { by: 0, t: 4, op: 18 }, Write { by: 1, t: 0, op: 15, k: 0, v: 3 }, Edge { by: 0, t: 4, holder: 1, role: Some(Role::Read) }, Edge { by: 0, t: 6, holder: 1, role: Some(Role::Admin) }, Roster { by: 0, t: 6 }, Advance { who: None, ms: 3721574 }, Write { by: 1, t: 7, op: 15, k: 2, v: 7 }, Nested { by: 0, other: 2, t: 4, k: 0, text: false, compact: true, also: true }, Demote { by: 0, t: 0, holder: 1, at: 4, to_read: false }, Edge { by: 0, t: 7, holder: 2, role: Some(Role::Write) }, Compact { by: 1, t: 7, op: 4 }, Sync { from: 0, to: 2 }, Write { by: 1, t: 1, op: 4, k: 1, v: 3 }, Write { by: 2, t: 4, op: 0, k: 1, v: 8 }, Demote { by: 0, t: 4, holder: 2, at: 1, to_read: true }, Edge { by: 0, t: 7, holder: 1, role: Some(Role::Write) }, Write { by: 1, t: 0, op: 18, k: 2, v: 5 }];
    let played = play(3401073, &h2);
    let held = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 13, 14, 16, 17, 18, 20, 21, 23, 26, 27, 28, 30];
    let order = [3, 8, 13, 30, 20, 4, 27, 0, 11, 2, 28, 26, 14, 16, 18, 10, 5, 6, 21, 1, 17, 7, 23];
    let (want, got) = (judged(&mut deliver(&played, &held), &played), judged(&mut deliver(&played, &order), &played));
    assert_ne!(want.index.as_ref().unwrap().carried, got.index.as_ref().unwrap().carried, "the carried index differs");
    assert_eq!(alike_exchanged(&played, &want, &held, &got, &order, None, &|_, _| false), None);
}

// spec/commits.md §5 (a snapshot's carried write killed by a lower-stamped write dies for it at
// its `ts`; a copy of a body dropped for its keep bounds joins again), order seed 21187: A's
// keep-at-most-0 snapshot carries B's entry, which B's undo (stamped before the snapshot, unseen
// by A) killed; A's demotion of B then makes the undo invalid. Held after the undo, the snapshot
// dropped (keeping its frontiers); with the demotion first, it stays. A drop before a flip,
// though the invalid killer is stamped before the snapshot (`flip` counts such killers).
#[test]
fn snapshot_dropped_by_earlier_stamped_kill_joins_again_spec_commits_5() {
    use Step::*;
    let h = vec![Write { by: 1, t: 1, op: 19, k: 0, v: 1 }, Sync { from: 1, to: 0 }, Compact { by: 1, t: 4, op: 0 }, Undo { by: 1, back: 1 }, Advance { who: None, ms: 6766743 }, Compact { by: 0, t: 0, op: 20 }, Demote { by: 0, t: 6, holder: 1, at: 1, to_read: false }];
    let played = play(21187, &h);
    let made: Vec<usize> = (0..played.packs.len()).collect();
    let rev: Vec<usize> = made.iter().rev().copied().collect();
    let want = judged(&mut deliver(&played, &made), &played);
    let got = judged(&mut deliver(&played, &rev), &played);
    let snap = |j: &Judged| j.index.as_ref().unwrap().commits.values().find(|c| c.kind == osis_commit::Kind::ContentSnapshot && c.rest.contains("t:gonemap.0")).unwrap().clone();
    assert!(!snap(&want).dropped.is_empty() && !snap(&want).gives.is_empty() && snap(&got).dropped.is_empty(), "dropped in one order only, keeping its frontiers");
    assert_eq!(alike_exchanged(&played, &want, &made, &got, &rev, None, &|_, _| false), None);
    check(21187, &h, LARGE).unwrap();
}

// spec/crdt.md §4.6 Un-merge, §4.7 (an expired delta's non-value writes stay), order seed
// 24111: A writes v5, B writes v1, B's undo of v1 writes v5 back expiring; past its expiry its
// body goes, leaving a value-less write that beats v1. A's later undo superseded it in the state,
// then B's backdated demotion of A un-merges that undo: the value-less write must win again (was
// v1 as made, absent in reverse: the residue lived in the state alone).
#[test]
fn expired_residue_survives_unmerge_spec_crdt_4_6() {
    use Step::*;
    let h = vec![Write { by: 1, t: 7, op: 12, k: 2, v: 5 }, Write { by: 1, t: 5, op: 0, k: 2, v: 4 }, New { by: 0, parent: 3, write: false }, Write { by: 0, t: 0, op: 12, k: 2, v: 1 }, Edge { by: 0, t: 6, holder: 1, role: Some(Role::Write) }, Undo { by: 1, back: 0 }, Undo { by: 0, back: 1 }, Advance { who: None, ms: 7126221 }, Undo { by: 1, back: 2 }, Demote { by: 0, t: 0, holder: 1, at: 0, to_read: false }];
    let played = play(24111, &h);
    let made: Vec<usize> = (0..played.packs.len()).collect();
    // the setup first: in full reverse the expiring commit pends on its thing's creation past T
    // and counts as never received there (flagged suspect)
    let rev: Vec<usize> = (0..played.base).chain((played.base..played.packs.len()).rev()).collect();
    for o in [made, rev] {
        let mut p = deliver(&played, &o);
        assert_eq!(p.engine.get(&played.things[0], &ak("t:brief.0")).unwrap(), None, "order {o:?}");
    }
    let all: Vec<usize> = (0..played.packs.len()).rev().collect();
    let mut p = deliver(&played, &all);
    let suspect = p.engine.suspects().unwrap().iter().any(|x| x.0 == played.things[0] && x.1.as_str() == "t:brief.0");
    assert!(suspect || p.engine.get(&played.things[0], &ak("t:brief.0")).unwrap().is_none(), "differs unflagged");
    check(24111, &h, Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, par_orders: false, threads: 1, sync: false }).unwrap();
}

// spec/requirements.md Decentralization (the index is a function of what is held), seed 50036
// (plain writes expiring, ops 27-29): two expired deltas' value-less list was kept in the
// order they expired, so the persisted index differed by arrival order. Kept sorted.
#[test]
fn valueless_list_order_independent_spec_crdt_4_7() {
    use Step::*;
    let h = vec![Write { by: 1, t: 7, op: 28, k: 1, v: 6 }, Write { by: 1, t: 2, op: 28, k: 1, v: 2 }, Advance { who: None, ms: 4563278 }];
    check(50036, &h, Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, par_orders: false, threads: 1, sync: false }).unwrap();
}

// spec/crdt.md §4.6 Un-merge, §4.7 (residue), spec/commits.md §5 (purge): a purged delta whose
// body was dropped as covered keeps its residue from the coverer's copies, which the purge drops
// next; a later write that superseded it in the state and is un-merged does not take it along
// (was: made order "old" came back, demotion first absent). The purger's re-snapshot would hide
// it once it reaches the node.
#[test]
fn purged_covered_residue_survives_unmerge_spec_crdt_4_6() {
    let mut lp = LocalPeer::new(3, 24112, T0).unwrap();
    lp.sync_all().unwrap();
    let ids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.tid()).collect();
    let mut m = Mutation::new();
    let g = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    m.set(g, &KEPT, &s("k")).unwrap();
    lp.peers[0].commit(m).unwrap();
    set_edge(&mut lp.peers[0].engine, g, ids[1], Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, g, ids[2], Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    let mut seen: BTreeSet<CommitId> = lp.peers[0].engine.commit_ids().into_iter().collect();
    let mut packs: Vec<Package> = seen.iter().map(|id| lp.peers[0].engine.package(id).unwrap().unwrap()).collect();
    let mut take = |lp: &mut LocalPeer, i: usize| -> CommitId {
        let mut last = None;
        for id in lp.peers[i].engine.commit_ids() {
            if seen.insert(id) {
                packs.push(lp.peers[i].engine.package(&id).unwrap().unwrap());
                last = Some(id);
            }
        }
        last.unwrap()
    };
    let set = |lp: &mut LocalPeer, i: usize, v: &str| {
        let mut m = Mutation::new();
        m.set(g, &REG, &s(v)).unwrap();
        lp.peers[i].commit(m).unwrap().unwrap();
    };
    // peer 1's old write, unknown to peer 0 (its snapshot does not cover it)
    set(&mut lp, 1, "old");
    let c0 = take(&mut lp, 1);
    lp.advance(10);
    set(&mut lp, 0, "secret");
    let c = take(&mut lp, 0);
    lp.advance(10);
    lp.peers[0].engine.snapshot(&g, &ak("t:reg.0")).unwrap().unwrap();
    let snap = take(&mut lp, 0);
    lp.advance(10);
    set(&mut lp, 2, "w");
    let w = take(&mut lp, 2);
    lp.advance(10);
    // peer 2 demoted as of before its write: w is invalid
    let scope = DemotionScope { roles: BTreeMap::from([(ids[2], BTreeSet::from([g]))]), content: BTreeMap::from([(ids[2], BTreeSet::from([g]))]) };
    let before = WallMs(lp.peers[2].engine.header(&w).unwrap().ts.wall_ms().0 - 1);
    let f = lp.peers[0].engine.frontier(&scope, before).unwrap();
    let mut m = edge_write(g, ids[2], None);
    m.frontier(f.to_value());
    lp.peers[0].commit(m).unwrap().unwrap();
    let demote = take(&mut lp, 0);
    lp.advance(10);
    let mut m = Mutation::new();
    m.set(g, &KEPT, &s("k2")).unwrap();
    m.purge(osis_commit::PurgeItem::Commit { commit: c, tid: g, ak: ak("t:reg.0") });
    lp.peers[0].commit(m).unwrap().unwrap();
    let purge = take(&mut lp, 0);
    let now = lp.peers.iter().map(|p| p.engine.now()).max().unwrap();
    let base: Vec<&Package> = packs.iter().filter(|p| ![c0, c, snap, w, demote, purge].contains(&p.id)).collect();
    let by = |id: CommitId| packs.iter().find(|p| p.id == id).unwrap();
    let mut got = Vec::new();
    for order in [[c0, c, snap, w, purge, demote], [demote, c0, c, snap, w, purge]] {
        let mut p = Peer::new(FRESH, now).unwrap();
        for pk in &base {
            p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
        }
        for id in order {
            p.engine.ingest(&by(id).bytes, by(id).blobs.clone()).unwrap();
            if id == snap {
                // node-sync's compaction drop of the covered body
                p.engine.drop_body(&c, &g, &ak("t:reg.0")).unwrap();
            }
        }
        assert!(!p.engine.body_not_dropped(&snap, &g, &ak("t:reg.0")), "the purge drops the snapshot");
        got.push(p.engine.get(&g, &ak("t:reg.0")).unwrap());
    }
    assert_eq!(got, vec![None, None]);
}

// spec/permissions.md §5.2 (a part dropped as covered that no coverer carries any more gives
// nothing, as at a node that never held it), spec/crdt.md §4.7 (residue): a purged delta whose
// body was dropped as covered takes its residue from the coverer's copies; when the coverer turns
// invalid the delta is missing again and its residue goes with it, so a rebuild or a restart
// reads as the state just after (was: the residue joined back, hiding "old" again).
#[test]
fn cover_residue_goes_with_cover_spec_perm_5_2() {
    let mut lp = LocalPeer::new(3, 24114, T0).unwrap();
    lp.sync_all().unwrap();
    let ids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.tid()).collect();
    let mut m = Mutation::new();
    let g = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    m.set(g, &KEPT, &s("k")).unwrap();
    lp.peers[0].commit(m).unwrap();
    set_edge(&mut lp.peers[0].engine, g, ids[1], Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, g, ids[2], Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    let set = |lp: &mut LocalPeer, i: usize, v: &str| {
        let mut m = Mutation::new();
        m.set(g, &REG, &s(v)).unwrap();
        lp.peers[i].commit(m).unwrap().unwrap()
    };
    set(&mut lp, 1, "old");
    lp.sync_all().unwrap();
    lp.advance(10);
    let c = set(&mut lp, 0, "secret");
    lp.sync_all().unwrap();
    lp.advance(10);
    let snap = lp.peers[2].engine.snapshot(&g, &ak("t:reg.0")).unwrap().unwrap();
    lp.advance(10);
    lp.sync_all().unwrap();
    lp.advance(10);
    let mut m = Mutation::new();
    m.set(g, &KEPT, &s("k2")).unwrap();
    m.purge(osis_commit::PurgeItem::Commit { commit: c, tid: g, ak: ak("t:reg.0") });
    let purge = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(10);
    // peer 2 demoted as of before its snapshot: it turns invalid
    let scope = DemotionScope { roles: BTreeMap::from([(ids[2], BTreeSet::from([g]))]), content: BTreeMap::from([(ids[2], BTreeSet::from([g]))]) };
    let before = WallMs(lp.peers[2].engine.header(&snap).unwrap().ts.wall_ms().0 - 1);
    let f = lp.peers[0].engine.frontier(&scope, before).unwrap();
    let mut m = edge_write(g, ids[2], None);
    m.frontier(f.to_value());
    let demote = lp.peers[0].commit(m).unwrap().unwrap();
    let pks = lp.packages(0).unwrap();
    let by = |id: CommitId| pks.iter().find(|p| p.id == id).unwrap().clone();
    let snap_pk = lp.peers[2].engine.package(&snap).unwrap().unwrap();
    let now = lp.peers.iter().map(|p| p.engine.now()).max().unwrap();
    let mut p = Peer::new(FRESH, now).unwrap();
    for pk in pks.iter().filter(|pk| ![snap, purge, demote].contains(&pk.id)) {
        p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    p.engine.ingest(&snap_pk.bytes, snap_pk.blobs.clone()).unwrap();
    assert_eq!(p.engine.covered(&snap, &c, &g, &ak("t:reg.0")).unwrap(), Some(true), "S covers the write");
    // node-sync's compaction drop of the covered body
    p.engine.drop_body(&c, &g, &ak("t:reg.0")).unwrap();
    p.engine.ingest(&by(purge).bytes, by(purge).blobs.clone()).unwrap();
    p.engine.ingest(&by(demote).bytes, by(demote).blobs.clone()).unwrap();
    p.engine.reexamine().unwrap();
    let after = p.engine.get(&g, &ak("t:reg.0")).unwrap();
    p.engine.rebuild_state(&g, &ak("t:reg.0")).unwrap();
    assert_eq!(p.engine.get(&g, &ak("t:reg.0")).unwrap(), after, "rebuilt");
    p.restart(FRESH + 1).unwrap();
    assert_eq!(p.engine.get(&g, &ak("t:reg.0")).unwrap(), after, "restarted");
    assert_eq!(after, Some(s("old")), "the purged write is missing again");
}

// spec/crdt.md §4.7 (a copy arriving after T is stripped and joined): a part of an expired
// delta arriving after T, later than the rest of its commit (dropped at expiry while missing),
// joins value-less (was skipped: the whole commit hid "old", the split one showed it).
#[test]
fn expired_late_part_joins_valueless_spec_crdt_4_7() {
    let mut lp = LocalPeer::new(2, 24113, T0).unwrap();
    lp.sync_all().unwrap();
    let ids: Vec<Tid> = (0..2).map(|i| lp.peers[i].engine.tid()).collect();
    let mut m = Mutation::new();
    let g = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    lp.peers[0].commit(m).unwrap();
    set_edge(&mut lp.peers[0].engine, g, ids[1], Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.set(g, &REG, &s("old")).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(10);
    let mut m = Mutation::new();
    let now = lp.peers[0].engine.now();
    m.set(g, &REG, &s("brief")).unwrap();
    m.expires(g, &REG, WallMs(now.0 + 1000)).unwrap();
    m.set(g, &KEPT, &s("k")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(2000);
    let packs: Vec<Package> = lp.peers[0].engine.commit_ids().iter().map(|id| lp.peers[0].engine.package(id).unwrap().unwrap()).collect();
    let now = lp.peers.iter().map(|p| p.engine.now()).max().unwrap();
    let mut got = Vec::new();
    for split in [false, true] {
        let mut p = Peer::new(FRESH, now).unwrap();
        for pk in packs.iter().filter(|pk| pk.id != c) {
            p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
        }
        let pk = packs.iter().find(|pk| pk.id == c).unwrap();
        if split {
            let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
            let reg = b.header.aspects.iter().position(|a| a.ak.as_str() == "t:reg.0");
            let keep = b.parts.iter().map(|x| x.ai).filter(|ai| Some(*ai) != reg).max().unwrap();
            b.parts.retain(|x| x.ai == keep);
            p.engine.ingest(&b.encode(), pk.blobs.clone()).unwrap();
        }
        p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
        let _ = p.engine.reexamine();
        got.push(p.engine.get(&g, &ak("t:reg.0")).unwrap());
    }
    assert_eq!(got, vec![None, None]);
}

// Order seed 27039: a snapshot carries another's writes nested in an expiring put's entry in the
// entry's key-erased record (spec/crdt.md §4.7), their own delta keyed. When the snapshot turns invalid (its
// author revoked) its copies go though their own delta is held (`validity::regiven`), so the
// state is the keyed record alone, as when the snapshot was invalid on arrival.
#[test]
fn invalid_snapshot_key_erased_copies_go_spec_permissions_5_2() {
    use Step::*;
    let h = vec![Demote { by: 0, t: 0, holder: 2, at: 3, to_read: true }, Demote { by: 2, t: 3, holder: 2, at: 0, to_read: false }, Write { by: 1, t: 3, op: 28, k: 1, v: 0 }, Sync { from: 1, to: 0 }, Nested { by: 0, other: 1, t: 0, k: 1, text: false, compact: true, also: true }, Compact { by: 1, t: 4, op: 5 }, Write { by: 0, t: 2, op: 7, k: 1, v: 9 }, Nested { by: 0, other: 2, t: 7, k: 2, text: false, compact: true, also: true }, Roster { by: 0, t: 6 }, Edge { by: 0, t: 4, holder: 2, role: Some(Role::Write) }, Write { by: 0, t: 3, op: 1, k: 0, v: 4 }, Edge { by: 0, t: 7, holder: 1, role: Some(Role::Write) }, Write { by: 0, t: 7, op: 5, k: 2, v: 3 }, Edge { by: 0, t: 0, holder: 1, role: None }];
    let played = play(27039, &h);
    // the held set `check` failed on: neither the put (11) nor its author's nested write (13)
    let held = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 15, 16, 17, 19, 21, 23];
    let reversed: Vec<usize> = held.iter().rev().copied().collect();
    let map = |order: &[usize]| deliver(&played, order).engine.state(&played.things[0], &ak("t:map.0")).unwrap();
    let (made, rev) = (map(&held), map(&reversed));
    assert!(format!("{made:?}").contains("k1"), "the nested writes' own delta keeps them keyed");
    assert_eq!(made, rev);
}




// spec/crdt.md §4.6 (a record a valid snapshot's copy keeps keeps the valid writes nested in
// it), spec/crdt.md §8: order seed 4136, shrunk. The writer's expiring `Set` at k0 writes into an
// entry whose creation it judges invalid but its own earlier snapshot vouches for; un-merge used
// to drop the nested write at the writer, so its later snapshot, which lists the delta, carried
// k0's older content instead of the write value-less. A node that never applied the delta (the
// part went at T while pending) then read k0 where one that applied it read none.
#[test]
fn snapshot_carries_write_nested_in_vouched_entry_seed_4136() {
    use Step::*;
    let h = vec![Aim(Box::new(Nested { by: 2, other: 0, t: 7, k: 0, text: false, compact: true, also: false })), Aim(Box::new(Typed { by: 1, t: 0, op: 19, k: 1, v: 3 })), Aim(Box::new(Typed { by: 1, t: 5, op: 10, k: 1, v: 7 })), Aim(Box::new(Edge { by: 2, t: 7, holder: 1, role: Some(Role::Write) })), Aim(Box::new(Write { by: 1, t: 6, op: 1, k: 1, v: 5 })), Aim(Box::new(Edge { by: 0, t: 6, holder: 2, role: Some(Role::Read) })), Aim(Box::new(Typed { by: 0, t: 7, op: 28, k: 0, v: 8 })), Advance { who: Some(2), ms: 1447 }, Aim(Box::new(Nested { by: 1, other: 0, t: 6, k: 1, text: false, compact: true, also: false }))];
    check(4136, &h, LARGE).unwrap();
}

// spec/permissions.md §4 (a suspect flag is dormant while a held valid snapshot lists its delta;
// judged when read): order seed 4208, shrunk. An expiring register write goes at T while pending at
// a node; node 2's snapshot lists it and settled the flag, then node 2's demotion turned the
// snapshot invalid and took its value-less copy with it: the node reads the older value where one
// that applied the write reads none, and must say so (the flag shows again).
#[test]
fn suspect_shows_again_when_settling_snapshot_turns_invalid_seed_4208() {
    use Step::*;
    let h = vec![Aim(Box::new(Typed { by: 0, t: 3, op: 27, k: 0, v: 8 })), Sync { from: 0, to: 2 }, Aim(Box::new(Demote { by: 0, t: 5, holder: 1, at: 5, to_read: false })), Forged { by: 1, a: 5, b: 7, how: 4, op: 26, k: 1, v: 9 }, Forged { by: 0, a: 4, b: 3, how: 1, op: 15, k: 0, v: 3 }, Aim(Box::new(Demote { by: 0, t: 4, holder: 2, at: 4, to_read: false })), Aim(Box::new(Compact { by: 2, t: 3, op: 0 })), Aim(Box::new(Nested { by: 2, other: 0, t: 1, k: 1, text: false, compact: true, also: true })), Forged { by: 2, a: 0, b: 1, how: 1, op: 0, k: 0, v: 2 }, Aim(Box::new(Typed { by: 1, t: 1, op: 17, k: 2, v: 5 })), Forged { by: 1, a: 1, b: 7, how: 0, op: 10, k: 1, v: 9 }, Aim(Box::new(Compact { by: 0, t: 1, op: 28 })), Aim(Box::new(Typed { by: 0, t: 5, op: 4, k: 2, v: 4 })), Aim(Box::new(Write { by: 2, t: 5, op: 6, k: 1, v: 0 })), NewTop { by: 2 }, Advance { who: None, ms: 5744313 }, Aim(Box::new(Leave { by: 1, t: 2 })), Aim(Box::new(Nested { by: 1, other: 0, t: 7, k: 2, text: true, compact: true, also: true }))];
    check(4208, &h, LARGE).unwrap();
    // the expiring part first (pending, gone at T), then the rest as made but node 2's demotion
    // (the role commit made just before node 2's snapshot) last: the snapshot joins valid and
    // settles the flag, then turns invalid (as made, it joins invalid and settles nothing)
    let played = play(4208, &h);
    let g = played.things[0];
    let n = played.packs.len();
    let header = |i: usize| osis_commit::CommitBlob::decode(&played.packs[i].bytes).unwrap().header;
    let expiring = (0..n).find(|&i| header(i).aspects.iter().any(|a| a.tid == g && a.ak == ak("t:reg.0") && a.expires.is_some())).unwrap();
    let snap = (0..n).find(|&i| header(i).kind == osis_commit::Kind::ContentSnapshot).unwrap();
    let demote = snap - 1;
    assert_eq!(header(demote).kind, osis_commit::Kind::Role);
    let order: Vec<usize> = std::iter::once(expiring).chain((0..n).filter(|&i| i != expiring && i != demote)).chain([demote]).collect();
    let mut p = deliver(&played, &order);
    assert_eq!(p.engine.get(&g, &ak("t:reg.0")).unwrap(), Some(s("g")), "the older value shows: nothing valid carries the expired write");
    let flagged = p.engine.suspects().unwrap();
    assert!(flagged.iter().any(|x| x.0 == g && x.1 == ak("t:reg.0") && x.3 & osis_node::retention::suspect::Why::PendingExpiry as u8 != 0), "{flagged:?}");
}

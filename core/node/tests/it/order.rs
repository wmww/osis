#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! `held_set_decides` (spec/requirements.md Deterministic: what a node shows is a function of
//! the commits it holds, never of the order they came in). One generator (`generate`) plays
//! random histories over three writers: content writes on every encoding (typed and untyped,
//! inside map entries, struct fields and nested texts), grants, demotions with frontiers before,
//! inside and after the demoted writes (some linked), self-removals, compactions, things made
//! under things or by their record alone, flow grants and removals, undo, expiry, every history
//! mode, required retention set and broken, messages, signals, purges by name, wide and by author,
//! commits on several things, hostile commits and bad parts, partial syncs. Each feature draws
//! from its own stream; the seed picks an emphasis (`Emphasis`). Each held set goes to fresh
//! nodes in the orders of one config (`ORDERS`: as made, reversed, as fetched, shuffles, late
//! parts, part at an earlier clock; `Size` scales the counts, the exhaustive size tries every
//! order of short histories), syncing things by seed (`with_syncs`). Each node is judged by
//! `node_checks` against the node holding the same commits and keeping every body, and against
//! held-model (`held.rs`), the engine-independent reference; also reopened after every ingest
//! (`reopens_alike`) and, for parts away, given only what its snapshots leave uncovered
//! (`covered_away`). Every node takes the walk's side in each admin dispute it detected before
//! every judgment, after every ingest included (`disputes::walk_sides`): a default side is first
//! received, so it may rightly differ by arrival order (spec/permissions.md §5.1: alike under the
//! same trust set). Seeds run on a
//! thread per core. The scripted tests below are minimal reproducers, checked in named orders.

use crate::common;
use common::*;
use osis_base::testenv::{caught, par_map, threads};
use osis_base::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_node::local_peer::{LocalPeer, Package, Peer};
use osis_perm::DemotionScope;
use osis_schema::{History, Codec, PurgeBy, Retention};
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
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len() as u64) as usize]
    }
}

/// One step of a history. Thing indexes are taken modulo the things made so far (0 is G, owned
/// by peer 0), so any subsequence of a history is a history (shrinking drops steps).
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Step {
    /// A content write (`op` picks the aspect and shape) by `by` on thing `t`.
    Write { by: usize, t: usize, op: u8, k: u8, v: u8 },
    /// `Write` plus a write of `t:rec.0` under default retention in the same commit: two bodies
    /// when `op` has a keep bound (`generate`'s parts group draws it under purge on replace).
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
    /// A compaction snapshot of one aspect (`op` as in `Write`).
    Compact { by: usize, t: usize, op: u8 },
    /// A new thing whose first admin is thing `parent`, with a write in its creation commit or not.
    New { by: usize, parent: usize, write: bool },
    /// `by` puts entry `k` (a struct, or a text when `text`) on `t`, sends that commit to
    /// `other` alone, `other` writes inside the entry and, when `compact`, compacts the aspect:
    /// another's write nested under a creation that may be invalid; `also`: the put's commit
    /// writes the register too (two parts, one may arrive late).
    Nested { by: usize, other: usize, t: usize, k: u8, text: bool, compact: bool, also: bool },
    /// `by` undoes one of its last commits.
    Undo { by: usize, back: u8 },
    /// A permanent delta (spec/commits.md §5) of `by` on `t`'s register.
    Message { by: usize, t: usize, v: u8 },
    /// A write of the signal `t:sig~0` (spec/commits.md §5 Signals): kept for good, or half an
    /// hour after it is written, by `v`.
    Signal { by: usize, t: usize, v: u8 },
    /// `Purge`, by name only: none when `of` has no such commit.
    PurgeNamed { by: usize, t: usize, of: usize, back: u8, v: u8 },
    /// `by` purges `t`'s register, with a write there: one of `of`'s last commits by name, or (no
    /// such commit) the whole aspect.
    Purge { by: usize, t: usize, of: usize, back: u8, v: u8 },
    /// `by` purges `t`'s register by author: `of`'s deltas (spec/permissions.md §6), as the API does:
    /// no write on the register, a `purge.0` one.
    PurgeAuthor { by: usize, t: usize, of: usize },
    /// Every commit `from` holds to `to`.
    Sync { from: usize, to: usize },
    /// One of `from`'s last commits to `to`.
    Send { from: usize, to: usize, back: u8 },
    /// Time passes (`who`: one peer's clock, else every one).
    Advance { who: Option<usize>, ms: u64 },
    /// Every peer takes the walk's side in each admin dispute it detected (`disputes::walk_sides`),
    /// as every judged node does: `settled`'s compactions are then made under the judged nodes'
    /// trust set (spec/requirements.md Deterministic: reads are a function of the data and the
    /// trust set).
    WalkSides,
    /// The step, its author and thing first pointed at what it can write at play time (`aim`),
    /// so that most drawn steps make a commit.
    Aim(Box<Step>),
    /// The step by a writer predating the undo expiry rule (spec/crdt.md §4.6: an undo writing
    /// back an expiring value expires no later): played with `skip_writer_rules`.
    Old(Box<Step>),
    /// `Write` with the aspect's schema, its sequence offsets fitted to the writer's view
    /// (`fit`). `Write` is untyped: it cannot write sequences or counters and its puts hold a
    /// map encoding beside a field write's struct encoding (a `Slots` position).
    Typed { by: usize, t: usize, op: u8, k: u8, v: u8 },
    /// `Nested` with the schema's struct encoding (`Nested { text: true }` is typed too: an
    /// untyped sequence op is refused).
    NestedItem { by: usize, other: usize, t: usize, k: u8, compact: bool, also: bool },
    /// A commit past the writer's rules (`Engine::commit_hostile`), `how` % 4: a content write on
    /// `a` (for odd `v` acting for `b`); one on each of `a` and `b`; one role commit setting another
    /// peer's edge on both; `by` raising its own edge on `a`. The author is told of a thing it does
    /// not know first, so it may hold no chain to it.
    Forged { by: usize, a: usize, b: usize, how: u8, op: u8, k: u8, v: u8 },
    /// A commit past the writer's rules with a part that hashes right and is bad by itself, `how` % 2:
    /// a content write on `a` and `b`, `b`'s part not decoding; an edge write on both, `b`'s not
    /// decoding.
    BadPart { by: usize, a: usize, b: usize, how: u8 },
    /// `Demote` to no role with a frontier padded past `CHUNK_THRESHOLD`, linked.
    BigDemote { by: usize, t: usize, holder: usize },
    // for the judgment vectors and scripted examples (`generate` draws `NewTop`, `Require`,
    // `Breaking`, `Two` and `TwoEdges` too):
    /// A new thing whose first admin is peer `by` itself: no edge of G reaches it.
    NewTop { by: usize },
    /// A bare edge write past the writer's rules (`Engine::commit_hostile`):
    /// `holder`'s edge on `t` set to `role` with `invite`, or removed.
    Hostile { by: usize, t: usize, holder: usize, role: Option<Role>, invite: Option<Role> },
    /// A `keys.0` write of one field of `t`, unchecked: 1 (`write`) to none, 5 (`deposit_seed`).
    HostileKeys { by: usize, t: usize, field: u64 },
    /// A register write on `t`, unchecked.
    HostileWrite { by: usize, t: usize, v: u8 },
    /// A `required^.0` on `t` (spec/commits.md §5): by `rule % 4`, nothing, `op`'s aspect as
    /// `keep_of(op)`, every `t:` aspect as the default, or every aspect as `keep_of(op)`; `rule & 4`:
    /// past the writer's check, so a non-admin's when not aimed.
    Require { by: usize, t: usize, op: u8, rule: u8 },
    /// `op`'s write with `nobody` retention (or the default, `fits`) past the writer's check: it
    /// breaks most rules `Require` sets.
    Breaking { by: usize, t: usize, op: u8, v: u8, fits: bool },
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
    /// Removals on a new thing of `by`'s own, `other` writing there (`generate` ends every history
    /// with it): `by` adds tags, inserts list elements and text and delivers that to `other`;
    /// `by` deletes the first list element and chars; `other`, later and without the delete,
    /// writes into that element (a write above its reset, hidden) and removes a present tag; `by`
    /// undoes its delete (the chars undeleted, the element's value inserted again).
    Removals { by: usize, other: usize, v: u8 },
    /// A write with a paged delta (spec/crdt.md §8).
    Paged { by: usize, t: usize },
    /// A write of a large atomic value (spec/data-model.md §6).
    Large { by: usize, t: usize },
    /// A removal of `holder` on `t` with its frontier as of now, padded past `CHUNK_THRESHOLD`
    /// with things nobody holds, so it goes by link.
    LinkedDemote { by: usize, t: usize, holder: usize },
    // record-only things and the flows (`random_step` never draws these):
    /// `by` makes a thing by its record alone, whose first admin is itself, or thing `under` (needing
    /// write on it), with a write on it: a plain thing deriving from its first admin, whose
    /// record edge no entry holds.
    RecordOnly { by: usize, under: Option<usize> },
    /// `by` grants `holder` (a peer, or 3: G) `role` on `t` through `Engine::grant`: a plain
    /// target gets secrets of its own first.
    GrantFlow { by: usize, t: usize, holder: usize, role: Role },
    /// `by` removes `holder`'s edge (a peer, or 3: G) on `t`, or lowers it to write, through
    /// `Engine::demote`: a first admin's record edge included (a removal of no entry,
    /// spec/permissions.md §2).
    RemoveFlow { by: usize, t: usize, holder: usize, lower: bool },
}

const OPS: u8 = 37;
/// The ops random histories draw: `list_expiry_history` alone draws the rest.
const DRAWN: u8 = 32;

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
        // with a keep bound (when replaced counts only there): registers, a map under purge on replace
        // (bodies drop as they die), a kept set, kept writes into a map (nested, removals), a
        // kept text, a kept text in a map entry
        16 => "t:kept.0",
        17 | 18 => "t:gone.0",
        19 | 20 => "t:gonemap.0",
        21 => "t:keptset.0",
        22 | 25 => "t:map.0",
        23 | 24 => "t:text.0",
        // expiring twins (`expiry_of`) of a register set, a map put and a text insert
        27 => "t:reg.0",
        28 => "t:map.0",
        29 => "t:text.0",
        // a list insert with history kept until an absolute time (`retention_of`), a register
        // purged on replace
        30 => "t:list.0",
        31 => "t:gone.0",
        // an expiring list element, another's write in it, its removal
        32..=34 => "t:listtext.0",
        // a kept map of strings (an entry's creation and value under one stamp), put and removed
        35 | 36 => "t:keptmap.0",
        _ => "t:docs.0",
    })
}

/// The retention of `op`'s writes when not the default: keep at least 30 min, or purge on replace.
fn keep_of(op: u8) -> Option<Retention> {
    let d = Some(HOUR / 2);
    let at_least = Some(Retention { by: PurgeBy::AuthorOrAdmin, history: Some(osis_schema::History::Keep { until: None, after: d }) });
    // an author-only class among them: an admin's compaction drops none of another's bodies
    let author = Some(Retention { by: PurgeBy::Author, history: Some(osis_schema::History::Keep { until: None, after: d }) });
    let on_replace = Some(Retention { by: PurgeBy::Writer, history: Some(osis_schema::History::PurgeOnReplace) });
    match op % OPS {
        16 | 21..=23 | 35 | 36 => at_least,
        24..=26 => author,
        17..=20 | 31 => on_replace,
        _ => None,
    }
}

/// `keep_of(op)`, with history kept until an absolute time for op 30 and a third of op 16's
/// writes (a list, a register held-model judges; spec/commits.md §5): a second (a peer's own clock
/// steps pass it) or half an hour after `now`, by `v`.
fn retention_of(op: u8, v: u8, now: WallMs) -> Option<Retention> {
    if op % OPS != 30 && !(op % OPS == 16 && v.is_multiple_of(3)) {
        return keep_of(op);
    }
    let until = now.0 + if v.is_multiple_of(2) { 1_000 } else { HOUR / 2 };
    Some(Retention { by: PurgeBy::AuthorOrAdmin, history: Some(History::Keep { until: Some(until), after: None }) })
}

/// The signal `Step::Signal` writes.
fn sig() -> Ak {
    ak("t:sig~0")
}

/// The aspect a purge of `commit` on `t` names: its signal write if it has one on `t`, else
/// `t:reg.0` (a message, a register write).
fn purged_ak(e: &osis_node::Engine, commit: &CommitId, t: Tid) -> Ak {
    let signal = e.header(commit).is_some_and(|h| h.aspects.iter().any(|a| a.tid == t && a.ak == sig()));
    if signal { sig() } else { ak("t:reg.0") }
}

/// The expiry of `op`'s writes after their commit's wall time, if any (spec/crdt.md §4.7): a
/// second (a peer's own clock steps pass it) or half an hour (a global advance does). With
/// `k` 2 the commit also writes `t:rec.0`, expiring with it (one expiry per commit): two
/// parts, so split delivery makes one a late part, maybe arriving after T.
fn expiry_of(op: u8, v: u8) -> Option<u64> {
    matches!(op % OPS, 27..=29 | 32).then_some(if v.is_multiple_of(2) { 1_000 } else { HOUR / 2 })
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
        30 => return content_op(14, k, v),
        32 => PathOp { path: vec![], op: Op::Insert { at, items: vec![s(&val)] } },
        33 => PathOp { path: vec![PathSeg::Index(0)], op: Op::Set(s(&val)) },
        34 => PathOp { path: vec![], op: Op::Delete { at, len: 1 } },
        35 => PathOp { path: vec![key(k)], op: Op::Set(s(&val)) },
        36 => PathOp { path: vec![], op: Op::Remove(s(&format!("k{}", k % 3))) },
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
        "t:listtext.0" => &LISTTEXT,
        "t:rec.0" => &REC,
        "t:kept.0" => &KEPT,
        "t:gone.0" => &GONE,
        "t:gonemap.0" => &GONEMAP,
        "t:keptset.0" => &KEPTSET,
        "t:keptmap.0" => &KEPTMAP,
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
        Require { by, t, op, rule } => pick(lp, by, t, &admin).map(|(by, t)| Require { by, t, op, rule }),
        Breaking { by, t, op, v, fits } => pick(lp, by, t, &write).map(|(by, t)| Breaking { by, t, op, v, fits }),
        Compact { by, t, op } => {
            // an op of an aspect the author holds
            let holds = |lp: &LocalPeer, b: usize, x: &Tid| write(lp, b, x) && holding[b].contains(&(*x, aspect_of(op)));
            pick(lp, by, t, &holds).map(|(by, t)| Compact { by, t, op })
        }
        New { by, parent, write: w } => pick(lp, by, parent, &write).map(|(by, parent)| New { by, parent, write: w }),
        Nested { by, other, t, k, text, compact, also } => pick(lp, by, t, &|lp, b, x| write(lp, b, x) && write(lp, other, x)).filter(|x| x.0 != other).map(|(by, t)| Nested { by, other, t, k, text, compact, also }),
        NestedItem { by, other, t, k, compact, also } => pick(lp, by, t, &|lp, b, x| write(lp, b, x) && write(lp, other, x)).filter(|x| x.0 != other).map(|(by, t)| NestedItem { by, other, t, k, compact, also }),
        Message { by, t, v } => pick(lp, by, t, &write).map(|(by, t)| Message { by, t, v }),
        Signal { by, t, v } => pick(lp, by, t, &write).map(|(by, t)| Signal { by, t, v }),
        PurgeNamed { by, t, of, back, v } => pick(lp, by, t, &write).filter(|x| x.0 == by).map(|(by, t)| PurgeNamed { by, t, of, back, v }),
        Purge { by, t, of, back, v } => pick(lp, by, t, &write).filter(|x| x.0 == by).map(|(by, t)| Purge { by, t, of, back, v }),
        PurgeAuthor { by, t, of } => pick(lp, by, t, &write).filter(|x| x.0 == by).map(|(by, t)| PurgeAuthor { by, t, of }),
        RecordOnly { by, under: Some(t) } => pick(lp, by, t, &write).map(|(by, t)| RecordOnly { by, under: Some(t) }),
        GrantFlow { by, t, holder, role } => pick(lp, by, t, &admin).map(|(by, t)| GrantFlow { by, t, holder, role }),
        RemoveFlow { by, t, holder, lower } => {
            let h = if holder < 3 { ids[holder] } else { things[0] };
            let held = |lp: &LocalPeer, b: usize, x: &Tid| admin(lp, b, x) && lp.peers[b].engine.roster(x).get(&h).is_some_and(|e| !lower || e.role > Role::Write);
            pick(lp, by, t, &held).map(|(by, t)| RemoveFlow { by, t, holder, lower })
        }
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
    match rng.below(45) {
        0..=7 => aim(Step::Typed { by, t, op: rng.below(DRAWN as u64) as u8, k: rng.below(3) as u8, v: rng.below(10) as u8 }),
        8..=10 => aim(Step::Write { by, t, op: rng.pick(&UNTYPED), k: rng.below(3) as u8, v: rng.below(10) as u8 }),
        39 | 40 => {
            let other = (by + 1 + rng.below(2) as usize) % 3;
            aim(Step::NestedItem { by, other, t, k: rng.below(3) as u8, compact: rng.below(3) != 0, also: rng.below(2) == 0 })
        }
        41..=43 => Step::Forged { by, a: t, b: rng.below(8) as usize, how: rng.below(4) as u8, op: rng.below(DRAWN as u64) as u8, k: rng.below(3) as u8, v: rng.below(10) as u8 },
        44 => Step::NewTop { by },
        11..=13 => aim(Step::Edge { by: rng.pick(&[0, 0, 2]), t, holder: rng.pick(&[1, 2]), role: rng.pick(&[None, Some(Role::Read), Some(Role::Write), Some(Role::Write), Some(Role::Admin)]) }),
        14..=17 => aim(Step::Demote { by: rng.pick(&[0, 0, 2]), t, holder: rng.pick(&[1, 2]), at: rng.below(6) as u8, to_read: rng.below(3) == 0 }),
        18 => aim(Step::Leave { by: rng.pick(&[1, 2]), t }),
        19..=21 => aim(Step::Compact { by, t, op: rng.below(DRAWN as u64) as u8 }),
        22 | 23 => aim(Step::New { by: rng.pick(&[0, 0, 2]), parent: t, write: rng.below(2) == 0 }),
        24..=27 => {
            let other = (by + 1 + rng.below(2) as usize) % 3;
            // one draw: `compact` as before `also` (x % 6 % 3 == x % 3)
            let (k, text, c) = (rng.below(3) as u8, rng.below(2) == 0, rng.below(6));
            aim(Step::Nested { by, other, t, k, text, compact: c % 3 != 0, also: c >= 3 })
        }
        28 => aim(Step::Undo { by, back: rng.below(3) as u8 }),
        29..=31 => {
            let from = rng.below(3) as usize;
            Step::Sync { from, to: (from + 1 + rng.below(2) as usize) % 3 }
        }
        32..=35 => {
            let from = rng.below(3) as usize;
            Step::Send { from, to: (from + 1 + rng.below(2) as usize) % 3, back: rng.below(3) as u8 }
        }
        36 => Step::Advance { who: None, ms: HOUR + rng.below(HOUR) },
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
    if let Some(r) = retention_of(op, v, e.now()) {
        m.retention(t, &a, r).unwrap();
    }
    if let Some(ms) = expiry_of(op, v) {
        let at = WallMs(e.now().0 + ms);
        m.expires(t, &a, at).unwrap();
        if k == 2 {
            // one expiry per commit (spec/commits.md §6): the second aspect shares it
            op_on(m, e, t, 15, content_op(15, k, v).1, typed);
            m.expires(t, &aspect_of(15), at).unwrap();
        }
    }
    op_on(m, e, t, op, content_op(op, k, v).1, typed);
    // a second key in the same delta: one replaced leaves the body a live write
    if op % OPS == 19 && v.is_multiple_of(2) {
        op_on(m, e, t, op, content_op(op, k + 1, v).1, typed);
    }
}

/// `holder`'s edge on `t` as remove + put (`None`: removed), spec/permissions.md §2.
fn edge_write(by: &osis_node::Engine, t: Tid, holder: Tid, e: Option<osis_schema::core_types::Edge>) -> Mutation {
    let mut m = Mutation::new();
    m.op(t, &osis_schema::core_types::ROLES, PathOp { path: vec![], op: Op::Remove(Value::Tid(holder)) }).unwrap();
    if let Some(e) = &e {
        m.op(t, &osis_schema::core_types::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(e.to_value()) }).unwrap();
    }
    // an explicit removal, or a write that audits, carries a frontier: an empty one unless the
    // caller sets its own (with none a removal is a finalize, spec/permissions.md §2, §5.1)
    if by.needs_frontier(&t, &holder, e.as_ref()) {
        m.frontier(osis_schema::core_types::Frontier::default().to_value());
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
    /// Keys a node showed differently after its sync exchange than before (`Seen::restored`).
    restored: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// What the per-node checks judged (`Seen::judged`).
    judged: std::sync::Arc<[std::sync::atomic::AtomicU64; 2]>,
    /// Deliveries at an earlier clock whose move to `now` changed a state or a body (`Clock`).
    moved: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// How many commits were made before each step.
    steps_at: Vec<usize>,
    /// A `settled` history: its settling tail's first commit (`settling`). Every order delivers
    /// the tail last, as made, so each settling compaction counts when it arrives; the node then
    /// shows what the keep-everything node does before the sync exchange too, on `settled_last`.
    settle_from: Option<usize>,
    /// The aspects some writer compacted (or could, nothing having changed) after the last commit
    /// of another step, keyed as `shown` keys them: in a `settled` history, those settled. An
    /// aspect no writer is left to compact, or the tail does not compact, is not.
    settled_last: BTreeSet<(String, String)>,
    /// Commits `with_syncs` holds in part for good.
    withheld: u64,
    /// `Cfg::model`: the history for the held-model adapter, and what it compared.
    model: Option<std::sync::Arc<(crate::held::History, std::sync::Mutex<crate::held::Coverage>)>>,
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

/// The bodies of `(t, a)` peer `e` applied that purge item `item` names (`resnapshot`).
fn named_held(e: &osis_node::Engine, item: &osis_commit::PurgeItem, t: Tid, a: &Ak) -> Vec<CommitId> {
    let named = |c: &CommitId, m: &osis_node::engine::Meta| match item {
        osis_commit::PurgeItem::Commit { commit, .. } => c == commit,
        osis_commit::PurgeItem::Aspect { .. } => true,
        osis_commit::PurgeItem::Author { actor, .. } => m.view.actor == *actor,
    };
    let on = |m: &osis_node::engine::Meta| m.header.aspects.iter().any(|x| x.tid == t && x.ak == *a);
    // applied: held, or dropped as covered (its writes in the state through its cover)
    e.core.ix.commits.iter().filter(|(c, m)| named(c, m) && !m.view.kind.is_compaction() && on(m) && (e.body_not_dropped(c, &t, a) || !e.coverers_of(c, &t, a).is_empty())).map(|(c, _)| *c).collect()
}

/// After `by`'s purge request `r` naming `(t, a)`, `held` the named bodies it applied before: a
/// writer re-snapshots unless it holds a snapshot of the aspect the purge left whole covering every
/// one (spec/commits.md §5 Purge; a stripped one goes at hosts), as node-sync does. Without it a node
/// that never held a purged body reads what came before it for good (spec/requirements.md
/// Deterministic, the limit for expiring or purged edits).
fn resnapshot<T, E>(lp: &mut LocalPeer, r: &Result<Option<T>, E>, by: usize, t: Tid, a: &Ak, held: &[CommitId]) {
    let e = &mut lp.peers[by].engine;
    if !matches!(r, Ok(Some(_))) || e.role_on(&t) < Some(Role::Write) {
        return;
    }
    let snaps: Vec<CommitId> = e.core.ix.snapshots.get(&(t, a.clone())).into_iter().flatten().map(|x| x.1).filter(|s| e.holds_valid_snapshot(s, &t, a)).collect();
    let covered = snaps.iter().any(|s| held.iter().all(|b| s != b && e.covered(s, b, &t, a).ok().flatten() == Some(true)));
    if !covered {
        lp.peers[by].clock.advance(1);
        let _ = lp.peers[by].engine.snapshot(&t, a);
    }
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

/// `r`, a commit made past the writer's rules, its ID noted in `unchecked`.
fn noting<E>(r: Result<Option<CommitId>, E>, unchecked: &mut BTreeSet<CommitId>) -> Result<Option<CommitId>, E> {
    if let Ok(Some(id)) = &r {
        unchecked.insert(*id);
    }
    r
}

/// A fresh node under test: it answers removals with no addenda, so what it reads is a function
/// of the commits it received alone (`Engine::write_addenda`; the witness rule has its own tests).
fn fresh(now: WallMs) -> Peer {
    // its account's commits date from before any clock under test, so none parks for drift
    let mut p = Peer::new(FRESH, WallMs(T0.0 - 2 * 86_400_000)).unwrap();
    p.clock.set(now);
    p.engine.write_addenda(false);
    p
}

/// `LocalPeer::new` with every peer answering removals with no addenda (`fresh`).
fn local_peer_off(n: usize, seed: u64, t: WallMs) -> LocalPeer {
    let mut lp = LocalPeer::new(n, seed, t).unwrap();
    for p in &mut lp.peers {
        p.engine.write_addenda(false);
    }
    lp
}

/// Plays `steps` on three peers: 0 is G's first admin and gives 1 write and 2 admin on it. The
/// peers write no addenda (`play_with` for histories carrying them).
pub(crate) fn play(seed: u64, steps: &[Step]) -> Played {
    play_with(seed, steps, false)
}

/// `play`, the three peers answering removals with addenda when `addenda` (spec/permissions.md
/// §5.2): the fresh nodes judging them still write none.
pub(crate) fn play_with(seed: u64, steps: &[Step], addenda: bool) -> Played {
    let mut lp = if addenda { LocalPeer::new(3, seed, T0).unwrap() } else { local_peer_off(3, seed, T0) };
    lp.sync_all().unwrap();
    let ids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
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
    // each record-only thing's first admin
    let mut firsts: BTreeMap<Tid, Tid> = BTreeMap::new();
    // the blobs of `BadPart`, with what their authors' own copies dropped
    let mut forged: BTreeMap<CommitId, Vec<u8>> = BTreeMap::new();
    // every other commit made past the writer's rules: a peer may refuse it as bad input
    let mut unchecked: BTreeSet<CommitId> = BTreeSet::new();
    // per aspect compacted since the last commit of another step: whether a peer could
    let mut compacted_last: BTreeMap<(String, String), bool> = BTreeMap::new();
    let mut steps_at = Vec::new();
    for st in steps {
        let (old, st) = match st {
            Step::Old(x) => (true, &**x),
            x => (false, x),
        };
        for p in &mut lp.peers {
            p.engine.core.skip_writer_rules = old;
        }
        let aimed;
        let st = match st {
            Step::Aim(x) => {
                aimed = aim(x, &mut lp, &things, &ids, &own);
                &aimed
            }
            x => x,
        };
        let before = packs.len();
        steps_at.push(before);
        // typed twins play in the arm of the untyped step
        let (typed, st_) = match st.clone() {
            Step::Typed { by, t, op, k, v } => (true, Step::Write { by, t, op, k, v }),
            Step::NestedItem { by, other, t, k, compact, also } => (true, Step::Nested { by, other, t, k, text: false, compact, also }),
            x => (matches!(x, Step::Nested { text: true, .. }), x),
        };
        let th = |t: usize| things[t % things.len()];
        // why this step made no commit, when refused
        let mut no: Option<String> = None;
        // a `RemoveFlow` of a first admin's edge
        let mut record = false;
        let acted = match st_ {
            Step::Aim(_) | Step::Old(_) | Step::Typed { .. } | Step::NestedItem { .. } => unreachable!("aimed and twinned above"),
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
                if let Some(r) = retention_of(op, v, lp.peers[by].engine.now()) {
                    let _ = m.retention(th(t), &a, r);
                }
                let _ = m.op(th(t), &a2, po2);
                if m.op(th(t), &a, po).is_ok() && lp.peers[by].commit(m).is_ok_and(|x| x.is_some()) {
                    marks[by].push(lp.peers[by].engine.now());
                }
                Some(by)
            }
            Step::Edge { by, t, holder, role } => {
                let m = edge_write(&lp.peers[by].engine, th(t), ids[holder], role.map(edge));
                no = why(&lp.peers[by].commit(m));
                Some(by)
            }
            Step::Grant { by, t, holder, role, until, invite, flow } => {
                let e = osis_schema::core_types::Edge { until: until.map(|ms| WallMs(lp.peers[by].engine.now().0 + ms)), invite, ..edge(role) };
                if flow {
                    lp.peers[by].engine.grant(&th(t), &ids[holder], &e).unwrap();
                } else {
                    let m = edge_write(&lp.peers[by].engine, th(t), ids[holder], Some(e));
                    lp.peers[by].commit(m).unwrap().expect("a grant writes");
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
                    let mut m = edge_write(&lp.peers[by].engine, t, ids[holder], to_read.then_some(edge(Role::Read)));
                    m.frontier(f.to_value());
                    no = why(&lp.peers[by].commit(m));
                }
                Some(by)
            }
            Step::Leave { by, t } => {
                let d = osis_node::flows::Demotion { holder: ids[by], new: None, retain: None };
                no = why(&lp.peers[by].engine.demote(&th(t), &d));
                Some(by)
            }
            Step::Compact { by, t, op } => {
                no = why(&lp.peers[by].engine.snapshot(&th(t), &aspect_of(op)));
                Some(by)
            }
            Step::New { by, parent: p, write } => {
                let admin = th(p);
                let mut m = Mutation::new();
                let t = lp.peers[by].engine.new_thing(&mut m, admin);
                if write {
                    m.set(t, &REG, &s("n")).unwrap();
                }
                let r = lp.peers[by].commit(m);
                no = why(&r);
                if let Ok(Some(id)) = r {
                    things.push(t);
                    parent.insert(t, admin);
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
            Step::Message { by, t, v } => {
                let mut m = Mutation::new();
                m.retention(th(t), &REG, Retention { by: PurgeBy::AuthorOrAdmin, history: Some(osis_schema::History::FOREVER) }).unwrap();
                m.set(th(t), &REG, &s(&format!("m{v}"))).unwrap();
                no = why(&lp.peers[by].commit(m));
                Some(by)
            }
            Step::Signal { by, t, v } => {
                let mut m = Mutation::new();
                let history = if v.is_multiple_of(2) { History::FOREVER } else { History::Keep { until: None, after: Some(HOUR / 2) } };
                m.retention(th(t), &sig(), Retention { by: PurgeBy::AuthorOrAdmin, history: Some(history) }).unwrap();
                m.set(th(t), &sig(), &s(&format!("s{v}"))).unwrap();
                no = why(&lp.peers[by].commit(m));
                Some(by)
            }
            Step::PurgeNamed { by, t, of, back, v } => {
                let t = th(t);
                if let Some(commit) = own[of].len().checked_sub(1 + back as usize).and_then(|i| own[of].get(i)).copied() {
                    let mut m = Mutation::new();
                    let a = purged_ak(&lp.peers[by].engine, &commit, t);
                    let item = osis_commit::PurgeItem::Commit { commit, tid: t, ak: a.clone() };
                    let held = named_held(&lp.peers[by].engine, &item, t, &a);
                    m.purge(item);
                    m.set(t, &REG, &s(&format!("p{v}"))).unwrap();
                    let r = lp.peers[by].commit(m);
                    no = why(&r);
                    resnapshot(&mut lp, &r, by, t, &a, &held);
                }
                Some(by)
            }
            Step::Purge { by, t, of, back, v } => {
                let t = th(t);
                let k = ak("t:reg.0");
                let named = own[of].len().checked_sub(1 + back as usize).and_then(|i| own[of].get(i)).copied();
                let mut m = Mutation::new();
                let a = match named {
                    Some(commit) => purged_ak(&lp.peers[by].engine, &commit, t),
                    None => k,
                };
                let item = match named {
                    Some(commit) => osis_commit::PurgeItem::Commit { commit, tid: t, ak: a.clone() },
                    None => osis_commit::PurgeItem::Aspect { tid: t, ak: a.clone() },
                };
                let held = named_held(&lp.peers[by].engine, &item, t, &a);
                m.purge(item);
                m.set(t, &REG, &s(&format!("p{v}"))).unwrap();
                let r = lp.peers[by].commit(m);
                no = why(&r);
                resnapshot(&mut lp, &r, by, t, &a, &held);
                Some(by)
            }
            Step::PurgeAuthor { by, t, of } => {
                let (t, actor) = (th(t), lp.peers[of].engine.me());
                let mut m = Mutation::new();
                let now = lp.peers[by].engine.now();
                m.set(t, &osis_schema::core_types::PURGE, &now).unwrap();
                let item = osis_commit::PurgeItem::Author { tid: t, ak: ak("t:reg.0"), actor };
                let held = named_held(&lp.peers[by].engine, &item, t, &ak("t:reg.0"));
                m.purge(item);
                let r = lp.peers[by].commit(m);
                no = why(&r);
                resnapshot(&mut lp, &r, by, t, &ak("t:reg.0"), &held);
                Some(by)
            }
            Step::Sync { from, to } => {
                // a hostile commit `to` refuses stops `sync`: then each package is given alone,
                // the refused ones dropped
                if let Err(e) = lp.sync(from, to) {
                    assert_eq!(osis_base::Classified::class(&e), osis_base::ErrorClass::BadInput, "{e}");
                    for pk in lp.packages(from).unwrap() {
                        if let Err(e) = lp.deliver(to, &pk) {
                            assert_eq!(osis_base::Classified::class(&e), osis_base::ErrorClass::BadInput, "{e}");
                            assert!(forged.contains_key(&pk.id) || unchecked.contains(&pk.id), "an honest commit refused: {e}");
                        }
                    }
                }
                None
            }
            Step::Send { from, to, back } => {
                let n = own[from].len();
                if let Some(id) = n.checked_sub(1 + back as usize).and_then(|i| own[from].get(i)).copied()
                    && let Some(pk) = lp.peers[from].engine.package(&id).unwrap()
                    && let Err(e) = lp.deliver(to, &pk)
                {
                    assert!(osis_base::Classified::class(&e) == osis_base::ErrorClass::BadInput && (unchecked.contains(&id) || forged.contains_key(&id)), "an honest commit refused: {e}");
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
                match how % 4 {
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
                        // one expiry per commit (spec/commits.md §6): `b`'s write shares `a`'s
                        if let Some(ms) = expiry_of(op, v) {
                            let at = WallMs(lp.peers[by].engine.now().0 + ms);
                            m.expires(b, &aspect_of(op / 2), at).unwrap();
                        }
                    }
                    2 => {
                        edge_on(&mut m, a, other, edge(Role::Write));
                        edge_on(&mut m, b, other, edge(Role::Write));
                    }
                    _ => edge_on(&mut m, a, ids[by], osis_schema::core_types::Edge { invite: (v % 2 == 0).then_some(Role::Admin), ..edge(Role::Admin) }),
                }
                no = why(&noting(lp.peers[by].engine.commit_hostile(m), &mut unchecked));
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
                let mut bad = BTreeSet::new();
                if how % 2 == 0 {
                    m.set(a, &REG, &s("beside bad")).unwrap();
                    m.set(b, &REG, &s("bad")).unwrap();
                    bad.insert((b, Ak::new("t:reg.0").unwrap()));
                } else {
                    for x in [a, b] {
                        m.op(x, &roles, PathOp { path: vec![PathSeg::Key(Value::Tid(other))], op: Op::Set(edge(Role::Write).to_value()) }).unwrap();
                    }
                    bad.insert((b, Ak::new("roles.0").unwrap()));
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
                    let mut m = edge_write(&lp.peers[by].engine, t, ids[holder], None);
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
            Step::WalkSides => {
                for p in &mut lp.peers {
                    crate::disputes::walk_sides(p);
                }
                None
            }
            Step::RecordOnly { by, under } => {
                let first = under.map_or(ids[by], th);
                let r = lp.peers[by].engine.create_with_admin(&first);
                no = why(&r);
                if let Ok((t, done)) = r {
                    if let Some(id) = done.commits.first() {
                        made_by.insert(t, (by, *id));
                    }
                    let mut m = Mutation::new();
                    m.set(t, &REG, &s("o")).unwrap();
                    no = why(&lp.peers[by].commit(m));
                    things.push(t);
                    firsts.insert(t, first);
                    marks[by].push(lp.peers[by].engine.now());
                }
                Some(by)
            }
            Step::GrantFlow { by, t, holder, role } => {
                let h = if holder < 3 { ids[holder] } else { things[0] };
                no = why(&lp.peers[by].engine.grant(&th(t), &h, &edge(role)));
                Some(by)
            }
            Step::RemoveFlow { by, t, holder, lower } => {
                let h = if holder < 3 { ids[holder] } else { things[0] };
                record = firsts.get(&th(t)) == Some(&h);
                let d = osis_node::flows::Demotion { holder: h, new: lower.then(|| edge(Role::Write)), retain: None };
                no = why(&lp.peers[by].engine.demote(&th(t), &d));
                Some(by)
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
            Step::Hostile { by, t, holder, role, invite } => {
                let m = edge_write(&lp.peers[by].engine, th(t), ids[holder], role.map(|r| osis_schema::core_types::Edge { invite, ..edge(r) }));
                noting(lp.peers[by].engine.commit_hostile(m), &mut unchecked).unwrap().expect("an edge write writes");
                Some(by)
            }
            Step::HostileKeys { by, t, field } => {
                let v = match field {
                    5 => Some([9u8; 32]).to_value(),
                    _ => None::<osis_schema::core_types::Keyset>.to_value(),
                };
                let mut m = Mutation::new();
                m.op(th(t), &osis_schema::core_types::KEYS, PathOp { path: vec![PathSeg::Field(field)], op: Op::Set(v) }).unwrap();
                noting(lp.peers[by].engine.commit_hostile(m), &mut unchecked).unwrap().expect("a keys.0 write writes");
                Some(by)
            }
            Step::Require { by, t, op, rule } => {
                let keep = keep_of(op).unwrap_or_default();
                use osis_schema::core_types::{Required, RequiredRules};
                let every = |r: Retention| RequiredRules { default: Some(Required::new(r, None)), ..RequiredRules::default() };
                let rules = match rule % 4 {
                    0 => RequiredRules::default(),
                    1 => RequiredRules::from_iter([(aspect_of(op), Required::new(keep, None))]),
                    2 => every(Retention::default()),
                    _ => every(keep),
                };
                let m = {
                    let mut m = Mutation::new();
                    m.set(th(t), &osis_schema::core_types::REQUIRED, &rules).unwrap();
                    // a second part in another body class, so the setting may arrive late
                    if rule % 2 == 1 {
                        m.set(th(t), &REG, &s("beside")).unwrap();
                    }
                    m
                };
                no = why(&if rule & 4 != 0 { noting(lp.peers[by].engine.commit_hostile(m), &mut unchecked) } else { lp.peers[by].commit(m) });
                Some(by)
            }
            Step::Breaking { by, t, op, v, fits } => {
                let a = aspect_of(op);
                let mut m = Mutation::new();
                write_op(&mut m, &mut lp.peers[by].engine, th(t), op, 0, v, true);
                m.retention(th(t), &a, if fits { Retention::default() } else { Retention { by: PurgeBy::Nobody, history: Some(History::FOREVER) } }).unwrap();
                // a commit with a second part, its retention its own, in the same class when `v` says;
                // `nobody` beside `nobody` only, one expiry (spec/commits.md §5, §6)
                if v % 2 == 1 && a != aspect_of(0) {
                    let o = aspect_of(0);
                    write_op(&mut m, &mut lp.peers[by].engine, th(t), 0, 1, v, true);
                    let nobody = Retention { by: PurgeBy::Nobody, history: Some(History::FOREVER) };
                    let other = if fits { Retention { by: PurgeBy::Writer, ..Retention::default() } } else { Retention { history: Some(History::Keep { until: Some(osis_commit::FOREVER), after: Some(1) }), ..nobody } };
                    m.retention(th(t), &o, if v % 4 == 1 { if fits { Retention::default() } else { nobody } } else { other }).unwrap();
                    if let Some(ms) = expiry_of(op, v) {
                        m.expires(th(t), &o, WallMs(lp.peers[by].engine.now().0 + ms)).unwrap();
                    }
                }
                no = why(&noting(lp.peers[by].engine.commit_hostile(m), &mut unchecked));
                Some(by)
            }
            Step::HostileWrite { by, t, v } => {
                let mut m = Mutation::new();
                m.set(th(t), &REG, &s(&format!("v{v}"))).unwrap();
                noting(lp.peers[by].engine.commit_hostile(m), &mut unchecked).unwrap();
                Some(by)
            }
            Step::Two { by, a, b, v } => {
                let mut m = Mutation::new();
                m.set(th(a), &REG, &s(&format!("v{v}"))).unwrap();
                m.set(th(b), &REG, &s(&format!("v{v}"))).unwrap();
                no = why(&noting(lp.peers[by].engine.commit_hostile(m), &mut unchecked));
                Some(by)
            }
            Step::Three { by, a, b, c, v } => {
                let mut m = Mutation::new();
                for x in [th(a), th(b), th(c)] {
                    m.set(x, &REG, &s(&format!("v{v}"))).unwrap();
                }
                // `None` (as for `Two`, `HostileWrite`): the values were there already, no commit
                noting(lp.peers[by].engine.commit_hostile(m), &mut unchecked).unwrap();
                Some(by)
            }
            Step::TwoEdges { by, a, b, holder, role } => {
                let mut m = Mutation::new();
                for x in [th(a), th(b)] {
                    m.op(x, &osis_schema::core_types::ROLES, PathOp { path: vec![], op: Op::Remove(Value::Tid(ids[holder])) }).unwrap();
                    m.op(x, &osis_schema::core_types::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(ids[holder]))], op: Op::Set(edge(role).to_value()) }).unwrap();
                }
                no = why(&noting(lp.peers[by].engine.commit_hostile(m), &mut unchecked));
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
            Step::Removals { by, other, v } => {
                // one aspect per commit: no part of them is held away for good (`with_syncs`)
                let po = |path: Vec<PathSeg>, op: Op| PathOp { path, op };
                let tag = s(&format!("t{}", v % 4));
                let mut m = Mutation::new();
                let t = lp.peers[by].engine.new_thing(&mut m, ids[by]);
                let made = lp.peers[by].commit(m).unwrap().expect("a creation writes");
                assert_eq!(lp.peers[by].engine.header(&made).unwrap().aspects.len(), 1, "a creation alone");
                things.push(t);
                made_by.insert(t, (by, made));
                let one = |lp: &mut LocalPeer, p: usize, a: &osis_schema::Aspect<Value>, x: PathOp| {
                    let mut m = Mutation::new();
                    m.op(t, a, x).unwrap();
                    lp.peers[p].commit(m).unwrap().expect("a write")
                };
                let mut sent = vec![made];
                sent.push(one(&mut lp, by, &TAGS, po(vec![], Op::Add(tag.clone()))));
                sent.push(one(&mut lp, by, &LIST, po(vec![], Op::Insert { at: 0, items: vec![s(&format!("a{v}")), s("b")] })));
                sent.push(one(&mut lp, by, &TEXT, po(vec![], Op::Insert { at: 0, items: vec![s("abcd")] })));
                let m = edge_write(&lp.peers[by].engine, t, ids[other], Some(edge(Role::Write)));
                sent.push(lp.peers[by].commit(m).unwrap().expect("a grant writes"));
                for id in sent {
                    let pk = lp.peers[by].engine.package(&id).unwrap().unwrap();
                    lp.deliver(other, &pk).unwrap();
                }
                lp.peers[by].clock.advance(1);
                let dels = [one(&mut lp, by, &LIST, po(vec![], Op::Delete { at: 0, len: 1 })), one(&mut lp, by, &TEXT, po(vec![], Op::Delete { at: 1, len: 2 }))];
                // later than the deletes' stamps, which a seen future commit may hold above `by`'s clock
                let deleted = dels.iter().map(|d| lp.peers[by].engine.header(d).unwrap().ts.wall_ms().0).max().unwrap();
                lp.peers[other].clock.set(WallMs(deleted.max(lp.peers[other].engine.now().0) + 1));
                one(&mut lp, other, &LIST, po(vec![PathSeg::Index(0)], Op::Set(s(&format!("x{v}")))));
                one(&mut lp, other, &TAGS, po(vec![], Op::Remove(tag)));
                lp.peers[by].clock.advance(1);
                for d in dels {
                    lp.peers[by].engine.revert(&d).unwrap();
                }
                for p in [by, other] {
                    marks[p].push(lp.peers[p].engine.now());
                }
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
                let big: osis_base::ValueMap = (0..1100).map(|i| (s(&format!("key-{i:05}")), s(&"x".repeat(40)))).collect();
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
                let mut m = edge_write(&lp.peers[by].engine, t, ids[holder], None);
                m.frontier(f.to_value());
                let id = lp.peers[by].commit(m).unwrap().expect("a removal");
                assert!(lp.peers[by].engine.header(&id).unwrap().links.frontier.is_some(), "the frontier goes by link");
                Some(by)
            }
        };
        if let Some(i) = acted {
            collect(&mut lp, i, &mut seen, &mut packs, &mut authors, &mut own);
            let kind = format!("{st:?}");
            let kind = kind.split(' ').next().unwrap().to_string() + if matches!(st, Step::Nested { text: true, .. }) { "(text)" } else if record { "(record)" } else { "" } + if old { "(old)" } else { "" };
            match st {
                Step::Compact { t, op, .. } => {
                    let k = (format!("{:?}", things[t % things.len()]), aspect_of(*op).as_str().to_string());
                    let could = packs.len() > before || !no.as_deref().is_some_and(|x| x.starts_with("Permission"));
                    *compacted_last.entry(k).or_default() |= could;
                }
                _ if packs.len() > before => compacted_last.clear(),
                _ => {}
            }
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
    let settled_last = compacted_last.into_iter().filter(|x| x.1).map(|x| x.0).collect();
    // the fresh nodes' clock: the latest of the writers' (nothing parks for drift)
    let now = lp.peers.iter().map(|p| p.engine.now()).max().unwrap();
    for pk in &mut packs {
        if let Some(b) = forged.get(&pk.id) {
            pk.bytes = b.clone();
        }
    }
    Played { packs, authors, base, things, now, tally, sync: Syncs::None, restored: Default::default(), judged: Default::default(), moved: Default::default(), steps_at, settle_from: None, settled_last, withheld: 0, model: None }
}

/// Per body (commit, thing, aspect): when it was replaced, for keep-for-D (spec/commits.md §5).
type Replaced = BTreeMap<(CommitId, Tid, Ak), Option<osis_base::Ts>>;

fn replaced_of(e: &mut osis_node::Engine) -> Replaced {
    let mut out = Replaced::new();
    for id in e.commit_ids() {
        let Some(h) = e.header(&id) else { continue };
        for a in &h.aspects {
            out.insert((id, a.tid, a.ak.clone()), e.replaced_at(&id, &a.tid, &a.ak).unwrap());
        }
    }
    out
}
/// What a node shows its user, from the API alone: each aspect's read (or the error reading it)
/// and each of the history's things' roster, keyed by (thing, aspect) as printed (`ROSTER` for a
/// roster). An aspect a node holds nothing of reads `Ok(None)`.
type Shown = BTreeMap<(String, String), String>;

const ROSTER: &str = "roster";
const NOTHING: &str = "Ok(None)";

fn shown(p: &mut Peer, things: &[Tid]) -> Shown {
    let e = &mut p.engine;
    let mut out = Shown::new();
    for (t, a) in e.all_aspects().unwrap() {
        out.insert((format!("{t:?}"), a.as_str().to_string()), format!("{:?}", e.get(&t, &a)));
    }
    for t in things {
        out.insert((format!("{t:?}"), ROSTER.to_string()), format!("{:?}", e.roster(t)));
    }
    out
}

/// The first key where `got` shows other than `want`, outside `skip`.
fn shown_differs(want: &Shown, got: &Shown, skip: &dyn Fn(&(String, String)) -> bool) -> Option<String> {
    let of = |m: &Shown, k: &(String, String)| m.get(k).cloned().unwrap_or_else(|| NOTHING.to_string());
    want.keys().chain(got.keys()).find(|k| of(want, k) != of(got, k) && !skip(k)).map(|k| format!("{} {}:\n  want {}\n  got  {}", k.0, k.1, of(want, k), of(got, k)))
}

/// What a node holding `held` and keeping every body shows (`keep_bodies`): what each node given
/// those commits is judged against, so that arrival orders agree because each equals it.
struct Oracle {
    held: Vec<usize>,
    /// At `played.now`, and at `later_than` (every bound and expiry past).
    now: Shown,
    later: Shown,
    /// `Cfg::model`: every body it holds at `played.now`, for the model's judgment of the bodies
    /// a node dropped (`held::compare`).
    bodies: crate::held::Bodies,
}

fn oracle(played: &Played, held: &[usize]) -> Oracle {
    let mut p = fresh(played.now);
    p.engine.keep_bodies(true);
    for t in played.sync.things() {
        p.engine.set_syncing(*t, true).unwrap();
    }
    // a forged package may be refused, never fail the node
    for &i in held {
        let pk = &played.packs[i];
        if let Err(e) = p.receive(&pk.bytes, pk.blobs.clone()) {
            assert_ne!(osis_base::Classified::class(&e), osis_base::ErrorClass::Local, "the keep-everything node: {e}");
        }
    }
    p.tick().unwrap();
    crate::disputes::walk_sides(&mut p);
    // a purge drops at this node too: what one that fell left missing comes back as anywhere
    fetch_missing(&mut p, played, held);
    let now = shown(&mut p, &played.things);
    let bodies = if played.model.is_some() { crate::held::bodies(&mut p.engine) } else { Default::default() };
    p.clock.set(later_than(played));
    p.tick().unwrap();
    fetch_missing(&mut p, played, held);
    let later = shown(&mut p, &played.things);
    Oracle { held: held.to_vec(), now, later, bodies }
}

/// Past every keep bound and expiry the ops draw (30 min) from any death by `played.now`; close
/// enough that a body held long past its bound shows.
fn later_than(played: &Played) -> WallMs {
    WallMs(played.now.0 + 2 * HOUR)
}

/// The sync exchange, as node-sync makes it (`reopen_undropped`, `Changed::undropped`): every held
/// commit the node itself counts a part of missing is fetched again from the host (the history's
/// packs, which a host holding the label keeps), until none is or a round changes nothing. Only
/// the node's own count decides: a node that fails to count a body missing never gets it back.
fn fetch_missing(p: &mut Peer, played: &Played, held: &[usize]) {
    let missing = |p: &Peer| -> BTreeSet<CommitId> { p.engine.commit_parts_missing().into_iter().filter(|(_, m)| !m.is_empty()).map(|(c, _)| c).collect() };
    let mut was = missing(p);
    while !was.is_empty() {
        for &i in held.iter().filter(|&&i| was.contains(&played.packs[i].id)) {
            let pk = &played.packs[i];
            let _ = p.receive(&pk.bytes, pk.blobs.clone());
        }
        p.reexamine().unwrap();
        let now = missing(p);
        if now == was {
            break;
        }
        was = now;
    }
}

/// P3: no value of a delta past its expiry, or that a held purge request drops, is left in
/// the state or in a held body (spec/requirements.md Purge, spec/commits.md §5, §6).
fn value_past_end(p: &mut Peer, played: &Played, now: WallMs) -> Option<String> {
    let e = &mut p.engine;
    let mut ids = e.commit_ids();
    ids.sort();
    let requests: Vec<CommitId> = ids.iter().filter(|c| e.header(c).is_some_and(|h| !h.purge.is_empty())).copied().collect();
    for id in &ids {
        let Some(h) = e.header(id) else { continue };
        for a in &h.aspects {
            let expired = h.expires.is_some_and(|t| t <= now.0);
            let purged = requests.iter().find(|pc| e.purge_stands(pc, id, &a.tid, &a.ak));
            if !expired && purged.is_none() {
                continue;
            }
            played.judged[1].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Some(w) = e.value_held_of(id, &a.tid, &a.ak).unwrap() {
                return Some(format!("{w} holds a value of {id:?} ({:?}) {:?} {}, expired {expired}, purged by {purged:?}", h.kind, a.tid, a.ak.as_str()));
            }
        }
    }
    let pending: Vec<CommitId> = e.pending().into_iter().map(|x| x.0).collect();
    for id in pending {
        if let Some(w) = e.pending_value_past_end(&id, now).unwrap() {
            return Some(format!("the waiting copy of {id:?} holds a value: {w}"));
        }
    }
    None
}

/// `Cfg::model`: where the node and held-model judge what it holds differently (`held::compare`).
fn model_differs(p: &mut Peer, played: &Played, o: &Oracle) -> Option<String> {
    let m = played.model.as_ref()?;
    let mut cov = crate::held::Coverage::default();
    let d = crate::held::compare(&mut p.engine, &m.0, &o.bodies, &mut cov);
    m.1.lock().unwrap().add(&cov);
    d
}

/// The per-node properties of node `p`, given the commits keep-everything node `o` holds as a
/// delivery `w` (from the history) describes, at `played.now` and again at `later_than`:
/// - held-model's judgment (`Cfg::model`, `held::compare`);
/// - the permission index equals its walk from scratch;
/// - after the sync exchange (`fetch_missing`), it shows what `o` shows, but on an aspect a part
///   Before the exchange a node may rightly show less: a body dropped under a
///   snapshot that later fell, an edit dropped while it did not count, a purge that fell, each
///   missing until a copy arrives or a writer next compacts (spec/requirements.md Deterministic),
///   so in a `settled` history (every writer compacts last) it shows what `o` does before too, but
///   on an aspect no writer is left to compact;
/// - P3 `value_past_end`, before and after the exchange: no purged or expired value is held.
///
/// Leaves `p` past `later_than`, having fetched.
fn node_checks(p: &mut Peer, played: &Played, o: &Oracle) -> Result<(), String> {
    let at = |p: &mut Peer, want: &Shown, when: &str| -> Result<(), String> {
        let at = p.engine.now();
        value_past_end(p, played, at).or_else(|| model_differs(p, played, o)).map_or(Ok(()), |d| Err(format!("{when}: {d}")))?;
        if p.engine.perm_digest(false) != p.engine.perm_digest(true) {
            return Err(format!("{when}: the permission index differs from its walk from scratch"));
        }
        let before = shown(p, &played.things);
        // every writer compacted last: nothing is left apart until a copy arrives, on the aspects
        // a writer compacted (rosters: role commits are never dropped)
        let unsettled = |k: &(String, String)| k.1 != ROSTER && !played.settled_last.contains(k);
        if let Some(d) = shown_differs(want, &before, &unsettled).filter(|_| played.settle_from.is_some()) {
            return Err(format!("{when}, settled: shows other than the node keeping every body: {d}"));
        }
        fetch_missing(p, played, &o.held);
        let after = shown(p, &played.things);
        if let Some(d) = value_past_end(p, played, at) {
            return Err(format!("{when}, after the sync exchange: {d}"));
        }
        played.judged[0].fetch_add(after.len() as u64, std::sync::atomic::Ordering::Relaxed);
        if let Some(d) = shown_differs(want, &after, &|_| false) {
            return Err(format!("{when}, after the sync exchange: shows other than the node keeping every body: {d}"));
        }
        let back = after.iter().filter(|(k, v)| before.get(*k) != Some(*v)).count();
        played.restored.fetch_add(back as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    };
    at(p, &o.now, "now")?;
    p.clock.set(later_than(played));
    p.tick().unwrap();
    at(p, &o.later, "later")
}

/// `node_checks` of a fresh node given `order` (all of it held) on `way`, against the
/// keep-everything node holding the same commits.
fn order_checks(played: &Played, order: &[usize]) -> Result<(), String> {
    let mut held = order.to_vec();
    held.sort();
    let o = oracle(played, &held);
    let mut p = deliver(played, order);
    node_checks(&mut p, played, &o)
}

/// A node given `order` that reopens after every ingest, its clock a millisecond on each time,
/// shows what one given it the same way without reopening shows, once each has fetched what it
/// counts missing (a reopen moves where pending commits apply, so when a part dropped while
/// invalid is valid again). No excuse: both took the same parts at the same clocks.
fn reopens_alike(played: &Played, order: &[usize]) -> Result<(), String> {
    let tick = |p: &mut Peer| {
        let now = p.engine.now();
        p.clock.set(WallMs(now.0 + 1));
    };
    let mut r = deliver_with(played, order, None, None, &mut |p| tick(p));
    let mut p = deliver_with(played, order, None, None, &mut |p| {
        tick(p);
        p.engine.reload().unwrap();
    });
    let held: Vec<usize> = (0..played.packs.len()).collect();
    fetch_missing(&mut r, played, &held);
    fetch_missing(&mut p, played, &held);
    shown_differs(&shown(&mut r, &played.things), &shown(&mut p, &played.things), &|_| false).map_or(Ok(()), Err)
}

/// A node holding what hosts keep once covered bodies go (spec/permissions.md §5.1: a frontier
/// lists commit IDs; §5.2: a valid snapshot vouches for what it carries): every role commit and
/// snapshot whole, each other commit without the parts a held snapshot covers at the node keeping
/// every body (none of it when that leaves no part), as made. `node_checks` it against `o`, the
/// whole set's keep-everything node; how many parts it left out.
fn covered_away(played: &Played, o: &Oracle) -> Result<usize, String> {
    let mut full = fresh(played.now);
    full.engine.keep_bodies(true);
    for t in played.sync.things() {
        full.engine.set_syncing(*t, true).unwrap();
    }
    for pk in &played.packs {
        let _ = full.receive(&pk.bytes, pk.blobs.clone());
    }
    full.reexamine().unwrap();
    let snaps: Vec<(CommitId, Tid, Ak)> = full.engine.commit_ids().iter().filter_map(|c| full.engine.header(c).filter(|h| h.kind.is_compaction()).map(|h| h.aspects.iter().map(|a| (*c, a.tid, a.ak.clone())).collect::<Vec<_>>())).flatten().collect();
    let mut packs = played.packs.clone();
    let (mut order, mut ais, mut left) = (Vec::new(), BTreeMap::new(), 0);
    for (i, pk) in played.packs.iter().enumerate() {
        let h = full.engine.header(&pk.id).filter(|h| !h.kind.is_role() && !h.kind.is_compaction());
        let covered: BTreeSet<usize> = h.as_ref().map_or(BTreeSet::new(), |h| (0..h.aspects.len()).filter(|ai| snaps.iter().any(|(s, t, k)| *t == h.aspects[*ai].tid && *k == h.aspects[*ai].ak && full.engine.covered(s, &pk.id, t, k).unwrap() == Some(true))).collect());
        if covered.is_empty() {
            order.push(i);
            continue;
        }
        let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        let had = b.parts.len();
        b.parts.retain(|p| !covered.contains(&p.ai));
        left += had - b.parts.len();
        if had > 0 && b.parts.is_empty() {
            continue;
        }
        ais.insert(i, b.parts.iter().map(|p| p.ai).collect::<BTreeSet<usize>>());
        packs[i].bytes = b.encode();
        order.push(i);
    }
    let away = Played { packs, ..played.clone() };
    let mut p = deliver(&away, &order);
    node_checks(&mut p, played, o)?;
    Ok(left)
}

const FRESH: u64 = 0x5eed_f00d;

/// What the fresh nodes sync, and when they learn it: apply reads nothing of it (spec/commits.md
/// §4), so every order must judge alike.
#[derive(Clone, Debug)]
enum Syncs {
    None,
    /// `on` from before the first commit, some commits' other parts never held (`withhold`);
    /// `prefix` synced only for a stretch of each delivery.
    Early { on: Vec<Tid>, prefix: Vec<Tid> },
    /// Nothing at first, `on` from a point of each delivery, some stopping and starting again;
    /// some commits' other parts never held.
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

/// The history as the seed's fresh nodes get it, by `seed % 3` (`away`: one of the last two):
/// as made; each thing synced from the start with probability one half and half of the commits
/// with parts on several aspects held in part for good (`Syncs::Early`); or things synced at
/// varying points, with such parts withheld too (`Syncs::Late`). As made when `settled`: a part
/// a node did not sync or never got is not held before the sync exchange, so no compaction
/// settles it there (a `required^.0` body, never snapshotted, changes validity on its own),
/// spec/requirements.md Deterministic: the node reads as if it never had it until it arrives.
fn with_syncs(mut played: Played, seed: u64, settled: bool, away: bool) -> Played {
    let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d) | 1);
    let mut half = |ts: &[Tid]| ts.iter().copied().filter(|_| rng.below(2) == 0).collect::<Vec<_>>();
    let things = played.things.clone();
    let (on, other) = (half(&things), half(&things));
    let prefix: Vec<Tid> = other.into_iter().filter(|t| !on.contains(t)).collect();
    // parts away: always some synced and some parts withheld (the first multi-part commit and
    // half the rest; a parts-away history starts with some)
    match if settled { 0 } else if away { 1 + seed % 2 } else { seed % 3 } {
        0 => {}
        mode => {
            let mut first = away;
            for i in played.base..played.packs.len() {
                let mut b = osis_commit::CommitBlob::decode(&played.packs[i].bytes).unwrap();
                let ais: BTreeSet<usize> = b.parts.iter().map(|x| x.ai).collect();
                if ais.len() > 1 && (std::mem::take(&mut first) || rng.below(2) == 0) {
                    let keep = ais.iter().copied().nth(rng.below(ais.len() as u64) as usize).unwrap();
                    b.parts.retain(|x| x.ai == keep);
                    played.packs[i].bytes = b.encode();
                    played.withheld += 1;
                }
            }
            played.sync = if mode == 1 { Syncs::Early { on, prefix } } else { Syncs::Late { on } };
        }
    }
    played
}

/// A fresh node given `packs` in `order`.
fn deliver(played: &Played, order: &[usize]) -> Peer {
    deliver_with(played, order, None, None, &mut |_| {})
}

/// A fresh node given `packs` in `order`, each commit with parts on several aspects first with
/// those of one of them only (a seeded pick), the rest of it as late parts at the end (before a
/// settled history's settling tail), in reverse (spec/commits.md §4: a late delta joins on
/// arrival).
fn deliver_split(played: &Played, order: &[usize], rng: &mut Rng) -> Peer {
    deliver_with(played, order, Some(rng), None, &mut |_| {})
}

/// A delivery's clock (`deliver_with`): the first `at` ingests at wall time `early`, then the
/// clock moves to the history's end (`tick`: the expiries, purge-on-replace drops and drift parks
/// due in between run) and the rest arrive.
#[derive(Clone, Copy, Debug)]
struct Clock {
    at: usize,
    early: WallMs,
}

/// A seeded clock for delivering `order` (`deliver_with`): a split after 1 to all of its
/// commits, and an early time around the latest `ts` of the commits before it: just after (a
/// one-second expiry or keep bound may pass at the move), just before (those commits ahead of
/// the clock, within drift), up to an hour after, or anywhere from an hour before the first
/// commit to the end (commits parked for drift).
fn clock_of(played: &Played, order: &[usize], rng: &mut Rng) -> Clock {
    let ts = |i: usize| osis_commit::CommitBlob::decode_stored(&played.packs[i].bytes).map_or(0, |b| b.header.ts.wall_ms().0);
    let at = 1 + rng.below(order.len() as u64) as usize;
    let last = order[..at].iter().map(|&i| ts(i)).max().unwrap_or(0);
    let first = order.iter().map(|&i| ts(i)).min().unwrap_or(0).saturating_sub(HOUR);
    let early = match rng.below(4) {
        0 => last + rng.below(2_000),
        1 => last.saturating_sub(rng.below(2_000)),
        2 => last + rng.below(HOUR),
        _ => first + rng.below(played.now.0.saturating_sub(first) + 1),
    };
    Clock { at, early: WallMs(early.min(played.now.0)) }
}

/// A `Clock`'s move: node `p`'s clock to `played.now` and what is due run, counted in
/// `played.moved` when a state or the index changed (a coverage tally, compared nowhere).
fn move_clock(played: &Played, p: &mut Peer) {
    let states = |p: &mut Peer| -> Vec<String> { p.engine.all_aspects().unwrap().into_iter().map(|(t, a)| format!("{:?}", p.engine.state(&t, &a).unwrap())).collect() };
    let (before, index) = (states(p), p.engine.index_digest());
    p.clock.set(played.now);
    p.tick().unwrap();
    if states(p) != before || !index.diff(&p.engine.index_digest()).is_empty() {
        played.moved.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// `deliver` (no `rng`) or `deliver_split`, calling `each` after every ingest; with `clock`,
/// the first ingests at an earlier time (`Clock`). The node is made at `played.now` either way
/// and its clock set back, so its own things are the same as every fresh node's. Before every
/// `each` the node takes the walk's side in each dispute it detected (`disputes::walk_sides`),
/// so its trust set is empty wherever it is judged (spec/permissions.md §5.1).
fn deliver_with(played: &Played, order: &[usize], mut rng: Option<&mut Rng>, clock: Option<Clock>, each: &mut dyn FnMut(&mut Peer)) -> Peer {
    let mut each = |p: &mut Peer| {
        crate::disputes::walk_sides(p);
        each(p)
    };
    let mut p = fresh(played.now);
    // every component's walk saved, so reopens restore them
    p.engine.set_walk_cache_min(1);
    if let Some(c) = clock {
        p.clock.set(c.early);
    }
    let mut late = Vec::new();
    let mut plan = played.sync.plan(order);
    let mut done = 0;
    // a settled history's late parts come before its settling tail: one after it is a write
    // after the writers' last compactions, which then settle nothing
    let deliver_late = |p: &mut Peer, late: &mut Vec<usize>, plan: &mut SyncPlan, done: &mut usize, each: &mut dyn FnMut(&mut Peer)| {
        for &i in std::mem::take(late).iter().rev() {
            plan.upto(p, *done);
            *done += 1;
            let pk = &played.packs[i];
            let _ = p.receive(&pk.bytes, pk.blobs.clone());
            each(p);
        }
    };
    for &i in order {
        if played.settle_from.is_some_and(|f| i >= f) && !late.is_empty() {
            deliver_late(&mut p, &mut late, &mut plan, &mut done, &mut each);
        }
        if clock.is_some_and(|c| c.at == done) {
            move_clock(played, &mut p);
        }
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
        let _ = p.receive(&bytes, pk.blobs.clone());
        each(&mut p);
    }
    if clock.is_some_and(|c| c.at >= order.len()) {
        move_clock(played, &mut p);
        each(&mut p);
    }
    deliver_late(&mut p, &mut late, &mut plan, &mut done, &mut each);
    plan.upto(&mut p, usize::MAX);
    each(&mut p);
    if rng.is_some() {
        let _ = p.reexamine();
        each(&mut p);
    }
    // what is due runs, as node-sync runs it before every read (`SyncEngine::expire_due`): a
    // purge request's floor passing judges its purge-on-replace bodies again (spec/commits.md §5)
    p.tick().unwrap();
    each(&mut p);
    p
}



/// `OSIS_ORDER_DUMP`: on a failure, each commit whose index entry at node `p` differs from the
/// keep-everything node's holding `held` at the same clock (validity, dropped and why, stood in,
/// stripped, valued, missing), and both nodes' pending commits: where a read difference starts.
fn explain(played: &Played, held: &[usize], p: &mut Peer, what: &str) {
    if std::env::var("OSIS_ORDER_DUMP").is_err() {
        return;
    }
    let mut o = fresh(played.now);
    o.engine.keep_bodies(true);
    for t in played.sync.things() {
        o.engine.set_syncing(*t, true).unwrap();
    }
    for &i in held {
        let pk = &played.packs[i];
        let _ = o.receive(&pk.bytes, pk.blobs.clone());
    }
    o.clock.set(p.engine.now());
    o.tick().unwrap();
    crate::disputes::walk_sides(&mut o);
    fetch_missing(&mut o, played, held);
    let (a, b) = (p.engine.index_digest(), o.engine.index_digest());
    let mut out = format!("index differences ({what}), node at {:?}:\n", p.engine.now());
    let pack = |c: &CommitId| played.packs.iter().position(|q| q.id == *c);
    for (i, pk) in played.packs.iter().enumerate() {
        let shown = |e: &osis_node::Engine, c: Option<&osis_node::engine::CommitDigest>| match c {
            None => "absent".to_string(),
            Some(c) => {
                let why: Vec<String> = e.core.ix.commits.get(&pk.id).map(|m| m.dropped.iter().map(|(ai, d)| format!("{ai}: {:?} by {:?}", d.why, d.covered_by.iter().map(pack).collect::<Vec<_>>())).collect()).unwrap_or_default();
                format!("valid {:?} dropped {:?} {why:?} stands in {:?} stripped {:?} valued {:?} missing {:?}", c.valid, c.dropped, c.stands_in, c.stripped, c.valued, c.missing)
            }
        };
        let (x, y) = (shown(&p.engine, a.commits.get(&pk.id)), shown(&o.engine, b.commits.get(&pk.id)));
        if x == y {
            continue;
        }
        let h = o.engine.header(&pk.id).or_else(|| p.engine.header(&pk.id));
        let desc = h.map(|h| format!("{:?} {:?} [{}]", h.kind, h.ts, h.aspects.iter().map(|a| format!("{:?} {}", a.tid, a.ak.as_str())).collect::<Vec<_>>().join(", "))).unwrap_or_default();
        let _ = writeln!(out, "#{i}{} peer {} {desc}\n  node {x}\n  keep {y}", if held.contains(&i) { "" } else { " (not held)" }, played.authors.get(i).map_or("?".into(), |a| a.to_string()));
    }
    for (c, why) in p.engine.pending() {
        let _ = writeln!(out, "node pending #{:?}: {why:?}", pack(&c));
    }
    for (c, why) in o.engine.pending() {
        let _ = writeln!(out, "keep pending #{:?}: {why:?}", pack(&c));
    }
    // thrown out and not fetched again: no wake named what it awaits
    for (who, q) in [("node", &*p), ("keep", &o)] {
        for d in &q.discarded {
            let _ = writeln!(out, "{who} thrown out #{:?}: {}", pack(&d.commit), d.awaits.map_or("a part of an applied commit".into(), |t| format!("awaits {t:?}")));
        }
    }
    eprintln!("{out}");
}

/// `OSIS_ORDER_DUMP`: on an order's failure, prints the packs (index: id, author, kind, aspects)
/// and what the order's node reads as it changes after every ingest. Every failing check prints,
/// the shrink's too (`OSIS_ORDER_SHRINK=1`).
fn dump_order(played: &Played, order: &[usize]) {
    if std::env::var("OSIS_ORDER_DUMP").is_err() {
        return;
    }
    let mut out = String::new();
    let p = deliver(played, order);
    for (i, pk) in played.packs.iter().enumerate() {
        let who = played.authors.get(i).map_or("?".into(), |a| a.to_string());
        match p.engine.header(&pk.id) {
            Some(h) => {
                let aspects: Vec<String> = h.aspects.iter().map(|a| format!("{:?} {}", a.tid, a.ak.as_str())).collect();
                let _ = writeln!(out, "#{i} {:?} peer {who} {:?} {:?} {:?}: {}", pk.id, h.kind, h.form, h.ts, aspects.join(", "));
            }
            None => {
                let _ = writeln!(out, "#{i} {:?} peer {who}: no header", pk.id);
            }
        }
    }
    let _ = writeln!(out, "--- order {order:?}: reads as they change");
    let mut last = Shown::new();
    let mut n = 0;
    deliver_with(played, order, None, None, &mut |p| {
        let step = order.get(n).map_or("end".to_string(), |i| format!("#{i}"));
        n += 1;
        for (k, v) in shown(p, &played.things) {
            if last.get(&k) != Some(&v) {
                let _ = writeln!(out, "  after {step}: {} {} = {v}", k.0, k.1);
                last.insert(k, v);
            }
        }
    });
    eprintln!("{out}");
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
    /// How many of each held set's orders are tried again at an earlier clock (`Clock`): as made
    /// and reversed, then a sample spread evenly over the rest.
    clock: usize,
    /// A seed's orders are independent tasks (each late-parts order split by its own rng), run
    /// on `threads` threads; else they run in turn, split by one rng.
    par_orders: bool,
    /// Set by `held_set_decides_at`: the threads a seed's orders share (cores over the seeds run at once).
    threads: usize,
    /// Fresh nodes sync things, by seed (`with_syncs`).
    sync: bool,
    /// `settled` histories: the whole held set only, equal before the sync exchange too.
    settled: bool,
    /// Every node judged is also compared with held-model (`held::compare`).
    model: bool,
    /// The history's peers answer removals with addenda (`play_with`).
    addenda: bool,
    /// Parts away: fresh nodes sync things and hold half the multi-part commits in part for good
    /// (`with_syncs`), and the whole set is also given without what its snapshots cover
    /// (`covered_away`).
    away: bool,
}

/// The one order config (`held_set_decides`): as made, reversed, as fetched, every order of a
/// whole set of at most 4 commits after the setup, shuffles, two partial held sets, two orders
/// each with late parts and at an earlier clock; every node judged by held-model too. Sizes
/// change the counts (`Size`), never the kinds.
const ORDERS: Cfg = Cfg { all_up_to: 4, every_held: false, random: 2, subsets: 2, split: 2, clock: 2, par_orders: false, threads: 1, sync: true, settled: false, model: true, addenda: false, away: false };

/// A hand-written history's orders, none shuffled or drawn: as made, reversed and as a first
/// sync fetches it, of the whole set and two first-sync prefixes.
const NAMED: Cfg = Cfg { all_up_to: 0, random: 0, subsets: 0, split: 0, clock: 0, sync: false, model: false, ..ORDERS };

/// The arrival orders of `held` tried: as made (the reference), reversed, every order of the
/// held commits after the setup when there are at most `all_up_to` (and the whole set is held,
/// unless `every_held`), and `random` shuffles of everything; a settled history's tail last in
/// each, as made (`Played::settle_from`).
fn orders(played: &Played, held: &[usize], cfg: Cfg, rng: &mut Rng) -> Vec<Vec<usize>> {
    let n = held.len();
    let mut out = vec![held.to_vec(), held.iter().rev().copied().collect(), fill_order(played, held)];
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
    if let Some(f) = played.settle_from {
        for o in &mut out {
            let tail: Vec<usize> = held.iter().copied().filter(|&i| i >= f).collect();
            o.retain(|&i| i < f);
            o.extend(tail);
        }
    }
    out
}

/// `held` as a first sync fetches it (spec/sync.md §6): what judging needs, then newest first.
fn fill_order(played: &Played, held: &[usize]) -> Vec<usize> {
    let mut o = held.to_vec();
    let rank = |i: usize| osis_commit::CommitBlob::decode_stored(&played.packs[i].bytes).map_or(0, |b| osis_node::labeling::fetch_order(&b.header));
    o.sort_by_cached_key(|&i| {
        let r = rank(i);
        (r != 0, std::cmp::Reverse(r))
    });
    o
}

/// The held sets tried: everything, a first sync part way (the setup and its first half and three
/// quarters: it reads as if the rest never came), then `subsets` partial ones (alternately without one
/// writer's commits after the setup, as a node that never heard from it, and without a random
/// third of them); `usize::MAX`: every held set (all of the setup, any of the rest).
fn held_sets(played: &Played, subsets: usize, rng: &mut Rng) -> Vec<Vec<usize>> {
    let n = played.packs.len();
    let mut out = vec![(0..n).collect::<Vec<_>>()];
    let fill = fill_order(played, &(0..n).collect::<Vec<_>>());
    for part in [n / 2, n * 3 / 4] {
        let mut keep: Vec<usize> = fill[..part].iter().copied().chain(0..played.base).collect();
        keep.sort();
        keep.dedup();
        if !out.contains(&keep) {
            out.push(keep);
        }
    }
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
    /// Seeds passed per emphasis (`Emphasis`).
    emphases: BTreeMap<String, u64>,
    /// Its steps' outcomes.
    tally: Tally,
    /// Commit steps and those that made a commit, outside settled histories (whose tail tries
    /// every compaction, most refused).
    steps: (u64, u64),
    /// The reference node's pending commits, by reason, over the held sets.
    pending: BTreeMap<String, u64>,
    /// The reference node's commits with an invalid part, over the held sets.
    invalid: u64,
    /// Commits with a part on each aspect, the whole set held.
    aspects: BTreeMap<String, u64>,
    /// The reference node's parts breaking a required retention, and its `required^.0` parts
    /// fallen invalid, over the held sets.
    broken: u64,
    fallen: u64,
    /// Permanent deltas the reference node shows purged, over the held sets.
    tombstones: u64,
    /// Deltas the reference node shows purged by a request by author, over the held sets.
    by_author: u64,
    /// Keys (aspects, rosters) a node showed differently after its sync exchange than before:
    /// what fetching a body missing again (a fallen purge or cover, an edit that counts again)
    /// brought back.
    restored: u64,
    /// What the per-node checks judged: keys compared with the oracle, deltas past their expiry
    /// or purged (`value_past_end`).
    judged: [u64; 2],
    /// Deliveries at an earlier clock (`Clock`), and those whose move changed a state or a body.
    clocked: u64,
    moved: u64,
    /// Orders delivered reopening after every ingest (`reopens_alike`).
    reopened: u64,
    /// Parts left out as covered (`covered_away`), commits held in part for good (`with_syncs`).
    covered_away: u64,
    withheld: u64,
    /// Settled histories checked.
    settled: u64,
    /// What the held-model comparison covered (`Cfg::model`).
    model: crate::held::Coverage,
}

impl Seen {
    fn add(&mut self, o: &Seen) {
        self.orders += o.orders;
        self.tally.add(&o.tally);
        self.steps = (self.steps.0 + o.steps.0, self.steps.1 + o.steps.1);
        self.invalid += o.invalid;
        self.broken += o.broken;
        self.fallen += o.fallen;
        self.tombstones += o.tombstones;
        self.by_author += o.by_author;
        self.restored += o.restored;
        for (x, y) in self.judged.iter_mut().zip(&o.judged) {
            *x += y;
        }
        self.clocked += o.clocked;
        self.moved += o.moved;
        self.reopened += o.reopened;
        self.covered_away += o.covered_away;
        self.withheld += o.withheld;
        self.settled += o.settled;
        self.model.add(&o.model);
        for (k, v) in &o.pending {
            *self.pending.entry(k.clone()).or_default() += v;
        }
        for (k, v) in &o.aspects {
            *self.aspects.entry(k.clone()).or_default() += v;
        }
        for (k, v) in &o.emphases {
            *self.emphases.entry(k.clone()).or_default() += v;
        }
    }

    /// The coverage tally: a run that did not reach what the generator is for is a harness bug
    /// (the oracle would pass while testing nothing). Every floor follows from the run's size:
    /// every run judged nodes; each emphasis that ran outside the exhaustive cap reached its own
    /// outcome (`by`: those seeds per emphasis; a capped history may stop before its start ends);
    /// seeds of every emphasis outside the cap (`open`) reached a commit of every step kind tried
    /// ten times or more and every judging path (a clock move over 300 clocked deliveries).
    fn floors(&self, open: &Seen, by: &BTreeMap<String, Seen>) {
        let fail = |what: &str| -> ! { panic!("held_set_decides: {what}:\n{}\n{open:?}", open.tally.show()) };
        if self.judged[0] == 0 || self.model.compared == 0 {
            fail("no node judged against the oracle and held-model");
        }
        // each emphasis's outcome, over its own seeds
        type Reached = fn(&Seen) -> bool;
        let checks: [(Emphasis, &str, Reached); 8] = [
            (Emphasis::Purges, "a permanent delta purged by name and one by author", |s| s.tombstones > 0 && s.by_author > 0),
            (Emphasis::Keeps, "kept writes on a register, a set and a map, and held-model judging a covered body kept until T", |s| ["t:kept.0", "t:keptset.0", "t:keptmap.0"].iter().all(|a| s.aspects.contains_key(*a)) && s.model.reached.get("covered kept until T").is_some_and(|n| *n > 0)),
            (Emphasis::Required, "a delta broke a required retention and a setting fell", |s| s.broken > 0 && s.fallen > 0),
            (Emphasis::RecordOnly, "a first admin's record edge removed", |s| s.tally.kinds.get("RemoveFlow(record)").is_some_and(|x| x.1 > 0)),
            (Emphasis::Lists, "list elements written, some by a writer predating the undo expiry rule", |s| s.aspects.contains_key("t:listtext.0") && s.tally.kinds.iter().any(|(k, x)| k.ends_with("(old)") && x.1 > 0)),
            (Emphasis::PartsAway, "parts held away and parts left out as covered", |s| s.withheld > 0 && s.covered_away > 0),
            (Emphasis::Settled, "a settled history judged before its exchange", |s| s.settled > 0),
            (Emphasis::Addenda, "an addendum written", |s| s.aspects.contains_key(osis_schema::core_types::ADDENDA_AK)),
        ];
        for (e, what, reached) in checks {
            if by.get(&format!("{e:?}")).is_some_and(|s| !reached(s)) {
                fail(&format!("{e:?} seeds ran, but not {what}"));
            }
        }
        // every history's `Removals`, as held-model judged them (`held::compare`)
        for (e, s) in by {
            for k in crate::held::REMOVALS {
                if !s.model.reached.get(k).is_some_and(|n| *n > 0) {
                    fail(&format!("{e} seeds ran, but held-model judged no {k}"));
                }
            }
        }
        if !EMPHASES.iter().all(|e| by.contains_key(&format!("{e:?}"))) {
            return;
        }
        let (n, m) = open.steps;
        if m * 2 < n {
            fail(&format!("{m} of {n} commit steps made a commit"));
        }
        // a kind refused ten times in a row is refused always (most kinds commit half the time
        // or more)
        for (k, (n, c)) in &open.tally.kinds {
            if *n >= 10 && *c == 0 {
                fail(&format!("none of {n} {k} steps made a commit"));
            }
        }
        let paths = [
            ("an invalid part", open.invalid > 0),
            ("a commit waiting for what it needs", !open.pending.is_empty()),
            ("a signal write held and judged by held-model", open.aspects.contains_key("t:sig~0") && open.model.reached.get("signal parts").is_some_and(|n| *n > 0)),
            // about one clocked delivery in fifty moves something: judged over 300 or more
            ("a move of an earlier clock changing a state or a body", open.moved > 0 || open.clocked < 300),
            ("purged or expired deltas judged", open.judged[1] > 0),
            ("a reopen after every ingest", open.reopened > 0),
            ("a sync exchange bringing content back", open.restored > 0),
        ];
        for (what, ok) in paths {
            if !ok {
                fail(&format!("a whole emphasis cycle reached no {what}"));
            }
        }
    }
}

/// Checks one history: what it reached, or the first mismatch found, described (a panic counts,
/// so it shrinks).
fn check(seed: u64, steps: &[Step], cfg: Cfg) -> Result<Seen, String> {
    caught(|| check_orders(seed, steps, cfg))
}

fn check_orders(seed: u64, steps: &[Step], cfg: Cfg) -> Result<Seen, String> {
    let played = play_with(seed, steps, cfg.addenda);
    let played = if cfg.settled { settling(played, steps) } else { played };
    let played = if cfg.sync { with_syncs(played, seed, cfg.settled, cfg.away) } else { played };
    let model = cfg.model.then(|| std::sync::Arc::new((crate::held::History::new(&played.packs), std::sync::Mutex::new(crate::held::Coverage::default()))));
    let played = Played { model, ..played };
    let played = &played;
    let mut rng = Rng(seed ^ 0x0de5_ab1e | 1);
    let mut seen = Seen { tally: played.tally.clone(), ..Seen::default() };
    let n = played.packs.len();
    let whole: Vec<usize> = (0..n).collect();
    let split = played.packs.iter().any(|pk| osis_commit::CommitBlob::decode(&pk.bytes).is_ok_and(|b| b.parts.iter().any(|x| x.ai != b.parts[0].ai)));
    let mut full: Option<Oracle> = None;
    for held in held_sets(played, cfg.subsets, &mut rng).into_iter().take(if cfg.settled { 1 } else { usize::MAX }) {
        let of = format!("held {held:?} of {n} commits (base {})", played.base);
        let o = oracle(played, &held);
        // a partial set, then the rest (both ways), ends as the whole set's node
        if let Some(f) = full.as_ref() {
            let rest: Vec<usize> = (0..n).filter(|i| !held.contains(i)).collect();
            for order in [held.iter().chain(&rest).copied().collect::<Vec<_>>(), held.iter().chain(rest.iter().rev()).copied().collect()] {
                let mut p = deliver(played, &order);
                if let Some(d) = node_checks(&mut p, played, f).err() {
                    return Err(format!("{of}, then the rest: order {order:?}: {d}"));
                }
            }
        }
        let orders = orders(played, &held, cfg, &mut rng);
        seen.orders += orders.len();
        // the reference, as made: tallies
        let mut p = deliver(played, &orders[0]);
        for t in &played.things {
            for c in p.engine.purged_on(t, &ak("t:reg.0")).unwrap().into_keys() {
                seen.tombstones += u64::from(p.engine.header(&c).is_some_and(|h| h.aspects.iter().any(|a| a.tid == *t && a.ak.as_str() == "t:reg.0" && p.engine.permanent(&h, a))));
            }
            let (rows, _) = p.engine.held_parts(t, &ak("t:reg.0"), osis_node::engine::listing::CommitFrom::Oldest, usize::MAX - 1, usize::MAX).unwrap();
            for r in &rows {
                if let osis_node::engine::listing::PartBody::Purged(by) = &r.body {
                    seen.by_author += u64::from(p.engine.header(by).is_some_and(|h| h.purge.iter().any(|i| matches!(i, osis_commit::PurgeItem::Author { .. }))));
                }
            }
        }
        if p.discards > 0 {
            *seen.pending.entry("Awaits".to_string()).or_default() += 1;
        }
        for (_, why) in p.engine.pending() {
            let why = format!("{why:?}");
            *seen.pending.entry(why.split('(').next().unwrap_or("").to_string()).or_default() += 1;
        }
        if full.is_none() {
            for id in p.engine.commit_ids() {
                for a in p.engine.header(&id).into_iter().flat_map(|h| h.aspects.clone()) {
                    *seen.aspects.entry(a.ak.as_str().to_string()).or_default() += 1;
                }
            }
        }
        let idx = p.engine.index_digest();
        let invalid = idx.commits.values().filter(|c| c.valid.contains(&false)).count();
        seen.invalid += invalid as u64;
        seen.broken += p.engine.broken_parts() as u64;
        seen.fallen += p.engine.fallen_required() as u64;
        if std::env::var("OSIS_ORDER_STATS").is_ok() {
            eprintln!("seed {seed}: {} of {} commits held ({} base), {} with an invalid part, {} pending, {} things", held.len(), n, played.base, invalid, p.engine.pending().len(), played.things.len());
        }
        // order `k`: the per-node checks, after a reopen (P4) for orders as they are
        let one = |k: usize, split_rng: Option<&mut Rng>| -> Result<(), String> {
            let order = &orders[k];
            if let Some(rng) = split_rng {
                let mut p = deliver_split(played, order, rng);
                return node_checks(&mut p, played, &o).map_err(|d| {
                    explain(played, &held, &mut p, &d);
                    format!("{of}: order #{k} with late parts {order:?}: {d}")
                });
            }
            let mut p = deliver(played, order);
            let before = shown(&mut p, &played.things);
            p.engine.reload().unwrap();
            if let Some(d) = p.engine.misjudged() {
                return Err(format!("{of}, order #{k} {order:?}: judged anew after a reopen: {d}"));
            }
            p.reexamine().unwrap();
            if let Some(d) = shown_differs(&before, &shown(&mut p, &played.things), &|_| false) {
                return Err(format!("{of}, order #{k} {order:?}: reopen differs: {d}"));
            }
            node_checks(&mut p, played, &o).map_err(|d| {
                explain(played, &held, &mut p, &d);
                dump_order(played, order);
                format!("{of}, order #{k} {order:?}: {d}")
            })
        };
        // order `k` with its first commits delivered at an earlier clock (`clock_of`, drawn from
        // its own rng)
        let clock_base = seed.wrapping_mul(0xbf58_476d_1ce4_e5b9) ^ (held.len() as u64).wrapping_mul(0x94d0_49bb_1331_11eb);
        let clocks = cfg.clock.min(orders.len());
        // the `i`th clocked order: as made, reversed, then evenly spread over the rest
        let clocked = |i: usize| -> Result<(), String> {
            let k = if i < 2 || clocks <= 2 { i } else { 2 + (i - 2) * (orders.len() - 2) / (clocks - 2) };
            let order = &orders[k];
            let c = clock_of(played, order, &mut Rng(clock_base ^ (k as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1));
            // `Cfg::model`: held-model judges the node after every ingest too, at the early clock
            // and after the move (a drop before its bound or a value kept past its expiry shows
            // only between ticks)
            let mut early: Option<String> = None;
            let mut done = 0;
            let mut p = deliver_with(played, order, None, Some(c), &mut |p| {
                done += 1;
                if early.is_none() {
                    early = model_differs(p, played, &o).map(|d| format!("after {done} ingests at {:?}: {d}", p.engine.now()));
                    if let Some(d) = &early {
                        explain(played, &held, p, d);
                    }
                }
            });
            early
                .map_or(Ok(()), Err)
                .and_then(|_| {
                    node_checks(&mut p, played, &o).inspect_err(|d| explain(played, &held, &mut p, d))
                })
                .map_err(|d| format!("{of}: order #{k} at an earlier clock {c:?} {order:?}: {d}"))
        };
        // late parts only matter when a commit has parts on several aspects; without one the
        // sequential modes still deliver the first two again and re-examine
        let splits = if split || !cfg.par_orders { cfg.split.min(orders.len()) } else { 0 };
        seen.orders += clocks;
        seen.clocked += clocks as u64;
        if cfg.par_orders {
            // tasks: orders 0.. as they are, then 0.. with late parts, each split by its own rng,
            // then 0.. at an earlier clock
            let tasks: Vec<u64> = (0..orders.len() + splits + clocks).map(|x| x as u64).collect();
            let base = rng.0;
            let errs = par_map(&tasks, cfg.threads, |x| {
                let x = x as usize;
                caught(|| match x {
                    x if x < orders.len() => one(x, None),
                    x if x < orders.len() + splits => one(x - orders.len(), Some(&mut Rng(base ^ (x as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1))),
                    x => clocked(x - orders.len() - splits),
                })
            });
            if let Some(e) = errs.into_iter().find_map(Result::err) {
                return Err(e);
            }
        } else {
            for k in 0..orders.len() {
                one(k, None)?;
            }
            for k in 0..splits {
                one(k, Some(&mut rng))?;
            }
            for k in 0..clocks {
                clocked(k)?;
            }
        }
        if held == whole {
            if played.settle_from.is_none() {
                // a node reopening after every ingest (its clock moving) reads as one that never did
                for order in &orders[..2] {
                    reopens_alike(played, order).map_err(|d| format!("{of}, order {order:?} reopened after every ingest: {d}"))?;
                    seen.reopened += 1;
                }
            }
            if cfg.away {
                seen.covered_away += covered_away(played, &o).map_err(|d| format!("{of} without what its snapshots cover: {d}"))? as u64;
            }
            full = Some(o);
        }
    }
    seen.withheld = played.withheld;
    if played.settle_from.is_none() {
        seen.steps = played.tally.totals();
    }
    seen.settled = u64::from(played.settle_from.is_some());
    if let Some(m) = &played.model {
        seen.model = m.1.lock().unwrap().clone();
    }
    seen.restored = played.restored.load(std::sync::atomic::Ordering::Relaxed);
    seen.moved = played.moved.load(std::sync::atomic::Ordering::Relaxed);
    seen.judged = std::array::from_fn(|i| played.judged[i].load(std::sync::atomic::Ordering::Relaxed));
    Ok(seen)
}

/// Drops steps while the history still fails; the shortest failing history found. A `settled`
/// history keeps its settling tail whole: one cut short settles nothing.
fn shrink(seed: u64, mut steps: Vec<Step>, cfg: Cfg) -> (Vec<Step>, String) {
    let mut err = check(seed, &steps, cfg).unwrap_err();
    let tail = if cfg.settled { settled(Vec::new()).len() } else { 0 };
    let mut i = 0;
    while i + tail < steps.len() {
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

/// What a seed leans toward, by `seed % 8`: every feature is drawn in every history, each from its
/// own stream (`generate`), and the emphasis raises one group's share or shapes the whole
/// history (settled, addenda, parts away).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Emphasis {
    /// Permanent messages, signal writes, purges by name, wide and by author.
    Purges,
    /// Writes under keep-at-least (after replaced, or until T) and their compactions.
    Keeps,
    /// Required retention set, broken and fallen.
    Required,
    /// Things made by their record alone, grants and removals through the flows.
    RecordOnly,
    /// Sequences: expiring list elements, texts, writers predating the undo expiry rule.
    Lists,
    /// Multi-part commits held in part for good, split over things, bad parts, covered parts left
    /// out (`Cfg::away`).
    PartsAway,
    /// Every writer compacts last (`settled`): alike before the sync exchange too.
    Settled,
    /// The writers answer removals with addenda (`play_with`).
    Addenda,
}

const EMPHASES: [Emphasis; 8] = [Emphasis::Purges, Emphasis::Keeps, Emphasis::Required, Emphasis::RecordOnly, Emphasis::Lists, Emphasis::PartsAway, Emphasis::Settled, Emphasis::Addenda];

fn emphasis(seed: u64) -> Emphasis {
    EMPHASES[(seed % EMPHASES.len() as u64) as usize]
}

/// A step of a thing's required retention: an admin's change or a write that may break it.
fn required_step(r: &mut Rng) -> Step {
    let (by, t, op) = (r.below(3) as usize, r.below(3) as usize, r.below(DRAWN as u64) as u8);
    Step::Aim(Box::new(if r.below(3) == 0 {
        Step::Require { by: r.pick(&[0, 0, 2]), t, op, rule: r.below(4) as u8 }
    } else {
        Step::Breaking { by, t, op, v: r.below(10) as u8, fits: r.below(4) == 0 }
    }))
}

/// The ops of writes that keep history: after replaced (registers, sets, map fields, texts, a
/// map of strings), and until an absolute time (a list insert).
const KEPT_OPS: [u8; 9] = [16, 21, 22, 23, 24, 30, 35, 36, 26];
/// Sequence ops: texts in a map entry, texts, lists, kept texts, expiring list elements, others'
/// writes in them and their removals.
const SEQ_OPS: [u8; 12] = [8, 9, 10, 11, 14, 23, 24, 26, 32, 32, 33, 34];

/// One history of `len` steps for `seed`, and its emphasis. Every step first draws its group
/// (`General` mostly; the emphasis's own group five times its share), then draws its step from
/// that group's own stream, so a change to one group's draws leaves every other group's steps
/// as they were. Groups other than `General` act on the first three things, so their steps meet.
/// The emphasis also shapes the whole history: a start that reaches its outcome (a fallen and a
/// broken required setting, a record-only thing, an addendum, a signal), the settling tail.
fn generate(seed: u64, len: usize) -> (Emphasis, Vec<Step>) {
    use Step::*;
    let e = emphasis(seed);
    let stream = |k: u64| Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(k.wrapping_mul(0xd1b5_4a32_d192_ed03)) | 1);
    let mut pick = stream(1);
    let (mut general, mut purges, mut keeps, mut required, mut record, mut lists, mut parts) = (stream(2), stream(3), stream(4), stream(5), stream(6), stream(7), stream(8));
    let aim = |x: Step| Aim(Box::new(x));
    let mut h = Vec::new();
    // the start an emphasis needs, from its group's stream
    match e {
        // a signal, a message purged by author and one purged by name
        Emphasis::Purges => {
            let v = purges.below(10) as u8;
            let tick = Advance { who: None, ms: 1_000 };
            h.extend([aim(Signal { by: 1, t: 0, v }), Message { by: 1, t: 0, v }, Sync { from: 1, to: 0 }, tick.clone(), PurgeAuthor { by: 0, t: 0, of: 1 }, Message { by: 2, t: 0, v }, Sync { from: 2, to: 0 }, tick, Purge { by: 0, t: 0, of: 2, back: 0, v }]);
        }
        // a register write kept until T (`retention_of`: `v` 3 or 9) replaced and compacted, then
        // writes on a kept set and map (an even `v` adds to the set)
        Emphasis::Keeps => {
            let tick = Advance { who: None, ms: 10 };
            h.extend([Typed { by: 0, t: 0, op: 16, k: 0, v: 3 + 6 * keeps.below(2) as u8 }, tick.clone(), Typed { by: 0, t: 0, op: 16, k: 0, v: 2 * keeps.below(5) as u8 }, tick, Compact { by: 0, t: 0, op: 16 }]);
            h.extend([21, 35].map(|op| Typed { by: keeps.below(3) as usize, t: 0, op, k: keeps.below(3) as u8, v: 2 * keeps.below(5) as u8 }));
        }
        Emphasis::Required => {
            let op = required.pick(&KEPT_OPS);
            // the first admin's setting stands and 1's write breaks it; Carol's, a second on, falls
            // when Alice demotes her as of the setup (Carol has no writes before it)
            h.extend([Require { by: 0, t: 0, op, rule: 3 }, Advance { who: None, ms: 1_000 }, Require { by: 2, t: 0, op, rule: 2 }, Breaking { by: 1, t: 0, op, v: 1, fits: false }, Sync { from: 2, to: 0 }, Demote { by: 0, t: 0, holder: 2, at: 0, to_read: false }]);
        }
        // an expiring list element by a writer predating the undo expiry rule, another's edit in it
        Emphasis::Lists => {
            let v = 2 * lists.below(5) as u8;
            h.extend([Old(Box::new(Typed { by: 0, t: 0, op: 32, k: 0, v })), Typed { by: 1, t: 0, op: 33, k: 0, v: v + 1 }]);
        }
        // a record-only thing (thing 1), another admin, and its first admin's record edge removed
        // two two-part commits by G's first admin (`with_syncs` holds one in part), every peer
        // given them, then its snapshots of both aspects covering them (`covered_away` leaves
        // those parts out)
        Emphasis::PartsAway => {
            let op = parts.pick(&[17, 18, 19, 31]);
            let v = parts.below(5) as u8;
            let tick = Advance { who: None, ms: 10 };
            h.extend([Mixed { by: 0, t: 0, op, k: 0, v }, tick.clone(), Mixed { by: 0, t: 0, op, k: 0, v: v + 5 }, tick, Compact { by: 0, t: 0, op: 15 }, Compact { by: 0, t: 0, op }, Sync { from: 0, to: 1 }, Sync { from: 0, to: 2 }]);
        }
        Emphasis::RecordOnly => h.extend([RecordOnly { by: 0, under: None }, GrantFlow { by: 0, t: 1, holder: 2, role: Role::Admin }, RemoveFlow { by: 0, t: 1, holder: 0, lower: false }]),
        Emphasis::Addenda => {
            // Bob's write reaches Carol, Alice demotes him with a frontier before it, Carol applies
            // the demotion and vouches for the write, and grants Bob write again
            h.extend([Write { by: 1, t: 0, op: 0, k: 0, v: 0 }, Sync { from: 1, to: 2 }, Advance { who: None, ms: 1_000 }, Demote { by: 0, t: 0, holder: 1, at: 0, to_read: false }, Sync { from: 0, to: 2 }, Edge { by: 2, t: 0, holder: 1, role: Some(Role::Write) }]);
        }
        _ => {}
    }
    // group shares: general, purges, keeps, required, record-only, lists, parts
    let mut weights = [40u64, 6, 6, 5, 4, 5, 4];
    let own = match e {
        Emphasis::Purges => Some(1),
        Emphasis::Keeps => Some(2),
        Emphasis::Required => Some(3),
        Emphasis::RecordOnly => Some(4),
        Emphasis::Lists => Some(5),
        Emphasis::PartsAway => Some(6),
        _ => None,
    };
    if let Some(g) = own {
        weights[g] *= 5;
    }
    let total: u64 = weights.iter().sum();
    while h.len() + 1 < len {
        let mut x = pick.below(total);
        let g = weights.iter().position(|w| x < *w || { x -= w; false }).unwrap_or(0);
        h.push(match g {
            0 => random_step(&mut general),
            1 => {
                let r = &mut purges;
                let (by, t, v) = (r.below(3) as usize, r.below(3) as usize, r.below(10) as u8);
                match r.below(10) {
                    0..=3 => aim(Message { by, t, v }),
                    4 | 5 => aim(Purge { by: r.below(3) as usize, t, of: by, back: r.below(4) as u8, v }),
                    6 => aim(PurgeNamed { by: r.below(3) as usize, t, of: r.below(3) as usize, back: r.below(3) as u8, v }),
                    7 => aim(PurgeAuthor { by: r.below(3) as usize, t, of: by }),
                    _ => aim(Signal { by, t, v }),
                }
            }
            2 => {
                let r = &mut keeps;
                let (by, t, op) = (r.below(3) as usize, r.below(2) as usize, r.pick(&KEPT_OPS));
                match r.below(10) {
                    0..=4 => aim(Typed { by, t, op, k: r.below(3) as u8, v: r.below(10) as u8 }),
                    5..=7 => aim(Compact { by, t, op }),
                    8 => aim(Undo { by, back: r.below(3) as u8 }),
                    _ => Send { from: by, to: (by + 1 + r.below(2) as usize) % 3, back: r.below(3) as u8 },
                }
            }
            3 => required_step(&mut required),
            4 => {
                let r = &mut record;
                let (by, t) = (r.below(3) as usize, r.below(8) as usize);
                match r.below(6) {
                    0 if r.below(2) == 0 => RecordOnly { by, under: None },
                    0 => aim(RecordOnly { by, under: Some(0) }),
                    1 | 2 => aim(GrantFlow { by, t, holder: r.below(4) as usize, role: r.pick(&[Role::Read, Role::Write, Role::Admin, Role::Admin]) }),
                    _ => aim(RemoveFlow { by, t, holder: r.below(4) as usize, lower: r.below(4) == 0 }),
                }
            }
            5 => {
                let r = &mut lists;
                let (by, t, op) = (r.below(3) as usize, r.below(2) as usize, r.pick(&SEQ_OPS));
                let step = match r.below(10) {
                    0..=5 => aim(Typed { by, t, op, k: r.below(3) as u8, v: r.below(10) as u8 }),
                    6 | 7 => aim(Compact { by, t, op }),
                    8 => aim(Undo { by, back: r.below(3) as u8 }),
                    _ => Advance { who: Some(by), ms: 400 + r.below(800) },
                };
                // a writer predating the undo expiry rule, in a quarter of the writes and undos
                if !matches!(step, Advance { .. }) && !matches!(&step, Aim(x) if matches!(**x, Compact { .. })) && r.below(4) == 0 { Old(Box::new(step)) } else { step }
            }
            _ => {
                let r = &mut parts;
                let (by, a, b) = (r.below(3) as usize, r.below(3) as usize, r.below(3) as usize);
                let op = r.pick(&[17, 18, 19, 19, 20, 30, 31]);
                match r.below(13) {
                    // a removal whose frontier goes by link
                    12 => BigDemote { by: 0, t: a, holder: 1 + b % 2 },
                    0..=3 => Mixed { by, t: a % 2, op, k: r.below(3) as u8, v: r.below(10) as u8 },
                    // a snapshot covering what a node may then hold away
                    10 | 11 => aim(Compact { by, t: a % 2, op: r.pick(&[op, 15, 0]) }),
                    4 => Two { by, a, b: (a + 1 + b % 2) % 3, v: r.below(10) as u8 },
                    // one role commit on two things
                    5 => TwoEdges { by, a, b: (a + 1 + b % 2) % 3, holder: (by + 1) % 3, role: r.pick(&[Role::Read, Role::Write]) },
                    6 => BadPart { by, a, b: (a + 1) % 3, how: r.below(2) as u8 },
                    7 => aim(Nested { by, other: (by + 1 + r.below(2) as usize) % 3, t: a, k: r.below(3) as u8, text: r.below(2) == 0, compact: r.below(2) == 0, also: true }),
                    8 => Forged { by, a, b, how: 1, op: 27 + r.below(3) as u8, k: 2, v: r.below(10) as u8 },
                    _ => {
                        let from = r.below(3) as usize;
                        Sync { from, to: (from + 1 + r.below(2) as usize) % 3 }
                    }
                }
            }
        });
    }
    // every history ends in removals held-model judges (a list element's, chars brought back, a
    // present tag's): on a thing of its own, so no earlier step's rights decide them; last, so
    // the exhaustive size's cap keeps its random prefixes
    let mut r = stream(9);
    let by = r.below(3) as usize;
    h.push(Removals { by, other: (by + 1 + r.below(2) as usize) % 3, v: r.below(10) as u8 });
    if e == Emphasis::Settled {
        h = settled(h);
    }
    (e, h)
}

/// `cfg` for a history of emphasis `e`.
fn cfg_of(e: Emphasis, cfg: Cfg) -> Cfg {
    Cfg { settled: e == Emphasis::Settled, addenda: e == Emphasis::Addenda, away: e == Emphasis::PartsAway, ..cfg }
}

/// The longest prefix of `steps` making at most `max` commits after the setup (a prefix of a
/// history plays as its start), for the exhaustive size. A play that panics keeps its length:
/// `check` reports it.
fn cap(seed: u64, steps: &[Step], addenda: bool, max: usize) -> Vec<Step> {
    let fits = |k: usize| caught(|| Ok::<_, String>({
        let p = play_with(seed, &steps[..k], addenda);
        p.packs.len() - p.base <= max
    }))
    .unwrap_or(true);
    let (mut lo, mut hi) = (0, steps.len());
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if fits(mid) { lo = mid } else { hi = mid - 1 }
    }
    steps[..lo].to_vec()
}

/// A run of `held_set_decides`: seeds, steps per history, the orders, and for the exhaustive size
/// the bound on commits after the setup.
struct Size {
    name: &'static str,
    seeds: Vec<u64>,
    len: usize,
    cfg: Cfg,
    exhaustive: Option<usize>,
    /// Read from the environment: a seed replays alone by `OSIS_ORDER_SEED`.
    env: bool,
}

/// Default tests: a seed of every emphasis, and one of every emphasis capped to 4 commits after the
/// setup, checked in every order of every held set; no environment read.
fn quick() -> Vec<Size> {
    vec![
        Size { name: "quick", seeds: (0..8).collect(), len: 32, cfg: ORDERS, exhaustive: None, env: false },
        Size { name: "quick, exhaustive", seeds: (100..108).collect(), len: 30, cfg: Cfg { all_up_to: 4, every_held: true, random: 0, subsets: 1, split: usize::MAX, clock: 4, ..ORDERS }, exhaustive: Some(4), env: false },
    ]
}

/// The environment's range (`OSIS_ORDER_START`, `OSIS_ORDER_SEEDS`, or `OSIS_ORDER_SEED` alone),
/// a tenth of `full` unless `OSIS_FULL=1`; `OSIS_ORDER_LEN` sets the steps, `OSIS_ORDER_CLOCK`
/// the orders per held set at an earlier clock.
fn from_env(name: &'static str, full: std::ops::Range<u64>, len: usize, cfg: Cfg, exhaustive: Option<usize>) -> Size {
    use osis_base::testenv::{Seeds, large, u64_var};
    let range = Seeds::from_env("OSIS_ORDER_START", "OSIS_ORDER_SEEDS", large(full));
    range.announce(&format!("order::held_set_decides ({name})"));
    let seeds = u64_var("OSIS_ORDER_SEED").map_or_else(|| range.range.collect(), |s| vec![s]);
    let len = u64_var("OSIS_ORDER_LEN").map_or(len, |n| n as usize);
    let clock = u64_var("OSIS_ORDER_CLOCK").map_or(cfg.clock, |n| n as usize);
    Size { name, seeds, len, cfg: Cfg { clock, ..cfg }, exhaustive, env: true }
}

/// `plain`: 80 seeds of 60 steps at large size (`OSIS_FULL=1`), a tenth at small size.
fn plain() -> Size {
    from_env("plain", 0..80, 60, Cfg { random: 6, subsets: 4, ..ORDERS }, None)
}

/// Every order of the whole set and of every held set, each with late parts, of histories of at
/// most 6 commits after the setup (720 orders), 24 of them at an earlier clock; a seed's orders
/// run on a thread each.
fn exhaustive() -> Size {
    from_env("exhaustive", 0..80, 40, Cfg { all_up_to: 6, every_held: true, random: 0, subsets: 2, split: usize::MAX, clock: 24, par_orders: true, ..ORDERS }, Some(6))
}

impl Size {
    /// The command that replays `seed`.
    fn replay(&self, seed: u64) -> String {
        match (self.env, self.exhaustive) {
            (false, _) => "cargo test -p osis-node --test it -- --exact order::held_set_decides".to_string(),
            (true, None) => format!("OSIS_ORDER_SEED={seed} OSIS_ORDER_LEN={} cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain", self.len),
            (true, Some(_)) => format!("OSIS_ORDER_SEED={seed} OSIS_ORDER_LEN={} cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_exhaustive", self.len),
        }
    }
}

/// Checks the histories of `sizes`' seeds (one seed per task, a thread per core) and reports every
/// failing one, each with the command that replays it; then the coverage tally (`Seen::floors`)
/// over all of them. `OSIS_ORDER_SHRINK=1` shrinks each failure first (slow: a shrink reruns the
/// check per dropped step).
fn held_set_decides_at(sizes: Vec<Size>) {
    use osis_base::testenv::u64_var;
    let mut seen = Seen::default();
    let mut by: BTreeMap<String, Seen> = BTreeMap::new();
    let mut open = Seen::default();
    let mut fails = Vec::new();
    for size in &sizes {
        let t0 = std::time::Instant::now();
        // seeds on a thread per core; with fewer seeds than cores, a seed's orders share the rest
        let outer = threads("OSIS_ORDER_THREADS").min(size.seeds.len()).max(1);
        let inner = if size.cfg.par_orders { threads("OSIS_ORDER_THREADS").div_ceil(outer) } else { 1 };
        let results = par_map(&size.seeds, outer, |seed| {
            let (e, steps) = generate(seed, size.len);
            let cfg = Cfg { threads: inner, ..cfg_of(e, size.cfg) };
            let steps = match size.exhaustive {
                Some(max) => cap(seed, &steps, cfg.addenda, max),
                None => steps,
            };
            if std::env::var("OSIS_ORDER_STATS").is_ok() {
                eprintln!("seed {seed} ({e:?}): vec!{steps:?}");
            }
            let r = check(seed, &steps, cfg).map(|s| Seen { emphases: BTreeMap::from([(format!("{e:?}"), 1)]), ..s });
            let fail = r.as_ref().is_err().then(|| {
                let shrunk = u64_var("OSIS_ORDER_SHRINK").is_some_and(|n| n != 0);
                let (steps, err) = if shrunk { shrink(seed, steps, cfg) } else { (steps, r.clone().unwrap_err()) };
                let what = if shrunk { "shrunk" } else { "as made; OSIS_ORDER_SHRINK=1 shrinks it" };
                let msg = format!("seed {seed}, {e:?} (replay: {}; {what}, for check({seed}, &h, {cfg:?})): h = vec!{steps:?}\n{err}", size.replay(seed));
                eprintln!("{msg}\n");
                msg
            });
            (r.unwrap_or_default(), fail)
        });
        let mut here = Seen::default();
        for r in &results {
            here.add(&r.0);
            // an emphasis's outcome needs its whole start: none is judged under the exhaustive cap
            if size.exhaustive.is_none() {
                open.add(&r.0);
                for e in r.0.emphases.keys() {
                    by.entry(e.clone()).or_default().add(&r.0);
                }
            }
        }
        let failed: Vec<String> = results.into_iter().filter_map(|x| x.1).collect();
        // always shown: the counts are what a passing run is read for
        osis_base::testenv::visible(true, &format!("order::held_set_decides ({}): {} seeds from {}, {} steps, {} orders in the passing ones, {} failing, {:.1} s; held-model compared {} aspects over {} nodes", size.name, size.seeds.len(), size.seeds.first().copied().unwrap_or(0), size.len, here.orders, failed.len(), t0.elapsed().as_secs_f64(), here.model.compared, here.model.nodes));
        seen.add(&here);
        fails.extend(failed);
    }
    if std::env::var("OSIS_ORDER_STATS").is_ok() {
        eprintln!("{}\nemphases {:?}, pending {:?}, invalid {}, aspects {:?}, judged {:?}, {} of {} early clocks moved, model reached {:?}, skipped {:?}", seen.tally.show(), seen.emphases, seen.pending, seen.invalid, seen.aspects, seen.judged, seen.moved, seen.clocked, seen.model.reached, seen.model.skipped);
    }
    assert!(fails.is_empty(), "{} histories judged differently by what was held:\n{}", fails.len(), fails.join("\n\n"));
    seen.floors(&open, &by);
}

// spec/requirements.md Decentralization (Deterministic: a node's state and its judgment of every
// write are functions of the data it holds, never of arrival order); spec/commits.md §4, §5
// (purge, required retention, history modes, keep for D), §6; spec/crdt.md §4.6, §4.7, §4.8,
// §5.7; spec/permissions.md §1, §2, §3, §4, §5, §5.1, §5.2 (addenda), §6: one generator
// (`generate`), every node in every order judged by `node_checks` against the node keeping
// every body and against held-model.
#[test]
fn held_set_decides() {
    held_set_decides_at(quick());
}

// The same at small size (a tenth of large; `OSIS_FULL=1` large).
#[test]
#[ignore = "property"]
fn held_set_decides_plain() {
    held_set_decides_at(vec![plain()]);
}

// The same over short histories, in every order of every held set.
#[test]
#[ignore = "property"]
fn held_set_decides_exhaustive() {
    held_set_decides_at(vec![exhaustive()]);
}

/// The orders the step-4 order harness tried on its long histories: 8 shuffles, 4 partial sets.
const WIDE: Cfg = Cfg { all_up_to: 0, random: 8, subsets: 4, model: false, ..ORDERS };

// spec/requirements.md Deterministic (an expiring or purged edit a node never held), spec/commits.md
// §5 Purge: a delta dropped while invalid, valid again and purged by author before its refetch has
// no leftover, so the node reads the older value until it holds the purger's re-snapshot, which
// carries the purged write value-less; then it reads as a node that held the body.
#[test]
fn purge_before_write_resnapshot_repairs_spec_commits_5() {
    use Step::*;
    let h = vec![Sync { from: 1, to: 0 }, Sync { from: 2, to: 1 }, Sync { from: 0, to: 2 }, Aim(Box::new(PurgeAuthor { by: 2, t: 2, of: 0 })), Aim(Box::new(Message { by: 0, t: 2, v: 8 })), Aim(Box::new(PurgeAuthor { by: 2, t: 2, of: 1 })), Aim(Box::new(Message { by: 1, t: 2, v: 9 })), Aim(Box::new(Message { by: 1, t: 1, v: 5 })), Aim(Box::new(PurgeAuthor { by: 2, t: 3, of: 1 })), Sync { from: 0, to: 2 }, Aim(Box::new(PurgeAuthor { by: 0, t: 2, of: 2 })), Aim(Box::new(Message { by: 1, t: 3, v: 3 })), Aim(Box::new(Message { by: 0, t: 0, v: 5 })), Advance { who: None, ms: 1069 }, Advance { who: None, ms: 27 }, Aim(Box::new(PurgeAuthor { by: 0, t: 3, of: 2 })), Sync { from: 2, to: 0 }, Aim(Box::new(PurgeAuthor { by: 0, t: 1, of: 0 })), Aim(Box::new(Demote { by: 0, t: 3, holder: 2, at: 3, to_read: true })), Advance { who: None, ms: 1602 }, Aim(Box::new(Edge { by: 0, t: 0, holder: 2, role: Some(Role::Write) })), Aim(Box::new(Message { by: 0, t: 0, v: 2 })), Aim(Box::new(Message { by: 1, t: 1, v: 7 })), Aim(Box::new(Message { by: 0, t: 3, v: 2 })), Aim(Box::new(Message { by: 1, t: 3, v: 7 })), Aim(Box::new(Message { by: 2, t: 2, v: 0 })), Aim(Box::new(Message { by: 0, t: 1, v: 5 })), Aim(Box::new(PurgeAuthor { by: 1, t: 3, of: 2 })), Aim(Box::new(Message { by: 0, t: 2, v: 7 })), Aim(Box::new(PurgeAuthor { by: 0, t: 0, of: 1 })), Aim(Box::new(Message { by: 0, t: 1, v: 4 })), Sync { from: 0, to: 1 }, Aim(Box::new(PurgeAuthor { by: 2, t: 0, of: 2 })), Aim(Box::new(Message { by: 0, t: 3, v: 1 })), Advance { who: None, ms: 1887 }, Aim(Box::new(Message { by: 2, t: 1, v: 3 })), Aim(Box::new(Message { by: 1, t: 3, v: 3 })), Aim(Box::new(Message { by: 2, t: 3, v: 9 })), Advance { who: None, ms: 620 }, Sync { from: 2, to: 1 }, Aim(Box::new(Message { by: 0, t: 3, v: 9 })), Sync { from: 2, to: 1 }, Aim(Box::new(Message { by: 0, t: 2, v: 3 })), Aim(Box::new(Message { by: 0, t: 0, v: 7 })), Advance { who: None, ms: 1499 }, Aim(Box::new(Demote { by: 0, t: 1, holder: 0, at: 1, to_read: true })), Aim(Box::new(Message { by: 2, t: 0, v: 1 })), Aim(Box::new(Message { by: 0, t: 1, v: 2 })), Aim(Box::new(PurgeAuthor { by: 0, t: 0, of: 2 })), Aim(Box::new(PurgeAuthor { by: 2, t: 0, of: 2 }))];
    check(452234901986, &h, WIDE).unwrap();
}

// spec/permissions.md §5.2, spec/crdt.md §4.6: 2's snapshot, invalid once 0 lowers 2 to read,
// gave 1's text creations (1's put not held); stripping them leaves no record of them, as at a
// node that never joined the snapshot.
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
    assert!(!as_made.contains("created: None, content: None, pos: [], deleted: None"), "no record without a write: {as_made}");
}

// spec/crdt.md §4.8, spec/commits.md §5: a kept text's insert dies at its delete's `ts` whether
// the delete is held after it or before it.
#[test]
fn seq_death_delete_first_spec_crdt_4_8() {
    use Step::*;
    // on an empty text the first inserts (`fit`), the second deletes it
    let h = vec![Typed { by: 0, t: 0, op: 24, k: 0, v: 6 }, Typed { by: 0, t: 0, op: 24, k: 0, v: 9 }];
    let played = play(1054, &h);
    let b = played.base;
    let insert = played.packs[b].id;
    let death = |order: Vec<usize>| deliver(&played, &order).engine.replaced_at(&insert, &played.things[0], &ak("t:text.0")).unwrap();
    assert!(death((0..b + 2).collect()).is_some(), "the delete held last dates it");
    assert!(death((0..b).chain([b + 1, b]).collect()).is_some(), "the delete held first dates it");
}

// spec/crdt.md §5.6 (the records of one dot are one entry for superseding), spec/commits.md §5:
// an expiring put of k0, a kept write of k1, a snapshot (k0's records
// key-erased, value-less), then a put into k0's entry (nested writes, keyed). A node holding the
// snapshot and the later put, not the expiring put, dates the snapshot's body at the later put: its
// value-less copies in the key-erased record are beaten by the keyed record's writes (was: no
// death, the records never met in the state).
#[test]
fn map_death_across_key_erased_record_spec_crdt_5_6() {
    use Step::*;
    let h = vec![Write { by: 0, t: 0, op: 28, k: 0, v: 3 }, Typed { by: 0, t: 0, op: 22, k: 1, v: 2 }, Compact { by: 0, t: 0, op: 28 }, Nested { by: 0, other: 2, t: 0, k: 0, text: false, compact: false, also: false }];
    let played = play(338806, &h);
    let snap = played.base + 2;
    let held: Vec<usize> = (0..played.base).chain([snap, snap + 1]).collect();
    let mut o = fresh(played.now);
    o.engine.keep_bodies(true);
    for &i in &held {
        let pk = &played.packs[i];
        o.receive(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    let mut p = deliver(&played, &held);
    let (id, t, a) = (played.packs[snap].id, played.things[0], ak("t:map.0"));
    let want = o.engine.replaced_at(&id, &t, &a).unwrap();
    assert!(want.is_some(), "the node keeping every body dates it");
    assert_eq!(p.engine.replaced_at(&id, &t, &a).unwrap(), want);
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
        let mut p = fresh(played.now);
        for pk in &played.packs[..played.base] {
            p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
        }
        for t in [first, second] {
            let _ = p.receive(&part(t), last.blobs.clone());
        }
        p.reexamine().unwrap();
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
        let mut p = fresh(played.now);
        for pk in &played.packs[..played.base] {
            p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
        }
        if sync_first {
            p.engine.set_syncing(g, true).unwrap();
        }
        let _ = p.receive(&part, pk.blobs.clone());
        p.engine.set_syncing(g, true).unwrap();
        shown(&mut p, &played.things)
    };
    assert_eq!(node(true), node(false));
}


/// `h`, then every peer holds what the others do, takes the walk's side in each dispute (as the
/// judged nodes do) and compacts every aspect of every thing it may write: spec/commits.md §5's waiting part past its expiry and spec/requirements.md
/// Deterministic's limits last until a writer next compacts or writes, so a node given the
/// compactions last (each counting when it arrives: one dropped while it did not count repairs
/// nothing, spec/commits.md §5 Invalid) shows what the keep-everything node does before its sync
/// exchange too.
fn settled(mut h: Vec<Step>) -> Vec<Step> {
    use Step::*;
    let sync = |h: &mut Vec<Step>| {
        for from in 0..3 {
            for to in (0..3).filter(|to| *to != from) {
                h.push(Sync { from, to });
            }
        }
    };
    h.push(Advance { who: None, ms: 3 * HOUR });
    sync(&mut h);
    sync(&mut h);
    h.push(WalkSides);
    for t in 0..12 {
        for op in [0, 1, 3, 6, 8, 10, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 27, 28, 29, 32, 35] {
            h.extend((0..3).map(|by| Compact { by, t, op }));
        }
    }
    sync(&mut h);
    h
}

/// The pack of the setup's grant on G to peer `to` (0's edge naming `to`'s account; `to` authors
/// a commit in the history).
fn setup_grant(played: &Played, to: usize) -> usize {
    let decode = |i: usize| osis_commit::CommitBlob::decode(&played.packs[i].bytes).unwrap();
    let account = played.authors.iter().position(|a| *a == to).map(|i| decode(i).header.author).unwrap();
    (0..played.base)
        .find(|&i| played.authors[i] == 0 && decode(i).header.aspects.iter().any(|a| a.tid == played.things[0] && a.ak.as_str() == "roles.0") && played.packs[i].bytes.windows(15).any(|w| w == account.as_bytes()))
        .unwrap()
}

/// `played`, the history `steps`: when they end with `settled`'s tail (not cut short, as the
/// exhaustive size's cap cuts it), marked settled from the tail's first commit.
///
/// A thing with a `required^.0` delta settles nothing (spec/commits.md §5 Required retention,
/// Limit): one dropped while invalid and missing again changes the validity of its thing's later
/// deltas until its copy comes back, and no compaction carries it.
fn settling(mut played: Played, steps: &[Step]) -> Played {
    let tail = settled(Vec::new());
    let Some(at) = steps.len().checked_sub(tail.len()).filter(|&at| steps[at..] == tail[..]) else { return played };
    let from = played.steps_at.get(at).copied().unwrap_or(played.packs.len());
    let required: BTreeSet<String> = played.packs.iter().filter_map(|pk| osis_commit::CommitBlob::decode_stored(&pk.bytes).ok()).flat_map(|b| b.header.aspects.iter().filter(|a| a.ak.as_str() == "required^.0").map(|a| format!("{:?}", a.tid)).collect::<Vec<_>>()).collect();
    played.settled_last.retain(|k| !required.contains(&k.0));
    Played { settle_from: Some(from), ..played }
}

// spec/commits.md §5 Invalid, spec/sync.md §7: a body dropped while invalid and valid again is
// missing until a copy arrives or a writer next compacts. 1 writes G's register and 0 lowers 1
// to read (keeping the write), then 2 and itself: no writer is left to compact G, so the settled
// check spares G's register before the sync exchange. A node given 1's write after its lowering
// and before its grant drops the write as invalid and reads "g" there until it fetches it.
#[test]
fn settled_check_spares_aspects_no_writer_compacted_spec_commits_5() {
    use Step::*;
    let h = vec![Write { by: 1, t: 0, op: 0, k: 0, v: 1 }, Sync { from: 1, to: 0 }, Demote { by: 0, t: 0, holder: 1, at: 9, to_read: true }, Demote { by: 0, t: 0, holder: 2, at: 9, to_read: false }, Demote { by: 0, t: 0, holder: 0, at: 9, to_read: true }];
    let h = settled(h);
    let played = settling(play(5, &h), &h);
    let g = (format!("{:?}", played.things[0]), "t:reg.0".to_string());
    assert!(!played.settled_last.contains(&g), "no writer compacts: {:?}", played.tally);
    // the setup but 1's grant, the history from its end, then the grant
    let grant = setup_grant(&played, 1);
    let mut order: Vec<usize> = (0..played.base).filter(|i| *i != grant).collect();
    order.extend((played.base..played.packs.len()).rev());
    order.push(grant);
    let mut p = deliver(&played, &order);
    assert_eq!(shown(&mut p, &played.things)[&g], "Ok(Some(Str(\"g\")))", "1's write dropped while invalid");
    order_checks(&played, &order).unwrap();
}

// spec/crdt.md §5.7: 0 inserts `v5` and deletes the `5` (both kept, so the delete undoes), 1
// compacts (its snapshot has no char for the `5`), 0 undoes the delete. Held, the snapshot and the
// undelete: both orders read `v5`.
#[test]
fn undelete_with_snapshot_of_deleted_spec_crdt_5_7() {
    use Step::*;
    let tick = Advance { who: None, ms: 1 };
    let h = vec![Typed { by: 0, t: 0, op: 23, k: 0, v: 5 }, tick.clone(), Typed { by: 0, t: 0, op: 24, k: 0, v: 1 }, Sync { from: 0, to: 1 }, tick.clone(), Compact { by: 1, t: 0, op: 24 }, tick, Undo { by: 0, back: 0 }];
    let played = play(5, &h);
    let (b, n) = (played.base, played.packs.len());
    let read = |rest: [usize; 2]| deliver(&played, &(0..b).chain(rest).collect::<Vec<_>>()).engine.get(&played.things[0], &ak("t:text.0")).unwrap();
    assert_eq!(read([n - 2, n - 1]), Some(Value::Str("v5".into())));
    assert_eq!(read([n - 1, n - 2]), Some(Value::Str("v5".into())));
}

// spec/commits.md §5, spec/crdt.md §4.8 (replaced, a function of the held set): three writes of
// a kept register (no `v` a multiple of 3: kept after replaced, `retention_of`), X < Y < Z; X is
// replaced at Y and Y at Z, delivered in order or Z first.
#[test]
fn replaced_alike_in_any_order_spec_commits_5() {
    use Step::*;
    let h: Vec<Step> = (0..3).flat_map(|by| [Write { by, t: 0, op: 16, k: 0, v: [1, 2, 4][by] }, Advance { who: None, ms: 1000 }]).collect();
    let played = play(16, &h);
    let n = played.packs.len();
    let mut seen = Vec::new();
    for order in [(0..n).collect::<Vec<_>>(), (0..played.base).chain((played.base..n).rev()).collect()] {
        let mut p = deliver(&played, &order);
        seen.push(replaced_of(&mut p.engine).into_iter().filter(|x| x.1.is_some()).collect::<Vec<_>>());
    }
    let (x, y) = (played.packs[played.base].id, played.packs[played.base + 1].id);
    let at = |i: usize, c: CommitId| seen[i].iter().find(|e| e.0.0 == c).and_then(|e| e.1);
    let ty = deliver(&played, &(0..n).collect::<Vec<_>>()).engine.header(&y).unwrap().ts;
    assert!(seen[0].len() == 2 && seen[0] == seen[1] && at(0, x) == Some(ty) && at(0, y).is_some(), "{seen:?}");
}

// spec/commits.md §5: one body under purge on replace with two keys, one replaced: the other stays
// read, as at the node keeping every body. The generator rarely reaches this.
#[test]
fn live_write_outlives_its_body_at_the_bound_spec_commits_5() {
    use Step::*;
    let w = |k, v| Aim(Box::new(Typed { by: 0, t: 0, op: 19, k, v }));
    check(1, &[w(0, 0), w(0, 1)], NAMED).unwrap();
}

// spec/crdt.md §4.7-4.8: a purged register write stays held value-less (its leftover), so it
// still kills the write before it.
#[test]
fn register_deaths_purged_killer_spec_crdt_4_8() {
    let mut lp = local_peer_off(1, 1, T0);
    let me = lp.peers[0].engine.me();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &REG, &s("g")).unwrap();
    lp.peers[0].commit(m).unwrap();
    // each commit packaged as made, before a later purge drops its body
    let mut packs: Vec<Package> = lp.peers[0].engine.commit_ids().iter().map(|id| lp.peers[0].engine.package(id).unwrap().unwrap()).collect();
    let mut put = |v: &str, purge: Option<CommitId>| {
        lp.advance(1_000);
        let mut m = Mutation::new();
        if let Some(commit) = purge {
            m.purge(osis_commit::PurgeItem::Commit { commit, tid: t, ak: ak("t:kept.0") });
        }
        m.retention(t, &KEPT, keep_of(16).unwrap()).unwrap();
        m.set(t, &KEPT, &s(v)).unwrap();
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        packs.push(lp.peers[0].engine.package(&id).unwrap().unwrap());
        id
    };
    let w1 = put("1", None);
    let w2 = put("2", None);
    put("3", Some(w2));
    let mut p = fresh(lp.peers[0].engine.now());
    p.engine.keep_bodies(true);
    for pk in &packs {
        p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    assert!(!p.engine.body_not_dropped(&w2, &t, &ak("t:kept.0")), "the purge dropped w2");
    let w2_ts = p.engine.header(&w2).unwrap().ts;
    assert_eq!(p.engine.replaced_at(&w1, &t, &ak("t:kept.0")).unwrap(), Some(w2_ts));
}

// spec/commits.md §5, spec/crdt.md §4.8 (a write dies once, at its earliest superseder): a kept
// text inserted, deleted, the delete undone and the text deleted again. The insert's body is
// replaced at the first delete.
#[test]
fn text_redelete_replaced_at_first_delete_spec_commits_5() {
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
    assert_eq!(p.engine.replaced_at(&ins, &t, &text).unwrap(), Some(del));
}

// spec/commits.md §5 (a snapshot carries a dying write only when its body holds a write of its
// stamp): A puts entry k0 (a struct) in a kept map and undoes it; B, holding both, compacts (its
// snapshot holds nothing of the put's stamp); C, holding the put alone, sets a field of k0 after
// the snapshot. A node taking the field write, the snapshot, the undo and the put last dates the
// put's field dead at C's write while holding the snapshot, which never carried it: the snapshot
// is not replaced (was: credited from its frontier, taken after the put and before the date).
#[test]
fn snapshot_after_late_dated_death_not_credited_spec_commits_5() {
    use Step::*;
    let tick = Advance { who: None, ms: 1 };
    // k1 stays, so the snapshot carries a kept write and keeps it for D after replaced
    let h = vec![Typed { by: 0, t: 0, op: 22, k: 0, v: 8 }, Send { from: 0, to: 1, back: 0 }, Send { from: 0, to: 2, back: 0 }, tick.clone(), Typed { by: 0, t: 0, op: 22, k: 1, v: 5 }, Send { from: 0, to: 1, back: 0 }, Send { from: 0, to: 2, back: 0 }, tick.clone(), Undo { by: 0, back: 1 }, Send { from: 0, to: 1, back: 0 }, tick.clone(), Compact { by: 1, t: 0, op: 22 }, tick, TypedField { by: 2, t: 0, k: 0, v: 7 }];
    let played = play(83028, &h);
    let b = played.base;
    assert_eq!(played.packs.len(), b + 5);
    let (put, other, undo, snap, field) = (b, b + 1, b + 2, b + 3, b + 4);
    let order: Vec<usize> = (0..b).chain([other, field, snap, undo, put]).collect();
    let mut p = deliver(&played, &order);
    let a = osis_base::Ak::new("t:map.0").unwrap();
    let ids: Vec<CommitId> = [put, undo, snap, field].iter().map(|i| played.packs[*i].id).collect();
    let t = p.engine.header(&ids[2]).unwrap().aspects[0].tid;
    assert_eq!(p.engine.header(&ids[2]).unwrap().kind, osis_commit::Kind::ContentSnapshot);
    assert!(p.engine.header(&ids[2]).unwrap().aspects[0].retention.history.is_some_and(|h| h != History::PurgeOnReplace), "a kept snapshot");
    assert!(p.engine.replaced_at(&ids[0], &t, &a).unwrap().is_some(), "the put died");
    assert_eq!(p.engine.replaced_at(&ids[2], &t, &a).unwrap(), None, "not replaced");
}

// spec/commits.md §5 (a body dropped for its keep bounds counts as never received; a snapshot
// dropped other than as covered still stands in): B's write kills A's
// purge-on-replace write (and so A's snapshot of it) where it arrives before B's demotion, which
// makes it invalid; the snapshot dropped there still stands in (`stands_in`) and leaves the
// snapshot indexes until a copy arrives again and joins.
#[test]
fn snapshot_dropped_before_flip_joins_again_spec_commits_5() {
    use Step::*;
    let h = vec![Write { by: 0, t: 3, op: 18, k: 0, v: 2 }, Compact { by: 0, t: 4, op: 18 }, Edge { by: 0, t: 6, holder: 1, role: Some(Role::Admin) }, Write { by: 1, t: 7, op: 15, k: 2, v: 7 }, Nested { by: 0, other: 2, t: 4, k: 0, text: false, compact: true, also: true }, Demote { by: 0, t: 0, holder: 1, at: 4, to_read: false }, Edge { by: 2, t: 2, holder: 2, role: Some(Role::Admin) }, Write { by: 2, t: 4, op: 0, k: 1, v: 8 }, Demote { by: 0, t: 4, holder: 2, at: 1, to_read: true }, Write { by: 1, t: 0, op: 18, k: 2, v: 5 }];
    let played = play(3401073, &h);
    let made: Vec<usize> = (0..played.packs.len()).collect();
    let order = [15, 7, 19, 12, 5, 8, 20, 1, 10, 0, 17, 18, 9, 14, 3, 13, 6, 2, 16, 11, 4];
    assert_eq!(order_checks(&played, &made), Ok(()));
    assert_eq!(order_checks(&played, &order), Ok(()));
    // the seed's longer shrink: the dropped snapshot leaves the carried-writes index too
    let h2 = vec![Nested { by: 1, other: 2, t: 0, k: 1, text: false, compact: false, also: false }, Demote { by: 2, t: 6, holder: 2, at: 4, to_read: true }, Demote { by: 0, t: 6, holder: 2, at: 1, to_read: false }, Write { by: 0, t: 3, op: 18, k: 0, v: 2 }, Compact { by: 0, t: 4, op: 18 }, Write { by: 1, t: 0, op: 15, k: 0, v: 3 }, Edge { by: 0, t: 4, holder: 1, role: Some(Role::Read) }, Edge { by: 0, t: 6, holder: 1, role: Some(Role::Admin) }, Advance { who: None, ms: 3721574 }, Write { by: 1, t: 7, op: 15, k: 2, v: 7 }, Nested { by: 0, other: 2, t: 4, k: 0, text: false, compact: true, also: true }, Demote { by: 0, t: 0, holder: 1, at: 4, to_read: false }, Edge { by: 0, t: 7, holder: 2, role: Some(Role::Write) }, Compact { by: 1, t: 7, op: 4 }, Sync { from: 0, to: 2 }, Write { by: 1, t: 1, op: 4, k: 1, v: 3 }, Write { by: 2, t: 4, op: 0, k: 1, v: 8 }, Demote { by: 0, t: 4, holder: 2, at: 1, to_read: true }, Edge { by: 0, t: 7, holder: 1, role: Some(Role::Write) }, Write { by: 1, t: 0, op: 18, k: 2, v: 5 }];
    let played = play(3401073, &h2);
    let held = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 15, 16, 18, 20, 23, 24, 25, 27];
    let order = [3, 8, 27, 4, 24, 0, 10, 2, 25, 23, 12, 14, 16, 9, 5, 6, 18, 1, 15, 7, 20];
    assert_eq!(order_checks(&played, &held), Ok(()));
    assert_eq!(order_checks(&played, &order), Ok(()));
}

// spec/commits.md §5 (a snapshot's carried write killed by a lower-stamped write dies for it at
// its `ts`; a copy of a body dropped for its keep bounds joins again): A's
// purge-on-replace snapshot carries B's entry, which B's undo (stamped before the snapshot, unseen
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
    assert_eq!(order_checks(&played, &made), Ok(()));
    assert_eq!(order_checks(&played, &rev), Ok(()));
}

// spec/crdt.md §4.6 Un-merge, §4.7 (leftovers), spec/commits.md §5 (purge): a purged delta whose
// body was dropped as covered keeps its leftover from the coverer's copies, which the purge strips
// next; a later write that superseded it in the state and is un-merged does not take it along
// (was: made order "old" came back, demotion first absent). The purger's re-snapshot would hide
// it once it reaches the node.
#[test]
fn purged_covered_leftover_survives_unmerge_spec_crdt_4_6() {
    let mut lp = local_peer_off(3, 24112, T0);
    lp.sync_all().unwrap();
    let ids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
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
    let mut m = edge_write(&lp.peers[0].engine, g, ids[2], None);
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
        let mut p = fresh(now);
        for pk in &base {
            p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
        }
        for id in order {
            p.receive(&by(id).bytes, by(id).blobs.clone()).unwrap();
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

// spec/crdt.md §4.7 (leftovers), spec/permissions.md §5.2: a purged delta whose body was dropped
// as covered takes its leftover from the coverer's copies and is held again from then on; when
// the coverer turns invalid the leftover stays (a held body, no longer the cover's), so the
// value-less winner hides "old" alike at once, after a rebuild and after a restart.
#[test]
fn cover_leftover_outlives_its_cover_spec_perm_5_2() {
    let mut lp = local_peer_off(3, 24114, T0);
    lp.sync_all().unwrap();
    let ids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
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
    let mut m = edge_write(&lp.peers[0].engine, g, ids[2], None);
    m.frontier(f.to_value());
    let demote = lp.peers[0].commit(m).unwrap().unwrap();
    let pks = lp.packages(0).unwrap();
    let by = |id: CommitId| pks.iter().find(|p| p.id == id).unwrap().clone();
    let snap_pk = lp.peers[2].engine.package(&snap).unwrap().unwrap();
    let now = lp.peers.iter().map(|p| p.engine.now()).max().unwrap();
    let mut p = fresh(now);
    for pk in pks.iter().filter(|pk| ![snap, purge, demote].contains(&pk.id)) {
        p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    p.receive(&snap_pk.bytes, snap_pk.blobs.clone()).unwrap();
    assert_eq!(p.engine.covered(&snap, &c, &g, &ak("t:reg.0")).unwrap(), Some(true), "S covers the write");
    // node-sync's compaction drop of the covered body
    p.engine.drop_body(&c, &g, &ak("t:reg.0")).unwrap();
    p.receive(&by(purge).bytes, by(purge).blobs.clone()).unwrap();
    p.receive(&by(demote).bytes, by(demote).blobs.clone()).unwrap();
    p.reexamine().unwrap();
    let after = p.engine.get(&g, &ak("t:reg.0")).unwrap();
    p.engine.rebuild_state(&g, &ak("t:reg.0")).unwrap();
    assert_eq!(p.engine.get(&g, &ak("t:reg.0")).unwrap(), after, "rebuilt");
    p.restart(FRESH + 1).unwrap();
    assert_eq!(p.engine.get(&g, &ak("t:reg.0")).unwrap(), after, "restarted");
    assert_eq!(after, None, "the leftover from the cover's copies stays: the value-less winner");
}

// spec/crdt.md §4.7 (a copy arriving after T is stripped and joined): a part of an expired
// delta arriving after T, later than the rest of its commit (dropped at expiry while missing),
// joins value-less (was skipped: the whole commit hid "old", the split one showed it).
#[test]
fn expired_late_part_joins_valueless_spec_crdt_4_7() {
    let mut lp = local_peer_off(2, 24113, T0);
    lp.sync_all().unwrap();
    let ids: Vec<Tid> = (0..2).map(|i| lp.peers[i].engine.me()).collect();
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
    m.expires(g, &KEPT, WallMs(now.0 + 1000)).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(2000);
    let packs: Vec<Package> = lp.peers[0].engine.commit_ids().iter().map(|id| lp.peers[0].engine.package(id).unwrap().unwrap()).collect();
    let now = lp.peers.iter().map(|p| p.engine.now()).max().unwrap();
    let mut got = Vec::new();
    for split in [false, true] {
        let mut p = fresh(now);
        for pk in packs.iter().filter(|pk| pk.id != c) {
            p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
        }
        let pk = packs.iter().find(|pk| pk.id == c).unwrap();
        if split {
            let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
            let reg = b.header.aspects.iter().position(|a| a.ak.as_str() == "t:reg.0");
            let keep = b.parts.iter().map(|x| x.ai).filter(|ai| Some(*ai) != reg).max().unwrap();
            b.parts.retain(|x| x.ai == keep);
            p.receive(&b.encode(), pk.blobs.clone()).unwrap();
        }
        p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
        let _ = p.reexamine();
        got.push(p.engine.get(&g, &ak("t:reg.0")).unwrap());
    }
    assert_eq!(got, vec![None, None]);
}

// A snapshot carries another's writes nested in an expiring put's entry in the
// entry's key-erased record (spec/crdt.md §4.7), their own delta keyed. When the snapshot turns invalid (its
// author revoked) its copies go though their own delta is held, so the
// state is the keyed record alone, as when the snapshot was invalid on arrival.
#[test]
fn invalid_snapshot_key_erased_copies_go_spec_permissions_5_2() {
    use Step::*;
    let old = |x: Step| Old(Box::new(x));
    let h = vec![Demote { by: 0, t: 0, holder: 2, at: 3, to_read: true }, Demote { by: 2, t: 3, holder: 2, at: 0, to_read: false }, Write { by: 1, t: 3, op: 28, k: 1, v: 0 }, Sync { from: 1, to: 0 }, old(Nested { by: 0, other: 1, t: 0, k: 1, text: false, compact: true, also: true }), Compact { by: 1, t: 4, op: 5 }, old(Write { by: 0, t: 2, op: 7, k: 1, v: 9 }), old(Nested { by: 0, other: 2, t: 7, k: 2, text: false, compact: true, also: true }), Edge { by: 0, t: 4, holder: 2, role: Some(Role::Write) }, old(Write { by: 0, t: 3, op: 1, k: 0, v: 4 }), Edge { by: 0, t: 7, holder: 1, role: Some(Role::Write) }, old(Write { by: 0, t: 7, op: 5, k: 2, v: 3 }), Edge { by: 0, t: 0, holder: 1, role: None }];
    let played = play(27039, &h);
    // the held set `check` failed on: neither the put (11) nor its author's nested write (13)
    // (as positions past the setup)
    let held: Vec<usize> = (0..played.base).chain([1, 3, 5, 6, 7, 8, 9, 11, 13].map(|i| i + played.base)).collect();
    let reversed: Vec<usize> = held.iter().rev().copied().collect();
    let map = |order: &[usize]| deliver(&played, order).engine.state(&played.things[0], &ak("t:map.0")).unwrap();
    let (made, rev) = (map(&held), map(&reversed));
    assert!(format!("{made:?}").contains("k1"), "the nested writes' own delta keeps them keyed");
    assert_eq!(made, rev);
}




// spec/crdt.md §4.6, §4.7: 2 puts k0 expiring in a second, 1 writes inside it, 0 passes the
// expiry and compacts (its copy of 2's writes key-erased), then demotes 2 below the put. A node
// that held all of it before the expiry and one given it after read alike once both are past
// it. 1's write carries the key as its own value: only the put's values go, 1's stays.
#[test]
fn key_erased_copy_keeps_record_before_expiry_spec_crdt_4_6() {
    use Step::*;
    let h = vec![
        Write { by: 2, t: 0, op: 28, k: 0, v: 0 },
        Sync { from: 2, to: 0 },
        Sync { from: 2, to: 1 },
        Write { by: 1, t: 0, op: 4, k: 0, v: 5 },
        Advance { who: Some(0), ms: 2000 },
        Compact { by: 0, t: 0, op: 3 },
        Demote { by: 0, t: 0, holder: 2, at: 0, to_read: false },
        Sync { from: 1, to: 0 },
    ];
    let played = play(1, &h);
    let all: Vec<usize> = (0..played.packs.len()).collect();
    let mut after = deliver(&played, &all);
    let mut before = fresh(T0);
    for pk in &played.packs {
        let _ = before.engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    before.clock.set(played.now);
    before.tick().unwrap();
    let k = (format!("{:?}", played.things[0]), "t:map.0".to_string());
    let (a, b) = (shown(&mut after, &played.things), shown(&mut before, &played.things));
    assert_eq!(a.get(&k), b.get(&k));
    // the rule's point, inside the state: 1's value record stays
    for p in [&mut after, &mut before] {
        let st = format!("{:?}", p.engine.state(&played.things[0], &ak("t:map.0")).unwrap());
        assert!(st.contains("value: Some(Int(5))"), "1's write is kept: {st}");
    }
}

// spec/commits.md §5 (Purge), spec/permissions.md §6: held-model (`held.rs`) judges what each node
// holds alike: a writer's purge of an admin's delta, without the right, drops nothing; an
// admin's purge of a writer's delta drops it. Also a default-test run of the adapter.
#[test]
fn held_model_agrees_on_purge_rights_spec_commits_5() {
    use Step::*;
    let h = vec![
        Write { by: 2, t: 0, op: 0, k: 0, v: 1 },
        Write { by: 1, t: 0, op: 0, k: 0, v: 2 },
        Sync { from: 2, to: 1 },
        Sync { from: 1, to: 2 },
        Purge { by: 1, t: 0, of: 2, back: 0, v: 3 },
        Purge { by: 2, t: 0, of: 1, back: 1, v: 4 },
    ];
    let seen = check(9360000, &h, Cfg { model: true, ..NAMED }).unwrap();
    assert!(seen.model.compared > 0 && seen.model.reached.get("purged").is_some_and(|n| *n > 0), "{:?}", seen.model);
}

// A commit that kills the last live write of a body under purge on replace and
// whose purge request names that body: the node holds the body when it judges both, so it holds
// its leftover (spec/commits.md §5: a purged leftover is never dropped for keep bounds), in
// whichever order the request and the named delta arrive.
#[test]
fn kill_and_purge_in_one_commit_keeps_leftover_spec_commits_5() {
    use Step::*;
    let h = vec![Require { by: 0, t: 0, op: 17, rule: 3 }, Sync { from: 0, to: 1 }, Write { by: 1, t: 0, op: 0, k: 0, v: 1 }, Sync { from: 1, to: 0 }, Purge { by: 0, t: 0, of: 1, back: 0, v: 2 }];
    let played = play(913006, &h);
    let n = played.packs.len();
    let (t, a) = (played.things[0], ak("t:reg.0"));
    // the requirement, the write, the request, the purger's re-snapshot
    assert_eq!(n, played.base + 4, "{:?}", played.tally.show());
    let (write, purge) = (played.packs[n - 3].id, played.packs[n - 2].id);
    let made: Vec<usize> = (0..n).collect();
    let request_first: Vec<usize> = (0..played.base).chain([n - 2, n - 3, n - 1]).collect();
    for order in [made, request_first] {
        let mut p = deliver(&played, &order);
        let h = p.engine.header(&write).unwrap();
        assert_eq!(h.aspects[0].retention.history, Some(History::PurgeOnReplace), "the write is under the required purge on replace: {:?}", h.aspects[0].retention);
        assert_eq!(p.engine.get(&t, &a).unwrap(), Some(s("p2")), "the request's write killed it");
        assert!(p.engine.purge_stands(&purge, &write, &t, &a), "the request names the write and stands");
        let m = p.engine.core.ix.commits.get(&write).unwrap();
        let ai = m.header.aspects.iter().position(|x| x.tid == t && x.ak == a).unwrap();
        assert!(m.stripped.contains(&ai) && !m.dropped.contains_key(&ai), "order {order:?}: held as its leftover, not dropped: dropped {:?} stripped {:?}", m.dropped, m.stripped);
    }
}

// spec/commits.md §5 (keep for D, a snapshot at its latest death): A puts entry k0 in a kept
// map; A compacts (S1); B sets a field of k0 (its first death); C, not holding B's write,
// writes k1 and compacts twice, both snapshots carrying k0's dead field again; A removes k0 (the
// rest of it dies). S1 is replaced at the removal, not at C's second snapshot: copies of a dead
// write are no further deaths. Held-model's date bounds every node's keep in the named orders
// (`held::keep_for_d`).
#[test]
fn kept_snapshot_replaced_at_latest_death_any_order_spec_commits_5() {
    use Step::*;
    let a = |ms| Advance { who: None, ms };
    let h = vec![
        Typed { by: 0, t: 0, op: 35, k: 0, v: 1 },
        Sync { from: 0, to: 1 },
        Sync { from: 0, to: 2 },
        a(10),
        Compact { by: 0, t: 0, op: 35 },
        a(10),
        Typed { by: 1, t: 0, op: 35, k: 0, v: 2 },
        a(10),
        Typed { by: 2, t: 0, op: 35, k: 1, v: 3 },
        Compact { by: 2, t: 0, op: 35 },
        a(10),
        Typed { by: 2, t: 0, op: 35, k: 1, v: 4 },
        Compact { by: 2, t: 0, op: 35 },
        Sync { from: 1, to: 0 },
        a(10),
        Typed { by: 0, t: 0, op: 36, k: 0, v: 0 },
        Sync { from: 2, to: 0 },
    ];
    let (judged, _) = keep_for_d_named(9600001, &h);
    assert!(judged > 0);
}

// spec/commits.md §5 (keep for D): C's text snapshot (B's insert, C's delete; B re-deleted it
// concurrently) is replaced at B's re-delete, as held-model dates it, not at A's later insert
// (`held::keep_for_d`'s count dated later).
#[test]
fn kept_text_snapshot_replaced_at_the_re_delete_spec_commits_5() {
    use Step::*;
    let a = |s: Step| Aim(Box::new(s));
    let h = vec![a(Typed { by: 2, t: 0, op: 35, k: 0, v: 1 }), a(Typed { by: 1, t: 0, op: 24, k: 1, v: 1 }), Sync { from: 1, to: 2 }, a(Compact { by: 0, t: 0, op: 35 }), a(Typed { by: 2, t: 0, op: 24, k: 1, v: 0 }), a(Typed { by: 1, t: 1, op: 22, k: 1, v: 1 }), a(Typed { by: 1, t: 0, op: 24, k: 1, v: 7 }), a(Typed { by: 2, t: 0, op: 22, k: 0, v: 5 }), Advance { who: Some(0), ms: 1220 }, a(Typed { by: 0, t: 0, op: 24, k: 1, v: 1 }), a(Compact { by: 2, t: 0, op: 24 })];
    let (_, later) = keep_for_d_named(5059, &h);
    assert_eq!(later, 0, "dated later than held-model");
}

/// `held::keep_for_d` of history `h` in the named orders (as made, reversed, as fetched; the order
/// harness's own checks too): no body dated early; how many were judged and dated later.
fn keep_for_d_named(seed: u64, h: &[Step]) -> (usize, usize) {
    check(seed, h, NAMED).unwrap();
    let played = play(seed, h);
    let hist = crate::held::History::new(&played.packs);
    let all: Vec<usize> = (0..played.packs.len()).collect();
    let (mut judged, mut later) = (0, 0);
    for order in orders(&played, &all, NAMED, &mut Rng(1)) {
        let mut p = deliver(&played, &order);
        let (j, l, early) = crate::held::keep_for_d(&mut p.engine, &hist);
        assert_eq!(early, None, "order {order:?}");
        judged += j;
        later += l;
    }
    (judged, later)
}

// spec/crypto.md §4 Holder actors: what a rotation's `secrets.0` part shows for possession is
// kept across a reopen (the persisted index), so the part is judged again alike after one: an
// order-harness history over record-only things, in named orders (as made, a role commit's
// `secrets.0` part judged anew after a reopen differs when `Indexes::shown` is not reloaded at open).
#[test]
fn possession_judged_alike_after_reopen_spec_crypto_4() {
    use Step::*;
    let a = |x: Step| Aim(Box::new(x));
    let h = vec![RecordOnly { by: 0, under: None }, a(RecordOnly { by: 0, under: Some(0) }), a(Nested { by: 0, other: 1, t: 6, k: 1, text: false, compact: true, also: true }), a(GrantFlow { by: 0, t: 2, holder: 0, role: Role::Admin }), a(GrantFlow { by: 0, t: 4, holder: 2, role: Role::Read }), a(GrantFlow { by: 0, t: 6, holder: 3, role: Role::Admin }), a(RemoveFlow { by: 1, t: 4, holder: 3, lower: false })];
    check(31517018, &h, Cfg { sync: true, ..NAMED }).unwrap();
}

// spec/permissions.md §5.1 (Trust set): 2 removes 0's record edge on G while 0, not having seen
// it, lowers 2 to read. A node given 0's write first trusts it (its default side) until it takes
// the walk's side; held-model has no trust set, so every delivery takes the walk's side before
// each judgment, held-model's after every ingest included.
#[test]
fn judged_under_the_walks_side_after_every_ingest_spec_permissions_5_1() {
    use Step::*;
    let h = vec![RemoveFlow { by: 2, t: 0, holder: 0, lower: false }, Demote { by: 0, t: 0, holder: 2, at: 4, to_read: true }];
    let played = play(5021, &h);
    let played = Played { model: Some(std::sync::Arc::new((crate::held::History::new(&played.packs), Default::default()))), ..played };
    let n = played.packs.len();
    let o = oracle(&played, &(0..n).collect::<Vec<_>>());
    let (mut disputes, mut differs) = (0, None);
    deliver_with(&played, &(0..n).rev().collect::<Vec<_>>(), None, None, &mut |p| {
        disputes += crate::disputes::walk_sides(p);
        differs = differs.take().or_else(|| model_differs(p, &played, &o));
    });
    assert!(disputes > 0, "a dispute");
    assert_eq!(differs, None);
}

// spec/commits.md §5 Invalid: 0 lowers 1 to read, 2 grants 1 write again, 1 writes G's register,
// then 0 lowers 2 and itself to read, so 1 alone compacts last. A node given 2's own admin grant
// after all of it drops 1's write and 1's compactions as invalid, and once they count
// reads "g" until it fetches them again; given the grant before the compactions it reads 1's
// value, as the node keeping every body does. So a settled history delivers its compactions last.
#[test]
fn compaction_dropped_while_invalid_repairs_nothing_spec_commits_5() {
    use Step::*;
    let h = settled(vec![
        Demote { by: 0, t: 0, holder: 1, at: 9, to_read: true },
        Edge { by: 2, t: 0, holder: 1, role: Some(Role::Write) },
        Write { by: 1, t: 0, op: 0, k: 0, v: 1 },
        Sync { from: 1, to: 0 },
        Sync { from: 2, to: 0 },
        Demote { by: 0, t: 0, holder: 2, at: 9, to_read: true },
        Demote { by: 0, t: 0, holder: 0, at: 9, to_read: true },
    ]);
    let played = settling(play(5, &h), &h);
    let g = (format!("{:?}", played.things[0]), "t:reg.0".to_string());
    assert!(played.settled_last.contains(&g), "1 compacts last: {:?}", played.tally);
    let n = played.packs.len();
    let o = oracle(&played, &(0..n).collect::<Vec<_>>());
    let grant = setup_grant(&played, 2);
    let without = || (0..n).filter(move |&i| i != grant);
    let read = |order: Vec<usize>| shown(&mut deliver(&played, &order), &played.things)[&g].clone();
    assert_eq!(read(without().chain([grant]).collect()), "Ok(Some(Str(\"g\")))", "1's write and compactions dropped while invalid");
    let f = played.settle_from.unwrap();
    let first = without().take_while(|&i| i < f).chain([grant]).chain(without().skip_while(|&i| i < f));
    assert_eq!(read(first.collect()), o.now[&g]);
    assert_ne!(o.now[&g], "Ok(Some(Str(\"g\")))");
}

// spec/commits.md §4 (Unjudgeable): a node whose clock is behind gets a write on a new thing
// first (thrown out: the thing's record is unknown), then the thing's creation (pending: its
// `ts` past `MAX_DRIFT` ahead). When the clock catches up the creation applies, its record
// arrives, and the write is fetched again: the node reads what the node given both on time does.
#[test]
fn record_from_drift_parked_creation_wakes_thrown_out_write_spec_commits_4() {
    use Step::*;
    let played = play(7, &[NewTop { by: 0 }, Write { by: 0, t: 1, op: 0, k: 0, v: 1 }]);
    let (creation, write) = (&played.packs[played.base], &played.packs[played.base + 1]);
    let ts = osis_commit::CommitBlob::decode_stored(&creation.bytes).unwrap().header.ts.wall_ms().0;
    let mut p = fresh(played.now);
    for pk in &played.packs[..played.base] {
        p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    p.clock.set(WallMs(ts - osis_base::format::MAX_DRIFT_MS - 1));
    assert!(matches!(p.receive(&write.bytes, write.blobs.clone()).unwrap(), osis_node::Ingested::Awaits(..)));
    assert!(matches!(p.receive(&creation.bytes, creation.blobs.clone()).unwrap(), osis_node::Ingested::Pending(..)));
    p.clock.set(played.now);
    p.tick().unwrap();
    let all: Vec<usize> = (0..played.packs.len()).collect();
    assert_eq!(shown(&mut p, &played.things), shown(&mut deliver(&played, &all), &played.things));
}

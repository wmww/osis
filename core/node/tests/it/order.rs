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
//! order must give the same reads and states of every aspect, rosters, pending set and timelines,
//! and a reopen and a rebuild must give them too. Which bodies a node holds and how it dates deaths
//! are its own, so three per-node checks stand in for comparing those: `body_past_bound` and
//! `bound_kept_now` (keep bounds), `live_write_lost` (no live write goes), `value_past_end` (no
//! value after its expiry or a held purge).
//! Short focused histories (bounded writes, compactions, undo, demotions, late writes) are also
//! checked in every arrival order of a few held sets. Seeds run on a thread per core.

use crate::common;
use common::*;
use osis_base::testenv::{caught, par_map, threads};
use osis_base::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_node::engine::IndexField;
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
    /// A permanent delta (spec/commits.md §5) of `by` on `t`'s register.
    Message { by: usize, t: usize, v: u8 },
    /// `Purge`, by name only: none when `of` has no such commit.
    PurgeNamed { by: usize, t: usize, of: usize, back: u8, v: u8 },
    /// `by` purges `t`'s register, with a write there: one of `of`'s last commits by name, or (no
    /// such commit) the whole aspect.
    Purge { by: usize, t: usize, of: usize, back: u8, v: u8 },
    /// `by` purges `t`'s register by author: `of`'s deltas (spec/permissions.md §7), as the API does:
    /// no write on the register, a `purge.0` one.
    PurgeAuthor { by: usize, t: usize, of: usize },
    /// Every commit `from` holds to `to`.
    Sync { from: usize, to: usize },
    /// One of `from`'s last commits to `to`.
    Send { from: usize, to: usize, back: u8 },
    /// Time passes (`who`: one peer's clock, else every one).
    Advance { who: Option<usize>, ms: u64 },
    /// The step, its author and thing first pointed at what it can write at play time (`aim`),
    /// so that most drawn steps make a commit.
    Aim(Box<Step>),
    /// The step by a writer predating the copy-expiry rule (spec/crdt.md §4.7: a write copying
    /// an expiring value expires no later): played with `skip_writer_rules`.
    Old(Box<Step>),
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
    /// A roster snapshot of `t` by `by` holding `holder` with `role` and an invite above it.
    OverInviteRoster { by: usize, t: usize, holder: usize, role: Role, invite: Role },
    /// A `keys.0` write of one field of `t`, unchecked: 1 (`write`) to none, 5 (`deposit_seed`).
    HostileKeys { by: usize, t: usize, field: u64 },
    /// A register write on `t`, unchecked.
    HostileWrite { by: usize, t: usize, v: u8 },
    /// A `required.0^` on `t` (spec/commits.md §5): by `rule % 4`, nothing, `op`'s aspect as
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
    /// A write with a paged delta (spec/crdt.md §8).
    Paged { by: usize, t: usize },
    /// A write of a large atomic value (spec/data-model.md §6).
    Large { by: usize, t: usize },
    /// A removal of `holder` on `t` with its frontier as of now, padded past `CHUNK_THRESHOLD`
    /// with things nobody holds, so it goes by link.
    LinkedDemote { by: usize, t: usize, holder: usize },
}

const OPS: u8 = 35;
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
        // with a keep bound (deaths count only there): registers, a map under keep at most 0
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
        // under an absolute keep at most (`retention_of`): a list insert, a register also under
        // 0 after replaced
        30 => "t:list.0",
        31 => "t:gone.0",
        // an expiring list element, another's write in it, its removal
        32..=34 => "t:listtext.0",
        _ => "t:docs.0",
    })
}

/// The retention of `op`'s writes when not the default: keep at least 30 min, or at most 0 after
/// replaced.
fn keep_of(op: u8) -> Option<Retention> {
    let d = Some(HOUR / 2);
    let at_least = Some(Retention { by: PurgeBy::AuthorOrAdmin, at_least: Bound { abs: None, rel: d }, at_most: Bound::default() });
    // an author-only class among them: an admin's compaction drops none of another's bodies
    let author = Some(Retention { by: PurgeBy::Author, at_least: Bound { abs: None, rel: d }, at_most: Bound::default() });
    let at_most = Some(Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs: None, rel: Some(0) } });
    match op % OPS {
        16 | 21..=23 => at_least,
        24..=26 => author,
        17..=20 | 31 => at_most,
        _ => None,
    }
}

/// `keep_of(op)`, with an absolute keep at most for ops 30 and 31 (spec/commits.md §5): a second
/// (a peer's own clock steps pass it) or half an hour after `now`, by `v`.
fn retention_of(op: u8, v: u8, now: WallMs) -> Option<Retention> {
    let abs = (30..=31).contains(&(op % OPS)).then(|| now.0 + if v.is_multiple_of(2) { 1_000 } else { HOUR / 2 });
    match (keep_of(op), abs) {
        (r, None) => r,
        (r, Some(t)) => {
            let mut r = r.unwrap_or_default();
            r.at_most.abs = Some(t);
            Some(r)
        }
    }
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
        PurgeNamed { by, t, of, back, v } => pick(lp, by, t, &write).filter(|x| x.0 == by).map(|(by, t)| PurgeNamed { by, t, of, back, v }),
        Purge { by, t, of, back, v } => pick(lp, by, t, &write).filter(|x| x.0 == by).map(|(by, t)| Purge { by, t, of, back, v }),
        PurgeAuthor { by, t, of } => pick(lp, by, t, &write).filter(|x| x.0 == by).map(|(by, t)| PurgeAuthor { by, t, of }),
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
        0..=7 => aim(Step::Typed { by, t, op: rng.below(DRAWN as u64) as u8, k: rng.below(3) as u8, v: rng.below(10) as u8 }),
        8..=10 => aim(Step::Write { by, t, op: rng.pick(&UNTYPED), k: rng.below(3) as u8, v: rng.below(10) as u8 }),
        40 | 41 => {
            let other = (by + 1 + rng.below(2) as usize) % 3;
            aim(Step::NestedItem { by, other, t, k: rng.below(3) as u8, compact: rng.below(3) != 0, also: rng.below(2) == 0 })
        }
        42..=44 => Step::Forged { by, a: t, b: rng.below(8) as usize, how: rng.below(5) as u8, op: rng.below(DRAWN as u64) as u8, k: rng.below(3) as u8, v: rng.below(10) as u8 },
        45 => Step::NewTop { by },
        11..=13 => aim(Step::Edge { by: rng.pick(&[0, 0, 2]), t, holder: rng.pick(&[1, 2]), role: rng.pick(&[None, Some(Role::Read), Some(Role::Write), Some(Role::Write), Some(Role::Admin)]) }),
        14..=17 => aim(Step::Demote { by: rng.pick(&[0, 0, 2]), t, holder: rng.pick(&[1, 2]), at: rng.below(6) as u8, to_read: rng.below(3) == 0 }),
        18 => aim(Step::Leave { by: rng.pick(&[1, 2]), t }),
        19 => aim(Step::Roster { by: rng.pick(&[0, 0, 2]), t }),
        20..=22 => aim(Step::Compact { by, t, op: rng.below(DRAWN as u64) as u8 }),
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
    // a second key in the same delta: one replaced leaves the body a live write to its bound
    if op % OPS == 19 && v.is_multiple_of(2) {
        op_on(m, e, t, op, content_op(op, k + 1, v).1, typed);
    }
}

/// `holder`'s edge on `t` as remove + put (`None`: removed), spec/permissions.md §2.
fn edge_write(t: Tid, holder: Tid, e: Option<osis_schema::core_types::Edge>) -> Mutation {
    let mut m = Mutation::new();
    m.op(t, &osis_schema::core_types::ROLES, PathOp { path: vec![], op: Op::Remove(Value::Tid(holder)) }).unwrap();
    match e {
        Some(e) => m.op(t, &osis_schema::core_types::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(e.to_value()) }).map(|_| ()).unwrap(),
        // an explicit removal: with no frontier it would be a finalize (spec/permissions.md §2)
        None => {
            m.frontier(osis_schema::core_types::Frontier::default().to_value());
        }
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
    /// Bodies of a fallen purge given again and judged alike (`alike_exchanged`).
    restored: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// What the per-node checks judged (`Seen::judged`).
    judged: std::sync::Arc<[std::sync::atomic::AtomicU64; 3]>,
    /// Deliveries at an earlier clock whose move to `now` changed a state or a body (`Clock`).
    moved: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// The history ends with every writer compacting what it holds (`settled`): no exception left.
    settled: bool,
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
                let d = osis_node::flows::Demotion { holder: ids[by], new: None, presync: osis_node::flows::PreSync::Backdated(T0), keep: None };
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
            Step::Message { by, t, v } => {
                let mut m = Mutation::new();
                m.retention(th(t), &REG, Retention { by: PurgeBy::AuthorOrAdmin, at_least: Bound { abs: Some(osis_commit::FOREVER), rel: None }, at_most: Bound::default() }).unwrap();
                m.set(th(t), &REG, &s(&format!("m{v}"))).unwrap();
                no = why(&lp.peers[by].commit(m));
                Some(by)
            }
            Step::PurgeNamed { by, t, of, back, v } => {
                let t = th(t);
                if let Some(commit) = own[of].len().checked_sub(1 + back as usize).and_then(|i| own[of].get(i)).copied() {
                    let mut m = Mutation::new();
                    m.purge(osis_commit::PurgeItem::Commit { commit, tid: t, ak: ak("t:reg.0") });
                    m.set(t, &REG, &s(&format!("p{v}"))).unwrap();
                    no = why(&lp.peers[by].commit(m));
                }
                Some(by)
            }
            Step::Purge { by, t, of, back, v } => {
                let t = th(t);
                let k = ak("t:reg.0");
                let named = own[of].len().checked_sub(1 + back as usize).and_then(|i| own[of].get(i)).copied();
                let mut m = Mutation::new();
                m.purge(match named {
                    Some(commit) => osis_commit::PurgeItem::Commit { commit, tid: t, ak: k },
                    None => osis_commit::PurgeItem::Aspect { tid: t, ak: k },
                });
                m.set(t, &REG, &s(&format!("p{v}"))).unwrap();
                no = why(&lp.peers[by].commit(m));
                Some(by)
            }
            Step::PurgeAuthor { by, t, of } => {
                let (t, actor) = (th(t), lp.peers[of].engine.tid());
                let mut m = Mutation::new();
                let now = lp.peers[by].engine.now();
                m.set(t, &osis_schema::core_types::PURGE, &now).unwrap();
                m.purge(osis_commit::PurgeItem::Author { tid: t, ak: ak("t:reg.0"), actor });
                no = why(&lp.peers[by].commit(m));
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
                let d = osis_node::flows::Demotion { holder: ids[holder], new: None, presync: osis_node::flows::PreSync::Backdated(T0), keep: None };
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
            Step::OverInviteRoster { by, t, holder, role, invite } => {
                let roster: osis_schema::core_types::Holders = [(ids[holder], osis_schema::core_types::Edge { invite: Some(invite), ..edge(role) })].into_iter().collect();
                let mut m = Mutation::new();
                m.replace(th(t), &osis_schema::core_types::ROLES, &roster).unwrap();
                m.replace(th(t), &osis_schema::core_types::TENURES, &osis_schema::core_types::Tenures(Vec::new())).unwrap();
                m.roster_for_tests();
                lp.peers[by].engine.commit_hostile(m).unwrap().expect("a snapshot writes");
                Some(by)
            }
            Step::HostileKeys { by, t, field } => {
                let v = match field {
                    5 => Some([9u8; 32]).to_value(),
                    _ => None::<osis_schema::core_types::Keyset>.to_value(),
                };
                let mut m = Mutation::new();
                m.op(th(t), &osis_schema::core_types::KEYS, PathOp { path: vec![PathSeg::Field(field)], op: Op::Set(v) }).unwrap();
                lp.peers[by].engine.commit_hostile(m).unwrap().expect("a keys.0 write writes");
                Some(by)
            }
            Step::Require { by, t, op, rule } => {
                let keep = keep_of(op).unwrap_or_default();
                let one = |p: &str, r: Retention| std::collections::BTreeMap::from([(p.to_string(), osis_schema::core_types::Required::new(r, None))]);
                let rules = match rule % 4 {
                    0 => std::collections::BTreeMap::new(),
                    1 => one(aspect_of(op).as_str(), keep),
                    2 => one("t:", Retention::default()),
                    _ => one("", keep),
                };
                let m = {
                    let mut m = Mutation::new();
                    m.set(th(t), &osis_schema::core_types::REQUIRED, &osis_schema::core_types::RequiredRules::from(rules.clone())).unwrap();
                    // a second part in another body class, so the setting may arrive late
                    if rule % 2 == 1 {
                        m.set(th(t), &REG, &s("beside")).unwrap();
                    }
                    m
                };
                no = why(&if rule & 4 != 0 { lp.peers[by].engine.commit_hostile(m) } else { lp.peers[by].commit(m) });
                Some(by)
            }
            Step::Breaking { by, t, op, v, fits } => {
                let a = aspect_of(op);
                let mut m = Mutation::new();
                write_op(&mut m, &mut lp.peers[by].engine, th(t), op, 0, v, true);
                m.retention(th(t), &a, if fits { Retention::default() } else { Retention { by: PurgeBy::Nobody, ..Retention::default() } }).unwrap();
                // a commit with a second part, its retention its own, in the same class when `v` says;
                // `nobody` beside `nobody` only, one expiry (spec/commits.md §5, §6)
                if v % 2 == 1 && a != aspect_of(0) {
                    let o = aspect_of(0);
                    write_op(&mut m, &mut lp.peers[by].engine, th(t), 0, 1, v, true);
                    let nobody = Retention { by: PurgeBy::Nobody, ..Retention::default() };
                    let other = if fits { Retention { by: PurgeBy::Writer, ..Retention::default() } } else { Retention { at_least: Bound { abs: None, rel: Some(1) }, ..nobody } };
                    m.retention(th(t), &o, if v % 4 == 1 { if fits { Retention::default() } else { nobody } } else { other }).unwrap();
                    if let Some(ms) = expiry_of(op, v) {
                        m.expires(th(t), &o, WallMs(lp.peers[by].engine.now().0 + ms)).unwrap();
                    }
                }
                no = why(&lp.peers[by].engine.commit_hostile(m));
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
    Played { packs, authors, base, things, now, tally, sync: Syncs::None, restored: Default::default(), judged: Default::default(), moved: Default::default(), settled: false, model: None }
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

/// What a node holding `held` and keeping every body judges (`keep_bodies`): the reference of the
/// per-node checks.
struct Oracle {
    held: Vec<usize>,
    /// Recomputed from every body: each write's earliest superseder (spec/crdt.md §4.8).
    deaths: Deaths,
    facts: String,
    /// Aspects a held snapshot carries writes of whose own commit is not held: a recompute plays
    /// those at the snapshot, so `deaths` may be late there and is not judged.
    carried: BTreeSet<(Tid, Ak)>,
    /// The live writes of each aspect's state after `later_than`.
    live_later: BTreeMap<(Tid, Ak), BTreeSet<osis_crdt::Dot>>,
    /// What each aspect reads after `later_than`.
    reads_later: BTreeMap<(Tid, Ak), String>,
    expired_pending: BTreeSet<(String, String)>,
    /// `Cfg::model`: every body it holds at `played.now`, for the model's judgment of the bodies
    /// a node dropped (`held::compare`).
    bodies: crate::held::Bodies,
}

fn oracle(played: &Played, held: &[usize]) -> Oracle {
    let mut p = Peer::new(FRESH, played.now).unwrap();
    p.engine.keep_bodies(true);
    for t in played.sync.things() {
        p.engine.set_syncing(*t, true).unwrap();
    }
    // twice: a body a purge dropped before it fell here comes back
    for _ in 0..2 {
        for &i in held {
            let pk = &played.packs[i];
            let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
        }
    }
    let mut aspects = BTreeSet::new();
    for id in p.engine.commit_ids() {
        aspects.extend(p.engine.header(&id).into_iter().flat_map(|h| h.aspects.iter().map(|a| (a.tid, a.ak.clone())).collect::<Vec<_>>()));
    }
    let carried = aspects.iter().filter(|(t, a)| !p.engine.carried_dots(t, a).is_empty()).cloned().collect();
    for (t, a) in &aspects {
        p.engine.replay_deaths(t, a).unwrap();
    }
    let (deaths, facts) = (deaths_of(&mut p.engine), facts_text(&mut p.engine));
    let bodies = if played.model.is_some() { crate::held::bodies(&mut p.engine) } else { Default::default() };
    p.clock.set(later_than(played));
    p.engine.tick().unwrap();
    let live_later = live_writes(&mut p.engine);
    let reads_later = live_later.keys().map(|(t, a)| ((*t, a.clone()), format!("{:?}", p.engine.get(t, a).unwrap()))).collect();
    let expired_pending = expired_pending(&mut p.engine);
    Oracle { held: held.to_vec(), deaths, facts, carried, live_later, reads_later, expired_pending, bodies }
}

/// Past every keep bound, grace and expiry the ops draw (30 min, plus 1 h with a live write), from
/// any death by `played.now`; close enough that a body held long past its bound shows.
fn later_than(played: &Played) -> WallMs {
    WallMs(played.now.0 + 2 * HOUR)
}

fn live_writes(e: &mut osis_node::Engine) -> BTreeMap<(Tid, Ak), BTreeSet<osis_crdt::Dot>> {
    let mut out = BTreeMap::new();
    for (t, a) in e.all_aspects().unwrap() {
        let dots = e.state(&t, &a).unwrap().map_or(BTreeSet::new(), |f| f.live_writes().into_iter().map(|x| x.0).collect());
        out.insert((t, a), dots);
    }
    out
}

/// Check (a), at the clock the node was delivered at: no dead body under keep at most 0 is held
/// (it drops in the killing transaction) and no body under it is gone before the earliest
/// superseder any held body gives. A commit carrying a purge request
/// keeps its blobs to `ROLE_KEEP` (spec/commits.md §5, Purge request); a drop before a flip or an
/// aspect flagged for a part gone at its expiry has no bound to judge against.
fn bound_kept_now(p: &mut Peer, o: &Oracle, played: &Played) -> Option<String> {
    let now = played.now;
    let (mine, _) = facts_of(&facts_text(&mut p.engine));
    let (theirs, inv) = facts_of(&o.facts);
    let mut apart: BTreeSet<(String, String)> = theirs.keys().filter(|k| mine.contains_key(*k) && flip(&theirs, &mine, &inv, k)).map(|k| (k.1.clone(), k.2.clone())).collect();
    apart.extend(expired_pending(&mut p.engine));
    let e = &mut p.engine;
    let mut ids = e.commit_ids();
    ids.sort();
    for id in ids {
        let Some(h) = e.header(&id) else { continue };
        for (ai, a) in h.aspects.iter().enumerate() {
            if a.retention.at_most.rel.is_none() {
                continue;
            }
            let key = (format!("{:?}", a.tid), a.ak.as_str().to_string());
            let missing = e.core.ix.commits.get(&id).is_some_and(|m| m.missing.contains(&ai));
            if missing || o.carried.contains(&(a.tid, a.ak.clone())) || apart.contains(&key) {
                continue;
            }
            let what = format!("{id:?} ({:?}) {:?} {}", h.kind, a.tid, a.ak.as_str());
            if e.body_not_dropped(&id, &a.tid, &a.ak) {
                if h.purge.is_empty() && e.deaths(&id, &a.tid, &a.ak).unwrap().is_some() && !e.body_live(&id, &a.tid, &a.ak).unwrap() {
                    return Some(format!("dead body kept under keep at most 0: {what}"));
                }
            } else {
                let first = o.deaths.get(&(id, a.tid, a.ak.clone())).copied().flatten();
                let k = (format!("{id:?}"), key.0, key.1);
                if h.kind.has_own_writes() && a.retention.at_most.abs.is_none_or(|t| t > now.0) && theirs.get(&k).is_some_and(|f| f.held) && !first.is_some_and(|y| y.0.wall_ms().0 <= now.0) {
                    return Some(format!("body dropped before its keep-at-most bound: {what}, earliest superseder {first:?}"));
                }
            }
        }
    }
    None
}

/// Check (a), later (the node ticked): no applied body under a keep at most is held past its
/// bound (spec/commits.md §5): an absolute one, valid or not; first death plus grace, live writes
/// or not; and, whatever its deaths say, none under 0 after replaced without a live write.
fn body_past_bound(p: &mut Peer, played: &Played, o: &Oracle) -> Option<String> {
    let e = &mut p.engine;
    let mut ids = e.commit_ids();
    ids.sort();
    for id in ids {
        let Some(h) = e.header(&id) else { continue };
        if !h.purge.is_empty() {
            continue;
        }
        for (ai, a) in h.aspects.iter().enumerate() {
            let (rel, abs) = (a.retention.at_most.rel, a.retention.at_most.abs);
            let abs_past = abs.is_some_and(|t| t <= later_than(played).0);
            if !abs_past && rel.is_none() {
                continue;
            }
            played.judged[0].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let missing = e.core.ix.commits.get(&id).is_some_and(|m| m.missing.contains(&ai));
            if missing || !e.body_not_dropped(&id, &a.tid, &a.ak) {
                continue;
            }
            let dead_long = rel.is_some() && e.deaths(&id, &a.tid, &a.ak).unwrap().is_some_and(|x| x.0.wall_ms().0 + osis_base::format::AT_MOST_GRACE_MS <= later_than(played).0);
            if !abs_past && !dead_long && e.body_live(&id, &a.tid, &a.ak).unwrap() {
                continue;
            }
            // no death, so no bound (spec/commits.md §5): its killers went with bodies dropped
            // before it came. A fall is no such case: a write invalid here counts dead from it, as
            // does one an un-merge took (no write live, an invalid write on the aspect, nothing dropped)
            if !abs_past && !dead_long && e.deaths(&id, &a.tid, &a.ak).unwrap().is_none() {
                let k = (a.tid, a.ak.clone());
                let dropped = e.core.ix.by_aspect.get(&k).into_iter().flatten().any(|x| e.core.ix.commits.get(&x.1).is_some_and(|m| m.header.aspects.iter().position(|y| y.tid == a.tid && y.ak == a.ak).is_some_and(|i| m.dropped.contains_key(&i))));
                let invalid = e.body_valid(&id, &a.tid, &a.ak) == Some(false);
                let fallen = h.kind != osis_commit::Kind::Role && (invalid || !dropped && h.kind.has_own_writes() && !e.invalid_writes(&a.tid, &a.ak).is_empty());
                if !fallen && (dropped || o.deaths.get(&(id, a.tid, a.ak.clone())).copied().flatten().is_none()) {
                    continue;
                }
            }
            return Some(format!("body held past its bound: {id:?} ({:?}) {:?} {}, deaths {:?}", h.kind, a.tid, a.ak.as_str(), e.deaths(&id, &a.tid, &a.ak).unwrap()));
        }
    }
    None
}

/// Check (c): no value of a delta past its expiry, or that a held purge request drops, is left in
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
            played.judged[2].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

/// Whether what `p` reads now differs from the keep-everything node later, on an aspect not
/// in `skip`; the first such aspect.
fn read_differs(p: &mut Peer, o: &Oracle, skip: &dyn Fn(&(String, String)) -> bool) -> Option<String> {
    for ((t, a), want) in &o.reads_later {
        let got = format!("{:?}", p.engine.get(t, a).unwrap());
        if got != *want && !skip(&(format!("{t:?}"), a.as_str().to_string())) {
            return Some(format!("{t:?} {} reads {got} where the node keeping every body reads {want}", a.as_str()));
        }
    }
    None
}

/// Check (b), later. A drop leaves live writes in the state, so a node reads as the
/// keep-everything node with no body given again, on an aspect where nothing fell, rose from a
/// fall or was purged (a flip or purge after a drop: spec/requirements.md Deterministic). Given again every body that
/// node holds, the node reads as it and its state has every write live there. An aspect flagged for
/// a part gone at its expiry is left out, the part counting as never received (spec/commits.md §5);
/// such a flag names an aspect some commit writes with an expiry. Leaves the node holding those
/// bodies.
fn live_write_lost(p: &mut Peer, o: &Oracle, played: &Played, flips: &dyn Fn(&str, &str) -> bool) -> Option<String> {
    let headers: Vec<osis_commit::Header> = played.packs.iter().filter_map(|pk| osis_commit::CommitBlob::decode_stored(&pk.bytes).ok().map(|b| b.header)).collect();
    let key = |t: &Tid, a: &osis_base::Ak| (format!("{t:?}"), a.as_str().to_string());
    let expiring: BTreeSet<_> = headers.iter().filter(|h| h.expires.is_some()).flat_map(|h| h.aspects.iter().map(|a| key(&a.tid, &a.ak)).collect::<Vec<_>>()).collect();
    let flagged = expired_pending(&mut p.engine);
    if let Some(k) = flagged.iter().find(|k| !expiring.contains(*k)) {
        return Some(format!("{k:?} flagged for a part gone at its expiry, and nothing writes it with an expiry"));
    }
    let named: BTreeSet<_> = headers.iter().flat_map(|h| h.purge.iter().map(|i| key(i.tid(), i.ak())).collect::<Vec<_>>()).collect();
    let (mine, inv) = facts_of(&facts_text(&mut p.engine));
    let (theirs, inv2) = facts_of(&o.facts);
    let mut fell: BTreeSet<(String, String)> = inv.into_keys().chain(inv2.into_keys()).collect();
    fell.extend(mine.iter().chain(theirs.iter()).filter(|(_, f)| !f.valid).map(|(k, _)| (k.1.clone(), k.2.clone())));
    // dropped from its fall, valid since: missing until given again (spec/commits.md §5)
    fell.extend(mine.iter().filter(|(_, f)| f.at_most && f.missing).map(|(k, _)| (k.1.clone(), k.2.clone())));
    if let Some(d) = read_differs(p, o, &|k| flagged.contains(k) || o.expired_pending.contains(k) || named.contains(k) || fell.contains(k) || flips(&k.0, &k.1)) {
        return Some(d);
    }
    for &i in &o.held {
        let pk = &played.packs[i];
        let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    p.engine.reexamine().unwrap();
    let flagged = expired_pending(&mut p.engine);
    if let Some(d) = read_differs(p, o, &|k| flagged.contains(k) || o.expired_pending.contains(k)) {
        return Some(format!("given every body again: {d}"));
    }
    let here = live_writes(&mut p.engine);
    for ((t, a), dots) in &o.live_later {
        let key = (format!("{t:?}"), a.as_str().to_string());
        if flagged.contains(&key) || o.expired_pending.contains(&key) {
            continue;
        }
        played.judged[1].fetch_add(dots.len() as u64, std::sync::atomic::Ordering::Relaxed);
        let have = here.get(&(*t, a.clone()));
        if let Some(d) = dots.iter().find(|d| !have.is_some_and(|h| h.contains(*d))) {
            return Some(format!("live write {d:?} of {t:?} {} lost: the node keeping every body has it, this one did not get it back", a.as_str()));
        }
    }
    None
}

/// `judged` with the per-node checks around it, for a node `o` is the keep-everything node of.
fn judged_checked(p: &mut Peer, played: &Played, o: &Oracle, flips: &dyn Fn(&str, &str) -> bool) -> Result<Judged, String> {
    bound_kept_now(p, o, played).or_else(|| value_past_end(p, played, played.now)).or_else(|| model_differs(p, played, o)).map_or(Ok(()), Err)?;
    let j = judged(p, played);
    later_checks(p, played, o, flips).map_or(Ok(j), Err)
}

/// The per-node checks later (the node ticked by `later`); leaves it holding `o`'s bodies.
fn later_checks(p: &mut Peer, played: &Played, o: &Oracle, flips: &dyn Fn(&str, &str) -> bool) -> Option<String> {
    model_differs(p, played, o).or_else(|| body_past_bound(p, played, o)).or_else(|| value_past_end(p, played, later_than(played))).or_else(|| live_write_lost(p, o, played, flips))
}

/// `Cfg::model`: where the node and held-model judge what it holds differently (`held::compare`).
fn model_differs(p: &mut Peer, played: &Played, o: &Oracle) -> Option<String> {
    let m = played.model.as_ref()?;
    let mut cov = crate::held::Coverage::default();
    let d = crate::held::compare(&mut p.engine, &m.0, &o.bodies, &mut cov);
    m.1.lock().unwrap().add(&cov);
    d
}

/// The facts of each body the harness uses to tell which bodies to give again after a flip and
/// which commits a part's expiry parted: never compared across orders, deaths and held bodies being
/// per node. Per body: commit, thing, aspect, under keep at most, held, valid, `ts`, copies,
/// lowest carried `ts`, missing; per aspect its invalid writes (`inv`).
fn facts_text(e: &mut osis_node::Engine) -> String {
    let mut facts = String::new();
    let mut aspects = BTreeSet::new();
    for id in e.commit_ids() {
        let Some(h) = e.header(&id) else { continue };
        for (ai, a) in h.aspects.iter().enumerate() {
            let at_most = a.retention.at_most.rel.is_some() || a.retention.at_most.abs.is_some();
            let valid = e.body_valid(&id, &a.tid, &a.ak).unwrap();
            let held = e.body_not_dropped(&id, &a.tid, &a.ak);
            let copies = !h.kind.has_own_writes();
            // a held copies body's lowest carried `ts` (`-`: dropped, or not copies)
            let low = if copies { e.body_min_ts(&id, &a.tid, &a.ak).unwrap().map_or("-".into(), |t| format!("{t:?}")) } else { "-".to_string() };
            let missing = e.core.ix.commits.get(&id).is_some_and(|m| m.missing.contains(&ai));
            let _ = writeln!(facts, "{id:?}|{:?}|{}|{at_most}|{held}|{valid}|{:?}|{copies}|{low}|{missing}", a.tid, a.ak.as_str(), h.ts);
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

/// What a node judged, as text by part: `alike` compares these across orders.
#[derive(Clone)]
struct Judged {
    parts: Vec<(&'static str, String)>,
    /// `facts_text`: read by the exchange, not compared.
    facts: String,
    /// Parts not received later (`judged`; `None` from `judged_now`): read by the exchange.
    missing_later: Option<BTreeMap<CommitId, BTreeSet<usize>>>,
    /// Aspects (as `facts_text` prints them) the node flags suspect for a part it held pending
    /// at its expiry (counts as never received, spec/commits.md §5): not compared.
    expired_pending: BTreeSet<(String, String)>,
    /// Aspects the node flags suspect for any reason: a writer repairs them (`alike_repaired`).
    suspect: BTreeSet<(String, String)>,
    /// Delivered in part at an earlier clock (`Clock`).
    early: bool,
}

impl Judged {
    fn part(&self, name: &str) -> &str {
        &self.parts.iter().find(|x| x.0 == name).unwrap().1
    }
}

/// A state's text, with what spec/crdt.md §5.7 leaves to the node taken out: a deleted text
/// element's char (a node may drop it locally; a reopen has), also once an undelete's copy of
/// it reads in its place (seed 198 of `required_drops_read_alike_large`: dropped at a reopen
/// while deleted, then undeleted).
fn plain_state(state: &str) -> String {
    const AT: &str = "SeqElem {";
    let mut parts = state.split(AT);
    let mut out = parts.next().unwrap_or("").to_string();
    for el in parts {
        out.push_str(AT);
        let deleted = el.find("deleted: Some").is_some_and(|i| el[i..].find("span:").is_some_and(|j| el[i..i + j].contains(", true))")));
        let copied = |i: usize| el[i..].strip_prefix("content: Char(").and_then(|c| c.get(..3)).is_some_and(|c| el.contains(&format!("undel: Some({c})")));
        match el.find("content: Char(").filter(|i| deleted || copied(*i)) {
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
/// at its expiry (never dormant, `retention::suspect`).
fn expired_pending(e: &mut osis_node::Engine) -> BTreeSet<(String, String)> {
    e.suspects().unwrap().into_iter().filter(|x| x.3 & osis_node::retention::suspect::Why::PendingExpiry as u8 != 0).map(|(t, a, _, _)| (format!("{t:?}"), a.as_str().to_string())).collect()
}

/// What a node holding `packs` judges and reads now, as text, by part: reads and states of every
/// aspect, rosters, pending set, timelines.
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
    let parts = vec![("reads", reads), ("states", states), ("rosters", rosters), ("pending", pending.join("\n")), ("timelines", perm), ("timelines from scratch", scratch)];
    let expired_pending = expired_pending(e);
    let suspect = e.suspects().unwrap().into_iter().map(|(t, a, _, _)| (format!("{t:?}"), a.as_str().to_string())).collect();
    Judged { parts, facts, missing_later: None, expired_pending, suspect, early: false }
}

/// Moves the node's clock to `later_than` and adds its reads and states then to `v`.
fn later(v: &mut Judged, p: &mut Peer, played: &Played) {
    let at = later_than(played);
    if p.engine.now().0 < at.0 {
        p.clock.set(at);
    }
    p.engine.tick().unwrap();
    let l = judged_now(p, &played.things);
    v.parts.push(("reads later", l.part("reads").to_string()));
    v.parts.push(("states later", l.part("states").to_string()));
    v.expired_pending.extend(l.expired_pending);
    v.suspect.extend(l.suspect);
    v.missing_later = Some(p.engine.commit_parts_missing());
}

/// `judged_now`, then `later` (moves the node's clock).
fn judged(p: &mut Peer, played: &Played) -> Judged {
    let mut v = judged_now(p, &played.things);
    later(&mut v, p, played);
    v
}

/// A body's facts at one node (`facts_text`), keyed by (commit, thing, aspect) as they print.
struct Fact {
    at_most: bool,
    held: bool,
    valid: bool,
    ts: u64,
    /// A snapshot body (copies): its carried writes die for it at its `ts` when
    /// killed by a lower-stamped write (spec/commits.md §5).
    copies: bool,
    /// Held there, a copies body's lowest carried write `ts` (a killer is stamped after it).
    low: Option<u64>,
    /// Missing (counting as never received, as after a fall) when judged.
    missing: bool,
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
        out.insert((f[0].into(), f[1].into(), f[2].into()), Fact { at_most: b(3), held: b(4), valid: b(5), ts: ts_of(f[6]), copies: b(7), low: (f[8] != "-").then(|| ts_of(f[8])), missing: b(9) });
    }
    (out, inv)
}

/// Facts per body and invalid writes per aspect (`facts_of`).
type Facts = BTreeMap<BodyKey, Fact>;
type Invalid = BTreeMap<(String, String), Vec<(String, u64)>>;

/// The drop-before-flip difference on body `k` between nodes with facts `w` and `g`: held at
/// one node only, under keep at most, with its own write invalid (its delta, or a write it
/// carries) or an invalid write of its aspect that may have killed it: stamped at or after it,
/// or for a snapshot at or after the lowest write it carries (a lower-stamped kill of
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
    let ((wf, inv), (gf, _)) = (facts_of(&want.facts), facts_of(&got.facts));
    let again = refetched(want, got);
    wf.keys().filter(|k| gf.contains_key(*k) && (flip(&wf, &gf, &inv, k) || again.contains(&k.0))).map(|k| k.0.clone()).collect()
}

/// The commits with a keep-at-most part missing at either node: dropped while invalid and valid
/// since, so fetched again (`valid_again`).
fn refetched(want: &Judged, got: &Judged) -> BTreeSet<String> {
    let ((wf, _), (gf, _)) = (facts_of(&want.facts), facts_of(&got.facts));
    wf.keys().filter(|k| gf.contains_key(*k) && wf[*k].at_most && (wf[*k].missing || gf[*k].missing)).map(|k| k.0.clone()).collect()
}

/// Whether two nodes holding the same commits read alike (`None`), else the first difference: reads
/// and states of every aspect, now and later, rosters, pending sets and timelines, exactly. A
/// body dropped before a validity flip, at one node or both, is no exception: callers give both
/// nodes such bodies again first (`alike_exchanged`). Which bodies are held and how deaths are dated
/// are per node and not compared (`body_past_bound`, `live_write_lost`, `value_past_end`).
fn alike(want: &Judged, got: &Judged) -> Option<String> {
    // a part held pending at its expiry counts as never received at that node (spec/commits.md
    // §5; Tess: nodes may read differently when a part expired before a node could apply it):
    // what such an aspect reads and its states may differ, repaired by a writer's snapshot
    // (spec/sync.md §7), which the node cannot tell (its flag stays). Nothing else: whether a
    // commit is applied or pending, and every other aspect, must agree.
    let expired: BTreeSet<(String, String)> = want.expired_pending.union(&got.expired_pending).cloned().collect();
    let on_expired = |k: &BodyKey| expired.contains(&(k.1.clone(), k.2.clone()));
    let ((wf, _), (gf, _)) = (facts_of(&want.facts), facts_of(&got.facts));
    // a node given a commit before a part of it expired may have applied it by that part, where
    // one given it after holds it pending (spec/requirements.md Deterministic): with an
    // early clock, a commit with a part on such an aspect applied at one node only has its pending
    // line left out
    // known by any body of it: with one expiry per commit (spec/commits.md §6) every part of such
    // a commit may be on an expired aspect
    let known = |f: &Facts, c: &str| f.keys().any(|x| x.0 == c);
    let parted: BTreeSet<String> = if want.early || got.early {
        wf.keys().chain(gf.keys()).filter(|k| on_expired(k) && known(&wf, &k.0) != known(&gf, &k.0)).map(|k| k.0.clone()).collect()
    } else {
        BTreeSet::new()
    };
    for ((name, x), (_, y)) in want.parts.iter().zip(&got.parts) {
        if x == y {
            continue;
        }
        if name.starts_with("reads") || name.starts_with("states") {
            // keyed by thing and aspect: one may lack an aspect the other shows
            let (a, b) = (keyed(x), keyed(y));
            // an aspect a node holds nothing of reads as one holding no state
            let of = |m: &BTreeMap<(String, String), String>, k| m.get(k).cloned().unwrap_or_else(|| "None".into());
            for k in a.keys().chain(b.keys()) {
                if of(&a, k) != of(&b, k) && !expired.contains(k) {
                    return Some(format!("{name} on {k:?}:\n  want {:?}\n  got  {:?}", a.get(k), b.get(k)));
                }
            }
            continue;
        }
        if *name == "pending" && !parted.is_empty() {
            let other = |s: &str| s.lines().filter(|l| !parted.iter().any(|c| l.starts_with(&format!("{c} ")))).collect::<Vec<_>>().join("\\n");
            if other(x) == other(y) {
                continue;
            }
        }
        return first_diff_parts(&[(name, x.clone())], &[(name, y.clone())]);
    }
    None
}

/// Reads or states as `judged_now` prints them, by (thing, aspect).
fn keyed(text: &str) -> BTreeMap<(String, String), String> {
    text.lines().map(|l| {
        let f: Vec<&str> = l.splitn(3, ' ').collect();
        ((f[0].into(), f.get(1).copied().unwrap_or("").into()), f.get(2).copied().unwrap_or("").into())
    }).collect()
}

/// The commits (as `facts_text` prints them) of the bodies dropped at both nodes, under keep at
/// most or snapshots on an aspect a purge request names (dropped for carrying purged writes, seed
/// 34000), on an aspect whose reads or states differ and
/// that flipped on the way (`flips`): what the state alone held of such a body and lost to an
/// un-merge comes back only with a copy (spec/crdt.md §4.6), which joins as a late part or, purged,
/// value-less (spec/commits.md §5), so both are given them again (`alike_exchanged`).
fn both_dropped_flips(want: &Judged, got: &Judged, flips: &dyn Fn(&str, &str) -> bool) -> BTreeSet<String> {
    let ((wf, _), (gf, _)) = (facts_of(&want.facts), facts_of(&got.facts));
    let dropped = |k: &BodyKey, f: &Fact| f.at_most && !f.held && gf.get(k).is_some_and(|g| !g.held);
    let mut apart: BTreeSet<(String, String)> = BTreeSet::new();
    for name in ["reads", "states"] {
        let (a, b) = (keyed(want.part(name)), keyed(got.part(name)));
        apart.extend(a.keys().chain(b.keys()).filter(|k| a.get(*k) != b.get(*k)).cloned());
    }
    apart.retain(|k| wf.iter().any(|(b, f)| (&b.1, &b.2) == (&k.0, &k.1) && dropped(b, f)) && flips(&k.0, &k.1));
    wf.iter().filter(|(k, f)| apart.contains(&(k.1.clone(), k.2.clone())) && dropped(k, f)).map(|(k, _)| k.0.clone()).collect()
}


/// The packs of the commits `ids` (as `facts_text` prints them).
fn packs_of(played: &Played, ids: &BTreeSet<String>) -> Vec<usize> {
    (0..played.packs.len()).filter(|&i| ids.contains(&format!("{:?}", played.packs[i].id))).collect()
}

/// `alike` of the judgements `want` (a node given `want_order`) and `got` (one given `got_order`,
/// split by `rng` as `deliver_split`), after both nodes are given once more the commits of
/// every body one dropped before a validity flip and the other holds (`drop_flips`), and of the
/// bodies both dropped on an aspect read apart after a flip (`both_dropped_flips`): a copy that
/// arrives again joins (spec/commits.md §5), so they then hold the same bodies and judge alike
/// with no exception for the drop.
fn alike_exchanged(played: &Played, want: &Judged, want_order: &[usize], got: &Judged, got_order: &[usize], way: Way, flips: &dyn Fn(&str, &str) -> bool) -> Option<String> {
    if played.settled {
        return alike_repaired(played, want, want_order, got, got_order, way);
    }
    let (rng, clock) = way.parts();
    let fallen = purge_flips(played, want, got);
    let mut apart = drop_flips(want, got);
    apart.extend(fallen.iter().cloned());
    apart.extend(both_dropped_flips(want, got, flips));
    if apart.is_empty() {
        return alike(want, got);
    }
    let again = packs_of(played, &apart);
    let mut rng = rng;
    let mut w = deliver_with(played, want_order, None, None, &mut |_| {});
    let mut g = deliver_with(played, got_order, rng.as_mut(), clock, &mut |_| {});
    for p in [&mut w, &mut g] {
        for &i in &again {
            let pk = &played.packs[i];
            let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
        }
        p.engine.reexamine().unwrap();
    }
    let (mut wj, mut gj) = (judged(&mut w, played), judged(&mut g, played));
    gj.early = clock.is_some();
    // a commit waiting past that copy, a part of it stripped for a purge that fell, applies later and
    // only then counts it missing (`index_later`): node-sync fetches it then (`Changed::undropped`)
    let later = purge_flips(played, &wj, &gj);
    if !later.is_empty() {
        let again = packs_of(played, &later);
        for p in [&mut w, &mut g] {
            for &i in &again {
                let pk = &played.packs[i];
                let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
            }
            p.engine.reexamine().unwrap();
        }
        (wj, gj) = (judged(&mut w, played), judged(&mut g, played));
        gj.early = clock.is_some();
    }
    let diff = alike(&wj, &gj).map(|d| format!("after the bodies dropped before a flip ({apart:?}) were given again: {d}"));
    if diff.is_none() {
        played.restored.fetch_add(fallen.len() as u64, std::sync::atomic::Ordering::Relaxed);
    }
    diff
}

/// `alike` in a `settled` history: reads of the aspects a writer compacted at the end (on one with
/// no writer left the exceptions have no end), value-less stamps may stay apart. That compaction
/// may reach a node before a flip that its keep bounds or a purge dropped the snapshot for: the
/// node flags the aspect suspect and a writer snapshots it again (spec/sync.md §7), so here a
/// flagged aspect's compactions come again, as that snapshot does, and a body missing again comes
/// from a node holding it.
fn alike_repaired(played: &Played, want: &Judged, want_order: &[usize], got: &Judged, got_order: &[usize], way: Way) -> Option<String> {
    let at = played.now.0.saturating_sub(HOUR);
    let compactions: Vec<(usize, BTreeSet<(String, String)>)> = played
        .packs
        .iter()
        .enumerate()
        .filter_map(|(i, p)| Some((i, osis_commit::CommitBlob::decode_stored(&p.bytes).ok()?.header)))
        .filter(|(_, h)| h.kind.is_compaction() && h.ts.wall_ms().0 >= at)
        .map(|(i, h)| (i, h.aspects.iter().map(|a| (format!("{:?}", a.tid), a.ak.as_str().to_string())).collect()))
        .collect();
    let compacted: BTreeSet<&(String, String)> = compactions.iter().flat_map(|c| &c.1).collect();
    let plain = |j: &Judged| {
        let parts: Vec<_> = j.parts.iter().filter(|x| !x.0.starts_with("states")).cloned().collect();
        let others = keyed(j.part("reads")).into_keys().chain(keyed(want.part("reads")).into_keys()).chain(keyed(got.part("reads")).into_keys()).filter(|k| !compacted.contains(k)).collect();
        Judged { expired_pending: others, parts, ..j.clone() }
    };
    // what a flag's body is fetched as, then the compactions
    let mut again = packs_of(played, &refetched(want, got));
    again.extend(compactions.iter().filter(|c| c.1.iter().any(|k| want.suspect.contains(k) || got.suspect.contains(k))).map(|c| c.0));
    if again.is_empty() {
        return alike(&plain(want), &plain(got));
    }
    let (mut rng, clock) = way.parts();
    let mut w = deliver_with(played, want_order, None, None, &mut |_| {});
    let mut g = deliver_with(played, got_order, rng.as_mut(), clock, &mut |_| {});
    for p in [&mut w, &mut g] {
        for &i in &again {
            let pk = &played.packs[i];
            let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
        }
        p.engine.reexamine().unwrap();
    }
    let (wj, mut gj) = (judged(&mut w, played), judged(&mut g, played));
    gj.early = clock.is_some();
    alike(&plain(&wj), &plain(&gj)).map(|d| format!("after a flagged aspect's compactions came again: {d}"))
}

/// The commits (as `facts_text` prints them) with a part on an aspect some purge request names
/// that is missing at one node and not at the other, when judged or later (an expiry by
/// then drops it at both): the purge fell after one applied it, and the part counts as never
/// received there (spec/permissions.md §7), as `drop_flips` for keep bounds.
fn purge_flips(played: &Played, want: &Judged, got: &Judged) -> BTreeSet<String> {
    let (Some(w), Some(g)) = (&want.missing_later, &got.missing_later) else { return BTreeSet::new() };
    // packages the harness made: no delete-key point checks (`decode_stored`)
    let headers: Vec<Option<osis_commit::Header>> = played.packs.iter().map(|p| osis_commit::CommitBlob::decode_stored(&p.bytes).ok().map(|b| b.header)).collect();
    let named: BTreeSet<(Tid, osis_base::Ak)> = headers.iter().flatten().flat_map(|h| h.purge.iter().map(|i| (*i.tid(), i.ak().clone())).collect::<Vec<_>>()).collect();
    let ((wf, _), (gf, _)) = (facts_of(&want.facts), facts_of(&got.facts));
    let missing_now = |id: &str, a: &osis_commit::AspectEntry| {
        let k = (id.to_string(), format!("{:?}", a.tid), a.ak.as_str().to_string());
        wf.get(&k).map(|f| f.missing) != gf.get(&k).map(|f| f.missing)
    };
    played.packs.iter().zip(&headers).filter(|&(p, h)| {
        let (Some(x), Some(y), Some(h)) = (w.get(&p.id), g.get(&p.id), h.as_ref()) else { return false };
        let id = format!("{:?}", p.id);
        let on_named = |a: &osis_commit::AspectEntry| named.contains(&(a.tid, a.ak.clone()));
        x.symmetric_difference(y).any(|ai| h.aspects.get(*ai).is_some_and(on_named)) || h.aspects.iter().any(|a| on_named(a) && missing_now(&id, a))
    }).map(|(p, _)| format!("{:?}", p.id)).collect()
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

/// The history as the seed's fresh nodes get it, by `seed % 3`: as made; each thing synced from
/// the start with probability one half and half of the commits with parts on several aspects
/// held in part for good (`Syncs::Early`); or things synced at varying points, with such parts
/// withheld too (`Syncs::Late`).
fn with_syncs(mut played: Played, seed: u64, settled: bool) -> Played {
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
                // not when settled: a part held by a writer and never here is no settled history,
                // the node reads as if it never had it until it arrives (seed 96410020)
                if ais.len() > 1 && rng.below(2) == 0 && !settled {
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
    deliver_with(played, order, None, None, &mut |_| {})
}

/// A fresh node given `packs` in `order`, each commit with parts on several aspects first with
/// those of one of them only (a seeded pick), the rest of it as late parts at the end, in
/// reverse (spec/commits.md §4: a late delta joins on arrival).
fn deliver_split(played: &Played, order: &[usize], rng: &mut Rng) -> Peer {
    deliver_with(played, order, Some(rng), None, &mut |_| {})
}

/// A delivery's clock (`deliver_with`): the first `at` ingests at wall time `early`, then the
/// clock moves to the history's end (`tick`: the expiries, keep-at-most drops and drift parks
/// due in between run) and the rest arrive.
#[derive(Clone, Copy, Debug)]
struct Clock {
    at: usize,
    early: WallMs,
}

/// How a compared node was given its order (`deliver_with`): as it is, with late parts split by
/// the rng (`deliver_split`), or in part at an earlier clock.
#[derive(Clone)]
enum Way {
    Plain,
    Split(Rng),
    Clocked(Clock),
}

impl Way {
    fn parts(self) -> (Option<Rng>, Option<Clock>) {
        match self {
            Way::Plain => (None, None),
            Way::Split(r) => (Some(r), None),
            Way::Clocked(c) => (None, Some(c)),
        }
    }
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
/// `played.moved` when a state or a body's facts changed.
fn move_clock(played: &Played, p: &mut Peer) {
    let states = |p: &mut Peer| {
        let mut out: Vec<String> = p.engine.all_aspects().unwrap().into_iter().map(|(t, a)| format!("{:?}", p.engine.state(&t, &a).unwrap())).collect();
        out.push(facts_text(&mut p.engine));
        out
    };
    let before = states(p);
    p.clock.set(played.now);
    p.engine.tick().unwrap();
    if states(p) != before {
        played.moved.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// `deliver` (no `rng`) or `deliver_split`, calling `each` after every ingest; with `clock`,
/// the first ingests at an earlier time (`Clock`). The node is made at `played.now` either way
/// and its clock set back, so its own things are the same as every fresh node's.
fn deliver_with(played: &Played, order: &[usize], mut rng: Option<&mut Rng>, clock: Option<Clock>, each: &mut dyn FnMut(&mut Peer)) -> Peer {
    let mut p = Peer::new(FRESH, played.now).unwrap();
    // every component's walk saved, so reopens restore them
    p.engine.set_walk_cache_min(1);
    if let Some(c) = clock {
        p.clock.set(c.early);
    }
    let mut late = Vec::new();
    let mut plan = played.sync.plan(order);
    let mut done = 0;
    for &i in order {
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
        let _ = p.engine.ingest(&bytes, pk.blobs.clone());
        each(&mut p);
    }
    if clock.is_some_and(|c| c.at >= order.len()) {
        move_clock(played, &mut p);
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
    // what is due runs, as node-sync runs it before every read (`SyncEngine::expire_due`): an
    // absolute keep at most passed at apply drops the body by its timer (spec/commits.md §5)
    p.engine.tick().unwrap();
    each(&mut p);
    p
}


/// `OSIS_ORDER_DUMP`: on an order's failure, prints the packs (index: id, author, kind, aspects),
/// each order's reads as they change after every ingest, and both nodes' judged parts. Every
/// failing check prints, the shrink's too: use it on a pinned history or with
/// `OSIS_ORDER_SHRINK=0`.
fn dump_orders(played: &Played, want_order: &[usize], got_order: &[usize], want: &Judged, got: &Judged) {
    if std::env::var("OSIS_ORDER_DUMP").is_err() {
        return;
    }
    let mut out = String::new();
    let p = deliver(played, want_order);
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
    for (name, order) in [("want", want_order), ("got", got_order)] {
        let _ = writeln!(out, "--- {name} order {order:?}: reads as they change");
        let mut last: BTreeMap<String, String> = BTreeMap::new();
        let mut n = 0;
        deliver_with(played, order, None, None, &mut |p| {
            let step = order.get(n).map_or("end".to_string(), |i| format!("#{i}"));
            n += 1;
            for (t, a) in p.engine.all_aspects().unwrap() {
                let k = format!("{t:?} {}", a.as_str());
                let v = format!("{:?}", p.engine.get(&t, &a).unwrap());
                if last.get(&k) != Some(&v) {
                    let _ = writeln!(out, "  after {step}: {k} = {v}");
                    last.insert(k, v);
                }
            }
            let pending = p.engine.pending().len();
            if pending > 0 {
                let _ = writeln!(out, "  after {step}: {pending} pending");
            }
        });
    }
    for (name, j) in [("want", want), ("got", got)] {
        let _ = writeln!(out, "--- {name} expired_pending {:?}\n--- {name} facts\n{}", j.expired_pending, j.facts);
        for (part, text) in &j.parts {
            let _ = writeln!(out, "--- {name} {part}\n{text}");
        }
    }
    eprintln!("{out}");
}

/// Whether delivering `order` (split as `deliver_split` with `rng`) judged a body of `(tid, ak)`
/// (as `facts_text` prints them) both valid and invalid on the way: a validity flip in that
/// order. A delivery with facts at every step: asked only about a difference found.
fn flipped(played: &Played, order: &[usize], way: Way, tid: &str, ak: &str) -> bool {
    let (rng, clock) = way.parts();
    let mut seen: BTreeMap<BodyKey, BTreeSet<bool>> = BTreeMap::new();
    let mut rng = rng;
    deliver_with(played, order, rng.as_mut(), clock, &mut |p| {
        for (k, f) in facts_of(&facts_text(&mut p.engine)).0 {
            if k.1 == tid && k.2 == ak {
                seen.entry(k).or_default().insert(f.valid);
            }
        }
    });
    seen.values().any(|v| v.len() > 1)
}

/// The first difference between one node's two judgements, facts included.
fn first_diff(a: &Judged, b: &Judged) -> Option<String> {
    first_diff_parts(&a.parts, &b.parts).or_else(|| first_diff_parts(&[("facts", a.facts.clone())], &[("facts", b.facts.clone())]))
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
    /// How many of each held set's orders are tried again at an earlier clock (`Clock`): as made
    /// and reversed, then a sample spread evenly over the rest.
    clock: usize,
    /// A seed's orders are independent tasks (each late-parts order split by its own rng), run
    /// on `threads` threads; else they run in turn, split by one rng.
    par_orders: bool,
    /// Set by `run`: the threads a seed's orders share (cores over the seeds run at once).
    threads: usize,
    /// Set by `run`: fresh nodes sync things, by seed (`with_syncs`). Pinned histories do not.
    sync: bool,
    /// `settled` histories: the whole held set only, and `alike` with no exception.
    settled: bool,
    /// Every node judged is also compared with held-model (`held::compare`).
    model: bool,
}

const SMALL: Cfg = Cfg { all_up_to: 4, every_held: false, random: 2, subsets: 1, split: 2, clock: 2, par_orders: false, threads: 1, sync: false, settled: false, model: false };
const LARGE: Cfg = Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, clock: 2, par_orders: false, threads: 1, sync: false, settled: false, model: false };
/// Every order of the whole set and 2 partial sets (`OSIS_ORDER_ALL_HELD`: of every held set),
/// every order with late parts too (6 commits: up to 720 orders), 24 of them at an earlier clock
/// (every order clocked cost +50%; `OSIS_ORDER_CLOCK=720` gives that back).
const EXHAUST: Cfg = Cfg { all_up_to: 6, every_held: true, random: 0, subsets: 2, split: usize::MAX, clock: 24, par_orders: true, threads: 1, sync: false, settled: false, model: false };
/// The same up to 5 commits (120 orders), for tier 1.
const EXHAUST_SMALL: Cfg = Cfg { all_up_to: 5, subsets: 1, ..EXHAUST };

/// The arrival orders of `held` tried: as made (the reference), reversed, every order of the
/// held commits after the setup when there are at most `all_up_to` (and the whole set is held,
/// unless `every_held`), and `random` shuffles of everything.
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
    /// Its steps' outcomes.
    tally: Tally,
    /// The reference node's pending commits, by reason, over the held sets.
    pending: BTreeMap<String, u64>,
    /// The reference node's commits with an invalid part, over the held sets.
    invalid: u64,
    /// Commits with a part on each aspect, the whole set held.
    aspects: BTreeMap<String, u64>,
    /// The reference node's parts breaking a required retention, and its `required.0^` parts
    /// fallen invalid, over the held sets.
    broken: u64,
    fallen: u64,
    /// Permanent deltas the reference node shows purged, over the held sets.
    tombstones: u64,
    /// Deltas the reference node shows purged by a request by author, over the held sets.
    by_author: u64,
    /// Bodies of a purge that fell after a node applied it, given again and judged alike.
    restored: u64,
    /// What the per-node checks judged: bodies under keep at most 0 after replaced (a), live writes
    /// of the keep-everything node (b), deltas past their expiry or purged (c).
    judged: [u64; 3],
    /// Deliveries at an earlier clock (`Clock`), and those whose move changed a state or a body.
    clocked: u64,
    moved: u64,
    /// What the held-model comparison covered (`Cfg::model`).
    model: crate::held::Coverage,
}

impl Seen {
    fn add(&mut self, o: &Seen) {
        self.orders += o.orders;
        self.tally.add(&o.tally);
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
        self.model.add(&o.model);
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
    /// reach every shape too (over 500 such seeds, no window lacked one; 8-step histories rarely
    /// reach any).
    fn floors(&self, name: &str, seeds: usize, broad: bool) {
        let (n, m) = self.tally.totals();
        // `settled` tries every compaction, most refused
        assert!(n < 20 || m * 2 >= n || name.contains("settled"), "order::{name}: {m} of {n} commit steps made a commit:\n{}", self.tally.show());
        // what the required retention harness is for
        assert!(!name.contains("required") || (self.broken > 0 && self.fallen > 0), "order::{name}: no delta broke a required retention, or none of them fell: {self:?}");
        if seeds < 20 {
            return;
        }
        assert!(!self.tally.kinds.contains_key("PurgeAuthor") || self.by_author > 0, "order::{name}: no delta purged by author: {self:?}");
        // a history with no role change or hostile commit (`seq_compact_history`) has none to reach
        assert!(!self.tally.kinds.contains_key("Purge") || self.tombstones > 0, "order::{name}: no permanent delta purged: {self:?}");
        // a purge whose right fell after a node applied it (spec/permissions.md §7)
        assert!(!self.tally.kinds.contains_key("Purge") || self.restored > 0 || name.contains("settled"), "order::{name}: no fallen purge restored: {self:?}");
        let can_fall = ["Forged", "Demote", "Edge"].iter().any(|k| self.tally.kinds.contains_key(*k));
        assert!(!can_fall || self.invalid > 0, "order::{name}: no invalid part: {self:?}");
        // an earlier clock that never changes anything at its move tests nothing (where histories
        // pass expiries and keep bounds: purge and required ones need not)
        let timed = name.contains("alike") || name.contains("exhaustive");
        assert!(!timed || self.clocked == 0 || self.moved > 0, "order::{name}: no move of an earlier clock changed a state or a body: {self:?}");
        // the per-node checks judged something
        // `focused_history` draws no expiry or purge, so check (c) may meet nothing there
        assert!(!timed || (self.judged[0] > 0 && self.judged[1] > 0 && (self.judged[2] > 0 || name.contains("exhaustive"))), "order::{name}: a per-node check judged nothing: {self:?}");
        // a history setting required retentions reaches a delta breaking one
        assert!(!self.tally.kinds.contains_key("Require") || self.broken > 0, "order::{name}: no delta broke a required retention: {self:?}");
        if broad {
            for a in ["t:text.0", "t:docs.0", "t:list.0", "t:count.0", "t:map.0"] {
                assert!(self.aspects.contains_key(a), "order::{name}: no write on {a}: {self:?}");
            }
            assert!(self.pending.contains_key("MissingChain"), "order::{name}: no commit without its chain: {self:?}");
        }
    }
}

/// Checks one history: what it reached, or the first mismatch found, described (a panic counts,
/// so it shrinks).
fn check(seed: u64, steps: &[Step], cfg: Cfg) -> Result<Seen, String> {
    caught(|| check_orders(seed, steps, cfg))
}

fn check_orders(seed: u64, steps: &[Step], cfg: Cfg) -> Result<Seen, String> {
    let played = play(seed, steps);
    let played = if cfg.sync { with_syncs(played, seed, cfg.settled) } else { played };
    let model = cfg.model.then(|| std::sync::Arc::new((crate::held::History::new(&played.packs), Default::default())));
    let played = Played { model, ..played };
    let mut rng = Rng(seed ^ 0x0de5_ab1e | 1);
    let mut seen = Seen { tally: played.tally.clone(), ..Seen::default() };
    let mut full: Option<Judged> = None;
    let n = played.packs.len();
    let split = played.packs.iter().any(|pk| osis_commit::CommitBlob::decode(&pk.bytes).is_ok_and(|b| b.parts.iter().any(|x| x.ai != b.parts[0].ai)));
    // `OSIS_ORDER_ALL_HELD`: every held set in exhaustive mode (about 2.3x the time)
    let subsets = if cfg.every_held && std::env::var("OSIS_ORDER_ALL_HELD").is_ok() { usize::MAX } else { cfg.subsets };
    let synced = Played { settled: cfg.settled, ..played };
    for held in held_sets(&synced, subsets, &mut rng).into_iter().take(if cfg.settled { 1 } else { usize::MAX }) {
        let played = &synced;
        let of = format!("held {held:?} of {n} commits (base {})", played.base);
        let o = oracle(played, &held);
        // a partial set, then the rest (both ways), ends where the whole set does
        if let Some(f) = full.as_ref() {
            let rest: Vec<usize> = (0..n).filter(|i| !held.contains(i)).collect();
            for order in [held.iter().chain(&rest).copied().collect::<Vec<_>>(), held.iter().chain(rest.iter().rev()).copied().collect()] {
                let mut p = deliver(played, &order);
                let flips = |t: &str, a: &str| flipped(played, &(0..n).collect::<Vec<_>>(), Way::Plain, t, a) || flipped(played, &order, Way::Plain, t, a);
                let whole: Vec<usize> = (0..n).collect();
                if let Some(d) = alike_exchanged(played, f, &whole, &judged(&mut p, played), &order, Way::Plain, &flips) {
                    return Err(format!("{of}, then the rest: order {order:?} vs the whole set as made: {d}"));
                }
            }
        }
        let orders = orders(played, &held, cfg, &mut rng);
        seen.orders += orders.len();
        // the reference, as made: the per-node checks hold, a reopen from the persisted index and a
        // rebuild judge alike and give one index (an open re-examines what pends)
        let mut p = deliver(played, &orders[0]);
        if let Some(d) = bound_kept_now(&mut p, &o, played).or_else(|| value_past_end(&mut p, played, played.now)).or_else(|| model_differs(&mut p, played, &o)) {
            return Err(format!("{of}, as made: {d}"));
        }
        let now = judged_now(&mut p, &played.things);
        for t in &played.things {
            for c in p.engine.purged_on(t, &ak("t:reg.0")).unwrap().into_keys() {
                seen.tombstones += u64::from(p.engine.header(&c).is_some_and(|h| h.aspects.iter().any(|a| a.tid == *t && a.ak.as_str() == "t:reg.0" && h.permanent(a))));
            }
            let (rows, _) = p.engine.history(t, &ak("t:reg.0"), osis_node::engine::history::HistoryFrom::Oldest, usize::MAX - 1, usize::MAX).unwrap();
            for r in &rows {
                if let osis_node::engine::history::RowBody::Purged(by) = &r.body {
                    seen.by_author += u64::from(p.engine.header(by).is_some_and(|h| h.purge.iter().any(|i| matches!(i, osis_commit::PurgeItem::Author { .. }))));
                }
            }
        }
        for l in now.part("pending").lines() {
            let why = l.split(' ').nth(1).unwrap_or(l).split('(').next().unwrap_or("");
            *seen.pending.entry(why.to_string()).or_default() += 1;
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
        let opened = p.engine.index_digest().without_held();
        p.engine.rebuild_index().unwrap();
        p.engine.reexamine().unwrap();
        if let Some(d) = opened.first_diff(&p.engine.index_digest().without_held()) {
            return Err(format!("{of}, as made: the index reopened and rebuilt differ: {d}"));
        }
        if let Some(d) = alike(&now, &judged_now(&mut p, &played.things)) {
            return Err(format!("{of}, as made: rebuild differs: {d}"));
        }
        let mut want = now;
        later(&mut want, &mut p, played);
        let idx = p.engine.index_digest();
        let invalid = idx.commits.values().filter(|c| c.valid.contains(&false)).count();
        seen.invalid += invalid as u64;
        seen.broken += p.engine.broken_parts() as u64;
        seen.fallen += p.engine.fallen_required() as u64;
        if std::env::var("OSIS_ORDER_STATS").is_ok() {
            let carried: usize = idx.carried.values().map(Vec::len).sum();
            eprintln!("seed {seed}: {} of {} commits held ({} base), {} with an invalid part, {} carried groups, {} pending, {} things", held.len(), n, played.base, invalid, carried, want.part("pending").lines().count(), played.things.len());
        }
        if let Some(d) = later_checks(&mut p, played, &o, &|t, a| flipped(played, &orders[0], Way::Plain, t, a)) {
            return Err(format!("{of}, as made, later: {d}"));
        }
        if full.is_none() {
            full = Some(want.clone());
        }
        // order `k` alike (and alike after a reopen), or with late parts (split by `rng`) alike
        let one = |k: usize, split_rng: Option<&mut Rng>| -> Result<(), String> {
            let order = &orders[k];
            let vs = format!("{of}: order #0 (as made, want) {held:?} vs order #{k}");
            if let Some(rng) = split_rng {
                let copy = rng.clone();
                let mut p = deliver_split(played, order, rng);
                let flips = |t: &str, a: &str| flipped(played, &orders[0], Way::Plain, t, a) || flipped(played, order, Way::Split(copy.clone()), t, a);
                let d = judged_checked(&mut p, played, &o, &flips).map(|got| alike_exchanged(played, &want, &orders[0], &got, order, Way::Split(copy.clone()), &flips));
                return match d {
                    Err(d) | Ok(Some(d)) => Err(format!("{vs} with late parts (got) {order:?}: {d}")),
                    Ok(None) => Ok(()),
                };
            }
            let mut p = deliver(played, order);
            if let Some(d) = bound_kept_now(&mut p, &o, played).or_else(|| value_past_end(&mut p, played, played.now)).or_else(|| model_differs(&mut p, played, &o)) {
                return Err(format!("{of}, order #{k} {order:?}: {d}"));
            }
            let mut got = judged_now(&mut p, &played.things);
            p.engine.reload().unwrap();
            p.engine.reexamine().unwrap();
            if let Some(d) = first_diff(&got, &judged_now(&mut p, &played.things)) {
                return Err(format!("{of}, order #{k} {order:?}: reopen differs: {d}"));
            }
            later(&mut got, &mut p, played);
            if let Some(d) = later_checks(&mut p, played, &o, &|t, a| flipped(played, order, Way::Plain, t, a)) {
                return Err(format!("{of}, order #{k} {order:?}, later: {d}"));
            }
            match alike_exchanged(played, &want, &orders[0], &got, order, Way::Plain, &|t, a| flipped(played, &orders[0], Way::Plain, t, a) || flipped(played, order, Way::Plain, t, a)) {
                Some(d) => {
                    dump_orders(played, &orders[0], order, &want, &got);
                    Err(format!("{vs} (got) {order:?}: {d}"))
                }
                None => Ok(()),
            }
        };
        // order `k` with its first commits delivered at an earlier clock (`clock_of`, drawn from
        // its own rng: the main stream, and so pinned replays, unchanged) alike
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
                }
            });
            if let Some(d) = early {
                return Err(format!("{of}: order #{k} at an earlier clock {c:?} {order:?}, {d}"));
            }
            let flips = |t: &str, a: &str| flipped(played, &orders[0], Way::Plain, t, a) || flipped(played, order, Way::Clocked(c), t, a);
            let d = judged_checked(&mut p, played, &o, &flips).map(|got| alike_exchanged(played, &want, &orders[0], &Judged { early: true, ..got }, order, Way::Clocked(c), &flips));
            match d {
                Err(d) | Ok(Some(d)) => Err(format!("{of}: order #0 (as made, want) {held:?} vs order #{k} at an earlier clock {c:?} (got) {order:?}: {d}")),
                Ok(None) => Ok(()),
            }
        };
        // late parts only matter when a commit has parts on several aspects; without one the
        // sequential modes still deliver the first two again and re-examine (as before)
        let splits = if split || !cfg.par_orders { cfg.split.min(orders.len()) } else { 0 };
        seen.orders += clocks;
        seen.clocked += clocks as u64;
        if cfg.par_orders {
            // tasks: orders 1.. as they are, then 0.. with late parts, each split by its own rng,
            // then 0.. at an earlier clock
            let tasks: Vec<u64> = (1..orders.len() + splits + clocks).map(|x| x as u64).collect();
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
            for k in 1..orders.len() {
                one(k, None)?;
            }
            for k in 0..splits {
                one(k, Some(&mut rng))?;
            }
            for k in 0..clocks {
                clocked(k)?;
            }
        }
    }
    if let Some(m) = &synced.model {
        seen.model = m.1.lock().unwrap().clone();
    }
    seen.restored = synced.restored.load(std::sync::atomic::Ordering::Relaxed);
    seen.moved = synced.moved.load(std::sync::atomic::Ordering::Relaxed);
    seen.judged = std::array::from_fn(|i| synced.judged[i].load(std::sync::atomic::Ordering::Relaxed));
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
    let mut steps: Vec<Step> = (0..len).map(|_| random_step(&mut rng)).collect();
    // every other history also sets required retentions and breaks them (the stream above
    // unchanged, so a pinned odd seed replays)
    if seed.is_multiple_of(2) {
        let mut r = Rng(seed.wrapping_mul(0xd6e8_feb8_6659_fd93) | 1);
        for _ in 0..len / 6 {
            steps.insert(r.below(steps.len() as u64 + 1) as usize, required_step(&mut r));
        }
    }
    steps
}

/// A short history aimed at deaths and validity together: writes of two bounded aspects
/// (keep-at-most ones by the owner, keep-at-least ones mostly by the others), their compactions, undo, demotions
/// and grants, nested writes under others' entries, one clock pulled ahead (a write made later
/// by a peer behind sorts earlier), sends and syncs. Cut to the longest prefix making at most
/// `cfg.all_up_to` commits after the setup (a prefix of a history plays as its start).
/// A step of a thing's required retention: an admin's change or a write that may break it.
fn required_step(r: &mut Rng) -> Step {
    let (by, t, op) = (r.below(3) as usize, r.below(3) as usize, r.below(DRAWN as u64) as u8);
    Step::Aim(Box::new(if r.below(3) == 0 {
        Step::Require { by: r.pick(&[0, 0, 2]), t, op, rule: r.below(4) as u8 }
    } else {
        Step::Breaking { by, t, op, v: r.below(10) as u8, fits: r.below(4) == 0 }
    }))
}

/// Short histories around required retention: changes, breaking and fitting writes, demotions of
/// the admin who made a change, compactions, all on one thing, so every order meets them.
fn required_history(seed: u64, len: usize, cfg: Cfg) -> Vec<Step> {
    let mut rng = Rng(seed.wrapping_mul(0xa24b_aed4_963e_e407) | 1);
    let op = rng.below(DRAWN as u64) as u8;
    // Carol's rule, a write breaking it, and Alice demoting her with or without having received
    // the rule, so it may fall
    let mut steps = vec![
        Step::Require { by: 2, t: 0, op, rule: 2 + rng.below(2) as u8 },
        Step::Breaking { by: 1, t: 0, op, v: 1, fits: false },
    ];
    if rng.below(2) == 0 {
        steps.push(Step::Sync { from: 2, to: 0 });
    }
    steps.push(Step::Aim(Box::new(Step::Demote { by: 0, t: 0, holder: 2, at: rng.below(2) as u8, to_read: false })));
    while steps.len() < len {
        let by = rng.below(3) as usize;
        steps.push(match rng.below(11) {
            10 => Step::Require { by: 1, t: 0, op, rule: 4 + rng.below(4) as u8 },
            0..=3 => Step::Aim(Box::new(Step::Breaking { by, t: 0, op, v: rng.below(10) as u8, fits: rng.below(3) == 0 })),
            4 | 5 => Step::Aim(Box::new(Step::Require { by: rng.pick(&[0, 2]), t: 0, op, rule: rng.below(4) as u8 })),
            6 => Step::Aim(Box::new(Step::Demote { by: 0, t: 0, holder: 2, at: rng.below(4) as u8, to_read: false })),
            7 => Step::Aim(Box::new(Step::Compact { by: rng.pick(&[0, by]), t: 0, op })),
            8 => Step::Advance { who: Some(by), ms: 1 + rng.below(2_000) },
            _ => Step::Sync { from: by, to: (by + 1 + rng.below(2) as usize) % 3 },
        });
    }
    // the bound on commits an exhaustive run takes
    let mut k = steps.len();
    while k > 0 && !caught(|| {
        let p = play(seed, &steps[..k]);
        Ok::<_, String>(p.packs.len() - p.base <= cfg.all_up_to)
    })
    .unwrap_or(true)
    {
        k -= 1;
    }
    steps.truncate(k);
    steps
}

fn focused_history(seed: u64, len: usize, cfg: Cfg) -> Vec<Step> {
    let mut rng = Rng(seed.wrapping_mul(0xa076_1d64_78bd_642f) | 1);
    // two bounded aspects per history, so writes, compactions and undos meet
    const BOUNDED: [u8; 12] = [16, 17, 18, 19, 20, 21, 22, 23, 24, 26, 30, 31];
    let ops = [rng.pick(&BOUNDED), rng.pick(&BOUNDED)];
    let steps: Vec<Step> = (0..len)
        .map(|_| {
            let by = rng.below(3) as usize;
            let t = rng.below(2) as usize;
            let op = rng.pick(&ops);
            match rng.below(22) {
                // a hostile commit among the rest: its parts wait, or judge invalid, in every order
                20 | 21 => Step::Forged { by, a: t, b: rng.below(2) as usize, how: rng.below(5) as u8, op, k: rng.below(2) as u8, v: rng.below(10) as u8 },
                0..=6 => Step::Aim(Box::new(Step::Typed { by: if (17..=20).contains(&op) || op == 31 || rng.below(3) == 0 { 0 } else { 1 + rng.below(2) as usize }, t, op, k: rng.below(2) as u8, v: rng.below(10) as u8 })),
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
/// depend on the seed, the length and the test alone. `OSIS_ORDER_SHRINK=0` reports a failure unshrunk.
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
    // `OSIS_ORDER_CLOCK=n`: n orders per held set at an earlier clock (0: none)
    let clock = u64_var("OSIS_ORDER_CLOCK").map_or(cfg.clock, |n| n as usize);
    let cfg = Cfg { threads: if cfg.par_orders { threads("OSIS_ORDER_THREADS").div_ceil(outer) } else { 1 }, sync: true, clock, ..cfg };
    let results = par_map(&seeds, outer, |seed| {
        let steps = generate(seed, len, cfg);
        if std::env::var("OSIS_ORDER_STATS").is_ok() {
            eprintln!("seed {seed}: vec!{steps:?}");
        }
        let r = check(seed, &steps, cfg);
        let fail = r.as_ref().is_err().then(|| {
            // `OSIS_ORDER_SHRINK=0`: the failure as found, unshrunk
            let (steps, err) = if u64_var("OSIS_ORDER_SHRINK") == Some(0) { (steps, r.clone().unwrap_err()) } else { shrink(seed, steps, cfg) };
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
    if cfg.model {
        osis_base::testenv::visible(true, &format!("order::{name}: held-model compared {} aspects over {} nodes, reaching {:?}; skipped {:?}", seen.model.compared, seen.model.nodes, seen.model.reached, seen.model.skipped));
    }
    if std::env::var("OSIS_ORDER_STATS").is_ok() {
        eprintln!("{}\npending {:?}, invalid {}, aspects {:?}, per-node checks judged {:?}, {} of {} early clocks changed a state or a body at the move", seen.tally.show(), seen.pending, seen.invalid, seen.aspects, seen.judged, seen.moved, seen.clocked);
    }
    assert!(fails.is_empty(), "{summary}\n{} of {} histories judged differently by arrival order:\n{}", fails.len(), seeds.len(), fails.join("\n\n"));
    seen.floors(name, seeds.len(), !cfg.par_orders && !cfg.settled && len >= 60);
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
    assert!(death((0..b + 2).collect()).is_some(), "the delete held last dates it");
    assert!(death((0..b).chain([b + 1, b]).collect()).is_some(), "the delete held first dates it");
}

// spec/crdt.md §5.6 (the records of one dot are one entry for superseding), spec/commits.md §5:
// order seed 338806. An expiring put of k0, a kept write of k1, a snapshot (k0's records
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

// spec/commits.md §5, spec/permissions.md §5.2: required retention judged by the setting in force
// at the delta's key, every arrival order and held subset alike. Seeds 2..4: 3 breaks a required
// retention, 2 lets one fall; more in `_large`.
#[test]
fn arrival_order_required_spec_commits_5() {
    run("arrival_order_required_spec_commits_5", 2..4, 12, EXHAUST_SMALL, required_history);
}

// The same over more histories.
#[test]
#[ignore = "tier 2"]
fn arrival_order_required_large_spec_commits_5() {
    run("arrival_order_required_large_spec_commits_5", osis_base::testenv::large(0..40), 12, EXHAUST_SMALL, required_history);
}

/// Every arrival order, a node dropping what `drop_broken` lets it after each commit (its clock
/// moving, so a body may arrive before or after the setting it breaks) and then receiving every
/// body again: reads as a node with that order that dropped nothing (spec/permissions.md §7: only
/// the body held differs, and only until a holder uploads it). The reads are compared twice: after
/// the bodies come again and after dropping again.
fn drops_alike(seed: u64, steps: &[Step], cfg: Cfg) -> Result<Seen, String> {
    caught(|| {
        let played = play(seed, steps);
        let mut seen = Seen { tally: played.tally.clone(), ..Seen::default() };
        let mut rng = Rng(seed ^ 0x0de5_ab1e | 1);
        let n = played.packs.len();
        let held: Vec<usize> = (0..n).collect();
        let tick = |p: &mut Peer| {
            let now = p.engine.now();
            p.clock.set(WallMs(now.0 + 1));
        };
        let view = |j: Judged| -> String { j.parts.iter().filter(|(k, _)| matches!(*k, "reads" | "states" | "rosters" | "pending" | "timelines")).map(|(k, v)| format!("== {k}\n{v}\n")).collect() };
        let orders = orders(&played, &held, cfg, &mut rng);
        seen.orders += orders.len();
        for order in &orders {
            // the same order with no drops: what arrival order alone does is `arrival_order_*`'s
            let mut r = deliver_with(&played, order, None, None, &mut |p| tick(p));
            for pk in &played.packs {
                let _ = r.engine.ingest(&pk.bytes, pk.blobs.clone());
                tick(&mut r);
            }
            seen.broken += r.engine.broken_parts() as u64;
            seen.fallen += r.engine.fallen_required() as u64;
            let want = view(judged_now(&mut r, &played.things));
            let mut p = deliver_with(&played, order, None, None, &mut |p| {
                tick(p);
                p.engine.drop_broken(None).unwrap();
                p.engine.reload().unwrap();
            });
            for pk in &played.packs {
                let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
                tick(&mut p);
            }
            let cmp = |a: &str, b: &str, what: &str| -> Result<(), String> {
                match a.lines().zip(b.lines()).find(|(x, y)| x != y) {
                    Some((x, y)) => Err(format!("order {order:?}, {what}:\n  want {x}\n  got  {y}")),
                    None if a.lines().count() != b.lines().count() => Err(format!("order {order:?}, {what}: {} lines vs {}", a.lines().count(), b.lines().count())),
                    None => Ok(()),
                }
            };
            cmp(&want, &view(judged_now(&mut p, &played.things)), "bodies again")?;
            p.engine.drop_broken(None).unwrap();
            cmp(&want, &view(judged_now(&mut p, &played.things)), "dropped again")?;
            // what is dropped reopens and rebuilds as made
            let now = p.engine.index_digest();
            p.engine.reload().unwrap();
            if let Some(f) = now.diff(&p.engine.index_digest()).first() {
                return Err(format!("order {order:?}: reopen differs at {f:?}"));
            }
            p.engine.rebuild_index().unwrap();
            if let Some(f) = now.diff(&p.engine.index_digest()).into_iter().find(|f| matches!(f, IndexField::Table(t) if *t == "required")) {
                return Err(format!("order {order:?}: rebuild differs at {f:?}: {:?} vs {:?}", now.show(&f), p.engine.index_digest().show(&f)));
            }
        }
        Ok(seen)
    })
}

fn run_drops(name: &str, seeds: std::ops::Range<u64>, len: usize, cfg: Cfg, generate: fn(u64, usize, Cfg) -> Vec<Step>) {
    let range = osis_base::testenv::Seeds::from_env("OSIS_ORDER_START", "OSIS_ORDER_SEEDS", seeds);
    let seeds: Vec<u64> = match osis_base::testenv::u64_var("OSIS_ORDER_SEED") {
        Some(o) => vec![o],
        None => range.range.clone().collect(),
    };
    let results = par_map(&seeds, threads("OSIS_ORDER_THREADS").min(seeds.len()).max(1), |seed| {
        let steps = generate(seed, len, cfg);
        (seed, steps.clone(), drops_alike(seed, &steps, cfg))
    });
    let mut seen = Seen::default();
    let mut fails = Vec::new();
    for (seed, steps, r) in results {
        match r {
            Ok(s) => seen.add(&s),
            Err(e) => fails.push(format!("seed {seed}: h = vec!{steps:?}\n{e}")),
        }
    }
    osis_base::testenv::visible(true, &format!("order::{name}: {} seeds from {}, {} orders, {} broken, {} fallen, {} failing", seeds.len(), seeds.first().copied().unwrap_or(0), seen.orders, seen.broken, seen.fallen, fails.len()));
    assert!(fails.is_empty(), "{}", fails.join("\n\n"));
    assert!(seeds.len() < 20 || seen.broken > 0, "no delta broke a required retention");
}

// spec/permissions.md §7: what a node may drop without a right changes nothing it reads once the
// body is held again, whichever arrived first. Seeds 2..4 (3 breaks a required retention); more
// in `_large`.
#[test]
fn required_drops_read_alike_spec_perm_7() {
    run_drops("required_drops_read_alike_spec_perm_7", 2..4, 12, EXHAUST_SMALL, required_history);
}

// The same over the general histories.
#[test]
#[ignore = "tier 2"]
fn required_drops_read_alike_large_spec_perm_7() {
    run_drops("required_drops_read_alike_large_spec_perm_7", osis_base::testenv::large(0..200), 12, EXHAUST_SMALL, required_history);
    run_drops("required_drops_read_alike_large_spec_perm_7 (general)", 0..200, 30, LARGE, history);
}

// The same at size: long histories, random orders.
#[test]
#[ignore = "tier 2"]
fn arrival_order_alike_large_spec_permissions_5_2() {
    run("arrival_order_alike_large_spec_permissions_5_2", osis_base::testenv::large(1000..1060), 60, LARGE, history);
}

/// `history` with permanent messages and purges by anyone mixed in, on their own draws (`history`'s
/// seeds replay as they were). A purge whose right falls after it applied counts as never received
/// (spec/permissions.md §7): `alike_exchanged` gives both nodes its bodies again.
/// `h`, then every peer holds what the others do and each compacts every aspect of every thing it
/// may write: spec/requirements.md Deterministic's keep-at-most and expiry limit lasts "until a writer next
/// compacts", so all orders read alike with no body given again and no flag excused.
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
    for t in 0..12 {
        for op in [0, 1, 3, 6, 8, 10, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 27, 28, 29] {
            h.extend((0..3).map(|by| Compact { by, t, op }));
        }
    }
    sync(&mut h);
    h
}

fn purge_history(seed: u64, len: usize, cfg: Cfg) -> Vec<Step> {
    let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d) | 1);
    let mut out = Vec::new();
    for st in history(seed, len, cfg) {
        out.push(st);
        let (by, t, v) = (rng.below(3) as usize, rng.below(8) as usize, rng.below(10) as u8);
        match rng.below(8) {
            0 | 1 => out.push(Step::Aim(Box::new(Step::Message { by, t, v }))),
            2 => out.push(Step::Aim(Box::new(Step::Purge { by: rng.below(3) as usize, t, of: by, back: rng.below(4) as u8, v }))),
            _ => {}
        }
    }
    out
}

/// Short histories for purges by author, on what a chat does: permanent messages by three writers,
/// demotions, grants, compactions, sync, purges by any of them, so requests fall and rise. Not `history`'s mix: a whole-aspect or by-author request with
/// keep-at-most bodies or commits split over parts still differs (issues/wide-purge-order.md).
fn purge_author_history(seed: u64, len: usize, _: Cfg) -> Vec<Step> {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut out = Vec::new();
    while out.len() < len {
        let (by, t, v) = (rng.below(3) as usize, rng.below(4) as usize, rng.below(10) as u8);
        out.push(match rng.below(12) {
            0..=4 => Step::Aim(Box::new(Step::Message { by, t, v })),
            5 | 6 => Step::Aim(Box::new(Step::PurgeAuthor { by: rng.below(3) as usize, t, of: by })),
            7 => Step::Aim(Box::new(Step::Demote { by: 0, t, holder: by, at: rng.below(4) as u8, to_read: rng.below(2) == 0 })),
            8 => Step::Aim(Box::new(Step::Edge { by: 0, t, holder: by, role: Some(Role::Write) })),
            9 => Step::Advance { who: None, ms: 1 + rng.below(2_000) },
            _ => Step::Sync { from: by, to: (by + 1 + rng.below(2) as usize) % 3 },
        });
    }
    out
}

/// Short histories on one register: requests stand, fall and rise over deltas that also expire, with
/// compactions, so a leftover set aside by a fall meets each. By seed, requests by name or wide. Keep at
/// most or a required retention in this mix still differs: issues/wide-purge-order.md.
fn purge_rows_history(seed: u64, len: usize, _: Cfg) -> Vec<Step> {
    let mut rng = Rng(seed.wrapping_mul(0xc2b2_ae3d_27d4_eb4f) | 1);
    let wide = seed % 2 == 1;
    let mut out = vec![Step::Edge { by: 0, t: 0, holder: 1, role: Some(Role::Admin) }, Step::Edge { by: 0, t: 0, holder: 2, role: Some(Role::Admin) }, Step::Sync { from: 0, to: 1 }, Step::Sync { from: 0, to: 2 }];
    while out.len() < len {
        let (by, v) = (rng.below(3) as usize, rng.below(10) as u8);
        let to = (by + 1 + rng.below(2) as usize) % 3;
        out.push(match rng.below(24) {
            0 | 1 => Step::Aim(Box::new(Step::Typed { by, t: 0, op: 0, k: 0, v })),
            2 | 3 => Step::Aim(Box::new(Step::Typed { by, t: 0, op: 27, k: rng.below(3) as u8, v })),
            4 => Step::Aim(Box::new(Step::Message { by, t: 0, v })),
            8 | 9 => Step::Aim(Box::new(Step::Compact { by, t: 0, op: 0 })),
            10..=12 if wide => Step::Aim(Box::new(Step::Purge { by, t: 0, of: rng.below(3) as usize, back: rng.below(3) as u8, v })),
            10..=12 => Step::Aim(Box::new(Step::PurgeNamed { by, t: 0, of: rng.below(3) as usize, back: rng.below(3) as u8, v })),
            13 | 14 => Step::Aim(Box::new(Step::Demote { by: rng.below(3) as usize, t: 0, holder: rng.below(3) as usize, at: rng.below(4) as u8, to_read: rng.below(3) == 0 })),
            15 => Step::Edge { by: rng.below(3) as usize, t: 0, holder: rng.below(3) as usize, role: rng.pick(&[Some(Role::Admin), Some(Role::Write)]) },
            16 => Step::Advance { who: Some(by), ms: 1 + rng.below(1_500) },
            17 => Step::Advance { who: None, ms: rng.pick(&[1_100, HOUR]) },
            18 => Step::Send { from: by, to, back: rng.below(2) as u8 },
            _ => Step::Sync { from: by, to },
        });
    }
    out
}

// spec/permissions.md §7, spec/crdt.md §4.7: a leftover set aside by a fall, value-less again by expiry or a
// purge, and reopened.
#[test]
#[ignore = "tier 2"]
fn arrival_order_purge_rows_large_spec_perm_7() {
    run("arrival_order_purge_rows_large_spec_perm_7", osis_base::testenv::large(7000..7060), 40, LARGE, purge_rows_history);
}

// spec/commits.md §5 (a snapshot carrying a purged value is held as its leftover), spec/crdt.md
// §4.7: an open rebuilding the index lists the stripped snapshot as the incremental path does
// (was: its slot gone from the blob, the rebuild left it out of the snapshots index).
#[test]
fn stripped_snapshot_indexed_on_rebuild_seed_9210005() {
    use Step::*;
    let h = vec![Aim(Box::new(Demote { by: 0, t: 0, holder: 1, at: 1, to_read: true })), Sync { from: 0, to: 1 }, Aim(Box::new(Compact { by: 1, t: 0, op: 0 })), Aim(Box::new(Purge { by: 2, t: 0, of: 1, back: 0, v: 3 }))];
    check(9210005, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

// spec/permissions.md §7, §5.2: a re-grant gives back the right of a purge request its author made
// while demoted, as it does the request's writes, so the deltas it names stay purged in any arrival
// order (was: the right also asked the role held at the request's time, so the request held none,
// a node as made lost the named body anyway and one given the history reversed kept its value).
#[test]
fn regrant_gives_purge_right_back_seed_3001() {
    use Step::*;
    let h = vec![Aim(Box::new(Nested { by: 1, other: 0, t: 5, k: 1, text: true, compact: false, also: false })), Aim(Box::new(Nested { by: 2, other: 0, t: 0, k: 2, text: true, compact: false, also: false })), Forged { by: 0, a: 4, b: 3, how: 3, op: 29, k: 1, v: 8 }, Aim(Box::new(Nested { by: 1, other: 2, t: 5, k: 0, text: false, compact: true, also: true })), Aim(Box::new(Message { by: 0, t: 2, v: 1 })), Advance { who: Some(1), ms: 671 }, Aim(Box::new(New { by: 0, parent: 3, write: true })), Aim(Box::new(Purge { by: 1, t: 1, of: 1, back: 3, v: 3 })), Aim(Box::new(Demote { by: 0, t: 0, holder: 1, at: 2, to_read: true })), Forged { by: 1, a: 5, b: 1, how: 1, op: 7, k: 1, v: 8 }, Forged { by: 2, a: 5, b: 4, how: 4, op: 19, k: 2, v: 4 }, Aim(Box::new(Nested { by: 0, other: 1, t: 4, k: 0, text: true, compact: false, also: true })), Aim(Box::new(NestedItem { by: 0, other: 2, t: 1, k: 2, compact: false, also: true })), Aim(Box::new(NestedItem { by: 1, other: 0, t: 7, k: 2, compact: true, also: true })), Forged { by: 1, a: 7, b: 0, how: 1, op: 0, k: 1, v: 1 }, Aim(Box::new(Message { by: 2, t: 1, v: 3 })), Aim(Box::new(Nested { by: 2, other: 1, t: 7, k: 0, text: true, compact: true, also: true })), Forged { by: 0, a: 4, b: 3, how: 2, op: 30, k: 1, v: 2 }];
    check(3001, &h, Cfg { random: 0, subsets: 0, clock: 0, split: 0, sync: true, model: true, ..LARGE }).unwrap();
}

// spec/permissions.md §7, spec/wire.md §4: arrival order decides nothing with purges by author,
// whichever deltas and demotions come after them.
#[test]
fn arrival_order_purge_author_small_spec_perm_7() {
    run("arrival_order_purge_author_small_spec_perm_7", 0..3, 24, SMALL, purge_author_history);
}

#[test]
#[ignore = "tier 2"]
fn arrival_order_purge_author_large_spec_perm_7() {
    run("arrival_order_purge_author_large_spec_perm_7", osis_base::testenv::large(4000..4100), 50, LARGE, purge_author_history);
}

// spec/commits.md §5 (purge, lasting headers), spec/permissions.md §7: arrival order decides nothing
// with purges in the history either.
#[test]
fn arrival_order_purge_small_spec_commits_5() {
    run("arrival_order_purge_small_spec_commits_5", 0..4, 8, Cfg { model: true, ..SMALL }, purge_history);
}

// spec/permissions.md §7: a waiting commit's part stripped for a purge that falls before it applies
// comes back from a copy given after it applied.
#[test]
#[ignore = "tier 2"]
fn stripped_while_waiting_purge_falls_seed_890044() {
    run("stripped_while_waiting_purge_falls_seed_890044", 890044..890045, 60, LARGE, purge_history);
}

// spec/commits.md §4: a roster snapshot's `tenures.0` part arriving before its `roles.0` part does
// not show who stays, so it counts no removed author's delta as held yet (seed 3050, no purge
// needed). Tier 1 tries only the orders that fail without it (the whole set, reversed with late
// parts; no shuffles, partial sets or clock); the tier-2 twin all of LARGE.
#[test]
fn partial_roster_snapshot_removes_nobody_seed_3050() {
    let cfg = Cfg { random: 0, subsets: 0, clock: 0, sync: true, ..LARGE };
    check(3050, &purge_history(3050, 60, cfg), cfg).unwrap();
}

#[test]
#[ignore = "tier 2"]
fn partial_roster_snapshot_removes_nobody_seed_3050_large() {
    run("partial_roster_snapshot_removes_nobody_seed_3050_large", osis_base::testenv::large(3050..3051), 60, LARGE, purge_history);
}

#[test]
#[ignore = "tier 2"]
fn arrival_order_purge_large_spec_commits_5() {
    run("arrival_order_purge_large_spec_commits_5", osis_base::testenv::large(3000..3060), 60, Cfg { model: true, ..LARGE }, purge_history);
}

// spec/requirements.md Decentralization, spec/crdt.md §4.8: short histories mixing bounded
// writes, compactions, undo, demotions and late writes, every arrival order (the setup first)
// of the whole set and a partial one, each with late parts too.
#[test]
fn arrival_order_exhaustive_small_spec_crdt_4_8() {
    run("arrival_order_exhaustive_small_spec_crdt_4_8", 0..3, 30, EXHAUST_SMALL, focused_history);
}

#[test]
fn arrival_order_settled_small_spec_commits_5() {
    run("arrival_order_settled_small_spec_commits_5", 0..2, 60, Cfg { settled: true, ..LARGE }, |s, l, c| settled(history(s, l, c)));
}

#[test]
#[ignore = "tier 2"]
fn arrival_order_settled_large_spec_commits_5() {
    run("arrival_order_settled_large_spec_commits_5", osis_base::testenv::large(7000..7060), 60, Cfg { settled: true, ..LARGE }, |s, l, c| settled(history(s, l, c)));
}

#[test]
#[ignore = "tier 2"]
fn arrival_order_settled_purges_large_spec_commits_5() {
    run("arrival_order_settled_purges_large_spec_commits_5", osis_base::testenv::large(7100..7160), 60, Cfg { settled: true, ..LARGE }, |s, l, c| settled(purge_history(s, l, c)));
}

// spec/sync.md §7 (repair): seed 61840041. A writer's last snapshot of a keep-at-most-0 aspect reached
// a node before the lowering of a later writer did, so the node dropped it and every other body of
// the value, then flagged the aspect. It reads alike only once a writer's snapshot comes after that.
#[test]
fn settled_flagged_aspect_alike_after_repair_spec_sync_7() {
    let cfg = Cfg { settled: true, sync: true, ..LARGE };
    let h = settled(history(61840041, 60, cfg));
    check(61840041, &h, cfg).unwrap();
}

// The same over more histories, up to 6 commits.
#[test]
#[ignore = "tier 2"]
fn arrival_order_exhaustive_large_spec_crdt_4_8() {
    run("arrival_order_exhaustive_large_spec_crdt_4_8", osis_base::testenv::large(2023..2063), 30, Cfg { model: true, ..EXHAUST }, focused_history);
}

/// A history of writes under keep at most, some with a part under default retention, on G.
fn carrierless_history(seed: u64, len: usize) -> Vec<Step> {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut steps = vec![Step::Sync { from: 0, to: 1 }];
    for _ in 0..len {
        let (by, op, k, v) = (rng.below(2) as usize, rng.pick(&[17, 18, 19, 19, 20, 30, 31]), rng.below(3) as u8, rng.below(10) as u8);
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

/// spec/commits.md §4 (a node never waits for a part), §5: whether a part under keep at most
/// arrives never, or after its commit applied, or with the rest, in any order, the node ends alike
/// and nothing pends, for every part a holder dropped with no live write (what hosts delete with no
/// carrier). A part with no commit on its aspect stamped as late, live or not, is waited for by
/// nothing: its commit applies without it, and it joins when it comes.
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
            if a.retention.at_most.rel.is_none() && a.retention.at_most.abs.is_none() {
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
        if !p.engine.pending().is_empty() || !p.engine.commit_ids().contains(&id) {
            return Err(format!("{id:?} part {ai} away, nothing on its aspect as late: its commit did not apply: {:?}", p.engine.pending()));
        }
        let pk = played.packs.iter().find(|pk| pk.id == id).unwrap();
        let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
        let _ = p.engine.reexamine();
        let got = dump(&mut p);
        for part in ["reads", "states", "pending"] {
            if got.part(part) != want.part(part) {
                return Err(format!("{id:?} part {ai} late: {part} differ:\n{}\nvs\n{}", want.part(part), got.part(part)));
            }
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

// spec/commits.md §4 (a node never waits for a part), §5: `carrierless_check`.
#[test]
fn carrierless_part_alike_small_spec_commits_4() {
    carrierless_run("carrierless_part_alike_small_spec_commits_4", 0..12, 14);
}

// The same over more histories, longer.
#[test]
#[ignore = "tier 2"]
fn carrierless_part_alike_large_spec_commits_4() {
    carrierless_run("carrierless_part_alike_large_spec_commits_4", osis_base::testenv::large(1000..1200), 30);
}

/// A history for `new_device_alike`: a random one with, in its middle, writer 1's commits
/// synced to the owner and compacted there, and at its end the owner's demotion of writer 1
/// (its frontier as of a random point among 1's writes).
fn device_history(seed: u64, len: usize, cfg: Cfg) -> Vec<Step> {
    let mut steps = history(seed, len, cfg);
    let mut rng = Rng(seed.wrapping_mul(0xd1b5_4a32_d192_ed03) | 1);
    let at = steps.len() / 2;
    let op = rng.below(DRAWN as u64) as u8;
    steps.splice(at..at, [Step::Write { by: 1, t: 0, op, k: rng.below(3) as u8, v: rng.below(10) as u8 }, Step::Sync { from: 1, to: 0 }, Step::Advance { who: None, ms: 1_000 }, Step::Compact { by: 0, t: 0, op }]);
    steps.push(Step::Advance { who: None, ms: 1_000 });
    steps.push(Step::Demote { by: 0, t: 0, holder: 1, at: rng.below(6) as u8, to_read: false });
    steps
}

/// Checks Tess's decision (a)'s new-device equivalence (spec/permissions.md §5.1: a frontier lists
/// commit IDs, leaving out commits covered at the demoter; §5.2: a valid snapshot vouches for
/// what it carries): a node holding every body and a fresh node holding only what hosts keep
/// once covered bodies go (every role commit and snapshot whole; each other commit without its
/// parts the first node finds covered by a held snapshot, or not at all when none is left) read
/// every aspect and roster alike. Both keep every body past its keep-at-most bound, so only
/// coverage tells them apart. The one limit: an aspect a node flags for a part that went at its
/// expiry while it waited may read
/// differently, as in `alike`: that part counts as never received (spec/commits.md §5).
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
    let expired: BTreeSet<(String, String)> = expired_pending(&mut full.engine).union(&expired_pending(&mut fresh.engine)).cloned().collect();
    for (t, a) in full.engine.all_aspects().unwrap() {
        let (want, got) = (full.engine.get(&t, &a).unwrap(), fresh.engine.get(&t, &a).unwrap());
        if want != got && !expired.contains(&(format!("{t:?}"), a.as_str().to_string())) {
            return Err(format!("{t:?} {}: every body {want:?}, after covered drops {got:?}\nevery body:\n{}\nafter covered drops:\n{}", a.as_str(), full.engine.aspect_dump(&t, &a), fresh.engine.aspect_dump(&t, &a)));
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

// spec/permissions.md §5.1 (frontier by commit ID), §5.2 (snapshots vouch), Tess's decision (a)
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
    run_new_device("new_device_alike_large_spec_permissions_5_1", osis_base::testenv::large(0..256), 40);
}

// spec/crdt.md §4.7, §5.7: expiring list elements, others' writes in them, snapshots written before
// and after T carrying their marks, removals by writers who may fall.
fn list_expiry_history(seed: u64, len: usize, _: Cfg) -> Vec<Step> {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    // a write or undo in four by a writer predating the copy expiry rule (spec/crdt.md §4.7), so
    // readers meet carriers of an expiring value that do not expire with it; drawn from a stream
    // of its own, so the steps stay those of the seed
    let mut old = Rng(seed.wrapping_mul(0xd6e8_feb8_6659_fd93) | 1);
    let steps: Vec<Step> = (0..len)
        .map(|_| {
            let by = rng.below(3) as usize;
            let to = (by + 1 + rng.below(2) as usize) % 3;
            match rng.below(16) {
                0..=3 => Step::Aim(Box::new(Step::Typed { by, t: 0, op: 32, k: 0, v: rng.below(10) as u8 })),
                4..=6 => Step::Aim(Box::new(Step::Typed { by, t: 0, op: 33, k: 0, v: rng.below(10) as u8 })),
                7 => Step::Aim(Box::new(Step::Typed { by, t: 0, op: 34, k: 0, v: rng.below(10) as u8 })),
                8 | 9 => Step::Compact { by, t: 0, op: 32 },
                10 => Step::Aim(Box::new(Step::Undo { by, back: rng.below(3) as u8 })),
                11 => Step::Aim(Box::new(Step::Demote { by, t: 0, holder: to, at: rng.below(6) as u8, to_read: rng.below(2) == 0 })),
                12 => Step::Advance { who: Some(by), ms: 400 + rng.below(800) },
                13 => Step::Send { from: by, to, back: rng.below(2) as u8 },
                _ => Step::Sync { from: by, to },
            }
        })
        .collect();
    steps.into_iter().map(|x| if matches!(&x, Step::Aim(a) if matches!(**a, Step::Typed { .. } | Step::Undo { .. })) && old.below(4) == 0 { Step::Old(Box::new(x)) } else { x }).collect()
}

#[test]
#[ignore = "tier 2"]
fn arrival_order_list_expiry_large_spec_crdt_4_7() {
    run("arrival_order_list_expiry_large_spec_crdt_4_7", 3000..3040, 40, LARGE, list_expiry_history);
}

// spec/crdt.md §4.6 (records a valid snapshot holds), spec/permissions.md §5.2: 1's snapshot,
// taken after 2's expiring insert turned invalid, holds the element as a hidden anchor with its
// creation's copy, which vouches for the record: the delta's chars stay in it as hidden anchors.
// Was: the join took a vouch only where `remove_dots` would change the piece, so with the
// snapshot after the delta nothing rebuilt and the state lacked them (the debug rebuild check).
#[test]
fn snapshot_anchor_vouches_invalid_insert_seed_9220021() {
    use Step::*;
    let h = vec![Aim(Box::new(Typed { by: 2, t: 0, op: 32, k: 0, v: 8 })), Aim(Box::new(Demote { by: 0, t: 0, holder: 2, at: 0, to_read: true })), Sync { from: 2, to: 1 }, Send { from: 0, to: 1, back: 0 }, Compact { by: 1, t: 0, op: 32 }];
    check(9220021, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

// The same, read: without the vouch the list read absent in one arrival order and empty in
// another (also seeds 9200037, 7520035).
#[test]
fn snapshot_anchor_vouch_reads_alike_seed_9200020() {
    use Step::*;
    let h = vec![Aim(Box::new(Typed { by: 1, t: 0, op: 32, k: 0, v: 3 })), Aim(Box::new(Demote { by: 0, t: 0, holder: 1, at: 1, to_read: false })), Sync { from: 1, to: 0 }, Compact { by: 0, t: 0, op: 32 }];
    check(9200020, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

// spec/crdt.md §4.7: an undo undeleting an expiring element's chars carries them under the
// creator's dots; once both expired no held body holds them (was: the undo's leftover kept them).
#[test]
fn undelete_copy_expires_seed_9220029_spec_crdt_4_7() {
    use Step::*;
    let h = vec![Aim(Box::new(Typed { by: 2, t: 0, op: 32, k: 0, v: 8 })), Aim(Box::new(Typed { by: 2, t: 0, op: 33, k: 0, v: 9 })), Aim(Box::new(Undo { by: 2, back: 2 }))];
    check(9220029, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

// The same with the undo undeleting chars of an earlier text set (also seed 9250009 below).
#[test]
fn undelete_copy_expires_seed_7520036_spec_crdt_4_7() {
    use Step::*;
    let h = vec![Aim(Box::new(Typed { by: 2, t: 0, op: 32, k: 0, v: 3 })), Aim(Box::new(Typed { by: 2, t: 0, op: 33, k: 0, v: 0 })), Aim(Box::new(Typed { by: 2, t: 0, op: 33, k: 0, v: 3 })), Aim(Box::new(Undo { by: 2, back: 1 }))];
    check(7520036, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

#[test]
fn undelete_copy_expires_seed_9250009_spec_crdt_4_7() {
    use Step::*;
    let h = vec![
        Aim(Box::new(Demote { by: 2, t: 0, holder: 1, at: 2, to_read: false })),
        Sync { from: 2, to: 1 },
        Aim(Box::new(Typed { by: 1, t: 0, op: 32, k: 0, v: 5 })),
        Aim(Box::new(Typed { by: 1, t: 0, op: 32, k: 0, v: 4 })),
        Aim(Box::new(Typed { by: 2, t: 0, op: 33, k: 0, v: 9 })),
        Aim(Box::new(Typed { by: 1, t: 0, op: 34, k: 0, v: 8 })),
        Aim(Box::new(Typed { by: 2, t: 0, op: 32, k: 0, v: 6 })),
        Aim(Box::new(Undo { by: 2, back: 2 })),
    ];
    check(9250009, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

// spec/requirements.md Decentralization, spec/crdt.md §5.7: the same for sequences compacted with
// nothing fallen (no role change, no hostile commit): several writers, undo, partial holders.
#[test]
#[ignore = "tier 2"]
fn arrival_order_seq_compact_large_spec_crdt_5_7() {
    run("arrival_order_seq_compact_large_spec_crdt_5_7", osis_base::testenv::large(3000..3020), 40, LARGE, seq_compact_history);
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
    let mut seen = Vec::new();
    for order in [(0..n).collect::<Vec<_>>(), (0..played.base).chain((played.base..n).rev()).collect()] {
        let mut p = deliver(&played, &order);
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
        assert_eq!(bound_kept_now(&mut p, &o, &played), None, "order {rel:?}");
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
    // dated nothing in the recompute (its leftover did not play)
    let h = vec![Nested { by: 2, other: 0, t: 6, k: 0, text: true, compact: true, also: true }, Typed { by: 2, t: 7, op: 22, k: 1, v: 7 }, Write { by: 2, t: 2, op: 1, k: 2, v: 8 }, Nested { by: 2, other: 0, t: 3, k: 2, text: false, compact: true, also: true }];
    let mut h: Vec<Step> = h.into_iter().map(|s| Aim(Box::new(s))).collect();
    h.push(Send { from: 2, to: 0, back: 2 });
    h.extend([Typed { by: 2, t: 5, op: 28, k: 1, v: 2 }, Nested { by: 0, other: 1, t: 4, k: 2, text: true, compact: false, also: false }, Typed { by: 2, t: 4, op: 11, k: 1, v: 9 }, NestedItem { by: 2, other: 0, t: 1, k: 0, compact: true, also: true }].map(|s| Aim(Box::new(s))));
    h.extend([NewTop { by: 0 }, Send { from: 0, to: 2, back: 0 }]);
    h.extend([Nested { by: 2, other: 0, t: 5, k: 0, text: true, compact: true, also: true }, Nested { by: 2, other: 1, t: 4, k: 2, text: true, compact: true, also: true }, Edge { by: 0, t: 6, holder: 1, role: Some(Role::Write) }, NestedItem { by: 0, other: 2, t: 4, k: 2, compact: true, also: true }, Demote { by: 0, t: 5, holder: 2, at: 4, to_read: false }, New { by: 0, parent: 0, write: true }, Demote { by: 0, t: 6, holder: 2, at: 5, to_read: false }, New { by: 0, parent: 7, write: false }, Typed { by: 2, t: 4, op: 25, k: 1, v: 4 }].map(|s| Aim(Box::new(s))));
    cases.push((7714, h, Cfg { sync: true, ..LARGE }));
    // seeds 40050, 731018 (spec/commits.md §4: a part past its expiry decides nothing about its
    // commit): a forged two-thing commit, one part expiring (a schema default) and the other on
    // a thing whose creation is not held. It was applied with the other part aside in one order
    // and pending whole in another (was "body known at one node only")
    let synced = Cfg { sync: true, ..LARGE };
    let h = vec![New { by: 0, parent: 6, write: false }, New { by: 2, parent: 5, write: false }, Forged { by: 1, a: 6, b: 2, how: 1, op: 12, k: 1, v: 0 }, Undo { by: 1, back: 2 }, Advance { who: None, ms: 4851689 }];
    cases.push((40050, h.into_iter().map(|s| if matches!(s, Forged { .. } | Advance { .. }) { s } else { Aim(Box::new(s)) }).collect(), synced));
    let h = vec![NestedItem { by: 0, other: 1, t: 7, k: 2, compact: false, also: false }, Nested { by: 0, other: 2, t: 6, k: 0, text: false, compact: true, also: false }, NestedItem { by: 0, other: 2, t: 0, k: 1, compact: true, also: false }, New { by: 0, parent: 4, write: false }, New { by: 2, parent: 2, write: false }, Sync { from: 0, to: 1 }, New { by: 0, parent: 1, write: false }, Sync { from: 1, to: 2 }, Forged { by: 2, a: 4, b: 3, how: 1, op: 12, k: 0, v: 0 }, Advance { who: None, ms: 3797162 }];
    cases.push((731018, h.into_iter().map(|s| if matches!(s, Forged { .. } | Advance { .. } | Sync { .. }) { s } else { Aim(Box::new(s)) }).collect(), synced));
    // seed 990031 (spec/crdt.md §4.7, spec/commits.md §5): an expiring write into
    // another's map entry, pending at its expiry at one node, and a snapshot listing it (the
    // flag stays): the snapshot holds its value-less copies in the entry's key-erased record
    // (its writer held the creation value-less), the node that applied the part keeps them in
    // the keyed record too. Reads agree here; seed 5288 below is one where they do not
    let h = vec![Write { by: 2, t: 5, op: 28, k: 0, v: 5 }, Leave { by: 2, t: 3 }, Sync { from: 2, to: 0 }, Typed { by: 2, t: 1, op: 28, k: 0, v: 7 }, Advance { who: None, ms: 7048894 }, Compact { by: 0, t: 1, op: 3 }];
    cases.push((990031, h.into_iter().map(|s| if matches!(s, Advance { .. } | Sync { .. }) { s } else { Aim(Box::new(s)) }).collect(), synced));
    // seed 83009: as 40093 below (fails without `retention::never_received` in `regiven`)
    let h = vec![Roster { by: 0, t: 3 }, Nested { by: 0, other: 2, t: 4, k: 1, text: false, compact: true, also: true }, Roster { by: 0, t: 3 }, Typed { by: 0, t: 3, op: 28, k: 2, v: 7 }, Sync { from: 0, to: 1 }, NestedItem { by: 2, other: 1, t: 7, k: 1, compact: true, also: true }, Advance { who: None, ms: 6192620 }, NewTop { by: 2 }, New { by: 2, parent: 1, write: true }, Demote { by: 0, t: 1, holder: 1, at: 5, to_read: false }, New { by: 2, parent: 2, write: false }, NewTop { by: 0 }, New { by: 2, parent: 6, write: true }];
    cases.push((83009, h.into_iter().map(|s| if matches!(s, Advance { .. } | Sync { .. } | NewTop { .. }) { s } else { Aim(Box::new(s)) }).collect(), synced));
    // seed 40093 (spec/permissions.md §5.2, spec/commits.md §6): a text part withheld for good
    // expired, and a snapshot carrying its writes turned invalid after joining: the part, never
    // received, was recorded dropped at T, so what the snapshot gave under its dots stayed as
    // hidden anchors (a node meeting the snapshot invalid had no state). Such a part counts as
    // never received there (`retention::never_received`)
    let h = vec![Demote { by: 0, t: 2, holder: 2, at: 4, to_read: true }, Typed { by: 2, t: 2, op: 29, k: 2, v: 6 }, Compact { by: 2, t: 4, op: 23 }, Advance { who: None, ms: 5607172 }, New { by: 0, parent: 2, write: true }, New { by: 0, parent: 4, write: true }];
    cases.push((40093, h.into_iter().map(|s| if matches!(s, Advance { .. }) { s } else { Aim(Box::new(s)) }).collect(), synced));
    // seed 98057 (spec/commits.md §5): the oracle took an unheld undo whose `t:docs.0` write a
    // held snapshot carried, and so dated a `t:kept.0` death at its other part, which nothing
    // held gives; it leaves such aspects undated now
    let h = vec![New { by: 0, parent: 0, write: true }, Edge { by: 2, t: 7, holder: 2, role: Some(Role::Write) }, NestedItem { by: 2, other: 1, t: 6, k: 2, compact: true, also: false }, Nested { by: 2, other: 0, t: 4, k: 0, text: false, compact: true, also: true }, Roster { by: 2, t: 6 }, NewTop { by: 0 }, Edge { by: 0, t: 4, holder: 2, role: Some(Role::Write) }, Sync { from: 0, to: 2 }, Demote { by: 0, t: 7, holder: 1, at: 3, to_read: false }, New { by: 0, parent: 3, write: false }, Forged { by: 0, a: 0, b: 0, how: 1, op: 16, k: 0, v: 5 }, Undo { by: 0, back: 0 }, Compact { by: 0, t: 4, op: 8 }, Leave { by: 1, t: 1 }, Typed { by: 1, t: 5, op: 14, k: 0, v: 9 }, Nested { by: 0, other: 1, t: 0, k: 2, text: true, compact: true, also: true }, NewTop { by: 0 }, Typed { by: 1, t: 2, op: 22, k: 2, v: 7 }, Demote { by: 0, t: 3, holder: 2, at: 0, to_read: true }, Typed { by: 0, t: 0, op: 25, k: 0, v: 8 }, Nested { by: 2, other: 1, t: 1, k: 0, text: true, compact: true, also: true }, Write { by: 0, t: 3, op: 15, k: 2, v: 4 }, Demote { by: 0, t: 4, holder: 1, at: 5, to_read: false }, Demote { by: 0, t: 6, holder: 2, at: 1, to_read: false }, Edge { by: 0, t: 4, holder: 2, role: Some(Role::Write) }, Nested { by: 2, other: 1, t: 1, k: 0, text: true, compact: true, also: true }, Nested { by: 0, other: 1, t: 2, k: 0, text: false, compact: true, also: false }, Roster { by: 0, t: 2 }, Edge { by: 0, t: 2, holder: 2, role: Some(Role::Read) }, NestedItem { by: 2, other: 0, t: 6, k: 1, compact: false, also: true }, Write { by: 1, t: 5, op: 16, k: 0, v: 1 }, Write { by: 0, t: 4, op: 28, k: 1, v: 8 }, Compact { by: 0, t: 1, op: 4 }, Demote { by: 0, t: 2, holder: 2, at: 4, to_read: false }, Typed { by: 1, t: 3, op: 23, k: 0, v: 7 }, Edge { by: 0, t: 0, holder: 1, role: Some(Role::Admin) }];
    cases.push((98057, h.into_iter().map(|s| if matches!(s, Forged { .. } | Sync { .. } | NewTop { .. }) { s } else { Aim(Box::new(s)) }).collect(), synced));
    // seed 5288 (spec/permissions.md §4, spec/commits.md §5): A's expiring put into B's entry
    // (its creation invalid after B's removal, kept by C's valid snapshot's copy) arrives past T;
    // applied at once in one order, dropped as never received where it waited. A's snapshot
    // after T lists it but carries nothing of it (A lacks C's snapshot, so its un-merge took the
    // entry whole), so the flag went dormant though the reads differed (k1 absent vs its old
    // fields): a pending-expiry flag is never dormant (with a second put in the same commit, A's
    // snapshot carried the part's write value-less in a key-erased record, and the reads still
    // differed)
    let h = vec![Nested { by: 1, other: 2, t: 1, k: 1, text: false, compact: true, also: true }, NewTop { by: 1 }, Typed { by: 2, t: 3, op: 8, k: 2, v: 4 }, NestedItem { by: 2, other: 0, t: 6, k: 1, compact: true, also: false }, Roster { by: 0, t: 3 }, Demote { by: 2, t: 4, holder: 2, at: 4, to_read: false }, Typed { by: 2, t: 4, op: 28, k: 1, v: 9 }, Edge { by: 2, t: 1, holder: 1, role: None }, Nested { by: 0, other: 1, t: 6, k: 0, text: false, compact: true, also: true }, Sync { from: 1, to: 0 }, Advance { who: None, ms: 6831206 }, Compact { by: 1, t: 4, op: 4 }, Compact { by: 0, t: 7, op: 4 }];
    cases.push((5288, h.into_iter().map(|s| if matches!(s, Advance { .. } | Sync { .. } | NewTop { .. }) { s } else { Aim(Box::new(s)) }).collect(), synced));
    // seq_compact seed 9410015 (spec/crdt.md §4.8): a held snapshot carries a write whose own
    // commit is not held, at that write's own `ts`, killing another snapshot's last write there;
    // the oracle, before taking that commit, played it at its snapshot's `ts` and dated later
    let h = vec![aim(Typed { by: 1, t: 0, op: 24, k: 1, v: 4 }), aim(Typed { by: 1, t: 0, op: 23, k: 0, v: 2 }), aim(Typed { by: 1, t: 0, op: 23, k: 0, v: 4 }), aim(Typed { by: 1, t: 0, op: 11, k: 1, v: 0 }), aim(Typed { by: 1, t: 0, op: 23, k: 1, v: 6 }), aim(Typed { by: 1, t: 0, op: 11, k: 1, v: 2 }), Compact { by: 1, t: 0, op: 11 }, Compact { by: 2, t: 0, op: 11 }, aim(Typed { by: 1, t: 0, op: 11, k: 1, v: 3 }), aim(Typed { by: 2, t: 0, op: 24, k: 1, v: 5 }), aim(Typed { by: 2, t: 0, op: 24, k: 1, v: 7 }), aim(Undo { by: 2, back: 2 }), Compact { by: 2, t: 0, op: 24 }, aim(Undo { by: 2, back: 2 }), Sync { from: 2, to: 0 }, aim(Typed { by: 0, t: 0, op: 11, k: 0, v: 0 }), Compact { by: 0, t: 0, op: 23 }];
    cases.push((9410015, h, synced));
    // in parallel: the slowest test of the module otherwise
    let idx: Vec<u64> = (0..cases.len() as u64).collect();
    let results = par_map(&idx, threads("OSIS_ORDER_THREADS"), |i| {
        let (seed, h, cfg) = &cases[i as usize];
        check(*seed, h, *cfg)
    });
    // every failing case, not the first
    let fails: Vec<String> = results.into_iter().zip(&cases).filter_map(|(r, (seed, ..))| r.err().map(|e| format!("seed {seed}: {e}"))).collect();
    assert!(fails.is_empty(), "{}", fails.join("\n\n"));
}

// spec/commits.md §5: one body under keep at most 0 with two keys, one replaced: the other stays
// read, the body goes at its grace bound (`body_past_bound`, `live_write_lost`). The generator
// rarely reaches this.
#[test]
fn live_write_outlives_its_body_at_the_bound_spec_commits_5() {
    use Step::*;
    let w = |k, v| Aim(Box::new(Typed { by: 0, t: 0, op: 19, k, v }));
    check(1, &[w(0, 0), w(0, 1)], LARGE).unwrap();
}

// spec/crdt.md §4.7-4.8: a purged register write stays in the state value-less (its leftover), so
// it still kills the write before it, in the replay too.
#[test]
fn register_deaths_purged_killer_spec_crdt_4_8() {
    let mut lp = LocalPeer::new(1, 1, T0).unwrap();
    let me = lp.peers[0].engine.tid();
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
    let mut p = Peer::new(FRESH, lp.peers[0].engine.now()).unwrap();
    p.engine.keep_bodies(true);
    for pk in &packs {
        p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    assert!(!p.engine.body_not_dropped(&w2, &t, &ak("t:kept.0")), "the purge dropped w2");
    for (t, a) in p.engine.all_aspects().unwrap() {
        p.engine.replay_deaths(&t, &a).unwrap();
    }
    let deaths = deaths_of(&mut p.engine);
    let w2_ts = p.engine.header(&w2).unwrap().ts;
    assert_eq!(deaths.get(&(w1, t, ak("t:kept.0"))).copied().flatten(), Some((w2_ts, w2_ts)));
}

// spec/crdt.md §4.8 (a write dies once, at its earliest superseder), spec/commits.md §5: order
// seed 4900, shrunk. Two deletes of one text element: the replay dated the creation's death at
// both, so a node meeting only the first had a last death earlier than the oracle's.
#[test]
fn text_creation_dies_once_seed_4900_spec_crdt_4_8() {
    use Step::*;
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![aim(Typed { by: 2, t: 0, op: 24, k: 0, v: 2 }), aim(Typed { by: 2, t: 0, op: 26, k: 1, v: 5 }), Sync { from: 2, to: 0 }, aim(Typed { by: 2, t: 0, op: 26, k: 0, v: 4 }), aim(Typed { by: 0, t: 0, op: 24, k: 1, v: 0 }), aim(Typed { by: 2, t: 0, op: 11, k: 1, v: 2 }), aim(Typed { by: 0, t: 0, op: 24, k: 1, v: 8 }), Compact { by: 2, t: 0, op: 26 }, Send { from: 2, to: 1, back: 0 }, Compact { by: 1, t: 0, op: 26 }, Send { from: 2, to: 0, back: 1 }, Compact { by: 0, t: 0, op: 11 }];
    check(4900, &h, Cfg { sync: true, ..LARGE }).unwrap();
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
    check(5016, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

// spec/crdt.md §4.8: exhaustive order seed 9605, shrunk. A commit inserts a char and deletes it;
// arriving first, into an empty state, the join took it whole and reported no death, which a
// join into a held text and the replay did.
#[test]
fn text_creation_deleted_into_empty_state_dies_seed_9605_spec_crdt_4_8() {
    use Step::*;
    let h = vec![Aim(Box::new(Typed { by: 2, t: 1, op: 23, k: 1, v: 3 })), Forged { by: 2, a: 1, b: 1, how: 1, op: 23, k: 0, v: 7 }];
    check(9605, &h, Cfg { par_orders: false, sync: true, ..EXHAUST }).unwrap();
}

// spec/permissions.md §5.2: exhaustive order seed 9310189, shrunk. A compaction snapshot carrying
// a write whose own delta is never received drops while valid at one node (its copy stays in the
// state), then turns invalid there; given again, it is judged invalid and takes back what it
// gave, as at a node that held it when it turned invalid.
#[test]
fn dropped_valid_snapshot_given_again_invalid_takes_back_seed_9310189_spec_perm_5_2() {
    use Step::*;
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![aim(Typed { by: 2, t: 0, op: 30, k: 1, v: 2 }), Sync { from: 2, to: 1 }, Advance { who: Some(0), ms: 1006 }, Forged { by: 2, a: 0, b: 0, how: 1, op: 20, k: 1, v: 3 }, aim(Undo { by: 0, back: 0 }), aim(Compact { by: 0, t: 0, op: 30 }), aim(Compact { by: 0, t: 1, op: 30 }), Edge { by: 0, t: 0, holder: 1, role: None }];
    check(9310189, &h, Cfg { random: 16, all_up_to: 0, every_held: false, clock: 24, par_orders: false, sync: true, ..EXHAUST }).unwrap();
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
    check(1006, &h, Cfg { sync: false, ..LARGE }).unwrap();
}

// as above, order seed 1042, shrunk (an in-place un-merge differed from a rebuild).
#[test]
fn invalid_snapshot_owner_late_seed_1042() {
    let h = vec![Step::Nested { by: 0, other: 2, t: 1, k: 0, text: false, compact: true, also: true }, Step::New { by: 0, parent: 3, write: false }, Step::New { by: 0, parent: 6, write: false }, Step::Sync { from: 2, to: 1 }, Step::Demote { by: 2, t: 3, holder: 1, at: 3, to_read: true }, Step::Nested { by: 2, other: 1, t: 0, k: 1, text: false, compact: true, also: true }];
    check(1042, &h, Cfg { sync: false, ..LARGE }).unwrap();
}

// spec/commits.md §5 (a body dropped for its keep bounds counts as never received: a copy that
// arrives again joins): histories the harness found with holders writing keep-at-most ops
// (shrunk), where a body is dropped at one node and held at another: seeds 1053, 1024 (its
// killer turned invalid), 1085, 1200 (its own write turned invalid, op 17's bound passed).
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
    assert!(alike(&want, &got).is_some(), "the orders differ until the body is given again");
    let apart = drop_flips(&want, &got);
    assert_eq!(apart.len(), 1, "one body dropped before the flip: {apart:?}");
    assert_eq!(alike_exchanged(&played, &want, &made, &got, &rev, Way::Plain, &|_, _| false), None);
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

// spec/crdt.md §4.6, spec/commits.md §5 (a body dropped at both nodes: their states may differ in
// a dropped body's creation stamp until a copy joins again), order seeds 47289, 583188 and
// 845143. B's entry in a keep-at-most-0 map (its body dropped once B's own later write inside it
// killed the value, the bound passed); B's writes are valid with every commit held, invalid
// before the re-grant: where they arrived valid, then turned invalid and valid again, the
// un-merge took the dropped body's creation, which nothing held gives back, and the later write
// came back into a record without it, which is not live (spec/crdt.md §5.6 Live): the key reads
// at one node and not at the other. Given the dropped body again (`both_dropped_flips`), both
// judge alike.
#[test]
fn creation_lost_by_drop_then_flip_given_again_spec_crdt_4_6() {
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
    // B's later write first, the demotion, the re-grant: its body falls in both orders, so the
    // two already read alike with nothing given again (spec/commits.md §5)
    let played = play(47289, &h);
    let b = played.base;
    let made: Vec<usize> = (0..played.packs.len()).collect();
    let mut order: Vec<usize> = (0..b).collect();
    order.extend([b, b + 2, b + 1, b + 3]);
    let want = judged(&mut deliver(&played, &made), &played);
    let got = judged(&mut deliver(&played, &order), &played);
    assert_eq!(alike(&want, &got), None);
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
// dropped other than as covered still stands in), order seed 3401073: B's write kills A's
// keep-at-most-0 write (and so A's snapshot of it) where it arrives before B's demotion, which
// makes it invalid; the snapshot dropped there still stands in (`stands_in`) and leaves the
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
    assert_eq!(alike_exchanged(&played, &want, &made, &got, &order, Way::Plain, &|_, _| false), None);
    check(3401073, &h, LARGE).unwrap();
    // the seed's longer shrink: the dropped snapshot leaves the carried-writes index too
    let h2 = vec![Roster { by: 0, t: 2 }, Nested { by: 1, other: 2, t: 0, k: 1, text: false, compact: false, also: false }, Demote { by: 2, t: 6, holder: 2, at: 4, to_read: true }, Roster { by: 0, t: 0 }, Demote { by: 0, t: 6, holder: 2, at: 1, to_read: false }, Write { by: 0, t: 3, op: 18, k: 0, v: 2 }, Compact { by: 0, t: 4, op: 18 }, Write { by: 1, t: 0, op: 15, k: 0, v: 3 }, Edge { by: 0, t: 4, holder: 1, role: Some(Role::Read) }, Edge { by: 0, t: 6, holder: 1, role: Some(Role::Admin) }, Roster { by: 0, t: 6 }, Advance { who: None, ms: 3721574 }, Write { by: 1, t: 7, op: 15, k: 2, v: 7 }, Nested { by: 0, other: 2, t: 4, k: 0, text: false, compact: true, also: true }, Demote { by: 0, t: 0, holder: 1, at: 4, to_read: false }, Edge { by: 0, t: 7, holder: 2, role: Some(Role::Write) }, Compact { by: 1, t: 7, op: 4 }, Sync { from: 0, to: 2 }, Write { by: 1, t: 1, op: 4, k: 1, v: 3 }, Write { by: 2, t: 4, op: 0, k: 1, v: 8 }, Demote { by: 0, t: 4, holder: 2, at: 1, to_read: true }, Edge { by: 0, t: 7, holder: 1, role: Some(Role::Write) }, Write { by: 1, t: 0, op: 18, k: 2, v: 5 }];
    let played = play(3401073, &h2);
    let held = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 13, 14, 16, 17, 18, 20, 21, 23, 26, 27, 28, 30];
    let order = [3, 8, 13, 30, 20, 4, 27, 0, 11, 2, 28, 26, 14, 16, 18, 10, 5, 6, 21, 1, 17, 7, 23];
    let (want, got) = (judged(&mut deliver(&played, &held), &played), judged(&mut deliver(&played, &order), &played));
    assert_eq!(alike_exchanged(&played, &want, &held, &got, &order, Way::Plain, &|_, _| false), None);
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
    assert_eq!(alike_exchanged(&played, &want, &made, &got, &rev, Way::Plain, &|_, _| false), None);
    check(21187, &h, LARGE).unwrap();
}

// spec/crdt.md §4.6 Un-merge, §4.7 (an expired delta's non-value writes stay), order seed
// 24111: A writes v5, B writes v1, B's undo of v1 writes v5 back expiring; past its expiry its
// body goes, leaving a value-less write that beats v1. A's later undo superseded it in the state,
// then B's backdated demotion of A un-merges that undo: the value-less write must win again (was
// v1 as made, absent in reverse: the leftover lived in the state alone).
#[test]
fn expired_leftover_survives_unmerge_spec_crdt_4_6() {
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
    check(24111, &h, Cfg { sync: false, ..LARGE }).unwrap();
}

// spec/requirements.md Decentralization (the index is a function of what is held), seed 50036
// (plain writes expiring, ops 27-29): two expired deltas' value-less list was kept in the
// order they expired, so the persisted index differed by arrival order. Kept sorted.
#[test]
fn valueless_list_order_independent_spec_crdt_4_7() {
    use Step::*;
    let h = vec![Write { by: 1, t: 7, op: 28, k: 1, v: 6 }, Write { by: 1, t: 2, op: 28, k: 1, v: 2 }, Advance { who: None, ms: 4563278 }];
    check(50036, &h, Cfg { sync: false, ..LARGE }).unwrap();
}

// spec/crdt.md §4.6 Un-merge, §4.7 (leftovers), spec/commits.md §5 (purge): a purged delta whose
// body was dropped as covered keeps its leftover from the coverer's copies, which the purge strips
// next; a later write that superseded it in the state and is un-merged does not take it along
// (was: made order "old" came back, demotion first absent). The purger's re-snapshot would hide
// it once it reaches the node.
#[test]
fn purged_covered_leftover_survives_unmerge_spec_crdt_4_6() {
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

// spec/crdt.md §4.7 (leftovers), spec/permissions.md §5.2: a purged delta whose body was dropped
// as covered takes its leftover from the coverer's copies and is held again from then on; when
// the coverer turns invalid the leftover stays (a held body, no longer the cover's), so the
// value-less winner hides "old" alike at once, after a rebuild and after a restart.
#[test]
fn cover_leftover_outlives_its_cover_spec_perm_5_2() {
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
    assert_eq!(after, None, "the leftover from the cover's copies stays: the value-less winner");
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
    m.expires(g, &KEPT, WallMs(now.0 + 1000)).unwrap();
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
    let old = |x: Step| Old(Box::new(x));
    let h = vec![Demote { by: 0, t: 0, holder: 2, at: 3, to_read: true }, Demote { by: 2, t: 3, holder: 2, at: 0, to_read: false }, Write { by: 1, t: 3, op: 28, k: 1, v: 0 }, Sync { from: 1, to: 0 }, old(Nested { by: 0, other: 1, t: 0, k: 1, text: false, compact: true, also: true }), Compact { by: 1, t: 4, op: 5 }, old(Write { by: 0, t: 2, op: 7, k: 1, v: 9 }), old(Nested { by: 0, other: 2, t: 7, k: 2, text: false, compact: true, also: true }), Roster { by: 0, t: 6 }, Edge { by: 0, t: 4, holder: 2, role: Some(Role::Write) }, old(Write { by: 0, t: 3, op: 1, k: 0, v: 4 }), Edge { by: 0, t: 7, holder: 1, role: Some(Role::Write) }, old(Write { by: 0, t: 7, op: 5, k: 2, v: 3 }), Edge { by: 0, t: 0, holder: 1, role: None }];
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
    let expiring = (0..n).find(|&i| { let h = header(i); h.expires.is_some() && h.aspects.iter().any(|a| a.tid == g && a.ak == ak("t:reg.0")) }).unwrap();
    let snap = (0..n).find(|&i| header(i).kind == osis_commit::Kind::ContentSnapshot).unwrap();
    let demote = snap - 1;
    assert_eq!(header(demote).kind, osis_commit::Kind::Role);
    let order: Vec<usize> = std::iter::once(expiring).chain((0..n).filter(|&i| i != expiring && i != demote)).chain([demote]).collect();
    let mut p = deliver(&played, &order);
    assert_eq!(p.engine.get(&g, &ak("t:reg.0")).unwrap(), Some(s("g")), "the older value shows: nothing valid carries the expired write");
    let flagged = p.engine.suspects().unwrap();
    assert!(flagged.iter().any(|x| x.0 == g && x.1 == ak("t:reg.0") && x.3 & osis_node::retention::suspect::Why::PendingExpiry as u8 != 0), "{flagged:?}");
}


// spec/crdt.md §4.8 (a text creation dies once, at its earliest delete), spec/commits.md §5:
// order seed 7731022, shrunk. A node holds a delete and an undelete of a text element, then a
// snapshot whose copy of the element's creation is all it holds of it (the creating delta never
// came). The state shows only the undelete, so the recompute met the creation with no delete
// before it and left the snapshot undated; the oracle, playing the creation at its own `ts`,
// dates it at the delete.
#[test]
fn snapshot_copy_of_deleted_text_creation_dies_seed_7731022_spec_crdt_4_8() {
    use Step::*;
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![aim(Roster { by: 0, t: 0 }), aim(Nested { by: 0, other: 1, t: 0, k: 0, text: false, compact: false, also: false }), aim(Edge { by: 0, t: 4, holder: 2, role: Some(Role::Write) }), aim(Edge { by: 0, t: 2, holder: 1, role: Some(Role::Admin) }), aim(Demote { by: 0, t: 1, holder: 2, at: 3, to_read: false }), aim(Typed { by: 1, t: 4, op: 23, k: 0, v: 4 }), aim(Nested { by: 1, other: 0, t: 2, k: 1, text: false, compact: true, also: false }), aim(Nested { by: 1, other: 0, t: 1, k: 1, text: false, compact: false, also: true }), Forged { by: 0, a: 2, b: 4, how: 4, op: 19, k: 2, v: 7 }, aim(New { by: 0, parent: 4, write: false }), aim(Nested { by: 0, other: 1, t: 4, k: 2, text: true, compact: true, also: true }), Forged { by: 2, a: 5, b: 6, how: 2, op: 29, k: 2, v: 0 }, aim(Edge { by: 0, t: 7, holder: 2, role: None }), aim(Write { by: 0, t: 0, op: 19, k: 1, v: 9 }), aim(Typed { by: 1, t: 4, op: 11, k: 1, v: 5 }), aim(Roster { by: 0, t: 7 }), aim(Demote { by: 2, t: 7, holder: 1, at: 2, to_read: false }), aim(Typed { by: 2, t: 6, op: 16, k: 2, v: 4 }), Sync { from: 1, to: 2 }, aim(Compact { by: 2, t: 1, op: 4 }), Sync { from: 2, to: 0 }, aim(Edge { by: 2, t: 6, holder: 1, role: Some(Role::Admin) }), aim(Nested { by: 2, other: 0, t: 6, k: 0, text: true, compact: false, also: true }), aim(Typed { by: 2, t: 0, op: 1, k: 2, v: 8 }), Sync { from: 0, to: 2 }, aim(Edge { by: 0, t: 7, holder: 1, role: Some(Role::Write) }), aim(Nested { by: 0, other: 1, t: 7, k: 0, text: true, compact: false, also: true }), Forged { by: 1, a: 5, b: 5, how: 2, op: 14, k: 0, v: 0 }, aim(Nested { by: 1, other: 0, t: 5, k: 1, text: true, compact: true, also: false }), aim(Undo { by: 1, back: 2 }), NewTop { by: 1 }, Sync { from: 0, to: 1 }, aim(Edge { by: 0, t: 6, holder: 1, role: Some(Role::Admin) }), aim(Undo { by: 1, back: 2 }), aim(Compact { by: 1, t: 6, op: 10 }), aim(Typed { by: 0, t: 3, op: 29, k: 2, v: 8 }), Forged { by: 2, a: 1, b: 5, how: 4, op: 14, k: 2, v: 2 }, aim(Compact { by: 2, t: 2, op: 5 }), aim(Compact { by: 0, t: 1, op: 5 })];
    check(7731022, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

// spec/crdt.md §4.8 (a write dies once, at its earliest superseder): seq_compact seed 8413009,
// shrunk. A reset prunes a text creation as it lands; a later snapshot carries a copy of it after
// the element's delete. The copy's creation died at the reset already: the delete dates nothing
// new, so an earlier snapshot carrying it keeps its death at its own `ts`.
#[test]
fn pruned_text_creation_copy_not_dated_again_seed_8413009_spec_crdt_4_8() {
    use Step::*;
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![aim(Typed { by: 2, t: 0, op: 11, k: 1, v: 9 }), Compact { by: 0, t: 0, op: 24 }, aim(Typed { by: 1, t: 0, op: 11, k: 1, v: 1 }), Compact { by: 0, t: 0, op: 10 }, aim(Undo { by: 1, back: 2 }), aim(Typed { by: 2, t: 0, op: 10, k: 1, v: 8 }), aim(Typed { by: 2, t: 0, op: 24, k: 1, v: 6 }), Compact { by: 2, t: 0, op: 10 }, aim(Typed { by: 2, t: 0, op: 11, k: 1, v: 3 }), Compact { by: 2, t: 0, op: 10 }];
    check(8413009, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

// spec/crdt.md §4.8, spec/commits.md §5: seq_compact seed 8413015, shrunk. A text creation dies
// at a reset and at a delete of one `ts`; a later snapshot had applied the delete but not the
// reset, so the reset's death dates it at its `ts`. The death a snapshot copy's late creation
// gets at the delete must not hide the reset's.
#[test]
fn late_creation_death_hides_no_reset_death_seed_8413015_spec_crdt_4_8() {
    use Step::*;
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![aim(Typed { by: 1, t: 0, op: 26, k: 0, v: 3 }), aim(Typed { by: 0, t: 0, op: 23, k: 0, v: 3 }), aim(Typed { by: 1, t: 0, op: 24, k: 1, v: 0 }), aim(Typed { by: 0, t: 0, op: 26, k: 1, v: 7 }), aim(Typed { by: 1, t: 0, op: 24, k: 1, v: 7 }), aim(Typed { by: 2, t: 0, op: 26, k: 1, v: 2 }), aim(Typed { by: 2, t: 0, op: 24, k: 0, v: 7 }), aim(Typed { by: 1, t: 0, op: 26, k: 1, v: 5 }), aim(Undo { by: 1, back: 1 }), aim(Typed { by: 1, t: 0, op: 23, k: 1, v: 2 }), aim(Undo { by: 1, back: 2 }), Compact { by: 1, t: 0, op: 26 }, aim(Undo { by: 2, back: 2 }), aim(Typed { by: 2, t: 0, op: 24, k: 1, v: 3 }), aim(Typed { by: 2, t: 0, op: 23, k: 1, v: 4 }), aim(Typed { by: 1, t: 0, op: 23, k: 0, v: 2 }), aim(Typed { by: 2, t: 0, op: 23, k: 1, v: 8 }), Compact { by: 1, t: 0, op: 24 }, aim(Typed { by: 0, t: 0, op: 24, k: 0, v: 7 }), aim(Typed { by: 2, t: 0, op: 26, k: 1, v: 5 }), Compact { by: 0, t: 0, op: 23 }, aim(Typed { by: 1, t: 0, op: 26, k: 1, v: 4 }), aim(Typed { by: 0, t: 0, op: 26, k: 0, v: 1 }), Compact { by: 2, t: 0, op: 23 }, aim(Typed { by: 1, t: 0, op: 26, k: 0, v: 9 }), aim(Typed { by: 2, t: 0, op: 23, k: 0, v: 7 }), aim(Typed { by: 2, t: 0, op: 23, k: 0, v: 7 }), aim(Undo { by: 2, back: 2 }), aim(Typed { by: 2, t: 0, op: 26, k: 0, v: 4 }), Compact { by: 1, t: 0, op: 24 }, aim(Typed { by: 0, t: 0, op: 23, k: 0, v: 6 }), aim(Undo { by: 0, back: 2 }), aim(Typed { by: 1, t: 0, op: 26, k: 1, v: 5 }), Compact { by: 0, t: 0, op: 26 }, aim(Typed { by: 0, t: 0, op: 26, k: 1, v: 5 })];
    check(8413015, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

// spec/permissions.md §7: a snapshot purged, the purge falling, then purged again with no copy reads
// alike; what it gives then differs, a stated limit (`alike`) (seed 3265).
#[test]
#[ignore = "tier 2"]
fn snapshot_purged_fell_purged_reads_alike_seed_3265() {
    run("snapshot_purged_fell_purged_reads_alike_seed_3265", 3265..3266, 60, LARGE, purge_history);
}

// spec/permissions.md §7: a by-author request standing, falling and another rising over a part with
// no copy left: the part leaves what it left, so a value-less winner stays the winner (seed 872030).
#[test]
#[ignore = "tier 2"]
fn purged_fell_purged_leaves_its_leftover_seed_872030() {
    run("purged_fell_purged_leaves_its_leftover_seed_872030", 872030..872031, 50, LARGE, purge_author_history);
}

// spec/commits.md §5: a text creation arriving under an undelete whose delete's body
// this node dropped (keep at most 0, no live write left) has no death here and stays held: the
// nodes read alike (seed 733028, shrunk).
#[test]
fn creation_after_its_dropped_delete_has_no_death_seed_733028_spec_commits_5() {
    use Step::*;
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![aim(Demote { by: 0, t: 7, holder: 2, at: 4, to_read: true }), aim(Leave { by: 1, t: 7 }), aim(Require { by: 0, t: 1, op: 18, rule: 3 }), aim(Breaking { by: 0, t: 1, op: 6, v: 1, fits: false }), aim(Breaking { by: 0, t: 1, op: 6, v: 1, fits: false }), Send { from: 0, to: 2, back: 2 }, aim(Nested { by: 0, other: 2, t: 3, k: 2, text: true, compact: false, also: false }), aim(Undo { by: 2, back: 1 }), aim(Typed { by: 1, t: 0, op: 1, k: 0, v: 4 }), aim(Edge { by: 0, t: 2, holder: 1, role: Some(Role::Write) }), aim(Typed { by: 2, t: 4, op: 3, k: 2, v: 7 }), aim(Undo { by: 2, back: 2 }), aim(Typed { by: 0, t: 4, op: 7, k: 1, v: 3 }), aim(Typed { by: 0, t: 3, op: 10, k: 1, v: 6 })];
    check(733028, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

// spec/crdt.md §4.6: an un-merge takes the records a delta created; one whose body was dropped
// under keep at most gives them back only with a copy, so the states differ in records with no
// write left until both nodes are given it again (`both_dropped_flips`) (seed 733028, shrunk on
// that failure).
#[test]
fn records_of_a_dropped_body_after_a_flip_seed_733028_spec_crdt_4_6() {
    use Step::*;
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![Forged { by: 2, a: 2, b: 5, how: 1, op: 1, k: 1, v: 3 }, aim(Edge { by: 2, t: 3, holder: 2, role: Some(Role::Write) }), aim(NestedItem { by: 0, other: 2, t: 5, k: 0, compact: true, also: false }), aim(Demote { by: 0, t: 7, holder: 2, at: 4, to_read: true }), aim(Breaking { by: 2, t: 0, op: 28, v: 2, fits: true }), aim(Typed { by: 1, t: 1, op: 27, k: 1, v: 6 }), aim(Typed { by: 1, t: 3, op: 13, k: 0, v: 9 }), aim(Typed { by: 0, t: 2, op: 26, k: 0, v: 1 }), Forged { by: 0, a: 4, b: 0, how: 3, op: 26, k: 2, v: 1 }, aim(Nested { by: 0, other: 1, t: 4, k: 2, text: false, compact: true, also: false }), aim(Leave { by: 1, t: 7 }), aim(Nested { by: 0, other: 1, t: 1, k: 0, text: true, compact: true, also: true }), aim(Roster { by: 0, t: 4 }), aim(Require { by: 0, t: 1, op: 18, rule: 3 }), aim(Breaking { by: 0, t: 1, op: 6, v: 1, fits: false }), aim(Breaking { by: 0, t: 1, op: 6, v: 1, fits: false }), Send { from: 0, to: 2, back: 2 }, aim(Nested { by: 1, other: 0, t: 7, k: 0, text: true, compact: false, also: true }), aim(Nested { by: 0, other: 2, t: 3, k: 2, text: true, compact: false, also: false }), aim(Undo { by: 2, back: 1 }), Advance { who: None, ms: 5621907 }, aim(Edge { by: 0, t: 2, holder: 1, role: Some(Role::Write) }), aim(Roster { by: 0, t: 4 }), aim(Typed { by: 2, t: 4, op: 3, k: 2, v: 7 }), aim(Breaking { by: 1, t: 2, op: 11, v: 9, fits: false }), aim(Edge { by: 2, t: 3, holder: 2, role: Some(Role::Write) }), aim(Typed { by: 1, t: 0, op: 11, k: 0, v: 5 }), aim(Typed { by: 0, t: 2, op: 7, k: 0, v: 8 }), Forged { by: 1, a: 1, b: 2, how: 0, op: 13, k: 1, v: 2 }, aim(Undo { by: 0, back: 1 }), aim(Typed { by: 0, t: 4, op: 7, k: 1, v: 3 }), aim(Typed { by: 0, t: 3, op: 10, k: 1, v: 6 })];
    check(733028, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

// spec/permissions.md §7: a part a fallen purge took counts as never received until a copy comes;
// an expiry later drops it at every node, so the harness tells the fall by its missing part
// when judged (`purge_flips`) (seed 29617 of the purge-rows mix, shrunk).
#[test]
fn fallen_purge_part_missing_before_its_expiry_seed_29617_spec_perm_7() {
    use Step::*;
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![Edge { by: 0, t: 0, holder: 1, role: Some(Role::Admin) }, Sync { from: 0, to: 2 }, Sync { from: 2, to: 1 }, Edge { by: 2, t: 0, holder: 0, role: Some(Role::Write) }, aim(Message { by: 1, t: 0, v: 0 }), aim(Typed { by: 2, t: 0, op: 0, k: 0, v: 7 }), Edge { by: 0, t: 0, holder: 1, role: Some(Role::Admin) }, aim(Purge { by: 0, t: 0, of: 2, back: 2, v: 0 }), aim(Typed { by: 1, t: 0, op: 27, k: 1, v: 0 }), aim(Message { by: 0, t: 0, v: 4 }), aim(Typed { by: 2, t: 0, op: 27, k: 2, v: 2 }), aim(Typed { by: 0, t: 0, op: 0, k: 0, v: 1 }), aim(Typed { by: 0, t: 0, op: 27, k: 1, v: 9 }), Send { from: 2, to: 1, back: 0 }, aim(Typed { by: 1, t: 0, op: 27, k: 1, v: 4 }), aim(Compact { by: 2, t: 0, op: 0 }), aim(Typed { by: 0, t: 0, op: 27, k: 0, v: 7 }), Edge { by: 0, t: 0, holder: 1, role: Some(Role::Write) }, Edge { by: 2, t: 0, holder: 0, role: Some(Role::Write) }, aim(Demote { by: 1, t: 0, holder: 1, at: 3, to_read: true }), Edge { by: 2, t: 0, holder: 2, role: Some(Role::Admin) }, aim(Demote { by: 2, t: 0, holder: 2, at: 1, to_read: false }), Edge { by: 0, t: 0, holder: 2, role: Some(Role::Admin) }, Sync { from: 0, to: 2 }, aim(Purge { by: 2, t: 0, of: 1, back: 1, v: 3 })];
    check(29617, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

// spec/commits.md §5: a body dropped under keep at most whose other part is still missing leaves that
// part missing (never received, fetched as such): a node that applied the kill, then saw it turn
// invalid and was given the body again, judges the commit as one that never applied the kill (seed
// 106342, shrunk; #26's `t:docs.0` part is missing, #28 kills its `t:reg.0` write until #17
// turns #28 invalid).
#[test]
fn class_drop_leaves_missing_part_missing_seed_106342_spec_commits_5() {
    use Step::*;
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![aim(New { by: 0, parent: 4, write: false }), Forged { by: 0, a: 1, b: 3, how: 0, op: 16, k: 2, v: 2 }, aim(Breaking { by: 0, t: 1, op: 28, v: 9, fits: false }), aim(Compact { by: 0, t: 4, op: 5 }), aim(Nested { by: 2, other: 0, t: 6, k: 1, text: true, compact: true, also: true }), aim(Typed { by: 2, t: 3, op: 18, k: 1, v: 5 }), aim(Require { by: 0, t: 0, op: 3, rule: 1 }), aim(Edge { by: 2, t: 7, holder: 2, role: Some(Role::Write) }), aim(Edge { by: 2, t: 5, holder: 1, role: Some(Role::Write) }), aim(Typed { by: 2, t: 1, op: 29, k: 2, v: 2 }), aim(Roster { by: 0, t: 2 }), aim(Require { by: 0, t: 0, op: 17, rule: 3 }), Forged { by: 0, a: 5, b: 4, how: 2, op: 3, k: 0, v: 6 }, aim(Leave { by: 1, t: 6 }), aim(Edge { by: 2, t: 5, holder: 1, role: Some(Role::Read) }), aim(Nested { by: 0, other: 2, t: 5, k: 1, text: true, compact: false, also: true }), aim(Write { by: 1, t: 0, op: 27, k: 1, v: 6 }), aim(Nested { by: 0, other: 2, t: 7, k: 0, text: false, compact: true, also: true }), Advance { who: None, ms: 6502368 }, aim(Typed { by: 2, t: 5, op: 19, k: 1, v: 7 })];
    let played = with_syncs(play(106342, &h), 106342, false);
    let digest = |order: &[usize]| {
        let mut p = deliver(&played, order);
        let pk = &played.packs[26];
        let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
        p.engine.reexamine().unwrap();
        p.engine.index_digest().commits.get(&pk.id).cloned().unwrap()
    };
    for order in [&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 17, 19, 20, 21, 22, 26, 27, 28, 29, 30, 31, 32], &[5, 10, 32, 20, 31, 6, 8, 13, 29, 19, 21, 2, 15, 26, 0, 30, 9, 4, 27, 3, 12, 14, 1, 28, 17, 7, 22]] {
        assert_eq!(digest(order).missing, [1].into(), "the t:docs.0 part never came");
    }
}

// spec/commits.md §4, spec/permissions.md §7: a snapshot's part dropped for a purge, reopened as
// missing when the purge fell, then dropped for another with no copy come still stands in (a bit
// of its header, no body needed), as at a node that dropped it once (seed 32032 of the purge-rows
// mix, shrunk).
#[test]
fn snapshot_purged_fell_purged_stands_in_seed_32032_spec_perm_7() {
    use Step::*;
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![Edge { by: 0, t: 0, holder: 1, role: Some(Role::Admin) }, Sync { from: 0, to: 1 }, aim(Demote { by: 1, t: 0, holder: 2, at: 1, to_read: false }), aim(Compact { by: 2, t: 0, op: 0 }), aim(Typed { by: 2, t: 0, op: 0, k: 0, v: 4 }), aim(Typed { by: 1, t: 0, op: 0, k: 0, v: 3 }), Edge { by: 0, t: 0, holder: 2, role: Some(Role::Admin) }, aim(Typed { by: 1, t: 0, op: 0, k: 0, v: 7 }), aim(Typed { by: 2, t: 0, op: 0, k: 0, v: 1 }), aim(PurgeNamed { by: 2, t: 0, of: 2, back: 2, v: 9 }), aim(PurgeNamed { by: 2, t: 0, of: 1, back: 1, v: 3 }), aim(Compact { by: 1, t: 0, op: 0 }), Edge { by: 1, t: 0, holder: 0, role: Some(Role::Admin) }, aim(Compact { by: 1, t: 0, op: 0 }), aim(Message { by: 2, t: 0, v: 0 }), Edge { by: 1, t: 0, holder: 2, role: Some(Role::Write) }, aim(PurgeNamed { by: 0, t: 0, of: 2, back: 2, v: 7 }), aim(Typed { by: 0, t: 0, op: 0, k: 0, v: 6 }), Edge { by: 0, t: 0, holder: 1, role: Some(Role::Admin) }];
    let played = with_syncs(play(32032, &h), 32032, false);
    let digest = |order: &[usize]| {
        let mut p = deliver(&played, order);
        let _ = judged(&mut p, &played);
        let ix = p.engine.index_digest();
        played.packs.iter().filter(|pk| ix.commits.get(&pk.id).is_some_and(|c| c.kind == osis_commit::Kind::ContentSnapshot && !c.dropped.is_empty())).map(|pk| (pk.id, ix.commits[&pk.id].clone())).collect::<Vec<_>>()
    };
    for order in [(0..played.packs.len()).collect::<Vec<_>>(), vec![18, 15, 8, 6, 7, 1, 0, 21, 2, 24, 3, 19, 9, 12, 11, 16, 20, 25, 17, 5, 4, 26, 22, 23, 13, 10, 14]] {
        let got = digest(&order);
        assert!(got.iter().any(|(_, c)| c.stands_in == [0].into()), "a dropped snapshot stands in: {got:?}");
    }
}

// spec/commits.md §5 (Purge request): a commit carrying a purge request keeps its body to
// `ROLE_KEEP` though it writes under keep at most 0 (a required retention's) and a later write
// killed it; `bound_kept_now` does not take that for a dead body kept (seed 32014, shrunk).
#[test]
fn purge_commit_body_kept_under_at_most_0_seed_32014_spec_commits_5() {
    use Step::*;
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![aim(New { by: 0, parent: 2, write: true }), aim(Breaking { by: 0, t: 2, op: 24, v: 5, fits: false }), aim(Breaking { by: 1, t: 0, op: 18, v: 5, fits: false }), NewTop { by: 2 }, aim(Nested { by: 2, other: 0, t: 7, k: 2, text: false, compact: true, also: true }), Forged { by: 1, a: 0, b: 1, how: 1, op: 23, k: 2, v: 2 }, aim(Require { by: 2, t: 1, op: 20, rule: 3 }), Forged { by: 0, a: 6, b: 3, how: 4, op: 9, k: 0, v: 6 }, aim(Purge { by: 2, t: 1, of: 1, back: 1, v: 6 }), NewTop { by: 2 }, aim(Demote { by: 2, t: 1, holder: 2, at: 0, to_read: false }), aim(Require { by: 2, t: 0, op: 26, rule: 1 })];
    check(32014, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

// spec/crdt.md §4.6, spec/commits.md §5: a keep-at-most-0 body dropped with its write live, then
// its delta turned invalid (the un-merge took the write) and valid again: the write comes back
// only with a copy, so the harness gives both nodes the body dropped at both (`both_dropped_flips`)
// and compares reads exactly (seed 733028, shrunk).
#[test]
fn dropped_live_write_given_again_after_flip_seed_733028_spec_crdt_4_6() {
    use Step::*;
    let aim = |x: Step| Aim(Box::new(x));
    let h = vec![Forged { by: 2, a: 2, b: 5, how: 1, op: 1, k: 1, v: 3 }, aim(Edge { by: 2, t: 3, holder: 2, role: Some(Role::Write) }), aim(NestedItem { by: 0, other: 2, t: 5, k: 0, compact: true, also: false }), aim(Demote { by: 0, t: 7, holder: 2, at: 4, to_read: true }), aim(Breaking { by: 2, t: 0, op: 28, v: 2, fits: true }), aim(Typed { by: 1, t: 1, op: 27, k: 1, v: 6 }), aim(Typed { by: 1, t: 3, op: 13, k: 0, v: 9 }), aim(Typed { by: 0, t: 2, op: 26, k: 0, v: 1 }), Forged { by: 0, a: 4, b: 0, how: 3, op: 26, k: 2, v: 1 }, aim(Nested { by: 0, other: 1, t: 4, k: 2, text: false, compact: true, also: false }), aim(Leave { by: 1, t: 7 }), aim(Nested { by: 0, other: 1, t: 1, k: 0, text: true, compact: true, also: true }), aim(Roster { by: 0, t: 4 }), aim(Require { by: 0, t: 1, op: 18, rule: 3 }), aim(Breaking { by: 0, t: 1, op: 6, v: 1, fits: false }), aim(Breaking { by: 0, t: 1, op: 6, v: 1, fits: false }), Send { from: 0, to: 2, back: 2 }, aim(Nested { by: 1, other: 0, t: 7, k: 0, text: true, compact: false, also: true }), aim(Nested { by: 0, other: 2, t: 3, k: 2, text: true, compact: false, also: false }), aim(Undo { by: 2, back: 1 }), Advance { who: None, ms: 5621907 }, aim(Edge { by: 0, t: 2, holder: 1, role: Some(Role::Write) }), aim(Roster { by: 0, t: 4 }), aim(Typed { by: 2, t: 4, op: 3, k: 2, v: 7 }), Forged { by: 0, a: 5, b: 7, how: 2, op: 19, k: 0, v: 6 }, aim(Edge { by: 2, t: 3, holder: 2, role: Some(Role::Write) }), aim(Typed { by: 1, t: 0, op: 11, k: 0, v: 5 }), aim(Typed { by: 0, t: 2, op: 7, k: 0, v: 8 }), Forged { by: 1, a: 1, b: 2, how: 0, op: 13, k: 1, v: 2 }, aim(Undo { by: 0, back: 1 }), aim(Typed { by: 0, t: 4, op: 7, k: 1, v: 3 }), aim(Typed { by: 0, t: 3, op: 10, k: 1, v: 6 })];
    check(733028, &h, Cfg { sync: true, ..LARGE }).unwrap();
}


// spec/permissions.md §5.2, seed 7340054 of `new_device_alike_large`: 1 puts k0, 0 writes a
// field into it, 1 removes k0 (its reset prunes the creation) and 0 compacts; 0 demotes 1 below
// both. The snapshot holds the record k0 without its creation, alive by 0's field: it keeps the
// record, so a node holding 1's invalid deltas reads k0 as a node holding the snapshot alone.
#[test]
fn new_device_record_without_creation_kept_spec_permissions_5_2() {
    use Step::*;
    let a = |s: Step| Aim(Box::new(s));
    let h = vec![a(Typed { by: 1, t: 3, op: 1, k: 2, v: 6 }), a(New { by: 2, parent: 1, write: false }), Advance { who: None, ms: 6961542 }, a(New { by: 0, parent: 1, write: true }), a(Nested { by: 1, other: 0, t: 0, k: 0, text: false, compact: false, also: false }), a(Breaking { by: 1, t: 1, op: 25, v: 9, fits: false }), Sync { from: 1, to: 0 }, a(Compact { by: 0, t: 0, op: 3 }), Demote { by: 0, t: 0, holder: 1, at: 1, to_read: false }];
    check_new_device(7340054, &h).unwrap();
}

// spec/crdt.md §5.7, seed 198 of `required_drops_read_alike_large` (general): 1 deletes a char
// and undoes the delete. A node reopening while it is deleted drops its char; the undelete's
// copy then reads in its place (`plain_state`).
#[test]
fn drops_alike_undeleted_char_after_reopen_spec_crdt_5_7() {
    use Step::*;
    let a = |s: Step| Aim(Box::new(s));
    let h = vec![a(Demote { by: 2, t: 7, holder: 1, at: 3, to_read: true }), Send { from: 2, to: 1, back: 0 }, a(Demote { by: 2, t: 3, holder: 2, at: 5, to_read: false }), a(Breaking { by: 1, t: 2, op: 10, v: 5, fits: false }), a(Edge { by: 2, t: 4, holder: 1, role: Some(Role::Write) }), Sync { from: 0, to: 1 }, Forged { by: 1, a: 0, b: 4, how: 1, op: 22, k: 1, v: 8 }, a(Undo { by: 1, back: 1 })];
    drops_alike(198, &h, LARGE).unwrap();
}

// spec/crdt.md §4.6, §4.7, seed 7340007 of `arrival_order_alike_large`: 2 puts k0 with its expiry
// past (held value-less: the record is key-erased), then is demoted; 1 puts into k0 (its body
// names the record by key) and 0's valid snapshot holds the key-erased record. A key-erased
// record keeps every record of its dot, so it keeps 1's valid writes whichever of 2's expired
// delta, 1's put, the demotion and the snapshot came first.
#[test]
fn expired_record_keeps_keyed_valid_writes_seed_7340007_spec_crdt_4_6() {
    use Step::*;
    let a = |s: Step| Aim(Box::new(s));
    let h = vec![NewTop { by: 1 }, a(Typed { by: 2, t: 7, op: 28, k: 0, v: 9 }), a(Typed { by: 2, t: 7, op: 22, k: 1, v: 4 }), Send { from: 2, to: 1, back: 1 }, NewTop { by: 2 }, a(Edge { by: 0, t: 5, holder: 2, role: Some(Role::Read) }), Advance { who: None, ms: 6647992 }, a(Nested { by: 0, other: 1, t: 3, k: 2, text: false, compact: true, also: true }), a(Demote { by: 0, t: 5, holder: 1, at: 4, to_read: true }), NewTop { by: 1 }, a(Nested { by: 1, other: 0, t: 4, k: 0, text: false, compact: true, also: false }), NewTop { by: 1 }, NewTop { by: 1 }, Forged { by: 0, a: 6, b: 6, how: 2, op: 17, k: 1, v: 2 }];
    check(7340007, &h, Cfg { sync: true, ..LARGE }).unwrap();
}

// spec/crdt.md §4.8, spec/commits.md §5, seed 52040 of `arrival_order_alike_large`: 1 puts k2,
// 0 writes into it under keep at most 0, 0 removes k2 (a reset on 1's dot), and 1 is demoted
// below its put. 0's nested write is un-merged with 1's record, yet 0's later valid reset
// supersedes it (judged against the write alone), so its body has a death and is dropped at a
// node that joined it before the demotion (the thing's creation last: everything applies at
// once, newest first) and at one that un-merged it on join (as made); the oracle's recompute
// dates it too.
#[test]
fn nested_write_dies_under_unmerged_record_seed_52040_spec_crdt_4_8() {
    use Step::*;
    let a = |s: Step| Aim(Box::new(s));
    let h = vec![a(Typed { by: 2, t: 3, op: 20, k: 1, v: 9 }), a(Typed { by: 0, t: 5, op: 15, k: 0, v: 0 }), Send { from: 0, to: 2, back: 2 }, a(Demote { by: 0, t: 0, holder: 1, at: 4, to_read: true }), a(Undo { by: 0, back: 2 }), a(Compact { by: 0, t: 4, op: 19 }), a(Nested { by: 1, other: 0, t: 1, k: 0, text: true, compact: true, also: false }), a(Typed { by: 0, t: 1, op: 14, k: 2, v: 7 }), Send { from: 2, to: 0, back: 1 }, a(Demote { by: 0, t: 1, holder: 1, at: 3, to_read: false }), a(Typed { by: 1, t: 6, op: 19, k: 2, v: 1 }), Forged { by: 1, a: 7, b: 7, how: 2, op: 29, k: 2, v: 8 }, Sync { from: 0, to: 1 }, a(Breaking { by: 2, t: 0, op: 11, v: 2, fits: false }), a(Breaking { by: 2, t: 1, op: 2, v: 5, fits: false }), Forged { by: 0, a: 2, b: 5, how: 2, op: 15, k: 1, v: 6 }, Sync { from: 2, to: 0 }, Advance { who: Some(0), ms: 1697 }, Send { from: 1, to: 0, back: 2 }, a(Write { by: 2, t: 0, op: 6, k: 1, v: 8 }), a(Write { by: 2, t: 6, op: 0, k: 1, v: 1 }), Forged { by: 2, a: 6, b: 3, how: 0, op: 6, k: 1, v: 1 }, a(Typed { by: 2, t: 2, op: 17, k: 1, v: 0 }), a(Typed { by: 1, t: 6, op: 26, k: 1, v: 6 }), a(Nested { by: 0, other: 1, t: 7, k: 2, text: true, compact: true, also: true }), a(Demote { by: 2, t: 3, holder: 1, at: 4, to_read: false }), a(Compact { by: 1, t: 3, op: 17 }), a(Breaking { by: 0, t: 2, op: 14, v: 1, fits: false }), Advance { who: Some(0), ms: 6 }, Advance { who: Some(0), ms: 83 }, a(Nested { by: 0, other: 1, t: 4, k: 1, text: true, compact: true, also: false }), Sync { from: 1, to: 2 }, a(Typed { by: 0, t: 3, op: 7, k: 2, v: 8 }), a(Typed { by: 1, t: 2, op: 22, k: 1, v: 6 }), a(NestedItem { by: 0, other: 1, t: 7, k: 0, compact: true, also: true }), a(Breaking { by: 2, t: 0, op: 4, v: 6, fits: false }), a(Require { by: 0, t: 0, op: 15, rule: 1 }), a(Require { by: 0, t: 1, op: 19, rule: 1 }), Forged { by: 2, a: 1, b: 0, how: 0, op: 7, k: 1, v: 1 }, a(Edge { by: 2, t: 1, holder: 1, role: Some(Role::Read) }), a(Breaking { by: 1, t: 0, op: 28, v: 1, fits: true }), Advance { who: None, ms: 5662678 }, a(Typed { by: 1, t: 7, op: 26, k: 0, v: 5 }), a(Typed { by: 0, t: 4, op: 14, k: 2, v: 2 }), a(Typed { by: 2, t: 5, op: 9, k: 2, v: 8 }), a(Nested { by: 0, other: 1, t: 6, k: 0, text: false, compact: false, also: false }), a(Typed { by: 0, t: 6, op: 3, k: 0, v: 1 }), a(Typed { by: 1, t: 1, op: 4, k: 2, v: 6 }), Send { from: 1, to: 2, back: 2 }, a(Typed { by: 0, t: 0, op: 11, k: 1, v: 4 }), a(Edge { by: 2, t: 2, holder: 2, role: Some(Role::Write) }), a(Edge { by: 0, t: 5, holder: 2, role: Some(Role::Write) }), a(Compact { by: 0, t: 7, op: 1 }), Sync { from: 1, to: 0 }, a(Write { by: 0, t: 6, op: 19, k: 2, v: 0 }), a(Leave { by: 2, t: 2 }), a(Require { by: 0, t: 2, op: 12, rule: 0 }), a(Breaking { by: 1, t: 0, op: 14, v: 9, fits: false }), a(Breaking { by: 1, t: 2, op: 19, v: 4, fits: false }), a(Typed { by: 1, t: 6, op: 20, k: 2, v: 4 }), a(Demote { by: 2, t: 5, holder: 1, at: 3, to_read: false }), Forged { by: 2, a: 1, b: 7, how: 4, op: 13, k: 0, v: 3 }, Advance { who: None, ms: 7162431 }, a(Write { by: 2, t: 3, op: 27, k: 0, v: 6 }), a(Typed { by: 2, t: 7, op: 26, k: 2, v: 6 }), a(Compact { by: 2, t: 6, op: 20 }), a(NestedItem { by: 0, other: 1, t: 2, k: 1, compact: false, also: false }), a(New { by: 2, parent: 7, write: true }), Advance { who: None, ms: 3964782 }, a(Typed { by: 1, t: 0, op: 14, k: 2, v: 0 })];
    let played = with_syncs(play(52040, &h), 52040, false);
    let held = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15, 16, 17, 19, 20, 23, 24, 25, 27, 28, 30, 31, 32, 33, 34, 35, 39, 40, 42, 43, 44, 46, 47, 49, 50, 51, 52, 54, 55, 57];
    let rev: Vec<usize> = held.iter().rev().copied().collect();
    let o = oracle(&played, &held);
    let (mut w, mut g) = (deliver(&played, &held), deliver(&played, &rev));
    assert_eq!(bound_kept_now(&mut w, &o, &played), None);
    assert_eq!(bound_kept_now(&mut g, &o, &played), None);
    assert!(!w.engine.body_not_dropped(&played.packs[46].id, &tid_of(&played, "t:gonemap.0"), &ak("t:gonemap.0")), "the dead body under keep at most 0 is dropped as made");
    assert!(!g.engine.body_not_dropped(&played.packs[46].id, &tid_of(&played, "t:gonemap.0"), &ak("t:gonemap.0")), "and reversed");
    let (want, got) = (judged(&mut w, &played), judged(&mut g, &played));
    assert_eq!(alike_exchanged(&played, &want, &held, &got, &rev, Way::Plain, &|t, a| flipped(&played, &held, Way::Plain, t, a) || flipped(&played, &rev, Way::Plain, t, a)), None);
}

/// The thing an aspect `ak` is written on in `played` (one thing per aspect name in a history).
fn tid_of(played: &Played, ak: &str) -> Tid {
    played.packs.iter().find_map(|pk| osis_commit::CommitBlob::decode_stored(&pk.bytes).ok()?.header.aspects.iter().find(|a| a.ak.as_str() == ak).map(|a| a.tid)).unwrap()
}

// spec/crdt.md §4.6, §4.7: 2 puts k0 expiring in a second, 1 writes inside it, 0 passes the
// expiry and compacts (its copy of 2's record key-erased), then demotes 2 below the put. A node
// that held all of it before the expiry and one given it after read alike once both are past
// it. 1's write (by a writer predating the copy-expiry rule) repeats the key: only the key goes
// with the put, 1's value stays (spec/crdt.md §4.7 Copies).
#[test]
fn key_erased_copy_keeps_record_before_expiry_spec_crdt_4_6() {
    use Step::*;
    let h = vec![
        Write { by: 2, t: 0, op: 28, k: 0, v: 0 },
        Sync { from: 2, to: 0 },
        Sync { from: 2, to: 1 },
        Old(Box::new(Write { by: 1, t: 0, op: 4, k: 0, v: 5 })),
        Advance { who: Some(0), ms: 2000 },
        Compact { by: 0, t: 0, op: 3 },
        Demote { by: 0, t: 0, holder: 2, at: 0, to_read: false },
        Sync { from: 1, to: 0 },
    ];
    let played = play(1, &h);
    let all: Vec<usize> = (0..played.packs.len()).collect();
    let mut after = deliver(&played, &all);
    let mut before = Peer::new(FRESH, T0).unwrap();
    for pk in &played.packs {
        let _ = before.engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    before.clock.set(played.now);
    before.engine.tick().unwrap();
    let (a, b) = (judged_now(&mut after, &played.things), judged_now(&mut before, &played.things));
    let map = |j: &Judged, i: usize| j.parts[i].1.lines().filter(|l| l.contains(" t:map.0 ")).collect::<Vec<_>>().join("\n");
    for i in 0..2 {
        assert_eq!(map(&a, i), map(&b, i), "{}", a.parts[i].0);
    }
    assert!(map(&a, 1).contains("value: Some(Int(5))"), "1's write is kept");
}

// spec/commits.md §5 (Purge), spec/permissions.md §7: held-model (`held.rs`) judges what each node
// holds alike: a writer's purge of an admin's delta, without the right, drops nothing; an
// admin's purge of a writer's delta drops it. Also a tier-1 run of the adapter.
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
    let seen = check(9360000, &h, Cfg { model: true, ..SMALL }).unwrap();
    assert!(seen.model.compared > 0 && seen.model.reached.get("purged").is_some_and(|n| *n > 0), "{:?}", seen.model);
}

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Arrival-order differential (spec/requirements.md Decentralization: a node's state and its
//! judgment of every write are functions of the data it holds, never of arrival order;
//! spec/permissions.md §5, §5.2; spec/crdt.md §4.6). Random histories over three writers
//! (grants, demotions with frontiers before, inside and after the demoted writes, re-grants,
//! self-removals, roster and compaction snapshots, things created under things in later
//! commits, writes inside map entries, struct fields and nested texts, undo, expiry, partial
//! syncs) are delivered, as one held set, to fresh nodes in several arrival orders (two of them
//! also with multi-aspect commits split into a part and late parts): every
//! order must give the same per-delta verdicts, reads and states of every aspect, rosters,
//! pending set, persisted index and timelines, and a reopen and a rebuild must give them too.
//! Short focused histories (bounded writes, compactions, undo, demotions, late writes) are also
//! checked in every arrival order of a few held sets. Seeds run on a thread per core.

use crate::common;
use common::*;
use osis_base::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_node::local_peer::{LocalPeer, Package, Peer};
use osis_perm::DemotionScope;
use osis_schema::{Bound, Codec, PurgeBy, Retention};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

const HOUR: u64 = 3_600_000;

#[derive(Clone)]
struct Rng(u64);
impl Rng {
    fn below(&mut self, n: u64) -> u64 {
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
#[derive(Clone, Debug)]
enum Step {
    /// A content write (`op` picks the aspect and shape) by `by` on thing `t`.
    Write { by: usize, t: usize, op: u8, k: u8, v: u8 },
    /// `member`'s edge on `t` set to `role` (a grant, re-grant or demotion without frontier).
    Edge { by: usize, t: usize, member: usize, role: Option<Role> },
    /// An explicit demotion (removal, or to read) with a frontier as of one of the member's
    /// writes (`at`: 0 before all of them, backdated; the last: now).
    Demote { by: usize, t: usize, member: usize, at: u8, to_read: bool },
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
}

const OPS: u8 = 27;

fn aspect_of(op: u8) -> Ak {
    ak(match op % OPS {
        0 => "/t/reg",
        1 | 2 => "/t/tags",
        3..=5 => "/t/map",
        6 | 7 => "/t/book",
        8 | 9 => "/t/docs",
        10 | 11 => "/t/text",
        12 => "/t/brief",
        13 => "/t/count",
        14 => "/t/list",
        15 => "/t/rec",
        // with a keep bound (deaths count only there): registers, a map under keep at most 0
        // (bodies drop as they die), a kept set, kept writes into a map (nested, removals), a
        // kept text, a kept text in a map entry
        16 => "/t/kept",
        17 => "/t/short",
        18 => "/t/gone",
        19 | 20 => "/t/gonemap",
        21 => "/t/keptset",
        22 | 25 => "/t/map",
        23 | 24 => "/t/text",
        _ => "/t/docs",
    })
}

/// The retention of `op`'s writes when not the default: keep at least 30 min, or at most 30
/// min or 0.
fn keep_of(op: u8) -> Option<Retention> {
    let d = Some(HOUR / 2);
    let at_least = Some(Retention { by: PurgeBy::Author, at_least: Bound { abs: None, rel: d }, at_most: Bound::default() });
    let at_most = |rel| Some(Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs: None, rel: Some(rel) } });
    match op % OPS {
        16 | 21..=26 => at_least,
        17 => at_most(HOUR / 2),
        18..=20 => at_most(0),
        _ => None,
    }
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
        _ => PathOp { path: vec![], op: Op::Set(s(&val)) },
    };
    (aspect_of(op), po)
}

fn random_step(rng: &mut Rng) -> Step {
    let by = rng.below(3) as usize;
    let t = rng.below(8) as usize;
    match rng.below(40) {
        0..=10 => {
            let op = rng.below(OPS as u64) as u8;
            Step::Write { by, t, op, k: rng.below(3) as u8, v: rng.below(10) as u8 }
        }
        11..=13 => Step::Edge { by: rng.pick(&[0, 0, 2]), t, member: rng.pick(&[1, 2]), role: rng.pick(&[None, Some(Role::Read), Some(Role::Write), Some(Role::Write), Some(Role::Admin)]) },
        14..=17 => Step::Demote { by: rng.pick(&[0, 0, 2]), t, member: rng.pick(&[1, 2]), at: rng.below(6) as u8, to_read: rng.below(3) == 0 },
        18 => Step::Leave { by: rng.pick(&[1, 2]), t },
        19 => Step::Roster { by: rng.pick(&[0, 0, 2]), t },
        20..=22 => Step::Compact { by, t, op: rng.below(OPS as u64) as u8 },
        23 | 24 => Step::New { by: rng.pick(&[0, 0, 2]), parent: t, write: rng.below(2) == 0 },
        25..=28 => {
            let other = (by + 1 + rng.below(2) as usize) % 3;
            // one draw: `compact` as before `also` (x % 6 % 3 == x % 3)
            let (k, text, c) = (rng.below(3) as u8, rng.below(2) == 0, rng.below(6));
            Step::Nested { by, other, t, k, text, compact: c % 3 != 0, also: c >= 3 }
        }
        29 => Step::Undo { by, back: rng.below(3) as u8 },
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

/// `member`'s edge on `t` as remove + put (`None`: removed), spec/permissions.md §2.
fn edge_write(t: Tid, member: Tid, role: Option<Role>) -> Mutation {
    let mut m = Mutation::new();
    m.op(t, &osis_schema::core_types::MEMBERS, PathOp { path: vec![], op: Op::Remove(Value::Tid(member)) }).unwrap();
    if let Some(role) = role {
        m.op(t, &osis_schema::core_types::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(member))], op: Op::Set(edge(role).to_value()) }).unwrap();
    }
    m
}

/// A history as played: every commit made, in the order made, and the things.
struct Played {
    packs: Vec<Package>,
    /// Each commit's author peer (3: none of the three).
    authors: Vec<usize>,
    /// How many of `packs` are the setup (identities, G, the first grants).
    base: usize,
    things: Vec<Tid>,
    now: WallMs,
}

/// Plays `steps` on three peers: 0 owns G and gives 1 write and 2 admin on it.
fn play(seed: u64, steps: &[Step]) -> Played {
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
    for st in steps {
        let th = |t: usize| things[t % things.len()];
        let acted = match st.clone() {
            Step::Write { by, t, op, k, v } => {
                let (a, po) = content_op(op, k, v);
                let mut m = Mutation::new();
                if let Some(r) = keep_of(op) {
                    let _ = m.retention(th(t), &a, r);
                }
                if m.op(th(t), &a, po).is_ok() && lp.peers[by].commit(m).is_ok_and(|x| x.is_some()) {
                    marks[by].push(lp.peers[by].engine.now());
                }
                Some(by)
            }
            Step::Edge { by, t, member, role } => {
                let _ = lp.peers[by].commit(edge_write(th(t), ids[member], role));
                Some(by)
            }
            Step::Demote { by, t, member, at, to_read } => {
                let t = th(t);
                let mut below = BTreeSet::from([t]);
                loop {
                    let more: Vec<Tid> = parent.iter().filter(|(c, p)| below.contains(p) && !below.contains(c)).map(|(c, _)| *c).collect();
                    if more.is_empty() {
                        break;
                    }
                    below.extend(more);
                }
                let ms = &marks[member];
                let as_of = match (at as usize).checked_sub(1) {
                    None => WallMs(ms.first().map_or(T0.0, |x| x.0 - 1)),
                    Some(i) => ms.get(i).copied().unwrap_or_else(|| lp.peers[by].engine.now()),
                };
                let scope = DemotionScope { membership: BTreeMap::from([(ids[member], BTreeSet::from([t]))]), content: BTreeMap::from([(ids[member], below)]) };
                if let Ok(f) = lp.peers[by].engine.frontier(&scope, as_of) {
                    let mut m = edge_write(t, ids[member], to_read.then_some(Role::Read));
                    m.frontier(f.to_value());
                    let _ = lp.peers[by].commit(m);
                }
                Some(by)
            }
            Step::Leave { by, t } => {
                let mut m = Mutation::new();
                m.op(th(t), &osis_schema::core_types::MEMBERS, PathOp { path: vec![], op: Op::Remove(Value::Tid(ids[by])) }).unwrap();
                let _ = lp.peers[by].commit(m);
                Some(by)
            }
            Step::Roster { by, t } => {
                let _ = lp.peers[by].engine.roster_snapshot(&th(t), None);
                Some(by)
            }
            Step::Compact { by, t, op } => {
                let _ = lp.peers[by].engine.snapshot(&th(t), &aspect_of(op));
                Some(by)
            }
            Step::New { by, parent: p, write } => {
                let owner = th(p);
                let mut m = Mutation::new();
                let t = lp.peers[by].engine.new_thing(&mut m, owner);
                if write {
                    m.set(t, &REG, &s("n")).unwrap();
                }
                if lp.peers[by].commit(m).is_ok_and(|x| x.is_some()) {
                    things.push(t);
                    parent.insert(t, owner);
                }
                Some(by)
            }
            Step::Nested { by, other, t, k, text, compact, also } => {
                let (put, inner) = if text { (8, 8) } else { (3, 4) };
                let (a, po) = content_op(put, k, 1);
                let mut m = Mutation::new();
                if also {
                    let _ = m.set(th(t), &REG, &s("also"));
                }
                if m.op(th(t), &a, po).is_ok() && let Ok(Some(id)) = lp.peers[by].commit(m) {
                    marks[by].push(lp.peers[by].engine.now());
                    let pk = lp.peers[by].engine.package(&id).unwrap().unwrap();
                    lp.deliver(other, &pk).unwrap();
                    lp.peers[other].clock.advance(1);
                    let (a, po) = content_op(inner, k, 7);
                    let mut m = Mutation::new();
                    if m.op(th(t), &a, po).is_ok() && lp.peers[other].commit(m).is_ok_and(|x| x.is_some()) {
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
                    let _ = lp.peers[by].engine.revert(&id);
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
            Step::Advance { who, ms } => {
                match who {
                    Some(i) => lp.peers[i].clock.advance(ms),
                    None => lp.advance(ms),
                }
                None
            }
        };
        if let Some(i) = acted {
            collect(&mut lp, i, &mut seen, &mut packs, &mut authors, &mut own);
        }
    }
    // the fresh nodes' clock: the latest of the writers' (nothing parks for drift)
    let now = lp.peers.iter().map(|p| p.engine.now()).max().unwrap();
    Played { packs, authors, base, things, now }
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
    /// membership commit, a creation, or one not played): a recompute plays those at the
    /// snapshot, not at their own `ts`, so the oracle does not judge them.
    carried: BTreeSet<(Tid, Ak)>,
}

fn oracle(played: &Played, held: &[usize]) -> Oracle {
    let mut p = Peer::new(FRESH, played.now).unwrap();
    p.engine.keep_bodies(true);
    for &i in held {
        let pk = &played.packs[i];
        let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    let mut aspects = BTreeSet::new();
    for id in p.engine.commit_ids() {
        aspects.extend(p.engine.header(&id).into_iter().flat_map(|h| h.aspects.iter().map(|a| (a.tid, a.ak.clone())).collect::<Vec<_>>()));
    }
    // carried writes whose own commit is not held: the oracle takes those commits too where
    // they are plain writes (no membership part, no creation), so its recompute plays them at
    // their own `ts`; more superseders date no later, so `dating` stays sound
    let want: BTreeSet<(Tid, osis_base::Ts)> = aspects.iter().flat_map(|(t, a)| p.engine.carried_writes(t, a)).collect();
    if !want.is_empty() {
        let whole = deliver(played, &(0..played.packs.len()).collect::<Vec<_>>());
        for (i, pk) in played.packs.iter().enumerate() {
            let Some(h) = whole.engine.header(&pk.id) else { continue };
            if !held.contains(&i) && want.contains(&(h.author, h.ts)) && !h.kind.is_membership() && h.kind.has_own_writes() && h.aspects.iter().all(|a| a.ak.as_str() != "/created") {
                let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
            }
        }
    }
    let carried: BTreeSet<(Tid, Ak)> = aspects.iter().filter(|(t, a)| !p.engine.carried_writes(t, a).is_empty()).cloned().collect();
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
    let (mine, _) = facts_of(&[("facts", facts_text(&mut p.engine))]);
    let (theirs, inv) = facts_of(&[("facts", o.facts.clone())]);
    let flipped: BTreeSet<(String, String)> = theirs.keys().filter(|k| mine.get(*k).is_some_and(|m| flip(&theirs, &mine, &inv, k) && m.held != theirs[*k].held)).map(|k| (k.1.clone(), k.2.clone())).collect();
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
            let what = format!("{id:?} {:?} {}: here {x:?}, earliest superseders {y:?}", a.tid, a.ak.as_str());
            if e.holds_body(&id, &a.tid, &a.ak) {
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
            let held = e.holds_body(&id, &a.tid, &a.ak);
            let _ = writeln!(facts, "{id:?}|{:?}|{}|{at_most}|{held}|{valid}|{:?}|{approx}", a.tid, a.ak.as_str(), h.ts);
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

/// What a node holding `packs` judges and reads now, as text, by part: reads and states of every
/// aspect, rosters, pending set, timelines, body facts. Deaths are the node's own (`dating`).
fn judged_now(p: &mut Peer, things: &[Tid]) -> Vec<(&'static str, String)> {
    let e = &mut p.engine;
    let mut reads = String::new();
    let mut states = String::new();
    // every aspect held (fresh nodes share a seed, so their own things agree too)
    let all = e.all_aspects().unwrap();
    for (t, a) in &all {
        let (t, a) = (*t, a.clone());
        let _ = writeln!(reads, "{t:?} {} {:?}", a.as_str(), e.get(&t, &a).unwrap());
        let _ = writeln!(states, "{t:?} {} {:?}", a.as_str(), e.state(&t, &a).unwrap());
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
    vec![("reads", reads), ("states", states), ("rosters", rosters), ("pending", pending.join("\n")), ("timelines", perm), ("timelines from scratch", scratch), ("facts", facts)]
}

/// The persisted index as a day after `played.now` (every keep-at-most bound past: which bodies
/// a node dropped before is its own dating, `dating`). Moves the node's clock there.
fn index_later(p: &mut Peer, played: &Played) -> String {
    let later = WallMs(played.now.0 + 24 * HOUR);
    if p.engine.now().0 < later.0 {
        p.clock.set(later);
    }
    p.engine.tick().unwrap();
    p.engine.index_digest()
}

/// `judged_now`, then `index_later` (moves the node's clock).
fn judged(p: &mut Peer, played: &Played) -> Vec<(&'static str, String)> {
    let mut v = judged_now(p, &played.things);
    v.insert(0, ("index", index_later(p, played)));
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
}

type BodyKey = (String, String, String);

/// A `Ts(n)`'s n.
fn ts_of(t: &str) -> u64 {
    t.trim_start_matches("Ts(").trim_end_matches(')').parse().unwrap()
}

/// The bodies' facts, and per (thing, aspect) its invalid writes: (commit or carrying snapshot, `ts`).
fn facts_of(j: &[(&'static str, String)]) -> (Facts, Invalid) {
    let text = &j.iter().find(|x| x.0 == "facts").unwrap().1;
    let (mut out, mut inv) = (BTreeMap::new(), BTreeMap::<_, Vec<_>>::new());
    for l in text.lines() {
        let f: Vec<&str> = l.split('|').collect();
        if f[0] == "inv" {
            inv.entry((f[1].into(), f[2].into())).or_default().push((f[3].into(), ts_of(f[4])));
            continue;
        }
        let b = |i: usize| f[i] == "true";
        out.insert((f[0].into(), f[1].into(), f[2].into()), Fact { at_most: b(3), held: b(4), valid: b(5), ts: ts_of(f[6]), approx: b(7) });
    }
    (out, inv)
}

/// Facts per body and invalid writes per aspect (`facts_of`).
type Facts = BTreeMap<BodyKey, Fact>;
type Invalid = BTreeMap<(String, String), Vec<(String, u64)>>;

/// The drop-before-flip difference on body `k` between nodes with facts `w` and `g`: held at
/// one node only, under keep at most, with its own write invalid (its delta, or a write it
/// carries) or an invalid write of its aspect stamped at or after it (one that may have killed
/// it).
fn flip(w: &Facts, g: &Facts, inv: &Invalid, k: &BodyKey) -> bool {
    let (w, g) = (&w[k], &g[k]);
    let own = !w.valid || inv.get(&(k.1.clone(), k.2.clone())).is_some_and(|v| v.iter().any(|(c, _)| *c == k.0));
    let killer = inv.get(&(k.1.clone(), k.2.clone())).is_some_and(|v| v.iter().any(|(c, ts)| *c != k.0 && *ts >= w.ts));
    w.held != g.held && w.at_most && (own || killer)
}

/// Whether two nodes holding the same commits judged alike (`None`), else the first difference.
/// Values, validity, rosters, pending sets, timelines and the index a day later are compared
/// exactly; held bodies too, except what spec/commits.md §5 allows: a body under a relative
/// keep at most (deaths are dated per node; `dating` checks them, and that a dead body under
/// at most 0 with no live write is dropped), and the drop before a
/// validity flip: a body dropped at one node and held at the other where a write of its aspect
/// is invalid (a drop made before its killer, or its own write, turned invalid stays): its
/// commit line's dropped parts, and that aspect's reads and state (where the kept body's write
/// is back). Anything else is a failure.
fn alike(want: &[(&'static str, String)], got: &[(&'static str, String)]) -> Option<String> {
    let ((wf, inv), (gf, _)) = (facts_of(want), facts_of(got));
    if wf.keys().ne(gf.keys()) {
        return first_diff(&want[want.len() - 1..], &got[got.len() - 1..]);
    }
    let flip = |k: &BodyKey| flip(&wf, &gf, &inv, k);
    let flipped: BTreeSet<(String, String)> = wf.keys().filter(|k| flip(k)).map(|k| (k.1.clone(), k.2.clone())).collect();
    if let Some(k) = wf.keys().find(|k| wf[*k].held != gf[*k].held && !wf[*k].approx && !flip(k)) {
        return Some(format!("body {k:?} held {} vs {}", wf[k].held, gf[k].held));
    }
    let no_dropped = |l: &str| -> String {
        match (l.find('{'), l.find('}')) {
            (Some(i), Some(j)) if i < j => format!("{}{}", &l[..i], &l[j + 1..]),
            _ => l.into(),
        }
    };
    let allowed = |name: &str, x: &str, y: &str| -> bool {
        match name {
            "index" if x.starts_with("commit ") => {
                let id = x.split(' ').nth(1).unwrap_or("");
                let changed: Vec<&BodyKey> = wf.keys().filter(|k| k.0 == id && wf[*k].held != gf[*k].held).collect();
                no_dropped(x) == no_dropped(y) && !changed.is_empty() && changed.iter().all(|k| flip(k))
            }
            _ => false,
        }
    };
    for ((name, x), (_, y)) in want.iter().zip(got) {
        if x == y || *name == "facts" {
            continue;
        }
        let (xl, yl): (Vec<&str>, Vec<&str>) = (x.lines().collect(), y.lines().collect());
        let fail = |i: usize| Some(format!("{name} line {i}:\n  want {}\n  got  {}", xl.get(i).unwrap_or(&"<end>"), yl.get(i).unwrap_or(&"<end>")));
        if *name == "reads" || *name == "states" {
            // keyed by thing and aspect: one may lack an aspect the other shows
            let keyed = |ls: &[&str]| -> BTreeMap<(String, String), String> {
                ls.iter().map(|l| {
                    let f: Vec<&str> = l.splitn(3, ' ').collect();
                    ((f[0].into(), f.get(1).copied().unwrap_or("").into()), f.get(2).copied().unwrap_or("").into())
                }).collect()
            };
            let (a, b) = (keyed(&xl), keyed(&yl));
            for k in a.keys().chain(b.keys()) {
                if a.get(k) != b.get(k) && !flipped.contains(k) {
                    return Some(format!("{name} on {k:?}:\n  want {:?}\n  got  {:?}", a.get(k), b.get(k)));
                }
            }
            continue;
        }
        if xl.len() != yl.len() {
            return first_diff(&[(name, x.clone())], &[(name, y.clone())]);
        }
        for (i, (p, q)) in xl.iter().zip(&yl).enumerate() {
            if p != q && !allowed(name, p, q) {
                return fail(i);
            }
        }
    }
    None
}

const FRESH: u64 = 0x5eed_f00d;

/// A fresh node given `packs` in `order`.
fn deliver(played: &Played, order: &[usize]) -> Peer {
    let mut p = Peer::new(FRESH, played.now).unwrap();
    // every component's walk saved, so reopens restore them
    p.engine.set_walk_cache_min(1);
    for &i in order {
        let pk = &played.packs[i];
        let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    p
}

/// A fresh node given `packs` in `order`, each commit with parts on several aspects first with
/// those of one of them only (a seeded pick), the rest of it as late parts at the end, in
/// reverse (spec/commits.md §4: a late delta joins on arrival).
fn deliver_split(played: &Played, order: &[usize], rng: &mut Rng) -> Peer {
    let mut p = Peer::new(FRESH, played.now).unwrap();
    p.engine.set_walk_cache_min(1);
    let mut late = Vec::new();
    for &i in order {
        let pk = &played.packs[i];
        let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        let ais: BTreeSet<usize> = b.parts.iter().map(|x| x.ai).collect();
        if ais.len() > 1 {
            let keep = ais.iter().copied().nth(rng.below(ais.len() as u64) as usize).unwrap();
            b.parts.retain(|x| x.ai == keep);
            late.push(i);
        }
        let _ = p.engine.ingest(&b.encode(), pk.blobs.clone());
    }
    for &i in late.iter().rev() {
        let pk = &played.packs[i];
        let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    let _ = p.engine.reexamine();
    p
}

fn first_diff(a: &[(&'static str, String)], b: &[(&'static str, String)]) -> Option<String> {
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
}

const SMALL: Cfg = Cfg { all_up_to: 4, every_held: false, random: 2, subsets: 1, split: 2, par_orders: false, threads: 1 };
const LARGE: Cfg = Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, par_orders: false, threads: 1 };
/// Every order of the whole set and 2 partial sets (`OSIS_ORDER_ALL_HELD`: of every held set),
/// every order with late parts too (6 commits: up to 720 orders).
const EXHAUST: Cfg = Cfg { all_up_to: 6, every_held: true, random: 0, subsets: 2, split: usize::MAX, par_orders: true, threads: 1 };
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

/// Checks one history; the number of orders tried, or the first mismatch found, described (a
/// panic counts, so it shrinks).
fn check(seed: u64, steps: &[Step], cfg: Cfg) -> Result<usize, String> {
    caught(|| check_orders(seed, steps, cfg))
}

fn check_orders(seed: u64, steps: &[Step], cfg: Cfg) -> Result<usize, String> {
    let played = play(seed, steps);
    let mut rng = Rng(seed ^ 0x0de5_ab1e | 1);
    let mut tried = 0;
    let mut full: Option<Vec<(&'static str, String)>> = None;
    let n = played.packs.len();
    let split = played.packs.iter().any(|pk| osis_commit::CommitBlob::decode(&pk.bytes).is_ok_and(|b| b.parts.iter().any(|x| x.ai != b.parts[0].ai)));
    // `OSIS_ORDER_ALL_HELD`: every held set in exhaustive mode (about 2.3x the time)
    let subsets = if cfg.every_held && std::env::var("OSIS_ORDER_ALL_HELD").is_ok() { usize::MAX } else { cfg.subsets };
    for held in held_sets(&played, subsets, &mut rng) {
        let of = format!("held {held:?} of {n} commits (base {})", played.base);
        let o = oracle(&played, &held);
        // a partial set, then the rest (both ways), ends where the whole set does
        if let Some(f) = &full {
            let rest: Vec<usize> = (0..n).filter(|i| !held.contains(i)).collect();
            for order in [held.iter().chain(&rest).copied().collect::<Vec<_>>(), held.iter().chain(rest.iter().rev()).copied().collect()] {
                let mut p = deliver(&played, &order);
                if let Some(d) = alike(f, &judged(&mut p, &played)) {
                    return Err(format!("{of}, then the rest: order {order:?} vs the whole set as made: {d}"));
                }
            }
        }
        let orders = orders(&played, &held, cfg, &mut rng);
        tried += orders.len();
        // the reference, as made: its deaths dated as the spec allows, a reopen from the
        // persisted index and a rebuild judge alike (an open re-examines what pends)
        let mut p = deliver(&played, &orders[0]);
        if let Some(d) = dating(&mut p, &o, played.now) {
            return Err(format!("{of}, as made: {d}"));
        }
        let now = judged_now(&mut p, &played.things);
        p.engine.reload().unwrap();
        p.engine.reexamine().unwrap();
        if let Some(d) = first_diff(&now, &judged_now(&mut p, &played.things)) {
            return Err(format!("{of}, as made: reopen differs: {d}"));
        }
        p.engine.rebuild_index().unwrap();
        p.engine.reexamine().unwrap();
        // a rebuild recomputes deaths from the held bodies: dated otherwise, never earlier
        if let Some(d) = alike(&now, &judged_now(&mut p, &played.things)).or_else(|| dating(&mut p, &o, played.now)) {
            return Err(format!("{of}, as made: rebuild differs: {d}"));
        }
        let mut want = now;
        want.insert(0, ("index", index_later(&mut p, &played)));
        if std::env::var("OSIS_ORDER_STATS").is_ok() {
            let idx = &want[0].1;
            let invalid = idx.lines().filter(|l| l.starts_with("commit ") && l.contains("false")).count();
            let carried = idx.lines().find(|l| l.starts_with("carried ")).map_or(0, |l| l.matches("invalid: [").count() - l.matches("invalid: []").count());
            eprintln!("seed {seed}: {} of {} commits held ({} base), {} with an invalid part, {} carried groups with invalid writes, {} pending, {} things", held.len(), n, played.base, invalid, carried, want[4].1.lines().count(), played.things.len());
        }
        if full.is_none() {
            full = Some(want.clone());
        }
        // order `k` alike (and alike after a reopen), or with late parts (split by `rng`) alike
        let one = |k: usize, split_rng: Option<&mut Rng>| -> Result<(), String> {
            let order = &orders[k];
            let vs = format!("{of}: order #0 (as made, want) {held:?} vs order #{k}");
            if let Some(rng) = split_rng {
                let mut p = deliver_split(&played, order, rng);
                return match dating(&mut p, &o, played.now).or_else(|| alike(&want, &judged(&mut p, &played))) {
                    Some(d) => Err(format!("{vs} with late parts (got) {order:?}: {d}")),
                    None => Ok(()),
                };
            }
            let mut p = deliver(&played, order);
            if let Some(d) = dating(&mut p, &o, played.now) {
                return Err(format!("{of}, order #{k} {order:?}: {d}"));
            }
            let mut got = judged_now(&mut p, &played.things);
            p.engine.reload().unwrap();
            p.engine.reexamine().unwrap();
            if let Some(d) = first_diff(&got, &judged_now(&mut p, &played.things)) {
                return Err(format!("{of}, order #{k} {order:?}: reopen differs: {d}"));
            }
            got.insert(0, ("index", index_later(&mut p, &played)));
            match alike(&want, &got) {
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
    Ok(tried)
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
            match rng.below(20) {
                0..=6 => Step::Write { by: if (17..=20).contains(&op) || rng.below(3) == 0 { 0 } else { 1 + rng.below(2) as usize }, t, op, k: rng.below(2) as u8, v: rng.below(10) as u8 },
                7 | 8 => Step::Compact { by: rng.pick(&[0, 0, by]), t, op },
                9 | 10 => Step::Undo { by: rng.pick(&[0, by]), back: rng.below(3) as u8 },
                11 | 12 => Step::Demote { by: rng.pick(&[0, 0, 2]), t, member: rng.pick(&[1, 2]), at: rng.below(4) as u8, to_read: rng.below(3) == 0 },
                13 => Step::Edge { by: 0, t, member: rng.pick(&[1, 2]), role: rng.pick(&[None, Some(Role::Read), Some(Role::Write)]) },
                14 => Step::Nested { by, other: (by + 1 + rng.below(2) as usize) % 3, t, k: rng.below(2) as u8, text: rng.below(2) == 0, compact: rng.below(2) == 0, also: rng.below(3) == 0 },
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
        let p = play(seed, &steps[..k]);
        p.packs.len() - p.base <= cfg.all_up_to
    };
    let (mut lo, mut hi) = (0, steps.len());
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if fits(mid) { lo = mid } else { hi = mid - 1 }
    }
    steps[..lo].to_vec()
}

/// Checks the histories `gen` makes from `seeds` (one seed per task, a thread per core), shrinks
/// every failing one and reports them all, each with the command that replays it.
/// `OSIS_ORDER_SEED=n` runs only seed n; `OSIS_ORDER_START=n`, `OSIS_ORDER_SEEDS=n` and
/// `OSIS_ORDER_LEN=n` set the first seed, how many seeds and steps; a seed's history and orders
/// depend on the seed, the length and the test alone.
fn run(name: &str, seeds: std::ops::Range<u64>, len: usize, cfg: Cfg, generate: fn(u64, usize, Cfg) -> Vec<Step>) {
    let env = |k: &str| std::env::var(k).ok().and_then(|x| x.parse::<u64>().ok());
    let only = env("OSIS_ORDER_SEED");
    let start = env("OSIS_ORDER_START").unwrap_or(seeds.start);
    let seeds = start..env("OSIS_ORDER_SEEDS").map_or(start + (seeds.end - seeds.start), |n| start + n);
    let len = env("OSIS_ORDER_LEN").map_or(len, |n| n as usize);
    let seeds: Vec<u64> = match only {
        Some(o) => vec![o],
        None => seeds.collect(),
    };
    let settings: Vec<String> = std::env::vars().filter(|(k, _)| k.starts_with("OSIS_ORDER_")).map(|(k, v)| format!("{k}={v}")).collect();
    let t0 = std::time::Instant::now();
    // seeds on a thread per core; with fewer seeds than cores, a seed's orders share the rest
    let outer = threads("OSIS_ORDER_THREADS").min(seeds.len()).max(1);
    let cfg = Cfg { threads: if cfg.par_orders { threads("OSIS_ORDER_THREADS").div_ceil(outer) } else { 1 }, ..cfg };
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
        (r.unwrap_or(0), fail)
    });
    let tried: usize = results.iter().map(|x| x.0).sum();
    let fails: Vec<String> = results.into_iter().filter_map(|x| x.1).collect();
    eprintln!("order::{name}: {} seeds from {}, {len} steps, {tried} orders in the passing ones, {} failing, {:.1} s (settings: {settings:?})", seeds.len(), seeds.first().copied().unwrap_or(0), fails.len(), t0.elapsed().as_secs_f64());
    assert!(fails.is_empty(), "{} of {} histories judged differently by arrival order (settings: {settings:?}):\n{}", fails.len(), seeds.len(), fails.join("\n\n"));
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

// spec/crdt.md §4.8, order seed 7855 (exhaustive, shrunk): W1 and W2 put one `/t/gonemap` key, U
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
    let h = vec![Nested { by: 2, other: 1, t: 6, k: 0, text: false, compact: true, also: false }, New { by: 2, parent: 1, write: true }, Send { from: 1, to: 0, back: 1 }, Edge { by: 0, t: 2, member: 2, role: Some(Role::Read) }];
    cases.push((1038, h, LARGE));
    // seed 1558: C lowers its own edge (a nested write into the roster snapshot's entry) with a
    // clock behind A's, so it sorts before that snapshot: an open read it first and left it
    // waiting for the entry's creation, which a fresh apply had resolved
    let h = vec![Demote { by: 0, t: 5, member: 1, at: 4, to_read: false }, Roster { by: 0, t: 4 }, Sync { from: 0, to: 1 }, Demote { by: 0, t: 6, member: 2, at: 1, to_read: false }, Sync { from: 1, to: 2 }, Write { by: 0, t: 7, op: 7, k: 0, v: 4 }, Send { from: 0, to: 2, back: 0 }, Edge { by: 2, t: 4, member: 2, role: Some(Role::Read) }];
    cases.push((1558, h, LARGE));
    // seed 1053 (spec/crdt.md §4.8): two writes of a keep-at-most-0 register with one `ts`; the
    // later by commit ID lost by dot and died on arrival, and its drop went before its own
    // record was written, which then held it undropped (a reopen disagreed)
    let h = vec![Write { by: 2, t: 4, op: 18, k: 2, v: 4 }, Write { by: 1, t: 6, op: 18, k: 1, v: 4 }];
    cases.push((1053, h, LARGE));
    // seed 1173 (spec/crdt.md §4.8): peer 0's kept write inside peer 1's entry dies at peer 2's;
    // peer 1's creation arriving invalid un-merged both, and nothing replayed the deaths
    let h = vec![Nested { by: 1, other: 2, t: 7, k: 1, text: false, compact: false, also: false }, Send { from: 1, to: 0, back: 0 }, Edge { by: 2, t: 2, member: 1, role: Some(Role::Read) }, Write { by: 0, t: 0, op: 22, k: 1, v: 9 }];
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
    let h = vec![Nested { by: 1, other: 2, t: 0, k: 2, text: false, compact: true, also: true }, Sync { from: 2, to: 0 }, Write { by: 0, t: 1, op: 22, k: 2, v: 1 }, Compact { by: 0, t: 1, op: 25 }, Edge { by: 0, t: 3, member: 2, role: Some(Role::Read) }, New { by: 0, parent: 5, write: false }, New { by: 0, parent: 6, write: true }];
    cases.push((12161, h, LARGE));
    let h = vec![Edge { by: 0, t: 5, member: 1, role: Some(Role::Write) }, Nested { by: 0, other: 2, t: 2, k: 1, text: false, compact: true, also: true }, Edge { by: 0, t: 1, member: 2, role: None }, Write { by: 1, t: 5, op: 6, k: 1, v: 4 }, Edge { by: 2, t: 3, member: 1, role: Some(Role::Write) }, Write { by: 1, t: 4, op: 16, k: 0, v: 7 }, Nested { by: 1, other: 0, t: 0, k: 1, text: false, compact: true, also: true }];
    cases.push((12236, h, LARGE));
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

// spec/commits.md §5 (dropping a body destroys every local index entry derived from it),
// spec/requirements.md Decentralization (a rebuild judges alike): seed 1291, a keep-at-most-0
// write, its compaction snapshot, the write undone: both bodies drop dead, and the snapshot's
// frontier stayed in `Core::snapshots` incrementally but not after a rebuild of the index.
#[test]
fn dropped_snapshot_rebuilds_alike_spec_commits_5() {
    use Step::*;
    let h = vec![Write { by: 0, t: 2, op: 18, k: 2, v: 3 }, Compact { by: 0, t: 3, op: 18 }, Demote { by: 0, t: 3, member: 1, at: 3, to_read: false }, Undo { by: 0, back: 2 }];
    check(1291, &h, LARGE).unwrap();
    // the dropped snapshot keeps no frontier: it dropped dead, so it stays dead
    let played = play(1291, &h);
    let mut p = deliver(&played, &(0..played.packs.len()).collect::<Vec<_>>());
    let snap = p.engine.commit_ids().into_iter().find(|id| p.engine.header(id).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot)).unwrap();
    let a = p.engine.header(&snap).unwrap().aspects[0].clone();
    assert!(!p.engine.holds_body(&snap, &a.tid, &a.ak), "the snapshot dropped dead");
    assert!(!p.engine.body_live(&snap, &a.tid, &a.ak).unwrap(), "the undo reset it");
}

// spec/permissions.md §5.2 (an invalid snapshot gives none of its writes), spec/crdt.md §4.6:
// order seed 1006, shrunk. Bob's snapshot (invalid after his demotion) carries Alice's entry
// creation, held before her commit: the un-merge of its dots strips Alice's later write nested in
// that entry; her creating commit arriving last must give it back (`refill` rebuilds).
#[test]
fn invalid_snapshot_owner_late_seed_1006() {
    let h = vec![Step::Edge { by: 0, t: 0, member: 2, role: None }, Step::Nested { by: 0, other: 1, t: 4, k: 2, text: false, compact: true, also: true }, Step::Write { by: 2, t: 6, op: 12, k: 1, v: 2 }, Step::Write { by: 0, t: 1, op: 18, k: 2, v: 6 }, Step::Demote { by: 0, t: 2, member: 1, at: 5, to_read: true }, Step::Write { by: 0, t: 0, op: 3, k: 2, v: 9 }];
    check(1006, &h, Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, par_orders: false, threads: 1 }).unwrap();
}

// as above, order seed 1042, shrunk (an in-place un-merge differed from a rebuild).
#[test]
fn invalid_snapshot_owner_late_seed_1042() {
    let h = vec![Step::Nested { by: 0, other: 2, t: 1, k: 0, text: false, compact: true, also: true }, Step::New { by: 0, parent: 3, write: false }, Step::New { by: 0, parent: 6, write: false }, Step::Sync { from: 2, to: 1 }, Step::Demote { by: 2, t: 3, member: 1, at: 3, to_read: true }, Step::Nested { by: 2, other: 1, t: 0, k: 1, text: false, compact: true, also: true }];
    check(1042, &h, Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, par_orders: false, threads: 1 }).unwrap();
}

// spec/commits.md §5 (a keep-at-most drop is final): histories the harness found with members
// writing keep-at-most ops (shrunk), where a body is dropped at one node and held at another:
// seeds 1053, 1024 (its killer turned invalid), 1085, 1200 (its own write turned invalid, the op
// 17 bound passed). They pass `alike`, though the judged texts differ; the same held-or-dropped
// difference on an aspect with no invalid write fails it.
#[test]
fn drop_before_flip_tolerated_spec_commits_5() {
    use Step::*;
    let flips = vec![
        (1053, vec![Write { by: 2, t: 4, op: 18, k: 2, v: 4 }, Write { by: 1, t: 6, op: 18, k: 1, v: 4 }, Demote { by: 0, t: 4, member: 2, at: 3, to_read: false }]),
        (1024, vec![Write { by: 0, t: 7, op: 18, k: 0, v: 9 }, Edge { by: 0, t: 0, member: 2, role: Some(Role::Read) }, Write { by: 2, t: 4, op: 18, k: 2, v: 4 }]),
        (1085, vec![Write { by: 2, t: 6, op: 17, k: 2, v: 7 }, Write { by: 0, t: 6, op: 17, k: 1, v: 4 }, Demote { by: 0, t: 0, member: 2, at: 0, to_read: false }, Advance { who: None, ms: 5203966 }]),
        (1200, vec![Demote { by: 0, t: 7, member: 1, at: 5, to_read: true }, Write { by: 1, t: 5, op: 17, k: 0, v: 1 }, Write { by: 0, t: 5, op: 17, k: 0, v: 5 }, Advance { who: None, ms: 5183786 }]),
    ];
    for (seed, h) in &flips {
        check(*seed, h, LARGE).unwrap_or_else(|e| panic!("seed {seed}: {e}"));
    }
    // seed 1053 as made against reversed: they differ, only by the tolerated drop
    let (seed, h) = &flips[0];
    let played = play(*seed, h);
    let made: Vec<usize> = (0..played.packs.len()).collect();
    let want = judged(&mut deliver(&played, &made), &played);
    let got = judged(&mut deliver(&played, &made.iter().rev().copied().collect::<Vec<_>>()), &played);
    assert!(first_diff(&want, &got).is_some(), "the orders differ");
    assert_eq!(alike(&want, &got), None);
    // with every write judged valid, the same difference is a failure
    // with every write judged valid, or the invalid ones stamped before every body (none can
    // have killed it), the same difference is a failure
    let edit = |j: &[(&'static str, String)], f: &dyn Fn(Vec<&str>) -> Option<String>| -> Vec<(&'static str, String)> { j.iter().map(|(n, t)| (*n, if *n == "facts" { t.lines().filter_map(|l| f(l.split('|').collect())).collect::<Vec<_>>().join("\n") } else { t.clone() })).collect() };
    let all_valid = |f: Vec<&str>| (f[0] != "inv").then(|| format!("{}|true|{}", f[..5].join("|"), f[6..].join("|")));
    assert!(alike(&edit(&want, &all_valid), &edit(&got, &all_valid)).is_some(), "a drop difference with no invalid write passed");
    let early = |mut f: Vec<&str>| {
        if f[0] == "inv" {
            f[4] = "Ts(0)";
        }
        Some(f.join("|"))
    };
    assert!(edit(&want, &early).iter().any(|(n, t)| *n == "facts" && t.contains("inv|")), "an invalid write");
    assert!(alike(&edit(&want, &early), &edit(&got, &early)).is_some(), "a drop difference with only earlier invalid writes passed");
}

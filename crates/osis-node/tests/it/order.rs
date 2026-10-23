#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Arrival-order differential (spec/requirements.md Decentralization: a node's state and its
//! judgment of every write are functions of the data it holds, never of arrival order;
//! spec/permissions.md §5, §5.2; spec/crdt.md §4.6). Random histories over three writers
//! (grants, demotions with frontiers before, inside and after the demoted writes, re-grants,
//! self-removals, roster and compaction snapshots, things created under things in later
//! commits, writes inside map entries, struct fields and nested texts, undo, expiry, partial
//! syncs) are delivered, as one held set, to fresh nodes in several arrival orders: every
//! order must give the same per-delta verdicts, reads and states of every aspect, rosters,
//! pending set, persisted index and timelines, and a reopen and a rebuild must give them too.

use crate::common;
use common::*;
use osis_core::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_node::local_peer::{LocalPeer, Package, Peer};
use osis_perm::DemotionScope;
use osis_schema::Codec;
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
    /// another's write nested under a creation that may be invalid.
    Nested { by: usize, other: usize, t: usize, k: u8, text: bool, compact: bool },
    /// `by` undoes one of its last commits.
    Undo { by: usize, back: u8 },
    /// Every commit `from` holds to `to`.
    Sync { from: usize, to: usize },
    /// One of `from`'s last commits to `to`.
    Send { from: usize, to: usize, back: u8 },
    /// Time passes (`who`: one peer's clock, else every one).
    Advance { who: Option<usize>, ms: u64 },
}

const OPS: u8 = 16;

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
        _ => "/t/rec",
    })
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
        _ => PathOp { path: vec![PathSeg::Field(0)], op: Op::Set(s(&val)) },
    };
    (aspect_of(op), po)
}

fn random_step(rng: &mut Rng) -> Step {
    let by = rng.below(3) as usize;
    let t = rng.below(8) as usize;
    match rng.below(40) {
        0..=10 => Step::Write { by, t, op: rng.below(OPS as u64) as u8, k: rng.below(3) as u8, v: rng.below(10) as u8 },
        11..=13 => Step::Edge { by: rng.pick(&[0, 0, 2]), t, member: rng.pick(&[1, 2]), role: rng.pick(&[None, Some(Role::Read), Some(Role::Write), Some(Role::Write), Some(Role::Admin)]) },
        14..=17 => Step::Demote { by: rng.pick(&[0, 0, 2]), t, member: rng.pick(&[1, 2]), at: rng.below(6) as u8, to_read: rng.below(3) == 0 },
        18 => Step::Leave { by: rng.pick(&[1, 2]), t },
        19 => Step::Roster { by: rng.pick(&[0, 0, 2]), t },
        20..=22 => Step::Compact { by, t, op: rng.below(OPS as u64) as u8 },
        23 | 24 => Step::New { by: rng.pick(&[0, 0, 2]), parent: t, write: rng.below(2) == 0 },
        25..=28 => {
            let other = (by + 1 + rng.below(2) as usize) % 3;
            Step::Nested { by, other, t, k: rng.below(3) as u8, text: rng.below(2) == 0, compact: rng.below(3) != 0 }
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
                if m.op(th(t), &a, po).is_ok() && lp.peers[by].commit(m).is_ok_and(|x| x.is_some()) {
                    marks[by].push(lp.peers[by].engine.now());
                }
                Some(by)
            }
            Step::Edge { by, t, member, role } => {
                let mut m = Mutation::new();
                let po = match role {
                    Some(role) => PathOp { path: vec![PathSeg::Key(Value::Tid(ids[member]))], op: Op::Set(edge(role).to_value()) },
                    None => PathOp { path: vec![], op: Op::Remove(Value::Tid(ids[member])) },
                };
                m.op(th(t), &osis_schema::core_types::MEMBERS, po).unwrap();
                let _ = lp.peers[by].commit(m);
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
                    let mut m = Mutation::new();
                    let po = if to_read {
                        PathOp { path: vec![PathSeg::Key(Value::Tid(ids[member]))], op: Op::Set(edge(Role::Read).to_value()) }
                    } else {
                        PathOp { path: vec![], op: Op::Remove(Value::Tid(ids[member])) }
                    };
                    m.op(t, &osis_schema::core_types::MEMBERS, po).unwrap();
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
            Step::Nested { by, other, t, k, text, compact } => {
                let (put, inner) = if text { (8, 8) } else { (3, 4) };
                let (a, po) = content_op(put, k, 1);
                let mut m = Mutation::new();
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
                    let _ = lp.peers[by].engine.undo(&id);
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

/// What a node holding `packs` judged and reads, as text, by part.
fn judged(p: &mut Peer, things: &[Tid]) -> Vec<(&'static str, String)> {
    let e = &mut p.engine;
    // held commits are listed in arrival order, which nothing else may show
    let index: String = e.index_digest().lines().filter(|l| !l.starts_with("held ")).map(|l| format!("{l}\n")).collect();
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
    vec![("index", index), ("reads", reads), ("states", states), ("rosters", rosters), ("pending", pending.join("\n")), ("timelines", perm), ("timelines from scratch", scratch)]
}

const FRESH: u64 = 0x5eed_f00d;

/// A fresh node given `packs` in `order`.
fn deliver(played: &Played, order: &[usize]) -> Peer {
    let mut p = Peer::new(FRESH, played.now).unwrap();
    for &i in order {
        let pk = &played.packs[i];
        let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
    }
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

/// The arrival orders of `held` tried: as made (the reference), reversed, every order of the
/// commits after the setup when they are all held and at most `all_up_to`, and `random`
/// shuffles of everything.
fn orders(played: &Played, held: &[usize], all_up_to: usize, random: usize, rng: &mut Rng) -> Vec<Vec<usize>> {
    let n = held.len();
    let mut out = vec![held.to_vec(), held.iter().rev().copied().collect()];
    let rest = played.packs.len() - played.base;
    if n == played.packs.len() && rest <= all_up_to {
        for p in perms(rest) {
            out.push((0..played.base).chain(p.into_iter().map(|i| played.base + i)).collect());
        }
    }
    for _ in 0..random {
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
/// third of them).
fn held_sets(played: &Played, subsets: usize, rng: &mut Rng) -> Vec<Vec<usize>> {
    let n = played.packs.len();
    let mut out = vec![(0..n).collect::<Vec<_>>()];
    for j in 0..subsets {
        let peer = rng.below(3) as usize;
        let keep: Vec<usize> = (0..n).filter(|&i| i < played.base || if j % 2 == 0 { played.authors[i] != peer } else { rng.below(3) != 0 }).collect();
        if !out.contains(&keep) {
            out.push(keep);
        }
    }
    out
}

/// Checks one history; the first mismatch found, described.
fn check(seed: u64, steps: &[Step], all_up_to: usize, random: usize, subsets: usize) -> Result<usize, String> {
    let played = play(seed, steps);
    let mut rng = Rng(seed ^ 0x0de5_ab1e | 1);
    let mut tried = 0;
    for held in held_sets(&played, subsets, &mut rng) {
        let orders = orders(&played, &held, all_up_to, random, &mut rng);
        tried += orders.len();
        let mut want: Option<Vec<(&'static str, String)>> = None;
        for (k, order) in orders.iter().enumerate() {
            let mut p = deliver(&played, order);
            let got = judged(&mut p, &played.things);
            let Some(w) = &want else {
                // the reference: a reopen from the persisted index and a rebuild judge alike
                // (an open re-examines what pends)
                p.engine.reload_index().unwrap();
                p.engine.reexamine().unwrap();
                if let Some(d) = first_diff(&got, &judged(&mut p, &played.things)) {
                    return Err(format!("held {held:?}: reopen differs: {d}"));
                }
                p.engine.rebuild_index().unwrap();
                p.engine.reexamine().unwrap();
                if let Some(d) = first_diff(&got, &judged(&mut p, &played.things)) {
                    return Err(format!("held {held:?}: rebuild differs: {d}"));
                }
                if std::env::var("OSIS_ORDER_STATS").is_ok() {
                    let idx = &got[0].1;
                    let invalid = idx.lines().filter(|l| l.starts_with("commit ") && l.contains("false")).count();
                    let carried = idx.lines().find(|l| l.starts_with("carried ")).map_or(0, |l| l.matches("invalid: [").count() - l.matches("invalid: []").count());
                    eprintln!("seed {seed}: {} of {} commits held ({} base), {} with an invalid part, {} carried groups with invalid writes, {} pending, {} things", held.len(), played.packs.len(), played.base, invalid, carried, got[4].1.lines().count(), played.things.len());
                }
                want = Some(got);
                continue;
            };
            if let Some(d) = first_diff(w, &got) {
                return Err(format!("held {held:?} of {} commits (base {}), order #{k} {order:?}: {d}", played.packs.len(), played.base));
            }
        }
    }
    Ok(tried)
}

/// Drops steps while the history still fails; the shortest failing history found.
fn shrink(seed: u64, mut steps: Vec<Step>, all_up_to: usize, random: usize, subsets: usize) -> (Vec<Step>, String) {
    let mut err = check(seed, &steps, all_up_to, random, subsets).unwrap_err();
    let mut i = 0;
    while i < steps.len() {
        let mut fewer = steps.clone();
        fewer.remove(i);
        match check(seed, &fewer, all_up_to, random, subsets) {
            Err(e) => {
                steps = fewer;
                err = e;
            }
            Ok(_) => i += 1,
        }
    }
    (steps, err)
}

fn history(seed: u64, len: usize) -> Vec<Step> {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    (0..len).map(|_| random_step(&mut rng)).collect()
}

/// `OSIS_ORDER_SEED=n` runs only seed n; `OSIS_ORDER_SEEDS=n` and `OSIS_ORDER_LEN=n` set how
/// many seeds and steps.
fn run(seeds: std::ops::Range<u64>, len: usize, all_up_to: usize, random: usize, subsets: usize) {
    let env = |k: &str| std::env::var(k).ok().and_then(|x| x.parse::<u64>().ok());
    let only = env("OSIS_ORDER_SEED");
    let seeds = seeds.start..env("OSIS_ORDER_SEEDS").map_or(seeds.end, |n| seeds.start + n);
    let len = env("OSIS_ORDER_LEN").map_or(len, |n| n as usize);
    let mut fails = Vec::new();
    let seeds: Vec<u64> = match only {
        Some(o) => vec![o],
        None => seeds.collect(),
    };
    for seed in seeds {
        let steps = history(seed, len);
        if check(seed, &steps, all_up_to, random, subsets).is_err() {
            let (steps, err) = shrink(seed, steps, all_up_to, random, subsets);
            fails.push(format!("seed {seed}: vec!{steps:?}\n{err}"));
        }
    }
    assert!(fails.is_empty(), "{} histories judged differently by arrival order:\n{}", fails.len(), fails.join("\n\n"));
}

// spec/requirements.md Decentralization, spec/permissions.md §5 and §5.2, spec/crdt.md §4.6:
// small histories, every arrival order of what follows the setup, plus shuffles of everything.
#[test]
fn arrival_order_alike_small_spec_permissions_5_2() {
    run(0..4, 8, 4, 2, 1);
}

// The same at size: long histories, random orders.
#[test]
#[ignore = "tier 2"]
fn arrival_order_alike_large_spec_permissions_5_2() {
    run(1000..1060, 60, 0, 8, 4);
}

// spec/crdt.md §4.6, spec/permissions.md §5.2: histories the harness found, shrunk (each
// fixed). Seed 1038: C puts an entry, B (sent it alone) writes inside it and compacts, A lowers
// C to read (an audit with no frontier): a node holding B's write and snapshot but not C's
// creation kept the entry when B's write came first (was issues/unmerge-nested-write-order.md).
#[test]
fn arrival_order_found_histories_spec_crdt_4_6() {
    use Step::*;
    let h = vec![Nested { by: 2, other: 1, t: 6, k: 0, text: false, compact: true }, New { by: 2, parent: 1, write: true }, Send { from: 1, to: 0, back: 1 }, Edge { by: 0, t: 2, member: 2, role: Some(Role::Read) }];
    check(1038, &h, 0, 8, 4).unwrap();
    // seed 1558: C lowers its own edge (a nested write into the roster snapshot's entry) with a
    // clock behind A's, so it sorts before that snapshot: an open read it first and left it
    // waiting for the entry's creation, which a fresh apply had resolved
    let h = vec![Demote { by: 0, t: 5, member: 1, at: 4, to_read: false }, Roster { by: 0, t: 4 }, Sync { from: 0, to: 1 }, Demote { by: 0, t: 6, member: 2, at: 1, to_read: false }, Sync { from: 1, to: 2 }, Write { by: 0, t: 7, op: 7, k: 0, v: 4 }, Send { from: 0, to: 2, back: 0 }, Edge { by: 2, t: 4, member: 2, role: Some(Role::Read) }];
    check(1558, &h, 0, 8, 4).unwrap();
}

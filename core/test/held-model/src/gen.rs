//! A small random history generator (for this crate's properties and for an engine adapter), and a
//! shuffle of a held set's order. Dependency-free PRNG so a seed means the same history everywhere.

use crate::model::evaluate;
use crate::types::*;
use std::collections::BTreeSet;

/// xorshift64*.
#[derive(Clone, Debug)]
pub struct Rng(pub u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
    pub fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
    pub fn pick<T: Copy>(&mut self, v: &[T]) -> T {
        v[self.below(v.len() as u64) as usize]
    }
    pub fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            v.swap(i, j);
        }
    }
}

pub const REG: Aspect = Aspect::reg(1);
pub const MAP: Aspect = Aspect::map(2);
pub const TEXT: Aspect = Aspect::text(3);
pub const ADM: Aspect = Aspect::admin_reg(4);
/// `purge.0`: what a purge request with nothing to reset writes.
pub const PURGE: Aspect = Aspect::reg(9);
pub const ASPECTS: [Aspect; 4] = [REG, MAP, TEXT, ADM];
pub const NODES: u64 = 4;
pub const THINGS: [Thing; 2] = [Thing { id: 1, owner: 0 }, Thing { id: 2, owner: 1 }];
pub const START: u64 = 1_000_000_000;

/// Retention presets the generator draws from.
pub fn retentions(wall_now: u64) -> [Retention; 6] {
    [
        Retention::PLAIN,
        Retention::WRITER,
        Retention { by: PurgeBy::Nobody, least_abs: Some(FOREVER), ..Retention::PLAIN },
        Retention { most_zero: true, ..Retention::WRITER },
        Retention { least_rel: Some(HOUR), ..Retention::PLAIN },
        Retention { by: PurgeBy::Admin, most_abs: Some(wall_now + 2 * HOUR), ..Retention::PLAIN },
    ]
}

fn stamp(ts: u64, commit: CommitId, ctr: u32) -> Stamp {
    Stamp { ts, dot: Dot { commit, ctr } }
}

/// A random history of `n` commits by `NODES` nodes on `THINGS`, every body held but about one in
/// ten missing, `now` up to six hours after the last commit. Snapshots are written from the
/// author's model state of everything before them.
pub fn history(seed: u64, n: usize) -> Held {
    let mut r = Rng::new(seed);
    let mut commits: Vec<Commit> = Vec::new();
    let mut ids: BTreeSet<CommitId> = BTreeSet::new();
    let mut w = START;
    let mut logical = 0u64;
    for _ in 0..n {
        let step = r.below(4) * HOUR / 2;
        if step == 0 {
            logical += 1;
        } else {
            logical = 0;
        }
        w += step;
        let ts = w * MS + logical;
        let id = loop {
            let id = r.below(1_000_000) as CommitId + 1;
            if ids.insert(id) {
                break id;
            }
        };
        let th = r.pick(&THINGS);
        let thing = th.id;
        // owners write half the time, so most histories have valid writes and rights
        let author = if r.chance(50) { th.owner } else { r.below(NODES) as NodeId };
        let roll = r.below(100);
        let base = Commit { id, author, ts, expires: None, kind: CommitKind::Content, parts: vec![], purge: vec![], frontier: None };
        let c = if roll < 15 {
            let holder = r.below(NODES) as NodeId;
            let role = r.pick(&[None, Some(Role::Read), Some(Role::Write), Some(Role::Admin)]);
            let frontier = (role != Some(Role::Admin))
                .then(|| commits.iter().filter(|c| c.author == holder && r.chance(60)).map(|c| c.id).collect());
            let body = Body::Held(Delta::Edge(EdgeWrite { holder, role }));
            Commit { kind: CommitKind::Role, frontier, parts: vec![Part { thing, aspect: Aspect::ROLES, retention: Retention::ROLE, body, stripped: Default::default() }], ..base }
        } else if roll < 25 && !commits.is_empty() {
            let aspect = r.pick(&ASPECTS);
            let prefix = Held { now: w, me: author, things: THINGS.to_vec(), commits: commits.clone(), own_state: vec![] };
            let o = evaluate(&prefix);
            let mut ws = o.states.get(&(thing, aspect)).cloned().unwrap_or_default();
            // a snapshot carries writes of expiring deltas value-less (spec/crdt.md §8)
            for x in &mut ws {
                x.strip(|c| commits.iter().any(|k| k.id == c && k.expires.is_some()));
            }
            let retention = if r.chance(15) { Retention { least_rel: Some(HOUR), most_zero: true, ..Retention::WRITER } } else { Retention::WRITER };
            let body = Body::Held(Delta::Writes(ws));
            Commit { kind: CommitKind::Snapshot, parts: vec![Part { thing, aspect, retention, body, stripped: Default::default() }], ..base }
        } else if roll < 35 && !commits.is_empty() {
            let target = commits[r.below(commits.len() as u64) as usize].clone();
            let tp = target.parts[0].clone();
            let item = match r.below(3) {
                0 => PurgeItem::Commit(target.id),
                1 => PurgeItem::Aspect { thing: tp.thing, aspect: tp.aspect },
                _ => PurgeItem::Author { thing: tp.thing, aspect: tp.aspect, author: target.author },
            };
            let ws = vec![Write { stamp: stamp(ts, id, 1), op: Op::Set { value: Some(r.below(5) as Val) } }];
            let part = Part { thing: tp.thing, aspect: PURGE, retention: Retention::PLAIN, body: Body::Held(Delta::Writes(ws)), stripped: Default::default() };
            Commit { purge: vec![item], parts: vec![part], ..base }
        } else {
            let aspect = r.pick(&ASPECTS);
            let prior: Vec<Write> = commits
                .iter()
                .flat_map(|c| c.parts.iter())
                .filter(|p| p.thing == thing && p.aspect == aspect)
                .flat_map(|p| match &p.body {
                    Body::Held(Delta::Writes(ws)) => ws.clone(),
                    _ => vec![],
                })
                .collect();
            let ws = content_writes(&mut r, aspect.kind, ts, id, &prior);
            let retention = r.pick(&retentions(w));
            let expires = (r.chance(15) && retention.least_abs.is_none()).then(|| w + (1 + r.below(4)) * HOUR);
            Commit { expires, parts: vec![Part { thing, aspect, retention, body: Body::Held(Delta::Writes(ws)), stripped: Default::default() }], ..base }
        };
        commits.push(c);
    }
    for c in &mut commits {
        for p in &mut c.parts {
            if r.chance(10) {
                p.body = Body::Missing;
            }
        }
    }
    Held { now: w + r.below(13) * HOUR / 2, me: r.below(NODES) as NodeId, things: THINGS.to_vec(), commits, own_state: vec![] }
}

fn content_writes(r: &mut Rng, kind: AspectKind, ts: u64, id: CommitId, prior: &[Write]) -> Vec<Write> {
    let d = stamp(ts, id, 1);
    let v = r.below(5) as Val;
    let reset = Write { stamp: d, op: Op::Reset };
    match kind {
        AspectKind::Register => match r.below(5) {
            0 => vec![reset],
            1 => vec![reset, Write { stamp: d, op: Op::Set { value: Some(v) } }],
            _ => vec![Write { stamp: d, op: Op::Set { value: Some(v) } }],
        },
        AspectKind::Map => {
            let entries: Vec<(Dot, Option<Val>)> = prior
                .iter()
                .filter_map(|w| match w.op {
                    Op::Create { key } => Some((w.stamp.dot, key)),
                    _ => None,
                })
                .collect();
            match r.below(8) {
                0 => vec![reset],
                1 | 2 if !entries.is_empty() => {
                    let (e, key) = r.pick(&entries);
                    vec![Write { stamp: d, op: Op::SetIn { entry: e, key, value: Some(v) } }]
                }
                3 if !entries.is_empty() => vec![Write { stamp: d, op: Op::Remove { entry: r.pick(&entries).0 } }],
                _ => {
                    let key = Some(r.below(3) as Val);
                    vec![Write { stamp: d, op: Op::Create { key } }, Write { stamp: d, op: Op::SetIn { entry: d.dot, key, value: Some(v) } }]
                }
            }
        }
        AspectKind::Text => {
            let elems: Vec<Dot> = prior.iter().filter(|w| matches!(w.op, Op::Insert { .. })).map(|w| w.stamp.dot).collect();
            match r.below(6) {
                0 => vec![reset],
                1 | 2 if !elems.is_empty() => vec![Write { stamp: d, op: Op::Delete { elem: r.pick(&elems) } }],
                _ => {
                    let anchor = if elems.is_empty() || r.chance(30) { None } else { Some(r.pick(&elems)) };
                    let mut out = vec![Write { stamp: d, op: Op::Insert { anchor, ch: Some(v) } }];
                    if r.chance(50) {
                        out.push(Write { stamp: stamp(ts, id, 2), op: Op::Insert { anchor: Some(d.dot), ch: Some(v + 1) } });
                    }
                    out
                }
            }
        }
    }
}

/// The same held set in another order: commits, writes inside bodies, own state, things.
pub fn shuffle(h: &Held, seed: u64) -> Held {
    let mut r = Rng::new(seed);
    let mut n = h.clone();
    r.shuffle(&mut n.commits);
    r.shuffle(&mut n.things);
    r.shuffle(&mut n.own_state);
    for c in &mut n.commits {
        if let Some(f) = &mut c.frontier {
            r.shuffle(f);
        }
        for p in &mut c.parts {
            if let Body::Held(Delta::Writes(ws)) = &mut p.body {
                r.shuffle(ws);
            }
        }
    }
    n
}

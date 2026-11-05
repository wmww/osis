//! Builders for hand-made held sets. spec: none
#![allow(dead_code)]
use held_model::gen::THINGS;
use held_model::*;

pub const T: ThingId = 10; // owned by node 0
pub const OWNER: NodeId = 0;
pub const W0: u64 = 1_000_000_000;

/// The ts of wall `h` hours after `W0`.
pub fn ts(h: u64) -> u64 {
    (W0 + h * HOUR) * MS
}
pub fn at(h: u64) -> u64 {
    W0 + h * HOUR
}
pub fn st(h: u64, c: CommitId, ctr: u32) -> Stamp {
    Stamp { ts: ts(h), dot: Dot { commit: c, ctr } }
}
pub fn set(h: u64, c: CommitId, v: Val) -> Write {
    Write { stamp: st(h, c, 1), op: Op::Set { value: Some(v) } }
}
pub fn reset(h: u64, c: CommitId) -> Write {
    Write { stamp: st(h, c, 1), op: Op::Reset }
}
pub fn part(aspect: Aspect, retention: Retention, ws: Vec<Write>) -> Part {
    Part { thing: T, aspect, retention, body: Body::Held(Delta::Writes(ws)), stripped: Default::default() }
}
pub fn content(id: CommitId, author: NodeId, h: u64, parts: Vec<Part>) -> Commit {
    Commit { id, author, actor: author, ts: ts(h), expires: None, kind: CommitKind::Content, parts, purge: vec![], frontier: None, undoes: None }
}
/// A one-part register write of `v` by `author` at hour `h`.
pub fn reg(id: CommitId, author: NodeId, h: u64, a: Aspect, r: Retention, v: Val) -> Commit {
    content(id, author, h, vec![part(a, r, vec![set(h, id, v)])])
}
pub fn edge(id: CommitId, author: NodeId, h: u64, holder: NodeId, role: Option<Role>, frontier: Option<Vec<CommitId>>) -> Commit {
    edge_on(id, author, h, T, EdgeWrite::role(holder, role), frontier)
}
/// A role commit writing one edge on `thing`.
pub fn edge_on(id: CommitId, author: NodeId, h: u64, thing: ThingId, e: EdgeWrite, frontier: Option<Vec<CommitId>>) -> Commit {
    let body = Body::Held(Delta::Edge(e));
    let part = Part { thing, aspect: Aspect::ROLES, retention: Retention::ROLE, body, stripped: Default::default() };
    Commit { kind: CommitKind::Role, frontier, ..content(id, author, h, vec![part]) }
}
pub fn snap(id: CommitId, author: NodeId, h: u64, a: Aspect, r: Retention, ws: Vec<Write>) -> Commit {
    Commit { kind: CommitKind::Snapshot, ..content(id, author, h, vec![part(a, r, ws)]) }
}
pub fn purge(id: CommitId, author: NodeId, h: u64, item: PurgeItem) -> Commit {
    Commit { purge: vec![item], ..reg(id, author, h, held_model::gen::PURGE, Retention::PLAIN, 0) }
}
pub fn held(now_h: u64, commits: Vec<Commit>) -> Held {
    Held { now: at(now_h), me: OWNER, things: THINGS.to_vec(), commits, own_state: vec![] }
}
pub fn missing(mut c: Commit, i: usize) -> Commit {
    c.parts[i].body = Body::Missing;
    c
}
pub fn read(h: &Held, a: Aspect) -> Read {
    evaluate(h).reads.get(&(T, a)).cloned().unwrap_or(Read::Absent)
}
pub fn fate(h: &Held, c: CommitId) -> Fate {
    evaluate(h).fates[&(c, 0)]
}

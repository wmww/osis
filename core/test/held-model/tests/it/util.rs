//! Builders for hand-made held sets: commit-form fragments of single writes (crdt-model's). spec: none
#![allow(dead_code)]
use crdt_model::state::{Anchor, Content, Entry, SeqElem};
use held_model::gen::{creations, RECORDS};
use held_model::*;
use std::collections::BTreeMap;

pub const T: ThingId = 10; // first admin: node 0
pub const FIRST_ADMIN: NodeId = 0;
pub const W0: u64 = 1_000_000_000;

/// The ts of wall `h` hours after `W0`.
pub fn ts(h: u64) -> u64 {
    (W0 + h * HOUR) * MS
}
pub fn at(h: u64) -> u64 {
    W0 + h * HOUR
}
/// Dot `ctr` of commit-form commit `c`.
pub fn dot(c: CommitId, ctr: u64) -> Dot {
    Dot { source: commit_source(c), ctr }
}
pub fn st(h: u64, c: CommitId, ctr: u64) -> Stamp {
    stamp(ts(h), c, ctr)
}
pub fn int(v: i64) -> Option<Value> {
    Some(Value::Int(v))
}
/// A text char by number (`a` is 0).
pub fn ch(v: u8) -> char {
    (b'a' + v) as char
}
pub fn text(cs: &[u8]) -> Option<Value> {
    Some(Value::Str(cs.iter().map(|&c| ch(c)).collect()))
}
pub fn map(kv: &[(i64, i64)]) -> Option<Value> {
    Some(Value::map(kv.iter().map(|&(k, v)| (Value::Int(k), Value::Int(v))).collect()))
}

/// Root register write of `v`.
pub fn set(h: u64, c: CommitId, v: i64) -> Frag {
    Frag::Register { reset: None, write: Some((st(h, c, 1), int(v))) }
}
/// The register write of `set`, held value-less.
pub fn set_valueless(h: u64, c: CommitId) -> Frag {
    Frag::Register { reset: None, write: Some((st(h, c, 1), None)) }
}
/// Root reset (`remove_aspect`) of a register.
pub fn reset(h: u64, c: CommitId) -> Frag {
    Frag::Register { reset: Some(st(h, c, 1)), write: None }
}
/// Root reset of a map.
pub fn map_reset(h: u64, c: CommitId) -> Frag {
    let mut f = Frag::empty(7);
    f.set_reset(Some(st(h, c, 1)));
    f
}
/// Root reset of a text.
pub fn text_reset(h: u64, c: CommitId) -> Frag {
    let mut f = Frag::empty(9);
    f.set_reset(Some(st(h, c, 1)));
    f
}
fn entry(e: CommitId, k: i64, en: Entry) -> Frag {
    Frag::Map { c: Default::default(), entries: BTreeMap::from([((dot(e, 1), Some(Value::Int(k))), en)]) }
}
/// Map entry creation of key `k` by `c` (its entry is dot `(c, 1)`), without its value.
pub fn created(h: u64, c: CommitId, k: i64) -> Frag {
    entry(c, k, Entry { reset: None, frag: None, created: Some(st(h, c, 1)) })
}
/// Value `v` written by `c` into the entry of key `k` that `e` created.
pub fn put(h: u64, c: CommitId, e: CommitId, k: i64, v: i64) -> Frag {
    entry(e, k, Entry { reset: None, frag: Some(Box::new(set(h, c, v))), created: None })
}
/// A new entry of key `k` holding `v`: its creation and its value.
pub fn new_entry(h: u64, c: CommitId, k: i64, v: i64) -> Vec<Frag> {
    vec![created(h, c, k), put(h, c, c, k, v)]
}
fn seq(d: Dot, el: SeqElem) -> Frag {
    Frag::Seq { text: true, c: Default::default(), elems: BTreeMap::from([(d, el)]) }
}
/// Text element `(c, ctr)` with char `v`, after `anchor` (`(commit, ctr)`), none: HEAD.
pub fn ins(h: u64, c: CommitId, ctr: u64, anchor: Option<(CommitId, u64)>, v: Option<u8>) -> Frag {
    let a = anchor.map_or(Anchor::Head, |(x, n)| Anchor::Dot(dot(x, n)));
    let content = v.map_or(Content::None, |v| Content::Char(ch(v)));
    seq(dot(c, ctr), SeqElem::new(st(h, c, ctr), a, content))
}
/// A delete of text element `(e, 1)` by `c`.
pub fn del(h: u64, c: CommitId, e: CommitId) -> Frag {
    seq(dot(e, 1), SeqElem::flag(st(h, c, 1), true, None))
}
/// An undelete of text element `(e, 1)` by `c`, carrying char `v`.
pub fn undel(h: u64, c: CommitId, e: CommitId, v: u8) -> Frag {
    seq(dot(e, 1), SeqElem::flag(st(h, c, 1), false, Some(ch(v))))
}

pub fn part(aspect: Aspect, retention: Retention, ws: Vec<Frag>) -> Part {
    Part { thing: T, aspect, retention, body: Body::Held(Delta::Writes(join(ws))), stripped: Default::default(), replaces: None }
}
pub fn content(id: CommitId, author: NodeId, h: u64, parts: Vec<Part>) -> Commit {
    Commit { id, author, actor: author, ts: ts(h), expires: None, kind: CommitKind::Content, parts, purge: vec![], frontier: None, undoes: None , boxes: vec![] }
}
/// A one-part register write of `v` by `author` at hour `h`.
pub fn reg(id: CommitId, author: NodeId, h: u64, a: Aspect, r: Retention, v: i64) -> Commit {
    content(id, author, h, vec![part(a, r, vec![set(h, id, v)])])
}
pub fn edge(id: CommitId, author: NodeId, h: u64, holder: NodeId, role: Option<Role>, frontier: Option<Vec<CommitId>>) -> Commit {
    edge_on(id, author, h, T, EdgeWrite::role(holder, role), frontier)
}
/// A role commit writing one edge on `thing`.
pub fn edge_on(id: CommitId, author: NodeId, h: u64, thing: ThingId, e: EdgeWrite, frontier: Option<Vec<CommitId>>) -> Commit {
    let body = Body::Held(Delta::Edge(e));
    let part = Part { thing, aspect: Aspect::ROLES, retention: Retention::ROLE, body, stripped: Default::default(), replaces: None };
    Commit { kind: CommitKind::Role, frontier, ..content(id, author, h, vec![part]) }
}
pub fn snap(id: CommitId, author: NodeId, h: u64, a: Aspect, r: Retention, ws: Vec<Frag>) -> Commit {
    Commit { kind: CommitKind::Snapshot, ..content(id, author, h, vec![part(a, r, ws)]) }
}
pub fn purge(id: CommitId, author: NodeId, h: u64, item: PurgeItem) -> Commit {
    Commit { purge: vec![item], ..reg(id, author, h, held_model::gen::PURGE, Retention::PLAIN, 0) }
}
/// What node 0 holds at hour `now_h`: `commits` and the things' creations (`gen::creations`)
/// `commits` does not give.
pub fn held(now_h: u64, mut commits: Vec<Commit>) -> Held {
    let more: Vec<Commit> = creations().into_iter().filter(|x| !commits.iter().any(|c| c.id == x.id)).collect();
    commits.extend(more);
    Held { now: at(now_h), me: FIRST_ADMIN, records: RECORDS.to_vec(), commits, dots: vec![] }
}
pub fn missing(mut c: Commit, i: usize) -> Commit {
    c.parts[i].body = Body::Missing;
    c
}
pub fn read(h: &Held, a: Aspect) -> Option<Value> {
    evaluate(h).reads.get(&(T, a)).cloned().flatten()
}
pub fn fate(h: &Held, c: CommitId) -> Fate {
    evaluate(h).fates[&(c, 0)]
}
/// A `retention^.0` setting `x` on `T` by `author` at hour `h`.
pub fn setting_by(id: CommitId, author: NodeId, h: u64, x: Setting) -> Commit {
    let p = Part { thing: T, aspect: Aspect::RETENTION, retention: Retention::FIXED, body: Body::Held(Delta::Retention(x)), stripped: Default::default(), replaces: None };
    content(id, author, h, vec![p])
}
/// The first admin's setting at hour `h` giving aspect `a` the entry `opt`.
pub fn setting(id: CommitId, h: u64, a: Aspect, opt: Opt) -> Commit {
    setting_by(id, FIRST_ADMIN, h, Setting { rules: vec![(a.name, SettingEntry { history: opt, expires: None })], default: None })
}
/// Kept `d` hours after replaced.
pub fn keep_after(d: u64) -> Opt {
    Opt::Keep { after: d * HOUR, until: 0 }
}
/// Kept until hour `h`.
pub fn keep_until(h: u64) -> Opt {
    Opt::Keep { after: 0, until: at(h) }
}
/// Kept for good.
pub const KEPT: Opt = Opt::Keep { after: 0, until: NEVER };

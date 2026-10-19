//! Test support: conversion from the reference model (models/crdt) and random op sequences from
//! its generator (notes/crdt.md, Reference model).

use crate::fragment::{Bag, BagKind, CaseWrite, Elem, Encoding, Entry, Enum, Fragment, Map, Meta, RegWrite, Register, Set, Slots, Struct};
use crate::seq::{Anchor, Seq, SeqContent, SeqElem};
use crate::stamp::{Dot, Source, Stamp};
use crdt_model::r#gen::{Rng, random_op};
use crdt_model::ops::{Ty, Writer as MWriter};
use crdt_model::state as m;
use osis_core::{CommitId, Float, Tid, Ts, Value};
use std::collections::BTreeMap;

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
        m::Frag::Map { c, entries } => Fragment::Map(Map {
            meta: meta(c),
            entries: entries
                .iter()
                .map(|(d, e)| (dot(d), Entry { reset: ostamp(&e.reset), key: e.key.as_ref().map(value), frag: e.frag.as_ref().map(|f| Box::new(frag(f))) }))
                .collect(),
        }),
        m::Frag::Seq { text, c, elems } => Fragment::Seq(Seq {
            text: *text,
            meta: meta(c),
            elems: elems
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
                    };
                    (dot(d), el)
                })
                .collect(),
        }),
        m::Frag::Slots { reg, slots } => Fragment::Slots(Slots {
            reg: reg.as_ref().map(|r| match frag(r) {
                Fragment::Register(r) => r,
                _ => panic!("register slot"),
            }),
            members: slots.iter().map(|(k, f)| (Encoding::from_id(u64::from(*k)).unwrap(), frag(f))).collect(),
        }),
    }
}

pub fn ostate(f: &Option<m::Frag>) -> Fragment {
    f.as_ref().map(frag).unwrap_or_default()
}

/// The kitchen-sink type without sequences: every encoding crdt-core implements, nested.
pub fn sink_no_seq() -> Ty {
    let inner = Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect());
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

/// Model join of a delta into an optional state (models/crdt/tests/props.rs `apply`).
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
    let mut ws: Vec<MWriter> = (0..n).map(|i| MWriter::new(crdt_model::stamp::Source::node(i as u8 + 1), 1 << 16, 0)).collect();
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

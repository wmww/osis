//! Random values and ops for property tests (notes/crdt.md, Reference model). Deterministic from a seed.
use crate::ops::{self, Ty, Writer};
use crate::state::{BagKind, Content, Frag};
use crate::value::Value;
use std::collections::BTreeMap;

pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.next() % den < num
    }
}

/// A type exercising every encoding: a struct with one field per encoding, nested collections.
pub fn kitchen_sink() -> Ty {
    let inner = Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect());
    let mut cases = BTreeMap::new();
    cases.insert(0, None);
    cases.insert(1, Some(Ty::Register));
    cases.insert(2, Some(inner.clone()));
    Ty::Struct(
        [
            (1, Ty::Register),
            (2, Ty::Counter),
            (3, Ty::Max),
            (4, Ty::Text),
            (5, Ty::Enum(cases)),
            (6, Ty::Set(Box::new(Ty::Register))),
            (7, Ty::Map(Box::new(Ty::Register), Box::new(inner.clone()))),
            (8, Ty::List(Box::new(inner))),
            (9, Ty::Min),
        ]
        .into_iter()
        .collect(),
    )
}

pub fn random_value(r: &mut Rng, ty: &Ty, depth: u32) -> Value {
    let small = |r: &mut Rng| Value::Int(r.below(4) as i64);
    match ty {
        Ty::Register | Ty::Counter | Ty::Max | Ty::Min => small(r),
        Ty::Text => Value::Str(random_text(r, if depth > 2 { 2 } else { 5 })),
        Ty::Struct(fts) => Value::fields(fts.iter().map(|(id, t)| (*id, random_value(r, t, depth + 1))).collect()),
        Ty::Enum(cases) => {
            let ids: Vec<_> = cases.keys().collect();
            let id = *ids[r.below(ids.len())];
            Value::Enum(id, cases[&id].as_ref().map(|t| Box::new(random_value(r, t, depth + 1))))
        }
        Ty::Set(et) => Value::set((0..r.below(4)).map(|_| random_value(r, et, depth + 1)).collect()),
        Ty::Map(kt, vt) => Value::map((0..r.below(3)).map(|_| (random_value(r, kt, depth + 1), random_value(r, vt, depth + 1))).collect()),
        Ty::List(et) => Value::List((0..r.below(if depth > 1 { 2 } else { 4 })).map(|_| random_value(r, et, depth + 1)).collect()),
    }
}

pub fn random_text(r: &mut Rng, max: usize) -> String {
    let n = r.below(max + 1);
    (0..n).map(|_| (b'a' + r.below(6) as u8) as char).collect()
}

/// One random op against `state` (local view), as a delta. `None` when the op is a no-op.
pub fn random_op(r: &mut Rng, w: &mut Writer, ty: &Ty, state: Option<&Frag>) -> Option<Frag> {
    let state = state.and_then(|s| s.slot(ty.enc())).filter(|s| s.present());
    if state.is_none() || r.chance(1, 12) {
        let v = random_value(r, ty, 0);
        return if r.chance(1, 3) { Some(ops::replace(w, ty, &v)) } else { crate::diff::diff(w, state, ty, &v) };
    }
    let st = state.unwrap();
    if r.chance(1, 40) {
        return Some(ops::remove(w, ty.enc()));
    }
    match (ty, st) {
        (Ty::Register, _) => Some(ops::create(w, ty, &random_value(r, ty, 0))),
        (Ty::Counter, _) => Some(ops::bag_inc(w, BagKind::Counter, Value::Int(r.below(5) as i64 - 2))),
        (Ty::Max, _) => Some(ops::bag_inc(w, BagKind::Max, Value::Int(r.below(10) as i64))),
        (Ty::Min, _) => Some(ops::bag_inc(w, BagKind::Min, Value::Int(r.below(10) as i64))),
        (Ty::Text, Frag::Seq { elems, .. }) => {
            let n = ops::visible(true, elems).len();
            match r.below(5) {
                4 => {
                    // undelete a run of deleted elements whose content this node still holds
                    let dead: Vec<_> = elems.iter().filter(|(_, e)| e.is_deleted(true) && matches!(e.content, Content::Char(_))).map(|(d, _)| d.clone()).collect();
                    if dead.is_empty() {
                        return None;
                    }
                    let from = r.below(dead.len());
                    let to = (from + 1 + r.below(3)).min(dead.len());
                    Some(ops::seq_undelete(w, st, &dead[from..to]))
                }
                0 | 1 => {
                    let s = random_text(r, 4);
                    if s.is_empty() {
                        return None;
                    }
                    Some(ops::seq_insert(w, Some(st), true, r.below(n + 1), s.chars().map(Content::Char).collect()))
                }
                2 => {
                    let from = r.below(n);
                    ops::seq_delete(w, st, from, 1 + r.below(3))
                }
                _ => {
                    let from = r.below(n);
                    let len = 1 + r.below(3);
                    if from + len > n {
                        return None;
                    }
                    ops::seq_move(w, st, from, len, r.below(n - len + 1))
                }
            }
        }
        (Ty::List(et), Frag::Seq { elems, .. }) => {
            let n = ops::visible(false, elems).len();
            match r.below(5) {
                0 => {
                    let items: Vec<Content> = (0..1 + r.below(2)).map(|_| Content::Frag(Box::new(ops::create(w, et, &random_value(r, et, 1))))).collect();
                    Some(ops::seq_insert(w, Some(st), false, r.below(n + 1), items))
                }
                1 => ops::seq_delete(w, st, r.below(n), 1),
                2 => {
                    let from = r.below(n);
                    let len = 1 + r.below(2);
                    if from + len > n {
                        return None;
                    }
                    ops::seq_move(w, st, from, len, r.below(n - len + 1))
                }
                _ => {
                    if n == 0 {
                        return None;
                    }
                    let i = r.below(n);
                    let d = ops::visible(false, elems)[i].clone();
                    let cur = match &elems[&d].content {
                        Content::Frag(f) => Some(&**f),
                        _ => None,
                    };
                    // nested random op on the element
                    let delta = random_op(r, w, et, cur)?;
                    let mut f = Frag::Seq { text: false, c: Default::default(), elems: BTreeMap::new() };
                    let Frag::Seq { elems: de, .. } = &mut f else { unreachable!() };
                    de.insert(d, crate::state::SeqElem::write(Content::Frag(Box::new(delta)), vec![], None));
                    Some(f)
                }
            }
        }
        (Ty::Struct(fts), Frag::Struct { fields, .. }) => {
            let ids: Vec<_> = fts.keys().collect();
            let id = *ids[r.below(ids.len())];
            let delta = random_op(r, w, &fts[&id], fields.get(&id))?;
            let f = Frag::Struct { c: Default::default(), fields: [(id, delta)].into_iter().collect() };
            Some(f)
        }
        (Ty::Enum(cases), Frag::Enum { case, payloads, .. }) => {
            if let (Some((_, Some(id))), true) = (case, r.chance(2, 3)) {
                if let Some(Some(pt)) = cases.get(id) {
                    let delta = random_op(r, w, pt, payloads.get(id))?;
                    let f = Frag::Enum { c: Default::default(), case: None, payloads: [(*id, delta)].into_iter().collect() };
                    return Some(f);
                }
            }
            ops::enum_set(w, Some(st), ty, &random_value(r, ty, 0))
        }
        (Ty::Set(et), _) => {
            let v = random_value(r, et, 1);
            if r.chance(1, 2) {
                ops::set_add(w, Some(st), et, &v)
            } else {
                ops::set_remove(w, Some(st), &v)
            }
        }
        (Ty::Map(kt, vt), Frag::Map { entries, .. }) => {
            let k = random_value(r, kt, 1);
            match r.below(3) {
                0 => ops::map_put(w, Some(st), vt, &k, &random_value(r, vt, 1)),
                1 => ops::map_remove(w, Some(st), &k),
                _ => {
                    let live = ops::live_entries(entries);
                    let keys: Vec<_> = live.keys().cloned().collect();
                    if keys.is_empty() {
                        return None;
                    }
                    let k = keys[r.below(keys.len())].clone();
                    let d = live[&k][0].clone();
                    let delta = random_op(r, w, vt, entries[&d].frag.as_deref())?;
                    let f = Frag::Map { c: Default::default(), entries: [(d, crate::state::Entry { reset: None, key: Some(k), frag: Some(Box::new(delta)) })].into_iter().collect() };
                    Some(f)
                }
            }
        }
        _ => None,
    }
}

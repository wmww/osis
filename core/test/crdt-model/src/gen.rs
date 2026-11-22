//! Random values and ops for property tests (notes/crdt.md, Reference model). Deterministic from a seed.
use crate::ops::{self, Ty, Writer};
use crate::stamp::{Dot, Source};
use crate::state::{BagKind, Content, Frag};
use crate::value::Value;
use std::collections::BTreeMap;

pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        // xorshift64* (which never leaves a zero state, nor reaches one: 0 seeds as any other)
        let mut x = if self.0 == 0 { 0x9E37_79B9_7F4A_7C15 } else { self.0 };
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
    // a set of structs: elements are registers holding the whole value (§3.2)
    let pair = Ty::Struct([(1, Ty::Register), (2, Ty::Register)].into_iter().collect());
    let inner = Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(pair)))].into_iter().collect());
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
        // a root register now and then holds a string, which a text at the same position embeds as chars (§7)
        Ty::Register if depth == 0 && r.chance(1, 3) => Value::Str(random_text(r, 4)),
        Ty::Register | Ty::Counter | Ty::Max | Ty::Min => small(r),
        Ty::Text => Value::Str(random_text(r, if depth > 2 { 2 } else { 5 })),
        Ty::Struct(fts) => Value::fields(fts.iter().map(|(id, t)| (*id, random_value(r, t, depth + 1))).collect()),
        Ty::Enum(cases) => {
            let ids: Vec<_> = cases.keys().collect();
            let id = *ids[r.below(ids.len())];
            Value::Enum(id, cases[&id].as_ref().map(|t| Box::new(random_value(r, t, depth + 1))))
        }
        Ty::Set(et) => Value::set((0..r.below(4)).map(|_| elem_value(r, et, depth + 1)).collect()),
        Ty::Map(kt, vt) => Value::map((0..r.below(3)).map(|_| (random_value(r, kt, depth + 1), random_value(r, vt, depth + 1))).collect()),
        Ty::List(et) => Value::List((0..r.below(if depth > 1 { 2 } else { 4 })).map(|_| random_value(r, et, depth + 1)).collect()),
    }
}

/// Parts a remover holds as headers only (§5.5): none half the time, else one or two counter
/// ranges of the sessions other writers use (a node holds its own parts), ascending and apart.
pub fn random_seen(r: &mut Rng, own: &crate::stamp::Source) -> Vec<(crate::stamp::Dot, u64)> {
    let mut out: Vec<(crate::stamp::Dot, u64)> = Vec::new();
    if r.chance(1, 2) {
        return out;
    }
    let mut v: Vec<(crate::stamp::Dot, u64)> = (0..1 + r.below(2))
        .map(|_| {
            let lo = 1 + r.below(6) as u64;
            (crate::stamp::Dot { source: crate::stamp::Source::session(1 + r.below(4) as u8, 0), ctr: lo }, lo + 1 + r.below(6) as u64)
        })
        .filter(|(d, _)| d.source != *own)
        .collect();
    v.sort();
    for (d, hi) in v {
        match out.last_mut() {
            Some((l, lhi)) if l.source == d.source && d.ctr <= *lhi => *lhi = (*lhi).max(hi),
            _ => out.push((d, hi)),
        }
    }
    out
}

/// A set element: a register set holds a reference half the time, whose removal may name parts (§5.5).
fn elem_value(r: &mut Rng, et: &Ty, depth: u32) -> Value {
    if matches!(et, Ty::Register) && r.chance(1, 2) {
        let t = [r.below(3) as u8; 15];
        return if r.chance(1, 2) { Value::Strong(t) } else { Value::Weak(t) };
    }
    random_value(r, et, depth)
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
        return if r.chance(1, 3) && ty.enc() != 0 { Some(ops::replace(w, ty, &v)) } else { crate::diff::diff(w, state, ty, &v) };
    }
    let st = state.unwrap();
    // not for registers: a nested register carries no reset (spec §3.3 rule 7), and this may be nested
    if r.chance(1, 40) && ty.enc() != 0 {
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
                    let dead: Vec<_> = elems.iter().filter(|(_, e)| e.deletes() && matches!(e.content, Content::Char(_))).map(|(d, _)| d.clone()).collect();
                    if dead.is_empty() {
                        return None;
                    }
                    let from = r.below(dead.len());
                    let to = (from + 1 + r.below(3)).min(dead.len());
                    // now and then without content where the register's embedding restores it (embedded
                    // chars, §7), as a writer bootstrapped from a snapshot may send
                    let derived = dead[from..to].iter().all(|d| matches!(d.source, crate::stamp::Source::Derived(_)));
                    if derived && r.chance(1, 2) {
                        return Some(ops::seq_undelete(w, &Frag::Seq { text: true, c: Default::default(), elems: BTreeMap::new() }, &dead[from..to]));
                    }
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
            let v = elem_value(r, et, 1);
            if r.chance(1, 2) {
                ops::set_add(w, Some(st), &v)
            } else {
                let seen = random_seen(r, &w.source);
                ops::set_remove(w, Some(st), &v, &seen)
            }
        }
        (Ty::Map(kt, vt), Frag::Map { entries, .. }) => {
            let k = random_value(r, kt, 1);
            match r.below(3) {
                0 if r.chance(1, 4) => Some(ops::map_put_new(w, vt, &k, &random_value(r, vt, 1))),
                0 => ops::map_put(w, Some(st), vt, &k, &random_value(r, vt, 1)),
                1 => ops::map_remove(w, Some(st), &k),
                _ => {
                    let live = ops::live_entries(entries);
                    let keys: Vec<_> = live.keys().cloned().collect();
                    if keys.is_empty() {
                        return None;
                    }
                    let k = keys[r.below(keys.len())].clone();
                    let delta = random_op(r, w, vt, ops::key_state(entries, &live[&k]).as_ref())?;
                    let f = Frag::Map { c: Default::default(), entries: ops::key_writes(entries, &live[&k], delta) };
                    Some(f)
                }
            }
        }
        _ => None,
    }
}

/// Model join of a delta into an optional state (core/test/crdt-model/tests/props.rs `apply`).
pub fn apply(state: &mut Option<Frag>, d: Frag) {
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
pub struct Commit {
    pub w: Writer,
    pub delta: Frag,
}

/// `n` writers (one per source) make `rounds` rounds of random ops, writer `i` with type
/// `types[i % len]`, seeing a random part of the others' commits: commits in creation order. With
/// `bulk` each ends with a large write (`bulk_value`); `honest`: a clock past every commit seen and
/// keyless removals (else odd writers remove keyed, §5.6); `twins`: writers 0 and 1 share a source
/// (pass it twice) and a clock but choose their ops apart, so copies of one write (equal stamps)
/// differ in payload and one dot has two stamps, as forged copies carry (spec/permissions.md §5.2).
pub fn history(r: &mut Rng, types: &[Ty], sources: Vec<Source>, rounds: usize, bulk: bool, honest: bool, twins: bool) -> Vec<Commit> {
    let n = sources.len();
    // odd writers remove keyed (role-class aspects), even ones keyless (§5.6)
    let mut ws: Vec<Writer> = sources.into_iter().enumerate().map(|(i, s)| Writer { keyed: !honest && i % 2 == 1, ..Writer::new(s, 1 << 16, 0) }).collect();
    let mut states: Vec<Option<Frag>> = vec![None; n];
    let mut seen: Vec<usize> = vec![0; n];
    let mut commits: Vec<Commit> = Vec::new();
    for round in 0..rounds {
        for i in 0..n {
            // catch up on a random prefix of the others' commits
            let upto = seen[i] + r.below(commits.len() - seen[i] + 1);
            for c in &commits[seen[i]..upto] {
                apply(&mut states[i], c.delta.clone());
            }
            seen[i] = upto;
            let t = ((round as u64 * 10 + r.below(10) as u64 + 1) << 16) + i as u64;
            let t = t.max(ws[i].ts + 1);
            let t = if honest { commits[..upto].iter().fold(t, |t, c| t.max(c.w.ts + 1)) } else { t };
            let t = if twins && i == 1 { ws[0].ts.max(ws[1].ts + 1) } else { t };
            let before = ws[i].clone();
            ws[i].next_commit(t);
            let ty = &types[i % types.len()];
            let op = if bulk && round + 1 == rounds {
                let v = bulk_value(r, ty, 0);
                crate::diff::diff(&mut ws[i], states[i].as_ref().and_then(|s| s.slot(ty.enc())).filter(|s| s.present()), ty, &v)
            } else {
                random_op(r, &mut ws[i], ty, states[i].as_ref())
            };
            match op {
                Some(d) => {
                    apply(&mut states[i], d.clone());
                    commits.push(Commit { w: ws[i].clone(), delta: d });
                }
                None => ws[i] = before,
            }
        }
    }
    commits
}

/// A value of `ty` large enough to page at small page parameters: long texts, many elements.
pub fn bulk_value(r: &mut Rng, ty: &Ty, depth: u32) -> Value {
    use Value as V;
    let many = |r: &mut Rng| if depth <= 1 { 40 + r.below(160) } else { r.below(6) };
    match ty {
        Ty::Text => V::Str(random_text(r, if depth <= 1 { 300 } else { 40 })),
        Ty::Struct(fts) => V::fields(fts.iter().map(|(id, t)| (*id, bulk_value(r, t, depth + 1))).collect()),
        Ty::Set(et) => V::set((0..many(r)).map(|_| random_value(r, et, depth + 1)).collect()),
        Ty::Map(kt, vt) => V::map((0..many(r)).map(|_| (bulk_value(r, kt, depth + 1), random_value(r, vt, depth + 1))).collect()),
        Ty::List(et) => V::List((0..many(r)).map(|_| random_value(r, et, depth + 1)).collect()),
        Ty::Register if depth > 0 => V::Str(random_text(r, 12)),
        _ => random_value(r, ty, depth),
    }
}

/// Hostile single-record deltas on one text or list (§5.7, §6): creation chains anchored at
/// random dots (their own run, unknown dots, later dots), forged copies of one creation or
/// position write with other anchors or keys, moves with random anchors and sibling keys (cycles
/// through chains and range records), deletes, undeletes, resets; with `slots` (text), register
/// writes of strings at the position (§7: embedded chars, `Derived` dots moved, deleted and
/// anchored at, held or not), forged copies of a register write (other strings) and of its
/// embedding (other chars, fewer or more, as a snapshot carries them, with the reset the
/// register write copied implies). Joined into deltas of
/// 1..4 writes each.
pub fn hostile(r: &mut Rng, list: bool, slots: bool) -> Vec<Frag> {
    let mut deltas = Vec::new();
    let mut single = hostile_writes(r, list, slots, 48).into_iter().peekable();
    while single.peek().is_some() {
        let mut d = None;
        for w in single.by_ref().take(1 + r.below(4)) {
            apply(&mut d, w);
        }
        deltas.extend(d);
    }
    // a char without a creation (no wire form: rejected, §3.3 rule 7) joins as none
    for w in &mut deltas {
        if let Frag::Seq { text: true, elems, .. } = w {
            for e in elems.values_mut().filter(|e| e.created.is_none()) {
                if r.chance(1, 4) {
                    e.content = Content::Char(char::from(b'a' + r.below(4) as u8));
                }
            }
        }
    }
    deltas
}

fn hostile_writes(r: &mut Rng, list: bool, slots: bool, n: usize) -> Vec<Frag> {
    use crate::stamp::Stamp as MStamp;
    use crate::state::{Anchor as MAnchor, Composite, SeqElem as MElem};
    let srcs = [Source::session(1, 0), Source::session(2, 0), Source::session(3, 0)];
    // the dots of the register writes so far (their embedded chars: `Derived(d)`, 1..), and
    // their stamps (forged copies of a write and of its embedding)
    let mut regs: Vec<Dot> = Vec::new();
    let mut reg_stamps: Vec<MStamp> = Vec::new();
    fn dot(r: &mut Rng, srcs: &[Source; 3], regs: &[Dot]) -> Dot {
        if !regs.is_empty() && r.chance(1, 4) {
            return Dot { source: Source::Derived(Box::new(regs[r.below(regs.len())].clone())), ctr: 1 + r.below(4) as u64 };
        }
        Dot { source: srcs[r.below(3)].clone(), ctr: 1 + r.below(12) as u64 }
    }
    // a position or flag write on register write `o`'s embedded char stamped with dot `o` has no
    // wire form (§3.3 rule 7): a forged copy's reused counter skips it
    fn theirs(d: &Dot, src: &Source, ctr: u64) -> bool {
        matches!(&d.source, Source::Derived(o) if o.source == *src && o.ctr == ctr)
    }
    fn anchor(r: &mut Rng, srcs: &[Source; 3], regs: &[Dot]) -> MAnchor {
        if r.chance(1, 6) { MAnchor::Head } else { MAnchor::Dot(dot(r, srcs, regs)) }
    }
    let content = |r: &mut Rng, s: &MStamp| Content::Frag(Box::new(Frag::Register { reset: None, write: Some((s.clone(), Some(Value::Int(r.below(3) as i64)))) }));
    // chars at random: creation copies of one dot and undeletes may carry other chars (forged
    // copies, §4.1 copy order, §5.7)
    let any_char = |r: &mut Rng| char::from(b'a' + r.below(4) as u8);
    let seq = |elems: BTreeMap<Dot, MElem>, reset: Option<MStamp>| Frag::Seq { text: !list, c: Composite { reset, w: None, w_valueless: false }, elems };
    // stamps: ts in a small range so writes interleave; position write counters apart from dots
    let mut pos_ctr = 100u64;
    let mut out = Vec::new();
    for _ in 0..n {
        let t = (1 + r.below(30) as u64) << 16;
        let k = r.below(20);
        let mut elems = BTreeMap::new();
        if k < 8 && !reg_stamps.is_empty() && r.chance(1, 3) {
            // a forged copy of a register write's embedding (§7): its chars' creations, some or
            // more than it embeds, other chars, mostly at its stamps, sometimes another `ts`
            let rs = reg_stamps[r.below(reg_stamps.len())].clone();
            let src = Source::Derived(Box::new(rs.dot.clone()));
            let ct = if r.chance(1, 4) { t } else { rs.ts };
            let (first, len) = (1 + r.below(3) as u64, 1 + r.below(4) as u64);
            let mut a = if first == 1 { MAnchor::Head } else { MAnchor::Dot(Dot { source: src.clone(), ctr: first - 1 }) };
            for i in first..first + len {
                let e = Dot { source: src.clone(), ctr: i };
                elems.insert(e.clone(), MElem::new(MStamp { ts: ct, dot: e.clone() }, a.clone(), Content::Char(any_char(r))));
                a = MAnchor::Dot(e);
            }
            // with the reset the register write it copies implies (§3.3 rule 7, §7)
            out.push(seq(elems, Some(MStamp { ts: ct, dot: rs.dot.clone() })));
            continue;
        } else if k < 8 {
            // a creation chain of 1..4 elements (never of a `Derived` source: a writer's delta
            // rejects them)
            let d = Dot { source: srcs[r.below(3)].clone(), ctr: 1 + r.below(12) as u64 };
            let len = 1 + r.below(4) as u64;
            let mut a = anchor(r, &srcs, &regs);
            // mostly one creation `ts` per dot (so copies of one stamp meet, differing in char
            // or anchor), sometimes another (a forged copy under another `ts`, §5.7 Join)
            let forged = r.chance(1, 4);
            for i in 0..len {
                let e = Dot { source: d.source.clone(), ctr: d.ctr + i };
                let ct = if forged { t } else { (1 + (srcs.iter().position(|x| *x == e.source).unwrap() as u64 * 7 + e.ctr * 3) % 30) << 16 };
                let s = MStamp { ts: ct, dot: e.clone() };
                let c = if list { content(r, &s) } else { Content::Char(any_char(r)) };
                elems.insert(e.clone(), MElem::new(s, a.clone(), c));
                a = MAnchor::Dot(e);
            }
        } else if k < 15 {
            // a move (or a forged copy of an earlier position write: same counter)
            let d = dot(r, &srcs, &regs);
            if r.chance(1, 4) {
                pos_ctr = pos_ctr.saturating_sub(r.below(3) as u64);
            }
            pos_ctr += 1;
            let src = srcs[r.below(3)].clone();
            while theirs(&d, &src, pos_ctr) {
                pos_ctr += 1;
            }
            let s = MStamp { ts: t, dot: Dot { source: src, ctr: pos_ctr } };
            let key = if r.chance(1, 3) && t > 1 << 16 { Some(MStamp { ts: t - (1 << 16), dot: dot(r, &srcs, &[]) }) } else { None };
            elems.insert(d, MElem::write(Content::None, vec![(s, anchor(r, &srcs, &regs), key)], None));
        } else if k < 19 {
            // a delete or (text) an undelete with a char; a run of 1..3
            let d = dot(r, &srcs, &regs);
            let len = 1 + r.below(3) as u64;
            pos_ctr += 1;
            let src = srcs[r.below(3)].clone();
            while theirs(&d, &src, pos_ctr) {
                pos_ctr += 1;
            }
            let s = MStamp { ts: t, dot: Dot { source: src, ctr: pos_ctr } };
            let undel = !list && r.chance(1, 3);
            for i in 0..len {
                let e = Dot { source: d.source.clone(), ctr: d.ctr + i };
                // an undelete's chars: some elements' missing (the undo buffer lacked them)
                let c = if undel && !r.chance(1, 5) { Some(any_char(r)) } else { None };
                elems.insert(e, MElem::flag(s.clone(), !undel, c));
            }
        } else if slots && r.chance(1, 2) {
            if !reg_stamps.is_empty() && r.chance(1, 3) {
                // a forged copy of a register write: its stamp, another string (§4.1 copy order)
                let rs = reg_stamps[r.below(reg_stamps.len())].clone();
                let v: String = (0..r.below(4)).map(|_| if r.chance(1, 4) { 'é' } else { any_char(r) }).collect();
                out.push(Frag::Register { reset: None, write: Some((rs, Some(Value::Str(v)))) });
                continue;
            }
            // an old app's save: a register write of a string (a reset of everything older)
            pos_ctr += 1;
            let d = Dot { source: srcs[r.below(3)].clone(), ctr: pos_ctr };
            let v: String = (0..r.below(4)).map(|i| char::from(b'a' + ((d.ctr + i as u64 + 1) % 4) as u8)).collect();
            let s = MStamp { ts: t, dot: d.clone() };
            out.push(Frag::Register { reset: None, write: Some((s.clone(), Some(Value::Str(v)))) });
            regs.push(d);
            reg_stamps.push(s);
            continue;
        } else {
            pos_ctr += 1;
            let s = MStamp { ts: t / 2, dot: Dot { source: srcs[r.below(3)].clone(), ctr: pos_ctr } };
            out.push(seq(elems, Some(s)));
            continue;
        }
        out.push(seq(elems, None));
    }
    out
}


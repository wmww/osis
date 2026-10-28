//! Structural diff (spec §9).
use crate::ops::{create, elem_reset, live_elems, live_entries, replace, visible, Ty, Writer};
use crate::state::{Anchor, BagKind, Composite, Content, Elem, Entry, Frag, SeqElem};
use crate::value::Value;
use std::collections::BTreeMap;

fn comp() -> Composite {
    Composite::default()
}

/// Writes that turn `st` into `v`; `None` when nothing changes.
pub fn diff(w: &mut Writer, st: Option<&Frag>, ty: &Ty, v: &Value) -> Option<Frag> {
    // what the app sees is the position's read; the writes go into the slot of the schema's encoding (§7)
    let cur = st.filter(|s| s.present()).and_then(|s| s.read());
    if cur.as_ref() == Some(v) {
        return None;
    }
    let st = st.and_then(|s| s.slot(ty.enc())).filter(|s| s.present());
    let Some(st) = st else { return Some(create(w, ty, v)) };
    let cur = st.read();
    let out = match (ty, st, v) {
        (Ty::Register, _, v) => Frag::Register { reset: None, write: Some((w.delta(), Some(v.clone()))) },
        (Ty::Counter, _, Value::Int(n)) => {
            let c = match cur {
                Some(Value::Int(c)) => c,
                _ => 0,
            };
            crate::ops::bag_inc(w, BagKind::Counter, Value::Int(n - c))
        }
        (Ty::Max | Ty::Min | Ty::Counter, _, v) => replace(w, ty, v),
        (Ty::Text, Frag::Seq { elems, .. }, Value::Str(s)) => {
            let vis = visible(true, elems);
            let old: Vec<char> = vis.iter().map(|d| match &elems[d].content {
                Content::Char(c) => *c,
                _ => unreachable!(),
            }).collect();
            let new: Vec<char> = s.chars().collect();
            let script = lcs_script(&old, &new, |a, b| a == b);
            let mut f = Frag::Seq { text: true, c: comp(), elems: BTreeMap::new() };
            apply_script(w, &mut f, &vis, &script, |w, f, anchor, items| {
                crate::ops::insert_run(w, f, anchor, items.iter().map(|i| Content::Char(new[*i])).collect());
            });
            f
        }
        (Ty::List(et), Frag::Seq { elems, .. }, Value::List(items)) => {
            let vis = visible(false, elems);
            let old: Vec<Value> = vis.iter().map(|d| match &elems[d].content {
                Content::Frag(fr) => fr.read().unwrap(),
                _ => unreachable!(),
            }).collect();
            let script = lcs_script(&old, items, |a, b| a == b);
            let mut f = Frag::Seq { text: false, c: comp(), elems: BTreeMap::new() };
            // pair leftovers in order: Op::Replace(i, j) edits old i into new j
            let script = pair_leftovers(script);
            for op in &script {
                if let Op::Replace(i, j) = op {
                    let d = &vis[*i];
                    let cur = match &elems[d].content {
                        Content::Frag(fr) => Some(&**fr),
                        _ => None,
                    };
                    if let Some(delta) = diff(w, cur, et, &items[*j]) {
                        let Frag::Seq { elems: de, .. } = &mut f else { unreachable!() };
                        de.insert(d.clone(), SeqElem::write(Content::Frag(Box::new(delta)), vec![], None));
                    }
                }
            }
            apply_script(w, &mut f, &vis, &script, |w, f, anchor, idx| {
                let contents = idx.iter().map(|j| Content::Frag(Box::new(create(w, et, &items[*j])))).collect();
                crate::ops::insert_run(w, f, anchor, contents);
            });
            f
        }
        (Ty::Struct(fts), Frag::Struct { fields, .. }, Value::Map(kv)) => {
            let mut out = BTreeMap::new();
            for (k, fv) in kv {
                let Value::Int(id) = k else { continue };
                let id = *id as u64;
                if let Some(ft) = fts.get(&id) {
                    if let Some(d) = diff(w, fields.get(&id), ft, fv) {
                        out.insert(id, d);
                    }
                }
            }
            if out.is_empty() {
                return None;
            }
            Frag::Struct { c: comp(), fields: out }
        }
        (Ty::Enum(..), _, _) => return crate::ops::enum_set(w, Some(st), ty, v),
        (Ty::Set(_), Frag::Set { elems, .. }, Value::Set(items)) => {
            let live = live_elems(elems);
            let gone: Vec<_> = live.iter().filter(|(_, x)| !items.contains(x)).map(|(d, _)| (*d).clone()).collect();
            let mut f = if gone.is_empty() { Frag::Set { c: comp(), elems: BTreeMap::new() } } else { elem_reset(w, 6, &gone) };
            let Frag::Set { elems: de, .. } = &mut f else { unreachable!() };
            for it in items {
                if !live.iter().any(|(_, x)| x == it) {
                    let d = w.stamp().dot;
                    de.insert(d, Elem { reset: None, frag: Some(Box::new(crate::ops::register(w, it.clone()))) });
                }
            }
            f
        }
        (Ty::Map(_, vt), Frag::Map { entries, .. }, Value::Map(kv)) => {
            let live = live_entries(entries);
            let mut de = BTreeMap::new();
            let gone: Vec<(&Value, &Vec<_>)> = live.iter().filter(|(k, _)| !kv.iter().any(|(k2, _)| k2 == *k)).collect();
            if !gone.is_empty() {
                let s = w.delta();
                for (_, dots) in gone {
                    for d in dots {
                        de.insert(d.clone(), Entry { reset: Some(s.clone()), key: None, frag: None, created: None });
                    }
                }
            }
            for (k, val) in kv {
                match live.get(k) {
                    Some(dots) => {
                        let d = dots[0].clone();
                        if let Some(delta) = diff(w, crate::ops::key_state(entries, dots).as_ref(), vt, val) {
                            de.insert(d, Entry { reset: None, key: Some(k.clone()), frag: Some(Box::new(delta)), created: None });
                        }
                    }
                    None => {
                        let st = w.stamp();
                        let d = st.dot.clone();
                        de.insert(d, Entry { reset: None, key: Some(k.clone()), frag: Some(Box::new(create(w, vt, val))), created: Some(st) });
                    }
                }
            }
            if de.is_empty() {
                return None;
            }
            Frag::Map { c: comp(), entries: de }
        }
        _ => panic!("type/value mismatch in diff"),
    };
    if out.is_empty() {
        return None;
    }
    Some(out)
}

#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    Keep(usize, usize),
    Del(usize),
    Ins(usize),
    Replace(usize, usize),
}

/// LCS edit script over old indices / new indices, in old order.
pub fn lcs_script<T>(old: &[T], new: &[T], eq: impl Fn(&T, &T) -> bool) -> Vec<Op> {
    let (n, m) = (old.len(), new.len());
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if eq(&old[i], &new[j]) { dp[i + 1][j + 1] + 1 } else { dp[i + 1][j].max(dp[i][j + 1]) };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    while i < n || j < m {
        if i < n && j < m && eq(&old[i], &new[j]) {
            out.push(Op::Keep(i, j));
            i += 1;
            j += 1;
        } else if j < m && (i == n || dp[i][j + 1] >= dp[i + 1][j]) {
            out.push(Op::Ins(j));
            j += 1;
        } else {
            out.push(Op::Del(i));
            i += 1;
        }
    }
    out
}

/// Within each gap between keeps, pair deletions with insertions in order as replacements.
fn pair_leftovers(script: Vec<Op>) -> Vec<Op> {
    let mut out = Vec::new();
    let mut dels = Vec::new();
    let mut inss = Vec::new();
    let flush = |out: &mut Vec<Op>, dels: &mut Vec<usize>, inss: &mut Vec<usize>| {
        let k = dels.len().min(inss.len());
        for t in 0..k {
            out.push(Op::Replace(dels[t], inss[t]));
        }
        for d in &dels[k..] {
            out.push(Op::Del(*d));
        }
        for j in &inss[k..] {
            out.push(Op::Ins(*j));
        }
        dels.clear();
        inss.clear();
    };
    for op in script {
        match op {
            Op::Keep(..) => {
                flush(&mut out, &mut dels, &mut inss);
                out.push(op);
            }
            Op::Del(i) => dels.push(i),
            Op::Ins(j) => inss.push(j),
            Op::Replace(..) => unreachable!(),
        }
    }
    flush(&mut out, &mut dels, &mut inss);
    out
}

/// Turn a script into delete flags and insert runs; insert runs anchor to the previous old element (or HEAD).
fn apply_script(w: &mut Writer, f: &mut Frag, vis: &[crate::stamp::Dot], script: &[Op], mut insert: impl FnMut(&mut Writer, &mut Frag, Anchor, &[usize])) {
    let dels: Vec<_> = script.iter().filter_map(|o| if let Op::Del(i) = o { Some(vis[*i].clone()) } else { None }).collect();
    if !dels.is_empty() {
        let s = w.delta();
        let Frag::Seq { elems, .. } = f else { unreachable!() };
        for d in dels {
            elems.insert(d, SeqElem::write(Content::None, vec![], Some((s.clone(), true))));
        }
    }
    let mut prev_old: Option<usize> = None;
    let mut pending: Vec<usize> = Vec::new();
    let mut flush = |w: &mut Writer, f: &mut Frag, prev_old: Option<usize>, pending: &mut Vec<usize>| {
        if !pending.is_empty() {
            let anchor = prev_old.map_or(Anchor::Head, |i| Anchor::Dot(vis[i].clone()));
            insert(w, f, anchor, pending);
            pending.clear();
        }
    };
    for op in script {
        match op {
            Op::Ins(j) => pending.push(*j),
            Op::Keep(i, _) | Op::Del(i) | Op::Replace(i, _) => {
                flush(w, f, prev_old, &mut pending);
                prev_old = Some(*i);
            }
        }
    }
    flush(w, f, prev_old, &mut pending);
}

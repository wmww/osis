//! Sequence diff (spec/crdt.md §9 list, text) and the sequence part of `edit(base, new)`
//! (notes/api.md): Myers over chars or element views, list leftovers paired in order.

use crate::batch::Batch;
use crate::error::Error;
use crate::fragment::{Fragment, Meta};
use crate::ops::{Op, PathOp, PathSeg, Writer};
use crate::seq::{Anchor, Seq, SeqContent, SeqElem, visible};
use crate::stamp::Dot;
use crate::view::View;
use osis_core::Value;
use std::collections::{BTreeMap, HashMap};

/// Edits beyond which Myers gives up and treats the rest as replaced (any script is valid, §9).
const MAX_D: usize = 512;

/// Matched index pairs of a longest common subsequence (Myers, after trimming the common prefix
/// and suffix), ascending in both.
pub(crate) fn lcs<A, B>(a: &[A], b: &[B], eq: impl Fn(&A, &B) -> bool) -> Vec<(usize, usize)> {
    let mut pre = 0;
    while let (Some(x), Some(y)) = (a.get(pre), b.get(pre)) {
        if !eq(x, y) {
            break;
        }
        pre += 1;
    }
    let mut suf = 0;
    while pre + suf < a.len().min(b.len()) {
        let (Some(x), Some(y)) = (a.get(a.len() - 1 - suf), b.get(b.len() - 1 - suf)) else { break };
        if !eq(x, y) {
            break;
        }
        suf += 1;
    }
    let mut out: Vec<(usize, usize)> = (0..pre).map(|i| (i, i)).collect();
    let (am, bm) = (a.get(pre..a.len() - suf).unwrap_or_default(), b.get(pre..b.len() - suf).unwrap_or_default());
    out.extend(myers(am, bm, &eq).into_iter().map(|(i, j)| (i + pre, j + pre)));
    out.extend((0..suf).map(|k| (a.len() - suf + k, b.len() - suf + k)));
    out
}

/// Myers' greedy forward search with a trace; `[]` past `MAX_D`.
fn myers<A, B>(a: &[A], b: &[B], eq: &impl Fn(&A, &B) -> bool) -> Vec<(usize, usize)> {
    let (n, m) = (a.len() as isize, b.len() as isize);
    if n == 0 || m == 0 {
        return Vec::new();
    }
    let max = (n + m).min(MAX_D as isize);
    let off = max + 1;
    let at = |k: isize| (k + off) as usize;
    let mut v = vec![0isize; (2 * off + 1) as usize];
    let mut trace: Vec<Vec<isize>> = Vec::new();
    let mut found = None;
    'd: for d in 0..=max {
        trace.push(v.clone());
        let mut k = -d;
        while k <= d {
            let down = k == -d || (k != d && v.get(at(k - 1)) < v.get(at(k + 1)));
            let mut x = if down { v.get(at(k + 1)).copied().unwrap_or(0) } else { v.get(at(k - 1)).copied().unwrap_or(0) + 1 };
            let mut y = x - k;
            while x < n && y < m && matches!((a.get(x as usize), b.get(y as usize)), (Some(p), Some(q)) if eq(p, q)) {
                x += 1;
                y += 1;
            }
            if let Some(s) = v.get_mut(at(k)) {
                *s = x;
            }
            if x >= n && y >= m {
                found = Some(d);
                break 'd;
            }
            k += 2;
        }
    }
    let Some(dmax) = found else { return Vec::new() };
    // walk back through the trace collecting diagonals
    let mut out = Vec::new();
    let (mut x, mut y) = (n, m);
    for d in (1..=dmax).rev() {
        let Some(v) = trace.get(d as usize) else { break };
        let k = x - y;
        let down = k == -d || (k != d && v.get(at(k - 1)) < v.get(at(k + 1)));
        let pk = if down { k + 1 } else { k - 1 };
        let px = v.get(at(pk)).copied().unwrap_or(0);
        let py = px - pk;
        let (sx, sy) = if down { (px, py + 1) } else { (px + 1, py) };
        while x > sx && y > sy {
            x -= 1;
            y -= 1;
            out.push((x as usize, y as usize));
        }
        x = px;
        y = py;
    }
    while x > 0 && y > 0 {
        x -= 1;
        y -= 1;
        out.push((x as usize, y as usize));
    }
    out.reverse();
    out
}

/// One step of an edit script over old indices `i` and new indices `j`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Keep(usize, usize),
    /// Changed in place (lists): unmatched old and new paired in order within a gap.
    Pair(usize, usize),
    Del(usize),
    /// Insert new `j` after old index (`None`: HEAD).
    Ins(Option<usize>, usize),
}

/// The script from matched pairs; with `pair`, leftovers in each gap are paired in order (§9).
fn script(n_old: usize, n_new: usize, keep: &[(usize, usize)], pair: bool) -> Vec<Step> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    let mut prev: Option<usize> = None;
    for &(ki, kj) in keep.iter().chain(std::iter::once(&(n_old, n_new))) {
        let olds: Vec<usize> = (i..ki).collect();
        let news: Vec<usize> = (j..kj).collect();
        let paired = if pair { olds.len().min(news.len()) } else { 0 };
        let mut anchor = prev;
        for t in 0..paired {
            if let (Some(o), Some(nw)) = (olds.get(t), news.get(t)) {
                out.push(Step::Pair(*o, *nw));
                anchor = Some(*o);
            }
        }
        out.extend(olds.iter().skip(paired).map(|o| Step::Del(*o)));
        out.extend(news.iter().skip(paired).map(|nw| Step::Ins(anchor, *nw)));
        if ki < n_old {
            out.push(Step::Keep(ki, kj));
            prev = Some(ki);
        }
        i = ki + 1;
        j = kj + 1;
    }
    out
}

/// Turns the inserts of a script into creation runs, one per gap.
fn insert_runs(w: &mut Writer, out: &mut Seq, steps: &[Step], anchor_of: &dyn Fn(Option<usize>) -> Anchor, content: &mut dyn FnMut(&mut Writer, usize) -> Result<SeqContent, Error>) -> Result<(), Error> {
    let mut groups: Vec<(Option<usize>, Vec<usize>)> = Vec::new();
    for s in steps {
        if let Step::Ins(a, j) = s {
            match groups.last_mut() {
                Some((ga, js)) if ga == a => js.push(*j),
                _ => groups.push((*a, vec![*j])),
            }
        }
    }
    for (a, js) in groups {
        let mut cs = Vec::with_capacity(js.len());
        for j in js {
            cs.push(content(w, j)?);
        }
        let mut prev = anchor_of(a);
        for c in cs {
            let st = w.fresh();
            let d = st.dot.clone();
            out.elems.insert(d.clone(), SeqElem { created: Some((st.clone(), prev.clone())), content: c, pos: vec![(st, prev)], deleted: None, span: 1 });
            prev = Anchor::Dot(d);
        }
    }
    Ok(())
}

fn chars(v: &Value) -> Result<Vec<char>, Error> {
    match v {
        Value::Str(s) => Ok(s.chars().collect()),
        _ => Err(Error::Mismatch("text value is not a string")),
    }
}

fn items(v: &Value) -> Result<&[Value], Error> {
    match v {
        Value::List(l) => Ok(l),
        _ => Err(Error::Mismatch("list value is not a list")),
    }
}

/// Visible list elements: dot, content and projected read (`None`: opaque, §9).
fn list_view<V: View>(s: &Seq, ev: &V) -> Vec<(Dot, Option<Fragment>, Option<Value>)> {
    visible(s)
        .into_iter()
        .map(|d| {
            let f = s.elems.get(&d).and_then(|e| if let SeqContent::Frag(f) = &e.content { Some((**f).clone()) } else { None });
            let p = f.as_ref().and_then(Fragment::read).and_then(|v| ev.project(&v).map(|c| c.into_owned()));
            (d, f, p)
        })
        .collect()
}

fn flag(out: &mut Seq, d: Dot, w: &Writer) {
    out.elems.insert(d, SeqElem { deleted: Some((w.delta_stamp(), true)), ..SeqElem::bare() });
}

/// Structural diff of present state `s` against `v` (§9 list, text); `None` when nothing changes.
pub(crate) fn diff<V: View>(w: &mut Writer, s: &Seq, view: &V, v: &Value) -> Result<Option<Seq>, Error> {
    let mut out = Seq { text: s.text, meta: Meta::default(), elems: BTreeMap::new() };
    if s.text {
        let vis = visible(s);
        let old: Vec<char> = vis.iter().filter_map(|d| s.elems.get(d)).filter_map(|e| if let SeqContent::Char(c) = e.content { Some(c) } else { None }).collect();
        let new = chars(v)?;
        let steps = script(old.len(), new.len(), &lcs(&old, &new, |a, b| a == b), false);
        for st in &steps {
            if let Step::Del(i) = st
                && let Some(d) = vis.get(*i)
            {
                flag(&mut out, d.clone(), w);
            }
        }
        let anchor_of = |a: Option<usize>| a.and_then(|i| vis.get(i)).cloned().map_or(Anchor::Head, Anchor::Dot);
        insert_runs(w, &mut out, &steps, &anchor_of, &mut |_, j| Ok(new.get(j).map_or(SeqContent::None, |c| SeqContent::Char(*c))))?;
    } else {
        let ev = view.element().ok_or(Error::Mismatch("list without element type"))?;
        let new = items(v)?;
        // opaque elements keep their place and are never touched (§9)
        let all = list_view(s, &ev);
        let old: Vec<&(Dot, Option<Fragment>, Option<Value>)> = all.iter().filter(|x| x.2.is_some()).collect();
        let keep = lcs(&old, new, |a, b| a.2.as_ref() == Some(b));
        let steps = script(old.len(), new.len(), &keep, true);
        for st in &steps {
            match st {
                Step::Pair(i, j) => {
                    let (Some((d, f, _)), Some(item)) = (old.get(*i), new.get(*j)) else { continue };
                    if let Some(c) = crate::ops::diff(w, f.as_ref(), &ev, item)? {
                        out.elems.insert(d.clone(), SeqElem { content: SeqContent::Frag(Box::new(c)), ..SeqElem::bare() });
                    }
                }
                Step::Del(i) => {
                    if let Some((d, _, _)) = old.get(*i) {
                        flag(&mut out, d.clone(), w);
                    }
                }
                _ => {}
            }
        }
        let anchor_of = |a: Option<usize>| a.and_then(|i| old.get(i)).map_or(Anchor::Head, |x| Anchor::Dot(x.0.clone()));
        insert_runs(w, &mut out, &steps, &anchor_of, &mut |w, j| {
            let item = new.get(j).ok_or(Error::Mismatch("index"))?;
            Ok(SeqContent::Frag(Box::new(crate::ops::create(w, &ev, item)?)))
        })?;
    }
    Ok((!out.elems.is_empty()).then_some(out))
}

/// The ops turning sequence value `base` into `new` at `path` (notes/api.md `edit`): one
/// `Op::Edit`, rebased onto the current sequence when applied.
pub(crate) fn diff_values<V: View>(base: &Value, new: &Value, _view: &V, path: &[PathSeg]) -> Result<Vec<PathOp>, Error> {
    let op = match (base, new) {
        (Value::Str(_), Value::Str(_)) | (Value::List(_), Value::List(_)) => Op::Edit { base: base.clone(), new: new.clone() },
        _ => Op::Set(new.clone()),
    };
    Ok(vec![PathOp { path: path.to_vec(), op }])
}

/// `edit(base, new)` against current state `s`: the script `base → new`, rebased onto the
/// current read by matching `base` to it exactly (LCS). Deletes and insert anchors use exact
/// matches only, so a base element changed or removed concurrently is never deleted and anchors
/// nothing; a list element changed on both sides is edited in place when it is the one unmatched
/// element of its gap on each side.
pub(crate) fn edit<V: View>(w: &mut Writer, s: &Seq, view: &V, base: &Value, new: &Value) -> Result<Option<Seq>, Error> {
    let mut out = Seq { text: s.text, meta: Meta::default(), elems: BTreeMap::new() };
    if s.text {
        let (b, n) = (chars(base)?, chars(new)?);
        let vis = visible(s);
        let cur: Vec<char> = vis.iter().filter_map(|d| s.elems.get(d)).filter_map(|e| if let SeqContent::Char(c) = e.content { Some(c) } else { None }).collect();
        let to_cur: HashMap<usize, usize> = lcs(&b, &cur, |x, y| x == y).into_iter().collect();
        let steps = script(b.len(), n.len(), &lcs(&b, &n, |x, y| x == y), false);
        for st in &steps {
            if let Step::Del(i) = st
                && let Some(d) = to_cur.get(i).and_then(|c| vis.get(*c))
            {
                flag(&mut out, d.clone(), w);
            }
        }
        let anchor_of = |a: Option<usize>| matched_before(a, &to_cur).and_then(|c| vis.get(c)).cloned().map_or(Anchor::Head, Anchor::Dot);
        insert_runs(w, &mut out, &steps, &anchor_of, &mut |_, j| Ok(n.get(j).map_or(SeqContent::None, |c| SeqContent::Char(*c))))?;
    } else {
        let ev = view.element().ok_or(Error::Mismatch("list without element type"))?;
        let (b, n) = (items(base)?, items(new)?);
        let cur = list_view(s, &ev);
        // base to current by exact match; a base element changed concurrently is paired, for
        // nested edits only, when it is the one unmatched element of its gap on both sides
        let keep = lcs(b, &cur, |x, y| y.2.as_ref() == Some(x));
        let to_cur: HashMap<usize, usize> = keep.iter().copied().collect();
        let mut changed: HashMap<usize, usize> = HashMap::new();
        let mut prev: Option<(usize, usize)> = None;
        for &(ki, kc) in keep.iter().chain(std::iter::once(&(b.len(), cur.len()))) {
            let (i0, c0) = prev.map_or((0, 0), |(i, c)| (i + 1, c + 1));
            if ki == i0 + 1 && kc == c0 + 1 {
                changed.insert(i0, c0);
            }
            prev = Some((ki, kc));
        }
        let steps = script(b.len(), n.len(), &lcs(b, n, |x, y| x == y), true);
        for st in &steps {
            match st {
                Step::Pair(i, j) => {
                    let at = to_cur.get(i).or_else(|| changed.get(i));
                    let (Some((d, f, _)), Some(bv), Some(nv)) = (at.and_then(|c| cur.get(*c)), b.get(*i), n.get(*j)) else { continue };
                    if let Some(c) = nested_edit(w, f.as_ref(), &ev, bv, nv)? {
                        out.elems.insert(d.clone(), SeqElem { content: SeqContent::Frag(Box::new(c)), ..SeqElem::bare() });
                    }
                }
                Step::Del(i) => {
                    if let Some((d, _, _)) = to_cur.get(i).and_then(|c| cur.get(*c)) {
                        flag(&mut out, d.clone(), w);
                    }
                }
                _ => {}
            }
        }
        let anchor_of = |a: Option<usize>| matched_before(a, &to_cur).and_then(|c| cur.get(c)).map_or(Anchor::Head, |x| Anchor::Dot(x.0.clone()));
        insert_runs(w, &mut out, &steps, &anchor_of, &mut |w, j| {
            let item = n.get(j).ok_or(Error::Mismatch("index"))?;
            Ok(SeqContent::Frag(Box::new(crate::ops::create(w, &ev, item)?)))
        })?;
    }
    Ok((!out.elems.is_empty()).then_some(out))
}

/// The current index of the nearest base element at or before `a` that is still current.
fn matched_before(a: Option<usize>, to_cur: &HashMap<usize, usize>) -> Option<usize> {
    let mut i = a?;
    loop {
        if let Some(c) = to_cur.get(&i) {
            return Some(*c);
        }
        i = i.checked_sub(1)?;
    }
}

/// `edit(base, new)` of one list element, resolved against its current content.
fn nested_edit<V: View>(w: &mut Writer, cur: Option<&Fragment>, ev: &V, base: &Value, new: &Value) -> Result<Option<Fragment>, Error> {
    let ops = crate::ops::diff_values(Some(base), new, ev)?;
    let empty = Fragment::default();
    let mut b = Batch::new(cur.unwrap_or(&empty), w.clone());
    for op in &ops {
        b.apply(op, ev)?;
    }
    let (delta, back) = b.into_parts();
    *w = back;
    Ok(delta)
}

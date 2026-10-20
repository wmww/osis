//! Sequence ops (spec/crdt.md §5.7 Ops, Undo; §4.5 net effect): creation runs, delete, move,
//! paste (move + undelete), list element edits, undo. Index paths resolve against local state
//! and never go on the wire.

use crate::error::Error;
use crate::fragment::{Fragment, Meta};
use crate::linearize::{Placement, place};
use crate::ops::{Op, Writer};
use crate::seq::{Anchor, Seq, SeqContent, SeqElem, is_visible, top2, visible};
use crate::seq_span::{elem, expand};
use crate::stamp::{Dot, Stamp};
use crate::undo::Undone;
use crate::view::View;
use osis_core::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;

fn delta(text: bool) -> Seq {
    Seq { text, meta: Meta::default(), elems: BTreeMap::new() }
}

/// A creation run of `contents` chained from `anchor` (§5.7 insert); returns the new dots.
fn insert_run(w: &mut Writer, s: &mut Seq, anchor: Anchor, contents: Vec<SeqContent>) -> Vec<Dot> {
    let mut prev = anchor;
    let mut out = Vec::with_capacity(contents.len());
    for c in contents {
        let st = w.fresh();
        let d = st.dot.clone();
        s.elems.insert(d.clone(), SeqElem { created: Some((st.clone(), prev.clone())), content: c, pos: vec![(st, prev)], deleted: None, span: 1 });
        prev = Anchor::Dot(d.clone());
        out.push(d);
    }
    out
}

/// The contents of `items`: chars of strings (text) or created element fragments (list). List
/// contents take their counters before the elements (as the reference model).
fn contents<V: View>(w: &mut Writer, text: bool, view: &V, items: &[Value]) -> Result<Vec<SeqContent>, Error> {
    let mut out = Vec::new();
    if text {
        for it in items {
            let Value::Str(x) = it else { return Err(Error::Mismatch("text insert of a non-string")) };
            out.extend(x.chars().map(SeqContent::Char));
        }
    } else {
        let ev = view.element().ok_or(Error::Mismatch("list without element type"))?;
        for it in items {
            out.push(SeqContent::Frag(Box::new(crate::ops::create(w, &ev, it)?)));
        }
    }
    Ok(out)
}

/// A fresh sequence holding `v` (a string or list) as a creation run from HEAD; an empty one
/// gets an explicit `W` (§4.3).
pub(crate) fn create<V: View>(w: &mut Writer, text: bool, view: &V, v: &Value) -> Result<Seq, Error> {
    let items = match (text, v) {
        (true, Value::Str(_)) => std::slice::from_ref(v),
        (false, Value::List(items)) => items.as_slice(),
        _ => return Err(Error::Mismatch("value does not fit the sequence")),
    };
    let cs = contents(w, text, view, items)?;
    let mut s = delta(text);
    if cs.is_empty() {
        s.meta.w = Some(w.delta_stamp());
    } else {
        insert_run(w, &mut s, Anchor::Head, cs);
    }
    Ok(s)
}

fn anchor_after(vis: &[Dot], at: usize) -> Result<Anchor, Error> {
    match at {
        0 => Ok(Anchor::Head),
        i => vis.get(i - 1).cloned().map(Anchor::Dot).ok_or(Error::Mismatch("index out of range")),
    }
}

/// The range of a selection: the slice of the placement order (node indices) from its first to
/// its last visible element, hidden anchors inside included (§5.7).
fn range_of(p: &Placement, vis: &[Dot], at: usize, len: usize) -> Result<Range<usize>, Error> {
    let end = at.checked_add(len).filter(|e| *e <= vis.len()).ok_or(Error::Mismatch("range out of range"))?;
    let (Some(first), Some(last)) = (vis.get(at), end.checked_sub(1).and_then(|e| vis.get(e))) else { return Ok(0..0) };
    let i0 = p.order.iter().position(|d| d == first).unwrap_or(0);
    let i1 = p.order.iter().position(|d| d == last).unwrap_or(i0);
    Ok(i0..i1 + 1)
}

/// First dots of the nodes in `r`.
fn dots_of(p: &Placement, r: Range<usize>) -> Vec<Dot> {
    p.order.get(r).map(<[Dot]>::to_vec).unwrap_or_default()
}

fn position(w: &mut Writer, a: Anchor) -> SeqElem {
    SeqElem { pos: vec![(w.fresh(), a)], ..SeqElem::bare() }
}

/// The position writes moving `range` (placement order, by node) to `dest`, re-anchoring the
/// nodes outside it that hang below it at `pred` (§5.7 move). A node's first element carries its
/// edge; the next root anchors at the last element of the previous root's moved subtree.
fn move_writes(w: &mut Writer, p: &Placement, range: &[Dot], pred: Anchor, dest: Anchor) -> BTreeMap<Dot, SeqElem> {
    let inr: HashSet<&Dot> = range.iter().collect();
    let last_el: HashMap<&Dot, &Dot> = p.order.iter().zip(&p.last).collect();
    let parent: HashMap<&Dot, Option<&Dot>> = p.order.iter().zip(&p.parent).map(|(d, x)| (d, x.as_ref())).collect();
    let par = |d: &Dot| parent.get(d).copied().flatten();
    let roots: Vec<&Dot> = p.order.iter().filter(|d| inr.contains(d) && !par(d).is_some_and(|x| inr.contains(x))).collect();
    let outside: Vec<&Dot> = p.order.iter().filter(|d| !inr.contains(d) && par(d).is_some_and(|x| inr.contains(x))).collect();
    // the root whose moved subtree holds each element (preorder: parents come first)
    let rootset: HashSet<&Dot> = roots.iter().copied().collect();
    let outset: HashSet<&Dot> = outside.iter().copied().collect();
    let mut root_of: HashMap<&Dot, &Dot> = HashMap::new();
    let mut last: HashMap<&Dot, &Dot> = HashMap::new();
    for d in &p.order {
        let r = if outset.contains(d) || !inr.contains(d) && !rootset.contains(d) {
            None
        } else if rootset.contains(d) {
            Some(d)
        } else {
            par(d).and_then(|x| root_of.get(x).copied())
        };
        if let Some(r) = r {
            root_of.insert(d, r);
            last.insert(r, d);
        }
    }
    let mut out = BTreeMap::new();
    for o in outside.iter().rev() {
        out.insert((*o).clone(), position(w, pred.clone()));
    }
    let mut anchor = dest;
    for r in roots {
        out.insert(r.clone(), position(w, anchor));
        let l = last.get(r).copied().unwrap_or(r);
        anchor = Anchor::Dot(last_el.get(l).copied().unwrap_or(l).clone());
    }
    out
}

/// The visible element before node `i` in placement order, or HEAD.
fn pred_of(p: &Placement, s: &Seq, i: usize) -> Anchor {
    p.order.get(..i).unwrap_or_default().iter().rev().find(|d| s.elems.get(*d).is_some_and(|e| is_visible(e, s.text))).cloned().map_or(Anchor::Head, Anchor::Dot)
}

/// The dots a cut of `len` visible elements from `at` removes and a paste restores: the visible
/// ones (the clipboard text). A client remembers them beside the clipboard (§5.7 cut, paste).
pub fn cut_dots(state: &Fragment, at: usize, len: usize) -> Result<Vec<Dot>, Error> {
    let Fragment::Seq(s) = state.chosen() else { return Err(Error::Mismatch("not a sequence")) };
    let vis = visible(&s);
    let end = at.checked_add(len).filter(|e| *e <= vis.len()).ok_or(Error::Mismatch("range out of range"))?;
    Ok(vis.get(at..end).map(<[Dot]>::to_vec).unwrap_or_default())
}

/// Sequence op against present state `s` (§5.7 Ops); `None` if a no-op.
pub(crate) fn op<V: View>(w: &mut Writer, text: bool, s: Option<&Seq>, view: &V, op: &Op) -> Result<Option<Seq>, Error> {
    let empty = delta(text);
    let s = s.unwrap_or(&empty);
    let mut out = delta(text);
    match op {
        Op::Insert { at, items } => {
            let vis = visible(s);
            let anchor = anchor_after(&vis, *at)?;
            let cs = contents(w, text, view, items)?;
            if cs.is_empty() {
                return Ok(None);
            }
            insert_run(w, &mut out, anchor, cs);
        }
        Op::Delete { at, len } => {
            let vis = visible(s);
            let p = place(&s.elems);
            let d = w.delta_stamp();
            let r = range_of(&p, &vis, *at, *len)?;
            let n = p.span.get(r.clone()).unwrap_or_default().iter().fold(0u64, |a, b| a.saturating_add(*b));
            if n > osis_core::format::MAX_DELTA_BARE {
                // §3.3 rule 7: the caller splits a delete this long across commits
                return Err(Error::Mismatch("delete longer than MAX_DELTA_BARE"));
            }
            for (dot, span) in dots_of(&p, r.clone()).into_iter().zip(p.span.get(r).unwrap_or_default()) {
                out.elems.insert(dot, SeqElem { deleted: Some((d.clone(), true)), span: *span, ..SeqElem::bare() });
            }
        }
        Op::Move { at, len, to } => {
            let vis = visible(s);
            let p = place(&s.elems);
            let range = dots_of(&p, range_of(&p, &vis, *at, *len)?);
            if range.is_empty() {
                return Ok(None);
            }
            let inr: HashSet<&Dot> = range.iter().collect();
            let rest: Vec<Dot> = vis.iter().filter(|d| !inr.contains(d)).cloned().collect();
            let dest = anchor_after(&rest, *to)?;
            let pred = anchor_after(&vis, *at)?;
            out.elems = move_writes(w, &p, &range, pred, dest);
        }
        Op::Paste { dots, at } => {
            if !text {
                return Err(Error::Mismatch("paste is a text op"));
            }
            let held = |d: &Dot| s.elems.get(d).is_some_and(|e| matches!(e.content, SeqContent::Char(_)));
            if dots.is_empty() || !dots.iter().all(held) {
                return Err(Error::Mismatch("the clipboard no longer matches"));
            }
            let p = place(&s.elems);
            let at_of: HashMap<&Dot, usize> = p.order.iter().enumerate().map(|(i, d)| (d, i)).collect();
            let idx: Vec<usize> = dots.iter().filter_map(|d| at_of.get(d).copied()).collect();
            let (Some(i0), Some(i1)) = (idx.iter().min(), idx.iter().max()) else { return Err(Error::Mismatch("the clipboard no longer matches")) };
            if idx.len() != dots.len() {
                return Err(Error::Mismatch("the clipboard no longer matches"));
            }
            let range = dots_of(&p, *i0..*i1 + 1);
            // visible text inside the remembered range: the clipboard no longer matches
            let clip: HashSet<&Dot> = dots.iter().collect();
            if range.iter().any(|d| !clip.contains(d) && s.elems.get(d).is_some_and(|e| is_visible(e, text))) {
                return Err(Error::Mismatch("the clipboard no longer matches"));
            }
            let inr: HashSet<&Dot> = range.iter().collect();
            let rest: Vec<Dot> = visible(s).into_iter().filter(|d| !inr.contains(d)).collect();
            let dest = anchor_after(&rest, *at)?;
            let pred = pred_of(&p, s, *i0);
            out.elems = move_writes(w, &p, &range, pred, dest);
            let d = w.delta_stamp();
            for dot in dots {
                let c = s.elems.get(dot).map_or(SeqContent::None, |e| e.content.clone());
                let el = out.elems.entry(dot.clone()).or_insert_with(SeqElem::bare);
                el.deleted = Some((d.clone(), false));
                el.content = c;
            }
        }
        Op::Edit { base, new } => return crate::seq_diff::edit(w, s, view, base, new),
        _ => return Err(Error::Mismatch("not a sequence op")),
    }
    Ok((!out.elems.is_empty()).then_some(out))
}

/// The visible element at index `i`: its dot and, for a list, its content fragment.
pub(crate) fn element_at(s: &Seq, i: usize) -> Option<(Dot, Option<Fragment>)> {
    let d = visible(s).into_iter().nth(i)?;
    let content = match s.elems.get(&d).map(|e| &e.content) {
        Some(SeqContent::Frag(f)) => Some((**f).clone()),
        _ => None,
    };
    Some((d, content))
}

/// A list delta carrying `content` (a nested delta) on existing element `d` (§5.7 element edits).
pub(crate) fn wrap_element(d: Dot, content: Fragment) -> Seq {
    let el = SeqElem { content: SeqContent::Frag(Box::new(content)), ..SeqElem::bare() };
    Seq { text: false, meta: Meta::default(), elems: BTreeMap::from([(d, el)]) }
}

/// Merges `d`, a later op of the same commit, into `acc` (§4.5 net effect): a later write
/// overrides, a later reset drops the commit's earlier content, an element created and removed
/// in the commit is omitted and anchors naming it are rewritten to its own anchor.
pub(crate) fn overlay(acc: Seq, d: Seq, w: &Writer) -> Seq {
    let text = acc.text;
    let (mut meta, mut elems) = if d.meta.reset.is_some() { (d.meta, BTreeMap::new()) } else { (Meta { reset: acc.meta.reset, w: d.meta.w.or(acc.meta.w) }, expand(acc.elems)) };
    for (dot, de) in expand(d.elems) {
        let prev = elems.remove(&dot).unwrap_or_else(SeqElem::bare);
        let mut pos = prev.pos;
        pos.extend(de.pos);
        top2(&mut pos);
        // a list element reset drops the commit's earlier content of the element (same stamp)
        let content = match (prev.content, de.content) {
            (_, SeqContent::Frag(b)) if !text && de.deleted.is_some() => SeqContent::Frag(b),
            (_, SeqContent::None) if !text && de.deleted.is_some() => SeqContent::None,
            (SeqContent::Frag(a), SeqContent::Frag(b)) => SeqContent::Frag(Box::new(crate::batch::overlay(*a, *b, w))),
            (a, SeqContent::None) => a,
            (_, b) => b,
        };
        let mut el = SeqElem { created: prev.created.or(de.created), content, pos, deleted: de.deleted.or(prev.deleted), span: 1 };
        if text && el.flag() {
            // a deleted char is never carried (§3.3 rule 5)
            el.content = SeqContent::None;
        }
        elems.insert(dot, el);
    }
    // created and removed in this commit, and no write of the commit anchors at it: omitted (§4.5)
    let mut omitted = false;
    loop {
        let named: HashSet<&Dot> = elems.values().flat_map(|e| e.created.iter().chain(e.pos.iter())).filter_map(|(_, a)| if let Anchor::Dot(x) = a { Some(x) } else { None }).collect();
        let gone: Vec<Dot> = elems.iter().filter(|(d, e)| w.made(d) && e.created.is_some() && e.flag() && !named.contains(d)).map(|(d, _)| d.clone()).collect();
        if gone.is_empty() {
            break;
        }
        omitted = true;
        for g in gone {
            elems.remove(&g);
        }
    }
    if omitted && elems.is_empty() && meta.w.is_none() {
        // the omitted removal was a write inside the sequence (§4.3)
        meta.w = Some(w.delta_stamp());
    }
    Seq { text, meta, elems }
}

/// Nested undo of a list element's content: `(writer, undone content, current content, content
/// before the undone commit)`.
pub(crate) type NestedUndo<'a> = dyn FnMut(&mut Writer, &Fragment, Option<&Fragment>, Option<Fragment>) -> Result<Option<Fragment>, Error> + 'a;

/// Undo of a sequence delta (§4.6, §5.7 Undo) against the current state `cur` and the state
/// `before` the undone commit; `u` tells elements the undone commit created.
pub(crate) fn undo<V: View>(w: &mut Writer, undone: &Seq, cur: Option<&Seq>, before: Option<&Seq>, u: &Undone, view: &V, nested: &mut NestedUndo) -> Result<Option<Seq>, Error> {
    let made = |d: &Dot| u.made(d);
    let text = undone.text;
    let r = w.delta_stamp();
    let mut out = delta(text);
    let mut moves: Vec<(Stamp, Dot, Anchor)> = Vec::new();
    let mut reinsert: Vec<(Dot, Value)> = Vec::new();
    let was_visible = |d: &Dot| before.is_none_or(|b| b.elems.get(d).is_some_and(|e| is_visible(e, text)));
    for (dot, el) in &expand(undone.elems.clone()) {
        let now = cur.and_then(|c| elem(&c.elems, dot));
        let now = now.as_deref();
        let pre = before.and_then(|b| elem(&b.elems, dot));
        let pre = pre.as_deref();
        if el.created.is_some() && made(dot) {
            // insert: text delete flag, list element reset
            out.elems.insert(dot.clone(), SeqElem { deleted: Some((r.clone(), true)), ..SeqElem::bare() });
            continue;
        }
        match &el.deleted {
            Some((_, true)) if text && was_visible(dot) => {
                // delete: undelete carrying the content
                let c = [pre, now].into_iter().flatten().map(|e| e.content.clone()).find(|c| matches!(c, SeqContent::Char(_)));
                out.elems.insert(dot.clone(), SeqElem { deleted: Some((r.clone(), false)), content: c.unwrap_or(SeqContent::None), ..SeqElem::bare() });
            }
            Some((_, true)) if !text => {
                // list delete: re-insert the value with a fresh dot after the old element
                let v = pre.and_then(|e| if let SeqContent::Frag(f) = &e.content { f.read() } else { None });
                if let Some(v) = v {
                    reinsert.push((dot.clone(), v));
                }
            }
            Some((_, false)) if before.is_none() || pre.is_some_and(SeqElem::flag) => {
                out.elems.insert(dot.clone(), SeqElem { deleted: Some((r.clone(), true)), ..SeqElem::bare() });
            }
            _ => {}
        }
        // position writes: back to the pre-move anchor if still `cur`, or if an undo in effect
        // restored its anchor (then only from the pre-commit state)
        for (st, a) in el.pos.iter().filter(|p| p.0.dot != *dot) {
            let cur_w = now.and_then(|n| n.pos.first());
            if !u.steps_back((st, a), cur_w.map(|p| (&p.0, &p.1))) {
                continue;
            }
            let won = cur_w.is_some_and(|p| p.0 == *st);
            let back = pre.and_then(|e| e.pos.first()).or_else(|| if won { now.and_then(|n| n.pos.get(1)) } else { None });
            if let Some((bs, a)) = back {
                moves.push((bs.clone(), dot.clone(), a.clone()));
            }
        }
        if let SeqContent::Frag(f) = &el.content
            && !(el.created.is_some() && made(dot))
        {
            let cur_c = now.and_then(|n| if let SeqContent::Frag(x) = &n.content { Some(&**x) } else { None });
            let pre_c = pre.and_then(|e| if let SeqContent::Frag(x) = &e.content { Some((**x).clone()) } else { None });
            if let Some(c) = nested(w, f, cur_c, pre_c)? {
                let e = out.elems.entry(dot.clone()).or_insert_with(SeqElem::bare);
                e.content = SeqContent::Frag(Box::new(c));
            }
        }
    }
    // restored positions in their original stamp order, so siblings keep their order
    moves.sort_by(|a, b| a.0.cmp(&b.0));
    for (_, d, a) in moves {
        let st = w.fresh();
        out.elems.entry(d).or_insert_with(SeqElem::bare).pos.push((st, a));
    }
    if !reinsert.is_empty() {
        let ev = view.element().ok_or(Error::Mismatch("list without element type"))?;
        for (d, v) in reinsert {
            let c = SeqContent::Frag(Box::new(crate::ops::create(w, &ev, &v)?));
            insert_run(w, &mut out, Anchor::Dot(d), vec![c]);
        }
    }
    Ok((!out.elems.is_empty()).then_some(out))
}

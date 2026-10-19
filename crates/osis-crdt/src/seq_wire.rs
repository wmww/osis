//! Sequence runs on the wire (spec/crdt.md §3.2 Run, §3.3 rules 2, 3, 5, 7).

use crate::error::Error;
use crate::seq::{Anchor, Seq, SeqContent, SeqElem, top2};
use crate::stamp::{Dot, Stamp};
use crate::wire::{Dec, DeltaKind, Enc, MAX_RUN, as_array, as_uint, uint};
use osis_core::Value;
use osis_core::format::MAX_DELTA_BARE;

/// Content goes on the wire for text elements not deleted (rule 5) and for list elements whose
/// fragment exists.
fn has_content(e: &SeqElem) -> bool {
    match &e.content {
        SeqContent::None => false,
        SeqContent::Char(_) => !e.flag(),
        SeqContent::Frag(_) => true,
    }
}

/// "Carries something" (rule 3): deleted (text) or reset (list), or has content.
fn carries(e: &SeqElem) -> bool {
    e.flag() || !matches!(e.content, SeqContent::None)
}

/// Maximal runs (rule 3) as `(start, n)` over the wire-ordered elements.
fn runs(text: bool, v: &[(&Dot, &SeqElem)]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some((d0, e0)) = v.get(i) {
        let mut n = 1;
        while (n as u64) < MAX_RUN {
            let (Some((d, e)), Some((dp, _))) = (v.get(i + n), v.get(i + n - 1)) else { break };
            let next = dp.ctr.checked_add(1);
            if d.src != d0.src || Some(d.ctr) != next || carries(e) != carries(e0) || (!text && has_content(e) != has_content(e0)) {
                break;
            }
            let ok = if e0.created.is_some() {
                matches!(&e.created, Some((_, Anchor::Dot(a))) if a == *dp)
            } else {
                e.created.is_none() && e.pos.is_empty() && e0.pos.is_empty() && e.deleted == e0.deleted
            };
            if !ok {
                break;
            }
            n += 1;
        }
        out.push((i, n));
        i += n;
    }
    out
}

fn anchor(cx: &mut Enc, a: &Anchor) -> Value {
    match a {
        Anchor::Head => cx.anchor(None),
        Anchor::Dot(d) => cx.anchor(Some(d)),
    }
}

/// The commit index of a stamp as `Enc::stamp` encodes it (`Ci` or `[Ci, ctr]`).
fn commit_index(v: &Value) -> u64 {
    let ci = match v {
        Value::List(a) => a.first(),
        v => Some(v),
    };
    ci.and_then(|c| as_uint(c).ok()).unwrap_or(0)
}

/// The `[Run*]` array of `s` (before paging), runs in wire order.
pub(crate) fn encode_elems(s: &Seq, cx: &mut Enc) -> Result<Vec<Value>, Error> {
    let v = cx.sorted(&s.elems);
    let mut out = Vec::new();
    for (start, n) in runs(s.text, &v) {
        let run = v.get(start..start + n).unwrap_or_default();
        let Some((d0, e0)) = run.first() else { continue };
        let first = cx.dot(d0);
        let creation = match &e0.created {
            None => Value::List(Vec::new()),
            Some((_, a)) => {
                let a = anchor(cx, a);
                let mut segs: Vec<(u64, u64)> = Vec::new();
                for (_, e) in run {
                    let Some((st, _)) = &e.created else { continue };
                    let ci = commit_index(&cx.stamp(st));
                    match segs.last_mut() {
                        Some((c, k)) if *c == ci => *k += 1,
                        _ => segs.push((ci, 1)),
                    }
                }
                let segs = segs.into_iter().map(|(c, k)| Value::List(vec![uint(c), uint(k)])).collect();
                Value::List(vec![a, Value::List(segs)])
            }
        };
        let content = if !run.iter().any(|(_, e)| has_content(e)) {
            Value::List(Vec::new())
        } else if s.text {
            Value::Str(run.iter().filter(|(_, e)| has_content(e)).filter_map(|(_, e)| if let SeqContent::Char(c) = e.content { Some(c) } else { None }).collect())
        } else {
            let mut fs = Vec::with_capacity(run.len());
            for (_, e) in run {
                if let SeqContent::Frag(f) = &e.content {
                    fs.push(cx.fragment(f)?);
                }
            }
            Value::List(fs)
        };
        let mut posw = Vec::new();
        for (k, (d, e)) in run.iter().enumerate() {
            for (st, a) in e.pos.iter().filter(|p| p.0.dot != **d) {
                let st = cx.stamp(st);
                posw.push(Value::List(vec![uint(k as u64), st, anchor(cx, a)]));
            }
        }
        let mut flagw = Vec::new();
        let mut k = 0;
        while let Some((_, e)) = run.get(k) {
            let Some((st, b)) = &e.deleted else {
                k += 1;
                continue;
            };
            let mut j = k;
            while run.get(j + 1).is_some_and(|(_, x)| x.deleted.as_ref() == e.deleted.as_ref()) {
                j += 1;
            }
            flagw.push(Value::List(vec![uint(k as u64), uint(j as u64), cx.stamp(st), Value::Bool(*b)]));
            k = j + 1;
        }
        out.push(Value::List(vec![first, uint(n as u64), creation, content, Value::List(posw), Value::List(flagw)]));
    }
    Ok(out)
}

fn index(v: &Value, n: usize) -> Result<usize, Error> {
    usize::try_from(as_uint(v)?).ok().filter(|i| *i < n).ok_or(Error::Malformed("run index out of range"))
}

fn dec_anchor(cx: &Dec, v: &Value) -> Result<Anchor, Error> {
    Ok(cx.anchor(v)?.map_or(Anchor::Head, Anchor::Dot))
}

/// Reads runs (one page or the whole array) into `s`; the canonical re-encode checks the rest.
pub(crate) fn decode_elems(s: &mut Seq, runs: &[Value], cx: &mut Dec) -> Result<(), Error> {
    let writer = cx.kind() == DeltaKind::Writer;
    for r in runs {
        let [d, n, creation, content, posw, flagw] = as_array(r)? else { return Err(Error::Malformed("run")) };
        let first = cx.dot(d)?;
        let n = as_uint(n)?;
        if n == 0 || n > MAX_RUN {
            return Err(Error::Malformed("run length"));
        }
        let last = first.ctr.checked_add(n - 1).ok_or(Error::Malformed("run counter overflow"))?;
        // before allocating: bare anchors only in snapshots, content-less elements bounded
        // elsewhere (rule 7)
        let empty = |v: &Value| matches!(v, Value::List(x) if x.is_empty());
        if cx.kind() != DeltaKind::Snapshot {
            if empty(creation) && empty(content) && empty(posw) && empty(flagw) {
                return Err(Error::Malformed("bare anchors outside a snapshot"));
            }
            if empty(content) {
                cx.bare = cx.bare.saturating_add(n);
                if cx.bare > MAX_DELTA_BARE {
                    return Err(Error::Malformed("more than MAX_DELTA_BARE elements without content"));
                }
            }
        }
        let own = first.src == *cx.own();
        if writer && own && last >= cx.range().hi {
            return Err(Error::Malformed("own dot above the counter range"));
        }
        let n = usize::try_from(n).map_err(|_| Error::Malformed("run length"))?;
        let dot = |i: usize| Dot::new(first.src.clone(), first.ctr + i as u64);
        let mut elems: Vec<SeqElem> = (0..n).map(|_| SeqElem::bare()).collect();
        match as_array(creation)? {
            [] => {}
            [a, segs] => {
                if writer && first.src.is_derived() {
                    return Err(Error::Malformed("embedded characters in a writer's delta"));
                }
                let mut prev = dec_anchor(cx, a)?;
                let mut i = 0usize;
                let mut last_ci = None;
                for seg in as_array(segs)? {
                    let [ci, k] = as_array(seg)? else { return Err(Error::Malformed("segment")) };
                    let k = usize::try_from(as_uint(k)?).map_err(|_| Error::Malformed("segment length"))?;
                    if k == 0 || last_ci.as_ref() == Some(ci) {
                        return Err(Error::Malformed("non-canonical segments"));
                    }
                    last_ci = Some(ci.clone());
                    let base = cx.stamp(ci)?;
                    if base.dot.src != first.src {
                        return Err(Error::Malformed("segment of another source"));
                    }
                    let end = i.checked_add(k).filter(|e| *e <= n).ok_or(Error::Malformed("segments exceed the run"))?;
                    for j in i..end {
                        let d = dot(j);
                        if writer && own && !cx.range().contains(d.ctr) {
                            return Err(Error::Malformed("own write outside the counter range"));
                        }
                        cx.claim(&d)?;
                        let st = Stamp { ts: base.ts, dot: d.clone() };
                        if let Some(e) = elems.get_mut(j) {
                            e.created = Some((st.clone(), prev.clone()));
                            e.pos.push((st, prev));
                        }
                        prev = Anchor::Dot(d);
                    }
                    i = end;
                }
                if i != n {
                    return Err(Error::Malformed("segments short of the run"));
                }
            }
            _ => return Err(Error::Malformed("creation")),
        }
        for p in as_array(posw)? {
            let [i, st, a] = as_array(p)? else { return Err(Error::Malformed("position write")) };
            let i = index(i, n)?;
            let st = cx.stamp(st)?;
            cx.claim(&st.dot)?;
            let a = dec_anchor(cx, a)?;
            if let Some(e) = elems.get_mut(i) {
                e.pos.push((st, a));
            }
        }
        for f in as_array(flagw)? {
            let [i, j, st, b] = as_array(f)? else { return Err(Error::Malformed("flag write")) };
            let (i, j) = (index(i, n)?, index(j, n)?);
            let st = cx.stamp(st)?;
            if writer && st.dot.ctr != cx.range().lo {
                // a commit-level write: the delta stamp (§2.3)
                return Err(Error::Malformed("flag write off the delta stamp"));
            }
            let Value::Bool(b) = b else { return Err(Error::Malformed("flag")) };
            if i > j {
                return Err(Error::Malformed("flag range"));
            }
            if !s.text && !b {
                return Err(Error::Malformed("undelete of a list element"));
            }
            for e in elems.get_mut(i..=j).unwrap_or_default() {
                if e.deleted.as_ref().is_none_or(|x| st > x.0) {
                    e.deleted = Some((st.clone(), *b));
                }
            }
        }
        match (content, s.text) {
            (Value::List(v), _) if v.is_empty() => {}
            (Value::Str(chars), true) => {
                let mut cs = chars.chars();
                for e in elems.iter_mut().filter(|e| !e.flag()) {
                    e.content = SeqContent::Char(cs.next().ok_or(Error::Malformed("content shorter than the run"))?);
                }
                if cs.next().is_some() {
                    return Err(Error::Malformed("content longer than the run"));
                }
            }
            (Value::List(fs), false) => {
                if fs.len() != n {
                    return Err(Error::Malformed("content length differs from the run"));
                }
                for (e, f) in elems.iter_mut().zip(fs) {
                    let f = cx.fragment(f)?;
                    if f.is_empty() {
                        return Err(Error::Malformed("empty element fragment"));
                    }
                    e.content = SeqContent::Frag(Box::new(f));
                }
            }
            _ => return Err(Error::Malformed("content")),
        }
        for (i, mut e) in elems.into_iter().enumerate() {
            top2(&mut e.pos);
            if s.elems.insert(dot(i), e).is_some() {
                return Err(Error::Malformed("element in two runs"));
            }
        }
    }
    Ok(())
}

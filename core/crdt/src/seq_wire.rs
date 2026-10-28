//! Sequence runs on the wire (spec/crdt.md §3.2 Run, §3.3 rules 2, 3, 5, 7).

use crate::error::Error;
use crate::seq::{Anchor, Seq, SeqContent, SeqElem, top2};
use crate::seq_span::{nth, overlaps};
use crate::stamp::{Dot, Stamp};
use osis_base::Ts;
use crate::wire::{Dec, DeltaKind, Enc, MAX_RUN, as_array, as_uint, uint};
use osis_base::Value;
use osis_base::format::{CHUNK_MAX, MAX_DELTA_BARE};

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

/// A run element range: `(record dot, record, offset, length)`.
type Piece<'a> = (&'a Dot, &'a SeqElem, u64, u64);

/// Maximal runs (rule 3) over the wire-ordered records, as pieces of records (a range record's
/// elements share every property the rule compares, and chain to each other).
fn runs<'a>(text: bool, v: &[(&'a Dot, &'a SeqElem)]) -> Vec<Vec<Piece<'a>>> {
    let mut out = Vec::new();
    let (mut i, mut off) = (0usize, 0u64);
    while let Some((k0, e0)) = v.get(i).copied() {
        let d0 = nth(k0, off);
        let mut run: Vec<Piece<'a>> = Vec::new();
        let (mut n, mut prev) = (0u64, d0.clone());
        while let Some((k, e)) = v.get(i).copied() {
            if n > 0 {
                // a new record starts here (`off` is 0)
                if k.src != d0.src || Some(k.ctr) != prev.ctr.checked_add(1) || carries(e) != carries(e0) || (!text && has_content(e) != has_content(e0)) {
                    break;
                }
                let ok = if e0.created.is_some() {
                    matches!(&e.created, Some((_, Anchor::Dot(a))) if *a == prev)
                } else {
                    e.created.is_none() && e.pos.is_empty() && e0.pos.is_empty() && e.deleted == e0.deleted
                };
                if !ok {
                    break;
                }
            }
            let take = (e.span - off).min(MAX_RUN - n);
            run.push((k, e, off, take));
            n += take;
            prev = nth(k, off + take - 1);
            off += take;
            if off == e.span {
                i += 1;
                off = 0;
            }
            if n == MAX_RUN {
                break;
            }
        }
        out.push(run);
    }
    out
}

fn anchor(cx: &mut Enc, a: &Anchor) -> Value {
    match a {
        Anchor::Head => cx.anchor(None),
        Anchor::Dot(d) => cx.anchor(Some(d)),
    }
}

/// The `[Run*]` array of `s` (before paging), runs in wire order.
pub(crate) fn encode_elems(s: &Seq, cx: &mut Enc) -> Result<Vec<Value>, Error> {
    let v = cx.sorted(s.elems());
    let mut out = Vec::new();
    for run in runs(s.text, &v) {
        // a list run also closes once its content reaches `CHUNK_MAX` bytes (rule 3), so a run
        // fits a page; the collecting pass ignores this (rule 1 orders sources without it)
        if s.text || cx.collecting() || !run.iter().any(|p| has_content(p.1)) {
            out.push(encode_run(s.text, &run, None, cx)?);
            continue;
        }
        // content-carrying list elements are single-element records, all of the run's
        let (mut start, mut size, mut fs) = (0, 0, Vec::new());
        for (j, p) in run.iter().enumerate() {
            if let SeqContent::Frag(f) = &p.1.content {
                let v = cx.fragment(f)?;
                size += osis_base::encode(&v).len();
                fs.push(v);
            }
            if size >= CHUNK_MAX || j + 1 == run.len() {
                out.push(encode_run(false, run.get(start..=j).unwrap_or_default(), Some(std::mem::take(&mut fs)), cx)?);
                start = j + 1;
                size = 0;
            }
        }
    }
    Ok(out)
}

/// One run; `content`: its list content already encoded.
fn encode_run(text: bool, run: &[Piece], content: Option<Vec<Value>>, cx: &mut Enc) -> Result<Value, Error> {
    let Some(&(k0, e0, off0, _)) = run.first() else { return Err(Error::Malformed("empty run")) };
    let n: u64 = run.iter().map(|p| p.3).sum();
    let first = cx.dot(&nth(k0, off0));
    let creation = match &e0.created {
        None => Value::List(Vec::new()),
        Some((_, a)) => {
            let a = if off0 == 0 { anchor(cx, a) } else { anchor(cx, &Anchor::Dot(nth(k0, off0 - 1))) };
            let mut segs: Vec<(u64, u64)> = Vec::new();
            for &(k, e, off, len) in run {
                let Some((st, _)) = &e.created else { continue };
                let ci = if off == 0 { cx.commit_of(st) } else { cx.commit_of(&Stamp { ts: st.ts, dot: nth(k, off) }) };
                let ci = as_uint(&ci).unwrap_or(0);
                match segs.last_mut() {
                    Some((c, x)) if *c == ci => *x += len,
                    _ => segs.push((ci, len)),
                }
            }
            let segs = segs.into_iter().map(|(c, k)| Value::List(vec![uint(c), uint(k)])).collect();
            Value::List(vec![a, Value::List(segs)])
        }
    };
    // content and extra position writes sit only on single-element records
    let content = if let Some(fs) = content {
        Value::List(fs)
    } else if !run.iter().any(|p| has_content(p.1)) {
        Value::List(Vec::new())
    } else if text {
        Value::Str(run.iter().filter(|p| has_content(p.1)).filter_map(|p| p.1.char()).collect())
    } else {
        let mut fs = Vec::with_capacity(run.len());
        for p in run {
            if let SeqContent::Frag(f) = &p.1.content {
                fs.push(cx.fragment(f)?);
            }
        }
        Value::List(fs)
    };
    let mut posw = Vec::new();
    let mut flagw: Vec<(u64, u64, &(Stamp, bool))> = Vec::new();
    let mut idx = 0u64;
    for &(k, e, _, len) in run {
        if e.span == 1 {
            for (st, a) in e.pos.iter().filter(|p| p.0.dot != *k) {
                let st = cx.stamp(st);
                posw.push(Value::List(vec![uint(idx), st, anchor(cx, a)]));
            }
        }
        if let Some(dl) = &e.deleted {
            match flagw.last_mut() {
                Some((_, to, x)) if *to + 1 == idx && *x == dl => *to = idx + len - 1,
                _ => flagw.push((idx, idx + len - 1, dl)),
            }
        }
        idx += len;
    }
    let mut fw = Vec::with_capacity(flagw.len());
    for (i, j, (st, b)) in flagw {
        fw.push(Value::List(vec![uint(i), uint(j), cx.stamp(st), Value::Bool(*b)]));
    }
    if matches!(&content, Value::List(x) if x.is_empty()) {
        cx.note_bare(n)?;
    }
    Ok(Value::List(vec![first, uint(n), creation, content, Value::List(posw), Value::List(fw)]))
}

fn index(v: &Value, n: u64) -> Result<u64, Error> {
    Some(as_uint(v)?).filter(|i| *i < n).ok_or(Error::Malformed("run index out of range"))
}

fn dec_anchor(cx: &Dec, v: &Value) -> Result<Anchor, Error> {
    Ok(cx.anchor(v)?.map_or(Anchor::Head, Anchor::Dot))
}

/// Reads runs (one page or the whole array) into `s`; the canonical re-encode checks the rest.
/// Allocates per run, not per element: uniform content-less stretches become range records.
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
        // before allocating: bare anchors only in snapshots and imports, content-less elements
        // bounded elsewhere (rule 7)
        let empty = |v: &Value| matches!(v, Value::List(x) if x.is_empty());
        if cx.kind() != DeltaKind::Snapshot {
            if writer && empty(creation) && empty(content) && empty(posw) && empty(flagw) {
                return Err(Error::Malformed("bare anchors outside a snapshot or an import"));
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
        // creation: the first anchor and segments `(offset, length, ts)`
        let mut anchor0 = Anchor::Head;
        let mut segs: Vec<(u64, u64, Ts)> = Vec::new();
        match as_array(creation)? {
            [] => {}
            [a, ss] => {
                if writer && first.src.is_derived() {
                    return Err(Error::Malformed("embedded characters in a writer's delta"));
                }
                anchor0 = dec_anchor(cx, a)?;
                let mut i = 0u64;
                let mut last_ci = None;
                for seg in as_array(ss)? {
                    let [ci, k] = as_array(seg)? else { return Err(Error::Malformed("segment")) };
                    let k = as_uint(k)?;
                    if k == 0 || last_ci == Some(ci) {
                        return Err(Error::Malformed("non-canonical segments"));
                    }
                    last_ci = Some(ci);
                    let base = cx.stamp(ci)?;
                    if base.dot.src != first.src {
                        return Err(Error::Malformed("segment of another source"));
                    }
                    let end = i.checked_add(k).filter(|e| *e <= n).ok_or(Error::Malformed("segments exceed the run"))?;
                    if writer && own {
                        // a writer's own counters: bounded by its header range and rule 7
                        for j in i..end {
                            let d = nth(&first, j);
                            if !cx.range().contains(d.ctr) {
                                return Err(Error::Malformed("own write outside the counter range"));
                            }
                            cx.claim(&d)?;
                        }
                    }
                    segs.push((i, end - i, base.ts));
                    i = end;
                }
                if i != n {
                    return Err(Error::Malformed("segments short of the run"));
                }
            }
            _ => return Err(Error::Malformed("creation")),
        }
        let mut pws: Vec<(u64, Stamp, Anchor)> = Vec::new();
        for p in as_array(posw)? {
            let [i, st, a] = as_array(p)? else { return Err(Error::Malformed("position write")) };
            let i = index(i, n)?;
            let st = cx.stamp(st)?;
            cx.claim(&st.dot)?;
            let a = dec_anchor(cx, a)?;
            pws.push((i, st, a));
        }
        pws.sort_by_key(|p| p.0);
        let mut fws: Vec<(u64, u64, (Stamp, bool))> = Vec::new();
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
            // canonical flag writes are maximal ranges in order (rule 2), so never overlap
            if fws.last().is_some_and(|x| i <= x.1) {
                return Err(Error::Malformed("overlapping flag writes"));
            }
            fws.push((i, j, (st, *b)));
        }
        // content: one char per element not deleted (text), one fragment per element (list)
        let mut chars: Option<std::str::Chars> = None;
        let mut frags: Option<std::slice::Iter<Value>> = None;
        match (content, s.text) {
            (Value::List(v), _) if v.is_empty() => {}
            (Value::Str(cs), true) => {
                let deleted: u64 = fws.iter().filter(|f| f.2.1).map(|f| f.1 - f.0 + 1).sum();
                let want = usize::try_from(n - deleted).map_err(|_| Error::Malformed("run length"))?;
                match cs.chars().count().cmp(&want) {
                    std::cmp::Ordering::Less => return Err(Error::Malformed("content shorter than the run")),
                    std::cmp::Ordering::Greater => return Err(Error::Malformed("content longer than the run")),
                    std::cmp::Ordering::Equal => {}
                }
                chars = Some(cs.chars());
            }
            (Value::List(fs), false) => {
                if fs.len() as u64 != n {
                    return Err(Error::Malformed("content length differs from the run"));
                }
                frags = Some(fs.iter());
            }
            _ => return Err(Error::Malformed("content")),
        }
        // records: cut wherever a property may change; elements with content stand alone
        let mut cuts: Vec<u64> = vec![0, n];
        cuts.extend(segs.iter().map(|x| x.0));
        cuts.extend(pws.iter().flat_map(|x| [x.0, x.0 + 1]));
        cuts.extend(fws.iter().flat_map(|x| [x.0, x.1 + 1]));
        cuts.sort_unstable();
        cuts.dedup();
        let (mut si, mut pi, mut fi) = (0usize, 0usize, 0usize);
        for w in cuts.windows(2) {
            let [a, b] = *w else { continue };
            while segs.get(si).is_some_and(|x| x.0 + x.1 <= a) {
                si += 1;
            }
            while fws.get(fi).is_some_and(|x| x.1 < a) {
                fi += 1;
            }
            let deleted = fws.get(fi).filter(|x| x.0 <= a).map(|x| x.2.clone());
            let ts = segs.get(si).map(|x| x.2);
            let flag = deleted.as_ref().is_some_and(|x| x.1);
            let single = frags.is_some() || chars.is_some() && !flag;
            let mut at = a;
            while at < b {
                let len = if single { 1 } else { b - at };
                let dot = nth(&first, at);
                let created = ts.map(|ts| (Stamp { ts, dot: dot.clone() }, if at == 0 { anchor0.clone() } else { Anchor::Dot(nth(&first, at - 1)) }));
                let mut pos: Vec<(Stamp, Anchor)> = created.iter().cloned().collect();
                while let Some((i, st, an)) = pws.get(pi) {
                    if *i != at {
                        break;
                    }
                    pos.push((st.clone(), an.clone()));
                    pi += 1;
                }
                top2(&mut pos);
                let content = if let Some(fs) = frags.as_mut() {
                    let f = cx.fragment(fs.next().ok_or(Error::Malformed("content length differs from the run"))?)?;
                    if f.is_empty() {
                        return Err(Error::Malformed("empty element fragment"));
                    }
                    SeqContent::Frag(Box::new(f))
                } else if let (Some(cs), false) = (chars.as_mut(), flag) {
                    SeqContent::Char(cs.next().ok_or(Error::Malformed("content shorter than the run"))?)
                } else {
                    SeqContent::None
                };
                if overlaps(s.elems(), &dot, len) {
                    return Err(Error::Malformed("element in two runs"));
                }
                s.elems_mut().insert(dot, SeqElem { created, content, pos, deleted: deleted.clone(), span: len });
                at += len;
            }
        }
    }
    Ok(())
}

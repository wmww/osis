//! Sequence runs on the wire (spec/crdt.md §3.2 Run, §3.3 rules 2, 3, 5, 7).

use crate::error::Error;
use crate::seq::{Anchor, PosW, Seq, SeqContent, SeqElem, top2};
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

/// A `FlagW` range being encoded: bounds, the write, an undelete's chars.
type FlagRange<'a> = (u64, u64, &'a (Stamp, bool), Option<String>);

/// A `FlagW` range decoded: bounds, the write, an undelete's chars (one per element).
type FlagRun = (u64, u64, (Stamp, bool), Option<Vec<char>>);

/// The creation's char (what a run's `Content` lists; an undelete's copy rides its `FlagW`).
fn creation_char(e: &SeqElem) -> Option<char> {
    if let SeqContent::Char(c) = e.content { Some(c) } else { None }
}

/// Elements of one record in a run, as the run's encoding reads them (list content is encoded
/// as it is pushed): first dot, length, creation stamp and anchor of the first, the extra
/// position writes (single-element records only), the deletion and a text char.
struct Part {
    dot: Dot,
    len: u64,
    created: Option<(Stamp, Anchor)>,
    pos: Vec<PosW>,
    deleted: Option<(Stamp, bool)>,
    /// The undelete's char (§5.7), carried in its `FlagW`.
    undel: Option<char>,
    ch: Option<char>,
}

/// The run being built: what rule 3 compares against its first record, and the chunk not yet
/// written (a list run's content is cut at `CHUNK_MAX`; the run goes on in the next chunk).
struct Open {
    src: crate::stamp::Source,
    carries: bool,
    content: bool,
    creation: bool,
    pos_empty: bool,
    deleted: Option<(Stamp, bool)>,
    prev: Dot,
    n: u64,
    parts: Vec<Part>,
    fs: Vec<Value>,
    size: usize,
    /// Sources of the written chunks' position and flag writes, noted when the run closes
    /// (a later chunk's content may close nested runs first).
    held: [Vec<crate::stamp::Source>; 2],
}

/// Maximal runs (rule 3) over records pushed in wire order, written as they close: whole
/// sequences and, across pages, streamed ones (one open run held). Every source is noted in the
/// order of rule 1: a run's first dot and anchor, its content, then (deferred to the end of the
/// run, past any `CHUNK_MAX` cut) its position writes and flag writes.
pub(crate) struct Runs {
    text: bool,
    open: Option<Open>,
}

impl Runs {
    pub(crate) fn new(text: bool) -> Runs {
        Runs { text, open: None }
    }

    /// Whether record `(k, e)` continues the open run `o` (rule 3).
    fn continues(&self, o: &Open, k: &Dot, e: &SeqElem) -> bool {
        if k.src != o.src || Some(k.ctr) != o.prev.ctr.checked_add(1) || carries(e) != o.carries || (!self.text && has_content(e) != o.content) {
            return false;
        }
        if o.creation {
            matches!(&e.created, Some((_, Anchor::Dot(a))) if *a == o.prev)
        } else {
            e.created.is_none() && e.pos.is_empty() && o.pos_empty && e.deleted == o.deleted
        }
    }

    /// Adds record `(k, e)`, the next in wire order; closed runs go to `out`.
    pub(crate) fn push(&mut self, k: &Dot, e: &SeqElem, cx: &mut Enc, out: &mut Vec<Value>) -> Result<(), Error> {
        let mut off = 0u64;
        while off < e.span {
            // past the first piece of a record the open run is full
            if let Some(o) = &self.open
                && (o.n == MAX_RUN || off > 0 || !self.continues(o, k, e))
            {
                self.close(cx, out)?;
            }
            let anchor_at = |a: &Anchor| if off == 0 { a.clone() } else { Anchor::Dot(nth(k, off - 1)) };
            if self.open.is_none() {
                let d0 = nth(k, off);
                cx.dot(&d0);
                if let Some((_, a)) = &e.created {
                    anchor(cx, &anchor_at(a));
                }
                let deleted = e.deleted.clone();
                self.open = Some(Open { src: k.src.clone(), carries: carries(e), content: has_content(e), creation: e.created.is_some(), pos_empty: e.pos.is_empty(), deleted, prev: d0, n: 0, parts: Vec::new(), fs: Vec::new(), size: 0, held: Default::default() });
            }
            let Some(o) = self.open.as_mut() else { return Err(Error::Malformed("run")) };
            let take = (e.span - off).min(MAX_RUN - o.n);
            let created = e.created.as_ref().map(|(st, a)| (if off == 0 { st.clone() } else { Stamp { ts: st.ts, dot: nth(k, off) } }, anchor_at(a)));
            let pos = if e.span == 1 { e.pos.iter().filter(|p| p.0.dot != *k).cloned().collect() } else { Vec::new() };
            let ch = if self.text && has_content(e) { creation_char(e) } else { None };
            o.parts.push(Part { dot: nth(k, off), len: take, created, pos, deleted: e.deleted.clone(), undel: e.undel, ch });
            o.n += take;
            o.prev = nth(k, off + take - 1);
            off += take;
            // a list run also closes once its content reaches `CHUNK_MAX` bytes (rule 3), so a
            // run fits a page; content-carrying list elements are single-element records
            if let (false, SeqContent::Frag(f)) = (self.text, &e.content) {
                let v = cx.fragment(f)?;
                o.size += osis_base::encode(&v).len();
                o.fs.push(v);
                if o.size >= CHUNK_MAX {
                    self.chunk(cx, out)?;
                }
            }
        }
        Ok(())
    }

    /// Writes the open run's parts so far as one run.
    fn chunk(&mut self, cx: &mut Enc, out: &mut Vec<Value>) -> Result<(), Error> {
        let Some(o) = self.open.as_mut() else { return Ok(()) };
        if o.parts.is_empty() {
            return Ok(());
        }
        let parts = std::mem::take(&mut o.parts);
        let fs = std::mem::take(&mut o.fs);
        o.size = 0;
        let content = (!self.text && o.content).then_some(fs);
        out.push(encode_run(self.text, &parts, content, cx)?);
        let [p, f] = cx.undefer();
        o.held[0].extend(p);
        o.held[1].extend(f);
        Ok(())
    }

    /// Closes the open run: its last chunk, then the sources of its position and flag writes.
    pub(crate) fn close(&mut self, cx: &mut Enc, out: &mut Vec<Value>) -> Result<(), Error> {
        self.chunk(cx, out)?;
        if let Some(o) = self.open.take() {
            cx.note_held(o.held);
        }
        Ok(())
    }
}

fn anchor(cx: &mut Enc, a: &Anchor) -> Value {
    match a {
        Anchor::Head => cx.anchor(None),
        Anchor::Dot(d) => cx.anchor(Some(d)),
    }
}

/// The runs of `s` in wire order, into `p` as they close.
pub(crate) fn encode_elems(s: &Seq, cx: &mut Enc, p: &mut crate::codec::Pager) -> Result<(), Error> {
    let mut out = Vec::new();
    let mut runs = Runs::new(s.text);
    for (k, e) in cx.sorted(s.elems()) {
        runs.push(k, e, cx, &mut out)?;
        for v in out.drain(..) {
            p.push(cx.sink(), v)?;
        }
    }
    runs.close(cx, &mut out)?;
    for v in out {
        p.push(cx.sink(), v)?;
    }
    Ok(())
}

/// One run of `parts`; `content`: its list content, encoded.
fn encode_run(text: bool, parts: &[Part], content: Option<Vec<Value>>, cx: &mut Enc) -> Result<Value, Error> {
    let Some(p0) = parts.first() else { return Err(Error::Malformed("empty run")) };
    let n: u64 = parts.iter().map(|p| p.len).sum();
    let first = cx.dot(&p0.dot);
    let creation = match &p0.created {
        None => Value::List(Vec::new()),
        Some((_, a)) => {
            let a = anchor(cx, a);
            let mut segs: Vec<(u64, u64)> = Vec::new();
            for p in parts {
                let Some((st, _)) = &p.created else { continue };
                let ci = as_uint(&cx.commit_of(st)).unwrap_or(0);
                match segs.last_mut() {
                    Some((c, x)) if *c == ci => *x += p.len,
                    _ => segs.push((ci, p.len)),
                }
            }
            let segs = segs.into_iter().map(|(c, k)| Value::List(vec![uint(c), uint(k)])).collect();
            Value::List(vec![a, Value::List(segs)])
        }
    };
    let content = match content {
        Some(fs) => Value::List(fs),
        None if text && parts.iter().any(|p| p.ch.is_some()) => Value::Str(parts.iter().filter_map(|p| p.ch).collect()),
        None => Value::List(Vec::new()),
    };
    // rule 1: sources of position and flag writes count after the whole run's content (held:
    // `Runs::chunk` takes them, `Runs::close` notes them)
    cx.defer(0);
    let mut posw = Vec::new();
    // flag writes: maximal ranges of one write, an undelete's chars (one per element) with it
    let mut flagw: Vec<FlagRange<'_>> = Vec::new();
    let mut idx = 0u64;
    for p in parts {
        for (st, a, key) in &p.pos {
            let st = cx.stamp(st);
            let mut w = vec![uint(idx), st, anchor(cx, a)];
            w.extend(key.as_ref().map(|k| cx.stamp(k)));
            posw.push(Value::List(w));
        }
        if let Some(dl) = &p.deleted {
            match flagw.last_mut() {
                Some((_, to, x, u)) if *to + 1 == idx && *x == dl && u.is_some() == p.undel.is_some() => {
                    *to = idx + p.len - 1;
                    u.iter_mut().zip(p.undel).for_each(|(u, c)| u.push(c));
                }
                _ => flagw.push((idx, idx + p.len - 1, dl, p.undel.map(String::from))),
            }
        }
        idx += p.len;
    }
    cx.defer(1);
    let mut fw = Vec::with_capacity(flagw.len());
    for (i, j, (st, b), u) in flagw {
        let mut w = vec![uint(i), uint(j), cx.stamp(st), Value::Bool(*b)];
        w.extend(u.map(Value::Str));
        fw.push(Value::List(w));
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
        // before allocating: bare anchors only in snapshots, content-less elements
        // bounded elsewhere (rule 7)
        let empty = |v: &Value| matches!(v, Value::List(x) if x.is_empty());
        if cx.kind() != DeltaKind::Snapshot {
            if writer && empty(creation) && empty(content) && empty(posw) && empty(flagw) {
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
        let mut pws: Vec<(u64, PosW)> = Vec::new();
        for p in as_array(posw)? {
            let (i, st, a, key) = match as_array(p)? {
                [i, st, a] => (i, st, a, None),
                [i, st, a, k] => (i, st, a, Some(k)),
                _ => return Err(Error::Malformed("position write")),
            };
            let i = index(i, n)?;
            let st = cx.stamp(st)?;
            cx.claim(&st.dot)?;
            let a = dec_anchor(cx, a)?;
            // a sibling key is an older commit's write stamp, any commit's (§5.7, §3.3 rule 7); its
            // `ts` below the write's, so no held stamp is above an applied commit's (§2.2)
            let key = key.map(|k| cx.key_stamp(k)).transpose()?;
            if key.as_ref().is_some_and(|k| k.ts >= st.ts) {
                return Err(Error::Malformed("sibling key not below its stamp's ts"));
            }
            pws.push((i, (st, a, key)));
        }
        pws.sort_by_key(|p| p.0);
        // flag writes; an undelete's chars, one per element of its range, with it (§5.7)
        let mut fws: Vec<FlagRun> = Vec::new();
        for f in as_array(flagw)? {
            let (i, j, st, b, u) = match as_array(f)? {
                [i, j, st, b] => (i, j, st, b, None),
                [i, j, st, b, Value::Str(u)] => (i, j, st, b, Some(u)),
                _ => return Err(Error::Malformed("flag write")),
            };
            let (i, j) = (index(i, n)?, index(j, n)?);
            let st = cx.level_stamp(st)?;
            let Value::Bool(b) = b else { return Err(Error::Malformed("flag")) };
            if i > j {
                return Err(Error::Malformed("flag range"));
            }
            if !s.text && !b {
                return Err(Error::Malformed("undelete of a list element"));
            }
            let u = match u {
                None => None,
                Some(_) if *b => return Err(Error::Malformed("chars on a delete")),
                Some(u) => {
                    let cs: Vec<char> = u.chars().collect();
                    if cs.len() as u64 != j - i + 1 {
                        return Err(Error::Malformed("undelete chars differ from the range"));
                    }
                    Some(cs)
                }
            };
            // canonical flag writes are maximal ranges in order (rule 2), so never overlap
            if fws.last().is_some_and(|x| i <= x.1) {
                return Err(Error::Malformed("overlapping flag writes"));
            }
            fws.push((i, j, (st, *b), u));
        }
        // content: one char per element not deleted (text), one fragment per element (list)
        let mut chars: Option<std::str::Chars> = None;
        let mut frags: Option<std::slice::Iter<Value>> = None;
        match (content, s.text) {
            (Value::List(v), _) if v.is_empty() => {}
            (Value::Str(cs), true) => {
                // a text char is the creation's payload (an undelete's rides its `FlagW`)
                if segs.is_empty() {
                    return Err(Error::Malformed("text content without a creation"));
                }
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
            let fw = fws.get(fi).filter(|x| x.0 <= a);
            let deleted = fw.map(|x| x.2.clone());
            let undels = fw.and_then(|x| x.3.as_ref().map(|u| (x.0, u)));
            let ts = segs.get(si).map(|x| x.2);
            let flag = deleted.as_ref().is_some_and(|x| x.1);
            let single = frags.is_some() || chars.is_some() && !flag || undels.is_some();
            let mut at = a;
            while at < b {
                let len = if single { 1 } else { b - at };
                let dot = nth(&first, at);
                let created = ts.map(|ts| (Stamp { ts, dot: dot.clone() }, if at == 0 { anchor0.clone() } else { Anchor::Dot(nth(&first, at - 1)) }));
                let mut pos: Vec<PosW> = created.iter().map(|(s, a)| (s.clone(), a.clone(), None)).collect();
                while let Some((i, p)) = pws.get(pi) {
                    if *i != at {
                        break;
                    }
                    pos.push(p.clone());
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
                let undel = undels.and_then(|(from, u)| u.get((at - from) as usize).copied());
                s.elems_mut().insert(dot, SeqElem { created, content, pos, deleted: deleted.clone(), undel, span: len });
                at += len;
            }
        }
    }
    Ok(())
}

//! Range records: one record may stand for `span` consecutive elements of one source that are
//! uniform: no position write but the creation, one deleted write or element reset, either no
//! creation or creations (element `i` created at `dot + i` at its own `ts`, never below the one
//! before, anchored anywhere, by default at element `i - 1`: `SeqElem::each`) on one side of
//! its flag write (text: the flag wins for all or none, §5.7, `seq::flag_cut`), and no content
//! or, for a list without an element reset, the same value-less content written at each
//! creation's own stamp (a template: the first element's, `template`). Value-less records
//! (deleted, expired, purged) so cost a `ts` and an anchor each at most, about what the wire
//! holds. Decoding (a page's records among themselves) and `Fragment::compact` make maximal
//! ranges (`coalesce`); join, prune and linearization split a range only where a write lands or
//! anchors inside it, and linearization before each element not anchored at the one before (its
//! nodes are creation chains). Element `i` of a record is `piece(.., i, 1)`.
//!
//! Invariant: no record key lies inside another record's span. In dot order a `Derived(S, c)`
//! dot sits between `(S, c)` and `(S, c + 1)`, so an `S` range never spans such a key; the record
//! holding a dot is then the one at or before it.

use crate::fragment::{Enum, Fragment, Meta, Register, Struct};
use crate::seq::{Anchor, Each, SeqContent, SeqElem};
use crate::stamp::{Dot, SourceKind, Stamp};
use osis_base::Ts;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

pub(crate) type Elems = BTreeMap<Dot, SeqElem>;

/// The dot `k` after `d` in its source.
pub(crate) fn nth(d: &Dot, k: u64) -> Dot {
    Dot::new(d.src.clone(), d.ctr.saturating_add(k))
}

/// Elements `off..off + len` of record `(d, e)` as one record (`off > 0` only for a range).
pub(crate) fn piece(d: &Dot, e: &SeqElem, off: u64, len: u64) -> (Dot, SeqElem) {
    let each = |from: usize| e.each.as_ref().filter(|_| len > 1).map(|x| Box::new(Each { ts: x.ts.clone(), at: x.at.clone(), from: x.from + from }));
    if off == 0 {
        let mut x = e.clone();
        x.span = len;
        x.each = each(0);
        return (d.clone(), x);
    }
    let start = nth(d, off);
    let created = e.creation_at(d, off).zip(e.anchor_at(d, off));
    let pos = created.iter().map(|(s, a)| (s.clone(), a.clone(), None)).collect();
    // a template written at the first creation's stamp, at this one's
    let content = match (&e.content, &e.created, &created) {
        (SeqContent::Frag(f), Some((from, _)), Some((to, _))) => SeqContent::Frag(Box::new(restamped(f, from, to))),
        _ => SeqContent::None,
    };
    let each = each(usize::try_from(off).unwrap_or(usize::MAX));
    (start, SeqElem { created, content, pos, deleted: e.deleted.clone(), undel: None, valueless: e.valueless, span: len, each })
}

/// A stamp of the record's first element (its creation) moved to the last element.
pub(crate) fn last_of(d: &Dot, e: &SeqElem, st: &Stamp) -> Stamp {
    if e.span < 2 || st.dot != *d {
        return st.clone();
    }
    match &e.created {
        Some((c, _)) if c == st => e.creation_at(d, e.span - 1).unwrap_or_else(|| st.clone()),
        _ => Stamp { ts: st.ts, dot: nth(d, e.span - 1) },
    }
}

/// Whether `f` is a range's content template at creation stamp `s`: non-empty, value-less, every
/// write stamped `s`, and no record of its own (registers, structs and enums only), so element
/// `i`'s content is `f` at its own creation stamp (`restamped`).
pub(crate) fn template(f: &Fragment, s: &Stamp) -> bool {
    let at = |x: &Option<Stamp>| x.as_ref().is_none_or(|x| x == s);
    let meta = |m: &Meta| at(&m.reset) && at(&m.w) && (m.w.is_none() || m.w_valueless);
    !f.is_empty()
        && match f {
            Fragment::Register(Register { reset, write }) => at(reset) && write.as_ref().is_none_or(|w| w.stamp == *s && w.value.is_none()),
            Fragment::Struct(Struct { meta: m, fields }) => meta(m) && fields.values().all(|x| template(x, s)),
            Fragment::Enum(Enum { meta: m, case, payloads }) => meta(m) && case.as_ref().is_none_or(|c| c.stamp == *s && c.case.is_none()) && payloads.values().all(|x| template(x, s)),
            _ => false,
        }
}

/// Template `f` (`template` at `from`) with every write at `to`.
pub(crate) fn restamped(f: &Fragment, from: &Stamp, to: &Stamp) -> Fragment {
    let mut f = f.clone();
    restamp(&mut f, from, to);
    f
}

fn restamp(f: &mut Fragment, from: &Stamp, to: &Stamp) {
    let at = |x: &mut Option<Stamp>| {
        if let Some(x) = x.as_mut().filter(|x| **x == *from) {
            *x = to.clone();
        }
    };
    let meta = |m: &mut Meta| {
        at(&mut m.reset);
        at(&mut m.w);
    };
    match f {
        Fragment::Register(r) => {
            at(&mut r.reset);
            if let Some(w) = r.write.as_mut().filter(|w| w.stamp == *from) {
                w.stamp = to.clone();
            }
        }
        Fragment::Struct(x) => {
            meta(&mut x.meta);
            x.fields.values_mut().for_each(|y| restamp(y, from, to));
        }
        Fragment::Enum(x) => {
            meta(&mut x.meta);
            if let Some(c) = x.case.as_mut().filter(|c| c.stamp == *from) {
                c.stamp = to.clone();
            }
            x.payloads.values_mut().for_each(|y| restamp(y, from, to));
        }
        _ => {}
    }
}

/// How many writes template `f` holds (`walk` visits each per element of its range).
pub(crate) fn template_writes(f: &Fragment) -> usize {
    let n = |x: &Option<Stamp>| usize::from(x.is_some());
    match f {
        Fragment::Register(r) => n(&r.reset) + usize::from(r.write.is_some()),
        Fragment::Struct(x) => n(&x.meta.reset) + n(&x.meta.w) + x.fields.values().map(template_writes).sum::<usize>(),
        Fragment::Enum(x) => n(&x.meta.reset) + n(&x.meta.w) + usize::from(x.case.is_some()) + x.payloads.values().map(template_writes).sum::<usize>(),
        _ => 0,
    }
}

/// Whether an element may be part of a range record.
fn uniform(d: &Dot, e: &SeqElem) -> bool {
    e.undel.is_none()
        && match &e.created {
            None => e.pos.is_empty() && matches!(e.content, SeqContent::None),
            Some(c) => c.0.dot == *d && e.pos.len() == 1 && e.pos.first().is_some_and(|p| crate::seq::is_creation(p, c)),
        }
        && match (&e.content, &e.created) {
            (SeqContent::None, _) => true,
            (SeqContent::Frag(f), Some((c, _))) => e.deleted.is_none() && template(f, c),
            _ => false,
        }
}

/// Whether a record (or row) of `span` elements starting at `k` holds `d`.
pub(crate) fn holds(k: &Dot, span: u64, d: &Dot) -> bool {
    k.src == d.src && d.ctr.checked_sub(k.ctr).is_some_and(|o| o < span)
}

/// The record holding `d`.
pub(crate) fn find<'a>(m: &'a Elems, d: &Dot) -> Option<(&'a Dot, &'a SeqElem)> {
    let (k, e) = m.range(..=d).next_back()?;
    holds(k, e.span, d).then_some((k, e))
}

/// Element records looked up by dot: a sequence's own, or a state's under a delta's
/// (`seq::Layered`).
pub(crate) trait Recs {
    /// The record holding `d`.
    fn find(&self, d: &Dot) -> Option<(&Dot, &SeqElem)>;
    /// The records starting in `a..=b`, in dot order; `None` where they cannot be listed.
    fn starting(&self, a: &Dot, b: &Dot) -> Option<Vec<(&Dot, &SeqElem)>>;
    /// The record starting at `d`.
    fn get(&self, d: &Dot) -> Option<&SeqElem> {
        self.find(d).filter(|(k, _)| *k == d).map(|x| x.1)
    }
    /// Element `d` (a copy for one inside a range).
    fn elem(&self, d: &Dot) -> Option<Cow<'_, SeqElem>> {
        let (k, e) = self.find(d)?;
        Some(if e.span == 1 { Cow::Borrowed(e) } else { Cow::Owned(piece(k, e, d.ctr - k.ctr, 1).1) })
    }
}

impl Recs for Elems {
    fn find(&self, d: &Dot) -> Option<(&Dot, &SeqElem)> {
        find(self, d)
    }
    fn starting(&self, a: &Dot, b: &Dot) -> Option<Vec<(&Dot, &SeqElem)>> {
        Some(self.range(a..=b).collect())
    }
    fn get(&self, d: &Dot) -> Option<&SeqElem> {
        BTreeMap::get(self, d)
    }
}

/// Splits the record holding `x` and a dot before it, so a record starts at `x`.
fn split_plain(m: &mut Elems, x: &Dot) {
    let Some((k, e)) = m.range(..x).next_back() else { return };
    if !holds(k, e.span, x) {
        return;
    }
    let (k, off) = (k.clone(), x.ctr - k.ctr);
    let Some(e) = m.remove(&k) else { return };
    let (a, ea) = piece(&k, &e, 0, off);
    let (b, eb) = piece(&k, &e, off, e.span - off);
    m.insert(a, ea);
    m.insert(b, eb);
}

/// Splits records so none spans across `x`, nor, for a `Derived(S, c)` dot, across its place
/// between `(S, c)` and `(S, c + 1)`.
pub(crate) fn split_at(m: &mut Elems, x: &Dot) {
    split_plain(m, x);
    if let SourceKind::Derived(u) = x.src.kind() {
        split_plain(m, &nth(u, 1));
    }
}

/// Whether a new record `(d, span)` would overlap a record of `m` or break the invariant.
pub(crate) fn overlaps(m: &Elems, d: &Dot, span: u64) -> bool {
    let last = nth(d, span - 1);
    let straddles = |x: &Dot| m.range(..x).next_back().is_some_and(|(k, e)| holds(k, e.span, x));
    m.range(d..=&last).next().is_some() || straddles(d) || matches!(d.src.kind(), SourceKind::Derived(u) if straddles(&nth(u, 1)))
}

/// For a range whose creations straddle `e`: how many leading elements are created below it.
pub(crate) fn chain_cut(d: &Dot, el: &SeqElem, e: Option<&Stamp>) -> Option<u64> {
    let (e, (st, _)) = (e?, el.created.as_ref()?);
    if el.span < 2 || *st >= *e {
        return None;
    }
    let at = |i: u64| el.creation_at(d, i).unwrap_or_else(|| st.clone());
    let (mut lo, mut hi) = (1u64, el.span);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if at(mid) >= *e { hi = mid } else { lo = mid + 1 }
    }
    (lo < el.span).then_some(lo)
}

/// Splits the records whose creations straddle `e`.
pub(crate) fn cut_chains(m: &mut Elems, e: Option<&Stamp>) {
    if e.is_none() {
        return;
    }
    let cuts: Vec<Dot> = m.iter().filter_map(|(d, el)| chain_cut(d, el, e).map(|c| nth(d, c))).collect();
    for x in cuts {
        split_plain(m, &x);
    }
}

/// Element-wise equality, whatever the split into records.
pub(crate) fn elems_eq(a: &Elems, b: &Elems) -> bool {
    let (mut ia, mut ib) = (a.iter(), b.iter());
    let (mut ca, mut cb) = (ia.next().map(|(k, e)| (k, e, 0u64)), ib.next().map(|(k, e)| (k, e, 0u64)));
    loop {
        let (Some((ka, ea, oa)), Some((kb, eb, ob))) = (ca, cb) else { return ca.is_none() && cb.is_none() };
        let len = (ea.span - oa).min(eb.span - ob);
        let same = if oa == 0 && ob == 0 && ea.span == len && eb.span == len {
            ka == kb && ea == eb
        } else {
            piece(ka, ea, oa, len) == piece(kb, eb, ob, len)
        };
        if !same {
            return false;
        }
        ca = if oa + len < ea.span { Some((ka, ea, oa + len)) } else { ia.next().map(|(k, e)| (k, e, 0)) };
        cb = if ob + len < eb.span { Some((kb, eb, ob + len)) } else { ib.next().map(|(k, e)| (k, e, 0)) };
    }
}

/// Every element as its own record: for deltas, whose element count the format bounds (§3.3
/// rule 7), never for a received state.
pub(crate) fn expand(m: Elems) -> Elems {
    if m.values().all(|e| e.span == 1) {
        return m;
    }
    let mut out = BTreeMap::new();
    for (d, e) in m {
        if e.span == 1 {
            out.insert(d, e);
        } else {
            for i in 0..e.span {
                let (x, y) = piece(&d, &e, i, 1);
                out.insert(x, y);
            }
        }
    }
    out
}

/// Whether record `(d, e)` continues range record `(a, ea)`: the next dot, both uniform, the same
/// deleted write, both without creation or both with (`ts` never falling), one side of the flag
/// write, and the same content template.
fn continues(a: &Dot, ea: &SeqElem, d: &Dot, e: &SeqElem) -> bool {
    let at = |x: &Dot, k: u64| x.src == a.src && Some(x.ctr) == a.ctr.checked_add(k);
    let chain = match (&ea.created, &e.created) {
        (None, None) => true,
        // an embedding is one chain, all at its register write's `ts` (§7)
        (Some(_), Some((y, ay))) => ea.ts_at(ea.span - 1).is_some_and(|t| y.ts >= t && (!a.src.is_derived() || (y.ts == t && *ay == Anchor::Dot(nth(a, ea.span - 1))))),
        _ => false,
    };
    let content = match (&ea.content, &e.content, &ea.created, &e.created) {
        (SeqContent::None, SeqContent::None, ..) => true,
        (SeqContent::Frag(x), SeqContent::Frag(y), Some((s, _)), Some((t, _))) => restamped(x, s, t) == **y,
        _ => false,
    };
    uniform(a, ea) && uniform(d, e) && at(d, ea.span) && chain && content && ea.deleted == e.deleted && ea.valueless == e.valueless && ea.win_flag().is_some() == e.win_flag().is_some()
}

/// Merges adjacent uniform records into maximal ranges: what decoding and `Fragment::compact`
/// hold (and tests build every state and delta as, so joins and linearization meet range
/// records). Records are merged only next to each other in dot order, so no range spans another
/// record's key.
pub(crate) fn coalesce(m: Elems) -> Elems {
    // each range with its elements' creation `ts` and own anchors, once any differs
    type Creations = Option<(Vec<Ts>, Vec<Option<Anchor>>)>;
    let mut out: Vec<(Dot, SeqElem, Creations)> = Vec::with_capacity(m.len());
    for (d, e) in m {
        if let Some((a, ea, each)) = out.last_mut()
            && continues(a, ea, &d, &e)
        {
            let chained = |x: &Dot, xe: &SeqElem, i: u64| xe.anchor_at(x, i).filter(|an| i == 0 || *an != Anchor::Dot(nth(x, i - 1)));
            if each.is_none() && (ea.each.is_some() || e.each.is_some() || e.ts_at(0) != ea.ts_at(0) || e.created.as_ref().is_some_and(|c| c.1 != Anchor::Dot(nth(a, ea.span - 1)))) {
                *each = Some(((0..ea.span).filter_map(|i| ea.ts_at(i)).collect(), (0..ea.span).map(|i| if i == 0 { None } else { chained(a, ea, i) }).collect()));
            }
            if let Some((ts, at)) = each {
                ts.extend((0..e.span).filter_map(|i| e.ts_at(i)));
                // `e`'s first element is the range's element `ea.span`
                at.extend((0..e.span).map(|i| if i == 0 { e.anchor_at(&d, 0).filter(|an| *an != Anchor::Dot(nth(a, ea.span - 1))) } else { chained(&d, &e, i) }));
            }
            ea.span += e.span;
            continue;
        }
        out.push((d, e, None));
    }
    // in order: a bulk build
    out.into_iter()
        .map(|(d, mut e, each)| {
            if let Some((ts, at)) = each {
                let first = e.ts_at(0);
                let ts = ts.iter().any(|t| Some(*t) != first).then(|| Arc::from(ts));
                let at = at.iter().any(Option::is_some).then(|| Arc::from(at));
                e.each = (ts.is_some() || at.is_some()).then(|| Box::new(Each { ts, at, from: 0 }));
            }
            (d, e)
        })
        .collect()
}

/// `coalesce` of the records at `fresh` (record keys of `m`) among themselves, in place: a
/// record not in `fresh` keeps its place and keeps the ones beside it apart.
pub(crate) fn coalesce_fresh(m: &mut Elems, fresh: &[Dot]) {
    let mut fresh = fresh.to_vec();
    fresh.sort();
    // groups of fresh keys next to each other in `m`
    let mut groups: Vec<Vec<Dot>> = Vec::new();
    for k in fresh {
        match groups.last_mut() {
            Some(g) if g.last().is_some_and(|p| m.range(p..=&k).nth(2).is_none()) => g.push(k),
            _ => groups.push(vec![k]),
        }
    }
    for g in groups.into_iter().filter(|g| g.len() > 1) {
        let held: Elems = g.into_iter().filter_map(|k| m.remove(&k).map(|e| (k, e))).collect();
        m.extend(coalesce(held));
    }
}

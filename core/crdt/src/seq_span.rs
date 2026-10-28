//! Range records: one record may stand for `span` consecutive elements of one source that are
//! uniform: no content, no position write but the creation, one deleted write or element reset,
//! and either no creation or a creation chain (one creation `ts`, element `i` anchored at element
//! `i - 1`). Decoding allocates per run, not per element (a run of 2^16 bare anchors is a few
//! bytes on the wire); join, prune and linearization split a range only where a write lands or
//! anchors inside it. Element `i` of a record is `piece(.., i, 1)`.
//!
//! Invariant: no record key lies inside another record's span. In dot order a `Derived(S, c)`
//! dot sits between `(S, c)` and `(S, c + 1)`, so an `S` range never spans such a key; the record
//! holding a dot is then the one at or before it.

use crate::seq::{Anchor, SeqContent, SeqElem};
use crate::stamp::{Dot, SourceKind, Stamp};
use std::borrow::Cow;
use std::collections::BTreeMap;

pub(crate) type Elems = BTreeMap<Dot, SeqElem>;

/// The dot `k` after `d` in its source.
pub(crate) fn nth(d: &Dot, k: u64) -> Dot {
    Dot::new(d.src.clone(), d.ctr.saturating_add(k))
}

/// Elements `off..off + len` of record `(d, e)` as one record (`off > 0` only for a range).
pub(crate) fn piece(d: &Dot, e: &SeqElem, off: u64, len: u64) -> (Dot, SeqElem) {
    if off == 0 {
        let mut x = e.clone();
        x.span = len;
        return (d.clone(), x);
    }
    let start = nth(d, off);
    let created = e.created.as_ref().map(|(st, _)| (Stamp { ts: st.ts, dot: start.clone() }, Anchor::Dot(nth(d, off - 1))));
    let pos = created.iter().cloned().collect();
    (start, SeqElem { created, content: SeqContent::None, pos, deleted: e.deleted.clone(), span: len })
}

/// A stamp of the record's first element (its creation) moved to the last element.
pub(crate) fn last_of(d: &Dot, e: &SeqElem, st: &Stamp) -> Stamp {
    if e.span > 1 && st.dot == *d { Stamp { ts: st.ts, dot: nth(d, e.span - 1) } } else { st.clone() }
}

/// Whether an element may be part of a range record.
pub(crate) fn uniform(d: &Dot, e: &SeqElem) -> bool {
    matches!(e.content, SeqContent::None)
        && match &e.created {
            None => e.pos.is_empty(),
            Some(c) => c.0.dot == *d && e.pos.len() == 1 && e.pos.first() == Some(c),
        }
}

/// The record holding `d`.
pub(crate) fn find<'a>(m: &'a Elems, d: &Dot) -> Option<(&'a Dot, &'a SeqElem)> {
    let (k, e) = m.range(..=d).next_back()?;
    (k.src == d.src && d.ctr - k.ctr < e.span).then_some((k, e))
}

/// Element `d` (a copy for one inside a range).
pub(crate) fn elem<'a>(m: &'a Elems, d: &Dot) -> Option<Cow<'a, SeqElem>> {
    let (k, e) = find(m, d)?;
    Some(if e.span == 1 { Cow::Borrowed(e) } else { Cow::Owned(piece(k, e, d.ctr - k.ctr, 1).1) })
}

/// Element records looked up by dot: a sequence's own, or a state's under a batch's
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
    if k.src != x.src || x.ctr - k.ctr >= e.span {
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
    let straddles = |x: &Dot| m.range(..x).next_back().is_some_and(|(k, e)| k.src == x.src && x.ctr - k.ctr < e.span);
    m.range(d..=&last).next().is_some() || straddles(d) || matches!(d.src.kind(), SourceKind::Derived(u) if straddles(&nth(u, 1)))
}

/// For a range whose creations straddle `e`: how many leading elements are created below it.
pub(crate) fn chain_cut(d: &Dot, el: &SeqElem, e: Option<&Stamp>) -> Option<u64> {
    let (e, (st, _)) = (e?, el.created.as_ref()?);
    if el.span < 2 || *st >= *e {
        return None;
    }
    let at = |i: u64| Stamp { ts: st.ts, dot: nth(d, i) };
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
/// deleted write, and both without creation or one creation chain.
fn continues(a: &Dot, ea: &SeqElem, d: &Dot, e: &SeqElem) -> bool {
    let at = |x: &Dot, k: u64| x.src == a.src && Some(x.ctr) == a.ctr.checked_add(k);
    let chain = match (&ea.created, &e.created) {
        (None, None) => true,
        (Some((x, _)), Some((y, Anchor::Dot(p)))) => x.ts == y.ts && at(p, ea.span - 1),
        _ => false,
    };
    uniform(a, ea) && uniform(d, e) && at(d, ea.span) && chain && ea.deleted == e.deleted
}

/// Merges adjacent uniform records into maximal ranges (a reset leaves the records it pruned bare;
/// tests: deltas and states built per element, so joins and linearization meet range records).
pub(crate) fn coalesce(m: Elems) -> Elems {
    let mut out: Vec<(Dot, SeqElem)> = Vec::with_capacity(m.len());
    for (d, e) in m {
        if let Some((a, ea)) = out.last_mut()
            && continues(a, ea, &d, &e)
        {
            ea.span += e.span;
            continue;
        }
        out.push((d, e));
    }
    // in order: a bulk build
    out.into_iter().collect()
}

/// `coalesce` in place, copying the records only when some merge.
pub(crate) fn coalesce_in(m: &mut Elems) {
    if m.iter().zip(m.iter().skip(1)).any(|((a, ea), (d, e))| continues(a, ea, d, e)) {
        *m = coalesce(std::mem::take(m));
    }
}

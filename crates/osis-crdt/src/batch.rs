//! A commit's delta for one aspect as the net effect of its ops (spec/crdt.md §4.5): ops resolve
//! against the state plus the batch's earlier ops; a later op overrides an earlier one at the
//! same register; an element created and removed in the batch is omitted.

use crate::error::Error;
use crate::fragment::{Bag, Elem, Encoding, Entry, Enum, Fragment, Map, Meta, Set, Struct};
use crate::ops::{PathOp, PathSeg, Writer, joined, key_state, leaf, seq_text};
use crate::seq::{self, Layered, SeqRead};
use crate::stamp::{CounterRange, Dot, Stamp, max_opt};
use crate::view::View;
use std::borrow::Cow;
use std::collections::BTreeMap;

/// Does the op's path plus a value it carries nest deeper than `MAX_VALUE_DEPTH` (spec/data-model.md
/// §5, Depth)? Checked before resolving, which recurses per level.
fn too_deep(op: &PathOp) -> bool {
    use crate::ops::Op;
    use osis_core::format::MAX_VALUE_DEPTH;
    let Some(room) = MAX_VALUE_DEPTH.checked_sub(op.path.len()) else { return true };
    let keys = op.path.iter().any(|s| matches!(s, PathSeg::Key(k) if k.deeper_than(MAX_VALUE_DEPTH)));
    keys || match &op.op {
        Op::Set(v) | Op::Replace(v) | Op::Put(v) | Op::Add(v) | Op::Remove(v) | Op::Inc(v) => v.deeper_than(room),
        Op::Edit { base, new } => base.deeper_than(room) || new.deeper_than(room),
        Op::Insert { items, .. } | Op::InsertAfter { items, .. } => items.iter().any(|v| v.deeper_than(room)),
        Op::RemoveAspect | Op::Delete { .. } | Op::Move { .. } | Op::Paste { .. } | Op::DeleteDots { .. } => false,
    }
}

/// Builds one aspect's delta from path ops.
pub struct Batch<'s> {
    state: &'s Fragment,
    w: Writer,
    acc: Option<Fragment>,
    /// The batch's view of the sequence position the last op met, if the batch had writes there.
    seen: Option<Seen<'s>>,
}

/// State joined with the batch's writes at one sequence position, reached through fields and
/// cases (`at`; `index`: the list an index segment steps into, else the position an op ends at),
/// under the batch's reset `e` from above: what `resolve` would copy there. Kept across ops at
/// that position while joining each op's delta into it equals the net effect (§4.5), dropped by
/// any other op.
struct Seen<'s> {
    at: Vec<PathSeg>,
    index: bool,
    frag: Over<'s>,
}

/// A view of a sequence position: the state's sequence under the batch's records, or (where a
/// reset of the batch lies above, or the placement cannot follow) a copy of both joined.
enum Over<'s> {
    Layer(Layered<'s>),
    Copy(Fragment),
}

/// Where `resolve` meets the probed sequence position (`rest` path segments left): it uses
/// `over` instead of copying state and batch writes there, and hands back what it used in `out`.
struct Probe<'s> {
    rest: usize,
    over: Option<Over<'s>>,
    out: Option<Over<'s>>,
}

/// What an op at a position resolves against: the fragment there (borrowed from the state where
/// the batch has no writes) or a layered sequence.
enum Cur<'a> {
    Frag(Option<Cow<'a, Fragment>>),
    Layer(Layered<'a>),
}

/// The sequence position `path` and `op` meet through fields and cases: prefix length and
/// whether an index steps into it; `None` past a map key (resolved by `key_lookup`, no copy) or
/// for a non-sequence op.
fn seq_point(path: &[PathSeg], op: &crate::ops::Op) -> Option<(usize, bool)> {
    use crate::ops::Op;
    for (i, s) in path.iter().enumerate() {
        match s {
            PathSeg::Field(_) | PathSeg::Case(_) => {}
            PathSeg::Index(_) => return Some((i, true)),
            PathSeg::Key(_) => return None,
        }
    }
    matches!(op, Op::Insert { .. } | Op::Delete { .. } | Op::Move { .. } | Op::Paste { .. } | Op::Edit { .. }).then_some((path.len(), false))
}

/// The fragment of `f` at a sequence point and the reset from above there, as `resolve` reaches
/// it (`e` grows with the batch side's resets only).
fn at_point<'f>(f: Option<&'f Fragment>, at: &[PathSeg], index: bool, batch: bool) -> (Option<&'f Fragment>, Option<Stamp>) {
    let mut f = f;
    let mut e = None;
    let step = |f: Option<&'f Fragment>, enc: Encoding, e: &mut Option<Stamp>| {
        let m = member(f, enc);
        if batch {
            *e = max_opt(e.take(), reset_of(m));
        }
        m
    };
    for seg in at {
        f = match seg {
            PathSeg::Field(id) => step(f, Encoding::Struct, &mut e).and_then(|x| if let Fragment::Struct(x) = x { x.fields.get(id) } else { None }),
            PathSeg::Case(id) => step(f, Encoding::Enum, &mut e).and_then(|x| if let Fragment::Enum(x) = x { x.payloads.get(id) } else { None }),
            _ => None,
        };
    }
    if index {
        f = step(f, Encoding::List, &mut e);
    }
    (f, e)
}

impl<'s> Batch<'s> {
    /// Ops resolve against `state` (the aspect's local state, pruned as join and decode leave
    /// it) and the batch so far.
    pub fn new(state: &'s Fragment, w: Writer) -> Batch<'s> {
        Batch { state, w, acc: None, seen: None }
    }

    /// Applies `op` under the writer's `view` (of the aspect root).
    pub fn apply<V: View>(&mut self, op: &PathOp, view: &V) -> Result<(), Error> {
        if too_deep(op) {
            return Err(Error::Mismatch("value nested deeper than MAX_VALUE_DEPTH"));
        }
        let point = seq_point(&op.path, &op.op).map(|(n, index)| (op.path.get(..n).unwrap_or_default().to_vec(), index));
        let seen = self.seen.take().filter(|x| point.as_ref().is_some_and(|(at, index)| *at == x.at && *index == x.index));
        let mut probe = point.as_ref().map(|(at, _)| Probe { rest: op.path.len() - at.len(), over: seen.map(|x| x.frag), out: None });
        let d = resolve(&mut self.w, Some(self.state), self.acc.as_ref(), None, &op.path, op, view, true, probe.as_mut())?;
        let kept = probe.and_then(|p| p.out);
        let Some(d) = d else {
            self.seen = point.zip(kept).map(|((at, index), frag)| Seen { at, index, frag });
            return Ok(());
        };
        let Some(a) = self.acc.take() else {
            self.acc = Some(d);
            return Ok(());
        };
        // the kept view goes on only if state ⊔ acc ⊔ d = state ⊔ next there (associativity):
        // checked at `d`'s elements only (`seq::Foot`), else on copies
        let mut follow = None;
        if let (Some((at, index)), Some(frag)) = (point, kept) {
            let (a_at, e) = at_point(Some(&a), &at, index, true);
            let (d_at, _) = at_point(Some(&d), &at, index, false);
            let foot = match (&frag, a_at, d_at) {
                (_, Some(Fragment::Seq(x)), Some(Fragment::Seq(y))) => seq::Foot::new(x, y, &self.w, e.as_ref()),
                _ => None,
            };
            let a_at = if foot.is_some() { None } else { a_at.cloned() };
            follow = Some((at, index, frag, e, foot, a_at, d_at.cloned()));
        }
        let next = overlay(a, d, &self.w);
        if let Some((at, index, frag, e, foot, a_at, d_at)) = follow {
            let (n_at, ne) = at_point(Some(&next), &at, index, true);
            let same = ne == e
                && match (&foot, n_at) {
                    (Some(f), Some(Fragment::Seq(n))) => f.matches(n),
                    (Some(_), _) => false,
                    (None, _) => {
                        let mut ch = crate::changes::Changes::new();
                        let mut j = a_at.unwrap_or_default();
                        j.prune(e.as_ref(), &mut ch);
                        if let Some(d_at) = &d_at {
                            j.join_into(d_at.clone(), e.as_ref(), &mut ch);
                        }
                        let mut n = n_at.cloned().unwrap_or_default();
                        n.prune(e.as_ref(), &mut ch);
                        j == n
                    }
                };
            let mut ch = crate::changes::Changes::new();
            let frag = match (frag, d_at) {
                _ if !same => None,
                (f, None) => Some(f),
                (Over::Copy(mut f), Some(d_at)) => {
                    f.join_into(d_at, e.as_ref(), &mut ch);
                    Some(Over::Copy(f))
                }
                (Over::Layer(mut l), Some(Fragment::Seq(d_at))) if e.is_none() => l.join(d_at).then_some(Over::Layer(l)),
                _ => None,
            };
            if let Some(frag) = frag {
                #[cfg(debug_assertions)]
                {
                    // what `resolve` would copy at this position for the next op
                    let (s_at, _) = at_point(Some(self.state), &at, index, false);
                    let mut whole = joined(s_at, n_at, e.as_ref()).unwrap_or_default();
                    let view = match &frag {
                        Over::Copy(f) => Cow::Borrowed(f),
                        Over::Layer(l) => {
                            // a layer over a `Slots` member: that member of the joined position
                            if let Fragment::Slots(x) = &mut whole {
                                whole = x.members.remove(&l.to_seq().encoding()).unwrap_or_default();
                            }
                            Cow::Owned(Fragment::Seq(l.to_seq()))
                        }
                    };
                    debug_assert!(whole == *view, "batch view differs from state + net effect");
                }
                self.seen = Some(Seen { at, index, frag });
            }
        }
        self.acc = Some(next);
        Ok(())
    }

    /// Whether a view of a sequence position is kept (tests).
    #[cfg(test)]
    pub(crate) fn keeps_view(&self) -> bool {
        self.seen.is_some()
    }

    /// The state as the batch sees it: the local state joined with the batch's writes.
    pub fn view(&self) -> Fragment {
        joined(Some(self.state), self.acc.as_ref(), None).unwrap_or_default()
    }

    /// The delta and the counter range it consumes; `None` if the ops changed nothing.
    pub fn finish(self) -> Option<(Fragment, CounterRange)> {
        let range = self.w.range();
        self.acc.filter(|f| !f.is_empty()).map(|f| (f, range))
    }

    /// The delta and the writer, whose counters continue (a nested batch inside another op).
    pub(crate) fn into_parts(self) -> (Option<Fragment>, Writer) {
        (self.acc.filter(|f| !f.is_empty()), self.w)
    }
}

fn member(f: Option<&Fragment>, enc: Encoding) -> Option<&Fragment> {
    match f?.slot(enc)? {
        crate::state::MemberRef::Frag(x) => Some(x),
        crate::state::MemberRef::Reg(_) => None,
    }
}

fn reset_of(f: Option<&Fragment>) -> Option<Stamp> {
    f.and_then(|f| f.meta()).and_then(|m| m.reset.clone())
}

/// The position's state with the batch's writes: borrowed when there are none.
fn current<'a>(s: Option<&'a Fragment>, a: Option<&Fragment>, e: Option<&Stamp>) -> Option<Cow<'a, Fragment>> {
    if a.is_none() && e.is_none() {
        return s.map(Cow::Borrowed);
    }
    joined(s, a, e).map(Cow::Owned)
}

/// `current`, or where the probe meets the path (`left` segments left) its kept view, else the
/// state's sequence layered under the batch's writes there.
fn point<'a>(probe: &mut Option<&mut Probe<'a>>, left: usize, s: Option<&'a Fragment>, a: Option<&Fragment>, e: Option<&Stamp>) -> Cur<'a> {
    if let Some(p) = probe.as_deref_mut().filter(|p| p.rest == left) {
        match p.over.take() {
            Some(Over::Copy(f)) => return Cur::Frag(Some(Cow::Owned(f))),
            Some(Over::Layer(l)) => return Cur::Layer(l),
            None => {}
        }
        if e.is_none()
            && let (Some(Fragment::Seq(b)), Some(Fragment::Seq(x))) = (seq_member(s, a), a)
            && let Some(l) = Layered::new(b, x.clone())
        {
            return Cur::Layer(l);
        }
    }
    Cur::Frag(current(s, a, e))
}

/// The state's sequence a batch's sequence writes `a` join as they would at the position `s`: at a
/// `Slots` position (§7) its member of `a`'s encoding when that carries the position's reset
/// (the join then leaves the other members as they are), else `s`.
fn seq_member<'a>(s: Option<&'a Fragment>, a: Option<&Fragment>) -> Option<&'a Fragment> {
    match (s, a) {
        (Some(f @ Fragment::Slots(x)), Some(Fragment::Seq(d))) => x.members.get(&d.encoding()).filter(|m| m.reset() == f.reset()),
        _ => s,
    }
}

/// Hands a view `point` made (or the kept one) back to the probe.
fn keep<'a>(probe: &mut Option<&mut Probe<'a>>, left: usize, cur: Cur<'a>) {
    if let Some(p) = probe.as_deref_mut().filter(|p| p.rest == left) {
        p.out = match cur {
            Cur::Frag(Some(Cow::Owned(f))) => Some(Over::Copy(f)),
            Cur::Layer(l) => Some(Over::Layer(l)),
            Cur::Frag(_) => None,
        };
    }
}

/// Resolves `op` at `path` below the position whose state is `s` and batch writes `a`; `e` is
/// the batch's effective reset from above. Returns the root-relative delta.
#[allow(clippy::too_many_arguments)]
fn resolve<'s, V: View>(w: &mut Writer, s: Option<&'s Fragment>, a: Option<&Fragment>, e: Option<Stamp>, path: &[PathSeg], op: &PathOp, view: &V, root: bool, mut probe: Option<&mut Probe<'s>>) -> Result<Option<Fragment>, Error> {
    let Some((seg, rest)) = path.split_first() else {
        // nothing of the batch at this position: resolve against the state itself, no clone
        let cur = point(&mut probe, 0, s, a, e.as_ref());
        let r = match &cur {
            Cur::Frag(c) => leaf(w, c.as_deref(), view, &op.op, root),
            // a sequence op (the probe stops only there); what `leaf` does with the joined copy
            Cur::Layer(l) => seq_text(view, &op.op).and_then(|text| {
                let s = (l.text() == text && l.present()).then_some(l as &dyn SeqRead);
                Ok(seq::op(w, text, s, view, &op.op)?.map(Fragment::Seq))
            }),
        };
        keep(&mut probe, 0, cur);
        return r;
    };
    let enc = match seg {
        PathSeg::Field(_) => Encoding::Struct,
        PathSeg::Key(_) => Encoding::Map,
        PathSeg::Case(_) => Encoding::Enum,
        PathSeg::Index(_) => view.encoding().filter(|e| *e == Encoding::List).ok_or(Error::Mismatch("index into a non-list"))?,
    };
    if view.encoding().is_some_and(|x| x != enc) {
        return Err(Error::Mismatch("path does not fit the type"));
    }
    let (s, a) = (member(s, enc), member(a, enc));
    let e = max_opt(e, reset_of(a));
    Ok(match seg {
        PathSeg::Field(id) => {
            let fview = view.field(*id).ok_or(Error::Mismatch("field not in the type"))?;
            let sc = s.and_then(|f| if let Fragment::Struct(x) = f { x.fields.get(id) } else { None });
            let ac = a.and_then(|f| if let Fragment::Struct(x) = f { x.fields.get(id) } else { None });
            resolve(w, sc, ac, e, rest, op, &fview, false, probe)?.map(|c| Fragment::Struct(Struct { meta: Meta::default(), fields: BTreeMap::from([(*id, c)]) }))
        }
        PathSeg::Case(id) => {
            let cur = current(s, a, e.as_ref());
            let case = match cur.as_deref() {
                Some(Fragment::Enum(x)) => x.case.as_ref().and_then(|c| c.case),
                _ => None,
            };
            if case != Some(*id) {
                return Err(Error::Mismatch("case is not current"));
            }
            let pview = view.case(*id).ok_or(Error::Mismatch("case has no payload"))?;
            let sc = s.and_then(|f| if let Fragment::Enum(x) = f { x.payloads.get(id) } else { None });
            let ac = a.and_then(|f| if let Fragment::Enum(x) = f { x.payloads.get(id) } else { None });
            resolve(w, sc, ac, e, rest, op, &pview, false, probe)?.map(|c| Fragment::Enum(Enum { meta: Meta::default(), case: None, payloads: BTreeMap::from([(*id, c)]) }))
        }
        PathSeg::Key(k) => {
            let vview = view.element().ok_or(Error::Mismatch("map without value type"))?;
            let put = match &op.op {
                crate::ops::Op::Put(v) if rest.is_empty() => Some(v),
                _ => None,
            };
            match key_lookup(s, a, e.as_ref(), k).filter(|_| put.is_none()) {
                Some((d, ks)) => {
                    // against what the key reads as (batch writes included), written into the lowest live dot (§5.6)
                    resolve(w, ks.as_deref(), None, None, rest, op, &vview, false, None)?
                        .map(|c| Fragment::Map(Map::new(Meta::default(), BTreeMap::from([(d, Entry { reset: None, key: Some(k.clone()), frag: Some(Box::new(c)), created: None })]))))
                }
                None => {
                    // a key that is not live, or a put_new: a new entry holding the op's writes
                    // against an absent value (§5.6); an op that writes nothing creates nothing.
                    // A path on through a field or case would create a partial struct or enum.
                    if matches!(rest.first(), Some(PathSeg::Field(_) | PathSeg::Case(_))) {
                        return Err(Error::Mismatch("no live entry with that key: put the whole value"));
                    }
                    let mut w2 = w.clone();
                    let d = w2.fresh().dot;
                    let c = match (&op.op, put, rest.is_empty()) {
                        (_, Some(v), _) | (crate::ops::Op::Set(v), None, true) => Some(crate::ops::create(&mut w2, &vview, v)?),
                        _ => resolve(&mut w2, None, None, None, rest, op, &vview, false, None)?,
                    };
                    let Some(c) = c else { return Ok(None) };
                    *w = w2;
                    let created = Some(Stamp::new(w.ts(), d.src.clone(), d.ctr));
                    Some(Fragment::Map(Map::new(Meta::default(), BTreeMap::from([(d, Entry { reset: None, key: Some(k.clone()), frag: Some(Box::new(c)), created })]))))
                }
            }
        }
        PathSeg::Index(i) => {
            let eview = view.element().ok_or(Error::Mismatch("list without element type"))?;
            let cur = point(&mut probe, path.len(), s, a, e.as_ref());
            let found = match &cur {
                Cur::Frag(c) => match c.as_deref() {
                    Some(Fragment::Seq(sq)) => seq::element_at(sq, *i),
                    _ => return Err(Error::Mismatch("index out of range")),
                },
                Cur::Layer(l) => seq::element_at(l, *i),
            };
            let (d, content) = found.ok_or(Error::Mismatch("index out of range"))?;
            keep(&mut probe, path.len(), cur);
            let c = resolve(w, content.as_ref(), None, None, rest, op, &eview, false, None)?;
            c.map(|c| Fragment::Seq(seq::wrap_element(d, c)))
        }
    })
}

/// The lowest live entry of key `k` and what the key reads as, at a map position with state `s`
/// and batch writes `a` under the reset `e` from above (§5.6). Only the entries carrying `k`
/// join: entries are independent per dot, so this equals a lookup in the whole join, in
/// O(log n) instead of a copy of the map; a key with one live entry the batch has not written
/// is read in place (no copy of what it holds).
fn key_lookup<'s>(s: Option<&'s Fragment>, a: Option<&Fragment>, e: Option<&Stamp>, k: &osis_core::Value) -> Option<(Dot, Option<std::borrow::Cow<'s, Fragment>>)> {
    fn map(f: Option<&Fragment>) -> Option<&Map> {
        match f {
            Some(Fragment::Map(m)) => Some(m),
            _ => None,
        }
    }
    let (sm, am) = (map(s), map(a));
    if e.is_none()
        && let Some(m) = sm
        && am.is_none_or(|a| !a.keys.contains_key(k) && m.keys.get(k).into_iter().flatten().all(|d| !a.entries.contains_key(d)))
        && let [d] = m.live_dots(k).as_slice()
    {
        return Some(((*d).clone(), m.entries.get(*d).and_then(|x| x.frag.as_deref()).map(std::borrow::Cow::Borrowed)));
    }
    let dots: std::collections::BTreeSet<&Dot> = [sm, am].into_iter().flatten().filter_map(|m| m.keys.get(k)).flatten().collect();
    if dots.is_empty() {
        return None;
    }
    let restrict = |m: Option<&Map>| m.map(|m| Fragment::Map(Map::new(m.meta.clone(), dots.iter().filter_map(|d| Some(((*d).clone(), m.entries.get(*d)?.clone()))).collect())));
    let Some(Fragment::Map(m)) = joined(restrict(sm).as_ref(), restrict(am).as_ref(), e) else { return None };
    let ds = m.live_dots(k);
    Some(((*ds.first()?).clone(), key_state(&m, &ds).map(std::borrow::Cow::Owned)))
}

/// Merges `d` (a later op of the same commit) into `acc` (§4.5 net effect).
pub(crate) fn overlay(acc: Fragment, d: Fragment, w: &Writer) -> Fragment {
    if acc.encoding() != d.encoding() {
        return d;
    }
    match (acc, d) {
        (Fragment::Register(mut a), Fragment::Register(b)) => {
            if b.reset.is_some() {
                a.reset = b.reset;
                a.write = None;
            }
            if b.write.is_some() {
                a.write = b.write;
            }
            Fragment::Register(a)
        }
        (Fragment::Bag(a), Fragment::Bag(b)) => {
            let (meta, elems) = overlay_elems(a.meta, a.elems, b.meta, b.elems, w);
            Fragment::Bag(Bag { kind: a.kind, meta, elems })
        }
        (Fragment::Set(a), Fragment::Set(b)) => {
            let (meta, elems) = overlay_elems(a.meta, a.elems, b.meta, b.elems, w);
            Fragment::Set(Set { meta, elems })
        }
        (Fragment::Struct(a), Fragment::Struct(b)) => {
            let (meta, fields) = overlay_children(a.meta, a.fields, b.meta, b.fields, w);
            Fragment::Struct(Struct { meta, fields })
        }
        (Fragment::Enum(a), Fragment::Enum(b)) => {
            let case = if b.meta.reset.is_some() || b.case.is_some() { b.case } else { a.case };
            let (meta, payloads) = overlay_children(a.meta, a.payloads, b.meta, b.payloads, w);
            Fragment::Enum(Enum { meta, case, payloads })
        }
        (Fragment::Map(a), Fragment::Map(b)) => {
            // the index carries over (a superset stays valid), so a long batch stays linear
            let keys = a.keys;
            let (mut meta, mut entries) = start(a.meta, a.entries, b.meta);
            let mut omitted = false;
            let touched: Vec<Dot> = b.entries.keys().cloned().collect();
            for (dot, de) in b.entries {
                if de.reset.is_some() && w.made(&dot) {
                    omitted |= entries.remove(&dot).is_some();
                    continue;
                }
                let prev = entries.remove(&dot).unwrap_or_default();
                let frag = overlay_opt(prev.frag, de.frag, de.reset.is_some(), w);
                let key = if frag.is_some() { de.key.or(prev.key) } else { None };
                let created = if frag.is_some() { de.created.or(prev.created) } else { None };
                entries.insert(dot, Entry { reset: de.reset.or(prev.reset), key, frag, created });
            }
            keep_present(&mut meta, omitted && entries.is_empty(), w);
            let mut m = Map { meta, entries, keys };
            for d in &touched {
                m.index_dot(d);
            }
            Fragment::Map(m)
        }
        (Fragment::Seq(a), Fragment::Seq(b)) => Fragment::Seq(seq::overlay(a, b, w)),
        (_, d) => d,
    }
}

/// A later reset drops the batch's earlier content below it (same commit, same stamp).
fn start<T>(a: Meta, items: BTreeMap<Dot, T>, b: Meta) -> (Meta, BTreeMap<Dot, T>) {
    if b.reset.is_some() {
        return (Meta { reset: b.reset, w: b.w }, BTreeMap::new());
    }
    (Meta { reset: a.reset, w: b.w.or(a.w) }, items)
}

fn overlay_opt(a: Option<Box<Fragment>>, b: Option<Box<Fragment>>, reset: bool, w: &Writer) -> Option<Box<Fragment>> {
    let a = if reset { None } else { a };
    match (a, b) {
        (a, None) => a,
        (None, b) => b,
        (Some(a), Some(b)) => Some(Box::new(overlay(*a, *b, w))),
    }
}

fn overlay_elems(am: Meta, ae: BTreeMap<Dot, Elem>, bm: Meta, be: BTreeMap<Dot, Elem>, w: &Writer) -> (Meta, BTreeMap<Dot, Elem>) {
    let (mut meta, mut elems) = start(am, ae, bm);
    let mut omitted = false;
    for (dot, de) in be {
        if de.reset.is_some() && w.made(&dot) {
            // created and removed in this commit: omitted (§4.5)
            omitted |= elems.remove(&dot).is_some();
            continue;
        }
        let prev = elems.remove(&dot).unwrap_or_default();
        let frag = overlay_opt(prev.frag, de.frag, de.reset.is_some(), w);
        elems.insert(dot, Elem { reset: de.reset.or(prev.reset), frag });
    }
    keep_present(&mut meta, omitted && elems.is_empty(), w);
    (meta, elems)
}

/// The omitted removal was a write inside the collection; with nothing else left, an explicit
/// `W` keeps the collection present as the one-by-one ops would (§4.3).
fn keep_present(meta: &mut Meta, empty: bool, w: &Writer) {
    if empty && meta.w.is_none() {
        meta.w = Some(w.delta_stamp());
    }
}

fn overlay_children(am: Meta, ac: BTreeMap<u64, Fragment>, bm: Meta, bc: BTreeMap<u64, Fragment>, w: &Writer) -> (Meta, BTreeMap<u64, Fragment>) {
    let (meta, mut children) = if bm.reset.is_some() { (Meta { reset: bm.reset, w: bm.w }, BTreeMap::new()) } else { (Meta { reset: am.reset, w: bm.w.or(am.w) }, ac) };
    for (k, f) in bc {
        let merged = match children.remove(&k) {
            Some(prev) => overlay(prev, f, w),
            None => f,
        };
        children.insert(k, merged);
    }
    (meta, children)
}

//! A commit's delta for one aspect as the net effect of its ops (spec/crdt.md §4.5): ops resolve
//! against the state plus the batch's earlier ops; a later op overrides an earlier one at the
//! same register; an element created and removed in the batch is omitted.

use crate::error::Error;
use crate::fragment::{Bag, Elem, Encoding, Entry, Enum, Fragment, Map, Meta, Set, Struct};
use crate::ops::{PathOp, PathSeg, Writer, joined, key_state, leaf, live_entries};
use crate::seq;
use crate::stamp::{CounterRange, Dot, Stamp, max_opt};
use crate::view::View;
use std::collections::BTreeMap;

/// Does the op's path plus a value it carries nest deeper than `MAX_VALUE_DEPTH` (spec/data-model.md
/// §5, Depth)? Checked before resolving, which recurses per level.
fn too_deep(op: &PathOp) -> bool {
    use crate::ops::Op;
    use osis_core::format::MAX_VALUE_DEPTH;
    let Some(room) = MAX_VALUE_DEPTH.checked_sub(op.path.len()) else { return true };
    let keys = op.path.iter().any(|s| matches!(s, PathSeg::Key(k) if k.deeper_than(MAX_VALUE_DEPTH)));
    keys || match &op.op {
        Op::Set(v) | Op::Replace(v) | Op::Add(v) | Op::Remove(v) | Op::Inc(v) => v.deeper_than(room),
        Op::Edit { base, new } => base.deeper_than(room) || new.deeper_than(room),
        Op::Insert { items, .. } => items.iter().any(|v| v.deeper_than(room)),
        Op::RemoveAspect | Op::Delete { .. } | Op::Move { .. } | Op::Paste { .. } => false,
    }
}

/// Builds one aspect's delta from path ops.
pub struct Batch<'s> {
    state: &'s Fragment,
    w: Writer,
    acc: Option<Fragment>,
}

impl<'s> Batch<'s> {
    /// Ops resolve against `state` (the aspect's local state) and the batch so far.
    pub fn new(state: &'s Fragment, w: Writer) -> Batch<'s> {
        Batch { state, w, acc: None }
    }

    /// Applies `op` under the writer's `view` (of the aspect root).
    pub fn apply<V: View>(&mut self, op: &PathOp, view: &V) -> Result<(), Error> {
        if too_deep(op) {
            return Err(Error::Mismatch("value nested deeper than MAX_VALUE_DEPTH"));
        }
        let d = resolve(&mut self.w, Some(self.state), self.acc.as_ref(), None, &op.path, op, view, true)?;
        if let Some(d) = d {
            let acc = self.acc.take();
            self.acc = Some(match acc {
                None => d,
                Some(a) => overlay(a, d, &self.w),
            });
        }
        Ok(())
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

/// Resolves `op` at `path` below the position whose state is `s` and batch writes `a`; `e` is
/// the batch's effective reset from above. Returns the root-relative delta.
#[allow(clippy::too_many_arguments)]
fn resolve<V: View>(w: &mut Writer, s: Option<&Fragment>, a: Option<&Fragment>, e: Option<Stamp>, path: &[PathSeg], op: &PathOp, view: &V, root: bool) -> Result<Option<Fragment>, Error> {
    let Some((seg, rest)) = path.split_first() else {
        // nothing of the batch at this position: resolve against the state itself, no clone
        if a.is_none() && e.is_none() {
            return leaf(w, s, view, &op.op, root);
        }
        let cur = joined(s, a, e.as_ref());
        return leaf(w, cur.as_ref(), view, &op.op, root);
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
            resolve(w, sc, ac, e, rest, op, &fview, false)?.map(|c| Fragment::Struct(Struct { meta: Meta::default(), fields: BTreeMap::from([(*id, c)]) }))
        }
        PathSeg::Case(id) => {
            let cur = joined(s, a, e.as_ref());
            let current = match &cur {
                Some(Fragment::Enum(x)) => x.case.as_ref().and_then(|c| c.case),
                _ => None,
            };
            if current != Some(*id) {
                return Err(Error::Mismatch("case is not current"));
            }
            let pview = view.case(*id).ok_or(Error::Mismatch("case has no payload"))?;
            let sc = s.and_then(|f| if let Fragment::Enum(x) = f { x.payloads.get(id) } else { None });
            let ac = a.and_then(|f| if let Fragment::Enum(x) = f { x.payloads.get(id) } else { None });
            resolve(w, sc, ac, e, rest, op, &pview, false)?.map(|c| Fragment::Enum(Enum { meta: Meta::default(), case: None, payloads: BTreeMap::from([(*id, c)]) }))
        }
        PathSeg::Key(k) => {
            let vview = view.element().ok_or(Error::Mismatch("map without value type"))?;
            let cur = joined(s, a, e.as_ref());
            let found = match &cur {
                Some(Fragment::Map(m)) => live_entries(&m.entries).get(k).and_then(|ds| Some(((*ds.first()?).clone(), key_state(m, ds)))),
                _ => None,
            };
            match found {
                Some((d, ks)) => {
                    // against what the key reads as (batch writes included), written into the lowest live dot (§5.6)
                    resolve(w, ks.as_ref(), None, None, rest, op, &vview, false)?
                        .map(|c| Fragment::Map(Map { meta: Meta::default(), entries: BTreeMap::from([(d, Entry { reset: None, key: Some(k.clone()), frag: Some(Box::new(c)) })]) }))
                }
                None => {
                    // a key that is not live: only a put creates it
                    let crate::ops::Op::Set(v) = &op.op else { return Err(Error::Mismatch("no live entry with that key")) };
                    if !rest.is_empty() {
                        return Err(Error::Mismatch("no live entry with that key"));
                    }
                    let d = w.fresh().dot;
                    let c = crate::ops::create(w, &vview, v)?;
                    Some(Fragment::Map(Map { meta: Meta::default(), entries: BTreeMap::from([(d, Entry { reset: None, key: Some(k.clone()), frag: Some(Box::new(c)) })]) }))
                }
            }
        }
        PathSeg::Index(i) => {
            let eview = view.element().ok_or(Error::Mismatch("list without element type"))?;
            let cur = joined(s, a, e.as_ref());
            let Some(Fragment::Seq(cur)) = cur else { return Err(Error::Mismatch("index out of range")) };
            let (d, content) = seq::element_at(&cur, *i).ok_or(Error::Mismatch("index out of range"))?;
            let c = resolve(w, content.as_ref(), None, None, rest, op, &eview, false)?;
            c.map(|c| Fragment::Seq(seq::wrap_element(d, c)))
        }
    })
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
            let (mut meta, mut entries) = start(a.meta, a.entries, b.meta);
            let mut omitted = false;
            for (dot, de) in b.entries {
                if de.reset.is_some() && w.made(&dot) {
                    omitted |= entries.remove(&dot).is_some();
                    continue;
                }
                let prev = entries.remove(&dot).unwrap_or_default();
                let frag = overlay_opt(prev.frag, de.frag, de.reset.is_some(), w);
                let key = if frag.is_some() { de.key.or(prev.key) } else { None };
                entries.insert(dot, Entry { reset: de.reset.or(prev.reset), key, frag });
            }
            keep_present(&mut meta, omitted && entries.is_empty(), w);
            Fragment::Map(Map { meta, entries })
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

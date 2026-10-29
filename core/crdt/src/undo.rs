//! Undo: cancel per dot (spec/crdt.md §4.6). An undo commit's delta is ordinary writes chosen per
//! write of the original delta; content removed or reset by the original comes from an
//! `UndoBuffer` the node fills with pre-commit state.

use crate::error::Error;
use crate::fragment::{Bag, Elem, Entry, Enum, Fragment, Map, Meta, RegWrite, Register, Set, Struct};
use crate::ops::{PathSeg, Writer, create, key_state, present_slot, remove, replace};
use crate::seq;
use crate::stamp::{CounterRange, Dot, Source, Stamp};
use crate::view::View;
use std::collections::BTreeMap;

/// The aspect as it was just before the undone commit applied, by path.
pub trait UndoBuffer {
    /// The fragment at `path` before the undone commit (a map key's lowest live entry).
    fn before(&self, path: &[PathSeg]) -> Option<Fragment>;
    /// Whether this is the whole state before the commit, so a position absent here was absent
    /// (§4.6 "Absent before"); a node missing older bodies says no.
    fn complete(&self) -> bool {
        true
    }
}

/// The pre-commit state itself is an undo buffer.
impl UndoBuffer for Fragment {
    fn before(&self, path: &[PathSeg]) -> Option<Fragment> {
        // unlike `Fragment::at`, also through a case not current here: the undone op found it
        // current, and a buffer joined from held bodies may show a concurrent case write it never
        // saw. A key: the join of its live entries (§4.6); `undo` itself restarts below each entry.
        self.walk(path, true)
    }
}

/// The original commit's delta for the aspect, with the facts undo needs.
pub struct Undone<'a> {
    /// The delta as joined (full stamps).
    pub delta: &'a Fragment,
    /// The original writer's source and counter range: elements it created.
    pub source: &'a Source,
    pub range: CounterRange,
    /// Whether the write stamped so may be stepped back through (§4.6): written by an undo
    /// commit in effect (one no undo commit in effect undoes), with every change of the aspect
    /// after the undone commit out of effect. A node's judgment from its commit headers.
    pub restored: &'a dyn Fn(&Stamp) -> bool,
}

impl Undone<'_> {
    pub(crate) fn made(&self, d: &Dot) -> bool {
        d.src == *self.source && self.range.contains(d.ctr)
    }
    /// Whether undoing a register, case or position write `(stamp, value)` writes the previous
    /// value against the current winner `cur` (§4.6): the undone write still wins, or an undo
    /// in effect restored its value (so undo steps back through repeated edits of one register).
    /// A value-less write (expired, §4.7) equals nothing: callers pass only valued ones.
    pub(crate) fn steps_back<T: PartialEq>(&self, undone: (&Stamp, &T), cur: Option<(&Stamp, &T)>) -> bool {
        cur.is_some_and(|(s, v)| s == undone.0 || (v == undone.1 && (self.restored)(s)))
    }
}

/// The undo delta for `undone` against the current `state` (§4.6); `None` if nothing to write.
pub fn undo<V: View>(w: &mut Writer, undone: &Undone, state: &Fragment, buffer: &dyn UndoBuffer, view: &V) -> Result<Option<Fragment>, Error> {
    let mut path = Vec::new();
    undo_at(w, undone, undone.delta, Some(state), buffer, view, &mut path, true)
}

fn before_read(buffer: &dyn UndoBuffer, path: &[PathSeg]) -> Option<osis_base::Value> {
    buffer.before(path).filter(Fragment::present).and_then(|f| f.read())
}

/// Whether `o` at `path` lands in a position undo resets (§4.6 "Absent before"): a composite
/// or the aspect root, absent before the commit, holding no write but the commit's now (`s`).
fn absent_before(u: &Undone, o: &Fragment, s: Option<&Fragment>, buffer: &dyn UndoBuffer, path: &[PathSeg], root: bool) -> bool {
    let present = |p: &[PathSeg]| buffer.before(p).is_some_and(|f| f.present());
    // the outermost absent position only: below a blocked one the per-write rules run
    (root || !matches!(o, Fragment::Register(_)))
        && buffer.complete()
        && !present(path)
        && path.split_last().is_none_or(|(_, up)| present(up))
        && s.is_none_or(|s| only_from(u, s))
}

/// Whether every value-carrying write (§4.7) in `f` is the undone commit's or one undo may
/// step back through (`Undone::restored`), explicit `W`s included: resets, flags, moves and
/// deleted sequence elements' creations do not count.
fn only_from(u: &Undone, f: &Fragment) -> bool {
    let ok = |s: &Stamp, n: u64| {
        let d = s.dot.owner();
        (d.src == *u.source && d.ctr >= u.range.lo && d.ctr.saturating_add(n) <= u.range.hi) || (u.restored)(s)
    };
    let reg = |r: &Register| r.write.as_ref().is_none_or(|w| ok(&w.stamp, 1));
    // an explicit `W` (an empty collection someone wrote) counts too
    if f.meta().and_then(|m| m.w.as_ref()).is_some_and(|w| !ok(w, 1)) {
        return false;
    }
    let elems = |e: &BTreeMap<Dot, Elem>| e.values().all(|e| e.frag.as_deref().is_none_or(|f| only_from(u, f)));
    match f {
        Fragment::Register(r) => reg(r),
        Fragment::Bag(Bag { elems: e, .. }) | Fragment::Set(Set { elems: e, .. }) => elems(e),
        Fragment::Struct(x) => x.fields.values().all(|f| only_from(u, f)),
        Fragment::Enum(x) => x.case.as_ref().is_none_or(|c| ok(&c.stamp, 1)) && x.payloads.values().all(|f| only_from(u, f)),
        Fragment::Map(m) => m.entries.values().all(|e| e.created.as_ref().is_none_or(|c| ok(c, 1)) && e.frag.as_deref().is_none_or(|f| only_from(u, f))),
        // a deleted element's creation does not count
        Fragment::Seq(x) => x.elems().values().all(|e| {
            let content = match &e.content {
                crate::seq::SeqContent::Frag(c) => Some(&**c),
                _ => None,
            };
            let deleted = e.deleted.as_ref().is_some_and(|d| d.1) || (!x.text && !content.is_some_and(Fragment::present));
            (deleted || e.created.as_ref().is_none_or(|(st, _)| ok(st, e.span))) && content.is_none_or(|c| only_from(u, c))
        }),
        Fragment::Slots(x) => x.reg.as_ref().is_none_or(reg) && x.members.values().all(|f| only_from(u, f)),
    }
}

/// Re-inserts the pre-reset value (nothing when there was none).
fn undo_reset<V: View>(w: &mut Writer, buffer: &dyn UndoBuffer, view: &V, path: &[PathSeg]) -> Result<Option<Fragment>, Error> {
    // nothing before: making the position absent is "Absent before"'s, which declined here
    before_read(buffer, path).map(|v| replace(w, view, &v)).transpose()
}

#[allow(clippy::too_many_arguments)]
fn undo_at<V: View>(w: &mut Writer, u: &Undone, o: &Fragment, s: Option<&Fragment>, buffer: &dyn UndoBuffer, view: &V, path: &mut Vec<PathSeg>, root: bool) -> Result<Option<Fragment>, Error> {
    let r = w.delta_stamp();
    if absent_before(u, o, s, buffer, path, root) {
        return remove(w, o.encoding()).map(Some);
    }
    let slot = present_slot(s, o.encoding());
    let slot = slot.as_deref();
    let out = match o {
        Fragment::Register(reg) => {
            if reg.reset.is_some() {
                return undo_reset(w, buffer, view, path);
            }
            let Some(ow) = &reg.write else { return Ok(None) };
            // only if the undone write still wins, or an undo in effect restored its value
            let cur = match &slot {
                Some(Fragment::Register(x)) => x.write.as_ref().filter(|x| x.value.is_some()).map(|x| (&x.stamp, &x.value)),
                _ => None,
            };
            let won = matches!(&slot, Some(Fragment::Register(x)) if x.write.as_ref().is_some_and(|x| x.stamp == ow.stamp));
            if !won && (ow.value.is_none() || !u.steps_back((&ow.stamp, &ow.value), cur)) {
                return Ok(None);
            }
            match before_read(buffer, path) {
                Some(v) => Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: r, value: Some(v) }) }),
                // absent before: a root is removed above; a nested register carries no reset
                None => return Ok(None),
            }
        }
        Fragment::Bag(b) => {
            let mut elems = BTreeMap::new();
            if b.meta.reset.is_some() {
                // §5.2: cancel the undone commit's own contribution, re-add the pre-reset live ones
                for d in b.elems.keys().filter(|d| u.made(d)) {
                    elems.insert(d.clone(), Elem::tomb(&r));
                }
                if let Some(Fragment::Bag(prev)) = buffer.before(path).map(|f| f.chosen()) {
                    let ev = view.element();
                    for e in prev.elems.values() {
                        let Some(v) = e.frag.as_ref().and_then(|f| f.read()) else { continue };
                        let (d, e) = contribution(w, ev.as_ref(), v, &r)?;
                        elems.insert(d, e);
                    }
                }
            } else {
                let prev = buffer.before(path).map(|f| f.chosen());
                let ev = view.element();
                for (d, e) in &b.elems {
                    if e.frag.is_some() && u.made(d) {
                        elems.insert(d.clone(), Elem::tomb(&r));
                    } else if e.reset.is_some() {
                        // the undone commit cancelled a contribution (an undo): re-add it (redo)
                        let v = match &prev {
                            Some(Fragment::Bag(p)) => p.elems.get(d).and_then(|x| x.frag.as_ref()).and_then(|f| f.read()),
                            _ => None,
                        };
                        if let Some(v) = v {
                            let (d, e) = contribution(w, ev.as_ref(), v, &r)?;
                            elems.insert(d, e);
                        }
                    }
                }
            }
            Fragment::Bag(Bag { kind: b.kind, meta: Meta::default(), elems })
        }
        Fragment::Set(x) => {
            if x.meta.reset.is_some() {
                return undo_reset(w, buffer, view, path);
            }
            let prev = buffer.before(path).map(|f| f.chosen());
            let mut elems = BTreeMap::new();
            for (d, e) in &x.elems {
                if e.frag.is_some() && u.made(d) {
                    elems.insert(d.clone(), Elem::tomb(&r));
                } else if e.reset.is_some() {
                    // re-add the removed value with a fresh dot
                    let v = match &prev {
                        Some(Fragment::Set(p)) => p.elems.get(d).and_then(|e| e.frag.as_ref()).and_then(|f| f.read()),
                        _ => None,
                    };
                    if let Some(v) = v {
                        let (nd, e) = crate::ops::set_elem(w, v);
                        elems.insert(nd, e);
                    }
                }
            }
            Fragment::Set(Set { meta: Meta::default(), elems })
        }
        Fragment::Map(m) => {
            if m.meta.reset.is_some() {
                return undo_reset(w, buffer, view, path);
            }
            let vview = view.element().ok_or(Error::Mismatch("map without value type"))?;
            let prev = buffer.before(path).map(|f| f.chosen());
            let cur = match &slot {
                Some(Fragment::Map(c)) => Some(c),
                _ => None,
            };
            let mut entries = BTreeMap::new();
            // removed entries, joined per key: a key held by several entries comes back as one
            // (re-adding each at the undo's one stamp would tie their registers)
            let mut removed: BTreeMap<osis_base::Value, Fragment> = BTreeMap::new();
            for (d, e) in &m.entries {
                if e.frag.is_some() && u.made(d) {
                    entries.insert(d.clone(), Entry::tomb(&r));
                } else if let (Some(f), Some(k)) = (&e.frag, &e.key) {
                    // a nested edit into an existing entry
                    path.push(PathSeg::Key(k.clone()));
                    let sub = cur.and_then(|c| c.entries.get(d)).and_then(|x| x.frag.as_deref());
                    let pre = Sub(prev.as_ref().and_then(|p| entry_frag(p, d, k)), buffer.complete());
                    let res = undo_at(w, u, f, sub, &pre, &vview, &mut vec![], false);
                    path.pop();
                    if let Some(c) = res? {
                        entries.insert(d.clone(), Entry { reset: None, key: Some(k.clone()), frag: Some(Box::new(c)), created: None });
                    }
                } else if e.reset.is_some()
                    && let Some(Fragment::Map(p)) = &prev
                    && let Some(x) = p.entries.get(d)
                    && let (Some(k), Some(f)) = (&x.key, &x.frag)
                {
                    match removed.get_mut(k) {
                        Some(acc) => acc.join_into((**f).clone(), None, &mut crate::changes::Changes::new()),
                        None => {
                            removed.insert(k.clone(), (**f).clone());
                        }
                    }
                }
            }
            for (k, f) in removed {
                let Some(v) = f.read() else { continue };
                entries.extend(crate::ops::new_entry(w, k, |w| create(w, &vview, &v).map(Some))?);
            }
            Fragment::Map(Map::new(Meta::default(), entries))
        }
        Fragment::Struct(x) => {
            if x.meta.reset.is_some() {
                return undo_reset(w, buffer, view, path);
            }
            let mut fields = BTreeMap::new();
            for (id, f) in &x.fields {
                let Some(fview) = view.field(*id) else { continue };
                let sub = match &slot {
                    Some(Fragment::Struct(c)) => c.fields.get(id),
                    _ => None,
                };
                path.push(PathSeg::Field(*id));
                let res = undo_at(w, u, f, sub, buffer, &fview, path, false);
                path.pop();
                if let Some(c) = res? {
                    fields.insert(*id, c);
                }
            }
            Fragment::Struct(Struct { meta: Meta::default(), fields })
        }
        Fragment::Enum(x) => {
            if x.meta.reset.is_some() || x.case.is_some() {
                // a case change is a reset (§5.4)
                return undo_reset(w, buffer, view, path);
            }
            let mut payloads = BTreeMap::new();
            for (id, f) in &x.payloads {
                let Some(pview) = view.case(*id) else { continue };
                let sub = match &slot {
                    Some(Fragment::Enum(c)) => c.payloads.get(id),
                    _ => None,
                };
                path.push(PathSeg::Case(*id));
                let res = undo_at(w, u, f, sub, buffer, &pview, path, false);
                path.pop();
                if let Some(c) = res? {
                    payloads.insert(*id, c);
                }
            }
            Fragment::Enum(Enum { meta: Meta::default(), case: None, payloads })
        }
        Fragment::Seq(x) => {
            if x.meta.reset.is_some() {
                return undo_reset(w, buffer, view, path);
            }
            let cur = match &slot {
                Some(Fragment::Seq(c)) => Some(c),
                _ => None,
            };
            let before = buffer.before(path).map(|f| f.chosen());
            let before = match &before {
                Some(Fragment::Seq(b)) => Some(b),
                _ => None,
            };
            let ev = view.element();
            let complete = buffer.complete();
            let mut nested = |w: &mut Writer, f: &Fragment, c: Option<&Fragment>, pre: Option<Fragment>| match &ev {
                Some(ev) => undo_at(w, u, f, c, &Sub(pre, complete), ev, &mut vec![], false),
                None => Ok(None),
            };
            return Ok(seq::undo(w, x, cur, before, u, view, &mut nested)?.map(Fragment::Seq));
        }
        Fragment::Slots(_) => return Err(Error::Mismatch("slots in a writer's delta")),
    };
    Ok((!out.is_empty()).then_some(out))
}

/// What a nested edit into entry `d` of key `k` saw before the commit: the join of the key's
/// live entries (§5.6 path ops), or the entry alone if none is live.
fn entry_frag(p: &Fragment, d: &Dot, k: &osis_base::Value) -> Option<Fragment> {
    let Fragment::Map(m) = p else { return None };
    key_state(m, &m.live_dots(k)).or_else(|| m.entries.get(d)?.frag.as_deref().cloned())
}

/// A new bag contribution of `v` with a fresh dot: created under the element view, else a
/// register write at the undo's stamp `r`.
fn contribution<V: View>(w: &mut Writer, ev: Option<&V>, v: osis_base::Value, r: &Stamp) -> Result<(Dot, Elem), Error> {
    let d = w.fresh().dot;
    let f = match ev {
        Some(ev) => create(w, ev, &v)?,
        None => Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: r.clone(), value: Some(v) }) }),
    };
    Ok((d, Elem { reset: None, frag: Some(Box::new(f)) }))
}

/// The buffer below a map entry or list element: paths are relative to the entry the undone
/// write edited; complete as the buffer it came from.
struct Sub(Option<Fragment>, bool);

impl UndoBuffer for Sub {
    fn before(&self, path: &[PathSeg]) -> Option<Fragment> {
        self.0.as_ref().and_then(|e| e.before(path))
    }
    fn complete(&self) -> bool {
        self.1
    }
}

impl Fragment {
    /// The part of this pre-commit state that undoing `delta` reads (`UndoBuffer::before` along
    /// the delta's paths), so a node keeps O(change) per local commit: struct fields the delta
    /// writes, and of a map, set or bag the delta does not reset only the elements it writes
    /// (of a map also every live entry of a key it edits into, along the edit's paths: undo
    /// reads their join, §5.6), of a list or text the records holding the delta's dots (its undo
    /// reads by dot). Anything reset is kept whole.
    /// A composite kept in part keeps its presence (an explicit `W` at its presence stamp), so
    /// "absent before" (§4.6) reads the same as on the whole state.
    pub fn footprint(&self, delta: &Fragment) -> Fragment {
        if delta.meta().is_none_or(|m| m.reset.is_some()) || self.encoding() != delta.encoding() {
            return self.clone();
        }
        let mut out = self.footprint_part(delta);
        if self.present()
            && let Some(m) = out.meta_mut()
        {
            m.w = crate::stamp::max_opt(m.w.take(), self.written());
        }
        out
    }

    fn footprint_part(&self, delta: &Fragment) -> Fragment {
        match (self, delta) {
            (Fragment::Struct(s), Fragment::Struct(d)) => Fragment::Struct(Struct {
                meta: s.meta.clone(),
                fields: d.fields.iter().filter_map(|(id, df)| Some((*id, s.fields.get(id)?.footprint(df)))).collect(),
            }),
            (Fragment::Map(s), Fragment::Map(d)) => {
                // the delta's own entries whole; a nested edit into key k reads the join of k's
                // live entries along the edit's paths only
                let mut keep: BTreeMap<Dot, Entry> = BTreeMap::new();
                for (dot, e) in &d.entries {
                    if let (Some(f), Some(k)) = (&e.frag, &e.key) {
                        for ld in s.live_dots(k) {
                            if let Some(x) = s.entries.get(ld) {
                                let frag = x.frag.as_ref().map(|xf| Box::new(xf.footprint(f)));
                                keep.insert(ld.clone(), Entry { reset: x.reset.clone(), key: x.key.clone(), frag, created: x.created.clone() });
                            }
                        }
                    }
                    if let Some(x) = s.entries.get(dot) {
                        keep.entry(dot.clone()).or_insert_with(|| x.clone());
                    }
                }
                Fragment::Map(Map::new(s.meta.clone(), keep))
            }
            (Fragment::Set(s), Fragment::Set(d)) => {
                Fragment::Set(Set { meta: s.meta.clone(), elems: d.elems.keys().filter_map(|k| Some((k.clone(), s.elems.get(k)?.clone()))).collect() })
            }
            (Fragment::Bag(s), Fragment::Bag(d)) => {
                Fragment::Bag(Bag { kind: s.kind, meta: s.meta.clone(), elems: d.elems.keys().filter_map(|k| Some((k.clone(), s.elems.get(k)?.clone()))).collect() })
            }
            (Fragment::Seq(s), Fragment::Seq(d)) => Fragment::Seq(s.footprint(d)),
            _ => self.clone(),
        }
    }
}

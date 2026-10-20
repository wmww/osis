//! Undo: cancel per dot (spec/crdt.md §4.6). An undo commit's delta is ordinary writes chosen per
//! write of the original delta; content removed or reset by the original comes from an
//! `UndoBuffer` the node fills with pre-commit state.

use crate::error::Error;
use crate::fragment::{Bag, Elem, Entry, Enum, Fragment, Map, Meta, RegWrite, Register, Set, Struct};
use crate::ops::{PathSeg, Writer, create, present_slot, remove, replace};
use crate::seq;
use crate::stamp::{CounterRange, Dot, Source, Stamp};
use crate::view::View;
use std::collections::BTreeMap;

/// The aspect as it was just before the undone commit applied, by path.
pub trait UndoBuffer {
    /// The fragment at `path` before the undone commit (a map key's lowest live entry).
    fn before(&self, path: &[PathSeg]) -> Option<Fragment>;
}

/// The pre-commit state itself is an undo buffer.
impl UndoBuffer for Fragment {
    fn before(&self, path: &[PathSeg]) -> Option<Fragment> {
        let mut cur = self.clone();
        for seg in path {
            let next = match (seg, cur.chosen()) {
                (PathSeg::Field(id), Fragment::Struct(s)) => s.fields.get(id).cloned(),
                (PathSeg::Case(id), Fragment::Enum(e)) => e.payloads.get(id).cloned(),
                (PathSeg::Key(k), Fragment::Map(m)) => {
                    let d = m.live_dots(k).first().map(|d| (*d).clone());
                    d.and_then(|d| m.entries.get(&d)).and_then(|e| e.frag.as_deref().cloned())
                }
                (PathSeg::Index(i), Fragment::Seq(s)) => seq::element_at(&s, *i).and_then(|(_, c)| c),
                _ => None,
            };
            cur = next?;
        }
        Some(cur)
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

fn before_read(buffer: &dyn UndoBuffer, path: &[PathSeg]) -> Option<osis_core::Value> {
    buffer.before(path).filter(Fragment::present).and_then(|f| f.read())
}

/// Re-inserts the pre-reset value (or leaves the position reset when there was none).
fn undo_reset<V: View>(w: &mut Writer, o: &Fragment, buffer: &dyn UndoBuffer, view: &V, path: &[PathSeg]) -> Result<Option<Fragment>, Error> {
    match before_read(buffer, path) {
        Some(v) => replace(w, view, &v).map(Some),
        None => remove(w, o.encoding()).map(Some),
    }
}

#[allow(clippy::too_many_arguments)]
fn undo_at<V: View>(w: &mut Writer, u: &Undone, o: &Fragment, s: Option<&Fragment>, buffer: &dyn UndoBuffer, view: &V, path: &mut Vec<PathSeg>, root: bool) -> Result<Option<Fragment>, Error> {
    let r = w.delta_stamp();
    let slot = present_slot(s, o.encoding());
    let slot = slot.as_deref();
    let out = match o {
        Fragment::Register(reg) => {
            if reg.reset.is_some() {
                return undo_reset(w, o, buffer, view, path);
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
                None if root => remove(w, o.encoding())?,
                None => return Ok(None),
            }
        }
        Fragment::Bag(b) => {
            let mut elems = BTreeMap::new();
            if b.meta.reset.is_some() {
                // §5.2: cancel the undone commit's own contribution, re-add the pre-reset live ones
                for d in b.elems.keys().filter(|d| u.made(d)) {
                    elems.insert(d.clone(), Elem { reset: Some(r.clone()), frag: None });
                }
                if let Some(Fragment::Bag(prev)) = buffer.before(path).map(|f| f.chosen()) {
                    let ev = view.element();
                    for e in prev.elems.values() {
                        let Some(v) = e.frag.as_ref().and_then(|f| f.read()) else { continue };
                        let d = w.fresh().dot;
                        let f = match &ev {
                            Some(ev) => create(w, ev, &v)?,
                            None => Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: r.clone(), value: Some(v) }) }),
                        };
                        elems.insert(d, Elem { reset: None, frag: Some(Box::new(f)) });
                    }
                }
            } else {
                let prev = buffer.before(path).map(|f| f.chosen());
                let ev = view.element();
                for (d, e) in &b.elems {
                    if e.frag.is_some() && u.made(d) {
                        elems.insert(d.clone(), Elem { reset: Some(r.clone()), frag: None });
                    } else if e.reset.is_some() {
                        // the undone commit cancelled a contribution (an undo): re-add it (redo)
                        let v = match &prev {
                            Some(Fragment::Bag(p)) => p.elems.get(d).and_then(|x| x.frag.as_ref()).and_then(|f| f.read()),
                            _ => None,
                        };
                        if let Some(v) = v {
                            let nd = w.fresh().dot;
                            let f = match &ev {
                                Some(ev) => create(w, ev, &v)?,
                                None => Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: r.clone(), value: Some(v) }) }),
                            };
                            elems.insert(nd, Elem { reset: None, frag: Some(Box::new(f)) });
                        }
                    }
                }
            }
            Fragment::Bag(Bag { kind: b.kind, meta: Meta::default(), elems })
        }
        Fragment::Set(x) => {
            if x.meta.reset.is_some() {
                return undo_reset(w, o, buffer, view, path);
            }
            let ev = view.element().ok_or(Error::Mismatch("set without element type"))?;
            let prev = buffer.before(path).map(|f| f.chosen());
            let mut elems = BTreeMap::new();
            for (d, e) in &x.elems {
                if e.frag.is_some() && u.made(d) {
                    elems.insert(d.clone(), Elem { reset: Some(r.clone()), frag: None });
                } else if e.reset.is_some() {
                    // re-add the removed value with a fresh dot
                    let v = match &prev {
                        Some(Fragment::Set(p)) => p.elems.get(d).and_then(|e| e.frag.as_ref()).and_then(|f| f.read()),
                        _ => None,
                    };
                    if let Some(v) = v {
                        let nd = w.fresh().dot;
                        elems.insert(nd, Elem { reset: None, frag: Some(Box::new(create(w, &ev, &v)?)) });
                    }
                }
            }
            Fragment::Set(Set { meta: Meta::default(), elems })
        }
        Fragment::Map(m) => {
            if m.meta.reset.is_some() {
                return undo_reset(w, o, buffer, view, path);
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
            let mut removed: BTreeMap<osis_core::Value, Fragment> = BTreeMap::new();
            for (d, e) in &m.entries {
                if e.frag.is_some() && u.made(d) {
                    entries.insert(d.clone(), Entry { reset: Some(r.clone()), key: None, frag: None });
                } else if let (Some(f), Some(k)) = (&e.frag, &e.key) {
                    // a nested edit into an existing entry
                    path.push(PathSeg::Key(k.clone()));
                    let sub = cur.and_then(|c| c.entries.get(d)).and_then(|x| x.frag.as_deref());
                    let pre = Sub(prev.as_ref().and_then(|p| entry_frag(p, d)));
                    let res = undo_at(w, u, f, sub, &pre, &vview, &mut vec![], false);
                    path.pop();
                    if let Some(c) = res? {
                        entries.insert(d.clone(), Entry { reset: None, key: Some(k.clone()), frag: Some(Box::new(c)) });
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
                let nd = w.fresh().dot;
                entries.insert(nd, Entry { reset: None, key: Some(k), frag: Some(Box::new(create(w, &vview, &v)?)) });
            }
            Fragment::Map(Map::new(Meta::default(), entries))
        }
        Fragment::Struct(x) => {
            if x.meta.reset.is_some() {
                return undo_reset(w, o, buffer, view, path);
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
                return undo_reset(w, o, buffer, view, path);
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
                return undo_reset(w, o, buffer, view, path);
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
            let mut nested = |w: &mut Writer, f: &Fragment, c: Option<&Fragment>, pre: Option<Fragment>| match &ev {
                Some(ev) => undo_at(w, u, f, c, &Sub(pre), ev, &mut vec![], false),
                None => Ok(None),
            };
            return Ok(seq::undo(w, x, cur, before, u, view, &mut nested)?.map(Fragment::Seq));
        }
        Fragment::Slots(_) => return Err(Error::Mismatch("slots in a writer's delta")),
    };
    Ok((!out.is_empty()).then_some(out))
}

fn entry_frag(p: &Fragment, d: &Dot) -> Option<Fragment> {
    match p {
        Fragment::Map(m) => m.entries.get(d).and_then(|e| e.frag.as_deref().cloned()),
        _ => None,
    }
}

/// The buffer below a map entry: paths are relative to the entry the undone write edited.
struct Sub(Option<Fragment>);

impl UndoBuffer for Sub {
    fn before(&self, path: &[PathSeg]) -> Option<Fragment> {
        self.0.as_ref().and_then(|e| e.before(path))
    }
}

impl Fragment {
    /// The part of this pre-commit state that undoing `delta` reads (`UndoBuffer::before` along
    /// the delta's paths), so a node keeps O(change) per local commit: struct fields the delta
    /// writes, and of a map, set or bag the delta does not reset only the elements it writes
    /// (a key's lowest live entry is the one a local write went into, §5.6). Everything else,
    /// sequences included (their undo reads by position), is kept whole.
    pub fn footprint(&self, delta: &Fragment) -> Fragment {
        if delta.meta().is_none_or(|m| m.reset.is_some()) || self.encoding() != delta.encoding() {
            return self.clone();
        }
        match (self, delta) {
            (Fragment::Struct(s), Fragment::Struct(d)) => Fragment::Struct(Struct {
                meta: s.meta.clone(),
                fields: d.fields.iter().filter_map(|(id, df)| Some((*id, s.fields.get(id)?.footprint(df)))).collect(),
            }),
            (Fragment::Map(s), Fragment::Map(d)) => {
                Fragment::Map(Map::new(s.meta.clone(), d.entries.keys().filter_map(|k| Some((k.clone(), s.entries.get(k)?.clone()))).collect()))
            }
            (Fragment::Set(s), Fragment::Set(d)) => {
                Fragment::Set(Set { meta: s.meta.clone(), elems: d.elems.keys().filter_map(|k| Some((k.clone(), s.elems.get(k)?.clone()))).collect() })
            }
            (Fragment::Bag(s), Fragment::Bag(d)) => {
                Fragment::Bag(Bag { kind: s.kind, meta: s.meta.clone(), elems: d.elems.keys().filter_map(|k| Some((k.clone(), s.elems.get(k)?.clone()))).collect() })
            }
            _ => self.clone(),
        }
    }
}

//! Undo: cancel per dot (spec/crdt.md §4.6). An undo commit's delta is ordinary writes chosen per
//! write of the original delta; content removed or reset by the original comes from an
//! `UndoBuffer` the node fills with pre-commit state.

use crate::error::Error;
use crate::fragment::{Bag, Elem, Entry, Enum, Fragment, Map, Meta, RegWrite, Register, Set, Struct};
use crate::ops::{PathSeg, Writer, create, live_entries, present_slot, remove, replace};
use crate::seq;
use crate::stamp::{CounterRange, Dot, Source};
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
                    let d = live_entries(&m.entries).get(k).and_then(|ds| ds.first().map(|d| (*d).clone()));
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
}

impl Undone<'_> {
    fn made(&self, d: &Dot) -> bool {
        d.src == *self.source && self.range.contains(d.ctr)
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
    let out = match o {
        Fragment::Register(reg) => {
            if reg.reset.is_some() {
                return undo_reset(w, o, buffer, view, path);
            }
            let Some(ow) = &reg.write else { return Ok(None) };
            // only if the undone write is still the winner locally
            let winner = matches!(&slot, Some(Fragment::Register(x)) if x.write.as_ref().is_some_and(|x| x.stamp == ow.stamp));
            if !winner {
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
                } else if e.reset.is_some() {
                    let kv = prev.as_ref().and_then(|p| match p {
                        Fragment::Map(p) => p.entries.get(d).and_then(|x| Some((x.key.clone()?, x.frag.as_ref()?.read()?))),
                        _ => None,
                    });
                    if let Some((k, v)) = kv {
                        let nd = w.fresh().dot;
                        entries.insert(nd, Entry { reset: None, key: Some(k), frag: Some(Box::new(create(w, &vview, &v)?)) });
                    }
                }
            }
            Fragment::Map(Map { meta: Meta::default(), entries })
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
            let cur = match &slot {
                Some(Fragment::Seq(c)) => Some(c),
                _ => None,
            };
            return Ok(seq::undo(w, x, cur, &|d: &Dot| u.made(d), view)?.map(Fragment::Seq));
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

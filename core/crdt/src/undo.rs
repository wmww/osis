//! Undo (spec/crdt.md §4.6): an undo commit's delta is ordinary writes chosen per write of the
//! original delta, cancel per dot, so the aspect reads as before the commit where nothing but
//! undos changed it since. Content removed or reset by the original comes from `before`, the
//! state just before it as the node's kept history gives it; `restores` tells, by the writes'
//! kinds, whether it needs any.

use crate::error::Error;
use crate::fragment::{Bag, Eid, Elem, Entry, Enum, Fragment, Map, Meta, RegWrite, Register, Set, Struct};
use crate::ops::{Writer, create, key_state, present_slot, remove, replace};
use crate::seq;
use crate::stamp::{CounterRange, Dot, Source, Stamp};
use crate::view::View;
use std::collections::BTreeMap;

/// The original commit's delta for the aspect, with the facts undo needs.
pub struct Undone<'a> {
    /// The delta as joined (full stamps).
    pub delta: &'a Fragment,
    /// The original writer's source and counter range: elements it created.
    pub source: &'a Source,
    pub range: CounterRange,
}

impl Undone<'_> {
    pub(crate) fn made(&self, d: &Dot) -> bool {
        d.src == *self.source && self.range.contains(d.ctr)
    }
}

/// The undo delta for `undone` against the current `state` and the state `before` the undone
/// commit; `None` if nothing to write.
pub fn undo<V: View>(w: &mut Writer, undone: &Undone, state: &Fragment, before: &Fragment, view: &V) -> Result<Option<Fragment>, Error> {
    undo_at(w, undone, undone.delta, Some(state), Some(before), true, view, true)
}

/// The read of `b` (a position before the commit), noted as written back (`Writer::copied`).
fn before_read(w: &mut Writer, b: Option<&Fragment>) -> Option<osis_base::Value> {
    let f = b.filter(|f| f.present())?;
    let v = f.read()?;
    w.copy_from(f);
    Some(v)
}

/// The chosen slot of a position before the commit (§7).
fn chosen(b: Option<&Fragment>) -> Option<Fragment> {
    b.map(Fragment::chosen)
}

/// Whether the undo makes position `o` absent again: a composite or the aspect root, absent
/// before (`b`) below a position present before (`up`), whose current read (`s`) is what the
/// undone commit made it.
fn absent_before(o: &Fragment, s: Option<&Fragment>, b: Option<&Fragment>, up: bool, root: bool) -> bool {
    if !up || b.is_some_and(Fragment::present) || !(root || !matches!(o, Fragment::Register(_))) {
        return false;
    }
    let mut after = b.cloned().unwrap_or_default();
    after.join(o.clone());
    s.and_then(Fragment::read) == after.read()
}

/// Re-inserts the pre-reset value; `None` when there was none: the delta's other writes then
/// get their own rules.
fn undo_reset<V: View>(w: &mut Writer, b: Option<&Fragment>, view: &V) -> Result<Option<Fragment>, Error> {
    before_read(w, b).map(|v| replace(w, view, &v)).transpose()
}

/// Undo of `o`, the delta at one position, against `s` there now and `b` there before; `up`:
/// whether the enclosing position was present before.
#[allow(clippy::too_many_arguments)]
fn undo_at<V: View>(w: &mut Writer, u: &Undone, o: &Fragment, s: Option<&Fragment>, b: Option<&Fragment>, up: bool, view: &V, root: bool) -> Result<Option<Fragment>, Error> {
    let r = w.delta_stamp();
    if absent_before(o, s, b, up, root) {
        return remove(w, o.encoding()).map(Some);
    }
    let here = b.is_some_and(Fragment::present);
    let slot = present_slot(s, o.encoding());
    let slot = slot.as_deref();
    let out = match o {
        Fragment::Register(reg) => {
            if reg.reset.is_some()
                && let Some(f) = undo_reset(w, b, view)?
            {
                return Ok(Some(f));
            }
            // only while the register reads what the undone write wrote (an undo restoring it
            // included, so undo steps back through repeated edits)
            let Some(ow) = reg.write.as_ref().filter(|x| x.value.is_some()) else { return Ok(None) };
            let cur = match &slot {
                Some(Fragment::Register(x)) => x.write.as_ref().map(|x| &x.value),
                _ => None,
            };
            if cur != Some(&ow.value) {
                return Ok(None);
            }
            match before_read(w, b) {
                Some(v) => Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: r, value: Some(v) }) }),
                // absent before: a root is reset above; a nested register carries no reset
                None => return Ok(None),
            }
        }
        Fragment::Bag(x) => {
            let prev = chosen(b);
            let ev = view.element();
            let mut elems = BTreeMap::new();
            if x.meta.reset.is_some() {
                // §5.2: cancel the undone commit's own contribution, re-add the pre-reset live ones
                for d in x.elems.keys().filter(|d| u.made(d)) {
                    elems.insert(d.clone(), Elem::tomb(&r));
                }
                if let Some(Fragment::Bag(p)) = &prev {
                    for (pd, e) in &p.elems {
                        let Some(f) = e.frag.as_deref() else { continue };
                        let Some(v) = f.read() else { continue };
                        w.copy_dot(pd);
                        w.copy_from(f);
                        let (d, e) = contribution(w, ev.as_ref(), v, &r)?;
                        elems.insert(d, e);
                    }
                }
            } else {
                for (d, e) in &x.elems {
                    if e.frag.is_some() && u.made(d) {
                        elems.insert(d.clone(), Elem::tomb(&r));
                    } else if e.reset.is_some() {
                        // the undone commit cancelled a contribution (an undo): re-add it (redo)
                        let f = match &prev {
                            Some(Fragment::Bag(p)) => p.elems.get(d).and_then(|x| x.frag.as_deref()),
                            _ => None,
                        };
                        if let Some((f, v)) = f.and_then(|f| Some((f, f.read()?))) {
                            w.copy_dot(d);
                            w.copy_from(f);
                            let (d, e) = contribution(w, ev.as_ref(), v, &r)?;
                            elems.insert(d, e);
                        }
                    }
                }
            }
            Fragment::Bag(Bag { kind: x.kind, meta: Meta::default(), elems })
        }
        Fragment::Set(x) => {
            if x.meta.reset.is_some()
                && let Some(f) = undo_reset(w, b, view)?
            {
                return Ok(Some(f));
            }
            let prev = chosen(b);
            let mut elems = BTreeMap::new();
            for (d, e) in &x.elems {
                if e.frag.is_some() && u.made(d) {
                    elems.insert(d.clone(), Elem::tomb(&r));
                } else if e.reset.is_some() {
                    // re-add the removed value with a fresh dot
                    let f = match &prev {
                        Some(Fragment::Set(p)) => p.elems.get(d).and_then(|e| e.frag.as_deref()),
                        _ => None,
                    };
                    if let Some((f, v)) = f.and_then(|f| Some((f, f.read()?))) {
                        w.copy_dot(d);
                        w.copy_from(f);
                        let (nd, e) = crate::ops::set_elem(w, v);
                        elems.insert(nd, e);
                    }
                }
            }
            Fragment::Set(Set { meta: Meta::default(), elems })
        }
        Fragment::Map(m) => {
            if m.meta.reset.is_some()
                && let Some(f) = undo_reset(w, b, view)?
            {
                return Ok(Some(f));
            }
            let vview = view.element().ok_or(Error::Mismatch("map without value type"))?;
            let prev = chosen(b);
            let cur = match &slot {
                Some(Fragment::Map(c)) => Some(c),
                _ => None,
            };
            let mut entries = BTreeMap::new();
            // removed entries, joined per key: a key held by several entries comes back as one
            // (re-adding each at the undo's one stamp would tie their registers)
            let mut removed: BTreeMap<osis_base::Value, (Fragment, Vec<Dot>)> = BTreeMap::new();
            for (id, e) in &m.entries {
                if e.frag.is_some() && u.made(&id.dot) {
                    entries.insert(w.removal(id), Entry::tomb(&r));
                } else if let (Some(f), Some(k)) = (&e.frag, id.key()) {
                    // a nested edit into an existing entry: now and before, the key reads as
                    // the join of its live records (§5.6)
                    let joined = cur.and_then(|c| {
                        let live = c.live_ids(k);
                        (!live.is_empty() && live != [id]).then(|| key_state(c, &live)).flatten()
                    });
                    let own = cur.and_then(|c| c.record_frag(id));
                    let sub = joined.as_ref().or(own.as_deref());
                    let pre = prev.as_ref().and_then(|p| entry_frag(p, id, k));
                    if let Some(c) = undo_at(w, u, f, sub, pre.as_ref(), here, &vview, false)? {
                        entries.insert(id.clone(), Entry { reset: None, frag: Some(Box::new(c)), created: None });
                    }
                } else if e.reset.is_some()
                    && let Some(Fragment::Map(p)) = &prev
                {
                    // the live records it removed: its own, or a key-erased record's every
                    // record of the dot (§5.6)
                    let hit: Vec<_> = p.of_dot(&id.dot).map(|(x, _)| x).filter(|x| (id.key.is_none() || *x == id) && p.is_live(x)).collect();
                    for x in hit {
                        let (Some(k), Some(f)) = (x.key(), p.record_frag(x)) else { continue };
                        match removed.get_mut(k) {
                            Some((acc, dots)) => {
                                acc.join_into(f.into_owned(), None, &mut crate::changes::Changes::new());
                                dots.push(x.dot.clone());
                            }
                            None => {
                                removed.insert(k.clone(), (f.into_owned(), vec![x.dot.clone()]));
                            }
                        }
                    }
                }
            }
            for (k, (f, dots)) in removed {
                let Some(v) = f.read() else { continue };
                // the key is the creations' value (§4.7)
                dots.iter().for_each(|d| w.copy_dot(d));
                w.copy_from(&f);
                entries.extend(crate::ops::new_entry(w, k, |w| create(w, &vview, &v).map(Some))?);
            }
            Fragment::Map(Map::new(Meta::default(), entries))
        }
        Fragment::Struct(x) => {
            if x.meta.reset.is_some()
                && let Some(f) = undo_reset(w, b, view)?
            {
                return Ok(Some(f));
            }
            let prev = chosen(b);
            let mut fields = BTreeMap::new();
            for (id, f) in &x.fields {
                let Some(fview) = view.field(*id) else { continue };
                let sub = match &slot {
                    Some(Fragment::Struct(c)) => c.fields.get(id),
                    _ => None,
                };
                let pre = match &prev {
                    Some(Fragment::Struct(p)) => p.fields.get(id),
                    _ => None,
                };
                if let Some(c) = undo_at(w, u, f, sub, pre, here, &fview, false)? {
                    fields.insert(*id, c);
                }
            }
            Fragment::Struct(Struct { meta: Meta::default(), fields })
        }
        Fragment::Enum(x) => {
            // a case change is a reset (§5.4)
            if (x.meta.reset.is_some() || x.case.is_some())
                && let Some(f) = undo_reset(w, b, view)?
            {
                return Ok(Some(f));
            }
            let prev = chosen(b);
            let mut payloads = BTreeMap::new();
            for (id, f) in &x.payloads {
                let Some(pview) = view.case(*id) else { continue };
                let sub = match &slot {
                    Some(Fragment::Enum(c)) => c.payloads.get(id),
                    _ => None,
                };
                // also a case not current before: a concurrent case write may show there
                let pre = match &prev {
                    Some(Fragment::Enum(p)) => p.payloads.get(id),
                    _ => None,
                };
                if let Some(c) = undo_at(w, u, f, sub, pre, here, &pview, false)? {
                    payloads.insert(*id, c);
                }
            }
            Fragment::Enum(Enum { meta: Meta::default(), case: None, payloads })
        }
        Fragment::Seq(x) => {
            if x.meta.reset.is_some()
                && let Some(f) = undo_reset(w, b, view)?
            {
                return Ok(Some(f));
            }
            let cur = match &slot {
                Some(Fragment::Seq(c)) => Some(c),
                _ => None,
            };
            let prev = chosen(b);
            let before = match &prev {
                Some(Fragment::Seq(p)) => Some(p),
                _ => None,
            };
            let ev = view.element();
            let mut nested = |w: &mut Writer, f: &Fragment, c: Option<&Fragment>, pre: Option<&Fragment>| match &ev {
                Some(ev) => undo_at(w, u, f, c, pre, here, ev, false),
                None => Ok(None),
            };
            return Ok(seq::undo(w, x, cur, before, u, view, &mut nested)?.map(Fragment::Seq));
        }
        Fragment::Slots(_) => return Err(Error::Mismatch("slots in a writer's delta")),
    };
    Ok((!out.is_empty()).then_some(out))
}

/// What a nested edit into record `id` of key `k` saw before the commit: the join of the key's
/// live records (§5.6 path ops), or the record alone if none is live.
fn entry_frag(p: &Fragment, id: &Eid, k: &osis_base::Value) -> Option<Fragment> {
    let Fragment::Map(m) = p else { return None };
    key_state(m, &m.live_ids(k)).or_else(|| m.record_frag(id).map(|f| f.into_owned()))
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

/// Whether undoing `u` writes back content the delta replaced (spec/crdt.md §4.6), judged by
/// its writes' kinds alone, never by what is held: a register or value write, a case write, a
/// reset, a removal, a move or a text flag do; taking away what the delta itself created (a
/// sequence insert, a set or bag add, a map entry's creation, with all nested in them) does not.
pub fn restores(u: &Undone) -> bool {
    restores_at(u, u.delta)
}

fn restores_at(u: &Undone, o: &Fragment) -> bool {
    if o.meta().is_some_and(|m| m.reset.is_some()) {
        return true;
    }
    match o {
        Fragment::Register(r) => r.reset.is_some() || r.write.is_some(),
        Fragment::Bag(x) => x.elems.values().any(|e| e.reset.is_some()),
        Fragment::Set(x) => x.elems.values().any(|e| e.reset.is_some()),
        Fragment::Map(m) => m.entries.iter().any(|(id, e)| e.reset.is_some() || (!u.made(&id.dot) && e.frag.as_deref().is_some_and(|f| restores_at(u, f)))),
        Fragment::Struct(x) => x.fields.values().any(|f| restores_at(u, f)),
        Fragment::Enum(x) => x.case.is_some() || x.payloads.values().any(|f| restores_at(u, f)),
        Fragment::Seq(x) => crate::seq_span::expand(x.elems().clone()).iter().any(|(dot, el)| {
            if el.created.is_some() && u.made(dot) {
                return false;
            }
            el.deleted.is_some()
                || el.pos.iter().any(|p| p.0.dot != *dot)
                || match &el.content {
                    crate::seq::SeqContent::Frag(f) => restores_at(u, f),
                    _ => false,
                }
        }),
        Fragment::Slots(_) => true,
    }
}

//! Local ops producing deltas (spec/crdt.md §2.3, §4.5, §5, §9): the counter allocator,
//! creation, replace, the structural diff with a `View`, path ops and value-to-value diff.

use crate::changes::Changes;
use crate::error::Error;
use crate::fragment::{Bag, BagKind, CaseWrite, Elem, Encoding, Entry, Enum, Fragment, Map, Meta, RegWrite, Register, Set, Struct};
use crate::seq;
use crate::stamp::{CounterRange, Dot, Source, Stamp};
use crate::view::View;
use osis_core::{Float, Value};
use std::collections::BTreeMap;

/// One writer's counters for one aspect's delta in one commit (§2.3). Commit-level writes share
/// the delta stamp `(ts, source, lo)`; creations and position writes take `lo, lo+1, ..` in op
/// order. The delta consumes `[lo, max(lo + 1, last + 1))`.
///
/// A commit-form writer does not know its commit ID before signing; it writes with a placeholder
/// source and the delta is re-read with the real one (own dots are `Src` 0 on the wire, §3.2).
#[derive(Clone, Debug)]
pub struct Writer {
    ts: osis_core::Ts,
    src: Source,
    lo: u64,
    next: u64,
}

impl Writer {
    /// `lo` is the first unused counter of `src` for this aspect (≥ 1).
    pub fn new(ts: osis_core::Ts, src: Source, lo: u64) -> Writer {
        let lo = lo.max(1);
        Writer { ts, src, lo, next: lo }
    }
    pub fn ts(&self) -> osis_core::Ts {
        self.ts
    }
    pub fn source(&self) -> &Source {
        &self.src
    }
    /// Stamp of every commit-level write (register values, resets, flags, case, `W`).
    pub fn delta_stamp(&self) -> Stamp {
        Stamp::new(self.ts, self.src.clone(), self.lo)
    }
    /// A fresh counter for an element creation or position write.
    pub fn fresh(&mut self) -> Stamp {
        let s = Stamp::new(self.ts, self.src.clone(), self.next);
        self.next = self.next.saturating_add(1);
        s
    }
    /// The range this delta consumes so far.
    pub fn range(&self) -> CounterRange {
        CounterRange { lo: self.lo, hi: self.next.max(self.lo.saturating_add(1)) }
    }
    /// Whether `d` names an element created by this delta.
    pub(crate) fn made(&self, d: &Dot) -> bool {
        d.src == self.src && self.lo <= d.ctr && d.ctr < self.next
    }
}

/// One step of a path into an aspect value (notes/api.md): resolved against local state at
/// write time, never on the wire (§4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathSeg {
    /// A struct field.
    Field(u64),
    /// A map entry by key (writes go to the lowest live dot, §5.6).
    Key(Value),
    /// The payload of the current enum case.
    Case(u64),
    /// A list element by visible index.
    Index(usize),
}

/// An op at a path (§5.x).
#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    /// Make the position read `v`: structural diff (§9). A map key that is not live is put.
    Set(Value),
    /// Reset, then create `v`.
    Replace(Value),
    /// `remove_aspect`: reset with nothing after (root only).
    RemoveAspect,
    /// Set add.
    Add(Value),
    /// Set remove (by value) or map key remove.
    Remove(Value),
    /// Bag contribution: counter increment, max/min observation.
    Inc(Value),
    /// Sequence insert before visible index `at` (§5.7): list items, or strings whose chars a
    /// text inserts.
    Insert { at: usize, items: Vec<Value> },
    /// Sequence delete of `len` visible elements from `at` (§5.7).
    Delete { at: usize, len: usize },
    /// Sequence move of `len` visible elements from `at` so the range starts at index `to` of the
    /// sequence without it (§5.7).
    Move { at: usize, len: usize, to: usize },
    /// Text paste of cut elements `dots` (`cut_dots`) at visible index `at` of the text without
    /// them: a move plus an undelete (§5.7 cut, paste). Fails if a dot or its char is gone.
    Paste { dots: Vec<Dot>, at: usize },
    /// Sequence edit from `base` to `new` (`diff_values`), rebased onto the current sequence by
    /// matching `base` to its read (notes/api.md `edit`).
    Edit { base: Value, new: Value },
}

/// An op with its path.
#[derive(Clone, Debug, PartialEq)]
pub struct PathOp {
    pub path: Vec<PathSeg>,
    pub op: Op,
}

fn int_key(k: &Value) -> Result<u64, Error> {
    match k {
        Value::Int(i) => u64::try_from(*i).map_err(|_| Error::Mismatch("negative field id")),
        _ => Err(Error::Mismatch("struct key is not an int")),
    }
}

fn number(v: &Value) -> Result<(), Error> {
    match v {
        Value::Int(_) | Value::Float(_) => Ok(()),
        _ => Err(Error::Mismatch("bag contribution is not a number")),
    }
}

/// The encoding writes at a view's position use for `v` (§3.1: `any` takes the value's kind).
pub(crate) fn encoding_for<V: View>(view: &V, v: &Value) -> Encoding {
    view.encoding().unwrap_or_else(|| Encoding::of_value(v))
}

fn reg(w: &Writer, v: Value) -> Fragment {
    Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: w.delta_stamp(), value: Some(v) }) })
}

fn contribution(w: &mut Writer, kind: BagKind, v: Value) -> Fragment {
    let d = w.fresh().dot;
    let elems = BTreeMap::from([(d, Elem { reset: None, frag: Some(Box::new(reg(w, v))) })]);
    Fragment::Bag(Bag { kind, meta: Meta::default(), elems })
}

fn with_w(w: &Writer, empty: bool) -> Meta {
    Meta { reset: None, w: empty.then(|| w.delta_stamp()) }
}

/// The writes creating `v` from nothing (§9 "absent S"): composites without content get an
/// explicit `W`.
pub fn create<V: View>(w: &mut Writer, view: &V, v: &Value) -> Result<Fragment, Error> {
    let enc = encoding_for(view, v);
    Ok(match (enc, v) {
        (Encoding::Register, v) => reg(w, v.clone()),
        (Encoding::Counter | Encoding::Max | Encoding::Min, v) => {
            number(v)?;
            contribution(w, enc.bag_kind().ok_or(Error::Mismatch("bag"))?, v.clone())
        }
        (Encoding::Struct, Value::Map(kv)) => {
            let meta = with_w(w, kv.is_empty());
            let mut fields = BTreeMap::new();
            for (k, fv) in kv {
                let id = int_key(k)?;
                if let Some(fview) = view.field(id) {
                    fields.insert(id, create(w, &fview, fv)?);
                }
            }
            Fragment::Struct(Struct { meta, fields })
        }
        (Encoding::Enum, Value::Enum(id, p)) => {
            let case = Some(CaseWrite { stamp: w.delta_stamp(), case: Some(*id) });
            let mut payloads = BTreeMap::new();
            if let (Some(pview), Some(pv)) = (view.case(*id), p) {
                payloads.insert(*id, create(w, &pview, pv)?);
            }
            Fragment::Enum(Enum { meta: Meta::default(), case, payloads })
        }
        (Encoding::Set, Value::Set(items)) => {
            let meta = with_w(w, items.is_empty());
            let ev = view.element().ok_or(Error::Mismatch("set without element type"))?;
            let mut elems = BTreeMap::new();
            for it in items {
                let d = w.fresh().dot;
                elems.insert(d, Elem { reset: None, frag: Some(Box::new(create(w, &ev, it)?)) });
            }
            Fragment::Set(Set { meta, elems })
        }
        (Encoding::Map, Value::Map(kv)) => {
            let meta = with_w(w, kv.is_empty());
            let vv = view.element().ok_or(Error::Mismatch("map without value type"))?;
            let mut entries = BTreeMap::new();
            for (k, val) in kv {
                let d = w.fresh().dot;
                entries.insert(d, Entry { reset: None, key: Some(k.clone()), frag: Some(Box::new(create(w, &vv, val)?)) });
            }
            Fragment::Map(Map { meta, entries })
        }
        (Encoding::List | Encoding::Text, v) => Fragment::Seq(seq::create(w, enc == Encoding::Text, view, v)?),
        _ => return Err(Error::Mismatch("value does not fit the encoding")),
    })
}

/// Reset, then the writes of a diff against absent (§9 last line).
pub fn replace<V: View>(w: &mut Writer, view: &V, v: &Value) -> Result<Fragment, Error> {
    let r = w.delta_stamp();
    let mut f = create(w, view, v)?;
    f.set_reset(Some(r));
    Ok(f)
}

/// A reset-only fragment of `enc` (`remove_aspect`, §5.x).
pub fn remove(w: &Writer, enc: Encoding) -> Result<Fragment, Error> {
    let mut f = Fragment::empty(enc).ok_or(Error::Mismatch("no fragment of this encoding"))?;
    f.set_reset(Some(w.delta_stamp()));
    Ok(f)
}

/// Map tombstones `[dot, [D], []]` for `dots` at the delta stamp (§5.6): a reset of entries
/// whatever their liveness here (an explicit removal of an edge already removed).
pub fn reset_entries(w: &Writer, dots: &[Dot]) -> Fragment {
    let r = w.delta_stamp();
    let entries = dots.iter().map(|d| (d.clone(), Entry { reset: Some(r.clone()), key: None, frag: None })).collect();
    Fragment::Map(Map { meta: Meta::default(), entries })
}

/// The slot of encoding `enc` at a position, present only.
pub(crate) fn present_slot(st: Option<&Fragment>, enc: Encoding) -> Option<Fragment> {
    st.and_then(|s| s.slot(enc)).map(|m| m.to_fragment()).filter(Fragment::present)
}

/// Live set or bag elements: dot and read.
pub(crate) fn live_elems(elems: &BTreeMap<Dot, Elem>) -> Vec<(&Dot, Value)> {
    elems.iter().filter_map(|(d, e)| Some((d, e.frag.as_ref()?.read()?))).collect()
}

/// Live map entries: key to live dots, ascending (§5.6).
pub(crate) fn live_entries(entries: &BTreeMap<Dot, Entry>) -> BTreeMap<&Value, Vec<&Dot>> {
    let mut m: BTreeMap<&Value, Vec<&Dot>> = BTreeMap::new();
    for (d, e) in entries {
        if let (Some(k), Some(f)) = (&e.key, &e.frag)
            && f.present()
        {
            m.entry(k).or_default().push(d);
        }
    }
    m
}

/// What a key reads as: the join of its live entries' fragments (§5.6).
pub(crate) fn key_state(m: &Map, dots: &[&Dot]) -> Option<Fragment> {
    let mut out: Option<Fragment> = None;
    for f in dots.iter().filter_map(|d| m.entries.get(*d).and_then(|e| e.frag.as_deref())) {
        match &mut out {
            None => out = Some(f.clone()),
            Some(o) => o.join_into(f.clone(), None, &mut Changes::new()),
        }
    }
    out
}

fn projected<V: View>(view: &V, v: &Value) -> Option<Value> {
    view.project(v).map(|c| c.into_owned())
}

fn some_if_nonempty(f: Fragment) -> Option<Fragment> {
    (!f.is_empty()).then_some(f)
}

/// Writes that turn position `st` (any members) into `v` under the writer's view (§9);
/// `None` when nothing changes.
pub fn diff<V: View>(w: &mut Writer, st: Option<&Fragment>, view: &V, v: &Value) -> Result<Option<Fragment>, Error> {
    // the app sees the position's read; writes go into the slot of the schema's encoding (§7)
    if let Some(cur) = st.filter(|s| s.present()).and_then(Fragment::read)
        && projected(view, &cur).as_ref() == Some(v)
    {
        return Ok(None);
    }
    let enc = encoding_for(view, v);
    let Some(slot) = present_slot(st, enc) else { return create(w, view, v).map(Some) };
    let out = match (enc, &slot, v) {
        (Encoding::Register, _, v) => reg(w, v.clone()),
        (Encoding::Counter, _, Value::Int(n)) => {
            let c = match slot.read() {
                Some(Value::Int(c)) => c,
                _ => 0,
            };
            match n.checked_sub(c) {
                Some(d) => contribution(w, BagKind::Counter, Value::Int(d)),
                None => replace(w, view, v)?,
            }
        }
        (Encoding::Counter, _, Value::Float(n)) => {
            let c = match slot.read() {
                Some(Value::Float(c)) => c.get(),
                Some(Value::Int(c)) => c as f64,
                _ => 0.0,
            };
            contribution(w, BagKind::Counter, Value::Float(Float::new(n.get() - c)))
        }
        (Encoding::Counter | Encoding::Max | Encoding::Min, _, v) => replace(w, view, v)?,
        (Encoding::List | Encoding::Text, Fragment::Seq(s), v) => return Ok(seq::diff(w, s, view, v)?.map(Fragment::Seq)),
        (Encoding::Struct, Fragment::Struct(s), Value::Map(kv)) => {
            let mut out = BTreeMap::new();
            for (k, fv) in kv {
                let id = int_key(k)?;
                let Some(fview) = view.field(id) else { continue };
                let cur = s.fields.get(&id);
                // defaults are never materialized (§9)
                if cur.is_none_or(|c| !c.present()) && view.field_default(id).as_ref() == Some(fv) {
                    continue;
                }
                if let Some(d) = diff(w, cur, &fview, fv)? {
                    out.insert(id, d);
                }
            }
            Fragment::Struct(Struct { meta: Meta::default(), fields: out })
        }
        (Encoding::Enum, Fragment::Enum(e), Value::Enum(id, p)) => {
            if e.case.as_ref().and_then(|c| c.case) == Some(*id) {
                let (Some(pview), Some(pv)) = (view.case(*id), p) else { return Ok(None) };
                let Some(d) = diff(w, e.payloads.get(id), &pview, pv)? else { return Ok(None) };
                Fragment::Enum(Enum { meta: Meta::default(), case: None, payloads: BTreeMap::from([(*id, d)]) })
            } else {
                replace(w, view, v)?
            }
        }
        (Encoding::Set, Fragment::Set(s), Value::Set(items)) => {
            let ev = view.element().ok_or(Error::Mismatch("set without element type"))?;
            let live: Vec<(&Dot, Option<Value>)> = live_elems(&s.elems).into_iter().map(|(d, x)| (d, projected(&ev, &x))).collect();
            let mut elems = BTreeMap::new();
            let r = w.delta_stamp();
            for (d, p) in &live {
                // opaque elements are never removed (§9)
                if p.as_ref().is_some_and(|p| !items.contains(p)) {
                    elems.insert((*d).clone(), Elem { reset: Some(r.clone()), frag: None });
                }
            }
            for it in items {
                if !live.iter().any(|(_, p)| p.as_ref() == Some(it)) {
                    let d = w.fresh().dot;
                    elems.insert(d, Elem { reset: None, frag: Some(Box::new(create(w, &ev, it)?)) });
                }
            }
            Fragment::Set(Set { meta: Meta::default(), elems })
        }
        (Encoding::Map, Fragment::Map(m), Value::Map(kv)) => {
            let kview = view.key().ok_or(Error::Mismatch("map without key type"))?;
            let vview = view.element().ok_or(Error::Mismatch("map without value type"))?;
            let live = live_entries(&m.entries);
            // (projected key, stored key, live dots); a stored key is immutable (§5.6)
            let keyed: Vec<(Option<Value>, &Value, &Vec<&Dot>)> = live.iter().map(|(k, ds)| (projected(&kview, k), *k, ds)).collect();
            let mut entries = BTreeMap::new();
            let r = w.delta_stamp();
            for (k, _, dots) in &keyed {
                if k.as_ref().is_some_and(|k| !kv.contains_key(k)) {
                    for d in dots.iter() {
                        entries.insert((*d).clone(), Entry { reset: Some(r.clone()), key: None, frag: None });
                    }
                }
            }
            for (k, val) in kv {
                let mut matched = false;
                // every stored key the view projects to `k` is written, each into its lowest live dot,
                // against what it reads as
                for (_, stored, dots) in keyed.iter().filter(|(p, _, _)| p.as_ref() == Some(k)) {
                    matched = true;
                    let Some(d) = dots.first() else { continue };
                    let cur = key_state(m, dots);
                    if let Some(delta) = diff(w, cur.as_ref(), &vview, val)? {
                        entries.insert((*d).clone(), Entry { reset: None, key: Some((*stored).clone()), frag: Some(Box::new(delta)) });
                    }
                }
                if !matched {
                    let d = w.fresh().dot;
                    entries.insert(d, Entry { reset: None, key: Some(k.clone()), frag: Some(Box::new(create(w, &vview, val)?)) });
                }
            }
            Fragment::Map(Map { meta: Meta::default(), entries })
        }
        _ => return Err(Error::Mismatch("value does not fit the encoding")),
    };
    Ok(some_if_nonempty(out))
}

/// A leaf op at a position whose current (joined) value is `cur` (§5.x ops).
pub(crate) fn leaf<V: View>(w: &mut Writer, cur: Option<&Fragment>, view: &V, op: &Op, root: bool) -> Result<Option<Fragment>, Error> {
    match op {
        Op::Set(v) => diff(w, cur, view, v),
        Op::Replace(v) => replace(w, view, v).map(Some),
        Op::RemoveAspect => {
            if !root {
                return Err(Error::Mismatch("remove_aspect below the root"));
            }
            let enc = match (view.encoding(), cur) {
                (Some(e), _) => e,
                (None, Some(c)) => c.chosen().encoding(),
                (None, None) => return Ok(None),
            };
            remove(w, enc).map(Some)
        }
        Op::Add(v) => {
            let ev = view.element().ok_or(Error::Mismatch("set without element type"))?;
            if let Some(Fragment::Set(s)) = present_slot(cur, Encoding::Set)
                && live_elems(&s.elems).iter().any(|(_, x)| projected(&ev, x).as_ref() == Some(v))
            {
                return Ok(None);
            }
            let d = w.fresh().dot;
            let elems = BTreeMap::from([(d, Elem { reset: None, frag: Some(Box::new(create(w, &ev, v)?)) })]);
            Ok(Some(Fragment::Set(Set { meta: Meta::default(), elems })))
        }
        Op::Remove(x) => {
            let r = w.delta_stamp();
            let enc = view.encoding().or_else(|| cur.map(|c| c.chosen().encoding()));
            match (enc, enc.and_then(|e| present_slot(cur, e))) {
                (Some(Encoding::Set), Some(Fragment::Set(s))) => {
                    let ev = view.element().ok_or(Error::Mismatch("set without element type"))?;
                    let elems: BTreeMap<Dot, Elem> = live_elems(&s.elems)
                        .into_iter()
                        .filter(|(_, v)| projected(&ev, v).as_ref() == Some(x))
                        .map(|(d, _)| (d.clone(), Elem { reset: Some(r.clone()), frag: None }))
                        .collect();
                    Ok((!elems.is_empty()).then(|| Fragment::Set(Set { meta: Meta::default(), elems })))
                }
                (Some(Encoding::Map), Some(Fragment::Map(m))) => {
                    let kv = view.key().ok_or(Error::Mismatch("map without key type"))?;
                    let entries: BTreeMap<Dot, Entry> = live_entries(&m.entries)
                        .into_iter()
                        .filter(|(k, _)| projected(&kv, k).as_ref() == Some(x))
                        .flat_map(|(_, ds)| ds)
                        .map(|d| (d.clone(), Entry { reset: Some(r.clone()), key: None, frag: None }))
                        .collect();
                    Ok((!entries.is_empty()).then(|| Fragment::Map(Map { meta: Meta::default(), entries })))
                }
                (Some(Encoding::Set | Encoding::Map), None) => Ok(None),
                _ => Err(Error::Mismatch("remove needs a set or map")),
            }
        }
        Op::Inc(a) => {
            number(a)?;
            let kind = view
                .encoding()
                .or_else(|| cur.map(|c| c.chosen().encoding()))
                .and_then(Encoding::bag_kind)
                .ok_or(Error::Mismatch("inc needs a counter, max or min"))?;
            Ok(Some(contribution(w, kind, a.clone())))
        }
        Op::Insert { .. } | Op::Delete { .. } | Op::Move { .. } | Op::Paste { .. } | Op::Edit { .. } => {
            let enc = match op {
                Op::Edit { new, .. } => encoding_for(view, new),
                _ => view.encoding().ok_or(Error::Mismatch("sequence op needs a list or text type"))?,
            };
            let text = match enc {
                Encoding::Text => true,
                Encoding::List => false,
                _ => return Err(Error::Mismatch("sequence op needs a list or text")),
            };
            let s = match present_slot(cur, enc) {
                Some(Fragment::Seq(s)) => Some(s),
                _ => None,
            };
            Ok(seq::op(w, text, s.as_ref(), view, op)?.map(Fragment::Seq))
        }
    }
}

/// The ops that turn `base` into `new` under `view`, exact by field, case, key, set value and
/// bag value (notes/api.md `edit`); sequences are delegated to `seq`. Applied
/// against the current state they leave everything the user did not change alone.
pub fn diff_values<V: View>(base: Option<&Value>, new: &Value, view: &V) -> Result<Vec<PathOp>, Error> {
    let mut out = Vec::new();
    diff_values_at(base, new, view, &mut Vec::new(), &mut out)?;
    Ok(out)
}

fn diff_values_at<V: View>(base: Option<&Value>, new: &Value, view: &V, path: &mut Vec<PathSeg>, out: &mut Vec<PathOp>) -> Result<(), Error> {
    if base == Some(new) {
        return Ok(());
    }
    let set = |path: &Vec<PathSeg>, out: &mut Vec<PathOp>| out.push(PathOp { path: path.clone(), op: Op::Set(new.clone()) });
    let Some(base) = base else {
        set(path, out);
        return Ok(());
    };
    match (encoding_for(view, new), base, new) {
        (Encoding::Struct, Value::Map(b), Value::Map(n)) => {
            for (k, nv) in n {
                let id = int_key(k)?;
                let Some(fview) = view.field(id) else { continue };
                path.push(PathSeg::Field(id));
                diff_values_at(b.get(k), nv, &fview, path, out)?;
                path.pop();
            }
        }
        (Encoding::Enum, Value::Enum(bi, Some(bp)), Value::Enum(ni, Some(np))) if bi == ni => match view.case(*ni) {
            Some(pview) => {
                path.push(PathSeg::Case(*ni));
                diff_values_at(Some(bp), np, &pview, path, out)?;
                path.pop();
            }
            None => set(path, out),
        },
        (Encoding::Map, Value::Map(b), Value::Map(n)) => {
            let vview = view.element().ok_or(Error::Mismatch("map without value type"))?;
            for k in b.keys().filter(|k| !n.contains_key(*k)) {
                out.push(PathOp { path: path.clone(), op: Op::Remove(k.clone()) });
            }
            for (k, nv) in n {
                path.push(PathSeg::Key(k.clone()));
                diff_values_at(b.get(k), nv, &vview, path, out)?;
                path.pop();
            }
        }
        (Encoding::Set, Value::Set(b), Value::Set(n)) => {
            for x in b.difference(n) {
                out.push(PathOp { path: path.clone(), op: Op::Remove(x.clone()) });
            }
            for x in n.difference(b) {
                out.push(PathOp { path: path.clone(), op: Op::Add(x.clone()) });
            }
        }
        (Encoding::Counter, Value::Int(b), Value::Int(n)) => match n.checked_sub(*b) {
            Some(d) => out.push(PathOp { path: path.clone(), op: Op::Inc(Value::Int(d)) }),
            None => set(path, out),
        },
        (Encoding::Counter, Value::Float(b), Value::Float(n)) => {
            out.push(PathOp { path: path.clone(), op: Op::Inc(Value::Float(Float::new(n.get() - b.get()))) })
        }
        (Encoding::List | Encoding::Text, b, n) => out.extend(seq::diff_values(b, n, view, path)?),
        _ => set(path, out),
    }
    Ok(())
}

/// Joins `b` into a clone of `a` under `e` (used to see the batch's own writes over the state).
pub(crate) fn joined(a: Option<&Fragment>, b: Option<&Fragment>, e: Option<&Stamp>) -> Option<Fragment> {
    let mut ch = Changes::new();
    let mut out = a.cloned();
    if let Some(x) = &mut out {
        x.prune(e, &mut ch);
    }
    match (out, b) {
        (None, None) => None,
        (Some(x), None) => Some(x),
        (x, Some(y)) => {
            let mut x = x.unwrap_or_default();
            x.join_into(y.clone(), e, &mut ch);
            Some(x)
        }
    }
}

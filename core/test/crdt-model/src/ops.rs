//! Local operations resolved against local state, producing deltas (spec §4.5, §5).
use crate::seq::linearize;
use crate::stamp::{Dot, Source, Stamp, Ts};
use crate::state::{live_records, Anchor, BagKind, Composite, Content, Eid, Elem, Entry, Frag, SeqElem};
use crate::value::Value;
use std::collections::BTreeMap;

/// Schema-side type, enough to pick encodings for creations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ty {
    Register,
    Counter,
    Max,
    Min,
    Text,
    Struct(BTreeMap<u64, Ty>),
    Enum(BTreeMap<u64, Option<Ty>>),
    Set(Box<Ty>),
    Map(Box<Ty>, Box<Ty>),
    List(Box<Ty>),
}

impl Ty {
    pub fn enc(&self) -> u8 {
        match self {
            Ty::Register => 0,
            Ty::Counter => 1,
            Ty::Max => 2,
            Ty::Min => 3,
            Ty::Struct(_) => 4,
            Ty::Enum(_) => 5,
            Ty::Set(_) => 6,
            Ty::Map(..) => 7,
            Ty::List(_) => 8,
            Ty::Text => 9,
        }
    }
}

/// One writer's counter allocator for one aspect within one commit (spec §2.3): commit-level writes (register
/// values, resets, flags, case, presence, element resets) share the stamp `(ts, source, lo)`; creations and
/// position writes consume `lo, lo+1, ...` in op order. The range is `[lo, max(lo+1, next))`.
#[derive(Clone, Debug)]
pub struct Writer {
    pub source: Source,
    pub ts: Ts,
    pub lo: u64,
    pub next: u64,
    /// Map removals carry the removed record's key (membership-class aspects, spec §5.6); else a removal
    /// is the dot's key-erased record.
    pub keyed: bool,
}

impl Writer {
    pub fn new(source: Source, ts: Ts, lo: u64) -> Writer {
        Writer { source, ts, lo, next: lo, keyed: false }
    }
    /// The record a removal of entry record `id` writes (spec §5.6).
    pub fn removal(&self, id: &Eid) -> Eid {
        if self.keyed { id.clone() } else { (id.0.clone(), None) }
    }
    /// Start the next commit of this writer at `ts`; counters continue.
    pub fn next_commit(&mut self, ts: Ts) {
        self.ts = ts;
        self.lo = self.next.max(self.lo + 1);
        self.next = self.lo;
    }
    /// Stamp of a commit-level write (register value, reset, flag, case, presence, element reset).
    pub fn delta(&self) -> Stamp {
        Stamp::new(self.ts, self.source.clone(), self.lo)
    }
    /// End of this commit's counter range `[lo, hi)` (spec §2.3).
    pub fn hi(&self) -> u64 {
        self.next.max(self.lo + 1)
    }
    /// Fresh counter: element creation or position write.
    pub fn stamp(&mut self) -> Stamp {
        let s = Stamp::new(self.ts, self.source.clone(), self.next);
        self.next += 1;
        s
    }
}

fn comp(reset: Option<Stamp>) -> Composite {
    Composite { reset, w: None }
}

/// Live elements of a set/bag: dot -> value.
pub fn live_elems(elems: &BTreeMap<Dot, Elem>) -> Vec<(&Dot, Value)> {
    elems.iter().filter_map(|(d, e)| e.frag.as_ref().and_then(|f| f.read()).map(|v| (d, v))).collect()
}
/// Live map entry records: key -> live records (ascending).
pub fn live_entries(entries: &BTreeMap<Eid, Entry>) -> BTreeMap<Value, Vec<Eid>> {
    let mut m: BTreeMap<Value, Vec<Eid>> = BTreeMap::new();
    for (id, _) in live_records(entries) {
        m.entry(id.1.clone().expect("keyed")).or_default().push(id);
    }
    m
}
/// The value a key reads as: the join of its live records' reads (§5.6); a write by diff goes into the lowest
/// live record but is computed against this (§9).
pub fn key_state(entries: &BTreeMap<Eid, Entry>, ids: &[Eid]) -> Option<Frag> {
    let mut out: Option<Frag> = None;
    for (id, f) in live_records(entries) {
        if ids.contains(&id) {
            match &mut out {
                None => out = Some(f),
                Some(o) => o.join(f),
            }
        }
    }
    out
}
/// Visible sequence elements: not deleted and with content.
pub fn visible(text: bool, elems: &BTreeMap<Dot, SeqElem>) -> Vec<Dot> {
    linearize(elems, text)
        .into_iter()
        .filter(|d| match &elems[d].content {
            Content::None => false,
            Content::Char(_) => true,
            Content::Frag(f) => f.read().is_some(),
        })
        .collect()
}

/// A register write; also a set element's value, whatever the element type (spec §3.2, §5.5).
pub(crate) fn register(w: &mut Writer, v: Value) -> Frag {
    Frag::Register { reset: None, write: Some((w.delta(), Some(v))) }
}

/// Create a value from nothing (every write new). Composites without content get an explicit W.
pub fn create(w: &mut Writer, ty: &Ty, v: &Value) -> Frag {
    let f = match (ty, v) {
        (Ty::Register, v) => register(w, v.clone()),
        (Ty::Counter | Ty::Max | Ty::Min, v) => {
            let kind = match ty {
                Ty::Counter => BagKind::Counter,
                Ty::Max => BagKind::Max,
                _ => BagKind::Min,
            };
            let d = w.stamp().dot;
            let mut elems = BTreeMap::new();
            elems.insert(d, Elem { reset: None, frag: Some(Box::new(register(w, v.clone()))) });
            Frag::Bag { kind, c: comp(None), elems }
        }
        (Ty::Text, Value::Str(s)) => {
            let mut f = Frag::Seq { text: true, c: comp(None), elems: BTreeMap::new() };
            if s.is_empty() {
                f.composite_mut().unwrap().w = Some(w.delta());
            } else {
                insert_run(w, &mut f, Anchor::Head, s.chars().map(Content::Char).collect());
            }
            f
        }
        (Ty::Struct(fts), Value::Map(kv)) => {
            let mut fields = BTreeMap::new();
            let mut c = comp(None);
            if kv.is_empty() {
                c.w = Some(w.delta());
            }
            for (k, fv) in kv {
                if let (Value::Int(id), Some(ft)) = (k, fts.get(&(int_id(k)))) {
                    fields.insert(*id as u64, create(w, ft, fv));
                }
            }
            Frag::Struct { c, fields }
        }
        (Ty::Enum(cases), Value::Enum(id, p)) => {
            let case = Some((w.delta(), Some(*id)));
            let mut payloads = BTreeMap::new();
            if let (Some(Some(pt)), Some(pv)) = (cases.get(id), p) {
                payloads.insert(*id, create(w, pt, pv));
            }
            Frag::Enum { c: comp(None), case, payloads }
        }
        (Ty::Set(_), Value::Set(items)) => {
            let mut elems = BTreeMap::new();
            let mut c = comp(None);
            if items.is_empty() {
                c.w = Some(w.delta());
            }
            for it in items {
                let d = w.stamp().dot;
                elems.insert(d, Elem { reset: None, frag: Some(Box::new(register(w, it.clone()))) });
            }
            Frag::Set { c, elems }
        }
        (Ty::Map(_, vt), Value::Map(kv)) => {
            let mut entries = BTreeMap::new();
            let mut c = comp(None);
            if kv.is_empty() {
                c.w = Some(w.delta());
            }
            for (k, v) in kv {
                let st = w.stamp();
                let d = (st.dot.clone(), Some(k.clone()));
                entries.insert(d, Entry { reset: None, frag: Some(Box::new(create(w, vt, v))), created: Some(st) });
            }
            Frag::Map { c, entries }
        }
        (Ty::List(et), Value::List(items)) => {
            let mut f = Frag::Seq { text: false, c: comp(None), elems: BTreeMap::new() };
            if items.is_empty() {
                f.composite_mut().unwrap().w = Some(w.delta());
            } else {
                let contents: Vec<Content> = items.iter().map(|it| Content::Frag(Box::new(create(w, et, it)))).collect();
                insert_run(w, &mut f, Anchor::Head, contents);
            }
            f
        }
        _ => panic!("value does not match type"),
    };
    f
}

fn int_id(k: &Value) -> u64 {
    match k {
        Value::Int(i) => *i as u64,
        _ => u64::MAX,
    }
}

/// Reset-only delta for `enc`.
pub fn remove(w: &mut Writer, enc: u8) -> Frag {
    let mut f = Frag::empty(enc);
    f.set_reset(Some(w.delta()));
    f
}

/// Reset then create (`set_aspect_replace`, enum case change, nested replace).
pub fn replace(w: &mut Writer, ty: &Ty, v: &Value) -> Frag {
    let r = w.delta();
    let mut f = create(w, ty, v);
    f.set_reset(Some(r));
    f
}

/// Append a chained run of new elements after `anchor` into a Seq fragment (delta or state).
pub fn insert_run(w: &mut Writer, f: &mut Frag, anchor: Anchor, contents: Vec<Content>) -> Vec<Dot> {
    let Frag::Seq { elems, .. } = f else { panic!("seq") };
    let mut prev = anchor;
    let mut dots = Vec::new();
    for c in contents {
        let s = w.stamp();
        let d = s.dot.clone();
        elems.insert(d.clone(), SeqElem::new(s, prev, c));
        prev = Anchor::Dot(d.clone());
        dots.push(d);
    }
    dots
}

fn seq_delta(text: bool) -> Frag {
    Frag::Seq { text, c: comp(None), elems: BTreeMap::new() }
}

pub fn bag_inc(w: &mut Writer, kind: BagKind, amount: Value) -> Frag {
    let d = w.stamp().dot;
    let mut elems = BTreeMap::new();
    elems.insert(d, Elem { reset: None, frag: Some(Box::new(register(w, amount))) });
    let f = Frag::Bag { kind, c: comp(None), elems };
    f
}

/// Element reset on the given dots (bag/set undo, set remove), one stamp.
pub fn elem_reset(w: &mut Writer, enc: u8, dots: &[Dot]) -> Frag {
    let s = w.delta();
    let mut f = Frag::empty(enc);
    match &mut f {
        Frag::Bag { elems, .. } | Frag::Set { elems, .. } => {
            for d in dots {
                elems.insert(d.clone(), Elem { reset: Some(s.clone()), frag: None });
            }
        }
        _ => panic!("elem_reset"),
    }
    f
}

pub fn set_add(w: &mut Writer, state: Option<&Frag>, v: &Value) -> Option<Frag> {
    if let Some(Frag::Set { elems, .. }) = state {
        if live_elems(elems).iter().any(|(_, x)| x == v) {
            return None;
        }
    }
    let d = w.stamp().dot;
    let mut elems = BTreeMap::new();
    elems.insert(d, Elem { reset: None, frag: Some(Box::new(register(w, v.clone()))) });
    let f = Frag::Set { c: comp(None), elems };
    Some(f)
}

pub fn set_remove(w: &mut Writer, state: Option<&Frag>, v: &Value) -> Option<Frag> {
    let Some(Frag::Set { elems, .. }) = state else { return None };
    let dots: Vec<Dot> = live_elems(elems).into_iter().filter(|(_, x)| x == v).map(|(d, _)| d.clone()).collect();
    if dots.is_empty() {
        return None;
    }
    Some(elem_reset(w, 6, &dots))
}

pub fn map_put(w: &mut Writer, state: Option<&Frag>, vt: &Ty, k: &Value, v: &Value) -> Option<Frag> {
    let mut entries = BTreeMap::new();
    if let Some(Frag::Map { entries: st, .. }) = state {
        if let Some(dots) = live_entries(st).get(k) {
            let d = dots[0].clone();
            let cur = key_state(st, dots);
            let delta = crate::diff::diff(w, cur.as_ref(), vt, v)?;
            entries.insert(d, Entry { reset: None, frag: Some(Box::new(delta)), created: None });
            let f = Frag::Map { c: comp(None), entries };
            return Some(f);
        }
    }
    let st = w.stamp();
    let d = (st.dot.clone(), Some(k.clone()));
    entries.insert(d, Entry { reset: None, frag: Some(Box::new(create(w, vt, v))), created: Some(st) });
    let f = Frag::Map { c: comp(None), entries };
    Some(f)
}

/// `put_new(key, v)`: a new entry whatever is live (spec/crdt.md §5.6).
pub fn map_put_new(w: &mut Writer, vt: &Ty, k: &Value, v: &Value) -> Frag {
    let st = w.stamp();
    let d = (st.dot.clone(), Some(k.clone()));
    let entries = BTreeMap::from([(d, Entry { reset: None, frag: Some(Box::new(create(w, vt, v))), created: Some(st) })]);
    Frag::Map { c: comp(None), entries }
}

pub fn map_remove(w: &mut Writer, state: Option<&Frag>, k: &Value) -> Option<Frag> {
    let Some(Frag::Map { entries: st, .. }) = state else { return None };
    let dots = live_entries(st).remove(k)?;
    let s = w.delta();
    let mut entries = BTreeMap::new();
    for d in dots {
        entries.insert(w.removal(&d), Entry { reset: Some(s.clone()), frag: None, created: None });
    }
    let f = Frag::Map { c: comp(None), entries };
    Some(f)
}

pub fn enum_set(w: &mut Writer, state: Option<&Frag>, ty: &Ty, v: &Value) -> Option<Frag> {
    let Ty::Enum(cases) = ty else { panic!("enum") };
    let Value::Enum(id, p) = v else { panic!("enum value") };
    if let Some(Frag::Enum { case: Some((_, Some(cur))), payloads, .. }) = state {
        if cur == id {
            let (Some(Some(pt)), Some(pv)) = (cases.get(id), p) else { return None };
            let delta = crate::diff::diff(w, payloads.get(id), pt, pv)?;
            let f = Frag::Enum { c: comp(None), case: None, payloads: [(*id, delta)].into_iter().collect() };
            return Some(f);
        }
    }
    Some(replace(w, ty, v))
}

/// Insert `contents` after visible index `after` (0 = at the start).
pub fn seq_insert(w: &mut Writer, state: Option<&Frag>, text: bool, after: usize, contents: Vec<Content>) -> Frag {
    let anchor = match state {
        Some(Frag::Seq { elems, text, .. }) if after > 0 => Anchor::Dot(visible(*text, elems)[after - 1].clone()),
        _ => Anchor::Head,
    };
    let mut f = seq_delta(text);
    insert_run(w, &mut f, anchor, contents);
    f
}

fn flag(w: &mut Writer, text: bool, dots: &[Dot], b: bool, contents: Option<Vec<Content>>) -> Frag {
    let s = w.delta();
    let mut f = seq_delta(text);
    let Frag::Seq { elems, .. } = &mut f else { unreachable!() };
    for (i, d) in dots.iter().enumerate() {
        let content = contents.as_ref().map_or(Content::None, |c| c[i].clone());
        elems.insert(d.clone(), SeqElem::write(content, vec![], Some((s.clone(), b))));
    }
    f
}

/// Delete visible range [from, from+len): a deleted-flag write for text, an element reset for lists (§5.7).
pub fn seq_delete(w: &mut Writer, state: &Frag, from: usize, len: usize) -> Option<Frag> {
    let Frag::Seq { text, elems, .. } = state else { panic!("seq") };
    let vis = visible(*text, elems);
    if len == 0 || from + len > vis.len() {
        return None;
    }
    // the range: the slice of the full placement order from the first to the last visible element
    // of the selection, hidden elements inside included
    let (all, _) = crate::seq::linearize_full(elems);
    let i0 = all.iter().position(|d| *d == vis[from]).unwrap();
    let i1 = all.iter().position(|d| *d == vis[from + len - 1]).unwrap();
    Some(flag(w, *text, &all[i0..=i1], true, None))
}

/// Undelete the given text dots, carrying their content. Text only: a list element is restored by re-inserting
/// its value with a fresh dot (§5.7).
pub fn seq_undelete(w: &mut Writer, state: &Frag, dots: &[Dot]) -> Frag {
    let Frag::Seq { text: true, elems, .. } = state else { panic!("text") };
    let contents = dots.iter().map(|d| elems.get(d).map_or(Content::None, |e| e.content.clone())).collect();
    flag(w, true, dots, false, Some(contents))
}

/// Move visible range [from, from+len) so it follows the element at index `after` of the sequence without the
/// range (0 = to the start). Spec §5.7.
pub fn seq_move(w: &mut Writer, state: &Frag, from: usize, len: usize, after: usize) -> Option<Frag> {
    let Frag::Seq { text, elems, .. } = state else { panic!("seq") };
    let (all, parents) = crate::seq::linearize_full(elems);
    let vis = visible(*text, elems);
    if len == 0 || from + len > vis.len() {
        return None;
    }
    // the range is the slice of the full placement order (deleted elements included) from the first to the last
    // visible element of the selection, so hidden anchors inside the selection travel with it
    let i0 = all.iter().position(|d| *d == vis[from]).unwrap();
    let i1 = all.iter().position(|d| *d == vis[from + len - 1]).unwrap();
    let range: Vec<Dot> = all[i0..=i1].to_vec();
    let rest: Vec<&Dot> = vis.iter().filter(|d| !range.contains(d)).collect();
    if after > rest.len() {
        return None;
    }
    let dest = if after == 0 { Anchor::Head } else { Anchor::Dot(rest[after - 1].clone()) };
    let pred = if from == 0 { Anchor::Head } else { Anchor::Dot(vis[from - 1].clone()) };
    let in_range = |d: &Dot| range.contains(d);
    let parent = |d: &Dot| -> Option<&Dot> { parents.get(d).and_then(|p| p.as_ref()) };
    // roots: range elements whose parent is outside the range, in visual order
    let roots: Vec<&Dot> = all.iter().filter(|d| in_range(d) && !parent(d).map_or(false, in_range)).collect();
    // outside: elements outside the range whose parent is inside it, in visual order
    let outside: Vec<&Dot> = all.iter().filter(|d| !in_range(d) && parent(d).map_or(false, in_range)).collect();
    // which root's moved subtree an element belongs to (None: not moved)
    let moved_root = |d: &Dot| -> Option<Dot> {
        let mut x = d.clone();
        loop {
            if outside.contains(&&x) {
                return None;
            }
            if roots.contains(&&x) {
                return Some(x);
            }
            if !in_range(&x) {
                return None;
            }
            x = parent(&x)?.clone();
        }
    };
    let mut f = seq_delta(*text);
    let Frag::Seq { elems: de, .. } = &mut f else { unreachable!() };
    // Re-anchor outside elements to pred in reverse visual order so their newest-first sibling order is kept.
    for o in outside.iter().rev() {
        de.insert((*o).clone(), SeqElem::write(Content::None, vec![(w.stamp(), pred.clone(), None)], None));
    }
    let mut anchor = dest;
    for r in &roots {
        de.insert((*r).clone(), SeqElem::write(Content::None, vec![(w.stamp(), anchor.clone(), None)], None));
        let last = all.iter().rev().find(|d| moved_root(d).as_ref() == Some(*r)).unwrap();
        anchor = Anchor::Dot(last.clone());
    }
    Some(f)
}

/// Nested edit of the visible list element at `index`.
pub fn seq_set_elem(w: &mut Writer, state: &Frag, et: &Ty, index: usize, v: &Value) -> Option<Frag> {
    let Frag::Seq { text, elems, .. } = state else { panic!("seq") };
    let d = visible(*text, elems).get(index)?.clone();
    let cur = match &elems[&d].content {
        Content::Frag(f) => Some(&**f),
        _ => None,
    };
    let delta = crate::diff::diff(w, cur, et, v)?;
    let mut f = seq_delta(*text);
    let Frag::Seq { elems: de, .. } = &mut f else { unreachable!() };
    de.insert(d, SeqElem::write(Content::Frag(Box::new(delta)), vec![], None));
    Some(f)
}

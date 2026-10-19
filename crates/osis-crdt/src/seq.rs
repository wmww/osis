//! Sequences: list (8) and text (9) (spec/crdt.md §5.7, §6): element state, join, prune,
//! presence, read, expiry, un-merge, text embedding. Wire runs live in `seq_wire`, ops and undo
//! in `seq_ops`, diff and `edit` in `seq_diff`, linearization in `linearize`.
//!
//! Hook contract: the generic code owns `Seq::meta` (reset, `W`): it joins and prunes them and
//! passes the effective reset `e` (§4.2, already including the sequence's own reset) to the
//! element hooks. Nested list content recurses through `Fragment::join_into`, `Fragment::prune`,
//! `Fragment::read`, `Enc::fragment`, `Dec::fragment`. Deaths and changes go to `Changes`.

use crate::changes::Changes;
use crate::fragment::{Encoding, Fragment, Meta, Register};
use crate::stamp::{Dot, Source, Stamp, max_opt};
use osis_core::Value;
use std::collections::BTreeMap;

/// `HEAD` or an element's dot (§3.2 `Anchor`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Anchor {
    Head,
    Dot(Dot),
}

/// An element's content: text, one char; list, a fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeqContent {
    None,
    Char(char),
    Frag(Box<Fragment>),
}

/// One element record (§5.7 State), identified by its creation dot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeqElem {
    /// The creation write `(stamp, anchor)`; text content lives and dies with it.
    pub(crate) created: Option<(Stamp, Anchor)>,
    pub(crate) content: SeqContent,
    /// The two greatest position writes, creation included, greatest first.
    pub(crate) pos: Vec<(Stamp, Anchor)>,
    /// Text: the deleted flag (LWW bool). List: the element reset, always `true`.
    pub(crate) deleted: Option<(Stamp, bool)>,
}

/// A list or text fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seq {
    pub(crate) text: bool,
    pub(crate) meta: Meta,
    pub(crate) elems: BTreeMap<Dot, SeqElem>,
}

impl Seq {
    pub fn empty(text: bool) -> Seq {
        Seq { text, meta: Meta::default(), elems: BTreeMap::new() }
    }
    pub fn encoding(&self) -> Encoding {
        if self.text { Encoding::Text } else { Encoding::List }
    }
}


// ---- state hooks (§4, §5.7)

impl SeqElem {
    /// An empty record (a delta's element edit or flag write fills it).
    pub(crate) fn bare() -> SeqElem {
        SeqElem { created: None, content: SeqContent::None, pos: Vec::new(), deleted: None }
    }
    /// Whether the creation counts toward presence: value-less creations do not (§4.3).
    fn creation_counts(&self) -> bool {
        !matches!(self.content, SeqContent::None) || self.flag()
    }
    /// The deleted flag (text) or element reset (list) is set.
    pub(crate) fn flag(&self) -> bool {
        self.deleted.as_ref().is_some_and(|d| d.1)
    }
    fn is_record(&self) -> bool {
        self.created.is_some() || !self.pos.is_empty() || self.deleted.is_some() || matches!(self.content, SeqContent::Frag(_))
    }
    /// Records are never dropped, except a `Derived` one left without a write (§4.2, §4.7).
    fn keeps(&self, d: &Dot) -> bool {
        !d.src.is_derived() || self.is_record()
    }
    /// The flag write's stamp (a list element's reset, `E_elem` input).
    pub(crate) fn reset(&self) -> Option<Stamp> {
        self.deleted.as_ref().map(|d| d.0.clone())
    }
}

/// Prunes one record's writes under `e` (§4.2, §5.7); `false` if the record goes.
fn prune_elem(d: &Dot, el: &mut SeqElem, text: bool, e: Option<&Stamp>, ch: &mut Changes) -> bool {
    prune_fields(d, el, e, ch);
    let ee = if text { e.cloned() } else { max_opt(e.cloned(), el.reset()) };
    if let SeqContent::Frag(f) = &mut el.content {
        f.prune(ee.as_ref(), ch);
        if f.is_empty() {
            el.content = SeqContent::None;
        }
    }
    content_rule(el, text);
    el.keeps(d)
}

/// Prunes the creation, position and flag writes.
fn prune_fields(d: &Dot, el: &mut SeqElem, e: Option<&Stamp>, ch: &mut Changes) {
    let Some(e) = e else { return };
    if el.created.as_ref().is_some_and(|c| c.0 < *e)
        && let Some((s, _)) = el.created.take()
    {
        ch.died(&s, e.ts);
    }
    el.pos.retain(|(s, _)| {
        if *s >= *e {
            return true;
        }
        // the creation write's death is reported with `created`
        if s.dot != *d {
            ch.died(s, e.ts);
        }
        false
    });
    if el.deleted.as_ref().is_some_and(|x| x.0 < *e)
        && let Some((s, _)) = el.deleted.take()
    {
        ch.died(&s, e.ts);
    }
}

/// Text content lives and dies with the creation write (§5.7).
fn content_rule(el: &mut SeqElem, text: bool) {
    if text && el.created.is_none() && matches!(el.content, SeqContent::Char(_)) {
        el.content = SeqContent::None;
    }
}

/// Top-2 of the union of position writes (§5.7); reports the beaten `cur`.
fn join_pos(d: &Dot, s: &mut Vec<(Stamp, Anchor)>, inc: Vec<(Stamp, Anchor)>, ch: &mut Changes) {
    if inc.is_empty() {
        return;
    }
    let old = s.first().map(|p| p.0.clone());
    let fresh: Vec<Stamp> = inc.iter().filter(|p| !s.iter().any(|q| q.0 == p.0)).map(|p| p.0.clone()).collect();
    s.extend(inc);
    top2(s);
    let Some(cur) = s.first().map(|p| p.0.clone()) else { return };
    if !fresh.is_empty() {
        ch.touch();
    }
    for f in fresh.iter().filter(|f| **f != cur && f.dot != *d) {
        ch.died(f, cur.ts);
    }
    if let Some(o) = old
        && o != cur
        && o.dot != *d
    {
        ch.died(&o, cur.ts);
    }
}

/// Keeps the two greatest position writes, greatest first.
pub(crate) fn top2(s: &mut Vec<(Stamp, Anchor)>) {
    s.sort_by(|a, b| b.0.cmp(&a.0));
    s.dedup_by(|a, b| a.0 == b.0);
    s.truncate(2);
}

/// Joins a flag or element reset (greatest stamp; the loser dies). Returns whether it rose.
fn join_flag(s: &mut Option<(Stamp, bool)>, d: Option<(Stamp, bool)>, ch: &mut Changes) -> bool {
    let Some(d) = d else { return false };
    match s {
        Some(x) if x.0 >= d.0 => {
            if x.0 > d.0 {
                ch.died(&d.0, x.0.ts);
            }
            false
        }
        _ => {
            if let Some(x) = s.as_ref() {
                ch.died(&x.0, d.0.ts);
            }
            *s = Some(d);
            ch.touch();
            true
        }
    }
}

/// Joins record `de` into existing record `se` under `e` (§5.7 Join).
fn merge_elem(d: &Dot, se: &mut SeqElem, de: SeqElem, text: bool, e: Option<&Stamp>, ch: &mut Changes) {
    if se.created.is_none() && de.created.is_some() {
        se.created = de.created;
        ch.touch();
    }
    let raised = join_flag(&mut se.deleted, de.deleted, ch);
    if text
        && raised
        && se.flag()
        && let (Some((c, _)), Some((f, _))) = (&se.created, &se.deleted)
    {
        // a deleted element's creation write is dead (§4.8)
        ch.died(c, f.ts);
    }
    join_pos(d, &mut se.pos, de.pos, ch);
    prune_fields(d, se, e, ch);
    let ee = max_opt(e.cloned(), se.reset());
    if raised
        && !text
        && let SeqContent::Frag(x) = &mut se.content
    {
        x.prune(ee.as_ref(), ch);
    }
    match de.content {
        SeqContent::None => {}
        SeqContent::Char(c) => {
            if matches!(se.content, SeqContent::None) {
                se.content = SeqContent::Char(c);
                ch.touch();
            }
        }
        SeqContent::Frag(mut f) => match &mut se.content {
            SeqContent::Frag(x) => x.join_into(*f, ee.as_ref(), ch),
            _ => {
                f.prune(ee.as_ref(), ch);
                ch.touch();
                se.content = SeqContent::Frag(f);
            }
        },
    }
    if matches!(&se.content, SeqContent::Frag(x) if x.is_empty()) {
        se.content = SeqContent::None;
    }
    content_rule(se, text);
}

/// Joins `d`'s element records into `s` and prunes what lands against `e`.
pub(crate) fn join_elems(s: &mut Seq, d: Seq, e: Option<&Stamp>, ch: &mut Changes) {
    let text = s.text;
    for (dot, mut de) in d.elems {
        match s.elems.get_mut(&dot) {
            Some(se) => {
                merge_elem(&dot, se, de, text, e, ch);
                if !se.keeps(&dot) {
                    s.elems.remove(&dot);
                }
            }
            None => {
                if prune_elem(&dot, &mut de, text, e, ch) {
                    ch.touch();
                    s.elems.insert(dot, de);
                }
            }
        }
    }
}

/// Prunes every element record under effective reset `e` (records are never removed, §4.2).
pub(crate) fn prune_elems(s: &mut Seq, e: Option<&Stamp>, ch: &mut Changes) {
    let text = s.text;
    s.elems.retain(|d, el| prune_elem(d, el, text, e, ch));
}

/// Greatest stamp inside the elements; with `valued`, only presence-counting writes (§4.3).
pub(crate) fn inner_max(s: &Seq, valued: bool) -> Option<Stamp> {
    let mut m: Option<Stamp> = None;
    for (d, e) in &s.elems {
        let creation = !valued || e.creation_counts();
        if creation {
            m = max_opt(m, e.created.as_ref().map(|c| c.0.clone()));
        }
        // the creation write sits in `pos` too
        for p in e.pos.iter().filter(|p| creation || p.0.dot != *d) {
            m = max_opt(m, Some(p.0.clone()));
        }
        m = max_opt(m, e.reset());
        if let SeqContent::Frag(f) = &e.content {
            m = max_opt(m, if valued { max_opt(f.written(), f.reset()) } else { f.all_max() });
        }
    }
    m
}

/// Whether any record exists (emptiness, §4.2).
pub(crate) fn has_records(s: &Seq) -> bool {
    !s.elems.is_empty()
}

/// Placed records in order (§6).
fn placed(s: &Seq) -> Vec<(&Dot, &SeqElem)> {
    let p = crate::linearize::place_idx(&s.elems);
    p.order.iter().filter_map(|i| Some((*p.dots.get(*i)?, *p.elems.get(*i)?))).collect()
}

/// Visible elements in order: not deleted, with content that reads (§5.7 Read).
pub(crate) fn visible(s: &Seq) -> Vec<Dot> {
    placed(s).into_iter().filter(|(_, e)| is_visible(e, s.text)).map(|(d, _)| d.clone()).collect()
}

pub(crate) fn is_visible(e: &SeqElem, text: bool) -> bool {
    match &e.content {
        SeqContent::Char(_) => text && !e.flag(),
        SeqContent::Frag(f) => !text && f.read().is_some(),
        SeqContent::None => false,
    }
}

/// The read of a present sequence: string or list (§5.7 Read, §6).
pub(crate) fn read(s: &Seq) -> Option<Value> {
    let items = placed(s).into_iter().map(|(_, e)| e);
    Some(if s.text {
        Value::Str(items.filter(|e| !e.flag()).filter_map(|e| if let SeqContent::Char(c) = e.content { Some(c) } else { None }).collect())
    } else {
        Value::List(items.filter_map(|e| if let SeqContent::Frag(f) = &e.content { f.read() } else { None }).collect())
    })
}


/// Holds value-carrying writes of expired deltas value-less (§4.7); `expired` gets owner dots.
pub(crate) fn strip_values(s: &mut Seq, expired: &dyn Fn(&Dot) -> bool) {
    for (d, el) in s.elems.iter_mut() {
        match &mut el.content {
            // a list element loses only the content writes of the expiring delta (§4.7)
            SeqContent::Frag(f) => f.strip_values(expired),
            _ if expired(d.owner()) => {
                el.content = SeqContent::None;
                if d.src.is_derived() {
                    // an embedded character's creation is known only from the value (§7)
                    el.created = None;
                    el.pos.retain(|p| p.0.dot != *d);
                }
            }
            _ => {}
        }
    }
}

/// Removes every write whose dot's author matches (un-merge, §4.6); records stay as anchors.
pub(crate) fn remove_dots(s: &mut Seq, pred: &dyn Fn(&Dot) -> bool) {
    let bad = |st: &Stamp| pred(st.dot.owner());
    for (d, el) in s.elems.iter_mut() {
        // the creation write of an invalid insert stays, so the element is a hidden anchor
        el.pos.retain(|p| !bad(&p.0) || p.0.dot == *d);
        if el.deleted.as_ref().is_some_and(|x| bad(&x.0)) {
            el.deleted = None;
        }
        if pred(d.owner()) {
            el.content = SeqContent::None;
        } else if let SeqContent::Frag(f) = &mut el.content {
            f.remove_dots(pred);
            if f.is_empty() {
                el.content = SeqContent::None;
            }
        }
    }
    s.elems.retain(|d, el| el.keeps(d));
}

/// Elements of the embedding of register `r` into a text slot (§7); the caller sets the reset.
/// Their stamps `(s.ts, Derived(s.dot), i)` already order right after `s` (`Dot`'s order, §2.2).
pub(crate) fn embed_text(r: &Register) -> BTreeMap<Dot, SeqElem> {
    let mut out = BTreeMap::new();
    let Some(w) = &r.write else { return out };
    let Some(Value::Str(text)) = &w.value else { return out };
    let Some(src) = Source::derived(w.stamp.dot.clone()) else { return out };
    let mut prev = Anchor::Head;
    for (i, c) in text.chars().enumerate() {
        let d = Dot::new(src.clone(), i as u64 + 1);
        let st = Stamp { ts: w.stamp.ts, dot: d.clone() };
        out.insert(d.clone(), SeqElem { created: Some((st.clone(), prev.clone())), content: SeqContent::Char(c), pos: vec![(st, prev)], deleted: None });
        prev = Anchor::Dot(d);
    }
    out
}

// ---- wire hooks (§3.2 Run, §3.3)

pub(crate) use crate::seq_wire::{decode_elems, encode_elems};

// ---- op hooks (§5.7 Ops, Undo; §9): `seq_ops`, `seq_diff`

pub(crate) use crate::seq_diff::{diff, diff_values};
pub(crate) use crate::seq_ops::{create, element_at, op, overlay, undo, wrap_element};

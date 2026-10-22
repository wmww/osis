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
use crate::seq_lin::{Lin, Plan};
use crate::seq_span::{Elems, Recs, chain_cut, cut_chains, elems_eq, last_of, nth, piece, split_at};
use crate::stamp::{Dot, Source, SourceKind, Stamp, max_opt};
use osis_core::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

/// Sequences with fewer records build their placement per use instead of caching it (tests
/// cache every sequence, so the lockstep tests check the cache).
const LIN_MIN: usize = if cfg!(test) { 1 } else { 64 };

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
    /// Elements this record stands for (a range record above 1, `seq_span`); the fields are
    /// the first element's.
    pub(crate) span: u64,
}

/// A list or text fragment. Equality is per element, whatever the split into range records.
pub struct Seq {
    pub(crate) text: bool,
    pub(crate) meta: Meta,
    elems: Elems,
    /// Placement cache (`seq_lin`) of a sequence of `LIN_MIN` records or more: built on first
    /// use, kept up by joins that add elements, move them or change flags and content, dropped
    /// by any other change of `elems`. Not part of equality.
    lin: OnceLock<Arc<Lin>>,
}

impl Clone for Seq {
    fn clone(&self) -> Seq {
        Seq { text: self.text, meta: self.meta.clone(), elems: self.elems.clone(), lin: self.lin.clone() }
    }
}

impl PartialEq for Seq {
    fn eq(&self, o: &Seq) -> bool {
        self.text == o.text && self.meta == o.meta && elems_eq(&self.elems, &o.elems)
    }
}
impl Eq for Seq {}

impl std::fmt::Debug for Seq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Seq").field("text", &self.text).field("meta", &self.meta).field("elems", &self.elems).finish()
    }
}

impl Seq {
    pub fn empty(text: bool) -> Seq {
        Seq::new(text, Meta::default(), BTreeMap::new())
    }
    pub(crate) fn new(text: bool, meta: Meta, elems: Elems) -> Seq {
        Seq { text, meta, elems, lin: OnceLock::new() }
    }
    pub fn encoding(&self) -> Encoding {
        if self.text { Encoding::Text } else { Encoding::List }
    }
    /// The element records by dot.
    pub(crate) fn elems(&self) -> &Elems {
        &self.elems
    }
    /// The records for a change the placement cache does not follow (it is dropped).
    pub(crate) fn elems_mut(&mut self) -> &mut Elems {
        self.lin.take();
        &mut self.elems
    }
    pub(crate) fn into_elems(self) -> Elems {
        self.elems
    }
    /// The records undoing `delta` reads (`seq_ops::undo` looks the pre-commit state up by the
    /// delta's dots): every record holding a dot of a delta record. O(delta), not O(sequence).
    pub(crate) fn footprint(&self, delta: &Seq) -> Seq {
        let mut keep = Elems::new();
        for (d, e) in &delta.elems {
            if let Some((k, r)) = crate::seq_span::find(&self.elems, d) {
                keep.insert(k.clone(), r.clone());
            }
            let last = nth(d, e.span.saturating_sub(1));
            for (k, r) in self.elems.range::<Dot, _>((std::ops::Bound::Excluded(d), std::ops::Bound::Included(&last))) {
                keep.insert(k.clone(), r.clone());
            }
        }
        Seq::new(self.text, self.meta.clone(), keep)
    }
    /// The placement (§6), cached from `LIN_MIN` records.
    pub(crate) fn lin(&self) -> Arc<Lin> {
        if let Some(l) = self.lin.get() {
            return l.clone();
        }
        let l = Arc::new(Lin::build(&self.elems, self.text));
        if self.elems.len() >= LIN_MIN {
            let _ = self.lin.set(l.clone());
        }
        l
    }
    /// Whether a cached placement is held and equals a whole pass (tests).
    #[cfg(test)]
    pub(crate) fn lin_check(&self) -> Option<bool> {
        self.lin.get().map(|l| **l == Lin::build(&self.elems, self.text) && l.map_ok())
    }
}


// ---- state hooks (§4, §5.7)

impl SeqElem {
    /// An empty record (a delta's element edit or flag write fills it).
    pub(crate) fn bare() -> SeqElem {
        SeqElem { created: None, content: SeqContent::None, pos: Vec::new(), deleted: None, span: 1 }
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

/// Joins `d`'s element records into `s` and prunes what lands against `e`. A record is cut
/// where the state's records start (ranges of the state are first split at its bounds), so each
/// piece meets one state record of its own span, or none.
pub(crate) fn join_elems(s: &mut Seq, d: Seq, e: Option<&Stamp>, ch: &mut Changes) {
    // how the cached placement follows each record, decided before that record joins
    let mut plans = s.lin.get().map(|_| Vec::with_capacity(d.elems.len()));
    for (dot, de) in d.elems {
        let n = plans.as_ref().map_or(0, Vec::len);
        if let (Some(ps), Some(l)) = (plans.as_mut(), s.lin.get())
            && !l.plan(&s.elems, &dot, &de, ps)
        {
            plans = None;
        }
        let was = ch.take_changed();
        join_one(s, dot, de, e, ch);
        // a record that changed nothing (a duplicate, a re-embedding) moves nothing; only the
        // records it split need their rows cut
        if !ch.is_changed()
            && let Some(ps) = plans.as_mut()
        {
            let tail = ps.split_off(n);
            ps.extend(tail.into_iter().filter(|p| matches!(p.1, Plan::Cut)));
        }
        if was {
            ch.touch();
        }
    }
    let ok = match (plans, s.lin.get_mut()) {
        (Some(ps), Some(l)) => Arc::make_mut(l).follow(&s.elems, s.text, ps),
        _ => false,
    };
    if !ok {
        s.lin.take();
    }
}

/// Joins one record of a delta (`join_elems`).
fn join_one(s: &mut Seq, dot: Dot, de: SeqElem, e: Option<&Stamp>, ch: &mut Changes) {
    {
        let span = de.span.max(1);
        let last = nth(&dot, span - 1);
        split_at(&mut s.elems, &dot);
        split_at(&mut s.elems, &nth(&dot, span));
        // (offset, length, a state record starts there)
        let mut segs: Vec<(u64, u64, bool)> = Vec::new();
        let mut cur = 0u64;
        for (k, ke) in s.elems.range(&dot..=&last) {
            if k.src == dot.src {
                let off = k.ctr - dot.ctr;
                if off > cur {
                    segs.push((cur, off - cur, false));
                }
                segs.push((off, ke.span, true));
                cur = off.saturating_add(ke.span);
            } else if let SourceKind::Derived(u) = k.src.kind() {
                // a `Derived(S, c)` record sits between `(S, c)` and `(S, c + 1)`
                let cut = u.ctr.saturating_sub(dot.ctr).saturating_add(1).min(span);
                if cut > cur {
                    segs.push((cur, cut - cur, false));
                    cur = cut;
                }
            }
        }
        if cur < span {
            segs.push((cur, span - cur, false));
        }
        if let [(0, n, existing)] = segs.as_slice()
            && *n == span
        {
            join_record(s, dot, de, *existing, e, ch);
        } else {
            for (off, n, existing) in segs {
                let (pd, pe) = piece(&dot, &de, off, n);
                join_record(s, pd, pe, existing, e, ch);
            }
        }
    }
}


/// Joins record `de` into the state record at `dot` of the same span (`existing`) or as a new
/// record, first cutting a creation chain that straddles `e`.
fn join_record(s: &mut Seq, dot: Dot, de: SeqElem, existing: bool, e: Option<&Stamp>, ch: &mut Changes) {
    let text = s.text;
    let cut = chain_cut(&dot, &de, e).or_else(|| if existing { s.elems.get(&dot).and_then(|se| chain_cut(&dot, se, e)) } else { None });
    if let Some(c) = cut {
        if existing {
            split_at(&mut s.elems, &nth(&dot, c));
        }
        let (a, ea) = piece(&dot, &de, 0, c);
        let (b, eb) = piece(&dot, &de, c, de.span - c);
        join_record(s, a, ea, existing, e, ch);
        join_record(s, b, eb, existing, e, ch);
        return;
    }
    if existing {
        if let Some(se) = s.elems.get_mut(&dot) {
            merge_elem(&dot, se, de, text, e, ch);
            if !se.keeps(&dot) {
                s.elems.remove(&dot);
            }
        }
    } else {
        let mut de = de;
        if prune_elem(&dot, &mut de, text, e, ch) {
            ch.touch();
            s.elems.insert(dot, de);
        }
    }
}

/// Prunes every element record under effective reset `e` (records are never removed, §4.2).
pub(crate) fn prune_elems(s: &mut Seq, e: Option<&Stamp>, ch: &mut Changes) {
    let text = s.text;
    let elems = s.elems_mut();
    cut_chains(elems, e);
    elems.retain(|d, el| prune_elem(d, el, text, e, ch));
}

/// Greatest stamp inside the elements; with `valued`, only presence-counting writes (§4.3).
pub(crate) fn inner_max(s: &Seq, valued: bool) -> Option<Stamp> {
    let mut m: Option<Stamp> = None;
    for (d, e) in &s.elems {
        let creation = !valued || e.creation_counts();
        // a range's greatest creation is its last element's
        if creation {
            m = max_opt(m, e.created.as_ref().map(|c| last_of(d, e, &c.0)));
        }
        // the creation write sits in `pos` too
        for p in e.pos.iter().filter(|p| creation || p.0.dot != *d) {
            m = max_opt(m, Some(last_of(d, e, &p.0)));
        }
        m = max_opt(m, e.reset());
        if let SeqContent::Frag(f) = &e.content {
            m = max_opt(m, if valued { max_opt(f.written(), f.reset()) } else { f.all_max() });
        }
    }
    m
}

/// `inner_max(s, true).is_some()`, stopping at the first presence-counting write.
pub(crate) fn has_written(s: &Seq) -> bool {
    s.elems.iter().any(|(d, e)| {
        let creation = e.creation_counts();
        (creation && e.created.is_some())
            || e.pos.iter().any(|p| creation || p.0.dot != *d)
            || e.deleted.is_some()
            || matches!(&e.content, SeqContent::Frag(f) if f.present() || f.reset().is_some())
    })
}

/// Whether any record exists (emptiness, §4.2).
pub(crate) fn has_records(s: &Seq) -> bool {
    !s.elems.is_empty()
}

/// Visible elements in order: not deleted, with content that reads (§5.7 Read). Never inside a
/// range record (ranges have no content).
pub(crate) fn visible<S: SeqRead + ?Sized>(s: &S) -> Vis {
    Vis(s.placed())
}

/// What sequence ops read: a `Seq`, or a state's under a batch's records (`Layered`).
pub(crate) trait SeqRead {
    fn text(&self) -> bool;
    /// The placement (§6).
    fn placed(&self) -> Arc<Lin>;
    /// The record starting at `d` (a visible element's is its own).
    fn rec(&self, d: &Dot) -> Option<&SeqElem>;
}

impl SeqRead for Seq {
    fn text(&self) -> bool {
        self.text
    }
    fn placed(&self) -> Arc<Lin> {
        self.lin()
    }
    fn rec(&self, d: &Dot) -> Option<&SeqElem> {
        self.elems.get(d)
    }
}

/// A state's sequence with a batch's writes joined over it, without copying the state: what the
/// batch's next op there resolves against (§4.5). `top` holds the joined record of every dot the
/// batch wrote, each lined up with the state's record of that dot (same key and span) or new;
/// `lin` is the state's placement followed through them.
pub(crate) struct Layered<'s> {
    base: &'s Seq,
    top: Elems,
    w: Option<Stamp>,
    lin: Arc<Lin>,
}

/// The records of a `Layered`: the batch's over the state's.
struct Union<'a> {
    base: &'a Elems,
    top: &'a Elems,
}

impl Recs for Union<'_> {
    fn find(&self, d: &Dot) -> Option<(&Dot, &SeqElem)> {
        self.top.find(d).or_else(|| self.base.find(d))
    }
    fn starting(&self, _: &Dot, _: &Dot) -> Option<Vec<(&Dot, &SeqElem)>> {
        None
    }
}

impl<'s> Layered<'s> {
    /// `base` ⊔ `d` (a batch's writes, no reset); `None` where a record does not line up with
    /// the state's or the placement cannot follow (the caller copies instead).
    pub(crate) fn new(base: &'s Seq, d: Seq) -> Option<Layered<'s>> {
        let mut l = Layered { base, top: Elems::new(), w: base.meta.w.clone(), lin: base.lin() };
        l.join(d).then_some(l)
    }

    /// Joins `d` (more of the batch's writes); `false`: the layer is unusable, drop it.
    pub(crate) fn join(&mut self, d: Seq) -> bool {
        if d.text != self.base.text || d.meta.reset.is_some() {
            return false;
        }
        self.w = max_opt(self.w.take(), d.meta.w);
        let mut plans = Vec::with_capacity(d.elems.len());
        let mut ch = Changes::new();
        for (dot, de) in d.elems {
            match self.top.get(&dot) {
                Some(r) if r.span != de.span => return false,
                Some(_) => {}
                None => match self.base.elems.find(&dot) {
                    Some((k, r)) if *k == dot && r.span == de.span => {
                        self.top.insert(dot.clone(), r.clone());
                    }
                    Some(_) => return false,
                    None if de.span != 1 => return false,
                    None => {}
                },
            }
            if !self.lin.plan(&Union { base: &self.base.elems, top: &self.top }, &dot, &de, &mut plans) {
                return false;
            }
            let mut t = Seq::new(self.base.text, Meta::default(), std::mem::take(&mut self.top));
            join_one(&mut t, dot.clone(), de, None, &mut ch);
            self.top = t.elems;
            if !self.top.contains_key(&dot) {
                return false;
            }
        }
        Arc::make_mut(&mut self.lin).follow(&Union { base: &self.base.elems, top: &self.top }, self.base.text, plans)
    }

    /// Present (§4.3) as the joined state would be.
    pub(crate) fn present(&self) -> bool {
        self.w.is_some() || has_written(self.base) || has_written(&Seq::new(self.base.text, Meta::default(), self.top.clone()))
    }

    /// The joined state, copied (checks).
    #[cfg(debug_assertions)]
    pub(crate) fn to_seq(&self) -> Seq {
        let mut elems = self.base.elems.clone();
        elems.extend(self.top.iter().map(|(k, v)| (k.clone(), v.clone())));
        let s = Seq::new(self.base.text, Meta { reset: self.base.meta.reset.clone(), w: self.w.clone() }, elems);
        #[cfg(test)]
        assert!(*self.lin == Lin::build(&s.elems, s.text), "layered placement differs from a whole pass");
        s
    }
}

impl SeqRead for Layered<'_> {
    fn text(&self) -> bool {
        self.base.text
    }
    fn placed(&self) -> Arc<Lin> {
        self.lin.clone()
    }
    fn rec(&self, d: &Dot) -> Option<&SeqElem> {
        self.top.get(d).or_else(|| self.base.elems.get(d))
    }
}

/// The visible elements of a placement (`visible`).
pub(crate) struct Vis(pub Arc<Lin>);

impl Vis {
    pub(crate) fn len(&self) -> usize {
        self.0.p.shown()
    }
    /// Visible element `k`.
    pub(crate) fn get(&self, k: usize) -> Option<&Dot> {
        self.0.p.vis_nth(k).map(|r| &r.dot)
    }
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Dot> + '_ {
        self.0.p.vis().map(|r| &r.dot)
    }
    /// Visible elements and, in a text, their chars.
    pub(crate) fn rows(&self) -> impl Iterator<Item = &crate::seq_lin::Row> + '_ {
        self.0.p.vis()
    }
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
    let vis = visible(s);
    Some(if s.text {
        Value::Str(vis.rows().filter_map(|r| r.ch).collect())
    } else {
        Value::List(vis.iter().filter_map(|d| s.elems.get(d)).filter_map(|e| if let SeqContent::Frag(f) = &e.content { f.read() } else { None }).collect())
    })
}


/// Holds value-carrying writes of expired deltas value-less (§4.7); `expired` gets owner dots.
pub(crate) fn strip_values(s: &mut Seq, expired: &dyn Fn(&Dot) -> bool) {
    for (d, el) in s.elems_mut().iter_mut() {
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
    let elems = s.elems_mut();
    for (d, el) in elems.iter_mut() {
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
    elems.retain(|d, el| el.keeps(d));
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
        out.insert(d.clone(), SeqElem { created: Some((st.clone(), prev.clone())), content: SeqContent::Char(c), pos: vec![(st, prev)], deleted: None, span: 1 });
        prev = Anchor::Dot(d);
    }
    out
}

// ---- wire hooks (§3.2 Run, §3.3)

pub(crate) use crate::seq_wire::{decode_elems, encode_elems};

// ---- op hooks (§5.7 Ops, Undo; §9): `seq_ops`, `seq_diff`

pub(crate) use crate::seq_diff::{diff, diff_values};
pub(crate) use crate::seq_ops::{create, element_at, op, overlay, undo, wrap_element};

//! Fragment, delta and snapshot encode/decode (spec/crdt.md §3.2, §3.3, §8).
//!
//! Decoding checks the grammar and the rules of §2.3 and §3.3 rule 7, then re-encodes the result
//! and requires the input bytes back: every canonical-form rule (table order, bare forms, sort
//! order, maximal runs, `W`) is enforced by that one comparison.

use crate::error::Error;
use crate::fragment::{Bag, CaseWrite, Eid, Elem, Encoding, Entry, Enum, Fragment, Map, Meta, RegWrite, Register, Set, Slots, Struct};
use crate::page::{PageError, PageParams, PageSink, PageSource};
use crate::paging::Step;
use crate::seq::{self, Seq};
use crate::stamp::{Dot, Interner, Source, SourceKind, Stamp};
use crate::wire::{Dec, Delta, DeltaCtx, DeltaKind, Enc, Frontiers, NONCE_LEN, Snapshot, as_array, as_uint, uint};
use osis_base::format::{MAX_BLOB, MAX_OBJECT_DEPTH, MAX_VALUE_DEPTH};
use osis_base::{Limits, PageCutter, Value};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const LIMITS: Limits = Limits { max_depth: MAX_OBJECT_DEPTH, max_bytes: MAX_BLOB };

// ---- encode

fn opt_frag(cx: &mut Enc, f: Option<&Fragment>) -> Result<Value, Error> {
    Ok(Value::List(match f {
        Some(f) => vec![encode_fragment(cx, f)?],
        None => Vec::new(),
    }))
}

/// Length of a CBOR array head for `n` items.
pub(crate) fn array_head(n: usize) -> usize {
    match n {
        0..24 => 1,
        24..256 => 2,
        256..65536 => 3,
        _ if u32::try_from(n).is_ok() => 5,
        _ => 9,
    }
}

/// An element array (or, `map`, a struct's field map or an enum's payload map) as written (§8,
/// spec/wire.md §6), built element by element: itself while its plain encoding is at or below
/// the page target; past it, cut into pages as elements come (`PageCutter`; a field's key and
/// value bytes are one element, a page of fields a map), each page put through the sink as it
/// closes; at the end `[Link+]`, or link pages when that list is above the target. Holds the
/// elements of one page (all of them while the array may still be plain) and the links. The
/// collecting pass keeps nothing (§3.3 rule 1 notes sources as elements are encoded).
pub(crate) struct Pager {
    map: bool,
    keep: bool,
    params: PageParams,
    cutter: PageCutter,
    /// Elements not yet in a closed page: a list element, or a field's key and value.
    items: Vec<Item>,
    /// Elements and their encoded bytes so far: paged once the plain form passes the target.
    count: usize,
    size: usize,
    paging: bool,
    links: Vec<Value>,
    /// The test oracle's whole paging (`oracle`): every element held, then cut at the end.
    #[cfg(any(test, fuzzing))]
    whole: bool,
}

impl Pager {
    pub(crate) fn new(map: bool, params: PageParams) -> Pager {
        Pager {
            map,
            keep: true,
            params,
            cutter: PageCutter::new(params.cut),
            items: Vec::new(),
            count: 0,
            size: 0,
            paging: false,
            links: Vec::new(),
            #[cfg(any(test, fuzzing))]
            whole: false,
        }
    }

    /// A pager for an array `cx` encodes.
    pub(crate) fn of(cx: &mut Enc, map: bool) -> Pager {
        let params = cx.sink().map_or(PageParams::FORMAT, |p| p.params());
        let mut p = Pager::new(map, params);
        #[cfg(any(test, fuzzing))]
        {
            p.whole = cx.whole;
        }
        p.keep = !cx.collecting() || p.oracle();
        p
    }

    fn oracle(&self) -> bool {
        #[cfg(any(test, fuzzing))]
        return self.whole;
        #[cfg(not(any(test, fuzzing)))]
        false
    }

    /// The next list element.
    pub(crate) fn push(&mut self, sink: Option<&mut dyn PageSink>, v: Value) -> Result<(), Error> {
        self.add(sink, Item::Elem(v))
    }

    /// The next field (`map`).
    pub(crate) fn push_field(&mut self, sink: Option<&mut dyn PageSink>, k: Value, v: Value) -> Result<(), Error> {
        self.add(sink, Item::Field(k, v))
    }

    fn add(&mut self, mut sink: Option<&mut dyn PageSink>, item: Item) -> Result<(), Error> {
        if !self.keep {
            return Ok(());
        }
        let bytes = item.bytes();
        self.count += 1;
        self.size = self.size.saturating_add(bytes.len());
        if self.paging {
            return self.feed(sink, item, &bytes);
        }
        self.items.push(item);
        if self.oracle() || array_head(self.count).saturating_add(self.size) <= self.params.target {
            return Ok(());
        }
        // paged (the plain form only grows): cut what is held, then go on as elements come
        self.paging = true;
        for item in std::mem::take(&mut self.items) {
            let b = item.bytes();
            self.feed(re(&mut sink), item, &b)?;
        }
        Ok(())
    }

    fn feed(&mut self, sink: Option<&mut dyn PageSink>, item: Item, bytes: &[u8]) -> Result<(), Error> {
        self.items.push(item);
        self.cutter.feed(bytes);
        if self.cutter.end_element() { self.put_page(sink) } else { Ok(()) }
    }

    fn whole(&self, items: Vec<Item>) -> Value {
        let it = items.into_iter();
        if self.map {
            Value::Map(it.filter_map(|i| if let Item::Field(k, v) = i { Some((k, v)) } else { None }).collect())
        } else {
            Value::List(it.filter_map(|i| if let Item::Elem(v) = i { Some(v) } else { None }).collect())
        }
    }

    fn put_page(&mut self, sink: Option<&mut dyn PageSink>) -> Result<(), Error> {
        let sink = sink.ok_or(Error::Mismatch("a paged array needs a page sink"))?;
        let items = std::mem::take(&mut self.items);
        let page = self.whole(items);
        self.links.push(Value::link(sink.put(&osis_base::encode(&page))?));
        Ok(())
    }

    /// The array as written: at a streamed position of a root being checked (`stream`), its
    /// link list as the input has it.
    pub(crate) fn done(self, cx: &mut Enc) -> Result<Value, Error> {
        if let Some(v) = cx.check.as_mut().and_then(|c| c.streamed()) {
            return Ok(v);
        }
        #[cfg(any(test, fuzzing))]
        if self.whole {
            return self.done_whole(cx);
        }
        self.finish(cx.sink())
    }

    /// `done` as the whole encoder (`oracle`): the collecting pass returns the elements, the
    /// real one cuts them all at once.
    #[cfg(any(test, fuzzing))]
    fn done_whole(mut self, cx: &mut Enc) -> Result<Value, Error> {
        let items = std::mem::take(&mut self.items);
        if cx.collecting() {
            return Ok(self.whole(items));
        }
        let encoded = items.iter().map(Item::bytes).collect();
        oracle::paged(cx.sink(), items, encoded, |v| self.whole(v))
    }

    /// The array as written (the collecting pass: an empty one).
    pub(crate) fn finish(mut self, mut sink: Option<&mut dyn PageSink>) -> Result<Value, Error> {
        if !self.paging {
            let items = std::mem::take(&mut self.items);
            return Ok(self.whole(items));
        }
        if !self.items.is_empty() {
            self.put_page(re(&mut sink))?;
        }
        let list = Value::List(std::mem::take(&mut self.links));
        if osis_base::encode(&list).len() <= self.params.target {
            return Ok(list);
        }
        // link pages: the tree-node grouping rule, level 1 only
        let Value::List(links) = list else { return Err(Error::Mismatch("links")) };
        let sink = sink.ok_or(Error::Mismatch("a paged array needs a page sink"))?;
        let mut groups = Vec::new();
        for g in link_groups(&links, self.params.fanout) {
            groups.push(Value::link(sink.put(&osis_base::encode(&Value::List(g.to_vec())))?));
        }
        let top = Value::List(groups);
        if osis_base::encode(&top).len() > self.params.target {
            return Err(Error::Mismatch("fragment needs a third page level"));
        }
        Ok(top)
    }
}

/// `sink` reborrowed.
fn re<'s>(sink: &'s mut Option<&mut dyn PageSink>) -> Option<&'s mut dyn PageSink> {
    match sink {
        Some(p) => Some(&mut **p),
        None => None,
    }
}

/// A `Pager` element: a list element, or a field's key and value.
enum Item {
    Elem(Value),
    Field(Value, Value),
}

impl Item {
    /// Its bytes as the cutter reads them.
    fn bytes(&self) -> Vec<u8> {
        match self {
            Item::Elem(v) => osis_base::encode(v),
            Item::Field(k, v) => {
                let mut b = osis_base::encode(k);
                b.extend(osis_base::encode(v));
                b
            }
        }
    }
}

/// An element array as written (§8, spec/wire.md §6): itself at or below the sink's page target,
/// else `[Link+]` to pages, or to link pages when that list is above the target. Pages are put
/// through the sink; `None` is fine only for an array that does not page.
pub fn page_array(mut pages: Option<&mut dyn PageSink>, items: Vec<Value>) -> Result<Value, Error> {
    let mut p = Pager::new(false, pages.as_ref().map_or(PageParams::FORMAT, |p| p.params()));
    for v in items {
        p.push(re(&mut pages), v)?;
    }
    p.finish(pages)
}

/// Links grouped into link pages by the tree-node rule (spec/wire.md §6): a group closes after
/// a link whose hash starts with a zero byte (from its second link) or at `fanout` links.
pub(crate) fn link_groups(links: &[Value], fanout: usize) -> Vec<&[Value]> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, l) in links.iter().enumerate() {
        let zero = matches!(l, Value::Link(x) if x.hash.first() == Some(&0));
        let n = i + 1 - start;
        if (n >= 2 && zero) || n >= fanout {
            out.push(links.get(start..=i).unwrap_or_default());
            start = i + 1;
        }
    }
    if start < links.len() {
        out.push(links.get(start..).unwrap_or_default());
    }
    out
}

/// A bag or set element `[Dot, R, Opt(Fragment)]`.
pub(crate) fn encode_elem(cx: &mut Enc, d: &Dot, e: &Elem) -> Result<Value, Error> {
    let dot = cx.dot(d);
    let r = cx.opt_stamp(e.reset.as_ref());
    let f = opt_frag(cx, e.frag.as_deref())?;
    Ok(Value::List(vec![dot, r, f]))
}

fn encode_elems(cx: &mut Enc, elems: &BTreeMap<Dot, Elem>) -> Result<Value, Error> {
    let mut p = Pager::of(cx, false);
    for (d, e) in cx.sorted(elems) {
        let v = encode_elem(cx, d, e)?;
        p.push(cx.sink(), v)?;
    }
    p.done(cx)
}

/// A map entry record `[Dot, Ci?, R, Key?, Opt(Fragment)]`.
pub(crate) fn encode_entry(cx: &mut Enc, id: &Eid, e: &Entry) -> Result<Value, Error> {
    let mut x = vec![cx.dot(&id.dot)];
    // the creation's commit, where a snapshot carries it (a writer's own creations
    // are implied, §3.2)
    if let Some(c) = e.created.as_ref().filter(|c| !cx.is_own(c)) {
        x.push(cx.commit_of(c));
    }
    x.push(cx.opt_stamp(e.reset.as_ref()));
    x.extend(id.key().cloned());
    cx.step(|| Step::Entry(id.clone()));
    x.push(opt_frag(cx, e.frag.as_deref())?);
    cx.step_done();
    Ok(Value::List(x))
}

/// A struct field or enum payload `(id, Fragment)`; `step` names it in a path.
pub(crate) fn encode_field(cx: &mut Enc, k: u64, f: &Fragment, step: fn(u64) -> Step) -> Result<(Value, Value), Error> {
    cx.step(|| step(k));
    let v = encode_fragment(cx, f);
    cx.step_done();
    Ok((uint(k), v?))
}

fn head(cx: &mut Enc, enc: Encoding, meta: &Meta) -> Vec<Value> {
    // sources are noted in encoding order (§3.3 rule 1): the reset first
    let r = cx.opt_stamp(meta.reset.as_ref());
    let mut w = cx.opt_stamp(meta.w.as_ref());
    // a value-less `W` (§3.2, §4.7)
    if let (Value::List(v), true) = (&mut w, meta.w_valueless) {
        v.push(Value::Bool(false));
    }
    vec![uint(u64::from(enc.id())), r, w]
}

fn encode_children(cx: &mut Enc, c: &BTreeMap<u64, Fragment>, step: fn(u64) -> Step) -> Result<Value, Error> {
    let mut p = Pager::of(cx, true);
    for (k, f) in c {
        let (k, v) = encode_field(cx, *k, f, step)?;
        p.push_field(cx.sink(), k, v)?;
    }
    p.done(cx)
}

fn encode_register(cx: &mut Enc, r: &Register) -> Value {
    let mut a = vec![uint(0), cx.opt_stamp(r.reset.as_ref())];
    if let Some(w) = &r.write {
        a.push(cx.stamp(&w.stamp));
        if let Some(v) = &w.value {
            a.push(v.clone());
        }
    }
    Value::List(a)
}

pub(crate) fn encode_fragment(cx: &mut Enc, f: &Fragment) -> Result<Value, Error> {
    let Some(at) = cx.track().map(|t| t.enter()) else { return encode_fragment_at(cx, f) };
    let r = encode_fragment_at(cx, f);
    if let Some(t) = cx.track() {
        t.leave(at);
    }
    r
}

fn encode_fragment_at(cx: &mut Enc, f: &Fragment) -> Result<Value, Error> {
    Ok(match f {
        Fragment::Register(r) => encode_register(cx, r),
        Fragment::Bag(Bag { meta, elems, .. }) | Fragment::Set(Set { meta, elems }) => {
            let mut a = head(cx, f.encoding(), meta);
            a.push(encode_elems(cx, elems)?);
            Value::List(a)
        }
        Fragment::Struct(s) => {
            let mut a = head(cx, Encoding::Struct, &s.meta);
            a.push(encode_children(cx, &s.fields, Step::Field)?);
            Value::List(a)
        }
        Fragment::Enum(s) => {
            let mut a = head(cx, Encoding::Enum, &s.meta);
            let case = match &s.case {
                None => Vec::new(),
                Some(c) => {
                    let mut x = vec![cx.stamp(&c.stamp)];
                    x.extend(c.case.map(uint));
                    vec![Value::List(x)]
                }
            };
            a.push(Value::List(case));
            a.push(encode_children(cx, &s.payloads, Step::Case)?);
            Value::List(a)
        }
        Fragment::Map(m) => {
            let mut a = head(cx, Encoding::Map, &m.meta);
            let mut p = Pager::of(cx, false);
            for (id, e) in cx.sorted_by(&m.entries, |id| &id.dot) {
                let v = encode_entry(cx, id, e)?;
                p.push(cx.sink(), v)?;
            }
            a.push(p.done(cx)?);
            Value::List(a)
        }
        Fragment::Seq(s) => {
            let mut a = head(cx, s.encoding(), &s.meta);
            let mut p = Pager::of(cx, false);
            seq::encode_elems(s, cx, &mut p)?;
            a.push(p.done(cx)?);
            Value::List(a)
        }
        Fragment::Slots(s) => {
            let reg = Value::List(s.reg.iter().map(|r| encode_register(cx, r)).collect());
            let mut slots = Vec::with_capacity(s.slots.len());
            for f in s.slots.values() {
                slots.push(encode_fragment(cx, f)?);
            }
            Value::List(vec![uint(u64::from(Encoding::Slots.id())), reg, Value::List(slots)])
        }
    })
}

/// Runs the collecting pass and the real pass (§3.3 rule 1).
fn encode_top<'p>(cx: &DeltaCtx, f: &Fragment, frontiers: Option<&Frontiers>, pages: Option<&'p mut dyn PageSink>) -> Result<(Enc<'p>, Value, Option<Value>), Error> {
    let mut enc = Enc::new(cx, pages);
    encode_fragment(&mut enc, f)?;
    enc.finish_collecting();
    let frag = encode_fragment(&mut enc, f)?;
    let fr = frontiers.map(|fr| enc.frontiers_value(fr));
    Ok((enc, frag, fr))
}

/// The sources with a stamp, dot, anchor or sibling key in `f`'s canonical encoding (its
/// `Sources` table, §3.3 rule 1), the own source aside: what a snapshot of `f` may list a
/// frontier for (§8).
pub fn sources_of(f: &Fragment, cx: &DeltaCtx) -> Result<BTreeSet<Source>, Error> {
    let mut enc = Enc::new(cx, None);
    encode_fragment(&mut enc, f)?;
    enc.finish_collecting();
    Ok(enc.sources().cloned().collect())
}

/// A snapshot's frontier entries all name sources of its fragment (§8).
fn frontiers_traced(enc: &Enc<'_>, s: &Snapshot) -> Result<(), Error> {
    if s.frontiers.sources().any(|(src, _)| !enc.has_source(&src)) {
        return Err(Error::Mismatch("frontier of a source not in the fragment"));
    }
    Ok(())
}

/// Encodes a delta (§3.2) against its header facts.
pub fn encode_delta(d: &Delta, cx: &DeltaCtx, pages: Option<&mut dyn PageSink>) -> Result<Vec<u8>, Error> {
    #[cfg(test)]
    return oracle::twin(pages, |p| encode_delta_in(d, cx, p), |p| oracle::encode_delta(d, cx, p));
    #[cfg(not(test))]
    encode_delta_in(d, cx, pages)
}

pub(crate) fn encode_delta_in(d: &Delta, cx: &DeltaCtx, pages: Option<&mut dyn PageSink>) -> Result<Vec<u8>, Error> {
    let (enc, frag, _) = encode_top(cx, &d.fragment, None, pages)?;
    let top = Value::List(vec![Value::Bytes(d.nonce.to_vec()), enc.sources_value(), enc.commits_value(), frag]);
    Ok(osis_base::encode(&top))
}

/// Encodes a snapshot delta (§8). The caller strips values of expiring deltas first (§4.7).
pub fn encode_snapshot(s: &Snapshot, cx: &DeltaCtx, pages: Option<&mut dyn PageSink>) -> Result<Vec<u8>, Error> {
    #[cfg(test)]
    return oracle::twin(pages, |p| encode_snapshot_in(s, cx, p), |p| oracle::encode_snapshot(s, cx, p));
    #[cfg(not(test))]
    encode_snapshot_in(s, cx, pages)
}

fn encode_snapshot_in(s: &Snapshot, cx: &DeltaCtx, pages: Option<&mut dyn PageSink>) -> Result<Vec<u8>, Error> {
    let (enc, frag, fr) = encode_top(cx, &s.fragment, Some(&s.frontiers), pages)?;
    frontiers_traced(&enc, s)?;
    let fr = fr.unwrap_or(Value::List(Vec::new()));
    let absorbed = absorbed_value(&s.absorbed);
    let top = vec![Value::Bytes(s.nonce.to_vec()), enc.sources_value(), enc.commits_value(), frag, fr, absorbed];
    Ok(osis_base::encode(&Value::List(top)))
}

// ---- decode

fn opt_stamp_only<T>(v: &Value, f: impl FnOnce(&Value) -> Result<T, Error>) -> Result<Option<T>, Error> {
    match as_array(v)? {
        [] => Ok(None),
        [x] => f(x).map(Some),
        _ => Err(Error::Malformed("expected Opt(X)")),
    }
}

/// A register value or map key at read depth `cx.depth` (§3.3 rule 7): the value it reads as
/// nests at most `MAX_VALUE_DEPTH` deep counted from the aspect root.
fn check_value(cx: &Dec, v: &Value) -> Result<(), Error> {
    if MAX_VALUE_DEPTH.checked_sub(cx.depth).is_none_or(|room| v.deeper_than(room)) {
        return Err(Error::Malformed("value nests too deep"));
    }
    Ok(())
}

/// Read depth a fragment of encoding `e` adds above its children (§3.3 rule 7): the array or
/// map a struct, map or list reads as; the tag and array of an enum or set (whose elements'
/// registers are its values).
fn head_depth(e: Option<Encoding>) -> usize {
    match e {
        Some(Encoding::Struct | Encoding::Map | Encoding::List) => 1,
        Some(Encoding::Enum | Encoding::Set) => 2,
        _ => 0,
    }
}

pub(crate) fn links(items: &[Value]) -> Result<Option<Vec<osis_base::Link>>, Error> {
    let n = items.iter().filter(|i| matches!(i, Value::Link(_))).count();
    if n == 0 {
        return Ok(None);
    }
    if n != items.len() {
        return Err(Error::Malformed("links mixed with elements"));
    }
    Ok(Some(items.iter().filter_map(|i| if let Value::Link(l) = i { Some(**l) } else { None }).collect()))
}

/// Pages of one paged position (plaintext, link) in the order the encoder puts them: leaf pages,
/// then link pages. Handed to `Dec::done` after the position's items are decoded, so the
/// fetched list follows the encoder's order (nested pages first) and the replay gives equal
/// plaintexts their links back in place.
pub(crate) type Fetched = Vec<(Vec<u8>, osis_base::Link)>;

/// Fetches a page. Each blob is read once per delta, so expansion is bounded by the distinct
/// pages that exist.
pub(crate) fn fetch_page(cx: &mut Dec, link: &osis_base::Link) -> Result<(Value, Vec<u8>), Error> {
    if !cx.links_seen.insert(link.blob) {
        return Err(Error::Malformed("a page linked twice"));
    }
    let src = cx.pages.as_mut().ok_or(Error::Page(PageError::Missing))?;
    let bytes = src.get(link)?;
    check_items(&bytes, src.params())?;
    let v = osis_base::decode(&bytes, &LIMITS)?;
    Ok((v, bytes))
}

/// The leaf pages under a paged position `v` holding links `top`, link pages resolved (§8, at
/// most two levels).
fn leaf_pages(cx: &mut Dec, v: &Value, top: &[osis_base::Link]) -> Result<(Vec<Value>, Fetched), Error> {
    let params = cx.pages.as_ref().map_or(PageParams::FORMAT, |p| p.params());
    if osis_base::encode(v).len() > params.target {
        return Err(Error::Malformed("link list above the page target"));
    }
    let (mut out, mut leaves, mut link_pages) = (Vec::new(), Vec::new(), Vec::new());
    for l in top {
        let (page, bytes) = fetch_page(cx, l)?;
        let inner = match &page {
            Value::List(items) => links(items)?,
            _ => None,
        };
        let Some(inner) = inner else {
            out.push(page);
            leaves.push((bytes, *l));
            continue;
        };
        link_pages.push((bytes, *l));
        if inner.len() > params.fanout {
            return Err(Error::Malformed("link page above the fan-out"));
        }
        for l in &inner {
            let (page, bytes) = fetch_page(cx, l)?;
            if let Value::List(items) = &page
                && links(items)?.is_some()
            {
                return Err(Error::Malformed("a third page level"));
            }
            out.push(page);
            leaves.push((bytes, *l));
        }
    }
    leaves.extend(link_pages);
    Ok((out, leaves))
}

/// The items of an element array, pages and link pages resolved (§8), and its pages for
/// `Dec::done` once the items are decoded.
pub(crate) fn elem_items<'v>(cx: &mut Dec, v: &'v Value) -> Result<(Cow<'v, [Value]>, Fetched), Error> {
    let items = as_array(v)?;
    let Some(top) = links(items)? else { return Ok((Cow::Borrowed(items), Vec::new())) };
    let mut out = Vec::new();
    let (pages, fetched) = leaf_pages(cx, v, &top)?;
    for page in pages {
        match page {
            Value::List(items) if !items.is_empty() => out.extend(items),
            _ => return Err(Error::Malformed("page is not a non-empty array")),
        }
    }
    Ok((Cow::Owned(out), fetched))
}

impl Dec<'_> {
    /// Records a position's pages after its items are decoded (`Fetched`).
    pub(crate) fn done(&mut self, f: Fetched) {
        self.fetched.extend(f);
    }
}

/// Requires `bytes` to be what encoding `again` produces with the fetched pages replayed.
pub(crate) fn canonical(bytes: &[u8], again: Result<Vec<u8>, Error>) -> Result<(), Error> {
    match again {
        Ok(b) if b == bytes => Ok(()),
        Ok(_) | Err(Error::Page(_)) => Err(Error::Malformed("not canonical")),
        Err(e) => Err(e),
    }
}

/// §3.3 rule 7: a fragment carries no write its own resets, or `e` (the effective reset above
/// it), prune (§4.2): a delta is a state fragment, prune-stable like any state. Checked on a
/// copy, by its writes (`Fragment::winners`): prune also drops what is no write but a join
/// keeps (an undelete's chars, §5.7).
pub(crate) fn prune_stable(f: &Fragment, e: Option<&Stamp>) -> Result<(), Error> {
    let mut p = f.clone();
    p.prune(e, &mut crate::Changes::new());
    if p.winners() == f.winners() { Ok(()) } else { Err(Error::Malformed("carries a write its own resets prune")) }
}

fn decode_meta(cx: &mut Dec, r: &Value, w: &Value) -> Result<Meta, Error> {
    let (w, w_valueless) = match as_array(w)? {
        [s, Value::Bool(false)] => (Some(cx.level_stamp(s)?), true),
        _ => (cx.opt_level_stamp(w)?, false),
    };
    Ok(Meta { reset: cx.opt_level_stamp(r)?, w, w_valueless })
}

fn decode_elems(cx: &mut Dec, v: &Value) -> Result<BTreeMap<Dot, Elem>, Error> {
    let (items, fetched) = elem_items(cx, v)?;
    let out = decode_elem_items(cx, &items)?;
    cx.done(fetched);
    Ok(out)
}

/// Bag or set elements.
pub(crate) fn decode_elem_items(cx: &mut Dec, items: &[Value]) -> Result<BTreeMap<Dot, Elem>, Error> {
    let mut out = BTreeMap::new();
    for e in items {
        let [d, r, f] = as_array(e)? else { return Err(Error::Malformed("element")) };
        let dot = cx.dot(d)?;
        let reset = cx.opt_level_stamp(r)?;
        let frag = opt_stamp_only(f, |x| cx.fragment(x))?.map(Box::new);
        // a set or bag element's value is one register (§3.2), written only by the element's
        // creation, so by its dot's source (§3.3 rule 7)
        match frag.as_deref() {
            None | Some(Fragment::Register(Register { write: None, .. })) => {}
            Some(Fragment::Register(Register { write: Some(w), .. })) if w.stamp.dot.src == dot.src => {}
            Some(Fragment::Register(_)) => return Err(Error::Malformed("set or bag element value written by another source")),
            Some(_) => return Err(Error::Malformed("set or bag element not a register")),
        }
        if frag.is_some() {
            cx.claim(&dot)?;
        }
        out.insert(dot, Elem { reset, frag });
    }
    Ok(out)
}

/// A field or payload map, inline or paged (§8); fields ascend across pages (the re-encode
/// check then pins the cuts).
fn decode_children(cx: &mut Dec, v: &Value, step: fn(u64) -> Step) -> Result<BTreeMap<u64, Fragment>, Error> {
    let mut out = BTreeMap::new();
    let paged;
    let mut fetched = Vec::new();
    let pages = match v {
        Value::Map(_) => std::slice::from_ref(v),
        Value::List(items) => {
            let top = links(items)?.ok_or(Error::Malformed("expected a map or links"))?;
            (paged, fetched) = leaf_pages(cx, v, &top)?;
            paged.as_slice()
        }
        _ => return Err(Error::Malformed("expected a map")),
    };
    let is_paged = matches!(v, Value::List(_));
    for page in pages {
        decode_fields(cx, page, is_paged, step, &mut out)?;
    }
    cx.done(fetched);
    Ok(out)
}

/// The fields of one field map or page of one (`paged`: not empty) into `out`, ascending.
pub(crate) fn decode_fields(cx: &mut Dec, page: &Value, paged: bool, step: fn(u64) -> Step, out: &mut BTreeMap<u64, Fragment>) -> Result<(), Error> {
    let Value::Map(m) = page else { return Err(Error::Malformed("page is not a map")) };
    if paged && m.is_empty() {
        return Err(Error::Malformed("empty page"));
    }
    for (k, f) in m {
        let k = as_uint(k)?;
        if out.last_key_value().is_some_and(|(l, _)| *l >= k) {
            return Err(Error::Malformed("fields out of order across pages"));
        }
        cx.step(|| step(k));
        let f = cx.fragment(f);
        cx.step_done();
        out.insert(k, f?);
    }
    Ok(())
}

/// Map entry records.
pub(crate) fn decode_entries(cx: &mut Dec, items: &[Value]) -> Result<BTreeMap<Eid, Entry>, Error> {
    let mut entries = BTreeMap::new();
    for e in items {
        // `[Dot, Ci?, R, Key?, Opt(Fragment)]`: a `Ci` is an int, an `R` an array
        let (d, ci, rest) = match as_array(e)? {
            [d, ci @ Value::Int(_), rest @ ..] => (d, Some(ci), rest),
            [d, rest @ ..] => (d, None, rest),
            [] => return Err(Error::Malformed("entry")),
        };
        let (r, key, f) = match rest {
            [r, f] => (r, None, f),
            [r, k, f] => (r, Some(k), f),
            _ => return Err(Error::Malformed("entry")),
        };
        let dot = cx.dot(d)?;
        let reset = cx.opt_level_stamp(r)?;
        cx.step(|| Step::Entry(Eid::new(dot.clone(), key.cloned())));
        let frag = opt_stamp_only(f, |x| cx.fragment(x));
        cx.step_done();
        let frag = frag?.map(Box::new);
        if let Some(k) = key {
            check_value(cx, k)?;
        }
        if frag.is_some() {
            cx.claim(&dot)?;
        }
        // the creation: carried by a snapshot; implied in a writer's delta for an
        // entry created here (own dot in the range)
        let created = match ci {
            Some(_) if cx.kind() == DeltaKind::Writer => return Err(Error::Malformed("creation commit in a writer's delta")),
            Some(ci) => {
                let c = cx.stamp(ci)?;
                if c.dot.src != dot.src {
                    return Err(Error::Malformed("creation commit of another source"));
                }
                Some(Stamp::new(c.ts, dot.src.clone(), dot.ctr))
            }
            None if cx.kind() == DeltaKind::Writer && frag.is_some() && dot.src == *cx.own() && cx.range().contains(dot.ctr) => Some(Stamp::new(cx.ts(), dot.src.clone(), dot.ctr)),
            None => None,
        };
        entries.insert(Eid::new(dot, key.cloned()), Entry { reset, frag, created });
    }
    Ok(entries)
}

/// While a root is decoded for streaming, a paged collection reached through steps is left
/// undecoded (true) and recorded with its link list (`stream`).
fn defer(cx: &mut Dec, v: &Value, enc: Encoding) -> Result<bool, Error> {
    let depth = cx.depth;
    let Some((t, found)) = cx.streaming.as_mut().filter(|(t, _)| t.on) else { return Ok(false) };
    let Value::List(items) = v else { return Ok(false) };
    if links(items)?.is_none() {
        return Ok(false);
    }
    found.insert(t.path.clone(), crate::stream::Deferred { top: v.clone(), enc, depth });
    Ok(true)
}

fn decode_register(cx: &mut Dec, a: &[Value], may_reset: bool) -> Result<Register, Error> {
    let (r, rest) = match a {
        [_, r, rest @ ..] => (r, rest),
        _ => return Err(Error::Malformed("register")),
    };
    let reset = cx.opt_level_stamp(r)?;
    if reset.is_some() && !may_reset {
        return Err(Error::Malformed("nested register with a reset"));
    }
    let write = match rest {
        [] => None,
        [s] => Some(RegWrite { stamp: cx.level_stamp(s)?, value: None }),
        [s, v] => {
            check_value(cx, v)?;
            Some(RegWrite { stamp: cx.level_stamp(s)?, value: Some(v.clone()) })
        }
        _ => return Err(Error::Malformed("register arity")),
    };
    Ok(Register { reset, write })
}

/// Decodes a fragment; `may_reset` where a register may carry a reset (root, a `Slots` slot).
pub(crate) fn decode_fragment(cx: &mut Dec, v: &Value, may_reset: bool) -> Result<Fragment, Error> {
    // read depth counts across pages too (a page's fragments may hold paged arrays), so every
    // page level adds one; within a blob the CBOR depth bounds the recursion
    let up = head_depth(v.as_list().and_then(|a| a.first()).and_then(Value::as_uint).and_then(Encoding::from_id));
    if cx.depth + up > MAX_VALUE_DEPTH {
        return Err(Error::Malformed("fragment reads deeper than MAX_VALUE_DEPTH"));
    }
    cx.depth += up;
    let at = cx.streaming.as_mut().map(|(t, _)| t.enter());
    let r = decode_fragment_at(cx, v, may_reset);
    if let (Some(at), Some((t, _))) = (at, cx.streaming.as_mut()) {
        t.leave(at);
    }
    cx.depth -= up;
    let f = r?;
    if !derived_ok(&f) {
        return Err(Error::Malformed("write with a Derived stamp"));
    }
    Ok(f)
}

/// §3.3 rule 7: only a text element's creation (and that creation as a position write) carries
/// a `Derived` stamp; checks the writes of `f`'s own level (nested fragments check their own).
pub(crate) fn derived_ok(f: &Fragment) -> bool {
    let ok = |s: Option<&Stamp>| !s.is_some_and(|s| s.dot.src.is_derived());
    let meta = |m: &Meta| ok(m.reset.as_ref()) && ok(m.w.as_ref());
    match f {
        Fragment::Register(r) => ok(r.reset.as_ref()) && ok(r.write.as_ref().map(|w| &w.stamp)),
        Fragment::Bag(Bag { meta: m, elems, .. }) | Fragment::Set(Set { meta: m, elems }) => meta(m) && elems.values().all(|e| ok(e.reset.as_ref())),
        Fragment::Struct(x) => meta(&x.meta),
        Fragment::Enum(x) => meta(&x.meta) && ok(x.case.as_ref().map(|c| &c.stamp)),
        Fragment::Map(x) => meta(&x.meta) && x.entries.values().all(|e| ok(e.reset.as_ref()) && ok(e.created.as_ref())),
        Fragment::Seq(x) => {
            meta(&x.meta)
                && x.elems().values().all(|e| {
                    let created = e.created.as_ref().map(|c| &c.0);
                    ok(e.deleted.as_ref().map(|d| &d.0)) && (x.text || ok(created)) && e.pos.iter().all(|(p, _, _)| ok(Some(p)) || Some(p) == created)
                })
        }
        Fragment::Slots(_) => true,
    }
}

fn decode_fragment_at(cx: &mut Dec, v: &Value, may_reset: bool) -> Result<Fragment, Error> {
    let a = as_array(v)?;
    let id = as_uint(a.first().ok_or(Error::Malformed("empty fragment"))?)?;
    let enc = Encoding::from_id(id).ok_or(Error::UnknownEncoding(id))?;
    Ok(match (enc, a) {
        (Encoding::Register, _) => Fragment::Register(decode_register(cx, a, may_reset)?),
        (Encoding::Counter | Encoding::Max | Encoding::Min, [_, r, w, e]) => {
            let kind = enc.bag_kind().ok_or(Error::Malformed("bag"))?;
            let meta = decode_meta(cx, r, w)?;
            let elems = if defer(cx, e, enc)? { BTreeMap::new() } else { decode_elems(cx, e)? };
            Fragment::Bag(Bag { kind, meta, elems })
        }
        (Encoding::Set, [_, r, w, e]) => {
            let meta = decode_meta(cx, r, w)?;
            let elems = if defer(cx, e, enc)? { BTreeMap::new() } else { decode_elems(cx, e)? };
            Fragment::Set(Set { meta, elems })
        }
        (Encoding::Struct, [_, r, w, c]) => {
            let meta = decode_meta(cx, r, w)?;
            let fields = if defer(cx, c, enc)? { BTreeMap::new() } else { decode_children(cx, c, Step::Field)? };
            Fragment::Struct(Struct { meta, fields })
        }
        (Encoding::Enum, [_, r, w, k, c]) => {
            let meta = decode_meta(cx, r, w)?;
            let case = opt_stamp_only(k, |c| match as_array(c)? {
                [s] => Ok(CaseWrite { stamp: cx.level_stamp(s)?, case: None }),
                [s, id] => Ok(CaseWrite { stamp: cx.level_stamp(s)?, case: Some(as_uint(id)?) }),
                _ => Err(Error::Malformed("case")),
            })?;
            let payloads = if defer(cx, c, enc)? { BTreeMap::new() } else { decode_children(cx, c, Step::Case)? };
            Fragment::Enum(Enum { meta, case, payloads })
        }
        (Encoding::Map, [_, r, w, es]) => {
            let meta = decode_meta(cx, r, w)?;
            if defer(cx, es, enc)? {
                return Ok(Fragment::Map(Map::new(meta, BTreeMap::new())));
            }
            let (items, fetched) = elem_items(cx, es)?;
            let entries = decode_entries(cx, &items)?;
            cx.done(fetched);
            Fragment::Map(Map::new(meta, entries))
        }
        (Encoding::List | Encoding::Text, [_, r, w, es]) => {
            let meta = decode_meta(cx, r, w)?;
            let mut s = Seq::new(enc == Encoding::Text, meta, BTreeMap::new());
            if defer(cx, es, enc)? {
                return Ok(Fragment::Seq(s));
            }
            let (runs, fetched) = elem_items(cx, es)?;
            seq::decode_elems(&mut s, &runs, cx)?;
            cx.done(fetched);
            Fragment::Seq(s)
        }
        (Encoding::Slots, [_, reg, ms]) => {
            if cx.kind() == DeltaKind::Writer {
                return Err(Error::Malformed("slots in a writer's delta"));
            }
            let reg = opt_stamp_only(reg, |r| match decode_fragment(cx, r, true)? {
                Fragment::Register(r) => Ok(r),
                _ => Err(Error::Malformed("slots: first slot is not a register")),
            })?;
            let mut slots = BTreeMap::new();
            let mut last: Option<Encoding> = None;
            for m in as_array(ms)? {
                let f = decode_fragment(cx, m, true)?;
                let e = f.encoding();
                if matches!(e, Encoding::Register | Encoding::Slots) || last.is_some_and(|l| e <= l) {
                    return Err(Error::Malformed("slots: unsorted, repeated or nested slots"));
                }
                last = Some(e);
                slots.insert(e, f);
            }
            if usize::from(reg.is_some()) + slots.len() < 2 {
                return Err(Error::Malformed("slots with fewer than two slots"));
            }
            // §7 Canonical form (§3.3 rule 7): pruning changes nothing the wire carries (every
            // slot holds the register's embedding, none is empty or adds nothing to it, nothing
            // lies below the position's one reset; the chars of deleted embedded elements the
            // embedding restores are never carried, rule 5), so readers of an unjoined fragment
            // see what a join would; the pruned form is returned, so those chars are held again
            // as at a node that joined the register
            let pruned = crate::state::prune_slots(reg.clone(), slots.clone(), None, &mut crate::Changes::new());
            let mut carried = pruned.clone();
            carried.drop_deleted_chars();
            if carried != Fragment::Slots(Slots { reg, slots }) {
                return Err(Error::Malformed("slots not canonical: pruning changes it"));
            }
            pruned
        }
        _ => return Err(Error::Malformed("fragment arity")),
    })
}

pub(crate) fn nonce(v: &Value) -> Result<[u8; NONCE_LEN], Error> {
    v.as_array().ok_or(Error::Malformed("nonce"))
}

/// Items `MAX_PAGE_ITEMS` counts in one value spanning `bytes` (§8): one per CBOR head (a tag and
/// its content apart), one more per byte of a text string; by heads alone, at most `bytes.len()`.
pub fn page_items(bytes: &[u8]) -> Result<usize, Error> {
    let mut n = 0usize;
    osis_base::visit_items(bytes, &LIMITS, &mut |_, major, arg| {
        let text = if major == osis_base::cbor::MAJOR_TEXT { usize::try_from(arg).unwrap_or(usize::MAX) } else { 0 };
        n = n.saturating_add(1).saturating_add(text);
    })?;
    Ok(n)
}

/// Bad input when a page or root fragment counts more than `params.max_items` (§8), checked
/// before anything is decoded. The count never exceeds the bytes, so smaller blobs skip it.
pub(crate) fn check_items(bytes: &[u8], params: PageParams) -> Result<(), Error> {
    if bytes.len() > params.max_items && page_items(bytes)? > params.max_items {
        return Err(Error::Malformed("page or root fragment above MAX_PAGE_ITEMS items"));
    }
    Ok(())
}

/// `check_items` on the fragment of a delta or snapshot root (its fourth item), found by heads;
/// a root without one is left to the decoder to refuse.
pub(crate) fn check_root(bytes: &[u8], pages: Option<&dyn PageSource>) -> Result<(), Error> {
    let params = pages.map_or(PageParams::FORMAT, |p| p.params());
    if bytes.len() <= params.max_items {
        return Ok(());
    }
    // a 4-, 6- or 7-item array head (§3.2, §8)
    let Some((0x84 | 0x86 | 0x87, mut rest)) = bytes.split_first() else { return Ok(()) };
    for _ in 0..3 {
        let Some(r) = osis_base::item_prefix(rest, &LIMITS).ok().and_then(|item| rest.get(item.len()..)) else { return Ok(()) };
        rest = r;
    }
    match osis_base::item_prefix(rest, &LIMITS) {
        Ok(frag) => check_items(frag, params),
        Err(_) => Ok(()),
    }
}

/// Decodes a delta (§3.2) against its header facts; bad input unless canonical. The whole
/// fragment, pages joined in (`stream_delta` checks and yields it page by page).
pub fn decode_delta<'a>(bytes: &[u8], cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Result<Delta, Error> {
    let mut whole = crate::stream::Whole::default();
    let head = crate::stream::stream(bytes, cx, interner, pages, false, &mut |p| whole.add(p))?;
    Ok(Delta { nonce: head.nonce, fragment: whole.done() })
}

/// Decodes a snapshot delta (§8); bad input unless canonical. The whole fragment, as
/// `decode_delta`.
pub fn decode_snapshot<'a>(bytes: &[u8], cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Result<Snapshot, Error> {
    let mut whole = crate::stream::Whole::default();
    let head = crate::stream::stream(bytes, cx, interner, pages, true, &mut |p| whole.add(p))?;
    Ok(Snapshot { nonce: head.nonce, fragment: whole.done(), frontiers: head.frontiers, absorbed: head.absorbed })
}

/// `[nonce, Sources, Commits]` of a delta or snapshot root into `dec`.
pub(crate) fn root_tables(dec: &mut Dec, sources: &Value, commits: &Value) -> Result<(), Error> {
    dec.load_sources(sources)?;
    dec.load_commits(commits)
}

/// A snapshot's `Frontiers` and `Absorbed` (§8): one frontier entry per `Session` source of the
/// table, in table order, 0 included (a source with no write in the fragment has none, so an
/// absent source is one the snapshot holds nothing of).
pub(crate) fn snapshot_tail(dec: &Dec, fr: &Value, ab: &Value) -> Result<(Frontiers, BTreeMap<osis_base::CommitId, osis_base::Tid>), Error> {
    let mut frontiers = Frontiers::default();
    let mut counted = dec.sources().filter(|s| matches!(s.kind(), SourceKind::Session(_)));
    for e in as_array(fr)? {
        let [i, c] = as_array(e)? else { return Err(Error::Malformed("frontier")) };
        let src = dec.src(i)?;
        if counted.next() != Some(&src) {
            return Err(Error::Malformed("frontier entries not the fragment's session sources in order"));
        }
        frontiers.insert(&src, as_uint(c)?);
    }
    if counted.next().is_some() {
        return Err(Error::Malformed("a session source of the fragment without a frontier entry"));
    }
    let mut absorbed = BTreeMap::new();
    for e in as_array(ab)? {
        let [c, a] = as_array(e)? else { return Err(Error::Malformed("absorbed commit")) };
        let (Value::Bytes(c), Value::Tid(a)) = (c, a) else { return Err(Error::Malformed("absorbed commit")) };
        let c = <[u8; 32]>::try_from(c.as_slice()).map_err(|_| Error::Malformed("absorbed commit ID"))?;
        if absorbed.insert(osis_base::CommitId(c), *a).is_some() {
            return Err(Error::Malformed("absorbed commit repeated"));
        }
    }
    Ok((frontiers, absorbed))
}

/// The absorbed table as written (§8).
pub(crate) fn absorbed_value(absorbed: &BTreeMap<osis_base::CommitId, osis_base::Tid>) -> Value {
    Value::List(absorbed.iter().map(|(c, a)| Value::List(vec![Value::Bytes(c.0.to_vec()), Value::Tid(*a)])).collect())
}

/// The whole-delta decoder and encoder before streaming. The decoder decodes every page into one
/// fragment, then re-encodes all of it (two passes) and requires the input bytes: the test
/// oracle of `stream` (it must accept and reject exactly the same inputs). The encoder holds
/// every element of an array before cutting it into pages, and its collecting pass builds the
/// whole value tree: the test oracle of `Pager` (byte-identical output).
#[cfg(any(test, fuzzing))]
pub mod oracle {
    use super::*;

    /// Pages `items` (canonical bytes `encoded`) when the plain form `whole(items)` is above the
    /// target (spec/wire.md §6).
    pub(crate) fn paged<T>(mut pages: Option<&mut dyn PageSink>, items: Vec<T>, encoded: Vec<Vec<u8>>, whole: impl Fn(Vec<T>) -> Value) -> Result<Value, Error> {
        let params = pages.as_ref().map_or(PageParams::FORMAT, |p| p.params());
        // array and map heads have the same length
        let size = encoded.iter().fold(array_head(items.len()), |n, e| n.saturating_add(e.len()));
        if size <= params.target {
            return Ok(whole(items));
        }
        let sink = pages.as_mut().ok_or(Error::Mismatch("a paged array needs a page sink"))?;
        let mut cutter = PageCutter::new(params.cut);
        let mut links = Vec::new();
        let mut page = Vec::new();
        for (item, bytes) in items.into_iter().zip(&encoded) {
            page.push(item);
            cutter.feed(bytes);
            if cutter.end_element() {
                links.push(Value::link(sink.put(&osis_base::encode(&whole(std::mem::take(&mut page))))?));
            }
        }
        if !page.is_empty() {
            links.push(Value::link(sink.put(&osis_base::encode(&whole(page)))?));
        }
        let list = Value::List(links);
        if osis_base::encode(&list).len() <= params.target {
            return Ok(list);
        }
        let Value::List(links) = list else { return Err(Error::Mismatch("links")) };
        let mut groups = Vec::new();
        for g in link_groups(&links, params.fanout) {
            groups.push(Value::link(sink.put(&osis_base::encode(&Value::List(g.to_vec())))?));
        }
        let top = Value::List(groups);
        if osis_base::encode(&top).len() > params.target {
            return Err(Error::Mismatch("fragment needs a third page level"));
        }
        Ok(top)
    }

    /// A content-addressed sink (`twin`): equal pages get equal links whatever the order of puts.
    #[cfg(test)]
    struct Cas {
        params: PageParams,
        pages: Vec<Vec<u8>>,
    }

    #[cfg(test)]
    impl PageSink for Cas {
        fn put(&mut self, p: &[u8]) -> Result<osis_base::Link, PageError> {
            self.pages.push(p.to_vec());
            let hash = osis_base::hash::hash(p);
            Ok(osis_base::Link { hash, blob: osis_base::BlobId(hash), suite: 1, key: [0; 32] })
        }
        fn params(&self) -> PageParams {
            self.params
        }
    }

    /// In this crate's tests every encode runs `new` (the streaming encoder) beside the oracle
    /// `old`, each into a content-addressed sink, and requires the same root bytes and the same
    /// pages, or both an error; then `new` into `pages`.
    #[cfg(test)]
    pub(crate) fn twin(mut pages: Option<&mut dyn PageSink>, new: impl Fn(Option<&mut dyn PageSink>) -> Result<Vec<u8>, Error>, old: impl Fn(Option<&mut dyn PageSink>) -> Result<Vec<u8>, Error>) -> Result<Vec<u8>, Error> {
        type Encode<'f> = dyn Fn(Option<&mut dyn PageSink>) -> Result<Vec<u8>, Error> + 'f;
        let run = |f: &Encode| {
            let mut cas = pages.as_ref().map(|p| Cas { params: p.params(), pages: Vec::new() });
            let out = f(cas.as_mut().map(|c| c as &mut dyn PageSink));
            let mut written = cas.map(|c| c.pages).unwrap_or_default();
            written.sort();
            (out, written)
        };
        let (a, b) = (run(&new), run(&old));
        match (&a.0, &b.0) {
            (Ok(x), Ok(y)) => assert!(x == y && a.1 == b.1, "streaming encoder and oracle differ"),
            (Err(_), Err(_)) => {}
            (x, y) => panic!("streaming encoder {x:?}, oracle {y:?}"),
        }
        new(re(&mut pages))
    }

    fn encode_top<'p>(cx: &DeltaCtx, f: &Fragment, frontiers: Option<&Frontiers>, pages: Option<&'p mut dyn PageSink>) -> Result<(Enc<'p>, Value, Option<Value>), Error> {
        let mut enc = Enc::new(cx, pages);
        enc.whole = true;
        encode_fragment(&mut enc, f)?;
        enc.finish_collecting();
        let frag = encode_fragment(&mut enc, f)?;
        let fr = frontiers.map(|fr| enc.frontiers_value(fr));
        Ok((enc, frag, fr))
    }

    pub fn encode_delta(d: &Delta, cx: &DeltaCtx, pages: Option<&mut dyn PageSink>) -> Result<Vec<u8>, Error> {
        let (enc, frag, _) = encode_top(cx, &d.fragment, None, pages)?;
        let top = Value::List(vec![Value::Bytes(d.nonce.to_vec()), enc.sources_value(), enc.commits_value(), frag]);
        Ok(osis_base::encode(&top))
    }

    pub fn encode_snapshot(s: &Snapshot, cx: &DeltaCtx, pages: Option<&mut dyn PageSink>) -> Result<Vec<u8>, Error> {
        let (enc, frag, fr) = encode_top(cx, &s.fragment, Some(&s.frontiers), pages)?;
        super::frontiers_traced(&enc, s)?;
        let fr = fr.unwrap_or(Value::List(Vec::new()));
        let top = vec![Value::Bytes(s.nonce.to_vec()), enc.sources_value(), enc.commits_value(), frag, fr, absorbed_value(&s.absorbed)];
        Ok(osis_base::encode(&Value::List(top)))
    }

    fn replay(dec: &mut Dec) -> crate::wire::Replay {
        let mut r = crate::wire::Replay::new(dec.pages.as_ref().map_or(PageParams::FORMAT, |p| p.params()));
        r.extend(std::mem::take(&mut dec.fetched));
        r
    }

    pub fn decode_delta<'a>(bytes: &[u8], cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Result<Delta, Error> {
        check_root(bytes, pages.as_deref())?;
        let top = osis_base::decode(bytes, &LIMITS)?;
        let [n, sources, commits, frag] = as_array(&top)? else { return Err(Error::Malformed("delta arity")) };
        let mut dec = Dec::new(cx, interner, pages);
        root_tables(&mut dec, sources, commits)?;
        let fragment = decode_fragment(&mut dec, frag, true)?;
        let mut replay = replay(&mut dec);
        let d = Delta { nonce: nonce(n)?, fragment };
        canonical(bytes, self::encode_delta(&d, cx, Some(&mut replay)))?;
        prune_stable(&d.fragment, None)?;
        Ok(d)
    }

    pub fn decode_snapshot<'a>(bytes: &[u8], cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Result<Snapshot, Error> {
        check_root(bytes, pages.as_deref())?;
        let top = osis_base::decode(bytes, &LIMITS)?;
        let [n, sources, commits, frag, fr, ab] = as_array(&top)? else { return Err(Error::Malformed("snapshot arity")) };
        let mut dec = Dec::new(cx, interner, pages);
        root_tables(&mut dec, sources, commits)?;
        let fragment = decode_fragment(&mut dec, frag, true)?;
        let (frontiers, absorbed) = snapshot_tail(&dec, fr, ab)?;
        let mut replay = replay(&mut dec);
        let s = Snapshot { nonce: nonce(n)?, fragment, frontiers, absorbed };
        canonical(bytes, self::encode_snapshot(&s, cx, Some(&mut replay)))?;
        prune_stable(&s.fragment, None)?;
        Ok(s)
    }
}

/// `decoded_bound`'s charge per CBOR data item and per byte of a run's text content (each a
/// character, an element held, §5.7): above the most `Fragment::approx_bytes` takes per item
/// outside map and set heads (measured about 300, a one-entry map or one-field struct per level: a
/// whole B-tree node for a few items; a value item in a map key, held three times, about 320) and
/// per character (about 380). Tests `decoded_bound_*` and the wire round trips. Resource
/// estimate: 0 lets a blob of tiny entries pass a bound it decodes far past; infinity refuses
/// every blob checked against it.
pub const ITEM_BYTES: usize = 512;

/// `decoded_bound`'s charge per encoded byte: a map key's string is held three times (the entry
/// ID's, the key index's key and the index's entry ID). Resource estimate, as `ITEM_BYTES`.
pub const BYTE_BYTES: usize = 3;

/// Copies of a map key's value held (`BYTE_BYTES`): the bound does not tell keys from other
/// values, so every value-tree node counts that many times.
const KEY_COPIES: usize = 3;

/// `decoded_bound`'s extra charge per CBOR map head: a one-field struct's field map is a whole
/// B-tree node, and a `Value::Map` its entries, in each copy of a key.
const MAP_HEAD: usize = KEY_COPIES * crate::access::nodes(1, 2 * size_of::<Value>());

/// `decoded_bound`'s extra charge per set tag (a set fragment's node), as `MAP_HEAD`.
const SET_HEAD: usize = KEY_COPIES * crate::access::nodes(1, size_of::<Value>());

/// An upper bound on the `Fragment::approx_bytes` of what `decode_delta` or `decode_snapshot`
/// makes of unpaged `bytes`, found by its CBOR heads alone, nothing allocated: `ITEM_BYTES` per
/// data item and per byte of a text string a run may carry as content (the fourth of six, §3.2
/// `Run`), `MAP_HEAD` per map, `SET_HEAD` per set, `BYTE_BYTES` per byte. Bad input when the
/// bytes are not one CBOR value.
pub fn decoded_bound(bytes: &[u8]) -> Result<usize, Error> {
    use osis_base::Place;
    use osis_base::cbor::{MAJOR_MAP, MAJOR_TAG, MAJOR_TEXT};
    use osis_base::format::TAG_SET;
    let mut sum = 0usize;
    osis_base::visit_items(bytes, &LIMITS, &mut |place, major, arg| {
        let each = match major {
            MAJOR_TEXT if place == (Place::InArray { len: 6, index: 3 }) => usize::try_from(arg).unwrap_or(usize::MAX).saturating_add(1).saturating_mul(ITEM_BYTES),
            MAJOR_MAP => ITEM_BYTES + MAP_HEAD,
            MAJOR_TAG if arg == TAG_SET => ITEM_BYTES + SET_HEAD,
            _ => ITEM_BYTES,
        };
        sum = sum.saturating_add(each);
    })?;
    Ok(sum.saturating_add(bytes.len().saturating_mul(BYTE_BYTES)))
}

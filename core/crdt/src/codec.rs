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
use crate::wire::{Dec, Delta, DeltaCtx, DeltaKind, Enc, Frontiers, NONCE_LEN, Snapshot, as_array, as_uint};
use osis_base::cbor::{Item, List, encode_into, head_len, link_len, put_array, put_bool, put_bytes, put_link, put_map, put_tid, put_uint};
use osis_base::format::{MAX_BLOB, MAX_OBJECT_DEPTH, MAX_VALUE_DEPTH};
use osis_base::{CanonicalBytes, Limits, Link, PageCutter, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const LIMITS: Limits = Limits { max_depth: MAX_OBJECT_DEPTH, max_bytes: MAX_BLOB };

// ---- encode

/// `Opt(Fragment)`.
fn opt_frag(cx: &mut Enc, out: &mut Vec<u8>, f: Option<&Fragment>) -> Result<(), Error> {
    put_array(out, usize::from(f.is_some()));
    match f {
        Some(f) => encode_fragment(cx, out, f),
        None => Ok(()),
    }
}

/// An element array's (or field map's) head of `n` items.
fn put_head(out: &mut Vec<u8>, map: bool, n: usize) {
    if map { put_map(out, n) } else { put_array(out, n) }
}

/// `[Link*]`.
fn put_links(out: &mut Vec<u8>, links: &[Link]) {
    put_array(out, links.len());
    links.iter().for_each(|l| put_link(out, l));
}

/// `put_links(links).len()`.
fn links_len(n: usize) -> usize {
    head_len(n as u64).saturating_add(n.saturating_mul(link_len()))
}

/// An element array (or, `map`, a struct's field map or an enum's payload map) as written (§8,
/// spec/wire.md §6), written element by element: itself while its plain encoding is at or below
/// the page target; past it, cut into pages as elements come (`PageCutter`; a field's key and
/// value bytes are one element, a page of fields a map), each page put through the sink as it
/// closes; at the end `[Link+]`, or link pages when that list is above the target. Holds the
/// bytes of one page's elements (all of them while the array may still be plain) and the links.
/// The collecting pass keeps nothing (§3.3 rule 1 notes sources as elements are encoded).
pub(crate) struct Pager {
    map: bool,
    keep: bool,
    params: PageParams,
    cutter: PageCutter,
    /// Elements not yet in a closed page, as written, then the one being written.
    buf: Vec<u8>,
    /// Where the element being written starts in `buf`.
    mark: usize,
    /// Elements held in `buf`, and while not paging where each starts.
    held: usize,
    starts: Vec<usize>,
    /// Elements and their encoded bytes so far: paged once the plain form passes the target.
    count: usize,
    size: usize,
    paging: bool,
    links: Vec<Link>,
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
            buf: Vec::new(),
            mark: 0,
            held: 0,
            starts: Vec::new(),
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

    /// Where the next element (a list element, or a field's key and value) is written; `end`
    /// closes it.
    pub(crate) fn out(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    /// Closes the element written since the last `end`.
    pub(crate) fn end(&mut self, mut sink: Option<&mut dyn PageSink>) -> Result<(), Error> {
        if !self.keep {
            self.buf.truncate(self.mark);
            return Ok(());
        }
        self.count += 1;
        self.size = self.size.saturating_add(self.buf.len().saturating_sub(self.mark));
        if self.paging {
            return self.feed(sink);
        }
        self.starts.push(self.mark);
        self.held += 1;
        self.mark = self.buf.len();
        if self.oracle() || head_len(self.count as u64).saturating_add(self.size) <= self.params.target {
            return Ok(());
        }
        // paged (the plain form only grows): cut what is held, then go on as elements come
        self.paging = true;
        let (buf, starts) = (std::mem::take(&mut self.buf), std::mem::take(&mut self.starts));
        (self.held, self.mark) = (0, 0);
        for (i, s) in starts.iter().enumerate() {
            let e = starts.get(i + 1).copied().unwrap_or(buf.len());
            self.buf.extend_from_slice(buf.get(*s..e).unwrap_or_default());
            self.feed(re(&mut sink))?;
        }
        Ok(())
    }

    /// The element from `mark` to the end of `buf` to the cutter, while paging.
    fn feed(&mut self, sink: Option<&mut dyn PageSink>) -> Result<(), Error> {
        self.cutter.feed(self.buf.get(self.mark..).unwrap_or_default());
        self.held += 1;
        self.mark = self.buf.len();
        if self.cutter.end_element() { self.put_page(sink) } else { Ok(()) }
    }

    /// The held elements as an array or map.
    fn put_plain(&self, out: &mut Vec<u8>) {
        put_head(out, self.map, self.held);
        out.extend_from_slice(&self.buf);
    }

    fn put_page(&mut self, sink: Option<&mut dyn PageSink>) -> Result<(), Error> {
        let sink = sink.ok_or(Error::Mismatch("a paged array needs a page sink"))?;
        let mut page = Vec::with_capacity(head_len(self.held as u64) + self.buf.len());
        self.put_plain(&mut page);
        self.links.push(sink.put(&page)?);
        self.buf.clear();
        (self.held, self.mark) = (0, 0);
        Ok(())
    }

    /// Writes the array as written: at a streamed position of a root being checked (`stream`),
    /// its link list as the input has it.
    pub(crate) fn done(self, cx: &mut Enc, out: &mut Vec<u8>) -> Result<(), Error> {
        if let Some(v) = cx.check.as_mut().and_then(|c| c.streamed()) {
            out.extend_from_slice(&v);
            return Ok(());
        }
        #[cfg(any(test, fuzzing))]
        if self.whole {
            return self.done_whole(cx, out);
        }
        self.finish(cx.sink(), out)
    }

    /// `done` as the whole encoder (`oracle`): the collecting pass writes the elements, the
    /// real one cuts them all at once.
    #[cfg(any(test, fuzzing))]
    fn done_whole(self, cx: &mut Enc, out: &mut Vec<u8>) -> Result<(), Error> {
        if cx.collecting() {
            self.put_plain(out);
            return Ok(());
        }
        let ends = self.starts.iter().skip(1).copied().chain([self.buf.len()]);
        let elems: Vec<&[u8]> = self.starts.iter().zip(ends).map(|(s, e)| self.buf.get(*s..e).unwrap_or_default()).collect();
        oracle::paged(cx.sink(), self.map, &elems, out)
    }

    /// Writes the array as written (the collecting pass: an empty one).
    pub(crate) fn finish(mut self, mut sink: Option<&mut dyn PageSink>, out: &mut Vec<u8>) -> Result<(), Error> {
        if !self.paging {
            self.put_plain(out);
            return Ok(());
        }
        if self.held > 0 {
            self.put_page(re(&mut sink))?;
        }
        link_list(sink, &self.links, self.params, out)
    }
}

/// `[Link+]` of an array's pages, or of link pages when that list is above the target (§8,
/// spec/wire.md §6: the tree-node grouping rule, level 1 only).
fn link_list(sink: Option<&mut dyn PageSink>, links: &[Link], params: PageParams, out: &mut Vec<u8>) -> Result<(), Error> {
    if links_len(links.len()) <= params.target {
        put_links(out, links);
        return Ok(());
    }
    let sink = sink.ok_or(Error::Mismatch("a paged array needs a page sink"))?;
    let mut top = Vec::new();
    for g in link_groups(links, params.fanout) {
        let mut page = Vec::with_capacity(links_len(g.len()));
        put_links(&mut page, g);
        top.push(sink.put(&page)?);
    }
    if links_len(top.len()) > params.target {
        return Err(Error::Mismatch("fragment needs a third page level"));
    }
    put_links(out, &top);
    Ok(())
}

/// `sink` reborrowed.
fn re<'s>(sink: &'s mut Option<&mut dyn PageSink>) -> Option<&'s mut dyn PageSink> {
    match sink {
        Some(p) => Some(&mut **p),
        None => None,
    }
}

/// An element array as written (§8, spec/wire.md §6): itself at or below the sink's page target,
/// else `[Link+]` to pages, or to link pages when that list is above the target. Pages are put
/// through the sink; `None` is fine only for an array that does not page.
pub fn page_array(mut pages: Option<&mut dyn PageSink>, items: &[Value]) -> Result<Vec<u8>, Error> {
    let mut p = Pager::new(false, pages.as_ref().map_or(PageParams::FORMAT, |p| p.params()));
    for v in items {
        encode_into(v, p.out());
        p.end(re(&mut pages))?;
    }
    let mut out = Vec::new();
    p.finish(pages, &mut out)?;
    Ok(out)
}

/// Links grouped into link pages by the tree-node rule (spec/wire.md §6): a group closes after
/// a link whose hash starts with a zero byte (from its second link) or at `fanout` links.
pub(crate) fn link_groups(links: &[Link], fanout: usize) -> Vec<&[Link]> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, l) in links.iter().enumerate() {
        let zero = l.hash.first() == Some(&0);
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
pub(crate) fn encode_elem(cx: &mut Enc, out: &mut Vec<u8>, d: &Dot, e: &Elem) -> Result<(), Error> {
    put_array(out, 3);
    cx.dot(out, d);
    cx.opt_stamp(out, e.reset.as_ref());
    opt_frag(cx, out, e.frag.as_deref())
}

fn encode_elems(cx: &mut Enc, out: &mut Vec<u8>, elems: &BTreeMap<Dot, Elem>) -> Result<(), Error> {
    let mut p = Pager::of(cx, false);
    for (d, e) in cx.sorted(elems) {
        encode_elem(cx, p.out(), d, e)?;
        p.end(cx.sink())?;
    }
    p.done(cx, out)
}

/// A map entry record `[Dot, Ci?, R, Key?, Opt(Fragment)]`.
pub(crate) fn encode_entry(cx: &mut Enc, out: &mut Vec<u8>, id: &Eid, e: &Entry) -> Result<(), Error> {
    // the creation's commit, where a snapshot carries it (a writer's own creations
    // are implied, §3.2)
    let created = e.created.as_ref().filter(|c| !cx.is_own(c));
    put_array(out, 3 + usize::from(created.is_some()) + usize::from(id.key().is_some()));
    cx.dot(out, &id.dot);
    if let Some(c) = created {
        put_uint(out, cx.commit_of(c));
    }
    cx.opt_stamp(out, e.reset.as_ref());
    if let Some(k) = id.key() {
        encode_into(k, out);
    }
    cx.step(|| Step::Entry(id.clone()));
    let r = opt_frag(cx, out, e.frag.as_deref());
    cx.step_done();
    r
}

/// A struct field or enum payload `(id, Fragment)`; `step` names it in a path.
pub(crate) fn encode_field(cx: &mut Enc, out: &mut Vec<u8>, k: u64, f: &Fragment, step: fn(u64) -> Step) -> Result<(), Error> {
    put_uint(out, k);
    cx.step(|| step(k));
    let r = encode_fragment(cx, out, f);
    cx.step_done();
    r
}

/// A fragment's array head of `len` items, its encoding ID, `R` and `W`.
fn head(cx: &mut Enc, out: &mut Vec<u8>, enc: Encoding, meta: &Meta, len: usize) {
    put_array(out, len);
    put_uint(out, u64::from(enc.id()));
    // sources are noted in encoding order (§3.3 rule 1): the reset first
    cx.opt_stamp(out, meta.reset.as_ref());
    // a value-less `W` (§3.2, §4.7)
    put_array(out, usize::from(meta.w.is_some()) + usize::from(meta.w_valueless));
    if let Some(w) = &meta.w {
        cx.stamp(out, w);
    }
    if meta.w_valueless {
        put_bool(out, false);
    }
}

fn encode_children(cx: &mut Enc, out: &mut Vec<u8>, c: &BTreeMap<u64, Fragment>, step: fn(u64) -> Step) -> Result<(), Error> {
    let mut p = Pager::of(cx, true);
    for (k, f) in c {
        encode_field(cx, p.out(), *k, f, step)?;
        p.end(cx.sink())?;
    }
    p.done(cx, out)
}

fn encode_register(cx: &mut Enc, out: &mut Vec<u8>, r: &Register) {
    let value = r.write.as_ref().and_then(|w| w.value.as_ref());
    put_array(out, 2 + usize::from(r.write.is_some()) + usize::from(value.is_some()));
    put_uint(out, 0);
    cx.opt_stamp(out, r.reset.as_ref());
    if let Some(w) = &r.write {
        cx.stamp(out, &w.stamp);
    }
    if let Some(v) = value {
        encode_into(v, out);
    }
}

pub(crate) fn encode_fragment(cx: &mut Enc, out: &mut Vec<u8>, f: &Fragment) -> Result<(), Error> {
    let Some(at) = cx.track().map(|t| t.enter()) else { return encode_fragment_at(cx, out, f) };
    let r = encode_fragment_at(cx, out, f);
    if let Some(t) = cx.track() {
        t.leave(at);
    }
    r
}

fn encode_fragment_at(cx: &mut Enc, out: &mut Vec<u8>, f: &Fragment) -> Result<(), Error> {
    match f {
        Fragment::Register(r) => encode_register(cx, out, r),
        Fragment::Bag(Bag { meta, elems, .. }) | Fragment::Set(Set { meta, elems }) => {
            head(cx, out, f.encoding(), meta, 4);
            encode_elems(cx, out, elems)?;
        }
        Fragment::Struct(s) => {
            head(cx, out, Encoding::Struct, &s.meta, 4);
            encode_children(cx, out, &s.fields, Step::Field)?;
        }
        Fragment::Enum(s) => {
            head(cx, out, Encoding::Enum, &s.meta, 5);
            put_array(out, usize::from(s.case.is_some()));
            if let Some(c) = &s.case {
                put_array(out, 1 + usize::from(c.case.is_some()));
                cx.stamp(out, &c.stamp);
                if let Some(k) = c.case {
                    put_uint(out, k);
                }
            }
            encode_children(cx, out, &s.payloads, Step::Case)?;
        }
        Fragment::Map(m) => {
            head(cx, out, Encoding::Map, &m.meta, 4);
            let mut p = Pager::of(cx, false);
            for (id, e) in cx.sorted_by(&m.entries, |id| &id.dot) {
                encode_entry(cx, p.out(), id, e)?;
                p.end(cx.sink())?;
            }
            p.done(cx, out)?;
        }
        Fragment::Seq(s) => {
            head(cx, out, s.encoding(), &s.meta, 4);
            let mut p = Pager::of(cx, false);
            seq::encode_elems(s, cx, &mut p)?;
            p.done(cx, out)?;
        }
        Fragment::Slots(s) => {
            put_array(out, 3);
            put_uint(out, u64::from(Encoding::Slots.id()));
            put_array(out, usize::from(s.reg.is_some()));
            if let Some(r) = &s.reg {
                encode_register(cx, out, r);
            }
            put_array(out, s.slots.len());
            for f in s.slots.values() {
                encode_fragment(cx, out, f)?;
            }
        }
    }
    Ok(())
}

/// The collecting pass over `f` (§3.3 rule 1): `enc`'s tables, nothing written.
fn collect(enc: &mut Enc, f: &Fragment) -> Result<(), Error> {
    encode_fragment(enc, &mut Vec::new(), f)?;
    enc.finish_collecting();
    Ok(())
}

/// The sources with a stamp, dot, anchor or sibling key in `f`'s canonical encoding (its
/// `Sources` table, §3.3 rule 1), the own source aside: what a snapshot of `f` may list a
/// frontier for (§8).
pub fn sources_of(f: &Fragment, cx: &DeltaCtx) -> Result<BTreeSet<Source>, Error> {
    let mut enc = Enc::new(cx, None);
    collect(&mut enc, f)?;
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
    write_delta(Enc::new(cx, pages), d)
}

/// `[nonce, Sources, Commits, Fragment]`, both passes by `enc`.
fn write_delta(mut enc: Enc, d: &Delta) -> Result<Vec<u8>, Error> {
    collect(&mut enc, &d.fragment)?;
    let mut out = Vec::new();
    put_array(&mut out, 4);
    put_bytes(&mut out, &d.nonce);
    enc.put_sources(&mut out);
    enc.put_commits(&mut out);
    encode_fragment(&mut enc, &mut out, &d.fragment)?;
    Ok(out)
}

/// Encodes a snapshot delta (§8). The caller strips values of expiring deltas first (§4.7).
pub fn encode_snapshot(s: &Snapshot, cx: &DeltaCtx, pages: Option<&mut dyn PageSink>) -> Result<Vec<u8>, Error> {
    #[cfg(test)]
    return oracle::twin(pages, |p| write_snapshot(Enc::new(cx, p), s), |p| oracle::encode_snapshot(s, cx, p));
    #[cfg(not(test))]
    write_snapshot(Enc::new(cx, pages), s)
}

/// `[nonce, Sources, Commits, Fragment, Frontiers, Absorbed, Facts]`, both passes by `enc`.
fn write_snapshot(mut enc: Enc, s: &Snapshot) -> Result<Vec<u8>, Error> {
    collect(&mut enc, &s.fragment)?;
    let mut out = Vec::new();
    put_array(&mut out, 7);
    put_bytes(&mut out, &s.nonce);
    enc.put_sources(&mut out);
    enc.put_commits(&mut out);
    encode_fragment(&mut enc, &mut out, &s.fragment)?;
    frontiers_traced(&enc, s)?;
    enc.put_frontiers(&mut out, &s.frontiers);
    put_absorbed(&mut out, &s.absorbed);
    enc.put_facts(&mut out, &s.facts);
    Ok(out)
}

// ---- decode

fn opt_stamp_only<'a, T>(v: Item<'a>, f: impl FnOnce(Item<'a>) -> Result<T, Error>) -> Result<Option<T>, Error> {
    let a = as_array(v)?;
    match a.tuple() {
        _ if a.is_empty() => Ok(None),
        Some([x]) => f(x).map(Some),
        None => Err(Error::Malformed("expected Opt(X)")),
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

pub(crate) fn links(items: List) -> Result<Option<Vec<osis_base::Link>>, Error> {
    let n = items.iter().filter(|i| i.as_link().is_some()).count();
    if n == 0 {
        return Ok(None);
    }
    if n != items.len() {
        return Err(Error::Malformed("links mixed with elements"));
    }
    Ok(Some(items.iter().filter_map(Item::as_link).collect()))
}

/// Pages of one paged position (plaintext, link) in the order the encoder puts them: leaf pages,
/// then link pages. Handed to `Dec::done` after the position's items are decoded, so the
/// fetched list follows the encoder's order (nested pages first) and the replay gives equal
/// plaintexts their links back in place.
pub(crate) type Fetched = Vec<(Vec<u8>, osis_base::Link)>;

/// Fetches a page, checked. Each blob is read once per delta, so expansion is bounded by the
/// distinct pages that exist.
pub(crate) fn fetch_page(cx: &mut Dec, link: &osis_base::Link) -> Result<CanonicalBytes, Error> {
    if !cx.links_seen.insert(link.blob) {
        return Err(Error::Malformed("a page linked twice"));
    }
    let src = cx.pages.as_mut().ok_or(Error::Page(PageError::Missing))?;
    let bytes = src.get(link)?;
    check_items(&bytes, src.params())?;
    Ok(CanonicalBytes::parse(bytes, &LIMITS)?)
}

/// A page's links when it is a link page.
fn page_links(page: &CanonicalBytes) -> Result<Option<Vec<osis_base::Link>>, Error> {
    page.item().as_list().map_or(Ok(None), links)
}

/// The leaf pages under a paged position `v` holding links `top`, in order, and its link pages
/// (§8, at most two levels).
fn leaf_pages(cx: &mut Dec, v: Item, top: &[osis_base::Link]) -> Result<(Vec<(CanonicalBytes, osis_base::Link)>, Fetched), Error> {
    let params = cx.pages.as_ref().map_or(PageParams::FORMAT, |p| p.params());
    if v.bytes().len() > params.target {
        return Err(Error::Malformed("link list above the page target"));
    }
    let (mut leaves, mut link_pages) = (Vec::new(), Vec::new());
    for l in top {
        let page = fetch_page(cx, l)?;
        let Some(inner) = page_links(&page)? else {
            leaves.push((page, *l));
            continue;
        };
        link_pages.push((page.into_bytes(), *l));
        if inner.len() > params.fanout {
            return Err(Error::Malformed("link page above the fan-out"));
        }
        for l in &inner {
            let page = fetch_page(cx, l)?;
            if page_links(&page)?.is_some() {
                return Err(Error::Malformed("a third page level"));
            }
            leaves.push((page, *l));
        }
    }
    Ok((leaves, link_pages))
}

/// A leaf page's items: a non-empty array.
pub(crate) fn leaf_items(page: Item) -> Result<List, Error> {
    page.as_list().filter(|l| !l.is_empty()).ok_or(Error::Malformed("page is not a non-empty array"))
}

/// The items of an element array through `each`, inline or a leaf page at a time, link pages
/// resolved (§8); then its pages to `Dec::done`.
pub(crate) fn elem_items(cx: &mut Dec, v: Item, each: &mut dyn FnMut(&mut Dec, List) -> Result<(), Error>) -> Result<(), Error> {
    let items = as_array(v)?;
    let Some(top) = links(items)? else { return each(cx, items) };
    let (leaves, link_pages) = leaf_pages(cx, v, &top)?;
    for (p, _) in &leaves {
        leaf_items(p.item())?;
    }
    for (p, _) in &leaves {
        each(cx, leaf_items(p.item())?)?;
    }
    cx.done(leaves, link_pages);
    Ok(())
}

impl Dec<'_> {
    /// Records a position's pages after its items are decoded (`Fetched`): its leaf pages, then
    /// its link pages.
    pub(crate) fn done(&mut self, leaves: Vec<(CanonicalBytes, osis_base::Link)>, link_pages: Fetched) {
        self.fetched.extend(leaves.into_iter().map(|(p, l)| (p.into_bytes(), l)).chain(link_pages));
    }

    /// Paged collections left for streaming so far (`defer`).
    fn deferred(&self) -> usize {
        self.streaming.as_ref().map_or(0, |(_, found)| found.len())
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
/// it), prune, nor a text flag write its own creation beats (§4.2): a delta is a state fragment,
/// prune-stable like any state. Checked on a copy, by the write copies it carries
/// (`Fragment::carried`), not by equality: what prune drops that is no write is judged by the
/// rules for it (a record carrying no write, `Slots` form). Returns the pruned form, which is what
/// the delta holds (`stream::Whole::done`).
pub(crate) fn prune_stable(f: &Fragment, e: Option<&Stamp>) -> Result<Fragment, Error> {
    let mut p = f.clone();
    p.prune(e, &mut crate::Changes::new());
    if p.carried() == f.carried() { Ok(p) } else { Err(Error::Malformed("carries a write its own pruning drops")) }
}

fn decode_meta(cx: &mut Dec, r: Item, w: Item) -> Result<Meta, Error> {
    let (w, w_valueless) = match as_array(w)?.tuple() {
        Some([s, f]) if f.as_bool() == Some(false) => (Some(cx.level_stamp(s)?), true),
        _ => (cx.opt_level_stamp(w)?, false),
    };
    Ok(Meta { reset: cx.opt_level_stamp(r)?, w, w_valueless })
}

fn decode_elems(cx: &mut Dec, v: Item) -> Result<BTreeMap<Dot, Elem>, Error> {
    let mut out = BTreeMap::new();
    elem_items(cx, v, &mut |cx, items| decode_elem_items(cx, items, &mut out))?;
    Ok(out)
}

/// Bag or set elements into `out`.
pub(crate) fn decode_elem_items(cx: &mut Dec, items: List, out: &mut BTreeMap<Dot, Elem>) -> Result<(), Error> {
    for e in items {
        let Some([d, r, f]) = as_array(e)?.tuple() else { return Err(Error::Malformed("element")) };
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
        if reset.is_none() && frag.as_deref().is_none_or(Fragment::is_empty) {
            return Err(Error::Malformed("record without a write"));
        }
        if frag.is_some() {
            cx.claim(&dot)?;
        }
        out.insert(dot, Elem { reset, frag });
    }
    Ok(())
}

/// A field or payload map, inline or paged (§8); fields ascend across pages (the re-encode
/// check then pins the cuts).
fn decode_children(cx: &mut Dec, v: Item, step: fn(u64) -> Step) -> Result<BTreeMap<u64, Fragment>, Error> {
    let mut out = BTreeMap::new();
    if v.as_map().is_some() {
        decode_fields(cx, v, false, step, &mut out)?;
        return Ok(out);
    }
    let items = v.as_list().ok_or(Error::Malformed("expected a map"))?;
    let top = links(items)?.ok_or(Error::Malformed("expected a map or links"))?;
    let (leaves, link_pages) = leaf_pages(cx, v, &top)?;
    for (page, _) in &leaves {
        decode_fields(cx, page.item(), true, step, &mut out)?;
    }
    cx.done(leaves, link_pages);
    Ok(out)
}

/// The fields of one field map or page of one (`paged`: not empty) into `out`, ascending.
pub(crate) fn decode_fields(cx: &mut Dec, page: Item, paged: bool, step: fn(u64) -> Step, out: &mut BTreeMap<u64, Fragment>) -> Result<(), Error> {
    let Some(mut m) = page.as_map() else { return Err(Error::Malformed("page is not a map")) };
    if paged && m.is_empty() {
        return Err(Error::Malformed("empty page"));
    }
    while let (Some(k), Some(f)) = (m.next(), m.next()) {
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
pub(crate) fn decode_entries(cx: &mut Dec, items: List, entries: &mut BTreeMap<Eid, Entry>) -> Result<(), Error> {
    for e in items {
        // `[Dot, Ci?, R, Key?, Opt(Fragment)]`: a `Ci` is an int, an `R` an array
        let mut rest = as_array(e)?;
        let d = rest.next().ok_or(Error::Malformed("entry"))?;
        let ci = if rest.first().is_some_and(Item::is_int) { rest.next() } else { None };
        let (r, key, f) = match (rest.tuple(), rest.tuple()) {
            (Some([r, f]), _) => (r, None, f),
            (_, Some([r, k, f])) => (r, Some(k), f),
            _ => return Err(Error::Malformed("entry")),
        };
        let key = key.map(Item::to_value).transpose()?;
        let id = Eid::new(cx.dot(d)?, key.clone());
        let dot = &id.dot;
        let reset = cx.opt_level_stamp(r)?;
        cx.step(|| Step::Entry(id.clone()));
        let paged = cx.deferred();
        let frag = opt_stamp_only(f, |x| cx.fragment(x));
        // content left to its pages carries writes (a page is non-empty, its records hold some)
        let paged = cx.deferred() > paged;
        cx.step_done();
        let frag = frag?.map(Box::new);
        if let Some(k) = &key {
            check_value(cx, k)?;
        }
        if frag.is_some() {
            cx.claim(dot)?;
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
        if reset.is_none() && created.is_none() && !paged && frag.as_deref().is_none_or(Fragment::is_empty) {
            return Err(Error::Malformed("record without a write"));
        }
        entries.insert(id, Entry { reset, frag, created });
    }
    Ok(())
}

/// While a root is decoded for streaming, a paged collection reached through steps is left
/// undecoded (true) and recorded with its link list (`stream`).
fn defer(cx: &mut Dec, v: Item, enc: Encoding) -> Result<bool, Error> {
    let depth = cx.depth;
    let Some((t, found)) = cx.streaming.as_mut().filter(|(t, _)| t.on) else { return Ok(false) };
    let Some(items) = v.as_list() else { return Ok(false) };
    if links(items)?.is_none() {
        return Ok(false);
    }
    let order = found.len();
    found.insert(t.path.clone(), crate::stream::Deferred { top: v.bytes().to_vec(), enc, depth, order });
    Ok(true)
}

fn decode_register(cx: &mut Dec, mut a: List, may_reset: bool) -> Result<Register, Error> {
    let (Some(_), Some(r)) = (a.next(), a.next()) else { return Err(Error::Malformed("register")) };
    let reset = cx.opt_level_stamp(r)?;
    if reset.is_some() && !may_reset {
        return Err(Error::Malformed("nested register with a reset"));
    }
    let write = match (a.is_empty(), a.tuple(), a.tuple()) {
        (true, _, _) => None,
        (_, Some([s]), _) => Some(RegWrite { stamp: cx.level_stamp(s)?, value: None }),
        (_, _, Some([s, v])) => {
            let v = v.to_value()?;
            check_value(cx, &v)?;
            Some(RegWrite { stamp: cx.level_stamp(s)?, value: Some(v) })
        }
        _ => return Err(Error::Malformed("register arity")),
    };
    Ok(Register { reset, write })
}

/// Decodes a fragment; `may_reset` where a register may carry a reset (root, a `Slots` slot).
pub(crate) fn decode_fragment(cx: &mut Dec, v: Item, may_reset: bool) -> Result<Fragment, Error> {
    // read depth counts across pages too (a page's fragments may hold paged arrays), so every
    // page level adds one; within a blob the CBOR depth bounds the recursion
    let up = head_depth(v.as_list().and_then(List::first).and_then(Item::as_uint).and_then(Encoding::from_id));
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

fn decode_fragment_at(cx: &mut Dec, v: Item, may_reset: bool) -> Result<Fragment, Error> {
    let a = as_array(v)?;
    let id = as_uint(a.first().ok_or(Error::Malformed("empty fragment"))?)?;
    let enc = Encoding::from_id(id).ok_or(Error::UnknownEncoding(id))?;
    const ARITY: Error = Error::Malformed("fragment arity");
    Ok(match enc {
        Encoding::Register => Fragment::Register(decode_register(cx, a, may_reset)?),
        Encoding::Counter | Encoding::Max | Encoding::Min => {
            let Some([_, r, w, e]) = a.tuple() else { return Err(ARITY) };
            let kind = enc.bag_kind().ok_or(Error::Malformed("bag"))?;
            let meta = decode_meta(cx, r, w)?;
            let elems = if defer(cx, e, enc)? { BTreeMap::new() } else { decode_elems(cx, e)? };
            Fragment::Bag(Bag { kind, meta, elems })
        }
        Encoding::Set => {
            let Some([_, r, w, e]) = a.tuple() else { return Err(ARITY) };
            let meta = decode_meta(cx, r, w)?;
            let elems = if defer(cx, e, enc)? { BTreeMap::new() } else { decode_elems(cx, e)? };
            Fragment::Set(Set { meta, elems })
        }
        Encoding::Struct => {
            let Some([_, r, w, c]) = a.tuple() else { return Err(ARITY) };
            let meta = decode_meta(cx, r, w)?;
            let fields = if defer(cx, c, enc)? { BTreeMap::new() } else { decode_children(cx, c, Step::Field)? };
            Fragment::Struct(Struct { meta, fields })
        }
        Encoding::Enum => {
            let Some([_, r, w, k, c]) = a.tuple() else { return Err(ARITY) };
            let meta = decode_meta(cx, r, w)?;
            let case = opt_stamp_only(k, |c| {
                let c = as_array(c)?;
                match (c.tuple(), c.tuple()) {
                    (Some([s]), _) => Ok(CaseWrite { stamp: cx.level_stamp(s)?, case: None }),
                    (_, Some([s, id])) => Ok(CaseWrite { stamp: cx.level_stamp(s)?, case: Some(as_uint(id)?) }),
                    _ => Err(Error::Malformed("case")),
                }
            })?;
            let payloads = if defer(cx, c, enc)? { BTreeMap::new() } else { decode_children(cx, c, Step::Case)? };
            Fragment::Enum(Enum { meta, case, payloads })
        }
        Encoding::Map => {
            let Some([_, r, w, es]) = a.tuple() else { return Err(ARITY) };
            let meta = decode_meta(cx, r, w)?;
            let mut entries = BTreeMap::new();
            if !defer(cx, es, enc)? {
                elem_items(cx, es, &mut |cx, items| decode_entries(cx, items, &mut entries))?;
            }
            Fragment::Map(Map::new(meta, entries))
        }
        Encoding::List | Encoding::Text => {
            let Some([_, r, w, es]) = a.tuple() else { return Err(ARITY) };
            let meta = decode_meta(cx, r, w)?;
            let mut s = Seq::new(enc == Encoding::Text, meta, BTreeMap::new());
            if !defer(cx, es, enc)? {
                elem_items(cx, es, &mut |cx, runs| seq::decode_elems(&mut s, runs, cx))?;
            }
            Fragment::Seq(s)
        }
        Encoding::Slots => {
            let Some([_, reg, ms]) = a.tuple() else { return Err(ARITY) };
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
    })
}

pub(crate) fn nonce(v: Item) -> Result<[u8; NONCE_LEN], Error> {
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
    let head = crate::stream::stream(bytes, cx, interner, pages, false, true, None, &mut |p| whole.add(p))?;
    Ok(Delta { nonce: head.nonce, fragment: whole.done() })
}

/// Decodes a snapshot delta (§8); bad input unless canonical. The whole fragment, as
/// `decode_delta`.
pub fn decode_snapshot<'a>(bytes: &[u8], cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Result<Snapshot, Error> {
    let mut whole = crate::stream::Whole::default();
    let head = crate::stream::stream(bytes, cx, interner, pages, true, true, None, &mut |p| whole.add(p))?;
    Ok(Snapshot { nonce: head.nonce, fragment: whole.done(), frontiers: head.frontiers, absorbed: head.absorbed, facts: head.facts })
}

/// `[nonce, Sources, Commits]` of a delta or snapshot root into `dec`.
pub(crate) fn root_tables(dec: &mut Dec, sources: Item, commits: Item) -> Result<(), Error> {
    dec.load_sources(sources)?;
    dec.load_commits(commits)
}

/// A snapshot's `Frontiers` and `Absorbed` (§8): one frontier entry per `Session` source of the
/// table, in table order, 0 included (a source with no write in the fragment has none, so an
/// absent source is one the snapshot holds nothing of).
pub(crate) fn snapshot_tail(dec: &Dec, fr: Item, ab: Item, fa: Item) -> Result<(Frontiers, BTreeMap<osis_base::CommitId, osis_base::Tid>, crate::wire::Facts), Error> {
    let mut frontiers = Frontiers::default();
    let mut counted = dec.sources().filter(|s| matches!(s.kind(), SourceKind::Session(_)));
    for e in as_array(fr)? {
        let Some([i, c]) = as_array(e)?.tuple() else { return Err(Error::Malformed("frontier")) };
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
        let Some([c, a]) = as_array(e)?.tuple() else { return Err(Error::Malformed("absorbed commit")) };
        let (Some(c), Some(a)) = (c.as_bytes(), a.as_tid()) else { return Err(Error::Malformed("absorbed commit")) };
        let c = <[u8; 32]>::try_from(c).map_err(|_| Error::Malformed("absorbed commit ID"))?;
        if absorbed.insert(osis_base::CommitId(c), a).is_some() {
            return Err(Error::Malformed("absorbed commit repeated"));
        }
    }
    let facts = dec.load_facts(fa, &absorbed)?;
    Ok((frontiers, absorbed, facts))
}

/// The absorbed table as written (§8).
pub(crate) fn put_absorbed(out: &mut Vec<u8>, absorbed: &BTreeMap<osis_base::CommitId, osis_base::Tid>) {
    put_array(out, absorbed.len());
    for (c, a) in absorbed {
        put_array(out, 2);
        put_bytes(out, &c.0);
        put_tid(out, a);
    }
}

/// The whole-delta decoder and encoder before streaming. The decoder decodes every page into one
/// fragment, then re-encodes all of it (two passes) and requires the input bytes: the test
/// oracle of `stream` (it must accept and reject exactly the same inputs). The encoder holds
/// every element of an array before cutting it into pages, and its collecting pass builds the
/// whole value tree: the test oracle of `Pager` (byte-identical output).
#[cfg(any(test, fuzzing))]
pub mod oracle {
    use super::*;

    /// Writes the array of elements `elems` (their canonical bytes), paged when the plain form is
    /// above the target (spec/wire.md §6).
    pub(crate) fn paged(mut pages: Option<&mut dyn PageSink>, map: bool, elems: &[&[u8]], out: &mut Vec<u8>) -> Result<(), Error> {
        let params = pages.as_ref().map_or(PageParams::FORMAT, |p| p.params());
        let plain = |out: &mut Vec<u8>, es: &[&[u8]]| {
            put_head(out, map, es.len());
            es.iter().for_each(|e| out.extend_from_slice(e));
        };
        // array and map heads have the same length
        let size = elems.iter().fold(head_len(elems.len() as u64), |n, e| n.saturating_add(e.len()));
        if size <= params.target {
            plain(out, elems);
            return Ok(());
        }
        let sink = pages.as_mut().ok_or(Error::Mismatch("a paged array needs a page sink"))?;
        let mut cutter = PageCutter::new(params.cut);
        let mut links = Vec::new();
        let mut from = 0;
        for (i, e) in elems.iter().enumerate() {
            cutter.feed(e);
            if cutter.end_element() || i + 1 == elems.len() {
                let mut page = Vec::new();
                plain(&mut page, elems.get(from..=i).unwrap_or_default());
                links.push(sink.put(&page)?);
                from = i + 1;
            }
        }
        link_list(Some(&mut **sink), &links, params, out)
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

    /// The whole encoder (`Pager::done_whole`).
    fn whole<'p>(cx: &DeltaCtx, pages: Option<&'p mut dyn PageSink>) -> Enc<'p> {
        let mut enc = Enc::new(cx, pages);
        enc.whole = true;
        enc
    }

    pub fn encode_delta(d: &Delta, cx: &DeltaCtx, pages: Option<&mut dyn PageSink>) -> Result<Vec<u8>, Error> {
        write_delta(whole(cx, pages), d)
    }

    pub fn encode_snapshot(s: &Snapshot, cx: &DeltaCtx, pages: Option<&mut dyn PageSink>) -> Result<Vec<u8>, Error> {
        write_snapshot(whole(cx, pages), s)
    }

    fn replay(dec: &mut Dec) -> crate::wire::Replay {
        let mut r = crate::wire::Replay::new(dec.pages.as_ref().map_or(PageParams::FORMAT, |p| p.params()));
        r.extend(std::mem::take(&mut dec.fetched));
        r
    }

    pub fn decode_delta<'a>(bytes: &[u8], cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Result<Delta, Error> {
        check_root(bytes, pages.as_deref())?;
        let top = Item::parse(bytes, &LIMITS)?;
        let Some([n, sources, commits, frag]) = as_array(top)?.tuple() else { return Err(Error::Malformed("delta arity")) };
        let mut dec = Dec::new(cx, interner, pages);
        root_tables(&mut dec, sources, commits)?;
        let fragment = decode_fragment(&mut dec, frag, true)?;
        let mut replay = replay(&mut dec);
        let d = Delta { nonce: nonce(n)?, fragment };
        canonical(bytes, self::encode_delta(&d, cx, Some(&mut replay)))?;
        Ok(Delta { fragment: prune_stable(&d.fragment, None)?, ..d })
    }

    pub fn decode_snapshot<'a>(bytes: &[u8], cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Result<Snapshot, Error> {
        check_root(bytes, pages.as_deref())?;
        let top = Item::parse(bytes, &LIMITS)?;
        let Some([n, sources, commits, frag, fr, ab, fa]) = as_array(top)?.tuple() else { return Err(Error::Malformed("snapshot arity")) };
        let mut dec = Dec::new(cx, interner, pages);
        root_tables(&mut dec, sources, commits)?;
        let fragment = decode_fragment(&mut dec, frag, true)?;
        let (frontiers, absorbed, facts) = snapshot_tail(&dec, fr, ab, fa)?;
        let mut replay = replay(&mut dec);
        let s = Snapshot { nonce: nonce(n)?, fragment, frontiers, absorbed, facts };
        canonical(bytes, self::encode_snapshot(&s, cx, Some(&mut replay)))?;
        Ok(Snapshot { fragment: prune_stable(&s.fragment, None)?, ..s })
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

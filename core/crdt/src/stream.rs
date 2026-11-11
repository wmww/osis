//! Durable deltas decoded page by page (spec/crdt.md §3.3, §8; issues/durable-decode-bound.md).
//!
//! The root decodes into a skeleton: every paged collection reached from the root through
//! `Step`s (struct fields, enum payloads, map entries) is left empty and streamed afterwards, one
//! leaf page at a time; a page's own nested paged positions decode whole inside it. The
//! canonical check is still "re-encode equals input" (rules 1-5): the skeleton re-encodes against
//! the root bytes with the input's own tables, each streamed position re-encodes element by
//! element (one open sequence run carried across pages) and is cut into pages compared with the
//! input's leaf pages in order, and the tables are checked at the end against what a collecting
//! pass would have built (first appearances in table order, each commit's base its smallest
//! counter). Memory: the skeleton, one decoded page, its encoding, and trackers sized by the
//! input (the tables, the leaf links, a writer's claimed counters).
//!
//! Bytes this node checked once are read again decode-only (`Checked`, `stream_checked`):
//! the same walk and limits without any re-encode, prune or table check, positions in the order
//! the root decode met them, which for canonical bytes is the order the check's root re-encode
//! meets them.

use crate::codec::{Pager, absorbed_value, canonical, check_root, decode_entries, decode_elem_items, decode_fields, decode_fragment, derived_ok, encode_elem, encode_entry, encode_field, encode_fragment, fetch_page, links, nonce, prune_stable, root_tables, snapshot_tail, LIMITS};
use crate::error::Error;
use crate::fragment::{Bag, Eid, Encoding, Entry, Enum, Fragment, Map, Meta, Set, Struct};
use crate::page::{PageParams, PageSource};
use crate::paging::Step;
use crate::seq::Seq;
use crate::seq_wire::Runs;
use crate::stamp::{Dot, Interner, Stamp, max_opt};
use crate::wire::{Dec, DeltaCtx, DeltaKind, Enc, Ev, Frontiers, NONCE_LEN, Track, as_array};
use osis_base::{CommitId, Tid, Value};
use std::collections::BTreeMap;

/// A paged collection of the root left for streaming: its link list as written, its encoding,
/// its fragment nesting.
pub(crate) struct Deferred {
    pub(crate) top: Value,
    pub(crate) enc: Encoding,
    pub(crate) depth: usize,
    /// Where the root decode met it among the root's paged positions: wire order.
    pub(crate) order: usize,
}

/// Delta bytes that passed the full check on this node (`stream_delta`, `stream_snapshot`,
/// `decode_delta`, `decode_snapshot`) against the same context and pages: the only input of the
/// decode-only readers (`stream_checked`, `decode_checked`). Never bytes from a peer not yet
/// checked.
#[derive(Clone, Copy)]
pub struct Checked<'a>(&'a [u8]);

impl<'a> Checked<'a> {
    /// `bytes`, which passed the full check: just now, or before the node stored them (its store
    /// keeps only checked deltas and returns what it was given).
    pub fn verified(bytes: &'a [u8]) -> Checked<'a> {
        Checked(bytes)
    }
}

/// What `stream_delta` and `stream_snapshot` hand over, in wire order. Joining every piece into
/// a state equals joining the whole fragment (§8: elements are independent per dot, fields per
/// field).
#[derive(Debug, PartialEq)]
pub enum Piece {
    /// The root fragment with every streamed collection empty (its own reset and `W` kept);
    /// first.
    Skeleton(Fragment),
    /// One leaf page's elements of the collection at `path`, as a fragment from the root
    /// holding nothing else (`Fragment::wrap`; entry steps carry their creations).
    Page { path: Vec<Step>, fragment: Fragment },
}

/// A snapshot root's tables besides its fragment.
#[derive(Debug, Default)]
pub struct Head {
    pub nonce: [u8; NONCE_LEN],
    pub frontiers: Frontiers,
    pub absorbed: BTreeMap<CommitId, Tid>,
}

/// A path's steps with their entry keys and creations (`Fragment::wrap`).
type WrapPath = Vec<(Step, Option<Value>, Option<Stamp>)>;

/// A piece before wrapping: the entry steps' keys and creations come from the skeleton.
pub(crate) enum Raw<'w> {
    Skeleton(Fragment),
    Page(&'w WrapPath, Fragment),
}

impl Raw<'_> {
    fn wrapped(self) -> Piece {
        match self {
            Raw::Skeleton(f) => Piece::Skeleton(f),
            Raw::Page(w, f) => Piece::Page { path: w.iter().map(|x| x.0.clone()).collect(), fragment: Fragment::wrap(w, f) },
        }
    }
}

/// Checks a delta (§3.2) and hands `each` its pieces, one page at a time; bad input unless
/// canonical. Pieces already handed over stay valid only if the whole call succeeds: check
/// first with a callback that keeps nothing, then stream again to use them.
pub fn stream_delta<'a>(bytes: &[u8], cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>, each: &mut dyn FnMut(Piece) -> Result<(), Error>) -> Result<[u8; NONCE_LEN], Error> {
    stream(bytes, cx, interner, pages, false, true, &mut |r| each(r.wrapped())).map(|h| h.nonce)
}

/// `stream_delta` for a snapshot delta (§8).
pub fn stream_snapshot<'a>(bytes: &[u8], cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>, each: &mut dyn FnMut(Piece) -> Result<(), Error>) -> Result<Head, Error> {
    stream(bytes, cx, interner, pages, true, true, &mut |r| each(r.wrapped()))
}

/// `stream_delta` or `stream_snapshot` (by `cx.kind`) of checked bytes, decode-only: the same
/// pieces in the same order (`tests_stream`). A snapshot's tables; a delta's nonce alone.
pub fn stream_checked<'a>(bytes: Checked<'_>, cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>, each: &mut dyn FnMut(Piece) -> Result<(), Error>) -> Result<Head, Error> {
    stream(bytes.0, cx, interner, pages, cx.kind == DeltaKind::Snapshot, false, &mut |r| each(r.wrapped()))
}

/// `decode_delta` or `decode_snapshot` (by `cx.kind`) of checked bytes, decode-only: the whole
/// fragment and the root's tables.
pub fn decode_checked<'a>(bytes: Checked<'_>, cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Result<(Head, Fragment), Error> {
    let mut whole = Whole::default();
    let head = stream(bytes.0, cx, interner, pages, cx.kind == DeltaKind::Snapshot, false, &mut |p| whole.add(p))?;
    Ok((head, whole.done()))
}

const NOT_CANONICAL: Error = Error::Malformed("not canonical");

/// Decodes the delta at `bytes` and hands `each` its pieces in wire order; `check`: bad input
/// unless canonical (rules 1-5 by re-encoding), else decode-only (`Checked` bytes). The grammar,
/// ranges and structural limits (items per page or root, links, fan-out, levels) hold either way,
/// so a decode-only read of bytes that changed fails, bounded, rather than trusting them.
pub(crate) fn stream<'a>(bytes: &[u8], cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>, snapshot: bool, check: bool, each: &mut dyn FnMut(Raw) -> Result<(), Error>) -> Result<Head, Error> {
    check_root(bytes, pages.as_deref())?;
    let top = osis_base::decode(bytes, &LIMITS)?;
    let (n, sources, commits, frag, tail) = match (snapshot, as_array(&top)?) {
        (false, [n, s, c, f]) => (n, s, c, f, None),
        (true, [n, s, c, f, fr, ab]) => (n, s, c, f, Some((fr, ab))),
        (false, _) => return Err(Error::Malformed("delta arity")),
        (true, _) => return Err(Error::Malformed("snapshot arity")),
    };
    let mut dec = Dec::new(cx, interner, pages);
    root_tables(&mut dec, sources, commits)?;
    dec.streaming = Some((Track::new(), BTreeMap::new()));
    let skeleton = decode_fragment(&mut dec, frag, true);
    let mut found = dec.streaming.take().map(|x| x.1).unwrap_or_default();
    let skeleton = skeleton?;
    let (frontiers, absorbed) = match tail {
        Some((fr, ab)) => snapshot_tail(&dec, fr, ab)?,
        None => Default::default(),
    };
    let nonce = nonce(n)?;
    let wraps: BTreeMap<Vec<Step>, (WrapPath, Option<Stamp>)> = found.keys().map(|p| (p.clone(), (wrap_path(&skeleton, p), reset_at(&skeleton, p)))).collect();

    if !check {
        dec.fetched.clear();
        let mut order: Vec<(Vec<Step>, Deferred)> = found.into_iter().collect();
        order.sort_by_key(|(_, d)| d.order);
        each(Raw::Skeleton(skeleton))?;
        for (path, d) in order {
            let (w, e) = wraps.get(&path).ok_or(NOT_CANONICAL)?;
            position(&mut dec, None, &d, w, e.as_ref(), each)?;
        }
        return Ok(Head { nonce, frontiers, absorbed });
    }

    // the root with the input's tables, streamed positions as written
    let mut enc = dec.checker(cx, found.iter().map(|(p, d)| (p.clone(), d.top.clone())).collect());
    let again = encode_fragment(&mut enc, &skeleton).map(|f| {
        let mut root = vec![Value::Bytes(nonce.to_vec()), enc.sources_value(), enc.commits_value(), f];
        if snapshot {
            root.extend([enc.frontiers_value(&frontiers), absorbed_value(&absorbed)]);
        }
        osis_base::encode(&Value::List(root))
    });
    canonical(bytes, again)?;
    let log = enc.check.as_mut().and_then(|c| c.log.take()).unwrap_or_default();
    // canonical bytes meet their positions in one order, decoding or encoding (`Checked`)
    debug_assert!(log.iter().filter_map(|ev| if let Ev::Stream(p) = ev { found.get(p).map(|d| d.order) } else { None }).is_sorted());

    prune_stable(&skeleton, None)?;
    each(Raw::Skeleton(skeleton))?;
    // the streamed positions where the root encoding met them, between its appearances
    for ev in log {
        match ev {
            Ev::Src(i) => {
                if let Some(c) = enc.check.as_mut() {
                    c.seen(i);
                }
            }
            Ev::Stream(path) => {
                let (Some(d), Some((w, e))) = (found.remove(&path), wraps.get(&path)) else { return Err(NOT_CANONICAL) };
                position(&mut dec, Some(&mut enc), &d, w, e.as_ref(), each)?;
            }
        }
    }
    if !found.is_empty() || !enc.check_tables() {
        return Err(NOT_CANONICAL);
    }
    Ok(Head { nonce, frontiers, absorbed })
}

/// Entry steps with their keys and the skeleton's creations (`Fragment::wrap`).
fn wrap_path(root: &Fragment, path: &[Step]) -> WrapPath {
    let mut at = Some(root);
    let mut out = Vec::with_capacity(path.len());
    for s in path {
        let (key, created) = match s {
            Step::Entry(id) => (id.key().cloned(), at.and_then(|f| f.entry_created(id)).cloned()),
            _ => (None, None),
        };
        out.push((s.clone(), key, created));
        at = at.and_then(|f| f.step(s));
    }
    out
}

/// The effective reset (§4.2) over the elements of the collection at `path`: the greatest reset
/// on the way down, with a map entry's the cross resets of its dot's records (§5.6).
fn reset_at(root: &Fragment, path: &[Step]) -> Option<Stamp> {
    let mut e = root.reset();
    let mut at = Some(root);
    for s in path {
        let Some(f) = at else { break };
        if let (Step::Entry(id), Fragment::Map(m)) = (s, f) {
            for (rid, en) in m.of_dot(&id.dot) {
                if id.key.is_none() || rid.key.is_none() || rid == id {
                    e = max_opt(e, en.reset.clone());
                }
            }
        }
        at = f.step(s);
        e = max_opt(e, at.and_then(Fragment::reset));
    }
    e
}

/// `prune_stable` of one leaf page under `e`, an element (a map dot's records, a field) at a
/// time, so the check copies one element, not the page. A map dot's records may straddle pages
/// and prune each other (§5.6): `carry` holds the previous page's last dot's records, checked
/// along with this page's first dot.
fn prune_page(f: &Fragment, e: Option<&Stamp>, carry: &mut Vec<(Eid, Entry)>) -> Result<(), Error> {
    let one = |f: Fragment| prune_stable(&f, e).map(drop);
    match f {
        Fragment::Map(m) => {
            let mut group: Vec<(Eid, Entry)> = std::mem::take(carry);
            for (id, en) in &m.entries {
                if group.first().is_some_and(|(g, _)| g.dot != id.dot) {
                    one(Fragment::Map(Map::new(Meta::default(), group.drain(..).collect())))?;
                }
                group.push((id.clone(), en.clone()));
            }
            one(Fragment::Map(Map::new(Meta::default(), group.iter().cloned().collect())))?;
            *carry = group;
            Ok(())
        }
        Fragment::Bag(b) => b.elems.iter().try_for_each(|(d, x)| one(Fragment::Bag(Bag { kind: b.kind, meta: Meta::default(), elems: BTreeMap::from([(d.clone(), x.clone())]) }))),
        Fragment::Set(x) => x.elems.iter().try_for_each(|(d, el)| one(Fragment::Set(Set { meta: Meta::default(), elems: BTreeMap::from([(d.clone(), el.clone())]) }))),
        Fragment::Seq(q) => q.elems().iter().try_for_each(|(d, el)| one(Fragment::Seq(Seq::new(q.text, Meta::default(), BTreeMap::from([(d.clone(), el.clone())]))))),
        Fragment::Struct(Struct { fields, .. }) | Fragment::Enum(Enum { payloads: fields, .. }) => fields.values().try_for_each(|x| prune_stable(x, e).map(drop)),
        Fragment::Register(_) | Fragment::Slots(_) => prune_stable(f, e).map(drop),
    }
}

/// Streams one paged position: every leaf page decoded and handed over. Checking (`enc`), each
/// is re-encoded too; the re-encoding, its pages put to the check's `Replay` (which holds the
/// input's pages: a page the encoder cuts differently is not there), must give the position's
/// link list as written (spec/wire.md §6: paged, leaf order, link pages).
fn position(dec: &mut Dec, mut enc: Option<&mut Enc>, d: &Deferred, wrap: &WrapPath, e: Option<&Stamp>, each: &mut dyn FnMut(Raw) -> Result<(), Error>) -> Result<(), Error> {
    let params = dec.pages.as_ref().map_or(PageParams::FORMAT, |p| p.params());
    if osis_base::encode(&d.top).len() > params.target {
        return Err(Error::Malformed("link list above the page target"));
    }
    let top = links(as_array(&d.top)?)?.unwrap_or_default();
    let mut out = Out::new(d.enc, params);
    let mut carry = Vec::new();
    let mut leaf = |dec: &mut Dec, enc: Option<&mut Enc>, page: Value, bytes: Vec<u8>, l: osis_base::Link| -> Result<(), Error> {
        let before = std::mem::take(&mut dec.fetched);
        dec.depth = d.depth;
        let inner = decode_page(dec, &page, d.enc);
        dec.depth = 0;
        let inner = inner?;
        let nested = std::mem::take(&mut dec.fetched);
        if let Some(enc) = enc {
            if let Some(c) = enc.check.as_mut() {
                c.replay.extend(vec![(bytes, l)]);
                c.replay.extend(before);
                c.replay.extend(nested);
            }
            out.push(enc, &inner)?;
            prune_page(&inner, e, &mut carry)?;
        }
        each(Raw::Page(wrap, inner))
    };
    for l in &top {
        let (page, bytes) = fetch_page(dec, l)?;
        let inner = match &page {
            Value::List(items) => links(items)?,
            _ => None,
        };
        let Some(inner) = inner else {
            leaf(dec, enc.as_deref_mut(), page, bytes, *l)?;
            continue;
        };
        if inner.len() > params.fanout {
            return Err(Error::Malformed("link page above the fan-out"));
        }
        if let Some(c) = enc.as_mut().and_then(|enc| enc.check.as_mut()) {
            c.replay.extend(vec![(bytes, *l)]);
        }
        for l in &inner {
            let (page, bytes) = fetch_page(dec, l)?;
            if let Value::List(items) = &page
                && links(items)?.is_some()
            {
                return Err(Error::Malformed("a third page level"));
            }
            leaf(dec, enc.as_deref_mut(), page, bytes, *l)?;
        }
    }
    if let Some(enc) = enc
        && out.finish(enc)? != d.top
    {
        return Err(NOT_CANONICAL);
    }
    Ok(())
}

/// One leaf page of a collection of encoding `e`, as that collection holding only its elements
/// (no reset, no `W`).
fn decode_page(dec: &mut Dec, page: &Value, e: Encoding) -> Result<Fragment, Error> {
    let items = || match page {
        Value::List(items) if !items.is_empty() => Ok(items.as_slice()),
        _ => Err(Error::Malformed("page is not a non-empty array")),
    };
    let meta = Meta::default();
    let f = match e {
        Encoding::Counter | Encoding::Max | Encoding::Min => {
            let kind = e.bag_kind().ok_or(Error::Malformed("bag"))?;
            Fragment::Bag(Bag { kind, meta, elems: decode_elem_items(dec, items()?)? })
        }
        Encoding::Set => Fragment::Set(Set { meta, elems: decode_elem_items(dec, items()?)? }),
        Encoding::Map => Fragment::Map(Map::new(meta, decode_entries(dec, items()?)?)),
        Encoding::List | Encoding::Text => {
            let mut s = Seq::new(e == Encoding::Text, meta, BTreeMap::new());
            crate::seq::decode_elems(&mut s, items()?, dec)?;
            Fragment::Seq(s)
        }
        Encoding::Struct | Encoding::Enum => {
            let mut fields = BTreeMap::new();
            let step = if e == Encoding::Struct { Step::Field } else { Step::Case };
            decode_fields(dec, page, true, step, &mut fields)?;
            if e == Encoding::Struct { Fragment::Struct(Struct { meta, fields }) } else { Fragment::Enum(Enum { meta, case: None, payloads: fields }) }
        }
        Encoding::Register | Encoding::Slots => return Err(Error::Malformed("not a collection")),
    };
    if !derived_ok(&f) {
        return Err(Error::Malformed("write with a Derived stamp"));
    }
    Ok(f)
}

/// The last element of a streamed position so far, in wire order (rule 2).
enum Last {
    Dot(Dot),
    Entry(Eid),
    Field(u64),
}

/// Re-encodes a streamed position element by element (`Pager`), sequence runs carried across
/// pages, checking that elements ascend across pages.
struct Out {
    map: bool,
    pager: Pager,
    last: Option<Last>,
    runs: Option<Runs>,
}

impl Out {
    fn new(e: Encoding, params: PageParams) -> Out {
        let runs = matches!(e, Encoding::List | Encoding::Text).then(|| Runs::new(e == Encoding::Text));
        let map = matches!(e, Encoding::Struct | Encoding::Enum);
        Out { map, pager: Pager::new(map, params), last: None, runs }
    }

    /// Elements must ascend across pages (within one, the re-encode sorts them): `next`, the
    /// page's first, comes after the last page's last.
    fn seam(&self, enc: &Enc, next: Last) -> Result<(), Error> {
        use std::cmp::Ordering::Less;
        let ok = match (&self.last, &next) {
            (None, _) => true,
            (Some(Last::Dot(a)), Last::Dot(b)) => enc.dot_order(a, b) == Less,
            (Some(Last::Entry(a)), Last::Entry(b)) => enc.dot_order(&a.dot, &b.dot).then_with(|| a.cmp(b)) == Less,
            (Some(Last::Field(a)), Last::Field(b)) => a < b,
            _ => false,
        };
        if ok {
            Ok(())
        } else if self.map {
            Err(Error::Malformed("fields out of order across pages"))
        } else {
            Err(NOT_CANONICAL)
        }
    }

    fn push(&mut self, enc: &mut Enc, f: &Fragment) -> Result<(), Error> {
        let last = match f {
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => {
                let elems = enc.sorted(elems);
                if let Some((d, _)) = elems.first() {
                    self.seam(enc, Last::Dot((*d).clone()))?;
                }
                for (d, e) in &elems {
                    let v = encode_elem(enc, d, e)?;
                    self.emit(enc, v)?;
                }
                elems.last().map(|(d, _)| Last::Dot((*d).clone()))
            }
            Fragment::Map(m) => {
                let entries = enc.sorted_by(&m.entries, |id| &id.dot);
                if let Some((id, _)) = entries.first() {
                    self.seam(enc, Last::Entry((*id).clone()))?;
                }
                for (id, e) in &entries {
                    let v = encode_entry(enc, id, e)?;
                    self.emit(enc, v)?;
                }
                entries.last().map(|(id, _)| Last::Entry((*id).clone()))
            }
            Fragment::Struct(Struct { fields, .. }) | Fragment::Enum(Enum { payloads: fields, .. }) => {
                if let Some(k) = fields.keys().next() {
                    self.seam(enc, Last::Field(*k))?;
                }
                for (k, x) in fields {
                    let (k, v) = encode_field(enc, *k, x, Step::Field)?;
                    self.pager.push_field(enc.sink(), k, v).map_err(cut)?;
                }
                fields.keys().next_back().map(|k| Last::Field(*k))
            }
            Fragment::Seq(s) => {
                let mut runs = self.runs.take().ok_or(NOT_CANONICAL)?;
                let recs = enc.sorted(s.elems());
                if let Some((k, _)) = recs.first() {
                    self.seam(enc, Last::Dot((*k).clone()))?;
                }
                let mut out = Vec::new();
                for (k, e) in &recs {
                    runs.push(k, e, enc, &mut out)?;
                    for v in out.drain(..) {
                        self.emit(enc, v)?;
                    }
                }
                self.runs = Some(runs);
                // a range record's last element
                recs.last().map(|(d, e)| Last::Dot(crate::seq_span::nth(d, e.span - 1)))
            }
            Fragment::Register(_) | Fragment::Slots(_) => return Err(NOT_CANONICAL),
        };
        if last.is_some() {
            self.last = last;
        }
        Ok(())
    }

    fn emit(&mut self, enc: &mut Enc, v: Value) -> Result<(), Error> {
        self.pager.push(enc.sink(), v).map_err(cut)
    }

    /// The position as the encoder writes it.
    fn finish(mut self, enc: &mut Enc) -> Result<Value, Error> {
        if let Some(mut runs) = self.runs.take() {
            let mut out = Vec::new();
            runs.close(enc, &mut out)?;
            for v in out {
                self.emit(enc, v)?;
            }
        }
        self.pager.finish(enc.sink()).map_err(cut)
    }
}

/// A page the re-encode cuts that the input does not have (`Replay` has no such page).
fn cut(e: Error) -> Error {
    match e {
        Error::Page(_) => NOT_CANONICAL,
        e => e,
    }
}

/// `decode_delta`'s fragment: the skeleton with every page's elements put back in place, pruned.
#[derive(Default)]
pub(crate) struct Whole(Option<Fragment>);

impl Whole {
    pub(crate) fn add(&mut self, p: Raw) -> Result<(), Error> {
        match p {
            Raw::Skeleton(f) => self.0 = Some(f),
            Raw::Page(w, piece) => {
                let path: Vec<Step> = w.iter().map(|x| x.0.clone()).collect();
                let at = self.0.as_mut().and_then(|r| r.at_steps_mut(&path)).ok_or(NOT_CANONICAL)?;
                match (at, piece) {
                    (Fragment::Bag(a), Fragment::Bag(b)) => a.elems.extend(b.elems),
                    (Fragment::Set(a), Fragment::Set(b)) => a.elems.extend(b.elems),
                    (Fragment::Map(a), Fragment::Map(b)) => {
                        for (id, e) in b.entries {
                            a.index_id(&id);
                            a.entries.insert(id, e);
                        }
                    }
                    (Fragment::Seq(a), Fragment::Seq(b)) => a.elems_mut().extend(b.into_elems()),
                    (Fragment::Struct(a), Fragment::Struct(b)) => a.fields.extend(b.fields),
                    (Fragment::Enum(a), Fragment::Enum(b)) => a.payloads.extend(b.payloads),
                    _ => return Err(NOT_CANONICAL),
                }
            }
        }
        Ok(())
    }

    /// The pruned form, which is what the delta holds (a delta is prune-stable, §3.3 rule 5): a
    /// creation's implied position write leaves `pos` where its map dot's other records' position
    /// writes push it out (§5.6, §5.7).
    pub(crate) fn done(self) -> Fragment {
        let mut f = self.0.unwrap_or_default();
        f.prune(None, &mut crate::Changes::new());
        f
    }
}

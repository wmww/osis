//! Large atomic values (spec/data-model.md §6): before an op's value is resolved, every
//! position that must be chunked (blobs, register strings, set elements and map keys above
//! `CHUNK_THRESHOLD`, in `set`/`replace`/`add` values and list `insert` and `edit` items) becomes a link to
//! a chunk tree written as blob ciphertexts in the store, framed like the delta's pages. A
//! position holding a large value now reuses that tree (spec/sync.md §1): unchanged chunks keep
//! their blob and key and are not introduced again, so an edit writes and uploads O(change).
//! Links compare by content hash, so an unchanged large value diffs as equal. Reads return the
//! link; `Engine::read_large` materializes it.

use super::blobs::TxBlobs;
use super::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, BlobId, ChunkParams, CommitId, Link, Role, Tid, Value};
use osis_crdt::{Fragment, Op, PathOp, PathSeg};
use osis_crypto::Secret32;
use osis_label::{BlobFetch, BlobReader, BlobWriter, Framing, HashSink, LargeParams, Reuse};
use osis_schema::{Large, Path, Schema, Step, Type, large_positions, type_at};
use osis_schema::core_types::is_membership_class;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

/// Upper bound on a large value read back whole (local policy; streams read beyond it).
pub const MAX_READ: usize = 1 << 30;

/// Largest current value a write indexes for reuse (local policy: one link of memory per chunk);
/// past it the rest of the new value is written afresh.
pub const MAX_REUSE: u64 = 16 << 30;

fn at<'v>(v: &'v mut Value, steps: &[Step]) -> Option<&'v mut Value> {
    let Some((s, rest)) = steps.split_first() else { return Some(v) };
    let next = match (s, v) {
        (Step::Field(id), Value::Map(m)) => m.get_mut(&Value::Int(i64::try_from(*id).ok()?)),
        (Step::Key(k), Value::Map(m)) => m.get_mut(k),
        (Step::Case(c), Value::Enum(x, Some(p))) => (*x == *c).then_some(p.as_mut()),
        (Step::Index(i), Value::List(l)) => l.get_mut(*i),
        _ => None,
    }?;
    at(next, rest)
}

/// Writes one value's chunk tree, reusing the tree its position holds now (if any); returns
/// what takes its place (itself when small, else its root link).
pub(crate) type Put<'a> = dyn FnMut(&Value, Option<&Link>) -> Result<Value> + 'a;

/// Replaces one position by its chunked form.
fn chunk_one(v: &mut Value, l: &Large, base: Option<&Link>, put: &mut Put<'_>) -> Result<()> {
    let steps = &l.path.0;
    let Some((last, parent)) = steps.split_last() else {
        let old = std::mem::replace(v, Value::Bool(false));
        *v = put(&old, base)?;
        return Ok(());
    };
    let p = at(v, parent).ok_or(Error::Misuse("large position"))?;
    match (last, p) {
        (Step::Elem(e), Value::Set(s)) => {
            if s.remove(e) {
                s.insert(put(e, None)?);
            }
        }
        (Step::Key(k), Value::Map(m)) if l.map_key => {
            if let Some(x) = m.remove(k) {
                m.insert(put(k, None)?, x);
            }
        }
        (s, p) => {
            let x = at(p, std::slice::from_ref(s)).ok_or(Error::Misuse("large position"))?;
            let old = std::mem::replace(x, Value::Bool(false));
            *x = put(&old, base)?;
        }
    }
    Ok(())
}

/// `l`'s path as op path segments; `None` for a set element or a map key.
fn segs(l: &Large) -> Option<Vec<PathSeg>> {
    if l.map_key {
        return None;
    }
    l.path.0.iter().map(|s| match s {
        Step::Field(i) => Some(PathSeg::Field(*i)),
        Step::Key(k) => Some(PathSeg::Key(k.clone())),
        Step::Case(c) => Some(PathSeg::Case(*c)),
        Step::Index(i) => Some(PathSeg::Index(*i)),
        Step::Elem(_) => None,
    }).collect()
}

/// The root link the state holds at `prefix` + `l`'s path now.
fn base_at(state: &Fragment, prefix: &[PathSeg], l: &Large) -> Option<Link> {
    let path = [prefix.to_vec(), segs(l)?].concat();
    match state.at(&path).filter(Fragment::present)?.read()? {
        Value::Link(k) => Some(k),
        _ => None,
    }
}

/// `base`: the op's path and the aspect's state, when `v` replaces what the state holds there.
fn chunk_value(v: &mut Value, schema: &Schema, ty: &Type, base: Option<(&[PathSeg], &Fragment)>, put: &mut Put<'_>) -> Result<()> {
    let mut ls = large_positions(schema, v, ty);
    ls.sort_by_key(|l| std::cmp::Reverse(l.path.0.len()));
    for l in &ls {
        let b = base.and_then(|(p, f)| base_at(f, p, l));
        chunk_one(v, l, b.as_ref(), put)?;
    }
    Ok(())
}

fn schema_path(p: &[PathSeg]) -> Path {
    Path(
        p.iter()
            .map(|s| match s {
                PathSeg::Field(i) => Step::Field(*i),
                PathSeg::Key(k) => Step::Key(k.clone()),
                PathSeg::Case(c) => Step::Case(*c),
                PathSeg::Index(i) => Step::Index(*i),
            })
            .collect(),
    )
}

/// The root links the state holds under `path`, by content hash.
fn held_links(state: Option<&Fragment>, path: &[PathSeg]) -> HashMap<[u8; 32], Link> {
    let mut out = Vec::new();
    if let Some(v) = state.and_then(|f| f.at(path)).filter(|f| f.present()).and_then(|f| f.read()) {
        links_in(&v, &mut out);
    }
    out.into_iter().map(|l| (l.hash, l)).collect()
}

/// The schema, type and whether it is a text, of what `path` of aspect `ak` holds (untyped:
/// `any`).
fn op_type<'s>(schema: Option<&'s Schema>, ak: &str, path: &[PathSeg]) -> (&'s Schema, Type, bool) {
    let (s, root): (&Schema, Type) = match schema.and_then(|s| s.aspects.get(ak).map(|a| (s, a.ty.clone()))) {
        Some(x) => x,
        None => (osis_schema::core_schema(), Type::Any),
    };
    let ty = if path.is_empty() { root } else { type_at(s, &root, &schema_path(path)).map(|x| x.0).unwrap_or(Type::Any) };
    let text = matches!(s.expand(&ty).as_deref(), Ok(Type::Text));
    (s, ty, text)
}

/// A list `edit` before its items are chunked (`list_edits`): base's items with their large
/// parts as links by content hash (no blob written), whether chunking changes base or new, and
/// where the edit resolves at base's own indices by those forms (`osis_crdt::edit_window`).
/// The links the list lends the edit are those its read holds there (`window_links`), so a node
/// holding the list in part resolves it from the pages there; else every link the list holds.
#[derive(Clone, Debug)]
pub(crate) struct ListEdit {
    base: Vec<Value>,
    pub(crate) large: bool,
    pub(crate) win: Option<osis_crdt::EditWindow>,
}

impl ListEdit {
    /// Base's length.
    pub(crate) fn base_len(&self) -> usize {
        self.base.len()
    }
}

/// `v` chunked without writing blobs: a large value as the link (content hash) a write gives it.
fn hashed(v: &Value, dedup: &Secret32) -> Result<Value> {
    Ok(osis_label::chunk_value(&mut HashSink::new(dedup.clone()), LargeParams::FORMAT, v)?)
}

/// The `ListEdit` of each op that is a list `edit` (others `None`), large parts hashed under
/// `dedup`.
pub(crate) fn list_edits(ops: &[PathOp], schema: Option<&Schema>, ak: &str, dedup: &Secret32) -> Result<Vec<Option<ListEdit>>> {
    let mut hash = |v: &Value, _: Option<&Link>| hashed(v, dedup);
    let mut out = Vec::with_capacity(ops.len());
    for op in ops {
        let Op::Edit { base, new: new @ Value::List(_) } = &op.op else {
            out.push(None);
            continue;
        };
        let (s, ty, text) = op_type(schema, ak, &op.path);
        if text {
            out.push(None);
            continue;
        }
        let (mut b, mut n) = (base.clone(), new.clone());
        chunk_value(&mut b, s, &ty, None, &mut hash)?;
        chunk_value(&mut n, s, &ty, None, &mut hash)?;
        let large = b != *base || n != *new;
        let (Value::List(b), Value::List(n)) = (b, n) else {
            out.push(None);
            continue;
        };
        let win = osis_crdt::edit_window(&b, &n);
        out.push(Some(ListEdit { base: b, large, win }));
    }
    Ok(out)
}

/// `v` with every link reduced to its content hash.
fn hash_only(v: &Value) -> Value {
    map_links(v, &|l| Value::Link(Link { hash: l.hash, blob: BlobId([0; 32]), suite: 0, key: [0; 32] }))
}

/// `v` with every link replaced by `f`'s value for it.
pub(crate) fn map_links(v: &Value, f: &dyn Fn(&Link) -> Value) -> Value {
    match v {
        Value::Link(l) => f(l),
        Value::List(x) => Value::List(x.iter().map(|v| map_links(v, f)).collect()),
        Value::Set(x) => Value::Set(x.iter().map(|v| map_links(v, f)).collect()),
        Value::Map(x) => Value::Map(x.iter().map(|(k, v)| (map_links(k, f), map_links(v, f))).collect()),
        Value::Enum(c, Some(p)) => Value::Enum(*c, Some(Box::new(map_links(p, f)))),
        v => v.clone(),
    }
}

/// The links list `list` lends edit `e` by content hash: those of its elements at the edit's
/// window when it has base's length and reads there as base does by content hash; `None` else
/// (then every link it holds), or where something there is not loaded.
pub(crate) fn window_links(list: &Fragment, e: &ListEdit) -> Option<HashMap<[u8; 32], Link>> {
    let w = e.win?;
    if list.visible_len()? != e.base.len() {
        return None;
    }
    let dots = list.visible_range(w.lo..w.hi)?;
    let Value::List(vals) = list.read_elems(&dots)? else { return None };
    let base = e.base.get(w.lo..w.hi)?;
    if vals.len() != base.len() || vals.iter().zip(base).any(|(v, b)| hash_only(v) != hash_only(b)) {
        return None;
    }
    let mut out = Vec::new();
    vals.iter().for_each(|v| links_in(v, &mut out));
    Some(out.into_iter().map(|l| (l.hash, l)).collect())
}

/// Chunks the large positions of an op's value (untyped writes are classified as `any`);
/// large values `state` holds at the positions a `set`/`replace` overwrites are reused. A list
/// `edit` (`edit`: its `ListEdit`) chunks `new`'s items as an insert's, except that an item the
/// list lends it (by content hash, `window_links`) keeps its link, and `base`'s items become
/// links by content hash (`hash`: the value's place without writing blobs) so they match the
/// list's read; at its window, base's and new's common items outside it take base's form.
pub(crate) fn chunk_op(op: &mut PathOp, schema: Option<&Schema>, ak: &str, state: Option<&Fragment>, edit: Option<&ListEdit>, put: &mut Put<'_>, hash: &mut dyn FnMut(&Value) -> Result<Value>) -> Result<()> {
    let PathOp { path, op } = op;
    // large map keys on the path: the link the state holds for the key, else a new tree
    for i in 0..path.len() {
        let (before, rest) = path.split_at_mut(i);
        let Some(PathSeg::Key(k)) = rest.first_mut() else { continue };
        if !atomic_large(k) {
            continue;
        }
        let Value::Link(h) = hash(k)? else { continue };
        let key_of = |f: &Fragment| match f {
            Fragment::Map(m) => m.live(&Value::Link(h)).first().and_then(|(d, _)| f.entry_key(d)).cloned(),
            _ => None,
        };
        // (`at` copies the position: the root is read in place)
        let held = match before {
            [] => state.and_then(key_of),
            _ => state.and_then(|f| f.at(before)).as_ref().and_then(key_of),
        };
        *k = match held {
            Some(x) => x,
            None => put(k, None)?,
        };
    }
    let (s, ty, text) = op_type(schema, ak, path);
    match op {
        Op::Set(v) | Op::Replace(v) | Op::Put(v) => chunk_value(v, s, &ty, state.map(|f| (&path[..], f)), put),
        // a set element or map key is chunked whole (spec/data-model.md §6); removal matches
        // the held link by content hash
        Op::Add(v) if atomic_large(v) => {
            *v = put(v, None)?;
            Ok(())
        }
        Op::Remove(v) if atomic_large(v) => {
            *v = hash(v)?;
            Ok(())
        }
        Op::Add(v) => chunk_value(v, s, &ty, None, put),
        // a list's (a text's edit holds strings)
        Op::Edit { base, new } if !text && matches!(new, Value::List(_)) => {
            if edit.is_some_and(|e| !e.large) {
                return Ok(());
            }
            let at_win = edit.and_then(|e| Some((e.win?, window_links(&state?.at(path)?, e)?)));
            let held = match &at_win {
                Some((_, h)) => h.clone(),
                None => held_links(state, path),
            };
            chunk_value(base, s, &ty, None, &mut |v, _| match hash(v)? {
                Value::Link(l) => Ok(Value::Link(held.get(&l.hash).copied().unwrap_or(l))),
                small => Ok(small),
            })?;
            // the common items outside the window as base's (what the list there lends, or the
            // content hash: never written, only matched)
            if let (Some((w, _)), Value::List(b), Value::List(n)) = (&at_win, &*base, &mut *new) {
                let (bl, nl) = (b.len(), n.len());
                for (j, x) in n.iter_mut().enumerate() {
                    let i = if j < w.pre {
                        j
                    } else if j + w.suf >= nl {
                        j + bl - nl
                    } else {
                        continue;
                    };
                    if !(w.lo..w.hi).contains(&i)
                        && let Some(v) = b.get(i)
                    {
                        *x = v.clone();
                    }
                }
            }
            // an item twice in `new` gets one tree; hashing first costs one more pass over the
            // items not held, and spares writing the (usually many) unchanged ones
            let mut made: HashMap<[u8; 32], Value> = HashMap::new();
            chunk_value(new, s, &ty, None, &mut |v, _| match hash(v)? {
                Value::Link(l) => match held.get(&l.hash) {
                    Some(x) => Ok(Value::Link(*x)),
                    None => {
                        if let Some(x) = made.get(&l.hash) {
                            return Ok(x.clone());
                        }
                        let x = put(v, None)?;
                        made.insert(l.hash, x.clone());
                        Ok(x)
                    }
                },
                small => Ok(small),
            })
        }
        // list items (a text's are characters: never chunked)
        Op::Insert { items, .. } if !text => {
            let mut list = Value::List(std::mem::take(items));
            let r = chunk_value(&mut list, s, &ty, None, put);
            if let Value::List(x) = list {
                *items = x;
            }
            r
        }
        _ => Ok(()),
    }
}

/// Whether `v`, held atomically (a set element, a map key), is held as a link
/// (spec/data-model.md §6: above `CHUNK_THRESHOLD`).
fn atomic_large(v: &Value) -> bool {
    !matches!(v, Value::Link(_)) && osis_base::encode(v).len() > osis_base::format::CHUNK_THRESHOLD
}

/// What an index lookup finds an atomic value by: a large one by its link (content hash only,
/// no blob written), as the state holds it.
pub(crate) fn lookup_form(v: &Value, dedup: &Secret32) -> Result<Value> {
    if !atomic_large(v) {
        return Ok(v.clone());
    }
    hashed(v, dedup)
}

/// Chunks the large positions of `ops` on `(tid, ak)` under `framing`, reusing the tree each
/// position holds now (spec/sync.md §1: a reused chunk keeps its blob unless the re-encryption
/// rule says otherwise; one this node no longer holds is written afresh). Returns the blobs
/// written: the delta's chunk list; reused blobs are not in it. `fresh`: blobs
/// never reused.
#[allow(clippy::too_many_arguments)]
pub(crate) fn chunk_ops(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, ops: &mut [PathOp], edits: &[Option<ListEdit>], schema: Option<&Schema>, framing: &Framing, fresh: &BTreeSet<BlobId>) -> Result<Vec<BlobId>> {
    // what the ops address is loaded (`commit_in`)
    tx.load_lazy(tid, ak)?;
    let state = tx.core.states.get(&(*tid, ak.clone())).and_then(Option::as_ref);
    // the blind of the header that introduced a held commit's chunk: a reused blob's
    // commitments are checked under it (spec/sync.md §1); of several listing it, the greatest ID
    // (`by_chunk`: one header decoded)
    let core = &*tx.core;
    let mut blind_of = |b: &BlobId| -> Option<[u8; 16]> { core.ix.by_chunk.get(b)?.iter().next_back().and_then(|c| core.ix.commits.get(c)).map(|m| m.header.blind) };
    let mut blobs = TxBlobs::new(&mut tx.txn);
    let rng = &mut *tx.rng;
    let max = usize::try_from(MAX_REUSE).unwrap_or(usize::MAX);
    let mut put = |v: &Value, base: Option<&Link>| -> Result<Value> {
        let reuse = match base {
            Some(b) => {
                let mut r = Reuse::index(b, framing.clone(), &mut blobs, &mut blind_of, ChunkParams::FORMAT, max)?;
                fresh.iter().for_each(|x| r.exclude(x));
                Some(r)
            }
            None => None,
        };
        let mut bw = match &reuse {
            Some(r) => BlobWriter::reusing(r, &mut blobs, rng),
            None => BlobWriter::new(framing, &mut blobs, rng),
        };
        Ok(osis_label::chunk_value(&mut bw, LargeParams::FORMAT, v)?)
    };
    let mut hash = |v: &Value| hashed(v, &framing.dedup);
    for (i, op) in ops.iter_mut().enumerate() {
        chunk_op(op, schema, ak.as_str(), state, edits.get(i).and_then(Option::as_ref), &mut put, &mut hash)?;
    }
    Ok(blobs.written)
}

/// A roster snapshot's `/tenures` value (spec/permissions.md §6, spec/data-model.md §6): a
/// tenure's frontier above `CHUNK_THRESHOLD` becomes a link to a fresh chunk tree, so every
/// blob it needs is in the commit's chunk list (receivers fetch frontiers by it before judging).
/// Returns the blobs written.
pub(crate) fn chunk_frontiers(tx: &mut Tx<'_>, ops: &mut [PathOp], framing: &Framing) -> Result<Vec<BlobId>> {
    let mut blobs = TxBlobs::new(&mut tx.txn);
    let rng = &mut *tx.rng;
    let frontier_field = Value::Int(4);
    for op in ops.iter_mut() {
        let (Op::Set(Value::Set(s)) | Op::Replace(Value::Set(s))) = &mut op.op else { continue };
        let mut out = std::collections::BTreeSet::new();
        for t in std::mem::take(s) {
            let Value::Map(mut m) = t else {
                out.insert(t);
                continue;
            };
            if let Some(Value::Enum(1, Some(f))) = m.get_mut(&frontier_field) {
                let mut bw = BlobWriter::new(framing, &mut blobs, rng);
                let v = osis_label::chunk_value(&mut bw, LargeParams::FORMAT, f)?;
                **f = v;
            }
            out.insert(Value::Map(m));
        }
        *s = out;
    }
    Ok(blobs.written)
}

/// Blob IDs a delta's canonical bytes link (its values' trees, its pages), through the held
/// node and page blobs.
pub(crate) fn delta_links(tx: &mut Tx<'_>, dedup: &Secret32, delta: &[u8]) -> Result<BTreeSet<BlobId>> {
    let mut out = LiveTrees::default();
    tree_blobs(tx, dedup, &delta_roots(delta), &mut out)?;
    Ok(out.blobs)
}

/// The root links in a delta's canonical bytes (none if they do not decode).
fn delta_roots(delta: &[u8]) -> Vec<Link> {
    let mut roots = Vec::new();
    if let Ok(v) = osis_base::decode(delta, &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: delta.len() }) {
        links_in(&v, &mut roots);
    }
    roots
}

/// Every link inside `v` (the root links of its large values).
pub(crate) fn links_in(v: &Value, out: &mut Vec<Link>) {
    match v {
        Value::Link(l) => out.push(*l),
        Value::List(l) => l.iter().for_each(|x| links_in(x, out)),
        Value::Set(s) => s.iter().for_each(|x| links_in(x, out)),
        Value::Map(m) => m.iter().for_each(|(k, x)| {
            links_in(k, out);
            links_in(x, out);
        }),
        Value::Enum(_, Some(p)) => links_in(p, out),
        _ => {}
    }
}

/// What a link reaches one step down: a tree node's children (with whether they are chunks),
/// or the links inside a page or link page; `Ok(None)` for anything else (a chunk);
/// `Err(Missing)` when the blob is not held.
fn below(blobs: &mut TxBlobs<'_, '_>, dedup: &Secret32, link: &Link) -> Result<Option<(bool, Vec<Link>)>> {
    let blob = blobs.fetch(&link.blob)?;
    if osis_label::blob_id(&blob) != link.blob {
        return Ok(None);
    }
    let Ok((_, pt)) = osis_label::open(&blob, &Secret32::from_bytes(link.key)) else { return Ok(None) };
    if let Ok((level, kids)) = osis_label::tree::parse_node(&pt)
        && osis_label::tree::node_hash(dedup, level, &kids) == link.hash
    {
        return Ok(Some((level <= 1, kids.into_iter().map(|(l, _)| l).collect())));
    }
    if osis_crypto::link_hash(dedup, &pt) != link.hash {
        return Ok(None);
    }
    let Ok(v) = osis_base::decode(&pt, &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: pt.len() }) else { return Ok(None) };
    let mut out = Vec::new();
    links_in(&v, &mut out);
    Ok(Some((false, out)))
}

/// Blob IDs of the trees a thing's live states link (`Engine::live_trees`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LiveTrees {
    /// Nodes and chunks reached through the node blobs held, and the roots.
    pub blobs: BTreeSet<BlobId>,
    /// Node blobs linked and not held: what lies below them is unknown until they are fetched.
    pub missing: BTreeSet<BlobId>,
}

/// The trees (and pages) under `roots`, through the node and page blobs this node holds,
/// added to `out`.
pub(crate) fn tree_blobs(tx: &mut Tx<'_>, dedup: &Secret32, roots: &[Link], out: &mut LiveTrees) -> Result<()> {
    // (link, whether it is known to be a chunk)
    let mut stack: Vec<(Link, bool)> = roots.iter().map(|l| (*l, false)).collect();
    let mut blobs = TxBlobs::new(&mut tx.txn);
    while let Some((l, leaf)) = stack.pop() {
        if !out.blobs.insert(l.blob) || leaf {
            continue;
        }
        match below(&mut blobs, dedup, &l) {
            // children of a level-1 node are chunks: not fetched
            Ok(Some((chunks, kids))) => stack.extend(kids.into_iter().map(|k| (k, chunks))),
            Ok(None) => {}
            Err(Error::Label(osis_label::Error::Missing)) => {
                out.missing.insert(l.blob);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Whether the trees under `roots`, as far as the held node blobs go, hold one of `blobs`.
fn tree_hits(tx: &mut Tx<'_>, dedup: &Secret32, roots: &[Link], blobs: &BTreeSet<BlobId>) -> Result<bool> {
    let mut out = LiveTrees::default();
    tree_blobs(tx, dedup, roots, &mut out)?;
    Ok(!out.blobs.is_disjoint(blobs))
}

impl Engine {
    /// Reads a chunked large value of thing `tid` back whole.
    pub fn read_large(&mut self, tid: &Tid, link: &Link) -> Result<Value> {
        self.read_large_max(tid, link, MAX_READ)
    }

    /// The chunk trees the live states of `tid`'s aspects link (spec/sync.md §3, §7: chunk
    /// blobs still linked from a retained version are kept and belong to the closure; a reused
    /// chunk is not in the reusing commit's chunk list). Complete when no node blob is
    /// `missing`. Cached until the next change or blob arrival.
    pub fn live_trees(&mut self, tid: &Tid) -> Result<LiveTrees> {
        if let Some(x) = self.core.live_trees.get(tid) {
            return Ok(x.clone());
        }
        let aks = self.aspects(tid)?;
        let tid = *tid;
        let r = self.run(|tx| {
            let mut out = LiveTrees::default();
            let Some(dedup) = tx.core.dedup(&tid) else { return Ok(out) };
            let mut roots = Vec::new();
            for ak in &aks {
                if let Some(v) = tx.state(&tid, ak)?.and_then(Fragment::read) {
                    links_in(&v, &mut roots);
                }
            }
            tree_blobs(tx, &dedup, &roots, &mut out)?;
            Ok(out)
        })?;
        self.core.live_trees.insert(tid, r.clone());
        Ok(r)
    }

    /// Chunks or tree nodes `lost`, gone from every server of a label, that this node's own
    /// commit links (spec/sync.md §1: a purger that had not seen this node's reuse judged them
    /// dead). For each aspect whose newest own commit linking one is held: every large position
    /// of the current value whose tree holds one is written again (`Op::Put` at that position:
    /// no reset, so every other write stays), with the lost blobs re-encrypted and the own
    /// commit's retention and expiry. `allow` gates each aspect (the caller's back-off). Needs
    /// write on the thing and the aspect's schema registered here. One commit, if any.
    pub fn relink(&mut self, lost: &BTreeSet<BlobId>, allow: &mut dyn FnMut(&Tid, &Ak) -> bool) -> Result<Option<CommitId>> {
        let held: BTreeSet<BlobId> = self.run(|tx| {
            let mut out = BTreeSet::new();
            for b in lost {
                if tx.txn.read_blob(b, 0, 0)?.is_some() {
                    out.insert(*b);
                }
            }
            Ok(out)
        })?;
        if held.is_empty() {
            return Ok(None);
        }
        let me = self.tid();
        // reuse links within one position of one aspect: the aspects of the commits listing it
        let core = &self.core;
        let cands: BTreeSet<(Tid, Ak)> = held.iter().flat_map(|b| core.ix.by_chunk.get(b).into_iter().flatten()).filter_map(|c| core.ix.commits.get(c)).flat_map(|m| m.view.aspects.iter().map(|a| (a.tid, a.ak.clone()))).collect();
        let now = self.now().0;
        let mut m = super::Mutation::new();
        m.fresh.clone_from(&held);
        for (tid, ak) in cands {
            if is_membership_class(ak.as_str()) || self.role_on(&tid).is_none_or(|r| r < Role::Write) {
                continue;
            }
            // one field failing (a blob not held, a value too large) leaves the others
            let e = match self.relink_field(&tid, &ak, &held, me, now) {
                Ok(Some(e)) => e,
                Ok(None) => continue,
                Err(e @ Error::Store(_)) => return Err(e),
                Err(_) => continue,
            };
            if allow(&tid, &ak) {
                m.aspects.insert((tid, ak), e);
            }
        }
        if m.aspects.is_empty() {
            return Ok(None);
        }
        self.commit(m)
    }

    /// `relink` of one field: its ops, with the retention, expiry and schema of the newest held
    /// commit whose delta links a `held` blob (the value rewritten), if a commit of `me` links one
    /// too; `None` when there is nothing to do here.
    fn relink_field(&mut self, tid: &Tid, ak: &Ak, held: &BTreeSet<BlobId>, me: Tid, now: u64) -> Result<Option<super::write::AspectMut>> {
        let commits: Vec<CommitId> = self.core.ix.by_aspect.get(&(*tid, ak.clone())).map(|s| s.iter().rev().map(|x| x.1).filter(|c| self.core.ix.commits.get(c).is_some_and(|m| m.header.kind == osis_commit::Kind::Content)).collect()).unwrap_or_default();
        let (k, held2) = ((*tid, ak.clone()), held.clone());
        // (newest linking commit and its aspect index, whether an own commit links one)
        let found = self.run(|tx| {
            let Some(dedup) = tx.core.dedup(&k.0) else { return Ok((None, false)) };
            let mut newest = None;
            for c in commits {
                let Some((ai, mine)) = tx.core.ix.commits.get(&c).and_then(|m| Some((m.header.aspects.iter().position(|a| a.tid == k.0 && a.ak == k.1)?, m.header.author == me))) else { continue };
                if newest.is_some() && !mine {
                    continue;
                }
                let mut roots = Vec::new();
                for d in crate::apply::held_parts(tx, &c, ai)? {
                    if let Some(v) = d.fragment().read() {
                        links_in(&v, &mut roots);
                    }
                }
                if !tree_hits(tx, &dedup, &roots, &held2)? {
                    continue;
                }
                newest = newest.or(Some((c, ai)));
                if mine {
                    return Ok((newest, true));
                }
            }
            Ok((newest, false))
        })?;
        let (Some((c, ai)), true) = found else { return Ok(None) };
        let Some(a) = self.core.ix.commits.get(&c).and_then(|m| m.header.aspects.get(ai).cloned()) else { return Ok(None) };
        if a.expires.is_some_and(|t| t <= now) {
            return Ok(None);
        }
        // the schema it was written with: an unregistered typed one cannot be written back
        let schema: Option<Arc<Schema>> = match a.schema {
            None => None,
            Some(i) => match self.core.ix.commits.get(&c).and_then(|m| m.header.schemas.get(i)).and_then(|(s, _)| self.core.schemas.get(s)) {
                Some(s) => Some(s.clone()),
                None => return Ok(None),
            },
        };
        let Some(state) = self.state(tid, ak)? else { return Ok(None) };
        let Some(v) = state.read() else { return Ok(None) };
        let core = osis_schema::core_schema();
        let (sc, ty): (&Schema, Type) = match schema.as_deref().and_then(|s| s.aspects.get(ak.as_str()).map(|d| (s, d.ty.clone()))) {
            Some(x) => x,
            None => (core, Type::Any),
        };
        let mut ops = Vec::new();
        for l in osis_schema::link_positions(sc, &v, &ty) {
            // set elements and map keys have no register position to write
            let Some(path) = segs(&l) else { continue };
            let Some(link) = base_at(&state, &[], &l) else { continue };
            let t = *tid;
            let hit = self.run(|tx| {
                let Some(dedup) = tx.core.dedup(&t) else { return Ok(false) };
                tree_hits(tx, &dedup, &[link], held)
            })?;
            if hit {
                let raw = self.read_large(tid, &link)?;
                // written whole without a reset: other writes at and around it stay
                ops.push(PathOp { path, op: Op::Put(raw) });
            }
        }
        if ops.is_empty() {
            return Ok(None);
        }
        Ok(Some(super::write::AspectMut { ops, schema, retention: Some(a.retention), expires: a.expires, ..Default::default() }))
    }

    /// The blobs the deltas of a body (`plaintext`: its commit blob plaintext) link, through
    /// held node and page blobs: the trees of its values and the pages of its fragments, listed
    /// by its commit or not (spec/sync.md §3 closure). Complete when nothing is `missing`.
    pub fn body_links(&mut self, plaintext: &[u8]) -> Result<LiveTrees> {
        let Ok(cb) = osis_commit::CommitBlob::decode(plaintext) else { return Ok(LiveTrees::default()) };
        let Some(h) = self.header(&cb.id()) else { return Ok(LiveTrees::default()) };
        self.run(|tx| {
            let mut out = LiveTrees::default();
            for p in &cb.parts {
                let Some(dedup) = h.aspects.get(p.ai).and_then(|a| tx.core.dedup(&a.tid)) else { continue };
                tree_blobs(tx, &dedup, &delta_roots(&p.delta), &mut out)?;
            }
            Ok(out)
        })
    }

    /// `read_large` failing with `osis_label::Error::TooLarge` past `max_len` canonical bytes
    /// (the API's materialization bound).
    pub fn read_large_max(&mut self, tid: &Tid, link: &Link, max_len: usize) -> Result<Value> {
        let (tid, link) = (*tid, *link);
        self.run(|tx| {
            let dedup = tx.core.dedup(&tid).ok_or(Error::UnknownThing(tid))?;
            let mut blobs = TxBlobs::new(&mut tx.txn);
            let mut r = BlobReader::new(&dedup, &mut blobs);
            Ok(osis_label::read_value(link, &dedup, &mut r, LargeParams::FORMAT, max_len)?)
        })
    }

    /// One step of a streaming read of a large value of `tid` (the API's `stream`): the next
    /// plaintext chunk of the canonical bytes `r` walks (`TreeReader::new(link, CHUNK_MIN, ..)`),
    /// `None` at the end. Memory: one chunk plus the tree path.
    pub fn next_chunk(&mut self, tid: &Tid, r: &mut osis_label::TreeReader) -> Result<Option<Vec<u8>>> {
        let tid = *tid;
        self.run(|tx| {
            let dedup = tx.core.dedup(&tid).ok_or(Error::UnknownThing(tid))?;
            let mut blobs = TxBlobs::new(&mut tx.txn);
            let mut src = BlobReader::new(&dedup, &mut blobs);
            Ok(r.next_chunk(&dedup, &mut src)?)
        })
    }

    /// The blobs of the tree under `link` (a large value of `tid`) this node lacks: node blobs
    /// below the held ones and the chunks held nodes list (spec/sync.md §6: a read that misses a
    /// chunk fetches that tree only). Empty when the tree is whole here; a node fetched may list
    /// more, so a reader asks again once those arrive. `UnknownThing` when the thing's secrets
    /// are not held (nothing could be read either).
    pub fn tree_missing(&mut self, tid: &Tid, link: &Link) -> Result<Vec<BlobId>> {
        let (tid, link) = (*tid, *link);
        self.run(|tx| {
            let dedup = tx.core.dedup(&tid).ok_or(Error::UnknownThing(tid))?;
            let mut out = LiveTrees::default();
            tree_blobs(tx, &dedup, &[link], &mut out)?;
            let mut v: Vec<BlobId> = out.missing.into_iter().collect();
            for b in out.blobs {
                if tx.txn.read_blob(&b, 0, 0)?.is_none() {
                    v.push(b);
                }
            }
            v.sort();
            v.dedup();
            Ok(v)
        })
    }

    /// `get` with every link materialized (large values read whole).
    pub fn get_full(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<Value>> {
        let Some(v) = self.get(tid, ak)? else { return Ok(None) };
        Ok(Some(self.materialize(tid, v)?))
    }

    fn materialize(&mut self, tid: &Tid, v: Value) -> Result<Value> {
        Ok(match v {
            Value::Link(l) => self.read_large(tid, &l)?,
            Value::List(l) => Value::List(l.into_iter().map(|x| self.materialize(tid, x)).collect::<Result<_>>()?),
            Value::Set(s) => Value::Set(s.into_iter().map(|x| self.materialize(tid, x)).collect::<Result<_>>()?),
            Value::Map(m) => Value::Map(m.into_iter().map(|(k, x)| Ok((self.materialize(tid, k)?, self.materialize(tid, x)?))).collect::<Result<_>>()?),
            Value::Enum(c, Some(p)) => Value::Enum(c, Some(Box::new(self.materialize(tid, *p)?))),
            v => v,
        })
    }
}

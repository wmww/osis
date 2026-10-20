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
use osis_core::{Ak, BlobId, ChunkParams, Link, Tid, Value};
use osis_crdt::{Fragment, Op, PathOp, PathSeg};
use osis_crypto::Secret32;
use osis_label::{BlobFetch, BlobReader, BlobWriter, Framing, HashSink, LargeParams, Reuse};
use osis_schema::{Large, Path, Schema, Step, Type, large_positions, type_at};
use std::collections::{BTreeSet, HashMap};

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

/// The root link the state holds at `prefix` + `l`'s path now.
fn base_at(state: &Fragment, prefix: &[PathSeg], l: &Large) -> Option<Link> {
    if l.map_key {
        return None;
    }
    let mut path = prefix.to_vec();
    for s in &l.path.0 {
        path.push(match s {
            Step::Field(i) => PathSeg::Field(*i),
            Step::Key(k) => PathSeg::Key(k.clone()),
            Step::Case(c) => PathSeg::Case(*c),
            Step::Index(i) => PathSeg::Index(*i),
            Step::Elem(_) => return None,
        });
    }
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

/// Chunks the large positions of an op's value (untyped writes are classified as `any`);
/// large values `state` holds at the positions a `set`/`replace` overwrites are reused. A list
/// `edit` chunks `new`'s items as an insert's, except that an item the list holds already (by
/// content hash) keeps its link, and `base`'s items become links by content hash (`hash`: the
/// value's place without writing blobs) so they match the list's read.
pub(crate) fn chunk_op(op: &mut PathOp, schema: Option<&Schema>, ak: &str, state: Option<&Fragment>, put: &mut Put<'_>, hash: &mut dyn FnMut(&Value) -> Result<Value>) -> Result<()> {
    let core = osis_schema::core_schema();
    let (s, root): (&Schema, Type) = match schema.and_then(|s| s.aspects.get(ak).map(|a| (s, a.ty.clone()))) {
        Some(x) => x,
        None => (core, Type::Any),
    };
    let PathOp { path, op } = op;
    let ty = if path.is_empty() { root } else { type_at(s, &root, &schema_path(path)).map(|x| x.0).unwrap_or(Type::Any) };
    let text = matches!(s.expand(&ty).as_deref(), Ok(Type::Text));
    match op {
        Op::Set(v) | Op::Replace(v) => chunk_value(v, s, &ty, state.map(|f| (&path[..], f)), put),
        Op::Add(v) => chunk_value(v, s, &ty, None, put),
        // a list's (a text's edit holds strings)
        Op::Edit { base, new } if !text && matches!(new, Value::List(_)) => {
            let held = held_links(state, path);
            chunk_value(base, s, &ty, None, &mut |v, _| match hash(v)? {
                Value::Link(l) => Ok(Value::Link(held.get(&l.hash).copied().unwrap_or(l))),
                small => Ok(small),
            })?;
            chunk_value(new, s, &ty, None, &mut |v, _| match hash(v)? {
                Value::Link(l) => match held.get(&l.hash) {
                    Some(x) => Ok(Value::Link(*x)),
                    None => put(v, None),
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

/// Chunks the large positions of `ops` on `(tid, ak)` under `framing`, reusing the tree each
/// position holds now (spec/sync.md §1: a reused chunk keeps its blob unless the re-encryption
/// rule says otherwise; one this node no longer holds is written afresh). Returns the blobs
/// written (ID, prefix salt): the delta's chunk list; reused blobs are not in it.
pub(crate) fn chunk_ops(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, ops: &mut [PathOp], schema: Option<&Schema>, framing: &Framing) -> Result<Vec<(BlobId, [u8; 16])>> {
    tx.load(tid, ak)?;
    let state = tx.core.states.get(&(*tid, ak.clone())).and_then(Option::as_ref);
    let mut blobs = TxBlobs::new(&mut tx.txn);
    let rng = &mut *tx.rng;
    let max = usize::try_from(MAX_REUSE).unwrap_or(usize::MAX);
    let mut put = |v: &Value, base: Option<&Link>| -> Result<Value> {
        let reuse = match base {
            Some(b) => Some(Reuse::index(b, framing.clone(), &mut blobs, ChunkParams::FORMAT, max)?),
            None => None,
        };
        let mut bw = match &reuse {
            Some(r) => BlobWriter::reusing(r, &mut blobs, rng),
            None => BlobWriter::new(framing, &mut blobs, rng),
        };
        Ok(osis_label::chunk_value(&mut bw, LargeParams::FORMAT, v)?)
    };
    let mut hash = |v: &Value| -> Result<Value> { Ok(osis_label::chunk_value(&mut HashSink::new(framing.dedup.clone()), LargeParams::FORMAT, v)?) };
    for op in ops.iter_mut() {
        chunk_op(op, schema, ak.as_str(), state, &mut put, &mut hash)?;
    }
    Ok(blobs.written)
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

/// Level and links of a tree node blob, if `link` names one (`Ok(None)`: a chunk);
/// `Err(Missing)` when the blob is not held.
fn node_links(blobs: &mut TxBlobs<'_, '_>, dedup: &Secret32, link: &Link) -> Result<Option<(u64, Vec<Link>)>> {
    let blob = blobs.fetch(&link.blob)?;
    if osis_label::blob_id(&blob) != link.blob {
        return Ok(None);
    }
    let Ok((_, pt)) = osis_label::open(&blob, &Secret32::from_bytes(link.key)) else { return Ok(None) };
    let Ok((level, kids)) = osis_label::tree::parse_node(&pt) else { return Ok(None) };
    if osis_label::tree::node_hash(dedup, level, &kids) != link.hash {
        return Ok(None);
    }
    Ok(Some((level, kids.into_iter().map(|(l, _)| l).collect())))
}

/// Blob IDs of the trees a thing's live states link (`Engine::live_trees`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LiveTrees {
    /// Nodes and chunks reached through the node blobs held, and the roots.
    pub blobs: BTreeSet<BlobId>,
    /// Node blobs linked and not held: what lies below them is unknown until they are fetched.
    pub missing: BTreeSet<BlobId>,
}

/// The trees under `roots`, through the node blobs this node holds.
fn tree_blobs(tx: &mut Tx<'_>, dedup: &Secret32, roots: &[Link]) -> Result<LiveTrees> {
    let mut out = LiveTrees::default();
    // (link, whether it is known to be a chunk)
    let mut stack: Vec<(Link, bool)> = roots.iter().map(|l| (*l, false)).collect();
    let mut blobs = TxBlobs::new(&mut tx.txn);
    while let Some((l, leaf)) = stack.pop() {
        if !out.blobs.insert(l.blob) || leaf {
            continue;
        }
        match node_links(&mut blobs, dedup, &l) {
            // children of a level-1 node are chunks: not fetched
            Ok(Some((level, kids))) => stack.extend(kids.into_iter().map(|k| (k, level <= 1))),
            Ok(None) => {}
            Err(Error::Label(osis_label::Error::Missing)) => {
                out.missing.insert(l.blob);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
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
            let Some(dedup) = tx.core.dedup(&tid) else { return Ok(LiveTrees::default()) };
            let mut roots = Vec::new();
            for ak in &aks {
                if let Some(v) = tx.state(&tid, ak)?.and_then(Fragment::read) {
                    links_in(&v, &mut roots);
                }
            }
            tree_blobs(tx, &dedup, &roots)
        })?;
        self.core.live_trees.insert(tid, r.clone());
        Ok(r)
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

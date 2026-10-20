//! Large atomic values (spec/data-model.md §6): before an op's value is resolved, every
//! position that must be chunked (blobs, register strings, set elements and map keys above
//! `CHUNK_THRESHOLD`, in `set`/`replace`/`add` values and list `insert` items) becomes a link to
//! a chunk tree written as blob ciphertexts in the store, framed like the delta's pages. A
//! position holding a large value now reuses that tree (spec/sync.md §1): unchanged chunks keep
//! their blob and key and are not introduced again, so an edit writes and uploads O(change).
//! Links compare by content hash, so an unchanged large value diffs as equal. Reads return the
//! link; `Engine::read_large` materializes it.

use super::blobs::TxBlobs;
use super::{Engine, Tx};
use crate::error::{Error, Result};
use osis_core::{Ak, BlobId, ChunkParams, CommitId, Link, Role, Tid, Value};
use osis_crdt::{Fragment, Op, PathOp, PathSeg};
use osis_crypto::Secret32;
use osis_label::{BlobFetch, BlobReader, BlobWriter, Framing, LargeParams, Reuse};
use osis_schema::{Large, Path, Schema, Step, Type, large_positions, type_at};
use osis_schema::core_types::is_membership_class;
use std::collections::{BTreeMap, BTreeSet};
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

/// Chunks the large positions of an op's value (untyped writes are classified as `any`);
/// large values `state` holds at the positions a `set`/`replace` overwrites are reused.
pub(crate) fn chunk_op(op: &mut PathOp, schema: Option<&Schema>, ak: &str, state: Option<&Fragment>, put: &mut Put<'_>) -> Result<()> {
    let core = osis_schema::core_schema();
    let (s, root): (&Schema, Type) = match schema.and_then(|s| s.aspects.get(ak).map(|a| (s, a.ty.clone()))) {
        Some(x) => x,
        None => (core, Type::Any),
    };
    let PathOp { path, op } = op;
    let ty = if path.is_empty() { root } else { type_at(s, &root, &schema_path(path)).map(|x| x.0).unwrap_or(Type::Any) };
    match op {
        Op::Set(v) | Op::Replace(v) => chunk_value(v, s, &ty, state.map(|f| (&path[..], f)), put),
        Op::Add(v) => chunk_value(v, s, &ty, None, put),
        // list items (a text's are characters: never chunked)
        Op::Insert { items, .. } if !matches!(s.expand(&ty).as_deref(), Ok(Type::Text)) => {
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
/// written (ID, prefix salt): the delta's chunk list; reused blobs are not in it. `fresh`: blobs
/// never reused.
pub(crate) fn chunk_ops(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, ops: &mut [PathOp], schema: Option<&Schema>, framing: &Framing, fresh: &BTreeSet<BlobId>) -> Result<Vec<(BlobId, [u8; 16])>> {
    tx.load(tid, ak)?;
    let state = tx.core.states.get(&(*tid, ak.clone())).and_then(Option::as_ref);
    let mut blobs = TxBlobs::new(&mut tx.txn);
    let rng = &mut *tx.rng;
    let max = usize::try_from(MAX_REUSE).unwrap_or(usize::MAX);
    let mut put = |v: &Value, base: Option<&Link>| -> Result<Value> {
        let reuse = match base {
            Some(b) => {
                let mut r = Reuse::index(b, framing.clone(), &mut blobs, ChunkParams::FORMAT, max)?;
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
    for op in ops.iter_mut() {
        chunk_op(op, schema, ak.as_str(), state, &mut put)?;
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
    let Ok((level, links)) = osis_label::tree::parse_node(&pt) else { return Ok(None) };
    let hashes: Vec<[u8; 32]> = links.iter().map(|l| l.hash).collect();
    Ok((osis_crypto::link_tree_hash(dedup, level, &hashes) == link.hash).then_some((level, links)))
}

/// Blob IDs of the trees under `roots` (nodes and chunks), through the node blobs this node
/// holds; `None` when one is not held (what lies below it is unknown).
pub(crate) fn tree_blobs(tx: &mut Tx<'_>, dedup: &Secret32, roots: &[Link]) -> Result<Option<BTreeSet<BlobId>>> {
    let mut out = BTreeSet::new();
    // (link, whether it is known to be a chunk)
    let mut stack: Vec<(Link, bool)> = roots.iter().map(|l| (*l, false)).collect();
    let mut blobs = TxBlobs::new(&mut tx.txn);
    while let Some((l, leaf)) = stack.pop() {
        if !out.insert(l.blob) || leaf {
            continue;
        }
        match node_links(&mut blobs, dedup, &l) {
            // children of a level-1 node are chunks: not fetched
            Ok(Some((level, kids))) => stack.extend(kids.into_iter().map(|k| (k, level <= 1))),
            Ok(None) => {}
            Err(Error::Label(osis_label::Error::Missing)) => return Ok(None),
            Err(e) => return Err(e),
        }
    }
    Ok(Some(out))
}

impl Engine {
    /// Reads a chunked large value of thing `tid` back whole.
    pub fn read_large(&mut self, tid: &Tid, link: &Link) -> Result<Value> {
        self.read_large_max(tid, link, MAX_READ)
    }

    /// Blob IDs of the chunk trees the live states of `tid`'s aspects link (spec/sync.md §7:
    /// chunk blobs still linked from a retained version are kept; a reused chunk is not in the
    /// reusing commit's chunk list). `None` when a node blob below is not held. Cached until the
    /// next change.
    pub fn live_trees(&mut self, tid: &Tid) -> Result<Option<BTreeSet<BlobId>>> {
        if let Some(x) = self.core.live_trees.get(tid) {
            return Ok(x.clone());
        }
        let aks = self.aspects(tid)?;
        let tid = *tid;
        let r = self.run(|tx| {
            let Some(dedup) = tx.core.dedup(&tid) else { return Ok(Some(BTreeSet::new())) };
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

    /// A chunk or tree node `lost` that a live value links was deleted at a server: a purger
    /// that had not seen a concurrent reuse of it judged it dead (spec/sync.md §1). Writes each
    /// aspect of a commit listing it whose state links it again (replace with its value read
    /// whole, every large value re-chunked against its current tree) with `lost` re-encrypted,
    /// where this node holds the value, may write the thing and knows the aspect's schema.
    /// Returns the commit, if one was written.
    pub fn relink(&mut self, lost: &BlobId) -> Result<Option<CommitId>> {
        let id = *lost;
        if !self.run(|tx| Ok(tx.txn.get_blob(&id)?.is_some()))? {
            return Ok(None);
        }
        // reuse links within one position of one aspect: the aspects of the commits listing it
        // the schema each was written with: `Some(None)` untyped, `None` not registered here
        let mut aspects: BTreeMap<(Tid, Ak), Option<Option<Arc<Schema>>>> = BTreeMap::new();
        for m in self.core.commits.values().filter(|m| m.header.chunks.iter().any(|c| c.blob == id)) {
            let h = &m.header;
            for a in &h.aspects {
                let schema = match a.schema {
                    None => Some(None),
                    Some(i) => h.schemas.get(i).and_then(|(s, _)| self.core.schemas.get(s)).map(|s| Some(s.clone())),
                };
                aspects.entry((a.tid, a.ak.clone())).or_insert(schema);
            }
        }
        let mut m = super::Mutation::new();
        m.fresh.insert(id);
        for ((tid, ak), schema) in aspects {
            // an unknown schema: a typed value cannot be written back safely
            let Some(schema) = schema else { continue };
            if is_membership_class(ak.as_str()) || self.role_on(&tid).is_none_or(|r| r < Role::Write) {
                continue;
            }
            let linked = self.run(|tx| {
                let Some(dedup) = tx.core.dedup(&tid) else { return Ok(None) };
                let mut roots = Vec::new();
                if let Some(v) = tx.state(&tid, &ak)?.and_then(Fragment::read) {
                    links_in(&v, &mut roots);
                }
                tree_blobs(tx, &dedup, &roots)
            })?;
            if !linked.is_some_and(|s| s.contains(&id)) {
                continue;
            }
            let Ok(Some(v)) = self.get_full(&tid, &ak) else { continue };
            let e = m.aspects.entry((tid, ak)).or_default();
            e.schema = schema;
            e.ops.push(PathOp { path: Vec::new(), op: Op::Replace(v) });
        }
        if m.aspects.is_empty() {
            return Ok(None);
        }
        self.commit(m)
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

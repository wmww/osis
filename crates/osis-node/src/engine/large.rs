//! Large atomic values (spec/data-model.md §6; plans/large-values.md): before an op's value is
//! resolved, every position that must be chunked (blobs, register strings, set elements and map
//! keys above `CHUNK_THRESHOLD`) becomes a link to a chunk tree written as blob ciphertexts in
//! the store, framed like the delta's pages. Links compare by content hash, so an unchanged
//! large value diffs as equal. Reads return the link; `Engine::read_large` materializes it.

use super::Engine;
use super::blobs::TxBlobs;
use crate::error::{Error, Result};
use osis_core::{Ak, Link, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_label::{BlobReader, LargeParams, TreeSink};
use osis_schema::{Large, Path, Schema, Step, Type, large_positions, type_at};

/// Upper bound on a large value read back whole (local policy; streams read beyond it).
pub const MAX_READ: usize = 1 << 30;

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

/// Replaces one position by its chunked form.
fn chunk_one(v: &mut Value, l: &Large, sink: &mut dyn TreeSink) -> Result<()> {
    let steps = &l.path.0;
    let Some((last, parent)) = steps.split_last() else {
        let old = std::mem::replace(v, Value::Bool(false));
        *v = osis_label::chunk_value(sink, LargeParams::FORMAT, &old)?;
        return Ok(());
    };
    let p = at(v, parent).ok_or(Error::Misuse("large position"))?;
    match (last, p) {
        (Step::Elem(e), Value::Set(s)) => {
            if s.remove(e) {
                s.insert(osis_label::chunk_value(sink, LargeParams::FORMAT, e)?);
            }
        }
        (Step::Key(k), Value::Map(m)) if l.map_key => {
            if let Some(x) = m.remove(k) {
                m.insert(osis_label::chunk_value(sink, LargeParams::FORMAT, k)?, x);
            }
        }
        (s, p) => {
            let x = at(p, std::slice::from_ref(s)).ok_or(Error::Misuse("large position"))?;
            let old = std::mem::replace(x, Value::Bool(false));
            *x = osis_label::chunk_value(sink, LargeParams::FORMAT, &old)?;
        }
    }
    Ok(())
}

fn chunk_value(v: &mut Value, schema: &Schema, ty: &Type, sink: &mut dyn TreeSink) -> Result<()> {
    let mut ls = large_positions(schema, v, ty);
    ls.sort_by_key(|l| std::cmp::Reverse(l.path.0.len()));
    for l in &ls {
        chunk_one(v, l, sink)?;
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

/// Chunks the large positions of an op's value (untyped writes are classified as `any`).
pub(crate) fn chunk_op(op: &mut PathOp, schema: Option<&Schema>, ak: &str, sink: &mut dyn TreeSink) -> Result<()> {
    let core = osis_schema::core_schema();
    let (s, root): (&Schema, Type) = match schema.and_then(|s| s.aspects.get(ak).map(|a| (s, a.ty.clone()))) {
        Some(x) => x,
        None => (core, Type::Any),
    };
    let ty = if op.path.is_empty() { root } else { type_at(s, &root, &schema_path(&op.path)).map(|x| x.0).unwrap_or(Type::Any) };
    match &mut op.op {
        Op::Set(v) | Op::Replace(v) | Op::Add(v) => chunk_value(v, s, &ty, sink),
        _ => Ok(()),
    }
}

impl Engine {
    /// Reads a chunked large value of thing `tid` back whole.
    pub fn read_large(&mut self, tid: &Tid, link: &Link) -> Result<Value> {
        self.read_large_max(tid, link, MAX_READ)
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

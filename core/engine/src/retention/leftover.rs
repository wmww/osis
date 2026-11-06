//! Leftovers (spec/crdt.md §4.7, issues/drop-rejoin-robust.md item 2): a part whose values went
//! (expired, purged, a snapshot carrying purged values, a waiting part a held request names) is
//! kept as its body with every value-carrying write value-less, one row per (commit, aspect)
//! (`records::LEFTOVER`), and read as the held body (`apply::each_held_piece`). Nothing else of
//! it is kept: a leftover holds stamps, dots, resets, flags and positions, never a value.

use crate::engine::index::Rec;
use crate::engine::records;
use crate::engine::{Gives, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Value};
use osis_crdt::Fragment;
use osis_store::Shred;

/// A leftover: the stripped fragment and, a snapshot's, its frontiers and `Absorbed`.
pub(crate) struct Leftover {
    pub fragment: Fragment,
    pub gives: Option<Gives>,
}

impl Leftover {
    fn encode(&self) -> Result<Vec<u8>> {
        let body = Value::Bytes(crate::engine::state::encode(&self.fragment)?);
        let v = match &self.gives {
            None => Value::List(vec![Value::Int(0), body]),
            Some((fr, abs)) => Value::List(vec![Value::Int(1), fr.to(), abs.to(), body]),
        };
        Ok(osis_base::encode(&v))
    }

    fn decode(b: &[u8]) -> Result<Leftover> {
        let bad = || Error::Corrupt("leftover");
        let v = osis_base::decode(b, &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: osis_base::format::MAX_BLOB }).map_err(|_| bad())?;
        let Value::List(items) = &v else { return Err(bad()) };
        let (gives, body) = match items.as_slice() {
            [Value::Int(0), Value::Bytes(b)] => (None, b),
            [Value::Int(1), fr, abs, Value::Bytes(b)] => (Some((Rec::from(fr).ok_or_else(bad)?, Rec::from(abs).ok_or_else(bad)?)), b),
            _ => return Err(bad()),
        };
        Ok(Leftover { fragment: crate::engine::state::decode(body)?, gives })
    }
}

/// The leftover of part `ai` of `c` on `(tid, ak)`, if kept (an applied part's, `Meta::stripped`,
/// or a waiting part's).
pub(crate) fn get(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize) -> Result<Option<Leftover>> {
    tx.txn.get_local(&records::leftover_key(tid, ak, c, ai))?.as_deref().map(Leftover::decode).transpose()
}

/// Keeps `l` as the leftover of part `ai` of `c` (replacing one kept), in the aspect's class.
pub(crate) fn put(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize, l: &Leftover) -> Result<()> {
    let key = records::leftover_key(tid, ak, c, ai);
    let enc = l.encode()?;
    tx.core.copy_index.remove(c);
    let memory = tx.txn.is_memory_aspect(tid, ak);
    tx.in_class(memory, |tx| Ok(tx.txn.put_local(&key, &enc, Shred::Yes)?))
}

/// Forgets the leftover of part `ai` of `c`, shredded.
pub(crate) fn remove(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize) -> Result<()> {
    tx.core.copy_index.remove(c);
    tx.txn.remove_local(&records::leftover_key(tid, ak, c, ai), Shred::Yes)?;
    Ok(())
}

/// Whether a leftover of part `ai` of `c` is kept.
pub(crate) fn has(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize) -> Result<bool> {
    Ok(tx.txn.get_local(&records::leftover_key(tid, ak, c, ai))?.is_some())
}

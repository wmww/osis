//! Leftovers (spec/crdt.md §4.7, issues/drop-rejoin-robust.md item 2): a part whose values went
//! (expired, purged, a snapshot carrying purged values, a waiting part a held request names) is
//! kept as its body without the writes gone here, one row per (commit, aspect)
//! (`records::LEFTOVER`), and read as the held body (`apply::each_held_piece`). Nothing else of
//! it is kept: a leftover holds stamps, dots, resets, flags and positions, never a value.

use crate::engine::index::Rec;
use crate::engine::records;
use crate::engine::{Gives, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Value};
use osis_crdt::Fragment;
use osis_store::Shred;

/// A leftover: the stripped fragment and, a snapshot's, its frontiers, `Absorbed` and facts, and
/// the gone-list entries its strips took writes of (`taken`): a snapshot's leftover lacks a write
/// no longer gone while one of them is off the list (`short`).
pub(crate) struct Leftover {
    pub fragment: Fragment,
    pub gives: Option<Gives>,
    pub taken: Vec<crate::engine::Owned>,
}

impl Leftover {
    fn encode(&self) -> Result<Vec<u8>> {
        let body = Value::Bytes(crate::engine::state::encode(&self.fragment)?);
        let taken = Value::Bytes(super::encode_owned(&self.taken));
        let v = match &self.gives {
            None => Value::List(vec![Value::Int(0), body, taken]),
            Some((fr, abs, facts)) => Value::List(vec![Value::Int(1), fr.to(), abs.to(), facts.to(), body, taken]),
        };
        Ok(osis_base::encode(&v))
    }

    fn decode(b: &[u8]) -> Result<Leftover> {
        let bad = || Error::Corrupt("leftover");
        let v = osis_base::decode(b, &osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB)).map_err(|_| bad())?;
        let Value::List(items) = &v else { return Err(bad()) };
        let (gives, body, taken) = match items.as_slice() {
            [Value::Int(0), Value::Bytes(b), Value::Bytes(t)] => (None, b, t),
            [Value::Int(1), fr, abs, facts, Value::Bytes(b), Value::Bytes(t)] => (Some((Rec::from(fr).ok_or_else(bad)?, Rec::from(abs).ok_or_else(bad)?, Rec::from(facts).ok_or_else(bad)?)), b, t),
            _ => return Err(bad()),
        };
        Ok(Leftover { fragment: crate::engine::state::decode(body)?, gives, taken: super::decode_owned(taken)? })
    }

    /// Whether a snapshot's leftover lacks a write that is no longer gone (an entry it was
    /// stripped for left the list `list`: its purge fell): it counts as never received whole,
    /// read meanwhile (spec/permissions.md §6).
    pub fn short(&self, list: &[crate::engine::Owned]) -> bool {
        self.gives.is_some() && self.taken.iter().any(|o| list.binary_search(o).is_err())
    }
}

/// The leftover of part `ai` of `c` on `(tid, ak)`, if kept (an applied part's, `Hold::Leftover`,
/// or a waiting part's).
pub(crate) fn get(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize) -> Result<Option<Leftover>> {
    tx.txn.get_local(&records::leftover_key(tid, ak, c, ai))?.as_deref().map(Leftover::decode).transpose()
}

/// Keeps `l` as the leftover of part `ai` of `c` (replacing one kept), in the aspect's class.
pub(crate) fn put(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize, l: &Leftover) -> Result<()> {
    let key = records::leftover_key(tid, ak, c, ai);
    let enc = l.encode()?;
    tx.core.note_kept_part(tid, ak, c, ai);
    tx.core.bodies_rewritten.push((*tid, ak.clone(), *c));
    let memory = ak.ephemeral();
    tx.in_class(memory, |tx| Ok(tx.txn.put_local(&key, &enc, Shred::Yes)?))
}

/// Forgets the leftover of part `ai` of `c`, shredded.
pub(crate) fn remove(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize) -> Result<()> {
    tx.core.note_kept_part(tid, ak, c, ai);
    tx.core.bodies_rewritten.push((*tid, ak.clone(), *c));
    tx.txn.remove_local(&records::leftover_key(tid, ak, c, ai), Shred::Yes)?;
    Ok(())
}

/// Whether a leftover of part `ai` of `c` is kept.
pub(crate) fn has(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize) -> Result<bool> {
    Ok(tx.txn.get_local(&records::leftover_key(tid, ak, c, ai))?.is_some())
}

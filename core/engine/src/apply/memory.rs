//! The node cap's measures of memory commits (spec/sync.md §9 Caps, notes/ephemeral.md Node
//! cap): what a held part costs a holder (`part_charge`, counted from Core's rows by
//! `Engine::memory_charge`) and a bound on it from the part's bytes alone (`part_bound`), so
//! `Engine::ingest_memory` decodes nothing past the room it is given.

use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::CommitId;
use osis_commit::CommitBlob;

/// Copies a holder keeps of a received part's writes, each counted by the node cap: the
/// decoded part and the joined state.
const HELD_COPIES: usize = 2;

/// Bytes a holder spends per held part past its fragments (the part's and aspect's records, the
/// header's aspect entry), as the node cap counts it. Resource estimate, measured
/// (`scale::eph_decoded_memory`, aspects shape: about 2.3 KiB of RSS per part with one small
/// write, release, x86-64): 0 leaves a commit of many small aspects counted at a tenth of what
/// it holds; infinity fills the cap with a label's first commit.
pub const PART_OVERHEAD: usize = 2048;

/// What a held part costs: its decoded heap size (`heap`, at least its encoded `bytes`) in each
/// copy kept, weighed as a part (`part_weight`).
pub(crate) fn part_charge(heap: usize, bytes: usize) -> u64 {
    part_weight(heap.max(bytes).saturating_mul(HELD_COPIES)) as u64
}

/// A part of `bytes` with the per-part overhead a holder's cap charges (`PART_OVERHEAD`). Shared
/// by the node cap (`part_charge`) and an author's compaction trigger, so the trigger weighs per
/// part what holders are charged: else a holder of many small parts fills its cap before the
/// snapshot comes.
pub(crate) fn part_weight(bytes: usize) -> usize {
    bytes.saturating_add(PART_OVERHEAD)
}

/// An upper bound on `part_charge` of part `p` once decoded, from its bytes alone
/// (`osis_crdt::decoded_bound`): a part of tiny map entries decodes to about 200 times its size.
pub(crate) fn part_bound(p: &osis_commit::Part) -> Result<u64> {
    let heap = osis_crdt::decoded_bound(&p.delta).map_err(|_| Error::BadInput("ephemeral part not one CBOR value"))?;
    let recs = records_bytes(p);
    Ok(part_charge(heap.saturating_add(recs), p.delta.len().saturating_add(recs)))
}

/// The encoded bytes of the records beside part `p`: held as ephemeral things while the commit
/// is, so the node cap counts them with the part (a record decoded is about its encoded size).
pub(crate) fn records_bytes(p: &osis_commit::Part) -> usize {
    p.records.iter().fold(0usize, |n, r| n.saturating_add(osis_base::encode(&r.to_value()).len()))
}

/// What the parts of `blob` not held or dropped here could cost decoded (`part_bound`): what
/// ingesting it may decode.
pub(crate) fn new_parts_bound(tx: &Tx<'_>, blob: &CommitBlob) -> Result<u64> {
    let known = tx.core.ix.commits.get(&blob.id());
    let mut sum = 0u64;
    for p in &blob.parts {
        if known.is_some_and(|m| !m.missing.contains(&p.ai)) {
            continue;
        }
        sum = sum.saturating_add(part_bound(p)?);
    }
    Ok(sum)
}

impl Engine {
    /// What held memory commit `id` costs a holder, as the node cap counts it (spec/sync.md §9
    /// Caps): per held part, its decoded heap size and records in each copy kept and
    /// `PART_OVERHEAD` (`part_charge`). 0 when not held. Decodes its held parts again.
    pub fn memory_charge(&mut self, id: &CommitId) -> Result<u64> {
        let Some(m) = self.core.ix.commits.get(id).filter(|m| m.view.memory).cloned() else { return Ok(0) };
        self.run(|tx| {
            tx.set_memory();
            let Some(blob) = tx.get_commit(id)? else { return Ok(0) };
            let ais: std::collections::BTreeSet<usize> = blob.parts.iter().map(|p| p.ai).filter(|ai| m.holds(*ai)).collect();
            let mut sum = 0u64;
            for ai in ais {
                let mut heap = 0usize;
                crate::apply::each_held_piece(tx, id, ai, &mut |_, f| {
                    heap = heap.saturating_add(f.approx_bytes());
                    Ok(())
                })?;
                let (recs, bytes) = blob.parts.iter().filter(|p| p.ai == ai).fold((0usize, 0usize), |(r, b), p| (r.saturating_add(records_bytes(p)), b.saturating_add(p.delta.len())));
                sum = sum.saturating_add(part_charge(heap.saturating_add(recs), bytes.saturating_add(recs)));
            }
            Ok(sum)
        })
    }
}

//! Memory class for node-sync (spec/sync-compaction.md §2, notes/ephemeral.md): what node-sync takes from
//! Core besides the ordinary change marks (commits forgotten with why, aspects whose snapshots
//! fell invalid), the node cap's measures of memory commits (what a held part costs a holder,
//! `part_charge`, and a bound on it from the part's bytes alone, `part_bound`, so
//! `Engine::ingest_memory` decodes nothing past the room it is given). The compaction trigger,
//! durable and ephemeral alike: `retention::compact`.

use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::CommitId;
use osis_commit::CommitBlob;
use std::collections::BTreeSet;

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
/// by the node cap (`part_charge`) and the compaction trigger, so the trigger weighs per part
/// what holders are charged: else a holder of many small parts fills its cap before the
/// snapshot comes.
pub(crate) fn part_weight(bytes: usize) -> usize {
    bytes.saturating_add(PART_OVERHEAD)
}

/// An upper bound on `part_charge` of part `p` once decoded, from its bytes alone
/// (`osis_crdt::decoded_bound`): a part of tiny map entries decodes to about 200 times its size.
/// Its pages are not counted (`pages_bound`).
pub(crate) fn part_bound(p: &osis_commit::Part) -> Result<u64> {
    let heap = osis_crdt::decoded_bound(&p.delta).map_err(|_| Error::BadInput("ephemeral part not one CBOR value"))?;
    Ok(part_charge(heap, p.delta.len()))
}

/// What a walk calls per page reached (`reach::walk`): its blob, its plaintext.
pub(crate) type PageVisit<'a> = dyn FnMut(&[u8], &[u8]) -> Result<()> + 'a;

/// Each page and link page held here that a paged part's `delta` links (spec/crdt.md §8), with
/// its plaintext: a link from the delta or a page whose held blob is no tree node
/// (`reach::walk`); a large value's root is no page, and nothing below it is visited. A delta
/// or page that is not one CBOR value is `BadInput`.
pub(crate) fn each_page(tx: &mut Tx<'_>, delta: &[u8], f: &mut PageVisit<'_>) -> Result<()> {
    let limits = osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: delta.len() };
    osis_base::visit_links(delta, &limits, &mut |_| {}).map_err(|_| Error::BadInput("part not one CBOR value"))?;
    super::reach::walk_deltas(tx, &[delta], false, f).map(|_| ())
}

/// What the parts of `blob` not held or dropped here could cost decoded (`part_bound`), the
/// pages held they link included (`each_page`, each by its plaintext's heads), and the bytes
/// their large values may still bring (`reach::unheld_bytes`, from their roots' lengths): what
/// ingesting it may decode and fetch.
pub(crate) fn new_parts_bound(tx: &mut Tx<'_>, blob: &CommitBlob) -> Result<u64> {
    let known = tx.core.ix.commits.get(&blob.id()).map(|m| m.missing_parts().collect::<BTreeSet<usize>>());
    let parts: Vec<&osis_commit::Part> = blob.parts.iter().filter(|p| known.as_ref().is_none_or(|missing| missing.contains(&p.ai))).collect();
    let mut sum = 0u64;
    for p in &parts {
        sum = sum.saturating_add(part_bound(p)?);
    }
    let deltas: Vec<&[u8]> = parts.iter().map(|p| p.delta.as_slice()).collect();
    let w = super::reach::walk_deltas(tx, &deltas, false, &mut |_, pt| {
        let heap = osis_crdt::decoded_bound(pt).map_err(|_| Error::BadInput("ephemeral page not one CBOR value"))?;
        sum = sum.saturating_add(part_charge(heap, pt.len()));
        Ok(())
    })?;
    Ok(sum.saturating_add(super::reach::unheld_bytes(tx, &w.roots)?))
}

/// What a received memory commit meets before anything of it is decoded (spec/sync-compaction.md §2 caps),
/// in stages: its header lists resolved, then every page and large value root its parts link
/// held (`reach::walk`), else it waits for them, nothing decoded (`Some(Pending)`); then its
/// `new_parts_bound` (parts, pages, and what its values' roots say the rest of their trees
/// holds) within the room node-sync gave (`Core::memory_room`), else `TooLarge` and nothing of
/// it kept, no chunk of it fetched. Admitted, its value trees are fetched at once
/// (`reach::Walks::trees_of`). Without a room (a re-examination) it is left waiting: node-sync
/// applies waiting memory commits itself, each within the room its label has then
/// (`Engine::apply_waiting_memory`). `None`: go on. `signed`: its signature's verdict, as
/// reached before (`signature`) and after.
pub(crate) fn memory_gate(tx: &mut Tx<'_>, blob: &mut CommitBlob, id: &CommitId, signed: &mut Option<osis_commit::Signed>) -> Result<Option<crate::Ingested>> {
    let pending = tx.core.ix.pending.get(id).cloned();
    // only a commit its author signed is kept waiting (as `examine` keeps one): an author not
    // held makes it unjudgeable there, nothing kept; an epoch not held, pending unverified there
    let Some(author) = tx.core.created(&blob.header.author).cloned() else { return Ok(None) };
    if let Some(vk) = super::author_key(tx.core, &blob.header, &blob.sigs, &author)? {
        *signed = Some(super::check_signature(tx, blob, id, &vk, *signed)?);
    }
    if !blob.header.is_resolved() {
        // no dedup secret: examine finds it unjudgeable before it decodes anything
        let Some(dedup) = tx.core.dedup(&blob.header.actor) else { return Ok(None) };
        match blob.header.resolve(&mut crate::engine::blobs::TxBlobs::new(&mut tx.blobs, true), &dedup) {
            Ok(()) => {}
            Err(e) if super::is_missing_page(&e) => return wait(tx, blob, id, *signed).map(Some),
            Err(e) => return Err(e.into()),
        }
    }
    // a held commit's late parts wait alone for their pages (`examine`), decoded no further
    // than the held pages `new_parts_bound` counts
    let held = tx.core.ix.commits.contains_key(id);
    if !held && super::reach::walk(tx, blob, false, &mut |_, _| Ok(()))?.missing().next().is_some() {
        return wait(tx, blob, id, *signed).map(Some);
    }
    let Some(room) = tx.core.memory_room else {
        return Ok(Some(crate::Ingested::Pending(*id, pending.unwrap_or(crate::Reason::Unexamined))));
    };
    if new_parts_bound(tx, blob)? > room {
        if super::drop_pending(tx, id)? {
            super::keys::forget_unchecked(tx, id)?;
        }
        return Ok(Some(crate::Ingested::TooLarge(*id)));
    }
    tx.core.walks.trees_of(*id);
    Ok(None)
}

/// Memory commit `id` waits for blobs its header names, nothing of it decoded.
fn wait(tx: &mut Tx<'_>, blob: &CommitBlob, id: &CommitId, signed: Option<osis_commit::Signed>) -> Result<crate::Ingested> {
    super::pend(tx, id, osis_store::PendingKind::Pending, signed, &blob.encode(), crate::Reason::WaitBlobs, Some(&blob.header))?;
    Ok(crate::Ingested::Pending(*id, crate::Reason::WaitBlobs))
}

impl Engine {
    /// What held memory commit `id` costs a holder, as the node cap counts it (spec/sync-compaction.md §2
    /// Caps): per held part, a leftover included (expired, purged), its decoded heap size in each
    /// copy kept and `PART_OVERHEAD` (`part_charge`). 0 when not held. Decodes its held parts again.
    pub fn memory_charge(&mut self, id: &CommitId) -> Result<u64> {
        let Some(m) = self.core.ix.commits.get(id).filter(|m| m.view.memory).cloned() else { return Ok(0) };
        self.run(|tx| {
            tx.set_memory();
            let Some(blob) = tx.get_commit(id)? else { return Ok(0) };
            let ais: BTreeSet<usize> = (0..m.view.aspects.len()).filter(|ai| m.holds(*ai)).collect();
            let mut sum = 0u64;
            for ai in ais {
                let mut heap = 0usize;
                crate::apply::each_held_piece(tx, id, ai, &mut |_, f| {
                    heap = heap.saturating_add(f.approx_bytes());
                    Ok(())
                })?;
                let bytes = blob.part(ai).map_or(0, |p| p.delta.len());
                sum = sum.saturating_add(part_charge(heap, bytes));
            }
            Ok(sum)
        })
    }

    /// What the parts of `blob` could cost decoded (`part_bound`), from their bytes alone: (the
    /// sum, the largest), a part that is not one CBOR value counting `u64::MAX`. No part past
    /// the room given is decoded (`ingest_memory`), so one whose bound passes a label's whole
    /// cap is never held under it.
    pub fn memory_bound(blob: &CommitBlob) -> (u64, u64) {
        blob.parts.iter().map(|p| part_bound(p).unwrap_or(u64::MAX)).fold((0, 0), |(s, m), b| (s.saturating_add(b), m.max(b)))
    }

    /// Whether memory commit `id` is held here (any part, or pending).
    pub fn holds_memory(&self, id: &CommitId) -> bool {
        self.core.ix.commits.get(id).is_some_and(|m| m.view.memory)
    }

    /// Whether memory commit `id` is held with something of it to keep or serve: a part held,
    /// or waiting. A commit known only for a part dropped while invalid holds nothing
    /// (`retention::memory::kept_invalid`): its entries cost no cap and are served by nobody here.
    pub fn memory_body_held(&self, id: &CommitId) -> bool {
        self.core.ix.commits.get(id).is_some_and(|m| m.view.memory && !crate::retention::kept_invalid(m)) || self.core.ix.pending.contains_key(id)
    }

    /// Whether memory commit `id` waits here (pending or parked): not fully checked yet.
    pub fn memory_pending(&self, id: &CommitId) -> bool {
        self.core.ix.pending.contains_key(id)
    }

    /// The blob of held memory commit `id` (header and the parts held), for the lane to place.
    pub fn memory_blob(&mut self, id: &CommitId) -> Result<Option<CommitBlob>> {
        if !self.holds_memory(id) {
            return Ok(None);
        }
        let id = *id;
        self.run(|tx| {
            tx.set_memory();
            Ok(tx.get_commit(&id)?.map(std::sync::Arc::unwrap_or_clone))
        })
    }

    /// Held memory commits: id, how many of its parts are held, whether this node authored it
    /// (tests, diagnostics).
    pub fn memory_commits(&self) -> Vec<(CommitId, usize, bool)> {
        let me = self.core.me();
        self.core.ix.commits.iter().filter(|(_, m)| m.view.memory).map(|(id, m)| (*id, (0..m.view.aspects.len()).filter(|ai| m.holds(*ai)).count(), Some(m.view.author) == me)).collect()
    }

    /// Writes a fresh snapshot of each aspect a held valid memory compaction snapshot turned
    /// invalid on (`Core::fallen`; a compactor's demotion not listing it, spec/permissions.md
    /// §5.2): its covered bodies were forgotten here and deleted at peers by any writer, so a
    /// writer that still holds a valid memory part of the aspect writes what it holds
    /// (spec/sync-compaction.md §2), stamped after every held snapshot. Run by `tick`.
    pub(crate) fn resnapshot_fallen(&mut self) -> Result<()> {
        let out = self.core.fallen.clone();
        for (tid, ak) in &out {
            let holds_valid = self.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().any(|(_, c)| {
                self.core.ix.commits.get(c).is_some_and(|m| m.view.memory && m.aspect(tid, ak).is_some_and(|ai| m.holds(ai) && m.valid_at(ai)))
            });
            if !holds_valid {
                continue;
            }
            // a node that may not write the aspect leaves it to the authors
            match self.snapshot(tid, ak) {
                Ok(_) | Err(Error::Permission { .. }) => {}
                Err(e) => return Err(e),
            }
        }
        self.core.fallen.retain(|x| !out.contains(x));
        Ok(())
    }
}

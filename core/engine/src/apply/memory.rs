//! Memory class for node-sync (spec/sync.md §9, notes/ephemeral.md): what node-sync takes from
//! Core besides the ordinary change marks (commits forgotten with why, aspects whose snapshots
//! fell invalid), the node cap's measures of memory commits (what a held part costs a holder,
//! `part_charge`, and a bound on it from the part's bytes alone, `part_bound`, so
//! `Engine::ingest_memory` decodes nothing past the room it is given), coalescing (one snapshot
//! of an aspect's unsent own commits) and the compaction trigger.

use crate::engine::{Engine, MemoryDrop, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid};
use osis_commit::{CommitBlob, Form};
use std::collections::{BTreeMap, BTreeSet};

/// Copies a holder keeps of a received part's writes, each counted by the node cap: the
/// decoded part and the joined state.
const HELD_COPIES: usize = 2;

/// Bytes a holder spends per held part past its fragments (the part's and aspect's records, the
/// header's aspect entry), as the node cap counts it. Resource estimate, measured
/// (`scale::eph_decoded_memory`, aspects shape: about 2.3 KiB of RSS per part with one small
/// write, release, x86-64): 0 leaves a commit of many small aspects counted at a tenth of what
/// it holds; infinity fills the cap with a label's first commit.
pub const PART_OVERHEAD: usize = 2048;

/// A node compacts a memory aspect once the bodies held of it cost more than this many times a
/// snapshot of it (spec/sync.md §9). Performance switch between correct strategies: 0 compacts
/// whenever two bodies are held (at every write), infinity never (bodies pile up to the node
/// and host caps, past which entries are refused). Rebuilds cost O(1) per byte written for any
/// value above 1; a host cap of this many times the sum of the aspects' snapshots holds every
/// entry.
pub const FACTOR: usize = 2;

/// Bytes charged per held memory commit besides its parts (`part_weight`) when a node weighs
/// the bodies it holds against their snapshot: about a host's per-entry and log record overhead
/// plus the commit header. Performance switch: 0 lets small writes pile up as entries whose
/// overhead dwarfs their bytes (a host's cap fills with overhead the trigger never sees),
/// infinity compacts at every write.
pub const ENTRY_CHARGE: usize = 1024;

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

/// A memory aspect's load at this node (`Engine::memory_load`): what the bodies held of it cost
/// (`held`, each its parts' `part_weight` plus `ENTRY_CHARGE`), what a snapshot of it would
/// (`snapshot`), and the costliest body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryLoad {
    pub tid: Tid,
    pub ak: Ak,
    pub held: usize,
    pub snapshot: usize,
    pub largest: usize,
    pub bodies: usize,
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
            let ais: BTreeSet<usize> = blob.parts.iter().map(|p| p.ai).filter(|ai| m.holds(*ai)).collect();
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

    /// Whether memory commit `id` waits here (pending or parked): not fully checked yet.
    pub fn memory_pending(&self, id: &CommitId) -> bool {
        self.core.ix.pending.contains_key(id)
    }

    /// Drops pending memory commit `id` (the lane has no room to keep it waiting, spec/sync.md
    /// §9 Caps): it comes again when the label is reconciled.
    pub fn forget_pending_memory(&mut self, id: &CommitId) -> Result<()> {
        if !self.memory_pending(id) {
            return Ok(());
        }
        let id = *id;
        self.run(|tx| {
            tx.set_memory();
            tx.txn.remove_pending(&id, osis_store::Shred::No)?;
            tx.core.ix.pending.remove(&id);
            tx.core.waits.unpended(&id);
            Ok(())
        })
    }

    /// The blob of held memory commit `id` (header and the parts held), for the lane to place.
    pub fn memory_blob(&mut self, id: &CommitId) -> Result<Option<CommitBlob>> {
        if !self.holds_memory(id) {
            return Ok(None);
        }
        let id = *id;
        self.run(|tx| {
            tx.set_memory();
            tx.get_commit(&id)
        })
    }

    /// Held memory commits: id, how many of its parts are held, whether this node authored it
    /// (tests, diagnostics).
    pub fn memory_commits(&self) -> Vec<(CommitId, usize, bool)> {
        let me = self.tid();
        self.core.ix.commits.iter().filter(|(_, m)| m.view.memory).map(|(id, m)| (*id, (0..m.view.aspects.len()).filter(|ai| m.holds(*ai)).count(), m.view.author == me)).collect()
    }

    /// Memory commits forgotten since the last take, with their header and why (node-sync
    /// releases their charge and deletes their entries at hosts where it may, `MemoryDrop`).
    /// Only commits no longer held are listed. Also frees the received memory things their
    /// commits were the last on (`free_unused_memory`).
    pub fn take_memory_drops(&mut self) -> Vec<(CommitId, std::sync::Arc<osis_commit::Header>, MemoryDrop)> {
        let d = std::mem::take(&mut self.core.memory.dropped);
        let d: Vec<_> = d.into_iter().filter(|(c, _, _)| !self.holds_memory(c)).collect();
        if let Err(e) = self.free_unused_memory() {
            let now = self.now();
            self.core.events.diagnostic(crate::events::Diagnostic { kind: crate::events::DiagnosticKind::EphemeralRefused, tids: Vec::new(), commit: None, peer: None, detail: format!("freeing unused ephemeral records: {e}") }, now);
        }
        d
    }

    /// Frees the memory things received from others (never one this session made: the app's
    /// own) that no held memory commit validly writes any more, among those of the commits
    /// forgotten since the last sweep: a record is no state of its own (every commit about the
    /// thing carries it again), so dropping it loses nothing and received things do not pile up
    /// (notes/ephemeral.md Synced ephemeral data). A durable thing is never
    /// freed.
    pub fn free_unused_memory(&mut self) -> Result<()> {
        let cands = std::mem::take(&mut self.core.memory.unused);
        let mut free = BTreeSet::new();
        for t in cands {
            if !self.core.ix.held.is_memory(&t) {
                continue;
            }
            let made_here = self.core.memory.things.get(&t).is_some_and(|m| m.made_here);
            // a commit counts through a part valid here (any signer's header lists any thing)
            let core = &self.core;
            let on = |c: &CommitId| core.ix.commits.get(c).is_some_and(|m| m.view.memory && m.view.aspects.iter().enumerate().any(|(ai, a)| a.tid == t && m.valid_at(ai)));
            let used = core.on_thing(&t).any(|c| on(&c)) || core.ix.held.first_admin_of(&t).next().is_some();
            if !made_here && !used {
                free.insert(t);
            }
        }
        if free.is_empty() {
            return Ok(());
        }
        self.run(|tx| {
            tx.set_memory();
            crate::apply::free::free(tx, &free)
        })
    }

    /// Memory aspects a held memory snapshot of which turned invalid since the last take (a
    /// compactor's demotion: its frontier lists no memory commit, spec/permissions.md §5.2). The
    /// bodies it covered were forgotten here (durable's residual) and deleted at hosts by any
    /// writer, so a holder of nothing else reads nothing until the authors' copies come back
    /// (they keep their own bodies under others' snapshots, `drop_covered`). A writer that still
    /// holds a valid memory part of the aspect writes a fresh snapshot of what it holds (spec/
    /// sync.md §9 Compaction): the lane uploads it as a new commit (a host's delete tombstone on
    /// the old entries does not stop it) and, stamped after every held snapshot, nothing held
    /// covers it away here. The lane also reconciles the aspects' labels for the rest.
    pub fn take_memory_invalidated(&mut self) -> Result<BTreeSet<(Tid, Ak)>> {
        // taken only once every snapshot is written: an error leaves them for the next step
        let out = self.core.memory.invalidated.clone();
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
        self.core.memory.invalidated.retain(|x| !out.contains(x));
        Ok(out)
    }

    /// The compaction trigger (spec/sync.md §9 Compaction): for each memory aspect changed since
    /// it was last weighed (every one with `force`), when the bodies held of it, two at least,
    /// cost more than `FACTOR` times a snapshot of it, each weighed per part as holders are
    /// charged (`part_weight`) plus `ENTRY_CHARGE`, this node writes the snapshot
    /// (`compaction_snapshot`) if it may. Weighed only once the held cost passes `FACTOR` times
    /// the snapshot cost last weighed, so rebuilds cost O(1) per byte written, amortized. Only
    /// aspects of things in a labeled closure here or never a label entry here (local-only data,
    /// whose bodies would pile up): of a thing that left every closure a snapshot goes nowhere
    /// while the bodies it covered may still travel in a commit that also touches the closure (a
    /// deletion's resets beside the unplacing). The snapshots written (marked changed by their apply: the passes place them).
    pub fn memory_compactions(&mut self, force: bool) -> Result<Vec<CommitId>> {
        let dirty: Vec<(Tid, Ak)> = if force { self.memory_aspects() } else { std::mem::take(&mut self.core.memory.dirty).into_iter().collect() };
        let mut out = Vec::new();
        for (tid, ak) in dirty {
            // out of every closure but once a label entry here: holders may still need its parts
            if (!self.core.ix.held.is_memory(&tid) && self.core.created(&tid).is_none()) || (self.core.memory.synced.contains(&tid) && !self.ephemeral_synced(&tid)) {
                continue;
            }
            let Some((held, largest, bodies)) = self.held_cost(&tid, &ak)? else { continue };
            let last = self.core.memory.weighed.get(&(tid, ak.clone())).copied().unwrap_or(0);
            if !force && (bodies < 2 || held <= FACTOR * last) {
                continue;
            }
            let Some(snapshot) = self.snapshot_cost(&tid, &ak)? else { continue };
            self.core.memory.weighed.insert((tid, ak.clone()), snapshot);
            let _ = largest;
            if bodies == 0 || (!force && (bodies < 2 || held <= FACTOR * snapshot)) {
                continue;
            }
            // a node that may not write the aspect leaves compaction to one that may
            match self.compaction_snapshot(&tid, &ak) {
                Ok(Some(c)) => out.push(c),
                Ok(None) | Err(Error::Permission { .. }) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Every memory aspect with a held commit.
    fn memory_aspects(&self) -> Vec<(Tid, Ak)> {
        self.core.ix.by_aspect.iter().filter(|(_, s)| s.iter().any(|(_, c)| self.holds_memory(c))).map(|(k, _)| k.clone()).collect()
    }

    /// What the write bodies held of memory aspect `(tid, ak)` cost (not expiring ones: a
    /// snapshot covers none; not snapshots: each author keeps its own until its next, so two
    /// authors' would otherwise make each compact the other's forever): (their sum, the
    /// costliest, how many).
    fn held_cost(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<(usize, usize, usize)>> {
        let ids: Vec<(CommitId, usize)> = self
            .core
            .ix
            .by_aspect
            .get(&(*tid, ak.clone()))
            .into_iter()
            .flatten()
            .filter_map(|(_, c)| {
                let m = self.core.ix.commits.get(c).filter(|m| m.view.memory && !m.view.kind.is_compaction())?;
                let ai = m.aspect(tid, ak).filter(|ai| m.holds(*ai))?;
                m.header.aspects.get(ai).filter(|_| m.header.expires.is_none())?;
                Some((*c, ai))
            })
            .collect();
        if ids.is_empty() {
            return Ok(None);
        }
        let (tid, ak) = (*tid, ak.clone());
        self.run(|tx| {
            tx.set_memory();
            // only bodies a snapshot built now would cover: one behind an invalid body of its
            // session (a hole its frontier cannot pass) is held until that body turns valid,
            // and must not make the trigger fire on every step
            let valid_on = |c: &CommitId| tx.core.ix.commits.get(c).is_some_and(|m| m.aspect(&tid, &ak).is_some_and(|ai| m.valid_at(ai) && !m.missing.contains(&ai)));
            let left_out = |c: &CommitId| tx.core.ix.commits.get(c).is_some_and(|m| m.aspect(&tid, &ak).is_some() && m.header.expires.is_some());
            let (_, reflected) = crate::retention::frontiers_now(tx, &tid, &ak, true, &valid_on, &left_out);
            let (mut sum, mut largest) = (0usize, 0usize);
            for (c, ai) in ids.iter().filter(|(c, _)| reflected.contains(c)) {
                let Some(blob) = tx.get_commit(c)? else { continue };
                let bytes: usize = blob.parts.iter().filter(|p| p.ai == *ai).map(|p| p.delta.len().saturating_add(records_bytes(p))).sum();
                let cost = part_weight(bytes).saturating_add(ENTRY_CHARGE);
                sum = sum.saturating_add(cost);
                largest = largest.max(cost);
            }
            let bodies = ids.iter().filter(|(c, _)| reflected.contains(c)).count();
            Ok(Some((sum, largest, bodies)))
        })
    }

    /// What a snapshot of memory aspect `(tid, ak)` would cost as a held body: its state (the
    /// expiring writes left out) encoded unpaged, weighed as a part plus `ENTRY_CHARGE`.
    fn snapshot_cost(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<usize>> {
        let (tid, ak) = (*tid, ak.clone());
        let me = self.tid();
        self.run(|tx| {
            tx.set_memory();
            let Some(st) = crate::retention::memory_state(tx, &tid, &ak)? else { return Ok(None) };
            let cx = osis_commit::writer_ctx(Form::Commit, osis_commit::Kind::ContentSnapshot, osis_base::Ts::default(), me, 0, 0);
            let s = osis_crdt::Snapshot { nonce: [0; osis_crdt::NONCE_LEN], fragment: st, frontiers: osis_crdt::Frontiers::default(), absorbed: BTreeMap::new() };
            // unpaged encoding fails only on a malformed fragment: counted as nothing
            let len = osis_crdt::encode_snapshot(&s, &cx, Some(&mut osis_crdt::Unpaged)).map_or(0, |b| b.len());
            Ok(Some(part_weight(len).saturating_add(ENTRY_CHARGE)))
        })
    }

    /// Per memory aspect held here, its load (tests, diagnostics: within `FACTOR` times the
    /// snapshot plus one body once the trigger ran).
    pub fn memory_load(&mut self) -> Result<Vec<MemoryLoad>> {
        let mut out = Vec::new();
        for (tid, ak) in self.memory_aspects() {
            let Some((held, largest, bodies)) = self.held_cost(&tid, &ak)? else { continue };
            let Some(snapshot) = self.snapshot_cost(&tid, &ak)? else { continue };
            out.push(MemoryLoad { tid, ak, held, snapshot, largest, bodies });
        }
        Ok(out)
    }
}

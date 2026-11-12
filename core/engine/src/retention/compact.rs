//! The compaction trigger (spec/sync.md §7 Trigger), one for durable and ephemeral aspects: a
//! node that may write a content aspect writes a snapshot of it once the bodies it holds of it
//! that the snapshot would drop, two at least, cost more than `FACTOR` times the snapshot. What a
//! body costs is what holders and hosts pay for it: its deltas' bytes and those of the pages or
//! chunks it lists for them (`apply::memory::page_bytes`), `PART_OVERHEAD` per part
//! (`apply::memory::part_weight`, what the node cap charges) and `ENTRY_CHARGE`. Bodies kept by
//! history (a replaced one in history, a live one kept while live, spec/commits.md §5) are not
//! counted: no snapshot drops them.

use crate::apply::memory::{page_bytes, part_weight};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid};
use osis_commit::{CommitBlob, Form, Header};
use std::collections::{BTreeMap, BTreeSet};

/// A node compacts an aspect once the bodies held of it a snapshot would drop cost more than
/// this many times the snapshot (spec/sync.md §7 Trigger). Performance switch between correct
/// strategies: 0 compacts whenever two bodies are held (at every write), infinity never (live
/// bodies pile up: a map's every key written apart keeps its own body, an ephemeral aspect's
/// pile up to the node and host caps, past which entries are refused). Snapshots cost O(1) per
/// byte written, amortized, for any value above 1; a host cap of this many times the sum of the
/// aspects' snapshots holds every ephemeral entry.
pub const FACTOR: usize = 2;

/// Bytes charged per held commit besides its parts (`part_weight`) when a node weighs the bodies
/// it holds against their snapshot: about a host's per-entry and log record overhead plus the
/// commit header. Performance switch: 0 lets small writes pile up as entries whose overhead
/// dwarfs their bytes (a host's cap fills with overhead the trigger never sees), infinity
/// compacts at every write.
pub const ENTRY_CHARGE: usize = 1024;

/// Whether the trigger compacts `ak`: content (not role-class, `created.0` or `retention^.0`),
/// no fixed retention, not a signal (no state).
pub(crate) fn compactable(ak: &Ak) -> bool {
    osis_schema::core_types::is_content(ak.as_str()) && osis_commit::retention::fixed_retention(ak.as_str()).is_none() && !ak.signal()
}

/// The trigger's state per aspect, in memory. An aspect is weighed (its bodies read) only once
/// what it may hold (`held`: the cost found when last weighed plus every body applied since)
/// passes `FACTOR` times the snapshot cost last found, so the work of weighing is O(1) per byte
/// written, amortized; a change that may let bodies count without a write (a validity flip, an
/// expiry, a setting) asks for a weighing (`weigh`).
#[derive(Clone, Debug, Default)]
pub struct Trigger {
    /// Per aspect: the held cost found when last weighed (0 after a snapshot) plus the cost of
    /// every body applied since, and the snapshot cost then.
    est: BTreeMap<(Tid, Ak), (usize, usize)>,
    /// Aspects whose `est` grew, or asked to be weighed, since the last step.
    due: BTreeSet<(Tid, Ak)>,
    /// Aspects weighed at the next step whatever their `est`.
    forced: BTreeSet<(Tid, Ak)>,
}

impl Trigger {
    /// Notes the bodies of applied commit `blob` (header `h`): each compactable aspect it writes
    /// may hold their cost more. A snapshot adds nothing: only writes make one stale, and only
    /// what they add makes the trigger weigh (so two writers never compact each other's
    /// snapshots in turn).
    pub(crate) fn applied(tx: &mut Tx<'_>, h: &Header, blob: &CommitBlob) -> Result<()> {
        if h.kind.is_compaction() || !h.kind.has_own_writes() {
            return Ok(());
        }
        for (ai, a) in h.aspects.iter().enumerate() {
            Trigger::counts(tx, &a.tid, &a.ak, blob, ai)?;
        }
        Ok(())
    }

    /// Part `ai` of `blob` on `(tid, ak)` may count for the trigger from now on (applied, or out
    /// of history): what `(tid, ak)` may hold grows by its cost.
    pub(crate) fn counts(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, blob: &CommitBlob, ai: usize) -> Result<()> {
        if !compactable(ak) {
            return Ok(());
        }
        let bytes = body_bytes(tx, blob, ai)?;
        tx.core.compaction.grow((*tid, ak.clone()), bytes);
        Ok(())
    }

    fn grow(&mut self, k: (Tid, Ak), bytes: usize) {
        let e = self.est.entry(k.clone()).or_default();
        e.0 = e.0.saturating_add(part_weight(bytes).saturating_add(ENTRY_CHARGE));
        self.due.insert(k);
    }

    /// `k` is weighed at the next step whatever its estimate.
    pub(crate) fn weigh(&mut self, k: (Tid, Ak)) {
        if compactable(&k.1) {
            self.forced.insert(k.clone());
            self.due.insert(k);
        }
    }
}

/// The bytes part `ai` of `blob` weighs: its deltas and the pages or chunks held here that the
/// commit lists under that delta's delete keys.
fn body_bytes(tx: &mut Tx<'_>, blob: &CommitBlob, ai: usize) -> Result<usize> {
    let deltas: usize = blob.parts.iter().filter(|p| p.ai == ai).map(|p| p.delta.len()).sum();
    Ok(deltas.saturating_add(page_bytes(tx, &blob.header, ai)?))
}

/// What the bodies held of `(tid, ak)` a snapshot written now would cover and drop cost (not
/// snapshots; not ones within their keep-at-least bound, a live one kept while live included;
/// not ones with an expiry before it, which a snapshot covers only as their leftover; not one
/// behind an invalid or missing body of its session, which its frontier cannot pass: counted,
/// it would fire the trigger at every step): (their sum, the costliest, how many). A leftover
/// counts as a part with no delta bytes.
fn held_cost(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<(usize, usize, usize)> {
    let memory = ak.ephemeral();
    // (commit, part, judged by ID, a snapshot)
    let ids: Vec<(CommitId, usize, bool, bool)> = tx
        .core
        .ix
        .by_aspect
        .get(&(*tid, ak.clone()))
        .into_iter()
        .flatten()
        .filter_map(|(_, c)| {
            let m = tx.core.ix.commits.get(c)?;
            let ai = m.aspect(tid, ak).filter(|ai| m.holds(*ai) && m.valid_at(*ai))?;
            m.header.aspects.get(ai).filter(|_| m.header.expires.is_none() || super::valueless(tx.core, c, ai))?;
            Some((*c, ai, super::snapshot::by_id(m.header.kind, m.header.form), m.view.kind.is_compaction()))
        })
        .collect();
    let valid_on = |c: &CommitId| tx.core.ix.commits.get(c).is_some_and(|m| m.aspect(tid, ak).is_some_and(|ai| m.valid_at(ai) && !m.missing.contains(&ai)));
    let (_, reflected) = super::snapshot::frontiers_now(tx, tid, ak, memory, &valid_on);
    let now = tx.now().0;
    let (mut sum, mut largest, mut bodies) = (0usize, 0usize, 0usize);
    for (c, ai, by_id, snapshot) in ids {
        // not snapshots: each author keeps its own ephemeral one until its next (spec/sync.md §9),
        // so two authors' would make each compact the other's forever
        if snapshot || (!by_id && !reflected.contains(&c)) {
            continue;
        }
        if super::bounds::part_keep(tx, &c, tid, ak)? > now {
            continue;
        }
        let Some(blob) = tx.get_commit(&c)? else { continue };
        let bytes = body_bytes(tx, &blob, ai)?;
        let cost = part_weight(bytes).saturating_add(ENTRY_CHARGE);
        sum = sum.saturating_add(cost);
        largest = largest.max(cost);
        bodies += 1;
    }
    Ok((sum, largest, bodies))
}

/// What a snapshot of `(tid, ak)` would cost as a held body: its state (the expiring writes
/// value-less) encoded, weighed as a part plus `ENTRY_CHARGE`. `None`: no state.
fn snapshot_cost(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, me: Tid) -> Result<Option<usize>> {
    let Some(st) = super::snapshot_state(tx, tid, ak)? else { return Ok(None) };
    let cx = osis_commit::writer_ctx(Form::Commit, osis_commit::Kind::ContentSnapshot, osis_base::Ts::default(), me, 0, 0);
    let s = osis_crdt::Snapshot { nonce: [0; osis_crdt::NONCE_LEN], fragment: st, frontiers: osis_crdt::Frontiers::default(), absorbed: BTreeMap::new() };
    // encoding fails only on a malformed fragment: counted as nothing
    let len = osis_crdt::encode_snapshot(&s, &cx, Some(&mut osis_crdt::Unpaged)).map_or(0, |b| b.len());
    Ok(Some(part_weight(len).saturating_add(ENTRY_CHARGE)))
}

/// An aspect's load at this node (`Engine::compaction_load`): what the bodies held of it a
/// snapshot would drop cost (`held`), what the snapshot would (`snapshot`), the costliest body and
/// how many.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Load {
    pub tid: Tid,
    pub ak: Ak,
    pub held: usize,
    pub snapshot: usize,
    pub largest: usize,
    pub bodies: usize,
}

/// `held_cost` and `snapshot_cost` of `(tid, ak)` in the class of its aspect.
fn load(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, me: Tid) -> Result<Option<Load>> {
    if ak.ephemeral() {
        tx.set_memory();
    }
    let (held, largest, bodies) = held_cost(tx, tid, ak)?;
    let Some(snapshot) = snapshot_cost(tx, tid, ak, me)? else { return Ok(None) };
    Ok(Some(Load { tid: *tid, ak: ak.clone(), held, snapshot, largest, bodies }))
}

impl Engine {
    /// The compaction trigger (spec/sync.md §7 Trigger), at each step: every aspect due whose
    /// estimate passes `FACTOR` times its last snapshot cost (or asked to be weighed) is weighed,
    /// and where the bodies a snapshot would drop, two at least, cost more than `FACTOR` times
    /// it, this node writes the snapshot if it may write the aspect (`snapshot`). Returns the
    /// snapshots written, by aspect: an ephemeral one's covered bodies are dropped as it applies
    /// (`retention::memory::drop_covered`), a durable one's by node-sync.
    pub fn compactions(&mut self) -> Result<Vec<(Tid, Ak, CommitId)>> {
        let due = std::mem::take(&mut self.core.compaction.due);
        let forced = std::mem::take(&mut self.core.compaction.forced);
        let mut out = Vec::new();
        for k in due {
            let (est, last) = self.core.compaction.est.get(&k).copied().unwrap_or_default();
            if !forced.contains(&k) && est <= FACTOR.saturating_mul(last) {
                continue;
            }
            let (tid, ak) = k.clone();
            if self.core.created(&tid).is_none() {
                self.core.compaction.est.remove(&k);
                continue;
            }
            // a node that may not write the aspect leaves compaction to one that may
            let Ok(me) = self.core.writer_for(&tid) else { continue };
            let memory = ak.ephemeral();
            let may = self.run(|tx| super::snapshot::may_snapshot(tx, &tid, &ak, memory, tx.core.hlc.peek()))?;
            if may != crate::engine::write::MayWrite::Yes {
                self.core.compaction.est.remove(&k);
                continue;
            }
            let Some(l) = self.run(|tx| load(tx, &tid, &ak, me))? else {
                self.core.compaction.est.remove(&k);
                continue;
            };
            let fire = l.bodies >= 2 && l.held > FACTOR.saturating_mul(l.snapshot);
            let mut held = l.held;
            if fire {
                match self.snapshot(&tid, &ak) {
                    Ok(Some(c)) => {
                        out.push((tid, ak.clone(), c));
                        held = 0;
                    }
                    Ok(None) | Err(Error::Permission { .. }) => {}
                    Err(e) => return Err(e),
                }
            }
            // an aspect of one body or none weighs again at its next write (O(1)): nothing kept
            if self.core.ix.by_aspect.get(&k).is_none_or(|s| s.len() <= 1) {
                self.core.compaction.est.remove(&k);
            } else {
                self.core.compaction.est.insert(k, (held, l.snapshot));
            }
        }
        Ok(out)
    }

    /// Tests: snapshots every ephemeral aspect held here with a body a snapshot may cover, now.
    #[doc(hidden)]
    pub fn compact_memory_now(&mut self) -> Result<Vec<CommitId>> {
        let aspects: Vec<(Tid, Ak)> = self.core.ix.by_aspect.iter().filter(|(k, s)| k.1.ephemeral() && s.iter().any(|(_, c)| self.holds_memory(c))).map(|(k, _)| k.clone()).collect();
        let mut out = Vec::new();
        for (tid, ak) in aspects {
            if self.core.created(&tid).is_none() || !compactable(&ak) {
                continue;
            }
            let Ok(me) = self.core.writer_for(&tid) else { continue };
            let Some(l) = self.run(|tx| load(tx, &tid, &ak, me))? else { continue };
            if l.bodies == 0 {
                continue;
            }
            match self.snapshot(&tid, &ak) {
                Ok(Some(c)) => out.push(c),
                Ok(None) | Err(Error::Permission { .. }) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Per compactable aspect held here, its load (tests, diagnostics: at a writer within
    /// `FACTOR` times the snapshot plus one body once the trigger ran).
    pub fn compaction_load(&mut self) -> Result<Vec<Load>> {
        let aspects: Vec<(Tid, Ak)> = self.core.ix.by_aspect.keys().filter(|k| compactable(&k.1)).cloned().collect();
        let mut out = Vec::new();
        for (tid, ak) in aspects {
            if self.core.created(&tid).is_none() {
                continue;
            }
            let Ok(me) = self.core.writer_for(&tid) else { continue };
            if let Some(l) = self.run(|tx| load(tx, &tid, &ak, me))? {
                out.push(l);
            }
        }
        Ok(out)
    }
}

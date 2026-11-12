//! The compaction trigger (spec/sync.md §7 Trigger), one for durable and ephemeral aspects: a
//! node that may write a content aspect writes a snapshot of it once the bodies it holds of it
//! that the snapshot would drop, two at least, cost more than `FACTOR` times the snapshot. What a
//! body costs is what holders and hosts pay for it: its deltas' bytes, an ephemeral one's pages
//! (`body_bytes`), `PART_OVERHEAD` per part
//! (`apply::memory::part_weight`, what the node cap charges) and `ENTRY_CHARGE`. Bodies kept by
//! history (a replaced one in history, a live one kept while live, spec/commits.md §5) are not
//! counted: no snapshot drops them.

use crate::apply::memory::{each_page, part_weight};
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
    /// By wall ms, aspects whose live bodies a setting keeps until then (a `keep` until T
    /// alone): uncounted when applied, weighed once the bound passes (`Engine::tick`).
    at: BTreeMap<u64, BTreeSet<(Tid, Ak)>>,
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
        let now = tx.now().0;
        for (ai, a) in h.aspects.iter().enumerate() {
            if !compactable(&a.ak) {
                continue;
            }
            // a live body its setting keeps (spec/commits.md §5 Kept while live) is no snapshot's
            // to drop: it counts once it leaves history (`leaving::left`) or the live bound passes
            let live = super::history::of(tx.core, &a.tid, &a.ak).live_until();
            if live > now {
                Trigger::live_until(tx, (a.tid, a.ak.clone()), live);
                continue;
            }
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

    /// `k` keeps its live bodies until wall ms `live` (past the clock): weighed then, unless
    /// that is never.
    pub(crate) fn live_until(tx: &mut Tx<'_>, k: (Tid, Ak), live: u64) {
        if live < osis_commit::retention::NEVER && compactable(&k.1) {
            tx.core.compaction.at.entry(live).or_default().insert(k);
            tx.core.timer_floor = tx.core.timer_floor.min(live);
        }
    }

    /// Asks a weighing of every aspect whose live bound passed by `now` (`at`).
    pub(crate) fn passed(&mut self, now: u64) {
        let later = self.at.split_off(&now.saturating_add(1));
        for k in std::mem::replace(&mut self.at, later).into_values().flatten() {
            self.weigh(k);
        }
    }

    /// When the first live bound in `at` passes (`u64::MAX`: none).
    pub(crate) fn next_at(&self) -> u64 {
        self.at.keys().next().copied().unwrap_or(u64::MAX)
    }

    /// `k` is weighed at the next step whatever its estimate.
    pub(crate) fn weigh(&mut self, k: (Tid, Ak)) {
        if compactable(&k.1) {
            self.forced.insert(k.clone());
            self.due.insert(k);
        }
    }
}

/// The bytes part `ai` of `blob` weighs: what dropping it frees. Its deltas and the pages held
/// here they link (`apply::memory::each_page`), either class. Not its large values' trees: the
/// live state, so the snapshot, links them while they are live (a replaced value's tree a drop
/// frees goes uncounted, issues/replaced-trees-unweighed.md). A delta that is not one CBOR value
/// weighs its bytes.
fn body_bytes(tx: &mut Tx<'_>, blob: &CommitBlob, ai: usize) -> Result<usize> {
    let listed: BTreeSet<osis_base::BlobId> = blob.header.chunks.iter().map(|ch| ch.blob).collect();
    let mut sum = 0usize;
    for p in blob.parts.iter().filter(|p| p.ai == ai) {
        sum = sum.saturating_add(p.delta.len());
        if listed.is_empty() {
            continue;
        }
        let r = each_page(tx, &p.delta, &listed, &mut |b, _| {
            sum = sum.saturating_add(b.len());
            Ok(())
        });
        match r {
            Ok(()) | Err(Error::BadInput(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(sum)
}

/// The bodies held of `(tid, ak)` a snapshot written now would cover (not snapshots; not ones
/// with an expiry before it, which a snapshot covers only as their leftover; not one behind an
/// invalid or missing body of its session, which its frontier cannot pass: counted, it would
/// fire the trigger at every step), with their part and its cost. A leftover counts as a part
/// with no delta bytes. Whether each is past its keep bound is the caller's (`Load::of`). Where
/// the setting keeps live bodies, only bodies out of history and leftovers are looked at
/// (`droppable`): kept ones are neither read nor walked past, so a weighing costs what it may
/// drop, not the kept history.
fn candidates(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Vec<(CommitId, usize, usize)>> {
    let memory = ak.ephemeral();
    let pool = droppable(tx, tid, ak);
    // (commit, part, judged by ID, a snapshot)
    let ids: Vec<(CommitId, usize, bool, bool)> = pool
        .into_iter()
        .filter_map(|c| {
            let m = tx.core.ix.commits.get(&c)?;
            let ai = m.aspect(tid, ak).filter(|ai| m.holds(*ai) && m.valid_at(*ai))?;
            m.header.aspects.get(ai).filter(|_| m.header.expires.is_none() || super::valueless(tx.core, &c, ai))?;
            Some((c, ai, super::snapshot::by_id(m.header.kind, m.header.form), m.view.kind.is_compaction()))
        })
        .collect();
    // counted: tests read how many bodies the trigger weighs
    crate::costs::count("compact: bodies weighed", ids.len() as u64);
    // per session source of a candidate, the last counter to walk to
    let mut upto: BTreeMap<osis_crdt::Source, u64> = BTreeMap::new();
    for (c, ai, by_id, snapshot) in &ids {
        if *by_id || *snapshot {
            continue;
        }
        if let Some(crate::engine::Owned::Range { src, lo, .. }) = tx.core.ix.commits.get(c).and_then(|m| crate::engine::Owned::of(&m.header, c, *ai)) {
            let e = upto.entry(src).or_insert(lo);
            *e = (*e).max(lo);
        }
    }
    let valid_on = |c: &CommitId| tx.core.ix.commits.get(c).is_some_and(|m| m.aspect(tid, ak).is_some_and(|ai| m.valid_at(ai) && !m.missing.contains(&ai)));
    let (_, reflected) = super::snapshot::frontiers_upto(tx, tid, ak, memory, &valid_on, Some(&upto));
    let mut out = Vec::new();
    for (c, ai, by_id, snapshot) in ids {
        // not snapshots: each author keeps its own ephemeral one until its next (spec/sync.md §9),
        // so two authors' would make each compact the other's forever
        if snapshot || (!by_id && !reflected.contains(&c)) {
            continue;
        }
        let Some(blob) = tx.get_commit(&c)? else { continue };
        let bytes = body_bytes(tx, &blob, ai)?;
        out.push((c, ai, part_weight(bytes).saturating_add(ENTRY_CHARGE)));
    }
    Ok(out)
}

/// The held bodies of `(tid, ak)` a snapshot may drop now. Where its setting keeps live bodies
/// (spec/commits.md §5 Kept while live), a body is kept while live or in history, so only the
/// replaced ones out of history (`leaving` rows up to the cursor) and the leftovers (value-less,
/// named by `Indexes::valueless`) may go; elsewhere every held body (history then keeps only
/// under a setting that changed, or a purge floor: `Load::of` reads the keep bounds).
fn droppable(tx: &Tx<'_>, tid: &Tid, ak: &Ak) -> BTreeSet<CommitId> {
    let key = (*tid, ak.clone());
    let ix = &tx.core.ix;
    if super::history::of(tx.core, tid, ak).live_until() <= tx.now().0 {
        return ix.by_aspect.get(&key).into_iter().flatten().map(|(_, c)| *c).collect();
    }
    let mut out = BTreeSet::new();
    if let Some((_, Some(last))) = ix.leave_from.get(&key).copied() {
        out.extend(ix.leaving.get(&key).into_iter().flat_map(|s| s.range(..=last)).map(|p| p.1));
    }
    for o in ix.valueless.get(&key).into_iter().flatten() {
        match o {
            crate::engine::Owned::Commit(c) => {
                out.insert(*c);
            }
            crate::engine::Owned::Range { src, lo, .. } => {
                let r = ix.ranges.get(&(*tid, ak.clone(), src.clone()));
                out.extend(r.into_iter().flat_map(|m| m.range((*lo, CommitId([0; 32]))..)).take_while(|((l, _), _)| l == lo).map(|((_, c), _)| *c));
            }
            crate::engine::Owned::Dots { src, ctrs } => {
                let Some(r) = ix.ranges.get(&(*tid, ak.clone(), src.clone())) else { continue };
                for ctr in ctrs {
                    // the range holding the counter
                    out.extend(r.range(..=(*ctr, CommitId([0xff; 32]))).next_back().filter(|(_, hi)| *ctr < **hi).map(|((_, c), _)| *c));
                }
            }
        }
    }
    out
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

impl Load {
    /// What the bodies held of `(tid, ak)` a snapshot written now would drop cost (`candidates`
    /// past their keep-at-least bound, a live one kept while live included, read from the
    /// per-commit memo: one judgment per commit), and what the snapshot would, in the class of
    /// its aspect. `None`: no state.
    fn of(e: &mut Engine, tid: &Tid, ak: &Ak, me: Tid) -> Result<Option<Load>> {
        let class = |tx: &mut Tx<'_>| {
            if ak.ephemeral() {
                tx.set_memory();
            }
        };
        let cands = e.run(|tx| {
            class(tx);
            candidates(tx, tid, ak)
        })?;
        let now = e.now().0;
        let (mut held, mut largest, mut bodies) = (0usize, 0usize, 0usize);
        for (c, ai, cost) in cands {
            if e.part_keeps(&c)?.get(ai).copied().unwrap_or(0) > now {
                continue;
            }
            held = held.saturating_add(cost);
            largest = largest.max(cost);
            bodies += 1;
        }
        let Some(snapshot) = e.run(|tx| {
            class(tx);
            snapshot_cost(tx, tid, ak, me)
        })?
        else {
            return Ok(None);
        };
        Ok(Some(Load { tid: *tid, ak: ak.clone(), held, snapshot, largest, bodies }))
    }
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
            // an aspect of one body or none has nothing to compact: weighed again at its next write
            if self.core.created(&tid).is_none() || self.core.ix.by_aspect.get(&k).is_none_or(|s| s.len() <= 1) {
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
            let Some(l) = Load::of(self, &tid, &ak, me)? else {
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
            let Some(l) = Load::of(self, &tid, &ak, me)? else { continue };
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
            if let Some(l) = Load::of(self, &tid, &ak, me)? {
                out.push(l);
            }
        }
        Ok(out)
    }
}

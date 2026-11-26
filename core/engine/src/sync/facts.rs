//! What `read` judges one body at a sync ID on beside `BodyFacts` (spec/sync-judgement.md §2-§3,
//! spec/sync-compaction.md §1), and what moves its judgement: the commits held (a feed) and the
//! falls on a body's aspects. Each field is a direct statement of its spec clause over what the
//! engine holds; every one answers the side that keeps data while it cannot be judged.

use super::{BlobOf, BodyFacts, BodyId, MustNot, PartSet, ReadFacts};
use crate::engine::{DropFor, Engine};
use crate::error::Result;
use osis_base::{BlobId, CommitId, SyncId, Tid};

use std::collections::BTreeSet;
use std::sync::Arc;

impl Engine {
    /// Whether a part of `parts` (a body of `c`) counts as never received here, other than one
    /// sealed below this node's floor (`rotation::floors::sealed_below_floor`): it never opens
    /// here, so it is fetched for nothing. Judged by the shared blob's sections also where the
    /// body is a copy: its readers make that copy from what they open, so one sharing this node's
    /// floor never has the part.
    /// With it, the parts held as leftovers that may count so too (`part_short`).
    fn body_missing(&self, c: &CommitId, m: &crate::engine::Meta, parts: impl IntoIterator<Item = usize>) -> (bool, Vec<usize>) {
        let below = |ai: usize| m.view.aspects.get(ai).is_some_and(|a| crate::rotation::floors::sealed_below_floor(&self.core, c, &a.tid, a.ak.as_str()));
        let parts: Vec<usize> = parts.into_iter().filter(|ai| !below(*ai)).collect();
        (parts.iter().any(|ai| m.missing(*ai)), parts.into_iter().filter(|ai| m.stripped(*ai)).collect())
    }

    /// Whether part `ai` of `c`, held as a snapshot's leftover, lacks a write no longer gone: an
    /// entry of the gone list its strips took left the list (its purge fell), so it counts as never
    /// received whole, its leftover read meanwhile (spec/permissions.md §6), until a copy replaces
    /// it (`retention::takes_late`).
    pub fn part_short(&mut self, c: &CommitId, ai: usize) -> bool {
        let Some(a) = self.core.ix.commits.get(c).and_then(|m| m.header.aspects.get(ai).cloned()) else { return false };
        let list = self.core.ix.gone.get(&(a.tid, a.ak.clone())).cloned().unwrap_or_default();
        self.read(|tx| Ok(crate::retention::leftover::get(tx, &a.tid, &a.ak, c, ai)?.is_some_and(|l| l.short(&list)))).unwrap_or(false)
    }

    /// Whether blob `b`, as opened here, carries a part of its commit that counts as never
    /// received here (`body_missing`, a short leftover among them): fetched, it gives that part,
    /// whether or not it would then leave (spec/sync-judgement.md §3 Dropped bodies).
    pub fn blob_gives_missing(&mut self, b: &BlobId) -> bool {
        let Some(x) = self.blob_of(b) else { return false };
        let Some(m) = self.core.ix.commits.get(&x.commit).cloned() else { return false };
        let (missing, leftovers) = self.body_missing(&x.commit, &m, x.parts.iter().copied());
        missing || leftovers.into_iter().any(|ai| self.part_short(&x.commit, ai))
    }

    /// The things whose read secrets may open what opened blob `b` holds sealed here: the thing
    /// of each part it carries in a section not opened (`BlobOf::parts` lacks it) and not sealed
    /// below this node's floor (it never opens here), whether or not a read secret of it is held
    /// yet. Any part, not only those of a sync ID's body: a commit held from a certificate copy
    /// has its other parts' sections opened from a blob under another sync ID, once their
    /// thing's secrets arrive. Held or missing alike: a part held from another blob goes missing
    /// with no move of `b` (dropped as access is lost), so what `b` waits for is fixed at its
    /// opening. Reads no record: the meta's view.
    pub fn blob_awaits_secrets(&mut self, b: &BlobId) -> BTreeSet<Tid> {
        let Some(o) = self.blob_of(b).filter(|o| !o.sealed.is_empty()) else { return BTreeSet::new() };
        let Some(m) = self.core.ix.commits.get(&o.commit).cloned() else { return BTreeSet::new() };
        let below = |ai: usize| m.view.aspects.get(ai).is_some_and(|a| crate::rotation::floors::sealed_below_floor(&self.core, &o.commit, &a.tid, a.ak.as_str()));
        o.ais.iter().filter(|ai| !o.parts.contains(ai) && !below(**ai)).filter_map(|ai| m.view.aspects.get(*ai).map(|a| a.tid)).collect()
    }

    /// spec/sync-judgement.md §2 must-not-hold (the clauses only the engine judges), §3 Role
    /// entries first, Dropped bodies.
    /// - `must_not`: purged (held requests purge every part of the body, `purged_by`). A blob
    ///   losing to another is per blob (`blob_loses`).
    /// - `own`: written here. `role`: a role commit or a purge request.
    /// - `later_unheld`: snapshots stamped later than it whose part is dropped here, each with
    ///   whether it was dropped as invalid, on the aspects of its parts established uncovered.
    /// - `missing`: a part of the body counts as never received (dropped as covered, its cover
    ///   gone, or found valid again), other than one sealed below this node's floor
    ///   (`rotation::floors::sealed_below_floor`): it never opens here, so it is fetched for
    ///   nothing, and the body is judged with it as every reader judges it.
    ///
    /// Its carriers are a call of their own (`carriers`): they move with every snapshot
    /// extending a chain of covers, which no other fact of a covered body does.
    pub(crate) fn read_facts_now(&mut self, s: &SyncId, id: &BodyId) -> Result<ReadFacts> {
        let c = &id.commit;
        let body: BodyFacts = self.body_facts(s, id)?;
        let mut f = ReadFacts { body, must_not: None, own: false, repair_fresh: Arc::default(), role: false, later_unheld: Vec::new(), missing: false };
        let (Some(b), Some(h)) = (self.sync_body(s, id)?, self.header(c)) else { return Ok(f) };
        let Some(m) = self.core.ix.commits.get(c) else { return Ok(f) };
        f.own = m.origin == crate::events::Origin::Local;
        f.repair_fresh = m.repair().cloned().unwrap_or_default();
        f.role = h.kind.is_role() || m.view.purges;
        let (missing, leftovers) = self.body_missing(c, m, b.parts.iter().copied());
        // a snapshot held as its leftover lacking a write no longer gone counts so too, its
        // leftover read meanwhile
        f.missing = missing || leftovers.into_iter().any(|ai| self.part_short(c, ai));
        let (id, parts) = (*c, b.parts.clone());
        // every part purged: one purged beside a live part strips (`strips`), the rest logged
        // as the rewrite
        let purged = !parts.is_empty() && self.read(|tx| {
            for ai in &parts {
                if crate::retention::purged_by(tx, &h, &id, *ai)?.is_none() {
                    return Ok(false);
                }
            }
            Ok(true)
        })?;
        if purged {
            f.must_not = Some(MustNot::Purged);
        }
        // a later snapshot not held matters only for a delta otherwise established uncovered
        // and not kept (spec/sync-judgement.md §2): so a snapshot of an aspect moves no fact of a
        // covered or kept body
        if f.body.covered == Some(true) || f.body.kept {
            return Ok(f);
        }
        for ai in &b.parts {
            let Some(a) = h.aspects.get(*ai) else { continue };
            if self.part_covered(c, &h, *ai)? != Some(false) {
                continue;
            }
            for x in self.core.ix.snapshots.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).filter(|x| x != c) {
                let Some(sm) = self.core.ix.commits.get(&x) else { continue };
                let later = self.header(&x).is_some_and(|sh| sh.ts > h.ts);
                if later && let Some(sai) = self.header(&x).and_then(|sh| sh.aspect_index(&a.tid, a.ak.as_str())) && let Some(d) = sm.dropped(sai) {
                    f.later_unheld.push((x, d.why == DropFor::Invalid));
                }
            }
        }
        f.later_unheld.sort();
        f.later_unheld.dedup();
        Ok(f)
    }

    /// spec/sync-compaction.md §1 Carriers, for `c`'s body under `s` taken as covered
    /// (`BodyFacts::covered`): per part a held valid snapshot under S covers, the snapshots
    /// covering it; per part dropped as covered, the held valid snapshots of its chain of covers
    /// (spec/permissions.md §5.2). One of each must be held where the body leaves.
    pub(crate) fn carriers_now(&mut self, s: &SyncId, id: &BodyId) -> Result<Vec<BTreeSet<CommitId>>> {
        let c = &id.commit;
        let (Some(b), Some(h)) = (self.sync_body(s, id)?, self.header(c)) else { return Ok(Vec::new()) };
        if !self.core.ix.commits.contains_key(c) {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for ai in &b.parts {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let covered_drop = self.core.ix.commits.get(c).is_some_and(|m| m.dropped(*ai).is_some_and(|d| d.as_cover()));
            let covering: BTreeSet<CommitId> = if covered_drop {
                // the chain of covers it dropped under (spec/permissions.md §5.2): its held valid
                // snapshots carry it
                let carries = |x: &CommitId| self.core.ix.commits.get(x).is_some_and(|sm| sm.view.kind.is_compaction() && sm.aspect(&a.tid, &a.ak).is_some_and(|sai| sm.valid_at(sai) && !sm.is_dropped(sai) && !sm.missing(sai)));
                crate::retention::coverers(&self.core, c, *ai).into_iter().filter(|x| carries(x)).collect()
            } else {
                let mut covering = BTreeSet::new();
                for x in self.core.ix.snapshots.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).filter(|x| x != c).collect::<Vec<_>>() {
                    if self.covered(&x, c, &a.tid, &a.ak)? == Some(true) {
                        covering.insert(x);
                    }
                }
                covering
            };
            if !covering.is_empty() {
                out.push(covering);
            }
        }
        Ok(out)
    }

    /// The deltas of `c`'s body under `s` only a blob carries (spec/sync-judgement.md §2 Per
    /// blob, §3 Neither): kept or holding a live write, and covered by no snapshot under the sync
    /// ID, established as for must-hold. `None` while that is not established (a later snapshot
    /// not judged yet) or `s` carries no body of `c`. An entry under S being fetched or pending is
    /// sync's to know; one not counted here only widens this set, toward keeping.
    pub(crate) fn blob_only(&mut self, s: &SyncId, id: &BodyId) -> Result<Option<PartSet>> {
        let c = &id.commit;
        let (Some(b), Some(h)) = (self.sync_body(s, id)?, self.header(c)) else { return Ok(None) };
        let keeps = self.part_keeps(c)?;
        let mut out = PartSet::new();
        for ai in &b.parts {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let kept = keeps.get(*ai).is_some_and(|k| self.core.time.until(Some(*k)) < *k);
            if !kept && !self.delta_live(c, &a.tid, &a.ak)? {
                continue;
            }
            match self.part_covered(c, &h, *ai)? {
                None => return Ok(None),
                Some(true) => {}
                Some(false) => {
                    out.insert(*ai);
                }
            }
        }
        Ok(Some(out))
    }

    /// Held blob `x` as a carrier of `c`'s body under `s`: a blob of `c` this node opened or
    /// sealed (its delta set checked against the header, never a peer's word), not must-not-hold
    /// (no part of it strips here, `blob_gone`), of the body's kind (only a copy holds a copy's body,
    /// spec/sync-judgement.md §1 Per-sync-ID copies).
    fn carried_by(&self, c: &CommitId, copy: bool, x: &BlobId) -> Option<Arc<BlobOf>> {
        let p = self.core.ix.blob_parts.get(x)?;
        (p.commit == *c && p.of_kind(copy) && !self.blob_gone(x)).then(|| p.clone())
    }

    /// Whether blob `b` holds S's body of its commit (spec/sync-judgement.md §1): a blob of the
    /// body's kind (a per-sync-ID copy or the shared blob) carrying each of its parts that does not
    /// strip here (`bodies::strips`: a strip's rewrite holds the body). A blob not
    /// opened or sealed here holds none.
    pub fn holds_body(&mut self, s: &SyncId, b: &BlobId) -> Result<bool> {
        let Some(id) = self.blob_body(s, b)? else { return Ok(false) };
        let Some(meta) = self.sync_body(s, &id)? else { return Ok(false) };
        Ok(self.body_held_by(&meta, b))
    }

    /// `holds_body` of `meta`, a body of `b`'s commit as the caller holds it (sync read's settled
    /// bodies): reads `b`'s parts and what strips of the commit alone, never how the body was
    /// derived.
    pub fn body_held_by(&self, meta: &super::BodyMeta, b: &BlobId) -> bool {
        let Some(row) = self.core.ix.blob_parts.get(b) else { return false };
        let gone = |ai: &usize| self.core.ix.commits.get(&row.commit).is_some_and(|m| super::bodies::strips(m, *ai));
        // a certificate copy is its body only holding exactly S's cut (spec/permissions.md §4
        // Copies): one blob per distinct cut
        let exact = !meta.certificate || row.parts.iter().all(|ai| meta.parts.contains(ai));
        row.of_kind(meta.copy) && exact && meta.parts.iter().filter(|ai| !gone(ai)).all(|ai| row.parts.contains(ai))
    }

    /// spec/sync-judgement.md §3 Neither: a body a delete removed from S (an entry of it that is
    /// not a certificate copy) is neither logged nor relayed while each of its deltas only a blob
    /// carries is held there by another blob of the commit that is not must-not-hold (one of
    /// `there`, the blobs of `c` held where the delete was) and no held purge request signed by
    /// ones that could hold the right names a delta of it without dropping it.
    pub fn neither(&mut self, s: &SyncId, id: &BodyId, there: &BTreeSet<BlobId>) -> Result<bool> {
        let c = &id.commit;
        let Some(meta) = self.sync_body(s, id)? else { return Ok(false) };
        if meta.certificate {
            return Ok(false);
        }
        let held: PartSet = there.iter().filter_map(|x| self.carried_by(c, meta.copy, x)).flat_map(|x| x.parts.iter().copied().collect::<Vec<_>>()).collect();
        // a blob there holding the whole body carries what only a blob carries of it, whatever that is
        if !meta.parts.is_subset(&held) {
            let Some(only) = self.blob_only(s, id)? else { return Ok(false) };
            if !only.is_subset(&held) {
                return Ok(false);
            }
        }
        let parts: Vec<usize> = meta.parts.iter().copied().collect();
        Ok(!self.named_by_a_fallen_purge(c, &parts)?)
    }

    /// Falls of held parts on commit `c`'s aspects so far, summed (spec/sync-judgement.md §4: a
    /// stand compares marks).
    pub fn body_fall_mark(&mut self, c: &CommitId) -> u64 {
        let Some(h) = self.header(c) else { return 0 };
        h.aspects.iter().map(|a| self.fall_mark(&a.tid, &a.ak)).fold(0u64, u64::saturating_add)
    }
}

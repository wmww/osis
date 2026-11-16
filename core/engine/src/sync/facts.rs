//! What `read` judges one body at a sync ID on beside `BodyFacts` (spec/sync-judgement.md §2-§3,
//! spec/sync-compaction.md §1), and what moves its judgement: the commits held (a feed) and the
//! falls on a body's aspects. Each field is a direct statement of its spec clause over what the
//! engine holds; every one answers the side that keeps data while it cannot be judged.

use super::{BlobOf, BodyFacts, MustNot, PartSet, ReadFacts};
use crate::engine::{DropFor, Engine};
use crate::error::Result;
use osis_base::{BlobId, CommitId, SyncId, Tid};
use osis_commit::Header;
use std::collections::BTreeSet;
use std::sync::Arc;

/// The aspects of a node's card (spec/permissions.md §4).
const CARD: [&str; 3] = ["keys.0", "node.0", "reach.0"];

impl Engine {
    /// Whether a part of `parts` (a body of `c`) counts as never received here, other than one
    /// sealed below this node's floor (`rotation::floors::sealed_below_floor`): it never opens
    /// here, so it is fetched for nothing. Judged by the shared blob's sections also where the
    /// body is a copy: its readers make that copy from what they open, so one sharing this node's
    /// floor never has the part.
    fn body_missing(&self, c: &CommitId, m: &crate::engine::Meta, parts: impl IntoIterator<Item = usize>) -> bool {
        let below = |ai: usize| m.view.aspects.get(ai).is_some_and(|a| crate::rotation::floors::sealed_below_floor(&self.core, c, &a.tid, a.ak.as_str()));
        parts.into_iter().any(|ai| m.missing(ai) && !below(ai))
    }

    /// The things whose read secrets may open what opened blob `b` holds sealed here: the thing
    /// of each part it carries in a section not opened (`BlobOf::parts` lacks it) that counts
    /// missing (`body_missing`), whether or not a read secret of it is held yet. Any part, not
    /// only those of a sync ID's body: an account's rotation goes only under its devices actor's
    /// sync IDs, and its part on the account (`keys.0`) opens from there alone; a commit held
    /// from a certificate copy has its other parts' sections opened from a blob under another
    /// sync ID, once their thing's secrets arrive. Reads no record: the meta's view and missing
    /// parts.
    pub fn blob_awaits_secrets(&mut self, b: &BlobId) -> BTreeSet<Tid> {
        let Some(o) = self.blob_of(b).filter(|o| !o.sealed.is_empty()) else { return BTreeSet::new() };
        let Some(m) = self.core.ix.commits.get(&o.commit).cloned() else { return BTreeSet::new() };
        o.ais.iter().filter(|ai| !o.parts.contains(ai) && self.body_missing(&o.commit, &m, [**ai])).filter_map(|ai| m.view.aspects.get(*ai).map(|a| a.tid)).collect()
    }

    /// spec/sync-judgement.md §2 must-not-hold (the clauses only the engine judges), §3 Role
    /// entries first, Dropped bodies, Neither; spec/sync-compaction.md §1 Carriers.
    /// - `must_not`: purged (a held request purges a part of the body, `purged_by`); another
    ///   node's card commit superseded (`card_superseded`) or ended (`card_ended`). A strict
    ///   subset is per blob (`strict_subset`).
    /// - `own`: written here. `role`: a role commit or a purge request.
    /// - `carriers`: for a covered body, per part a held valid snapshot under S covers, the
    ///   snapshots covering it (one of each must be held where the body leaves); a part dropped
    ///   as covered, the held valid snapshots of its chain of covers (spec/permissions.md §5.2).
    /// - `later_unheld`: snapshots stamped later than it whose part is dropped here, each with
    ///   whether it was dropped as invalid, on the aspects of its parts established uncovered.
    /// - `missing`: a part of the body counts as never received (dropped as covered, its cover
    ///   gone, or found valid again), other than one sealed below this node's floor
    ///   (`rotation::floors::sealed_below_floor`): it never opens here, so it is fetched for
    ///   nothing, and the body is judged with it as every reader judges it.
    pub(crate) fn read_facts_now(&mut self, s: &SyncId, c: &CommitId) -> Result<ReadFacts> {
        let body: BodyFacts = self.body_facts(s, c)?;
        let mut f = ReadFacts { body, must_not: None, own: false, repair_fresh: Arc::default(), role: false, carriers: Vec::new(), later_unheld: Vec::new(), missing: false };
        // a card is judged by its header alone: it is no closure body of S (spec/permissions.md §4)
        if let Some(h) = self.header(c)
            && let Some(node) = self.card_node(s, &h)?
        {
            f.must_not = self.card_must_not(c, &h, &node);
        }
        let (Some(b), Some(m), Some(h)) = (self.sync_body_now(s, c)?, self.core.ix.commits.get(c).cloned(), self.header(c)) else { return Ok(f) };
        f.own = m.origin == crate::events::Origin::Local;
        f.repair_fresh = m.repair.clone().unwrap_or_default();
        f.role = h.kind.is_role() || m.view.purges;
        f.missing = self.body_missing(c, &m, b.parts.iter().copied());
        let (id, parts) = (*c, b.parts.clone());
        let purged = self.read(|tx| {
            for ai in &parts {
                if crate::retention::purged_by(tx, &h, &id, *ai)?.is_some() {
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        if purged {
            f.must_not = Some(MustNot::Purged);
        }
        // carriers matter only for a covered body (spec/sync-compaction.md §1), a later snapshot
        // not held only for a delta otherwise established uncovered (spec/sync-judgement.md §2):
        // so a snapshot of an aspect moves no fact of a body it cannot drop
        let covered = f.body.covered == Some(true);
        for ai in &b.parts {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let dropped = m.dropped(*ai).is_some_and(|d| d.as_cover());
            if covered && dropped {
                // the chain of covers it dropped under (spec/permissions.md §5.2): its held valid
                // snapshots carry it
                let carries = |x: &CommitId| self.core.ix.commits.get(x).is_some_and(|sm| sm.view.kind.is_compaction() && sm.aspect(&a.tid, &a.ak).is_some_and(|sai| sm.valid_at(sai) && !sm.is_dropped(sai) && !sm.missing(sai)));
                let covering: BTreeSet<CommitId> = crate::retention::coverers(&self.core, c, *ai).into_iter().filter(|x| carries(x)).collect();
                if !covering.is_empty() {
                    f.carriers.push(covering);
                }
                continue;
            }
            let uncovered = !covered && self.part_covered(c, &h, *ai)? == Some(false);
            if !covered && !uncovered {
                continue;
            }
            let snaps: Vec<CommitId> = self.core.ix.snapshots.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).filter(|x| x != c).collect();
            let mut covering = BTreeSet::new();
            for x in snaps {
                if covered && self.covered(&x, c, &a.tid, &a.ak)? == Some(true) {
                    covering.insert(x);
                }
                if !uncovered {
                    continue;
                }
                let Some(sm) = self.core.ix.commits.get(&x) else { continue };
                let later = self.header(&x).is_some_and(|sh| sh.ts > h.ts);
                if later && let Some(sai) = self.header(&x).and_then(|sh| sh.aspect_index(&a.tid, a.ak.as_str())) && let Some(d) = sm.dropped(sai) {
                    f.later_unheld.push((x, d.why == DropFor::Invalid));
                }
            }
            if !covering.is_empty() {
                f.carriers.push(covering);
            }
        }
        f.later_unheld.sort();
        f.later_unheld.dedup();
        Ok(f)
    }

    /// The node whose card `h` is, when it is another node's card commit under this node's
    /// account's D's home sync ID (spec/permissions.md §4: a node's `keys.0`, `node.0` and
    /// `reach.0` commits, each touching nothing else, go under D's home sync ID only).
    fn card_node(&mut self, s: &SyncId, h: &Header) -> Result<Option<Tid>> {
        let Some(node) = h.aspects.first().map(|a| a.tid) else { return Ok(None) };
        if node == self.core.id.tid() || !h.aspects.iter().all(|a| a.tid == node && CARD.contains(&a.ak.as_str())) {
            return Ok(None);
        }
        let Some((_, d)) = self.core.account_devices() else { return Ok(None) };
        if self.home_sync_id(&d)? != Some(*s) || !self.is_node(&node)? {
            return Ok(None);
        }
        Ok(Some(node))
    }

    /// The must-not-hold condition another node's card commit `c` meets, if any.
    fn card_must_not(&self, c: &CommitId, h: &Header, node: &Tid) -> Option<MustNot> {
        if self.card_superseded(c, h, node) {
            Some(MustNot::CardSuperseded)
        } else if self.card_ended(h, node) {
            Some(MustNot::CardEnded)
        } else {
            None
        }
    }

    /// spec/sync-judgement.md §2 must-not-hold: another node's card commit once a later valid card
    /// commit of that node writing the same aspect is under the sync ID (an entry of it this node
    /// opened and checked against its header). Every aspect of `c` must be so written.
    fn card_superseded(&self, c: &CommitId, h: &Header, node: &Tid) -> bool {
        h.aspects.iter().all(|a| self.later_card_held(c, h.ts, node, &a.ak))
    }

    /// A valid card commit of `node` stamped after `ts` writing `ak`, other than `c`, with a blob
    /// this node opened (or sealed) holding that part: a commit known by its header alone, or
    /// only claimed by a peer, supersedes nothing.
    fn later_card_held(&self, c: &CommitId, ts: osis_base::Ts, node: &Tid, ak: &osis_base::Ak) -> bool {
        let ix = &self.core.ix;
        ix.by_aspect.get(&(*node, ak.clone())).into_iter().flatten().map(|x| x.1).filter(|x| x != c).any(|x| {
            let (Some(h), Some(ai)) = (self.header(&x), ix.commits.get(&x).and_then(|m| m.aspect(node, ak))) else { return false };
            h.ts > ts
                && h.aspects.iter().all(|a| a.tid == *node && CARD.contains(&a.ak.as_str()))
                && self.judged_valid(&x, &(0..h.aspects.len()).collect::<Vec<_>>())
                && ix.commit_blobs.get(&x).into_iter().flatten().any(|b| ix.blob_parts.get(b).is_some_and(|p| p.parts.contains(&ai)))
        })
    }

    /// spec/sync-judgement.md §2 must-not-hold: another node's card commit, for `node.0` and
    /// `reach.0`, once that node is a node of the account no more: the chain held here names it a
    /// device (creation or a pairing) and D's roster lacks it (spec/permissions.md §5.4, Roster).
    /// A node whose pairing is not held here has ended nothing.
    fn card_ended(&self, h: &Header, node: &Tid) -> bool {
        if !h.aspects.iter().all(|a| matches!(a.ak.as_str(), "node.0" | "reach.0")) {
            return false;
        }
        let Some((p, _)) = self.core.account_devices() else { return false };
        let Some(v) = self.core.account_view(&p) else { return false };
        v.named_device(node) && !v.roster().contains(node)
    }

    /// The deltas of `c`'s body under `s` only a blob carries (spec/sync-judgement.md §2 strict
    /// subset, §3 Neither): kept or holding a live write, and covered by no snapshot under the sync
    /// ID, established as for must-hold. `None` while that is not established (a later snapshot
    /// not judged yet) or `s` carries no body of `c`. An entry under S being fetched or pending is
    /// sync's to know; one not counted here only widens this set, toward keeping.
    fn blob_only(&mut self, s: &SyncId, c: &CommitId) -> Result<Option<PartSet>> {
        let (Some(b), Some(h)) = (self.sync_body_now(s, c)?, self.header(c)) else { return Ok(None) };
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
    /// (no part of it dropped here for good), of the body's kind (only a copy holds a copy's body,
    /// spec/sync-judgement.md §1 Per-sync-ID copies).
    fn carried_by(&self, c: &CommitId, copy: bool, x: &BlobId) -> Option<Arc<BlobOf>> {
        let p = self.core.ix.blob_parts.get(x)?;
        (p.commit == *c && p.of_kind(copy) && !self.blob_dropped(x)).then(|| p.clone())
    }

    /// Whether blob `b` holds S's body of its commit (spec/sync-judgement.md §1): a blob of the
    /// body's kind (a per-sync-ID copy or the shared blob) carrying each of its parts. A blob not
    /// opened or sealed here holds none.
    pub fn holds_body(&mut self, s: &SyncId, b: &BlobId) -> Result<bool> {
        let Some(row) = self.core.ix.blob_parts.get(b).cloned() else { return Ok(false) };
        let Some(meta) = self.sync_body_now(s, &row.commit)? else { return Ok(false) };
        Ok(row.of_kind(meta.copy) && meta.parts.iter().all(|ai| row.parts.contains(ai)))
    }

    /// spec/sync-judgement.md §2 must-not-hold: blob `b` of commit C, whose delta set is a strict
    /// subset of another held blob of C under that sync ID (one of `held`) that is not itself
    /// must-not-hold and whose extra deltas include one only a blob carries. A blob not opened or
    /// sealed here is no blob of C to this node; both are of the body's kind (copy or shared).
    /// Judged over what this node checked (spec/sync-compaction.md §1 Duplicates): the larger
    /// holds each section of `b` this node did not open byte for byte, and its extra deltas are
    /// among those it opened.
    pub fn strict_subset(&mut self, s: &SyncId, b: &BlobId, held: &BTreeSet<BlobId>) -> Result<bool> {
        let Some(mine) = self.core.ix.blob_parts.get(b).cloned() else { return Ok(false) };
        let (c, parts) = (mine.commit, &mine.parts);
        let Some(copy) = self.sync_body_now(s, &c)?.map(|m| m.copy) else { return Ok(false) };
        // a blob of the other kind holds no body of it here (a certificate copy beside the shared
        // blob carries parts S's readers cannot open there, whatever this node opens of it)
        if !mine.of_kind(copy) {
            return Ok(false);
        }
        let larger: Vec<Arc<BlobOf>> = held
            .iter()
            .filter(|x| *x != b)
            .filter_map(|x| self.carried_by(&c, copy, x))
            .filter(|o| parts.is_subset(&o.parts) && o.parts.len() > parts.len() && mine.sealed.is_subset(&o.sealed))
            .collect();
        if larger.is_empty() {
            return Ok(false);
        }
        let Some(only) = self.blob_only(s, &c)? else { return Ok(false) };
        Ok(larger.iter().any(|other| other.parts.difference(parts).any(|ai| only.contains(ai))))
    }

    /// spec/sync-judgement.md §3 Neither: a body a delete removed from S (an entry of it that is
    /// not a certificate copy) is neither logged nor relayed while each of its deltas only a blob
    /// carries is held there by another blob of the commit that is not must-not-hold (one of
    /// `there`, the blobs of `c` held where the delete was) and no held purge request signed by
    /// ones that could hold the right names a delta of it without dropping it.
    pub fn neither(&mut self, s: &SyncId, c: &CommitId, there: &BTreeSet<BlobId>) -> Result<bool> {
        let Some(meta) = self.sync_body_now(s, c)? else { return Ok(false) };
        if meta.certificate {
            return Ok(false);
        }
        let held: PartSet = there.iter().filter_map(|x| self.carried_by(c, meta.copy, x)).flat_map(|x| x.parts.iter().copied().collect::<Vec<_>>()).collect();
        // a blob there holding the whole body carries what only a blob carries of it, whatever that is
        if !meta.parts.is_subset(&held) {
            let Some(only) = self.blob_only(s, c)? else { return Ok(false) };
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

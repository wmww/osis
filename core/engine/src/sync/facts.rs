//! What `read` judges one body at a sync ID on beside `BodyFacts` (spec/sync-judgement.md §2-§3,
//! spec/sync-compaction.md §1), and what moves its judgement: the commits held (a feed) and the
//! falls on a body's aspects. Each field is a direct statement of its spec clause over what the
//! engine holds; every one answers the side that keeps data while it cannot be judged.

use super::{BodyFacts, MustNot, PartSet, ReadFacts};
use crate::engine::{DropFor, Engine};
use crate::error::Result;
use osis_base::{BlobId, CommitId, Role, SyncId, Tid};
use osis_commit::Header;
use std::collections::BTreeSet;

/// The aspects of a node's card (spec/permissions.md §4).
const CARD: [&str; 3] = ["keys.0", "node.0", "reach.0"];

impl Engine {
    /// spec/sync-judgement.md §2 must-not-hold (the clauses only the engine judges), §3 Role
    /// entries first, Dropped bodies, Neither; spec/sync-compaction.md §1 Carriers.
    /// - `must_not`: purged (a held request purges a part of the body, `purged_by`); another
    ///   node's card commit superseded (`card_superseded`) or ended (`card_ended`). A strict
    ///   subset is per blob (`strict_subset_now`).
    /// - `own`: written here. `role`: a role commit or a purge request.
    /// - `carriers`: per part of the body a held valid snapshot under S covers, the snapshots
    ///   covering it (one of each must be held where the body leaves).
    /// - `later_unheld`: snapshots of the body's aspects stamped later than it whose part is
    ///   dropped here, each with whether it was dropped as invalid.
    /// - `missing`: a part of the body counts as never received (dropped as covered, its cover
    ///   gone, or found valid again).
    pub(crate) fn read_facts_now(&mut self, s: &SyncId, c: &CommitId) -> Result<ReadFacts> {
        let body: BodyFacts = self.body_facts_now(s, c)?;
        let mut f = ReadFacts { body, must_not: None, own: false, repair: false, role: false, carriers: Vec::new(), later_unheld: Vec::new(), missing: false };
        // a card is judged by its header alone: it is no closure body of S (spec/permissions.md §4)
        if let Some(h) = self.header(c)
            && let Some(node) = self.card_node(s, &h)?
        {
            f.must_not = self.card_must_not(c, &h, &node);
        }
        let bodies = self.sync_bodies_now(c)?;
        let (Some(b), Some(m), Some(h)) = (bodies.get(s).cloned(), self.core.ix.commits.get(c).cloned(), self.header(c)) else { return Ok(f) };
        f.own = m.origin == crate::events::Origin::Local;
        f.repair = m.repair;
        f.role = h.kind.is_role() || m.view.purges;
        f.missing = b.parts.iter().any(|ai| m.missing(*ai));
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
        for ai in &b.parts {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let snaps: Vec<CommitId> = self.core.ix.snapshots.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).filter(|x| x != c).collect();
            let mut covering = BTreeSet::new();
            for x in snaps {
                if self.covered(&x, c, &a.tid, &a.ak)? == Some(true) {
                    covering.insert(x);
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
                && ix.commit_blobs.get(&x).into_iter().flatten().any(|b| ix.blob_parts.get(b).is_some_and(|p| p.1.contains(&ai)))
        })
    }

    /// spec/sync-judgement.md §2 must-not-hold: another node's card commit, for `node.0` and
    /// `reach.0`, once that node is a node of the account no more after an applied edge write on D
    /// ended its grant (removed it, or its `until` passed). A node never granted on D here (its
    /// grant not applied yet) has ended nothing.
    fn card_ended(&self, h: &Header, node: &Tid) -> bool {
        if !h.aspects.iter().all(|a| matches!(a.ak.as_str(), "node.0" | "reach.0")) {
            return false;
        }
        let Some((_, d)) = self.core.account_devices() else { return false };
        let Some(tl) = self.core.timelines.get(&d) else { return false };
        if !tl.roles_ever(node).contains_key(&d) {
            return false;
        }
        match tl.roster(&d, osis_perm::At::KEYS).get(node) {
            None => true,
            Some(e) => e.role < Role::Read || e.until.is_some_and(|u| self.core.time.until(Some(u.0)) >= u.0),
        }
    }

    /// The deltas of `c`'s body under `s` only a blob carries (spec/sync-judgement.md §2 strict
    /// subset, §3 Neither): kept or holding a live write, and covered by no snapshot under the sync
    /// ID, established as for must-hold. `None` while that is not established (a later snapshot
    /// not judged yet) or `s` carries no body of `c`. An entry under S being fetched or pending is
    /// sync's to know; one not counted here only widens this set, toward keeping.
    fn blob_only(&mut self, s: &SyncId, c: &CommitId) -> Result<Option<PartSet>> {
        let bodies = self.sync_bodies_now(c)?;
        let (Some(b), Some(h)) = (bodies.get(s), self.header(c)) else { return Ok(None) };
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

    /// The parts held blob `x` carries of `c`'s body under `s`: a blob of `c` this node opened or
    /// sealed (its delta set checked against the header, never a peer's word), not must-not-hold
    /// (no part of it dropped here for good), of the body's kind (only a copy holds a copy's body,
    /// spec/sync-judgement.md §1 Per-sync-ID copies).
    fn carried_by(&self, c: &CommitId, copy: bool, x: &BlobId) -> Option<PartSet> {
        let p = self.core.ix.blob_parts.get(x)?;
        (p.0 == *c && p.2 == copy && !self.blob_dropped_now(x)).then(|| p.1.clone())
    }

    /// spec/sync-judgement.md §2 must-not-hold: blob `b` of commit C, whose delta set is a strict
    /// subset of another held blob of C under that sync ID (one of `held`) that is not itself
    /// must-not-hold and whose extra deltas include one only a blob carries. A blob not opened or
    /// sealed here is no blob of C to this node; both are of the body's kind (copy or shared).
    pub(crate) fn strict_subset_now(&mut self, s: &SyncId, b: &BlobId, held: &BTreeSet<BlobId>) -> Result<bool> {
        let Some(mine) = self.core.ix.blob_parts.get(b).cloned() else { return Ok(false) };
        let (c, parts) = (mine.0, &mine.1);
        let Some(copy) = self.sync_bodies_now(&c)?.get(s).map(|m| m.copy) else { return Ok(false) };
        // a blob of the other kind holds no body of it here (a certificate copy beside the shared
        // blob carries parts S's readers cannot open there, whatever this node opens of it)
        if mine.2 != copy {
            return Ok(false);
        }
        let larger: Vec<PartSet> = held.iter().filter(|x| *x != b).filter_map(|x| self.carried_by(&c, copy, x)).filter(|o| parts.is_subset(o) && o.len() > parts.len()).collect();
        if larger.is_empty() {
            return Ok(false);
        }
        let Some(only) = self.blob_only(s, &c)? else { return Ok(false) };
        Ok(larger.iter().any(|other| other.difference(parts).any(|ai| only.contains(ai))))
    }

    /// spec/sync-judgement.md §3 Neither: a body a delete removed from S (an entry of it that is
    /// not a certificate copy) is neither logged nor relayed while each of its deltas only a blob
    /// carries is held there by another blob of the commit that is not must-not-hold (one of
    /// `there`, the blobs of `c` held where the delete was) and no held purge request signed by
    /// ones that could hold the right names a delta of it without dropping it.
    pub(crate) fn neither_now(&mut self, s: &SyncId, c: &CommitId, there: &BTreeSet<BlobId>) -> Result<bool> {
        let Some(meta) = self.sync_bodies_now(c)?.get(s).cloned() else { return Ok(false) };
        if meta.certificate {
            return Ok(false);
        }
        let held: PartSet = there.iter().filter_map(|x| self.carried_by(c, meta.copy, x)).flatten().collect();
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
    pub(crate) fn body_fall_mark_now(&mut self, c: &CommitId) -> u64 {
        let Some(h) = self.header(c) else { return 0 };
        h.aspects.iter().map(|a| self.fall_mark_now(&a.tid, &a.ak)).fold(0u64, u64::saturating_add)
    }
}

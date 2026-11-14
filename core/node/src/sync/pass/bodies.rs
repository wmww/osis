//! What a label should hold (spec/sync.md §6): must-hold judgment, which entry holds a body,
//! placing one, and whether an entry is genuine.

use super::*;

impl SyncEngine {
    /// The entries the must-hold bodies of `l` need (spec/sync.md §6), by priority: the entry of
    /// each body (at `source` if there, else any genuine one; `None`: this node's own served
    /// state, any entry), else a fresh placement when this node may log or deposit it, with
    /// the blobs it links when this node writes. Another node's body not at `source` waits for
    /// its author or a co-writer (`relay_at`). `behind`: this node writes here and a must-hold role
    /// commit not at the source waits for its relay (`At::behind`).
    pub(super) fn body_sends(&mut self, p: &Head, bodies: &[Body], snaps: &Snaps, snapping: &Unsettled, left: &mut Left, behind: &mut bool) -> Result<Vec<Out>> {
        let (g, l, keys, read_ok, source) = (&p.g, p.l, &p.keys, p.read_ok, p.source.as_ref());
        let mut sends = Vec::new();
        self.stats.bodies += bodies.len() as u64;
        let mut note = Note::default();
        // a fill always has an entry on its way that may be a snapshot, but none covers what only
        // this node has sent: its own writes go out meanwhile
        let filling = self.filling(&l);
        let own_snapping: Unsettled = snapping.iter().flatten().cloned().map(Some).collect();
        // placed by priority: a source pulls this node's store in the order it logged them, so a
        // removal goes before the content placed beside it (spec/permissions.md §3)
        let mut ordered: Vec<(u8, &Body)> = bodies.iter().map(|b| (self.prio(b), b)).collect();
        let mut own_roles = None;
        ordered.sort_by_key(|(p, _)| *p);
        for (prio, b) in ordered {
            let snapping_b = if filling && self.own(&b.commit) { &own_snapping } else { snapping };
            let needed = self.must_hold(b, snaps, snapping_b, &mut note)?;
            note.leave(b.commit, left);
            if snapping.contains(&None) {
                left.waits.held_back.insert(b.commit);
            }
            let Some(needed) = needed else { continue };
            let entry = self.entry_for(source, &l, b);
            // another blob of the commit holding every needed delta holds it (a rewrite a
            // right holder dropped covered deltas from, a superset), unless it is must-not-hold
            // (`holds_nothing`, spec/sync.md §6)
            let here = entry.is_some_and(|id| source.is_none_or(|s| self.state.is_present(s, &l, &id)));
            if !here && self.carried_by(source, &l, &b.commit, &needed, b.to_label) {
                continue;
            }
            // a right holder deleted it here: its keep bounds, judged from what it holds, passed
            // there (spec/commits.md §5); not placed again while its live writes are carried
            let stands = !here && self.delete_stands(source, (l, p.id), b, &needed, snaps, &mut note)?;
            note.leave(b.commit, left);
            if stands {
                continue;
            }
            // another node's commit not at this source: its author (or a co-writer) first
            if !here && self.relay_at(p.l, &b.commit).is_some() {
                left.commits.insert(b.commit);
                *behind |= b.role_commit && keys.is_writer();
                continue;
            }
            let (id, fresh) = match entry {
                Some(id) => (id, false),
                None if read_ok && (keys.is_writer() || self.may_deposit(keys, b)) => {
                    let again = self.delete_took(source, l, b).then_some(p.id);
                    // a placement again waits, as deletes do (`At::behind`), until every
                    // source not full holds this node's own role commits and requests: the
                    // deleter pulls them first, else it judges the placement by older roles,
                    // deletes it again, and that delete stands (one refused there until a step
                    // registers comes after it). Another node's role commits it relays have
                    // their own wait (`relay_at`)
                    if again.is_some() && self.roles_lacking(&l, own_roles.get_or_insert_with(|| self.own_roles(&l))) {
                        left.commits.insert(b.commit);
                        continue;
                    }
                    match self.place(g, l, b, false, again)? {
                        Some(id) => (id, true),
                        None => continue,
                    }
                }
                None => continue,
            };
            let of = Some(Touch::Commit(b.commit));
            sends.push(Out { prio, id, fresh, of });
            if keys.is_writer() {
                let mut linked = self.list_blobs(&b.commit)?;
                linked.extend(self.body_blobs(&l, b, left)?);
                // a memory commit's pages are of its class (spec/wire.md §5)
                let memory = self.engine.header(&b.commit).is_some_and(|h| h.ephemeral.is_some());
                for cb in linked {
                    let fresh = !self.state.entries.contains_key(&(l, cb));
                    if fresh {
                        let wrap = osis_crypto::filler_wrap(&mut *self.rng);
                        let expires = self.held_expiry(&cb)?;
                        self.state.set_entry(l, cb, Entry { wrap, stamp: None, cert: false, salt: None, expires, size: None, kind: Kind::Unknown, source: None, memory });
                    }
                    sends.push(Out { prio, id: cb, fresh, of });
                }
            }
        }
        Ok(sends)
    }

    /// Whether a peer that cannot read `l`, where this node keeps it open and that is not full
    /// (nothing waits for a full peer: `LabelAt::full`), lacks one of `own` (`own_roles`).
    fn roles_lacking(&self, l: &LabelId, own: &[BlobId]) -> bool {
        let open = |id: &ConnId, c: &crate::sync::conn::Conn| c.up() && c.labels.get(l).is_some_and(|x| x.phase.is_open() && !x.full) && self.read_as_store(*id, l) && !self.shared_reads(*id, l);
        self.conns.iter().filter(|(id, c)| open(id, c)).filter_map(|(_, c)| c.peer).any(|peer| self.roles_lacking_at(&peer, l, own))
    }

    /// Whether `source` lacks one of `own` (`own_roles`).
    pub(super) fn roles_lacking_at(&self, source: &PeerKey, l: &LabelId, own: &[BlobId]) -> bool {
        own.iter().any(|id| self.lacks_at(source, l, id))
    }

    /// The entries under `l` of this node's own commits placed first (`prio`: role commits and
    /// requests, `judges_deletes`), held here, so every source pulls them. Read from the store,
    /// not from what a pass placed: one placed by a pass with no source to judge it at (cut off,
    /// or reading the source after a reconnect) is in no later pass's sends.
    pub(super) fn own_roles(&self, l: &LabelId) -> Vec<BlobId> {
        let judging = |c: &CommitId| self.own(c) && (self.first.contains(c) || self.engine.header(c).is_some_and(|h| h.kind.is_role()) || self.engine.core.ix.commits.get(c).is_some_and(|m| m.view.purges));
        self.state.label_entries(l).filter(|(_, e)| !e.shredded() && matches!(&e.kind, Kind::Commit { commit, .. } if judging(commit))).map(|(id, _)| id).collect()
    }

    /// Whether `source` lacks entry `id` of `l`: neither present there nor deleted there, refused
    /// included.
    fn lacks_at(&self, source: &PeerKey, l: &LabelId, id: &BlobId) -> bool {
        !self.state.is_present(source, l, id) && !self.state.is_gone_at(source, l, id)
    }

    /// Must-hold for a closure body (spec/sync.md §6), judged per part the label's actor reads
    /// (`b.parts`): a part kept (`part_kept`) or established uncovered by the label's
    /// snapshots (never a signal's). Must-hold: the parts a blob of the commit must hold to hold the body (those
    /// kept, and those of the aspects no snapshot covers).
    pub(super) fn must_hold(&mut self, b: &Body, snaps: &Snaps, unsettled: &Unsettled, note: &mut Note) -> Result<Option<Vec<usize>>> {
        let Some(h) = self.engine.header(&b.commit) else { return Ok(None) };
        let aspects: Vec<(Tid, Ak)> = b.parts.iter().filter_map(|ai| h.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect();
        let mut before = false;
        let mut covered = !aspects.is_empty();
        // an aspect where a snapshot under the label may cover the body, unjudged here (not
        // held: forgotten or dropped as covered in turn), is not established uncovered
        let mut unjudged = false;
        let mut needed = Vec::new();
        let keeps = self.engine.part_keeps(&b.commit)?;
        for (ai, (t, a)) in b.parts.iter().zip(&aspects) {
            let kept = self.part_kept(&keeps, *ai, note);
            before |= kept;
            // a signal's delta is never joined, so never established uncovered: must-hold only
            // while kept (spec/sync.md §6, spec/commits.md §5 Signals)
            let mut c = a.signal();
            let mut open = false;
            for s in snaps.get(&(*t, a.clone())).into_iter().flatten().filter(|_| !c) {
                if *s == b.commit {
                    continue;
                }
                match self.covered_noted(s, &b.commit, t, a, note)? {
                    Some(true) => {
                        // covered-equal snapshots (equal `ts`): the one with the higher commit ID goes
                        if is_snapshot(h.kind) && self.covered_noted(&b.commit, s, t, a, note)? == Some(true) && b.commit < *s {
                            continue;
                        }
                        c = true;
                        break;
                    }
                    // one stamped no later than the body never saw it (spec/crdt.md §2.2, HLC
                    // rules), so covers none of it
                    None => open |= self.stamp_of(s).is_none_or(|x| x > h.ts),
                    Some(false) => {}
                }
            }
            unjudged |= open && !c;
            covered &= c;
            if kept || !c {
                needed.push(*ai);
            }
        }
        let known = !unjudged && !unsettled.contains(&None) && !aspects.iter().any(|k| unsettled.contains(&Some(k.clone())));
        let covered = if covered || known { Some(covered) } else { None };
        let must = classify(&Facts { required: true, closure: true, before_at_least: before, covered, ..Facts::default() }) == Hold::Must;
        Ok(must.then_some(needed))
    }

    /// The `ts` of commit `c`: held, or a memory commit forgotten here.
    fn stamp_of(&self, c: &CommitId) -> Option<osis_base::Ts> {
        self.engine.header(c).map(|h| h.ts).or_else(|| self.memory.forgotten.get(c).map(|f| f.header.ts))
    }

    /// Whether part `p` of commit `c` is kept whatever covers it (spec/sync.md §6): before its
    /// keep-at-least bound (noted when that ends; never for one kept for good). `keeps`: the
    /// commit's `Engine::part_keeps`, read once per commit judged.
    pub(super) fn part_kept(&self, keeps: &[u64], ai: usize, note: &mut Note) -> bool {
        let Some(k) = keeps.get(ai).copied() else { return false };
        let kept = k > self.now();
        if kept && k < osis_commit::FOREVER {
            note.at(k);
        }
        kept
    }

    /// Whether only a blob of commit `c` can carry its part on aspect `ai` under the label (spec/sync.md §6):
    /// kept (`part_kept`) or holding a live write, and no snapshot under the label (`snaps`)
    /// covers it. A blob missing such a part (a rewrite that dropped it) is healed by placing
    /// the commit's blob again.
    /// Invariant: what one honest node deletes at a source no other's `must_carry` puts back.
    /// When a body was replaced is judged from the bodies each node holds (spec/commits.md §5), so
    /// a right holder may drop a covered body as past keep-at-least while a holder of other bodies
    /// judges it replaced later, or not at all, and kept. Both sides read the covering snapshot under the
    /// label alike, so a covered part is never one only a blob carries.
    /// `keeps`: the commit's `Engine::part_keeps`.
    pub(super) fn must_carry(&mut self, h: &osis_commit::Header, c: &CommitId, keeps: &[u64], ai: usize, snaps: &Snaps, note: &mut Note) -> Result<bool> {
        if !self.part_kept(keeps, ai, note) && !self.part_live(h, c, ai) {
            return Ok(false);
        }
        Ok(!self.parts_covered(snaps, c, h, &[ai], note)?)
    }

    /// Whether a delete took body `b` from `l` (a blob of the commit whose `readable` parts are the
    /// body's, from this node's store, or at `source`: an entry of it gone there and not present,
    /// not a wrap of no use) and it stays out: every one of its `parts` only a blob can carry
    /// (`must_carry`) is held there (at `source`) by another genuine blob of the commit, and no
    /// purge that fell may have been what took it (spec/sync.md §6).
    /// A memory body's delete stands too while memory entries this node refused for its cap are
    /// held there (`refused_there`): a delete-key holder deletes only once the carrier is there,
    /// and this node, not reading those entries, cannot show it is not (a fresh encryption past
    /// that delete would be deleted again, forever).
    /// A delete this node finds unfounded (a part to carry with no carrier there) stands too once
    /// it took a blob this node sealed to place the body again past such a delete at label head
    /// `head` (`BlobRec::again`): the right holder judges it covered by a snapshot this node
    /// does not hold (one on its way, or a host keeping it from this node), and placing it again
    /// would only be deleted again, one fresh blob and tombstone per round trip. It stands while
    /// that tombstone lasts, the head is that step and no held part on the body's aspects fell
    /// invalid here since (`again_fell`): a role change may make the deleter's cover or killing
    /// write fall, so one more placement goes then.
    pub(super) fn delete_stands(&mut self, source: Option<&PeerKey>, (l, head): (LabelId, osis_label::StepId), b: &Body, parts: &[usize], snaps: &Snaps, note: &mut Note) -> Result<bool> {
        if !self.delete_took(source, l, b) {
            return Ok(false);
        }
        // expiring within the clock drift allowed: a holder whose clock is ahead took it at expiry
        if b.expires.is_some_and(|x| x <= self.now().saturating_add(osis_base::format::MAX_DRIFT_MS)) {
            return Ok(true);
        }
        let Some(h) = self.engine.header(&b.commit) else { return Ok(false) };
        let keeps = self.engine.part_keeps(&b.commit)?;
        let unjudged = h.ephemeral.is_some() && self.refused_there(source, &l);
        for ai in parts {
            if self.must_carry(&h, &b.commit, &keeps, *ai, snaps, note)? && !self.carried_by(source, &l, &b.commit, &[*ai], b.to_label) && !unjudged {
                return Ok(self.again_deleted(source, (l, head), b, note));
            }
        }
        Ok(!self.engine.named_by_a_fallen_purge(&b.commit, parts)?)
    }

    /// Whether a delete took body `b` from `l`: a blob of the commit whose `readable` parts are
    /// the body's, from this node's store (`State::deleted_bodies`), or at `source` (an entry of
    /// it gone there and not present: not a wrap of no use).
    pub(super) fn delete_took(&mut self, source: Option<&PeerKey>, l: LabelId, b: &Body) -> bool {
        // compared on what the label's actor reads, as the body is: a deleted blob holding more
        // it reads was another body (a rewrite replaced it for a dropped part)
        let Some(g) = self.group_of(&l, None) else { return false };
        let mut deleted: Vec<Vec<usize>> = self.state.deleted_bodies(l, b.commit).cloned().collect();
        if let Some(h) = source {
            let there = self.state.entries_of(&l, &b.commit).filter(|(id, _)| self.state.is_gone_at(h, &l, id) && !self.state.is_present(h, &l, id));
            deleted.extend(there.filter_map(|(_, e)| if let Kind::Commit { parts, .. } = &e.kind { Some(parts.clone()) } else { None }).collect::<Vec<_>>());
        }
        deleted.into_iter().any(|p| self.readable(&g, &b.commit, &p) == b.parts)
    }

    /// Whether a blob this node sealed to place body `b` again past a delete at label head
    /// `head` (`BlobRec::again`) was deleted under `l` too: tombstoned here, or gone at `source`
    /// and not present there, until that record ends (`State::deleted_until`), when a pass comes.
    fn again_deleted(&mut self, source: Option<&PeerKey>, (l, head): (LabelId, osis_label::StepId), b: &Body, note: &mut Note) -> bool {
        let Some(g) = self.group_of(&l, None) else { return false };
        let now = self.now();
        let st = &self.state;
        let gone: Vec<(Vec<usize>, u64)> = st.by_commit.get(&b.commit).into_iter().flatten().filter(|id| st.blobs.get(id).is_some_and(|r| r.again == Some(head))).filter_map(|id| Some((st.blobs.get(id)?.parts.clone(), st.deleted_until(source, &l, id).filter(|t| *t > now)?))).collect();
        let until = gone.into_iter().filter(|(p, _)| self.readable(&g, &b.commit, p) == b.parts).map(|(_, t)| t).max();
        if let Some(t) = until {
            note.at(t);
        }
        until.is_some()
    }

    /// Held parts on these aspects fell invalid here (`Engine::take_fell`): a cover or killing
    /// write the deleter of a placement again may have relied on, so the placements again of
    /// commits on them (`BlobRec::again`) mark one no more, their deletes stand only as any
    /// other's and their commits are judged again (spec/sync.md §6 Placed again once). Walks the
    /// commits on each aspect (`by_aspect`), as the re-judge that found the fall did.
    pub(in crate::sync) fn again_fell(&mut self) {
        let fell = self.engine.take_fell();
        let by_aspect = &self.engine.core.ix.by_aspect;
        let commits: BTreeSet<CommitId> = fell.iter().flat_map(|k| by_aspect.get(k).into_iter().flatten().map(|x| x.1)).collect();
        for c in commits {
            let marked: Vec<BlobId> = self.state.by_commit.get(&c).into_iter().flatten().filter(|b| self.state.blobs.get(b).is_some_and(|r| r.again.is_some())).copied().collect();
            for id in &marked {
                self.state.clear_again(id);
            }
            if !marked.is_empty() {
                self.state.touched_commits.insert(c);
            }
        }
    }

    /// Whether every part's aspect of commit `c` is covered by a snapshot under `l`.
    pub(in crate::sync) fn parts_covered_at(&mut self, l: &LabelId, c: &CommitId, h: &osis_commit::Header, parts: &[usize]) -> Result<bool> {
        let mut snaps: BTreeMap<(Tid, Ak), Vec<CommitId>> = BTreeMap::new();
        for ai in parts {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let k = (a.tid, a.ak.clone());
            let snapshots = self.engine.core.ix.snapshots.get(&k).into_iter().flatten().map(|x| x.1);
            let on: Vec<CommitId> = snapshots.chain(self.engine.own_covers(c, &k.0, &k.1)).filter(|s| self.state.entries_of(l, s).next().is_some()).collect();
            snaps.insert(k, on);
        }
        self.parts_covered(&snaps, c, h, parts, &mut Note::default())
    }

    /// `Engine::covered`, noting an answer not established yet (`Note::unsure`: it may become
    /// one without a trigger).
    pub(super) fn covered_noted(&mut self, s: &CommitId, c: &CommitId, t: &Tid, a: &Ak, note: &mut Note) -> Result<Option<bool>> {
        let r = self.engine.covered(s, c, t, a)?;
        note.unsure |= r.is_none();
        Ok(r)
    }

    /// Whether every part's aspect of commit `c` is covered by a snapshot under the label
    /// (`snaps`).
    pub(super) fn parts_covered(&mut self, snaps: &Snaps, c: &CommitId, h: &osis_commit::Header, parts: &[usize], note: &mut Note) -> Result<bool> {
        for ai in parts {
            let Some(a) = h.aspects.get(*ai) else { return Ok(false) };
            let mut ok = false;
            for s in snaps.get(&(a.tid, a.ak.clone())).into_iter().flatten() {
                if s != c && self.covered_noted(s, c, &a.tid, &a.ak, note)? == Some(true) {
                    ok = true;
                    break;
                }
            }
            if !ok {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether memory entries of `l` this node refused for its cap (unopened here, any of them a
    /// possible carrier) are held at `source` (`None`: known anywhere).
    fn refused_there(&self, source: Option<&PeerKey>, l: &LabelId) -> bool {
        let refused = |b: &BlobId| self.memory.unfit.contains(*l, *b) || self.memory.refused.get(l).is_some_and(|r| r.ids.contains(b));
        self.memory_entries_of(l).any(|(b, _)| refused(&b) && source.is_none_or(|s| self.state.is_present(s, l, &b)))
    }

    /// Whether an entry of commit `c` holding `parts` is present at `source` under `l` (any
    /// entry when `None`: this node's own served state), checked genuine: a forged blob listing
    /// the parts holds nothing, nor a must-not-hold one (`holds_nothing`). `copy`: the body is a
    /// per-label copy (`Body::to_label`), which only a copy holds.
    pub(super) fn carried_by(&mut self, source: Option<&PeerKey>, l: &LabelId, c: &CommitId, parts: &[usize], copy: bool) -> bool {
        let ids: Vec<BlobId> = self.state.entries_of(l, c).filter(|(id, e)| !e.cert && (!copy || self.is_copy(id)) && matches!(&e.kind, Kind::Commit { parts: p, .. } if parts.iter().all(|x| p.contains(x)) && !self.holds_nothing(c, p)) && source.is_none_or(|s| self.state.holds_at(s, l, id))).map(|(id, _)| id).collect();
        ids.into_iter().any(|id| self.genuine(&id))
    }

    /// Whether a blob of commit `c` holding `parts` (those this node opened) is must-not-hold
    /// whatever its siblings: it holds a delta this node dropped (purge, expiry, compaction,
    /// purge on replace; not one it dropped while invalid, `Engine::left_at_hosts`). It holds no
    /// body and makes no other blob a strict subset (spec/sync.md §6).
    pub(super) fn holds_nothing(&self, c: &CommitId, parts: &[usize]) -> bool {
        let Some(m) = self.engine.core.ix.commits.get(c) else { return false };
        parts.iter().any(|p| m.body_gone(*p) && !self.engine.left_at_hosts(c, *p))
    }

    /// The parts of an entry of commit `c` under a label of `g` that `g`'s actor may read
    /// (`Engine::readable_parts`): what judgments compare with the label's bodies, so every
    /// node syncing the label judges alike whatever else it holds secrets for.
    pub(super) fn readable(&mut self, g: &Tid, c: &CommitId, parts: &[usize]) -> Vec<usize> {
        let ctx = self.engine.body_ctx(g);
        self.engine.readable_parts(&ctx, c, parts)
    }

    /// `readable` of what entry `b` under `l` (of `g`) opened; empty for no commit entry.
    pub(super) fn others_readable(&mut self, g: &Tid, l: &LabelId, b: &BlobId) -> Vec<usize> {
        let Some(Entry { kind: Kind::Commit { commit, parts, .. }, .. }) = self.state.entries.get(&(*l, *b)).cloned() else { return Vec::new() };
        self.readable(g, &commit, &parts)
    }

    /// The sections of commit `c` this node could not open, from the genuine blobs of it held
    /// here (any: every copy carries the same sealed sections, or a rewrite's subset), to copy
    /// verbatim into a fresh encryption (spec/wire.md §4).
    pub(super) fn sealed_sections(&mut self, c: &CommitId) -> Result<Vec<osis_commit::Section>> {
        let ids: Vec<BlobId> = self.state.by_commit.get(c).into_iter().flatten().copied().filter(|b| self.state.blobs.get(b).is_some_and(|r| !r.cert && crate::sync::state::sealed(&r.ais, &r.parts))).collect();
        let mut out: Vec<osis_commit::Section> = Vec::new();
        for id in ids {
            if !self.genuine(&id) {
                continue;
            }
            let Some(key) = self.state.blobs.get(&id).map(|r| r.key.clone()) else { continue };
            let Some(bytes) = self.engine.blob(&id)? else { continue };
            let Ok(o) = self.engine.open_commit(&bytes, &key) else { continue };
            for s in o.sealed {
                if !out.iter().any(|x| x.ais == s.ais) {
                    out.push(s);
                }
            }
        }
        Ok(out)
    }

    /// The genuine entry under `l` holding exactly this body, not tombstoned at `source` (with no
    /// source: whose bytes this node holds), whoever placed it (a certificate copy of the same parts holds it too: other nodes see one entry).
    /// One present at `source` first: the label then holds the body (spec/sync.md §6), and
    /// logging another encryption (this node's own, whose pull was lost) would only add a
    /// duplicate for the tiebreak of §7 to delete. `None`: any entry (this node's served state).
    pub(super) fn entry_for(&mut self, source: Option<&PeerKey>, l: &LabelId, b: &Body) -> Option<BlobId> {
        let g = self.group_of(l, None)?;
        let cands: Vec<(BlobId, Vec<usize>)> = self.state.entries_of(l, &b.commit).filter(|(id, e)| matches!(&e.kind, Kind::Commit { .. }) && source.is_none_or(|s| !self.state.is_gone_at(s, l, id))).filter_map(|(id, e)| if let Kind::Commit { parts, .. } = &e.kind { Some((id, parts.clone())) } else { None }).collect();
        // this node's served state (`source` `None`) serves only what it holds: an entry whose
        // bytes it dropped (a snapshot dropped a part of the blob it does not serve here, on
        // another thing) is no entry of the body, which is placed again as a blob of its own
        // a per-label copy's body is held only by a copy: the label's readers cannot open a
        // shared blob's sections (`Body::to_label`)
        let mut ids: Vec<BlobId> = cands.into_iter().filter(|(id, parts)| self.readable(&g, &b.commit, parts) == b.parts && (!b.to_label || self.is_copy(id)) && (source.is_some() || self.engine.has_blob(id))).map(|(id, _)| id).collect();
        match source {
            Some(source) => ids.sort_by_key(|id| !self.state.is_present(source, l, id)),
            // one useless at no source first
            None => ids.sort_by_key(|id| self.state.useless_anywhere(l, id)),
        }
        ids.into_iter().find(|id| self.genuine(id))
    }

    /// Whether blob `id` is a copy (`BlobRec::cert`): its one section under its blob key.
    pub(super) fn is_copy(&self, id: &BlobId) -> bool {
        self.state.blobs.get(id).is_some_and(|r| r.cert)
    }

    /// Whether every delta of commit blob `id` hashes to its header entry (spec/commits.md §4;
    /// `Engine::parts_genuine`). Opening a blob checks its prefix, not its deltas, and a held
    /// commit's late parts are skipped unchecked, so an entry's parts are only its own claim
    /// until this says yes. A forged blob is marked `Bad` under every label; unknown yet (a
    /// thing's `created.0` missing) counts as no.
    pub(crate) fn genuine(&mut self, id: &BlobId) -> bool {
        if let Some(v) = self.genuine.get(id) {
            return *v;
        }
        let Some(key) = self.state.blobs.get(id).map(|r| r.key.clone()) else { return false };
        let Ok(Some(bytes)) = self.engine.blob(id) else { return false };
        let verdict = match self.engine.open_commit(&bytes, &key) {
            Ok(o) => self.engine.parts_genuine(&o.commit),
            Err(_) => Some(false),
        };
        let Some(v) = verdict else { return false };
        self.genuine.insert(*id, v);
        if !v {
            let ls: Vec<LabelId> = self.state.labels_of(id);
            for l in ls {
                if let Some(mut e) = self.state.entries.get(&(l, *id)).cloned() {
                    e.kind = Kind::Bad;
                    self.state.set_entry(l, *id, e);
                }
            }
            self.diag(format!("blob {id:?}: a delta does not match its header"));
        }
        v
    }

    /// Places a body under `l`: an encryption of it this node holds (never a copy's, never one
    /// tombstoned there; for a certificate copy, this node's own copy of exactly its parts), else
    /// a fresh one (`Engine::seal`: every held part in sections, the sections this node could not
    /// open copied verbatim; a copy: `Engine::seal_to`); wrapped for the label.
    /// `again`: placed past a delete at that label head (`BlobRec::again`), always sealed now.
    /// Invariant: each placement again is a blob of its own recording its own label's head, so
    /// a delete of it stands under that label (`again_deleted`); a reused blob (sealed for
    /// another label's placement again, or none) would carry another head or none, and the body
    /// would go again under this label after its delete.
    pub(crate) fn place(&mut self, g: &Tid, l: LabelId, b: &Body, cert: bool, again: Option<osis_label::StepId>) -> Result<Option<BlobId>> {
        let Some(secret) = self.engine.wrap_secret(g, Some((&b.commit, &b.parts)))? else { return Ok(None) };
        // a memory commit's blobs carry its class and live in memory (spec/sync.md §9)
        let class = self.engine.header(&b.commit).map_or(osis_label::Class::Durable, |h| osis_label::Class::of_marker(h.ephemeral));
        let memory = class != osis_label::Class::Durable;
        // what the blob carries: every held part (a copy: the body's own, in one section under
        // the blob key, spec/sync.md §3); a per-label copy (a cross-published `label.0`) is
        // shared with no other label, a certificate copy with every label needing its parts
        let own = cert || b.to_label;
        let held: Vec<usize> = if own { b.parts.clone() } else { self.engine.body(&b.commit)?.map(|x| x.parts).unwrap_or_default() };
        // a held encryption carrying the body's parts and nothing not held any more (the
        // fullest; one sealed here may lack parts this node holds no secret for)
        // not one deleted under `l` (a peer refuses it while its tombstone lasts)
        let skip = |id: &BlobId| self.state.is_gone(&l, id) || self.state.entries.contains_key(&(l, *id)) || self.state.tombs.contains_key(&(l, *id));
        let reuse = if b.to_label || again.is_some() {
            None
        } else if cert {
            self.state.own_copy(&b.commit, &b.parts, skip)
        } else {
            self.state.blob_for(&b.commit, &b.parts, &held, skip)
        };
        let (id, key, parts, ais) = match reuse.and_then(|id| self.state.blobs.get(&id).map(|r| (id, r.key.clone(), r.parts.clone(), r.ais.clone()))) {
            Some(x) => x,
            None => {
                let sealed = if own {
                    self.engine.seal_to(b, class, &mut *self.rng)?
                } else {
                    let extra = self.sealed_sections(&b.commit)?;
                    self.engine.seal(b, class, &extra, &mut *self.rng)?
                };
                let Some(s) = sealed else { return Ok(None) };
                if memory {
                    self.engine.put_memory_blobs(vec![(s.id, s.blob)])?;
                } else {
                    self.engine.put_blobs(vec![(s.id, s.blob)])?;
                }
                // a copy is recorded as one: never reused for a body (`blob_for`)
                self.state.add_blob(s.id, BlobRec { commit: b.commit, parts: s.parts.clone(), ais: s.ais.clone(), key: s.key.clone(), cert: own, memory, again });
                (s.id, s.key, s.parts, s.ais)
            }
        };
        let Some(bytes) = self.engine.blob(&id)? else { return Ok(None) };
        let Some((salt, expires)) = osis_label::Prefix::parse(&bytes).ok().map(|p| (*p.salt(), p.expiry().map(|t| t.0))) else { return Ok(None) };
        let wrap = osis_crypto::wrap(&secret, &id, &key, b.order)?;
        self.state.set_entry(l, id, Entry { wrap, stamp: None, cert, salt: Some(salt), expires, size: None, kind: Kind::Commit { commit: b.commit, parts, ais }, source: None, memory });
        self.state.note_memory_size(l, id, bytes.len());
        Ok(Some(id))
    }

    /// The header-list blobs of a commit that this node holds.
    pub(super) fn list_blobs(&mut self, c: &CommitId) -> Result<Vec<BlobId>> {
        Ok(self.engine.header_list_blobs(c)?.into_iter().collect())
    }

    /// Blobs the body's own delta values link (trees of large values, pages): reused chunks and
    /// a snapshot's values belong to the closure too (spec/sync.md §3), so a reader under a label
    /// new to the body (a move) gets them. Those held here or already an entry under `l`; the
    /// walk is cached per body once complete.
    pub(super) fn body_blobs(&mut self, l: &LabelId, b: &Body, left: &mut Left) -> Result<Vec<BlobId>> {
        let (all, missing) = self.body_walk(b)?;
        // the walk goes on once the missing nodes are here
        for m in missing {
            left.link(m, b.commit);
        }
        let (here, not): (Vec<BlobId>, Vec<BlobId>) = all.into_iter().partition(|id| self.state.entries.contains_key(&(*l, *id)) || self.engine.has_blob(id));
        for id in not {
            left.link(id, b.commit);
        }
        Ok(here)
    }

    /// What the body's delta values link (`Engine::body_links`, through the node and page blobs
    /// held), and the node blobs the walk lacks; cached per body once complete.
    pub(in crate::sync) fn body_walk(&mut self, b: &Body) -> Result<(Vec<BlobId>, BTreeSet<BlobId>)> {
        let key = (b.commit, b.parts.clone());
        if let Some(x) = self.body_links.get(&key) {
            return Ok((x.clone(), BTreeSet::new()));
        }
        let pt = self.engine.body_plaintext(b)?;
        let r = self.engine.body_links(&pt)?;
        let all: Vec<BlobId> = r.blobs.into_iter().collect();
        if r.missing.is_empty() {
            self.body_links.insert(key, all.clone());
        }
        Ok((all, r.missing))
    }

    /// Whether this node placed the entry (its certificates, role writes).
    pub(crate) fn mine(&self, e: &Entry) -> bool {
        e.cert || matches!(&e.kind, Kind::Commit { commit, .. } if self.own(commit))
    }

    /// A non-writer deposits a must-hold body it holds no entry of (spec/sync.md §6 Reader):
    /// one it judges valid, and its own role writes (an invite grant, a self-removal, spec/sync.md
    /// §3) and requests (a destruction by an admin of the thing alone) whatever it judges. Else a
    /// value a reader alone holds, its entries deleted (its own write under its own snapshot that
    /// fell with its demotion) and every writer holding it restarted, reaches no one again.
    pub(super) fn may_deposit(&self, keys: &HeadKeys, b: &Body) -> bool {
        keys.deposit.is_some() && ((self.judges_deletes(b) && self.own(&b.commit)) || self.engine.judged_valid(&b.commit, &b.parts))
    }

    /// A body's place in a pass's order: placed first by a flow, then what deletes are judged
    /// by, then the rest (certificates are 2, `cert_sends`).
    fn prio(&self, b: &Body) -> u8 {
        if self.first.contains(&b.commit) {
            0
        } else if self.judges_deletes(b) {
            1
        } else {
            3
        }
    }

    /// Body `b` is what deletes are judged by: a role commit or a request (a source holds it
    /// before them, `At::behind`).
    pub(super) fn judges_deletes(&self, b: &Body) -> bool {
        b.role_commit || self.engine.core.ix.commits.get(&b.commit).is_some_and(|m| m.view.purges)
    }

    /// This node's verdicts on label `l` at node `node` it dialed under the keys its last pass
    /// there used (simulator invariants, spec/sync.md §6); `None` when the label is not open
    /// there.
    pub fn verdicts(&mut self, node: &[u8; 32], l: &LabelId) -> Result<Option<Verdicts>> {
        let Some((lc, source)) = self.conns.values().filter(|c| c.dial_key() == Some(*node)).find_map(|c| c.labels.get(l).filter(|x| x.phase.is_open()).zip(c.peer)) else { return Ok(None) };
        let source = &source;
        let (g, keys) = (lc.group, lc.keys.clone());
        let Some(head) = lc.head.as_ref().map(|h| h.id()) else { return Ok(None) };
        let mut v = Verdicts { writer: keys.is_writer(), ..Verdicts::default() };
        let bodies = self.engine.label_bodies_meta(&g)?;
        let mut w = Work::fresh();
        self.rebuild(&g, l, &mut w);
        let snaps: Snaps = w.snaps.iter().map(|(k, v)| (k.clone(), v.iter().map(|(_, c)| *c).collect())).collect();
        let fetching = w.unopened.iter().any(|b| self.asked(b).is_some());
        let (unsettled, snapping) = self.unsettled_sets(!w.unopened.is_empty(), fetching)?;
        v.unsettled = unsettled.iter().cloned().collect();
        let mut note = Note::default();
        for b in &bodies {
            if let Some(needed) = self.must_hold(b, &snaps, &snapping, &mut note)? {
                // not placed again (`body_sends`); one held there is checked whatever deletes of
                // other copies of it took (a duplicate's, the luck of the order a pass drew)
                if !self.carried_by(Some(source), l, &b.commit, &needed, b.to_label) && self.delete_stands(Some(source), (*l, head), b, &needed, &snaps, &mut note)? {
                    continue;
                }
                v.must_hold.push((b.commit, needed));
            }
        }
        let desired = desired(&bodies);
        let entries: Vec<(BlobId, Entry)> = self.state.label_entries(l).map(|(b, e)| (b, e.clone())).collect();
        let full = self.conns.values().filter(|c| c.peer == Some(*source)).any(|c| c.labels.get(l).is_some_and(|x| x.full));
        let at = At { g, l: *l, source: Some(*source), keys: &keys, snaps: &snaps, settled: unsettled.is_empty(), behind: false, full };
        for (id, e) in entries {
            if let Fate::Delete(why, _) = self.deletable(&at, &id, &e, &desired, false, &mut note)? {
                v.must_not.push((id, format!("{why:?}")));
            }
        }
        Ok(Some(v))
    }

    /// Prefix vs header for commit blobs whose header lists went by link (spec/commits.md §4):
    /// checked once the applied header is resolved, before the entry counts as holding its
    /// body; a disagreeing blob is bad input (`Kind::Bad`) and the body is judged missing there.
    pub(super) fn check_linked_prefixes(&mut self, l: LabelId, scope: &Scope) -> Result<()> {
        type Parts = Vec<usize>;
        let commits: Vec<CommitId> = match scope {
            Scope::All => self.state.label_commits(&l).collect(),
            Scope::Some { commits, .. } => commits.iter().copied().collect(),
        };
        let mut todo: Vec<(BlobId, CommitId, Parts)> = Vec::new();
        for c in commits {
            if !self.engine.header(&c).is_some_and(|h| osis_commit::ListField::ALL.iter().any(|f| h.links.get(*f).is_some())) {
                continue;
            }
            for (b, e) in self.state.entries_of(&l, &c) {
                if let Kind::Commit { ais, .. } = &e.kind
                    && !self.prefix_checked.contains(&b)
                {
                    todo.push((b, c, ais.clone()));
                }
            }
        }
        todo.sort_by_key(|x| x.0);
        for (b, c, ais) in todo {
            let Some(bytes) = self.engine.blob(&b)? else { continue };
            let Some(h) = self.engine.header(&c) else { continue };
            self.prefix_checked.insert(b);
            let agrees = match (osis_label::Prefix::parse(&bytes), osis_commit::prefix_groups(&h, ais.iter().copied())) {
                (Ok(p), Ok(groups)) => p.agrees(osis_commit::prefix_expiry(&h, &ais).map(WallMs), &h.blind, &groups, osis_label::Class::Durable),
                _ => false,
            };
            if !agrees {
                self.diag(format!("blob {b:?}: prefix disagrees with its resolved header"));
                if let Some(mut e) = self.state.entries.get(&(l, b)).cloned() {
                    e.kind = Kind::Bad;
                    self.state.set_entry(l, b, e);
                }
                self.state.remove_blob(&b);
            }
        }
        Ok(())
    }
}


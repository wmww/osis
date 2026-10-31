//! A pass's deletion judgment (spec/sync.md §5-§7): which entries under the label are
//! must-not-hold and may go now (`judge`, `deletable`), carriers first, by the label delete key
//! or a delete key, timed deletes for relative keep-at-most, chunks of dropped deltas; at a
//! host (`deletions`) and in this node's own served state (`local_deletions`).

use super::*;

impl SyncEngine {
    /// The deletion step of a local pass, over the entries of `scope` no host or peer holds
    /// (those go by their deletions, spec/sync.md §5-§7): a commit entry goes as `deletable` says
    /// (a live body only with a carrier, a covering snapshot asked for meanwhile, even when its
    /// bytes are gone), an expired one outright; any other entry whose bytes this node no longer
    /// holds serves nothing and goes, one past its prefix's expiry goes outright (a heartbeat's
    /// chunk, an inbox blob); chunks of dropped deltas go, and the blobs a gone certificate copy
    /// linked. Removed entries are tombstoned (`State::remove_entry`), expired ones not. What
    /// waits goes into `left`.
    pub(super) fn local_deletions(&mut self, at: &At, bodies: &[Body], scope: &Scope, left: &mut Left) -> Result<()> {
        let (l, settled) = (at.l, at.settled);
        let ids: Vec<BlobId> = self.scope_entries(&l, scope).into_iter().filter(|id| self.state.entries.contains_key(&(l, *id)) && !self.state.present_anywhere(&l, id)).collect();
        self.stats.entries += ids.len() as u64;
        let now = self.now();
        let desired = desired(bodies);
        let mut note = Note::default();
        for id in ids {
            let Some(e) = self.state.entries.get(&(l, id)).cloned() else { continue };
            let held = self.engine.has_blob(&id);
            if let Kind::Commit { commit, .. } = e.kind {
                let fate = self.deletable(at, &id, &e, &desired, true, &mut note)?;
                note.leave(commit, left);
                if !settled {
                    left.held_back.insert(commit);
                }
                match fate {
                    Fate::Wait => continue,
                    Fate::Expired => {
                        self.state.drop_entry(l, id);
                        self.forget_entry_blob(&id)?;
                        continue;
                    }
                    Fate::Delete(..) => {
                        self.state.remove_entry(l, id);
                        self.forget_entry_blob(&id)?;
                        continue;
                    }
                    Fate::Keep if held => continue,
                    Fate::Keep => {}
                }
            }
            if !held {
                self.state.drop_entry(l, id);
                self.local_expiry.remove(&id);
                continue;
            }
            let expiry = match self.local_expiry.get(&id) {
                Some(x) => *x,
                None => {
                    let x = self.engine.blob(&id)?.and_then(|b| osis_label::Prefix::parse(&b).ok()).and_then(|p| p.expiry()).map(|t| t.0);
                    self.local_expiry.insert(id, x);
                    x
                }
            };
            match expiry {
                Some(t) if t <= now => {
                    self.state.drop_entry(l, id);
                    self.local_expiry.remove(&id);
                    self.forget_entry_blob(&id)?;
                }
                Some(t) => {
                    left.due_blobs.entry(t).or_default().insert(id);
                }
                None => {}
            }
        }
        // chunks of dropped deltas (a purge, spec/commits.md §5): those listed by the commits of
        // `scope` and the chunk entries it names
        let cands = self.chunk_entries(&l, scope, |s, b| !s.state.present_anywhere(&l, b));
        let (chunks, waiting) = self.dropped_chunks(&cands)?;
        left.blobs.extend(waiting);
        for b in chunks.into_keys() {
            self.state.remove_entry(l, b);
            self.local_expiry.remove(&b);
            self.forget_chunk(&b)?;
        }
        // the blobs certificate copies linked, as a pass at a host deletes them (the bytes
        // stay: they are the engine's own): of the copies in `scope`, of every one when a
        // linked entry is
        let copied = self.copies_in(&l, scope);
        let mut gone = self.copy_links(&l, copied)?;
        gone.retain(|b| !self.state.present_anywhere(&l, b));
        if !gone.is_empty() {
            let all: Vec<BlobId> = self.state.label_entries(&l).map(|(b, _)| b).collect();
            for b in self.linked_by(&l, all)? {
                gone.remove(&b);
            }
        }
        for b in gone {
            self.state.remove_entry(l, b);
            self.local_expiry.remove(&b);
        }
        Ok(())
    }

    /// What may become of entry `id` under `l` (spec/sync.md §6, §7): `judge`, then a live
    /// body goes only with a carrier (`carried`; else a covering snapshot is asked for,
    /// `snapshot_first`, when `carrier`) and by a delete item this node can make. `host`
    /// `None`: this node's own served state.
    pub(super) fn deletable(&mut self, at: &At, id: &BlobId, e: &Entry, desired: &Desired, carrier: bool, note: &mut Note) -> Result<Fate> {
        let Some((Hold::MustNot(why), live, aspects)) = self.judge(at, id, e, desired, note)? else { return Ok(Fate::Keep) };
        if why == Why::Expired {
            return Ok(Fate::Expired);
        }
        let (carried, need, via) = match why {
            _ if !live => (true, Vec::new(), None),
            Why::Duplicate | Why::StrictSubset => (true, Vec::new(), None),
            _ => self.carried(at, e)?,
        };
        if !may_delete(why, live, carried) {
            if carrier && let Kind::Commit { commit, .. } = &e.kind {
                self.snapshot_first(&need, commit)?;
            }
            // judged again once a write on its aspects changes liveness (a carrier is a trigger)
            note.waits.extend(aspects);
            return Ok(Fate::Wait);
        }
        Ok(match self.delete_for(at.keys, &at.l, id, e, None)? {
            Some(item) => Fate::Delete(why, item, via),
            None => {
                note.keyless = true;
                Fate::Wait
            }
        })
    }

    /// A body under a relative keep-at-most with a known bound and no live write, held by entry
    /// `id` under `l` (spec/commits.md §5): its entry and bound, for a timed delete. A body with
    /// a live write gets none: it goes at the next compaction or its bound, carried then
    /// (`deletable`), so an edit erasing part of it does not re-snapshot the aspect. `None`: not
    /// under a relative keep-at-most; else what the body waits on and, when due, entry and bound.
    fn keep_at_most_due(&mut self, l: &LabelId, b: &Body, id: &BlobId) -> Result<Option<(AtMost, TimedDue)>> {
        let Some(h) = self.engine.header(&b.commit) else { return Ok(None) };
        let Some(a) = b.parts.first().and_then(|(ai, _)| h.aspects.get(*ai)) else { return Ok(None) };
        if a.retention.at_most.rel.is_none() {
            return Ok(None);
        }
        let (tid, ak) = (a.tid, a.ak.clone());
        // deaths and bound first: liveness costs a look through the state (cached per aspect)
        let Some(t) = self.engine.body_keep(&b.commit, &tid, &ak)?.at_most else { return Ok(Some((AtMost::Live(tid, ak), None))) };
        if self.engine.body_live(&b.commit, &tid, &ak).unwrap_or(true) {
            return Ok(Some((AtMost::Dead(tid, ak), None)));
        }
        Ok(Some((AtMost::Dead(tid, ak), self.state.entries.get(&(*l, *id)).cloned().map(|e| (e, t)))))
    }

    /// Facts about an entry under the label (spec/sync.md §6): `None` when this node cannot
    /// judge it (may-hold). `host` `None`: this node's own served state (every entry counts
    /// as present).
    fn judge(&mut self, at: &At, id: &BlobId, e: &Entry, desired: &Desired, note: &mut Note) -> Result<Option<Judged>> {
        let (g, l, host, snaps, settled) = (&at.g, &at.l, at.host.as_ref(), at.snaps, at.settled);
        let now = self.now();
        let Kind::Commit { commit, parts, .. } = &e.kind else { return Ok(None) };
        let Some(m) = self.engine.core.ix.commits.get(commit).cloned() else { return Ok(None) };
        let h = m.header.clone();
        // a blob expires whole with its class (spec/sync.md §3)
        if let Some(t) = parts.first().and_then(|(ai, _)| h.aspects.get(*ai)).and_then(|a| a.expires) {
            if t <= now {
                return Ok(Some((Hold::MustNot(Why::Expired), false, Vec::new())));
            }
            note.at(t);
        }
        let aspects: Vec<(Tid, Ak)> = parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect();
        if parts.iter().any(|p| m.dropped.contains_key(&p.0)) {
            // every delta's live writes count, the kept ones' too (spec/sync.md §7, `carried`)
            let live = parts.iter().any(|p| self.part_live(&h, commit, p));
            return Ok(Some((Hold::MustNot(Why::Dropped), live, aspects)));
        }
        if e.cert {
            return Ok(Some((Hold::May, false, aspects)));
        }
        let desired: Vec<&Vec<(usize, usize)>> = desired.get(commit).into_iter().flatten().collect();
        let mut f = Facts { required: false, closure: true, covered: None, ..Facts::default() };
        if desired.contains(&parts) {
            f.required = true;
            // the duplicate with the higher blob ID goes (spec/sync.md §7)
            // (only a genuine one: a forged duplicate must not get the real entry deleted)
            let lower: Vec<BlobId> = self.state.entries_of(l, commit).filter(|(b, o)| b < id && !o.cert && o.kind == e.kind && host.is_none_or(|s| self.state.is_present(s, l, b))).map(|(b, _)| b).collect();
            f.duplicate_higher = lower.into_iter().any(|b| self.genuine(&b));
        } else if desired.iter().any(|d| d.iter().all(|p| parts.contains(p))) {
            // a superset projection: every delta in it must be one the label's actor may read
            let x = self.engine.group_actor(g);
            let foreign = parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).any(|a| !self.engine.core.may_read(&x, &self.engine.core.reader_of(&a.tid)));
            if foreign && settled {
                return Ok(Some((Hold::MustNot(Why::Outside), true, aspects)));
            }
            f.required = true;
        } else {
            let sups: Vec<Vec<(usize, usize)>> = self
                .state
                .entries_of(l, commit)
                .filter(|(b, _)| b != id && (host.is_none() || self.state.present_anywhere(l, b)))
                .filter_map(|(b, o)| match &o.kind {
                    // a must-not-hold superset counts for nothing
                    Kind::Commit { parts: p2, .. } if p2.len() > parts.len() && parts.iter().all(|p| p2.contains(p)) && !self.holds_nothing(g, commit, p2) => Some((b, p2.clone())),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .into_iter()
                // a forged superset holds nothing (it would get the real projection deleted)
                .filter(|(b, _)| self.genuine(b))
                .map(|(_, p2)| p2)
                .collect();
            // a superset whose extra deltas a snapshot under the label covers carries nothing
            // more: this projection is one a right holder dropped them from (spec/sync.md §7)
            let mut sup = false;
            for p2 in sups {
                let extra: Vec<(usize, usize)> = p2.into_iter().filter(|p| !parts.contains(p)).collect();
                if !self.parts_covered(snaps, commit, &h, &extra, note)? {
                    sup = true;
                    break;
                }
            }
            if sup {
                f.required = true;
                f.strict_subset = true;
            } else if desired.iter().any(|d| parts.iter().all(|p| d.contains(p))) {
                // a lagging projection: the superset goes up first
                return Ok(None);
            } else {
                // another node's card nobody needs any more goes (spec/permissions.md §4), and
                // a certificate copy nobody completes (`orphan`)
                if settled && (self.stale_card(at, commit, &h, parts) || self.orphan(at, id, commit, &h, parts, note)?) {
                    return Ok(Some((Hold::MustNot(Why::Outside), false, aspects)));
                }
                // other certificates (membership-class, node cards, heartbeats) are not ours to judge
                let card = h.aspects.iter().all(|a| matches!(a.ak.as_str(), "/keys" | "/node" | "/reach" | "/seen" | "/created"));
                if h.kind.is_membership() || card {
                    return Ok(None);
                }
                // only deltas this node holds can be judged outside the label
                let c = *commit;
                let held: Vec<(usize, usize)> = self.engine.run(|tx| Ok(tx.get_commit(&c)?.map(|b| b.parts.iter().map(|p| (p.ai, p.di)).collect()).unwrap_or_default()))?;
                // and only once the view is settled (a peer's placement this node cannot
                // explain yet stays: a receiver keeps what a peer placed, spec/sync.md §3)
                if !parts.iter().all(|p| held.contains(p)) || !settled {
                    return Ok(None);
                }
            }
        }
        // a body outside the required set holds no write this label must keep
        let hold = classify(&f);
        Ok(Some((hold, hold != Hold::MustNot(Why::Outside), aspects)))
    }

    /// Unopened entries present at `host` under replaced label `l` that only content commits
    /// list (their chunks, tree nodes and pages): no membership-class commit or certificate
    /// kept there needs them (spec/sync.md §2). A blob no held commit lists stays.
    pub(crate) fn replaced_leftovers(&self, host: &HostKey, l: &LabelId) -> Vec<BlobId> {
        let unknown: BTreeSet<BlobId> = self.state.present_at(host, l).into_iter().filter(|b| self.state.entries.get(&(*l, *b)).is_some_and(|e| e.kind == Kind::Unknown)).collect();
        if unknown.is_empty() {
            return Vec::new();
        }
        let core = &self.engine.core;
        // the commits listing each (`by_chunk`, their views)
        unknown
            .into_iter()
            .filter(|b| {
                let listers = core.ix.by_chunk.get(b).into_iter().flatten().filter_map(|c| core.ix.commits.get(c));
                let mut any = false;
                for m in listers {
                    if m.view.aspects.iter().any(|a| kept_when_replaced(a.ak.as_str())) {
                        return false;
                    }
                    any = true;
                }
                any
            })
            .collect()
    }

    /// Whether an entry of commit `c` holding `parts` is another node's card that no member
    /// needs (spec/permissions.md §4): every part is its author's `/node`, `/reach` or `/keys`,
    /// and each is superseded by a newer commit on that aspect present here under `l`, or, for
    /// `/node` and `/reach`, the node departed (a departed node is never dialed; its `/keys`
    /// stays while chains of its old writes may need it).
    fn stale_card(&mut self, at: &At, c: &CommitId, h: &osis_commit::Header, parts: &[(usize, usize)]) -> bool {
        let (g, l, host) = (&at.g, &at.l, at.host.as_ref());
        let me = self.engine.tid();
        let aks: BTreeSet<&str> = parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).filter(|a| a.tid == h.author).map(|a| a.ak.as_str()).collect();
        let all_card = parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).all(|a| a.tid == h.author && is_card(a.ak.as_str()));
        if h.author == me || aks.is_empty() || !all_card {
            return false;
        }
        // departed: it reads the actor no more, and an applied write removed an edge on its way
        // to the actor, or one there passed its `until`: its own, or that of an actor it reads
        // through (its person). A view lacking the node's chain holds no such write on its way
        // and proves nothing ("reads no more" alone misjudged such members, spec/sync.md §6)
        let actor = self.engine.group_actor(g);
        let core = &self.engine.core;
        let now = osis_base::Ts::make(WallMs(self.now()), 0).unwrap_or_default();
        let author = h.author;
        let departed = !core.may_read(&author, &actor)
            && core.timelines.get(&author).is_some_and(|tl| {
                tl.applied().keys().any(|w| match w {
                    osis_perm::WriteId::Op(x, i) => tl.membership_commit(x).and_then(|mc| mc.ops.get(*i as usize)).is_some_and(|op| {
                        let ended = op.edge.is_none_or(|e| !e.alive_at(Some(now)));
                        let way = (op.member == author || core.may_read(&author, &op.member)) && (op.target == actor || core.may_read(&op.target, &actor));
                        ended && way
                    }),
                    osis_perm::WriteId::Snapshot(_) => false,
                })
            });
        aks.into_iter().all(|ak| {
            if departed && ak != "/keys" {
                return true;
            }
            // newer: the node's own valid write, with an entry here checked genuine (anyone may
            // sign a commit writing another's card with a later `ts`)
            let Some(x) = self.engine.latest_by(&author, ak, Some(&author)) else { return false };
            if x == *c || !self.engine.header(&x).is_some_and(|n| n.ts > h.ts) {
                return false;
            }
            let ids: Vec<BlobId> = self.state.entries_of(l, &x).filter(|(id, _)| host.is_none_or(|s| self.state.is_present(s, l, id))).map(|(id, _)| id).collect();
            ids.into_iter().any(|id| self.genuine(&id))
        })
    }

    /// Whether entry `id` of commit `c` holding `parts`, outside the label's closure, is a
    /// certificate copy whose author no longer reads the label's actor and whose author's chain
    /// no entry under `l` at `host` completes: outside the required set (spec/sync.md §6),
    /// since nobody is obliged to complete it and a verifier would hold it pending for ever.
    /// Judged only on a commit this node applied (it knows the author and the chain), and not on
    /// a deposit there: promotion completes or leaves those (spec/sync.md §5).
    fn orphan(&mut self, at: &At, id: &BlobId, c: &CommitId, h: &osis_commit::Header, parts: &[(usize, usize)], note: &mut Note) -> Result<bool> {
        let (g, l) = (&at.g, &at.l);
        // this node's own served state: deposits get their chains completed (`local_promote`);
        // another writer's stamped copy with an incomplete chain stays (issues/node-sync-gaps.md)
        let Some(host) = &at.host else { return Ok(false) };
        let actor = self.engine.group_actor(g);
        if h.author == self.engine.tid() || self.state.deposited.contains(&(*host, *l, *id)) || self.engine.core.may_read(&h.author, &actor) {
            return Ok(false);
        }
        // the chain's entries are other commits': judged again each pass
        note.unsure = true;
        Ok(self.chain_missing(Some(*host), g, *l, c, parts)?.is_some_and(|m| !m.is_empty()))
    }

    /// Deletes must-not-hold entries present at the host, carriers first (spec/sync.md §6,
    /// §7); timed deletes for bodies under a relative keep-at-most (spec/commits.md §5). Judges
    /// the entries and bodies of `scope`; what waits goes into `left`.
    pub(super) fn deletions(&mut self, conn: ConnId, at: &At, bodies: &[Body], scope: &Scope, left: &mut Left, out: &mut Vec<crate::sync::Action>) -> Result<()> {
        let (g, l, keys, settled) = (&at.g, at.l, at.keys, at.settled);
        let Some(host) = at.host else { return Ok(()) };
        let ids: Vec<BlobId> = match scope {
            Scope::All => self.state.present_at(&host, &l),
            Scope::Some { .. } => self.scope_entries(&l, scope).into_iter().filter(|b| self.state.is_present(&host, &l, b)).collect(),
        };
        self.stats.entries += ids.len() as u64;
        let desired = desired(bodies);
        // deletes in flight on this connection are not sent again (`RESEND_MS`)
        let raw = self.raw_now();
        let busy = |s: &Self, id: &BlobId| s.conns.get(&conn).is_some_and(|c| crate::sync::in_flight(c, &c.req.deleting, (l, *id), raw));
        let send = |s: &mut Self, id: BlobId| {
            if let Some(c) = s.conns.get_mut(&conn) {
                c.req.deleting.insert((l, id), (raw, crate::sync::UNTAGGED));
            }
        };
        let mut items = Vec::new();
        // capped rewrites to upload again, each replacing the bodies it carries
        let mut replace: BTreeMap<BlobId, Vec<osis_label::DeleteItem>> = BTreeMap::new();
        let mut note = Note::default();
        for id in &ids {
            let id = *id;
            let Some(e) = self.state.entries.get(&(l, id)).cloned() else { continue };
            let Kind::Commit { commit, .. } = e.kind else { continue };
            let fate = self.deletable(at, &id, &e, &desired, true, &mut note)?;
            note.leave(commit, left);
            if !settled {
                left.held_back.insert(commit);
            }
            match fate {
                Fate::Keep | Fate::Wait => {}
                Fate::Expired => {
                    // the host drops it unattended (spec/sync.md §5)
                    self.absent_at(Some(host), l, id)?;
                }
                Fate::Delete(_, item, via) => {
                    left.commits.insert(commit);
                    if !busy(self, &id) {
                        send(self, id);
                        match via {
                            Some(q) => replace.entry(q).or_default().push(item),
                            None => items.push(item),
                        }
                    }
                }
            }
        }
        // chunks of dropped deltas (spec/commits.md §5: a purge drops every body carrying the
        // values; spec/sync.md §3: chunk blobs belong to the closure): those listed by the
        // commits of `scope` and the chunk entries it names
        let cands = self.chunk_entries(&l, scope, |s, b| s.state.is_present(&host, &l, b));
        let (chunks, waiting) = self.dropped_chunks(&cands)?;
        left.blobs.extend(waiting);
        let wants: Vec<BlobId> = std::mem::take(&mut self.tree_wants).into_iter().filter(|b| self.state.is_present(&host, &l, b)).collect();
        self.fetch_on(conn, l, wants, out)?;
        for (id, chunk) in &chunks {
            left.blobs.insert(*id);
            if busy(self, id) {
                continue;
            }
            if let Some(item) = self.chunk_delete(conn, keys, &l, id, chunk, out)? {
                send(self, *id);
                items.push(item);
            }
        }
        // under a replaced label the chunk and page entries of content commits go with them
        // (spec/sync.md §2: only membership-class commits and certificates stay)
        if keys.delete.is_some() && self.is_replaced(g, &l) {
            for b in self.replaced_leftovers(&host, &l) {
                if busy(self, &b) {
                    continue;
                }
                if let Some(item) = delete_item(keys, &l, b, None, None, &[]) {
                    send(self, b);
                    items.push(item);
                }
            }
        }
        // the blobs certificate copies link (`place_linked`) once this node knows no entry of
        // their commit under the label any more (deleted; one placed and not confirmed yet still
        // counts), unless another present entry links them too (roster snapshots sharing tree
        // pages): nothing under the label needs them
        if keys.delete.is_some() {
            let copied = self.copies_in(&l, scope);
            let mut gone = BTreeSet::new();
            for b in self.copy_links(&l, copied)? {
                if self.state.is_present(&host, &l, &b) {
                    left.blobs.insert(b);
                    if !busy(self, &b) {
                        gone.insert(b);
                    }
                }
            }
            if !gone.is_empty() {
                let present = self.state.present_at(&host, &l);
                for b in self.linked_by(&l, present)? {
                    gone.remove(&b);
                }
            }
            for b in gone {
                if let Some(item) = delete_item(keys, &l, b, None, None, &[]) {
                    send(self, b);
                    items.push(item);
                }
            }
        }
        // timed deletes: bodies under a relative keep-at-most with a known bound
        for b in bodies {
            let Some(id) = self.entry_for(Some(&host), &l, b) else { continue };
            if !self.state.is_present(&host, &l, &id) || self.state.timed.contains(&(host, l, id)) {
                continue;
            }
            if self.conns.get(&conn).is_some_and(|c| c.req.timed_sent.contains(&(l, id))) {
                left.commits.insert(b.commit);
                continue;
            }
            let Some((a, due)) = self.keep_at_most_due(&l, b, &id)? else { continue };
            let Some((e, t)) = due else {
                // judged again when its bound or liveness changes (`AtMost`)
                match a {
                    AtMost::Live(t, k) => left.wait_at_most(t, k, b.commit),
                    AtMost::Dead(t, k) => left.wait(t, k, b.commit),
                }
                continue;
            };
            match self.delete_for(keys, &l, &id, &e, Some(WallMs(t)))? {
                Some(item) => {
                    left.commits.insert(b.commit);
                    if let Some(c) = self.conns.get_mut(&conn) {
                        c.req.timed_sent.insert((l, id));
                    }
                    items.push(item);
                }
                None => {
                    left.keyless.insert(b.commit);
                }
            }
        }
        if !items.is_empty() {
            self.command(conn, Command::Delete { label: l, items }, out)?;
        }
        self.replace_sends(conn, keys, l, replace, out)?;
        self.given(conn);
        Ok(())
    }

    /// Uploads this node's rewrites the host refused for the label's cap again, each naming
    /// the bodies it carries as replaced with their delete items (spec/sync.md §5, §7): the
    /// host admits it in the room they free and removes them in the same step, so the label
    /// never lacks the kept live writes.
    fn replace_sends(&mut self, conn: ConnId, keys: &HeadKeys, l: LabelId, replace: BTreeMap<BlobId, Vec<osis_label::DeleteItem>>, out: &mut Vec<crate::sync::Action>) -> Result<()> {
        let raw = self.raw_now();
        let mut uploads = Vec::new();
        for (q, items) in replace {
            let Some(mut e) = self.state.entries.get(&(l, q)).cloned() else { continue };
            let Some(blob) = self.engine.blob(&q)? else { continue };
            let stamp = match (&keys.write, e.stamp) {
                (Some(w), _) => osis_label::sign_stamp(w, &l, &q, &e.wrap),
                (None, Some(s)) => s,
                (None, None) => continue,
            };
            e.stamp = Some(stamp);
            let wrap = e.wrap;
            self.state.set_entry(l, q, e);
            if let Some(c) = self.conns.get_mut(&conn) {
                c.req.sent.insert((l, q), (raw, crate::sync::UNTAGGED));
                c.req.replacing.insert((l, q), items.iter().map(|i| i.blob).collect());
            }
            uploads.push(osis_proto::Entry { blob, wrap, stamp, replaces: items });
        }
        if !uploads.is_empty() {
            self.command(conn, Command::Upload { label: l, entries: uploads }, out)?;
        }
        Ok(())
    }

    /// Whether a delta of commit `c` has a live write in this node's state (spec/commits.md §5): a
    /// dropped body keeps its live writes there (spec/crdt.md §4.6); a purged one holds none.
    pub(super) fn part_live(&mut self, h: &osis_commit::Header, c: &CommitId, p: &(usize, usize)) -> bool {
        let Some(a) = h.aspects.get(p.0) else { return false };
        let o = crate::engine::Owned::of(h, c, p.0);
        if self.engine.core.ix.valueless.get(&(a.tid, a.ak.clone())).is_some_and(|v| o.as_ref().is_some_and(|o| v.contains(o))) {
            return false;
        }
        self.engine.body_live(c, &a.tid, &a.ak).unwrap_or(true)
    }

    /// Whether other entries under the label at the host carry every live write of
    /// must-not-hold entry `e` the label's actor may read (spec/sync.md §7), and the aspects only
    /// a snapshot this node writes can carry.
    /// A kept delta's: a blob of the commit holding it that is not must-not-hold (the dropping
    /// node's rewrite, `carried_by`) or a snapshot covering it; none is asked for while this node
    /// has such a blob placed. A dropped delta's: the snapshot that covered it when it was dropped.
    /// With a carrier that is this node's rewrite refused for the cap (`rewrite_capped`): it.
    fn carried(&mut self, at: &At, e: &Entry) -> Result<Carriage> {
        let (g, l, host) = (&at.g, &at.l, at.host.as_ref());
        let Kind::Commit { commit, parts, .. } = &e.kind else { return Ok((false, Vec::new(), None)) };
        let Some(m) = self.engine.core.ix.commits.get(commit).cloned() else { return Ok((false, Vec::new(), None)) };
        let x = self.engine.group_actor(g);
        let (mut all, mut need, mut via) = (true, Vec::new(), None);
        for p in parts {
            let Some(a) = m.header.aspects.get(p.0) else { continue };
            let (t, a) = (a.tid, a.ak.clone());
            // a delta the label's actor may not read is carried under its readers' labels
            if !self.engine.core.may_read(&x, &self.engine.core.reader_of(&t)) || !self.part_live(&m.header, commit, p) {
                continue;
            }
            let dropped = m.dropped.contains_key(&p.0);
            if !dropped && self.carried_by(host, g, l, commit, &[*p]) || self.snapshot_carries(at, commit, &t, &a, dropped)? {
                continue;
            }
            // this node's rewrite, refused at the host for the label's cap: it goes up again
            // replacing this body, in the room it frees (else a full label would keep a purged
            // body for good)
            if !dropped
                && let Some(q) = host.and_then(|s| self.rewrite_capped(s, g, l, commit, parts, p))
            {
                via = via.or(Some(q));
                continue;
            }
            all = false;
            if dropped || !self.carried_by(None, g, l, commit, &[*p]) {
                need.push((t, a));
            }
        }
        Ok((all, need, via))
    }

    /// A blob of commit `c` under `l` holding delta `p`, a strict subset of `parts` (so smaller
    /// than the body it would carry), that is this node's upload `host` refused for the
    /// label's cap (`SyncEngine::capped`).
    fn rewrite_capped(&mut self, host: &HostKey, g: &Tid, l: &LabelId, c: &CommitId, parts: &[(usize, usize)], p: &(usize, usize)) -> Option<BlobId> {
        let ids: Vec<BlobId> = self
            .state
            .entries_of(l, c)
            .filter(|(id, e)| !e.cert && self.capped.contains(&(*host, *l, *id)) && matches!(&e.kind, Kind::Commit { parts: q, .. } if q.contains(p) && q.len() < parts.len() && q.iter().all(|x| parts.contains(x)) && !self.holds_nothing(g, c, q)))
            .map(|(id, _)| id)
            .collect();
        ids.into_iter().find(|id| self.genuine(id))
    }

    /// Whether a later snapshot of `(t, a)` under the label at the host carries body `body`'s
    /// writes there: one covering it, or for a `dropped` delta (its content is gone, so `covered`
    /// checks only the frontier) the snapshot that covered it when it was dropped, or one
    /// covered-equal to that whose frontier holds the body's counters (a co-writer's that went
    /// up in its place).
    fn snapshot_carries(&mut self, at: &At, body: &CommitId, t: &Tid, a: &Ak, dropped: bool) -> Result<bool> {
        let (l, host, snaps) = (&at.l, at.host.as_ref(), at.snaps);
        let carrier = self.carrier_of(body, t, a);
        let candidates: Vec<CommitId> = match carrier {
            None if dropped => Vec::new(),
            _ => carrier.into_iter().chain(snaps.get(&(*t, a.clone())).cloned().unwrap_or_default()).collect(),
        };
        for s in candidates {
            if s == *body || !self.state.entries_of(l, &s).any(|(b, _)| host.is_none_or(|host| self.state.is_present(host, l, &b))) {
                continue;
            }
            let covers = self.engine.covered(&s, body, t, a)? == Some(true);
            let stand_in = match carrier {
                Some(k) => k == s || (covers && self.engine.covered(&s, &k, t, a)? == Some(true) && self.engine.covered(&k, &s, t, a)? == Some(true)),
                None => false,
            };
            if stand_in || (!dropped && covers) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// A right holder that must delete a body with live writes and finds no carrier writes a
    /// covering snapshot first when it may write the aspect (spec/sync.md §7).
    pub(in crate::sync) fn snapshot_first(&mut self, aspects: &[(Tid, Ak)], body: &CommitId) -> Result<()> {
        if aspects.iter().all(|(t, a)| self.carrier_of(body, t, a).is_some()) {
            return Ok(());
        }
        for (t, a) in aspects {
            // `/created` is kept forever and never compacted
            if is_membership(a) || a.as_str() == "/created" || self.engine.role_on(t) < Some(Role::Write) {
                continue;
            }
            if self.carrier_of(body, t, a).is_some() {
                continue;
            }
            // a snapshot from this node's whole state covers every body of the aspect it applied
            if let Some(s) = self.engine.snapshot(t, a)? {
                self.state.set_carrier(*body, s);
            }
        }
        Ok(())
    }

    /// The recorded carrier of a dropped body on `(t, a)`, followed through carriers that were
    /// dropped in turn to one whose body this node still holds (a carrier dropped before it went
    /// up carries nothing: its writes moved to a later snapshot, or a new one is due).
    fn carrier_of(&self, body: &CommitId, t: &Tid, a: &Ak) -> Option<CommitId> {
        let on = |c: &CommitId| self.engine.header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == *t && x.ak == *a));
        let mut c = *self.state.carriers.get(body)?.iter().rev().find(|c| on(c))?;
        for _ in 0..64 {
            if self.engine.body_not_dropped(&c, t, a) {
                return Some(c);
            }
            c = *self.state.carriers.get(&c)?.iter().rev().find(|c| on(c))?;
        }
        None
    }

    /// Chunk, tree-node and page blobs among `cands` whose creating deltas this node dropped
    /// (purge, expiry, keep at most, compaction), by the commit and chunk entry that list them,
    /// unless a commit whose creating deltas are not all dropped lists them too (chunk reuse,
    /// spec/sync.md §1). A chunk's creating deltas are those whose delete-key indices are its own
    /// (one class); with no such delta, every delta of the commit. Nor those a live tree links
    /// (spec/sync.md §7: reused chunks and the chunks of compacted values are not in the
    /// linking commit's list): those are returned apart, judged again while trees may link them.
    pub(crate) fn dropped_chunks(&mut self, cands: &BTreeSet<BlobId>) -> Result<(DroppedChunks, BTreeSet<BlobId>)> {
        let mut out = BTreeMap::new();
        if cands.is_empty() {
            return Ok((out, BTreeSet::new()));
        }
        for b in cands {
            let listers: Vec<CommitId> = self.engine.core.ix.by_chunk.get(b).into_iter().flatten().copied().collect();
            let mut first = None;
            let mut live = false;
            for id in listers {
                let Some(m) = self.engine.core.ix.commits.get(&id) else { continue };
                let h = &m.header;
                for ch in h.chunks.iter().filter(|ch| ch.blob == *b) {
                    let class: Vec<usize> = h.aspects.iter().enumerate().filter(|(_, a)| a.keys == ch.keys).map(|(ai, _)| ai).collect();
                    let ais: Vec<usize> = if class.is_empty() { (0..h.aspects.len()).collect() } else { class };
                    let parts = parts_of(h, |i| ais.contains(&i));
                    let dropped = !parts.is_empty() && parts.iter().all(|p| m.dropped.contains_key(&p.0));
                    if dropped {
                        first.get_or_insert((id, ch.clone()));
                    } else {
                        live = true;
                    }
                }
            }
            if let (false, Some(x)) = (live, first) {
                out.insert(*b, x);
            }
        }
        // the things of the listing commits: reuse and snapshots link within a thing
        let mut by_thing: BTreeMap<Tid, BTreeSet<BlobId>> = BTreeMap::new();
        for (b, (c, _)) in &out {
            for a in self.engine.header(c).map(|h| h.aspects.clone()).unwrap_or_default() {
                by_thing.entry(a.tid).or_default().insert(*b);
            }
        }
        let mut waiting = BTreeSet::new();
        for (t, bs) in by_thing {
            // a tree not all held here may link any of them: its missing nodes are fetched
            // (`tree_wants`) and the chunks judged once they are here
            let linked = self.engine.live_trees(&t)?;
            for b in &bs {
                if !linked.missing.is_empty() || linked.blobs.contains(b) {
                    waiting.insert(*b);
                }
            }
            out.retain(|b, _| !bs.contains(b) || linked.missing.is_empty() && !linked.blobs.contains(b));
            self.tree_wants.extend(linked.missing);
        }
        Ok((out, waiting))
    }

    /// A delete item for a dropped chunk: the label delete key, else a delete key of its delta
    /// (signed for the salt in its prefix; a chunk never fetched is fetched first).
    fn chunk_delete(&mut self, conn: ConnId, keys: &HeadKeys, l: &LabelId, id: &BlobId, (c, ch): &(CommitId, osis_commit::ChunkEntry), out: &mut Vec<crate::sync::Action>) -> Result<Option<osis_label::DeleteItem>> {
        if keys.delete.is_some() {
            return Ok(delete_item(keys, l, *id, None, None, &[]));
        }
        let Some(blob) = self.engine.blob(id)? else {
            self.fetch_on(conn, *l, [*id], out)?;
            return Ok(None);
        };
        let Ok(prefix) = osis_label::Prefix::parse(&blob) else { return Ok(None) };
        let dks = self.engine.chunk_delete_secrets(c, ch);
        let Some(hb) = self.engine.header(c).map(|h| h.blind) else { return Ok(None) };
        Ok(delete_item(keys, l, *id, None, Some((prefix.salt(), &hb)), &dks))
    }

    /// A delete item for an entry: the label delete key, else a delete key this node holds.
    fn delete_for(&mut self, keys: &HeadKeys, l: &LabelId, id: &BlobId, e: &Entry, at: Option<WallMs>) -> Result<Option<osis_label::DeleteItem>> {
        if keys.delete.is_some() {
            return Ok(delete_item(keys, l, *id, at, None, &[]));
        }
        Ok(match &e.kind {
            Kind::Commit { commit, parts, salt } => {
                let dks = self.engine.delete_secrets_of(commit, parts);
                let hb = self.engine.header(commit).map(|h| h.blind);
                delete_item(keys, l, *id, at, hb.as_ref().map(|hb| (salt, hb)), &dks)
            }
            _ => None,
        })
    }
}

fn is_membership(a: &Ak) -> bool {
    osis_schema::core_types::is_membership_class(a.as_str())
}

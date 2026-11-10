//! A pass's deletion judgment (spec/sync.md §5-§7): which entries under the label are
//! must-not-hold and may go now (`judge`, `deletable`), carriers first, by the label delete key
//! or a delete key, chunks of dropped deltas; at a host (`deletions`) and in this node's own served state (`local_deletions`).

use super::*;
use crate::engine::MemoryDrop;

impl SyncEngine {
    /// The deletion step of a local pass, under every label, over the entries of `scope` no host
    /// or peer holds (those go by their deletions, spec/sync.md §5-§7; one whose upload a host
    /// takes after this is recorded again from its tombstone, `host_holds`): a commit entry goes
    /// as `deletable` says
    /// (a live body only with a carrier, a covering snapshot asked for meanwhile, even when its
    /// bytes are gone), an expired one outright; any other entry whose bytes this node no longer
    /// holds serves nothing and goes, one past its prefix's expiry goes outright (an inbox
    /// blob); chunks of dropped deltas go, and the blobs a gone certificate copy
    /// linked. Removed entries are tombstoned (`State::remove_entry`), expired ones not. What
    /// waits goes into `left`.
    pub(super) fn local_deletions(&mut self, at: &At, bodies: &[Body], scope: &Scope, left: &mut Left) -> Result<()> {
        let (l, settled) = (at.l, at.settled);
        let ids: Vec<BlobId> = self.scope_entries(&l, scope).into_iter().filter(|id| self.state.entries.contains_key(&(l, *id)) && !self.state.present_anywhere(&l, id)).collect();
        self.stats.entries += ids.len() as u64;
        let now = self.now();
        let desired = desired(bodies);
        // chunks of dropped deltas (a purge, spec/commits.md §5), first: tombstoned, whether or
        // not their bytes are here (those went with the purge, `forget_dropped`), never taken
        // below as an entry serving nothing. Those listed by the commits of `scope` and the
        // chunk entries it names
        let cands = self.chunk_entries(&l, scope, |s, b| !s.state.present_anywhere(&l, b));
        let (chunks, waiting) = self.dropped_chunks(&cands)?;
        left.blobs.extend(waiting);
        for b in chunks.into_keys() {
            // the bytes first: the salt goes into the tombstone (`keep_salts`)
            self.forget_chunk(&b)?;
            self.state.remove_entry(l, b);
            self.local_expiry.remove(&b);
        }
        let mut note = Note::default();
        for id in ids {
            let Some(e) = self.state.entries.get(&(l, id)).cloned() else { continue };
            let held = self.engine.has_blob(&id);
            if let Kind::Commit { commit, .. } = e.kind {
                let fate = self.deletable(at, &id, &e, &desired, true, &mut note)?;
                note.leave(commit, left);
                if !settled {
                    left.waits.held_back.insert(commit);
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
                    left.at(t, Touch::Blob(id));
                }
                None => {}
            }
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
        // a Delete needs every commitment group signed, a Replace (`via`) one (spec/sync.md §5)
        Ok(match self.delete_for(at.keys, &at.l, id, e, via.is_none())? {
            Some(item) => Fate::Delete(why, item, via),
            None => {
                note.keyless = true;
                Fate::Wait
            }
        })
    }

    /// Facts about an entry under the label (spec/sync.md §6): `None` when this node cannot
    /// judge it (may-hold). `host` `None`: this node's own served state (every entry counts
    /// as present).
    fn judge(&mut self, at: &At, id: &BlobId, e: &Entry, desired: &Desired, note: &mut Note) -> Result<Option<Judged>> {
        let (g, l, host, snaps, settled) = (&at.g, &at.l, at.host.as_ref(), at.snaps, at.settled);
        let now = self.now();
        let Kind::Commit { commit, parts: opened, .. } = &e.kind else { return Ok(None) };
        // judged on the parts the label's actor reads (`readable`), as every node of it does
        let parts = &self.readable(g, commit, opened);
        let Some(m) = self.engine.core.ix.commits.get(commit).cloned() else { return Ok(self.judge_forgotten(commit, opened, note)) };
        let h = m.header.clone();
        // a blob expires whole at its prefix's expiry, as the host drops it (spec/sync.md §3, §5),
        // whatever of it the label's actor still reads
        if let Some(t) = osis_commit::blob_expiry(&h) {
            if t <= now {
                return Ok(Some((Hold::MustNot(Why::Expired), false, Vec::new())));
            }
            note.at(t);
        }
        let aspects: Vec<(Tid, Ak)> = parts.iter().filter_map(|ai| h.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect();
        if opened.iter().any(|p| m.body_gone(*p) && !self.engine.left_at_hosts(commit, *p)) {
            // every delta's live writes count, the kept ones' too (spec/sync.md §7, `carried`)
            let live = opened.iter().any(|ai| self.part_live(&h, commit, *ai));
            return Ok(Some((Hold::MustNot(Why::Dropped), live, aspects)));
        }
        // a delta dropped here while invalid: no right deletes it (spec/permissions.md §6), so
        // the hosts keep the copy a re-grant fetches, unless a right dropped another (above)
        if opened.iter().any(|p| self.engine.left_at_hosts(commit, *p)) {
            return Ok(None);
        }
        if e.cert {
            return Ok(Some((Hold::May, false, aspects)));
        }
        let desired: Vec<&Vec<usize>> = desired.get(commit).into_iter().flatten().collect();
        let mut f = Facts { required: false, closure: true, covered: None, ..Facts::default() };
        if desired.contains(&parts) {
            f.required = true;
            if e.memory {
                self.state.memory_in_closure.insert((*l, *id));
            }
            // the duplicate with the higher blob ID goes (spec/sync.md §7): the same delta set
            // (each encryption has its own salt), only a genuine one (a forged duplicate must not
            // get the real entry deleted); one whose wrap is of no use there counts as no copy,
            // and goes itself once there is one, whatever its ID
            let useless = host.is_some_and(|s| self.state.is_gone_at(s, l, id));
            let same: Vec<BlobId> = self.state.entries_of(l, commit).filter(|(b, o)| (b < id || (useless && b != id)) && !o.cert && matches!(&o.kind, Kind::Commit { .. }) && host.is_none_or(|s| self.state.holds_at(s, l, b))).map(|(b, _)| b).collect();
            let lower: Vec<BlobId> = same.into_iter().filter(|b| self.others_readable(g, l, b) == *parts).collect();
            f.duplicate_higher = lower.into_iter().any(|b| self.genuine(&b));
        } else if desired.iter().any(|d| d.iter().all(|p| parts.contains(p))) {
            // a superset: more of the commit than the label's bodies ask for holds them too
            f.required = true;
        } else {
            // one the label's actor reads nothing of (a certificate another node placed, a
            // blob sealed to this node) is a strict subset of nothing: judged by the rest
            let others: Vec<(BlobId, Vec<usize>)> = if parts.is_empty() {
                Vec::new()
            } else {
                self.state
                    .entries_of(l, commit)
                    .filter(|(b, _)| b != id && host.is_none_or(|s| self.state.holds_at(s, l, b)))
                    .filter_map(|(b, o)| match &o.kind {
                        // a must-not-hold superset counts for nothing, nor one at another host (the
                        // label there lacks the writes this one carries: the superset goes up first)
                        Kind::Commit { parts: p2, .. } if !self.holds_nothing(commit, p2) => Some((b, p2.clone())),
                        _ => None,
                    })
                    .collect()
            };
            let mut sups: Vec<Vec<usize>> = Vec::new();
            for (b, _) in others {
                // compared on what the label's actor reads of each (`readable`); a forged
                // superset holds nothing (it would get the real blob deleted)
                let p2 = self.others_readable(g, l, &b);
                if p2.len() > parts.len() && parts.iter().all(|p| p2.contains(p)) && self.genuine(&b) {
                    sups.push(p2);
                }
            }
            // a superset whose extra deltas hold nothing only a blob can carry (`must_carry`)
            // carries nothing more: this blob is one a right holder dropped them from
            // (spec/sync.md §6, §7)
            let mut sup = false;
            let keeps = if sups.is_empty() { Default::default() } else { self.keeps(commit)? };
            'sups: for p2 in sups {
                for ai in p2.iter().filter(|ai| !parts.contains(ai)) {
                    if self.must_carry(&h, commit, &keeps, *ai, snaps, note)? {
                        sup = true;
                        break 'sups;
                    }
                }
            }
            if sup {
                f.required = true;
                f.strict_subset = true;
            } else if desired.iter().any(|d| parts.iter().all(|p| d.contains(p))) {
                // a lagging blob: the superset goes up first
                return Ok(None);
            } else {
                // another node's card nobody needs any more goes (spec/permissions.md §4). A copy
                // is not judged by its author's chain: the chain moves after it (the granter's
                // edge lowered, a removal of him), a judge cannot tell a chain that will not come
                // from one still uploading, and a copy deleted is a grant its group's later
                // readers never find
                if settled && self.stale_card(at, commit, &h, opened) {
                    return Ok(Some((Hold::MustNot(Why::Outside), false, aspects)));
                }
                // other certificates (role-class, node cards, creation records of
                // things outside the closure) are not ours to judge; by this entry's parts: a
                // creation record's commit usually writes more (a group's first placement, a
                // thing's first value)
                let closure = self.engine.closure(g);
                let card = opened.iter().filter_map(|ai| h.aspects.get(*ai)).all(|a| matches!(a.ak.as_str(), "keys.0" | "node.0" | "reach.0") || a.ak.as_str() == "created.0" && !closure.contains(&a.tid));
                if h.kind.is_role() || card {
                    return Ok(None);
                }
                // a lasting header this node does not judge lasting: a node may yet judge it so, or
                // it is left from a purge that fell. Deleting what another must hold would not end:
                // it stays (spec/sync.md §6)
                if opened.is_empty() && (!h.purge.is_empty() || (h.ephemeral.is_none() && h.aspects.iter().any(|a| h.permanent(a)))) {
                    return Ok(None);
                }
                // only deltas this node holds can be judged outside the label
                let c = *commit;
                let held: Vec<usize> = self.engine.run(|tx| Ok(tx.get_commit(&c)?.map(|b| b.parts.iter().map(|p| p.ai).collect()).unwrap_or_default()))?;
                // and only once the view is settled (a peer's placement this node cannot
                // explain yet stays: a receiver keeps what a peer placed, spec/sync.md §3)
                if !opened.iter().all(|p| held.contains(p)) || !settled {
                    return Ok(None);
                }
                // a memory entry never in this label's closure here: after a start the closure is
                // what has arrived so far, and the placement may still be on its way (deleting
                // it here while a holder uploads it again is a storm until that placement comes)
                if e.memory && !self.state.memory_in_closure.contains(&(*l, *id)) {
                    return Ok(None);
                }
            }
        }
        // a body outside the required set holds no write this label must keep
        let hold = classify(&f);
        Ok(Some((hold, hold != Hold::MustNot(Why::Outside), aspects)))
    }

    /// An entry of a memory commit the engine forgot whole (spec/sync.md §9: covered,
    /// superseded, expired, freed): must-not-hold, with live writes to carry when a snapshot or
    /// superseder covers it (`carried`), none otherwise. Judged again every pass until it goes
    /// (`unsure`: what it waits for is the carrier's presence at the host, no state change here).
    /// A superseded body is its author's to delete, nobody else's.
    fn judge_forgotten(&mut self, commit: &CommitId, parts: &[usize], note: &mut Note) -> Option<Judged> {
        let f = self.memory.forgotten.get(commit)?;
        let aspects: Vec<(Tid, Ak)> = parts.iter().filter_map(|ai| f.header.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect();
        let live = match &f.why {
            MemoryDrop::Gone => false,
            MemoryDrop::Covered { .. } => true,
            MemoryDrop::Superseded { .. } => {
                if Some(f.header.author) != self.engine.account_tid() {
                    return None;
                }
                true
            }
        };
        note.unsure = true;
        Some((Hold::MustNot(Why::Dropped), live, aspects))
    }

    /// Unopened entries present at `host` under replaced label `l` that only content commits
    /// list (their chunks, tree nodes and pages): no role-class commit or certificate
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

    /// Whether an entry of commit `c` holding `parts` is another node's card that no holder
    /// needs (spec/permissions.md §4): every part is its author's `node.0`, `reach.0` or `keys.0`,
    /// and each is superseded by a newer commit on that aspect present here under `l`, or, for
    /// `node.0` and `reach.0`, the node departed (a departed node is never dialed; its `keys.0`
    /// stays while chains of its old writes may need it).
    fn stale_card(&mut self, at: &At, c: &CommitId, h: &osis_commit::Header, parts: &[usize]) -> bool {
        let (g, l, host) = (&at.g, &at.l, at.host.as_ref());
        // a card is the node's own write
        let me = self.engine.tid();
        let aks: BTreeSet<&str> = parts.iter().filter_map(|ai| h.aspects.get(*ai)).filter(|a| a.tid == h.author).map(|a| a.ak.as_str()).collect();
        let all_card = parts.iter().filter_map(|ai| h.aspects.get(*ai)).all(|a| a.tid == h.author && is_card(a.ak.as_str()));
        if h.author == me || aks.is_empty() || !all_card {
            return false;
        }
        // departed: it reads the actor no more, and an applied write removed an edge on its way
        // to the actor, or one there passed its `until`: its own, or that of an actor it reads
        // through (its person). A view lacking the node's chain holds no such write on its way
        // and proves nothing ("reads no more" alone misjudged such holders, spec/sync.md §6)
        let actor = self.engine.group_actor(g);
        // a node reads through its account, as its own `reach.0` states (one forged only keeps its card)
        let author = h.author;
        let principal = self.engine.get_typed(&author, &ct::REACH).ok().flatten().and_then(|r| r.account).unwrap_or(author);
        let core = &self.engine.core;
        let now = osis_base::Ts::make(WallMs(self.now()), 0).unwrap_or_default();
        let departed = !core.may_read(&principal, &actor)
            && core.timelines.get(&principal).is_some_and(|tl| {
                tl.applied().keys().any(|w| {
                    tl.role_commit(&w.0).and_then(|mc| mc.ops.get(w.1 as usize)).is_some_and(|op| {
                        let ended = op.edge.is_none_or(|e| !e.alive_at(Some(now)));
                        let way = (op.holder == principal || core.may_read(&principal, &op.holder)) && (op.target == actor || core.may_read(&op.target, &actor));
                        ended && way
                    })
                })
            });
        aks.into_iter().all(|ak| {
            if departed && ak != "keys.0" {
                return true;
            }
            // newer: the node's own valid write, with an entry here checked genuine (anyone may
            // sign a commit writing another's card with a later `ts`)
            let Some(x) = self.engine.latest_by(&author, ak, Some(&author)) else { return false };
            if x == *c || !self.engine.header(&x).is_some_and(|n| n.ts > h.ts) {
                return false;
            }
            let ids: Vec<BlobId> = self.state.entries_of(l, &x).filter(|(id, _)| host.is_none_or(|s| self.state.holds_at(s, l, id))).map(|(id, _)| id).collect();
            ids.into_iter().any(|id| self.genuine(&id))
        })
    }

    /// Deletes must-not-hold entries present at the host, carriers first (spec/sync.md §6,
    /// §7). Judges the entries and bodies of `scope`; what waits goes into `left`.
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
                left.waits.held_back.insert(commit);
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
        // (spec/sync.md §2: only role-class commits and certificates stay)
        if keys.delete.is_some() && self.is_replaced(g, &l) {
            for b in self.replaced_leftovers(&host, &l) {
                if busy(self, &b) {
                    continue;
                }
                if let Some(item) = delete_item(keys, &l, b, None, &[], true) {
                    send(self, b);
                    items.push(item);
                }
            }
        }
        // the blobs certificate copies link (`place_linked`) once this node knows no entry of
        // their commit under the label any more (deleted; one placed and not confirmed yet still
        // counts), unless another present entry links them too (another copy of the commit):
        // nothing under the label needs them
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
                if let Some(item) = delete_item(keys, &l, b, None, &[], true) {
                    send(self, b);
                    items.push(item);
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

    /// Whether the delta of commit `c` on aspect `ai` has a live write in this node's state (spec/commits.md §5): a
    /// dropped body keeps its live writes there (spec/crdt.md §4.6); a purged one holds none.
    pub(super) fn part_live(&mut self, h: &osis_commit::Header, c: &CommitId, ai: usize) -> bool {
        let Some(a) = h.aspects.get(ai) else { return false };
        if self.engine.part_valueless(h, c, ai) {
            return false;
        }
        self.engine.delta_live(c, &a.tid, &a.ak).unwrap_or(true)
    }

    /// Whether other entries under the label at the host carry every live write of
    /// must-not-hold entry `e` the label's actor may read (spec/sync.md §7), and the aspects only
    /// a snapshot this node writes can carry.
    /// A kept delta's: a blob of the commit holding it that is not must-not-hold (the dropping
    /// node's rewrite, `carried_by`) or a snapshot covering it; none is ever asked for: the
    /// rewrite is this node's to place. A dropped delta's: the snapshot that covered it when it
    /// was dropped.
    /// With a carrier that is this node's rewrite refused for the cap (`rewrite_capped`): it.
    fn carried(&mut self, at: &At, e: &Entry) -> Result<Carriage> {
        let (g, l, host) = (&at.g, &at.l, at.host.as_ref());
        let Kind::Commit { commit, parts, .. } = &e.kind else { return Ok((false, Vec::new(), None)) };
        // a forgotten memory commit: carried once an entry of what covered or superseded it is
        // held at the host (spec/sync.md §9); nothing here to snapshot for it
        if self.memory.forgotten.contains_key(commit) {
            // what covers or supersedes it now: a coverer forgotten in turn (superseded before
            // it was placed, covered by a later snapshot) stands for what covers that
            let by = self.carriers_of_forgotten(commit);
            let carried = by.iter().any(|s| self.state.entries_of(l, s).any(|(b, _)| host.is_none_or(|host| self.state.holds_at(host, l, &b))));
            // a coverer the host refused for the label's cap goes up again replacing this
            // body, in the room it frees (spec/sync.md §5, §7)
            let via = if carried { None } else { host.and_then(|s| by.iter().flat_map(|c| self.state.entries_of(l, c).map(|(b, _)| b)).find(|b| self.capped.contains(&(*s, *l, *b)))) };
            return Ok((carried || via.is_some(), Vec::new(), via));
        }
        let Some(m) = self.engine.core.ix.commits.get(commit).cloned() else { return Ok((false, Vec::new(), None)) };
        let x = self.engine.group_actor(g);
        let (mut all, mut need, mut via) = (true, Vec::new(), None);
        for &ai in parts {
            let Some(a) = m.header.aspects.get(ai) else { continue };
            let (t, a) = (a.tid, a.ak.clone());
            // a delta the label's actor may not read is carried under its readers' labels
            if !self.engine.core.may_read(&x, &self.engine.core.reader_of(&t)) || !self.part_live(&m.header, commit, ai) {
                continue;
            }
            let dropped = m.body_gone(ai);
            if !dropped && self.carried_by(host, l, commit, &[ai]) || self.snapshot_carries(at, commit, &t, &a, dropped)? {
                continue;
            }
            // this node's rewrite, refused at the host for the label's cap: it goes up again
            // replacing this body, in the room it frees (else a full label would keep a purged
            // body for good)
            if !dropped
                && let Some(q) = host.and_then(|s| self.rewrite_capped(s, l, commit, parts, ai))
            {
                via = via.or(Some(q));
                continue;
            }
            all = false;
            // a kept delta's carrier is the rewrite this node places (spec/sync.md §7, No
            // carrier): only a dropped delta's live writes need a snapshot
            if dropped {
                need.push((t, a));
            }
        }
        Ok((all, need, via))
    }

    /// A blob of commit `c` under `l` holding its delta on aspect `ai`, a strict subset of `parts` (so smaller
    /// than the body it would carry), that is this node's upload `host` refused for the
    /// label's cap (`SyncEngine::capped`).
    fn rewrite_capped(&mut self, host: &HostKey, l: &LabelId, c: &CommitId, parts: &[usize], ai: usize) -> Option<BlobId> {
        let ids: Vec<BlobId> = self
            .state
            .entries_of(l, c)
            .filter(|(id, e)| !e.cert && self.capped.contains(&(*host, *l, *id)) && matches!(&e.kind, Kind::Commit { parts: q, .. } if q.contains(&ai) && q.len() < parts.len() && q.iter().all(|x| parts.contains(x)) && !self.holds_nothing(c, q)))
            .map(|(id, _)| id)
            .collect();
        ids.into_iter().find(|id| self.genuine(id))
    }

    /// Whether a later snapshot of `(t, a)` under the label at the host carries body `body`'s
    /// writes there. A held delta: one covering it, the same test its holders' must-hold asks
    /// (a recorded carrier that covers it no more, turned invalid, carries nothing). A `dropped`
    /// delta (its content is gone, so `covered` checks only the frontier): the snapshot that
    /// covered it when it was dropped, or one covering that whose frontier holds the body's
    /// counters (a co-writer's that went up in its place).
    fn snapshot_carries(&mut self, at: &At, body: &CommitId, t: &Tid, a: &Ak, dropped: bool) -> Result<bool> {
        let (l, host, snaps) = (&at.l, at.host.as_ref(), at.snaps);
        let carrier = if dropped { self.carrier_of(body, t, a) } else { None };
        let candidates: Vec<CommitId> = match carrier {
            None if dropped => Vec::new(),
            _ => carrier.into_iter().chain(snaps.get(&(*t, a.clone())).cloned().unwrap_or_default()).collect(),
        };
        for s in candidates {
            if s == *body || !self.state.entries_of(l, &s).any(|(b, _)| host.is_none_or(|host| self.state.holds_at(host, l, &b))) {
                continue;
            }
            let covers = self.engine.covered(&s, body, t, a)? == Some(true);
            let carries = match carrier {
                Some(k) => k == s || (covers && self.engine.covered(&s, &k, t, a)? == Some(true)),
                None => covers,
            };
            if carries {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// A right holder that must delete a body with live writes and finds no carrier writes a
    /// covering snapshot first when it may write the aspect (spec/sync.md §7). A held valid
    /// snapshot covering the body (another writer's carrier, arrived with the kill) is its
    /// carrier; else every writer dropping the body writes one (duplicates are harmless).
    pub(in crate::sync) fn snapshot_first(&mut self, aspects: &[(Tid, Ak)], body: &CommitId) -> Result<()> {
        if aspects.iter().all(|(t, a)| self.carrier_of(body, t, a).is_some()) {
            return Ok(());
        }
        for (t, a) in aspects {
            // `created.0` is kept forever and never compacted
            if is_role(a) || a.as_str() == "created.0" || self.engine.role_on(t) < Some(Role::Write) {
                continue;
            }
            if self.carrier_of(body, t, a).is_some() {
                continue;
            }
            let held: Vec<CommitId> = self.engine.core.ix.snapshots.get(&(*t, a.clone())).into_iter().flatten().map(|x| x.1).filter(|s| s != body).collect();
            let mut covering = None;
            for s in held {
                if self.engine.covered(&s, body, t, a)? == Some(true) {
                    covering = Some(s);
                    break;
                }
            }
            if let Some(s) = covering {
                self.state.set_carrier(*body, s);
                continue;
            }
            // a snapshot from this node's whole state covers every body of the aspect it applied
            if let Some(s) = self.engine.snapshot(t, a)? {
                self.state.set_carrier(*body, s);
            }
        }
        Ok(())
    }

    /// A carrier of body `body` on `(t, a)` whose own body this node still holds: one recorded
    /// for it here (`State::carriers`), one the engine dropped its part under (`Dropped::covered_by`)
    /// or what a forgotten memory commit was covered or superseded by, followed through carriers
    /// dropped in turn (a carrier dropped before it went up carries nothing: its writes moved to
    /// a later snapshot, or a new one is due).
    fn carrier_of(&self, body: &CommitId, t: &Tid, a: &Ak) -> Option<CommitId> {
        let has = |h: &osis_commit::Header| h.aspects.iter().any(|x| x.tid == *t && x.ak == *a);
        let on = |c: &CommitId| self.engine.header(c).is_some_and(|h| has(&h)) || self.memory.forgotten.get(c).is_some_and(|f| has(&f.header));
        let next = |c: &CommitId| -> Vec<CommitId> {
            let mut v: Vec<CommitId> = self.state.carriers.get(c).map(|x| x.by.iter().rev().copied().collect()).unwrap_or_default();
            v.extend(self.engine.coverers_of(c, t, a));
            v.extend(self.memory.forgotten.get(c).map(|f| f.why.by()).unwrap_or_default());
            v
        };
        let mut seen = BTreeSet::from([*body]);
        let mut stack = next(body);
        while let Some(c) = stack.pop() {
            if !seen.insert(c) || !on(&c) {
                continue;
            }
            if self.engine.body_not_dropped(&c, t, a) {
                return Some(c);
            }
            stack.extend(next(&c));
        }
        None
    }

    /// Chunk, tree-node and page blobs among `cands` whose creating deltas this node dropped
    /// (purge, expiry, compaction), by the commit and chunk entry that list them,
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
                    let dropped = parts.iter().all(|p| m.body_gone(*p)) && parts.iter().any(|p| !self.engine.left_at_hosts(&id, *p));
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

    /// A delete item for a dropped chunk: the label delete key, else a delete key of its delta,
    /// signed for its entry's salt (`Entry::salt`; one never here is fetched for it, its bytes
    /// kept nowhere: `log_events`).
    fn chunk_delete(&mut self, conn: ConnId, keys: &HeadKeys, l: &LabelId, id: &BlobId, (c, ch): &(CommitId, osis_commit::ChunkEntry), out: &mut Vec<crate::sync::Action>) -> Result<Option<osis_label::DeleteItem>> {
        if keys.delete.is_some() {
            return Ok(delete_item(keys, l, *id, None, &[], true));
        }
        self.keep_salts(id, None)?;
        let Some(salt) = self.state.entries.get(&(*l, *id)).and_then(|e| e.salt) else {
            self.fetch_on(conn, *l, [*id], out)?;
            return Ok(None);
        };
        // a chunk's prefix has one group: its creating delta's keys
        let dks = vec![self.engine.chunk_delete_secrets(c, ch)];
        let Some(hb) = self.engine.header(c).map(|h| h.blind) else { return Ok(None) };
        Ok(delete_item(keys, l, *id, Some((&salt, &hb)), &dks, true))
    }

    /// A delete item for an entry: the label delete key, else delete keys this node holds, one
    /// per commitment group of the blob (`every`: a Delete) or of any group (a Replace).
    fn delete_for(&mut self, keys: &HeadKeys, l: &LabelId, id: &BlobId, e: &Entry, every: bool) -> Result<Option<osis_label::DeleteItem>> {
        if keys.delete.is_some() {
            return Ok(delete_item(keys, l, *id, None, &[], true));
        }
        let (Kind::Commit { commit, ais, .. }, Some(salt)) = (&e.kind, e.salt) else { return Ok(None) };
        // a forgotten memory commit's keys are in the header kept for it
        let (dks, hb) = match self.memory.forgotten.get(commit) {
            Some(f) => (self.engine.delete_secrets_by_group(&f.header, ais), Some(f.header.blind)),
            None => (self.engine.delete_secrets_of(commit, ais), self.engine.header(commit).map(|h| h.blind)),
        };
        Ok(delete_item(keys, l, *id, hb.as_ref().map(|hb| (&salt, hb)), &dks, every))
    }
}

fn is_role(a: &Ak) -> bool {
    osis_schema::core_types::is_role_class(a.as_str())
}

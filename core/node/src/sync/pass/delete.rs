//! A pass's deletion judgment (spec/sync.md §5-§7): which entries under the label are
//! must-not-hold and may go now (`judge`, `deletable`), carriers first, by the label delete key
//! or a delete key, freed links of the scope (`freed_now`); at a host (`deletions`) and in this node's own served state (`local_deletions`).

use super::*;
use crate::engine::MemoryDrop;

impl SyncEngine {
    /// The deletion step of a pass's own part, over the entries of `scope` no source holds (those
    /// go by their deletions there, spec/sync.md §5-§7; one a source pulled before this is
    /// recorded again from its tombstone when its stream shows it): a commit entry goes
    /// as `deletable` says
    /// (a live body only with a carrier, a covering snapshot asked for meanwhile, even when its
    /// bytes are gone); any other entry whose bytes this node no longer holds serves nothing and
    /// goes; freed links go (`freed_now`), and the blobs a gone certificate copy linked. Removed
    /// entries are tombstoned (`State::remove_entry`). Expired ones went before
    /// (`expire_entries`). What waits goes into `left`.
    pub(super) fn local_deletions(&mut self, at: &At, bodies: &[Body], scope: &Scope, left: &mut Left) -> Result<()> {
        let (l, settled) = (at.l, at.settled);
        let ids: Vec<BlobId> = self.scope_entries(&l, scope).into_iter().filter(|id| self.state.entries.contains_key(&(l, *id)) && !self.state.present_anywhere(&l, id)).collect();
        self.stats.entries += ids.len() as u64;
        let desired = desired(bodies);
        // freed links (spec/sync.md §7), first: tombstoned, whether or not their bytes are here
        // (those went when judged, `freed_now`), never taken below as an entry serving nothing
        let all = self.scope_entries(&l, scope);
        for f in self.freed_now(all)? {
            let b = f.link.blob;
            if self.state.entries.contains_key(&(l, b)) && !self.state.present_anywhere(&l, &b) {
                self.state.remove_entry(l, b);
            }
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
                    Fate::Delete(..) => {
                        self.state.remove_entry(l, id);
                        self.forget_entry_blob(&id)?;
                        continue;
                    }
                    Fate::Keep if held => continue,
                    Fate::Keep => {}
                }
            }
            // one awaiting a record keeps its entry: the record arriving fetches it again
            // (`reopen_awaiting`), from a peer that reads the label too
            if !held && !matches!(e.kind, Kind::Awaits { .. }) {
                self.state.drop_entry(l, id);
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
        }
        Ok(())
    }

    /// What may become of entry `id` under `l` (spec/sync.md §6, §7): `judge`, then a body
    /// with a delta to carry goes only with a carrier (`carried`; else a covering snapshot is asked for,
    /// `snapshot_first`, when `carrier`) and by a delete item this node can make. `host`
    /// `None`: this node's own served state.
    pub(super) fn deletable(&mut self, at: &At, id: &BlobId, e: &Entry, desired: &Desired, carrier: bool, note: &mut Note) -> Result<Fate> {
        let Some((Hold::MustNot(why), to_carry, aspects)) = self.judge(at, id, e, desired, note)? else { return Ok(Fate::Keep) };
        let (carried, need) = match why {
            _ if !to_carry => (true, Vec::new()),
            Why::Duplicate | Why::StrictSubset => (true, Vec::new()),
            _ => self.carried(at, e)?,
        };
        if !may_delete(to_carry, carried) {
            if carrier && let Kind::Commit { commit, .. } = &e.kind {
                self.snapshot_first(&need, commit)?;
            }
            // judged again once a write on its aspects changes liveness (a carrier is a trigger)
            note.waits.extend(aspects);
            return Ok(Fate::Wait);
        }
        // a Delete needs every commitment group signed (spec/sync.md §5)
        Ok(match self.delete_for(at.keys, &at.l, id, e)? {
            Some(item) => Fate::Delete(why, item),
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
        let aspects: Vec<(Tid, Ak)> = parts.iter().filter_map(|ai| h.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect();
        // a minting's header alone its things' witnesses supersede (spec/commits.md §5, A thing's
        // mintings travel with its record)
        if opened.is_empty() && settled && !desired.get(commit).is_some_and(|d| d.iter().any(|p| p.is_empty())) {
            match self.superseded_minting(g, l, host, commit, &h) {
                Some(true) => return Ok(Some((Hold::MustNot(Why::Outside), false, Vec::new()))),
                // its witness not up yet: judged again next pass
                Some(false) => note.unsure = true,
                None => {}
            }
        }
        // a certificate of destroyed things (their frozen edges or a request destroying one outside the
        // closure, a minting's or a request's header alone: spec/permissions.md §4, spec/commits.md
        // §5 Destruction) is there for the label's things that need them told destroyed, whatever this
        // node kept: it goes once a settled view finds none on an authority path into the
        // closure or listing or referencing one there (`destroyed_needed`)
        if let Some(about) = self.destroyed_certificate(g, commit, &h, opened, desired) {
            if !settled {
                return Ok(None);
            }
            let needed = self.engine.destroyed_needed(g)?;
            if about.iter().any(|t| needed.contains(t)) {
                // judged again once what names, lists or references them ends, changes or
                // leaves the closure
                let held = &self.engine.core.ix.held;
                let named: BTreeSet<Tid> = about.iter().flat_map(|t| held.named_on(t).copied().collect::<Vec<_>>()).collect();
                note.waits.extend(named.into_iter().map(|n| (n, ct::CREATED.name())));
                for t in &about {
                    note.waits.extend(self.engine.references_to(t)?.into_iter().map(|r| (r.source, r.ak)));
                }
                note.waits.push((*g, ct::GROUP.name()));
                return Ok(None);
            }
            return Ok(Some((Hold::MustNot(Why::Outside), false, Vec::new())));
        }
        if opened.iter().any(|p| m.body_gone(*p) && !self.engine.left_at_hosts(commit, *p)) {
            // a body dropped as covered leaves hosts `MAX_DRIFT` past its keep-at-least bound, once
            // every node's clock agrees it may go (spec/commits.md §5 Keep bounds)
            let from = opened.iter().filter_map(|p| m.dropped(*p)).map(|d| d.hosts_from).max().unwrap_or(0);
            if from > now {
                note.at(from);
                return Ok(None);
            }
            // every delta only a blob carries counts, the kept ones too (spec/sync.md §7,
            // `carried`); under a replaced label no content entry stays, carried there or not:
            // its replacement holds the content (spec/sync.md §2)
            let content_gone = self.is_replaced(g, l) && super::replaced_content(opened.iter().filter_map(|ai| h.aspects.get(*ai)).map(|a| &a.ak));
            let keeps = self.engine.part_keeps(commit)?;
            let to_carry = !content_gone && opened.iter().any(|ai| self.part_to_carry(commit, &m, &keeps, *ai, note));
            return Ok(Some((Hold::MustNot(Why::Dropped), to_carry, aspects)));
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
            // (in this node's own store: useless at a source, where another encryption replaces it;
            // one whose bytes it dropped is no copy either, as `entry_for` places the body anew)
            let useless = match host {
                Some(s) => self.state.is_gone_at(s, l, id),
                None => self.state.useless_anywhere(l, id),
            };
            let same: Vec<BlobId> = self.state.entries_of(l, commit).filter(|(b, o)| (b < id || (useless && b != id)) && !o.cert && matches!(&o.kind, Kind::Commit { .. }) && match host {
                Some(s) => self.state.holds_at(s, l, b),
                None => !self.state.useless_anywhere(l, b) && self.engine.has_blob(b),
            }).map(|(b, _)| b).collect();
            f.duplicate_higher = same.into_iter().any(|b| self.others_readable(g, l, &b) == *parts && self.genuine(&b));
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
            let keeps = if sups.is_empty() { Default::default() } else { self.engine.part_keeps(commit)? };
            'sups: for p2 in sups {
                for ai in p2.iter().filter(|ai| !parts.contains(ai)) {
                    if self.must_carry(&h, commit, &keeps, *ai, snaps, note)? {
                        sup = true;
                        break 'sups;
                    }
                }
            }
            if sup && !settled {
                // "covered by no snapshot" needs a settled view, as must-hold's uncovered does
                // (spec/sync.md §6): an entry being fetched may be the snapshot covering the
                // extra delta, which a co-writer that dropped it judged by
                return Ok(None);
            } else if sup {
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
                if opened.is_empty() && (!h.purge.is_empty() || (h.ephemeral.is_none() && h.aspects.iter().any(|a| self.engine.permanent(&h, a)))) {
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

    /// Whether a header alone of commit `c` (header `h`) under `l` is a superseded minting of the
    /// things it mints, all outside `g`'s closure (spec/commits.md §5, A thing's mintings travel
    /// with its record): standing lower than each one's witness and expiring before it (or a
    /// minting tying it). `Some(true)`: the label holds such a witness at `host`, so it goes;
    /// `Some(false)`: not yet (judged again each pass); `None`: no such header. Any node judges it:
    /// one that lacks a request dropping its witness ranks that one no lower than it stands, so
    /// what stays reads the thing live while it is, and once it is destroyed its witness is placed
    /// again (`certificates`). Expiry orders copies alike in every view, so two nodes whose
    /// standings differ never delete each other's copy in one round: the latest-expiring copy stays.
    fn superseded_minting(&mut self, g: &Tid, l: &LabelId, host: Option<&HostKey>, c: &CommitId, h: &osis_commit::Header) -> Option<bool> {
        let minted: BTreeSet<Tid> = h.aspects.iter().filter(|a| a.ak.as_str() == osis_commit::retention::CREATED).map(|a| a.tid).collect();
        let closure = self.engine.closure(g);
        if minted.is_empty() || !h.requests().is_empty() || minted.iter().any(|t| closure.contains(t)) {
            return None;
        }
        let hosts = host.map(std::slice::from_ref);
        let mut held = true;
        for t in &minted {
            let w = self.engine.witness(t)?;
            if self.engine.mintings_of(t).iter().find(|m| m.commit == *c).is_none_or(|m| m.standing >= w.standing) {
                return None;
            }
            let later = |z: Option<u64>| match (h.expires, z) {
                (Some(x), Some(z)) => x < z,
                (x, z) => x.is_some() && z.is_none(),
            };
            let ties: Vec<CommitId> = self.engine.mintings_of(t).into_iter().filter(|m| m.standing == w.standing && m.commit != *c).map(|m| m.commit).collect();
            let ties: Vec<CommitId> = ties.into_iter().filter(|z| self.engine.header(z).is_some_and(|zh| later(zh.expires))).collect();
            if ties.is_empty() {
                return None;
            }
            held &= ties.iter().any(|z| self.header_held_at(*l, z, hosts));
        }
        Some(held)
    }

    /// The destroyed things an entry of commit `c` (header `h`, parts `opened`) is a certificate of
    /// under `g`'s label, when that is all it is: a header alone (no lasting header the label
    /// wants) minting one or carrying a request destroying one, outside the closure or, inside, a
    /// header that cannot be lasting (`Engine::may_last_on`); or every
    /// part a `roles.0` or destroying request (`purge.0`, `released.0`) part on one outside the
    /// closure (inside, such a part is a closure body).
    fn destroyed_certificate(&self, g: &Tid, c: &CommitId, h: &osis_commit::Header, opened: &[usize], desired: &Desired) -> Option<BTreeSet<Tid>> {
        let core = &self.engine.core;
        let closure = self.engine.closure(g);
        let outside = |t: &Tid| !closure.contains(t) && core.destroyed(t);
        let about: BTreeSet<Tid> = if opened.is_empty() {
            if desired.get(c).is_some_and(|d| d.iter().any(|p| p.is_empty())) {
                return None;
            }
            self.header_certifies(&closure, h)
        } else {
            let on: Vec<&osis_commit::AspectEntry> = opened.iter().filter_map(|ai| h.aspects.get(*ai)).collect();
            if on.len() < opened.len() || !on.iter().all(|a| (a.ak.as_str() == "roles.0" || osis_commit::retention::destroying_request(a.ak.as_str())) && outside(&a.tid)) {
                return None;
            }
            on.iter().map(|a| a.tid).collect()
        };
        (!about.is_empty()).then_some(about)
    }

    /// The destroyed things a header alone of `h` is a certificate of under a label of `closure`
    /// (`destroyed_certificate`): those it mints or requests, outside the closure or, inside, where
    /// it cannot be a lasting header (judged as one).
    pub(super) fn header_certifies(&self, closure: &BTreeSet<Tid>, h: &osis_commit::Header) -> BTreeSet<Tid> {
        let core = &self.engine.core;
        let minted = h.aspects.iter().filter(|a| a.ak.as_str() == osis_commit::retention::CREATED).map(|a| a.tid);
        let requested = h.requests().iter().map(|i| *i.tid()).collect::<Vec<_>>();
        minted.chain(requested).filter(|t| core.destroyed(t) && (!closure.contains(t) || !self.engine.may_last_on(h, t))).collect()
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
            // never kept as forgotten: its entries are skipped as awaiting (`memory_step`)
            MemoryDrop::Awaits { .. } => return None,
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
                    if !replaced_content(m.view.aspects.iter().map(|a| &a.ak)) {
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
        // a node's card: an account's `keys.0` is a chain certificate (spec/permissions.md §4)
        if h.author == me || aks.is_empty() || !all_card || self.engine.core.is_account(&h.author) {
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
        // deletes in flight on this connection are not sent again (`RESEND_MS`), nor one twice in
        // a pass (`sent`)
        let now = self.now();
        let mut sent: BTreeSet<BlobId> = BTreeSet::new();
        let busy = |s: &Self, sent: &BTreeSet<BlobId>, id: &BlobId| sent.contains(id) || s.conns.get(&conn).is_some_and(|c| crate::sync::in_flight(c, &c.req.deleting, (l, *id), now));
        let mut items = Vec::new();
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
                Fate::Delete(_, item) => {
                    left.commits.insert(commit);
                    if !busy(self, &sent, &id) {
                        sent.insert(id);
                        items.push(item);
                    }
                }
            }
        }
        // freed links, judged now (spec/sync.md §7: a piece no held source of its thing links),
        // deleted where present; the node blobs a judgment waits for fetched from here
        // of the scope, those whose delete is in flight wait for their resend, unjudged: a
        // judgment costs what the pass may send
        let (waiting, judged): (Vec<BlobId>, Vec<BlobId>) = ids.iter().partition(|id| busy(self, &BTreeSet::new(), id));
        left.blobs.extend(waiting);
        let freed = self.freed_now(judged)?;
        let wants: Vec<BlobId> = self.engine.freed_wants().filter(|b| self.state.is_present(&host, &l, b)).copied().collect();
        left.blobs.extend(wants.iter().copied());
        self.fetch_on(conn, l, wants, out)?;
        for f in &freed {
            let id = f.link.blob;
            if !self.state.is_present(&host, &l, &id) {
                continue;
            }
            left.blobs.insert(id);
            if busy(self, &sent, &id) {
                continue;
            }
            if let Some(item) = self.freed_delete(keys, &l, f) {
                sent.insert(id);
                items.push(item);
            }
        }
        // under a replaced label the chunk and page entries of content commits go with them
        // (spec/sync.md §2: only role-class commits and certificates stay)
        if keys.delete.is_some() && self.is_replaced(g, &l) {
            for b in self.replaced_leftovers(&host, &l) {
                if busy(self, &sent, &b) {
                    continue;
                }
                if let Some(item) = delete_item(keys, &l, b, None, &[]) {
                    sent.insert(b);
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
                    if !busy(self, &sent, &b) {
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
                if let Some(item) = delete_item(keys, &l, b, None, &[]) {
                    sent.insert(b);
                    items.push(item);
                }
            }
        }
        // a delete is judged by this node's role view (a carrier's validity, a purge's or a
        // compaction's rights); the label's other holders at the host judge by what the host
        // holds. While a role commit or a superseding body this node holds there is still on
        // its way, a holder lacking it may still hold what goes: a body it places again under a
        // fresh encryption past the tombstone, every pass; a large value's chunks it writes again
        // re-encrypted (`relink_lost`), reviving a purged or replaced value. So every delete
        // waits until the source holds what this node places there (`At::behind`; at most the
        // relay delay and a pull; `relay_at` schedules the pass)
        if !at.behind {
            if let Some(c) = self.conns.get_mut(&conn) {
                for id in &sent {
                    c.req.deleting.insert((l, *id), (now, crate::sync::UNTAGGED));
                }
            }
            if !items.is_empty() {
                self.command(conn, Command::Delete { label: l, items }, out)?;
            }
        }
        // tags this pass's earlier requests too (`clear_deposits`' deletes)
        self.given(conn);
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

    /// Whether part `ai` of a commit (`m`, its `Engine::part_keeps` `keeps`) leaves a label only
    /// with a carrier there (spec/sync.md §7): holding a live write; held and before its
    /// keep-at-least bound (must-hold whatever covers it: the deleter's side of `must_carry`,
    /// what a holder would place again); or dropped as covered (its cover is why it goes, and a
    /// holder lacking the cover judges it uncovered, so the cover goes up first).
    fn part_to_carry(&mut self, c: &CommitId, m: &crate::engine::Meta, keeps: &[u64], ai: usize, note: &mut Note) -> bool {
        if m.body_gone(ai) {
            return m.dropped(ai).is_some_and(|d| d.why == crate::engine::DropFor::Cover) || self.part_live(&m.header, c, ai);
        }
        self.part_live(&m.header, c, ai) || self.part_kept(keeps, ai, note)
    }

    /// Whether other entries under the label at the host carry every delta of must-not-hold
    /// entry `e` the label's actor may read that needs a carrier (`part_to_carry`, spec/sync.md
    /// §7 Carriers), and the aspects only a snapshot this node writes can carry.
    /// A held delta's: a blob of the commit holding it that is not must-not-hold (the dropping
    /// node's rewrite, `carried_by`) or a snapshot covering it; none is ever asked for: the
    /// rewrite is this node's to place. A dropped delta's: the snapshot that covered it when it
    /// was dropped.
    fn carried(&mut self, at: &At, e: &Entry) -> Result<Carriage> {
        let (g, l, host) = (&at.g, &at.l, at.host.as_ref());
        let Kind::Commit { commit, parts, .. } = &e.kind else { return Ok((false, Vec::new())) };
        // a forgotten memory commit not held again: carried once an entry of what covered or
        // superseded it is held at the host (spec/sync.md §9); nothing here to snapshot for it.
        // A superseded one, its author's own to delete, goes at a host full for the label too:
        // its superseder waits there for the room it holds, and no other node places it again.
        // Not a covered one: a co-writer lacking the cover there places what it covers again
        // (or covers it anew) into the room freed, the cover is refused again, and the two loop.
        // Held again, the join judges it like any held body (`judge`): the record of what
        // covered it then may cover it no more (a validity flip since)
        if let Some(f) = self.memory.forgotten.get(commit)
            && !self.engine.core.ix.commits.contains_key(commit)
        {
            let superseded = matches!(f.why, MemoryDrop::Superseded { .. });
            // what covers or supersedes it now: a coverer forgotten in turn (superseded before
            // it was placed, covered by a later snapshot) stands for what covers that
            let by = self.carriers_of_forgotten(commit);
            let carried = (at.full && superseded && !by.is_empty()) || by.iter().any(|s| self.state.entries_of(l, s).any(|(b, _)| host.is_none_or(|host| self.state.holds_at(host, l, &b))));
            return Ok((carried, Vec::new()));
        }
        let Some(m) = self.engine.core.ix.commits.get(commit).cloned() else { return Ok((false, Vec::new())) };
        // judged on what the label's actor reads (`readable`, an account's devices actor reading
        // as the account), as the label's bodies are: a delta it may not read is carried under
        // its readers' labels
        let readable = self.readable(g, commit, parts);
        let keeps = self.engine.part_keeps(commit)?;
        let (mut all, mut need) = (true, Vec::new());
        for &ai in parts {
            let Some(a) = m.header.aspects.get(ai) else { continue };
            let (t, a) = (a.tid, a.ak.clone());
            if !readable.contains(&ai) || !self.part_to_carry(commit, &m, &keeps, ai, &mut Note::default()) {
                continue;
            }
            let dropped = m.body_gone(ai);
            if !dropped && self.carried_by(host, l, commit, &[ai]) || self.snapshot_carries(at, commit, &t, &a, dropped)? {
                continue;
            }
            all = false;
            // a kept delta's carrier is the rewrite this node places (spec/sync.md §7, No
            // carrier): only a dropped delta's live writes need a snapshot
            if dropped {
                need.push((t, a));
            }
        }
        Ok((all, need))
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
            if !self.snapshots_on(t, a) || self.carrier_of(body, t, a).is_some() {
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

    /// Whether this node writes compaction snapshots of `(t, a)`: it may write there, and the
    /// aspect is compacted (`created.0` is kept forever, `addenda.0` read whole: never compacted).
    fn snapshots_on(&self, t: &Tid, a: &Ak) -> bool {
        !is_role(a) && a.as_str() != "created.0" && !osis_schema::core_types::is_addenda(a.as_str()) && self.engine.role_on(t) >= Some(Role::Write)
    }

    /// After purge requests applied (`Engine::take_purges`): on each named aspect this node
    /// snapshots, unless it holds a snapshot of the aspect the purge left whole covering every
    /// named body it had applied (held, or dropped as covered), it writes one from its whole state
    /// (spec/commits.md §5 Purge). It carries the purged writes value-less, so a node that never
    /// held them reads as this one once it holds it; duplicates from several writers are harmless
    /// (spec/sync.md §7).
    pub(in crate::sync) fn purge_resnapshots(&mut self) -> Result<()> {
        for ((t, a), held) in self.engine.take_purges() {
            if !self.snapshots_on(&t, &a) {
                continue;
            }
            // a snapshot the purge stripped goes at hosts (`snapshot_first`): only a whole, valid
            // one carries (and with no named body applied here, it alone decides)
            let snaps: Vec<CommitId> = self.engine.core.ix.snapshots.get(&(t, a.clone())).into_iter().flatten().map(|x| x.1).filter(|s| self.engine.holds_valid_snapshot(s, &t, &a)).collect();
            let mut covered = false;
            'snaps: for s in &snaps {
                for b in &held {
                    if self.engine.covered(s, b, &t, &a)? != Some(true) {
                        continue 'snaps;
                    }
                }
                covered = true;
                break;
            }
            // a refusal here leaves the rest of the engine's changes to drain
            if !covered && let Err(e) = self.engine.snapshot(&t, &a) {
                self.diag(format!("purge re-snapshot of {t} {a}: {e}"));
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

    /// The freed links among `scope`'s blobs and those freed since the last call, judged now
    /// (`Engine::judge_freed`, spec/sync.md §7), never the whole set: those freed for the first
    /// time are released (`freed_release`); those no label entry known here names leave the set.
    /// The rest, to delete where an entry of them is present.
    pub(crate) fn freed_now(&mut self, scope: impl IntoIterator<Item = BlobId>) -> Result<Vec<crate::retention::freed::Freed>> {
        let new = self.engine.take_freed_new();
        let blobs: BTreeSet<BlobId> = new.iter().copied().chain(scope).collect();
        let mut j = self.engine.judge_freed(&blobs)?;
        j.fresh.extend(new);
        self.freed_release(j)
    }

    /// Every freed link judged, a page at a time (at start, a crash may have come between a
    /// judgment and its release; a judgment of everything).
    pub(crate) fn freed_sweep(&mut self) -> Result<()> {
        let mut from = Vec::new();
        loop {
            let (mut j, next) = self.engine.judge_freed_page(&from)?;
            // a link judged before a crash may still have its bytes here
            let held: Vec<BlobId> = j.freed.iter().map(|f| f.link.blob).filter(|b| !self.state.blobs.contains_key(b) && self.engine.has_blob(b)).collect();
            j.fresh.extend(held);
            self.freed_release(j)?;
            match next {
                Some(n) => from = n,
                None => return Ok(()),
            }
        }
    }

    /// Of judgment `j`: the bytes of the freed links judged for the first time still held here
    /// go (their salts kept with the entries naming them, a memory entry's charge released) and
    /// their entries are judged again; those no label entry known here names leave the set.
    /// The rest.
    fn freed_release(&mut self, j: crate::retention::freed::Judgment) -> Result<Vec<crate::retention::freed::Freed>> {
        let mut labels = BTreeSet::new();
        let (mut durable, mut memory) = (Vec::new(), Vec::new());
        for f in j.freed.iter().filter(|f| j.fresh.contains(&f.link.blob)) {
            let b = f.link.blob;
            for l in self.state.labels_of(&b) {
                self.state.touch(l, b);
                labels.insert(l);
            }
            if self.state.blobs.contains_key(&b) || !self.engine.has_blob(&b) {
                continue;
            }
            self.keep_salts(&b, None)?;
            if f.memory() { &mut memory } else { &mut durable }.push(b);
            for l in self.state.labels_of(&b) {
                self.state.charge_memory(l, b, None);
            }
        }
        self.delete_blobs_of(&durable, false)?;
        self.delete_blobs_of(&memory, true)?;
        if !labels.is_empty() {
            self.mark_labels(labels.iter());
        }
        let (gone, out): (Vec<_>, Vec<_>) = j.freed.into_iter().partition(|f| !self.state.named(&f.link.blob));
        self.engine.freed_done(&gone.iter().map(|f| (f.tid, f.link.blob)).collect::<Vec<_>>())?;
        Ok(out)
    }

    /// A delete item for freed link `f` under `l`: the label delete key when the blob's held
    /// prefix bore the link (`Freed::borne`), else the delete keys it names that this node holds,
    /// signed for the link's salt and thing blind, which the host checks against the prefix.
    fn freed_delete(&self, keys: &HeadKeys, l: &LabelId, f: &crate::retention::freed::Freed) -> Option<osis_label::DeleteItem> {
        if keys.delete.is_some() && f.borne {
            return delete_item(keys, l, f.link.blob, None, &[]);
        }
        let (salt, blind) = f.blinding();
        delete_item_by_level(keys, l, f.link.blob, (&salt, &blind), &[self.engine.freed_delete_secrets(f)])
    }

    /// A delete item for an entry: the label delete key, else delete keys this node holds, one
    /// per commitment group of the blob.
    fn delete_for(&mut self, keys: &HeadKeys, l: &LabelId, id: &BlobId, e: &Entry) -> Result<Option<osis_label::DeleteItem>> {
        if keys.delete.is_some() {
            return Ok(delete_item(keys, l, *id, None, &[]));
        }
        let (Kind::Commit { commit, ais, .. }, Some(salt)) = (&e.kind, e.salt) else { return Ok(None) };
        // a forgotten memory commit's keys are in the header kept for it
        let (dks, hb) = match self.memory.forgotten.get(commit) {
            Some(f) => (self.engine.delete_secrets_by_group(&f.header, ais), Some(f.header.blind)),
            None => (self.engine.delete_secrets_of(commit, ais), self.engine.header(commit).map(|h| h.blind)),
        };
        Ok(delete_item(keys, l, *id, hb.as_ref().map(|hb| (&salt, hb)), &dks))
    }
}

fn is_role(a: &Ak) -> bool {
    osis_schema::core_types::is_role_class(a.as_str())
}


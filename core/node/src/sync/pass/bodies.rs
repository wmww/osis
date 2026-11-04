//! What a label should hold (spec/sync.md §6): must-hold judgment, which entry holds a body,
//! placing one, and whether an entry is genuine.

use super::*;

impl SyncEngine {
    /// The entries the must-hold bodies of `l` need (spec/sync.md §6), by priority: the entry of
    /// each body (at `host` if there, else any genuine one; `None`: this node's own served
    /// state, any entry), else a fresh placement when this node may upload or deposit it, with
    /// the blobs it links when this node writes. Another node's body not at `host` waits for
    /// its author or a co-writer (`relay_at`).
    pub(super) fn body_sends(&mut self, p: &Head, bodies: &[Body], snaps: &Snaps, snapping: &Unsettled, left: &mut Left) -> Result<Vec<Out>> {
        let (g, l, keys, read_ok, host) = (&p.g, p.l, &p.keys, p.read_ok, p.host.as_ref());
        let mut sends = Vec::new();
        self.stats.bodies += bodies.len() as u64;
        let mut note = Note::default();
        // a fill always has an entry on its way that may be a snapshot, but none covers what only
        // this node has sent: its own writes go out meanwhile
        let filling = self.filling(&l);
        let own_snapping: Unsettled = snapping.iter().flatten().cloned().map(Some).collect();
        for b in bodies {
            let snapping_b = if filling && self.own(&b.commit) { &own_snapping } else { snapping };
            let needed = self.must_hold(b, snaps, snapping_b, &mut note)?;
            note.leave(b.commit, left);
            if snapping.contains(&None) {
                left.waits.held_back.insert(b.commit);
            }
            let Some(needed) = needed else { continue };
            let entry = self.entry_for(host, &l, b);
            // another blob of the commit holding every needed delta holds it (a projection a
            // right holder dropped covered deltas from, a superset), unless it is must-not-hold
            // (`holds_nothing`, spec/sync.md §6)
            let here = entry.is_some_and(|id| host.is_none_or(|s| self.state.is_present(s, &l, &id)));
            if !here && self.carried_by(host, g, &l, &b.commit, &needed) {
                continue;
            }
            // a right holder deleted it here: its keep bounds, dated by its own deaths, passed
            // there (spec/commits.md §5); not placed again while its live writes are carried
            if !here && self.delete_stands(l, b, &needed, snaps, &mut note)? {
                continue;
            }
            // another node's commit not at this host: its author (or a co-writer) first
            if !here && self.relay_at(p.l, &b.commit).is_some() {
                left.commits.insert(b.commit);
                continue;
            }
            let (id, fresh) = match entry {
                Some(id) => (id, false),
                None if read_ok && (keys.is_writer() || self.may_deposit(keys, b)) => match self.place(g, l, b, false)? {
                    Some(id) => (id, true),
                    None => continue,
                },
                None => continue,
            };
            let prio = if self.first.contains(&b.commit) {
                0
            } else if b.role_commit {
                1
            } else {
                3
            };
            let of = Some(Touch::Commit(b.commit));
            sends.push(Out { prio, id, fresh, of });
            if keys.is_writer() {
                let mut linked = self.chunk_blobs(&b.commit)?;
                // chunks the header lists that are not here yet go up once they arrive
                if let Some(h) = self.engine.header(&b.commit) {
                    for ch in &h.chunks {
                        if !linked.contains(&ch.blob) {
                            left.link(ch.blob, b.commit);
                        }
                    }
                }
                linked.extend(self.body_blobs(&l, b, left)?);
                for cb in linked {
                    let fresh = !self.state.entries.contains_key(&(l, cb));
                    if fresh {
                        let wrap = osis_crypto::filler_wrap(&mut *self.rng);
                        self.state.set_entry(l, cb, Entry { wrap, stamp: None, cert: false, kind: Kind::Unknown, memory: false });
                    }
                    sends.push(Out { prio, id: cb, fresh, of });
                }
            }
        }
        Ok(sends)
    }

    /// Must-hold for a closure body (spec/sync.md §6): before its keep-at-least bound, under
    /// `nobody` while kept, or established uncovered by the label's snapshots. Must-hold: the parts a blob of the commit
    /// must hold to hold the body (all of them before keep-at-least or under `nobody`, else those of the aspects
    /// no snapshot covers).
    pub(super) fn must_hold(&mut self, b: &Body, snaps: &Snaps, unsettled: &Unsettled, note: &mut Note) -> Result<Option<Vec<(usize, usize)>>> {
        let Some(h) = self.engine.header(&b.commit) else { return Ok(None) };
        let aspects: Vec<(Tid, Ak)> = b.parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect();
        let now = self.now();
        let mut before = false;
        if let Some((t, a)) = aspects.first() {
            let at_least = self.engine.body_keep(&b.commit, t, a)?.at_least;
            // no right holder will ever drop a `nobody` body: must-hold while kept, covered or not
            let nobody = b.parts.first().and_then(|(ai, _)| h.aspects.get(*ai)).is_some_and(|x| x.retention.by == osis_base::PurgeBy::Nobody);
            before = nobody || at_least > now;
            if at_least > now {
                note.at(at_least);
            }
        }
        let mut covered = !aspects.is_empty();
        let mut needed = Vec::new();
        for (p, (t, a)) in b.parts.iter().zip(&aspects) {
            let mut c = false;
            for s in snaps.get(&(*t, a.clone())).into_iter().flatten() {
                if *s != b.commit && self.covered_noted(s, &b.commit, t, a, note)? == Some(true) {
                    // covered-equal snapshots (equal `ts`): the one with the higher commit ID goes
                    if is_snapshot(h.kind) && self.covered_noted(&b.commit, s, t, a, note)? == Some(true) && b.commit < *s {
                        continue;
                    }
                    c = true;
                    break;
                }
            }
            covered &= c;
            if before || !c {
                needed.push(*p);
            }
        }
        let known = !unsettled.contains(&None) && !aspects.iter().any(|k| unsettled.contains(&Some(k.clone())));
        let covered = if covered || known { Some(covered) } else { None };
        let must = classify(&Facts { required: true, closure: true, before_at_least: before, covered, ..Facts::default() }) == Hold::Must;
        Ok(must.then_some(needed))
    }

    /// Whether a delete took body `b` from `l` and it stays out: its live writes are carried there
    /// and no purge that fell may have been what took it (spec/sync.md §6).
    pub(super) fn delete_stands(&mut self, l: LabelId, b: &Body, parts: &[(usize, usize)], snaps: &Snaps, note: &mut Note) -> Result<bool> {
        Ok(self.state.body_deleted(l, b.commit, &b.parts) && self.live_carried(b, parts, snaps, note)? && !self.engine.named_by_a_fallen_purge(&b.commit, parts)?)
    }

    /// Whether each of `parts` of body `b` has no live write or a snapshot under the label
    /// (`snaps`) covering it.
    pub(super) fn live_carried(&mut self, b: &Body, parts: &[(usize, usize)], snaps: &Snaps, note: &mut Note) -> Result<bool> {
        let Some(h) = self.engine.header(&b.commit) else { return Ok(false) };
        for p in parts {
            if self.part_live(&h, &b.commit, p) && !self.parts_covered(snaps, &b.commit, &h, &[*p], note)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether every part's aspect of commit `c` is covered by a snapshot under `l`.
    pub(in crate::sync) fn parts_covered_at(&mut self, l: &LabelId, c: &CommitId, h: &osis_commit::Header, parts: &[(usize, usize)]) -> Result<bool> {
        let mut snaps: BTreeMap<(Tid, Ak), Vec<CommitId>> = BTreeMap::new();
        for (ai, _) in parts {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let k = (a.tid, a.ak.clone());
            let on: Vec<CommitId> = self.engine.core.ix.by_aspect.get(&k).into_iter().flatten().map(|x| x.1).filter(|s| self.engine.header(s).is_some_and(|x| is_snapshot(x.kind)) && self.state.entries_of(l, s).next().is_some()).collect();
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
    pub(super) fn parts_covered(&mut self, snaps: &Snaps, c: &CommitId, h: &osis_commit::Header, parts: &[(usize, usize)], note: &mut Note) -> Result<bool> {
        for (ai, _) in parts {
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

    /// Whether an entry of commit `c` holding `parts` is present at `host` under `l` (any
    /// entry when `None`: this node's own served state), checked genuine: a forged blob listing
    /// the parts holds nothing, nor a must-not-hold one (`holds_nothing`).
    pub(super) fn carried_by(&mut self, host: Option<&HostKey>, g: &Tid, l: &LabelId, c: &CommitId, parts: &[(usize, usize)]) -> bool {
        let ids: Vec<BlobId> = self.state.entries_of(l, c).filter(|(id, e)| !e.cert && matches!(&e.kind, Kind::Commit { parts: p, .. } if parts.iter().all(|x| p.contains(x)) && !self.holds_nothing(g, c, p)) && host.is_none_or(|s| self.state.holds_at(s, l, id))).map(|(id, _)| id).collect();
        ids.into_iter().any(|id| self.genuine(&id))
    }

    /// Whether a blob of commit `c` with delta set `parts` under a label of `g` is must-not-hold
    /// whatever its siblings: it holds a delta this node dropped (purge, expiry, keep-at-most,
    /// compaction) or one the label's actor may not read (outside the required set). It holds
    /// no body and makes no other blob a strict subset (spec/sync.md §6).
    pub(super) fn holds_nothing(&self, g: &Tid, c: &CommitId, parts: &[(usize, usize)]) -> bool {
        let Some(m) = self.engine.core.ix.commits.get(c) else { return false };
        let x = self.engine.group_actor(g);
        parts.iter().any(|p| m.body_gone(p.0) || m.header.aspects.get(p.0).is_some_and(|a| !self.engine.core.may_read(&x, &self.engine.core.reader_of(&a.tid))))
    }

    /// The genuine entry under `l` holding exactly this body, not tombstoned at `host`, whoever
    /// placed it (a certificate copy of the same parts holds it too: other nodes see one entry).
    /// One present at `host` first: the label then holds the body (spec/sync.md §6), and
    /// uploading another encryption (this node's own, whose upload was lost) would only add a
    /// duplicate for the tiebreak of §7 to delete. `None`: any entry (this node's served state).
    pub(super) fn entry_for(&mut self, host: Option<&HostKey>, l: &LabelId, b: &Body) -> Option<BlobId> {
        let mut ids: Vec<BlobId> = self.state.entries_of(l, &b.commit).filter(|(id, e)| matches!(&e.kind, Kind::Commit { parts, .. } if *parts == b.parts) && host.is_none_or(|s| !self.state.is_gone_at(s, l, id))).map(|(id, _)| id).collect();
        if let Some(host) = host {
            ids.sort_by_key(|id| !self.state.is_present(host, l, id));
        }
        ids.into_iter().find(|id| self.genuine(id))
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
        let verdict = match crate::labeling::open_commit(&bytes, &key) {
            Ok((_, c)) => self.engine.parts_genuine(&c),
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

    /// Places a body under `l`: an encryption of it this node holds (never a certificate
    /// copy's, never one tombstoned there), else a fresh one; wrapped for the label.
    pub(super) fn place(&mut self, g: &Tid, l: LabelId, b: &Body, cert: bool) -> Result<Option<BlobId>> {
        let Some(secret) = self.engine.wrap_secret(g, Some((&b.commit, &b.parts)))? else { return Ok(None) };
        // a memory commit's blobs carry its class and live in memory (spec/sync.md §9)
        let class = self.engine.header(&b.commit).map_or(osis_label::Class::Durable, |h| osis_label::Class::of_marker(h.ephemeral));
        let memory = class != osis_label::Class::Durable;
        let reuse = if cert { None } else { self.state.blob_for(&b.commit, &b.parts, |id| self.state.is_gone(&l, id) || self.state.entries.contains_key(&(l, *id))) };
        let (id, key) = match reuse.and_then(|id| self.state.blobs.get(&id).map(|r| (id, r.key.clone()))) {
            Some(x) => x,
            None => {
                let pt = self.engine.body_plaintext(b)?;
                if pt.is_empty() {
                    return Ok(None);
                }
                let s = crate::labeling::seal_body_as(&Body { plaintext: pt, ..b.clone() }, class, &mut *self.rng)?;
                if memory {
                    self.engine.put_memory_blobs(vec![(s.id, s.blob)])?;
                } else {
                    self.engine.put_blobs(vec![(s.id, s.blob)])?;
                }
                self.state.add_blob(s.id, BlobRec { commit: b.commit, parts: b.parts.clone(), key: s.key.clone(), cert, memory });
                (s.id, s.key)
            }
        };
        let Some(bytes) = self.engine.blob(&id)? else { return Ok(None) };
        let Some(salt) = osis_label::Prefix::parse(&bytes).ok().map(|p| *p.salt()) else { return Ok(None) };
        let wrap = osis_crypto::wrap(&secret, &id, &key, b.order)?;
        self.state.set_entry(l, id, Entry { wrap, stamp: None, cert, kind: Kind::Commit { commit: b.commit, parts: b.parts.clone(), salt }, memory });
        self.state.note_memory_size(l, id, bytes.len());
        if memory {
            self.state.memory_in_closure.insert((l, id));
        }
        if memory && let Some(h) = self.engine.header(&b.commit) {
            let things: Vec<Tid> = b.parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).map(|a| a.tid).collect();
            self.engine.note_memory_synced(things);
        }
        Ok(Some(id))
    }

    /// Chunk, page and header-list blobs a commit references that this node holds.
    pub(super) fn chunk_blobs(&mut self, c: &CommitId) -> Result<Vec<BlobId>> {
        Ok(self.engine.package(c)?.map(|p| p.blobs.into_iter().map(|(id, _)| id).collect()).unwrap_or_default())
    }

    /// Blobs the body's own delta values link (trees of large values, pages), listed by its
    /// commit or not: reused chunks and a snapshot's values belong to the closure too
    /// (spec/sync.md §3), so a reader under a new label (replacement, a move) gets them. Those
    /// held here or already an entry under `l`; the walk is cached per body once complete.
    pub(super) fn body_blobs(&mut self, l: &LabelId, b: &Body, left: &mut Left) -> Result<Vec<BlobId>> {
        let key = (b.commit, b.parts.clone());
        let all = match self.body_links.get(&key) {
            Some(x) => x.clone(),
            None => {
                let pt = self.engine.body_plaintext(b)?;
                let r = self.engine.body_links(&pt)?;
                let all: Vec<BlobId> = r.blobs.into_iter().collect();
                if r.missing.is_empty() {
                    self.body_links.insert(key, all.clone());
                } else {
                    // the walk goes on once the missing nodes are here
                    for m in r.missing {
                        left.link(m, b.commit);
                    }
                }
                all
            }
        };
        let (here, not): (Vec<BlobId>, Vec<BlobId>) = all.into_iter().partition(|id| self.state.entries.contains_key(&(*l, *id)) || self.engine.has_blob(id));
        for id in not {
            left.link(id, b.commit);
        }
        Ok(here)
    }

    /// Whether this node placed the entry (its certificates, heartbeats, role writes).
    pub(super) fn mine(&self, e: &Entry) -> bool {
        e.cert || matches!(&e.kind, Kind::Commit { commit, .. } if self.own(commit))
    }

    /// A non-writer deposits its own role writes (an invite grant, a self-removal,
    /// spec/sync.md §3).
    pub(super) fn may_deposit(&self, keys: &HeadKeys, b: &Body) -> bool {
        keys.deposit.is_some() && b.role_commit && self.own(&b.commit)
    }

    /// This node's verdicts on label `l` at `host` under the keys its last pass there used
    /// (simulator invariants, spec/sync.md §6); `None` when the label is not open there.
    pub fn verdicts(&mut self, host: &HostKey, l: &LabelId) -> Result<Option<Verdicts>> {
        let Some(lc) = self.conns.values().filter(|c| c.host == *host).find_map(|c| c.labels.get(l).filter(|x| x.phase == crate::sync::Phase::Open)) else { return Ok(None) };
        let (g, keys) = (lc.group, lc.keys.clone());
        let mut v = Verdicts { writer: keys.is_writer(), ..Verdicts::default() };
        let bodies = self.bodies_under(&g, l)?;
        let mut w = Work::fresh();
        self.rebuild(&g, l, &mut w);
        let snaps: Snaps = w.snaps.iter().map(|(k, v)| (k.clone(), v.iter().map(|(_, c)| *c).collect())).collect();
        let fetching = w.unopened.iter().any(|b| self.fetching(b));
        let (unsettled, snapping) = self.unsettled_sets(!w.unopened.is_empty(), fetching)?;
        v.unsettled = unsettled.iter().cloned().collect();
        let mut note = Note::default();
        for b in &bodies {
            if let Some(needed) = self.must_hold(b, &snaps, &snapping, &mut note)? {
                // not placed again (`body_sends`)
                if self.delete_stands(*l, b, &needed, &snaps, &mut note)? {
                    continue;
                }
                v.must_hold.push((b.commit, needed));
            }
        }
        let desired = desired(&bodies);
        let entries: Vec<(BlobId, Entry)> = self.state.label_entries(l).map(|(b, e)| (b, e.clone())).collect();
        let at = At { g, l: *l, host: Some(*host), keys: &keys, snaps: &snaps, settled: unsettled.is_empty() };
        for (id, e) in entries {
            if let Fate::Delete(why, _, _) = self.deletable(&at, &id, &e, &desired, false, &mut note)? {
                v.must_not.push((id, format!("{why:?}")));
            }
        }
        Ok(Some(v))
    }

    /// The bodies label `l` of `g` should hold: the closure's; under a replaced label
    /// role-class ones only (spec/sync.md §2: its content entries go).
    pub(in crate::sync) fn bodies_under(&mut self, g: &Tid, l: &LabelId) -> Result<Vec<Body>> {
        let mut bodies = self.engine.label_bodies_meta(g)?;
        if self.is_replaced(g, l) {
            bodies.retain(|b| b.role_commit);
        }
        Ok(bodies)
    }

    pub(crate) fn is_replaced(&mut self, g: &Tid, l: &LabelId) -> bool {
        self.engine.labels_of(g).iter().any(|x| x.id == *l && x.replaced)
    }

    /// Prefix vs header for commit blobs whose header lists went by link (spec/commits.md §4):
    /// checked once the applied header is resolved, before the entry counts as holding its
    /// body; a disagreeing blob is bad input (`Kind::Bad`) and the body is judged missing there.
    pub(super) fn check_linked_prefixes(&mut self, l: LabelId, scope: &Scope) -> Result<()> {
        type Parts = Vec<(usize, usize)>;
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
                if let Kind::Commit { parts, .. } = &e.kind
                    && !self.prefix_checked.contains(&b)
                {
                    todo.push((b, c, parts.clone()));
                }
            }
        }
        todo.sort_by_key(|x| x.0);
        for (b, c, parts) in todo {
            let Some(bytes) = self.engine.blob(&b)? else { continue };
            let Some(h) = self.engine.header(&c) else { continue };
            self.prefix_checked.insert(b);
            let agrees = match (osis_label::Prefix::parse(&bytes), osis_commit::prefix_inputs(&h, &parts)) {
                (Ok(p), Ok((expiry, keys))) => p.agrees(expiry.map(WallMs), &h.blind, &keys, osis_label::Class::Durable),
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

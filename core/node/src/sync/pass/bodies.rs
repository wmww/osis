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
            // another blob of the commit holding every needed delta holds it (a rewrite a
            // right holder dropped covered deltas from, a superset), unless it is must-not-hold
            // (`holds_nothing`, spec/sync.md §6)
            let here = entry.is_some_and(|id| host.is_none_or(|s| self.state.is_present(s, &l, &id)));
            if !here && self.carried_by(host, &l, &b.commit, &needed) {
                continue;
            }
            // a right holder deleted it here: its keep bounds, judged from what it holds, passed
            // there (spec/commits.md §5); not placed again while its live writes are carried
            if !here && self.delete_stands(host, l, b, &needed, snaps, &mut note)? {
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
                        self.state.set_entry(l, cb, Entry { wrap, stamp: None, cert: false, salt: None, kind: Kind::Unknown, memory: false });
                    }
                    sends.push(Out { prio, id: cb, fresh, of });
                }
            }
        }
        Ok(sends)
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
        let mut needed = Vec::new();
        let keeps = self.keeps(&b.commit)?;
        for (ai, (t, a)) in b.parts.iter().zip(&aspects) {
            let kept = self.part_kept(&keeps, *ai, note);
            before |= kept;
            // a signal's delta is never joined, so never established uncovered: must-hold only
            // while kept (spec/sync.md §6, spec/commits.md §5 Signals)
            let mut c = a.signal();
            for s in snaps.get(&(*t, a.clone())).into_iter().flatten().filter(|_| !c) {
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
            if kept || !c {
                needed.push(*ai);
            }
        }
        let known = !unsettled.contains(&None) && !aspects.iter().any(|k| unsettled.contains(&Some(k.clone())));
        let covered = if covered || known { Some(covered) } else { None };
        let must = classify(&Facts { required: true, closure: true, before_at_least: before, covered, ..Facts::default() }) == Hold::Must;
        Ok(must.then_some(needed))
    }

    /// `Engine::body_keeps` of `c`, judged once per change: kept until the engine marks `c`
    /// changed (`SyncEngine::keeps`); one marked but not drained yet is judged anew, and so is
    /// one whose bound a replacement dates (it moves earlier with no mark when an earlier
    /// superseder of an already dead write arrives).
    pub(super) fn keeps(&mut self, c: &CommitId) -> Result<std::sync::Arc<Vec<u64>>> {
        let pending = self.engine.core.changed.as_ref().is_some_and(|x| x.commits.contains(c));
        if !pending && let Some((at, k)) = self.keeps.get(c)
            && !self.engine.settings_moved_after(c, *at)
        {
            let k = k.clone();
            #[cfg(debug_assertions)]
            if self.engine.recheck(format!("keeps {c:?}")) {
                assert_eq!(*k, crate::costs::paused(|| self.engine.body_keeps(c))?, "body_keeps of {c:?} went stale");
            }
            return Ok(k);
        }
        let _s = crate::costs::span("pass: body keeps");
        let at = self.engine.settings_generation();
        let k = std::sync::Arc::new(self.engine.body_keeps(c)?);
        let undated = self.engine.header(c).is_some_and(|h| self.engine.keeps_unreplaced(&h) == *k);
        if !pending && undated {
            self.keeps.insert(*c, (at, k.clone()));
        }
        Ok(k)
    }

    /// Whether part `p` of commit `c` is kept whatever covers it (spec/sync.md §6): before its
    /// keep-at-least bound (noted when that ends; never for one kept for good). `keeps`: the
    /// commit's `Engine::body_keeps`, read once per commit judged.
    fn part_kept(&self, keeps: &[u64], ai: usize, note: &mut Note) -> bool {
        let Some(k) = keeps.get(ai).copied() else { return false };
        let kept = k > self.now();
        if kept && k < osis_commit::FOREVER {
            note.at(k);
        }
        kept
    }

    /// Whether only a blob of commit `c` can carry its part on aspect `ai` under the label (spec/sync.md §6):
    /// kept (`part_kept`) or holding a live write, and no snapshot under the label (`snaps`)
    /// covers it. A blob missing such a part (a junk Replace's victim, a rewrite that dropped it)
    /// is healed by an upload.
    /// Invariant: what one honest node deletes at a host no other's `must_carry` puts back.
    /// When a body was replaced is judged from the bodies each node holds (spec/commits.md §5), so
    /// a right holder may drop a covered body as past keep-at-least while a holder of other bodies
    /// judges it replaced later, or not at all, and kept. Both sides read the covering snapshot under the
    /// label alike, so a covered part is never one only a blob carries.
    /// `keeps`: the commit's `Engine::body_keeps`.
    pub(super) fn must_carry(&mut self, h: &osis_commit::Header, c: &CommitId, keeps: &[u64], ai: usize, snaps: &Snaps, note: &mut Note) -> Result<bool> {
        if !self.part_kept(keeps, ai, note) && !self.part_live(h, c, ai) {
            return Ok(false);
        }
        Ok(!self.parts_covered(snaps, c, h, &[ai], note)?)
    }

    /// Whether a delete took body `b` from `l` and it stays out: every one of its `parts` only a
    /// blob can carry (`must_carry`) is held there (at `host`) by another genuine blob of the
    /// commit, and no purge that fell may have been what took it (spec/sync.md §6).
    pub(super) fn delete_stands(&mut self, host: Option<&HostKey>, l: LabelId, b: &Body, parts: &[usize], snaps: &Snaps, note: &mut Note) -> Result<bool> {
        if !self.state.body_deleted(l, b.commit, &b.parts) {
            return Ok(false);
        }
        let Some(h) = self.engine.header(&b.commit) else { return Ok(false) };
        let keeps = self.keeps(&b.commit)?;
        for ai in parts {
            if self.must_carry(&h, &b.commit, &keeps, *ai, snaps, note)? && !self.carried_by(host, &l, &b.commit, &[*ai]) {
                return Ok(false);
            }
        }
        Ok(!self.engine.named_by_a_fallen_purge(&b.commit, parts)?)
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

    /// Whether an entry of commit `c` holding `parts` is present at `host` under `l` (any
    /// entry when `None`: this node's own served state), checked genuine: a forged blob listing
    /// the parts holds nothing, nor a must-not-hold one (`holds_nothing`).
    pub(super) fn carried_by(&mut self, host: Option<&HostKey>, l: &LabelId, c: &CommitId, parts: &[usize]) -> bool {
        let ids: Vec<BlobId> = self.state.entries_of(l, c).filter(|(id, e)| !e.cert && matches!(&e.kind, Kind::Commit { parts: p, .. } if parts.iter().all(|x| p.contains(x)) && !self.holds_nothing(c, p)) && host.is_none_or(|s| self.state.holds_at(s, l, id))).map(|(id, _)| id).collect();
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
            let g = self.state.labels_of(&id).into_iter().find_map(|l| self.group_of(&l, None));
            let Ok(o) = self.engine.open_commit(&bytes, &key, g.as_ref()) else { continue };
            for s in o.sealed {
                if !out.iter().any(|x| x.ais == s.ais) {
                    out.push(s);
                }
            }
        }
        Ok(out)
    }

    /// The genuine entry under `l` holding exactly this body, not tombstoned at `host`, whoever
    /// placed it (a certificate copy of the same parts holds it too: other nodes see one entry).
    /// One present at `host` first: the label then holds the body (spec/sync.md §6), and
    /// uploading another encryption (this node's own, whose upload was lost) would only add a
    /// duplicate for the tiebreak of §7 to delete. `None`: any entry (this node's served state).
    pub(super) fn entry_for(&mut self, host: Option<&HostKey>, l: &LabelId, b: &Body) -> Option<BlobId> {
        let g = self.group_of(l, None)?;
        let cands: Vec<(BlobId, Vec<usize>)> = self.state.entries_of(l, &b.commit).filter(|(id, e)| matches!(&e.kind, Kind::Commit { .. }) && host.is_none_or(|s| !self.state.is_gone_at(s, l, id))).filter_map(|(id, e)| if let Kind::Commit { parts, .. } = &e.kind { Some((id, parts.clone())) } else { None }).collect();
        let mut ids: Vec<BlobId> = cands.into_iter().filter(|(_, parts)| self.readable(&g, &b.commit, parts) == b.parts).map(|(id, _)| id).collect();
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
        let g = self.state.labels_of(id).into_iter().find_map(|l| self.group_of(&l, None));
        let verdict = match self.engine.open_commit(&bytes, &key, g.as_ref()) {
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

    /// Places a body under `l`: an encryption of it this node holds (never a certificate
    /// copy's, never one tombstoned there), else a fresh one (`Engine::seal`: every held part
    /// in sections, the sections this node could not open copied verbatim); wrapped for the
    /// label.
    pub(super) fn place(&mut self, g: &Tid, l: LabelId, b: &Body, cert: bool) -> Result<Option<BlobId>> {
        let Some(secret) = self.engine.wrap_secret(g, Some((&b.commit, &b.parts)))? else { return Ok(None) };
        // a memory commit's blobs carry its class and live in memory (spec/sync.md §9)
        let class = self.engine.header(&b.commit).map_or(osis_label::Class::Durable, |h| osis_label::Class::of_marker(h.ephemeral));
        let memory = class != osis_label::Class::Durable;
        // what the blob carries: every held part (a copy: the body's own)
        // a per-label copy (a certificate, a cross-published `label.0`) is sealed in one section
        // under the label's wrap secret and shared with no other label (spec/sync.md §3)
        let own = cert || b.to_label;
        let held: Vec<usize> = if own { b.parts.clone() } else { self.engine.body(&b.commit)?.map(|x| x.parts).unwrap_or_default() };
        // a held encryption carrying the body's parts and nothing not held any more (the
        // fullest; one sealed here may lack parts this node holds no secret for)
        let reuse = if own { None } else { self.state.blob_for(&b.commit, &b.parts, &held, |id| self.state.is_gone(&l, id) || self.state.entries.contains_key(&(l, *id))) };
        let (id, key, parts, ais) = match reuse.and_then(|id| self.state.blobs.get(&id).map(|r| (id, r.key.clone(), r.parts.clone(), r.ais.clone()))) {
            Some(x) => x,
            None => {
                let sealed = if own {
                    self.engine.seal_to(b, class, &secret, &mut *self.rng)?
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
                // a per-label copy is recorded as one: never reused under another label
                self.state.add_blob(s.id, BlobRec { commit: b.commit, parts: s.parts.clone(), ais: s.ais.clone(), key: s.key.clone(), cert: own, memory });
                (s.id, s.key, s.parts, s.ais)
            }
        };
        let Some(bytes) = self.engine.blob(&id)? else { return Ok(None) };
        let Some(salt) = osis_label::Prefix::parse(&bytes).ok().map(|p| *p.salt()) else { return Ok(None) };
        let wrap = osis_crypto::wrap(&secret, &id, &key, b.order)?;
        self.state.set_entry(l, id, Entry { wrap, stamp: None, cert, salt: Some(salt), kind: Kind::Commit { commit: b.commit, parts, ais }, memory });
        self.state.note_memory_size(l, id, bytes.len());
        if memory {
            self.state.memory_in_closure.insert((l, id));
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

    /// Whether this node placed the entry (its certificates, role writes).
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
        let fetching = w.unopened.iter().any(|b| self.asked(b).is_some());
        let (unsettled, snapping) = self.unsettled_sets(!w.unopened.is_empty(), fetching)?;
        v.unsettled = unsettled.iter().cloned().collect();
        let mut note = Note::default();
        for b in &bodies {
            if let Some(needed) = self.must_hold(b, &snaps, &snapping, &mut note)? {
                // not placed again (`body_sends`); one held there is checked whatever deletes of
                // other copies of it took (a duplicate's, the luck of the order a pass drew)
                if !self.carried_by(Some(host), l, &b.commit, &needed) && self.delete_stands(Some(host), *l, b, &needed, &snaps, &mut note)? {
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

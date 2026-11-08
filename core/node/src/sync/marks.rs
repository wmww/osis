//! From changes to passes: the engine's changes spread to the labels' work sets (`work`), and the
//! labels they concern are marked for a pass.

use super::*;

/// Whether a change on an aspect `a` of a thing concerns only labels holding that thing: content,
/// no role, creation or group record.
fn narrow_aspect(a: &Ak) -> bool {
    let s = a.as_str();
    !osis_schema::core_types::is_role_class(s) && !matches!(s, "created.0" | "group.0" | "groups.0")
}

impl SyncEngine {
    /// Drains the engine's changes: the changed commits (`Engine::take_changed`) go to every
    /// label's work set and mark every open label for a pass; events carry role changes: roles
    /// moved, keys, and remote role commits restart `complete_pass` for the actors they
    /// touch.
    pub(crate) fn engine_events(&mut self) -> Result<()> {
        let mut changed = false;
        // who wants a pass: every label (`wide`), or those holding what these aspects are on
        let (mut wide, mut narrow): (bool, BTreeSet<(Tid, Ak)>) = (false, BTreeSet::new());
        // things whose roles or reader actors moved: labels downstream of them want a pass
        let mut scoped: BTreeSet<Tid> = BTreeSet::new();
        // things with a new creation record (`note_role_moves`)
        let mut roots: BTreeSet<Tid> = BTreeSet::new();
        let mut own = false;
        let me = self.engine.tid();
        let clients = osis_schema::RawKey::ak(&osis_schema::core_types::CLIENTS);
        let moved_clients = |aspects: &[(Tid, Ak)]| aspects.iter().any(|(t, a)| *t == me && a.as_str() == clients);
        while let Ok(e) = self.events.try_recv() {
            match e {
                crate::Event::Applied { id, origin, changed: aspects, .. } => {
                    changed = true;
                    own |= origin == Origin::Local;
                    self.tied.touched(&aspects);
                    self.clients_moved |= moved_clients(&aspects);
                    self.placed_cache.0 = u64::MAX;
                    narrow.extend(aspects.iter().cloned());
                    let Some(h) = self.engine.header(&id) else {
                        wide = true;
                        continue;
                    };
                    narrow.extend(h.aspects.iter().map(|a| (a.tid, a.ak.clone())));
                    // a placement applied invalid changes no state but may decide a tie
                    self.tied.groups.extend(h.aspects.iter().filter(|a| a.ak.as_str() == "group.0").map(|a| a.tid));
                    // a creation record moves the roles downstream of the thing
                    roots.extend(h.aspects.iter().filter(|a| a.ak.as_str() == "created.0").map(|a| a.tid));
                    let role_commit = h.kind.is_role();
                    if role_commit {
                        scoped.extend(h.aspects.iter().map(|a| a.tid));
                    }
                    if role_commit {
                        self.served_cache = None;
                        self.holders_moved = true;
                        self.touched.keys = true;
                    }
                    if origin == Origin::Remote && role_commit {
                        self.seq += 1;
                        let at = self.raw_now();
                        for a in &h.aspects {
                            let actor = self.keys_actor(&a.tid);
                            self.role_change.insert(actor, (self.seq, at));
                            // only an admin registers its rotation's step: another's (a writer
                            // rotating for a departure) is this admin's to register at once
                            if a.ak.as_str() == "secrets.0" && self.engine.core.role_now(&h.author, &actor) == Some(osis_base::Role::Admin) {
                                self.rotation_at.insert(actor, at);
                            }
                        }
                        // new secrets may open a label that failed: retry at the next tick
                        for c in self.conns.values_mut() {
                            for l in c.labels.values_mut().filter(|l| l.phase == Phase::Failed) {
                                l.last_sync = 0;
                            }
                        }
                    }
                }
                // an expiry of ephemeral state only: nothing to sync
                crate::Event::Changed { cause: crate::events::Cause::Expiry, changed: aspects } if aspects.iter().all(|(_, a)| !osis_schema::RawKey::lifetime(a).is_durable()) => {}
                crate::Event::Changed { cause, changed: aspects } => {
                    changed = true;
                    narrow.extend(aspects.iter().cloned());
                    self.tied.touched(&aspects);
                    self.clients_moved |= moved_clients(&aspects);
                    if cause == crate::events::Cause::LostAccess {
                        self.touched.full = true;
                    }
                    if aspects.iter().any(|(_, a)| osis_schema::core_types::is_role_class(a.as_str())) {
                        self.touched.keys = true;
                    }
                }
                crate::Event::Joined { id } => {
                    changed = true;
                    let h = self.engine.header(&id);
                    wide |= h.is_none();
                    if let Some(h) = h {
                        narrow.extend(h.aspects.iter().map(|a| (a.tid, a.ak.clone())));
                        if h.kind.is_role() {
                            scoped.extend(h.aspects.iter().map(|a| a.tid));
                            self.touched.keys = true;
                        }
                        // a late creation record (`note_created`)
                        roots.extend(h.aspects.iter().filter(|a| a.ak.as_str() == "created.0").map(|a| a.tid));
                    }
                }
                crate::Event::Roster { thing } => {
                    changed = true;
                    scoped.insert(thing);
                    self.tied.targets.insert(thing);
                    self.served_cache = None;
                    self.holders_moved = true;
                }
                _ => {}
            }
        }
        // actors that got or lost secrets of their own: the reader actors under them moved
        if *self.engine.core.ix.own_keys != self.own_keys {
            let now: BTreeSet<Tid> = (*self.engine.core.ix.own_keys).clone();
            let moved: Vec<Tid> = now.symmetric_difference(&self.own_keys).copied().collect();
            scoped.extend(moved.iter().copied());
            self.touched.actors.extend(moved);
            self.own_keys = now;
            changed = true;
        }
        // changed commits: their aspects' states (verdicts waiting on them), their chunks (bodies
        // waiting on a linked blob), and the blobs of their dropped parts
        let ch = self.engine.take_changed();
        self.reopen_undropped(Some(&ch.undropped))?;
        self.note_role_moves(&roots, &ch.edges);
        for c in &ch.commits {
            let h = self.engine.header(c);
            // a commit gone from here names no thing: the labels with its entries are unknown
            wide |= h.is_none();
            if let Some(h) = h {
                self.touched.states.extend(h.aspects.iter().map(|a| (a.tid, a.ak.clone())));
                self.touched.blobs.extend(h.chunks.iter().map(|ch| ch.blob));
                if h.kind.is_role() {
                    scoped.extend(h.aspects.iter().map(|a| a.tid));
                    self.touched.clock |= h.ts.wall_ms().0 > self.state.now;
                }
                narrow.extend(h.aspects.iter().map(|a| (a.tid, a.ak.clone())));
            }
        }
        changed |= !ch.is_empty();
        wide |= !ch.undropped.is_empty();
        narrow.extend(ch.aspects.iter().cloned());
        self.touched.states.extend(ch.aspects);
        let cs = ch.commits;
        // this node's own write passes a filling label too (`LConn::want_pass`)
        if own {
            for l in self.conns.values_mut().flat_map(|c| c.labels.values_mut()) {
                l.dirty |= l.fill.is_some();
            }
        }
        if changed {
            scoped.extend(narrow.iter().filter(|(_, a)| !narrow_aspect(a)).map(|x| x.0));
            for t in self.engine.core.ix.held.reach(&scoped) {
                self.inbox_copied.moved(&t);
            }
            for (t, _) in narrow.iter().filter(|(_, a)| a.as_str() == "label.0") {
                self.inbox_copied.moved(t);
            }
            if wide || (narrow.is_empty() && scoped.is_empty()) || self.touched.full || self.cfg.full_passes || narrow.iter().any(|(t, _)| self.engine.core.is_key_actor(t)) || scoped.iter().any(|t| self.engine.core.is_key_actor(t)) {
                self.mark_dirty();
            } else {
                let mut things: BTreeSet<Tid> = narrow.iter().map(|x| x.0).collect();
                things.extend(self.downstream(&scoped));
                self.mark_dirty_of(&things);
            }
            let all = self.touched.full || self.cfg.full_passes;
            self.forget_dropped(if all { None } else { Some(&cs) })?;
        }
        self.touched.commits.extend(cs);
        Ok(())
    }

    /// Whose roles changed where (`work::RoleMoves`, for each label to judge): the edges that
    /// changed, the things with a new record (whose record chains also moved). A role comes from
    /// a holder up: it changes only upstream of the edge, and only below it.
    pub(super) fn note_role_moves(&mut self, records: &BTreeSet<Tid>, edges: &BTreeSet<(Tid, Tid)>) {
        if edges.is_empty() && records.is_empty() {
            return;
        }
        let core = &self.engine.core;
        self.touched.clock |= edges.iter().any(|(h, t)| core.timelines.get(&core.reader_of(t)).is_none_or(|tl| tl.edges_at(None).get(h, t).is_some_and(|e| e.until.is_some())));
        let held = &core.ix.held;
        let holders = edges.iter().map(|p| p.0).chain(records.iter().copied()).collect();
        let targets = edges.iter().map(|p| p.1).chain(records.iter().copied()).collect();
        self.touched.roles.merge(&work::RoleMoves { subjects: held.upstream(&holders), reached: held.reach(&targets) });
        self.touched.moved.extend(held.below(records));
    }

    /// Hands the changes noted since the last pass to every label's work set: the engine's
    /// (`touched`) to all, the sync state's to the label's (`State::touched`).
    pub(crate) fn spread_touches(&mut self) {
        if self.touched.is_empty() && self.state.touched.is_empty() && self.state.touched_commits.is_empty() {
            return;
        }
        let mut t = std::mem::take(&mut self.touched);
        let st = std::mem::take(&mut self.state.touched);
        t.commits.append(&mut self.state.touched_commits);
        let max = self.cfg.work_max;
        let elsewhere = t.size();
        let conns = self.conns.values_mut().flat_map(|c| c.labels.iter_mut().map(|(l, lc)| (l, &mut lc.work)));
        for (l, w) in conns.chain(self.local_work.iter_mut()) {
            w.again |= w.woken_by(&t);
            w.touched.absorb(&t);
            for (_, x) in st.range((*l, state::Touch::Commit(osis_base::CommitId([0; 32])))..).take_while(|(x, _)| x == l) {
                w.again = true;
                w.touched.add(*x);
            }
            w.bound(elsewhere, max);
        }
    }

    /// What a role, creation or group change on `things` can concern: where authority flows from
    /// them (`Held::reach`: things they are first admin of, things they are named on as a holder);
    /// up their record chains, whose home labels carry their `label.0` and `created.0` (spec/sync.md §3); and
    /// their holders with those holders' record chains, whose labels carry a route to them.
    pub(crate) fn downstream(&self, things: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        let held = &self.engine.core.ix.held;
        let mut out = held.reach(things);
        for t in things {
            out.extend(self.engine.record_chain(t));
            for h in held.named_holders(t) {
                out.extend(self.engine.record_chain(&h));
            }
        }
        out
    }

    /// `mark_dirty`, of the labels on connections whose closure holds one of `things`, and the
    /// local ones: a write on one thing leaves a label of another nothing new to judge: what it
    /// took in waits for its next pass (`Work::quiet`). O(labels), a set lookup each.
    pub(crate) fn mark_dirty_of(&mut self, things: &BTreeSet<Tid>) {
        if self.cfg.full_passes {
            return self.mark_dirty();
        }
        self.local_dirty = true;
        let mut groups: BTreeSet<Tid> = things.clone();
        for t in things {
            groups.extend(self.engine.groups_of(t));
        }
        #[cfg(debug_assertions)]
        for l in self.conns.values().flat_map(|c| c.labels.values()) {
            assert!(groups.contains(&l.group) || !self.engine.closure(&l.group).iter().any(|t| things.contains(t)), "groups.of misses {:?}", l.group);
        }
        for c in self.conns.values_mut() {
            for l in c.labels.values_mut() {
                if groups.contains(&l.group) {
                    l.want_pass();
                }
            }
        }
    }

    /// These labels want a pass on every connection (`LConn::want_pass`).
    pub(crate) fn mark_labels<'a>(&mut self, ids: impl IntoIterator<Item = &'a LabelId> + Clone) {
        if self.cfg.full_passes {
            return self.mark_dirty();
        }
        self.local_dirty = true;
        for c in self.conns.values_mut() {
            for id in ids.clone() {
                if let Some(l) = c.labels.get_mut(id) {
                    l.want_pass();
                }
            }
        }
    }

    /// Every label on every connection wants a pass (`LConn::want_pass`).
    pub(crate) fn mark_dirty(&mut self) {
        self.local_dirty = true;
        for l in self.conns.values_mut().flat_map(|c| c.labels.values_mut()) {
            l.want_pass();
        }
    }

    /// After role commits or placements on `things`: the labels they can concern (`downstream`)
    /// and `labels` want a pass; every label, for a key actor's things.
    pub(crate) fn mark_things(&mut self, things: &BTreeSet<Tid>, labels: &[LabelId]) {
        if things.iter().any(|t| self.engine.core.is_key_actor(t)) {
            return self.mark_dirty();
        }
        let scope = self.downstream(things);
        self.mark_dirty_of(&scope);
        self.mark_labels(labels);
    }
}

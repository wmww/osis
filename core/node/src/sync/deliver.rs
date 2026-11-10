//! Carrying out what role flows produce (`flows::Done`, `flows::Delivery`) and the sync
//! state flows ask about (`flows::SyncState`): inbox blobs deposited at the inbox's hosts,
//! direct commits handed to the app's pairing channel, placements before any other upload,
//! certificate copies under a home label, deposits; commits that travel by inbox only are never
//! placed under a label (spec/permissions.md §3, re-seal).

use super::conn::Phase;
use super::{Action, ConnId, HostKey, SyncEngine};
use crate::error::Result;
use crate::flows::{Delivery, Done, SyncState};
use crate::rotation::{Dropped, Leaving, LostScope};
use crate::local_peer::Package;
use osis_base::{CommitId, LabelId, Tid};
use std::collections::{BTreeMap, BTreeSet};

/// What `drop_left` last found, and when.
#[derive(Default)]
pub(crate) struct LeftCheck {
    /// Engine generation `leaving` was computed at.
    generation: Option<u64>,
    /// Sync state version placement was last checked at.
    version: Option<u64>,
    leaving: Leaving,
    /// Per actor of `leaving.timed`: the labels to hear out (those whose closure holds a thing
    /// its drop would forget), with whether each has a host.
    timed_labels: BTreeMap<Tid, Vec<(LabelId, bool)>>,
}

impl LeftCheck {
    /// When a pending grant keeping a leaver's actor ages out, or a timed loss's wait ends.
    pub(crate) fn recheck_at(&self) -> Option<u64> {
        self.leaving.recheck_at
    }
}

impl SyncEngine {
    /// Carries out a flow's result (call it with every `Done` a flow returns).
    pub fn carry_out(&mut self, done: Done) -> Result<Vec<Action>> {
        self.take_done_lost(done)?;
        Ok(self.handle(super::Event::Local))
    }

    /// `take_done` for a flow that may be a self-removal (`Done::drop_lost`): what it lost is
    /// dropped once it is placed (`drop_left`).
    fn take_done_lost(&mut self, done: Done) -> Result<()> {
        if done.drop_lost {
            self.left = Some(LeftCheck::default());
        }
        let all = done.drop_lost;
        let things: BTreeSet<Tid> = done.commits.iter().filter_map(|c| self.engine.header(c)).flat_map(|h| h.aspects.iter().map(|a| a.tid).collect::<Vec<_>>()).collect();
        self.take_done(done)?;
        // placements wait for a pass: the labels they concern and those they went under
        if all {
            self.mark_dirty();
        } else {
            let under: Vec<LabelId> = self.state.touched.iter().map(|(l, _)| *l).collect::<BTreeSet<_>>().into_iter().collect();
            self.mark_things(&things, &under);
        }
        Ok(())
    }

    /// Drops what this node lost read access to and the trigger left to it (`LostScope::Due`):
    /// an actor lost through its own self-removals once the self-removals behind it are placed
    /// (spec/permissions.md §3: the removal goes up before the leaver forgets the labels it
    /// would go under); one an `until` ended with nothing else received once its labels are
    /// heard out (`heard`, spec/permissions.md §2: its own writes from before the `until` went
    /// up, a renewal on its way arrived), or `LOST_HEARD_WAIT_MS` after it was first judged.
    /// Run while `left` is set: what was lost is recomputed after the engine changed (or a
    /// wake came due), placement rechecked after the sync state changed, hearing out every
    /// step. All derive from stored state: a crash in between leaves nothing behind (`left` is
    /// set at start).
    pub(crate) fn drop_left(&mut self) -> Result<()> {
        let (generation, now, version) = (self.engine.core.generation, self.now(), self.state.version);
        let Some(l) = self.left.as_mut() else { return Ok(()) };
        if l.generation != Some(generation) || l.leaving.recheck_at.is_some_and(|t| now >= t) {
            l.leaving = self.engine.lost_leaving()?;
            l.generation = Some(generation);
            l.version = None;
            l.timed_labels.clear();
        }
        if l.leaving.actors.is_empty() && l.leaving.timed.is_empty() {
            if l.leaving.recheck_at.is_none() {
                self.left = None;
            }
            return Ok(());
        }
        let mut ready = Vec::new();
        let timed = l.leaving.timed.clone();
        let mut timed_labels = std::mem::take(&mut l.timed_labels);
        if !timed.is_empty() {
            let labels = self.labels();
            for (a, since) in &timed {
                let affected = timed_labels.entry(*a).or_insert_with(|| {
                    let lost = BTreeSet::from([*a]);
                    let forgets = |t: &Tid| self.engine.would_forget(&lost, t);
                    labels.iter().filter(|(g, gl)| !gl.replaced && (forgets(g) || self.engine.closure(g).iter().any(forgets))).map(|(_, gl)| (gl.id, !super::peers::hostless(&gl.hosts))).collect()
                });
                if now >= since.saturating_add(crate::rotation::LOST_HEARD_WAIT_MS) || affected.iter().all(|(id, hosted)| !hosted || self.heard(id)) {
                    ready.push(*a);
                }
            }
        }
        let Some(l) = self.left.as_mut() else { return Ok(()) };
        l.timed_labels = timed_labels;
        if l.version != Some(version) {
            l.version = Some(version);
            let waiting = l.leaving.actors.clone();
            for (a, own) in &waiting {
                let mut placed = true;
                for c in own {
                    placed &= self.placed(c)?;
                }
                if placed {
                    ready.push(*a);
                }
            }
        }
        if ready.is_empty() {
            return Ok(());
        }
        // a failure retries on the next change; success changes the engine, so what is left
        // is recomputed
        self.forget_lost(LostScope::Only(&ready)).map(|_| ())
    }

    /// Whether label `l` (one with a host) is heard out: open somewhere, and everywhere open a
    /// pass ended with nothing outstanding (what the hosts have for this node has come, its own
    /// writes went); or some host refuses it (stranded: every key this node holds refused; or
    /// not admitted for now), so nothing of this node's can go there.
    fn heard(&self, l: &LabelId) -> bool {
        let (mut open, mut idle, mut refused) = (0, 0, false);
        for c in self.conns.values() {
            let Some(x) = c.labels.get(l) else { continue };
            match x.phase {
                Phase::Failed | Phase::Refused { .. } => refused = true,
                Phase::Open => {
                    open += 1;
                    if x.idle() && c.session.outstanding() == 0 {
                        idle += 1;
                    }
                }
                _ => {}
            }
        }
        refused || (open > 0 && idle == open)
    }

    /// Lost actors waiting for this node's own self-removals to be placed at a source
    /// (`drop_left`), as last computed: a node that never takes the removal keeps them for good (shown in
    /// `LabelStatus::leaving`).
    pub fn leaving(&self) -> impl Iterator<Item = &Tid> {
        self.left.iter().flat_map(|l| l.leaving.actors.keys())
    }

    /// Drops what this node lost read access to (`Engine::drop_lost_secrets`, spec/permissions.md
    /// §3) and its sync state about it: the engine forgets the records in its transaction, this
    /// reloads them and drops the sessions and in-memory marks of the forgotten labels. All at
    /// once, self-removals not yet placed included (`drop_left` drops those); an app calls it
    /// when told it was removed.
    pub fn drop_lost(&mut self) -> Result<()> {
        self.forget_lost(LostScope::All).map(|_| ())
    }

    /// Erases these kept copies at the user's word (`Engine::kept_copies`, spec/permissions.md
    /// §3, Retain).
    pub fn drop_kept(&mut self, actors: &[Tid]) -> Result<()> {
        self.forget_lost(LostScope::Kept(actors)).map(|_| ())
    }

    /// The lost-access trigger (`Engine::drop_lost_due`), run every step while received role
    /// commits or an aged-out pending grant left it work due, until none is (forgetting
    /// re-examines pending commits, which may apply more).
    pub(crate) fn drop_lost_due(&mut self) -> Result<()> {
        for _ in 0..16 {
            if !self.engine.lost_due() {
                break;
            }
            if self.forget_lost(LostScope::Due)? {
                self.left = Some(LeftCheck::default());
            }
        }
        Ok(())
    }

    /// `Engine::forget_lost`, and the sync state about what it forgot. Returns `Dropped::leaving`.
    fn forget_lost(&mut self, scope: LostScope<'_>) -> Result<bool> {
        self.state.flush(&mut self.engine)?;
        let Dropped { actors, forgotten: mut f, leaving } = self.engine.forget_lost(scope)?;
        // a link's label known only by its hint (K's commits not here yet): its session holds what
        // the head gave, gone with the secrets, so following it again opens it anew
        f.labels.extend(self.state.hints.iter().filter(|(_, h)| h.via.is_some() && actors.contains(&h.thing)).map(|(l, _)| *l));
        if f.things.is_empty() && f.labels.is_empty() {
            return Ok(leaving);
        }
        let mem_log = std::mem::take(&mut self.state.mem_log);
        let now = self.state.now;
        self.state = super::state::State::load(&mut self.engine)?;
        // what the passes knew of entries is gone with them: everything is judged again
        self.touched.full = true;
        self.keeps.clear();
        self.rotated.clear();
        self.state.mem_log = mem_log;
        self.state.now = now;
        // owed records are taken at start only; a copy waiting to rotate a forgotten group is moot
        self.state.owed.clear();
        let mut moot = Vec::new();
        for x in std::mem::take(&mut self.deferred) {
            // `place_certificate_in` places nothing there any more
            if self.engine.group_labels(&x.0).is_ok_and(|ls| ls.iter().all(|l| l.replaced)) {
                moot.extend(x.3);
            } else {
                self.deferred.push(x);
            }
        }
        for k in moot {
            self.settle_owed(k);
        }
        let gone = |l: &LabelId| f.labels.contains(l);
        for l in &f.labels {
            self.state.mem_log.forget(l);
            self.state.forget_passed(l);
        }
        for (id, c) in self.conns.iter_mut() {
            for l in c.labels.keys().filter(|l| gone(l)) {
                self.unsubscribe.insert((*id, *l));
            }
            c.labels.retain(|l, _| !gone(l));
            c.req.forget(gone);
        }
        // until `labels` is asked again, the forgotten labels are no actor's
        let mut s = (*self.synced).clone();
        s.actors.retain(|l, _| !gone(l));
        for ls in s.by_actor.values_mut() {
            ls.retain(|l| !gone(l));
        }
        self.synced = std::sync::Arc::new(s);
        self.passes.retain(|(_, l), _| !gone(l));
        self.peer_received.retain(|l, _| !gone(l));
        self.peer_passes.retain(|(_, l), _| !gone(l));
        self.served_cache = None;
        self.forget_inbox()?;
        Ok(leaving)
    }

    /// Stops the pushes of forgotten labels' sessions (spec/sync.md §8) still connected and not
    /// opened again.
    pub(crate) fn stop_pushes(&mut self, out: &mut Vec<Action>) {
        for (conn, l) in std::mem::take(&mut self.unsubscribe) {
            if !self.cfg.subscribe || self.conns.get(&conn).is_none_or(|c| c.labels.contains_key(&l)) {
                continue;
            }
            if let Err(e) = self.command(conn, osis_proto::Command::Unsubscribe { labels: vec![l] }, out) {
                self.diag(format!("unsubscribe: {e}"));
            }
        }
    }

    /// Records a flow's deliveries; the next step sends them.
    ///
    /// Invariant: after any crash, the placements and direct sends this node makes are those
    /// it would have made without the crash. Every delivery but an inbox blob is recorded in the
    /// transaction of the commit that owes it (`flows::owe`, `y/y`); its record goes in the
    /// sync state's flush that holds what carrying it out wrote (entries, certificates, outbox,
    /// direct lists), or, while a copy waits for a rotation (`deferred`), once the last such
    /// copy is placed. What is recorded at start is carried out again (`take_owed`); copies
    /// already placed are skipped (`State::certs`). Inbox blobs: `State::note_unsent`.
    pub(crate) fn take_done(&mut self, done: Done) -> Result<()> {
        for d in done.deliveries {
            let k = super::state::owed_key(&d);
            self.deliver(d, k)?;
            if let Some(k) = k {
                self.settle_owed(k);
            }
        }
        Ok(())
    }

    /// Carries out the deliveries owed at start (`take_done`).
    pub(crate) fn take_owed(&mut self) -> Result<()> {
        for (k, d) in std::mem::take(&mut self.state.owed) {
            self.deliver(d, Some(k))?;
            self.settle_owed(k);
        }
        Ok(())
    }

    /// Drops owed delivery `k`'s record unless a copy of it still waits for a rotation.
    pub(crate) fn settle_owed(&mut self, k: [u8; 32]) {
        if !self.deferred.iter().any(|x| x.3 == Some(k)) {
            self.state.settle_owed(k);
        }
    }

    /// Carries out one delivery, owed as `k` (copies waiting for a rotation keep it).
    fn deliver(&mut self, d: Delivery, k: Option<[u8; 32]>) -> Result<()> {
        match d {
            // sealed and sent from its record (`send_inbox`)
            Delivery::Inbox { resend, .. } => self.state.note_unsent(resend.holder, resend.commit, resend.things, resend.edge_only),
            Delivery::Direct { to, commits } => self.state.add_direct(to, &commits),
            Delivery::First { commits, under } => {
                for c in &commits {
                    self.first.insert(*c);
                }
                for t in under {
                    for g in self.groups_holding(&t) {
                        for c in &commits {
                            self.place_chain(&g, c, k)?;
                        }
                    }
                }
            }
            Delivery::Certificate { commits, under } => {
                for c in &commits {
                    self.place_chain(&under, c, k)?;
                }
            }
            Delivery::Deposit { commit, under } => {
                for g in self.groups_holding(&under) {
                    self.place_aspects(&g, &commit, k, |_| true)?;
                }
            }
            Delivery::Removal { commit, under } => {
                for g in self.groups_holding(&under) {
                    self.place_aspects(&g, &commit, k, |a| !matches!(a.ak.as_str(), "secrets.0" | "keys.0"))?;
                }
            }
        }
        Ok(())
    }

    /// Places `c`'s certificate deltas (edges, `keys.0`: spec/permissions.md §4) on things
    /// outside `g`'s closure as a certificate copy under `g`'s labels, and the records it mints
    /// raw (they outlive it); deltas on things inside it go up as its closure bodies (a whole
    /// copy duplicated them, and carried `secrets.0` boxes the label's readers cannot open).
    pub(crate) fn place_chain(&mut self, g: &Tid, c: &CommitId, owed: Option<[u8; 32]>) -> Result<()> {
        let closure = self.engine.closure(g);
        let minted: BTreeSet<Tid> = self.engine.header(c).map(|h| h.aspects.iter().filter(|a| a.ak.as_str() == "created.0").map(|a| a.tid).collect()).unwrap_or_default();
        if !minted.is_empty() {
            for l in self.engine.group_labels(g)?.into_iter().filter(|l| !l.replaced) {
                self.place_records(g, l.id, &minted)?;
            }
        }
        self.place_aspects(g, c, owed, |a| matches!(a.ak.as_str(), "roles.0" | "keys.0") && !closure.contains(&a.tid))
    }

    /// Places the aspects of `c` that `keep` admits as a certificate copy under the labels of
    /// `g` (`Delivery::Deposit`: all of them; `Delivery::Removal`: all but `secrets.0` and
    /// `keys.0`); nothing when it admits none.
    fn place_aspects(&mut self, g: &Tid, c: &CommitId, owed: Option<[u8; 32]>, keep: impl Fn(&osis_commit::AspectEntry) -> bool) -> Result<()> {
        let Some(h) = self.engine.header(c) else { return Ok(()) };
        let ais: BTreeSet<usize> = h.aspects.iter().enumerate().filter(|(_, a)| keep(a)).map(|(i, _)| i).collect();
        if ais.is_empty() {
            return Ok(());
        }
        self.place_certificate_in(g, c, &ais, owed)
    }

    /// Whether commit `c` is this node's own (made here, a held key actor's included).
    pub(crate) fn own(&self, c: &CommitId) -> bool {
        self.engine.core.ix.commits.get(c).is_some_and(|m| m.origin == crate::events::Origin::Local)
    }

    /// Whether `g`'s closure holds a thing commit `c` touches (its labels are `c`'s own).
    fn under_own_label(&self, g: &Tid, c: &CommitId) -> bool {
        let Some(h) = self.engine.header(c) else { return false };
        let closure = self.engine.closure(g);
        h.aspects.iter().any(|a| closure.contains(&a.tid))
    }

    /// Whether this node's commit `c` is placed (spec/sync.md §5): no deposit of it queued here
    /// under a label where no entry of it is present yet, and under every label this node syncs
    /// of the things it touches, each body of it the label must hold is in an entry present at
    /// one of the label's hosts (a label with no host: an entry this node serves, if it
    /// serves any) or covered by a snapshot there. Cached until entries, presence, the outbox or
    /// the engine change.
    pub(crate) fn placed(&mut self, c: &CommitId) -> Result<bool> {
        if self.placed_cache.0 != self.state.version {
            self.placed_cache = (self.state.version, Default::default());
        }
        if let Some(x) = self.placed_cache.1.get(c) {
            return Ok(*x);
        }
        let x = self.placed_now(c)?;
        self.placed_cache.1.insert(*c, x);
        Ok(x)
    }

    fn placed_now(&mut self, c: &CommitId) -> Result<bool> {
        let queued: Vec<LabelId> = self.state.outbox.iter().filter(|((_, _, b), _)| self.state.blobs.get(b).is_some_and(|r| r.commit == *c)).map(|(_, o)| o.label).collect();
        for l in queued {
            if !self.held_at(&l, c, None, true) {
                return Ok(false);
            }
        }
        let Some(h) = self.engine.header(c) else { return Ok(true) };
        let Some(body) = self.engine.body(c)? else { return Ok(true) };
        for (g, gl) in self.labels() {
            if gl.replaced || !self.under_own_label(&g, c) {
                continue;
            }
            let local = super::peers::hostless(&gl.hosts);
            if local && !self.serves_readers() {
                continue;
            }
            let ctx = self.engine.body_ctx(&g);
            let inside: Vec<usize> = body.parts.iter().filter(|ai| h.aspects.get(**ai).is_some_and(|a| ctx.closure.contains(&a.tid))).copied().collect();
            let parts = self.engine.readable_parts(&ctx, c, &inside);
            if parts.is_empty() {
                continue;
            }
            if !self.held_at(&gl.id, c, Some(&parts), true) && !self.parts_covered_at(&gl.id, c, &h, &parts)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether entries of `c` under `l` (present at a host when `present`) hold `parts`
    /// (any part when `None`). For `placed` of this node's own commit: any entry counts, at any
    /// one host. Not `held_parts` (`pass/`), which asks whether another node's entries spare
    /// this node a certificate copy, and so counts them only genuine, at every host and, with
    /// a rotation, readable under the newest secret.
    fn held_at(&self, l: &LabelId, c: &CommitId, parts: Option<&[usize]>, present: bool) -> bool {
        let mut held: BTreeSet<usize> = BTreeSet::new();
        for (id, e) in self.state.entries_of(l, c) {
            if let super::state::Kind::Commit { parts: p, .. } = &e.kind
                && (!present || self.state.held_anywhere(l, &id))
            {
                held.extend(p.iter().copied());
            }
        }
        match parts {
            Some(ps) => ps.iter().all(|p| held.contains(p)),
            None => !held.is_empty(),
        }
    }

    /// Groups with a label whose closure holds `t` (the thing itself when labeled).
    fn groups_holding(&mut self, t: &Tid) -> Vec<Tid> {
        // handed-off groups: nothing goes under their labels from here
        let mut out: Vec<Tid> = self.engine.labeled_groups().into_iter().filter(|g| !self.state.handed_off.contains(g) && (g == t || self.engine.groups_of(t).contains(g))).collect();
        out.dedup();
        out
    }

    /// The actor whose inbox `label` is for `to` (`Engine::inbox_of_actor`; its deposit seed
    /// signs the deposit).
    pub(crate) fn inbox_actor(&mut self, to: &Tid, label: &LabelId) -> Result<Option<Tid>> {
        Ok(self.engine.inbox_of_actor(to)?.filter(|(_, i)| i.label == *label).map(|(o, _)| o))
    }

    /// Commits for nodes over a direct connection (pairing): the app carries them, the
    /// receiving node `Engine::ingest`s them. Kept durably until taken.
    pub fn take_direct(&mut self) -> Vec<(Tid, Vec<Package>)> {
        let lists = self.state.take_direct(None);
        let out = lists.into_iter().map(|(to, cs)| (to, self.packages(&cs))).collect();
        let _ = self.state.flush(&mut self.engine);
        out
    }

    /// The packages for node `to` only; those for other nodes stay.
    pub fn take_direct_for(&mut self, to: &Tid) -> Vec<Package> {
        let lists = self.state.take_direct(Some(to));
        let out = lists.into_iter().flat_map(|(_, cs)| self.packages(&cs)).collect();
        let _ = self.state.flush(&mut self.engine);
        out
    }

    /// Packages of the held commits among `cs`.
    fn packages(&mut self, cs: &[CommitId]) -> Vec<Package> {
        cs.iter().filter_map(|c| self.engine.package(c).ok().flatten()).collect()
    }
}

impl SyncEngine {
    /// Finalizes the links due here (`Engine::links_due`, spec/permissions.md §7) after a
    /// complete pass of K's labels (`complete_pass`) that, for an expired link, ended at every
    /// host after `until` (a pass from before going offline does not count); at once when K's
    /// labels have no host (`peer://` nodes only count as none) and this node made the link (the redeemers reached it directly;
    /// another node of the sharer may not have their grants yet). A link whose finalization
    /// failed is not tried again in this run.
    pub(crate) fn finalize_links(&mut self) -> Result<()> {
        let due = self.engine.links_due()?;
        if due.is_empty() {
            return Ok(());
        }
        self.labels();
        for (h, until) in due {
            let k = h.k;
            let labels: Vec<(LabelId, &Vec<HostKey>)> = self.synced.by_actor.get(&k).into_iter().flatten().filter_map(|id| self.synced.actors.get(id).map(|(_, s)| (*id, s))).collect();
            let hostless = !labels.is_empty() && labels.iter().all(|(_, s)| s.is_empty());
            let after = labels.iter().all(|(id, s)| s.iter().all(|host| self.passes.get(&(*host, *id)).is_some_and(|p| until.is_none_or(|u| p.1 >= u.0))));
            let ready = if hostless { h.here } else { after && self.complete_pass(&k) };
            if self.links_failed.contains(&k) || !ready {
                continue;
            }
            match self.engine.finalize_link(&k, &h.l) {
                Ok(done) => {
                    self.take_done(done)?;
                    self.mark_dirty();
                }
                Err(e) => {
                    self.links_failed.insert(k);
                    self.diag(format!("finalizing link {k}: {e}"));
                }
            }
        }
        Ok(())
    }
}

/// The obligation to remove tied edges whose placement is gone (`SyncEngine::untie_unplaced`).
#[derive(Debug, Default)]
pub(crate) struct TiedWork {
    /// Derive every pair again (at start).
    pub all: bool,
    /// Groups whose `group.0` changed.
    pub groups: BTreeSet<Tid>,
    /// Things whose `roles.0` or roster changed.
    pub targets: BTreeSet<Tid>,
    /// (target, group): a tied edge whose placement this node holds dead.
    pub due: BTreeSet<(Tid, Tid)>,
    /// Removals that failed in this run: not tried again.
    pub failed: BTreeSet<(Tid, Tid)>,
}

impl TiedWork {
    pub(crate) fn touched(&mut self, changed: &[(Tid, osis_base::Ak)]) {
        for (t, ak) in changed {
            match ak.as_str() {
                "group.0" => {
                    self.groups.insert(*t);
                }
                "roles.0" => {
                    self.targets.insert(*t);
                }
                _ => {}
            }
        }
    }
}

impl SyncEngine {
    /// Removes the tied edges whose placement is gone (spec/permissions.md §2): a tied edge
    /// (G, T) whose named `group.0` element this node holds dead (`Engine::tie_dead`). As an
    /// explicit demotion by an admin of T, after a complete pass of every label holding a thing
    /// of its pre-sync scope ended after the last remote role commit of G and of T (its
    /// pre-sync, none for an empty scope); else as a self-removal by an admin of G; nothing when
    /// this node may do neither, or the pair or its scope meets a handed-off group.
    pub(crate) fn untie_unplaced(&mut self) -> Result<()> {
        let w = &mut self.tied;
        if w.all || !w.groups.is_empty() || !w.targets.is_empty() {
            let (all, groups, targets) = (std::mem::take(&mut w.all), std::mem::take(&mut w.groups), std::mem::take(&mut w.targets));
            if all {
                w.due.clear();
            } else {
                w.due.retain(|(t, g)| !groups.contains(g) && !targets.contains(t));
            }
            let found = self.engine.tied_unplaced(&groups, &targets, all)?;
            self.tied.due.extend(found);
        }
        if self.tied.due.is_empty() {
            return Ok(());
        }
        self.labels();
        let due: Vec<(Tid, Tid)> = self.tied.due.iter().filter(|p| !self.tied.failed.contains(p)).copied().collect();
        for (t, g) in due {
            let Some(how) = self.engine.may_remove(&t, &g) else { continue };
            // a pair or scope reaching a handed-off group is left to its holders:
            // its state here is stale and nothing would go under its labels from here
            let explicit = how == crate::flows::Untie::Explicit;
            let scope = if explicit { self.engine.removal_scope(&t, &g, None) } else { BTreeSet::new() };
            let reach: BTreeSet<Tid> = scope.iter().copied().chain([t, g]).collect();
            if !self.handed_off_groups(&reach).is_empty() {
                continue;
            }
            if explicit {
                let since = [g, t].iter().filter_map(|a| self.role_change.get(a)).map(|x| x.0).max().unwrap_or(0);
                let mut holding: BTreeSet<Tid> = BTreeSet::new();
                for x in &scope {
                    holding.extend(self.groups_holding(x));
                }
                if !holding.is_empty() && !self.passed_since(&holding, since, &[g, t]) {
                    continue;
                }
            }
            match self.engine.untie(&t, &g) {
                Ok(done) => {
                    self.tied.due.remove(&(t, g));
                    self.take_done_lost(done)?;
                }
                Err(e) => {
                    self.tied.failed.insert((t, g));
                    self.diag(format!("removing the tied edge of {g} on {t}: {e}"));
                }
            }
        }
        Ok(())
    }

    /// Every label of `groups` passed completely after `since` (`label_passed`), the peer wait
    /// counted from the last remote role commit of any of `actors`.
    fn passed_since(&self, groups: &BTreeSet<Tid>, since: u64, actors: &[Tid]) -> bool {
        let waited = actors.iter().all(|a| self.peers_waited(a));
        self.synced.labels.iter().filter(|(g, _)| groups.contains(g)).all(|(g, l)| self.label_passed(&l.id, g, super::peers::host_keys(&l.hosts), since, waited))
    }

    /// Whether a complete pass may stop waiting for peers on `actor`'s change: `peer_pass_wait_ms`
    /// after its last remote role commit, or after the start when none applied in this run
    /// (`role_change` is memory only; spec/permissions.md §3 bounds the wait after the change):
    /// a restarted node first hears its peers out.
    pub(crate) fn peers_waited(&self, actor: &Tid) -> bool {
        self.peer_wait_end(actor) <= self.raw_now()
    }

    /// When the wait of `peers_waited` ends (raw ms).
    pub(crate) fn peer_wait_end(&self, actor: &Tid) -> u64 {
        self.role_change.get(actor).map_or(self.started, |x| x.1).saturating_add(self.cfg.peer_pass_wait_ms)
    }

    /// Asks each host of the labels of every actor in `pass_wanted` for a pass end after that
    /// actor's last remote role commit (a Sync from the cursor), where the label is live and its
    /// last pass end there came before the commit: a commit applied from outside a label's
    /// host stream (an inbox, a Deposit item, another host) would otherwise wait for that label's
    /// next push (spec/permissions.md §3 Complete pass). A Sync in flight is asked again when it
    /// ends (`synced`): sent before the commit, its end is none after it.
    /// Passes go on meanwhile (`LConn::ending`): the label was read to its end before.
    pub(crate) fn ask_pass_ends(&mut self, out: &mut Vec<Action>) -> Result<()> {
        if self.pass_wanted.is_empty() {
            return Ok(());
        }
        self.labels();
        let mut ask = Vec::new();
        for a in std::mem::take(&mut self.pass_wanted) {
            let since = self.role_change.get(&a).map_or(0, |x| x.0);
            for l in self.synced.by_actor.get(&a).into_iter().flatten() {
                let Some((_, hosts)) = self.synced.actors.get(l) else { continue };
                for (id, c) in self.conns.iter().filter(|(_, c)| !c.peer && hosts.contains(&c.host)) {
                    let live = c.labels.get(l).is_some_and(|x| x.phase == Phase::Open && x.synced && !x.syncing && x.fill.is_none());
                    let cursor = self.state.cursors.get(&(c.host, *l)).copied();
                    if let Some(cursor) = cursor.filter(|_| live && self.passes.get(&(c.host, *l)).is_none_or(|p| p.0 <= since)) {
                        ask.push((*id, *l, cursor));
                    }
                }
            }
        }
        for (conn, label, cursor) in ask {
            self.ask_pass_end(conn, label, cursor, out)?;
        }
        Ok(())
    }

    /// Asks the host on `conn` for a pass end of live label `label`: a Sync from `cursor`.
    pub(crate) fn ask_pass_end(&mut self, conn: ConnId, label: LabelId, cursor: osis_proto::Cursor, out: &mut Vec<Action>) -> Result<()> {
        if let Some(x) = self.lc_mut(conn, &label) {
            (x.syncing, x.ending) = (true, true);
        }
        let inline_limit = self.cfg.inline_limit;
        self.command(conn, osis_proto::Command::Sync { label, cursor: Some(cursor), inline_limit, entries: Vec::new(), gained: Vec::new() }, out)
    }

    /// Whether label `l` (held under `thing`) passed completely after `since`
    /// (spec/permissions.md §3): at each of `hosts` and, until `waited`, at each source it was
    /// received from that still reads it, connected or not (`peer_received`). With neither,
    /// nothing upstream holds what it lacks: it passes once `waited` (a node serving it alone,
    /// spec/sync.md §5, else never re-seals or unties).
    fn label_passed(&self, l: &LabelId, thing: &Tid, hosts: impl Iterator<Item = HostKey>, since: u64, waited: bool) -> bool {
        let after = |p: Option<&(u64, u64)>| p.is_some_and(|p| p.0 > since);
        let mut any = false;
        for h in hosts {
            any = true;
            if !after(self.passes.get(&(h, *l))) {
                return false;
            }
        }
        if waited {
            return true;
        }
        let core = &self.engine.core;
        for t in self.peer_received.get(l).into_iter().flatten() {
            // an own node reads what its account reads (it proves the account too)
            let account = core.account.get().filter(|_| core.own_node(t));
            if core.judge(std::iter::once(*t).chain(account)).of(thing) != super::credentials::Judgment::Holder {
                continue;
            }
            any = true;
            if !after(self.peer_passes.get(&(*t, *l))) {
                return false;
            }
        }
        any
    }
}

impl SyncState for SyncEngine {
    fn complete_pass(&self, actor: &Tid) -> bool {
        let since = self.role_change.get(actor).map_or(0, |x| x.0);
        let waited = self.peers_waited(actor);
        // no label of the actor known (at start, before `labels()`): no pass yet
        let mut labels = self.synced.by_actor.get(actor).into_iter().flatten().filter_map(|l| self.synced.actors.get(l).map(|x| (l, x))).peekable();
        labels.peek().is_some() && labels.all(|(l, (a, hosts))| self.label_passed(l, a, hosts.iter().copied(), since, waited))
    }
}

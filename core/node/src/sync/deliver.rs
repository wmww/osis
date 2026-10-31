//! Carrying out what membership flows produce (`flows::Done`, `flows::Delivery`) and the sync
//! state flows ask about (`flows::SyncState`): inbox blobs deposited at the inbox's servers,
//! direct commits handed to the app's pairing channel, placements before any other upload,
//! certificate copies under a home label, deposits; commits that travel by inbox only are never
//! placed under a label (spec/permissions.md §3, re-seal).

use super::{Action, ServerKey, SyncEngine};
use crate::error::Result;
use crate::flows::{Delivery, Done, SyncState};
use crate::local_peer::Package;
use osis_base::{CommitId, LabelId, Tid};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

impl SyncEngine {
    /// Carries out a flow's result (call it with every `Done` a flow returns).
    pub fn carry_out(&mut self, done: Done) -> Result<Vec<Action>> {
        if done.drop_lost {
            if done.deliveries.iter().any(|d| matches!(d, Delivery::First { under, .. } if !under.is_empty())) {
                self.drop_when_idle = true;
            } else {
                self.drop_lost()?;
            }
        }
        self.take_done(done)?;
        // placements wait for a pass
        self.mark_dirty();
        Ok(self.handle(super::Event::Local))
    }

    /// Drops what this node lost read access to (`Engine::drop_lost_secrets`, spec/permissions.md
    /// §3) and its sync state about it: the engine forgets the records in its transaction, this
    /// reloads them and drops the sessions and in-memory marks of the forgotten labels. Flows'
    /// self-removals call it once uploaded; an app calls it when told it was removed.
    pub fn drop_lost(&mut self) -> Result<()> {
        self.forget_lost(false)
    }

    /// The lost-access trigger (`Engine::drop_lost_due`), run every step while received
    /// membership commits left it work, until none is left (forgetting re-examines pending
    /// commits, which may apply more).
    pub(crate) fn drop_lost_due(&mut self) -> Result<()> {
        for _ in 0..16 {
            if !self.engine.lost_due() {
                break;
            }
            self.forget_lost(true)?;
        }
        Ok(())
    }

    fn forget_lost(&mut self, due: bool) -> Result<()> {
        self.state.flush(&mut self.engine)?;
        let (_, f) = self.engine.forget_lost(due)?;
        if f.things.is_empty() {
            return Ok(());
        }
        let feed = std::mem::take(&mut self.state.feed);
        let now = self.state.now;
        self.state = super::state::State::load(&mut self.engine)?;
        // what the passes knew of entries is gone with them: everything is judged again
        self.touched.full = true;
        self.state.feed = feed;
        self.state.now = now;
        let gone = |l: &LabelId| f.labels.contains(l);
        for l in &f.labels {
            self.state.feed.forget(l);
        }
        for (id, c) in self.conns.iter_mut() {
            for l in c.labels.keys().filter(|l| gone(l)) {
                self.unsubscribe.insert((*id, *l));
            }
            c.labels.retain(|l, _| !gone(l));
            c.req.sent.retain(|(l, _), _| !gone(l));
            c.req.deleting.retain(|(l, _), _| !gone(l));
            c.req.replacing.retain(|(l, _), _| !gone(l));
            c.req.timed_sent.retain(|(l, _)| !gone(l));
            c.req.reopens.retain(|l, _| !gone(l));
        }
        self.synced.actors.retain(|l, _| !gone(l));
        self.passes.retain(|(_, l), _| !gone(l));
        self.peer_received.retain(|l, _| !gone(l));
        self.served_cache = None;
        self.forget_inbox()
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
    pub(crate) fn take_done(&mut self, done: Done) -> Result<()> {
        for d in done.deliveries {
            match d {
                // sealed and sent from its record (`send_inbox`)
                Delivery::Inbox { resend, .. } => self.state.note_unsent(resend.member, resend.commit, resend.things, resend.edge_only),
                Delivery::Direct { to, commits } => self.state.add_direct(to, &commits),
                Delivery::First { commits, under } => {
                    for c in &commits {
                        self.first.insert(*c);
                    }
                    for t in under {
                        for g in self.groups_holding(&t) {
                            for c in &commits {
                                self.place_chain(&g, c)?;
                            }
                        }
                    }
                }
                Delivery::Certificate { commits, under } => {
                    for c in &commits {
                        self.place_chain(&under, c)?;
                    }
                }
                Delivery::Deposit { commit, under } => {
                    for g in self.groups_holding(&under) {
                        self.place_all(&g, &commit)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Places `c`'s certificate deltas (edges, `/keys`, `/created`: spec/permissions.md §4) on
    /// things outside `g`'s closure as a certificate copy under `g`'s labels; deltas on things
    /// inside it go up as its closure bodies (a whole copy duplicated them, and carried
    /// `/secrets` boxes the label's readers cannot open).
    pub(crate) fn place_chain(&mut self, g: &Tid, c: &CommitId) -> Result<()> {
        let Some(h) = self.engine.header(c) else { return Ok(()) };
        let closure = self.engine.closure(g);
        let ais: BTreeSet<usize> = h.aspects.iter().enumerate().filter(|(_, a)| matches!(a.ak.as_str(), "/members" | "/tenures" | "/keys" | "/created") && !closure.contains(&a.tid)).map(|(i, _)| i).collect();
        if ais.is_empty() {
            return Ok(());
        }
        self.place_certificate_in(g, c, &ais)
    }

    /// Places every aspect of `c` as a certificate copy under the labels of `g`.
    fn place_all(&mut self, g: &Tid, c: &CommitId) -> Result<()> {
        let Some(h) = self.engine.header(c) else { return Ok(()) };
        let all: BTreeSet<usize> = (0..h.aspects.len()).collect();
        self.place_certificate_in(g, c, &all)
    }

    /// Whether commit `c` is this node's own (made here, a held key actor's included).
    pub(crate) fn own(&self, c: &CommitId) -> bool {
        self.engine.core.ix.commits.get(c).is_some_and(|m| m.origin == crate::events::Origin::Local || m.header.author == self.engine.tid())
    }

    /// Whether `g`'s closure holds a thing commit `c` touches (its labels are `c`'s own).
    pub(crate) fn under_own_label(&self, g: &Tid, c: &CommitId) -> bool {
        let Some(h) = self.engine.header(c) else { return false };
        let closure = self.engine.closure(g);
        h.aspects.iter().any(|a| closure.contains(&a.tid))
    }

    /// Whether this node's commit `c` is placed (spec/sync.md §5): no deposit of it queued here
    /// under a label where no entry of it is present yet, and under every label this node syncs
    /// of the things it touches, each body of it the label must hold is in an entry present at
    /// one of the label's servers (a label with no server: an entry this node serves, if it
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
        let bodies = self.engine.bodies(c)?;
        for (g, gl) in self.labels() {
            if gl.replaced || !self.under_own_label(&g, c) {
                continue;
            }
            let local = gl.servers.iter().all(super::peers::is_peer);
            if local && self.own_reach().is_none() {
                continue;
            }
            let closure = self.engine.closure(&g);
            let x = self.engine.group_actor(&g);
            for b in &bodies {
                let inside = b.parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).any(|a| closure.contains(&a.tid));
                if !inside || !self.engine.may_read(&x, &b.reader) {
                    continue;
                }
                if !self.held_at(&gl.id, c, Some(&b.parts), !local) && !self.parts_covered_at(&gl.id, c, &h, &b.parts)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Whether entries of `c` under `l` (present at a server when `present`) hold `parts`
    /// (any part when `None`). For `placed` of this node's own commit: any entry counts, at any
    /// one server. Not `held_parts` (pass.rs), which asks whether another node's entries spare
    /// this node a certificate copy, and so counts them only genuine, at every server and, with
    /// a rotation, readable under the newest secret.
    fn held_at(&self, l: &LabelId, c: &CommitId, parts: Option<&[(usize, usize)]>, present: bool) -> bool {
        let mut held: BTreeSet<(usize, usize)> = BTreeSet::new();
        for (id, e) in self.state.entries_of(l, c) {
            if let super::state::Kind::Commit { parts: p, .. } = &e.kind
                && (!present || self.state.present_anywhere(l, &id))
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
        let mut out: Vec<Tid> = self.engine.labeled_groups().into_iter().filter(|g| g == t || self.engine.durable_groups_of(t).contains(g)).collect();
        out.dedup();
        out
    }

    /// The actor up `to`'s owner chain whose `/keys` names `label` as its inbox (its deposit
    /// seed signs the deposit).
    pub(crate) fn inbox_owner(&mut self, to: &Tid, label: &LabelId) -> Result<Option<Tid>> {
        let chain: Vec<Tid> = self.engine.owner_chain(to).collect();
        for t in chain {
            if self.engine.get_typed(&t, &ct::KEYS)?.and_then(|k| k.inbox).is_some_and(|i| i.label == *label) {
                return Ok(Some(t));
            }
        }
        Ok(None)
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
    /// Finalizes the links due here (`Engine::links_due`, spec/permissions.md §9) after a
    /// complete pass of K's labels (`complete_pass`) that, for an expired link, ended at every
    /// server after `until` (a pass from before going offline does not count); at once when K's
    /// labels have no server and this node made the link (the redeemers reached it directly;
    /// another device of the sharer may not have their grants yet). A link whose finalization
    /// failed is not tried again in this run.
    pub(crate) fn finalize_links(&mut self) -> Result<()> {
        let due = self.engine.links_due()?;
        if due.is_empty() {
            return Ok(());
        }
        self.labels();
        for (h, until) in due {
            let k = h.k;
            let labels: Vec<(LabelId, &Vec<ServerKey>)> = self.synced.actors.iter().filter(|(_, (a, _))| *a == k).map(|(id, (_, s))| (*id, s)).collect();
            let serverless = !labels.is_empty() && labels.iter().all(|(_, s)| s.is_empty());
            let after = labels.iter().all(|(id, s)| s.iter().all(|sv| self.passes.get(&(*sv, *id)).is_some_and(|p| until.is_none_or(|u| p.1 >= u.0))));
            let ready = if serverless { h.here } else { after && self.complete_pass(&k) };
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
    /// Groups whose `/group` changed.
    pub groups: BTreeSet<Tid>,
    /// Things whose `/members` or roster changed.
    pub targets: BTreeSet<Tid>,
    /// (target, group): a tied edge whose group's `/group` here lacks the target.
    pub due: BTreeSet<(Tid, Tid)>,
    /// Removals that failed in this run: not tried again.
    pub failed: BTreeSet<(Tid, Tid)>,
}

impl TiedWork {
    pub(crate) fn touched(&mut self, changed: &[(Tid, osis_base::Ak)]) {
        for (t, ak) in changed {
            match ak.as_str() {
                "/group" => {
                    self.groups.insert(*t);
                }
                "/members" => {
                    self.targets.insert(*t);
                }
                _ => {}
            }
        }
    }
}

impl SyncEngine {
    /// Removes the tied edges whose placement is gone (spec/permissions.md §2): a tied edge
    /// (G, T) where G's `/group` here lacks T, once every label holding G (and, for an explicit
    /// demotion, every label holding a thing of its pre-sync scope) passed completely after the
    /// last remote membership commit of G and of T (the placement written with the edge has
    /// arrived by then, and a concurrent removal is seen). As an explicit demotion by an admin
    /// of T, else as a self-removal by an admin of G; nothing when this node may do neither.
    pub(crate) fn untie_unplaced(&mut self) -> Result<()> {
        let w = &mut self.tied;
        if w.all || !w.groups.is_empty() || !w.targets.is_empty() {
            let (all, groups, targets) = (std::mem::take(&mut w.all), std::mem::take(&mut w.groups), std::mem::take(&mut w.targets));
            if all {
                w.due.clear();
            } else {
                w.due.retain(|(t, g)| !groups.contains(g) && !targets.contains(t));
            }
            let found = self.engine.tied_unplaced(&groups, &targets, all);
            self.tied.due.extend(found);
        }
        if self.tied.due.is_empty() {
            return Ok(());
        }
        self.labels();
        let due: Vec<(Tid, Tid)> = self.tied.due.iter().filter(|p| !self.tied.failed.contains(p)).copied().collect();
        for (t, g) in due {
            let Some(how) = self.engine.may_remove(&t, &g) else { continue };
            let since = [g, t].iter().filter_map(|a| self.membership_seen.get(a)).copied().max().unwrap_or(0);
            let mut holding: BTreeSet<Tid> = self.groups_holding(&g).into_iter().collect();
            if how == crate::flows::Untie::Explicit {
                for x in self.engine.presync_scope(&t, &g, None) {
                    holding.extend(self.groups_holding(&x));
                }
            }
            if !self.passed_since(&holding, since, &t) {
                continue;
            }
            match self.engine.untie(&t, &g) {
                Ok(done) => {
                    self.tied.due.remove(&(t, g));
                    if done.drop_lost {
                        if done.deliveries.iter().any(|d| matches!(d, Delivery::First { under, .. } if !under.is_empty())) {
                            self.drop_when_idle = true;
                        } else {
                            self.drop_lost()?;
                        }
                    }
                    self.take_done(done)?;
                    self.mark_dirty();
                }
                Err(e) => {
                    self.tied.failed.insert((t, g));
                    self.diag(format!("removing the tied edge of {g} on {t}: {e}"));
                }
            }
        }
        Ok(())
    }

    /// Every label of `groups` passed completely after `since` at its servers and at the
    /// co-readers it was received from (those for at most `peer_pass_wait_ms` after the last
    /// remote membership commit of `actor`), as `complete_pass`; false when this node syncs no
    /// such label (it cannot judge the placement).
    fn passed_since(&self, groups: &BTreeSet<Tid>, since: u64, actor: &Tid) -> bool {
        let waited = self.membership_at.get(actor).is_none_or(|t| t.saturating_add(self.cfg.peer_pass_wait_ms) <= self.raw_now());
        let mut any = false;
        for (g, l) in &self.synced.labels {
            if !groups.contains(g) {
                continue;
            }
            any = true;
            let peers = self.pass_peers.get(&l.id).into_iter().flatten().filter(|_| !waited);
            for s in l.servers.iter().map(|a| &a.key).chain(peers) {
                if self.passes.get(&(*s, l.id)).is_none_or(|p| p.0 <= since) {
                    return false;
                }
            }
        }
        any
    }
}

impl SyncState for SyncEngine {
    fn complete_pass(&self, actor: &Tid) -> bool {
        let since = self.membership_seen.get(actor).copied().unwrap_or(0);
        let mut any = false;
        for (l, (a, servers)) in &self.synced.actors {
            if a != actor {
                continue;
            }
            // the label's servers, and the co-readers it received the label from while a
            // connection to them is up with the label started and they still read it
            // (spec/permissions.md §3), for at most `peer_pass_wait_ms` after the change
            let waited = self.membership_at.get(actor).is_some_and(|t| t.saturating_add(self.cfg.peer_pass_wait_ms) <= self.raw_now());
            let peers = self.pass_peers.get(l).into_iter().flatten().filter(|_| !waited);
            for s in servers.iter().chain(peers) {
                any = true;
                if self.passes.get(&(*s, *l)).is_none_or(|p| p.0 <= since) {
                    return false;
                }
            }
        }
        any
    }
}

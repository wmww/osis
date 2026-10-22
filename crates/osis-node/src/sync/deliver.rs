//! Carrying out what membership flows produce (`flows::Done`, `flows::Delivery`) and the sync
//! state flows ask about (`flows::SyncState`): inbox blobs deposited at the inbox's servers,
//! direct commits handed to the app's pairing channel, placements before any other upload,
//! certificate copies under a home label, deposits; commits that travel by inbox only are never
//! placed under a label (spec/permissions.md §3, re-seal).

use super::{Action, PLACE_WAIT_MS, SyncEngine};
use crate::error::Result;
use crate::flows::{Delivery, Done, SyncState};
use crate::local_peer::Package;
use osis_core::{CommitId, LabelId, Tid};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

impl SyncEngine {
    /// Carries out a flow's result (call it with every `Done` a flow returns).
    pub fn carry_out(&mut self, done: Done) -> Result<Vec<Action>> {
        if done.drop_lost {
            for d in &done.deliveries {
                if let Delivery::First { under, .. } = d {
                    self.leaving.extend(under.iter().copied());
                }
            }
            if self.leaving.is_empty() {
                self.drop_lost()?;
            }
        }
        self.take_done(done)?;
        // placements wait for a pass
        for c in self.conns.values_mut() {
            for l in c.labels.values_mut() {
                l.dirty = true;
            }
        }
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
        }
        self.label_actors.retain(|l, _| !gone(l));
        self.passes.retain(|(_, l), _| !gone(l));
        self.sent.retain(|(_, l, _), _| !gone(l));
        self.deleting.retain(|(_, l, _), _| !gone(l));
        self.timed_sent.retain(|(_, l, _)| !gone(l));
        self.peer_received.retain(|l, _| !gone(l));
        self.reopens.retain(|(_, l), _| !gone(l));
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

    /// Records a flow's deliveries; the next step sends them. A key actor's own departure
    /// (`Done::departed`) is ignored by the cover check while its commits are placed.
    pub(crate) fn take_done(&mut self, done: Done) -> Result<()> {
        let added: Vec<Tid> = done.departed.iter().copied().filter(|t| self.leaving.insert(*t)).collect();
        let r = self.take_deliveries(done);
        for t in added {
            self.leaving.remove(&t);
        }
        r
    }

    fn take_deliveries(&mut self, done: Done) -> Result<()> {
        for d in done.deliveries {
            match d {
                // sealed and sent from its record once its commit is placed (`send_inbox`)
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
        self.engine.core.commits.get(c).is_some_and(|m| m.origin == crate::events::Origin::Local || m.header.author == self.engine.tid())
    }

    /// Whether `g`'s closure holds a thing commit `c` touches (its labels are `c`'s own).
    pub(crate) fn under_own_label(&self, g: &Tid, c: &CommitId) -> bool {
        let Some(h) = self.engine.header(c) else { return false };
        let closure = self.engine.closure(g);
        h.aspects.iter().any(|a| closure.contains(&a.tid))
    }

    /// Whether a projection of commit `c` outside its things' labels (a certificate copy, an
    /// inbox blob) waits (spec/sync.md §5): `c` is this node's, writes no `/keys` and carries no
    /// frontier (removals, demotions and new keys go at once, spec/permissions.md §3), and is
    /// not placed yet (`placed`), for at most `PLACE_WAIT_MS` from when this node, connected,
    /// first found it not placed (in memory: a commit made offline waits from its first sync);
    /// past that it goes anyway, with a diagnostic. A wake is set for the bound.
    pub(crate) fn hold(&mut self, c: &CommitId) -> Result<bool> {
        let Some(h) = self.engine.header(c) else { return Ok(false) };
        if !self.own(c) || h.frontier.is_some() || h.aspects.iter().any(|a| a.ak.as_str() == "/keys") {
            return Ok(false);
        }
        if self.placed(c)? {
            self.wait_since.remove(c);
            return Ok(false);
        }
        let now = self.raw_now();
        if !self.conns.values().any(|x| x.up) {
            return Ok(true);
        }
        let until = self.wait_since.entry(*c).or_insert(now).saturating_add(PLACE_WAIT_MS);
        if until <= now {
            if self.late.insert(*c) {
                self.diag(format!("commit {c:?} not placed under its things' labels after {} s: its copies go anyway", PLACE_WAIT_MS / 1000));
            }
            return Ok(false);
        }
        self.settle_at = Some(self.settle_at.map_or(until, |x| x.min(until)));
        Ok(true)
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
        let queued: Vec<LabelId> = self.state.outbox.iter().filter(|((_, b), _)| self.state.blobs.get(b).is_some_and(|r| r.commit == *c)).map(|(_, o)| o.label).collect();
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
                if !self.held_at(&gl.id, c, Some(&b.parts), !local) && !self.parts_covered(&gl.id, c, &h, &b.parts)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Whether entries of `c` under `l` (present at a server when `present`) hold `parts`
    /// (any part when `None`).
    fn held_at(&self, l: &LabelId, c: &CommitId, parts: Option<&[(usize, usize)]>, present: bool) -> bool {
        let mut held: BTreeSet<(usize, usize)> = BTreeSet::new();
        for ((_, id), e) in self.state.entries.range((*l, osis_core::BlobId([0; 32]))..).take_while(|((x, _), _)| x == l) {
            if let super::state::Kind::Commit { commit, parts: p } = &e.kind
                && commit == c
                && (!present || self.state.present_anywhere(l, id))
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
        let mut out: Vec<Tid> = self.engine.labeled_groups().into_iter().filter(|g| g == t || self.engine.groups_of(t).contains(g)).collect();
        out.dedup();
        out
    }

    /// The actor up `to`'s owner chain whose `/keys` names `label` as its inbox (its deposit
    /// seed signs the deposit).
    pub(crate) fn inbox_owner(&mut self, to: &Tid, label: &LabelId) -> Result<Option<Tid>> {
        let mut cur = *to;
        for _ in 0..64 {
            if self.engine.get_typed(&cur, &ct::KEYS)?.and_then(|k| k.inbox).is_some_and(|i| i.label == *label) {
                return Ok(Some(cur));
            }
            match self.engine.core.created(&cur) {
                Some(osis_core::CreationRecord::Thing { owner, .. }) => cur = *owner,
                _ => return Ok(None),
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

impl SyncState for SyncEngine {
    fn complete_pass(&self, actor: &Tid) -> bool {
        let since = self.membership_seen.get(actor).copied().unwrap_or(0);
        let mut any = false;
        for (l, (a, servers)) in &self.label_actors {
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
                if self.passes.get(&(*s, *l)).is_none_or(|p| *p <= since) {
                    return false;
                }
            }
        }
        any
    }
}

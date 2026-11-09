//! This node's certificates under a label (spec/permissions.md §4), and which parts entries there
//! hold.

use super::*;

impl SyncEngine {
    /// Every certificate copy this node placed under `l` in `scope` to send: chain, card, flows'
    /// placements, promoted deposits' chains.
    pub(super) fn cert_sends(&self, l: LabelId, scope: &Scope) -> Vec<Out> {
        let mut sends = Vec::new();
        for id in self.cert_entries(&l, scope) {
            let Some(e) = self.state.entries.get(&(l, id)) else { continue };
            let c = if let Kind::Commit { commit, .. } = &e.kind { Some(*commit) } else { None };
            let beat = c.and_then(|c| self.engine.header(&c)).is_some_and(|h| is_beat(&h));
            let prio = if c.is_some_and(|c| self.first.contains(&c)) {
                0
            } else if beat {
                4
            } else {
                2
            };
            sends.push(Out { prio, id, fresh: false, of: Some(c.map_or(Touch::Blob(id), Touch::Commit)) });
        }
        sends
    }

    /// This node's chain certificates and node card under `l` (spec/permissions.md §4): the
    /// aspects no entry under the label holds yet, as a fresh encryption per label. Another
    /// node's entry counts only when this node checked it genuine (`genuine`), it is present at
    /// every host this node syncs the label with (the decision is the label's, not one
    /// host's), and a newcomer can open it: one granted after a rotation gets the history
    /// boxes with its grant (spec/crypto.md §4) and opens entries under older epochs like the
    /// label's older content, except a rotation commit of the label's actor, which is wrapped
    /// under the epoch it supersedes (spec/crypto.md §5): such an entry counts only when it
    /// opens under the newest read secret.
    pub(super) fn certificates(&mut self, g: &Tid, l: LabelId, authors: &BTreeSet<Tid>) -> Result<()> {
        let _s = crate::costs::span("pass: certificates");
        let closure = self.engine.closure(g);
        let mut wanted = self.engine.certificates(g);
        for (c, p) in self.inbox_certificates(g, l)? {
            wanted.entry(c).or_default().extend(p);
        }
        // revokes about authors seen under the label (spec/permissions.md
        // §4), so its verifiers judge their writes as this node does: authors of an entry
        // judged invalid here or not judged yet (`Engine::judged_valid`); a revoke changes no
        // verdict on the writes its frontier covers (a joiner's home label holds the copy of its grant by
        // link actor L, made before L's removal)
        // (`authors`: `Work::unjudged`)
        let me = self.engine.me();
        let mut authors = authors.clone();
        authors.remove(&me);
        let actor = self.engine.group_actor(g);
        for (c, p) in self.engine.revoke_certificates(&authors, &closure, &actor) {
            wanted.entry(c).or_default().extend(p);
        }
        // removals of the label's actor's edges on things in its closure, whoever made them
        // (spec/permissions.md §2): its holders still holding such an edge would re-upload
        // the thing's bodies that others delete, on every pass
        let (removals, own_removals) = self.engine.removal_certificates(&actor, &closure);
        for (c, p) in removals {
            wanted.entry(c).or_default().extend(p);
        }
        for (c, want) in wanted {
            let (mine, have) = self.held_parts(g, l, &c)?;
            // what the label's closure bodies carry is never copied (a copy duplicating closure
            // parts is a strict subset others delete), but a removal's own parts: no body carries
            // them once the label's actor reads the thing no more
            let inside = if own_removals.contains(&c) { Default::default() } else { self.engine.header(&c).map(|h| inside(&h, &closure)).unwrap_or_default() };
            let missing: BTreeSet<usize> = want.difference(&have).filter(|ai| !inside.contains(ai)).copied().collect();
            // this node's own copy placed before and gone since (deleted at the host): not
            // placed again, but for its own card while it reads the label's actor (admins delete
            // a departed node's card; a re-grant wants it back, spec/permissions.md §4)
            if missing.is_empty() || mine.is_empty() && self.state.certs.contains(&(l, c)) && !self.own_card_read(g, &c, &missing) {
                continue;
            }
            // another node's demotion or new `keys.0` received less than `SETTLE_MS` ago is its
            // author's to place (spec/permissions.md §3, §4): holders that learn of it under
            // another label first do not all copy it; a wake brings the pass back then. An author
            // that does not read the label's actor places nothing: its copy just comes that late
            let now = self.now();
            let due = self.engine.core.ix.commits.get(&c).filter(|m| m.origin != crate::events::Origin::Local).map(|m| m.received.0.saturating_add(SETTLE_MS)).filter(|t| *t > now);
            if let Some(t) = due
                && let Some(h) = self.engine.header(&c)
                && (h.frontier.is_some() || missing.iter().all(|ai| h.aspects.get(*ai).is_some_and(|a| a.ak.as_str() == "keys.0")))
            {
                let at = self.raw_now().saturating_add(t - now);
                self.settle_by(at, l);
                continue;
            }
            // nothing to place once its parts are dropped here (`State::sweep_certs`)
            let Some(body) = self.engine.part_body(&c, &missing)? else { continue };
            self.place_copy(g, l, &c, &missing, body)?;
        }
        Ok(())
    }

    /// Places `body` (of `parts` of `c`) as this node's certificate copy under `l` and records
    /// it; whether it was placed. With no current read secret nothing wraps it and nothing is
    /// recorded: a later pass places it.
    pub(super) fn place_copy(&mut self, g: &Tid, l: LabelId, c: &CommitId, parts: &BTreeSet<usize>, body: Body) -> Result<bool> {
        let placed = self.place(g, l, &body, true)?.is_some();
        if placed {
            self.place_linked(l, c, parts)?;
            self.state.add_cert(l, *c);
        }
        Ok(placed)
    }

    /// Whether `parts` of `c` are this node's own card (its `node.0`, `reach.0`, `keys.0` writes)
    /// and it currently reads `g`'s actor.
    pub(super) fn own_card_read(&self, g: &Tid, c: &CommitId, parts: &BTreeSet<usize>) -> bool {
        let me = self.engine.tid();
        let Some(h) = self.engine.header(c) else { return false };
        h.author == me && parts.iter().all(|ai| h.aspects.get(*ai).is_some_and(|a| a.tid == me && is_card(a.ak.as_str()))) && self.engine.core.may_read(&self.engine.me(), &self.engine.group_actor(g))
    }

    /// Whether entries under `l` already hold every delta of `c` on aspects `ais` (another
    /// holder's copy of the same grant counts: spec/permissions.md §4), so a copy would only be
    /// a duplicate.
    pub(super) fn held_whole(&mut self, g: &Tid, l: LabelId, c: &CommitId, ais: &BTreeSet<usize>) -> Result<bool> {
        let Some(h) = self.engine.header(c) else { return Ok(false) };
        let want = parts_of(&h, |i| ais.contains(&i));
        let (_, held) = self.held_parts(g, l, c)?;
        Ok(want.is_subset(&held))
    }

    /// The parts of commit `c` entries under `l` hold, as (this node's certificate copies, all
    /// that count): another node's copy or body counts once genuine and present at every host
    /// this node syncs the label with, and, carrying a rotation of the label's actor, only if it
    /// opens under the newest read secret (spec/permissions.md §4). Not `held_at` (whether this
    /// node's own commit is placed).
    pub(super) fn held_parts(&mut self, g: &Tid, l: LabelId, c: &CommitId) -> Result<(Parts, Parts)> {
        let hosts: Vec<HostKey> = self.conns.values().filter(|x| x.labels.contains_key(&l)).map(|x| x.host).collect();
        self.held_parts_at(g, l, c, Some(&hosts))
    }

    /// `held_parts` with another node's entries counted when present at each of `hosts`
    /// (`None`: this node's own served state, a label served with no host: every entry).
    pub(super) fn held_parts_at(&mut self, g: &Tid, l: LabelId, c: &CommitId, hosts: Option<&[HostKey]>) -> Result<(Parts, Parts)> {
        let newest = self.engine.wrap_secret(g, None)?;
        let mut mine: BTreeSet<usize> = BTreeSet::new();
        let mut others: Vec<(BlobId, Vec<usize>)> = Vec::new();
        for (id, e) in self.state.entries_of(&l, c) {
            let Kind::Commit { parts, .. } = &e.kind else { continue };
            if e.cert {
                mine.extend(parts.iter().copied());
            } else if hosts.is_none_or(|ss| !ss.is_empty() && ss.iter().all(|s| self.state.holds_at(s, &l, &id)))
                && (!self.engine.carries_secrets(g, c, parts) || newest.as_ref().is_some_and(|k| osis_crypto::unwrap(k, &id, &e.wrap).is_ok()))
            {
                others.push((id, parts.clone()));
            }
        }
        let mut held = mine.clone();
        for (id, parts) in others {
            if self.genuine(&id) {
                held.extend(parts);
            }
        }
        Ok((mine, held))
    }

    /// Whether this node may rotate the read role of `g`'s secret actor (spec/permissions.md §3).
    pub(super) fn may_rotate_read(&self, g: &Tid) -> bool {
        let me = self.engine.me();
        let a = self.keys_actor(g);
        crate::rotation::may_rotate(&self.engine.core, &me, &a).contains(&Role::Read)
    }
}

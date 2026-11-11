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
            let prio = if c.is_some_and(|c| self.first.contains(&c)) { 0 } else { 2 };
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
        wanted.extend(self.inbox_certificates(g, l)?);
        // revokes about authors seen under the label (spec/permissions.md
        // §4), so its verifiers judge their writes as this node does: authors of an entry
        // judged invalid here or not judged yet (`Engine::judged_valid`); a revoke changes no
        // verdict on the writes its frontier covers (a joiner's home label holds the copy of its grant by
        // link actor L, made before L's removal)
        // (`authors`: `Work::unjudged`)
        let mut authors = authors.clone();
        if let Some(me) = self.engine.account_tid() {
            authors.remove(&me);
        }
        let actor = self.engine.group_actor(g);
        wanted.extend(self.engine.revoke_certificates(&authors, &closure, &actor));
        // removals of the label's actor's edges on things in its closure, whoever made them
        // (spec/permissions.md §2): its holders still holding such an edge would re-upload
        // the thing's bodies that others delete, on every pass
        let (removals, own_removals) = self.engine.removal_certificates(&actor, &closure);
        wanted.extend(removals);
        // the things the account's commits placed here touch: their thing lists go with them
        let me = self.engine.account_tid();
        let mut listed_things: BTreeSet<Tid> = BTreeSet::new();
        for c in wanted.commits.keys() {
            if let Some(h) = self.engine.header(c).filter(|h| Some(h.author) == me && h.epoch.is_some()) {
                listed_things.extend(h.aspects.iter().map(|a| a.tid));
                if h.actor != h.author {
                    listed_things.insert(h.actor);
                }
            }
        }
        // the records, raw: they outlive the commits that minted them (spec/permissions.md §4)
        self.place_records(g, l, &wanted.records, false)?;
        for (c, want) in wanted.commits {
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
                self.settle_by(t, l);
                continue;
            }
            // nothing to place once its parts are dropped here (`State::sweep_certs`)
            let Some(body) = self.engine.part_body(&c, &missing)? else { continue };
            self.place_copy(g, l, &c, &missing, body)?;
        }
        // headers alone (an ended actor's mintings)
        let hosts = self.counted_at(g, l);
        for c in wanted.headers {
            // this node's own copy placed before and gone since is not placed again
            if self.state.certs.contains(&(l, c)) || self.header_held_at(l, &c, hosts.as_deref()) {
                continue;
            }
            let Some(body) = self.engine.header_body(&c) else { continue };
            self.place_copy(g, l, &c, &BTreeSet::new(), body)?;
        }
        self.place_lists(g, l, listed_things)
    }

    /// The thing lists of this node's account's rotations for the things in `g`'s closure, those
    /// its account's commits placed here touch (`extra`), and those a commit under `l` it names
    /// is on (a thing list is a chain certificate of its thing and goes where the thing's
    /// commits go, spec/permissions.md §5.5), as list blobs under `l` (spec/sync.md §3), a fresh
    /// encryption per label; each thing's list once (`State::listed`). Costs the names of the
    /// account's rotations per pass, until each list is placed.
    fn place_lists(&mut self, g: &Tid, l: LabelId, mut extra: BTreeSet<Tid>) -> Result<()> {
        let Some(me) = self.engine.account_tid().filter(|p| self.engine.core.is_account(p)) else { return Ok(()) };
        let rotations = self.engine.account_rotations(&me);
        if rotations.is_empty() {
            return Ok(());
        }
        extra.extend(self.engine.closure(g).iter().copied());
        for r in rotations {
            let want: BTreeSet<Tid> = self
                .engine
                .rotation_lists(&r)?
                .into_iter()
                .filter(|(t, ids)| !self.state.listed.contains(&(l, r, *t)) && (extra.contains(t) || ids.iter().any(|c| self.state.by_label_commit.contains_key(&(l, *c)))))
                .map(|(t, _)| t)
                .collect();
            if want.is_empty() {
                continue;
            }
            let Some(secret) = self.engine.wrap_secret(g, None)? else { return Ok(()) };
            if let Some(pt) = self.engine.list_blob(&r, Some(&want))? {
                let mut blind = [0u8; 16];
                self.rng.fill_bytes(&mut blind);
                let salt = osis_label::Prefix::random_salt(&mut *self.rng);
                let prefix = osis_label::Prefix::for_delete_keys(salt, &blind, None, &[])?;
                let (key, blob) = osis_label::frame(&prefix, &pt, &mut *self.rng)?;
                let id = osis_label::blob_id(&blob);
                self.engine.put_blobs(vec![(id, blob)])?;
                // fetched first: what it names reads as listed from the start
                let wrap = osis_crypto::wrap(&secret, &id, &key, 0)?;
                self.state.set_entry(l, id, Entry { wrap, stamp: None, cert: true, salt: Some(salt), expires: None, size: None, kind: Kind::List { rotation: r, held: true }, memory: false });
            }
            for t in want {
                self.state.add_listed(l, r, t);
            }
        }
        Ok(())
    }

    /// The records entries under `l` hold: this node's own record blobs, another node's present at
    /// each of `hosts` (`None`: every one), as `held_parts_at` counts copies; for a promotion
    /// (`stamped`), another node's only stamped. A record blob proves itself, but a deposited one
    /// is a reader's word on what to store (any made-up records may pad one real one): a promoter
    /// never counts it, so never stamps it, and places its own; it waits for clearing.
    pub(super) fn held_records_at(&self, l: LabelId, hosts: Option<&[HostKey]>, stamped: bool) -> BTreeSet<Tid> {
        let mut out = BTreeSet::new();
        for id in self.state.of_kind(&l, Kind::TAG_RECORDS) {
            let Some(e) = self.state.entries.get(&(l, id)) else { continue };
            let Kind::Records(ts) = &e.kind else { continue };
            if e.cert || (!stamped || e.stamp.is_some()) && hosts.is_none_or(|ss| !ss.is_empty() && ss.iter().all(|s| self.state.holds_at(s, &l, &id))) {
                out.extend(ts.iter().copied());
            }
        }
        out
    }

    /// Places the records of `want` that no entry under `l` holds at the hosts this node syncs it
    /// with (`held_records_at`) as one record blob of this node's (spec/wire.md §3); records this
    /// node does not hold are left out (`stamped`: as a promoter counts them). Whether every one of
    /// `want` is held there now.
    pub(crate) fn place_records(&mut self, g: &Tid, l: LabelId, want: &BTreeSet<Tid>, stamped: bool) -> Result<bool> {
        let hosts = self.counted_at(g, l);
        let held = self.held_records_at(l, hosts.as_deref(), stamped);
        let missing: Vec<osis_base::CreationRecord> = want.iter().filter(|t| !held.contains(t)).filter_map(|t| self.engine.core.created(t).cloned()).collect();
        let all = missing.len() == want.iter().filter(|t| !held.contains(t)).count();
        if missing.is_empty() {
            return Ok(all);
        }
        let Some(secret) = self.engine.wrap_secret(g, None)? else { return Ok(false) };
        let tids: Vec<Tid> = missing.iter().map(osis_base::CreationRecord::tid).collect::<BTreeSet<_>>().into_iter().collect();
        let plain = osis_commit::record_blob::encode_record_blob(&missing);
        let salt = osis_label::Prefix::random_salt(&mut *self.rng);
        let prefix = osis_label::Prefix::new(salt, None, Vec::new())?;
        let (key, blob) = osis_label::frame(&prefix, &plain, &mut *self.rng)?;
        let id = osis_label::blob_id(&blob);
        self.engine.put_blobs(vec![(id, blob)])?;
        let wrap = osis_crypto::wrap(&secret, &id, &key, 0)?;
        self.state.set_entry(l, id, Entry { wrap, stamp: None, cert: true, salt: Some(salt), expires: None, size: None, kind: Kind::Records(tids), memory: false });
        Ok(all)
    }

    /// Whether an entry under `l` carries commit `c`'s header (a body, a copy of any part of it,
    /// a header alone), counted as `held_parts_at` counts copies.
    pub(super) fn header_held_at(&mut self, l: LabelId, c: &CommitId, hosts: Option<&[HostKey]>) -> bool {
        let present: Vec<(BlobId, bool)> = self.state.entries_of(&l, c).filter(|(id, e)| matches!(e.kind, Kind::Commit { .. }) && (e.cert || hosts.is_none_or(|ss| !ss.is_empty() && ss.iter().all(|s| self.state.holds_at(s, &l, id))))).map(|(id, e)| (id, e.cert)).collect();
        present.into_iter().any(|(id, mine)| mine || self.genuine(&id))
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
        h.author == me && parts.iter().all(|ai| h.aspects.get(*ai).is_some_and(|a| a.tid == me && is_card(a.ak.as_str()))) && self.engine.account_tid().is_some_and(|account| self.engine.core.may_read(&account, &self.engine.group_actor(g)))
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
    /// that count): another node's copy or body counts once genuine and present where the
    /// label's entries count (`counted_at`), and, carrying a rotation of the label's actor, only
    /// if it opens under the newest read secret (spec/permissions.md §4). Not `held_at` (whether
    /// this node's own commit is placed).
    pub(super) fn held_parts(&mut self, g: &Tid, l: LabelId, c: &CommitId) -> Result<(Parts, Parts)> {
        let hosts = self.counted_at(g, l);
        self.held_parts_at(g, l, c, hosts.as_deref())
    }

    /// Where another node's entry under `l` counts as held: present at every host this node
    /// syncs the label with, or, for a label served with no host, in this node's own served
    /// state (`None`): this node is its host (`local_passes`), so what it places does not move
    /// with which peers happen to be connected.
    pub(super) fn counted_at(&mut self, g: &Tid, l: LabelId) -> Option<Vec<HostKey>> {
        if self.group_label(g, &l).is_some_and(|gl| crate::sync::peers::hostless(&gl.hosts)) {
            return None;
        }
        Some(self.conns.values().filter(|x| x.labels.contains_key(&l)).map(|x| x.host).collect())
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
        let Some(me) = self.engine.account_tid() else { return false };
        let a = self.keys_actor(g);
        crate::rotation::may_rotate(&self.engine.core, &me, &a).contains(&Role::Read)
    }
}

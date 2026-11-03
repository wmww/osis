//! Other nodes' writes (spec/sync.md §5, §6): a writer relays them and promotes deposits after a
//! wait, once the author's chain is under the label.

use super::*;

impl SyncEngine {
    /// Deposited commit entries at `host` a writer may promote now: past this node's wait
    /// (`RELAY_MIN_MS`: a co-writer may promote it first), not in flight, never a heartbeat.
    pub(super) fn due_entries(&mut self, conn: ConnId, host: HostKey, l: LabelId) -> Vec<(BlobId, Entry)> {
        let ids: Vec<(BlobId, Entry)> = self.state.deposited_at(&host, &l).into_iter().filter_map(|b| self.state.entries.get(&(l, b)).map(|e| (b, e.clone()))).collect();
        let raw = self.raw_now();
        self.deposit_seen.retain(|k, _| self.state.deposited.contains(k));
        let mut out = Vec::new();
        for (id, e) in ids {
            if self.conns.get(&conn).is_some_and(|c| crate::sync::in_flight(c, &c.req.sent, (l, id), raw)) {
                continue;
            }
            let seen = *self.deposit_seen.entry((host, l, id)).or_insert(raw);
            // by what it carries: a blob's ID is the luck of its sealing
            let due = seen.saturating_add(match &e.kind {
                Kind::Commit { commit, .. } => self.relay_delay(&commit.0),
                _ => self.relay_delay(&id.0),
            });
            if raw < due {
                self.settle_by(due, l);
                continue;
            }
            out.push((id, e));
        }
        out
    }

    /// The commit deposits among `due_entries`, but a heartbeat: due for promotion.
    pub(super) fn due_deposits(&mut self, conn: ConnId, host: HostKey, l: LabelId) -> Vec<Deposit> {
        let mut out = Vec::new();
        for (id, e) in self.due_entries(conn, host, l) {
            let Kind::Commit { commit, parts, .. } = &e.kind else { continue };
            let Some(h) = self.engine.header(commit) else { continue };
            if is_beat(&h) {
                continue;
            }
            let (commit, parts) = (*commit, parts.clone());
            out.push((id, e, commit, parts));
        }
        out
    }

    /// Whether entry `b` under `l`, deposited, is one a writer may yet promote: a commit, never a
    /// heartbeat (`due_deposits`).
    pub(super) fn promotable(&self, l: &LabelId, b: &BlobId) -> bool {
        match self.state.entries.get(&(*l, *b)).map(|e| &e.kind) {
            Some(Kind::Commit { commit, .. }) => !self.engine.header(commit).is_some_and(|h| is_beat(&h)),
            Some(Kind::Parked(_)) => true,
            _ => false,
        }
    }

    /// A promoter completes the chain it holds (spec/sync.md §5; spec/permissions.md §4): for
    /// each deposit due for promotion whose commit this writer applied, the parts of its
    /// author's chain no entry under `l` holds go up as this node's certificate copies, when it
    /// holds them all (else the deposit stays unpromoted).
    pub(super) fn complete_chains(&mut self, conn: ConnId, host: HostKey, g: &Tid, l: LabelId) -> Result<()> {
        for (_, _, c, parts) in self.due_deposits(conn, host, l) {
            self.complete_chain(Some(host), g, l, &c, &parts)?;
        }
        Ok(())
    }

    /// Places the parts of the author's chain for `parts` of `c` that no entry under `l` holds
    /// at `host` (`chain_missing`) as this node's certificate copies, when it holds them all.
    /// Returns whether the chain is complete under `l` now (`None` host: this node's served
    /// state, where a copy is in place once placed); `None` for a commit not applied here.
    pub(super) fn complete_chain(&mut self, host: Option<HostKey>, g: &Tid, l: LabelId, c: &CommitId, parts: &[(usize, usize)]) -> Result<Option<bool>> {
        let Some(missing) = self.chain_missing(host, g, l, c, parts)? else { return Ok(None) };
        if missing.is_empty() {
            return Ok(Some(true));
        }
        let mut bodies = Vec::new();
        for (x, p) in &missing {
            let bs = self.engine.part_bodies(x, p)?;
            let got: BTreeSet<(usize, usize)> = bs.iter().flat_map(|b| b.parts.iter().copied()).collect();
            if !p.is_subset(&got) {
                return Ok(Some(false));
            }
            bodies.push((*x, p.clone(), bs));
        }
        let mut complete = host.is_none();
        for (x, p, bs) in bodies {
            complete &= self.place_copy(g, l, &x, &p, bs)?;
        }
        Ok(Some(complete))
    }

    /// A writer serving `l` with no host promotes the deposits there as at a host
    /// (`complete_chains`, `promote`; spec/sync.md §5): another node's deposited commit it
    /// applied, past the relay wait since it arrived (a co-writer or the author may place the
    /// chain first), never a heartbeat, gets the missing parts of its author's chain placed as
    /// this node's certificate copies, then its stamp; one whose chain it cannot complete
    /// stays a deposit and is judged again next pass (one not applied yet, once applied). Of
    /// the entries `scope` names, but `ours` (this pass's placements).
    pub(super) fn local_promote(&mut self, g: &Tid, l: LabelId, write: &osis_crypto::SigningSecret, scope: &Scope, ours: &BTreeSet<BlobId>, left: &mut Left) -> Result<()> {
        for id in self.scope_entries(&l, scope).difference(ours).copied().collect::<Vec<_>>() {
            let Some(e) = self.state.entries.get(&(l, id)).cloned() else { continue };
            let Kind::Commit { commit, parts, .. } = &e.kind else { continue };
            let (commit, parts) = (*commit, parts.clone());
            if e.stamp.is_some() || e.cert || self.own(&commit) || self.engine.header(&commit).is_none_or(|h| is_beat(&h)) {
                continue;
            }
            if let Some(t) = self.relay_at(l, &commit) {
                left.at(t, Touch::Commit(commit));
                continue;
            }
            match self.complete_chain(None, g, l, &commit, &parts)? {
                Some(true) => {}
                Some(false) => {
                    left.commits.insert(commit);
                    continue;
                }
                None => continue,
            }
            self.stamp_entry(l, id, e, write);
        }
        Ok(())
    }

    /// A writer re-uploads stamped the deposited entries it verified (spec/sync.md §5): applied
    /// commits whose author's chain is under the label (`complete_chains` placed what it held
    /// of it), never a heartbeat; per host (a blob may be deposited at several).
    pub(super) fn promote(&mut self, conn: ConnId, host: HostKey, g: &Tid, l: LabelId, write: &osis_crypto::SigningSecret, uploads: &mut Vec<osis_proto::Entry>) -> Result<()> {
        for (id, e, c, parts) in self.due_deposits(conn, host, l) {
            if uploads.iter().any(|u| osis_label::blob_id(&u.blob) == id) || !self.chain_missing(Some(host), g, l, &c, &parts)?.is_some_and(|m| m.is_empty()) {
                continue;
            }
            let Some(blob) = self.engine.blob(&id)? else { continue };
            uploads.push(self.stamped_upload(l, id, e, blob, write));
            // still deposited there until the host takes the stamped upload (a refusal, say a
            // step registered meanwhile, leaves it for the next pass)
        }
        Ok(())
    }

    /// The author's chain `parts` of commit `c` need under a label (`Engine::author_chain`), less
    /// every `keys.0` but the author's own (its card, spec/permissions.md §4): a verifier judges
    /// a commit by creation records and edge writes alone (`apply::examine`, `validity`), and a
    /// holder reads a thing's keys where its bodies are. Any other keyset is often not for the
    /// label's readers (a removal's fresh deposit seed, spec/sync.md §3), a copier that took the
    /// commit from an inbox blob may not hold it, and it moves at every rotation of anyone on the
    /// way: every copy would owe it for good.
    pub(crate) fn chain_under(&mut self, c: &CommitId, parts: &Parts) -> Option<BTreeMap<CommitId, Parts>> {
        let mut chain = self.engine.author_chain(c, parts)?;
        let author = self.engine.header(c)?.author;
        for (x, q) in chain.iter_mut() {
            let Some(hx) = self.engine.header(x) else { continue };
            q.retain(|(ai, _)| hx.aspects.get(*ai).is_none_or(|a| a.ak.as_str() != "keys.0" || a.tid == author));
        }
        chain.retain(|_, q| !q.is_empty());
        Some(chain)
    }

    /// The parts of the author's chain for `parts` of commit `c` (`chain_under`) that
    /// no entry under `l` holds at `host` (`held_parts_at`: the promotion or deletion is
    /// that host's; `None`: this node's served state); `None` when this node has not applied
    /// `c`.
    pub(super) fn chain_missing(&mut self, host: Option<HostKey>, g: &Tid, l: LabelId, c: &CommitId, parts: &[(usize, usize)]) -> Result<Option<BTreeMap<CommitId, Parts>>> {
        let Some(chain) = self.chain_under(c, &parts.iter().copied().collect()) else { return Ok(None) };
        let closure = self.engine.closure(g);
        let mut out = BTreeMap::new();
        for (x, want) in chain {
            let (_, held) = self.held_parts_at(g, l, &x, host.as_ref().map(std::slice::from_ref))?;
            // closure bodies carry what is on the label's own things
            let inside = self.engine.header(&x).map(|h| inside(&h, &closure)).unwrap_or_default();
            let missing: Parts = want.difference(&held).filter(|(ai, _)| !inside.contains(ai)).copied().collect();
            if !missing.is_empty() {
                out.insert(x, missing);
            }
        }
        Ok(Some(out))
    }

    /// This node's wait before relaying another node's blob, named by `key` (`RELAY_MIN_MS` to
    /// `SETTLE_MS`, fixed per node and blob, so co-writers draw different points).
    pub(super) fn relay_delay(&self, key: &[u8]) -> u64 {
        let mut h = osis_base::hash::Hasher::new();
        h.update(b"osis relay wait").update(self.engine.tid().as_bytes()).update(key);
        let mut x = [0u8; 8];
        h.finalize_xof(&mut x);
        RELAY_MIN_MS + u64::from_le_bytes(x) % (SETTLE_MS - RELAY_MIN_MS)
    }

    /// When this node uploads or relays commit `c` at a host lacking it (corrected wall ms; a wake
    /// is set for then), `None` for now: its own (made here, a held key actor's included, or placed
    /// first by a flow) at once, another node's once `relay_delay` has passed since it arrived here.
    pub(super) fn relay_at(&mut self, l: LabelId, c: &CommitId) -> Option<u64> {
        let me = self.engine.tid();
        let m = self.engine.core.ix.commits.get(c)?;
        if m.origin == crate::events::Origin::Local || m.header.author == me || self.first.contains(c) {
            return None;
        }
        let due = m.received.0.saturating_add(self.relay_delay(&c.0));
        let now = self.now();
        if now >= due {
            return None;
        }
        let at = self.raw_now().saturating_add(due - now);
        self.settle_by(at, l);
        Some(due)
    }
}

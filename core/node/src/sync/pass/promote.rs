//! Other nodes' writes (spec/sync.md §5, §6): a writer relays them and promotes deposits after a
//! wait, once the author's chain is under the label; an admin clears deposits waiting for nothing.

use super::*;

impl SyncEngine {
    /// Deposited commit entries at `host` a writer may promote now: past this node's wait
    /// (`RELAY_MIN_MS`: a co-writer may promote it first), not in flight.
    pub(super) fn due_entries(&mut self, conn: ConnId, host: HostKey, l: LabelId) -> Vec<(BlobId, Entry)> {
        let ids: Vec<(BlobId, Entry)> = self.state.deposited_at(&host, &l).into_iter().filter_map(|b| self.state.entries.get(&(l, b)).map(|e| (b, e.clone()))).collect();
        let now = self.now();
        self.deposit_seen.retain(|k, _| self.state.deposited.contains(k));
        let mut out = Vec::new();
        for (id, e) in ids {
            if self.conns.get(&conn).is_some_and(|c| crate::sync::in_flight(c, &c.req.sent, (l, id), now)) {
                continue;
            }
            let seen = *self.deposit_seen.entry((host, l, id)).or_insert(now);
            // by what it carries: a blob's ID is the luck of its sealing
            let due = seen.saturating_add(match &e.kind {
                Kind::Commit { commit, .. } => self.relay_delay(&commit.0),
                _ => self.relay_delay(&id.0),
            });
            if now < due {
                self.settle_by(due, l);
                continue;
            }
            out.push((id, e));
        }
        out
    }

    /// The commit deposits among `due_entries` this writer would promote (`would_promote`).
    pub(super) fn due_deposits(&mut self, conn: ConnId, host: HostKey, g: &Tid, l: LabelId) -> Result<Vec<Deposit>> {
        let mut out = Vec::new();
        for (id, e) in self.due_entries(conn, host, l) {
            let Kind::Commit { commit, parts, .. } = &e.kind else { continue };
            let (commit, parts) = (*commit, parts.clone());
            if self.would_promote(g, l, Some(&host), &id)? {
                out.push((id, e, commit, parts));
            }
        }
        Ok(out)
    }

    /// Whether deposited entry `b` under `l` (of `g`) at `host` is one a writer may yet promote:
    /// a commit it would promote (`would_promote`), or one parked.
    pub(super) fn promotable(&mut self, g: &Tid, l: LabelId, host: &HostKey, b: &BlobId) -> Result<bool> {
        match self.state.entries.get(&(l, *b)).map(|e| &e.kind) {
            Some(Kind::Parked(_)) => Ok(true),
            Some(Kind::Commit { .. }) => self.would_promote(g, l, Some(host), b),
            _ => Ok(false),
        }
    }

    /// Whether this writer promotes deposited entry `id` under `l` (of `g`) at `host` (`None`:
    /// its served state; spec/sync.md §5 Promotion): a commit it applied with a valid part the
    /// label must hold that no stamped copy there holds yet (`stamped_parts`). By part, not
    /// `judged_valid`: a single-use race loser's role commit holds a void grant beside the valid
    /// removal of its link key the label needs. One copy per commit and part, however many
    /// encryptions are deposited; duplicates and what the label does not need wait for
    /// clearing. A part the label must hold: one on a thing of its closure (its bodies: the
    /// deletion judgment goes on from there), or a role commit's part writing or boxing an edge
    /// of a closure thing (a grant to the label's actor, a removal of it:
    /// `Engine::holders_named`), or a key actor's newest card (each aspect's newest valid write
    /// by itself). Never another chain certificate on its own (a role commit or creation outside
    /// the closure, a superseded card): it goes in the author's chain of a commit the label must
    /// hold, which the promoter places itself (`complete_chain`), so a deposited one is a
    /// duplicate; else anything on an authority path into the label (a reader's own account,
    /// edges it writes there) would be stamped for good.
    pub(super) fn would_promote(&mut self, g: &Tid, l: LabelId, host: Option<&HostKey>, id: &BlobId) -> Result<bool> {
        let Some(Entry { kind: Kind::Commit { commit, parts, .. }, cert: false, .. }) = self.state.entries.get(&(l, *id)).cloned() else { return Ok(false) };
        let Some(valid) = self.engine.valid_parts(&commit) else { return Ok(false) };
        let Some(h) = self.engine.header(&commit) else { return Ok(false) };
        let closure = self.engine.closure(g);
        let named = if h.kind.is_role() { self.engine.holders_named(&commit) } else { Default::default() };
        let mut need = Vec::new();
        for ai in parts.iter().filter(|ai| valid.contains(ai)) {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let about = named.get(ai).is_some_and(|hs| hs.iter().any(|x| closure.contains(x)));
            // a key actor's newest card, which no chain carries but its `keys.0` (spec/sync.md
            // §3: co-readers dial a node by its `reach.0`): one per aspect, its rewrites not
            let card = is_card(a.ak.as_str()) && a.tid == h.author && self.engine.latest_by(&a.tid, a.ak.as_str(), Some(&h.author)) == Some(commit);
            if closure.contains(&a.tid) || about || card {
                need.push(*ai);
            }
        }
        if need.is_empty() {
            return Ok(false);
        }
        let held = self.stamped_parts(g, l, &commit, host, id)?;
        Ok(need.iter().any(|ai| !held.contains(ai)))
    }

    /// The parts of commit `c` that entries under `l` other than `except` hold stamped at `host`
    /// (`None`: this node's served state): this node's certificate copies, and another genuine
    /// entry there that the host holds stamped or this node stamped (a promotion on its way); a
    /// rotation of the label's actor only opening under the newest read secret (`held_parts_at`).
    fn stamped_parts(&mut self, g: &Tid, l: LabelId, c: &CommitId, host: Option<&HostKey>, except: &BlobId) -> Result<Parts> {
        let newest = self.engine.wrap_secret(g, None)?;
        let mut held = Parts::new();
        let mut others: Vec<(BlobId, Vec<usize>)> = Vec::new();
        for (id, e) in self.state.entries_of(&l, c) {
            let Kind::Commit { parts, .. } = &e.kind else { continue };
            if id == *except {
                continue;
            }
            if e.cert {
                held.extend(parts.iter().copied());
                continue;
            }
            let stamped = match host {
                Some(s) => self.state.holds_at(s, &l, &id) && (e.stamp.is_some() || !self.state.deposited.contains(&(*s, l, id))),
                None => e.stamp.is_some(),
            };
            if stamped && (!self.engine.carries_secrets(g, c, parts) || newest.as_ref().is_some_and(|k| osis_crypto::unwrap(k, &id, &e.wrap).is_ok())) {
                others.push((id, parts.clone()));
            }
        }
        for (id, parts) in others {
            if self.genuine(&id) {
                held.extend(parts);
            }
        }
        Ok(held)
    }

    /// A promoter completes the chain it holds (spec/sync.md §5; spec/permissions.md §4): for
    /// each deposit due for promotion whose commit this writer applied, the parts of its
    /// author's chain no entry under `l` holds go up as this node's certificate copies, when it
    /// holds them all (else the deposit stays unpromoted).
    pub(super) fn complete_chains(&mut self, conn: ConnId, host: HostKey, g: &Tid, l: LabelId) -> Result<()> {
        for (_, _, c, parts) in self.due_deposits(conn, host, g, l)? {
            self.complete_chain(Some(host), g, l, &c, &parts)?;
        }
        Ok(())
    }

    /// Places the parts of the author's chain for `parts` of `c` that no entry under `l` holds
    /// at `host` (`chain_missing`) as this node's certificate copies, when it holds them all.
    /// Returns whether the chain is complete under `l` now (`None` host: this node's served
    /// state, where a copy is in place once placed); `None` for a commit not applied here.
    pub(super) fn complete_chain(&mut self, host: Option<HostKey>, g: &Tid, l: LabelId, c: &CommitId, parts: &[usize]) -> Result<Option<bool>> {
        let Some(missing) = self.chain_missing(host, g, l, c, parts)? else { return Ok(None) };
        if missing.is_empty() {
            return Ok(Some(true));
        }
        let mut bodies = Vec::new();
        for (x, p) in &missing.commits {
            let Some(b) = self.engine.part_body(x, p)? else { return Ok(Some(false)) };
            let got: BTreeSet<usize> = b.parts.iter().copied().collect();
            if !p.is_subset(&got) {
                return Ok(Some(false));
            }
            bodies.push((*x, p.clone(), b));
        }
        if missing.records.iter().any(|t| self.engine.core.created(t).is_none()) {
            return Ok(Some(false));
        }
        let mut complete = host.is_none();
        for (x, p, b) in bodies {
            complete &= self.place_copy(g, l, &x, &p, b)?;
        }
        for x in &missing.headers {
            let Some(b) = self.engine.header_body(x) else { return Ok(Some(false)) };
            complete &= self.place_copy(g, l, x, &Parts::new(), b)?;
        }
        if !missing.records.is_empty() {
            complete &= self.place_records(g, l, &missing.records, true)? && host.is_none();
        }
        Ok(Some(complete))
    }

    /// A writer serving `l` with no host promotes the deposits there as at a host
    /// (`complete_chains`, `promote`; spec/sync.md §5): another node's deposited commit it
    /// applied, past the relay wait since it arrived (a co-writer or the author may place the
    /// chain first), gets the missing parts of its author's chain placed as
    /// this node's certificate copies, then its stamp; one whose chain it cannot complete
    /// stays a deposit and is judged again next pass (one not applied yet, once applied). Of
    /// the entries `scope` names, but `ours` (this pass's placements).
    pub(super) fn local_promote(&mut self, g: &Tid, l: LabelId, write: &osis_crypto::SigningSecret, scope: &Scope, ours: &BTreeSet<BlobId>, left: &mut Left) -> Result<()> {
        for id in self.scope_entries(&l, scope).difference(ours).copied().collect::<Vec<_>>() {
            let Some(e) = self.state.entries.get(&(l, id)).cloned() else { continue };
            let Kind::Commit { commit, parts, .. } = &e.kind else { continue };
            let (commit, parts) = (*commit, parts.clone());
            if e.stamp.is_some() || e.cert || self.own(&commit) || !self.would_promote(g, l, None, &id)? {
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

    /// An admin keeps at most `DEPOSITS_WAITING` entries and bytes of the deposits at a host it can
    /// do nothing with, under any label (spec/sync.md §5, Clearing deposits): every one but a
    /// commit it judges valid (the judgment a reader deposits by: a writer promotes it), an inbox
    /// blob it stamps, and an inbox blob still waiting to apply. A deposit whose bytes never
    /// reached it is not judged yet. Over that, it deletes all but invite requests first, those
    /// expiring too far ahead or never before the rest, then the requests earliest to expire, so
    /// a reader's or stranger's fill ends with this pass, what does not open never costs a user an
    /// invite, and the rest of the budget stays free. A request goes only past `DEPOSITS_WAITING`
    /// of them. Counted by size, not bytes held: this node drops the bytes of what it judged
    /// invalid or cannot open.
    pub(super) fn clear_deposits(&mut self, conn: ConnId, host: HostKey, p: &Head, out: &mut Vec<crate::sync::Action>) -> Result<()> {
        let (l, keys) = (p.l, &p.keys);
        if keys.delete.is_none() {
            return Ok(());
        }
        let deposited = self.state.deposited_at(&host, &l);
        if deposited.is_empty() {
            return Ok(());
        }
        let latest = self.inbox_latest();
        let mut waiting = Vec::new();
        for id in deposited {
            let Some((kind, Some(size))) = self.state.entries.get(&(l, id)).map(|e| (e.kind.clone(), e.size)) else { continue };
            let idle = match &kind {
                Kind::Commit { .. } => !self.would_promote(&p.g, l, Some(&host), &id)?,
                Kind::Inbox(Some(c)) => {
                    // unapplied: it waits, as its inbox bytes do, until its turn past `latest`
                    let pending = !self.engine.core.ix.commits.contains_key(c) && self.inbox_opened(&l, &id)?.is_some_and(|o| o.until <= latest);
                    !pending && !self.inbox_stampable(&l, &id, c)?
                }
                _ => true,
            };
            if !idle {
                continue;
            }
            let until = self.engine.blob(&id)?.and_then(|b| osis_label::Prefix::parse(&b).ok().and_then(|x| x.expiry())).map_or(u64::MAX, |w| w.0);
            let near = until <= latest;
            waiting.push((near && matches!(kind, Kind::Request(_)), near, until, id, size as usize));
        }
        let over = |w: &[(bool, bool, u64, BlobId, usize)]| w.len() > osis_base::format::DEPOSITS_WAITING || w.iter().map(|x| x.4).sum::<usize>() > osis_base::format::DEPOSITS_WAITING_BYTES;
        if !over(&waiting) {
            return Ok(());
        }
        waiting.sort();
        waiting.reverse();
        let now = self.now();
        let mut items = Vec::new();
        while over(&waiting) {
            let Some((_, _, _, id, _)) = waiting.pop() else { break };
            let Some(c) = self.conns.get_mut(&conn) else { break };
            if crate::sync::in_flight(c, &c.req.deleting, (l, id), now) {
                continue;
            }
            if let Some(item) = delete_item(keys, &l, id, None, &[], true) {
                c.req.deleting.insert((l, id), (now, crate::sync::UNTAGGED));
                items.push(item);
            }
        }
        if !items.is_empty() {
            self.command(conn, Command::Delete { label: l, items }, out)?;
        }
        Ok(())
    }

    /// A writer re-uploads stamped the deposited entries it verified (spec/sync.md §5): applied
    /// commits whose author's chain is under the label (`complete_chains` placed what it held
    /// of it); per host (a blob may be deposited at several).
    pub(super) fn promote(&mut self, conn: ConnId, host: HostKey, g: &Tid, l: LabelId, write: &osis_crypto::SigningSecret, uploads: &mut Vec<osis_proto::Entry>) -> Result<()> {
        for (id, e, c, parts) in self.due_deposits(conn, host, g, l)? {
            // one promoted just now may hold its parts already (`stamp_entry`)
            if uploads.iter().any(|u| osis_label::blob_id(&u.blob) == id) || !self.would_promote(g, l, Some(&host), &id)? || !self.chain_missing(Some(host), g, l, &c, &parts)?.is_some_and(|m| m.is_empty()) {
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
    pub(crate) fn chain_under(&mut self, c: &CommitId, parts: &Parts) -> Option<crate::labeling::Certs> {
        let mut chain = self.engine.author_chain(c, parts)?;
        let author = self.engine.header(c)?.author;
        for (x, q) in chain.commits.iter_mut() {
            let Some(hx) = self.engine.header(x) else { continue };
            q.retain(|ai| hx.aspects.get(*ai).is_none_or(|a| a.ak.as_str() != "keys.0" || a.tid == author));
        }
        chain.commits.retain(|_, q| !q.is_empty());
        Some(chain)
    }

    /// The parts of the author's chain for `parts` of commit `c` (`chain_under`) that
    /// no entry under `l` holds at `host` (`held_parts_at`: the promotion or deletion is
    /// that host's; `None`: this node's served state); `None` when this node has not applied
    /// `c`.
    pub(super) fn chain_missing(&mut self, host: Option<HostKey>, g: &Tid, l: LabelId, c: &CommitId, parts: &[usize]) -> Result<Option<crate::labeling::Certs>> {
        let Some(chain) = self.chain_under(c, &parts.iter().copied().collect()) else { return Ok(None) };
        let closure = self.engine.closure(g);
        let mut out = crate::labeling::Certs::default();
        // records travel raw, also those of the label's own things: a creation's body goes when
        // its thing ends, and what depends on it lives on (spec/permissions.md §4)
        let held = self.held_records_at(l, host.as_ref().map(std::slice::from_ref), true);
        out.records = chain.records.difference(&held).copied().collect();
        for (x, want) in chain.commits {
            let (_, held) = self.held_parts_at(g, l, &x, host.as_ref().map(std::slice::from_ref))?;
            // closure bodies carry what is on the label's own things
            let inside = self.engine.header(&x).map(|h| inside(&h, &closure)).unwrap_or_default();
            let missing: Parts = want.difference(&held).filter(|ai| !inside.contains(ai)).copied().collect();
            if !missing.is_empty() {
                out.commits.insert(x, missing);
            }
        }
        for x in chain.headers {
            if !self.header_held_at(l, &x, host.as_ref().map(std::slice::from_ref)) {
                out.headers.insert(x);
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

    /// When this node uploads or relays commit `c` at a host lacking it (wall ms; a wake
    /// is set for then), `None` for now: its own (made here, a held key actor's included, or placed
    /// first by a flow) at once, another node's once `relay_delay` has passed since it arrived here.
    pub(super) fn relay_at(&mut self, l: LabelId, c: &CommitId) -> Option<u64> {
        let m = self.engine.core.ix.commits.get(c)?;
        if m.origin == crate::events::Origin::Local || self.first.contains(c) {
            return None;
        }
        let due = m.received.0.saturating_add(self.relay_delay(&c.0));
        if self.now() >= due {
            return None;
        }
        self.settle_by(due, l);
        Some(due)
    }
}

//! A new step of a label (spec/sync.md §5): when one is due, and registering it at a host.

use super::*;

impl SyncEngine {
    /// Whether this node may issue a new step for a label of `g` now: another node's rotation
    /// of the actor (a `secrets.0` write) received less than `SETTLE_MS` ago is its author's to
    /// register first (a second admin's step, issued before the author's reaches it, would be a
    /// sibling); a wake brings the pass back then. Other role writes (an admin recording
    /// a step in `label.0`, a `keys.0` update) get no step from their author and delay nothing.
    pub(super) fn step_settled(&mut self, g: &Tid, l: LabelId) -> bool {
        let a = self.keys_actor(g);
        let Some(t) = self.rotation_at.get(&a).map(|t| t.saturating_add(SETTLE_MS)) else { return true };
        if t <= self.raw_now() {
            return true;
        }
        self.settle_by(t, l);
        false
    }

    /// Whether this admin re-registers `l` of `g` before anything else (spec/sync.md §5): it
    /// holds, established, the head's epochs (`keys`) and a newer one, or the head's deposit key
    /// is not the one the actor's deposit seed derives (refreshed) and nothing under `l` that
    /// could carry a newer seed waits to be opened or applied (`keys_caught_up`: else a lagging
    /// admin would register its older seed back); a replaced label never.
    pub(super) fn step_due(&mut self, g: &Tid, l: &LabelId, keys: &HeadKeys) -> bool {
        if keys.delete.is_none() || keys.write.is_none() || self.is_replaced(g, l) {
            return false;
        }
        if self.engine.epochs(g).is_some_and(|e| osis_keys::newer_than_head(&e, keys.epochs)) {
            return true;
        }
        keys.deposit.is_none() && self.engine.deposit_seed(g).is_ok_and(|s| s.is_some()) && self.keys_caught_up(g, l)
    }

    /// No entry under `l` this node can open, present at a host it is connected to that has
    /// not said it lacks it, is unopened (in flight, or not fetched), and no pending commit by an
    /// admin writes the actor's `keys.0` (`Engine::keys_write_pending`). Entries only a host out
    /// of reach lists do not count: one that never comes back would hold the step back for good.
    pub(super) fn keys_caught_up(&mut self, g: &Tid, l: &LabelId) -> bool {
        let secrets = self.read_secrets(g);
        let fetchable: BTreeSet<BlobId> = self.conns.values().filter(|c| c.up).flat_map(|c| self.state.present_at(&c.host, l).into_iter().filter(|b| !c.req.missing.contains(b))).collect();
        let unopened = fetchable.into_iter().any(|b| self.state.entries.get(&(*l, b)).is_some_and(|e| e.unopened(&b, &secrets)));
        if unopened {
            return false;
        }
        let a = self.keys_actor(g);
        !self.engine.keys_write_pending(&a).unwrap_or(true)
    }

    /// Re-registration (spec/sync.md §5): an admin holding the head's epochs and a newer
    /// established one uploads the actor's role commits the host lacks under the head's
    /// keys, then registers a child step; the rest of the pass runs once it is registered, or
    /// under the host's head while the step is refused for now. True while the step is in flight.
    pub(super) fn reregister(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<crate::sync::Action>) -> Result<bool> {
        let Some(c) = self.conns.get(&conn) else { return Ok(false) };
        let host = c.host;
        let Some(lc) = c.labels.get(&l) else { return Ok(false) };
        let (g, keys, head, retry) = (lc.group, lc.keys.clone(), lc.head.clone(), lc.step_retry);
        // a replaced label is never stepped again (spec/sync.md §2: its replacement carries on)
        if !self.step_due(&g, &l, &keys) {
            return Ok(false);
        }
        // a step refused for now goes again only after its back-off; meanwhile the pass runs
        // under the host's head: what it uploads is wrapped under the newest read epoch, so a
        // removed holder still opening that head gets nothing it can read (spec/sync.md §5)
        if retry > self.raw_now() {
            return Ok(false);
        }
        let (Some(write), Some(head)) = (keys.write.clone(), head) else { return Ok(false) };
        let a = self.keys_actor(&g);
        let core = &self.engine.core;
        let ids: Vec<CommitId> = core.on_thing(&a).filter(|c| core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_role())).collect();
        let mut uploads = Vec::new();
        let ctx = self.engine.body_ctx(&g);
        for id in ids {
            let Some(mut b) = self.engine.body(&id)? else { continue };
            b.parts = self.engine.readable_parts(&ctx, &id, &b.parts);
            b.plaintext = Vec::new();
            if b.parts.is_empty() {
                continue;
            }
            {
                let bid = match self.entry_for(Some(&host), &l, &b) {
                    Some(x) => x,
                    None => match self.place(&g, l, &b, false)? {
                        Some(x) => x,
                        None => continue,
                    },
                };
                if self.state.is_present(&host, &l, &bid) {
                    continue;
                }
                let (Some(en), Some(blob)) = (self.state.entries.get(&(l, bid)).cloned(), self.engine.blob(&bid)?) else { continue };
                let stamp = osis_label::sign_stamp(&write, &l, &bid, &en.wrap);
                uploads.push(osis_proto::Entry { blob, wrap: en.wrap, stamp, replaces: Vec::new() });
            }
        }
        if !uploads.is_empty() {
            self.command(conn, Command::Upload { label: l, entries: uploads }, out)?;
        }
        // a child of the host's head already recorded in `label.0` (this node's local step,
        // another admin's) is registered first: the walk down the recorded path issues nothing
        let (step, set) = match self.recorded_child(&g, &l, &head.id()) {
            Some(x) => x,
            None => {
                if !self.step_settled(&g, l) {
                    return Ok(false);
                }
                let (step, done) = self.engine.issue_step(&g, &l, &head.id(), false)?;
                self.take_done(done)?;
                let Some(x) = step else { return Ok(false) };
                x
            }
        };
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.registering = Some((step.clone(), set.clone()));
        }
        self.command(conn, Command::Register { label: l, step, claim_set: Some(set) }, out)?;
        Ok(true)
    }

    /// A child of step `head` recorded in `label.0` with its claim set (the lowest ID among
    /// several).
    pub(super) fn recorded_child(&mut self, g: &Tid, l: &LabelId, head: &osis_label::StepId) -> Option<(osis_label::Step, osis_label::ClaimSet)> {
        let gl = self.group_label(g, l)?;
        gl.steps.values().filter_map(|(s, c)| c.clone().map(|c| (s.clone(), c))).filter(|(s, _)| s.prev == Some(*head)).min_by_key(|(s, _)| s.id())
    }
}

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
        if t <= self.now() {
            return true;
        }
        self.settle_by(t, l);
        false
    }

    /// Whether this admin re-registers `l` of `g` before anything else (spec/sync.md §5): it
    /// holds, established, the head's epochs (`keys`) and a newer one, or the head's deposit key
    /// is not the one the actor's deposit seed derives (refreshed) and nothing under `l` that
    /// could carry a newer seed waits to be opened or applied (`keys_caught_up`: else a lagging
    /// admin would register its older seed back). Only under `head`
    /// recorded in `label.0`: a step a peer named alone (an open with no head) may be forged.
    pub(super) fn step_due(&mut self, g: &Tid, l: &LabelId, head: &osis_label::StepId, keys: &HeadKeys) -> bool {
        if keys.delete.is_none() || keys.write.is_none() || !self.group_label(g, l).is_some_and(|gl| gl.steps.contains_key(head)) {
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

    /// Registration at a source (spec/sync.md §5, Register): a source on a step of the recorded
    /// path below its newest gets the recorded child of its head, by any reader holding the path
    /// (steps verify themselves); an admin holding the source head's epochs and a newer
    /// established one issues a child of it once `step_settled` (re-registration; the actor's role
    /// commits are in this node's store, which the source pulls). The rest of the pass there runs
    /// once it is registered, or under the source's head while the step waits or is refused for
    /// now. True while a step is in flight.
    pub(super) fn reregister(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<crate::sync::Action>) -> Result<bool> {
        let Some(lc) = self.lc(conn, &l) else { return Ok(false) };
        let (g, keys, head, retry) = (lc.group, lc.keys.clone(), lc.head.clone(), lc.step_retry);
        // a step refused for now goes again only after its back-off; meanwhile the pass runs
        // under the source's head: what it places is wrapped under the newest read epoch, so a
        // removed holder still opening that head gets nothing it can read (spec/sync.md §5)
        let Some(head) = head else { return Ok(false) };
        // a head the peer refused a child of is not where the peer is: nothing goes under it
        if retry > self.now() || self.doubting(conn, &l) {
            return Ok(false);
        }
        let (step, set) = match self.recorded_child(&g, &l, &head.id()) {
            Some(x) => x,
            None => {
                if !self.step_due(&g, &l, &head.id(), &keys) || !self.step_settled(&g, l) {
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
        self.request(conn, |id| osis_proto::Message::Register { id, label: l, step, claim_set: Some(set) }, crate::sync::conn::Pending::Register(l), out);
        Ok(true)
    }

    /// A child of step `head` recorded in `label.0` with its claim set (the lowest ID among
    /// several).
    pub(super) fn recorded_child(&mut self, g: &Tid, l: &LabelId, head: &osis_label::StepId) -> Option<(osis_label::Step, osis_label::ClaimSet)> {
        let gl = self.group_label(g, l)?;
        gl.steps.values().filter_map(|(s, c)| c.clone().map(|c| (s.clone(), c))).filter(|(s, _)| s.prev == Some(*head)).min_by_key(|(s, _)| s.id())
    }
}

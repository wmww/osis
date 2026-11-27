//! What sync signs entries with and what a step waits on (spec/sync-inbox.md §2-§4,
//! spec/sync-ids.md §6 Steps): the role keys of a sync ID's head held here, the sync IDs a
//! delivery names, and the role commits a step waits on.

use super::Signers;
use crate::engine::Engine;
use crate::error::Result;
use osis_base::{CommitId, Role, SyncId, Tid};
use osis_base::memo::Memo;
use osis_blob::{Step, StepId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

impl Engine {
    /// The keys this node signs entries of `s` with: its head's write and delete keys where
    /// established here, and its deposit key (from `actor`'s deposit seed when given: another
    /// actor's inbox, whose head this node need not record; else from the head's).
    pub fn signers(&mut self, s: &SyncId, actor: Option<&Tid>) -> Result<Signers> {
        let mut out = Signers::default();
        if let Some((t, o)) = self.recorded_owner(s)?
            && let Some(head) = o.path.steps.last()
        {
            let k = self.head_keys(&t, head)?;
            out.stamp = k.write;
            out.delete = k.delete;
            out.deposit = k.deposit;
        }
        if out.deposit.is_none()
            && let Some(a) = actor
            && let Some(seed) = self.deposit_seed(a)?
        {
            out.deposit = Some(osis_crypto::deposit_key(&seed, s));
        }
        Ok(out)
    }

    /// The role commits of `s`'s thing that recorded step `step` waits on (spec/sync-ids.md §6
    /// Steps), each waited on by one step (`steps_needs`). Empty for a step this node does not
    /// record.
    pub fn step_needs(&mut self, s: &SyncId, step: &StepId) -> Result<Arc<Vec<CommitId>>> {
        Ok(self.steps_needs(s)?.by_step.get(step).cloned().unwrap_or_default())
    }

    /// The parent of the recorded step of `s` waiting on role commit `c` (`step_needs`): entries
    /// of `c` are stamped under it.
    pub fn step_parent(&mut self, s: &SyncId, c: &CommitId) -> Result<Option<Step>> {
        Ok(self.steps_needs(s)?.parent.get(c).cloned())
    }

    /// `step_needs` of every recorded step of `s`, and its inverse (`memo`): built once per move
    /// of the path or the epochs it reads, then O(log) per step or commit asked.
    fn steps_needs(&mut self, s: &SyncId) -> Result<Arc<StepsNeeds>> {
        Memo::get_in(self, |e| &e.core.steps_needs, s, |e| e.steps_needs_derived(s))
    }

    /// Per recorded step, the held rotations of the epochs it registers and of those they
    /// supersede, but those an earlier step waits on. A role's epoch is the one whose key the
    /// step carries; where no secret held here tells (a reader registering a write or delete
    /// key), the rotations of the role's current epochs here, at the step that brought the role's
    /// newest key on the path alone.
    fn steps_needs_derived(&mut self, s: &SyncId) -> Result<Arc<StepsNeeds>> {
        let mut out = StepsNeeds::default();
        let Some((t, o)) = self.recorded_owner(s)? else { return Ok(Arc::default()) };
        let Some(ep) = self.epochs(&t) else { return Ok(Arc::default()) };
        let key = |st: &Step, r: usize| match r {
            0 => st.keys.sync.to_bytes(),
            1 => st.keys.write.to_bytes(),
            _ => st.keys.delete.to_bytes(),
        };
        // per role, the step that brought the newest step's key
        let mut brought = [0usize; 3];
        if let Some(last) = o.path.steps.last() {
            for (r, b) in brought.iter_mut().enumerate() {
                *b = o.path.steps.iter().rposition(|st| key(st, r) != key(last, r)).map_or(0, |i| i + 1);
            }
        }
        let mut seen = BTreeSet::new();
        let mut parent: Option<&Step> = None;
        for (i, st) in o.path.steps.iter().enumerate() {
            let needs: Vec<CommitId> = self.needs_of(&t, &ep, st, brought.map(|b| b == i))?.difference(&seen).copied().collect();
            seen.extend(needs.iter().copied());
            if let Some(p) = parent {
                for c in &needs {
                    out.parent.insert(*c, p.clone());
                }
            }
            out.by_step.insert(st.id(), Arc::new(needs));
            parent = Some(st);
        }
        Ok(Arc::new(out))
    }

    /// The held rotations of the epochs step `st` of a sync ID of `t` registers and of those they
    /// supersede (`steps_needs`, before what earlier steps wait on); `brought`, per role: `st`
    /// brought the role's newest key, so where no secret held tells its epoch, the role's
    /// current epochs are its.
    fn needs_of(&mut self, t: &Tid, ep: &osis_keys::ActorEpochs, st: &Step, brought: [bool; 3]) -> Result<BTreeSet<CommitId>> {
        let k = self.head_keys(t, st)?;
        let mut out = BTreeSet::new();
        for ((r, e), brought) in [Role::Sync, Role::Write, Role::Admin].into_iter().zip(k.epochs).zip(brought) {
            let re = ep.role(r);
            // the role's current epochs, their own rotations alone: what they supersede was
            // brought by a step this node cannot tell
            let (epochs, superseded) = match e {
                Some(e) => (vec![e], true),
                None if brought => (re.current(), false),
                None => continue,
            };
            for e in epochs {
                let Some(info) = re.get(&e) else { continue };
                out.extend(info.rotations.keys().copied());
                for x in info.superseded_epochs().into_iter().filter(|_| superseded) {
                    if let Some(i) = re.get(&x) {
                        out.extend(i.rotations.keys().copied());
                    }
                }
            }
        }
        Ok(out)
    }
}

/// `Engine::steps_needs`: per recorded step what it waits on, per role commit the parent of the
/// step waiting on it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct StepsNeeds {
    by_step: BTreeMap<StepId, Arc<Vec<CommitId>>>,
    parent: BTreeMap<CommitId, Step>,
}

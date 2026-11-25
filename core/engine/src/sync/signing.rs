//! What sync signs entries with and what a step waits on (spec/sync-inbox.md §2-§4,
//! spec/sync-ids.md §6 Steps): the role keys of a sync ID's head held here, the sync IDs a
//! delivery names, and the role commits a step's epochs depend on.

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
            && let Some((head, _)) = o.path.steps.last()
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

    /// The role commits of `s`'s thing that recorded step `step`'s epochs depend on: the held
    /// rotations of the epochs it registers and of those they supersede (spec/sync-ids.md §6
    /// Steps). A role's epoch is the one whose key the step carries; where no secret held here
    /// tells (a reader registering a write or delete key), each current epoch of the role here.
    /// Empty for a step this node does not record.
    pub fn step_needs(&mut self, s: &SyncId, step: &StepId) -> Result<Arc<Vec<CommitId>>> {
        Ok(self.steps_needs(s)?.by_step.get(step).cloned().unwrap_or_default())
    }

    /// The parents of the recorded steps of `s` whose epochs depend on role commit `c`
    /// (`step_needs`), earliest first.
    pub fn step_parents(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<Step>> {
        Ok(self.steps_needs(s)?.parents.get(c).cloned().unwrap_or_default())
    }

    /// `step_needs` of every recorded step of `s`, and its inverse (`memo`): built once per move
    /// of the path or the epochs it reads, then O(log) per step or commit asked.
    fn steps_needs(&mut self, s: &SyncId) -> Result<Arc<StepsNeeds>> {
        Memo::get_in(self, |e| &e.core.steps_needs, s, |e| e.steps_needs_derived(s))
    }

    fn steps_needs_derived(&mut self, s: &SyncId) -> Result<Arc<StepsNeeds>> {
        let mut out = StepsNeeds::default();
        let Some((t, o)) = self.recorded_owner(s)? else { return Ok(Arc::default()) };
        let Some(ep) = self.epochs(&t) else { return Ok(Arc::default()) };
        let mut parent: Option<&Step> = None;
        for (st, _) in &o.path.steps {
            let needs = self.needs_of(&t, &ep, st)?;
            if let Some(p) = parent {
                for c in &needs {
                    out.parents.entry(*c).or_default().push(p.clone());
                }
            }
            out.by_step.insert(st.id(), Arc::new(needs));
            parent = Some(st);
        }
        Ok(Arc::new(out))
    }

    /// `step_needs` of step `st` of a sync ID of `t`, whose epochs are `ep`.
    fn needs_of(&mut self, t: &Tid, ep: &osis_keys::ActorEpochs, st: &Step) -> Result<Vec<CommitId>> {
        let k = self.head_keys(t, st)?;
        let mut out = BTreeSet::new();
        for (r, e) in [Role::Sync, Role::Write, Role::Admin].into_iter().zip(k.epochs) {
            let re = ep.role(r);
            for e in e.map_or_else(|| re.current(), |e| vec![e]) {
                let Some(info) = re.get(&e) else { continue };
                out.extend(info.rotations.keys().copied());
                for x in info.superseded_epochs() {
                    if let Some(i) = re.get(&x) {
                        out.extend(i.rotations.keys().copied());
                    }
                }
            }
        }
        Ok(out.into_iter().collect())
    }
}

/// `Engine::steps_needs`: per recorded step its needs, per role commit the parents of the steps
/// needing it, earliest first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct StepsNeeds {
    by_step: BTreeMap<StepId, Arc<Vec<CommitId>>>,
    parents: BTreeMap<CommitId, Vec<Step>>,
}

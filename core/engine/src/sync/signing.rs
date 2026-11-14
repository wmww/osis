//! What sync signs entries with and what a step waits on (spec/sync-inbox.md §2-§4,
//! spec/sync-ids.md §6 Steps): the role keys of a sync ID's head held here, the sync IDs a
//! delivery names, and the role commits a step's epochs depend on.

use super::Signers;
use crate::engine::Engine;
use crate::error::Result;
use osis_base::{CommitId, Role, SyncId, Tid};
use osis_label::StepId;
use std::collections::BTreeSet;
use std::sync::Arc;

impl Engine {
    /// The keys this node signs entries of `s` with: its head's write and delete keys where
    /// established here, and its deposit key (from `actor`'s deposit seed when given: another
    /// actor's inbox, whose head this node need not record; else from the head's).
    pub(crate) fn signers_now(&mut self, s: &SyncId, actor: Option<&Tid>) -> Result<Signers> {
        let mut out = Signers::default();
        if let Some(t) = self.sync_owner_of(s)?
            && let Some(o) = self.owned_sync_ids(&t)?.iter().find(|o| o.id == *s && !o.hint).cloned()
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

    /// The sync IDs delivery (`c`, `holder`)'s blob names (spec/wire.md §9 position 1).
    pub(crate) fn delivery_names_now(&mut self, c: &CommitId, holder: &Tid) -> Result<Arc<Vec<SyncId>>> {
        let Some(o) = self.core.ix.owed_inbox.get(&(*c, *holder)).cloned() else { return Ok(Arc::default()) };
        let mut out = Vec::new();
        for t in &o.things {
            let t = *t;
            if let Some(s) = self.read(|tx| crate::flows::home_sync_id(tx, &t))? {
                out.push(s);
            }
        }
        out.sort();
        out.dedup();
        Ok(Arc::new(out))
    }

    /// The role commits of `s`'s thing that recorded step `step`'s epochs depend on: the held
    /// rotations of the epochs it registers and of those they supersede (spec/sync-ids.md §6
    /// Steps). Empty for a step this node does not record.
    pub(crate) fn step_needs_now(&mut self, s: &SyncId, step: &StepId) -> Result<Arc<Vec<CommitId>>> {
        let Some(t) = self.sync_owner_of(s)? else { return Ok(Arc::default()) };
        let Some(o) = self.owned_sync_ids(&t)?.iter().find(|o| o.id == *s).cloned() else { return Ok(Arc::default()) };
        let Some((st, _)) = o.path.steps.iter().find(|(x, _)| x.id() == *step).cloned() else { return Ok(Arc::default()) };
        let k = self.head_keys(&t, &st)?;
        let Some(ep) = self.epochs(&t) else { return Ok(Arc::default()) };
        let mut out = BTreeSet::new();
        for (r, e) in [Role::Sync, Role::Write, Role::Admin].into_iter().zip(k.epochs) {
            let Some(e) = e else { continue };
            let Some(info) = ep.role(r).get(&e) else { continue };
            out.extend(info.rotations.keys().copied());
            for x in &info.supersedes {
                if let Some(i) = ep.role(r).get(x) {
                    out.extend(i.rotations.keys().copied());
                }
            }
        }
        Ok(Arc::new(out.into_iter().collect()))
    }
}

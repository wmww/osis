//! `sync.0` (spec/sync-ids.md §4, spec/data-model.md §9): the aspect types are osis-schema's
//! (`SyncEntry`, `StepRecord`, `SyncIds`); this module converts records to verified steps and claim
//! sets and back.

use crate::step::{ClaimSet, Step, StepId};
use crate::Error;
use osis_crypto::{Signature, VerifyingKey};
pub use osis_schema::core_types::{SYNC, StepRecord, SyncEntry, SyncIds};
use std::collections::BTreeMap;

/// A step record from a step and its claim set (when held).
pub fn step_record(step: &Step, claims: Option<&ClaimSet>) -> StepRecord {
    StepRecord { step: step.to_bytes(), claims: claims.map(ClaimSet::to_bytes), endorsements: BTreeMap::new() }
}

/// Parses a record: canonical step bytes, and a claim set that hashes to the step's (spec/sync.md
/// §5: a set MUST hash to its step's).
pub fn parse_record(r: &StepRecord) -> Result<(Step, Option<ClaimSet>), Error> {
    let step = Step::parse(&r.step)?;
    let claims = r.claims.as_deref().map(ClaimSet::parse).transpose()?;
    if claims.as_ref().is_some_and(|c| c.hash() != step.claims_hash) {
        return Err(Error::Verify("claim set does not hash to the step's"));
    }
    Ok((step, claims))
}

/// The steps of a sync ID by ID, each keyed by its own ID.
pub fn sync_steps(sync_id: &SyncEntry) -> Result<BTreeMap<StepId, (Step, Option<ClaimSet>)>, Error> {
    let mut out = BTreeMap::new();
    for (id, r) in &sync_id.steps {
        let (s, c) = parse_record(r)?;
        if s.id().0 != *id {
            return Err(Error::Verify("step record key is not its step ID"));
        }
        out.insert(StepId(*id), (s, c));
    }
    Ok(out)
}

/// The endorsements a sync ID's records carry that verify (spec/sync-ids.md §4, §6 Register): by
/// endorsed step, the endorsing delete keys with their signatures. Others are ignored.
pub fn sync_endorsements(sync_id: &SyncEntry, steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> BTreeMap<StepId, BTreeMap<[u8; 32], Signature>> {
    let mut out = BTreeMap::new();
    for (id, r) in &sync_id.steps {
        let Some((step, _)) = steps.get(&StepId(*id)) else { continue };
        let ok: BTreeMap<[u8; 32], Signature> = r
            .endorsements
            .iter()
            .filter(|(k, sig)| VerifyingKey::from_slice(*k).is_ok_and(|vk| step.endorsed_by(&vk, &Signature(**sig))))
            .map(|(k, sig)| (*k, Signature(*sig)))
            .collect();
        if !ok.is_empty() {
            out.insert(StepId(*id), ok);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step::tests::{Group, TG};
    use crate::step::{Parent, register};
    use osis_crypto::{Epoch, SeededRng};
    use osis_schema::Codec;

    // spec/sync-ids.md §4, spec/data-model.md §9: `sync.0` holds steps by ID with their claim sets;
    // records round trip through the `sync_entry` value; paths follow `prev`.
    #[test]
    fn records() {
        let mut rng = SeededRng::from_u64(0);
        let g = Group::new(10);
        let e = Epoch::new(0, [0; 32]).unwrap();
        let (s0, c0) = register(Parent::Genesis(&g.delete()), g.keys(), &[], (&TG, e, &g.read), g.sync_at(), &mut rng).unwrap();
        let (s1, c1) = register(Parent::Child { step: &s0, delete: &g.delete() }, s0.keys, &[], (&TG, e, &g.read), g.sync_at(), &mut rng).unwrap();
        let (s2, _) = register(Parent::Child { step: &s0, delete: &g.delete() }, s0.keys, &[], (&TG, e, &g.read), g.sync_at(), &mut rng).unwrap();
        let mut sync_id = SyncEntry { steps: BTreeMap::new() };
        sync_id.steps.insert(s0.id().0, step_record(&s0, Some(&c0)));
        sync_id.steps.insert(s1.id().0, step_record(&s1, Some(&c1)));
        sync_id.steps.insert(s2.id().0, step_record(&s2, None));
        let back = SyncEntry::from_value(&sync_id.to_value()).unwrap();
        assert_eq!(back, sync_id);
        let steps: BTreeMap<StepId, Step> = sync_steps(&sync_id).unwrap().into_iter().map(|(k, (s, _))| (k, s)).collect();
        assert_eq!(crate::step::path_to(&steps, &s1.id()).unwrap(), vec![s0.clone(), s1.clone()]);
        // A claim set of another step, or a record under the wrong key, is rejected.
        let mut bad = sync_id.clone();
        bad.steps.insert(s1.id().0, step_record(&s1, Some(&c0)));
        assert!(sync_steps(&bad).is_err());
        let mut bad = sync_id;
        bad.steps.insert([0; 32], step_record(&s1, None));
        assert!(sync_steps(&bad).is_err());
    }
}

//! `sync.0` (spec/sync-ids.md §4, spec/data-model.md §9): the aspect types are osis-schema's
//! (`SyncEntry`, `StepRecord`, `SyncIds`); this module converts records to verified steps and
//! back.

use crate::step::{Step, StepId};
use crate::Error;
use osis_crypto::{Signature, VerifyingKey};
pub use osis_schema::core_types::{SYNC, StepRecord, SyncEntry, SyncIds};
use std::collections::BTreeMap;

/// A step record of a step, with no endorsement.
pub fn step_record(step: &Step) -> StepRecord {
    StepRecord { step: step.to_bytes(), endorsements: BTreeMap::new() }
}

/// Parses a record's canonical step bytes.
pub fn parse_record(r: &StepRecord) -> Result<Step, Error> {
    Step::parse(&r.step)
}

/// The steps of a sync ID by ID, each keyed by its own ID.
pub fn sync_steps(sync_id: &SyncEntry) -> Result<BTreeMap<StepId, Step>, Error> {
    let mut out = BTreeMap::new();
    for (id, r) in &sync_id.steps {
        let s = parse_record(r)?;
        if s.id().0 != *id {
            return Err(Error::Verify("step record key is not its step ID"));
        }
        out.insert(StepId(*id), s);
    }
    Ok(out)
}

/// The endorsements a sync ID's records carry that verify (spec/sync-ids.md §4, §6 Register): by
/// endorsed step, the endorsing delete keys with their signatures. Others are ignored.
pub fn sync_endorsements(sync_id: &SyncEntry, steps: &BTreeMap<StepId, Step>) -> BTreeMap<StepId, BTreeMap<[u8; 32], Signature>> {
    let mut out = BTreeMap::new();
    for (id, r) in &sync_id.steps {
        let Some(step) = steps.get(&StepId(*id)) else { continue };
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
    use crate::step::tests::Secrets;
    use crate::step::{genesis, register};
    use osis_schema::Codec;

    // spec/sync-ids.md §4, spec/data-model.md §9: `sync.0` holds steps by ID; records round trip
    // through the `sync_entry` value.
    #[test]
    fn records() {
        let g = Secrets::new(10);
        let s0 = genesis(&g.admin);
        let s1 = register(&s0, &g.delete(), s0.keys, [1; 32]).unwrap();
        let s2 = register(&s0, &g.delete(), s0.keys, [2; 32]).unwrap();
        let mut sync_id = SyncEntry { steps: BTreeMap::new() };
        for s in [&s0, &s1, &s2] {
            sync_id.steps.insert(s.id().0, step_record(s));
        }
        let back = SyncEntry::from_value(&sync_id.to_value()).unwrap();
        assert_eq!(back, sync_id);
        assert_eq!(sync_steps(&sync_id).unwrap().len(), 3);
        // A record under the wrong key is rejected.
        let mut bad = sync_id;
        bad.steps.insert([0; 32], step_record(&s1));
        assert!(sync_steps(&bad).is_err());
    }
}

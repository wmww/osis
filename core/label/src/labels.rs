//! `/label` (spec/sync.md §2, spec/data-model.md §9): the aspect types are osis-schema's
//! (`Label`, `StepRecord`, `Labels`); this module converts records to verified steps and claim
//! sets and back.

use crate::step::{ClaimSet, Step, StepId};
use crate::Error;
pub use osis_schema::core_types::{LABEL, Label, Labels, StepRecord};
use std::collections::BTreeMap;

/// A step record from a step and its claim set (when held).
pub fn step_record(step: &Step, claims: Option<&ClaimSet>) -> StepRecord {
    StepRecord { step: step.to_bytes(), claims: claims.map(ClaimSet::to_bytes) }
}

/// Parses a record: canonical step bytes, and a claim set that hashes to the step's (spec/sync.md
/// §5: a set MUST hash to its step's).
pub fn parse_record(r: &StepRecord) -> Result<(Step, Option<ClaimSet>), Error> {
    parse_step(&r.step, r.claims.as_deref())
}

/// `parse_record` of the canonical bytes of a step and its claim set.
pub(crate) fn parse_step(step: &[u8], claims: Option<&[u8]>) -> Result<(Step, Option<ClaimSet>), Error> {
    let step = Step::parse(step)?;
    let claims = claims.map(ClaimSet::parse).transpose()?;
    if claims.as_ref().is_some_and(|c| c.hash() != step.claims_hash) {
        return Err(Error::Verify("claim set does not hash to the step's"));
    }
    Ok((step, claims))
}

/// The steps of a label by ID, each keyed by its own ID.
pub fn label_steps(label: &Label) -> Result<BTreeMap<StepId, (Step, Option<ClaimSet>)>, Error> {
    let mut out = BTreeMap::new();
    for (id, r) in &label.steps {
        let (s, c) = parse_record(r)?;
        if s.id().0 != *id {
            return Err(Error::Verify("step record key is not its step ID"));
        }
        out.insert(StepId(*id), (s, c));
    }
    Ok(out)
}

/// Steps no other step of the label names as `prev`: the tips of each branch.
pub fn tips(label: &Label) -> Result<Vec<StepId>, Error> {
    let steps = label_steps(label)?;
    let parents: std::collections::BTreeSet<StepId> = steps.values().filter_map(|(s, _)| s.prev).collect();
    Ok(steps.keys().filter(|k| !parents.contains(k)).copied().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step::tests::Group;
    use crate::step::{Parent, register};
    use osis_crypto::{Epoch, SeededRng};
    use osis_schema::Codec;

    // spec/sync.md §2, spec/data-model.md §9: `/label` holds steps by ID with their claim sets;
    // records round trip through the `label` value; paths and tips follow `prev`.
    #[test]
    fn records() {
        let mut rng = SeededRng::from_u64(1);
        let g = Group::new(10);
        let e = Epoch::new(0, [0; 16]).unwrap();
        let (s0, c0) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &[], (e, &g.read), &mut rng).unwrap();
        let (s1, c1) = register(Parent::Child { step: &s0, delete: &g.delete(0) }, s0.keys, &[], (e, &g.read), &mut rng).unwrap();
        let (s2, _) = register(Parent::Child { step: &s0, delete: &g.delete(0) }, s0.keys, &[], (e, &g.read), &mut rng).unwrap();
        let mut label = Label { index: 0, steps: BTreeMap::new(), servers: vec![], replaced: false };
        label.steps.insert(s0.id().0, step_record(&s0, Some(&c0)));
        label.steps.insert(s1.id().0, step_record(&s1, Some(&c1)));
        label.steps.insert(s2.id().0, step_record(&s2, None));
        let back = Label::from_value(&label.to_value()).unwrap();
        assert_eq!(back, label);
        let steps: BTreeMap<StepId, Step> = label_steps(&label).unwrap().into_iter().map(|(k, (s, _))| (k, s)).collect();
        assert_eq!(crate::step::path_to(&steps, &s1.id()).unwrap(), vec![s0.clone(), s1.clone()]);
        let mut t = tips(&label).unwrap();
        t.sort();
        let mut want = vec![s1.id(), s2.id()];
        want.sort();
        assert_eq!(t, want);
        // A claim set of another step, or a record under the wrong key, is rejected.
        let mut bad = label.clone();
        bad.steps.insert(s1.id().0, step_record(&s1, Some(&c0)));
        assert!(label_steps(&bad).is_err());
        let mut bad = label;
        bad.steps.insert([0; 32], step_record(&s1, None));
        assert!(label_steps(&bad).is_err());
    }
}

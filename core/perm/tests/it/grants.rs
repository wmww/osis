//! Grant values.

use osis_base::{Role, Time};
use osis_perm::Grant;

// spec/data-model.md §9 (`signers.0`): a key's grant carries no retain, no floor and no until 0;
// any other until, role and may-grant fit.
#[test]
fn a_key_holds_no_retain_floor_or_until_0_spec_data_model_9() {
    let g = Grant::new(Role::Write);
    assert!(g.fits_key());
    assert!(Grant { until: Some(Time(5)), may_grant: true, ..g }.fits_key());
    assert!(!Grant { retain: true, ..g }.fits_key());
    assert!(!Grant { floor: Some(1), ..g }.fits_key());
    assert!(!Grant::kept_end().fits_key());
}

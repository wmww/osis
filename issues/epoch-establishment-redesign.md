# Epoch establishment by names, frozen coverage: the review
> Summary: Names establishment and frozen coverage (spec/crypto.md §4) are built for an actor's direct holders; holder actors are judged at depth 0 (issues/keys-depth0.md). Left: the review of the direct-holder model (study C2) and its open cases.
> Tags: security, keys, engine, tla

- Rule and invariants: `osis_keys::covers` (by names), `EpochInfo::names_met`, `rotation::departures::{events, names}`; notes/crypto.md (Frozen coverage).
- Tests: C2 `fork_sibling_reseal_spec_crypto_4`, the withheld-departure harnesses (`withheld_departures_*`), `forged_rotation_withheld_removal_spec_crypto_4` and its kin; TLA `MC_c2*`, `MC_withhold`, `MC_names_own` (core/test/tla/rotation).
- Name completeness is the risk: `thing_names` must stay a superset of `events` (else a rotator never covers what it knows: a livelock).
- Orthogonal, unchanged: issues/fork-held-by-non-rotators.md.

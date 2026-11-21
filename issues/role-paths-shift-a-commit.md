# Stating real role paths shifts a commit in the rotation property
> Summary: osis-engine `role_paths_change_no_verdict_in_the_rotation_property_large` fails on main on some seeds: the real-path and Interim empty-path runs of one history give the same verdict on the same edge writes, but from some point every timestamp in one run is one later, so one run wrote an extra commit (or one fewer) before it. Find which commit and whether stating paths changes what a node writes; or fix the oracle if the shift is not observable.
> Priority: normal
> Tags: engine, perm, tests

**Replay** (fails on main a4620f472's binary, as on `prune-delivery`): `OSIS_ROTATION_START=975804695883 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::role_paths_change_no_verdict_in_the_rotation_property_large_spec_permissions_5_2`. Panics `seed 975804695883 peer 0` at `core/engine/src/rotation/tests_property.rs` (the property's `assert_eq!`).

**Seen**: peer 0's verdict map (keyed by (Ts, thing, holder, target)) has 3,622 chars both sides, every entry `true`; the eight edge writes of thing `8gNB…` from Ts ...974 on are the same (holder, target) pairs at Ts n in the real run and n+1 in the Interim run. Earlier entries agree.

**Lead**: an extra or missing commit between the agreeing prefix and Ts ...974 in one run: a key rotation or a role commit written by one walk and not the other would be a behaviour difference the property exists to catch. If it is only a timestamp the user cannot observe, the oracle should compare verdicts per write identity, not per Ts (notes/principles.md, Test what users can observe). The property is A1's transitional check (notes/a1-spec/README.md step 3), so this may go with A1's switch after stage D; check first that it is not a live bug.

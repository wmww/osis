# Rotation and re-seal do not settle in the lacking-write shape at some seeds
> Summary: In `rotation::tests::lacking_write` (P lacks A's current write; F removed from A), the admins' rounds of `ensure_rotated` + `reseal_due` keep producing commits at about a third of seeds, on main too (not converging after 40 rounds); the test `rotator_lacking_carried_write_resealed_spec_permissions_3` passes only at seeds that settle.
> Tags: permissions, engine, tests

Found in sweep step 5 (AK spelling): the AK bytes changed the run at the test's seed 962, which stopped settling ("no fixpoint in 8 rounds"); the test moved to seed 961.

Probe (the test's body over seeds, `settle` with peers [2, 0] on [M, A], after P's own `ensure_rotated(A)` reported `{Read, Admin}` stranded):
- main 9338c682, seeds 955-969: 957, 958, 959, 963, 968 fail;
- the sweep-5 branch, same seeds: 960, 962, 964, 966 fail; those four still fail with 40 rounds (a livelock, not slow convergence).
- Without P's own `ensure_rotated` first, seeds 940-999 all settle on the branch.
- Sweep step 6 (schema table off the header) changed the run again: seeds 955-965 on that branch, 955, 956, 957, 959, 960, 961, 965 fail; the test moved back to seed 962.

Next: log which commits each round makes at a failing seed (rotation vs re-seal, which admin, which actor) and find the cycle; then turn the probe into a seed-range test (spec/permissions.md §3: re-seal trigger and rotation must reach a fixpoint).

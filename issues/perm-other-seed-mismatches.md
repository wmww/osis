# osis-perm random runs fail on some other seeds
> Summary: With `OSIS_PERM_SEED` (tier-2 runs on other histories) three samples fail: two snapshot-model differential mismatches and one certificate-projection mismatch on a joint history. All three fail identically before the epoch-start rejection fix, so they predate it; not yet diagnosed.
> Tags: permissions, tests

Default seed and seeds 1-3 pass everything; the neutrality runs (`roster`) pass on seeds 0-5.

- `OSIS_PERM_SEED=4 cargo test --release -p osis-perm --test differential -- --ignored snapshot_model_agrees_large`: sample 29038 (full): G edge of node 2, model admin, perm write. Node 2's own snapshot of G at t=2 (roster: 2 write) looks like G's epoch start in perm: P's start (K's snapshot at 14) carries a random model ledger whose open entry for node 2 (`since: None, until: None`) plus the roster edge make 2 a P admin from the beginning, so 2 has owner-chain authority on G at 2; the model judges that snapshot inapplicable. Probably a reading of a model-generated ledger (`common::snap_world`), not the walk; check which side follows spec/permissions.md §6.
- `OSIS_PERM_SEED=5`, same test: sample 16451 (full): G write 4, model applied, perm not.
- `OSIS_PERM_SEED=4 cargo test --release -p osis-perm --test queries -- --ignored certificates_project_joint_large`: sample 2836: a write applied in the full timeline (edge-admin class) is dropped in the certificate projection.

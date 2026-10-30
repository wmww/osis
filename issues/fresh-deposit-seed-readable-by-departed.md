# A departed party can read the fresh deposit seed
> Summary: an admin's read rotation writes a fresh deposit seed in the rotation commit's `/keys` delta, but that commit is wrapped under the epoch it supersedes (spec/crypto.md §5), and the §4 exception places that `/keys` delta under uncovered epochs; so a departed party that fetches the commit before the admin re-registers (or reads such a projection) still learns the new seed and keeps depositing. Writer rotations refresh nothing (the seed is admin-written).
> Tags: security, engine, sync

Severity: low (a race window per departure; worst case the departed party fills the deposit budget, grants wait).

Where: core/engine/src/rotation/mod.rs `refreshes_deposit` / `fresh_deposit_seed` (called from `rotate_now` and `edges` demotion); core/engine/src/labeling/certs.rs `inside_member_revokes`.

Why not a separate commit wrapped under the new epoch: certificates carry only `latest_on(actor, "/keys")`, so a seed-only commit would become the actor's certificate `/keys` and drop the keysets from every later chain certificate. A fix needs certificates to carry the newest writer of each `/keys` field (also wanted when roles rotate in separate commits), or the seed to live outside `/keys` (e.g. derived from the newest read secret plus a public nonce).

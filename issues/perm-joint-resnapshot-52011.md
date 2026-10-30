# Joint re-snapshot not neutral at OSIS_PERM_SEED=52011
> Summary: `roster::joint_resnapshot_neutral_large` fails at `OSIS_PERM_SEED=52011` (shard seed 0xb005eedca29, sample 662): re-snapshotting an actor adds an Admin edge to another actor's roster, compacted and uncompacted alike, so not a sticky-residue drop the test allows.
> Tags: perm, tests

Repro: `OSIS_PERM_SEED=52011 cargo test --workspace --test it -- --ignored roster::joint_resnapshot_neutral_large`. Found on branch inside-revokes, which does not touch osis-perm (pre-existing on main e7cede65).

Shape: snapshot of `HjybgSUUz14d…` changed the roster of `f6PkLyyN0F5J…` (also a member of the snapshotted actor): before `{yzHz…: Admin, 37KT…: Admin}`, after and compacted `{Eep_4c…: Admin, yzHz…: Admin, 37KT…: Admin}`; `Eep_4c…` is Write on the snapshotted actor. The panic prints the full history and ledger. Compare with notes/permissions.md Neutrality (residue rule, cascade seed 1900002).

# A removal's rotation of a holder actor is not followed upward at once
> Summary: `rotation::rotate_above` follows the rotations `ensure_rotated` makes, not a removal's or finalize's own rotation (`flows::edges::demote_in`, `finalize_in`), so after a removal from M every rotator of an actor holding M meets the stale box on its own pass and each forks, the grant-then-demote churn's shape on the removal path.
> Priority: low
> Tags: engine

Calling `rotate_above` after the removal's rotation commit fixes the count but changes what a
removal returns (its `Done` gains the rotations above): 13 engine tests that step a removal and
its cascade apart (`tests_carried::removed`, `removal_twelve_deep_*`,
`diamond_and_lattice_*`, `maker_through_keyless_grant_*`) and tests reading a removal's `Done` as one
commit (engine `it` `flows::revoke_joiner_one_rotation_spec_commits_2`) fail (counted before the
sync rebuild, which deleted more such callers). Options: follow it upward in the same transaction but as a separate `Done` the callers
carry out after the removal's; or let the remover's next rotation check answer it (today) and accept one
fork per rotator above.

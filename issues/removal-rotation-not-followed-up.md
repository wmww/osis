# Each rotator above a removal may fork once
> Summary: after a removal from M, every node that may rotate an actor holding M finds that actor's role duty due (`Engine::role_duty_due`: the box at M's superseded keyset is stale) and rotates it at its next step, so each such rotator may fork the actor once; the forks merge at the next rotation.
> Priority: low
> Tags: engine

The removal's own rotation (`flows::edges::demote_in`, `finalize_in`) is not followed upward in its transaction (`rotation::rotate_above` follows only what `ensure_rotated` makes). Sync's role duty (`Life`, per held actor) answers it at each node's next step, the remover's included: no actor stays stale, but every rotator that judges it before another's rotation reaches it rotates it too, one fork each (bounded by the actor's rotators, not by history).

Rejected for now: following the rotation upward inside the removal's transaction. It changes what a removal returns (its `Done` gains the rotations above) and the tests that step a removal and its cascade apart (`tests_carried::removed`, `removal_twelve_deep_*`, `diamond_and_lattice_*`, `maker_through_keyless_grant_*`, `flows::revoke_joiner_one_rotation_spec_commits_2`); the duty already removes the staleness, so only the fork count would change.

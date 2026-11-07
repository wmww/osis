# own_secrets boxes holders whose grant has ended
> Summary: `rotation::own_secrets_rot` boxes every holder for keys of a plain thing, a holder whose grant this node may finalize (past `until`) included: such a holder gets the thing's fresh own secrets, against spec/permissions.md §2 (finalize first, box that holder nothing).
> Tags: security, keys, engine

`own_secrets_rot` calls `ensure_rotated(t)`, which for a plain `t` resolves to the actor up its record chain, so `t`'s own ended grants are never finalized first, and `recipients(t)` boxes them. Re-seals skip such holders (`rotation::ended_holders`). Reachable through `own_secrets_due` (a thing turned plain again with holders) and concurrent grants. Fix candidate: pass `ended_holders` as `skip` (left out) to `recipients` there; needs a test (a timed holder of a thing that turns plain, past its `until`, then `own_secrets_due`).

# A roster snapshot's parts, its linked frontier away: arrival order decides
> Summary: at a node not syncing N, a roster snapshot's `roles.0` part first applies the snapshot and its `tenures.0` part, whose linked frontier's blobs are away, then waits alone; the `tenures.0` part first holds the snapshot whole, and the `roles.0` part waits with it. One held set, two rosters of N, for as long as the blobs stay away. Not new with parts waiting alone; `examine`'s invariant does not hold here.
> Tags: security, permissions, engine, spec

Repro (fails): `cargo test -p osis-engine --lib -- --ignored repro_linked_frontier_part_order`.

Making the `tenures.0` part wait alone is not the fix as it stands: spec/permissions.md §6 keeps a snapshot awaiting its frontier blobs out of the walk, and with its roster in the walk without its ledger a demoted writer's audit is missing until the blobs come (`linked_frontier_wait_order_independent_spec_perm_6` pins the wait). The other way, an applied snapshot whose late `tenures.0` part is away leaves the walk until the blobs come (`Indexes::frontier_unknown`), keeps one rule for both orders, at the cost of a snapshot's `roles.0` part being in state and out of the walk.

# held-model adapter: missing parts of applied commits count as dropped
> Summary: The adapter feeds a part an applied commit misses as `Body::Dropped`, so an engine applying a commit too early is never caught; feeding synced parts as `Missing` fails one purge seed, undiagnosed.
> Tags: tests, engine

osis-node `tests/it/held.rs` (`convert`): a part in `Meta::missing` of an applied commit becomes `Body::Dropped`, which held-model counts as held for atomic apply (spec/commits.md §4). The model has no sync scope, so for a thing the node does not sync that is right; for a synced thing it hides an early apply.

Tried: `Missing` when `e.core.syncs(tid)`, else `Dropped`. Tier 1 and exhaustive pass; `arrival_order_purge_large_spec_commits_5` seed 3004 (`OSIS_ORDER_SHRINK=0`) fails at a node holding every commit: a thing's creation commit applied with its `t:reg.0` part (`author_or_admin`, no bounds) missing and its `created.0` part held, no snapshot, purge or lowering on that thing held. Either the engine applied early, or a reason the model lacks (another blob class or section of the commit, a host deletion it accepts) applies. Find which; then the adapter can feed synced missing parts as `Missing` (or the reason, if the model should know it).

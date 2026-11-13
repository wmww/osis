# Persisted `void` index disagrees with a rebuild after restarts
> Summary: `ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6` seed 915623258342 fails on main: `check_index` opened from the persisted index finds `void` (commits voided by overlapping session ranges) holding two commits a fresh rebuild does not. A void row is kept, or not removed, across a restart.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_EPH_START=915623258342 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6` (deterministic, about 1 s). Panic at core/engine/src/engine/mod.rs `check_index`: `opened from the persisted index, the index Table("void"): want {} got {7dc9ba3b.., f10bc9bd..}`. Found by the cleanup-models gate, which changed only test models; engine code is main's (8ed53504f).

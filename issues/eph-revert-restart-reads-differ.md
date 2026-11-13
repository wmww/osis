# Ephemeral reverts with restarts: the two nodes read a thing differently
> Summary: `ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6` seed 750697698832 fails on main: after the run settles, writer `b` reads a listed thing's ephemeral state as `"3"` and admin `a` reads nothing (core/node/tests/it/ephemeral.rs `revert_run_with`, the read-alike check). Both list the thing alike. Not looked into.
> Priority: normal
> Tags: engine, ephemeral, tests

Replay (deterministic, about 2 s; in tools/known_failures.txt): `OSIS_EPH_START=750697698832 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6`. Panic: `seed 750697698832: Tid(..)`, `left: None`, `right: Some(Str("3"))` (left is `a`). Found by the prose-issues-2 gate (setup 750697698815, one of 20 seeds). Next: does it fail without the restarts (the run's restart steps are the difference from `ephemeral_reverts_within_rights_alike`), then reduce to a minimal reproducer.

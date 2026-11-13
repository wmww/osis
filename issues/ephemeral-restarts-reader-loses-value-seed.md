# Ephemeral reverts with restarts: a node ends without a value its peer reads
> Summary: osis-node property `ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6` fails on main at seed 704201441278: after the final sync, node a (the writer side) reads no ephemeral value on a listed thing where b reads `Str("2")` (core/node/tests/it/ephemeral.rs, final `eph_read` comparison). Deterministic; unrelated to account rotation (found gating epoch-order-knowledge).
> Priority: normal
> Tags: tests, node

## Repro
`OSIS_EPH_START=704201441278 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6`
Panic: `seed 704201441278: Tid(...)`, left (a) `None`, right (b) `Some(Str("2"))`. Not yet diagnosed: the steps mix restarts, reverts and demotions of b in a group (step 6).

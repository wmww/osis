# Ephemeral reverts with restarts: a message loop at seed 6
> Summary: osis-node property `ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6` seed 6 (on main at 85e446ce8) never settles: "no quiescence after 2000 rounds (8493 messages): a loop". Two hosts, no cap; not traced.
> Priority: normal
> Tags: ephemeral, sync, tests

- Repro: `OSIS_EPH_START=6 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6` (3 s).
- Found by the default (small) run of the property, so every run from start 0 hits it; gates draw their own start.
- Not the full-peer deletion rule (spec/sync.md §9 Deleting at a host, Full host): the loop is the same with and without it, and no host is capped.

# Properties and sims failing since the old account code's deletion
> Summary: properties and sync sims that fail on main on every seed since the accounts rewrite deleted the old account machinery; each listed in tools/known_failures.txt, to be fixed or rewritten by the pieces of notes/accounts-switch-brief.md (Code pieces still to build).
> Priority: normal
> Tags: accounts, tests

Found by a gate on main (every seed fails at the gate's offsets and at seed 0). Grouped by first panic:
- `not implemented: accounts: pairing` (harness pairing helpers; piece 3): osis-engine `parts::forged_parts_beside_a_part_past_expiry_alike_plain_spec_commits_4` and `_in_every_order_exhaustive_`, `waits::every_part_given_once_joins_in_any_order_plain_spec_commits_4`, `shred::purged_permanent_alike_plain_spec_commits_5` and `_in_every_order_exhaustive_`; osis-sync `differential::histories_hold_their_closure_plain`.
- `the reader holds its grant's offer` (grants to a node thing reach no inbox; brief, Minting with a key probe): osis-engine `apply::tests_addenda::a_removed_writers_writes_read_alike_plain_spec_perm_5_2` and `_large_`, `validity::unmerge_paged_matches_fresh_large_spec_crdt_4_6`.
- Model mismatches, cause not studied (piece 7: sync differential and sims with ordinary accounts): osis-engine `closure::sync_units_are_the_models_plain_spec_sync_set_2` (`the sync unit of`); osis-sync `sims::a_reader_through_a_node_keeping_it_unread_plain` (`reads thing 0 unlike the reference`), `sims::lost_and_repeated_messages_plain` (`w.net.faulted != (0, 0, 0)`: the network faults nothing).
- `node N reads thing N: ..., the model does not` (seed 0 and the gate's): osis-sync `sims::store_failures_plain`, `sims::a_peer_refusing_role_entries_plain`, `sims::crashes_and_restarts_in_place_plain`, and `sims::lost_and_repeated_messages_plain` beside its other panic. And osis-sync `idle::a_commit_judges_one_stranding_and_time_passing_no_duty_per_thing_spec_sync_status_1` (default test: `duties judged: 45 at n, 72 at 10n`).
- `refuses a fire of node N: Bad` (a node refuses another's signal fire): osis-sim's default `scenarios::` tests (seed 0) and the sim-sweep scenarios `crash_restart`, `drift_parks`, `revoke_while_writing`, `three_random`, `two_nodes`.
- `held-model differs: validity of commit` on some seeds (rate): osis-engine `order::held_set_decides_plain` and `_exhaustive` (OSIS_ORDER_SEED=850771093425).

Each piece that lands re-runs the ones it reaches and drops their lines; a test still failing after piece 7 is a bug of its own.

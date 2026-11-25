# Sims refuse a grant fire; a differential seed drops an unread thing
> Summary: On main at the cards change (public-and-cards piece 6), every osis-sim scenario fails at every seed with "node K refuses a fire of node K: Bad", and sync differential `histories_hold_their_closure_plain` fails at seed 188729745532 (node 0's sync set holds thing 0 as None, the model Unread). Cause not found.
> Priority: critical
> Tags: engine, sim, tests

Seen by the copy-cut-build gate and replayed on main's binaries (tools/bin-at origin/main): `osis_sim::replay("two_nodes", 0)` fails at step 17, node 1 refusing node 0's fire as `Bad`; the four `scenarios::*` default tests and `sim-sweep:{crash_restart, drift_parks, revoke_while_writing, three_random, two_nodes}` alike. `OSIS_SYNC_START=188729745532 OSIS_SYNC_SEEDS=1 osis-sync --ignored differential::histories_hold_their_closure_plain`: node 0 holds thing 0 (made by node 1, independent) not at all where the model keeps it unread; its why: no secrets of it held.

Failing sims print long traces, so `osis-sim/it` runs over its cost line; the line is raised to 8.5 while they fail (STALE-COST lowers it once fixed).

Likely place: what the cards change moved about a grant from outside (fires at `inbox_in`, the granter's "holds H's keys" check, `takes_grants`'s card in the harness but not in the sim's nodes).

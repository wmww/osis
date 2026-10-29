# Sim work_sets: a set element present at one member, missing at another
> Summary: sim-sweep `work_sets` seeds 15061 and 15110 (periodic run, range 15000+300) end with two members reading `/s/tags` differently at quiescence (`{ash, elm}` vs `{elm}`), both fully synced (same heads, nothing unsettled). Delete refusals (code 1) appear before it in 15061.
> Tags: tests, crdt, engine

Replay: `osis_sim::replay("work_sets", 15061)` / `15110` (notes/testing.md sim replay). Same shape in both seeds, so likely one cause. Check against branch small-order-bugs (crdt Slots/remove_dots changes) once merged.

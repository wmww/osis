# Peers hold different commits on a thing after a removed writer's writes
> Summary: osis-engine `apply::tests_addenda::a_removed_writers_writes_read_alike_{plain,large}` fail on main: after a writer's removal and its concurrent writes, the three peers do not hold the same commits on t; cause not sorted.
> Priority: normal
> Tags: engine, tests

Observed at baebb90c8 (the stub rewrite on main), seeds 3, 9, 13, 16, 21 of the plain run and most large seeds: "seed 3: Alice 1, Bob 2, Carol 0, tie 2, regrant false, writes [(false, true), (false, false)]: every peer holds the same commits on t". Every failing case has `regrant false`. Likely a peer that holds t only through the removed holder no longer receives what the others hold (a grant left untold since the rewrite, or a stub not carried); check what the differing peer holds of t and by which unit.

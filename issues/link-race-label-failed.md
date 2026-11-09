# A label stays Failed at quiescence in `link_race`
> Summary: sim `link_race` can end with a node's group label `Failed` on its host connection (never opened again), so the quiescence check fails; fails on main too. Property: a label a node syncs is open at each reachable host at rest.
> Priority: normal
> Tags: tests, node-sync

Found by a branch sweep at a random offset (`osis_sim::replay("link_race", 2078792205)` on main and on signing-cleanup): node 1's two labels of one group sit `Failed` after a cut link, with a host diagnostic "proto: malformed reply to no request" in the same round. Investigate what fails the open and why nothing retries it.

# osis sources:: tests flaky under load or few cores
> Summary: `sources::connecting_at_zero_and_infinity` fails almost always pinned to 2 cores (main too); `sources::an_empty_group_at_the_node_can_be_routed_to` failed once in a tier-1 run with `Unsynced`, not reproduced.
> Tags: tests, osis

- `connecting_at_zero_and_infinity`: `taskset -c 0-1 <osis it binary> sources::` fails 14 of 15 runs, on main and branches alike, at its first assert: with `connection_wait` 0 the in-process connection is made before the zero wait gives up, so `connect` returns `Ok` instead of `Error::Network`. Unpinned it passes. Either the 0 case should give up before trying (no race), or the test should not expect `Network` there.
- `an_empty_group_at_the_node_can_be_routed_to`: one tier-1 failure seen (`Unsynced` error, from `x.n.sync`, `grant` or `move_group`), passing alone and on reruns; 48 unpinned `sources::` runs, 6 in parallel, on main and a branch showed no failure. Likely a race between the node's sync and the route. Record the full panic next time it shows.

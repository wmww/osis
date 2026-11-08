# osis sources:: tests flaky under load or few cores
> Summary: `sources::connecting_at_zero_and_infinity` fails almost always pinned to 2 cores (main too); `sources::an_empty_group_at_the_node_can_be_routed_to` failed three times (a tier-1 run, gates on a busy box) with `Unsynced`, not reproduced alone; `sources::client_listener_key_is_its_own` failed once in a gate at load 45 (`Network("the node did not answer in time")` at the first read after `rotate_peer_address`), passing alone 5 of 5.
> Priority: normal
> Tags: tests, osis

- `connecting_at_zero_and_infinity`: `taskset -c 0-1 <osis it binary> sources::` fails 14 of 15 runs, on main and branches alike, at its first assert: with `connection_wait` 0 the in-process connection is made before the zero wait gives up, so `connect` returns `Ok` instead of `Error::Network`. Unpinned it passes. Either the 0 case should give up before trying (no race), or the test should not expect `Network` there.
- `an_empty_group_at_the_node_can_be_routed_to`: two failures seen (`Unsynced` from `move_group` at sources.rs `x.move_group(e, ..)`; the second in a gate under load), passing alone and on reruns; 48 unpinned `sources::` runs, 6 in parallel, on main and a branch showed no failure. Likely a race between the node's sync and the route. Record the full panic next time it shows.
- `client_listener_key_is_its_own`: one gate failure at load 45, at line 692 (`c.at(..).get()` right after the dialable key rotated, the client's `connection_wait` short): the client's connection likely still reconnecting under load. Passed alone 5 of 5.

# no_host_chain: a holder lacks another's commits at quiescence
> Summary: sim `no_host_chain` setup 303556118941 seed 303556118954 fails on main at step 150: holders 0 and 1 of a group read differently at quiescence; node 0 lacks four commits nodes 1 and 2 hold (one a Content commit on `s:tags.0` by another account), so it reads `cedar` where they read `cedar` and `elm`.
> Priority: normal
> Tags: tests, sync, sim

- Replay: `cargo run --bin sim-sweep -- --seeds 1 --from 303556118954 --setup 303556118941 --only no_host_chain` (under 1 s). Fails on main before and after the net-3i3c2 merge (checked at 8813916c6 and adade5f30), so not that change. Found by the cleanup-label review gate; the branch touches no sync path.
- Find why node 0 never pulls the four commits (no host: holders reach each other over LAN, public addresses, relays or punching by seed), then a minimal node test of the property it breaks.

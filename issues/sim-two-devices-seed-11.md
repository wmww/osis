# two_devices_server seed 11: a device misses the other's creation records
> Summary: `osis_sim::replay("two_devices_server", 11)` fails since sync round 2: at quiescence node 1 holds 11 commits pending `UnknownCreated` for two items node 0 created; passes on main and with the in-flight upload skip disabled.
> Tags: sync, tests

Repro: `osis_sim::replay("two_devices_server", 11)`.

- Seen only at seed 11 of 1..50. Node 0's verdicts do not list the creation commits as must-hold missing at the server (the label invariant passes); the creation commits never reach node 1. Not pinned down: likely a placement or projection that an earlier redundant re-upload used to carry, same family as issues/sim-disk-loss-chain-lost.md.

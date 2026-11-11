# release-expiry
- The test harness's `set_online(n, false)` stops feeding the node any event (no Ticks), so "the others offline" can't model a node that runs disconnected; a serving node alone needs a hostless label (`local_nodes`) instead. Cost a detour: an offline node never forgets anything at expiry.
- `local_rows_naming` returns raw keys; telling a tombstone (`y/x`) from a forgotten header (`y/G`) took printing key prefixes by hand.
- Review gate: every stage inside its own limit (default tests 122/439 s, properties 80/296 s, sim 87/254 s), yet gate.hold (289/177 s wall) and gate (349/220 s) reported LIMIT: the hold's limit is below the sum of its stages' normal times, so it fires on a clean run (notes/time-limits.md calibration).

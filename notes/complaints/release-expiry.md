# release-expiry
- The test harness's `set_online(n, false)` stops feeding the node any event (no Ticks), so "the others offline" can't model a node that runs disconnected; a serving node alone needs a hostless label (`local_nodes`) instead. Cost a detour: an offline node never forgets anything at expiry.
- `local_rows_naming` returns raw keys; telling a tombstone (`y/x`) from a forgotten header (`y/G`) took printing key prefixes by hand.

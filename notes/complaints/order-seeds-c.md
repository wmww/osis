# order-seeds-c
- The failing pair of seed 7340007 was the "held set, then the rest" comparison, which `dump_orders` does not print for; `OSIS_ORDER_DUMP=1` showed nothing until the first fix moved the failure to a plain order. A per-step probe test (reads, invalid writes, one commit's drop/death status after each ingest) found both causes faster than the dump.
- A `dating` failure ("body dropped before its keep-at-most bound") also prints no dump; the oracle's "earliest superseders None" was the key fact and came only from the probe.
- Shrinking 52040 was skipped: `OSIS_ORDER_SHRINK=0` plus the one failing held set and order reproduces in under a second, and the history pins as is (70 steps).

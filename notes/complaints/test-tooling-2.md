# test-tooling-2
> Summary: complaints from the structured-index-digest and tools/bin-at branch.

- Order oracle summaries print only when an `OSIS_ORDER_*` variable is set; to read the order counts at default sizes set one that changes nothing (`OSIS_ORDER_THREADS=16`).
- Default-size order/walks runs all pass at base, so "identical pass/fail" barely tests a rewritten exemption; the `_tolerated` tier-1 tests are what exercise it.

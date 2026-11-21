# sync-store-2
> Summary: footguns met folding connection rows into the sync store's memory part and charging the memory caps what memory holds.

- The workspace forbids `unsafe_code`, so a counting `#[global_allocator]` in a test binary is out; the by-hand heap check was `/proc/self/statm` RSS around a single-threaded `--exact` run.
- `source_bytes`' tag byte was hard-coded as `&[0]` in the start's connection scan: changing the encoding failed one test with an unrelated-looking message. It is a named constant (`rows::CONN`) now.
- Moving the memory log from maps into store rows turned hidden map work into counted "store rows read" and failed two cost tests; the map version does the same work uncounted (issues/sync-memory-uncounted.md).

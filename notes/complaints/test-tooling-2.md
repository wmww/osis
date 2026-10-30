# test-tooling-2
> Summary: complaints from the structured-index-digest and tools/bin-at branch.

- Default-size order/walks runs all pass at base, so "identical pass/fail" barely tests a rewritten exemption; the `_tolerated` tier-1 tests are what exercise it.
- Reviewer: Ctrl-C during `tools/bin-at` left incremental state that broke the next branch link (undefined `drop_glue::<IndexDigest>` etc.); touching sources did not help, deleting the newest `it`/`osis_node`/`osis_engine` incremental dirs did. An uninterrupted bin-at round trip linked fine.

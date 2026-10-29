# snapshot-bounds-purge
- `cargo test --workspace` stops at the first failing test binary (cli here), hiding the osis-node failures behind it: one extra 2.5 min run. Use `--no-fail-fast` when a change may break several crates.
- Changing what `Engine::snapshot` refuses silently weakens every harness that ignores its result (`let _ = e.snapshot(..)` in order, walks, retention random): only the tests that `unwrap()` it failed. Checked by hand which harnesses snapshot at peers that never wrote the aspect.
- The brief's oracle names (`order::arrival_order_alike_large`) lack their `_spec_*` suffix; with `--exact` they ran nothing and passed (`0 passed`): `--list --ignored` gives the real names. notes/testing.md and notes/coordination.md carry the short names too.
- Reviewer: a header-only snapshot ingested at a syncing node pends (`WaitDeltas`), so a late-part test must ingest it before `set_syncing`; nothing says so near `strip_parts`.

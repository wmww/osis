# keep-at-most
- `cargo test --workspace` without `--no-fail-fast` stops at the first failing binary (osis-commit's unit tests here), hiding every later failure behind one rebuild-and-rerun cycle; use `--no-fail-fast` for a removal that touches many tests.
- The D > 0 schemas lived in four test schemas (common, net, scale, sim workload) plus inline `most(None, Some(3_600_000))` helpers in other files; a grep for `keep_at_most:` misses the inline ones (they failed only at run time with a Build error).
- `tombstone::a_lasting_request_waits_when_its_killer_left_*` claimed "keeps its floor" while what held it was D = 1 h: the floor had passed. Name what holds a wait in the assert message from the arithmetic, not the intent.

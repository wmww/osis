# slow-tail
- Per-test timing at load 15-40 swings 1.5-4x between runs (one `after_reset` test read 10 s, then 16 s, at the same size): compare CPU-s of one test run alone, before and after, never `--report-time` lines of two whole-binary runs.
- `tools/cpuprof` was the fastest way to the cause every time: the two slowest tests were 89% a quadratic in node-sync's must-hold (issues/body-keep-quadratic.md), the forensic tests 70% re-trying sections already opened.

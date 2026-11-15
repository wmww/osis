# sync-test-cost
- `tools/icount BIN -q <module>::` filters by substring: `read::` also runs `unread::`, so per-module sums overcount; the whole binary in one process is the number to compare.
- `tools/cpuprof` gives no callers, so finding which of 61 `Timelines::get` callers moved the judgements took a throwaway probe (a `Stamps` per `#[track_caller]` location); a caller split in `Effects` cause counts would make that a counter read.

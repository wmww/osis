# fathom-test-opt-10
- `engine::testing::tables` returns a fixed-size array (`[_; N]`): every branch adding an index conflicts silently on rebase (no text conflict, a type error), and I pushed one such tip before re-running the build. A slice or Vec would rebase cleanly.
- The heavy lock was held by others for long stretches (pertest and whole-binary runs each waited minutes); a pertest run took 19 min wall with the wait, over the heavy limit's 598 s wall (load 22).
- `tools/cpuprof_report.py` takes minutes on a whole osis-sync `it` sample file; a 120 s Bash call times out on it.
- Index and timelines stamps were named by type or file:line (`JSetMap<(Tid, Ak), ...>`, `held.rs:574`), so `Effects` causes could not tell `by_aspect` from `originals` or a whole-component read from an edge read: now named by field and kind.

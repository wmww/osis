# alloc-cut
- No allocation profiler in tools/: counting by call site took a throwaway LD_PRELOAD malloc sampler (backtrace every Nth call) plus a report script. `tools/cpuprof` cannot do it: its self time puts 23% of samples in `??` (libc internals have no symbols), and inclusive malloc stacks are timer-sampled, not per call.
- llvm-symbolizer gives inlined frames short names without their path (`with_capacity_in<...>`, `head`, `{closure#0}`), so grouping by owning type needs the non-inlined caller; a first grouping by "first frame mentioning osis" matched generic arguments (`Vec<osis_base::Value>`) and was wrong.
- `order::held_set_decides` instruction counts move about 1% between identical runs (its seeds run on a thread pool): compare it by repeated runs.

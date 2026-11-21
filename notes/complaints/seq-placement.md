# seq-placement
- A run cap (`PREFETCH` 8) masked every other failure of `seq_cold_edits_keep_placement_plain`: once it went, four more classes showed (issues/seq-cold-edits-follow-gaps.md). One known_failures line per property hides what lies behind its first failure.
- Finding why a follow gave up meant hand-instrumenting every `return false` in `seq_lin.rs` with an env-gated print: the follow's bail reasons are invisible (a bool). A probe hook naming the bail site would have saved several builds.
- osis-engine lib test rebuilds take 1.5-4 min each on a crdt edit; a dozen probe cycles was most of the task.

# decode-step4
- `tools/bin-at main ... --release` checks main out in the worktree and builds release (5 min at load 25-35), then the next release build of the branch rebuilds again (4 min): a timing comparison of one test costs ~10 min of builds before anything runs.
- `scale::big_map_apply_memory` at 10^6 takes ~10+ min (writer alone 220 s); a step measured after a step that freed memory reads low (allocator reuse), so "peak" of later steps in one child understates.
- `paged_apply_matches_whole_large` (24 seeds) ran 200-250 s at load 35; with the debug differential on, tier 1 took ~6 min wall at load 40-60.
- Gate took 890 s at load 30-60 (rebase brought other crates' changes; app check ran too).

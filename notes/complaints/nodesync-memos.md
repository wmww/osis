# nodesync-memos
> Summary: Footguns met on the node-sync memo lane.

- `tools/cpuprof` records relative binary paths: `--report` must run from the directory the profiled command ran in, or every frame reads `??` (and a FILTER matches nothing).
- valgrind is not installed on this box, though issues/derived-state-recomputed.md Method names callgrind; `tools/cpuprof` over a sim seed (`sim-sweep --only X --seeds 1 --jobs 1`, 16k samples) stands in.
- A baseline by `git checkout main -- $(git diff --name-only main HEAD)` silently measures the branch once main has moved (pathspecs of files only main has fail the whole checkout): take the files from `git diff --name-only HEAD~1 HEAD`.
- Which stamp a stale memo entry missed on is not observable; finding it took a throwaway `#[track_caller]` on `Stamps::wrote` and the journal's writers. Worth a debug-only "why recomputed" counter in `memo.rs`.

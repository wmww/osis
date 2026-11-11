# nodesync-memos
> Summary: Footguns met on the node-sync memo lane.

- `tools/cpuprof` records relative binary paths: `--report` must run from the directory the profiled command ran in, or every frame reads `??` (and a FILTER matches nothing).
- valgrind is not installed on this box, though issues/derived-state-recomputed.md Method names callgrind; `tools/cpuprof` over a sim seed (`sim-sweep --only X --seeds 1 --jobs 1`, 16k samples) stands in.
- A baseline by `git checkout main -- $(git diff --name-only main HEAD)` silently measures the branch once main has moved (pathspecs of files only main has fail the whole checkout): take the files from `git diff --name-only HEAD~1 HEAD`.
- Which stamp a stale memo entry missed on is not observable; finding it took a throwaway `#[track_caller]` on `Stamps::wrote` and the journal's writers. Worth a debug-only "why recomputed" counter in `memo.rs`.
- Review: debug cross-checks beside a cache hit (`copy_index`'s fresh build) read stamped containers inside the memo computing, so they covered the very stamp the hit missed: removing it failed no default test in engine or node. Such checks now run under `memo::unrecorded`; worth auditing the other `costs::paused` rechecks the same way.
- Review: the default tests never caught a missing stamp on `leftover::get` or the `copy_index` hit, or a rollback leaving a memo's in-transaction answer; a probe build comparing every memo hit with a fresh run (`memo.rs` `check`) over the retention properties is a cheap stronger check (about 6 min for 2000 deaths seeds).

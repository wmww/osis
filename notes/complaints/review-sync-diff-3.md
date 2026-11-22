# Complaints: review-sync-diff-3
> Summary: mutate.py refuses two mutations whose OLD spans overlap even across separate runs' worth of sites; a foreground rebuild of `it` while a background run of the same binary is going replaces it under that run.

- `tools/mutate.py` with two sites in one expression ("overlap") refuses the batch; two invocations are needed, each a full build.
- Building the `it` binary (a probe) while a background `cargo test -p osis-sync` was running the same `target/debug/deps/it-*` replaces the file under it; the run happened to pass, but nothing warns. Wait for a background run before building again in that worktree.

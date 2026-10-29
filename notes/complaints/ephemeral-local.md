# ephemeral-local
> Summary: Mishaps met while building ephemeral step 1.

- A tier-1 run with a broken osis test hung on `watch::watch_current_and_changed` (a watch waiting forever) with no per-test timeout: `--no-fail-fast` ran the whole workspace behind it until stopped by hand. Running the osis `it` binary alone first would have shown it in 20 s.
- No profiler on the box (no valgrind, no perf): the cost breakdown took env-var toggles in the code and a release rebuild (40-80 s) per experiment.
- The Option<CommitId>/ChangeId change hit about 80 test lines; applying rustc's own JSON suggestions (`--message-format=json`, `suggested_replacement`) by script fixed most of them at once.
- Review: main rewrote notes/ephemeral.md (design simplified) while the branch was in flight, so the rebase conflicted on the design text; resolved by taking main's design and appending "Step 1 as built". Design notes under active owner review and a worker branch editing the same note collide every time.

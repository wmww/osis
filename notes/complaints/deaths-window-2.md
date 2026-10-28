# deaths-window-2
- The new worktree's first build took 13 min at load 35-70 (cold, notes say 80 s quiet).
- The order harness's shrink accepts any failure, so a window-check panic (debug assert) in one order hides behind a "judged differently" result of another, and the printed shrunk history may not reproduce the panic. Finding the panic's history took a throwaway shrink with a "window deaths" predicate.
- The window's debug check sat after its early returns, so a window that judged nothing skipped it; the mismatch showed up one late delta later, on a different commit. Now `check_window` runs after every window in `settle_due`.
- The strays test did not print its seed on a panic (fixed: catch_unwind per seed).
- I started 5 test shards with `&` in a plain Bash call, so claudewait could not wait for them; one `run_in_background` call that starts the shards and `wait`s works.
- `pkill -f PATTERN` in a background command killed its own shell (the pattern was in its command line), as notes/build.md warns for pgrep. Writing into the worktree while a background command had it checked out at an old commit blocked the checkout back.
- Review: the strays test stopped at the first failing seed, so one shard of a 10,000-seed sweep left 578 seeds unrun (now it reports every failing seed).
- Review: release timing under load 5-25 swung 2-4x between runs of the same binary (even paired concurrent runs); a main-vs-branch comparison needed four alternating runs to read as noise.
- Review: rebase onto main conflicted in walks.rs (the branch's catch_unwind loop vs main's `run_seeds`); kept main's.

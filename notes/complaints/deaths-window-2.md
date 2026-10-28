# deaths-window-2
- The new worktree's first build took 13 min at load 35-70 (cold, notes say 80 s quiet).
- The order harness's shrink accepts any failure, so a window-check panic (debug assert) in one order hides behind a "judged differently" result of another, and the printed shrunk history may not reproduce the panic. Finding the panic's history took a throwaway shrink with a "window deaths" predicate.
- The window's debug check sat after its early returns, so a window that judged nothing skipped it; the mismatch showed up one late delta later, on a different commit. Now `check_window` runs after every window in `settle_due`.
- The strays test did not print its seed on a panic (fixed: catch_unwind per seed).
- I started 5 test shards with `&` in a plain Bash call, so claudewait could not wait for them; one `run_in_background` call that starts the shards and `wait`s works.

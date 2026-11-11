# held-writes-amend
> Summary: icount on osis `sources::known_stays_here_and_unknown_goes_to_the_node` swings 1.33-1.48 G run to run (thread timing), so a 1-3% change there is unmeasurable without about ten runs a side; the sim scenarios are deterministic and the better yardstick.

- `tools/cpuprof --report OUT N FILTER` percentages are of the filtered samples, and inclusive lines for frames above the filter come first: easy to misread as shares of the run.
- Reviewer: building main's binary in a task worktree needs `git checkout --detach main` (main is checked out in the main checkout); `tools/bin-at` copies test binaries only, so an old-vs-new `sim-sweep` count is three hand builds.

# eph-own-covers
> Summary: footguns met while building own covers.

- Random caps exposed pre-existing bugs unrelated to covers (presence deletion records trimmed for the plain cap; empty presence commits from non-writers). Checking such a seed against main needed a second worktree (`tools/wt claim` of a throwaway branch): cheap when one is warm, worth knowing.
- `ephemeral_dump` lines filtered with `grep -v 'presence false'` hid the very plain entries I was looking for: the dump has no flag for "own plain".
- The sim-sweep log for a many-seed run prints only the FAIL line; the trace needs a re-run with `--seeds 1`.
- Tier-2 random_window runs: 300 seeds of all three take about 11 min together at nice 19; 1000 seeds about 35 min.
- Reviewer: the capped checks excuse all divergence once any entry is refused, so the single-server capped runs check no convergence on about a third of seeds (37 of 233 in one 300-seed run); a stronger check (each holder equals its own writes joined with the server's entries) would need a model of what the server holds. Re-review added the cheap exact part: holders of the same plain commits read alike (19 of 39 refused runs compare some pair).
- Reviewer: no test wrote an ephemeral aspect past 64 KiB, so covers failing to build (and losing unsent writes) went unseen by every randomized run.

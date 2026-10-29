# eph-own-covers
> Summary: footguns met while building own covers.

- Random caps exposed pre-existing bugs unrelated to covers (presence deletion records trimmed for the plain cap; empty presence commits from non-writers). Checking such a seed against main needed a second worktree (`tools/wt claim` of a throwaway branch): cheap when one is warm, worth knowing.
- `ephemeral_dump` lines filtered with `grep -v 'presence false'` hid the very plain entries I was looking for: the dump has no flag for "own plain".
- The sim-sweep log for a many-seed run prints only the FAIL line; the trace needs a re-run with `--seeds 1`.
- Tier-2 random_window runs: 300 seeds of all three take about 11 min together at nice 19; 1000 seeds about 35 min.

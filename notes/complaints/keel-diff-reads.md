# keel-diff-reads
- The brief's premise that seeds 1 and 39 came with the custody, S1 or strip commits was half right: 39 passes on main already, and 1 came with 8d4075946 alone (bin-at at 39a5d091c passes, at 8d4075946 fails). The Status line "9 of 100" at 011a09cf7 was run on an older build.
- The sync trace shows no verdict: finding why a self-removal's wait ended at once took hand-added prints in four modules (wait_if_own, status removal_done, held_at, classify, may_log). A trace line per verdict change (S, commit, verdict, which clause) would have shown "may-hold: not loggable" at once.
- `tools/bin-at` checks out the worktree, so a `wip` commit is needed first, and scratch replay modules must be committed or dropped; a test file edited meanwhile shows "changed on disk" afterwards.
- A sed pattern with `.` meant as a literal apostrophe matched a test line and replaced it; prefer the Edit tool for test lines.
- Squashing wip commits with `git reset --soft origin/main` after `origin/main` had moved (bin-at or a fetch) staged a revert of others' commits; caught by the diff stat (40 files). Squash onto the commit the branch started from, then rebase.

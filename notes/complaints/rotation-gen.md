# rotation-gen
- `tools/bin-at` checks REV out in the worktree for its whole build: a `grep` of a file the branch added said "no such file" mid-run. Expected, but easy to forget while doing notes work beside it.
- Old harnesses run from a `bin-at` binary panic at once on their `OSIS_*` variables once the branch drops them from core/base/testenv-known.txt (the list is read at run time from the worktree): "7 failed in 0.00s". Re-add the names temporarily to compare.
- Sabotage loops cost a 1-3 min osis-keys/osis-engine rebuild each; seven took about 10 min of builds.

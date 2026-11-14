# memo-stamps
- valgrind/callgrind is not installed on this box, though issues/derived-state-recomputed.md (Method) names it; tools/cpuprof samples were too coarse to place a 2% move, so finding the cause took rebuild experiments.
- A first measurement after moving the store onto one stamp table showed +2.5% on sim member_churn, all debug comparisons (`Checks` reruns at hits after any change of a container read): container granularity silently drives debug cost, worth a line wherever stamps are added.
- `origin/main` moves under a worktree (other agents fetch the shared repo): `git diff origin/main` showed others' changes as mine; diff against `git merge-base HEAD origin/main`.

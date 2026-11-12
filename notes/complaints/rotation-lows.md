# rotation-lows
- `git checkout main -- <files>` to measure a baseline stages main's copies: restoring the files by `cp` left them staged (MM). `git reset <paths>` after.
- The sim has no role-commit counter: measuring member_churn's rotations meant a throwaway eprintln in the scenario (count commits with a `keys.0`/`roles.0`/`secrets.0` aspect on g at node a). Issue counts (138/141) and this one (111) differ by what was counted; say which in an issue.
- One member_churn seed takes 2-3 min debug at load 40; `--jobs 1` still rebuilds osis-sim each time a scenario file changes.

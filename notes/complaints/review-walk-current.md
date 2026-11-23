# review-walk-current
> Summary: Mishaps met reviewing walk-current.

- No scale test opened a store holding many role commits: the branch's per-commit walk update in open's role loop made open quadratic (keys judged 525 at n, 23115 at 10n) with every test green. `scale::open_is_linear_in_role_commits` covers it now.
- Comparing a count against main meant checking main's engine `src` and its changed tests out over the worktree and back (the branch's tests call `Core::timelines()`); `tools/bin-at` builds whole binaries, not a probe test.

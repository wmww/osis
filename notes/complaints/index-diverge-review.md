# index-diverge-review
> Summary: Workflow notes from reviewing the released-vouch index fix.

- `git revert --no-edit HEAD -q` rejects `-q` and prints usage; chained with `&&` it stopped the probe silently. `git reset --hard HEAD~1` over a committed wip probe is the simple undo.
- The filed issue said "some 30 tests" fail with RoleParts compared; the lib alone fails 411: any LocalPeer world whose pass end forgets a record. Counts in issues go stale fast; name the cause instead.

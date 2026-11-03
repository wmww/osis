# eph-hole complaints
- The issue's premise was half wrong: a plain demote-then-grant re-grants (spec/permissions.md §5.2), so the earlier writes turn valid again and no hole forms; the first test passed without the fix. It needs a grant with `until` (or anything else that is no re-grant). Issues written from reading should say whether the scenario was reproduced.
- Tier 1 took 813 s wall at load ~40 (documented ~45 s quiet).
- A python `str.replace(..., 1)` aimed at the new test hit an identical line in the test above it first; anchor such edits to the function.
- Review: `git rebase main` said up to date while origin/main was 4 commits ahead (local main lagged); `git fetch && git rebase origin/main` was needed, as coordination.md says.
- Review gate took 1464 s at load 37-40 (documented about 90 s quiet).

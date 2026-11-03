# eph-hole complaints
- The issue's premise was half wrong: a plain demote-then-grant re-grants (spec/permissions.md §5.2), so the earlier writes turn valid again and no hole forms; the first test passed without the fix. It needs a grant with `until` (or anything else that is no re-grant). Issues written from reading should say whether the scenario was reproduced.
- Tier 1 took 813 s wall at load ~40 (documented ~45 s quiet).
- A python `str.replace(..., 1)` aimed at the new test hit an identical line in the test above it first; anchor such edits to the function.

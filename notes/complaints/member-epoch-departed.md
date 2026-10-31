# member-epoch-departed
> Summary: footguns met fixing issues/member-epoch-written-by-departed.md.

- Squashing wip commits with `git reset --soft main` after main had moved folded the inverse of main's newer commits into my commit. Reset to the claim's base commit instead (`git merge-base HEAD main`).
- Checking a new test fails without the fix: a hand-made "disable" hack was not equivalent to the old code and made the repro look vacuous. Running the test block on main's sources (copy main's non-test part over, restore after) was the reliable check.
- The first repro shapes passed on main for reasons unrelated to the bug (A's admin held no M `/secrets`, so presumed boxes; D's untouched key-actor write box counted as carrying read). The leak needs the rotator to hold M's `/secrets` and D to rotate every role it holds.
- Reviewer: checking whether a branch test fails on main needed a hand splice of main's non-test code under the branch's test module (plus signature patches); `tools/bin-at` only builds whole revisions.

# stranded-report-storage
> Summary: workflow notes from the stranded-report review.

- The same issue was fixed twice in parallel (stranded-bound landed on main while this branch was in review); most of this branch's work was dropped. A claim on an issue file would have saved a worker and most of a review.
- Checking a new test fails on the old code without `git stash` meant a wip commit and checkout of one file; each way rebuilds the test binary (about 2 min).

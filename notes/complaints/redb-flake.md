# redb-flake complaints
> Summary: workflow notes from fixing the redb any-write test flake.

- The flaky sweep's write-count dependence was only visible with a per-write trace (offset/len log in `FaultyFile`); a sweep over fault points that shares one store across points is fragile whenever a landed fault changes the next point's write count.

# redb-flake complaints
> Summary: workflow notes from fixing the redb any-write test flake.

- The flaky sweep's write-count dependence was only visible with a per-write trace (offset/len log in `FaultyFile`); a sweep over fault points that shares one store across points is fragile whenever a landed fault changes the next point's write count.
- Review: the rebase conflicted in tools/known_failures.txt and notes/local-store.md (main's unknown-write-subs review edited the same lines); gate wall 2.08x at load 29-41.

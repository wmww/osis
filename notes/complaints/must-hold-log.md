# must-hold-log
> Summary: workflow notes from the must-hold-log branch.

- The late-joiner probe patch was the whole branch diff plus the probe against an older base, so it did not apply; the probe hunks had to be picked out by hand. Hand over a probe as its own patch.
- (review) `claudewait` on a mistyped task ID fails fast, fine; but a `2>&1 > file` redirect order sent cargo's compile errors to the task output instead of the log, so a 3 s "pass" hid a build failure. Read `test result` lines, never a bare exit 0.

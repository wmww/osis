# keel-grant-history
> Summary: Mishaps met fixing the differential's class 3 (a grant after a keying).

- The brief's branch `keel-diff-200-wip` exists only on origin (`origin/keel-diff-200-wip`), not as a local branch.
- The issue's diagnosis (no path for the keying's history) was wrong: the grant already re-writes each boxed epoch's history; it boxed Bob only at sync. Printing the target's `secrets.0` box keys per node found it in minutes; the issue's narrative cost more than it saved.
- To read state after a failing `World::run` I again had to gate the must-hold check locally (same as keel-diff-200); a harness switch for by-hand probes would help.

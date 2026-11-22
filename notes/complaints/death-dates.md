# death-dates
> Summary: Workflow notes from making history rows exact per-body dates.

- The row-exactness debug check (`leaving::rows_exact`) found every miss: `forget_aspects` dropping rows of held bodies (engine lib), and two the order harness reached only at gate size (an aspect turning dated mid-transaction; a part held and dropped between the two end-of-transaction passes). Whole-aspect debug checks after each incremental step pay for themselves; the default tests alone missed two of the three.
- Mutation-checking a new crdt helper (`moved_by` with one branch disabled, by `sed ... && false` and a copy back) took seconds per branch: worth it for every branch of a completeness claim.
- `Commits::before` logs a commit once per mark, so "changes since position N of the log" is not a safe incremental cursor mid-transaction; a lagging-row check (`dating_due`) had to scan the log instead.
- One `tools/heavy` hold running the four crates' suites plus five property runs passed the heavy caps (1.14x CPU, 1.06x wall, box load 17): split a suite run and the property runs into separate holds.
- The order harness's trace interleaves several engines per thread (copies at tree branches): tracing one commit's history needed a hook in `Commits::insert` with a backtrace, not date_due prints.

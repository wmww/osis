# death-dates
> Summary: Workflow notes from making history rows exact per-body dates.

- A row-exactness debug check (`leaving::rows_exact`) found the only real miss in one engine lib run: `forget_aspects` dropping rows of aspects whose bodies stay held. Cheap whole-aspect debug checks after every incremental step pay for themselves.
- Mutation-checking a new crdt helper (`moved_by` with one branch disabled, by `sed ... && false` and a copy back) took seconds per branch: worth it for every branch of a completeness claim.
- `Commits::before` logs a commit once per mark, so "changes since position N of the log" is not a safe incremental cursor mid-transaction; a lagging-row check (`dating_due`) had to scan the log instead.

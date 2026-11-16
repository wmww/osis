# Role-at-now reads on the wall clock
> Summary: role-at-now reads use the wall clock, not the memo clock, project-wide
> Priority: low
> Tags: engine

Several reads of roles at "now" take the wall clock instead of the memo clock, so a memoized answer can differ from a fresh read across an `until`. Owner: Fathom.

Fix: every role-at-now read goes through one clock (`Core::role_now` is the model).

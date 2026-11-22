# Complaints: review-pass-wait
> Summary: a reviewer's rule finding sent the branch back for a rework and a second claim of the same worktree; nothing in the tooling blocked.

- The first review found the rule problem by reading alone (wall clock frozen or set back while running), which the branch's tests could not show: the fake ground tied the monotonic clock and the wall clock to one field. A fake ground with two clocks from the start would have let the worker see it.

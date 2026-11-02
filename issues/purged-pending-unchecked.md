# A purged waiting part keeps its values until the node can check it
> Summary: A waiting part a held purge request names is stripped only once its thing's record and pages are held (spec/commits.md §5, `retention::strip_purged`); until then its values stay in the pending copy, for good if the record never comes. Unbounded, unlike every other purge path.
> Tags: security, engine, retention

Why it waits: without the record the hash cannot be checked, and a stripped copy is trusted without one (`apply::examine` `kept`), so stripping an unchecked copy would let a junk copy join as the true part. Dropping it instead (the old rule) lost its non-value writes for good where hosts deleted the body (order dependence).

Options: bound it like other pending input (issues/pending-unbounded.md); or drop it unflagged at some bound and accept the divergence there. Same window for a part whose page is away: its inline values stay.

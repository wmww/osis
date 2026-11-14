# An applied commit's unjudgeable part is never fetched again
> Summary: a part of an applied commit that cannot be judged yet (its thing's record or chain away) is thrown out (`late_parts`, `Exam::Ready` unjudged parts) and the engine names the commit in `Wakes::woken` when the record comes, but the new sync takes no `Wakes` and keeps no carrier for it, so the part stays missing until something else brings it.
> Priority: normal
> Tags: sync, engine

Whole commits that cannot be judged pend and are kept by their carrier entries (spec/commits.md §4 Unjudgeable, Pending storage; notes/engine-apply.md). A part alone of an applied commit is still thrown out: the reader takes the entry as `Opening::Taken` (the commit is held), keeps nothing of it, and nothing opens it again. The simplest fix is the same mechanism: keep the unjudgeable parts in the applied commit's pending copy (as `pend_aside` keeps parts that wait) so `engine.pends(c)` holds the entry as carrier and `reexamine` joins them, then drop `Wakes::woken` and `waits.awaiting`.

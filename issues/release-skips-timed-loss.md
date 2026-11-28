# A release before a timed loss's drop leaves its retained copy empty
> Summary: `Engine::released` carries out a lost access first only when `lost_due` holds; a loss by an `until` alone (`lost_timed`) saying retain is not, so a release that comes first drops R's content and the later timed drop keeps a copy with nothing in it (the kept-copy bug, open for the `until` arm).
> Priority: normal
> Tags: engine, sync

`core/engine/src/retention/release.rs` (`released`): the due lost access of each released thing's actor is dropped before the release (spec/sync-set.md §3: a retained copy is excepted). `rotation::lost::due_now` is false for a loss by time alone (`lost_by_time`), which waits in `lost_timed` for its sync IDs to be heard out or `LOST_HEARD_WAIT_MS`. A grant whose `until` passes saying retain (spec/permissions.md §2 `retain`, §3 Retain "a value with another `until`, passed") reaches the release with its secrets still held, and the release takes the content first.

Two timers then decide the outcome by which fires first. Fix by one rule: a thing whose actor is judged lost (due or timed) and still holds secrets is not released until its lost-access drop has judged retain, or the release judges retain itself for both arms. Test: a grant with `until` saying retain passes; the copy reads what it held (the shape of `holding::a_direct_removal_saying_retain_keeps_a_copy_that_reads_spec_permissions_3`).

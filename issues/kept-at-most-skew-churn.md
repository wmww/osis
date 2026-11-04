# Keep-at-least re-upload churns across skew at a keep-at-most bound
> Summary: Since whole-2b's healing rule (`SyncEngine::must_carry`, spec/sync.md §6), a deleted body with a part before its keep-at-least bound is placed again unless another blob carries that part. Keep-at-least is clamped to keep-at-most, and a keep-at-most drop does not wait `MAX_DRIFT` (compaction does): when the bounds meet, the fast right holder drops and deletes the body, the slow one (still before its keep-at-least) uploads a fresh encryption each pass until its own clock passes, the fast one deletes it again. Bounded by the clock gap (about 1 h at `MAX_DRIFT`, longer for an out-of-spec clock), not an endless loop.
> Tags: sync

Repro: osis-node `negative::at_most_across_skew_no_churn_spec_sync_6` (ignored): a dead write with keep-at-least = keep-at-most = T, two writers `MAX_DRIFT` apart crossing T in 5 min steps: 7 deletions and 7 blobs of it at the host (1 and 1 with `delete_stands` judging only live writes, as before the fix). The same holds for a `nobody` part with a keep-at-most (`part_kept` counts `nobody` kept whatever its bound).

Needs a rule call (spec/sync.md §6 must-hold / must-carry): e.g. a part counts kept for must-carry only while it is more than `MAX_DRIFT` before its keep-at-most (a faster honest node may already have dropped it); or the delete stands while a held, signed reason to drop the part exists (keep-at-most past on some node is not signed, so likely the former).

Also seen: `negative::deletion_across_local_dating_no_churn_spec_sync_6` no longer tests two different death datings: once B syncs it dates X's death at Y like A (its keep-at-least equals A's when the loop starts), so it passes whoever wrote X.

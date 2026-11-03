# A purge request's blob drops early under keep at most 0
> Summary: spec/commits.md §5 keeps a purge request's blobs until `wall_ms(ts) + ROLE_KEEP` "whatever its deltas' keep bounds (at least and at most)"; `check_at_most`'s at-most-0 path ignores that floor and drops the body when its write dies. A device coming later then has no request, so a stale copy of the purged delta can join.
> Tags: engine, security

`check_at_most` (core/engine/src/retention/mod.rs:229): `zero = rel == Some(0) && d.is_some() && !live`, then `t <= now || zero` drops. `body_keep` had already raised `t` to the floor.

Run (throwaway test, deletion module): commit P with retention `writer`, at most 0 after replaced, naming an earlier delta in its purge request; a later write kills P's write. `body_keep` says at least 1707776000000 with now 1700000000000, yet `body_not_dropped(P)` turns false. Other paths (timers, compaction, host deletes) go through `body_keep` and hold.

Fix: `zero` only when the header has no purge list, or compare to `purge_keep_until`.

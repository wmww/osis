# Full outlives the entries it refused
> Summary: A node keeping S unread stays full (spec/sync-streams.md §4 Full) until a refusing cap has room for the least entry it refused, even after every refused entry left its sources (deleted, expired); with nothing else moving it stays full forever, and readers treat it as full: not heard out from it alone, role entries not awaited there, carriers counted held there for deletes.
> Priority: normal
> Tags: sync

The node keeps no memory per refused entry, only the least need per cap (`R/` rows), so it cannot see that what it refused is gone. Most visible with one oversized entry (larger than S's byte cap): full lasts until the cap rises, even once that entry is deleted upstream. Smaller entries arriving meanwhile are still taken; nothing stops syncing, but the full flag misleads status (spec/sync-status.md §1) and the reader's judgement (`read/judge.rs` `role_wait`, `deletes` treating a full source's missing carriers as held).

Directions: end full when a source's stream shows a deletion or expiry of S while full and re-learn by the pull anew (costs a listing per such event); or keep the refused entries' blob IDs per (S, cap) bounded by S's caps, ending full when each leaves the sources that showed it. Needs a spec rule either way.

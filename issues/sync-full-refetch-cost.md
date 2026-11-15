# A full node refetches every refused body per room growth
> Summary: A node keeping S unread that is full (spec/sync-streams.md §4 Full) pulls S again from the start from every source once any refusing cap's room grows (`Store::room_grew` → `ANEW_ROOM`), and fetches every body it lacks, so each entry leaving (one deletion upstream at S's own cap) costs a listing of S per source plus every refused body again, most refused again at once. Under churn at the cap that is O(refused bytes) per change, not O(change).
> Priority: normal
> Tags: sync

Bounded (each round needs room to grow, which needs an entry to leave or a cap to rise; a round with nothing new refuses nothing new), so no loop; it is cost, not a stuck state. Also `room_grew` and `untell_full` poll every tick over the full sync IDs instead of following usage changes (`add_usage`), against rewrite-guidance's effects-on-change.

Fix idea: once room grew, fetch refused bodies newest first only while room lasts (stop the fill of S at the first 12 of the round, staying full with the new room) instead of fetching all; and drive `room_grew` from a usage feed. Both need the spec's Full rule to say the refetch stops at the first refusal.

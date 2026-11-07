# A subgroup's expiring membership strands things with no report
> Summary: Cutting a subgroup out of a synced group by a write reports what it strands (`NotSynced`, `write.rs` `cut_off`). The same cut by its membership expiring reports nothing: verified by a probe (a subgroup added with `expires`, an item in it, the clock past it: `members` empty, no diagnostic).
> Priority: normal
> Tags: api, osis, node

Why not done in the API layer: `cut_off` compares what a label carried before and after one commit it can see coming (`carried_under`). An expiry is not a commit: the engine's `Event::Changed { cause: Expiry, .. }` reaches `osis` after the closure has already changed, so "what was carried" is gone. Fixes to weigh: the engine reports at the expiry, where it knows the closure before; or `osis` keeps a carried set per expiring subgroup membership, more state for a rare case. No correctness depends on it (diagnostics are informational): the items stay on this node and `status` says nothing of them, as for any unsynced thing.

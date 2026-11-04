# After a flip on a dropped body, a reader may hold what every writer dropped
> Summary: on keep at most or expiry, a killing write that turns invalid after every writer dropped the body leaves a reader that kept it reading the old value, and the writers reading without it, until the next write on the aspect. spec/requirements.md Deterministic says "until a writer next compacts", which does not hold here: no writer has it. Needs a rule call.
> Tags: engine, retention, spec

Pinned: `flip_after_drop_only_a_reader_holds_it_lasts_to_the_next_write_spec_sync_7` (osis-node `sync_more`). Writer B overwrites A's value under at most 0, every writer takes that write and drops the value, an admin's lowering of B with a frontier leaving the write out then makes it invalid. A reader that took the lowering first never dropped it. Nothing mends it: writers have nothing to snapshot and a reader's relay is refused, the blob ID being tombstoned. A flagged writer's report reaches only other writers.

Options:
- Reader deposit: a reader that reads a suspect report differing from its own digest deposits a fresh encryption of each body it must hold that the label lacks; a writer takes it as a late part and promotes it (spec/sync.md §5, §7). All read the value again. New rule, no new state; a reader may put back at the host a value a writer deleted, until a writer judges it.
- State the limit in the requirement: "until a writer holding it next compacts, or the next write".
- Rejected: a node dropping what a newer snapshot lacks. A snapshot's silence says "dead or never received" (spec/crdt.md §8), so this would drop live late writes, and here the writers hold no state to snapshot at all.

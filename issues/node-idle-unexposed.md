# Per-node idle: specified, not built
> Summary: spec/sync-status.md §3 defines per-node idle (no request, fill or Hello outstanding on any connection); nothing builds or exposes it, and `wait_synced` and `status` cover what a user observes: drop the clause and its two references.
> Priority: low
> Tags: sync, status

Idle is a fact about protocol traffic in flight, not about data: no model concept rests on it, and a point-in-time fact the next event may end is only a poll. What a user observes of sync is `status` per thing and `wait_synced` (heard out, own commits held elsewhere). Proposed spec edits:
- spec/sync-status.md §3, first item: end it at "the recorded peers it waits for." (drop "; and per node, idle when ... is not idle)").
- spec/sync-opens.md §1: "a connection up but without the peer's Hello is no peer yet." (drop "(and the node is not idle while it waits, spec/sync-status.md §3)").
- spec/sync-hostile.md: "A peer that drops what it pulls cannot keep a node's sync IDs from caught up: lacking counts only what a source pulls."

# A purge applied before its requester's demotion arrives stays
> Summary: spec/permissions.md §8 says a request drops a delta iff its author held the right at its time. A node holding the delta and request, then the demotion that took the right before the request's key, has dropped the body and keeps its writes value-less for good; a node that got the demotion first keeps the body. Arrival order decides. Same for every class, not new with the purge sets. A compaction snapshot's right has the same window.
> Tags: engine, permissions

Test: `retention::purge_rights_any_arrival_order_spec_perm_8` pins it (orders with the demotion last). `on_late` re-drops a held value-less part "even if the purge that made it so is no longer judged allowed", so a copy arriving again does not undo it.

Fix to weigh: re-judge purges of an aspect when the requester's timeline changes, take the delta out of the value-less list and take the body again from a holder (a dropped body counts as never received). The cost is a re-join path on every timeline change; the harm is one stale requester's drop at nodes that had not heard yet, and fresh holders still serve it. The order oracle has no purge step, so it would not see this.

Snapshots: a right holder that drops a body under a snapshot and then learns that its actor had lost the right at its key has dropped it too (and may have deleted it at hosts). Reads stay alike, since the snapshot stays valid and carries the live writes; only history differs. `snapshot_right` itself judges alike in every order (`retention::snapshot_right_any_arrival_order_spec_commits_5`). `uncover` does not ask for the right: a right-holding snapshot superseded by another writer's must keep its drops. So a part falling back needs another way to tell a stale drop.

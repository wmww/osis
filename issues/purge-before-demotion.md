# A purge applied before its requester's demotion arrives stays
> Summary: spec/permissions.md §8 says a request drops a delta iff its author held the right at its time. A node holding the delta and request, then the demotion that took the right before the request's key, has dropped the body and keeps its writes value-less for good; a node that got the demotion first keeps the body. Arrival order decides. Same for every class, not new with the purge sets.
> Tags: engine, permissions

Test: `retention::purge_rights_any_arrival_order_spec_perm_8` pins it (orders with the demotion last). `on_late` re-drops a held value-less part "even if the purge that made it so is no longer judged allowed", so a copy arriving again does not undo it.

Fix to weigh: re-judge purges of an aspect when the requester's timeline changes, take the delta out of the value-less list and take the body again from a holder (a dropped body counts as never received). The cost is a re-join path on every timeline change; the harm is one stale requester's drop at nodes that had not heard yet, and fresh holders still serve it. The order oracle has no purge step, so it would not see this.

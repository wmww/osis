# A permanent header-only group.0 part stops outside-closure deletion
> Summary: node-sync judges nothing outside a label's closure while a closure group holds part of its `group.0` as a header only (`Engine::closure_whole`, spec/sync.md §6). Where no node holds that body any more, the part never fills and those nodes never delete outside-closure entries of the label again: they stay at hosts.
> Priority: low
> Tags: sync, ephemeral

- How a hole becomes permanent: snapshot S2 covering S1 falls with its author's demotion; the demoter never held S1 (lagging device) and every other holder dropped S1 under S2 (spec/permissions.md §5.2 Limit). Missing parts are never forgotten (spec/commits.md §5 Forgetting needs them covered), and later compactions stop their frontier walk at the gap, so nothing covers it.
- Before the guard, such a node deleted outside-closure entries while a holder that still read the thing placed them again until it re-logged the listing (a storm, `header_only_list_keeps_what_it_may_list_spec_sync_6`); the guard trades that for this leak.
- Possible bound, in the shape of Forgetting: a header-only part none of whose commit's entries this node knows, and no delete of one within `TOMBSTONE_LIFETIME`, counts as gone (not listing). A holder coming back after that re-logs it and the hole fills; deletes meanwhile are one round, not a loop. Needs node-sync's per-commit entry and tombstone knowledge in the judgment.
- Also unexamined: a header-only part whose writes are past their expiry lists nothing and could count as absent.

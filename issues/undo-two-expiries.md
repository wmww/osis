# Undo that would need two expiries
> Summary: An undo copying back a value expiring beside one that does not (or two expiring at different times) is refused until the sooner has expired, and undo is stuck in that scope meanwhile. Decide whether it should be several commits under one revert instead, which needs revert to act on siblings.
> Tags: api, engine, spec

Reached by a commit writing two or more aspects, where one's earlier value expires and another's doesn't. Refused, nothing applied, naming both; nothing older is undone instead; works again after the sooner T (test `undo_needing_two_expiries_waits_spec_crdt_4_6`).

The alternative is one undo commit per expiry, each naming the undone commit. That alone gives half a redo: redo and the next undo revert one commit, `pick` chooses one, so `revert_one` must treat commits of one `ts` naming one target as one revert, at every depth, and a peer may hold one of them alone. It also breaks "an undo commit" as spec/commits.md §7 and spec/crdt.md §4.6 say it.

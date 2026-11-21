# A received move-and-insert delta drops a paged text's stored placement
> Summary: engine pages: a received delta (made against an older state) holding a move then an insert, joined in a new session, is not followed through the stored placement: the write invalidates it, so the next read by index lays the sequence out anew.
> Priority: normal
> Tags: tests, engine

`engine::pages::tests::seq_cold_edits_keep_placement_plain_spec_crdt_6_1` (its random plan) fails at every seed tried (0, 1, 517, 518) with `step N: placement kept (writer 1: ["move a l b", "insert c n"])`: the set's placement is `Place::Missing` after `write_touched` (`invalidate_placement`: the join did not follow the cached placement). The default test's plan never makes that commit, and the seeds the test was pinned to (187, 189) never did either.

Reproducer to build: the default test's text, one received delta of `Move` then `Insert` in one commit, made against a state a few writes old.

Open: whether the follow should keep the placement here (spec/crdt.md §6; notes/engine-paged.md lists a follow miss as an invalidation, at the cost of a whole layout), or the test claims too much for received deltas.

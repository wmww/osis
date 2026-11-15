# link-join-held
- `World::advance` flushes everything in flight, so a test can't cut a peer off between one node's write and its delivery; `World::step_or_wake` (one input or one wake) added for that.
- A test passing for the wrong reason: the follow-time test's "joined, the join not held" held only because `Status::held` waited on D (no source for a one-node account), not on the partition; the join had already reached the sharer.
- `cmd1 && git commit -qm wip && python edit` silently skips the edit when there is nothing to commit (exit 1).
- Several tests passed only because a redeemer followed its link forever (a key actor proven to everyone, K's sync ID always synced, the sharer always a dial hint): a removed node learning its removal, a hint test, a joiner surviving the sharer's rotation. Each took a trace against the base to find.
- Review: two more tests (`flows::writers_of_two_accounts_keep_each_others_certificates`, osis `sync::an_outsider_reads_the_accounts_writes_across_a_node_removal`) failed on the branch and were not reported: run `-p osis` and the whole `-p osis-sync` before handing off whenever what syncs or is forgotten changes.

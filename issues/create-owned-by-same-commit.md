# A thing cannot be created under a thing created in the same commit
> Summary: The local commit check refuses (`Permission`) a `create` whose owner is another thing created in the same `Write` batch, so a tree of new things takes one commit per level; apps (and the permutation test in osis-node `apply/tests_order.rs`) work around it with separate commits.
> Tags: api, node

Repro: a `Write` that creates A then creates B owned by A; the commit fails with `Permission` from the local rights check, which does not yet see A's `/created` in the batch.

Fix idea: the local check resolves owners through the batch's own pending creations (the engine already applies the batch's writes in order at commit). Not a wire matter.

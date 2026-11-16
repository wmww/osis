# TLA models that no longer model the design
> Summary: Two TLA models check mechanisms the design replaced: core/test/tla/rotation/Account.tla (seeds under D epochs, thing lists for D; cut it to descent over the chain or delete it) and the sides model's replacement-sync-ID fork form (drop it, keep HostBranch). Rerun under tools/heavy after each change.
> Priority: low
> Tags: tests, sync, engine

## Account.tla models the old D-list seed placement
core/test/tla/rotation/Account.tla checks descent (an epoch covers a removal only descending from its rotation) but models seeds in D's `account.0` under D epochs, thing lists for D and `Met`, which the chain roster and seed boxes replaced (notes/account-forks-design.md); roles-model `custody` checks the current mechanism. Cut the model to descent over the chain, or delete it.

## The sides TLA model still has a replacement candidate
core/test/tla/sides models fork candidate (c) with the loser making a replacement sync ID R (Fork without HostBranch). A sync ID is never replaced (spec/sync-ids.md §2: two admins' steps form a tree), so only the HostBranch form models the design. Drop the replacement form (configs, README rows, ASSUMPTIONS "Fork (c)") and rerun the matrix under tools/heavy.

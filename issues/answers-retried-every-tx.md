# Answers waiting on delete keys are recomputed every transaction
> Summary: `answer_removals` and `answer_rotations` recompute every due answer at the end of every durable transaction; one waiting for a thing's minting or delete keys (`write::MayWrite::Later`) is rebuilt in full (demoted pairs and their commits, or the epochs' commits) only to wait again. Per-transaction cost grows with the waiting answers and their history, not with what changed. Purge-on-replace covers wait in `Indexes::cover_waits` and wake from the transaction's journals (`retention::replace::wake_covers`); answers do not.
> Priority: low
> Tags: permissions, engine

## Direction
One wait for every own write: key the waiting answer (removal or rotation commit) under the record chain of the thing that was `Later`, beside covers (generalise `cover_waits` to a waiter enum), and skip a parked answer until `wake_covers` wakes it; not persisted, so an open tries each due answer once. A rotation also waits while pending or while its epoch's seed is missing: those need their own wake (account commits) or stay retried per transaction.

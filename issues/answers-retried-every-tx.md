# Answers waiting on delete keys are recomputed every transaction
> Summary: `addenda::write_owed` recomputes every due answer at the end of every durable transaction; one waiting for a thing's minting or delete keys (`write::MayWrite::Later`) is rebuilt in full (the removal's candidates) only to wait again. Per-transaction cost grows with the waiting answers and their history, not with what changed. Purge-on-replace covers wait in `Indexes::cover_waits` and wake from the transaction's journals (`retention::replace::wake_covers`); answers do not.
> Priority: low
> Tags: permissions, engine

## Direction
One wait for every own write: key the waiting answer (removal or rotation commit) under the record chain of the thing that was `Later`, beside covers (generalise `cover_waits` to a waiter enum), and skip a parked answer until `wake_covers` wakes it; not persisted, so an open tries each due answer once. A rotation also waits while pending or while its epoch's seed is missing: those need their own wake (account commits) or stay retried per transaction.

## Failed answers
An answer whose step fails (`OwnWriteFailed`) stays due the same way: retried, and reported again, at the end of every later durable transaction. A failure that repeats on the same state (an engine bug) never succeeds until the state moves, so it costs a rebuild and a diagnostic per transaction meanwhile: for a listing that is one built, signed, sealed and rolled-back commit per thing it names. No loop or wake: it runs only when something else commits. The same park fixes it: a failed answer waits for the next change to what it reads (or the next open), not the next transaction.

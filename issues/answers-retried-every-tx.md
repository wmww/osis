# Answers waiting on delete keys are recomputed every transaction
> Summary: `addenda::write_owed` recomputes every due answer at the end of every durable transaction; one waiting for a thing's minting or delete keys (`write::MayWrite::Later`), or one whose write failed (`OwnWriteFailed`), is rebuilt in full only to wait or fail again. Per-transaction cost grows with the waiting answers, not with what changed.
> Priority: low
> Tags: engine, perm

Purge-on-replace covers already wait right: `Indexes::cover_waits`, woken from the transaction's journals by `retention::replace::wake_covers`. Fix: one wait for every own write. Key a waiting answer under the record chain of the thing that was `Later` (generalise `cover_waits` to a waiter enum) and skip it until `wake_covers` wakes it; a failed answer waits for the next change to what it reads. Not persisted: an open tries each due answer once. A rotation waiting on a pending epoch or a missing seed needs its own wake or stays retried.

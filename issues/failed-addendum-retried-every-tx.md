# A failed addendum is decided again every transaction
> Summary: `addenda::decide_due` wants every removal whose judgement or addendum write failed (`OwnWriteFailed`) again at the next call, so `write_owed` re-decides it in full at the end of every durable transaction until it succeeds. Per-transaction cost grows with the failing removals, not with what changed.
> Priority: low
> Tags: engine, perm

A decide that waits (a thing outside the node closure, minting or keys not arrived) is stamped by its reads and decided again only when one moves (`decide`); a failure has no read to wait on. Fix: a failed decide waits for the next change to what it read, as a waiting one does. Not persisted: an open decides each followed removal once.

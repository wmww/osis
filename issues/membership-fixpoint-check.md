# Model-check the membership validity fixpoint
> Summary: The validity definition in notes/permissions.md (membership timeline in claimed-time order, iterated with the receipt condition for finally-revoked actors) is conjectured to terminate with a unique result; verify by exhaustive/random small histories before implementing it.
> Tags: tests, permissions, security

Generate small histories of grants, revokes, hand-overs and receipts (2-4 admins, skewed clocks, offline periods). Check: the iteration terminates; the stable result is unique and independent of the order in which writes are dropped; mutual removal resolves to the earlier timestamp; a backdated revoke from a removed device is cancelled by the owner's further-backdated revoke. If a counterexample appears, the definition needs stratification or a different base.

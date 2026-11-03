# A stranger can hold an inbox's deposit budget for good
> Summary: Neither host nor node bounds a deposit's expiry (none, or years ahead), and no node path deletes junk, so someone with an actor's public keys fills the budget once and grants through it wait until an admin clears it by hand; spec/requirements.md states the limit.
> Tags: security, node-sync, host

A stamp already refuses a far expiry (`stamp_inbox`). What stays open: the budget itself. A host cannot tell an inbox blob from another deposit, so it cannot apply `INBOX_LIFETIME` without a spec rule on every deposit's prefix expiry; a writer could instead delete deposits under an inbox label that open to nothing or expire too far ahead (spec/sync.md §3 allows admins to). The owner's call on what a stranger may hold decides which.

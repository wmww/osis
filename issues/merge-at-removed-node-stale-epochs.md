# A removed node ingesting the merge leaves its epochs unjudged
> Summary: debug assertion "stale validity left unjudged" (`ix.epochs_due` holds the account) at a removed node that ingests the merge rejecting its own rotation.
> Priority: normal
> Tags: engine, accounts, tests

## Shape
`rotation::tests_signing` world(3, 3): node 2 removes node 1 (`remove(&mut lp, 2, a.devices, 1)`); node 0 removes node 2; node 0 gets node 2's two commits and calls `signing_due` (a D re-key, then the merge); sending the merge to node 2 panics in `ingest_with_lists` (engine/mod.rs, the end-of-transaction check). With node 2 only rotating (`rotate_in`) instead of removing node 1 it passes.

## Why
Unknown: something after `refresh_epochs` in the transaction marks the account due again (node 2 does not hold the merge's parent R, so the merge is pending there).

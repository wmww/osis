# Storage audit: arms of the release test still missing
> Summary: Every stored row should have an owner and releasing everything should return a node's storage to a fresh node's (notes/node-closure.md, Storage owners). The growth tests' own-things, expiry, held-history, grant, decline and redeem arms pass; a purge, an admin dispute, a retained copy and a dependent thing leaving the closure while its carrying sync ID stays are untested. Set tombstones that outlive releases are issues/zero-growth.md's; work per round over what is kept a bounded time is issues/many-sync-ids-cost.md's.
> Priority: normal
> Tags: sync, engine, retention

## Releasing everything
Bounded leftovers once a node releases everything (notes/node-closure.md, Storage owners): inbox fires for the history setting (`INBOX_LIFETIME`; issues/stranger-fire-bounds.md), a link's sync ID while redeemed, role changes under a former grantee's sync ID for `ROLE_KEEP`, tombstones for `TOMBSTONE_LIFETIME`, peer records within `RECORD_BUDGET`. Anything else left is a bug.

## Owed
One count test arm per case, in osis-sync `growth::`: a node holding a thing with a purge, with an admin dispute (`sides`), with a retained copy, and a dependent thing that leaves the node closure while the sync ID that carried it stays (spec/sync-set.md §3: released), each released; store rows and bytes by family equal a fresh node's that synced nothing, and re-syncing reads as a node that never left.

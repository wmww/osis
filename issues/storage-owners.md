# Storage audit: re-syncing after releasing everything
> Summary: Every stored row has an owner and releasing everything returns a node's storage to a fresh node's (notes/node-closure.md, Storage owners): osis-sync `growth::` checks it for own things, expiry, held history, grant, decline, redeem, purge, admin dispute, retained copy and a dependent thing leaving while its sync ID stays. Untested: that a node syncing a thing again after releasing it reads as one that never held it. Set tombstones that outlive releases are issues/zero-growth.md's; work per round over what is kept a bounded time is issues/many-sync-ids-cost.md's.
> Priority: normal
> Tags: sync, engine, retention, tests

## Releasing everything
Bounded leftovers once a node releases everything (notes/node-closure.md, Storage owners): inbox fires for the history setting (`INBOX_LIFETIME`; issues/stranger-fire-bounds.md), a link's sync ID while redeemed, role changes under a former grantee's sync ID for `ROLE_KEEP`, tombstones for `TOMBSTONE_LIFETIME`, peer records within `RECORD_BUDGET`. Anything else left is a bug.

## Owed
Per arm of `growth::` (`two_as_fresh` worlds), the node reached again by a strong after its release: what it reads (values, roles, disputes and their sides) equals what a node of the same account syncing the thing for the first time reads. A side recorded before the release goes with its removal (spec/permissions.md §5.1), so the re-synced node judges it afresh.

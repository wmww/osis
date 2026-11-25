# Storage audit: arms of the release test still missing
> Summary: Every stored row should have an owner and releasing everything should return a node's storage to a fresh node's (notes/node-closure.md, Storage owners). The growth tests' own-things, expiry and held-history arms pass; the grant, decline and redeem arms fail on accounts as ordinary things (below); untested: a purge, an admin dispute, a retained copy, and a dependent thing leaving the closure while its carrying sync ID stays. Set tombstones that outlive releases are issues/zero-growth.md's.
> Priority: normal
> Tags: sync, engine, retention

## Releasing everything
Bounded leftovers once a node releases everything (notes/node-closure.md, Storage owners): inbox fires for the history setting (`INBOX_LIFETIME`; issues/stranger-fire-bounds.md), a link's sync ID while redeemed, role changes under a former grantee's sync ID for `ROLE_KEEP`, tombstones for `TOMBSTONE_LIFETIME`, peer records within `RECORD_BUDGET`. Anything else left is a bug.

## Failing arms (ignored on this issue, osis-sync `growth::`)
Each node acts for an account (its own node thing signing); the first symptom of each, not probed further:
- `a_granted_and_revoked_thing_returns_storage_to_a_fresh_worlds_spec_sync_set_3`: the grantee, after 1 round, keeps an `ou/` row (`records::OPENED_UNDER`) of a commit opened under its account's epoch.
- `a_declined_grant_returns_storage_to_a_fresh_worlds_spec_sync_set_3`: storage matches; read's judgements per round grow a few percent over the rounds (`flat_work`: rounds 2-4 892, the last three 914).
- `a_redeemed_and_ended_link_returns_storage_to_a_fresh_worlds_spec_sync_set_3`: the maker, after 1 round, keeps a `bp/` row (`sync::bodies::BLOB_PARTS`) of the grantee's account's minting commit (its record and key part, which the redeem brought).

## Owed
One count test arm per case, in osis-sync `growth::`: a node holding a thing with a purge, with an admin dispute (`sides`), with a retained copy, and a dependent thing that leaves the node closure while the sync ID that carried it stays (spec/sync-set.md §3: released), each released; store rows and bytes by family equal a fresh node's that synced nothing, the work flat between n and 10n of what stays, and re-syncing reads as a node that never left.

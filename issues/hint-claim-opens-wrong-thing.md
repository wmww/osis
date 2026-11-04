# A host can open a hinted label under the wrong thing by claim
> Summary: a host a sender names, holding the label's real path, can answer a hinted open with a step, then take the claim: the label is Open under the sender's thing there, and on an older connection `group_of` reads the real host's data under it, seen as a Fetch loop. Traced, not run.
> Tags: node-sync, security

`opened` checks a sync key against the head (spec/sync.md §3), but a claim cannot be checked: the client has no claim set for the host's step. So with a host of its own and the real path (a past reader's, say), a connected sender gets `Phase::Open` under its thing X at that host. `group_of` takes the first Open connection, so if that connection is older than the real host's, entries from the real host do not open under X. With the same wrong `group_of` before the fix, the node sent Fetch to the real host without end (`hint_at_a_silent_host_does_not_hold_off_the_group`, one Fetch per 2 ms until the test's bound).

Two separate things to fix: a Fetch loop when entries do not open should not exist under any group, and `group_of` should judge per connection (the callers holding a `conn` can pass it).

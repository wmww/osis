# A sibling never reads what its account joined by a link
> Summary: node 1 redeems node 0's card, filing K0 and p0 under D1 (a redeem is an accept); its sibling node 2 never gets K0's role commits, so K0 and p0 count as plain there (`thing_sync` Plain, `role_on(p0)` None) and the account's join reaches only the redeeming node.
> Priority: normal
> Tags: sync, engine

- Seen: siblings fixture run to quiet past a pass: node 1 reads p0 (`ThingSync::Read`), node 2 does not; node 2 syncs K1, p1 and D1 only.
- K0's keyset is a role commit on another thing than D1's actor: under D1 it travels only as a per-sync-ID copy (spec/sync-judgement.md §1), which nobody logs, and node 2 cannot open K0's own sync ID before it holds that keyset (spec/sync-set.md §2: a thing whose keyset commit is not held counts as plain). Find which rule should bring it (a copy under D1 logged by the joiner, or K0's sync ID reachable from the filing) and test that a sibling reads a joined link's target.

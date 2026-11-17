# keel-ticket-chain
> Summary: Mishaps while building the ticket-word rule and the sync-unbuilt security items.

- Task 1 went through three rules. "Reaches by any path" for every word broke seed 68's test (a sync ticket beside a removed holder's commits). The reviewer's rule (a word counts only with no role commit of T held; D's tickets never) broke T7 with `Core::keyed` as the roster test, five tests with the D clause (spec/sync-set.md §1 relies on D's tickets), and full-size differential seed 24 with "any held role commit" as the roster test. Kept: sync words count, read words while no held role commit reaches the holder.
- Pending by drift is transitive (HLC): a co-admin's step after a drift-pending refresh is pending too, so the keys.0 wait's exploit needs two refreshes, not a relayed step. A missing `keys.0` part was already covered by `deposit_seed_of`.
- Background runs racing my own edits gave stale failures twice; a main rename (`home_sync_id`) broke a new test after rebase. Full-size differential seeds 23 and 95 fail on main (6b073f142) too.

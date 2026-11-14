# Engine tests that pass or fail with the store's random draws
> Summary: Two engine tests flip with how many random values the store draws per commit (the store shares its rng with record ids, nonces and the node log incarnation): extra draws, or the store as built (a key tree as tall as its slots need draws fewer node keys), fail them. Each asserts an order or a count that random ids decide. The old sync's tests of this kind (and a real redeem flow failure, `sharing::redeem_after_a_joiner_left_spec_permissions_7`, at 1dcacb6b0) went with it: the rebuilt sync's tests must not depend on the store's draws.
> Priority: normal
> Tags: tests, engine

Reproduce: add `for _ in 0..k { let _ = Secret32::random(rng); }` at the top of `Pager::commit_inner` and run them (k = 2 fails the first).
- engine `order::kill_and_purge_in_one_commit_keeps_leftover_spec_commits_5` (k=2): the leftover is dropped as covered.
- engine property `validity::unmerge_paged_matches_fresh_large_spec_crdt_4_6` (deterministic, no seed; fails at the store's draws as built and at 1, 3, 5 extra draws, passes at 2 and 8): `rejudge: rebuild` counts 7, not one per flipped aspect (5). The re-judged set (`flipped`, core/engine/src/apply/validity.rs) holds two more aspects for some draws: an engine count, not old sync, so it outlives the rewrite; find which two aspects flip and whether that is right.

Each should pin what it means or the property should hold for every draw. Both are listed in tools/known_failures.txt.

# A deposited redemption in the link race is never promoted
> Summary: `link_race` seed 9: a link key's deposited membership commit (`/members`, `/secrets`, author = actor = the link key) sits under K's label unstamped at quiescence ("deposited ... not promote"). Fails with and without the race-winner fix, so it predates it.
> Tags: sync, tests

- Repro: `osis_sim::replay("link_race", 9)` (step 60). Probably the loser's redemption, invalid at the writer once L left: the promotion rule or the invariant should treat a deposited invalid commit as not must-hold (or delete it), not leave it.

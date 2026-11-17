# Purge floors at exact `ts` ties
> Summary: A purge floor is a setting's `ts`, so two concurrent settings at one exact `ts` (two admins, same ms and logical) make the join's skip ambiguous: a node holding the purging one and a later setting carrying the floor, but not the tied one, purges more than a node holding the later one alone. Floors as `(ts, author)` would order them as writes are.
> Priority: low
> Tags: engine, security

spec/commits.md §5 One way skips a purging setting X when a held floor is past `X.ts`. A floor equal to `X.ts` may be X's own (X ended an earlier purge: X's end still counts) or a concurrent setting Y at the same `ts` ending X (X's end already covered); the rule takes the first. Held-model `a_carried_join_makes_older_settings_add_nothing` leaves out worlds with two concurrent settings at one stamp for this. A writer holding a setting always stamps after it (HLC), so only concurrent settings tie.

Fix: `purge_before` as the ending setting's `(ts, author)`, compared with a dead write's `(ts, author)`; one author's commits have distinct `ts`, so a floor names one setting.

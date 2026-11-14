# A reader gets a grant copy kept for every thing it shares with the group
> Summary: A group's inbox holds its grant copy for each thing an edge write names the group on (spec/sync-inbox.md §5), whoever wrote the edge. A reader is admin of its own things, so it can mint things and grant the group a role on each: every such grant joins the group's sync ID's required set and its writers log it stamped. Unbounded in count; little chosen content per grant (one edge each).
> Priority: normal
> Tags: security, sync, tess-call

**Tess question:** should a reader's grant of a role to the group be kept only once a writer or admin accepts it, or should requirements' "small budget" for readers count such grants like other readers' changes?

Repro: osis-engine `readers_reach::a_readers_grants_to_the_group_stay_within_the_budget_spec_sync_inbox_5` (ignored): reader peer 1 of group g grants g read on 40 things it mints; at writer peer 0 all 40 grants have a body under g's sync ID (`sync_bodies`), against `DEPOSITS_WAITING` 32.

Promotion is closed: it needs the author's write on S's actor and a body S's closure carries, so the reader's deposited grant is never promoted (`readers_reach::a_readers_grant_to_the_group_is_not_promoted_spec_sync_inbox_4`). Sharing a thing with the group does not put the thing in the closure (`group.0` only, which a reader cannot write), so a reader's later writes on it are not kept either. Only the grant copy (the edge write, and each rotation's box to the group) is.

Why grant copies take every edge write: the group's other and later nodes, and a link's redeemers, find a grant whenever they come online, and honest members share things with the group. One copy per (actor, thing) already stops churn on one edge (a newer edge write replaces the older copy).

Directions (the minted-things case needs the requirements answer):
- Only writers' or admins' grants to the group get grant copies; a reader's waits for a writer's acceptance.
- Or requirements' "small budget" counts sharing like other readers' changes.

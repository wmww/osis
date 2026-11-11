# A reader gets a grant stamped for every thing it shares with the group
> Summary: Promotion takes a role commit's edge write or box naming a closure thing as holder, at any thing. A reader is admin of its own things, so it can mint things and grant the group a role on each (or rewrite one such edge again and again): every such commit is stamped under the group's label and kept (may-hold). Unbounded in count, bounded only by the deposit rate; little chosen content per commit (one edge each).
> Priority: normal
> Tags: security, sync, tess-call

Probe: `promotion::a_readers_grants_to_the_group_stay_within_the_budget_spec_sync_5` (ignored; 39 of 40 stamped, about 700 B each, plus the promoter's copies of each creation).

Not the shape the question first suggests: sharing a thing with the group does not put the thing in the label's closure (`group.0` only, which a reader cannot write), so a reader's later writes on it are not promoted. Only the grant (and each rotation's box to the group) is.

Why it is promoted at all: a grant to the label's actor or its removal must reach the group's readers (`tied::group_removal_deposit_promoted_without_new_keys`), and honest members share things with the group. Same class as issues/promotion-minted-key-actor-cards.md (a reader makes, at will, items the label must hold one commit each), but account-signing step 7 does not remove this one.

Directions:
- Churn on one edge: promote only the newest valid write of an edge naming a closure thing (as for cards); boxes stay (old epochs need them).
- Minted things: needs a requirements answer: either a member's sharing with the group is a write the group accepts (only writers' or admins' grants to the group are kept, a reader's waits for a writer's acceptance), or the requirement's "small budget" counts sharing like other readers' changes.

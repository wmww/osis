# A reader gets a grant stamped for every thing it shares with the group
> Summary: Promotion takes a role commit's edge write or box naming a closure thing as holder, at any thing. A reader is admin of its own things, so it can mint things and grant the group a role on each (or rewrite one such edge again and again): every such commit is stamped under the group's sync ID and kept (may-hold, spec/sync-inbox.md §4). Unbounded in count, bounded only by the deposit rate; little chosen content per commit (one edge each).
> Priority: normal
> Tags: security, sync, tess-call

**Tess question:** should a reader's grant of a role to the group be kept only once a writer or admin accepts it, or should requirements' "small budget" for readers count such grants like other readers' changes?

Measured on the sync before the rebuild: 39 of 40 stamped, about 700 B each, plus the promoter's copies of each creation. No test of the rebuilt sync probes it yet.

Not the shape the question first suggests: sharing a thing with the group does not put the thing in the group's closure (`group.0` only, which a reader cannot write), so a reader's later writes on it are not promoted. Only the grant (and each rotation's box to the group) is.

Why it is promoted at all: a grant to the sync ID's actor or its removal must reach the group's readers, and honest members share things with the group. Same class as issues/promotion-minted-key-actor-cards.md (a reader makes, at will, items the sync ID must hold one commit each), but account-signing step 7 does not remove this one.

Directions:
- Churn on one edge: promote only the newest valid write of an edge naming a closure thing (as for cards); boxes stay (old epochs need them).
- Minted things: needs a requirements answer: either a member's sharing with the group is a write the group accepts (only writers' or admins' grants to the group are kept, a reader's waits for a writer's acceptance), or the requirement's "small budget" counts sharing like other readers' changes.

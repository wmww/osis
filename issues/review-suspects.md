# Small open questions from the review since the sync rewrite
> Summary: Design questions left by the review since the sync rewrite, each with options: a writer's card pointing strangers at an earlier inbox (or frozen by an unverified commit), the boxed/unboxed split after a demoted admin's plant, the public's role kept on a stale certificate; plus a revoked store never reopened, for the opening design.
> Priority: normal
> Tags: engine, keys, security, tess-call

## A writer's card can point strangers at an earlier inbox (security)
A's inbox is an admin's `keys.0` field, but a card is written by any writer of A along a path through A and carries whichever of A's `keys.0` commits its writer picks. `refresh_card` rewrites a card only when a rewrite would carry, per thing, a `keys.0` commit newer by `ts` than the card's newest (`cards::carried`). Two ways a writer of A defeats that:
- carry the commit naming inbox I1, omit the admin's later move to I2, keep A's newest commit (a rotation): nothing newer per thing;
- add any commit that decodes with a `keys.0` part on A and a high `ts`: `carried` never verifies it, so the card looks newest to every honest node for good, while strangers take only its judged commits (an older state).

Either way a stranger holding only that card fires grants to A at an older inbox. Bounded: only an inbox an admin once chose, only at parties holding no newer `keys.0` of A, and a fire is sealed to A's keys (I1's readers learn the grant, not the secrets). The rule must settle across a fork: each side's current commits differ, so "rewrite any card lacking a commit current here" makes the sides rewrite each other's card forever.

Options:
1. **Per field, newest `ts`, signature-verified commits only**: stale iff for some `keys.0` field of A or its inbox, this node's current commit for it is newer than every verified card commit writing that field. Each rewrite raises some field's newest `ts`, and no side's own validity verdict enters, so the sides do not fight (a side leaves a card the other side wrote newer). Closes both attacks above. A removed admin's verified, later commit naming an old inbox still blocks rewrites, but readers judge it invalid, so the bound stays an inbox an admin once validly chose. Needs reading which fields each part writes.
2. **Union rewrite**: a rewrite keeps the card's commits and adds this node's current ones; stale iff it would add one. Monotone, and a stranger merging the commits sees the newest inbox. The card grows with every `keys.0` commit ever written, and pruning brings the fork fight back.
3. Accept the bound as stated (a stranger may fire at an inbox an admin once chose) and fix only the unverified-commit hole.

## Dependent box after a demoted admin's plant
An admin's step and box on a dependent Y with no keyset, the admin demoted after the plant, stays valid (judged at its point): Y counts independent at the boxed node and dependent elsewhere, for good (`tests_planted::an_admins_step_counts_at_the_boxed_node_after_its_demotion_spec_sync_set_2`). Nothing reconciles the two (the planted epochs are never established, so nothing re-seals). Hostile admin only; a rotation by an honest admin makes Y independent everywhere.

Options:
1. **Step and box count only at a node that reads no role commits** (spec/sync-set.md §2 Counts as independent): the clause exists for a node keeping Y unread, which cannot read keyset parts. A node holding a read secret of Y counts it independent by a keyset alone, so the boxed reader counts Y dependent like everyone and the content split goes; a sync-only node keeps Y's planted sync ID, which splits storage, not reads.
2. Keep as is: a stated, hostile-admin-only split (a low "strict model violation" issue).
3. Make the step alone count everywhere: the nodes without a box then hold no secret of Y's independent epoch and read nothing of Y. Worse than the split.

## The public's role on a stale certificate
`rotation::lost::role_here` counts the public's role wherever the node holds the public's grant, synced or not (spec/sync-set.md §2 Own things: "but for the public's"), and the lost-access drop judges by that role. A node that stops syncing A (unreached, unsynced), holding a public grant of A only as another commit's certificate, never receives the public's removal, so it keeps every secret of A for good: its own sealed history epochs included, which the public (granted without history) never had. The comment on `role_here` ("an outdated grant held gives only the open boxes") holds for boxes taken, not for secrets kept. Harm: no read (A's content goes with the unsync), but secrets of A stay with nothing synced to attribute them to, against "unsync all → zero". The exception exists so a node enters a public thing a strong reaches without a stub or signal.

Options:
1. **The public counts where A's grants count**, like any holder: drop the exception, and give entry to a public thing reached by a strong another way (its stub in the carrying unit, as for any granted thing). Removes a carve-out; needs checking that every route into a public thing still brings its stub.
2. Keep the exception for entry and the closure walk, but judge the lost-access drop by `role_by_grants` without it: the node keeps only what A's grants as synced give. Two roles where there was one.
3. Keep as is and correct the comment.

The opening design (notes/opening-design.md) changes the public's other source of role (`public_listed`, Holders by copies): decide after it lands.

## A revoked store never reopened (latent, no reproducer)
After a revocation nothing reopens S at a store whose credentials and `changed_at(S)` did not move, so it is never tested again (spec/sync-opens.md §5 Testing) and keeps S's entries. Rewritten by the opening design (notes/opening-design.md): judge against its open rule once it lands.

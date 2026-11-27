# Small suspects and open questions from the review since the sync rewrite
> Summary: Leftovers of the review of everything since the sync rewrite, each too small for an issue of its own: a writer's card pointing strangers at an earlier inbox, the boxed/unboxed split after a demoted admin's plant, two unreproduced suspects, a revoked store never reopened and stale status sources.
> Priority: normal
> Tags: engine, keys, security

## A writer's card can point strangers at an earlier inbox (security)
A's inbox is an admin's `keys.0` field, but a card is written by any writer of A along a path through A and carries whichever of A's `keys.0` commits its writer picks. A card carrying an older commit that named inbox I1 and omitting the admin's later move to I2 (keeping A's newest commit, so the per-thing newest-`ts` staleness test of `refresh_card` sees nothing newer) leaves a stranger holding only that card firing grants to A at I1, and no honest node rewrites it. Bounded: only an inbox an admin once chose, only at parties holding no newer `keys.0` of A, and a grant fire is sealed to A's keys, so I1's readers learn the grant, not the secrets. A rule rewriting any card lacking a commit current at the node does not settle across a fork (each side's current commits differ, so the two sides rewrite each other's card forever); a fix needs a staleness rule that is monotone across sides.

## Dependent box after a demoted admin's plant
An admin's step and box on a dependent Y with no keyset, the admin demoted after the plant, stays valid (judged at its point): Y counts independent at the boxed node and dependent elsewhere, for good (`tests_planted::an_admins_step_counts_at_the_boxed_node_after_its_demotion_spec_sync_set_2`). Nothing reconciles the two (the planted epochs are never established, so nothing re-seals). Hostile admin only; a rotation by an honest admin would make Y independent everywhere. Decide whether the step alone should count, or only with a keyset.

## Suspects not reproduced
- **The public's role wherever held** (`rotation::lost::role_here`) also feeds `may_take`/`readable` for the node's own sealed boxes, so a public grant whose removal the node lacks could keep a removed reader's sealed secrets. Harmless if a role through the public gives only open boxes.
- **A step's `since`** (`sync_ids::steps` `Recorded::of`) is the current write's stamp: an admin re-putting a step entry later leaves commits stamped in between miskeyed for good (hostile admin only).

## A revoked store never reopened (latent, no reproducer)
After a revocation nothing reopens S at a store whose credentials and `changed_at(S)` did not move, so it is never tested again (spec/sync-opens.md §5 Testing) and keeps S's entries. Rewritten by the opening design (notes/opening-design.md): judge against the new open rule once it lands.

## Stale status sources (unshrunk)
A sync differential panic, "sources status counts that are no member at quiet", that no current seed reproduces.

# Small suspects and open questions from the review since the sync rewrite
> Summary: Leftovers of the review of everything since the sync rewrite, each too small for an issue of its own: a writer's card pointing strangers at an earlier inbox, a removed node still reading as acting for its account, the KEM-less seal skip with no observable effect found, the boxed/unboxed split after a demoted admin's plant, and two unreproduced suspects.
> Priority: normal
> Tags: engine, keys, security, account

## A writer's card can point strangers at an earlier inbox (security)
A's inbox is an admin's `keys.0` field, but a card is written by any writer of A along a path through A and carries whichever of A's `keys.0` commits its writer picks. A card carrying an older commit that named inbox I1 and omitting the admin's later move to I2 (keeping A's newest commit, so the per-thing newest-`ts` staleness test of `refresh_card` sees nothing newer) leaves a stranger holding only that card firing grants to A at I1, and no honest node rewrites it. Bounded: only an inbox an admin once chose, only at parties holding no newer `keys.0` of A, and a grant fire's edge piece is boxed to A's keys, so I1's readers learn the grant, not the secrets. A rule rewriting any card lacking a commit current at the node does not settle across a fork (each side's current commits differ, so the two sides rewrite each other's card forever); a fix needs a staleness rule that is monotone across sides.

## A removed node still reads as acting for its account
`Account::of` is `settings^.0` on the node root, which nothing clears: after `remove_node` and its sync the removed node has no role on A (`role_on(A) == None`) and `Account::of` still returns A (probed in `pairing_and_removing_a_node_spec_permissions_8`). Gating it on `role_on(A)` is not enough: on a client (thin) handle `role_on` reads the client's thing's role, and `Account::make` on such a node refuses ("acts for A already"). Decide what a node does on learning its removal (clear `settings^.0`, or `of` reading the node thing's grant on A) and test both API sides.

## The KEM-less seal skip has no observable effect found
`members::sealing_at` and `notice_keyset` skip KEM-less keysets as Seal candidates (`bare`). With the skip removed, every rotation test passes, `tests_kem::a_kem_less_keyset_leaves_its_holder_out_spec_crypto_4` included: without it Seal gives the KEM-less newest keyset, and the loop's missing KEM key leaves the holder out alike. The skip could matter only for a joint seal (anchors forked, one anchor's newest descendant KEM-less): with it, Seal falls to the anchor itself and may seal jointly; without it, the holder is left out. Build that case; if it shows no difference, delete `bare` and say so in `kem.rs`'s invariant.

## Dependent box after a demoted admin's plant
An admin's step and box on a dependent Y with no keyset, the admin demoted after the plant, stays valid (judged at its point): Y counts independent at the boxed node and dependent elsewhere, for good (`tests_planted::an_admins_step_counts_at_the_boxed_node_after_its_demotion_spec_sync_set_2`). Nothing reconciles the two (the planted epochs are never established, so nothing re-seals). Hostile admin only; a rotation by an honest admin would make Y independent everywhere. Decide whether the step alone should count, or only with a keyset.

## Suspects not reproduced
- **The public's role wherever held** (`rotation::lost::role_here`) also feeds `may_take`/`readable` for the node's own sealed boxes, so a public grant whose removal the node lacks could keep a removed reader's sealed secrets. Harmless if a role through the public gives only open boxes.
- **A step's `since`** (`sync_ids::steps` `Recorded::of`) is the current write's stamp: an admin re-putting a step entry later leaves commits stamped in between miskeyed for good (hostile admin only).

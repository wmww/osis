# Lockout recovery without frontier omission
> Summary: Build notes/lockout-recovery.md: replace repudiation (`demote_repudiating`, `--repudiate`, the frontier's omission on purpose) with a removal whose required rotation, when every current epoch the remover cannot open was made by the holder being removed, supersedes current epochs the remover cannot open by listing them. Tess Q6/Q7.
> Tags: permissions, engine, keys, security

Repudiation is already gone from the API, port and CLI (Tess); until this is built a deliberate lockout has no recovery (notes/lockout-recovery.md Today). Tess: make it work, and no lockout concept in the API or UI. So no `recover` flag: recovery is an ordinary `set_role` removal of the holder that locked others out (notes/lockout-recovery.md, No flag).

## Steps
1. Spec: spec/permissions.md §3 Lockout recovery becomes one sentence (a removal or demotion made as recovery rotates holding no current secret of a role; its keyset lists the current epochs, its history box the established secrets it holds); §5.1 drop "Omission on purpose" and its pointer; spec/crypto.md §4 "an admin recovers" sentence points at it; §5 wrap exception: with no superseded read secret held, wrap under the newest established read epoch whose secret the rotator holds.
2. osis-keys `produce::rotate`: the wrap fallback (`wrap` is `None` today when no current read secret is held; check what the engine does with `None` and that it never wraps a recovery under its own new epoch).
3. Engine: `demote_in` skips the "lacks a current secret" refusal when every current epoch it lacks was made by the holder being removed; delete `demote_repudiating`, `lockout_rotations`, the omit set, the stays-valid check, `remove_signed`'s `repudiate`. Then also rotate eagerly every thing the removal's required rotation reaches whose current epochs this node lacks (today's repudiation covered things in question below the target).
4. osis/port/cli: nothing new. `set_role` docs say removing a holder who locked others out recovers. A model case in Lockout.tla for the rule (lacking an epoch not made by the holder refuses) before building.
5. Tests: rewrite `flows::*_spec_perm_3` lockout tests (core/node/tests/it/flows.rs around 2496-2780): recovered (the vandal's rotation stays valid, its epoch superseded, every holder reads and writes after), twice, concurrent recoveries (fork of two honest epochs, re-seals settle), holder actor, either arrival order, bundled own-thing rotation, a racing vandal rotation (unreceived, invalid), honest rotation missing the admin (content under it stays valid, a joiner reads it after its holder's next rotation). Delete `repudiation_without_audit_refused`. These are today the only users of `demote_repudiating` (issues/deprecated-terms.md).
6. Notes: notes/permissions.md Lockout recovery limits (first sentence to the shorter limit; hostile admin points at notes/lockout-recovery.md); frontier study F5 and §7; mvp-progress item; delete the "re-study" clause in questions-for-tess Q7 once built.

## Separate, for owner-removal step 6
Host step after a hostile admin's rotation (notes/lockout-recovery.md, Owner removal): the branch form's condition must also cover a head step whose epochs the registrar's current epochs supersede and whose delete key it lacks. Not part of this build.

## Interaction with a removal gone alone (depth0-hostile)
spec/permissions.md §3 now writes a removal alone while Seal waits; the one removal still held is
a remover lacking a current secret (spec/crypto.md §4), kept so a removal alone does not spend the
audit repudiation needs (issues/removal-without-possession.md). With recovery as an ordinary removal
of the holder who made the epochs, that rule's reason changes: decide whether any other removal by a remover lacking
secrets then goes alone (uniform; recovery would need a rotation-only act on a grant already
gone) or keeps waiting, and what a recovery does when Seal also waits (alone leaves the vandal's
epochs current and nobody writing until the holder actor merges).

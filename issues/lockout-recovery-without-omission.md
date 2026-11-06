# Lockout recovery without frontier omission
> Summary: Build notes/lockout-recovery.md: replace repudiation (`demote_repudiating`, `--repudiate`, the frontier's omission on purpose) with a removal whose required rotation, under an explicit `recover` flag, supersedes current epochs the remover cannot open by listing them. Tess Q6/Q7.
> Tags: permissions, engine, keys, security

## Steps
1. Spec: spec/permissions.md §3 Lockout recovery becomes one sentence (a removal or demotion made as recovery rotates holding no current secret of a role; its keyset lists the current epochs, its history box the established secrets it holds); §5.1 drop "Omission on purpose" and its pointer; spec/crypto.md §4 "an admin recovers" sentence points at it; §5 wrap exception: with no superseded read secret held, wrap under the newest established read epoch whose secret the rotator holds.
2. osis-keys `produce::rotate`: the wrap fallback (`wrap` is `None` today when no current read secret is held; check what the engine does with `None` and that it never wraps a recovery under its own new epoch).
3. Engine: `Demotion` gains `recover: bool`; `demote_in` skips the "lacks a current secret" refusal when set (its message names the flag); delete `demote_repudiating`, `lockout_rotations`, the omit set, the stays-valid check, `remove_signed`'s `repudiate`. With the flag, also rotate eagerly every thing the removal's required rotation reaches whose current epochs this node lacks (today's repudiation covered things in question below the target).
4. osis/port/cli: `repudiate` becomes the flag on `set_role` (`SetRoleOpts`), CLI `set-role --recover`; delete `REPUDIATE`. Passes notes/api-design.md. notes/api.md, notes/cli.md, notes/client-port.md rows.
5. Tests: rewrite `flows::*_spec_perm_3` lockout tests (core/node/tests/it/flows.rs around 2496-2780): recovered (the vandal's rotation stays valid, its epoch superseded, every holder reads and writes after), twice, concurrent recoveries (fork of two honest epochs, re-seals settle), holder actor, either arrival order, bundled own-thing rotation, a racing vandal rotation (unreceived, invalid), honest rotation missing the admin (content under it stays valid, a joiner reads it after its holder's next rotation). Delete `repudiation_without_audit_refused`.
6. Notes: notes/permissions.md Lockout recovery limits (first sentence to the shorter limit; hostile admin points at notes/lockout-recovery.md); frontier study F5 and §7; mvp-progress item; delete the "re-study" clause in questions-for-tess Q7 once built.

## Separate, for owner-removal step 6
Host step after a hostile admin's rotation (notes/lockout-recovery.md, Owner removal): the branch form's condition must also cover a head step whose epochs the registrar's current epochs supersede and whose delete key it lacks. Not part of this build.

## Interaction with a removal gone alone (depth0-hostile)
spec/permissions.md §3 now writes a removal alone while Seal waits; the one removal still held is
a remover lacking a current secret (spec/crypto.md §4), kept so a removal alone does not spend the
audit repudiation needs (issues/removal-without-possession.md). With recovery as a `recover`
removal that rule's reason changes: decide whether a removal without the flag by a remover lacking
secrets then goes alone (uniform; recovery would need a rotation-only act on a grant already
gone) or keeps waiting, and what a recovery does when Seal also waits (alone leaves the vandal's
epochs current and nobody writing until the holder actor merges).

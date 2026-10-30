# An import may name as origin a commit-form commit on its own thing
> Summary: nothing refuses an import on N whose origins include a commit-form commit C on N itself; then the import's writes share C's dots (forged copies attributed to C that survive the importer's revocation), and an invalid import (its creator removed) un-merges C's genuine writes, since `invalid_of` drops every origin's dots.
> Tags: security, engine

Severity: low (needs a commit-form content commit by someone else on a thing the attacker created; content is node-form by default, commit form is used by recovery and link keys and may be chosen by any author).

Scenario: W created N, later removed. Y (a recovery key) wrote commit-form content commit C on `(N, /body)`. W writes an import on N listing origin C (creator check passes). Invalid (W lacks write): `invalid_of` (core/engine/src/apply/atomic.rs:185-187) returns `Owned::Commit(C)`, so every `Commit(C)` dot on `/body`, C's own writes included, is un-merged at every node. While W is still a writer, the same import carries differing copies under C's dots, owned by C (`any_owner` prefers C, validity.rs `any_owner`), which a later revocation of W does not remove.

Spec: spec/permissions.md §7 imports take writes "from commits of other things"; §5.2 C owns its dots on N.

Fix direction: refuse as bad input an import with an origin that is a held commit on N (and judge it once C arrives, as the creator check is); `invalid_of` should skip origins that own their dots on N.

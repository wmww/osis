# A writer's compaction snapshot of `/keys` or `/secrets` writes admin-only fields
> Summary: a membership compaction snapshot is judged by the aspect's role (write for `/keys` and `/secrets`), not by what it carries, and a valid snapshot vouches for every carried write; so a writer of actor A can carry a forged admin keyset, inbox or deposit seed in `/keys`, or admin-role boxes, history boxes and tombstones in `/secrets` (which also establishes epochs), under dots nobody holds.
> Tags: security, engine

Severity: high (writer on A gets A's admin-level secrets of things A administers).

Scenario: W has write on team actor A; A holds an admin edge on thing T. W builds a `MembershipSnapshot` of `(A, /keys)` carrying a write of field 2 (admin keyset: W's own KEM key, some epoch) under a dot no node holds an owner for (`Commit(random)`, stamp just below the snapshot's `ts`). `Judge::part` (core/engine/src/apply/validity.rs:711-715) checks only `required_role("/keys")` = write; `rotation_required` (validity.rs:506), which demands admin for fields 2..5 of an ordinary `/keys` delta, is not used for snapshots. The carried write is not owner-received, so it joins (spec/permissions.md §5.2 "A valid S vouches for every write it carries"). Later an admin of T who does not hold A's admin secret rotates T's admin role or re-seals A: `flows::recipient` (core/engine/src/flows/mod.rs:213) seals to the `/keys` state, so to W's key. W now holds T's admin secret: admin label keys (register steps, delete any blob at T's servers) and admin-level reads. Same route forges `deposit_seed` / `inbox`.

`/secrets`: a writer's snapshot can carry admin-role boxes and history boxes, or tombstones of others' box entries; `after_join` (core/engine/src/apply/keys.rs:267-281) then establishes every epoch it keys (spec/crypto.md §4: a held `/secrets` snapshot establishes), e.g. a made-up admin epoch nobody holds.

Spec: spec/permissions.md §5.2 says a snapshot needs "the aspect's role (§1: admin for `/label`, `/moved`, `/was`, else write)"; §1/§3 and spec/crypto.md §3 make admin keysets, inbox, deposit seed and admin boxes admin-only. The snapshot rule bypasses them.

Fix direction: require admin for every compaction snapshot of a membership-class aspect (writers then never compact `/keys` and `/secrets`), or judge a `/keys`/`/secrets` snapshot by the highest role any carried write or tombstone touches. Spec §5.2 and commits §2 to match.

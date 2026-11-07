# A vandal that left is recovered only by removing someone else
> Summary: a writer rotates A to itself and then removes itself; the admin, holding no current secret, makes no due rotation, so it recovers only by removing or demoting another holder.
> Priority: normal
> Tags: keys, engine

Lockout recovery (spec/permissions.md §3, spec/crypto.md §4 Boxes) lets only a removal or demotion rotate while lacking every current secret. A self-removal carries no rotation, and `rotation::rotation_due` skips roles with no held current secret, so after W rotates to itself and leaves, A stays locked (writes commit locally, seal nothing) until the admin removes some other holder; any removal then recovers, since W holds no write (`vandal_that_left_recovered_by_any_removal_spec_perm_3` in core/node/tests/it/flows.rs). Re-removing W rotates nothing (no edge, no departure).

Candidate: let the due rotation an uncovered departure makes rotate under the same condition as a removal (every lacked epoch's maker holds no write; `rotation::lacked_made_by` with no overlay), so the admin's next write recovers. Check against `Lockout.tla` (a rogue self-removal action) first: it widens who supersedes epochs it lacks from removers to every rotator.

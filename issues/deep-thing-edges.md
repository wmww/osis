# Edge writes on things deeper than MAX_OWNER_DEPTH still reach perm
> Summary: `Judge::part` refuses layer-2 deltas on a thing more than `MAX_OWNER_DEPTH` owner links below its key actor, but edge writes are judged by perm, and `add_membership_in` adds a deep thing's `/members` ops unfiltered, so a deep actor's edges still grant roles (e.g. on a shallow thing it is a member of).
> Tags: security, engine, perm

Severity: low.

Code: core/engine/src/apply/validity.rs `add_membership_in` (no depth filter; `Judge::part`'s `too_deep` only affects the delta's own flag); `graph::chain` in core/perm gives owner-chain class through the capped ancestor list.

Spec: spec/permissions.md §1 "a delta written on a thing further below its key actor ... is invalid, its `/created` excepted".

Fix direction: skip ops whose target is too deep in `add_membership_in` (re-adding if a record arrives), or have perm ignore targets with no key actor within the cap.

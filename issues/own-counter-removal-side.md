# A node's own counter-removal is not recorded trusted
> Summary: spec/permissions.md §5.1 Sides has a node record each frontier-carrying lowering it makes as trusted when it makes it; the engine relies on held first, and records a lowering that arrives fresh in an update as untrusted, so a node writing a counter-removal after receiving the removal of itself may not side with its own write.
> Priority: low
> Tags: engine, perm

**World**: admin A holds B's removal of A (backdated). A writes R removing B, its list leaving B's removal out (The list reads A's walk with R trusted). `sides::after_update` sees R fresh in the update and records trust false; R does not apply at A. The spec has A side with itself. Whether A's writer check lets a removed admin write R at all is in `flows/edges.rs` (unchecked here): if it refuses, the spec's own-write clause is dead text and should go; if it allows, record own lowerings trusted at commit.

Also short of the spec in `sides.rs` (~144): "no order, no side" records trust false where the spec records nothing, so a later held-first trust for that dispute can never be recorded (pinned by the node test `disputes.rs` ~127). notes/disputes.md "a party holds its own write first" states the equivalence without this condition.

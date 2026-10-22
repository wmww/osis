# Admin-only aspects on shared actors
> Summary: Every writer of an actor may write all its non-membership aspects, so a shared tag's settings (`/name`, `/tag`, later chat moderation state) are writable by every member with write; a vandal's reset is only undone by history. Two fixes: a moderators actor owning a settings thing (no spec change), or a required role per delta on the wire judged like content validity (one byte per aspect, cleaner).
> Tags: permissions, owner-call

Repro: examples/chat `hide` (notes/chat.md) is written by any writer of C, not only admins; no test asserts admin-only. Any shared tag's `/name` likewise.

- spec/permissions.md §1: admin = write + membership + purge; notes/permissions.md Concepts: a role on an actor covers editing the actor thing. So "settings only admins change" has no home today.
- Option A (pattern, no spec change): a small moderators actor (members = the admins, a duplicated tiny roster) owning a settings thing, with an edge giving the shared actor read. Costs a second rotation per moderator change.
- Option B (spec change before stabilizing): the aspect list carries a required role per delta (write or admin), filled from the schema's default like retention, judged in layer 2 (spec/permissions.md §5.2) with that role instead of write; a writer's delta on an admin-only aspect is invalid and un-merged. A node without the schema judges what the writer declared; a node with the schema judges by its schema's flag for the AK, so an honest writer's omission is caught and a vandal's `write` declaration on an admin-only AK is invalid at schema-holding nodes. Convergence of state is unchanged; validity differs by schema like typed reads do. One byte per aspect per commit.
- Owner call: A, B, or neither (accept vandalism bounded by history and admin undo).

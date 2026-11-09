# A delete's membership removals depend on held group bodies
> Summary: `delete` and an undone creation reset every aspect of a thing that may hold content (present, or written by a part not received yet), so the reads end alike everywhere, but remove its group memberships only where this node holds the add (`ix.groups.defs`), so two nodes deleting or undoing the same creation can leave different listings.
> Priority: normal
> Tags: engine, osis

A set removal needs the add's dot, so a node holding a group's `group.0` add of N as a header only (body missing) cannot remove that entry: its delete leaves N listed there, another node's does not. Aspects avoid this because `remove_aspect` is a reset needing no state (`read::deleted_aspects`). Options: a removal by value stamped as a reset of every add of that tid before it (a keyed removal, as role-class aspects use, `Writer::keyed_removals`), so it needs no held add; or refuse the delete while a header names a missing `group.0` part that may list it (cannot tell which group without the body: every group's). The first keeps the aspects' rule (what may hold content is removed, whatever bodies are held).

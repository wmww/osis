# A moved thing's copy may be unreachable for its re-granted members
> Summary: `move_to` copies T into M owned by X and re-grants T's members on M by inbox, but M gets no label, and the inbox payload names no label for it. A member who does not sync a label of X writing M cannot fetch M's `/created` (its grant stays pending `UnknownCreated(M)`), and a member who only reads X's label cannot upload its writes on M (it stamps nothing there; other nodes wait for its deltas, `WaitDeltas`).
> Tags: flows, sync, permissions

- Seen in the simulator (`move_import`, now set up so the writer also writes the new owner's team): with the team shared read-only, the writer's commits touching the copy and the old doc stay pending `WaitDeltas` at the admin; with the team unshared, the writer's grant on the copy pends `UnknownCreated(copy)` for good.
- Options: `move_to` creates a label for M when T was a labeled group (before the grants, so the inbox payload names it), or the app must place M in a group every re-granted member writes; spec/permissions.md §7 says nothing about it. Owner-call if it changes the spec.

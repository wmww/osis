# Unsyncing's forgetting costs O(everything held)
> Summary: a leave forgets the things whose sync IDs stopped in one `Engine::forget_local` call (one reload per settle, however many stopped), and sync unlogs only the own entries of the commits that forgot whole; but the engine's forgetting itself scans every thing's aspects (`by_aspect`), decodes every held commit header (`retention::forget`) and reloads the engine (`Engine::reload`, `reexamine`): O(n) per leave, n everything held. Fathom's lane.
> Priority: normal
> Tags: engine, performance

- Where: core/engine/src/sync/mod.rs `Engine::forget_local` (the `by_aspect` scan for things under the left things' secrets), core/engine/src/retention/forget.rs `forget` (every commit header decoded, `ASPECTS` scanned, `index::invalidate`), then `reload` and `reexamine` to rebuild every index after the deletes.
- Numbers (core/sync/tests/it/leave.rs `leave_costs`, counter `forget: commits scanned`, one node, k things leaving, a thing staying with n own commits): k=1 n=5: 19 commits scanned; k=3 n=5: 25; k=3 n=50: 70. One reload in each. Sync's unlogs: 2 per thing left, constant in n.
- Wanted: the engine forgets a thing's state incrementally (the commits naming it from `by_thing`, its aspects from `by_aspect`, its pieces), with the indexes updated in the transaction rather than rebuilt by a reload, so a leave costs what left.
- Lost access (`rotation/lost.rs`: a forget with `Scope::Lost` and a reload per loss) is the same shape; several actors lost in one step should forget once.

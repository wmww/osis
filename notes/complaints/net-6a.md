# net-6a complaints
- Adding a role variant: ~10 places hard-coded `[Read, Write, Admin]` or `Role::Read` as the lowest role (perm `may_rotate`, the `keysets` index range start, `shown_roles`, local record bit packing with 2 bits for a role, test helpers rotating "all" roles); the compiler finds none of them. `Role::ALL`/`Role::id` now hold the order and wire ids in one place.
- `promotion::a_readers_copies_are_promoted_once_spec_sync_5` passed on main by commit-ID order luck: the host's deposit budget took no copy of the group's own-secrets rotation only because its random ID sorted late. Fixed the test's premise (a rotation held only under the epoch it supersedes may be promoted once).
- `claudewait` named in CLAUDE.md is not a tool here; background tasks notify instead.

# Deep member chains cost cubic time in the rotation cascade
> Summary: the departure walk holds one shared-tail hop per kept departure (`osis_keys::Via`), but each kept departure still costs O(L) time on a chain of L actors (the simple-chain `contains` test and `verdicts` running `covers` down the chain), so one walk is O(L^2) and a cascade (`ensure_rotated`, one walk per actor) O(L^3). Fine at realistic depths, a cost lever for an admin who builds a very deep chain below a shared group.
> Tags: engine, permissions

Levers: verdicts at U are U's box for W plus W's verdicts (notes/permissions.md), so they can be computed from the inner departure's kept verdicts in O(1) instead of re-running `covers` (it must then stay exactly `covers`' rule); the `contains` test is needed only in cycles. A cascade recomputes `departures` for each actor after every rotation (each rotation clears the cache): reusing the inner actors' found sets across one cascade would cut it further.

The second actor stays in the class key: the differential oracle keys on it (dropping it fails `walk_matches_path_walk`) and `inside_member_revokes` places the `/keys` of every chain actor.

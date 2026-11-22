# Complaints: cross-publish
> Summary: a removed rule's harness check gives the reproducer for free (`World::run` runs the quiet checks), but the old attempt's reproducer asserted the rejected behaviour and needed rewriting; a test fixture relying on the removed rule needed another route to the same state.

- `World::run` already runs `unreached_must_holds` at every quiet, so a sync reproducer needs no assertion of its own for the quiet check; nothing in notes/sync-test-harness.md says so near "Replaying a script", and the attempt branch's reproducer re-derived the check by hand.
- `grant` to a holder whose record edge already gives admin refuses a lower role ("a grant below the holder's edge lowers it") rather than adding a direct edge; only `Role::Admin` writes one. Found by trial.

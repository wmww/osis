# Examine's chain check ignores the author's owned actors
> Summary: a node that reaches a thing only through an actor it owns (owner link, then that actor's edge) writes there, but its own commit pends forever with `MissingChain(author)` ("own commit not applicable"): `validity::reaches` follows only edges naming the author, never owner links down to actors it owns, while spec/permissions.md §1 paths climb owner links too.
> Tags: node, permissions

Repro: in `resnapshot_residue_heals_on_sync_spec_perm_6` (crates/osis-node/tests/it/validity.rs) drop n0's admin edge on A1 (n0 owns A1, A1 admin on A0): n0's edge write on A0 fails. The writer check (`check_authority`, perm's `role_of`) allows it. Fix: let `reaches` also step from an actor to the things it owns (bounded like the edge walk), or name owned actors in `Held`.

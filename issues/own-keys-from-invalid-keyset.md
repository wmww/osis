# own_keys and keyset epochs kept from a /keys write that turns invalid
> Summary: `own_keys` (local `g/`) and the epochs in `k/` are "ever observed": a thing's first keyset seen only in a commit that later turns invalid keeps it own-keyed for good, so the node stops deriving it from the owner (`Core::epochs`, `own_secrets` no-ops), may hold only the invalid rotation's secrets, and writer rules and body classes follow this node's history, not the held set.
> Tags: engine, security

Pre-existing on a running node (the in-memory set and the old `node/own keys` table were insert-only); until branch own-keys-uncover an index rebuild (every build change) happened to clear it, now `g/` keeps it across rebuilds too, so open equals rebuild.

Case: T plain; admin A grants T's first non-owner member with the rotation from derived epochs (T's first `/keys`), while the owner concurrently removes A. The grant turns invalid here, `/keys` and `/secrets` of T un-merge, but T stays in `own_keys` and its epochs from A's rotation stay in `ix.secrets`/`k/`. Effects to check:
- encryption under T: `Core::epochs(T)` returns the invalid rotation's epochs (known to the removed A) or `None` (cannot encrypt), and `own_secrets(T)` returns early, so no valid rotation from derived epochs is made;
- `validity::check_content_rules` (writer side) requires a rotation for removals on T, which nodes that never saw A's commit do not;
- `retention::reader`/`body_class` and `delete_base` follow `own_keys`, so body IDs and delete bases can differ between nodes holding the same set.

The opposite fix (drop T on a flip) is unsafe for a merely uncovered valid keyset (issue own-keys-after-uncover, removed). A fix likely tells the two apart: own-keyed iff a valid membership `/keys` part with keysets is held, dropped or missing (headers stay), with epochs from invalid rotations dropped likewise.

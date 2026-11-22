# debug-dumps complaints
> Summary: Footguns met adding the sync/engine debug dumps.

- A commit's signer in a sync world is usually the account, not the node's tid: a describer test asserting `(n0)` failed; `World::describe_commit` marks both `(n<j>)` and `(n<j> account)`.
- An edit to `core/engine/src/engine/explain.rs` (debug-only) still relinks osis-sync's `it` (about 2 min): batch engine-side dump edits before building.

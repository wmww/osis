# lost-secrets
> Summary: Workflow snags met fixing lost secrets rejoining.

- `cargo test` captures a passing test's stderr: debug prints in a passing variant showed nothing until `-- --nocapture`; cost a confused round.
- `LocalPeer` hands plaintext to nodes that cannot read (notes/test-harnesses.md says so), so a receiver-side "no content of what you cannot read" rule at engine ingest breaks dozens of harness tests and the order property; the rule had to live where real nodes decrypt (node-sync's copy opening).
- Review: the gate's `git fetch` moves `origin/main`; a later `git checkout origin/main -- core/` (to replay a seed on main's code) then staged a file main had gained since the rebase. Replay against the merge base, not `origin/main`.

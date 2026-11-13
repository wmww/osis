# log-liar
> Summary: workflow snags met on the log-liar branch.

- Each edit to an osis-node source or test file cost about 3 min to rebuild and relink the `it` binary before a one-test run: a probe loop of five tries spent most of its time linking.
- `Engine::local_census` lumped every node-sync row under `y/`; it now splits `y/` by kind, which is what finding the growing rows (`y/b`, `y/g`, `y/x`) needed.
- A probe of the loop before the fix ran 100 s for 800 rounds: per-round work grows with the tombstones the loop leaves.
- log-liar-rr: the rebase over main conflicted in notes/time-limits.md (two gates appending their hit at the same last line); resolved by keeping both.

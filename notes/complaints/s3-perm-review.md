# s3-perm-review
> Summary: Workflow snags met reviewing the vouches build.

- A probe's `git checkout <file>` to undo a mutation also threw away an uncommitted edit to that file made just before; wip-commit before every probe, as the brief says, including edits made since the last one.
- `tools/mutate.py` piped through `tail` hid its first row; read its whole output (or MUTATE_OUT) for the table.
- perm test `World::nodes(n)` returns the same nodes on every call (salt 1): a test wanting fresh nodes per loop step must take them from one `nodes_salted` call, or its components silently merge.

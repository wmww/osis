# relink-order complaints
> Summary: workflow notes from the relink-order task.

- `net.read` on a large register returns the root `Link`, not the string: a test comparing it to the written value fails confusingly; compare `is_some()` or use `get_full`.

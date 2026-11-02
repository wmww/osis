# parts-holes-review2 (tiller-parts-holes-review2)
> Summary: footguns met reviewing redelivery.

- A "crash" simulated with `take_redeliver` after a `handle` tests nothing: `handle` already ran `redeliver`. To lose a name, change the engine directly (ingest, reexamine, take) and restart.
- A whole `package().bytes` of a commit with `created.0` is no label entry: a blob holds one retention class, and `open_commit` marks it `Bad`. Use `bodies()`.
- `check_unchanged` panicked only under a differential at the real node (`Err` from a junk-only stored copy under a delta wait); the Relay model never reached it in the seeds the author ran.
- `parts_differential` at its default 150 seeds took 518 s single-threaded (the table said 60 seeds 44 s; junk and bad parts grew it): over the per-branch 5 minutes. It wants the thread-per-core seed runner.

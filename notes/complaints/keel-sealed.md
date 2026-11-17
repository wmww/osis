# keel-sealed
> Summary: Mishaps on the sealed-sections branch.

- A World strip scenario (two strips apart, a third node reading neither) never reached `held_sections`' listing rule: readers relay each other's rewrites through the third node's store, so the strips meet anyway. The owed test drives `Engine::seal_body` at that node directly instead.
- A shell redirect into a scratch directory not yet made silently skipped a whole `cargo test` run (the background task reported exit 0).

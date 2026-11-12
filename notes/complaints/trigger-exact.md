# trigger-exact
> Summary: Footguns met making the compaction trigger exact.

- A durable snapshot's covered bodies drop in node-sync after `Engine::compactions` returns (`compact_due`): a probe of the load right after the snapshot reads everything still held; read it after `compacted`.
- Reverting temporary probes with `git checkout <file>` also drops the real edits in that file: put probes behind a separate wip commit or strip them by pattern.
- (review) The branch failed `cargo clippy -p osis-engine --all-targets -D warnings` (`walk_source` took 9 arguments): workers must run clippy last, after the final edit.

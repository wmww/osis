# app-select
- To see a chat in the app you need a store with one: the CLI binary in a worktree's target was older than the tree and its store failed to open in the app ("storage: commit blob"), so `cargo build --bin osis` (core, ~7 min cold-ish) just to make test data. A `--demo` chat in the app would save that.
- `osis-app` has no cheap widget test path: Masonry's TestHarness is behind masonry's `testing` feature (masonry_testing, a new dependency), so selectability is checked by hand in guibox only.

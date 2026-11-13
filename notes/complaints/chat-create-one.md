# chat-create-one
- The issue's reason for two commits (a joiner reads the record among role commits) no longer held: spec/commits.md §4 judges commits carrying `created.0` first, and the joiner's pending-read count was 0 either way. A stale rationale in a comment kept a two-commit write alive; the scale test's counter was the quick check.

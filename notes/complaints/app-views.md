# app-views
> Summary: friction met rewriting the app onto the view tree and osis-held UI state (issues/ui-state-*.md for what needs core).

- A `TextSession` does not hear this node's own writes to its path: clearing a draft means close the session (commits pending), remove the entry, reopen a new session on the next build.
- A `+` (ephemeral) write cannot share a commit with a durable one and needs a thing that already exists, so every menu or picker toggle is its own commit.
- Every window-state write fires the window's thing watch: the whole tree re-reads (nothing narrower to subscribe to per map entry that fits how a view reads).
- `Osis::profile` makes the profile on read; the app reads it for the "You" row and must guard on peers to keep reads pure.
- `wt` worktree: long `cargo clippy` runs while the kit+app split was half done; a generated-key rename (`ViewSource` from `view.0`) was only visible by reading OUT_DIR.

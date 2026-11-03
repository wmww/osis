# app-chat-rv (lodestar-app-chat-rv)
- First `cargo build --bin osis` in a worktree whose target held only test builds took 7.5 min (the bin's own artifacts); worth knowing before running the Chat recipe.
- `osis chat post --from ""` sends a blank name (`Some("")`), not none: readers must treat blank as absent.

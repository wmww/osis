# chat-e-review (tiller-chat-e-review)
- `cargo test-net --no-run` went past the 180 s foreground cap on a worktree only warm for the plain feature set: the tier-2 localhost test needs only `cargo test -p osis-cli`; the brief doesn't say which.
- `x | tail` around a store-in-use error showed rc=0 (footgun already noted in CLAUDE.md).

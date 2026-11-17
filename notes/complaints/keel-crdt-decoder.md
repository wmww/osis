# keel-crdt-decoder

- Running a `tools/bin-at` binary directly (outside cargo) skips `.cargo/config.toml`'s `[env]`, so a failing proptest writes `proptest-regressions/` into the tree; delete it before committing.
- c6f5ba465 removed `PurgeBy::Nobody` but left `nobody` in notes/purge-rights.md, notes/growth.md, notes/chat.md, notes/chat-cases.md (spec remnants fixed here).

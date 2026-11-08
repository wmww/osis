# listener-2 (undo from kept history)
- Untyped test keys (`DynamicAspectKey::untyped`) ignore a registered schema, so giving a test aspect history meant switching it to `aspect_key` keys (osis tests' `keep_day`/`kept`); a thin client cannot register a schema (`Unsupported`), and the CLI registers none on a memory store (`--schema` per call works).
- A pinned order history replays nothing once its undo stops writing: `assert_eq!(n, 15)` was the only sign; the replay prints no step outcomes.
- The kit workspace's first test run in a worktree took about 11 minutes cold.

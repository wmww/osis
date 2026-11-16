# keel-review-b
- `tools/bin-at` to an old rev leaves the worktree's target built for that rev: the next current build of the engine and osis recompiles for several minutes. Run old binaries first, then build current.
- The 5 engine lib failures lane (b) called pre-existing failed before it only on its own `todo!()`s: "fails at the parent commit" is no proof of pre-existing when the parent had stubs. Compare the panic, not the verdict.

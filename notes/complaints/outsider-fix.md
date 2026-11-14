# outsider-fix complaints
- Probing needed eprintln in engine and sync and many rebuilds of osis-sync (~30-90 s each): no way to see which node opened which entry under which sync ID, or why a pass ended, without editing code.
- Test clock stands still in the World harness: every "after" rule keyed on ms (passes, arrivals) is ambiguous there; caught several same-ms bugs only by tracing.
- A full-crate test run in the background while editing/building left stale artifacts and 27 spurious doc-test failures (E0460 "found possibly newer version of crate").
- A cost regression (pieces judged 28 -> 60) came from a module restart after an engine reload: the reload dropped the engine's followed links, so link sync IDs left the sync set for a round and waited a pass. Found only by probing restarts; nothing reports "a module restart saw these sync IDs leave".
- Three coordinator rebases mid-task (regrant-drop, outsider-lists, review-3), each with spec/issue conflicts on the same lines.

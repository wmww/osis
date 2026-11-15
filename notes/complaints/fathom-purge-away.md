# fathom-purge-away
> Summary: workflow notes from the owed-deletes-while-away fix.

- Read's `known` feed comment said rows before the first settle are judged then; nothing replayed them, so a restart never judged what sources showed before it (part of this bug). Feed comments that promise a replay deserve a test.
- Timing a World test alone misleads: ~5 s of the scaling test's 7 s was the first `world(0, 4)` build, cached for the whole binary; time the marginal part (a second run in the process) and cache a module's setup with `fixture_with`. On main the same test took ~67 s.
- Review: the source's class as last joined was a second, memory-only map in `Views` (unknown after a restart, never pruned for evicted records); it belongs with the rest of what the source showed (`Known`, a record row).

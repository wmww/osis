# fathom-purge-away
> Summary: workflow notes from the owed-deletes-while-away fix.

- Read's `known` feed comment said rows before the first settle are judged then; nothing replayed them, so a restart never judged what sources showed before it (part of this bug). Feed comments that promise a replay deserve a test.
- A World scaling test with `partition` runs ~7 s; on main (before the fix) the same test took ~67 s, so partition-heavy tests are worth timing before adding.

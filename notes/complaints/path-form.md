# path-form
- "Which commits state differing paths" had no counter: answering it took a throwaway probe in `engine::write::stated_path` writing to a file and a full osis-engine test run (7 min). A `costs::count` there ("write: paths differ") would make it a lookup in any test.
- `Write::commit`'s rule that a created thing must be held "by the same write" is checked at the transaction's end (`wrote_on`), which the doc comment does not say; found only by reading `engine/write.rs`.

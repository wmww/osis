# destroyed-leftovers
- Timer rows are keyed (time, commit, part) with the kind as value: a second timer kind on the same part at the same time overwrites the first silently. A purge's `T_KEPT` floor lands exactly on its destruction window, so a new kind there would have eaten it; reused `T_KEPT` instead.
- The first crate test run was started before a last code edit and had to be thrown away: edit, then start long runs.
- Review: the `Indexes::signed` debug check sat after `named_on`'s early return, so no test ever ran it (an inverted assert passed every engine and node test); it runs on every key actor judged now.

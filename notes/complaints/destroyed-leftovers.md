# destroyed-leftovers
- Timer rows are keyed (time, commit, part) with the kind as value: a second timer kind on the same part at the same time overwrites the first silently. A purge's `T_KEPT` floor lands exactly on its destruction window, so a new kind there would have eaten it; reused `T_KEPT` instead.
- The first crate test run was started before a last code edit and had to be thrown away: edit, then start long runs.
- Review: the `Indexes::signed` debug check sat after `named_on`'s early return, so no test ever ran it (an inverted assert passed every engine and node test); it runs on every key actor judged now.
- osis `keep_clients::chat_kick_as_seen_by_the_app_spec_permissions_3` failed once in a 4-crate run under load (its 200 ms sleep, issues/tests-4x.md item 6), passed three times alone.

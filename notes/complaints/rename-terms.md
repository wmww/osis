# rename-terms
- A plain sed over `label` catches field access: `label.0` (a `SyncId`'s bytes) is also the old aspect name, so an aspect rule must stay in prose and backticks only.
- Generic senses share the word (test-run labels in `testenv`/`costs`/roles-model, "labelled value", UI labels, network hosts in transport and the dogfood units): a word sweep needs an exclusion list per word, which is why the script keeps one.
- `cargo check --all-targets` over core after each script pass took about 1 min warm; fast enough to iterate on the script rather than hand-fix.

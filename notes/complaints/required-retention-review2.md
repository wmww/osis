# required-retention-review2
- `Net::group` twice gives one label ID unless the second is `group_seeded` with another seed: a test with two groups then flaps Upload/Delete for 300 s (`Outside`) with no failure and no quiescence assert below 200k messages. It read as a sync bug on main until a trace showed the label. Worth a panic in `Net::group` when a label ID repeats.
- A background `cargo test ... | grep` shows nothing until the end; a test's own 300 s looks like a slow build. `--no-run` first.
- `git checkout <file>` after a wip commit restores the wip's debug prints: drop them from the wip first.
- `target/debug/deps/it-*` has one binary per crate and the last `Running` line is not osis-node's: a copy of the wrong one runs 0 tests and says ok.

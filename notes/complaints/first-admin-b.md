# first-admin-b
- The owner removal touched 60+ files across nine crates; `cargo test --workspace` stops at the first failing binary, so the first full run told me about one crate: use `--no-fail-fast` from the start on a wide branch.
- The scratch check's `debug_assert!(w.history == self.history, "history")` says nothing about where; a one-line diff print (first differing index, both entries) found the late-record bug in minutes. Worth keeping as a debug helper.
- A `for ... sed -n "$line"p` loop over 50 files hung the shell (moved to background, had to be stopped); plain `grep -n` with `awk` for context was instant.
- Two behaviours hid behind one predicate (`inbox_label_here`): the fill's "unopened first" order and the unvouched-bytes cap. Widening what counts as an inbox broke a fill-order test and a deposit-budget test in opposite directions; a predicate used by two rules deserves two names from the start.
- `cargo test` accepts one positional filter; several go after `--` (`-- a:: b::`), which the test-command note did not say.
- A sim failure on one seed only (`disk_loss` seed 3: the creator lost its disk before its first pass) is a design hole, not flakiness; the replay log plus `label_status`/`entries` dumps found it faster than reading the pass code.

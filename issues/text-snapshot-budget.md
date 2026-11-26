# The text snapshot budget fails at 10 edits per commit
> Summary: osis-bench `budget_text_snapshot_ratio` (by hand) measures 7.22x the plain text at 10 edits per commit against its 7x budget; notes/crdt.md, Text size records 6.73x for the same synthetic typist.
> Priority: low
> Tags: crdt, bench

`cargo test -p osis-bench --test it -- --ignored budget_text_snapshot_ratio`: 100 edits per commit passes (22,623 of 26,957 bytes); 10 edits per commit gives a 55,596-byte snapshot against 53,914 (20,000 edits, 2,000 commits, text 7,702 B). Either the snapshot grew (find the commit with `tools/bin-at`) or the figure in notes/crdt.md is stale; fix the cause, or move the budget and the note's figure together.

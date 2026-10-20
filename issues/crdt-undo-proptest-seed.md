# Undo leaves an empty set field the earlier read did not have
> Summary: Undoing a writer's last commit can leave an empty set showing inside an enum payload where the value before that commit had no such field; the random property test hits it now and then.
> Tags: tests, crdt

Repro: `cargo test -p osis-crdt --lib undo_restores_spec_4_6` with the proptest regression line `cc 1f43b7445234ff7aa3844e0f34194802e8c53e33e1d0f369f146f0020bf9f05e` in `crates/osis-crdt/proptest-regressions/tests_ops.txt` (fails on main 640f3b6 as well).

`tests_ops::undo_restores_spec_4_6` (spec/crdt.md §4.6): after undo the read holds `5: Enum(2, {1: 2, 2: Set({})})` where the pre-commit read was `5: Enum(2, {1: 2})`. An empty set field materialized by undo (or a written-but-empty composite kept) inside an enum payload. Not investigated.

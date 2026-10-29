# A compaction snapshot counts a tombstone as a live write
> Summary: `retention::snapshot_live` matches the state's writes by dot via `Fragment::writes`, which lists an element's or entry's tombstone record under the creation's dot (no `ts`); a held keep-at-most snapshot that carried a since-removed entry stays "live" and is kept to its grace bound instead of dropping (spec/commits.md §5: a tombstone is no live write). Suspected from reading, not reproduced.
> Tags: engine, retention

Branch small-order-bugs fixed the delta side (`Fragment::holds_owned_write` in `retention::live`). `snapshot_live` still uses `st.writes()` (`Rec::Entry`/`Rec::Elem` push `(dot, None)` for a tombstone). Fix: match only records holding their creation (the remover's reset is a stamp of its own and still matches), keep seq bare anchors. Reproduce first: keep-at-most-0 map, compaction snapshot carrying one entry, then remove the entry; the snapshot body should drop in that transaction.

# history-5 complaints
> Summary: Footguns met building thing-history step 5 (one timer per aspect, history rows).

- The local store has no reverse scan, so a walk back from a cursor needs the rows in memory too (`Indexes::leaving` is loaded from `hr/` at open). An index rebuild (`drop_indexes`) wipes index tables, so derived state that costs body reads to recompute must live in local rows, not `node/*` tables.
- `retention::bounds::held_writes` caches only in a transaction that changed nothing yet; an end-of-transaction step that dates many parts needs its own memo (`Core::held_writes_memo`) or it reads the aspect's bodies once per part.
- A cost test's `measured` spans miss store reads unless `io.reads` is checked by hand: `all_flat` checks writes only.

# A removal re-runs a 64th of every follower that read an unstamped row
> Summary: a store row present since the open, or absent, reads at its hash bucket's stamp, so any removal in a table moves about 1/64 of the `Effects` keys that read such a row; per-piece judgement (sync read) and every follower over store rows pay O(followers/64) per removal after an open.
> Priority: low
> Tags: engine, sync, performance

- `osis_base::memo::Table::wrote(h, false)` moves its bucket's absent stamp, and `Effects::due` fans each removal out to every key read at that bucket (notes/engine.md; `ABSENT_BUCKETS` in notes/arbitrary-values-table.md). Needed today because a row present since the open has no stamp of its own and is read at the bucket's.
- Effect: after an open, sync read's pieces (one key per (S, piece blob), notes/sync-read.md Pieces) all read their own-store row at a bucket stamp, so each entry removal under any S re-judges about n/64 of n followed pieces; an edit whose freed links remove r entries re-judges about r·n/64. Before the open (rows written since), only pieces reading absent rows (tombstones, deletes seen, a source's `known` row) pay it.
- Candidate fix: a read that finds the row present gives it a stamp of its own at the bucket's value (no `ver` move, so no reader's dep breaks), and a removal of a key with a stamp of its own moves only that key's readers (the log says which); a removal of an unstamped key still moves its bucket. Stamps then grow with rows read, bounded by rows present, as rows written already do. Needs a `Stamps` read that says present, and the stores to call it.
- Test: count `read: piece judged` for one entry removal at n and 10n pieces after a reopen.

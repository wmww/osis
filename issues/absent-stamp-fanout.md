# After an open, a removal re-runs a 64th of the followers that read an unstamped row
> Summary: a store row present since the open (no stamp of its own) reads at its hash bucket's stamp, and its removal moves the bucket, so after an open any such removal moves about 1/64 of the `Effects` keys that read an unstamped or absent row of that table; before an open a removal moves only the removed key's readers.
> Priority: low
> Tags: engine, sync, performance

- `osis_base::memo::Table::wrote(h, false)` moves its bucket's absent stamp only when `h` had no stamp of its own (present before the stamps, or since `wrote_all`); a key with one falls back to the bucket's stamp (notes/engine.md, Stamps). So before an open, rows are all written since the stamps and no removal fans out.
- After an open, every row present reads at its bucket's stamp, so sync read's pieces (one key per (S, piece blob), notes/sync-read.md Pieces), which read their own-store row, re-judge about n/64 of n followed pieces per entry removal under any S.
- Candidate fix: a read that finds the row present gives it a stamp of its own at the bucket's value (no `ver` move, so no reader's dep breaks); needs a `Stamps` read that says present, and the stores to call it. Stamps then grow with rows read, bounded by rows present, as rows written already do.
- Test: count `read: piece judged` for one entry removal at n and 10n pieces after a reopen.
- Not this issue: in a fresh 3-node world (osis-sync `history::world`) peer record index rows (`store: record rows 0x58`) move about 520 of 4,650 judgements with no removal at all: writes of rows the judgements read.

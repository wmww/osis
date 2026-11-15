# A removal re-runs a 64th of the followers that read an absent or unstamped row
> Summary: every removal of a stamped key moves its hash bucket's absent stamp, so it moves about 1/64 of the `Effects` keys and memo answers that read an absent row, or a row present with no stamp of its own (every row after an open), of that table.
> Priority: low
> Tags: engine, sync, performance

- `osis_base::memo::Table::wrote(h, false)` moves the bucket of `h` at every removal (notes/engine.md, Stamps): a key present with no stamp of its own reads at the bucket's stamp, so a removed key falling back to the bucket's unmoved stamp would make an answer read before its first write hold again (a stale answer, the reason for the rule).
- Sync read's pieces (one key per (S, piece blob), notes/sync-read.md Pieces), which read their own-store row, re-judge about n/64 of n followed pieces per entry removal under any S whose rows they read absent or unstamped.
- Candidate fix (exact): a read that finds a key present gives it a stamp of its own at the bucket's value, flagged "read present at the bucket's stamp" (no `ver` move, so no reader's dep breaks); a removal moves the bucket only for a flagged key, else falls back (every reader of an unflagged key at the bucket's stamp saw it absent, as it is again). Needs a `Stamps` read that says present and every container (store, `Stamped`, the journaled maps) to call it; stamps then grow with rows read, bounded by rows present, as rows written already do.
- Test: count `read: piece judged` for one entry removal at n and 10n pieces, fresh and after a reopen.
- Not this issue: in a fresh 3-node world (osis-sync `history::world`) peer record index rows (`store: record rows 0x58`) move about 520 of 4,650 judgements with no removal at all: writes of rows the judgements read.

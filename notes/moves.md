# Moving a thing to another owner (not built)
> Summary: Moves were removed (issues/remove-moves.md); a thing never changes owner. What could be built if an app needs one, simplest first.

1. **Plain copy** (recommended if ever needed): the mover creates thing M under the new owner and writes the current values of T as ordinary writes of its own; T stays with its owner. Loses original authorship, edit history and others' purge rights over the copied values; needs nothing new in the protocol (an app can do it today).
2. **Copy with imported history** (what was built, removed in issues/remove-moves.md; the design is spec/permissions.md §7 as of git history before that removal): an import commit on M carries T's writes under their original authors and stamps (an origins table), so history, authorship and purge rights carry over. Cost: imported writes interact with purge, retention, validity and arrival order; 29 merged items and an order oracle were spent on it.

# What a commit pays per enclosing unit
> Summary: A small commit on an independent thing carried under one enclosing unit costs about 1230 B more on the wire (per reader pair), one sign and two stamp verifications more than the same commit on the root, measured in debug at main 6e38bcd03; the entry it adds under the enclosing sync ID is about 153 B. Where do the other bytes go, and which are needed?
> Priority: normal
> Tags: sync, engine, perf

## Measured
Throwaway debug test on the sync harness, main at 6e38bcd03, not kept: one root with 4 or 40 members (independent things promoted from dependents), node 0 the maker, node 2 a reader, node 1 keeping all unread; the same at both sizes.
- One small commit on an inner member against one on the root: 5156 B against 3926 B over all pairs; maker to reader 2146 against 1165 (+981), reader to maker 682 against 433 (+249); 5 signs against 4; 6 stamp verifications against 4.
- So per commit per enclosing unit per reader pair: about 1230 B, 1 sign, 2 stamp verifications.

## What the entry accounts for
A blob carried under a second sync ID costs, per that sync ID, its entry: blob ID 32 B, wrap 57 B, stamp 64 B, about 153 B (spec/wire.md §5; notes/thing-cost.md, Per entry, per sync ID a blob is under), plus a frame of about 170 B on the wire and the Applied and echo (notes/thing-cost.md, Survey). One sign is the stamp under the enclosing sync ID; the two stamp verifications are its check at each receiver. By those figures (computed, not traced) that is well under half of the 1230 B.

## The question
What are the rest? Not established. Candidates to rule in or out by counting the frames of the two commits side by side: a per-sync-ID copy of the body (spec/sync-judgement.md §1 Per-sync-ID copies: a second encryption of the commit where the enclosing unit's readers cannot open every section, about 1 KB for a small commit), certificate copies placed under the enclosing sync ID, the reader's echo of the entry (notes/thing-cost.md candidate 3). Then: what of it the built unit needs (an entry and stamp per enclosing unit are inherent to carrying a thing under each unit that reads it, notes/sync-unit-scope.md), and cut the rest (notes/priorities.md, Slimmer things).

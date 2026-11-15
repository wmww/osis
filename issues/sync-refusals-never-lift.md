# A source's refusal never lifts on the reader's side
> Summary: A reader records each refusal a node keeping S unread tells it (`Op::Refused`, record row `REFUSED` or `Known::refused`, core/sync/src/streams/known.rs) and removes it only when S is forgotten there; the stamp and head kept with it (`Refusal`) are never compared (`Known::refusal` has no caller). So one refused entry makes `Known::refusing(src, S)` true for good, against spec/sync-streams.md §4 Refused (not taken only while its stamp and that node's head are as they were): status never waits for that source again, and where it is the only source `heard_out` never holds, so `wait_synced`, life's heard out and emptying (`heard_out_or_alone` with a peer to wait for) wait forever.
> Priority: critical
> Tags: sync

A missing end: nothing ever turns `refusing` off while S stays shared there. The rows also grow with every entry ever refused, gone or not (no remover but `Op::Forget`).

Fix idea: a refusal stands only while its ground holds: drop the (source, S, blob) refusal when that source's head of S moves (`Op::Head` with another head), when the entry is shown again with another stamp, and when the entry leaves this node (or the source shows it deleted). `refusing` then reads only standing refusals; one row per entry held here at most.

Repro (fast, streams it with a `Pair`): a reads S, b keeps S unread and is a's only source; a logs an entry stamped under a key b's head does not know, b refuses it (code 1); assert `refusing` is true; register a new head at b whose key the stamp is under (or drop the entry at a); run: `refusing` must be false and a heard out once caught up. Today it stays true.

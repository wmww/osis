# A pending commit handed again is examined and stored again
> Summary: An identical copy of a commit already kept pending is decoded, its signature checked, examined, and its pending row written again (`apply::pend`: `put_pending`, `touch`), returning `Pending`, though it brings nothing; every duplicate arrival of a waiting commit costs a full ingest and a store write.
> Priority: normal
> Tags: engine, perf

Seen in osis-sync's `history::reference` (a reference engine handed every package until quiet): of 318 packages, 40 stay pending (content waiting outside the node closure until its ground comes) and every further round returned `Pending` for each and moved `Engine::point`. The harness now stops on "nothing applied, `Engine::pending` unchanged"; the product work per re-arrival stands.

Real nodes meet this whenever a waiting entry arrives again: several sources, a pull anew, a reconnect. The work is in proportion to the arrivals, not to what changed. Fix by structure: a copy whose parts the stored pending copy already holds (same ID, no part the pending copy lacks, `holds_whole`-style check against the pending row) returns `Duplicate` before decoding its parts or writing, as an applied commit's copy does. Check what the receipt (`first_received`) and the carrier set (apply/carriers.rs: a new carrier for an existing pending copy must still be recorded) need from the second arrival before skipping, and count it: ingests that write per duplicate pending arrival at n and 10n arrivals, 0 expected.

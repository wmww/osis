# A rebuild learns a thing's history roles secrets the live index misses
> Summary: The custody differential finds, in about 3 worlds in 2000, `check_index` failing when a fork rotation X made before its removal reaches A at the settle: rebuilt from the commit records, thing t's `secrets` hold epochs (n 6) known only by a roles secret from a history entry (`roles: Some`, no rotation, no secret) that the live index lacks. A rebuild differing from the live index is an engine bug whatever the model.
> Priority: normal
> Tags: engine, keys, tests

- Seen at the delivery of X's fork to A (the fork's epoch comes to be held and named; A holds its seed). Re-reading every actor boxing to P whole (not only its boxes keyed to P) when a keyset of P comes to be held (`account::refresh_epochs`, `JudgedEpochs::keyed`) was tried and does not close it, so the live path missing it is not the box ingest: find which history box the rebuild opens (`ingest_view`'s history alternatives, `open_histories`) and with which secret, and why the live arrival of the fork does not reach it.
- Reproduce by the differential with `CUSTODY_PROBE=1` (index checked after every delivery) and `--nocapture`; build the minimal test from the history box found (never pin the seed).

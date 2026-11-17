# keel-sync-sec
- A `sed` toggle of a fix for a fail-before check left a stray space, so the "re-applied" fix never matched and a world test passed for another reason (parked reopen). Toggle fixes with an exact grep count after, or a mutation probe (tools/mutate.py).
- World fill order is newest first: a hostile entry logged before the writer's own is fetched last. Partition, flush the writer, log the entry, heal.

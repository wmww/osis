# keel-owed2
- A 3 G budget fits engine and fake-ground tests only: one sync world test that waits out `PASS_WAIT_MS` (a delete waiting for a peer that is off) costs 7-10 G, mostly 500 dial ticks toward the absent node. `World::jump` with a low `horizon_ms` skips them but the delete then never comes (the wait runs on the monotonic clock?); no cheap way to wait an hour with a node away.
- `LocalPeer::sync` carries no ephemeral commit; an engine test hands one over by `memory_blob` + `ingest_memory`. Easy to miss: the test just reads as if the peer never held it.
- `mutate.py` batches only expressions; a statement mutation in the engine costs its own relink (two engine builds here).

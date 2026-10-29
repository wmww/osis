# Junk in a carried ephemeral `/created`
> Summary: A received ephemeral thing's `/created` part is checked only by its read value (a record hashing to the tid); the whole fragment is kept as `EphThing::created` on first sight and every node then carries it in each commit on the thing. A writer can add losing junk writes (any size) to that register and have honest nodes repeat them. Pre-existing; found in the eph-own-covers review, unverified by a test.
> Tags: security, engine, ephemeral

- Where: `Engine::ingest_ephemeral` (core/engine/src/ephemeral/remote.rs: `created` taken from the decoded part), `created_fragment`.
- Option: keep only the write `read()` returns (or refuse a `/created` part of more than one write; check first that an honest cover never joins two different minted writes for one thing).

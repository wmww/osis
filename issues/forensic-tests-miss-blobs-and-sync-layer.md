# Forensic deletion tests miss blobs, plaintext rows and the sync layer
> Summary: The shredding attack (`osis_store::forensic_plaintexts`, used by store/node shred tests and `removal_erasure_crash_safe`) opens only backend KV rows with store keys and greps for a literal marker. It never sees blob ciphertexts (`MemoryBackend` history records KV puts only), never chases application keys (wraps, label secrets, link keys, node-sync's `y/b` blob keys) into those blobs (only `purged_large_value_unrecoverable` does, for chunks), ignores unencrypted rows (`r`, `p`, `j`), and runs on the engine alone: no forensic test covers node-sync's records (`y/b` blob keys, `y/e` wraps, sealed body blobs). The crash-window leak fixed on branch store-audit (purger kept a purged body's blob key and ciphertext after a crash before node-sync's forget) was invisible to all of them.
> Tags: security, tests, store

## Suggested
- `MemoryBackend` history records blob puts too (a separate list).
- One shared attack helper: open every historic row with store keys (as now), then treat every 32-byte string and every wrap in recovered plaintexts as a candidate key for every historic blob (label `open`, wrap unwrap with recovered label secrets), to a fixpoint; also include unencrypted row values as plaintext.
- A node-sync-level forensic purge/expiry test (the `Net` harness with recording backends), including a crash at every write between the engine's dropping transaction and the sync flush, online and offline.
- Markers are not enough for "no confirmation of a guess": also assert no keyed hash (per-collection index keys) of a dropped map key survives in recovered plaintexts.

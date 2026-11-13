# Forgetting lost things keeps memory blobs of partly forgotten commits
> Summary: `State::forget_memory` (core/node/src/sync/state.rs) drops the memory records of forgotten labels and of commits forgotten whole, but not those of memory commit blobs holding a forgotten part of a commit that keeps other parts: their blob record (key) and bytes stay with their entries under labels still synced, until the entry goes. The store path drops such blobs (`forget_records`, `parts`).
> Priority: low
> Tags: ephemeral, node, security

- Bounded: one record per memory blob held at the forgetting, gone with its entry (deleted, expired, restart); no growth.
- Fix: the engine's `Forgotten` (core/engine/src/retention/forget.rs) hands node sync the `parts` map `retention::forget` already builds; `forget_memory` then treats a memory blob whose `BlobRec::parts` meets it as `forget_records` treats its `b` record.

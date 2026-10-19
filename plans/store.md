# Local store: Backend abstraction, encrypted units, key tree, paged state
> Summary: Implement `osis-store` per notes/local-store.md: the `Backend` trait (ciphertext key-value with transactions and a blob area; memory and one file implementation), the encrypted-unit layer with a key tree rooted in platform-erasable storage, unit kinds (aspect state with undo buffer and pre-reset snapshots, paged large states with index units, label wrap pages, secrets per actor, blob files, cursors), per-body death tracking, crash-safe transactions, and key-erasure deletion with tests that nothing survives.
> Tags: storage, security, tests

Crate: `osis-store`. Depends on: osis-core, osis-crypto (AEAD, kdf). Unblocks: node-core, server persistence (server may reuse `Backend`).
Spec: spec/commits.md §4 (one storage transaction per atomic apply), §5 (bodies, deaths, dropping means destroying every copy and index entry), spec/requirements.md (Deletion: forward secure; Scale). Notes: notes/local-store.md (the design), notes/data-model.md (Storage), notes/architecture.md §2 (`Backend`). Spec trumps this plan.

## Deliverables
- `Backend` trait: ordered byte keys; `get`, `put`, `delete`, `scan(prefix|range)`, atomic `WriteBatch` commit with durability, read snapshots; a blob area (`put_blob(BlobId, bytes)`, `get_blob`, `delete_blob`, streaming read of large blobs); `MemoryBackend` with a fault hook (fail or "crash" at the n-th write, used by crash tests and the simulator); one file backend behind feature `file-backend` (choose redb or rusqlite; criteria: pure Rust, build time, simplicity; record in notes/architecture.md). Backends hold ciphertext only.
- Key tree: 256-ary tree of 32-byte unit keys, interior nodes encrypted under their parent, root in `RootStorage` (trait: hardware keystore later; MVP: a file written with fsync-and-rename, plus an in-memory root for tests; record the tier). Delete/rotate a unit = fresh keys along the path, rewrite nodes, write root last, then delete old nodes; batched per transaction.
- `Store` API (what node uses): typed units with encrypt-on-write/decrypt-on-read: `AspectUnit` (state bytes + undo buffer + pre-reset snapshots + per-body death records: first and last death), paged large aspect state (pages at content-defined boundaries over consecutive elements plus index units `key -> page`, `dot range -> page`, text `dot -> position`, themselves paged when large: an edit rewrites one page and its index path), `LabelPage` units (entries with wraps per label, a few KB per page), `ActorSecrets` units, blob ciphertext storage, `Cursor`/gained-IDs units, counters per (aspect, node) (must be durable before a commit is signed), pending/parked commit units (bytes with header), `Transaction` spanning units with all-or-nothing semantics.
- Shredding operations: `drop_body(blob_id)` (removes the body's units' plaintext copies: its content in the aspect unit's undo buffer and pre-reset snapshots too), `drop_wrap(label, blob_id)` (rewrites the page under a fresh key), `drop_actor_secrets`, `drop_aspect`, each rotating the key path. Rebuildable indexes are declared so (dropped and rebuilt on purge).
- Crash safety: write-ahead semantics via the backend's atomic batch; recovery on open; the "deletion counts only after root replacement is durable" rule.
- Memory bound: paged units stream; no API materializes a whole large aspect.

## Steps
- [x] `Backend` + `MemoryBackend` with fault hook; file backend behind feature with the same test suite (trait-generic tests).
- [x] Key tree with `RootStorage`; unit encrypt/decrypt; rotation; tree tests (16M-unit shape test at reduced arity).
- [x] Units and `Transaction`; death records; counters; pending commits.
- [x] Paged large state units with indexes (works with `osis-crdt` paging via `PageSink`/`PageSource` adapters when crdt-core lands; until then over opaque pages).
- [x] Shredding: after `drop_*`, scan the raw backend bytes and the old key material to show the plaintext is unrecoverable (test encrypts a marker string and searches for it; and decrypting with every surviving key fails).
- [x] Crash tests: inject a crash at every write index of a transaction and reopen; state is either before or after, never between; the root rule holds.

## Tests
Property: random unit operations with crashes vs an in-memory oracle; concurrency: many handles, one writer; perf tier 2: a million small units, one edit of a million-key paged state touches O(1) pages.

## Done when
node-core persists through `Store` only; crash and shredding tests green on both backends; notes/local-store.md gains an "Implementation" section (backend chosen, unit key formats, limits). Delete this plan.

## Progress
- Steps 1-6 landed (osis-store: Backend, MemoryBackend/FaultyBackend, RedbBackend, RootStorage/FileRoot, key tree pager, tables, typed Store API, shredding and crash tests); notes/local-store.md has the Implementation section. Crash tests run on both backends; the forensic shredding attack runs on memory only (redb: no plaintext in the file). Review fixes: aborted-spill rollback, shred on page moves, blob rollback, FileRoot repair, crash-safe create. Left: node-core persisting through `Store` (node-core plan), concurrent readers (issues/store-concurrent-readers.md). PageSink/PageSource adapters belong to node (layer DAG).

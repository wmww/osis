# Node (osis-node)
> Summary: Module layout and ownership of `osis-node`, the engine's public surface, what it keeps in the store and in memory, and the readings node-core fixed (pending, validity, bodies, receipts, counters). node-sync and membership-flows extend the layout here.

## Modules and ownership
| module | owner plan | contents |
|---|---|---|
| `engine/` | node-core | `Engine` (create/open, one store transaction per call, caches), `Mutation` and the writing path (`write.rs`), reads and synthetic aspects (`read.rs`), HLC (`clock.rs`), secrets and the commit `Secrets` (`secrets.rs`), local state codec (`state.rs`), store record layouts (`records.rs`), blob adapters (`blobs.rs`) |
| `apply/` | node-core | `ingest`, `examine` (verification, pending reasons, parking), atomic apply (`atomic.rs`), perm adaptation and validity (`validity.rs`), receipt record (`receipt.rs`), `load` (index rebuild) |
| `retention/` | node-core | deaths, keep bounds, expiry and keep-at-most timers (`tick`), purge requests, body drops, compaction snapshots, `covered`, deletion and re-snapshot queues |
| `undo/` | node-core | undo buffer, undo commits, derived undo/redo stacks, admin change list |
| `identity/` | node-core | node seed, keys, creation records |
| `events/` | node-core | `Event`, `Diagnostic`, subscriber channels |
| `local_peer.rs` | node-core (sim grows it) | `Peer`, `LocalPeer`, `Package`, `Engine::package` |
| `labeling/` | node-sync | closure, entitlement, projection, wraps, stamps, deposits, certificates |
| `sync/` | node-sync | `SyncEngine` (sans-I/O) and its tokio driver |
| `flows/` (+ `rotation/`) | membership-flows | grants, demotions, rotations, roster snapshots, links, moves |

## Public surface (engine)
- Lifecycle: `Engine::create(backend, root, Config, clock, rng)` (new identity, node thing with `/created` + `/node`, then `/keys`), `Engine::open(..)` (reload, re-examine pending), `tid`, `identity`, `now` (corrected clock), `set_clock_offset`, `subscribe() -> Receiver<Event>`.
- Writing: `Mutation` (`create(record)`, `set`/`replace`/`remove_aspect`/`op` through any `AspectKey`, `retention`, `expires`, `purge`, `frontier`, `act_as`, `commit_form`); `Engine::new_thing(&mut m, owner)`, `Engine::commit(m) -> Option<CommitId>`.
- Receiving: `ingest(bytes, blobs)` / `ingest_from(.., peer)` -> `Ingested::{Applied, Duplicate, Pending(reason), Parked}`; `reexamine`, `set_syncing(tid, on)`, `tick` (expiry, keep-at-most, drift), `pending()`.
- Relaying: `commit_ids`, `header`, `commit_bytes`, `blob`, `package`.
- Reads: `get`, `get_typed`, `aspects`, `groups_of`, `roster`, `role_on`, `resolve`, `state`, `knows`, `all_aspects`.
- Retention: `snapshot(tid, ak)`, `covered(snapshot, body, tid, ak)`, `drop_body`, `body_keep`, `deaths`, `holds_body`, `deletions(from, limit)`.
- Undo: `undo(id)`, `undo_stack(actor, scope)`, `changes(scope)`.
- Membership inputs: `receipt(tid, ak)`, `frontier(scope, as_of)`.

## Store records
Local records (`*_local`): `seed`, `hlc`, `c/`+ID commit records (received, origin, dropped parts, current blob), `t/`+tid creation records, `r/` receipts, `v/` value-less deltas, `p/` purge requests per aspect, `x/`+T timers, `s/` synced things, `o/` voided commits, `k/`+tid opened epochs, `a/` aspect index; logs `deletions`, `resnapshot`. Store kinds: aspect units (state = snapshot grammar with its pages inline; undo = pre-commit states of recent local commits), counters, death records (body ID = commit ID), pending/parked commits, blob ciphertexts (pages, chunks, header-list trees).
In memory (`Core`, rebuilt by `apply::load` at open and after any failed transaction): states cache, perm `MemoryHeldSet` + `Timelines`, commit headers with validity and dropped parts, per-aspect commit index, node-form ranges, pending reasons, value-less lists, secrets, `/was`/`/moved`/group indexes, `/members` entry keys.

## Readings fixed here
- **Counters**: reserved in the same transaction that applies the signed commit; nothing signed leaves the node before it is durable, so no counter is reused and no gap is left by a crash.
- **HLC**: a writer exhausting `logical` within one ms moves to the next ms instead of waiting.
- **Pending "chain certificates missing"**: the author's or an owner chain's `/created` is missing, or the author is neither on the touched thing's owner chain nor named as a member by any held edge write. A commit whose author has a chain here but no role applies with its deltas invalid and re-merges on re-grant.
- **Body** = one delta (commit, aspect); death records per (aspect, commit). A projection's bounds are its deltas'.
- **Validity**: re-judged for every held delta whenever the perm held set changes (O(held deltas)); a flipped aspect is rebuilt as `unmerge(state + held bodies, sources with an invalid delta) + their valid bodies`. Compaction snapshots are bodies whose invalid sources' writes are removed the same way.
- **Edge writes from `/members` deltas**: a keyed entry sets the edge it reads; a reset of a known entry dot removes it (keys learned from held keyed entries; a commit whose removed key is unknown waits in `unresolved` and is re-derived when keys arrive); nested field writes overlay the entry's created value. Flows should write a change as remove + put.
- **Purge**: judged by perm `may_purge` at the request's point; kept per aspect so deltas arriving later are purged on arrival.
- **Undo buffer**: pre-commit states of the last 16 local commits per aspect; cleared (shredded) whenever a body of the aspect drops.

## Open
- Large atomic values (chunk trees) wait for plans/large-values.md; sequences for crdt-seq.
- Cost: open replays all commit records; every membership change re-judges every delta; states load whole (no paged local state).

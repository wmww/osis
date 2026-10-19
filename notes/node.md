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
| `moves.rs` | node-core | `move_thing`: copy with `/was`, one import commit per origin, re-sourcing (`Fragment::map_dots`), double-import guard |
| `local_peer.rs` | node-core (sim grows it) | `Peer`, `LocalPeer`, `Package`, `Engine::package` |
| `labeling/` | node-sync | reader actors, entitlement, closure, labels of a group (`actors.rs`), bodies, sealing, wraps, head keys, tokens (`blobs.rs`), certificates, step readers, new labels (`certs.rs`), the convergence rule (`converge.rs`) |
| `sync/` | node-sync | `SyncEngine` (sans-I/O: `mod.rs`), durable sync state (`state.rs`), opening and walking (`open.rs`), inbound entries and signals (`inbound.rs`), the pass (`pass.rs`), app and flows requests (`local.rs`), bundles (`bundle.rs`), tokio driver (`driver.rs`) |
| `flows/` (+ `rotation/`) | membership-flows | grants, demotions, rotations, roster snapshots, links, moves |

## Public surface (engine)
- Lifecycle: `Engine::create(backend, root, Config, clock, rng)` (new identity, node thing with `/created` + `/node`, then `/keys`), `Engine::open(..)` (reload, re-examine pending), `tid`, `identity`, `now` (corrected clock), `set_clock_offset`, `subscribe() -> Receiver<Event>`.
- Writing: `Mutation` (`create(record)`, `set`/`replace`/`remove_aspect`/`op` through any `AspectKey`, `retention`, `expires`, `purge`, `frontier`, `act_as`, `commit_form`); `Engine::new_thing(&mut m, owner)`, `Engine::commit(m) -> Option<CommitId>`.
- Receiving: `ingest(bytes, blobs)` / `ingest_from(.., peer)` -> `Ingested::{Applied, Duplicate, Pending(reason), Parked}`; `reexamine`, `set_syncing(tid, on)`, `tick` (expiry, keep-at-most, drift), `pending()`.
- Relaying: `commit_ids`, `header`, `commit_bytes`, `blob`, `package`.
- Reads: `get`, `get_full`, `read_large`, `get_typed`, `aspects`, `groups_of`, `roster`, `role_on`, `resolve`, `state`, `knows`, `all_aspects`.
- Retention: `snapshot(tid, ak)`, `covered(snapshot, body, tid, ak)`, `drop_body`, `body_keep`, `deaths`, `holds_body`, `deletions(from, limit)`.
- Undo: `undo(id)`, `undo_stack(actor, scope)`, `changes(scope)`.
- Membership inputs: `receipt(tid, ak)`, `frontier(scope, as_of)`, `epochs(actor)`, `register_schema`.
- Labeling: `group_actor`, `may_read`, `closure`, `labeled_groups`, `group_labels`, `bodies`, `label_bodies`, `partial_bodies`, `wrap_secret`, `stranded_secret`, `deposit_seed`, `head_keys`, `tokens_for`, `certificates`, `create_label` (notes/sync.md, Implementation (osis-node sync)).
- Move: `move_thing(t, owner) -> (copy, imports)`; `/moved` is an ordinary write by T's admins; reads resolve tids (except in `/tid`, `/created`, `/was`, `/moved`) through `/was` standing then `/moved`.

## Store records
Local records (`*_local`): `y/` sync state (notes/sync.md), `seed`, `hlc`, `c/`+ID commit records (received, origin, dropped parts, current blob), `t/`+tid creation records, `r/` receipts, `v/` value-less deltas, `p/` purge requests per aspect, `x/`+T timers, `s/` synced things, `o/` voided commits, `k/`+tid opened epochs, `a/` aspect index; logs `deletions`, `resnapshot`. Store kinds: aspect units (state = snapshot grammar with its pages inline; undo = pre-commit states of recent local commits), counters, death records (body ID = commit ID), pending/parked commits, blob ciphertexts (pages, chunks, header-list trees).
In memory (`Core`, rebuilt by `apply::load` at open and after any failed transaction): states cache, perm `MemoryHeldSet` + `Timelines`, commit headers with validity and dropped parts, per-aspect commit index, node-form ranges, pending reasons, value-less lists, secrets, `/was`/`/moved`/group indexes, `/members` entry keys.

## Readings fixed here
- **Counters**: reserved in the same transaction that applies the signed commit; nothing signed leaves the node before it is durable, so no counter is reused and no gap is left by a crash.
- **HLC**: a writer exhausting `logical` within one ms moves to the next ms instead of waiting.
- **Pending "chain certificates missing"** (decided): the author's or an owner chain's `/created` is missing, or the author is not on the touched thing's owner chain and no held edge writes lead from it (as member, through member actors) to a thing on that chain. Revoked authors keep their certificates, so their commits apply, judged invalid; re-grant re-merges.
- **Prefix vs header** (spec/commits.md §4 last rule) is checked by node-sync where blobs are opened; `ingest` takes plaintext.
- **Body** (decided) = one projection class of a commit: deltas sharing the reader actor (the thing if it has secrets of its own, else its owner), retention, expiry and token indices. Its ID = BLAKE3(commit ID ‖ first aspect index of the class) keys the death records; first death = earliest, last = latest over its deltas; keep-at-most drops the whole class. Expiry and purge still drop single deltas (the commit is kept without them).
- **Validity**: re-judged for every held delta whenever the perm held set changes (O(held deltas)). Un-merge is by invalid delta, not by author: every body (the current state counting as one) is stripped of the writes owned by deltas invalid here (`Fragment::remove_dots` with `Owned::owns`: node-form counter range or commit ID) before it joins, on apply as well as on rebuild, so another writer's nested write under an invalid creation goes on every node alike. An invalid delta arriving rebuilds its aspect. Compaction snapshots are bodies stripped the same way.
- **Membership content rules** are writer-side only: a received commit breaking them is applied and perm judges each edge write at its point.
- **Atomic wait**: missing deltas that expired, or that a held purge request names with the right, count as held; a part whose bytes miss its delta hash is dropped alone (diagnostic) and the commit waits for, or applies without, it.
- **Rollback**: a failed transaction restores the indexes from a copy taken at the transaction's first change (`Core::touch`) and evicts the states it wrote; no reload from the store (cost: one copy of the indexes per changing transaction).
- **Snapshots**: frontiers cover node-form counters contiguously applied and valid on the aspect; retention takes the schema's default bounds from a registered schema (`Engine::register_schema`; local typed writes register theirs).
- **Moves** run in one store transaction (spec/permissions.md §7 edit).
- **Established epochs** (`apply/keys.rs`, spec/crypto.md §4): an applied valid commit's `/secrets` write calls `SecretsWrite::applied` with its `/keys` write (whole keysets: flows replace the field) and the keysets held before; a removal is a keyless reset, so box keys come from an index of held keyed entries, and a write whose removed keys are unknown waits (persisted under `w/`) until they arrive, so a rotation received before the one it supersedes is not established. A held `/secrets` compaction snapshot calls `snapshot_keyed`; a delta found invalid `unset_applied` + `establish`, valid again re-applies (keysets before taken as the current `/keys`). Epochs persist `established`, `applied`, `snapshot` (`k/`), never re-inferred. `/secrets` compaction is gated on `may_compact_secrets`. `Engine::epochs(actor)` exposes the view.
- **`/secrets` and `/keys`** deltas need the highest role they rotate or box (at least write): admin for an admin box, history key or keyset.
- **Edge writes from `/members` deltas**: a keyed entry sets the edge it reads; a reset of a known entry dot removes it (keys learned from held keyed entries; a commit whose removed key is unknown waits in `unresolved` and is re-derived when keys arrive); nested field writes overlay the entry's created value. Flows should write a change as remove + put.
- **Purge**: judged by perm `may_purge` at the request's point; kept per aspect so deltas arriving later are purged on arrival.
- **Undo buffer**: pre-commit states of the last 16 local commits per aspect; cleared (shredded) whenever a body of the aspect drops. Undoing another node's commit (admin view) takes the pre-state as the join of the held valid bodies ordered before it.
- **Writer-side membership rules**: at most one `/members` edge per membership commit (a redemption's grant plus self-removal excepted); a frontier only on a commit that lowers an edge; a removal or demotion of another member on a thing with a `/keys` keyset carries `/secrets` and `/keys` deltas of it. A local commit breaking them, or with any delta invalid at this node, fails before it leaves.
- **Import**: one import commit per origin commit (header kind 4 has one delta per aspect and each delta carries its origin's retention); a write of origin C on T maps to `(Commit(C), ctr)`, foreign dots it references to `(Commit(creator), ctr)` via the node-form range index; expiring, value-less, invalid and dropped deltas are skipped. An invalid import un-merges its origins' re-sourced writes.

## Open (issues/node-core-gaps.md)
- Large values: positions of root and path `set`/`replace`/`add` values are chunked (osis-label `chunk_value`, framed like the delta's pages, blobs in the store); no chunk reuse from the current tree yet (`Reuse`), no streaming reads (`read_large` reads whole); sequence `Insert` items are not chunked.
- Cost: open replays all commit records; every membership change re-judges every delta; states load whole (no paged local state).

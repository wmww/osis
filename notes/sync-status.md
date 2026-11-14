# Sync: status
> Summary: osis-sync's `status` module (core/sync/src/status/): sources and caught up, heard out, lacking counts, own commits held elsewhere, complete passes and `wait`; read when asked in O(sources of S); the readings it implements beyond the spec's words, its costs, and what is not built (held elsewhere for own entries).

Spec: spec/sync-status.md. Model: core/test/tla/net/NetStream.tla (`Synced`, `CaughtUpHolds`). Principle: the module doc of core/sync/src/status/mod.rs. Overview: notes/sync.md.

## What it owns
What a source is caught up on, full or refusing is streams' (stamped per connection and per (source, S)), so a sync ID's status is read when asked (`Status::of`, `Node::status_of`), O(its sources): nothing is kept per S that a push would have to move. Status keeps only what needs acting on, each an `Effects` key: the sources of S (from `Moved`, handed by the driver beside streams), the sync set's projection (a row per S held, kept unread included), lacking counts per (S, source keeping S unread), own commits per read S and those not held elsewhere, self-removals, complete passes. Durable: held elsewhere, as a flag on the entry (`Store::set_elsewhere`), so it goes with the entry.

`SyncStatus { holding, sources, stranded, pass_waits, unheld }` with `heard_out()`, `readers()` (by account), `synced()` (heard out and `unheld == Some(0)`). `Node::idle` is `Sessions::idle` (no request, fill or Hello outstanding).

Seams: `status::Net` (read when asked: streams, unread) and `status::Ground: Net` (the settle's: engine, store, opens, read; `status/live.rs` the product's), so core/sync/tests/it/status.rs runs it on a fake.

## Caught up and passes
- Streams gives `caught_since(conn, s)`: caught up both ways (this side's stream at its end, `SN_rearm`; and the peer pulled, is followed at the log's end with the memory mark current, no join left in pages, its Applied at or past the last message served asking a report), with when the Pull the last reply answered was sent.
- A complete pass reads `caught_since` against its start and asks `Streams::pull_again` (a Pull sent once any under way ends). Opens lists `records_holding(store, s)` (the store's member index merged with records in memory; at a pass's start only).
- Wants come from the engine's `passes_wanted()` (notes/sync-facade.md); each pass's begin is kept on both clocks: the node's (caught-up times and `PASS_WAIT_MS`) and `Engine::pass_clock` (the engine's, on which `received` and the wants are), the latter told back by `note_complete_pass`. A new want past a pass under way queues at most one more pass of S, each bounded by `PASS_WAIT_MS`.

## Readings
Written into spec/sync-status.md: caught up is per connection (every message served there, whatever S); heard out needs one source not full or refusing (only such sources is not heard out); a source keeping S unread counts for held elsewhere by its stream alone (its Applied passes what it refused for room, `Full` names no entry, and an unstamped entry it never takes and never refuses); a reader also by a reported position at or past the entry's first log position, capped at a member's `until`; a wait on a thing runs to its timeout while one sync ID carrying it is unconnected.

Kept in code only: lacking applies to sources keeping S unread (a reader re-encrypts and judges what it keeps), counted as the stamped entries here its stream did not show (deposits offered are not counted); the heard-out half of a pass is "every waited source caught up since it began" (with none: vacuous), so a pass with no source waits only on its records; a full or refusing source is not waited on in a pass; stranded is per S (unread's); `wait(All)` is every S held; `wait(Deliveries)` is inbox's (`Never` here, which the osis API fails `NotBuilt`).

Model check: core/sync/tests/it/streams.rs `caught_up_matches_what_each_side_holds_spec_sync_status_1` runs random histories (logs, inline and fetched bodies, frame orders, pushes refused for room) against both sides' holdings.

## Costs
A lacking count is taken again whole, O(S's stamped entries), at each change of what that source showed or of S's entries (issues/status-lacking-count.md). `passes_wanted` is one whole memo (issues/sync-passes-wanted-whole.md).

## Not built
issues/sync-held-elsewhere.md: the store's own entries by commit (`status/live.rs` `own_entries` answers `NotBuilt`), so no own commit of a read S that S must hold is ever held elsewhere: `wait` on such a sync ID stays pending and a self-removal's secrets never drop. issues/sync-unbuilt.md (status): covered by a snapshot at a source (spec/sync-status.md §2: a body a source dropped under a snapshot before showing it never counts, an under-claim); a wait on a stranded sync ID failing `Unsynced` (best as a distinct answer of `Node::wait`, not a `Never`); waits on deliveries.

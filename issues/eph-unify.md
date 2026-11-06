# Ephemeral as a storage property: what is left
> Summary: Ephemeral data is ordinary data whose commits, bodies and index rows live in memory (Tess's direction: "ephemeral should be same as durable in almost every way"; built through the durable sync path, notes/ephemeral.md, `core/node/src/sync/memory.rs`). Left: D (undo over held bodies, so the ephemeral undo log goes), E (durable automatic compaction, Tess's call), and four residuals below.
> Tags: ephemeral, design

Kept by design: memory storage itself, presence (author tie), signals (relay-only), the restart reconcile, a node cap and host caps. What differs from durable: an expired ephemeral delta vanishes whole, never value-less (spec/crdt.md §4.7); a memory commit's header is forgotten once spent (spec/commits.md §5).

## D. Undo over held bodies
Undo of ephemeral writes still runs on its own log: `core/engine/src/ephemeral/log.rs`, `Config::ephemeral_history` (16 MiB), ephemeral `NotUndoable{Compacted}`, and `BatchId::Ephemeral` for an ephemeral-only write. Make it durable's undo over held bodies, with undo depth set by retention (keep at least on an ephemeral aspect = kept in memory while anyone holds it). `BatchId::Ephemeral` then becomes a commit ID (issues/deprecated-terms.md, batch row). API delta in notes/api.md. Independent of E.

## E. Durable automatic compaction
Durable has only explicit `compact`; ephemeral aspects compact automatically (the memory trigger, `Engine::memory_compactions`). A durable policy changes host storage and purge timing for durable data: Tess's decision, so `tess-call` belongs on its own issue when someone picks it up.

## Residuals
- **Carrier-only retention**: durable never compacts an aspect whose snapshot would keep at least and at most (carrier only, spec/commits.md §5); such ephemeral aspects get no coalescing either and grow until their keep-at-most bounds or expiry drop bodies, against the caps. Refuse that retention on ephemeral aspects, or accept it.
- **Reconnect burst**: over `MAX_GAINED` memory entries per label a new connection lists no `gained`, so every held body goes up again there once (a cap-sized burst per reconnect).
- **Unplaced bodies**: a memory body is deleted at a label for leaving its closure only by a node that judged or placed it while its thing was in the closure since the node started (`State::memory_in_closure`, spec/sync.md §9); bodies of an unplaced thing stay at a host if only other nodes remain.
- **Paging and a divergence**: issues/eph-unpaged-cover.md (memory deltas never page), issues/ephemeral-restart-reverts-diverge.md.

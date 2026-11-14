# Sync: overview
> Summary: Map of osis sync as built: the principle, the crates, the one step and its settle loop, how a write reaches a peer, where each spec area lives in code, and the index of the sync notes (one per osis-sync module, the engine facade, design reasons, harness).

The rules: spec/sync.md (words, the two holdings, one principle per area) and spec/sync-*.md; byte layouts spec/wire.md. The requirements behind them: spec/requirements.md, Data a node cannot read, Deletion, Offline and network.

## Principle
The engine owns plaintext and every judgement of what a thing carries; sync owns ciphertext, connections and what peers showed. Sync reads the engine only through one facade of memo-backed queries and a few commands (`osis_engine::sync`, notes/sync-facade.md); the engine calls nothing of sync's. Every rule is driven by change: each module follows what it reads through `osis_base::memo::Effects` keys and feeds, so an idle node does no per-sync-ID work and a change costs what it touched (spec/sync.md §2 Work in proportion to change).

One kind of node: whether a node reads data is a property of the pair (node, S). Per S a node holds it read (a read secret held: full judgement in `read`), kept unread (a sync secret only: `unread` judges signatures and its own grant), or not at all.

## Crates
- **osis-sync** (core/sync): the node's connections, its store per sync ID and the judgement over them, as one sans-IO step. Modules, one per area, each owning its state and changing no other's: `session`, `opens`, `store`, `read`, `unread`, `streams`, `inbox`, `status`, `driver`; `set` (the sync set followed per key, shared by store, opens and dials); `types` (every type two modules share; a type one module owns and others only read lives in that module). A part not built answers `Error::NotBuilt` or does nothing; no path a test reaches panics. The tokio transport glue is behind the default `driver` feature, the crate's one feature set.
- **osis-engine**'s `sync` module (core/engine/src/sync): the facade.
- **osis-proto** (core/proto): codecs below sync (frames, Hello, proofs, messages and their limits, filters, relay gate, the client port's messages); no session or store (notes/sync-protocol.md).
- **osis-label** (core/label): blob prefix and wraps, steps, claim sets, stamps and deposit signatures, inbox blobs, links, bundles.
- **osis-store**: the store primitives sync builds on (local rows, per-peer `record` rows under `RECORD_BUDGET`, `nodelog`, `changed`), and `CipherHost`, through which the engine keeps blob bytes in sync's store.
- **osis-transport**: connections below sync (notes/networking.md).
- **osis** holds a `Node` per handle and steps it from its driver task (notes/api-implementation.md).

## The one step
`Node::handle(input) -> Vec<Out>` is all of sync: route the input to its module, run the compaction trigger, settle every module (store, unread, opens, read, inbox, streams, status) until none acted, flush opens' records, decide dials and keep-or-close, then emit sends, dials, closes and one wake. `apply(out, links)` alone carries outputs out. Inputs: a connection up or down, bytes, bytes the transport took, a wake, a discovery, and `Wrote` after the osis handle writes. Details and failure handling: notes/sync-driver.md.

## How a write reaches a peer
1. The app writes through the osis handle; the engine commits it and calls nothing; the handle calls `handle(Wrote)`.
2. `read` follows the engine's commit feed: the commit's `sync_bodies` say under which sync IDs S of the sync set it has a body; per (S, commit) it judges must-hold and logs an own entry (`seal_body`, stamped where this node writes S's head, else deposited) into the `store`, one transaction with its node-log event.
3. The store's entry and log changes are stamped. On each connection where S is in the shared set (`opens`), `streams` serves the peer's Pull from the node log filtered by the shared set; with the peer following, the event goes as a push under `follow` with `seq`, the body inline up to `INLINE_LIMIT` or fetched.
4. At the peer, `streams` applies messages in order once their bodies are held: a reader opens the entry (`Engine::open_entry`), which ingests the commit; a node keeping S unread verifies the stamp and logs it. The peer stores its cursor only then and reports it in an Applied.
5. `status` at the writer sees the source caught up and, once the peer's stream showed the entry (or a reader reported a position past it), counts the commit held elsewhere.

## Spec areas in code
| spec | code |
|---|---|
| spec/sync-set.md (what a node syncs) | engine `sync/set.rs` (`sync_things`, `thing_sync`, `sync_set`), osis-sync `set.rs`; `unread` for leaving |
| spec/sync-ids.md (sync IDs, steps, the store, Register, Behind, Walk) | engine `labeling` and `sync/records.rs`; `store` (entries, paths, caps, Register, Delete, Behind); `opens` (Walk); `inbox/register.rs` |
| spec/sync-opens.md (dials, proofs, records, the shared set) | `driver/dials.rs`, `session` (proofs), `opens` |
| spec/sync-judgement.md, spec/sync-compaction.md | `read` (reader), `unread` (kept unread); engine `sync/facts.rs`, `bodies.rs`, retention |
| spec/sync-inbox.md | `inbox`; engine `sync/inbox.rs`, `deliveries.rs` |
| spec/sync-streams.md | `streams`, `session` (window, pushes) |
| spec/sync-status.md | `status`; engine `sync/held.rs` (passes, held elsewhere) |
| spec/sync-hostile.md | bounds in each module: `session` (per connection), `store` (caps, peer budget, deposits), `opens` (records, filters) |
| spec/sync-transport.md | osis-transport, `driver/links.rs` |
| spec/wire.md §11 | osis-proto `msg`, `session` |

## The sync notes
- notes/sync-session.md, sync-opens.md, sync-store.md, sync-read.md, sync-unread.md, sync-streams.md, sync-inbox.md, sync-status.md, sync-driver.md: one per module (what it owns, its implementation choices, bounds, reasons, what is not built).
- notes/sync-facade.md: the engine's facade, the memo and `Effects` mechanism, the engine tables kept for sync.
- notes/sync-test-harness.md: the one harness (worlds of `Node`s, scripted peers, histories, faults).
- Design reasons: notes/sync-reasons.md (core: blobs, sync IDs, stamps, delete keys, nodes), notes/sync-access.md (steps, claims, re-seal, static entries), notes/sync-convergence.md (judgement and deletion), notes/inbox.md (deposits, inbox), notes/unreadable-data.md (what a node keeping S unread learns), notes/sync-protocol.md (wire, osis-proto, osis-label), notes/networking.md (transports, reachability, first contact), notes/growth.md (permanent growth).
- Open: issues/sync-unbuilt.md (every stub, per module), issues/sync-tess-calls.md (reversible choices waiting on Tess), and the `sync`-tagged issues.

## The osis API over sync
The handle holds the `Node`. `status`, `on_status_change` (status reads are stamped, so a memo over `Node::status` moves with it), `wait_synced` (`Node::wait`; a `Never` is a part not built and fails `NotBuilt`), links and redeem (`Node::redeem`), contact cards and profiles, invitations and `accept_invite`, bundles, `listen`, `rotate_peer_address`, `Config::dial`, the client port (`PortEvent`), and `internals::ManualNet` (the API tests' in-memory fabric, one `Links` per node through `apply`) all run on it (notes/api.md Sync configuration and status). No peer list exists and sync IDs are internal: a thing syncs by being in a synced group's closure.

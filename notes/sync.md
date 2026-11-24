# Sync: overview
> Summary: Map of osis sync as built: the principle, the crates, the one step and its settle loop, how a write reaches a peer, where each spec area lives in code, and the index of the sync notes (one per osis-sync module, the engine facade, design reasons, harness).

The rules: spec/sync.md (words, the two holdings, one principle per area) and spec/sync-*.md; byte layouts spec/wire.md. The requirements behind them: spec/requirements.md, Data a node cannot read, Deletion, Offline and network.

Where the spec is unclear, code the simplest reading behind one named function and write the reading into the spec or the module's note.

## Principle
The engine owns plaintext and every judgement of what a thing carries; sync owns ciphertext, connections and what peers showed. Sync reads the engine only through one facade of memo-backed queries and a few commands (`osis_engine::sync`, notes/sync-facade.md); the engine calls nothing of sync's. Every rule is driven by change: each module follows what it reads through `osis_base::memo::Effects` keys and feeds, so an idle node does no per-sync-ID work and a change costs what it touched (spec/sync.md §2 Work in proportion to change).

One kind of node: whether a node reads data is a property of the pair (node, S). Per S a node holds it read (a read secret held: full judgement in `read`), for keys (a holder its synced things' grants name: role entries alone, judged as read; Held for keys below), kept unread (a sync secret only: `unread` judges signatures and its own grant), or not at all.

## Arriving early: one parking place
**Rule (Tess):** an item that arrives before what it needs parks under the one thing it awaits, and that thing arriving wakes only what is parked under it: nothing walks every waiting item, and no layer grows its own wait-and-retry. One rule, two forms, because the two sides await different kinds of thing:
- **Engine**: a pending commit awaits the engine's own rows (a record, a commit, a time, blobs, a thing's lists, the role inputs), which must roll back with `pending` in one journal. So it parks in `Indexes::pend_on` under each `Wake` it awaits, journaled with `pending`; `reexamine` examines what the arrivals woke (notes/sync-facade.md Pending). `Engine::lost_wakes` (the `order` harness, every step) checks a full scan applies nothing the wakes left.
- **Sync**: what sync awaits is always a facade value, which `Effects` already follows by what each settle read: a waiting item is an `Effects` key whose last value read it, due exactly when what it awaits is written; no second index. Where many items await one value (a store entry that did not open, awaiting S's read secrets; one whose blob holds a missing part sealed, awaiting that part's thing's), the value is one key and the items are a set under it (`store::Follow::parked`), examined only when the key moves: O(items parked), never O(S's entries). An entry's wait is a function of its commit being held or pending (neither: it waits for S again), so the store re-parks the entries of each commit the engine stops holding and of each it stops pending (`Engine::unheld_feed`, `unpending_feed`): a pending copy can go while its entry stays (a fire's copy applies it and it is forgotten between two follows). `Node::lost_parks` (the convergence harness, every step) checks every entry of a known commit is parked under all it awaits; flows.rs counts the work at n and 10n.

A failed read is no wait: `Effects::try_settle` records nothing and leaves the key due, and the error fails the step. Waits on a peer (an offer refused for now, a refused Pull, a Behind) are back-offs and timers, not this rule: nothing local arrives to end them.

## Held for keys
A holder the engine holds for keys (notes/node-closure.md, The node's role) has its sync ID in the sync set as `Holding::Keys` (`Engine::thing_holdings`; `rows::fold`: read over keys over kept unread). Spec: spec/sync.md §3, spec/sync-opens.md §4 Source, spec/sync-streams.md §4.
- **The class says it**: each Hit, Static and ByRole item and each answer accepting one declares how its side holds S (`class`, spec/wire.md §11.2: 0 reader, 1 store, 2 keys; `osis_proto::SourceClass`, `types::class_of`). A selector on `Pull` would tell the server only what to send; the class also tells every rule reading a source that this peer holds none of S's content (held elsewhere counts it by its stream alone, `status` `reported`; no Register, Delete or deposit goes to it), on every connection and before any Pull. A class that moves closes the member and opens it again (notes/sync-opens.md, Class).
- **Served** (`streams::serve::for_keys`, `role_entry`): a keys source gets Added events and Fetch answers of role entries alone, no ephemeral listing and no relay-only blob (`relay::pass_on`); Deleted and head events go as to any member. A server keeping S unread tells a role entry by its row (`Entry::role`, the domain its stamp or deposit signature verified under); one reading S by its own judgement (`Ground::role_entry`, `Engine::role_entry`: a record or list blob, or a blob of a `role_commit`).
- **Role entries are stamped as such** (spec/sync-ids.md §6 Role entries; `read::live` `own_entry`, `restamp`, `deposit`): role commits, commits carrying a purge request, record and list blobs. A store takes them outside its caps.
- **At the node holding for keys** every ask whether S is opened by a read secret answers as for a read (`Holding::opens`: credentials, taking and opening, parking, own entries, steps, record blobs, promotion, passes, stranding, status), since its sources show it role entries alone; it takes no relay-only blob. History completeness (`caught_up`) counts read sync IDs alone. Raised from keys to read, or from kept unread to keys, S is pulled anew from every source (`store::raised`).

## Crates
- **osis-sync** (core/sync): the node's connections, its store per sync ID and the judgement over them, as one sans-IO step. Modules, one per area, each owning its state and changing no other's: `session`, `opens`, `store`, `read`, `unread`, `leave`, `streams`, `inbox`, `status`, `life` (lifecycle duties, notes/sync-driver.md Duties), `driver`; `set` (the engine's sync set followed per key, which `leave` alone follows, and `SyncsFollow`, each module's cursor over the sync IDs this node syncs: the sync set plus leaving ones while they wait, notes/sync-leave.md); `types` (every type two modules share; a type one module owns and others only read lives in that module). A part not built answers `Error::NotBuilt` or does nothing; no path a test reaches panics. The tokio transport glue is behind the default `driver` feature, the crate's one feature set.
- **osis-engine**'s `sync` module (core/engine/src/sync): the facade.
- **osis-proto** (core/proto): codecs below sync (frames, Hello, proofs, messages and their limits, filters, relay gate, the client port's messages); no session or store (notes/sync-protocol.md).
- **osis-blob** (core/blob): blob prefix and wraps, steps, claim sets, stamps and deposit signatures, holder keys, sealed fires, links.
- **osis-store**: the store primitives sync builds on (local rows, per-peer `record` rows under `RECORD_BUDGET`, `nodelog`, `changed`), and `CipherHost`, through which the engine keeps blob bytes in sync's store.
- **osis-transport**: connections below sync (notes/networking.md).
- **osis** holds a `Node` per handle and steps it from its driver task (notes/api-implementation.md).

## The one step
`Node::handle(input) -> Vec<Out>` is all of sync: route the input to its module, run the compaction trigger, settle every module (leave, store, unread, opens, read, inbox, streams, status, life) until none acted, flush opens' records, decide dials and keep-or-close, then emit sends, dials, closes and one wake. `apply(out, links)` alone carries outputs out. Inputs: a connection up or down, bytes, bytes the transport took, a wake, a discovery, and `Wrote` after the osis handle writes. Details and failure handling: notes/sync-driver.md.

## How a write reaches a peer
1. The app writes through the osis handle; the engine commits it and calls nothing; the handle calls `handle(Wrote)`.
2. `read` follows the engine's commit feed: the commit's `sync_bodies` say under which sync IDs S it has a body; per (S, commit) it judges must-hold and logs an own entry (`seal_body`, stamped where this node writes S's head, else deposited) into the `store`, one transaction with its node-log event.
3. The store's entry and log changes are stamped. On each connection where S is in the shared set (`opens`), `streams` serves the peer's Pull from the node log filtered by the shared set; with the peer following, the event goes as a push under `follow` with `seq`, the body inline up to `INLINE_LIMIT` or fetched.
4. At the peer, `streams` applies messages in order once their bodies are held: a reader opens the entry (`Engine::open_entry`), which ingests the commit; a node keeping S unread verifies the stamp and logs it. The peer stores its cursor only then and reports it in an Applied.
5. `status` at the writer sees the source caught up and, once the peer's stream showed the entry (or a reader reported a position past it), counts the commit held elsewhere.

## Spec areas in code
| spec | code |
|---|---|
| spec/sync-set.md (what a node syncs) | engine `sync/set.rs` (`sync_things`, `thing_sync`, `sync_set`, `sync_holder`), `released`; osis-sync `set.rs`; `leave` (what the node syncs, and leaving) |
| spec/sync-ids.md (sync IDs, steps, the store, Register, Behind, Walk) | engine `sync_ids`; `store` (entries, paths, caps, Register, Delete, Behind); `opens` (Walk); `inbox/register.rs` |
| spec/sync-opens.md (dials, proofs, records, the shared set) | `driver/dials.rs`, `session` (proofs), `opens` |
| spec/sync-judgement.md, spec/sync-compaction.md | `read` (reader), `unread` (kept unread); engine `sync/facts.rs`, `bodies.rs`, retention |
| spec/sync-inbox.md | `inbox`; engine `flows/inbox.rs` |
| spec/sync-streams.md | `streams`, `session` (window, pushes) |
| spec/sync-status.md | `status`; engine `sync/held.rs` (passes, held elsewhere) |
| spec/sync-hostile.md | bounds in each module: `session` (per connection), `store` (caps, peer budget, deposits), `opens` (records, filters) |
| spec/sync-transport.md | osis-transport, `driver/links.rs` |
| spec/wire.md §11 | osis-proto `msg`, `session` |

## The sync notes
- notes/sync-session.md, sync-opens.md, sync-store.md, sync-read.md, sync-unread.md, sync-leave.md, sync-streams.md, sync-inbox.md, sync-status.md, sync-driver.md: one per module (what it owns, its implementation choices, bounds, reasons, what is not built).
- notes/sync-facade.md: the engine's facade, the memo and `Effects` mechanism, the engine tables kept for sync.
- notes/sync-test-harness.md: the one harness (worlds of `Node`s, scripted peers, histories, faults).
- Design reasons: notes/sync-reasons.md (core: blobs, sync IDs, stamps, delete keys, nodes), notes/sync-access.md (steps, claims, re-seal, static entries), notes/sync-convergence.md (judgement and deletion), notes/sync-inbox.md (deposits, fires), notes/unreadable-data.md (what a node keeping S unread learns), notes/sync-protocol.md (wire, osis-proto, osis-blob), notes/networking.md (transports, reachability, first contact), notes/growth.md (permanent growth).
- Open: issues/sync-unbuilt.md (every stub, per module), issues/sync-tests-owed.md (missing tests), issues/sync-tess-calls.md (reversible choices waiting on Tess), and the `sync`-tagged issues.

## The osis API over sync
The handle holds the `Node`. `status`, `on_status_change` (status reads are stamped, so a memo over `Node::status` moves with it), `wait_synced` (`Node::wait`; a `Waiting::Stranded` fails `Error::Stranded`, a `Never` is a part not built and fails `NotBuilt`), links and redeem (`Node::redeem`), contact cards and profiles, `listen`, `rotate_peer_address`, `Config::dial`, the client port (`PortEvent`), and `internals::ManualNet` (the API tests' in-memory fabric, one `Links` per node through `apply`) all run on it (notes/api.md Sync configuration and status). No peer list exists and sync IDs are internal: a thing syncs by being in the node closure (spec/sync-set.md §2).

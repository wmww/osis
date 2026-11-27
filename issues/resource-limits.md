# Resource limits: one node-wide budget system
> Summary: osis has no coherent memory budget: memory is bounded per connection and per input, never node-wide, so spec/requirements.md Scale ("peer input never causes ... unbounded allocation") is not met for memory. Wanted: node configuration data sets budgets, one node-wide view of memory and storage and what each subsystem uses, subsystems ask the budget and shed by a fair rule. Lists every place with no real total limit today.
> Priority: low
> Tags: security, sync, engine

Decided (Tess): no arbitrary per-subsystem memory caps (served-session slots, per-source eviction and counting module state against the received bound were built and removed as no more correct than no limit). Storage caps and per-thing budgets stay for now; `MAX_*` wire and decode bounds are input validation and stay.

## The system wanted
- Node configuration data (a node-local setting, like `caps^.0`) sets the budgets: how much memory and storage the node may use.
- One node-wide view: what the system has, what each subsystem holds now (sessions, transport, opens, streams, inbox, engine waits, memos, the store's memory part).
- A subsystem about to hold more asks the budget; past it, the node sheds by one fair rule (which connection, source or entry goes, how it is told), the same everywhere.
- Must pass notes/arbitrary-values.md: the defaults derive from the configured total, not picked per place.

## Where nothing bounds the total today
Each is bounded per connection, per input or per thing at most; the total grows with what is listed.
- **Open connections and their transport buffers** (osis-transport `link`, `quic`): up to `link::CONN_MEMORY` (about 2 MiB each way) per connection, a reader task and channel each; a node serves any number (spec/sync-transport.md §5). Grows with connections.
- **Transport connections that never open a session** (`link::serve`/`serve_conn`): each keeps quinn's connection state, a task and a channel until its first stream or `LINGER` idle; the node never sees them (`Input::Up` comes with a session). `MAX_INCOMING` bounds handshakes in progress per listener, not connections past them. Grows with connections opened.
- **Sessions** (osis-sync `session`): per connection one partial frame and `UNANSWERED`; node-wide only `IN_BOUND` (received frames) and `OUT_BOUND` (unwritten plus reply allowances). Per-session state beyond those (request maps, clock samples, proofs) grows with connections.
- **Peer filters** (osis-sync `opens`): per connection the generation arriving (`peer_gen`) and the held entries of its record, up to 2^22 entries and as many additions (about 10 MB coded, more decoded). Records are bounded by `RECORD_BUDGET`; connections without a record are not. Grows with connections.
- **Messages held while bodies arrive** (osis-sync `streams::pull`, `Pulling::pending`): up to `PENDING_CAP` messages per connection, each up to `MAX_MESSAGE`. Grows with connections.
- **Streams' per-source state** (`streams::known::Known`, `Pulling` sets: `queue`, `failed`, `settled`, `join_listing`, `listing`): presence, heads and refusals per (connection source, S), what a listing under way has listed so far. Grows with connections times shared set, and with what a peer lists.
- **Inbox and opens per-connection maps** (`inbox::offers` conns and loose, `stranded` out): grow with connections times sync IDs.
- **Loose records** (`waits::Loose`): every loose record in RAM, bounded only by the carriers' peer budgets, per connection for record-less peers: issues/sync-pending-leftovers.md.
- **Peer budget for record-less peers** (spec/sync-ids.md §5 Peer budget): charged per connection, so the total grows with connections.
- **Blob waits** (osis-engine `apply/reach.rs`): a waiting commit's walk keeps only its frontier (per lacked blob, notes/decode-bounds.md), but waiting commits are not bounded in total.
- **Memos and caches** (osis-base `memo::Memo`, perm memos): at most twice what is current plus what was asked since (`SWEEP`), so they grow with the state held; no node-wide budget. The store pager's unit cache is bounded (`unit_cache_bytes`).
- **Inbox deposits**: one deposit budget per sync ID (spec/sync-inbox.md §3), no node-wide total; ephemeral deposits are held in memory and grow with sync IDs held.
- **The store's memory part** and per-entry module memory beyond it (streams' `Known`, follow's parked set, untombed removal events): issues/sync-memory-uncounted.md.
- **Decode and write paths** that load a whole state: issues/durable-decode-bound.md; ephemeral decode ratio: issues/eph-node-cost-bounds.md.

## Grant signals
Nothing bounds how many grant signals a card holder fires beyond the inbox's lifetime and the deposit rate; each followed one adds a sync ID the node follows and names in ByRole to every peer it meets.

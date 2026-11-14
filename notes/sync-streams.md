# Sync: streams
> Summary: osis-sync's `streams` module (core/sync/src/streams/): serving and pulling each shared sync ID over the peer's node log, joins, bodies, `known` (what each source showed); its durable place per source, presence and listings, failure handling, the shred rule, remaining O(members) costs and what is not built.

Spec: spec/sync-streams.md §3-§6, spec/wire.md §11.2 (Pull, PullReply, Stream, Applied, Fetch), spec/sync-judgement.md §3 `known`. Model: core/test/tla/net/NetStream.tla (each `SN_*` rule names its function). Principle and state: the module doc of core/sync/src/streams/mod.rs. Overview: notes/sync.md.

## Shape
- Both sides serve (`serve.rs`: Pulls from the node log filtered by the shared set now, pages by `max_reply`, joins in pages, ephemeral listings, pushes under `follow` with `seq`, Fetches, reported positions) and pull (`pull.rs`: one Pull out, received vs stored cursors, joins by generation, messages in hand applied in order once their bodies settle, gaps read again, bodies one source at a time in fill order, Full and Refused at a node keeping S unread; `refetch`: a body read finds missing, queued outside any message from a source that showed it, `Streams::fetch_again`).
- A **source** is a peer's record, else the connection (`store::Source`). Per source a `Place` (stored cursor, members at the stream, joins with their cursors, where members stopped), held in memory while a connection pulls from the source.
- `Known` (`known.rs`): heads, full, refusals and presence per source; stamped per (source, S, blob), per (S, blob) for `present`, per (source, S) for listing, so read, unread, status and inbox follow it by key. `Streams::new(store)`: `Known` keeps the store handle so its `&self` reads need no store argument (a world copy resets it, `set_store`).
- Members come by `Moved` from opens; ended members are known by `Moved::Until`, so serving reads the shared set per event and checks `until` only for ended members: a push costs its events, not the members. Reported positions go back to opens as `Reported` after each message, move and settle; streams reads them through `Shared::reported`.
- The core runs over `streams::Ctx { store, ground: &mut dyn Ground, wire: &mut dyn Wire, shared: &dyn Shared, now, reported }` (`Ground`: `open`, `rank` from the engine; `Wire`: sessions; `Shared`: opens' `members`, `agreed`, `record`, `reported`), so core/sync/tests/it/streams.rs runs two sides over real stores with scripted opens and engine.

## Durability
- A record source's rows (tags `c` cursor, `a` at the stream, `j` joining with its cursor, `p` stopped; `k` present per blob, `h` head, `f` full, `r` refusal) are written by `save`: one transaction per applied message (what it showed and the cursor it stores, after its bodies were taken in their own transactions), per join or leave, per Full or Refused. A join started writes its cursor as `joining`, so a restart joins from it whatever opens wrote. An Applied goes only once that transaction committed.
- A connection's `Known` (ephemeral entries, record-less peers) stays in memory. An evicted record needs no call: streams keeps nothing in memory for a record no connection holds, and its rows go with it.
- `room` (entries refused for room) stays in memory: after a restart the node refuses again and tells `full` again.

## Presence and listings
A listing read from the start to its end (a whole reply and its pages: no cursor, one naming no position, or trimmed; a join from the start) replaces what that source is known to hold of each member it covers (spec/sync-streams.md §4 Applying). Until its end it stores no cursor (a join keeps its stored start) and owes no Applied, so one cut short by a lost connection or a restart is listed from the start again.

## Failures
- A store read of a record's rows that fails answers as if nothing were shown, which only holds back acts (held elsewhere, Leave, Register all need presence); the one read whose absence would act, the presence a listing replaces, fails the step (`Known::list`).
- A body the store or engine fails to take stays owed and fails the step: it is never settled, so no cursor passes it.
- A failed step sends nothing it queued (notes/sync-driver.md): a frame might tell of what the failure undid; the peers see a dropped connection.

## Shred
A shred of S takes S's place rows in the store's transaction and S out of every place in memory before any place is next read (`Streams::place` drains the store's shred feed). A member leaving S later in that step would otherwise write its pre-shred position back, and S read again would rejoin past entries it no longer holds.

## Costs left in O(members)
A Pull's reply builds the members map (per Pull: joins, gaps, pages, not per event); `inline_check` scans a connection's members when a member gains or loses a source; every connection's ephemeral listing reads each listed member's memory part when any ephemeral entry moves (issues/streams-ephemeral-scan.md). What a hostile source can make `Known` and `crossed` grow: issues/streams-per-source-growth.md.

## Constants
`INLINE_LIMIT` (16 KiB), `PENDING_CAP` (64 messages in hand), `FETCHES_OUT` (2), `RESYNC_MS` (30 s, before a refused Pull goes again or a refused join is joined again), `ASKED_MS` (the stall timeout, a blob asked of one source).

## Not built
issues/sync-unbuilt.md (streams): relay-only entries; the engine's linked blobs (`Engine::wants`: pages and header lists before apply); bundle import (`Streams::import` answers `NotBuilt`; `Node::export_bundle` is built); `Rank::Never` from the engine (a keyset without history: the facade has no call for it).

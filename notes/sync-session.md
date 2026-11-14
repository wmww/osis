# Sync: session
> Summary: osis-sync's `session` module (core/sync/src/session.rs): one connection's frames, Hello, connection proofs, request ids and routing to modules, the window, pushes, the stall clock and dial deadlines; its hostile-peer bounds and what is not built.

Spec: spec/wire.md §11.1-§11.2, spec/sync-streams.md §1-§2, spec/sync-opens.md §1 Dial timeout and §2, spec/sync-transport.md §1. Overview: notes/sync.md.

## What it owns
Per connection, in memory only: Hello and both challenges, proofs shown and proven (`Proven`: account, key actors, own node), request ids and their send order, the window, the stall clock, unanswered-in bytes, bytes written and taken, clock samples. Per dial not up yet, its deadline. Pure: messages in, frames out; time comes in inputs (`Sessions::set_now`), what the transport took as `Input::Taken`.

The driver owns every `Session` in one `Sessions`. A module that sends takes `&mut Sessions` in its entry points and `settle`, and sends on the connection it acts on (`request`, `answer`, `push`, `push_now`); what it sent leaves at the end of the step (`take_sends`). Nothing is sent from outside a step.

## Routing
- **Replies by asker, requests by kind** (`Incoming::to`): a Shared may answer opens' Hits or inbox's Deposit items, only the asker knows, so a reply goes to the `To` that sent the request. Requests and pushes by kind: Resume, Beacons, Offer, Lost, NoRecord, Digest, Members to opens; Pull, Fetch, Stream, Applied to streams; Register, Delete, Stranded, Suspect to inbox; Auth, Call, Sub, Unsub and Notify to the client port (`PortEvent`, the owner's). A message no module takes closes the connection. A reply of a kind that does not answer its request (`osis_proto::msg::answers`) is dropped.
- **Skipped requests**: Pulls and Fetches are answered in order; one still out when a later one's answer arrives reaches its module as `Reply(.., Error 14)` (a Pull) or an empty `FetchReply`, so streams has one path for refusals. Every Fetch takes a top-bit id.
- `push` waits (returns false) while untaken bytes would pass `REPLY_BUDGET`; the pusher retries at a later settle (`Input::Taken` steps the node). `push_now` (opens' Digest and Members, bounded by a record's shared set) never waits.

## Deadlines and keep-alive
- `STALL_TIMEOUT_MS` (2 min) from the oldest request's last move, or from Up while the peer's Hello has not come; `DIAL_TIMEOUT_MS` (the same) from `Sessions::dialing`. Kept in one ordered set, refreshed only for sessions a step touched, so a step's work is in proportion to the connections it reached.
- No request out means no wake: the dialer alone sends `PINGS` (3) Pings, one at a time, then none.
- `Session::quiet` (keep or close, notes/sync-driver.md): a Ping sent while this side had nothing under way came back with no other frame before it.

## Hostile peers
- Memory per connection is bounded by constants: one partial frame, `UNANSWERED` bytes of the peer's requests, unwritten bytes past `CLOSING` plus this side's in flight close it, checked as bytes arrive.
- The stall clock catches stuck peers, not hostile ones: a peer trickling a reply to the oldest request, a small push every few minutes, or a dialer that sends Hello and nothing more holds its own connection (a served connection is never closed for silence, spec/sync-transport.md §5), each at that bounded cost.

## Not built
issues/sync-unbuilt.md (session): the account's rotations in a Prove (`Engine::prove_rotations`/`take_rotations` answer `NotBuilt`: none sent, none taken); closing a connection where this node came to act for an actor it did not prove there; the node-wide bound on what served connections hold (spec/sync-transport.md §5).

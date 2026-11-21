# Sync: session
> Summary: osis-sync's `session` module (core/sync/src/session.rs): one connection's frames, Hello, connection proofs, request ids and routing to modules, the window, pushes, the stall clock and dial deadlines; its hostile-peer bounds and proving again after a rotation.

Spec: spec/wire.md §11.1-§11.2, spec/sync-streams.md §1-§2, spec/sync-opens.md §1 Dial timeout and §2, spec/sync-transport.md §1. Overview: notes/sync.md.

**Principle:** pure per-connection state: messages in, frames out, time and what the transport took as inputs; every byte a peer can make it hold is bounded per connection and node-wide.

## What it owns
Per connection, in memory only: Hello and both challenges, proofs shown and proven (`Proven`: account, key actors, own node), request ids and their send order, the window, the stall clock, unanswered-in bytes, bytes written and taken, clock samples. Per dial not up yet, its deadline. Time comes in inputs (`Sessions::set_now`), what the transport took as `Input::Taken`.

The driver owns every `Session` in one `Sessions`. A module that sends takes `&mut Sessions` in its entry points and `settle`, and sends on the connection it acts on (`request`, `answer`, `push`, `push_now`); what it sent leaves at the end of the step (`take_sends`). Nothing is sent from outside a step.

## Routing (`Incoming::to`)
- **Replies by asker**: only the asker knows what a reply answers (a Shared may answer opens' Hits or inbox's Deposit items), so a reply goes to the `To` that sent the request. A reply of a kind that does not answer its request (`osis_proto::msg::answers`) is dropped.
- **Requests and pushes by kind**: Resume, Beacons, Offer, Lost, NoRecord, Twin, Digest, Members to opens; Pull, Fetch, Stream, Applied to streams; Register, Delete, Stranded, Suspect to inbox; Auth, Call, Sub, Unsub and Notify to the client port (`PortEvent`, the owner's). A message no module takes closes the connection.
- **Skipped requests**: Pulls and Fetches are answered in order; one still out when a later one's answer arrives reaches its module as a refusal (`Code::DECLINED`, a Pull) or an empty `FetchReply`, so streams has one path for refusals. Every Fetch takes a top-bit id.
- `push` waits (returns false) while untaken bytes would pass `REPLY_BUDGET`; the pusher retries at a later settle (`Input::Taken` steps the node). `push_now` (opens' Digest and Members, bounded by a record's shared set) never waits.

## Deadlines and keep-alive
- `STALL_TIMEOUT_MS` from the oldest request's last move, or from Up while the peer's Hello has not come; `DIAL_TIMEOUT_MS` (the same) from `Sessions::dialing`. Kept in one ordered set, refreshed only for sessions a step touched, so a step's work is in proportion to the connections it reached.
- No request out means no wake: the dialer alone sends `PINGS` Pings (its clock offset estimate), one at a time, then none.
- `Session::quiet` (keep or close, notes/sync-driver.md): a Ping sent while this side had nothing under way came back with no other frame before it.

## Hostile peers
- **Per connection**, bounded by constants checked as bytes arrive: one partial frame, `UNANSWERED` bytes of the peer's requests; unwritten bytes past `CLOSING` plus this side's in flight close it.
- **Node-wide** (spec/sync-transport.md §5 Served connections), dialed and served alike. `Sessions` keeps the totals held out (`Session::out_held`: unwritten plus the allowances of the peer's requests handed on and not answered) and received (`in_held`: the decoder's bytes plus unanswered requests' frames), recounting the session it lent last (`get_mut`, the one door to a session's state; checked against a full sum in debug at `take_sends`), and tells each lent session its room and share (`OUT_BOUND` over the connections up).
  - A peer's request that does not fit (`Session::fits`) is held in its session and nothing behind it is decoded; `take_sends` tells the transport to stop reading (`Out::Read`). `Sessions::admit`, the driver's first act each settle round, hands on the waiting ones that fit, in the order they began to wait: one short of the bound's room stops those after it (and pushes and own requests everywhere, `blocked`); one short only of its share waits alone.
  - Past `IN_BOUND` received, the connection holding the most closes (`over_in`, after each receive). A wait for room past half `STALL_TIMEOUT_MS` closes connections until it fits (`room_closes`, at `tick`): first those the transport took nothing of while it waited, most holding first.
  - Links pause reading: the product's reader task waits on a watch (QUIC's flow control then holds the peer); the harness and the osis fabric hold the end's bytes and close.
- The stall clock catches stuck peers, not hostile ones: a peer trickling a reply, a small push every few minutes, or a dialer that sends Hello and nothing more holds its own connection at that bounded cost (a served connection is never closed for silence, spec/sync-transport.md §5).

## Proving again
A connection proves once (spec/sync-opens.md §1).
- The driver (`Node::proving`) closes each connection where this node now acts for a (key actor, key) it did not act for when it proved there (`Session::acted_for`: its provers then, whatever its policy sent, so a connection that proved nothing counts too), and redials at once where it dialed. It reads `Engine::provers` at each owner's write, and at the end of any step where `Engine::account_open_key` moved (a rotation of its account another node made, or the new epoch's seed arriving).
- Without this an account's rotation silently ends every sync ID opened by J between its nodes and other accounts' (the closed-epoch proof no longer counts), and with it the thing lists its rotations carry.
- A node's epoch can close while it dials (a sibling's rotation taken before its seed): while the open epoch's seed is missing it proves its account at no epoch and keeps its connections (nothing it proved is missing from what it proves), and proves again once the seed comes.
- A Prove, and a Proved that proves the account, carries the account's rotations as header-only copies (`Engine::prove_rotations`, minting rotation first, then the newest a message fits, as a verifier more likely holds the oldest), so a verifier behind on them judges the new key open. A node removed from its account learns its removal this way when it dials a sibling: nothing else reaches it.
- The verifier (and a dialer taking a Proved's, one path) keeps only what it holds the account's chain by (`take_rotations`: a trial of them all, then only those): the rotations that count, and the Warning's first rise (the contested tips with what they need, only while no rotation held before contests). A fork beside the followed line, one that would pend, and a second dispute's line keep nothing, so a removed node proving forks at every reconnection stores nothing past one dispute (`rotation::tests_account::a_removed_nodes_proved_forks_are_bounded_*`). A verifier lacking more than one message of the chain learns the newest by syncing the data the chain travels with.
- Rejected: re-proving on the live connection. The wire's Prove is once per connection, and every module reading a peer's proofs would have to follow them moving mid-connection; one close and redial per connection per rotation is the cost.

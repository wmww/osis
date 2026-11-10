# Stream requests ignore the request window
> Summary: A node's Pull and stream Fetches go straight out (`shared_send`, `Command::Peer`), each reserving `REPLY_BUDGET`, outside the client's `WINDOW`; a listener's `ServingSession` closes a connection whose requests in one read pass `MAX_UNANSWERED` (about three such), so a Pull plus Fetches for three labels landing in one read would close an honest reader connection. Found by reading (net-owed review), not reproduced.
> Priority: normal
> Tags: node, sync, proto

## The case
`ServingSession::frame` charges each request's allowance (`client::allowance`: `max_reply` for Pull and Fetch) within one `ServingInput::Bytes`; answers to node messages (`ServingOutput::Peer`) come only after `handle` returns, so nothing is credited back within the input. `stream_fetch` sends one Fetch per label (per 1024 IDs) with `max_reply` `REPLY_BUDGET`, and one reply announcing bodies of several labels (every body in a mesh, `inline_limit` 0) makes as many Fetches in one step, plus the next Pull. The sim delivers each Send as its own input, so it never charges them together; a real driver hands one read (up to 64 KiB) of several frames.

## Directions
- Stream requests within a window of their own (allowances outstanding per connection), or Fetch `max_reply` per ID as a Sync's first page does (notes/flow-control.md).
- First a test: a `ServingSession` fed a Pull and three stream Fetches in one input.

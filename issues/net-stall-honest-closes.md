# The stall rule closes some honest slow peers
> Summary: The oldest request must move within `STALL_TIMEOUT_MS`, and push or Notify bytes are not progress, so an honest peer whose reply waits behind more pushes than the link carries in 2 min (about 9 MiB at under ~80 KB/s), or a client-port `settle` waiting on Notifies a slow thin client reads, is closed. Answering first does not fix it; counting other bytes up to the peer's queue bound would.
> Priority: low
> Tags: sync, proto, client-port

## The case
An honest peer queues at most `REPLY_BUDGET` of pushes ahead of a reply (spec/sync.md §6 Pushes), or one push frame of up to `MAX_MESSAGE` when nothing was unwritten. On a link moving that less than once per stall time (under ~80 KB/s) the reply's first byte arrives after the deadline and the connection closes; the redial can meet the same backlog. A thin client's `settle` is answered only once its connection has nothing dirty (`port/serve.rs`), so on a slow client with steady changes it can stay unanswered past the deadline while Notifies flow. Both are limits on "any link speed passes" (notes/flow-control.md, Stall).

## Not the fix: answers before pushes
Sending replies ahead of queued pushes and Notifies:
- does not lower the worst case: a push frame already being written (up to `REPLY_BUDGET`) cannot be overtaken, so the reply can still wait ~9 MiB;
- breaks ordering the protocol relies on: a `settle` must follow the Notifies before it (notes/client-port.md, Settling), and a Stream follows on from its PullReply's cursor until the next Pull (spec/wire.md §11.2, Pull);
- needs frame-aware two-lane send queues in every driver, and `Taken` positions would no longer match `written` order.

## Direction
Count any received bytes as the oldest request's progress until, since it last moved by its own events (sent, became oldest, frame taken), more bytes arrived than an honest peer can have queued ahead of its reply: the Closing bound (`WINDOW + 2 × (MAX_MESSAGE + 4)` plus the peer's own requests in flight, below `WINDOW`) plus the transport's buffers. A bound already in the spec, not a picked number; a pushing peer that answers nothing is still closed, after a bounded number of bytes rather than at once. `settle` under endless churn would still close (its wait is unbounded in bytes), which is a `settle` question of its own.

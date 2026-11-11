# Output bound passed by one input per connection
> Summary: fair shares of `max_buffered_bytes` let each connection under its share take an input whose replies reach `SEND_QUEUE` (about 34 MiB), so unread output is bounded by `max_buffered_bytes` + `max_connections` × `SEND_QUEUE` (about 9 GiB at the defaults), not by `max_buffered_bytes`.
> Priority: normal
> Tags: security, node, host

## The case
notes/serving.md, Connection memory: a served connection holding more than its share waits; one under it is served, and an input's replies are made at once. Connections sharing one group (a public link) that each ask a full request window and then read 16 KiB per `PUSH_POLL_MS` are moving, so never closed, and each holds up to its share plus one window: at `max_connections` 256, about 8.7 GiB beside the 512 MiB bound. Honest readers slow only themselves, as wanted; only the strictness of the bound is lost.

## Way out
A pausable `ServingSession`: take a waiting connection's requests (they are already within its request window) but answer each only when its reply fits the connection's share, so output never passes the bound; the turns then only order work. Needs the session to queue parsed requests and the hub to resume them as shares free (notes/flow-control.md, serving-side back-pressure).

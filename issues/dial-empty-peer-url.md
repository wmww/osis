# A `peer://` URL with no items is dialed though nothing can reach it
> Summary: a node with LAN off dials a key known only by an empty `peer://` URL (a link sharer's or a grantor's hint from a node with no global listener, a node's own `reach.0` on loopback) every `REDIAL_MS`, failing at once (`unreachable: peer://`); and a dial of a peer known at both tries the empty one first. Noise in `diag`, one wasted dial per redial.
> Priority: low
> Tags: sync, transport

Seen in the dogfood rehearsal (notes/dogfood.md): member B kept dialing A's node (the link's sharer hint, A listens nowhere) every 30 s, and each redial of the shared node (listening on loopback, so its `reach.0` has no items) went to `peer://#KEY` first, then `quic://`. Spec reading: "none means LAN only" (spec/sync-transport.md §3), so with LAN off such a URL names no route; the simplest rule is that a URL with no route is no dial candidate (or ranks after any URL with one).

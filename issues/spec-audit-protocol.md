# Spec audit: node-to-node protocol and transport gaps
> Summary: From the spec audit of spec/sync.md and spec/wire.md §5-§13 (protocol rules the code enforces were written into the spec on branch spec-audit): the P2P transport and `peer://` addresses are unspecified, so no other implementation can reach a co-reader; one replay-cursor nit left.
> Tags: spec, sync, transport

## Needs an owner decision
- **P2P transport**: spec/sync.md §10 and §3 name `peer://` and relays but define neither. Code: `transport/src/lib.rs` (a `peer://` URL plus space-separated relay URLs, or socket addresses), `transport/src/iroh.rs` (iroh 1.x, ALPN `osis`); `node/src/sync/peers.rs` treats `peer://` entries in `label.0` hosts as never-dialed and a label with only them as hostless. Either spec iroh's protocol (a dependency's wire format becomes ours) or define our own; then add the URL grammar, transport, relay scheme and the never-dialed rule to §10.

## Code nit
- Replay cursor position keeps 63 bits of a blob ID, so a replay page can skip an ID sharing them with the last one sent (`serving.rs` `replay_pos`/`after_pos`). Negligible, but a full-ID position would be exact (the cursor is opaque in spec, so the change is free on the wire).

Done (devbox): the rules that were only in code (Delete of a non-held entry, `want` and add events in Sync, Path's `after`, same-wrap re-upload and re-deposit) are in spec/wire.md §11.2 and spec/sync.md §5, checked against both label stores; the Hello deadline is host policy (spec/sync.md §10); the policy asides moved to notes/sync.md Policy defaults.

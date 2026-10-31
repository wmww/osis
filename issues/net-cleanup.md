# Server engine: costs a peer can still cause
> Summary: What remains after the net-cleanup pass: the listener backlog that `link::serve` keeps unreachable.
> Tags: proto, server, transport, security

- **Listener backlog** (`quic.rs` `accept_loop`, used by `iroh.rs` too): a connection whose handshake completed waits in its own task for a slot in the 64-entry accept channel; if nobody accepted, those tasks would pile up. `link::serve` accepts continuously (closing past its cap), so this is not reachable today.

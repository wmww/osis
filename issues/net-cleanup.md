# Server engine: costs a peer can still cause
> Summary: What remains after the net-cleanup pass: the listener backlog that `link::serve` keeps unreachable, and the depth of the server driver's shared input queue.
> Tags: proto, server, transport, security

- **Listener backlog** (`quic.rs` `accept_loop`, used by `iroh.rs` too): a connection whose handshake completed waits in its own task for a slot in the 64-entry accept channel; if nobody accepted, those tasks would pile up. `link::serve` accepts continuously (closing past its cap), so this is not reachable today.
- **Input queue depth** (`osis-server` `driver::run`): every connection's reader sends 64 KiB chunks into one 1024-slot channel and reads on while it has room, so one fast connection can queue hundreds of inputs ahead of another's. Each input is bounded (notes/sync.md, Hub stall bounds: at 10^5 entries about 135 ms for three whole-space Reconciles, a full Upload chunk similar), but an honest input can wait behind the sum. A per-connection limit of one queued input would make the interleaving per chunk that the notes assume.

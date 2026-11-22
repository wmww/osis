# Accepted connections without a session are not bounded in number
> Summary: spec/requirements.md Scale: peer input never causes unbounded allocation. Served sessions are bounded (slots, spec/sync-transport.md §5) but a transport connection that opens no session holds its QUIC state until `LINGER`, counted nowhere, so a peer opening connections and no streams grows memory with their number.
> Priority: normal
> Tags: transport, security

- `link::serve`/`serve_conn` (core/transport/src/link.rs) keeps each accepted connection until its first stream or `LINGER` (`STALL_TIMEOUT_MS`) idle; the node sees a connection only once a session (stream) comes up (`Input::Up`), so the slots never count it. `MAX_INCOMING` bounds handshakes per listener, not connections past them.
- Each such connection holds quinn's per-connection state (no stream windows filled), a task and its channel; a peer completing handshakes fast holds thousands for two minutes.
- Wanted: the same slot rule at the transport (connections without a live session share the served slots, or a bound of their own derived from them), with the defined outcome of the slots (fair by source, `osis_transport::evict_for`).

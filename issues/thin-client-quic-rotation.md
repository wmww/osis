# A thin client cannot reconnect over QUIC after the node rotates its address
> Summary: by-hand osis `sources::thin_client_over_quic` fails every run: after `rotate_peer_address`, connecting to the new key is refused ("the server refused to accept a new connection").
> Priority: normal
> Tags: transport, osis, tests

- `core/osis/tests/it/sources.rs` (the rotation part, the connect to the new address): `Network("transport protocol error: aborted by peer: the server refused to accept a new connection")`. Reproduces alone in under a second (`cargo test -p osis --test it -- --ignored --exact sources::thin_client_over_quic`).
- Not looked at: whether the new listener's QUIC endpoint is up when the client dials, or the old endpoint is still the one answering the port.

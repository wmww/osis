# Transport crate: the Transport abstraction, in-process and QUIC implementations
> Summary: Implement `osis-transport`: the `Transport`/`Connection`/`Stream` traits every network user depends on, a deterministic in-process implementation with fault injection for tests and the simulator, and a direct server transport with a pinned static key and ephemeral client keys (QUIC or a lighter pure-Rust option, recorded). P2P (iroh) and LAN discovery are plans/p2p.md.
> Tags: sync, networking, tests

Crate: `osis-transport` (features: `quic`; `iroh` later). Depends on: osis-core; tokio. Unblocks: server binary, node-sync over a network, apps-e2e.
Spec: spec/sync.md §10 (ordered bidirectional stream, confidentiality, authenticated peer key, pinned server key, ephemeral client keys, no direct addresses published). Notes: notes/networking.md (decisions 1, 5, 6; risks), notes/architecture.md §2. Spec trumps this plan.

## Deliverables
- Traits: `Transport { dial(&Address) -> Connection; listen(ListenConfig) -> Listener }`, `Connection { peer_key(), open_stream(), accept_stream(), close() }`, `Stream` = ordered bidirectional bytes (`AsyncRead + AsyncWrite` or a minimal own pair of traits; keep tokio types out of the trait signatures if cheap). `Address` parse/print is osis-label's; transport maps URL schemes to implementations.
- `InProcess`: a registry of listeners by name; connections are channel pairs; a fault layer (latency, drop connection, partition sets, bandwidth cap) controlled by a test handle. It tests the drivers and the stream layer on a plain tokio runtime; the simulator does not use it (it carries proto messages engine-to-engine, plans/sim.md), so it need not be deterministic.
- Direct server transport: QUIC via quinn + rustls with a custom verifier pinning the server's static public key from the address, client uses a fresh ephemeral key per connection; or, if build time or complexity argues for it, a Noise-based framing over TCP; record the decision and its deps in notes/architecture.md. Server side: listener bound to a config (port, static key file).
- Connection manager helpers used by node and server: reconnect with backoff, one connection syncing many labels (streams per purpose), graceful close.

## Steps
- [x] Traits + InProcess + fault layer; tests: a byte stream round trip, partition heals, deterministic under a fixed seed.
- [x] Direct server transport behind the feature; test: pinned-key mismatch refused; ephemeral client keys differ per connection; large stream transfer.
- [ ] Manager helpers; a loopback test driving osis-proto engines over InProcess and over the real transport on localhost.

## Done when
server and node run over both implementations through the traits only; `cargo test -p osis-transport` without `--features quic` builds no TLS stack; notes/networking.md "Implementation" section written. Delete this plan.

## Progress
- Step 1: traits (own `SendStream`/`RecvStream`, `impl Future + Send`, no runtime types), `InProcess` on a `Net` with virtual steps (latency, jitter, bandwidth, partition, disconnect, kill), `Sched` seeded executor; deterministic, no tokio.
- Step 2: `Quic` (feature `quic`): quinn + rustls (ring), TLS 1.3 with RFC 7250 raw Ed25519 keys both ways, server key pinned by a custom verifier, fresh client key per dial; `quic://host:port` written into spec/sync.md §10; localhost tests `#[ignore]` (tier 2).

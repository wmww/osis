# Networking: transport, discovery, reachability
> Summary: Decided with owner. The sync protocol runs over any ordered, bidirectional byte stream behind our own transport abstraction; direct server connections (QUIC/TLS/WebSocket) need no iroh; iroh 1.0 is the P2P transport (LAN, hole punching, relays, later BLE), used without n0's infrastructure; we run an official blind server and relays. Addresses and relays are osis data, server addresses pin the server's key; transport keys are separate from node signing keys. Push wake-ups are a proposal; Tor a future option.

## What osis needs from the network (spec/requirements.md)
- Long-lived connections with server push (subscriptions, signals), several labels per connection, one round trip for the common case.
- Blind always-on nodes are the backbone; client-to-server reachability matters most. Direct P2P adds LAN, offline and no-server sync.
- No required coordinator: any helper is replaceable and self-hostable; osis works without it (LAN, any blind node, a known address).
- A blind node must not learn authorship or membership. It learns client IPs (accepted), not node identities.
- Authorization is application-level (node signatures, label role keys), so the transport only needs confidentiality and a stable peer key to dial.

## Decisions (owner)
1. **Own transport abstraction.** Sync is framed messages over ordered streams; nothing depends on QUIC or iroh. Implementations: direct server connections (QUIC or TLS/TCP, WebSocket for browsers) without iroh; iroh for P2P; in-process for tests; file bundles for sneakernet (spec/sync.md §11).
2. **iroh for P2P.** Dial by public key, QUIC multipath, hole punching with relay fallback, Rust-native, MIT/Apache-2.0; 1.0 has a stable wire protocol and API.
3. **Official infrastructure, never required.** We run an official blind server (cheap services free, storage for paying accounts) and `iroh-relay`. Anyone may run their own; any blind node may relay. n0's public relays and DNS discovery are not used: n0 would see every node's key and IP.
4. **Reachability is osis data.** A node's dialable key and preferred relays live in `/reach`, published under every label it tracks so co-readers can dial it; blind nodes see nothing of it. Direct addresses are never published: they are IPs, and iroh exchanges them with the specific peer during hole punching. Apps exclude `/reach` from labels whose audience is open (public or bearer-read), where strangers dialing the device is the concern (notes/permissions.md, Public content). LAN discovery uses our own announcement (rotating tag from the `/reach` lan secret plus a per-network transport key, spec/sync.md §10), not iroh's mDNS, which announces the stable endpoint key on every network and lets anyone track the device; needs a custom iroh discovery service. A co-reader removed from every label still knows the lan secret; rotate it with `/reach` now and then. Mainline-DHT discovery opt-in.
5. **Transport keys are not node signing keys**, or every blind node and relay learns which device uploaded what. Clients dial blind nodes with an ephemeral key per connection (blind nodes never dial out). A node's dialable P2P key is separate, published only in `/reach`, rotatable at will.
6. **Server addresses pin a key**: a transport URL plus the server's static public key, so a self-hosted server needs no certificate authority and a middlebox cannot pose as the server.

## First contact
A link (and so a contact card) may carry the sharer node's dialable key and relays (spec/wire.md §10): a redeemer sharing no server with the sharer dials that node, which serves K's label as a member peer (spec/sync.md §5). No new mechanism; redemption then needs the sharer online, as any P2P exchange does. Relay defaulting to the official server is client policy.

## Local and offline transports
Owner wants "just works" across LAN, Bluetooth and similar. LAN works in iroh today. Custom transports (BLE, WiFi Aware, mixnets) use an iroh API that is unstable and outside 1.0 guarantees; the only BLE crate is experimental and AGPL, so BLE means our own transport on that API (owner's license call if the crate is used instead). Not MVP. Low-bandwidth links suit small commits and signals; large bodies wait for a fast path (chunk fetch is lazy, spec/sync.md §6). Recheck the iroh state before relying on any of this.

## Future option: Tor
Hides IPs from blind nodes, relays and peers. Not needed now (owner). Paths: iroh custom transport, or a direct-server transport over Arti (onion services were not production-ready at last check).

## Risks
- **Single vendor.** iroh's NAT traversal is an n0 Internet-Draft on n0's own QUIC fork; open code, stable wire, no multi-implementation standard. Mitigated by decision 1; rust-libp2p is the fallback.
- **Browsers are relay-only** in iroh. Browsers use the WebSocket server transport instead.
- **Relays see metadata** (IPs, timing, volume, endpoint IDs). Same class as a blind node; ephemeral client keys limit linkability.
- Mobile background limits: sync through blind nodes in background, P2P in foreground.

## Alternatives considered
- **rust-libp2p**: most decentralized (spec'd, many implementations, DHT, circuit relays, browser transports). Large surface, mostly unneeded since peers come from group state. Fallback if the single-vendor risk materializes.
- **Veilid**: private routing plus its own storage model, overlaps osis's data layer. Not a base.
- **Willow/WGPS, Syncthing BEP, Hyperswarm**: sync protocols or JS-only stacks, not transports. Syncthing's community relays plus self-hostable discovery are the precedent for decision 3.

## Proposal: push wake-ups from blind nodes
Mobile notifications need the server to wake a device with no live connection (spec/sync.md §8 pushes only on subscriptions). A push token (APNs, FCM) is a stable device identifier, so registering one token for several labels would link them at the server beyond the accepted overlap leak. Not in the spec; nothing is needed before the initial implementation.
- **Wake handles**: per label the device registers a sealed box to a push proxy's public key holding the push token plus fresh randomness, so the server sees unrelated handles. On a new log event the server hands the handle to the proxy, which opens it and sends an empty push; the device syncs. The server learns handle counts per label and wake timing; the proxy learns tokens and timing, never labels; both together can link labels by timing.
- **UnifiedPush**: the server posts to per-label endpoint URLs directly, no proxy; an osis server can itself be a distributor. iOS needs APNs through the official proxy.
- Rate limits: at most one wake per handle per short interval; events batch into one wake.
- **Priority** (which writes wake): a per-upload wake bit (server learns which entries matter), a separate wake label per chat (overlap shows its pairing), or wake on everything with client-side filtering (battery). Undecided.
- Owner calls when it comes up: official proxy beside the official server or separately operated; priority; who pays (accounts deferred, notes/sync.md Open).
- Constraints to keep while implementing: per-entry upload-time attributes stay outside the hashed blob prefix (as the deposit flag does), so a wake bit never touches blob IDs; local-store root keys must be readable after first unlock while the device is locked, or a woken app cannot present the sync key.

## Implementation (osis-transport)
- Traits: `Transport`/`Listener`/`Connection`/`SendStream`/`RecvStream` (notes/architecture.md §2). `Address { url, key }` mirrors the schema's `address`; the URL scheme picks the transport, an unknown scheme is `Error::UnknownScheme` (Parked). Error classes: key mismatch, bad URL, protocol = BadInput; unreachable, closed, I/O = Local.
- Stream contract (both impls): the peer's `accept_stream` sees a stream once data or finish is sent on it; `finish` resolves once the peer's transport has everything (quinn `stopped`); dropping a send half finishes it; `close` is abrupt (unread data lost). Graceful end: the dialer finishes, reads the peer to its end and closes (`close_gracefully`); the accepting side finishes and waits for that close, since closing first can cut the dialer's read.
- `InProcess`: endpoints on a shared `Net`; virtual steps; faults `latency`, seeded `jitter` (reorders deliveries across streams only, never within one), `bandwidth` per stream direction per step, `partition` (dials fail, data waits until `heal`), `disconnect`, `kill`; `Net::sleep(steps)` virtual timers. A listener's key is `derive_key("osis-transport mem static key", secret)`; dialers get seeded random ephemeral keys (`dial_as`: the same derivation of their secret). Closing a listener resets the connections it has not accepted. `Sched` polls ready tasks in seeded order and steps the net when all are blocked: same seed, same interleaving, no tokio. Writes never block (unbounded buffers).
- `Quic` (feature `quic`, spec/sync.md §10 `quic://host:port`): quinn 0.11 + rustls 0.23 (ring), TLS 1.3 only, ALPN `osis`, no 0-RTT, no session tickets, no SNI, RFC 7250 raw Ed25519 keys both ways: the listener's key pair comes from its 32-byte secret (an Ed25519 seed, hand-built PKCS#8), a client's from OS randomness per dial (or the given secret for `dial_as`); custom verifiers pin the server key (mismatch -> `KeyMismatch`) and accept any Ed25519 client key. Peer protocol/TLS failures -> `Protocol` (not retried by `connect`). Each dial binds its own UDP socket, so a server cannot link a client's connections by source port. Listener handshakes run concurrently, each under a 5 s deadline (at most 1024 in progress), so a silent client blocks nobody. Per-connection memory is bounded: 16 bidi streams, no uni streams or datagrams, stream window 2 × MAX_MESSAGE, connection window 4 × MAX_MESSAGE; idle timeout 60 s, keep-alive 15 s (all provisional). Why QUIC over Noise-over-TCP: native multiplexed streams, flow control, migration and keep-alive without our own mux; same stack as iroh. Cost: build time (behind the feature) and ring's C/asm.
- Helpers (`manage`): `Backoff` (seeded jitter in `[d/2, d]`, 500 ms doubling to 60 s, provisional), `connect` (retries only `Local` errors, sleep injected so tests use `Net::sleep`), `close_gracefully`. One connection serves many labels through proto's message ids on one session stream; no stream-per-label scheme.
- `link` (feature `link`, tokio): a session = one stream as a `Link` (`peer_key`, `LinkTx` with a not-yet-written byte count and cap, `LinkRx` read-ahead 16 × 64 KiB so flow control holds the peer) with two pump tasks. `link::dial(t, addr, Option<&StaticSecret>, wait)`: one stream, the dialer closes after finishing. `link::serve(listener, idle, wait, out)`: every stream a dialer opens is a session; the accepting side finishes its side, closes only after the dialer closed or `idle` without sessions. The server driver uses it; the node driver should too (plans/node-sync.md).
- Not yet: a scheme-dispatching transport (mem + quic + iroh behind one type) for the node driver; a WebSocket transport for browsers; backpressure in `InProcess`.

## Open
- Which free services the official server offers, and abuse limits for free relaying (deferred, notes/sync.md Open).

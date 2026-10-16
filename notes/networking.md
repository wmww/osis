# Networking: transport, discovery, reachability
> Summary: Decided with owner. The sync protocol runs over any ordered, bidirectional byte stream behind our own transport abstraction; direct server connections (QUIC/TLS/WebSocket) need no iroh; iroh 1.0 is the P2P transport (LAN, hole punching, relays, later BLE), used without n0's infrastructure; we run an official blind server and relays. Addresses and relays are osis data, server addresses pin the server's key; transport keys are separate from node signing keys. Tor saved as a future option.

## What osis needs from the network (spec/requirements.md)
- Long-lived connections with server push (subscriptions, signals), several labels per connection, one round trip for the common case.
- Blind always-on nodes are the backbone: two briefly-online devices syncing via a blind node is a primary case. So client-to-server reachability matters most; direct P2P adds latency, LAN, offline and no-server sync.
- No required coordinator. Any helper (relay, discovery server) is replaceable and self-hostable; osis still works without it (LAN, any blind node, a known address).
- A blind node must not learn authorship or membership. It already learns client IPs (accepted), not node identities.
- Authorization is application-level (node signatures, label role keys), so the transport only needs confidentiality and a stable peer key to dial.

## Decisions (owner)
1. **Own transport abstraction.** Sync is framed messages over ordered streams; nothing depends on QUIC or iroh. Implementations: direct server connections (QUIC or TLS/TCP, WebSocket for browsers) without iroh; iroh for P2P; in-process for tests; file bundles for sneakernet (like `git bundle`: blobs are self-contained, so a bundle is entries plus wraps).
2. **iroh for P2P.** Dial by public key, QUIC multipath, hole punching with relay fallback, LAN discovery, Rust-native, MIT/Apache-2.0. 1.0 has a stable wire protocol and API (wire breaks only on major versions).
3. **Official infrastructure, never required.** We run an official blind server: cheap, unexploitable services free (likely including relaying and first-contact help), services with real cost (storage) for paying accounts. It also runs `iroh-relay` (open source, one TOML file, ACME TLS). Anyone may run their own; any blind node may relay. n0's public relays and DNS discovery (dns.iroh.link) are not used: n0 would see every node's key and IP.
4. **Reachability is osis data.** A node's dialable key and preferred relays live on its node thing (`/reach`), published under every label it tracks so co-readers can dial it; blind nodes see nothing of it. Direct addresses are not published: they are IPs, and iroh exchanges them with the specific peer during hole punching, so publishing them bought a round trip and leaked an IP to every co-reader. With key and relays only, `/reach` reveals nothing a co-reader does not already get from the node card (a stable node identity), except that the node can be dialed. The earlier rule omitted `/reach` under labels with link members, which cut P2P sync for every link-shared group while still handing IPs to large admin-populated ones; now apps exclude labels whose audience is open (public or bearer-read), where strangers dialing the device is the concern (notes/permissions.md, Public content). mDNS on by default for LAN; mainline-DHT discovery opt-in.
5. **Transport keys are not node signing keys**, or every blind node and relay learns which device uploaded what. Clients dial blind nodes with an ephemeral key per connection (blind nodes never dial out). For P2P a node has a separate dialable key, published only in `/reach`, rotatable at will.
6. **Server addresses pin a key**: an entry in a label's `servers` list is a transport URL plus the server's static public key (QUIC/TLS certificate key or iroh endpoint key), so a self-hosted server needs no certificate authority and a middlebox cannot pose as the server. Everything of value is end-to-end signed and encrypted, so the pin protects only the metadata the server sees anyway.

## Local and offline transports (state when researched; recheck before relying on it)
Owner wants iroh's "just works" across LAN, Bluetooth and similar. Actual state:
- LAN: works today (mDNS-style local discovery, direct UDP, no internet needed).
- Custom transports: iroh API since 0.97, behind feature `unstable-custom-transports`, not covered by 1.0 stability. Any unreliable datagram link with 1200-byte packets fits; QUIC runs on top and multipath can switch between paths in one connection.
- BLE: `iroh-ble-transport` (third-party, mcginty/jakebot.org, n0-adjacent): experimental, **AGPL** (commercial license available), macOS/iOS/Android/Linux, about 100 kbps, 3-5 connections on mobile. The license needs an owner call before we ship it; alternative is our own BLE transport on the same API.
- WiFi Aware: advertised in the 1.0 post, no crate found. Nym mixnet transport exists (`iroh-nym-transport`).
- Low bandwidth links are fine for small commits and signals; large bodies should wait for a fast path (chunk fetch is already lazy by local policy, spec/sync.md §6).

## Future option: Tor
Hides IPs from blind nodes, relays and peers. Not needed now (owner). Paths: iroh custom transport (Tor listed on iroh's compatibility page) or a direct-server transport over Arti. Arti onion services were not production-ready at last confirmed status; recheck when it comes up.

## Risks
- **Single vendor.** iroh's NAT traversal is an n0 Internet-Draft (draft-bruynooghe-n0-quic-nat-traversal-00, informational) on n0's own QUIC fork (noq). Open code, stable wire, no multi-implementation standard. Mitigated by decision 1.
- **Browsers are relay-only** in iroh. Browsers use the WebSocket server transport instead.
- **Relays see metadata** (IPs, timing, volume, endpoint IDs). Same class as a blind node; ephemeral client keys limit linkability.
- Hole-punch rates are vendor claims (iroh ~95% of bytes direct; it cites libp2p DCUtR at ~70%).
- Mobile background limits: sync through blind nodes in background, P2P in foreground.

## Alternatives considered
- **rust-libp2p**: most decentralized (spec'd, many implementations, Kademlia DHT, any peer can be a circuit relay, WebRTC/WebTransport to browsers). Large surface, mostly unneeded since peers come from group state. Fallback if iroh's single-vendor risk materializes.
- **Veilid** (MPL-2.0): private routing plus its own DHT/storage model, overlaps osis's data layer, activity unclear. Not a base.
- **Willow/WGPS, Syncthing BEP, Hyperswarm**: sync protocols or JS-only stacks, not transports. Syncthing's community relays plus self-hostable discovery are the precedent for decision 3.

## Open
- First contact between two users with no shared blind node: invite link carrying dialable key plus relay URL (like iroh tickets), relay defaulting to the official server. A contact card is a link to a profile thing holding `/keys` (spec/sync.md §3).
- Which free services the official server offers, and abuse limits for free relaying: issues/server-abuse-limits.md.
- BLE: issues/ble-transport.md.
- LAN discovery tracking leak: issues/lan-discovery-tracking.md.

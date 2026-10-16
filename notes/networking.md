# Networking: transport, discovery, reachability
> Summary: Decided with owner 2026-10-16. The sync protocol runs over any ordered, bidirectional byte stream behind our own transport abstraction; direct server connections (QUIC/TLS/WebSocket) need no iroh; iroh 1.0 is the P2P transport (LAN, hole punching, relays, later BLE), used without n0's infrastructure; we run an official blind server and relays. Addresses and relays are osis data, server addresses pin the server's key; transport keys are separate from node signing keys. Tor saved as a future option.

## What osis needs from the network (from notes/sync.md, notes/constraints.md)
- Long-lived connections with server push (subscriptions, signals), several labels per connection, one round trip for the common case.
- Blind always-on nodes are the backbone: two briefly-online devices syncing via a blind node is a primary case. So client-to-server reachability matters most; direct P2P adds latency, LAN, offline and no-server sync.
- No required coordinator. Any helper (relay, discovery server) is replaceable and self-hostable; osis still works without it (LAN, any blind node, a known address).
- A blind node must not learn authorship or membership. It already learns client IPs (accepted), not node identities.
- Authorization is application-level (node signatures, label role keys), so the transport only needs confidentiality and a stable peer key to dial.

## Decisions (owner 2026-10-16)
1. **Own transport abstraction.** Sync is framed messages over ordered streams; nothing depends on QUIC or iroh. Implementations: direct server connections (QUIC or TLS/TCP, WebSocket for browsers) without iroh; iroh for P2P; in-process for tests; file bundles for sneakernet (like `git bundle`: blobs are self-contained, so a bundle is entries plus wraps).
2. **iroh for P2P.** Dial by public key, QUIC multipath, hole punching with relay fallback, LAN discovery, Rust-native, MIT/Apache-2.0. 1.0 shipped 2026-06-15 with stable wire protocol and API (wire breaks only on major versions).
3. **Official infrastructure, never required.** We run an official blind server: cheap, unexploitable services free (likely including relaying and first-contact help), services with real cost (storage) for paying accounts. It also runs `iroh-relay` (open source, one TOML file, ACME TLS). Anyone may run their own; any blind node may relay. n0's public relays and DNS discovery (dns.iroh.link) are not used: n0 would see every node's key and IP.
4. **Reachability is osis data.** A node's dialable key, preferred relays and direct addresses live on its node thing (`/reach`), published under the labels it tracks so co-readers can dial it (not under labels with bearer or public readers by default; notes/permissions.md, Nodes as things); blind nodes see nothing of it. mDNS on by default for LAN; mainline-DHT discovery opt-in.
5. **Transport keys are not node signing keys**, or every blind node and relay learns which device uploaded what. Clients dial blind nodes with an ephemeral key per connection (blind nodes never dial out). For P2P a node has a separate dialable key, published only in `/reach`, rotatable at will.
6. **Server addresses pin a key** (sync review 2026-10-16): an entry in a label's `servers` list is a transport URL plus the server's static public key (QUIC/TLS certificate key or iroh endpoint key), so a self-hosted server needs no certificate authority and a middlebox cannot pose as the server. Everything of value is end-to-end signed and encrypted, so the pin protects only the metadata the server sees anyway.

## Local and offline transports (state 2026-10-16)
Owner wants iroh's "just works" across LAN, Bluetooth and similar. Actual state:
- LAN: works today (mDNS-style local discovery, direct UDP, no internet needed).
- Custom transports: iroh API since 0.97, behind feature `unstable-custom-transports`, not covered by 1.0 stability. Any unreliable datagram link with 1200-byte packets fits; QUIC runs on top and multipath can switch between paths in one connection.
- BLE: `iroh-ble-transport` (third-party, mcginty/jakebot.org, n0-adjacent): experimental, **AGPL** (commercial license available), macOS/iOS/Android/Linux, about 100 kbps, 3-5 connections on mobile. The license needs an owner call before we ship it; alternative is our own BLE transport on the same API.
- WiFi Aware: advertised in the 1.0 post, no crate found. Nym mixnet transport exists (`iroh-nym-transport`).
- Low bandwidth links are fine for small commits and signals; large bodies should wait for a fast path (chunk fetch is already lazy by local policy, notes/sync.md).

## Future option: Tor
Hides IPs from blind nodes, relays and peers. Not needed now (owner 2026-10-16). Paths: iroh custom transport (Tor listed on iroh's compatibility page) or a direct-server transport over Arti. Arti onion services were not production-ready at last confirmed status; recheck when it comes up.

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
- First contact between two users with no shared blind node: invite link carrying dialable key plus relay URL (like iroh tickets), relay defaulting to the official server. A contact card can be a bearer link to a profile thing holding `/keys` (notes/crypto.md).
- Which free services the official server offers exactly, and abuse limits for free relaying.
- BLE: AGPL crate vs our own.
- LAN discovery announces the dialable key on every network the device joins, a stable identifier for tracking across networks. Options: a dialable key per network, or announcing only on networks the user marks trusted. Anonymity against network analysis is out of scope, but this leak is gratuitous.

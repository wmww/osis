# Networking: transport, discovery, reachability
> Summary: Proposal 2026-10-16, not decided by owner. The sync protocol runs over any ordered, bidirectional byte stream and needs no transport-level auth; iroh 1.0 (QUIC, hole punching, relays) is the primary P2P transport, used without depending on n0's infrastructure: addresses and relays are osis data, blind nodes double as relays, transport keys are separate from node signing keys. libp2p, Veilid, Tor/Arti and plain QUIC/WebSocket evaluated.

## What osis needs from the network (from notes/sync.md, notes/constraints.md)
- Long-lived connections with server push (subscriptions, signals), several labels per connection, one round trip for the common case.
- Blind always-on nodes are the backbone: two briefly-online devices syncing via a blind node is a primary case. So client-to-server reachability matters more than NAT traversal; direct P2P is an optimization (latency, LAN, no server).
- No required coordinator. Any helper (relay, discovery server) must be replaceable, self-hostable, and osis must still work without it (LAN, a blind node, a known address).
- A blind node must not learn authorship or membership. It already learns client IPs (accepted). It must not learn node identities.
- Authorization is application-level (node signatures, label role keys), so the transport only needs confidentiality and a stable peer key to dial.

## Recommendation
1. **Transport-agnostic sync protocol.** Framed messages over ordered streams; nothing depends on QUIC. Lets us add TLS/TCP or WebSocket to blind nodes, in-process for tests, and file bundles (sneakernet, like `git bundle`: blobs are self-contained, so a bundle is just entries plus wraps).
2. **iroh as the primary transport.** Dial by public key, QUIC multipath, hole punching with relay fallback, LAN discovery, Rust-native, MIT/Apache-2.0. 1.0 shipped 2026-06-15 with a stable wire protocol and API (wire breaks only on major versions).
3. **No dependency on n0.** iroh's defaults (n0 public relays, DNS/pkarr discovery at dns.iroh.link) are a central point and a metadata leak: n0 would see every node's key and IP. Instead:
   - A node's reachability (endpoint ID, preferred relays, direct addresses) is ordinary state on its node thing (`/node`), so it syncs encrypted to exactly the peers who may contact it; blind nodes and n0 never see it.
   - Any blind node may also run `iroh-relay` (open source, one TOML file, ACME TLS). A group's relays are the blind nodes it already uses. Optional public relay lists are config, not protocol.
   - mDNS on by default for LAN; mainline-DHT discovery opt-in; n0 DNS discovery off.
4. **Transport keys are not node signing keys.** Otherwise every blind node and relay learns which device uploaded what, breaking the authorship rule. Clients dial blind nodes with an ephemeral key per connection (blind nodes never dial out). For trusted P2P a node has a separate dialable key, published only in encrypted `/node` state and rotatable at will.

## Risks and gaps
- **Single vendor.** iroh's NAT traversal is an n0 Internet-Draft (draft-bruynooghe-n0-quic-nat-traversal-00, informational, admits bugs) on n0's own QUIC fork (noq). Code is open and wire is stable, but there is no multi-implementation standard like libp2p's. Mitigated by point 1: swapping transports costs a transport module, not a protocol change.
- **Browsers are relay-only** in iroh (no UDP from browsers). Fine if blind nodes run relays; a plain WebSocket endpoint on blind nodes is the simpler browser path.
- **Relays see metadata** (IPs, timing, volume, endpoint IDs). Same class as what a blind node sees; ephemeral client keys limit linkability.
- Hole-punch success rates are vendor claims (iroh ~95% of bytes direct; it cites libp2p DCUtR at ~70%). Unverified.
- Mobile background limits apply to any transport: on mobile, sync through blind nodes, P2P only in foreground.

## Alternatives considered
- **rust-libp2p**: most decentralized (spec'd, many implementations, Kademlia DHT, any peer can be a circuit relay, WebRTC/WebTransport to browsers). Much larger surface and configuration burden; most of it (DHT, gossipsub, swarm) osis does not need, since peers come from group state. Fallback choice if iroh's single-vendor risk materializes.
- **Plain QUIC (quinn) or TLS/WebSocket to blind nodes only**: simplest and enough for the blind-node topology, but no direct device-to-device sync outside a LAN. Worth keeping as the browser/server path regardless.
- **Veilid** (Rust, MPL-2.0): private routing and its own DHT/storage model. Overlaps with osis's data layer, small ecosystem, activity unclear. Not a base; maybe a later optional transport for metadata privacy.
- **Tor via Arti**: strongest metadata privacy (hides IPs from blind nodes too). Arti onion services were not production-ready as of the last confirmed status. iroh 1.0 advertises pluggable transports including Tor; revisit as an opt-in.
- **Willow/WGPS, Syncthing BEP, Hyperswarm**: sync protocols or JS-only stacks, not transports. Syncthing's community relay pool plus self-hostable discovery is the precedent for point 3.

## Open
- Owner decision on all of the above.
- Whether shipped apps default to any public relay pool (n0's or a community one) for first contact between two users with no shared blind node.
- How two users with no shared blind node exchange a first address (invite link carrying endpoint ID plus relay URL, like iroh tickets).

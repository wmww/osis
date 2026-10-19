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

## Open
- Which free services the official server offers, and abuse limits for free relaying (deferred, notes/sync.md Open).

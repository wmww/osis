# Own P2P transport, replacing iroh
> Summary: Ready to build. Replace iroh (Tess's decision, notes/networking.md decision 2) with P2P on our quinn stack: any willing node relays and acts as hole-punch meeting point, direct paths replace relayed ones by reconnecting, NAT behaviour modelled in the in-process net. Then remove the `iroh`, `relay` features, iroh-relay and probably netwatch, and turn P2P on in every build.
> Tags: transport, node, spec

## Pieces
1. **Relay protocol**, served by any node that opts in (limits per source, bytes and connections; what happens at 0 and infinity per notes/arbitrary-values.md). A node registers its dialable key by signature over a connection it keeps open; a dialer asks for a stream to that key; the relay forwards bytes only. End-to-end TLS 1.3 with raw keys (as `quic://`) runs over the forwarded stream, so the relay sees addresses and volume, never identities (spec/requirements.md, Offline and network). No standalone relay program until needed (Tess): it is a node mode.
2. **Observed addresses**: the relay tells each side the address it sees (as STUN).
3. **Hole punching**: the two sides swap candidate addresses over the relayed stream and dial each other at once from the one UDP socket their quinn endpoint listens on. Port mapping (UPnP, NAT-PMP, PCP) optional, later.
4. **Switching**: once a direct connection completes, sessions move to it and the relayed one closes. Sync reconciles after a reconnect, so no in-connection path migration.
5. **NAT model in `InProcess`**: endpoint-independent, address-dependent and symmetric mapping, so hole punching and relay fallback are tier-1 tested (also issues/no-server-audit.md Fixes 1: honour `peer://` hints).
6. **Network changes**: decide whether `lan::NetWatch` keeps netwatch or route polling alone suffices.

## Decided (Tess)
- **Who relays**: every reachable node relays for its co-readers by default; for strangers only when the user turns it on.
- **Direct addresses**: a reachable node lists them in `reach.0`, so co-readers dial it directly. IPs between nodes sharing data are fine; with a stranger they are exchanged only after consent (accepting an invite). Spec change: spec/sync.md §10 "Published forms list relays only".
- **No default relay** in builds for now: a later product decision. A node lists the relays it knows: co-readers that relay, saved peers, configured ones.

## Open
- Two nodes that both changed networks and share no live relay cannot find each other until one learns the other's new `reach.0` through a third node. A DHT is a later option.
- Spec: spec/sync.md §10 `peer://` defines nodes as iroh endpoints; rewrite it with the relay and punching wire once built.

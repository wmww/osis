# P2P transport: iroh, reachability, LAN discovery
> Summary: Add the iroh-based P2P `Transport` implementation behind a feature: dial by the node's dialable key published in `/reach`, self-hosted relays, hole punching, LAN discovery by rotating tags from the `/reach` lan secret with a per-network transport key, and co-reader dialing in node-sync. Best effort for the MVP: if iroh's API fights the transport abstraction or blows the budget, keep the server transport and file an issue.
> Tags: sync, networking

Crate: `osis-transport` (feature `iroh`), `osis-node` (`/reach` handling, peer selection). Depends on: transport, node-sync. Unblocks: nothing on the critical path.
Spec: spec/sync.md §10 (dialable key separate from signing key; relays in `/reach`; no direct addresses published; LAN tag `kdf("lan tag", lan secret, le64(window))`, fresh transport key per network join), spec/data-model.md §9 (`/reach`). Notes: notes/networking.md (decisions 2, 4; custom discovery, not mDNS; risks). Spec trumps this plan.

## Deliverables
- `IrohTransport` implementing the traits: dial by endpoint key with relay fallback (relay URLs from `/reach`, none from n0 by default), listen, peer key = iroh endpoint key; configuration for self-hosted `iroh-relay`.
- Node: generate and rotate the dialable key and lan secret; publish `/reach` under labels per policy (excluded for open-audience labels by app flag); dial co-readers known from node cards; sync labels peer-to-peer with the member-peer rule (spec/sync.md §5 last bullet: serve a label to an authenticated node of a current member).
- LAN discovery service (custom iroh discovery or own UDP announce): announce tag for the current window + per-network transport key; match tags of known nodes for current and adjacent windows; dial.
- Tests: two nodes over iroh on localhost (tier 2, network-dependent, skipped in CI without a flag); LAN tag property (tags unlinkable across windows and networks without the secret).

## Steps
- [ ] IrohTransport behind feature; loopback test.
- [ ] `/reach` publish/dial; member-peer serving; LAN discovery.
- [ ] Record the iroh version pin and relay setup in notes/networking.md.

## Done when
Two devices on one LAN sync a label with no server; over the internet via a self-hosted relay; or an issue explains what blocked it and what works. Delete this plan.

## Progress

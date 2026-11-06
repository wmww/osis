# Own P2P transport, replacing iroh
> Summary: Transport built (`osis_transport::p2p`, notes/networking.md Implementation): relay protocol as a node mode, observed addresses, hole punching, switching to direct by reconnecting, NAT model in `InProcess`, tier-1 tested; spec/sync.md §10 `peer://` describes it. Left: nodes using it instead of iroh (driver, `Multi`, osis), who relays and direct addresses in `reach.0`, removing iroh and its features, network-change watching, relayed sessions per target blockable by strangers (Open).
> Tags: transport, node, spec, security

## Built
`P2p<U>` over `QuicUdp` (quinn) and `MemUdp` (NAT model): pieces 1 (relay wire, `RelayConfig` with `allow`, `rate`, `max_conns`), 2 (`P2pListener::observed`, the dial answer's addresses), 3 (target punches on its forwarded stream, dialer dials the observed address from its relay socket), 4 (switching: a late direct connection is parked, the relayed one closed) and 5 (`nat.rs`). Tests: `osis-transport` `it` `p2p::` (tier 1 over the NAT model; `quic_relay_loopback_spec_sync_10` tier 2).

## Next stage
1. **Nodes on `P2p`**: `Multi` gets a `p2p` field (`peer://` to it); osis `net.rs`/`port/client.rs` and the node driver's `Control::Reach` listener use it in place of `Iroh` (listener URL: one socket address plus relay items; the LAN listener's `peer://0.0.0.0:0 [::]:0` becomes one dual-stack socket or two listeners). Tier-2 `driver::` tests move from iroh/`TestRelay` to a relaying `P2p` node.
2. **Who relays** (decided): the node builds its `RelayConfig::allow` from its co-readers' dialable keys (`peers()`), or anyone when the user turns relaying for strangers on; a node lists the relays it knows (co-readers that relay, saved peers, configured ones) in `reach.0`.
3. **Direct addresses in `reach.0`** (decided): a reachable node lists them; spec/sync.md §10 "Published forms list relays only" and "Direct addresses are never published" change then. How a node knows it is reachable (an observed address equal to a local one, or a dial-back through a relay) is open.
4. **Remove iroh**: features `iroh`, `relay`, the iroh and iroh-relay deps, `TestRelay`, the iroh arms of `Multi` and `quic_streams!`'s second use, deny exceptions; P2P on in every build (issues/node-host-unify.md).
5. **Network changes**: `lan::NetWatch` uses netwatch's monitor only with `iroh`; decide whether route polling alone suffices once netwatch is only `lan`'s interface list. A listener's socket and registrations survive a network change only as the relay connection does (QUIC migration is off): re-listen on a change.
6. Port mapping (UPnP, NAT-PMP, PCP): optional, later.

## Decided (Tess)
- **Who relays**: every reachable node relays for its co-readers by default; for strangers only when the user turns it on.
- **Direct addresses**: a reachable node lists them in `reach.0`, so co-readers dial it directly. IPs between nodes sharing data are fine; with a stranger they are exchanged only after consent (accepting an invite).
- **No default relay** in builds for now: a later product decision. A node lists the relays it knows: co-readers that relay, saved peers, configured ones.
- No standalone relay program until needed: relaying is a node mode.

## Open
- **Relayed sessions per target are blockable** (security): the relay opens each forwarded stream on the target's registration connection, which takes 16 at once (quinn's stream limit). A 17th dial waits in the relay without bound (keep-alive holds the relay connections up), and so does the dialer's `dial`. Anyone who knows a key and its relay can dial it 16 times and never send a ClientHello: the target's handshake on a forwarded stream has no deadline while its registration lives, so all 16 stay held and honest dials through that relay hang. The NAT model has no stream limit, so tier 1 does not show it. Needs a rule with a defined outcome past the bound, e.g. the relay answering busy instead of waiting, and the target aborting its oldest unfinished forwarded handshake (as `quic` does past 1024) under a larger stream limit for registration connections.
- `RelayConfig::allow` is checked at registration only: a key that stops being allowed stays registered until its connection ends (matters once `allow` follows co-readers).
- Two nodes that both changed networks and share no live relay cannot find each other until one learns the other's new `reach.0` through a third node. A DHT is a later option.
- Hole punching shows the dialer's IP to the target (and the target's to the dialer) at every relayed dial. Dialing a stranger through a relay (a link's sharer, before consent) therefore exchanges IPs, against the decided rule above; the next stage needs a way to dial without punching (a flag on the dial) for those, or Tess's call that link redemption counts as consent.
- Switching interrupts the relayed session (one reconnect per P2P connection that punches late; on loopback the relayed path usually completes first). Moving the session without a reconnect would need in-connection migration, which the design rules out.

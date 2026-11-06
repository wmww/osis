# Own P2P: what nodes still lack
> Summary: Our P2P (`osis_transport::p2p`, spec/sync.md §10 `peer://`, notes/networking.md Implementation) is the only P2P transport, on in every build: nodes, `Multi` and osis use it, relay for their co-readers and exchange IPs only with them. Left: direct addresses in `reach.0`, co-readers as relays, relaying for strangers as a user setting, port mapping; open: a stranger can learn a target's IP, a registration's shared flow-control window, DHT.
> Tags: transport, node, spec, security

## Next
1. **Direct addresses in `reach.0`** (decided: a reachable node lists them, so co-readers dial it directly; spec/sync.md §10 "Published forms list relays only" and "Direct addresses are never published" change then). Rename `reach.0` field 1 (`relays`) to the URL's items when it carries both. How a node knows it is reachable is open: an observed address (`P2pListener::observed`) equal to a local one with the same port is the simple rule, but needs a relay; without one, a dial-back or listing the route addresses (`lan::route_ip`) always. Links must keep carrying relays only (filter the items in `make_link`). The listener binds `[::]:0`, so the port changes per run: a fixed port with a fallback avoids a `reach.0` commit per restart.
2. **Co-readers as relays** (decided): a node lists the relays it knows in `reach.0`: co-readers that relay (reachable ones, from their direct addresses), saved peers, configured ones (`Config::relays`). Needs registrations that follow that set without re-listening (`P2pListener` takes its relays from the URL once).
3. **Relaying for strangers** (decided: only when the user turns it on): a `Config` switch making `RelayConfig::allow` answer true (passes notes/api-design.md).
4. Port mapping (UPnP, NAT-PMP, PCP): optional, later.

## Decided (Tess)
- **Who relays**: every reachable node relays for its co-readers by default; for strangers only when the user turns it on. Relaying is a setting of an ordinary node, never a kind of node; no standalone relay program until needed.
- **Direct addresses**: a reachable node lists them in `reach.0`. IPs between nodes sharing data are fine; with a stranger they are exchanged only after consent (accepting an invite).
- **No default relay** in builds for now: a later product decision.
- **IP consent** (notes/questions-for-tess.md §17, reversible, not yet answered): punch only between nodes that share data; a stranger (a link's sharer) is dialed hidden until the invite is accepted. One predicate: osis `net.rs` gives `P2p::punching` the co-reader set; `|_| true` flips it.

## Open
- **A stranger can learn a target's IP**: hidden dials are the dialer's choice. Anyone holding a key and its relay (a link's holder) can send a plain dial and gets the target's observed address, and the target punches to it. The target cannot tell (dialers use ephemeral keys; the co-reader proof comes inside the session). A fix would move punching after the session proves a co-reader (an in-session exchange), or have targets refuse plain dials from relays they did not ask for it.
- **One registration, one flow-control window** (security): every forwarded stream to a target shares its registration connection's 4 MiB connection window. A relayed session whose data the target's user does not read (queued for `accept`, or a session the node reads slowly) holds window that honest sessions through that relay then lack. Bounded by `MAX_FORWARDED` and the listener's queue, not removed.
- Hidden dials all arrive with the zero address: the target's per-source fairness (`link::Slots`, `evict_for`) counts them as one source.
- Two nodes that both changed networks and share no live relay cannot find each other until one learns the other's new `reach.0` through a third node. A DHT is a later option.
- Switching interrupts the relayed session (one reconnect per P2P connection that punches late; on loopback the relayed path usually completes first). Moving the session without a reconnect would need in-connection migration, which the design rules out.
- Network changes are seen by route polling only (`lan::NetWatch`); a P2P listener's registrations renew once their relay connections time out (up to the 60 s idle timeout).
- A LAN listener on `[::]` relies on the OS making it dual-stack (Linux does by default); where it does not, IPv4 LAN dials to it fail.

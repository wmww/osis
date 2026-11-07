# Connecting: which nodes connect, and the lower network layer
> Summary: The first of the two layers (Tess): which nodes a node connects to. Proposed: on a LAN, every osis node connects to every other (an announcement of a per-join key and port, nothing else; no tag, lan secret or signature), kept while issues/net-shared-set.md finds something shared; beyond a LAN, nodes known from group data, covering each synced group; one stable listening key, no automatic rotation; identity exchanged with every LAN node, shared set only with known actors (Tess). Plus `lan` in every build, a runtime always, LAN rule fixes, Android. Open: meeting points for nodes that never met on different networks. Part of issues/net-rework.md.
> Priority: normal
> Tags: transport, node, spec, tess-call

## Today (code as built)
- `lan` is an optional feature of osis-transport, osis-node and osis; only `cargo test-net`/`clippy-net` turn it on, so no shipped build announces or listens on the LAN (row 1). The CLI runs a runtime only for commands that sync (`cli/src/lib.rs` `config(g, net)`; row 3).
- Dialed (`conn.rs` `wanted_hosts`): config hosts, labels' and hints' non-`peer://` hosts, queued deposits' hosts, receipt groups' hosts, co-readers and a link's sharer (row 28). Co-readers (`peers.rs` `peers`): node things with a held `reach.0` that `may_read` a synced label's group, at most 8 per label and 64 in all, newest `seen.0` first; an unreachable 8 hide a reachable 9th (row 36).
- `reach.0` (dialable key, global addresses, relays, lan secret) goes under every synced label. Rows 22 and 23 (link-shared groups get none) and row 10's grant and second-link rotations predate that; re-probe them (issues/net-tests.md).
- LAN: a 124-byte announcement of a tag (from the lan secret), a per-join key, a port and a signature by the dialable key sealed under the lan secret. A receiver matches it only against co-readers it knows from `reach.0`, only from a private source address (`lan.rs` `recv` and `peers.rs` `lan_seen`, row 30), within ±1 ten-minute window (row 34), and runs a candidate, heard-count, replay-binding and route-switching machine on the match (notes/peers.md LAN).
- Rotation (`rotate_reach`): by hand (`rotate_peer_address`) and when a direct link ends (osis `upkeep_links`; spec/permissions.md §7 SHOULD). It drops the old listener at once, so a node that knows only the old key and hears the new `reach.0` from nobody is cut off for good (rest of row 10).
- So a node connects only to nodes it already knows something of. Two nodes holding the same thing that never met (new devices on both sides; nodes granted by nodes now gone) never connect, on a LAN or off it.

## Rules (Tess)
- **Connect, then identify, then share.** A node connects to every osis node on its LAN. Both sides then exchange identity: each proves the actors it acts for (its node key, its chain to its account; a key actor it holds, such as a link key it redeems), since nobody can be trusted before a handshake. The shared set (issues/net-shared-set.md) runs only with a node that proved a **known actor**: one whose keys this node holds (its own account, contacts, holders of anything it holds, a link key on a roster it administers).
- Showing an account's identity to anyone on the LAN is accepted (Tess). Hiding it from unknown accounts while still finding known ones is wanted if cheap: issues/privacy.md.
- Conflicts with spec/requirements.md, Offline and network ("reveals its address, never which node, actor or account it is") and Data a node cannot read ("must not learn ... node identities"): both need rewording for the LAN; Tess accepts showing the account on the LAN, so the wording changes with this job. Who proves first: issues/net-shared-set.md (on a LAN both at once; off it the dialer).
- Connecting never depends on what the other node holds; what opens is the shared set's job.

## On a LAN: connect to every osis node
- **Announcement**: `"osis lan 2"` || per-join transport key (32) || be16 port: 44 bytes, to the same targets as today. No tag, no signature, no lan secret: nothing stable across networks, nothing meaningful to anyone, and nothing to match.
- **Dialing**: a node dials every announcer it hears, at the source address and announced port, with an ephemeral key. Once per pair: of two nodes that hear each other only one connection stays (Unsure (implementor): e.g. the dialer names its own announced key in the session and the higher announced key closes its duplicate). Dials go out paced (a few at once), with no cap on how many are dialed in the end.
- **Keeping**: a connection stays while the shared set has something; one with nothing in common closes, and is dialed again when this node's set of sync IDs grows (its own change, which it knows), or either side rejoins (a fresh key is a fresh announcement). The other side's growth reaches it the same way: the side that grew dials.
- **Preferring the LAN**: once a LAN connection's peer proves itself node X (Rules), other connections to X close and X is not dialed elsewhere while it lasts. This replaces the candidate, heard, bound and `lan_probe`/`lan_switched` machinery.
- **Strangers**: any node on the LAN can already dial an announced key today. Served sessions stay bounded by `max_served` (oldest that opened nothing evicted). Announcements are unauthenticated, so a forged one costs one dial; pacing and at most one pending dial per source address bound a flood.
- **What goes**: the lan secret (`reach.0` field 2), LAN tags and windows, the sealed signature (osis-crypto `seal_lan_sig`/`open_lan_sig`, `core/test/vectors/lan/announce.vec`), the source-address filter (row 30 falls out: routed meshes, CGNAT and global sources all work), the replay binding, and rows 34 and 36 for the LAN (nothing to match).
- A link's redeemer on a LAN then finds the sharer with no special case: it connects to every LAN node, proves the link key (a known actor to the sharer, on K's roster), and K's sync ID matches through the shared set (row 6, with issues/net-first-contact.md).
- Two accounts that both hold T but neither holds the other's keys do not share over their connection; they sync through any node that knows both. Accepted for now, can change later (Tess).
- Unsure (design): a big LAN (hundreds of osis nodes) makes every pair connect once per join and run the shared set; check its cost at 10^3 nodes with issues/net-shared-set.md's numbers before shipping. Rejected: capping LAN connections (some pair that shares a group would never meet).

## Beyond a LAN: nodes known from group data
- `reach.0` keeps the dialable key, global addresses and relays; peers that cannot read are listed by key plus hints the same way (issues/net-one-peer.md). These are the address book for nodes off the LAN.
- Candidates: every node whose `reach.0` or listed key this node holds, whatever group it came from, plus a link's sharer. Which to keep connected is a priority, never a filter on what may open: try first those whose roles say they hold the synced groups, newest `seen.0` first, and keep going through every candidate until each synced group has its target of connected nodes that share it (by the shared set, not by role data). The cap counts connected nodes that share something, never candidates, so an unreachable few never hide a reachable one (row 36).
- Unsure (design): the target per group and the total (today 8 and 64), passed through notes/arbitrary-values.md: at 0 a group syncs with nobody; at infinity a node dials every member of a large group.
- Co-reader proof 3 and the role-based part of `wanted_labels` move to issues/net-shared-set.md.

## The listening key
- One listening key per node (decided): the dialable key, dialed by key from `reach.0`, links and group data. LAN listeners keep a fresh key per network join, since an announcement is heard by strangers and a stable key in it would let anyone track the device across networks (spec/sync.md §10).
- Unsure (Tess): spec/requirements.md says "a node is dialed by its one listening key". Recommended: keep the per-join LAN key as the one exception, worded "a node is dialed by its one listening key, or on a LAN by the key it announced there".
- Unsure (Tess): **no automatic rotation**. Recommended: the key stays put; `rotate_peer_address` stays as an explicit user act; ending a direct link no longer rotates (spec/permissions.md §7 SHOULD goes). Why: once LAN recognition and opening need no known key, an old key gives an ex-holder only a way to dial the node, which opens nothing for it; what it still learns is the node's address and that it is online, which is issues/privacy.md's. Rotation's costs stay: it strands nodes that knew only the old key (row 10), breaks a key named in `Config.relays` (issues/p2p-own.md Open) and changes the key every group lists for a peer that cannot read.
- If rotation stays for the hand-made case: keep the old listener until the new `reach.0` was delivered under every synced label, or a bound passes (Unsure (design)), so connected peers learn the new key before the old one goes.

## Nodes that never met, on different networks
- Two nodes that share a group, never met, are on different networks and have no common node online cannot connect: neither holds the other's `reach.0`, and no relay or default meeting point is in builds (decided). Example: both sides of a chat replaced their phones while the old ones are gone. On a LAN or with any common node online they meet as above.
- Needed: a meeting point both can name without knowing the other node. Per-sync-ID announcement is rejected (Tess). What both do know is the other's account (roster, contacts).
- Unsure (Tess): whether this case must work before release, given no default relay. Recommended: not for the first release; then a lookup by account: each node registers once, under a beacon of its own account's key, at the meeting points it uses; a node looking for co-holders looks up the accounts of its groups' holders. Meeting points are relays (any node relaying, listed in `reach.0` as relays are) or an opt-in DHT (notes/networking.md decision 3). One record per node, not per sync ID. Anyone holding an account's public key could then find its nodes' addresses (issues/privacy.md).
- Unsure (design): a mesh with no broadcast across hops (row 31) is the same case unless extra announcement targets are configured.

## Connect by default
- `lan` becomes non-optional in osis-transport, osis-node and osis, as QUIC and P2P are (a default on `osis` alone breaks the gate's unification check, notes/build.md). `cargo test-net`/`clippy-net` then lose `--features osis/lan`; tier-2 LAN tests stay `#[ignore]`d (rows 1, 31).
- The CLI and app always run a runtime, saved peers or not (row 3).
- Android: `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE` and a held multicast lock over JNI; `/proc/net/if_inet6` may be unreadable on newer APIs. Unverified, needs a real phone (issues/no-server-audit.md, Builds).
- Wi-Fi client isolation blocks LAN discovery entirely; nothing to do but fall back to the above.

## LAN rules that stay (independent, any time)
- `SO_REUSEADDR` (and on Linux every socket on the port getting broadcasts) or a status for a failed bind of 47380; today a second node on one machine only logs it (`driver.rs` `lan_start`, row 32).
- Extra announcement targets for routed meshes, `LanConfig` in `Config` (row 31; passes notes/api-design.md).
- A joining node announces a few times in its first seconds; a lost first announcement waits 30 s today (row 33). Unsure (implementor): how many and how fast.

## Spec and code to change
spec/sync.md §10 (LAN discovery: announcement, tag, sealed signature, receiver rules; `reach.0` lan secret; Keys and reach), spec/data-model.md §9 `reach.0` field 2, spec/permissions.md §7 rotation, spec/requirements.md (one listening key, if Tess agrees), osis-crypto LAN sealing and its vector, notes/peers.md LAN and `reach.0`, notes/networking.md decision 4.

## Related
Relays (co-readers as relays, relaying for strangers, port mapping): issues/p2p-own.md. What opens once connected: issues/net-shared-set.md. Links and inbox delivery: issues/net-first-contact.md.

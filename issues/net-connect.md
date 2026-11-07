# Connecting: which nodes connect, and the lower network layer
> Summary: The first of the two layers (Tess): which nodes a node connects to, and the transport work under it. LAN in every build, a runtime always, direct sync between everyone sharing a group, who to trust on the LAN (a setting), rotation only on real removal, LAN rule fixes, Android. Finding shared sync IDs once connected is issues/net-shared-set.md. Part of issues/net-rework.md.
> Priority: normal
> Tags: transport, node, tess-call

## Connect by default
- `lan` becomes non-optional in osis-transport, osis-node and osis, as QUIC and P2P are (a default on `osis` alone breaks the gate's unification check, notes/build.md). Rows 1, 31.
- The CLI and app always run a runtime, saved peers or not (row 3).
- Nodes that share a group sync directly by default, links included: today `reach.0` goes out only where every reader is this account or a contact (rows 22, 23).
- Rotate the dialable key only when someone is really removed: a grant, a second direct link or a link ending must not cut joiners off (row 10).
- Android: `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE` and a held multicast lock over JNI; unverified, needs a real phone (issues/no-server-audit.md, Builds).

## Whom to connect to (Tess: probably a setting)
- Today a node dials only nodes it already knows (config, saved peers, co-readers' `reach.0`, hints, a link's sharer; row 28), and on the LAN recognises only co-readers it knows. So two nodes holding the same thing that never met cannot connect (new devices on both sides, or nodes granted by nodes now gone).
- Proposed: connecting does not depend on knowing what the other holds; that is the next layer's job. On a LAN, connect to all osis nodes, or only to ones whose verified identity matches a contact, one of your own nodes, or similar (a setting).
- Unsure (Tess): the default, and what "trusted" is (contacts? own nodes? anyone sharing a group, which needs layer 2 first?).
- Unsure (design): beyond one LAN, how nodes that never met meet (relays as meeting points, a DHT; issues/p2p-own.md), and whether that is needed soon.
- Unsure (design): what a LAN announcement then carries, and what replaces today's co-reader LAN tags (lan secret per node in `reach.0`).

## LAN rules (independent, any time)
- Drop the source-address check: tag and signature already decide (row 30).
- Tag windows as wide as `MAX_DRIFT` (row 34).
- `SO_REUSEADDR` or a status for a failed bind (row 32).
- Recognition over every known node, a cap only on dials (row 36).
- Extra announcement targets for routed meshes, `LanConfig` in `Config` (row 31).
- Faster re-announce on a join; a lost announcement waits 30 s today (row 33).
Some of these may go if the announcement changes (above).

## Related
Relays (co-readers as relays, relaying for strangers, port mapping): issues/p2p-own.md.

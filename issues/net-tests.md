# Networking tests that can fail
> Summary: The sim never makes peer connections and `InProcess` finds any listener by key, so tier 1 cannot see most networking failures. Give the sim peer connections, NAT and partitions, make in-process `peer://` need a route, and rebuild the audit's probes as failing tests. First job of issues/net-rework.md.
> Priority: normal
> Tags: tests, sim, transport

- The sim's `World` drops every dial that isn't a hub (core/test/sim/src/world.rs), so sims and sweeps never run peers. Give it peer connections, NAT types and partitions.
- `Transport::InProcess` dials any listener by key (core/transport/src/multi.rs `peer://`): make it need a hint or a LAN route, as real P2P does. Today a `works` over it says the sync logic holds, not that nodes find each other.
- Rebuild issues/no-server-audit.md's probes (pNN/qN, never committed) as tier-1 tests; those for rows still open fail, and are the rework's checklist.
- Harness words follow the code (`World::add_host`, `NetHost`), renamed with issues/net-rename.md.

Unsure:
- (implementor) How much of the LAN to model in process: announcements, source addresses, time windows, lost packets.
- (design) Whether tier 2 (`cargo test-net`) needs a multi-machine or netns setup to cover what localhost cannot (routed meshes, client isolation).

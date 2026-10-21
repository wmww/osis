# P2P follow-ups
> Summary: A direct share link lets a newcomer reach the sharer's device without a server, but only when that device already syncs the shared group with a server or another of its devices (one that syncs with nobody hands out an empty group); IPv6 LAN discovery uses only the default network interface.
> Tags: sync, networking

Repro: in crates/osis/tests/runtime.rs `redeem_direct_in_process_spec_permissions_9`, give Alice no server (and drop the `wait_synced`): Bob's `redeem` times out.

1. **Sharer that syncs with nobody** (spec/permissions.md §9, spec/sync.md §5 member peer): a node serves only the entries its own passes placed, and passes run per connection it dialed (pass.rs `place`, `certificates`). With no server and no other device, K's label and the target's are never passed, so the redeemer opens K at the sharer and finds nothing. Fix idea: a node is its own "server" for labels it syncs with nobody: a local pass placing bodies, certificates and heartbeats with no presence or deletion step (or a loopback session in the engine), so the served state is complete. Touches pass.rs and the engine, not the transport.
2. **IPv6 on several interfaces** (spec/sync.md §10): ff02::1 announcements go out the default multicast interface only (`lan::multicast`, interface 0). A host on two IPv6 LANs is heard on one. Fix: send per interface with its scope (netwatch lists them).

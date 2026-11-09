# Networking tests that can fail
> Summary: Tier-1 networking coverage. In-process `peer://` and the driver's LAN loop run the real code over the NAT model and the sims have peer links over one reachability model (`osis_sim::reach`). Each open audit row has a `repro_*` test its job un-ignores. First job of issues/net-rework.md.
> Priority: normal
> Tags: tests, sim, transport

## Today
- **Sim peer links** (notes/testing.md, Reachability model): `osis_sim::reach::Reach` places each node on LAN segments with a public address, a NAT or no uplink; a `peer://` dial reaches the listener by key when some item routes: a LAN address on a shared segment, a public address, a punch (`osis_transport::nat::punch_opens`, the rule `punch_by_nat_type` checks against the packet machine) or a relay both reach. Both sims use it and serve dials through `SyncEngine::accept`. `World` (core/test/sim/src/world.rs): `place`, `peer_routes`, `set_peer_reachable`, `set_relay_up`, `lan_announce`, `restart`, `cfg_clocked` (per-node clocks); its hub links and `set_reachable` are as they were. `NetSim`: `reach`, `listen_peer`, `lan_announce` (droppable), `set_relay_up`, `peer_routes`; its link faults, crashes and restarts apply to peer links unchanged, and partitions also pick (node, node) and (node, relay) pairs when nodes are placed. A peer that cannot read stays a node's hub until issues/net-one-peer.md.
- **Checks over peers**: `NetSim`'s liveness and agreement judge the holders the model keeps connected (`check::Connected`: every host they reach, replication, routes between holders); a holder the model cuts off is left out and counted (`Report::unjudged`). Sweep scenarios `no_host` (one LAN, public, relayed or punched, by seed) and `no_host_chain` (two LANs joined by a holder) have no host.
- **Tokio tests** over `InProcess` (`Internals.transport`, core/osis/src/net.rs `spawn_driver`): `peer://` needs `P2p`; without one it is `UnknownScheme`. A node placed on a host of a nat.rs net (`Internals.host`, `Net::run_on_tokio`) dials `peer://` through `P2p<MemUdp>` over the route it names (`Multi<U>`): core/osis/tests/it/runtime.rs, core/node/tests/it/driver.rs. A node with no host does not reach anyone by key.
- **Route tests**: core/transport/tests/it/p2p.rs `peer_*`, a `Multi<MemUdp>` under `Sched`: no route, direct item, relay, LAN address (same NAT).
- **LAN**: the driver's loop (`Control::Lan`) takes its announcement socket from the transport (`Transport::lan`: `lan::Lan`'s UDP sockets on `QuicUdp` with feature `lan`, a `MemLan` on `MemUdp`), so tier 1 runs the production loop over the nat.rs model: LAN segments a host joins at an address (`MemUdp::on_lan`), loss per segment (`Net::set_lan_loss`), source addresses per segment (core/node/tests/it/driver.rs `driver_lan_*`, row 30 as `repro_lan_any_source_connects`). Real sockets on localhost stay tier 2 (`driver_lan_loop_*`).

## Do
1. In-process P2P with routes: built (Today).
2. In-process LAN: built (Today).
3. Sim peer links and 4. Checks over peers: built (Today).
5. Audit rows as tests: built (core/test/sim/tests/it/no_server.rs on `World`, model time; `repro_row1_*` in core/osis/tests/it/runtime.rs, `repro_row3_row12_*` in cli/tests/it/cli.rs). The job that fixes a row renames and un-ignores its test. Still without a repro: row 33 (a lost announcement waits a whole interval, the driver's LAN loop can now show it) and row 4 end to end.

Not in tier 1: row 32 (a real port's bind: tier 2), Android, real broadcast reach (row 31, beyond what a model says).

Harness words follow the code (`World::add_host`, `NetHost`), renamed with issues/net-rename.md.

Unsure:
- (design) Real sockets beyond localhost. Proposed: one tier-2 setup in unprivileged network namespaces (`unshare -rn`, veth and bridges) for broadcast across a bridge, routed meshes and client isolation; no multi-machine test in any gate; phones by hand.

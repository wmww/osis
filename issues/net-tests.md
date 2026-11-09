# Networking tests that can fail
> Summary: Tier 1 cannot see most networking failures: both sims connect nodes only to hubs. In-process `peer://` runs the real P2P code over the NAT model (done); give the sims peer connections over one reachability model (LAN segments, NAT, relays, partitions, restarts, per-node clocks) and commit the audit's probes as ignored `repro_*` tests each job un-ignores. First job of issues/net-rework.md.
> Priority: normal
> Tags: tests, sim, transport

## Today
- **API sim** `World` (core/test/sim/src/world.rs; `Runtime::Manual`, drives most core/osis tests): `actions` links a `Dial` only to an up hub whose address matches (`add_host`, or a node's `Action::Host`), else `Down`. Nothing in core/test/sim calls `SyncEngine::accept`, so no node is ever dialed. One `ManualClock` for every node; cuts are node-to-hub only (`set_online`, `set_reachable`).
- **Engine sim** `NetSim` (core/test/sim/src/net/mod.rs; `sim-sweep`): `dial` likewise matches host keys only (its comment "finds a node by its current `reach.0`" is not what it does). It has what `World` lacks: per-node skew and drift (`ClockSpec`), crash and restart over durable state, link faults, pair partitions (`blocked`, `unreachable`), invariant checks.
- **Tokio tests** over `InProcess` (`Internals.transport`, core/osis/src/net.rs `spawn_driver`): `peer://` needs `P2p`; without one it is `UnknownScheme`. A node placed on a host of a nat.rs net (`Internals.host`, `Net::run_on_tokio`) dials `peer://` through `P2p<MemUdp>` over the route it names (`Multi<U>`): core/osis/tests/it/runtime.rs, core/node/tests/it/driver.rs. A node with no host does not reach anyone by key.
- **Route tests**: core/transport/tests/it/p2p.rs `peer_*`, a `Multi<MemUdp>` under `Sched`: no route, direct item, relay, LAN address (same NAT).
- **LAN**: the loop is real UDP only (transport `Lan`, driver `Control::Lan`), tested on localhost in tier 2 (core/node/tests/it/driver.rs `driver_lan_loop_*`). Its engine side (`lan_announcement`, `lan_seen`) needs no socket.

## Do
1. **In-process P2P with routes.** Done (Today, Tokio tests and Route tests).
2. **In-process LAN.** The driver's LAN loop over a `MemUdp` broadcast domain per segment, with loss and the source addresses the model assigns (row 30 then tests in tier 1).
3. **Sim peer links**, in `World` and `NetSim` over one shared reachability model (not nat.rs's packet machine again): each node sits on LAN segments and has a public address or a NAT type; a `peer://` dial reaches node N's dialable listener (`SyncEngine::accept`) when some item routes: a LAN address on a shared segment, a public address, a relay both reach, or a punch the NAT pair allows (the table `punch_by_nat_type` checks). On top: pair partitions, cut links, restarts over the same store, per-node clocks in `World`, LAN announcements within a segment through `lan_announcement`/`lan_seen`, droppable. A peer that cannot read is a node's hub until issues/net-one-peer.md gives it the node's own serving path.
4. **Checks over peers.** `NetSim`'s liveness and agreement judge nodes the model keeps connected (directly or through a chain of nodes serving the group), not hub clients only. At least one sweep scenario with no hub at all; a scenario still broken goes in `osis_sim::BLOCKED` naming its job.
5. **The audit's probes as tests.** Every row still open (issues/no-server-audit.md: pNN/qN, never committed) becomes a `repro_*` test with `#[ignore = "issues/net-<job>.md"]` (notes/testing.md, Phase C: the `repro_` convention), asserting the right outcome over 1-3; the job that fixes the row renames and un-ignores it. Timeouts in them (40 s, 100 s) run on model time (`ManualClock`, the nat.rs net's steps), never wall time.

Done means: 5 for every row testable in process; 2 and 3 with a hubless sweep scenario passing for the data rows that work today (row 20) and repro tests for the rest. Not in tier 1: row 32 (a real port's bind: tier 2), Android, real broadcast reach (row 31, beyond what a model says).

Order: 5 comes first: each job's "tests that fail without it" needs them. 3 is needed before issues/net-honest-status.md (deterministic waits and timeouts) and before issues/net-shared-set.md, net-reconnect.md and net-one-peer.md (sweeps over peers, restarts). 2 before issues/net-connect.md's LAN rules.

Harness words follow the code (`World::add_host`, `NetHost`), renamed with issues/net-rename.md.

Unsure:
- (design) Where the reachability model lives so `World` and `NetSim` share it (a module of core/test/sim), and whether `NetSim`'s fault scheduler applies to peer links unchanged.
- (implementor) The `MemUdp` broadcast domain: in nat.rs, or a `Lan` trait the driver takes.
- (design) Real sockets beyond localhost. Proposed: one tier-2 setup in unprivileged network namespaces (`unshare -rn`, veth and bridges) for broadcast across a bridge, routed meshes and client isolation; no multi-machine test in any gate; phones by hand.

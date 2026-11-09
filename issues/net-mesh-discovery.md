# Finding nodes on a mesh where broadcasts stop at one hop
> Summary: Tess: spec/requirements.md promises every feature "including a dynamic mesh with no internet at all"; issues/net-connect.md's LAN discovery reaches one broadcast domain, and nothing in issues/net-rework.md carries an announcement across hops. Either the requirement means one broadcast domain plus known addresses and any reachable node, or a later job gossips announcements over the mesh. Proposed: the first, as the requirement's reading.
> Priority: low
> Tags: tess-call, transport, spec

## Question
On a network where a broadcast does not reach every node (a routed mesh: several Wi-Fi segments joined by routers, a layer-3 ad-hoc mesh), should two osis nodes that have never met find each other automatically, or is it enough that they meet when one knows the other's address, when they share a reachable node, or on one segment? A layer-2 mesh (one that forwards broadcasts, as most mesh Wi-Fi does) is one broadcast domain and works as a LAN.

## Trade-off
- **One broadcast domain (proposed)**: discovery works within a segment; across segments a node needs an address to dial (configured; a link's connect hints; its own account's nodes; a serving node a contact lists) or a node both can reach. issues/net-connect.md's extra announcement targets let an operator name the other segments by hand. Nothing more to build.
- **Automatic across hops**: nodes pass on announcements they hear (gossip with de-duplication and a hop bound), so every node on the mesh learns every node's address and per-join key. Cost: per node, state for every node on the mesh and a steady trickle of relayed announcements growing with the mesh; a node's address travels onto segments it never announced on (IP exposure is issues/privacy.md's); the per-join key still names nobody. A later job of issues/net-connect.md's "Nodes that never met", the same shape as its lookup by account.
- Rejected: each node re-announcing what it hears one hop on. On one segment of n nodes it is n² datagrams per round, it reaches two hops and not three, so it is a mechanism that handles only most cases (issues/net-rework.md, Rules), and it carries addresses one hop further for no complete result.

## Why users care
Off-grid and disaster setups are where "no internet at all" matters. On one segment everything works; across a routed mesh, two people who never exchanged an address or a link do not find each other until someone configures a target or a common node appears. If that is the intended promise, spec/requirements.md says so in one phrase ("on one network segment, to a known address, or through any node both can reach"); if not, the gossip job is scheduled after the rework.

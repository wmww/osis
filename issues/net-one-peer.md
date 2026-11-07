# One kind of peer
> Summary: A node has two kinds of peer (saved peer, the old host; direct peer, a co-reader) with three serving paths, two stores and three listening keys. Make one: `peer://` as an address, one key, one serving path where the proof decides what opens, one store, consent by `Admit`, carriers listed in group data; then the API (`SyncId` out). The concept unification the rename waits for. Part of issues/net-rework.md.
> Priority: normal
> Tags: node, sync, host, proto, api, spec

| | Saved peer (old host) | Direct peer (co-reader) |
|---|---|---|
| Found by | fixed address in `label.0`, link and card text | `reach.0`, LAN, a link's sharer |
| Who can be one | a node with `set_serving` and `Admit` | a node that reads the group |
| Serving code | the hub (`osis-host`) | `sync/serve.rs` |
| Store | `host.redb` (blobs) | `db.redb` (plaintext state) |
| Key | serving key | dialable key (plus the client listener key) |
| Confirms | a pass: `Synced`, waits, `complete` | only `Connected` (issues/net-honest-status.md) |

Steps, in the order of what they unblock:
1. **An address that names a node**: `peer://` among a group's peers, dialed by key (spec/sync.md §10, spec/wire.md §10, conn.rs skips `peer://` today; rows 26, 27).
2. **One listening key per node** (decided): the dialable key, also its key as a peer of groups it cannot read; dialers stay ephemeral. The client port keeps its own access rules on it (notes/client-port.md §5).
3. **One serving path**: the hub and co-reader serving become one, differing only in what proof opens a sync ID (spec/sync.md §4-§6). Hosts replicating to each other folds in or goes.
4. **One store**: a node serving a group it also reads keeps it once.
5. **Consent**: `Admit` defaults to the user's own nodes (decided), not phrased around servers. Wider later.
6. **Finding peers that cannot read**: listed in group data by key plus hints, as `reach.0` (decided). Adding one later works per group, also for someone else's group (row 26).
7. **API**: `add_peer` takes any node, `peers(g)` one list, `sync(g, peers)` adds to it, `set_serving` only limits, `SyncId` leaves the public API (decided). Admission by sync ID (`admitted: set<SyncId>`) needs a replacement.

Keep: the code that serves data a node cannot read cannot decrypt anything (`osis-host` has no engine or keys; `tools/policy.py` `host_blind`). A security boundary inside every node, not a kind of node.

Also: `osis-proto`'s `ClientSession` (the dialing side, unrelated to API clients) and `ServingSession::port_only` get names that say so (issues/net-rename.md). Row 24 (C to A through B never relayed: C's chain certificates) is a small bug of its own.

Unsure:
- (design) One serving path as one protocol path, or one store with two session kinds.
- (design) Replacement of a sync ID (issues/net-role-sync.md).
- (Tess) Whether serving data a node cannot read stays opt-in by `Serving` config. Proposed: own nodes and groups served with no setup, anyone else's opt-in.
- (design) Admission without `SyncId`: by group, resolved by the admitting node, or by grant.
- (design) spec/data-model.md §9 `host.0^` admission by record chain (static: names the first admin for good).

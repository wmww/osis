# One kind of peer
> Summary: A node has two kinds of peer (saved peer, the old host; direct peer, a co-reader) with two stores behind osis-proto's one `ServingSession`, local passes besides, and three listening keys. Make one: one key, one blind store and serving path (the hub, fed public data by node sync) that opens by key proof alone, peers that cannot read listed in group data, consent by own nodes; then the API (`SyncId` out). The concept unification the rename waits for. Part of issues/net-rework.md.
> Priority: normal
> Tags: node, sync, host, proto, api, spec, tess-call

| | Saved peer (old host) | Direct peer (co-reader) |
|---|---|---|
| Found by | fixed address in `label.0`, link and card text | `reach.0`, LAN, a link's sharer |
| Who can be one | a node with `host.0^` that admits the label | a node that reads the group |
| Serving code | `ServingSession` in the hub (`osis-host`, `HostStore`) | `ServingSession` in `sync/serve.rs` (`PeerStore`); local passes when no host is listed (notes/peers.md) |
| Store | `host.redb` (entries, blobs, durable log) | node sync's entries and the engine's blobs; log in memory (`Feed`) |
| Key | host key | dialable key; the client port has its own |
| Opens by | sync key, claim, static entry | those and proof 3 (co-reader by dialable key) |
| Registration | first come, by parent's delete key | steps recorded in `label.0`, plus child steps peers register (memory only); new labels refused |

## Steps, in the order of what they unblock
1. **An address names a node**: a peer is dialed by key with hints (spec/sync.md §10, spec/wire.md §10). Today conn.rs never dials a `peer://` saved peer (rows 26, 27).
2. **One listening key per node** (design choice, not Tess's; re-justify or drop): the dialable key, for sync, serving and the client port; dialers stay ephemeral. The client port keeps its own access rules (notes/client-port.md).
3. **One serving path**: the protocol is already one (`ServingSession` over a `LabelStore`); what differs is the store, the open rules and registration. The hub serves every sync ID the node holds, readable or not; `PeerStore`, proof 3 and hosts replicating to each other go (replication is sync with a peer); local passes become node sync's pass against its own store. Node sync is a client of the local store for its own uploads and reads, and hands the hub public data only: admitted sync IDs, and for groups it reads the steps recorded in valid `label.0` (so no first-come registration there; issues/net-role-sync.md, Replacement). Between readers a sync ID opens by issues/net-shared-set.md's offer; at a peer that cannot read, by key proof (sync key, claim, static entry), deposits by deposit key. Per-label logs become the node-wide log (issues/net-reconnect.md).
4. **One store**: ciphertext (entries, wraps, blobs, log) in the hub's store, shredding on delete (notes/serving.md, Decisions); plaintext state in the engine's. A group a node reads and serves is held once as ciphertext. The durable log replaces `Feed` (no replay after a restart; issues/net-reconnect.md).
5. **Keep the boundary**: the code serving data a node cannot read cannot decrypt (`osis-host` has no engine or keys; tools/policy.py `host_blind`). With one path it serves readable data too, so the boundary is the crate: node sync stays the only reader, the hub keeps no secrets and the policy check carries over to the renamed crate.
6. **Consent**: who may store data a node cannot read on it: by default only the user's own nodes, which serve the user's groups with no setup; anyone else's is opt-in (decided), as `host.0^` admission written by them. Wider later.
7. **Peers that cannot read** are listed in group data by key plus hints (decided; issues/account-signing.md proposes their account instead, as groups carry no per-node data). Adding one later works per group, also for someone else's group (row 26). Its own nodes that read the groups listing it keep the listings current when its key rotates.
8. **API**: `peers(g)` one list; `sync(g, peers)` adds to it; `set_serving` only limits; `SyncId` and `sync_ids` leave the public API (decided). Admission (`admitted: set<SyncId>`, `caps` by `SyncId`) becomes internal: own nodes write the sync IDs of groups that list the peer into its `host.0^`.

Also: row 24 (C to A through B never relayed: C's chain certificates) is a bug of its own, here because it is about relaying peers. `osis-proto`'s `ClientSession` (the dialing side, not an API client) and `ServingSession::port_only` get names that say so (issues/net-rename.md).

## Unsure
- (design) A box you run to store your data without reading it (Tess, direction only, easy to change): it has no keys to your data. It is its own node, with an account of its own or none, set to sync your sync IDs encrypted; your account may hold admin over its actor without sharing your data with it. No special kind of node: its admission names the sync IDs or accounts it serves. Settle the details when this job starts.
- (design) Rotating the one key: clients and listings in group data name it. Listings are rewritten by own reader nodes (step 7); clients reconnect by issues/client-auth.md's credentials, not the key.
- (design) Admission by record chain (spec/data-model.md §9 `host.0^` `own`: names the first admin for good) against admission listed by own nodes (step 8): one of them goes.
- (design) Whether node sync reaching the local store through the hub's API costs too much on hot paths (every upload, every pass); measure before step 4.
- (design) Replacement of a sync ID: issues/net-role-sync.md.

# Node sync structure for the rework
> Summary: The structural refactors in core/node/src/sync that the networking rework's jobs need, each tied to the job it unblocks: one connection record (`Conn` + `Served`), one `sources(L)` in place of five per-label peer sets, the LAN route machinery deleted with issues/net-connect.md, one retry rule for ten, local passes as the empty-source pass, one serving implementation (osis-host's `Hub`; serve.rs's `PeerStore` goes). Three low bugs in the code they replace. Part of issues/net-rework.md.
> Priority: normal
> Tags: node, sync

Each item is done inside the job named, not as a job of its own: the job's design says what the one structure holds.

## (a) One connection record
Two records describe a connection by who dialed: `Conn` (conn.rs: a dialed connection, its `labels: BTreeMap<LabelId, LConn>` with phases, passes and cursors, its `Requests`) and `Served` (serve.rs: an accepted `ServingSession`, its tier, idle times, client binding). A label open on a served connection has no `LConn`: nothing runs a pass on it, status sees it only in `peers_connected`. One record per connection, whoever dialed, holding the session, the proven actors, the shared set S with each member's state, and the pass state; the dialed/served difference is a field read by nothing but the dial logic.
Unblocks: issues/net-honest-status.md (both sides judge: a pass runs over every connection with L open); issues/net-reconnect.md (one record per peer; two connections to one peer are one record, the older closing).

## (b) One `sources(L)`
Five computations each answer "which nodes does L sync with" over different inputs, and they disagree at the edges (audit rows 13, 15-18, 36):
- `wanted_hosts` (conn.rs): the hosts to dial, from config, labels' and hints' hosts, queued deposits' hosts, then `peer_addresses` and `link_routes`;
- `wanted_labels` (conn.rs): per label, the host keys to open it at, co-readers' and link routes' keys appended;
- `drop_unwanted_peers`' set (conn.rs): `peers()` keys plus `link_routes()`, closing every peer connection outside it;
- `group_peers` (status.rs): a group's hosts, co-readers and link routes, for the API;
- `Synced.actors` (mod.rs): per label its actor and hosts, `peer://` left out, read by `complete_pass` and `passed_since` (deliver.rs).
Not one of them: the sources a complete pass waits for (`peer_received`) are proven identities kept across disconnects (spec/permissions.md §3, notes/peers.md Complete passes), not connections up.
One function: `sources(L)` = the connections up now with L open (issues/net-honest-status.md Design), the set issues/net-shared-set.md produces. Whom to dial is a separate question with a separate answer (issues/net-connect.md: everyone on the LAN, known addresses, own nodes), never a filter on what may open or on what a pass judges.
Unblocks: issues/net-honest-status.md step 1 (states and waits read `sources`); issues/net-shared-set.md (an open is a member of S on a connection, nothing else).

## (c) Delete the LAN route machinery with issues/net-connect.md
`LanRoute` with `good`, `candidate`, `failed`, `cut`, `changed`, `bound`, `window`, `heard`; `LanTags` and the per-window tag cache; `lan_seen`, `lan_up`, `lan_probe`, `lan_switched`, `lan_cut`, `lan_failed`, `peer_addresses` (peers.rs); `LAN_HEARD`, `LAN_BOUND`, `LAN_CHANGE_MS`, `LAN_FRESH_MS`, `LAN_WINDOW_MS`; the lan secret in `reach.0` and osis-crypto's `seal_lan_sig`/`open_lan_sig` with its vector. All of it exists to match an announcement to a co-reader known from `reach.0` and to switch a running connection to the proven route. issues/net-connect.md connects to every announcer with nothing to match and prefers the LAN by the peer record (issues/net-reconnect.md). Not touched before that job: the pieces hold each other up (a route is dialed only by `wanted_hosts`, a switch only through `lost`), and a partial removal leaves the LAN dead in the meantime.
Unblocks: issues/net-connect.md.

## (d) One retry rule
Ten rules decide when something is tried again:
1. a host redialed after `retry_ms` (conn.rs `lost`);
2. a co-reader after `peer_retry_ms`;
3. a co-reader whose connection was up redialed at once, once per `peer_retry_ms` (`redialed`);
4. a link's sharer being redeemed redialed after a host's pause, not a co-reader's;
5. a LAN address that failed backed off per address, the next route dialed at once (`lan_failed`);
6. a waiting LAN candidate skipping the peer's pause once per pause (`lan_cut`);
7. a label registration refused for now: `backoff(retry_ms, resync_ms, refusals)` doubling (open.rs `step_retry`);
8. an open refused: `Phase::Refused { retry_at }` with the same back-off (open.rs);
9. `MAX_REOPENS` (3) reopens of a label on one connection, then the retry timer (open.rs);
10. a refused deposit: `retry_ms` doubling to `DEPOSIT_RETRY_CAP_MS` (local.rs), and `MAX_INBOX_RESENDS` per `INBOX_LIFETIME`.
Under the rework an open is never retried: it is judged, and re-judged on any change to what the node holds (issues/net-shared-set.md Opens), so 7-9 have no event to wait for. A refused deposit is an Offer item sent again on the next change or connection (issues/net-shared-set.md Deposits). What remains is one dial rule: a node not connected is dialed again after one pause, the pause reset by any change this node knows of (a new sync ID, a new delivery, an announcement heard), at most once per pause per node (issues/net-connect.md Keeping; the number passes notes/arbitrary-values.md as a performance switch: 0 dials in a loop, infinity never redials).
Unblocks: issues/net-connect.md (dialing), issues/net-shared-set.md (opens), issues/net-reconnect.md (Lost and Offers retried by connection, not by timer).

## (e) Local passes as the empty-source case
A label with no non-`peer://` host gets a **local pass** (`local_passes`, pass/mod.rs; notes/peers.md): the pass logic run with `conn = None` against the node's own entries, so a sharer with no host still promotes deposits, places certificates and deletes locally. It is the same pass with `sources(L) = {}`: nothing upstream holds what the node lacks, so it judges over what it holds. With (b), a pass runs over `sources(L)`, and the empty set is one case of it, not a second entry point. The pass reads the one store (issues/net-one-peer.md step 4) and judges each source by its `known`; built in issues/net-one-peer.md 3h2.
Unblocks: issues/net-one-peer.md step 3.

## (f) One serving implementation
Two serve the node-to-node protocol: osis-host's `Hub` (core/host/src/hub.rs: `ServingSession`s and `Replicator`s over `HostStore`, a durable log) and node sync's `serve.rs` (`ServingSession` over `PeerStore`, a `LabelStore` over the engine's entries and blobs, with no per-label log: readers pull its durable node log as one stream (notes/peers.md, The stream); co-reader proofs by `reach_nodes`; per-peer byte charges; `MAX_PEER_STEPS` registered steps in memory). The `Hub` stays, over the node-wide durable log (issues/net-reconnect.md); `PeerStore` and the `Replicator` go (replication is sync with a peer). tools/policy.py's `host_blind` keeps the serving crate without keys (issues/net-one-peer.md step 5).
Unblocks: issues/net-one-peer.md steps 3-4; issues/net-reconnect.md (the durable log is the hub's).

## Bugs in the code these replace (low; fixed by the item named, not before)
- **Replay protection pruned with the route** (peers.rs `peer_addresses`): `self.lan.retain(...)` drops a peer's `LanRoute` once it has no fresh `good` or `candidate`, no `failed` address and no recent `cut`. `bound` and `window`, the binding of each verified announcement to its first source, go with it, so an announcement of the newest window replayed from another source after the prune verifies again and becomes a candidate: one dial to a spoofed source, the leak the binding exists to stop (notes/peers.md LAN). Goes with (c).
- **A LAN switch spends the quick redial** (peers.rs `lan_switched`): the old route is closed through `lost` (conn.rs), which for an up co-reader connection takes the once-per-`peer_retry_ms` immediate redial (`redialed[host] = now`) before `lan_switched` removes the retry entry. A real loss of the LAN connection within the pause then waits the whole pause. Goes with (c), (d).
- **A peer counted per connection** (status.rs `label_status`): `sources` counts `Conn`s plus sessions beyond the co-readers dialed, so a co-reader whose LAN route is dialed beside its relayed connection (`lan_probe`) counts twice while both are up. Goes with (a).

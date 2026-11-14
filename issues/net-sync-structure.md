# Node sync structure for the rework
> Summary: Structural refactors in core/node/src/sync that the open networking jobs need, each done inside the job named: one rule for a source over every connection (with issues/sync-rewrite.md 6c), one answer to "which nodes does L sync with" in place of four, the LAN route machinery deleted with issues/net-connect.md, one retry rule in place of six, osis-host's `Hub` over the node-wide log. Two low bugs in the code they replace. Part of issues/sync-rewrite.md.
> Priority: normal
> Tags: node, sync

Each item is done inside the job named, not as a job of its own: the job's design says what the one structure holds.

## (a) One connection record
Built: one `Conn` per connection, whoever dialed (conn.rs), its peer kept by `Conn::peer`. Left: a source is a connection where L is served as a store (a `LabelAt`: a node a label names that this node dialed, or a dialer that proved L's sync secret); one rule (a pass over every connection with L open, by the credential's class) comes with issues/sync-rewrite.md 6c.

## (b) One `sources(L)`
Status reads the sources (`SyncEngine::label_status`). Four other computations each answer "which nodes does L sync with" over different inputs, and they disagree at the edges (audit rows 13, 15-18, 36):
- `wanted_nodes` (conn.rs): the nodes to dial, from config, labels' and hints' hosts, queued deposits' hosts, then `peer_addresses` and `link_routes` (also what `drop_unwanted` keeps);
- `wanted_labels` (conn.rs): per label, the host keys to open it at, co-readers' and link routes' keys appended;
- `group_peers` (status.rs): a group's hosts, co-readers and link routes, for the API;
- `Synced.actors` (mod.rs): per label its actor and hosts, `peer://` left out, read by `complete_pass` and `passed_since` (deliver.rs).
Not one of them: the sources a complete pass waits for (`peer_received`) are proven identities kept across disconnects (spec/permissions.md §3, notes/peers.md Complete passes), not connections up.
One function: `sources(L)` = the connections up now with L open (notes/api.md, Sync configuration and status), the set issues/net-shared-set.md produces; the four go. Whom to dial is a separate question with a separate answer (issues/net-connect.md: everyone on the LAN, known addresses, own nodes), never a filter on what may open or on what a pass judges.
Unblocks: issues/sync-rewrite.md (an open is a member of S on a connection, nothing else).

## (c) Delete the LAN route machinery with issues/net-connect.md
`LanRoute` with `good`, `candidate`, `failed`, `cut`, `changed`, `bound`, `window`, `heard`; `LanTags` and the per-window tag cache; `lan_seen`, `lan_up`, `lan_probe`, `lan_switched`, `lan_cut`, `lan_failed`, `peer_addresses` (peers.rs); `LAN_HEARD`, `LAN_BOUND`, `LAN_CHANGE_MS`, `LAN_FRESH_MS`, `LAN_WINDOW_MS`; the lan secret in `reach.0` and osis-crypto's `seal_lan_sig`/`open_lan_sig` with its vector. All of it exists to match an announcement to a co-reader known from `reach.0` and to switch a running connection to the proven route. issues/net-connect.md connects to every announcer with nothing to match and prefers the LAN by the peer record (issues/net-reconnect.md). Not touched before that job: the pieces hold each other up (a route is dialed only by `wanted_nodes`, a switch only through `lost`), and a partial removal leaves the LAN dead in the meantime.
Unblocks: issues/net-connect.md.

## (d) One retry rule
Six rules decide when something is tried again:
1. a node dialed (conn.rs `lost`): a relayed connection that was up at once, once per `peer_retry_ms` (`redialed`); another that was up after `retry_ms`; a failed dial's pause doubling from `retry_ms` to `peer_retry_ms`;
2. a LAN address that failed backed off per address, the next route dialed at once (`lan_failed`);
3. a waiting LAN candidate skipping the peer's pause once per pause (`lan_cut`);
4. a label registration refused for now: `backoff(retry_ms, resync_ms, refusals)` doubling (open.rs `step_retry`);
5. an open refused: `Phase::Refused { retry_at }` with the same back-off (open.rs);
6. a refused deposit: `retry_ms` doubling to `DEPOSIT_RETRY_CAP_MS` (local.rs), and `MAX_INBOX_RESENDS` per `INBOX_LIFETIME`.
Under the rework an open is never retried: it is judged, and re-judged on any change to what the node holds (issues/net-shared-set.md Opens), so 4-5 have no event to wait for. A refused deposit is an Offer item sent again on the next change or connection (issues/net-shared-set.md Deposits). What remains is one dial rule: a node not connected is dialed again after one pause, the pause reset by any change this node knows of (a new sync ID, a new delivery, an announcement heard), at most once per pause per node (issues/net-connect.md Keeping; the number passes notes/arbitrary-values.md as a performance switch: 0 dials in a loop, infinity never redials).
Unblocks: issues/net-connect.md (dialing), issues/sync-rewrite.md (opens).

## (f) One serving implementation
Built: every served connection is a session of osis-host's `Hub`, node sync above it. Left: the `Hub` over the node-wide durable log (issues/net-reconnect.md). tools/policy.py's `host_blind` keeps the serving crate without keys (issues/sync-rewrite.md step 5).
Unblocks: issues/sync-rewrite.md.

## Bugs in the code these replace (low; fixed by the item named, not before)
- **Replay protection pruned with the route** (peers.rs `peer_addresses`): `self.lan.retain(...)` drops a peer's `LanRoute` once it has no fresh `good` or `candidate`, no `failed` address and no recent `cut`. `bound` and `window`, the binding of each verified announcement to its first source, go with it, so an announcement of the newest window replayed from another source after the prune verifies again and becomes a candidate: one dial to a spoofed source, the leak the binding exists to stop (notes/peers.md LAN). Goes with (c).
- **A LAN switch spends the quick redial** (peers.rs `lan_switched`): the old route is closed through `lost` (conn.rs), which for an up co-reader connection takes the once-per-`peer_retry_ms` immediate redial (`redialed[host] = now`) before `lan_switched` removes the retry entry. A real loss of the LAN connection within the pause then waits the whole pause. Goes with (c), (d).

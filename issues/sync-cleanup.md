# Sync module cleanup left over
> Summary: Simplifications of osis-node `sync/` found in the sync-simplify review and not done: per-connection bookkeeping kept in engine-wide maps, `labels()` as a query with side effects, pass functions with long argument lists, magic request kinds, uneven fetch paths, hand-rolled owner-chain walks.
> Tags: node, sync

No failing test; behaviour-preserving refactors.

- **Per-connection state outside `Conn`**: `sent`, `deleting`, `timed_sent`, `missing`, `reopens` (keyed by `ConnId`) and `fetching` (valued by it) live on `SyncEngine`, and `lost()` has to purge each by hand (a session closed by the client used to keep its fetches). Moving them onto `Conn` makes dropping the `Conn` the cleanup. `SyncEngine` has about 70 flat fields and a 75-line initializer; the peer caches (`peers_cache`, `reach_index`, `lan_tags`, `peers_key`) and the charge fields (`charges*`) could each be one struct.
- **`labels()` mutates**: it retires replaced labels and rewrites `label_actors` while answering a query, and it is called many times per step (`wanted_servers`, `wanted_labels`, `local_passes`, `link_routes`, `peers`, `check_reach`, `queue_inbox`, and `placed_now` once per uncached commit). One computation per step, with retirement a separate step, would make it cheap and side-effect free.
- **Pass signatures**: eight `#[allow(clippy::too_many_arguments)]` in `pass.rs` (`deletions`, `deletable`, `judge`, `body_sends`, `local_deletions`, `snapshot_carries`, ...) thread the same (server, g, l, keys, snaps, settled) through; a per-pass context struct would carry them. `judge_label` still does send ordering, deposit queueing and promotion inline (about 150 lines).
- **Request kinds**: `open.rs` `refused` matches wire message kinds as numbers (4, 7, 8, 10, 12, 14, 15, 17); osis-proto should name them.
- **Fetch paths differ**: `fetch_on` skips blobs in flight and those the connection's server did not deliver; the app's `fetch` records nothing in `fetching`, and `log_events`' fetch of announced commit blobs skips in-flight ones but not `missing`.
- **Owner-chain walks**: `reseal`, `deliver_inbox`, `inbox_owner`, `membership_moved`, `contacts_only` each walk owners by hand with different caps (16, 64, `MAX_OWNER_DEPTH`); an engine iterator over the owner chain would do.
- `held_parts` (pass.rs) and `held_at` (deliver.rs) answer near-identical questions (parts of a commit held under a label, present somewhere) with different rules for certificate copies and genuineness.

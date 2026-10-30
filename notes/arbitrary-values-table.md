# Arbitrary values: audit table
> Summary: Every picked number in core/, cli/ and spec/ with its class (notes/arbitrary-values.md) and what 0 and infinity do; the owner-agreed tradeoffs awaiting sign-off first. Future audits diff against this table.

Classes: **P** performance switch between correct strategies (or a cache/batch size: only speed changes); **R** resource bound with a defined safe outcome past it; **M** minor consequence; **O** owner-agreed tradeoff (protocol constant, spec); **X** not acceptable (only makes a bug unlikely), with the issue or fix. Left out: structural constants (CBOR tags, enum discriminants, byte lengths fixed by an algorithm, versions, table ids, `MAX_CHAIN = MAX_OWNER_DEPTH + 1` and other values derived from listed ones), unit-test fixtures, kit/ and app/.

## For owner sign-off
Values no choice makes free; each is in the spec or should be. Listed with what it trades.

| value | trades | where |
|---|---|---|
| `MAX_DRIFT` 1 h | clock skew tolerated vs how far a commit's `ts` may lie ahead (and every bound measured from it) | wire §2 |
| `MAX_LEASE` 20 min, `KEEPALIVE` 15 min | presence staleness after a crash vs presence traffic (spec says owner-agreed already) | wire §2 |
| `MEMBERSHIP_KEEP` 90 days | how long an offline device can return and sync cleanly vs membership history kept | wire §2 |
| `AT_MOST_GRACE` 1 h | skew slack on keep-at-most vs bodies kept past their bound | wire §2 |
| `INBOX_LIFETIME` 90 days | how long an offline recipient's grant waits at the server vs server storage of undelivered blobs | wire §2 |
| `HEARTBEAT_MIN/MAX_LIFETIME` 1/14 days, `HEARTBEAT_MIN_INTERVAL` 6 h | how fast a silent member is noticed vs heartbeat traffic | wire §2 |
| `TOMBSTONE_LIFETIME` 30 days (recommended) | a holder offline longer re-uploads a deleted entry (re-deleted by the next writer that judges it) vs tombstone storage | wire §2, sync §4 |
| `MAX_CLAIMS` 65 536 | most claim keys per step: caps the members of a label that can catch up by claim at one step vs claim-set size | wire §2 |
| LAN tag window 10 min | discovery stability vs trackability of the tag | sync §10 |
| `PLACE_WAIT` 5 min (recommended) | placement order kept vs projections (grants, copies) held behind an unreachable label server | sync §5 |
| `MAX_INBOX_RESENDS` 3 (node policy; spec: MAY bound) | a recipient silent for 3 × 90 days is given up vs re-sends forever | `sync/local.rs` |
| `INBOX_COPY_MIN_LEFT` = `INBOX_LIFETIME` / 2 (spec sync §3) | at 0 a stranger with the deposit seed recycles the deposit budget by short expiries and gets grants copied without bound; at `INBOX_LIFETIME` nobody copies. Past it a device opening a late blob applies the grant without copying: if no device copied it earlier, the actor's later devices never find it (applying counts as acting, so no re-send). Owner sign-off pending | `sync/pass.rs` |
| `MAX_LIST_BYTES` 8 MiB, `MAX_READ` 1 GiB (node policy) | a commit whose header lists exceed 8 MiB is not applied here (`TooLarge`, Local) although spec/requirements.md says a change has no size limit; large values beyond 1 GiB stream only | `commit/lists.rs`, `engine/large.rs` |
| schema limits `MAX_EXPAND` 64, `MAX_TYPE_DEPTH` 256, `MAX_INSTANCES` 10 000, `MAX_CHECK_WORK` 100 000, `MAX_NEST` 64 | decide whether a schema is valid but are not in the spec: another implementation could accept what osis refuses | `schema/` |

## Not acceptable
| value | where | problem | status |
|---|---|---|---|
| `reopen_all` 8 sweeps | `engine/flows/mod.rs` | taking up a key actor opened at most 8 levels of a member-actor chain (a 12-chain left 4 unread) | fixed: fixpoint, each learner's dependents reopened at once (one sweep opens a chain in any tid order); test `keys::key_actor_opens_deep_member_chain_spec_crypto_4` |
| `reopen_dependents` 4096 steps | `engine/flows/mod.rs` | the reopen fixpoint stopped silently; it terminates anyway: an actor is pushed only when its held epochs grew (epochs and secrets are only added, `set_secret` only when absent), so pushes are bounded by the secrets the held `/secrets` states carry, which writers paid for | fixed: cap removed (no test: needs > 4096 steps) |
| rotation `MAX_DEPTH` 8 | `engine/rotation/mod.rs` | departures more than 8 member actors deep are never rotated (security) | fixed: no cap; departures one per covers class (fixpoint over the member graph, polynomial), cascade iterative, each actor once; tests `rotation::tests::removal_twelve_deep_rotates_every_level_spec_crypto_4`, `wide_lattice_departures_bounded`, differential `walk_matches_path_walk` |
| `HINT_INDEXES` 4 | `node/sync/open.rs` | a label of index 4 or more cannot be opened from a hint (inbox, link) | fixed: inbox things carry the label index (spec/wire.md §9), links and cards name index 0; test `inbox_retry::hint_opens_a_label_replaced_many_times_spec_wire_9` |
| `MAX_INBOX_TRIES` 8 | `node/sync/local.rs`, `inbound.rs` | a deposit refused for about 21 min (budget full while the recipient is offline) is dropped; resent only after `INBOX_LIFETIME` | fixed: retried at the capped back-off until taken or moot (delivery forgotten or re-sealed, label replaced); test `inbox_retry::inbox_deposit_retried_for_hours_spec_sync_5` |
| `MAX_QUEUED` 64 MiB, server `max_queued_bytes` 32 MiB, `REQUEST_TIMEOUT_MS` 2 min | `node/sync/driver.rs`, `server/`, `proto/client.rs` | no send window: a large upload or fetch on a slow link closes the connection, the redial repeats it | fixed: request window `WINDOW` (spec/sync.md §6 Flow control) keeps both queues under `WINDOW_QUEUE`; `STALL_TIMEOUT_MS` from the last progress; pushes wait while the connection's unwritten bytes leave no room for one (`ServerInput::Taken`), so a subscriber's queue stays under `SEND_QUEUE`; tests `slow_link::*` |
| `HANDSHAKE_TIMEOUT` 5 s (quic), 10 s (iroh) | `transport/quic.rs`, `iroh.rs` | a link that cannot finish a handshake in 5-10 s never connects | fixed: no deadline; QUIC's idle timeout ends a silent handshake, a listener drops its oldest handshake past `MAX_INCOMING` (`Handshakes`); test `quic::tests::handshakes_evict_oldest` |
| `CLOSE_WAIT` 5 s | `osis/handle.rs` | `close` returns Ok with the database still held when a callback or engine call outlasts it | fixed: no cap; user handles counted, `close` fails `StillOpen` while others exist, else waits for the callback, engine call or timer to end (and for the driver task on the app's multi-thread runtime); test `api::close_waits_or_names_holders_spec_api_handle` |

## Table
0 / ∞: what the value at 0 and at infinity would do.

### Spec format and protocol constants (`base/format.rs`, spec/wire.md §2, §11, §13)
| value | class | 0 / ∞ |
|---|---|---|
| `MAX_BLOB` 8 MiB | R | nothing fits / unbounded per-blob memory; larger values chunk |
| `CHUNK_THRESHOLD` 128 KiB, `PAGE_TARGET` 64 KiB | P (fixed by format: dedup) | everything chunked/paged / nothing |
| `CHUNK_MIN` 16 KiB, `CHUNK_MAX` 256 KiB, `CHUNK_MASK_BITS` 16 | P (format) | tiny chunks / one chunk |
| `TREE_FANOUT` 512 | P (format) | no tree / one node |
| `TREE_MAX_LEVEL` 48 | R (never binding: 512^48) | no trees / unbounded recursion on hostile input |
| `MAX_DELTA_BARE` 2^18 | R | no bare runs / a small delta creates unbounded records |
| `MAX_RELAY_BLOB` 64 KiB | R | no relay-only blobs / relays as big as blobs |
| `MAX_DRIFT`, `MAX_LEASE`, `KEEPALIVE`, `MEMBERSHIP_KEEP`, `AT_MOST_GRACE`, `INBOX_LIFETIME`, `HEARTBEAT_*`, `TOMBSTONE_LIFETIME`, `MAX_CLAIMS`, LAN window | O | sign-off list |
| `RESOLUTION_HOPS` 8 | M | no resolution / cycles (guarded); past it a tid reads as an intermediate copy |
| `MAX_OWNER_DEPTH` 64 | R | only key actors / unbounded chain walks; deeper is invalid everywhere alike |
| `MAX_LINKED_FRONTIERS` 64 MiB | R | no linked frontiers / unbounded snapshot work |
| `MAX_VALUE_DEPTH` 64, `MAX_OBJECT_DEPTH` 512, `MAX_AK_BYTES` 1024, `MAX_URL_BYTES` 256, `MAX_SCHEMAS` 256, `MAX_RUN` 2^16, `MAX_STEP_BYTES` | R (decoder limits, refuse) | nothing decodes / stack and memory on hostile input |
| `MAX_MESSAGE` 9 MiB, `REPLY_BUDGET`/`MAX_CLAIM_SET` = it − 64 KiB | R (headroom derived) | no messages / unbounded frame buffers |
| per-message caps (`MAX_ITEMS` 1024, `MAX_GAINED` 4096, `MAX_LABELS` 1024, reconcile ranges 256/4096, `MAX_PATH_STEPS` 1024, `MAX_OPEN_LABELS` 4096) | R | nothing per message / unbounded per-message work |
| `MAX_HELLO_VERSIONS` 16, `MAX_HELLO_BYTES` 256 | R | no handshake / unbounded first frame |
| rbsr `LIST_MAX` 32, `DIFF_MAX` 1024, `SPLIT` 16, `DENSE_LIST` 8 | P (spec: either mode valid) | more rounds / bigger messages |
| deposit budget `64 + 4 × claims` entries × 32 KiB (`DEPOSIT_ENTRY_BYTES`, `ENTRY_UNIT`) | R (server policy) | no deposits / unbounded junk deposits |
| `PLACE_WAIT_MS` 5 min | M (spec local policy; sign-off) | no ordering / projections held forever behind a down server |

### Clock and session (`proto/client.rs`, `hello.rs`)
| value | class | 0 / ∞ |
|---|---|---|
| `INITIAL_PINGS` 3, `MIN_PONGS` 3, `MAX_SAMPLES` 9 | M | no offset / slow start, memory |
| `PING_INTERVAL_MS` 5 min | M | ping storm / offset never refreshed |
| `OFFSET_DIAGNOSTIC_MS` 5 s | M (diagnostic only) | always reported / never |
| `MAX_SAMPLE_RTT_MS` 10 s | M (spec: ignore long round trips) | no samples / suspend-length errors |
| `STALL_TIMEOUT_MS` 2 min | M (liveness: nothing moved either way while requests are in flight) | every session closes / a hung peer holds it; a link moving under one `WRITE_CHUNK` per timeout counts as stalled |
| `WINDOW` 16 MiB (spec), `SMALL_REPLY` 64 KiB | R/P (per-peer buffer vs throughput, `WINDOW` per round trip; one request always goes) | one request at a time / queues overflow the caps |
| `MAX_RECONCILE_MESSAGES` 4096, `MAX_RECONCILE_IDS` 2^21, `MAX_RECONCILE_QUEUED` 2^17 | R (abandon as peer error) | no reconciliation / a splitting responder holds us forever |
| `MAX_EMPTY_PAGES` 16 | R | first empty page fails / a cursor-only peer loops forever |

### Server (`proto/server.rs`, `relay.rs`, `server/`)
| value | class | 0 / ∞ |
|---|---|---|
| `LOG_BATCH` 256, replicate `BATCH_RECORDS` 256, `BATCH_BYTES` 4 MiB, `MAX_STEPS` 64, hub `SWEEP_BUDGET` 1024 | P | no progress per call / unbounded call latency |
| `OLDER_KEYS` 8 | M | every stale key REFUSED / unbounded signature checks per refused item; past it a writer 8+ rotations behind gets REFUSED, not the head; the entry stays unsent and goes again at the next pass, under the head the connection learned by open (a stale sync key opens to its child and walks) or by registration pushes (checked) |
| `MAX_CACHED` 64 | P | head keys only: reload per message (two store reads, up to 33 key parses) / memory (about 7 KB each per connection, any label a peer names; 4096 was up to 30 MB per connection) |
| `MAX_CROSSED` 2^14, `MAX_ORIGINS` 2^20 | P (optimizations, cleared past the cap) | blobs inlined back, entries replicated back to their origin (refused there as held) / memory |
| `PRESENCE_PRUNE` 1024, `SEQ_BLOCK` 1024 | P (commented in code) | |
| `ENTRY_OVERHEAD` 896, `TOMB_OVERHEAD` 160, `REC_OVERHEAD` 96 | measured, tested (`overheads_cover_the_structures`) | |
| `EPH_LOG_KEEP` 2^16 | R (commented) | every cursor replays / log bounded by the cap only |
| `EPH_TOMBSTONE_MS` = `MAX_DRIFT` | M (commented) | |
| `MAX_RELAY_SEEN` 2^16 | M (commented) | |
| `RelayLimits` 6000 / 32 MiB per 60 s | R (rate, code 4) | no relays / relay floods |
| `Policy` defaults: caps per label (2^20 entries, 16 GiB), totals (2^20 labels, 2^26 entries, 256 GiB), rates per 60 s (deletes, replacements 20 000, deposits 600, `entry_replacements` 4), ephemeral 16 MiB/label, 1 GiB total, presence 4 MiB, `log_keep` 2^20, `max_connections` 10 000, `hello_ms` 10 s, `max_buffered_bytes` 512 MiB | R (operator config; refuse with a code or close) | |
| `max_queued_bytes` 48 MiB (at least `SEND_QUEUE` = `WINDOW_QUEUE` + `PUSH_QUEUE`, config refuses less) | R (a peer that does not read) | sessions keeping the window closed / unbounded buffer |
| `PUSH_POLL_MS` 1 s | M (held pushes resume up to this late after the queue drains) | the driver spins while a slow subscriber drains / pushes wait for an unrelated tick |
| `MAX_PATH` 2^20 | R (corrupt-store guard) | |
| replicate `RETRY_MIN/MAX_MS` 1-60 s, driver `BACKOFF_MIN/MAX` 1-60 s, `SWEEP_BACKOFF_MS` 1 s, `MAX_IDLE` 60 s, `FINISH_WAIT` 10 s | M | busy loop / never retries |

### Transport (`transport/`)
| value | class | 0 / ∞ |
|---|---|---|
| `KEEP_ALIVE` 15 s, `IDLE_TIMEOUT` 60 s | M (also ends a silent handshake) | keep-alive storm / dead connections and handshakes linger |
| `STREAM_WINDOW` 1 MiB, `CONN_WINDOW` 4 MiB | R/P (buffer per peer vs throughput on long fat links) | stall / unbounded buffering |
| `MAX_STREAMS` 16, `MAX_INCOMING` 1024 (handshakes in progress; past it the oldest goes) | R | |
| link `READ_CHUNK` 64 KiB, `READ_AHEAD` 16 | P | |
| manage `Backoff` 0.5-60 s | M | |

### Node sync (`node/sync/`)
| value | class | 0 / ∞ |
|---|---|---|
| `MAX_INBOX_RESENDS` 3 | O (sign-off) | |
| `DEPOSIT_RETRY_CAP_MS` 1 h | M | resent every tick / lands that much later once the refusal clears |
| `MAX_REOPENS` 3 | M (then the retry timer) | |
| `MAX_ROUNDS` 16 | M (the rest opens at the next pass: `refetch`) | |
| `MAX_NOTIFY` 8 | M (the rest goes at the next `handle`) | |
| `PENDING_SHARE` 4, `RELAYS_REMEMBERED` 2^16 | R (commented) | |
| `MAX_PEER_STEPS` 64, `LAN_HEARD` 4, `LAN_CHANGE_MS` 5 s | R | |
| `LOG_KEEP` 4096 | M (a cursor below replays) | |
| `MAX_QUEUED` 64 MiB (at least `SEND_QUEUE`, asserted) | R (a peer that does not read) | sessions keeping the window closed / unbounded buffer |
| link `WRITE_CHUNK` 16 KiB | M (grain of send progress for the stall timeout) | no progress shown / a link under a chunk per stall timeout counts as stalled |
| `SERVE_IDLE` / `serve_idle_ms` 120 s, `serve_open_ms` 30 s, `max_served` 64 | R | |
| `MAX_IDLE` 60 s, `MIN_WAKE_MS` 1 s, `FINISH_WAIT` 10 s, `RELISTEN_RETRY` 5 s | M | |
| `RESEND_MS` 30 s | M (retry pacing after an answer that did not settle the entry; never while its request is unanswered, `ClientSession::answered`) | retry every pass / no retry on this connection |
| `LAN_CHECK` 5 s, `LAN_ANNOUNCE` 30 s, `LAN_REJOIN_MIN` 30 s (provisional) | M | |
| `LAN_FRESH_MS` 2 windows, `PEERS_TTL_MS` 60 s | M (dialing only; opens check access) | |
| `SETTLE_MS` 30 s, `RELAY_MIN_MS` 5 s | M (co-writers both upload: duplicate work, idempotent) | |
| `RELINK_BACKOFF_MS` 1 h - 7 days | R (a server deleting fresh chunks) | |
| `SyncConfig` defaults: `resync_ms` 60 s, `retry_ms` 5 s, `peer_retry_ms` 60 s, `tight_budget` 16, `peer_pass_wait_ms` 5 min, `heartbeat_lifetime_ms` 2 days | M | |
| `SyncConfig` defaults: `max_peers_per_label` 8, `max_peers` 64, `peer_bytes` 64 MiB, `peer_total_bytes` 1 GiB, `unvouched_cap` 2^16, `ephemeral_bytes` 16 MiB | R | |
| diagnostics kept 256 | M | |

### Engine, keys, perm, crdt, store, schema, API
| value | class | 0 / ∞ |
|---|---|---|
| `reopen_all` sweeps, `reopen_dependents` steps | was X | fixed (no cap) |
| rotation `MAX_DEPTH` 8 | was X | fixed (no cap) |
| `MAX_READING` 256, `MAX_READING_PER_AUTHOR` 64, `MAX_READING_ACTORS` 64 | R (tested, keys `boxes.rs`; counts epochs known only from pending commits; a genuine one past it waits for its checked box) | |
| `PENDING_GRANT_WAIT_MS` 1 day (engine rotation) | M: past it a plausible granter's pending grant no longer keeps a node that lost access holding the actor; the node re-learns from the grant's boxes when it applies and re-fetches content. 0: every such grant waits that way; infinity: a grant that never applies keeps lost secrets for good | `rotation/mod.rs` |
| `MAX_HINT_COMMITS` 64 | R (lowest commit ID evicted, not oldest; inbox spam can evict a genuine hint) | the grantee then writes once the thing's `/keys` syncs, as after a restart (candidates are not persisted): a delay (checked) |
| `UNDO_DEPTH` 16 | M | no undo / memory |
| `ROSTER_SNAPSHOT_AFTER` 64, `WALK_CACHE_MIN` 64, `MAX_WAIT_BYTES` 64 KiB / 16 MiB, `COPY_CACHE_MAX` 2^20 | P | |
| pages `PAGE_BYTES` 8 KiB, `SEQ_PAGE_BYTES` 3 KiB, `MIN_PAGED` 64, `GROUP` 32, `PREFETCH` 8, `OP_RUNS` 8, prefetch budget `max(1024)`, `SCAN_PAGE` 256, pending page 256 | P | |
| pages run expansion `1 << 20` | R (corrupt local row) | |
| `MAX_REUSE` 16 GiB | P | |
| `MAX_LIST_BYTES` 8 MiB, `MAX_READ` 1 GiB | R (sign-off) | |
| `ENTRY_CHARGE` 1024, `COVER_FACTOR` 2, `MAX_DELIVERED` 2^16, `DEFAULT_EPHEMERAL_HISTORY` 16 MiB | P/R (commented) | |
| events `PER_PEER` 64 per `WINDOW_MS` 60 s, `DEDUP` 1024 | M (diagnostics) | |
| `GRANULARITY_MS` 60 s | M | |
| perm `CHECKPOINT` 32, `FORWARD_MAX` 4, `SHADOW_SHARE` 8 (512), debug `check_scratch` above 400 | P | |
| crdt `BLOCK` 256, `STEP` 8, `SIBS` 256, `isqrt().max(64)`, work `max(1024)`, `LIN_MIN` 64, `MAX_D` 512, `CTX` 32 | P | |
| store `arity` 256, `depth` 5 | R: 2^40 unit slots, never reused; exhaustion refuses writes for good, after about 35 years at 1000 unit writes/s | |
| store `page_max` 8 KiB, `spill_bytes` 16 MiB, `node_cache` 4096, `unit_cache_bytes` 16 MiB | P | |
| schema `MAX_EXPAND`, `MAX_TYPE_DEPTH`, `MAX_INSTANCES`, `MAX_CHECK_WORK`, `MAX_NEST`, `MAX_CHECK_DEPTH` | R (refuse; sign-off: not specced) | |
| osis `DEFAULT_LIMIT` 64 MiB | R (error past it) | |
| osis `DEFAULT_WAIT` 60 s, `PRESYNC_WAIT` 30 s, cli `DEFAULT_WAIT` 30 s | M (the caller gets an error) | |
| osis `DEFAULT_IDLE_COMMIT` 2 s | M (a crash loses at most that much typing) | |
| osis `STOP_WAIT` 5 s | M (the database is already durable) | |
| osis `OFFER_LIFETIME_MS` 10 min | M | |

### Test oracles (`core/test/`)
| value | class | note |
|---|---|---|
| sim `STATE_FACTOR` 2 etc. | M (calibrated detection bound, notes/testing.md) | growth below the bound goes unseen |
| sim `IDLE_ROUNDS` 3 | M | ping-pong with a longer period goes unseen |
| sim `STORM` 5000, `ROGUE_STORM` 100 000, `SLOW_MS` 30 s | M | |

## Counts
Table rows (a row may group several related values): P 17, R 33, M 33, O 2 rows covering the 13 sign-off items, X 7 rows (9 values: 2 fixed, 7 in 4 issues), 1 measured.

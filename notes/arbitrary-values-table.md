# Arbitrary values: audit table
> Summary: Every picked number in core/, cli/ and spec/ with its class (notes/arbitrary-values.md), what 0 and infinity do, and why this value. The project's durable record of magic numbers: every change that adds, changes or removes a picked number updates its row in the same commit. Tess's review of the tradeoff values: issues/magic-number-review.md.

Classes: **P** performance switch between correct strategies (or a cache/batch size: only speed changes); **R** resource bound with a defined safe outcome past it; **M** minor consequence; **O** Tess-agreed tradeoff (protocol constant, spec); **X** not acceptable (only makes a bug unlikely): never kept; see Caps that must not come back. Left out: structural constants (CBOR tags, enum discriminants, byte lengths fixed by an algorithm, versions, table ids, values derived from listed ones), unit-test fixtures, libs/kit/ and app/.

## Caps that must not come back
Each was a number that only made a bug unlikely (class X); the code ends by a fixpoint, a window or a count it can argue, so no number replaces them.
| was | where | what holds instead | test |
|---|---|---|---|
| `reopen_all` sweeps, `reopen_dependents` steps | `engine/flows/mod.rs` | taking up a key actor reopens to a fixpoint, each learner's dependents at once; it terminates because an actor is pushed only when its held epochs grew (epochs and secrets are only added), bounded by the secrets the held `secrets.0` states carry | `keys::key_actor_opens_deep_holder_chain_spec_crypto_4` |
| rotation `MAX_DEPTH` | `engine/rotation/mod.rs` | departures one per covers class, a fixpoint over the holder graph (polynomial), cascade iterative, each actor once: any depth rotates | `rotation::tests::removal_twelve_deep_rotates_every_level_spec_crypto_4` |
| `HINT_INDEXES` | `node/sync/open.rs` | inbox things carry the label index (spec/wire.md §9), links and cards name index 0 | `inbox_retry::hint_opens_a_label_replaced_many_times_spec_wire_9` |
| `MAX_INBOX_TRIES` | `node/sync/local.rs`, `inbound.rs` | a refused deposit is retried at the capped back-off until taken or moot (delivery forgotten or re-sealed, label replaced) | `inbox_retry::inbox_deposit_retried_for_hours_spec_sync_5` |
| queue caps and a request timeout as flow control | `node/sync/driver.rs`, `host/`, `proto/client.rs` | the request window `WINDOW` (spec/sync.md §6 Flow control) keeps both queues under `WINDOW_QUEUE`; `STALL_TIMEOUT_MS` counts from the last progress; pushes wait while the connection's unwritten bytes leave no room for one (`ServingInput::Taken`), so a subscriber's queue stays under `SEND_QUEUE` | `slow_link::*` |
| `HANDSHAKE_TIMEOUT` | `transport/quic.rs`, `p2p.rs` | no deadline; QUIC's idle timeout ends a silent handshake, a listener drops its oldest handshake past `MAX_INCOMING` | `quic::tests::handshakes_evict_oldest` |
| `CLOSE_WAIT` | `osis/handle.rs` | user handles counted: `close` fails `StillOpen` while others exist, else waits for the callback, engine call or timer to end (and the driver task on the app's multi-thread runtime) | `api::close_waits_or_names_holders_spec_api_handle` |

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
| `MAX_DELTA_BARE` 2^18 | R | no content-less runs / a small delta creates unbounded records |
| `MAX_PAGE_ITEMS` 2^21 | R (validity rule, every durable reader alike; honest worst case about 1.4 x 2^20, notes/crdt.md Page items) | every delta invalid / one blob decodes to GBs |
| `MAX_RELAY_BLOB` 64 KiB | R | no relay-only blobs / relays as big as blobs |
| `MAX_DRIFT`, `ROLE_KEEP`, `INBOX_LIFETIME`, `HEARTBEAT_*`, `TOMBSTONE_LIFETIME`, `MAX_CLAIMS`, LAN window | O | sign-off list |
| `MAX_HEARTBEAT_SUSPECTS` 32 | R | no repair at all / a heartbeat as long as the label's flagged aspects (a deposit, budgeted); past it the newest flags are reported and the rest wait for those to clear (repair a few intervals late, nothing lost: flags stay until repaired) |
| `MAX_REQUIRED_ENTRIES` 64 | R | no setting can say anything / `MAX_VALUE_BYTES` of AKs in every node's memory per `required^.0` delta; past it the delta requires nothing, a writer refuses it |
| `LIST_TREE_DEPTH` 32 (format) | R | levels of a rotation's list tree: a rotator listing more than 2^32 things refuses the rotation (0: one thing per rotation, infinity: unbounded paths); fixed at the largest useful size so a path (1 KiB) shows nothing of how many things a rotator lists, where padding to the actual depth shows its log |
| `MAX_CHAIN_DEPTH` 64 | R | only key actors / unbounded chain walks; deeper is invalid everywhere alike |
| `MAX_VALUE_DEPTH` 64, `MAX_OBJECT_DEPTH` 512, `MAX_AK_BYTES` 1024, `MAX_URL_BYTES` 256, `MAX_RUN` 2^12 (keeps a run, one page element, far below `MAX_PAGE_ITEMS`), `MAX_STEP_BYTES` | R (decoder limits, refuse) | nothing decodes / stack and memory on hostile input |
| `MAX_MESSAGE` 9 MiB, `REPLY_BUDGET`/`MAX_CLAIM_SET` = it − 64 KiB | R (headroom derived) | no messages / unbounded frame buffers |
| per-message caps (`MAX_ITEMS` 1024, `MAX_GAINED` 4096, `MAX_LABELS` 1024, reconcile ranges 256/4096, `MAX_PATH_STEPS` 1024, `MAX_OPEN_LABELS` 4096) | R | nothing per message / unbounded per-message work |
| `MAX_HELLO_VERSIONS` 16, `MAX_HELLO_BYTES` 256 | R | no handshake / unbounded first frame |
| `MAX_MESSAGE_ITEMS` 2^20 (osis-proto `msg`: CBOR items per message, counted before decoding) | R (densest engine reply about 760 000 items, densest §11.2-valid message about 1 021 000; a decoded item is 100-260 bytes, so at most about 270 MB per decode, one at a time in a hub) | no message decodes / about 2 GB of value tree per 9 MiB frame from any peer |
| rbsr `LIST_MAX` 32, `DIFF_MAX` 1024, `SPLIT` 16, `DENSE_LIST` 8 | P (spec: either mode valid) | more rounds / bigger messages |
| deposit budget `64 + 4 × claims` entries × 32 KiB (`DEPOSIT_ENTRY_BYTES`, `ENTRY_UNIT`) | R (host policy) | no deposits / unbounded junk deposits |

### Clock and session (`proto/client.rs`, `hello.rs`)
| value | class | 0 / ∞ |
|---|---|---|
| `INITIAL_PINGS` 3, `MIN_PONGS` 3, `MAX_SAMPLES` 9 | M | no offset / slow start, memory |
| `PING_INTERVAL_MS` 5 min | M | ping storm / offset never refreshed |
| `OFFSET_DIAGNOSTIC_MS` 5 s | M (diagnostic only) | always reported / never |
| `MAX_SAMPLE_RTT_MS` 10 s | M (spec: ignore long round trips) | no samples / suspend-length errors |
| `STALL_TIMEOUT_MS` 2 min | M (liveness: nothing moved either way while requests are in flight) | every session closes / a hung peer holds it; a link moving under one `WRITE_CHUNK` per timeout counts as stalled |
| `SyncConfig::fill_batch` 128 (`node/sync/io.rs`) | M (a first sync's order and the lock held per batch, against a round trip per batch; only speed changes) | at least 1 is taken; order lost to what a reply fits, node's lock held minutes |
| `WINDOW` 16 MiB (spec), `SMALL_REPLY` 16 KiB | R/P (per-peer buffer vs throughput, `WINDOW` per round trip; one request always goes) | one request at a time / queues overflow the caps |
| `MAX_RECONCILE_MESSAGES` 4096, `MAX_RECONCILE_IDS` 2^21, `MAX_RECONCILE_QUEUED` 2^17 | R (abandon as peer error) | no reconciliation / a splitting responder holds us forever |
| `MAX_EMPTY_PAGES` 16 | R | first empty page fails / a cursor-only peer loops forever |

### Serving (`proto/serving.rs`, `relay.rs`, `host/`)
| value | class | 0 / ∞ |
|---|---|---|
| `LOG_BATCH` 256, replicate `BATCH_RECORDS` 256, `BATCH_BYTES` 4 MiB, `MAX_STEPS` 64, hub `SWEEP_BUDGET` 1024 | P | no progress per call / unbounded call latency |
| `OLDER_KEYS` 8 | M | every stale key REFUSED / unbounded signature checks per refused item; past it a writer 8+ rotations behind gets REFUSED instead of 9 (neither carries the head); the entry stays unsent and goes again at the next pass, under the head the connection learned by open (a stale sync key opens to its child and walks) or by registration pushes (checked) |
| `MAX_CACHED` 64 | P | head keys only: reload per message (two store reads, up to 33 key parses) / memory (about 7 KB each per connection, any label a peer names; 4096 would be up to 30 MB per connection) |
| `MAX_CROSSED` 2^14, `MAX_ORIGINS` 2^20 | P (optimizations, cleared past the cap) | blobs inlined back, entries replicated back to their origin (refused there as held) / memory |
| `SEQ_BLOCK` 1024 | P (commented in code) | |
| `ENTRY_OVERHEAD` 896, `TOMB_OVERHEAD` 160, `REC_OVERHEAD` 96 | measured, tested (`overheads_cover_the_structures`) | |
| `EPH_LOG_KEEP` 2^16 | R (commented) | every cursor replays / log bounded by the cap only |
| `EPH_TOMBSTONE_MS` = `MAX_DRIFT` | M (commented) | |
| `MAX_RELAY_SEEN` 2^16 | M (commented) | |
| connection source = IPv6 /64 (`osis_transport::Source`; slots shared by source, `evict_for`, no per-source number) | M (commented): a holder of a larger prefix counts as many sources; /128 would let one machine take every slot, /0 makes every client one source | |
| `RelayLimits` 6000 / 32 MiB per 60 s | R (rate, code 4) | no relays / relay floods |
| `HostPolicy` defaults: caps per label (2^20 entries, 16 GiB), totals (2^20 labels, 2^26 entries, 256 GiB), rates per 60 s (deletes, deposits 600, registers 600), ephemeral 16 MiB/label, 1 GiB total, `log_keep` 2^20, `max_connections` 10 000, `hello_ms` 10 s, `max_buffered_bytes` 512 MiB | R (operator config; refuse with a code or close) | |
| `HostPolicy::over_cap_step_ms` 1 h | R | a child step past the byte caps even without its claim set: one per label per interval, else Error 12 (the admin's node keeps its open and retries each resync). 0: bare steps bounded only by `registers` (600/min per label, kept for good: disk growth past the cap at bandwidth); infinity: one such step per label until room appears, so a later removal's rotation waits at that full host (the removed holder keeps opening there; uploads are refused for the cap anyway). Only a valid child of the head spends it (signed by the label's admin; a replay of one is a no-op or 9), so outsiders cannot spend it for an honest label; filling the host (anyone, `max_bytes`) puts every label on it at one rotation per interval, while its uploads are refused for the cap anyway. An admin of the label (or one being removed, until the removal lands) can take each interval's slot first: the same power it has by spending `registers`. A clock set back waits at most one interval |
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
| quic `DEFAULT_PORT` 4040 (a `quic://` URL without a port; CLI `serve` listens on `quic://0.0.0.0:4040` when hosting without a listen URL) | O (Tess's pick; any free port works, spec/sync.md §10) | not a port (0 binds a random one, unreachable by URL) / no such port |
| p2p `MAX_ITEMS` 16 (`peer://` items looked at) | R (items past it ignored) | dials nothing / a published URL starts unbounded attempts |
| p2p `RELAY_RATE` 1 MiB/s per source, one-second burst (`RelayConfig::rate`, provisional) | R (forwarding past it waits) | 0 taken as 1 B/s: nothing flows / one source takes the relay's link |
| p2p `RELAY_CONNS` 1024 (`RelayConfig::max_conns`, provisional) | R (past it fair shares by source, `evict_for`, else refused) | relays nothing / unbounded connections |
| p2p `MAX_FORWARDED` 1024 (forwarded streams a listener holds not yet accepted) | R (past it the oldest ends; `silent_dials_do_not_block`) | no relayed connection completes / silent dials fill the relay's grant |
| p2p `REG_STREAMS` 2048 (= 2 × `MAX_FORWARDED`: streams a registration grants its relay) | R (past it the relay answers busy, never waits; `relay_busy`) | no relayed connection / unbounded memory per relay |
| p2p `RELAY_STREAM_WINDOW` 64 KiB (receive window per stream of a registration's relay connection; its connection window is `REG_STREAMS` times it, 128 MiB) | R/P (memory a relay can make a registrant hold vs a relayed session's throughput on the relay hop, 64 KiB per round trip; `quic_relay_unread_sessions`) | nothing flows / a relay makes its registrants buffer without bound |
| p2p `ACCEPT_QUEUE` 64 (connections waiting for a listener's `accept`) | R (past it relayed ones wait inside `MAX_FORWARDED`, each holding only its own stream's window; direct ones pause accepting) | refused by tokio / unbounded queued connections |
| p2p `PORT` 47381 (a node's P2P listener port when free, else any) | M (a fixed port keeps a node's socket address across restarts, for another node's `Config.relays`) | a new port per run / not a port |
| p2p `COPY_BUF` 16 KiB (per forwarded direction) | M (memory per stream vs reads per byte) | no progress / unbounded buffer |
| p2p `PARK_MS` 60 s (= `IDLE_TIMEOUT`; a direct connection found after a relayed one waits for the redial) | M (past it the next dial goes relayed and punches again) | never switches / an unclaimed connection kept alive forever |
| lan `ROUTE_POLL` 5 s (`NetWatch`: how often the routes' local addresses are read, provisional) | M (a network change is seen this much later) | a busy loop / no fresh LAN key per network; registrations renew only at their relay connections' 60 s idle timeout |
| nat model `RESEND_MS` 100, `DIAL_MS` 60 s (= `IDLE_TIMEOUT`; per net `Net::set_dial_ms`) | M (test timing only) | busy loop / a failing dial never ends |

### Node sync (`node/sync/`)
| value | class | 0 / ∞ |
|---|---|---|
| `MAX_INBOX_RESENDS` 3 | O (sign-off) | |
| `INBOX_WAITING` 32, `INBOX_WAITING_BYTES` 1 MiB | R | half the recommended minimum deposit budget, so the rest stays free; past it what is no request goes first, then the requests earliest to expire. 0: nobody unconnected can invite; infinity: a stranger holds the budget up to `INBOX_LIFETIME` |
| `DEPOSIT_RETRY_CAP_MS` 1 h | M | resent every tick / lands that much later once the refusal clears (a deposit taken at that host and label ends the wait of the others there) |
| `RECORD_SWEEP_MS` 1 h (`serve.rs`) | P | every tick scans every entry and its presence (about 100 ms at 10^6 entries) / unneeded carrier and certificate rows are never forgotten (they wait `TOMBSTONE_LIFETIME` anyway, so an hour is noise) |
| `MAX_REOPENS` 3 | M (then the retry timer) | |
| registration refused for now, or a label unknown at a host with nothing to register (an invitee ahead of the label): back-off `retry_ms` doubling per refusal in a row on a connection (an open resets it), at most `resync_ms` (`open.rs` `refused_for_now`) | M (existing knobs) | opens every tick / a label the host admits or gets later never syncs on that connection |
| `MAX_ROUNDS` 16 | M (the rest opens at the next pass: `refetch`) | |
| `SyncEngine::redeliver` visits per commit per round, 1 + its entries | R (past it the name waits for the next step; 0 would look at nothing, infinity spins should a name's invariant fail) | one look per copy |
| `MAX_NOTIFY` 8 | M (the rest goes at the next `handle`) | |
| `PENDING_SHARE` 4, `RELAYS_REMEMBERED` 2^16, `WAITING_MAX` 2^12, `UNFIT_MAX` 2^12, `SHARE_REFUSED_MAX` 2^12 | R (commented) | |
| `MAX_PEER_STEPS` 64, `LAN_HEARD` 4, `LAN_BOUND` 64 (announcements bound to their source per co-reader; past it only a self-flooding co-reader reopens replays of its own), `LAN_CHANGE_MS` 5 s | R | |
| `LOG_KEEP` 4096 | M (a cursor below replays) | |
| `MAX_QUEUED` 64 MiB (at least `SEND_QUEUE`, asserted) | R (a peer that does not read) | sessions keeping the window closed / unbounded buffer |
| link `WRITE_CHUNK` 16 KiB | M (grain of send progress for the stall timeout) | no progress shown / a link under a chunk per stall timeout counts as stalled |
| `SERVE_IDLE` / `serve_idle_ms` 120 s, `serve_open_ms` 30 s, `max_served` 64 | R | |
| `work_max` 2^14 (osis-node `SyncConfig`, changes from elsewhere a label's work set takes in before its pass) | R (past it the set goes and the label's next pass is full, always correct, O(what the label holds): over about 270 changes/s sustained, every resync) | a pass after any change full / 32 B per message since the pass, per label |
| `max_clients` 64 (osis-node `SyncConfig`, client port (b), (c)) | R (past it the oldest unauthenticated main session is closed, else the newcomer; client-actor sessions counted apart, a further Auth is Error 4; also the nonce sessions kept for the main session) | no client served / local dials exhaust memory |
| `client_pending` 64 (osis-node `SyncConfig`, client listener: connections at `link::Slots::Pending`, sessions at `accept_peer`) | R (the oldest unauthenticated gives way to another source's newcomer; a source already holding the most is refused; an authenticated one is out of the count, `max_clients` caps those) | no client ever gets in / a flood holds unbounded memory |
| `REBIND_WAIT` 5 s, `REBIND_RETRY` 50 ms (osis-node `driver`, replacing a client listener) | M (past it the replace fails `Network`, calling it again works: the old socket lives until its connections finished closing) | fails while they drain / waits forever on a port someone else holds; each try blocks that driver |
| `RETRY_MIN` 100 ms, `RETRY_MAX` 30 s (osis `port::client`, redial back-off) | M (how late a client notices its node returned; calls fail `Network` meanwhile) | a tight dial loop / never redials, the connection stays `Network` |
| `NONCE_RESENT` bit 62 (osis `port::client`, spec/wire.md §11.2) | not a tradeoff (a flag; nonces stay below it: 2^62 writes) | |
| `CONNECTION_WAIT` 30 s (osis `port::client`: one attempt to reach a node, and a write in flight across a drop before `OutcomeUnknown`) | M (a write's answer is that late; a caller of `connect` races its own timeout) | nothing connects, a write across a drop is unknown / a silent node holds an attempt and a sync write for good |
| `MAX_SUBS` 4096 per connection (osis-proto `api`, spec/wire.md §11.2) | R (code 4; counted apart from open labels) | no remote watching / one connection grows the dirty-flag table and per-change filter walk without bound |
| `SMALL_REPLY` 16 KiB (holds a Status of 1024 codes, a Path page of 48 steps; the smallest `max_reply`, the allowance of every request whose reply is bounded small) | P (requests per round trip are `WINDOW` over it; a larger reply is `TooLarge` or pages under `REPLY_BUDGET`) | every reply `TooLarge` / two requests per round trip |
| `FIRST_REPLY` 64 KiB (a first Sync page, a Fetch per ID) | P (Syncs and Fetches per round trip are `WINDOW` over it; a larger reply takes one more round trip) | a role commit asked twice / two per round trip |
| `MAX_PATH_STEPS` 48 (a page fits `SMALL_REPLY` at 323 bytes a step) | P (a long path takes a round trip per 48 steps) | no path / a Path's allowance grows with it |
| `REPLY_HEAD` 1 KiB (`serving`) | R (a reply's head and one bare event inside its `max_reply`) | a reply can pass its allowance / less room for events |
| `WRITE_NONCES` 64 per session (osis `port`) | R (an older nonce is "outcome unknown") | every retry an unknown outcome / unbounded per session |
| `MAX_WAITS` 16 per connection (osis `port`, rows that wait still running) | R (`Invalid`; a finished wait counts no more) | no waiting through the port / `MAX_SUBS` waiters each O(labels) per change under `eng` |
| `MAX_CONNS_PER_CLIENT` 8 (osis-node `sync`, client port (c)) | R (a further Auth of that client is Error 4; also the nonce sessions kept per client) | no client served / one client takes the whole `max_clients` pool |
| `PUSH_BYTES` 1 MiB per connection (osis `port`) | R (the subscription whose fired signal, diagnostic or waiting commit does not fit lapses; the client subscribes again) | every subscription lapses under backpressure / a slow client holds unbounded memory |
| `MAX_SCHEMA_BYTES` 1 MiB per node (osis `port`, distinct sources; registrations are process-wide and kept) | R (`TooLarge`) | no typed set through the port / main-session clients fill memory |
| `STREAM_CHUNK` 1 MiB (osis `port`, `stream_read` page) | P | nothing moves / one page bounded by `REPLY_BUDGET` |
| `MAX_AUTHOR_ITEMS` 32 (osis-base `format`, by-author items of one commit's purge) | R (bad input; more in further commits) | no purge by author / one commit stalls every node for items x the aspect's length |
| `COMMIT_PAGE` 256 (osis `commits`, commits of a page) | R (a page ends early, `more`) | reads nothing / a whole scope in one call under `eng` |
| cli `PAGE` 256 (`history --max`'s default, `chat watch --after`'s fetch) | M (past it the next page) | reads nothing / the cap of the API's own page |
| `COMMIT_DIRTY_BYTES` 64 (osis `port`, an ID waiting in a commit subscription against `PUSH_BYTES`) | R (lapse; the client reads again) | nothing counted, unbounded for a slow client / the first ID lapses |
| `COMMIT_SEND` 64 (osis `port`, commits read per send) | P | nothing sent / every waiting commit read per send, most not fitting |
| `MAX_WRITE_OPS` 1024 per `write` (osis `port`, the method table) | R (`Invalid`) | no remote write / a batch's cost unbounded per call (one frame bounds it anyway) |
| unix `MAX_PATH` 107 bytes (osis-transport `unix`) | O (`sun_path`, the OS's) | |
| unix `ACCEPT_RETRY` 100 ms (osis-transport `unix`, wait after an accept error) | M (a client waits up to this long once the cause, e.g. EMFILE, is gone) | spins on a lasting error / the listener ends at the first one |
| `MAX_IDLE` 60 s, `MIN_WAKE_MS` 1 s, `FINISH_WAIT` 10 s, `RELISTEN_RETRY` 5 s | M | |
| `RESEND_MS` 30 s | M (retry pacing after an answer that did not settle the entry; never while its request is unanswered, `ClientSession::answered`) | retry every pass / no retry on this connection |
| `LAN_JOIN_REPEATS` 2, `LAN_JOIN_GAP` 1 s (provisional) | M | a lost first announcement waits `LAN_ANNOUNCE` / one datagram per gap for ever |
| `LAN_ANNOUNCE` 30 s, `LAN_REJOIN_MIN` 30 s (provisional) | M | repeats at the loop's speed, a network change rejoins at once / one announcement per join, a network change never rejoins |
| `LAN_FRESH_MS` 2 windows, `PEERS_TTL_MS` 60 s | M (dialing only; opens check access) | |
| `SETTLE_MS` 30 s, `RELAY_MIN_MS` 5 s | M (co-writers both upload: duplicate work, idempotent) | |
| `PASS_AGAIN` 8 (sync/mod.rs) | M (past it a marked label waits for the next event, a resync at the latest) | |
| `RELINK_BACKOFF_MS` 1 h - 7 days | R (a host deleting fresh chunks) | |
| `sync_now` pings a connection quiet for `retry_ms`, nothing outstanding (`SyncEngine::refresh`) | M (existing knob) | a ping per poll per connection / a dead connection found only by the periodic ping |
| a quiet label's slowest pass: `HEARTBEAT_MIN_INTERVAL_MS` from its last (`schedule_pass`), no number of its own | M (a trigger missed waits that long; 0: every resync passes every label; infinity: a missed trigger waits for a reconnect) | |
| `SyncConfig` defaults: `resync_ms` 60 s, `retry_ms` 5 s, `peer_retry_ms` 60 s, `tight_budget` 16, `peer_pass_wait_ms` 5 min, `heartbeat_lifetime_ms` 2 days | M | |
| `SyncConfig` defaults: `max_peers_per_label` 8, `max_peers` 64, `peer_bytes` 64 MiB, `peer_total_bytes` 1 GiB, `unvouched_cap` 2^16, `ephemeral_bytes` 16 MiB (memory held, decoded: `Engine::memory_charge`; 16 MiB is about 4,000 tiny map entries or 7,000 small parts per label, far above cursors and selections, while 0 holds nothing of others and infinity lets a writer fill memory; a commit is decoded part by part only within the room left, each part's pre-decode bound `part_bound` fitting, else refused with a diagnostic) | R | |
| diagnostics kept 256 | M | |

### Shared set and reconnect (design, issues/net-shared-set.md, issues/net-reconnect.md)
| value | class | 0 / ∞ |
|---|---|---|
| `P` 8 (filter's false-positive bits) | P | every own credential a refused 32 B Hit / 32-byte beacons sent whole; both correct |
| whole-filter re-send at doubling (additions up to n of the whole) | P (receiver enforces the same limit) | re-send each change / false positives grow only |
| `RECORD_BUDGET` 256 MiB | R (evict least recently used record not in use; a filter that does not fit is tested and not stored) | every connection a first contact / disk |

### Engine, keys, perm, crdt, store, schema, API
| value | class | 0 / ∞ |
|---|---|---|
| `MAX_READING` 256, `MAX_READING_PER_AUTHOR` 64, `MAX_READING_ACTORS` 64 | R (tested, keys `boxes.rs`; counts epochs known only from pending commits; a genuine one past it waits for its checked box) | |
| `LOST_HEARD_WAIT_MS` = `ROLE_KEEP` 90 days (engine rotation) | M: how long an actor lost by an `until` passing alone waits for node-sync to hear its labels out. Past it a node out of reach loses unsent writes on what a renewal it has not heard would have kept, and comes back by a re-seal; before it the erase is late. No new number: past `ROLE_KEEP` such a node does not sync cleanly anyway. At 0 every offline holder loses those writes; at infinity one dead or hostile host keeps every expired share it hosts on the node for good | `rotation/lost.rs`; `keep_clients::an_until_ended_out_of_reach_goes_past_role_keep` |
| `PENDING_GRANT_WAIT_MS` 1 day (engine rotation) | M: past it a plausible granter's pending grant no longer keeps a node that lost access holding the actor; the node re-learns from the grant's boxes when it applies and re-fetches content. 0: every such grant waits that way; infinity: a grant that never applies keeps lost secrets for good | `rotation/mod.rs` |
| `MAX_HINT_COMMITS` 64 | R (lowest commit ID evicted, not oldest; inbox spam can evict a genuine hint) | the grantee then writes once the thing's `keys.0` syncs, as after a restart (candidates are not persisted): a delay (checked) |
| `WALK_CACHE_MIN` 64, `MAX_WAIT_BYTES` 64 KiB / 16 MiB, `COPY_CACHE_MAX` 2^20, `HELD_WRITES_MAX` 2^20 (engine `retention/bounds.rs`: other aspects' `HeldWrites` kept beside the last read) | P | |
| pages `PAGE_BYTES` 8 KiB, `SEQ_PAGE_BYTES` 3 KiB, `MIN_PAGED` 64, `GROUP` 32, `PREFETCH` 8, `OP_RUNS` 8, prefetch budget `max(1024)`, `SCAN_PAGE` 256, pending page 256 | P | |
| pages run expansion `1 << 20` | R (corrupt local row) | |
| `MAX_REUSE` 16 GiB | P | |
| `MAX_LIST_BYTES` 64 MiB (format), `MAX_READ` 1 GiB | R (`MAX_LIST_BYTES`: Tess's decision; `MAX_READ` sign-off) | past `MAX_LIST_BYTES` an author's commit fails (`TooLarge`) and every receiver refuses it as bad input (0: lists inline only, infinity: a hostile header holds unbounded memory), so a demotion's frontier over about 1.9*10^6 IDs waits for frontier heads |
| `ENTRY_CHARGE` 1024, `FACTOR` 2 (apply/memory.rs), `MAX_DELIVERED` 2^16 | P/R (commented) | |
| `PART_OVERHEAD` 2048 (engine `apply/memory.rs`, node cap charge per held part) | R, measured estimate (commented; `memory::eph_decoded_memory`) | |
| `ITEM_BYTES` 512, `BYTE_BYTES` 3 (osis-crdt `decoded_bound`: a pre-decode bound on `approx_bytes`, per CBOR item and per byte of a run's text content, and per byte; plus a whole value B-tree node, three times, per map head and set tag, from `size_of::<Value>()`; the node cap's per-part decode check, engine `part_bound`) | R, measured estimate (commented; worst seen about 300 per item outside map and set heads, 380 per text character, a map key's bytes held three times; 0 lets a blob decode past the cap, infinity refuses every blob) | |
| events `PER_PEER` 64 per `WINDOW_MS` 60 s, `DEDUP` 1024 | M (diagnostics) | |
| perm `CHECKPOINT` 32, `FORWARD_MAX` 4, `SHADOW_SHARE` 8 (512), debug `check_scratch` above 400 | P | |
| perm `DETECT_MAX` 16 (dispute candidates walked per update), osis `LIST_MAX` 64 (per `disputes()` call) | R: a hostile author's contestable writes each cost a walk once; past the bound an op that stopped applying keeps its side (trusted unexamined) and a newly held one gets the walk's (`DisputesUnexamined`; the list counts what it skipped) | 0: every op that stops applying trusted unexamined (no warning), the listing shows only recorded sides; infinity: a batch of k hostile writes, or k honest writes one backdated removal voids, costs k walks (0.3-0.5 s each at 10^4) |
| crdt `BLOCK` 256, `STEP` 8, `SIBS` 256, `isqrt().max(64)`, work `max(1024)`, `LIN_MIN` 64, `MAX_D` 512, `CTX` 32 | P | |
| store `arity` 256, `depth` 5 | R: 2^40 unit slots, never reused; exhaustion refuses writes for good, after about 35 years at 1000 unit writes/s | |
| store `page_max` 8 KiB, `spill_bytes` 16 MiB, `node_cache` 4096, `unit_cache_bytes` 16 MiB | P | |
| store row padding `UNIT_MIN` 512 B (`pager.rs`; above it Padmé, spec/wire.md §5) | M (length leak of small units; notes/local-store.md, Row padding) | 0: units below a few hundred bytes show their length to within Padmé's 1-16 bytes, so a small page's drop shows / every unit that big. At 512 Padmé's class width is 32 B; measured cost on engine tests' unit rows: 3.7% (Padmé alone 2.3%, 1024: 6.5%) |
| schema `MAX_EXPAND`, `MAX_TYPE_DEPTH`, `MAX_INSTANCES`, `MAX_CHECK_WORK`, `MAX_NEST`, `MAX_CHECK_DEPTH` | R (refuse; sign-off: not specced) | |
| osis `DEFAULT_LIMIT` 64 MiB | R (error past it) | |
| cli `DEFAULT_WAIT` 30 s (a command with no `--timeout`), app `JOIN_WAIT` 60 s | M (the caller gets an error) | every wait fails at once / a wait nobody answers lasts for good |
| osis `DEFAULT_IDLE_COMMIT` 2 s | M (a crash loses at most that much typing) | |
| osis `REFRESH_DIVISOR` 2: `KeepAlive` rewrites every half of its key's default expiry | M (past the other half's slack a holder sees the value blink off until the rewrite arrives) | 1: it blinks at every refresh / a write per moment; at 2 a holder holds about three writes per kept value |
| osis `STOP_WAIT` 5 s | M (the store is already durable) | `close` on `Runtime::Own` waits up to twice this for the runtime to stop; 0: it returns while the host may still hold its store / a stuck task hangs `close` |
| osis `OFFER_LIFETIME_MS` 10 min | M | |

### Test oracles (`core/test/`)
| value | class | note |
|---|---|---|
| sim `STATE_FACTOR` 2 etc. | M (calibrated detection bound, notes/testing.md) | growth below the bound goes unseen |
| `MAX_CHAIN_BYTES` 1 MiB (`proto/prove.rs`: chain certificates in a Prove or Proved) | R | a stranger's commits are checked before the verifier knows it, so the cap bounds its cost per connection (one Prove per connection, connections by `max_served`): a real chain is a handful of commits, 1 MiB is about 1,500; past it a node proves its key alone and a message is refused whole; 0: no account is ever proved; ∞: a frame the peer rejects and seconds of event loop per connection |
| `MAX_PROOFS` 256 (`proto/prove.rs`: proofs in a Prove or Proved) | R | a stranger pays one signature per proof: about 12 ms of verification per connection, once; a node holding more key actors proves its own key and the first by tid, the rest unproved on that connection; past it a message is refused whole; 0: nothing proved; ∞: seconds of event loop per connection |
| `MAX_ACCOUNT_CLAIMS` 1 (`proto/prove.rs`: account claims in a Prove or Proved) | R | a node names one account; judging a claim walks the chain, so more claims multiply it; past it a message is refused whole; 0: no account proved; ∞: claims times chain |
| sim `IDLE_ROUNDS` 3 | M | ping-pong with a longer period goes unseen |
| sim `STORM` 5000, `ROGUE_STORM` 100 000, `SLOW_MS` 30 s | M | |
| sim `reach::PORT`, `NetSim::lan_drop_pct` 25 | M | a port is only text in an address; the drop rate shapes the mix of events, quiet announces undropped |
| sim world `STORM` 5000 rounds (`world.rs`; busiest osis-test settle about 300) | M | a storm panics; at infinity it hangs the test |
| seed runner `SEED_TIMEOUT_SECS` 600 (`osis_base::testenv`, CPU-seconds a seed's thread uses, or seconds it uses none; `OSIS_SEED_TIMEOUT_SECS` overrides; slowest seeds take a few CPU-s) | M | 0: every seed is hung; ∞: a hung seed hangs the run silently |

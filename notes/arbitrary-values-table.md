# Arbitrary values: audit table
> Summary: Every picked number in core/, cli/ and spec/ with its class (notes/arbitrary-values.md), what 0 and infinity do, and why this value. The project's durable record of magic numbers: every change that adds, changes or removes a picked number updates its row in the same commit. Tess's review of the tradeoff values: issues/magic-number-review.md.

Classes: **P** performance switch between correct strategies (or a cache/batch size: only speed changes); **R** resource bound with a defined safe outcome past it; **M** minor consequence; **O** Tess-agreed tradeoff (protocol constant, spec); **X** only makes a bug unlikely: never kept (Caps that must not come back). Left out: structural constants (CBOR tags, enum discriminants, algorithm-fixed byte lengths, versions, table ids, values derived from listed ones), unit-test fixtures, app/, and libs/kit/ styling (colors, padding); libs/kit/ values that shape behavior are listed.

## Caps that must not come back
Each only made a bug unlikely (class X); the code ends by a fixpoint, a window or a count it can argue, so no number replaces them.
| was | where | what holds instead | test |
|---|---|---|---|
| `reopen_all` sweeps, `reopen_dependents` steps | `engine/flows/mod.rs` | taking up a key actor reopens to a fixpoint, each learner's dependents at once; terminates because an actor is pushed only when its held epochs grew (epochs and secrets are only added), bounded by the secrets the held `secrets.0` states carry | `keys::key_actor_opens_deep_holder_chain_spec_crypto_4` |
| rotation `MAX_DEPTH` | `engine/rotation/mod.rs` | departures one per covers class, a polynomial fixpoint over the holder graph, cascade iterative, each actor once: any depth rotates | `rotation::tests::removal_twelve_deep_rotates_every_level_spec_crypto_4` |
| `MAX_INBOX_TRIES` | old sync's deposits | a refused deposit is retried at the capped back-off until taken or moot (delivery forgotten or re-sealed, label replaced) | `inbox_retry::inbox_deposit_retried_for_hours_spec_sync_5` |
| queue caps and a request timeout as flow control | old sync's sessions | the request window `WINDOW` (spec/sync-streams.md §1 flow control) keeps both queues under `WINDOW_QUEUE`; `STALL_TIMEOUT_MS` counts from the oldest request's last move; pushes wait while the connection's unwritten bytes leave no room for one (`SessionInput::Taken`), so a subscriber's queue stays under `SEND_QUEUE` | `slow_link::*` |
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
| `MAX_DRIFT_MS` 1 h, `ROLE_KEEP_MS` 90 days, `INBOX_LIFETIME_MS` 90 days, `TOMBSTONE_LIFETIME_MS` 30 days, `MAX_CLAIMS` 65 536, `LAN_WINDOW_MS` 10 min, `INBOX_COPY_MIN_LEFT` = `INBOX_LIFETIME_MS` / 2 | O | what each trades: issues/magic-number-review.md |
| `MAX_RETENTION_ENTRIES` 64 | R | no setting can say anything / `MAX_VALUE_BYTES` of AKs in every node's memory per `retention^.0` delta; past it the delta is no setting, a writer refuses it |
| `LIST_TREE_DEPTH` 32 (format) | R | a rotator listing more than 2^32 things refuses the rotation (0: one thing per rotation; ∞: unbounded paths); the largest useful size, so a path (1 KiB) shows nothing of how many things a rotator lists, where padding to the actual depth shows its log |
| `MAX_CHAIN_DEPTH` 64 | R | only key actors / unbounded chain walks; deeper is invalid everywhere alike |
| `MAX_VALUE_DEPTH` 64, `MAX_OBJECT_DEPTH` 512, `MAX_AK_BYTES` 1024, `MAX_URL_BYTES` 256, `MAX_RUN` 2^12 (keeps a run, one page element, far below `MAX_PAGE_ITEMS`), `MAX_STEP_BYTES` 323 | R (decoder limits, refuse) | nothing decodes / stack and memory on hostile input |
| `MAX_MESSAGE` 9 MiB, `REPLY_BUDGET`/`MAX_CLAIM_SET` = it − 64 KiB | R (headroom derived) | no messages / unbounded frame buffers |
| osis-proto `limits` per-message caps: `MAX_DELETE_ITEMS`, `MAX_FETCH_IDS`, `MAX_OFFER_ITEMS` 1024, `MAX_ITEM_HITS` 256, `MAX_MEMBERS` 4096, `MAX_CURSOR_BYTES` 256, `MAX_RESUME_TAGS` ⌊(`MAX_MESSAGE` − 64) / 34⌋ (spec/wire.md §2, §11.2) | R (refused as malformed) | nothing per message / unbounded per-message work |
| `MAX_HELLO_VERSIONS` 16, `MAX_HELLO_FRAME` 256 (length included) | R | no handshake / unbounded first frame |
| `MAX_MESSAGE_ITEMS` 2^20 (osis-proto `msg`: CBOR items per message, counted before decoding) | R (densest engine reply about 760 000 items, densest §11.2-valid message about 1 021 000; a decoded item is 100-260 bytes, so at most about 270 MB per decode, one at a time in a hub) | no message decodes / about 2 GB of value tree per 9 MiB frame from any peer |

### Clock and window (`proto/hello.rs`, `proto/msg.rs`)
| value | class | 0 / ∞ |
|---|---|---|
| `MIN_PONGS` 3, `MAX_SAMPLES` 9 | M | no offset / slow start, memory |
| `OFFSET_DIAGNOSTIC_MS` 5 s | M (diagnostic only) | always reported / never |
| `MAX_SAMPLE_RTT_MS` 10 s | M (spec: ignore long round trips) | no samples / suspend-length errors |
| `STALL_TIMEOUT_MS` 2 min | M (liveness: the oldest request in flight did not move, either side; half of it bounds how long a served request waits in the hub's queue for the output bound's room before the biggest holders are closed) | every connection with a request out closes, every stream body is asked of a second source at once / a peer answering nothing holds its fetches; a link moving under one `WRITE_CHUNK` per timeout counts as stalled |
| `WINDOW` 16 MiB (spec) | R/P (per-peer buffer vs throughput, `WINDOW` per round trip; one request always goes) | one request at a time / queues overflow the caps |
| `SMALL_REPLY` 16 KiB (holds a Status of 1024 codes; the smallest `max_reply`, the allowance of every request whose reply is bounded small) | P (requests per round trip are `WINDOW` over it; a larger reply is `TooLarge` or pages under `REPLY_BUDGET`) | every reply `TooLarge` / two requests per round trip |

### Protocol (`proto/relay.rs`, `prove.rs`)
| value | class | 0 / ∞ |
|---|---|---|
| `MAX_PROOFS` 256 (proofs in a Prove or Proved) | R (past it a message is refused whole; a node holding more key actors proves its own key and the first by tid, the rest unproved on that connection) | nothing proved / seconds of event loop per connection (a stranger pays one signature per proof: about 12 ms per connection, once) |
| `MAX_RELAY_SEEN` 2^16 | M (commented) | |
| connection source = IPv6 /64 (`osis_transport::Source`: relay slots shared by source, `evict_for`, the driver's read turns) | M (commented; a holder of a larger prefix counts as many sources) | /0: every client one source / /128: one machine takes every relay slot and turn |
| `RelayLimits` 6000 / 32 MiB per 60 s | R (rate, code 4) | no relays / relay floods |

### Transport (`transport/`)
| value | class | 0 / ∞ |
|---|---|---|
| `KEEP_ALIVE` 15 s, `IDLE_TIMEOUT` 60 s | M (also ends a silent handshake) | keep-alive storm / dead connections and handshakes linger |
| `STREAM_WINDOW` 1 MiB, `CONN_WINDOW` = it, send window = it | R/P (buffer per peer vs throughput on long fat links: 1 MiB per round trip; with `MAX_STREAMS` reads, `link::CONN_MEMORY` 2 MiB per served connection, connections not counted) | stall / unbounded buffering |
| `MAX_STREAMS` 16, `MAX_INCOMING` 1024 (handshakes in progress; past it the oldest goes) | R | |
| link `READ_CHUNK` 64 KiB (largest read; a link reads only as its consumer asks) | P (the hub's per-input unit; in `CONN_MEMORY` per stream) | |
| link `WRITE_CHUNK` 16 KiB | M (grain of send progress for the stall timeout) | no progress shown / a link under a chunk per stall timeout counts as stalled |
| manage `Backoff` 0.5-60 s | M | |
| quic `DEFAULT_PORT` 4040 (a `quic://` URL without a port; CLI `serve` listens on `quic://0.0.0.0:4040` when hosting without a listen URL) | O (Tess's pick; any free port works, spec/sync-opens.md §4) | 0 binds a random port, unreachable by URL / no such port |
| unix `MAX_PATH` 107 bytes | O (`sun_path`, the OS's) | |
| unix `ACCEPT_RETRY` 100 ms (wait after an accept error) | M (a client waits up to this long once the cause, e.g. EMFILE, is gone) | spins on a lasting error / the listener ends at the first one |
| p2p `MAX_ITEMS` 16 (`peer://` items looked at) | R (items past it ignored) | dials nothing / a published URL starts unbounded attempts |
| p2p `RELAY_RATE` 1 MiB/s per source, one-second burst (`RelayConfig::rate`, provisional) | R (forwarding past it waits) | 0 taken as 1 B/s: nothing flows / one source takes the relay's link |
| p2p `RELAY_CONNS` 1024 (`RelayConfig::max_conns`, provisional) | R (past it fair shares by source, `evict_for`, else refused) | relays nothing / unbounded connections |
| p2p `MAX_FORWARDED` 1024 (forwarded streams a listener holds not yet accepted) | R (past it the oldest ends; `silent_dials_do_not_block`) | no relayed connection completes / silent dials fill the relay's grant |
| p2p `REG_STREAMS` 2 × `MAX_FORWARDED` (streams a registration grants its relay) | R (past it the relay answers busy, never waits; `relay_busy`) | no relayed connection / unbounded memory per relay |
| p2p `RELAY_STREAM_WINDOW` 64 KiB (per stream of a registration's relay connection; connection window `REG_STREAMS` × it, 128 MiB) | R/P (memory a relay can make a registrant hold vs throughput on the relay hop, 64 KiB per round trip; `quic_relay_unread_sessions`) | nothing flows / a relay makes its registrants buffer without bound |
| p2p `ACCEPT_QUEUE` 64 (connections waiting for a listener's `accept`) | R (past it relayed ones wait inside `MAX_FORWARDED`, each holding only its stream's window; direct ones pause accepting) | refused by tokio / unbounded queued connections |
| p2p `PORT` 47381 (a node's P2P listener port when free, else any) | M (keeps a node's socket address across restarts, for another node's `Config.relays`) | a new port per run / not a port |
| p2p `COPY_BUF` 16 KiB (per forwarded direction) | M (memory per stream vs reads per byte) | no progress / unbounded buffer |
| p2p `PARK_MS` = `IDLE_TIMEOUT` (a direct connection found after a relayed one waits for the redial) | M (past it the next dial goes relayed and punches again) | never switches / an unclaimed connection kept forever |
| lan `ROUTE_POLL` 5 s (`NetWatch` reads the routes' local addresses, provisional) | M (a network change is seen this much later) | busy loop / no fresh LAN key per network; registrations renew only at their relay connections' idle timeout |
| nat model `RESEND_MS` 100, `DIAL_MS` = `IDLE_TIMEOUT` (per net `Net::set_dial_ms`) | M (test timing only) | busy loop / a failing dial never ends |

### Sync (spec constants and policy)
| value | class | 0 / ∞ |
|---|---|---|
| `MAX_INBOX_RESENDS` 3 | O (sign-off) | |
| `DEPOSITS_WAITING` 32, `DEPOSITS_WAITING_BYTES` 1 MiB (base `format`) | R (deposits an admin leaves waiting under any label: half the recommended minimum deposit budget; past it what is no request goes first, then the requests earliest to expire) | nobody unconnected can invite, a deposit not judged yet may go / a stranger (inbox) or reader (any label) holds the budget for good |
| `PAGE_BYTES` 256 KiB (a filter's page), `MAX_SHARED_ITEMS` 1024, `MAX_BYROLE_HITS` 256 | P | more messages / a message beyond `MAX_MESSAGE` |
| `max_clients` 64 (spec/wire.md §11.2; client port (b), (c)) | R (connections authenticated as client actors: a further Auth is Error 4; also the nonce sessions kept for the main session) | no client served / clients take every connection |
| `MAX_CONNS_PER_CLIENT` 8 (spec/wire.md §11.2; client port (c)) | R (a further Auth of that client is Error 4; also the nonce sessions kept per client) | no client served / one client takes the whole `max_clients` pool |
| `SETTLE_MS` 30 s (spec/wire.md §2) | M (co-writers both upload: duplicate, idempotent work; admins all give a plain thing with holder secrets of its own: a fork and a label each, pruned) | every holder uploads every role commit at once / a role commit only its author places, and a co-writer's deletes at a host its author never reaches never go |
| `PASS_WAIT_MS` recommended 1 h (spec/sync-status.md §1; not built) | M (how long a complete pass waits for a peer whose record holds the sync ID; past it the pass ends without that peer, so a re-seal, rotation or link finalize may miss what only it holds: an extra box or a fork, healed by a later one) | a pass is S heard out, decisions miss every away peer / one peer away for good holds every decision on the sync ID |

### Client port and API (osis-proto `api`, `osis`, `cli`)
| value | class | 0 / ∞ |
|---|---|---|
| `MAX_SUBS` 4096 per connection (spec/wire.md §11.2) | R (code 4; counted apart from open labels) | no remote watching / one connection grows the dirty-flag table and per-change filter walk without bound |
| `MAX_AUTHOR_ITEMS` 32 (base `format`, by-author items of one commit's purge) | R (bad input; more in further commits) | no purge by author / one commit stalls every node for items × the aspect's length |
| `COMMIT_PAGE` 256 (`commits`), `BACKLINK_PAGE` 256 (`backlinks`) | R (a page ends early, `more`) | reads nothing / a whole scope, or every backlink of a thing, in one call under `eng` |
| cli `PAGE` 256 (`history --max`'s default, `chat watch --after`'s fetch) | M (past it the next page) | reads nothing / the cap of the API's own page |
| cli `DEFAULT_WAIT` 30 s (a command with no `--timeout`), kit `JOIN_WAIT` 60 s (`store.rs`) | M (the caller gets an error) | every wait fails at once / a wait nobody answers lasts for good |
| osis `DEFAULT_LIMIT` 64 MiB (`handle.rs`) | R (error past it) | |
| osis `DEFAULT_IDLE_COMMIT` 2 s | M (a crash loses at most that much typing) | |
| osis `REFRESH_DIVISOR` 2 (`keep.rs`): `KeepAlive` rewrites every half of its key's default expiry | M (past the other half's slack a holder sees the value blink off until the rewrite arrives) | 1: it blinks at every refresh / a write per moment; at 2 a holder holds about three writes per kept value |
| osis `OFFER_LIFETIME_MS` 10 min (`account.rs`) | M | |

### Shared set and node log (`proto/filter.rs`, `store/`)
| value | class | 0 / ∞ |
|---|---|---|
| `INCARNATIONS_KEPT` 4096 (`store/nodelog.rs`) | R (oldest evicted: a cursor on an evicted incarnation is no cursor, one listing for that peer) | every cursor before an appending start no cursor, a listing per peer / disk grows with appending starts |
| store `PAGE` 256 (`store/store.rs`: rows a node-log sweep or forget scan handles per call) | P (only how the work is split into transactions) | no progress / one transaction holds the whole sweep |
| `P` 8 (filter's false-positive bits) | P | every own credential a refused 32 B Hit / 32-byte beacons sent whole; both correct |
| whole-filter re-send at doubling (additions up to n of the whole) | P (receiver enforces the same limit) | re-send each change / false positives grow only |
| `RECORD_BUDGET` 256 MiB (`store/record.rs`) | R (evict least recently used record not in use; a filter that does not fit is tested and not stored) | every connection a first contact / disk |

### Engine, keys, perm, crdt, store, schema
| value | class | 0 / ∞ |
|---|---|---|
| `MAX_REMEMBERED` 4096 (`apply/waits.rs`, headers of unjudgeable commits kept for `awaits_on` and the record wake) | R (past it the smallest ID is forgotten: its record wake stops, a host listing it brings it back) | no record wakes across parts / one peer grows memory per unjudged header without end |
| `MAX_READING` 256, `MAX_READING_PER_AUTHOR` 64 (keys `epoch.rs`), `MAX_READING_ACTORS` 64 (engine `secrets.rs`) | R (tested; counts epochs known only from pending commits; a genuine one past it waits for its checked box) | |
| `LOST_HEARD_WAIT_MS` = `ROLE_KEEP_MS` (`rotation/lost.rs`) | M: how long an actor lost by an `until` passing alone waits for sync to hear its labels out. Past it a node out of reach loses unsent writes a renewal it has not heard would have kept, and comes back by a re-seal; before it the erase is late. No new number: past `ROLE_KEEP` such a node does not sync cleanly anyway (`keep_clients::an_until_ended_out_of_reach_goes_past_role_keep`) | every offline holder loses those writes / one dead or hostile host keeps every expired share it hosts on the node for good |
| release request `expires` = `ts` + `ROLE_KEEP_MS` (`osis_commit::retention::release_expires`) | M: how long a release request stays for nodes that have not seen it. No new number: past `ROLE_KEEP` a node that missed it does not sync cleanly anyway; the request is placed at a host before the thing's blobs are deleted there, one arriving late still destroys the thing, and a held thing needing the evidence keeps it past the expiry (node `lifetimes::a_released_thing_is_forgotten_at_its_requests_expiry_and_a_stale_copy_is_judged_again`) | forgotten as written: holders that missed it upload the thing again and right holders release it again, round for good (livelock, nothing lost) / a tombstone, which a release may not leave |
| `MAX_HINT_COMMITS` 64 (`engine/secrets.rs`) | R (lowest commit ID evicted, not oldest; inbox spam can evict a genuine hint: the grantee then writes once the thing's `keys.0` syncs, as after a restart, a delay) | |
| `WALK_CACHE_MIN` 64 | P | |
| `DECODED_MAX` 16 MiB (`engine/decoded.rs`: stored commit records and decoded parts kept, all forgotten past it) | P | every read decodes from the store / every commit read since the open stays decoded |
| `TOUCHES_MAX` 16 MiB (`undo/touch.rs`: the undo index's approximate bytes, every aspect's forgotten past it when a check starts) | P | every undo check reads every held part of its aspect / every aspect checked since the open stays indexed |
| `SWEEP` 2 (`osis_base::memo`: a memo checks every entry and drops those that no longer hold when it has grown to this many times what the last check kept) | P | at 1 every new entry checks them all / an answer nobody asks for again is never dropped |
| `ABSENT_BUCKETS` 64 (`osis_base::memo`: absent keys of a container share a stamp per bucket of their hash) | P | every removal moves what read any absent or unstamped key (every row read since an open) / a stamp per key ever removed, growing without bound |
| pages (`engine/pages.rs`) `PAGE_BYTES` 8 KiB, `SEQ_PAGE_BYTES` 3 KiB, `MIN_PAGED` 64, `GROUP` 32, `PREFETCH` 8, `OP_RUNS` 8, prefetch budget `max(1024)`; `SCAN_PAGE` 256 (`engine/mod.rs`) | P | |
| pages run expansion `1 << 20` | R (corrupt local row) | |
| `MAX_REUSE` 16 GiB (`engine/large.rs`) | P | |
| `MAX_LIST_BYTES` 64 MiB (format) | R (Tess's decision; past it an author's commit fails `TooLarge` and every receiver refuses it as bad input, so a demotion's frontier over about 1.9×10^6 IDs waits for frontier heads) | lists inline only / a hostile header holds unbounded memory |
| `MAX_READ` 1 GiB (`engine/large.rs`) | R (sign-off; larger values stream only) | |
| `ENTRY_CHARGE` 1024, `FACTOR` 2 (`retention/compact.rs`, the trigger for durable and ephemeral aspects), `MAX_DELIVERED` 2^16 (`ephemeral/signal.rs`) | P/R (commented) | |
| `QUIET_MS` = `MAX_DRIFT_MS` (`retention/compact.rs`: how long an aspect holding a leftover stays quiet before a writer covers it whatever `FACTOR` says) | O (reuses `MAX_DRIFT`; notes/engine-retention-trigger.md Cover once quiet) | one whole-aspect snapshot per expiry per writer (a collection of expiring elements pays its whole state per element) / a node that missed an expired write reads differently for good |
| `PART_OVERHEAD` 2048 (`apply/memory.rs`, node cap charge per held part) | R, measured estimate (commented; `memory::eph_decoded_memory`) | |
| `ITEM_BYTES` 512, `BYTE_BYTES` 3 (osis-crdt `codec.rs` `decoded_bound`: a pre-decode bound on `approx_bytes` per CBOR item and per byte of a run's content, plus a whole value B-tree node, three times, per map head and set tag; engine `part_bound`'s per-part check against the node cap) | R, measured estimate (commented; worst seen about 300 per item outside map and set heads, 380 per text character, a map key's bytes held three times) | a blob decodes past the cap / every blob refused |
| events `PER_PEER` 64 per `WINDOW_MS` 60 s, `DEDUP` 1024 | M (diagnostics) | |
| perm `CHECKPOINT` 32, `FORWARD_MAX` 4, `SHADOW_SHARE` 8, debug `check_scratch` above 400 commits | P | |
| perm `DETECT_MAX` 16 (dispute candidates walked per update), osis `LIST_MAX` 64 (per `disputes()` call) | R (a hostile author's contestable writes each cost a walk once; past the bound an op that stopped applying keeps its side, trusted unexamined, and a newly held one gets the walk's: `DisputesUnexamined`; the list counts what it skipped) | every op that stops applying trusted unexamined, no warning, the listing shows only recorded sides / k hostile writes, or k honest writes one backdated removal voids, cost k walks (0.3-0.5 s each at 10^4) |
| crdt `BLOCK` 256, `STEP` 8, `SIBS` 256, `isqrt().clamp(4, BLOCK)`, work `max(1024)` (`seq_lin.rs`), `LIN_MIN` 64, `MAX_D` 512, `CTX` 32 (`seq_diff.rs`) | P | |
| store `arity` 256, `depth` 5 | R: 2^40 unit slots, never reused; exhaustion refuses writes for good, after about 35 years at 1000 unit writes/s | |
| store `page_max` 8 KiB, `spill_bytes` 16 MiB, `node_cache` 4096, `unit_cache_bytes` 16 MiB | P | |
| store `RETRY_FIRST` 1 s doubling to `RETRY_MAX` 60 s (`pager.rs`: waits between a lost store's attempts to recover in place after its first, at the next call) | M (each attempt reopens the backend, which may scan the file; recovery up to a minute late once the device works) | a failing device costs a reopen per call / the store never recovers until opened again |
| store row padding `UNIT_MIN` 512 B (`pager.rs`; above it Padmé, spec/wire.md §5) | M (length leak of small units; notes/local-store.md, Row padding; Padmé's class width at 512 is 32 B; cost on engine tests' unit rows 3.7%, Padmé alone 2.3%, 1024: 6.5%) | units below a few hundred bytes show their length to within 1-16 bytes, so a small page's drop shows / every unit that big |
| schema `MAX_EXPAND` 64, `MAX_TYPE_DEPTH` 256, `MAX_INSTANCES` 10 000, `MAX_CHECK_WORK` 100 000, `MAX_NEST` 64, `MAX_CHECK_DEPTH` 2 × `MAX_TYPE_DEPTH` | R (refuse; sign-off: not specced) | |

### Kit (`libs/kit/`)
| value | class | 0 / ∞ |
|---|---|---|
| `WINDOW` 64, `MIN_SIDE` 16, `MARGIN` 1, `DAY_ROWS` 24; `MAX_SIDE` 512 | M (a list loads a little more or less often; a day says how many more; `WINDOW` is also all a list that is no page's scroller shows, the rest reached by opening its thing); `MAX_SIDE`: R (a widget asks at most a screenful of rows; past it clamped) | nothing shown / the whole list built |
| `Page`: head and foot pinned while the page keeps at least their height (a 1:1 split) | M (on a short page they scroll with it a little sooner or later; the rail's half-the-room rule) | always scrolled: a composer leaves the screen on every page / always pinned: at a short height they take it all |
| `GUTTER` 12 px, `MIN_THUMB` 24 px, `LINE` 60 px | M (the bar's size, a scroll step) | no bar or no room / no scroll |
| `ROW_MIN` 220 px (before spacing) | M (lists put rows side by side only at this width each; the rail is this wide plus its sides, and shows when it and a page as wide fit) | rows squeezed to their icons, the rail always shown / rows never side by side, the rail never shown |
| `STREAM_HEAD` 64 | P (a merge reads per-thing heads) | a read per thing per page / whole histories held |
| desktop `THRESHOLDS`: double click 500 ms and 4 px, long press 400 ms, touch slop 8 px (Android reads `ViewConfiguration`) | M (a touch is a tap, long press or drag a little sooner or later) | no double clicks, every touch a drag / every click counts on, no drags |
| `FLING_TAU` 325 ms, `VELOCITY_WINDOW` 100 ms; a selection handle's disc 0.4 of the line height | M (how far a flick carries; how much of a drag's end its speed reads; how big a handle is drawn, hit within the touch slop) | a lift stops dead, a jittery fling / a fling that never slows, a slow start dulling a flick; an invisible handle / one covering the text |
| selection menu (`widgets/menu.rs`): items 40 px high, 4 px inside the box, 8 px from the selection | M (looks and hit size) | items too small to hit / a menu covering what it acts on |

### Test oracles (`core/test/`, node tests)
| value | class | 0 / ∞ |
|---|---|---|
| seed runner `SEED_TIMEOUT_SECS` 600 (`osis_base::testenv`, CPU-seconds a seed's thread uses, or seconds it uses none; `OSIS_SEED_TIMEOUT_SECS` overrides; slowest seeds take a few CPU-s) | M | every seed hung / a hung seed hangs the run silently |
| gate `HANG` 10 (`tools/test_watch.py`: times the `test` wall limit a default-test target may go with no test finishing before the gate stops it as hung) | R (the target stopped, its running tests failed "hung"; 10 times a limit whose 2x overrun starts an investigation; floor 120 s, twice libtest's 60-second notice, so the tests are named on any box) | every target stopped before its first test ends / a hung test holds the gate and the heavy lock until someone notices |
| order `TWIN_SHARE` 0.25 (`core/engine/tests/it/order.rs`: the share of an exhaustive held set's enumerated orders tried again with late parts, besides its named three) | M (a twin costs about its order with its checks; each gate's fresh seeds draw other orders) | the named three only per held set with a multi-part commit / every order's twin, double the cost |

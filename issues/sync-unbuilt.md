# Parts of the rebuilt sync not built yet
> Summary: The parts of osis-sync and its engine facade that are stubbed, answer `NotBuilt` or are missing, per module, each with the spec rule it leaves unmet; wire strings and the link format that differ from the spec; larger gaps have their own issues (listed at the end).
> Priority: normal
> Tags: sync

Each line: what is missing, what it costs now. The module notes (notes/sync-*.md) point here.

## session
- The node-wide bound on what served connections hold (spec/sync-transport.md §5 Served connections: requests waiting for the bound's room, reading paused, the largest holders closed); needs `Sessions` to hold answers back. Each connection is bounded alone.

## opens
- Static entries claimed in the walk's tests (`Tested::Static` always has no step).

## store and streams
- Fetching an unjudgeable body again (spec/commits.md §4 Unjudgeable, spec/sync-judgement.md §3 Dropped bodies): needs byte-less entries (a body counting missing is fetched again through `Streams::fetch_again`, notes/sync-read.md); until then an awaiting entry keeps its bytes (notes/sync-store.md).
- Fill order again (spec/sync-streams.md §4 Fill order, 4): a body queued as not opening keeps its last place when a read secret of S arrives; it should park under S's read secrets and be ranked again then, as the store's parked entries are (notes/sync.md Arriving early).
- An ephemeral entry a reader refused for its memory cap (`Ingested::TooLarge`, spec/sync-compaction.md §2 Caps) is not fetched again once S's held bytes drop below what they were at the refusal: it comes again only with its next listing (a new connection's join). Needs streams to keep the refusal per S with the usage then, as `room` does for a node keeping S unread.
- `Rank::Never` (a keyset without history: the facade has no call for it). When built, an entry it ranks never is neither held nor taken, so `pull::concerns` keeps no presence of it at a source (spec/sync-judgement.md §3 `known` must then count it): emptying's deletes at a source keeping S unread (`judge::doom`, `seen_all`) would miss it until the closing step drops it.
- A source that drops S and keeps it again (shred, then listed again) is still at the step its stream last named for a registrar that joins it again from a stored position: the source's log forgot S's events (`log_forget`), so no head event or deletion clears it there, and nothing is registered (spec/sync-streams.md §3 names no event for a head gone). Reachable by unlisting and listing the thing again at that node: it takes nothing until a registrar with no stored position there registers the genesis step. A listing from the start that names no head could clear it (`known`'s head replaced like presence).

## read
- A reader shown an entry it holds under another stamp that also verifies under its head keeps the one it holds (spec/sync-ids.md §6 Role entries: it keeps the lower, as bytes), so two writers stamping one entry under either domain need not settle on one.
- A sole certificate (spec/sync-judgement.md §2 may-hold: a certificate blob whose author has no other blob under S) is never judged one: `BodyFacts::sole_certificate` is always false (engine sync/bodies.rs leaves it to the store) and read computes nothing, so such a certificate is must-hold (logged, relayed, owed). Build it from the author's other blobs under S, or drop the clause if the chain-certificate rule of §2 already covers it.
- `SrcView::role_unheld` is always false: deletes toward a source do not wait for a role commit it lacks.
- A peer's entry counting as lacking for its wrap (Duplicates, spec/sync-ids.md §6 Wraps).
- Freed links (spec/sync-compaction.md §1): a judgment waiting on a node blob not held (`Engine::freed_wants`) is not fetched, and nothing calls `judge_freed`/`judge_freed_page`, so a waiting row is judged again only when its thing's next freed link is, and a start judges none; freed deletes do not wait on Role entries first (spec/sync-judgement.md §3). A row is judged once, not again at each delete sent: a body arriving later that links the blob (another writer's reuse) does not stop deletes toward store sources that show it from then on, nor un-free its bytes here (`is_freed`); the reusing author's repair is then what restores it.
- Pieces: a thing leaving a group leaves its pieces under the old sync ID (Retag, spec/sync-judgement.md §1); a non-writer's pieces reach a store source only as deposits (inbox's offers), never relayed under the writer's stamp.
- HN_fallany (a snapshot arriving invalid moves the fall mark as one held valid falling does) is the engine's `fall_mark`, untested end to end.
- A reader's copy under a superseded stamp (spec/sync-judgement.md §3 Reader that is not a writer, notes/inbox.md) is not deposited once the source's head moved: seen in a World (writer writes an ephemeral value, rotates write and goes off while the reader is partitioned; the node keeping S unread restarts, losing it): the source pulled the reader's entry, refused it (9) under its new head, and the reader's `Live::deposit` ran only while its view of the source's head was the old one (relay under stamp); nothing deposited it after the head event.
- `Live::fresh` (the held blobs it hands `Engine::seal_body`) has no World test: a mutation passing none fails no osis-sync test; the engine's `rotation::tests_reseal::facade_*` cover the contract. Cheapest found: a purge of one thing's part of a commit spanning two things, the other thing's section then logged again verbatim.

## inbox
- Clearing at sources keeping S unread: needs streams' `known` to carry each entry's deposited flag and blob size.
- A decline stamping in place.
- Opens' members are not stamped, so a source's step moving reaches Register only through its next join.
- A deposit-only step (a refreshed seed, no newer role epoch) is issued without the waits spec/permissions.md §3 and spec/sync-ids.md §6 put on it (every entry it can open opened at the sources it reaches; no valid `keys.0` part of the actor missing; `flows::sync_ids::due_at`).

## status and API
- Connection diagnostics never dedup (each detail names its connection, `dN`/`aN`) and share one local rate bucket, so a peer opening and dropping connections pushes out real connection and dial-failure reports; key them per remote instead.
- Diagnostics name connections and failed dials only (`DiagnosticKind::Connection`): not an open refused (sync ID, code), a grant held but not accepted, nor a peer clock offset past a few seconds (spec/sync-streams.md §1: `Session::clock_offset` estimates it, nothing reports it).
- Covered by a snapshot at a source (spec/sync-status.md §2): needs the engine's covering snapshots of a commit; a body a source dropped under a snapshot before showing it never counts (an under-claim).
- `caps()`/`set_caps` in the osis API over `caps^.0` (the engine reads `caps^.0`; nothing writes it but a raw write).

## facade
- Nothing calls `history_complete` (spec/sync-status.md §3) from the API.
- `SETTLE_MS` (spec/wire.md §2, a MAY wait: spec/permissions.md §3, §4): nothing waits it. Every holder copies another node's demotion or `keys.0` at once (a duplicate copy each, 3.3 KB per holder per removal, notes/permissions.md Certificates), and every admin gives a plain thing with holders secrets of its own at its pass end (`own_secrets_candidates`), concurrent ones forking.
- A blob's prefix commitment groups are checked against the commit's delete keys only when its header's linked lists resolve here (`Engine::open_commit`; spec/sync-ids.md §1, spec/crypto.md §7); its expiry is checked always. Until the lists resolve, a reader keeps and serves a blob framed under commitments of its framer's choosing: the thing's delete-key holders cannot delete it (their signatures match no commitment) while its framer can, until its expiry (an open after the lists resolve refuses it, but nothing opens it again for that alone). Fix: hold such a blob unopened (not served) until its lists resolve, then check.
- A stale copy (spec/permissions.md §3: `open_entry` takes none of it, `Opened::NotOpen`) keeps its bytes in the store as an entry that did not open, and is opened again only when S's read secrets move, not when this node gets secrets of the part's actor (the engine names such waits in `Wakes`, `Engine::take_wakes`, which only its test peer takes, nothing in osis-sync).

## Own issues
issues/sync-link-first-contact.md, issues/sync-pending-leftovers.md; missing tests: issues/sync-tests-owed.md.

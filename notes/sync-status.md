# Sync: status
> Summary: osis-sync's `status` module (core/sync/src/status/): what its module doc leaves out about held elsewhere, lacking counts, self-removals, stranding, caught up, complete passes across restarts and `wait`; its owed state and bounds, the readings it implements beyond the spec's words, its costs, and what is not built.

Spec: spec/sync-status.md. Model: core/test/tla/net/NetStream.tla (`Synced`, `CaughtUpHolds`). Code: the module doc of core/sync/src/status/mod.rs (principle, what it keeps, read when asked in O(sources of S)). Overview: notes/sync.md.

**Principle:** status says only what is true now, per sync ID, of the sources connected now; nothing is synced with nobody connected, and no word of a peer counts until its stream showed it.

## What it owns, beyond mod.rs
- **Held elsewhere** is a durable row per entry beside it (`Store::set_elsewhere`), so it goes with the entry and recording it moves no reader of the entry (inbox's judgement reads the entry). A source showing or reporting an entry is recorded whatever read's verdict on the commit: status's own reading (`unheld`, `wait`) counts a may-hold or must-not-hold commit held at once, but a timed loss reads the rows alone (`life::Hears::timed_heard` through `leave::own_elsewhere`), since a node that lost access may log none of its own commits, so its verdict says nothing of them must be held (spec/sync-status.md §2 By a source's report).
- An own commit's entries under S are the entries of S holding a blob the engine's `commit_blobs(c)` names (both stamped).
- A source that left since the last settle still counts by where it stood as it left (`Moved::Left`'s `LeftAt`) and by what its record's stream showed: a source that reports a position and closes S in one step still counts by that report.
- **Lacking counts** per (S, record of a source keeping S unread) are kept across its connections, by the record's rows, the connection read only for an entry they do not show.
- `wait(Thing(t))` covers the engine's `carrying(t)`: t's own sync IDs and those of the sync units holding it, read or kept unread.
- `wait(All)` also stays `Pending` while `Engine::delivering` (a sealed fire owed, but an expired stranded notice): `Node::wait` adds it to status's answer. A fire goes with the last of its thing held, so nothing waits past what the node holds; one to a thing whose nodes this node never meets keeps the wait pending (to the caller's timeout).

## State
One rule, as read's (notes/sync-read.md, State): what status follows of a peer is the record's (its members of S and their class), kept across its connections; what is the connection's stays the connection's (caught up, full, reported positions, `until`, who it proved). S's sources are its members whose record a connection holds (`sources_of`). Keys: P a peer, E the engine or opens, N this node.

| State | Keys | Per | Bound (flood test) | Goes |
|---|---|---|---|---|
| `members` (S → source → class), `of_source` | opens' member-level `Moved` (E: a member opens only by proof that the peer may hold S) | record | members of the kept records in memory (`RECORD_BUDGET`) and of records kept nowhere (their connection) | the member closing (`Left`, `Gone`), `record_gone`; a record kept nowhere with its last member |
| `up` (source → connection, account, own node) | `Moved::Taken`/`Released` (E); who the peer proved from sessions | connection | connections | the release, `record_gone` |
| `lacking_fx`, `lacking` | (S, source) of a store member | record | store members | with the member |
| `leaving` (S, connection → source, `LeftAt`) | a member closing on a connection (E), with P's reported position and its `until` | connection | members closing in one step | each settle; a release keeps none (the next connection's Pull reports again) |
| `holding`, `own`, `own_feed`, `held_fx`, `held_pairs`, `unheld` (count per S), `by_commit`, `held`, `removals`, `release_fx` | E (the sync set, own commits by pair from `Engine::own_feed`, whole once per S read afresh; self-removals) | node | sync IDs held × own commits | S leaving the set, the commit no longer own |
| `wanted_fx`, `passes`, `pass_fx`, `again`, `done`, `modules_fx` | read S (E, leave, read) | node | read S | the pass's end, S leaving |
| pass start rows (durable, `Z/p/ s`: its wall time) | a pass of S beginning | node | passes under way | the pass's end; S leaving the sync set while no module wants its pass |
| `stranding_fx`, `strandings` | read S | node | read S | S not read |
| elsewhere rows (durable) | an entry of N's held at a source by P's stream or report | node | own entries | with the entry |

- Status sends no message of its own (a pass's fresh Pull goes through streams). What a peer controls reaches it only through streams and opens: a peer showing no credential is no member, a member whose credential stops being admissible ends or closes in the step of the change (notes/sync-opens.md, Judging), and a hostile reader can only claim positions (counted for held elsewhere, spec/sync-status.md §2).
- A restart changes nothing a user sees: nothing but the elsewhere rows and pass starts is durable, and no peer is a source before its connection takes its record.
- Seams: `status::Net` (read when asked) and `status::Ground: Net` (the settle's; `status/live.rs` the product's), so core/sync/tests/it/status.rs runs it on a fake.
- Tests: status.rs `a_reconnect_moves_no_member_spec_sync_status_1` (n and 10n), `a_taken_record_is_caught_up_per_connection_spec_sync_status_1`, `a_release_keeps_no_report_spec_sync_status_2`, `lacking_is_kept_per_record_across_connections_spec_sync_status_1`; idle.rs counts `status: members moved` at an idle reconnect.

## Self-removals
The rule is mod.rs's; the waits come from `Engine::waiting_removals` (notes/engine-lost-access.md Self-removal drops), "no peer but its own node" is `Ground::waited` (`Opens::waited` skipping a peer whose proven things include this node's node thing; notes/sync-opens.md Peers to wait for), and `Engine::removal_done` drops each thing lost that no other waiting removal is behind.
- The same rule as leaving (notes/sync-leave.md): it waits only while a peer could take it. Own nodes leave by the same commit, so counting them would leave two nodes of one account waiting on each other for good. Skipping them is safe because they learn the removal from this account's own sync IDs and inbox (spec/permissions.md §2), never only from S.
- `by_commit` is a plain map: a pair leaving it leaves `held_pairs`, which the judgement reads per (S, commit).
- Own commits come by pair (`Engine::own_feed`, each pair read as it stands with `own_has`), so one more own commit costs one pair, never the S's set (osis `minting::*`, `status: own commits taken`).
- Tests: status.rs `self_removal_*`, flows.rs `a_self_removal_*`, siblings.rs `a_siblings_self_removal_*`.

## Stranded
The rule is mod.rs's (`judge_strandings`: heard out and the engine's word, the report from `Engine::stranding`). The judgement reads the engine's word first and S's sources only where it could strand S, so a reconnect judges no other S. `SyncStatus::stranded` is that or unread's stranded.

## Caught up and passes
- **Caught up**: streams' `caught_since(conn, s)` gives the place (`Streams::pull_seq`) of the Pull the last reply answered, so a Pull answered moves only the passes. Two stamped parts: the connection's (`caught`, `SN_rearm`) and S's (`busy` per (connection, S), notes/sync-streams.md, Reports and caught up). One sync ID's traffic moves only its own key, so a commit judges one S's stranding, not every S shared on the connections its stream crosses. `track` keeps both: O(members busy there and events logged since its last read of the log).
- **A complete pass** reads `caught_since` against its start and asks `Streams::pull_again`. Opens lists `records_holding(store, s)` at a pass's start only.
- **Wants**: the engine's `pass_wanted(s)` (notes/sync-facade.md), leave's (`Leave::passes_wanted`, notes/sync-leave.md) and read's (`Read::passes_wanted`, notes/sync-read.md Outside S), merged by `Ground::module_passes`, all by pass place. A new want past a pass under way queues at most one more pass of S.
- A pass's place (`Engine::begin_pass`) is one count with role arrivals from elsewhere, so a pass begun before an arrival never counts after it, whatever the clock reads; kept per S (`Status::passed_since`, for leave and read). Its row goes with S leaving the sync set unless another module wants its pass: leave's release of a thing that left the node closure waits on a pass of each sync ID that carried it, which may have left too.
- **Across a restart** (mod.rs: the deadline from the row; `Ground::passes_begun`): every pass with a row begins again, wanted or not. Rejected: the deadline on the wall clock itself, judged by the latest reading: a wall clock frozen or set back while running holds the pass until it catches up. One begun again takes a new pass place, so it counts for every want from before the start: read re-judges at each start with its want at the place then (its waits are in memory), and a pass noted at its first place would never count for those, holding read's log for good. A want that arrived between the first start and the stop is served by that pass's remaining wait, short of a full `PASS_WAIT_MS` (the 0 end: a decision may miss what only an away peer holds). Tests: status.rs `a_pass_under_way_at_a_restart_ends_by_its_first_start_spec_sync_status_1`, `a_wall_clock_set_back_at_each_restart_still_ends_a_pass_spec_sync_status_1`, `complete_pass_gives_up_on_away_peer` (a frozen wall clock), `a_sync_id_leaving_takes_its_pass_and_row_spec_sync_status_1`; first.rs `restarts_hold_no_pass_past_its_wait_spec_sync_status_1`.
- Its end is told back by `note_complete_pass` only while the engine wants a pass of S, then `pass_end` on each of S's things (`sync_owners`): the engine re-seals and adds history once every sync ID of that thing had its pass (spec/permissions.md §3 Complete pass). A pass only leave or read wanted is not told: it would run those duties with no cause of the engine's.
- Model check: streams.rs `caught_up_matches_what_each_side_holds_plain_spec_sync_status_1` (a property) runs random histories against both sides' holdings.

## Readings
The spec's words are spec/sync-status.md §1-§2. Why a sync ID held by no other node holds no wait: a one-node account's home, whose sync unit carries everything it holds by strongs, would hold every wait on a thing for good; read by the engine's `others_may_hold` (S kept unread, or a holder of S's thing not held only by this node's own things: a thing with a key of its own that is not an own thing, or one some such thing holds).
- `wait` does not use `Opens::waited` (what leave and life read): a redeemer's first contact has no record before its dial completes, so the wait would end before the data came. The caller's timeout bounds a wait; a wait on a thing runs to its timeout while one sync ID carrying it some other node may hold is unconnected.

Kept in code only:
- Lacking applies to sources keeping S unread (a reader re-encrypts and judges what it keeps), counted as the stamped entries here its stream did not show (deposits offered are not counted).
- The heard-out half of a pass is "every waited source caught up since it began" (with none: vacuous), so a pass with no source waits only on its records and, while any, the peers to be waited for on S (`Opens::waited`, own nodes counted: a sync ID just joined waits for its other holders). A full or refusing source is not waited on in a pass.
- Stranded is per S (unread's for S kept unread, `strandings` for S read).
- `wait(All)` is every S held; a wait whose scope holds a stranded S answers `Waiting::Stranded`, which the osis API fails `Stranded` naming the S's owners (notes/api-design.md).

## Costs
A lacking count is taken again whole, O(S's stamped entries), at each change of what that source showed or of S's entries (issues/status-lacking-count.md).

## Not built
issues/sync-unbuilt.md (status): covered by a snapshot at a source (spec/sync-status.md §2: a body a source dropped under a snapshot before showing it never counts, an under-claim).

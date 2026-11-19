# What a node pays for holding many sync IDs
> Summary: Stage S1 of notes/redesign-plan.md. Briefs 1-2 are done: counted in debug tests at n and 10n sync IDs (core/sync/tests/it/idle.rs), an idle reconnect's deliveries, bytes, named judgements, members moved and store rows of streams, read, status and inbox are flat, and a small commit's work; opens carries no member at a take. Left: opens' filter reload (under a row per member), about 15 fixed rows per input (`Store::next_wake`'s scans), the first reconnect after first contact, and brief 3 (a first sync costs 4 deliveries and 47 KB per member, 23 KB of it sent back by the new reader, unexplained).
> Priority: normal
> Tags: sync, engine, perf

Every independent thing has a sync ID of its own, and a node holds one per independent thing it reaches, so work per sync ID held at a reconnect or a commit grows with the wrong thing (notes/principles.md, Fast by construction; spec/requirements.md Cost). Kept counts at n and 10n shared sync IDs: core/sync/tests/it/idle.rs (bytes of an idle reconnect; strandings and register plans judged at one; strandings at a commit; duties as time passes); the ignored `idle::probe_counts` prints every counter. No kept test counts a first sync.

## Counted
Method: `history::world(0, 3)`, script steps, `osis_base::costs`, `net.between`, `local_census`, store `scan_local`. idle.rs: node 0 makes 1 and 10 things (the `things` fixture), node 1 keeps each unread, node 2 reads each; per unit = difference / 9. The other rows are from throwaway tests at 6e38bcd03 on the sync harness (5 and 50 things, "flat"; one root with 4 and 40 members promoted from dependents, "closure"), whose row counts include the harness's own checks.

| | at n | at 10n | per unit | |
|---|---|---|---|---|
| Idle reconnect, writer and reader [idle.rs]: bytes | 2024 | 2044 | 2 | flat (integer widths) |
| same: `opens: members judged`, `opens standing`, `read: certificate blobs`, `status: stranded`, `status: members moved`, `inbox: register judged`, `inbox: members moved`, `inbox: offer judged`, `inbox: suspect sent`, `perm: roles walked`, `sync set: entered` | | | 0 | flat (`inbox: offer judged` 18 at n and at 10n: own deposits readied at each agreement and skipped where taken or not a store source) |
| same: store rows [idle.rs: `<- streams`, `<- read`, `<- status`, `<- inbox` flat, `<- opens` under a row per member, the total within that and a few inputs' fixed rows] | 831 | 871 | 4.4 | opens' filter 0.7 (below); the rest per node step, not per member: 2 more handled inputs at 10n (38 to 40), each reading about 15 fixed rows (`<- next wake` 8: `Store::next_wake`'s one-row scans; `<- driver store` 5; flush 1) |
| Idle reconnect, writer and node keeping all unread [idle.rs]: bytes | 2040 | 2028 | 0 | flat |
| same: the counters above, `status: lacking` | | | 0 | flat |
| same: store rows | 845 | 819 | 0 | flat |
| One small commit [idle.rs]: store rows / `status: stranded` | 1261 / 0 | 1270 / 0 | 1 / 0 | flat (an engine read per thing) |
| Reader restart, connected (flat): deliveries, bytes | 76, 5.7 KB | 82, 22.5 KB | 0.1, 373 B | bytes per sync ID; recount |
| First sync of a closure, reader: deliveries | 65 | 209 | 4.0 | constant high |
| same: bytes, both ways | 258 KB | 1955 KB | 47 KB, 23 KB of it reader to maker | role commits inherent (9.4 KB per independent thing, notes/thing-cost.md); the bytes sent back unexplained |
| same: signs / transactions / step verifications / stamp verifications | 54 / 243 / 81 / 76 | 327 / 1757 / 657 / 658 | 7.6 / 42 / 16 / 16 | to study |
| First sync of the root kept unread (one sync ID) | 111, 137 KB | 179, 754 KB | 1.9, 17 KB; 2 entries | |
| First sync by a newly paired node (flat), reader | 1550, 2.6 MB | 6126, 9.3 MB | 102, 148 KB world-wide | confounded: pairing rotates the account, which reaches every sync ID |

Held per sync ID, a thing with one small value granted to two accounts (flat, per unit, at 6e38bcd03): a node keeping it unread 37 store rows (4.3 KB), 12.2 entries naming 6.2 blobs of its own (35.9 KB), 8.6 engine rows (8.9 KB); a reader 48 store rows (5.2 KB), 14.2 entries, 8.2 blobs (43 KB), 40 engine rows (29.7 KB). About half a sync ID's entries name blobs held under other sync IDs too (certificate copies). Six rows of about 500 B exist per sync ID whatever it holds (`F/ H/ P/ Q/ U/ u/`, the path's 319 B the largest), plus 1.3 to 2 rows each of `T/ Y/ t/`.

Not established: what the reader sends back at a first sync; a first sync through a node keeping the closure unread only; whether the first sync's signs, transactions and verifications per member are inherent.

## Record-keyed state, as built
A kept record with a member stays in memory from its first take until it goes (evicted past `RECORD_BUDGET`, twin-dropped; one with none leaves memory when no connection holds it), its peer filter's entries dropped while no connection holds it and read again at its next take; opens gives `member_at` (stamped per (record, S), moved by no take or release) and `conn_of` ("record R is connected on C", stamped per record). Keyed by record and kept across its connections: J (`Holds::standing`, `Opens::followed`), register plans and progress, status's members of S and lacking counts (the connection per record from `Taken`/`Released`), read's owed acts, inbox's offers taken and suspect lists owed (notes/sync-status.md and notes/sync-inbox.md, State). A take or release is one fact (`Moved::Taken`, saying whether the record was just read from its rows, when the modules learn its members; `Released`); `Moved` is per member only for a member that opens, changes or closes. Each goes with S leaving the record or the sync set, or the record going (`flush` returns the records that went; the driver tells inbox and status, `record_gone`). What invalidates a record's member: J's reads moving (a removal or demotion, the account's key no longer counting: memo stamps), S's credentials or holding moving (`changed_at`), each judged in its step whether or not a connection holds the record (`Opens::judge`; a close with no connection is `Moved::Gone`, which drops the register keys and lacking count of (S, record)); what the record names moving at a take, or a take of a record read from its rows (a restart's: every member judged again); a step registered (the recorded path, a plan's read). Bound: the kept records with a member, all rows counted in `RECORD_BUDGET`; a hostile dialer makes a record per fresh key actor it proves (in memory only while connected), each evicting the least recently used past the budget (an honest record evicted costs its peer a first contact: a whole filter and every credential tested again), and gets a member only by proof that it may hold S.

## To fix
S1 briefs 1 (the join per shared sync ID at an idle reconnect) and 2 (the store rows behind an idle reconnect) are done: streams, read, status and inbox key what they keep by record and read the connection only where they send or ask; offers and suspect lists are owed per record as read's acts (go once the digests agree, done once taken, again on the next connection when refused or unanswered). Left:
- **Opens' filter reload**, 0.7 rows per member at an idle reconnect: the peer filter's entries are dropped while no connection holds the record and read again at its take (`records::filter_values`, O(filter rows), and a filter holds the shown credentials of every shared S). Keeping them costs up to 2^22 entries per record in memory (notes/sync-opens.md, Durability): a decision, not a defect, unless the filter is kept or tested without being read whole.
- **Fixed rows per input**, about 15 per handled input, per step and not per sync ID: `Store::next_wake` scans one row of each of four time indexes and the log's next due (8 rows) at every input; a kept next wake (updated where a time row or the log's due is written) would make it O(1), but those rows are written across the store's transaction code, so it is a store change of its own. `<- driver store` 5, flush 1.
- **The first reconnect after first contact** proves only the account where the record names the cards' key actors too, so it re-tests every credential and sends whole filters (spec/sync-opens.md §3): O(shared sync IDs) once per contact. Goes with A4 (accounts as ordinary things).
- **A first sync** (brief 3): opens found in one round should batch (spec/sync-streams.md §4 Joining): 4 deliveries per member now; and the 23 KB per member the new reader sends back.
- **A suspect list taken while its receiver waits for its own first sync**: answered Ok and kept in memory only (`Suspects::waiting`), so a receiver restart before that sync ends loses it until the sender's flags move (the sender owes it no more once taken). The receiver answers Ok whatever it judges (spec/wire.md §11.2).
- **Register goes on the record's connection** (`Net::conn_of`), not waiting for the digests to agree as offers, lists and read's acts do (spec/sync-opens.md §3 lists Pull, Fetch, Delete, Deposit item and Suspect).

## Rights ended while away
World tests (node 2 away from both, node 1 hears of the change from node 0, then meets node 2; node 2 away and back once first, since the first reconnect after first contact is a renamed take that judges every member and would hide a change not judged in its step), with the scripted tests that pin the judgement's step:
| How the right ends | What judges it with no connection | Test | Fails with |
|---|---|---|---|
| removal held, at a reader; at a node keeping S unread | standing (J departed) and the rotation's credentials; the registered step's credentials | `opens::a_removal_while_away_serves_nothing_after_it_spec_sync_opens_6` | no judgement while away |
| removal heard after a restart | the take of the record read from its rows | `opens::a_removal_after_a_restart_serves_nothing_after_it_spec_sync_opens_6` | the take not judging a record read from its rows |
| a grant's `until` passing | J at the until's wake (departed: a credential open stays, §4 Departed), then the finalize's rotation | `opens::an_until_passing_while_away_serves_nothing_after_it_spec_sync_opens_6` | no judgement while away |
| device revoked | none needed: back, node 2 proves its account at a closed epoch and resumes nothing holding S; with a key actor proven too, the take is renamed and judges | `opens::a_device_revoked_while_away_is_served_nothing_after_it_spec_sync_opens_6` | nothing (no row can exercise the in-place rule) |
| a proof (or sync key) open ending at a rotation | the credentials move; `until` is the position then | `opens::an_until_is_the_position_of_the_change_while_away_spec_sync_opens_6` (scripted) | no judgement while away |
| fork side switch, a late role commit making a removal valid | a J move like any other (memo reads of the role timelines) | `opens::standing_is_followed_per_record_across_connections_spec_sync_opens_6` (scripted: J departed while away) | no judgement while away |
S shredded while a reader of it is away (`Moved::Gone` on rows already gone): `opens::s_shredded_while_its_reader_is_away_spec_sync_opens_3`.

## Streams' state
Tabled in notes/sync-streams.md (State): connection state stays the connection's; the place, what the source showed and the class it keeps S as are the record's.

## Still to count
- Making n at once (sharing a tag of n notes): one keys commit and a sealed secret per holder each (a seal to a KEM key is over 1 KB), a genesis step each.
- Removing one reader from a thing that holds roles on n others: each of the n changes its keys (spec/permissions.md §3 Required rotation): commits, bytes, steps per store, what each remaining holder fetches.
- A first sync through a node keeping the closure unread only, and by a newly paired node without the pairing's own cost.
- Start-up and the closure walk with n sync IDs.

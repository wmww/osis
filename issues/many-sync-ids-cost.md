# What a node pays for holding many sync IDs
> Summary: Stage S1 of notes/redesign-plan.md. Counted in debug tests at n and 10n sync IDs: an idle reconnect's deliveries and bytes and a small commit's work are flat (core/sync/tests/it/idle.rs), but a reconnect still re-judges every shared member (about 52 store rows each with a reader, 95 with a node keeping them unread); a first sync costs 4 deliveries and 47 KB per member, 23 KB of it sent back by the new reader, unexplained. Fix those, then count what is still uncounted.
> Priority: normal
> Tags: sync, engine, perf

Every independent thing has a sync ID of its own, and a node holds one per independent thing it reaches, so work per sync ID held at a reconnect or a commit grows with the wrong thing (notes/principles.md, Fast by construction; spec/requirements.md Cost). Kept counts at n and 10n shared sync IDs: core/sync/tests/it/idle.rs (bytes of an idle reconnect; strandings and register plans judged at one; strandings at a commit; duties as time passes); the ignored `idle::probe_counts` prints every counter. No kept test counts a first sync.

## Counted (debug, main at 6e38bcd03, throwaway tests on the sync harness unless said)
Method: `history::world(0, 3)`, script steps, `osis_base::costs`, `net.between`, `local_census`, store `scan_local`. Sizes n and 10n: 5 and 50 independent things made by node 0, kept unread by node 1, read by node 2 ("flat"); and one root with 4 and 40 members promoted from dependents ("closure"). Per unit = difference / units added. The throwaway tests also counted store rows of the harness's own checks at quiet read and a time sweep reading a page of each index per step, so their row counts read high; idle.rs's worlds (2 and 20 things) count with caught up kept per (connection, S).

| | at n | at 10n | per unit | |
|---|---|---|---|---|
| Idle reconnect, writer and reader (flat): deliveries | 39 | 39 | 0 | flat |
| same, with a node keeping all unread: bytes [idle.rs] | 2088 | 2108 | 0.4 | flat (integer widths) |
| same, writer and reader [idle.rs]: store rows / `opens standing` / `read: certificate blobs` | 1267 / 24 / 40 | 2200 / 78 / 130 | 52 / 3 / 5 | **defect** |
| same, writer and node keeping all unread [idle.rs]: store rows / `inbox: register judged` / `status: lacking` / `perm: roles walked` | 1225 / 2 / 2 / 32 | 2928 / 40 / 40 / 160 | 95 / 2 / 2 / 7 | **defect** |
| One small commit (flat): deliveries, bytes | 29, 3926 | 29, 3926 | 0 | flat |
| same [idle.rs]: store rows / `status: stranded` | 1260 / 0 | 1278 / 0 | 1 / 0 | flat (an engine read per thing) |
| Reader restart, connected (flat): deliveries, bytes | 76, 5.7 KB | 82, 22.5 KB | 0.1, 373 B | bytes per sync ID; recount |
| First sync of a closure, reader: deliveries | 65 | 209 | 4.0 | constant high |
| same: bytes, both ways | 258 KB | 1955 KB | 47 KB, 23 KB of it reader to maker | role commits inherent (9.4 KB per independent thing, notes/thing-cost.md); the bytes sent back unexplained |
| same: signs / transactions / step verifications / stamp verifications | 54 / 243 / 81 / 76 | 327 / 1757 / 657 / 658 | 7.6 / 42 / 16 / 16 | to study |
| First sync of the root kept unread (one sync ID) | 111, 137 KB | 179, 754 KB | 1.9, 17 KB; 2 entries | |
| First sync by a newly paired node (flat), reader | 1550, 2.6 MB | 6126, 9.3 MB | 102, 148 KB world-wide | confounded: pairing rotates the account, which reaches every sync ID |

The throwaway tests at 6e38bcd03 also counted, per sync ID, an idle reconnect's Pull naming a join with an 80-byte cursor (108 B with a reader, 143 B with a node keeping them unread, against spec/sync-streams.md §4 Costs and Joining) and 314 to 369 store rows, and a small commit's 234 store rows (437 in the closure world); the idle.rs rows above are what holds on main: the joins and the commit's work are flat there.

Held per sync ID, a thing with one small value granted to two accounts (flat, per unit): a node keeping it unread 37 store rows (4.3 KB), 12.2 entries naming 6.2 blobs of its own (35.9 KB), 8.6 engine rows (8.9 KB); a reader 48 store rows (5.2 KB), 14.2 entries, 8.2 blobs (43 KB), 40 engine rows (29.7 KB). About half a sync ID's entries name blobs held under other sync IDs too (certificate copies). Six rows of about 500 B exist per sync ID whatever it holds (`F/ H/ P/ Q/ U/ u/`, the path's 319 B the largest), plus 1.3 to 2 rows each of `T/ Y/ t/`.

Not established: what the reader sends back at a first sync; a first sync through a node keeping the closure unread only; whether the first sync's signs, transactions and verifications per member are inherent.

## To fix
- **A reconnect re-judges every member.** A connection taking a record re-adds each member (opens `take`: `member_moved`, `holding`, a `Moved::Joined` and `rejudge` per member; `release` a `Moved::Left` per member), and every consumer keys its per-member state by connection, as spec/sync.md §2 allows and spec/sync-opens.md §6 asks ("a member is re-judged when a connection takes a record"). By consumer:
  - opens standing (core/sync/src/opens/holds.rs `standing`, keyed (connection, S)): J is a function of the peer's named actors and S, so key it by (record, S), followed while the record is in memory; spec/sync-opens.md §6 then says a member is judged when its standing, credentials or this node's sync set move.
  - certificate blobs (core/sync/src/read/mod.rs `cert_blobs`, `Ground::cert_blobs_missing`): `gone` reads every source's stream and `deletes` names each store source by `ConnId`; keyed by record (`Source`) and read only where the own store's blobs leave something to delete or forget, a reconnect moves none.
  - inbox register plans and progress (core/sync/src/inbox/register.rs, keyed (connection, S)) and lacking counts (core/sync/src/status/mod.rs `lacking_fx`, keyed (S, connection)): facts of the record, so keyed by record they survive a reconnect.
  - `Moved` per member: streams' `holders`, status' `sources`, read's `Views`, inbox's offers and suspects. The structure: the record holds its shared set; a connection takes it whole by one fact (record R is connected on C), read through the record only where needed.
  - engine `things_entered` (core/engine/src/sync/set.rs) re-wants every followed link at each follow that is not quiet (`sync set: entered`, 2 per thing at a reconnect): a feed of links followed and unfollowed would want only those.
- **The first reconnect after first contact** proves only the account where the record names the cards' key actors too, so it re-tests every credential and sends whole filters (spec/sync-opens.md §3): O(shared sync IDs) once per contact. Goes with A4 (accounts as ordinary things).
- **A first sync**: opens found in one round should batch (spec/sync-streams.md §4 Joining): 4 deliveries per member now; and the 23 KB per member the new reader sends back.

## Still to count
- Making n at once (sharing a tag of n notes): one keys commit and a sealed secret per holder each (a seal to a KEM key is over 1 KB), a genesis step each.
- Removing one reader from a thing that holds roles on n others: each of the n changes its keys (spec/permissions.md §3 Required rotation): commits, bytes, steps per store, what each remaining holder fetches.
- A first sync through a node keeping the closure unread only, and by a newly paired node without the pairing's own cost.
- Start-up and the closure walk with n sync IDs.

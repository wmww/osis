# What a node pays for holding many things with their own sync ID
> Summary: Central since a closure is many sync IDs (notes/sync-unit-scope.md). Partly counted (notes/sync-unit-design.md §8): an idle reconnect's round trips and bytes do not grow, but it re-judges every shared member (about 75 store rows each); a small commit re-judges the stranding of every sync ID on the connections its stream crosses (caught up is kept per connection); a first sync costs about 4 deliveries and 47 KB per unit. Left: those two redesigns, the first-sync batching, and counting making many at once, a removal's cascade and start-up.
> Priority: normal
> Tags: sync, engine, perf

Nothing bounds how many sync IDs one commit is carried under today; with a unit being one independent thing and its dependents a commit is under one per unit it writes.

No kept test counts an idle reconnect, a commit or a first sync at n and 10n shared sync IDs (`opens::a_reconnect_costs_the_same_at_n_and_10n` varies unshared ones): §8's growth came from a throwaway test; each fix lands with its count.

## Counted (debug, at n and 10n; tables and method in notes/sync-unit-design.md §8)
- **Idle reconnect** (nothing out of date; core/sync/tests/it/idle.rs at 2 and 20 things): deliveries and bytes flat. Per shared sync ID: about 75 store rows read, 7 `status: stranded`, 3 each of `inbox: register judged`, `opens standing` and `sync set: entered`, 5 `read: certificate blobs`.
- **The first reconnect after first contact** proves only the account where the record names the cards' key actors too, so it re-tests every credential and sends whole filters (spec/sync-opens.md §3: other actors than the record names): O(shared sync IDs) once per contact.
- **One small commit**: deliveries and bytes flat. Per sync ID held: about 11 store rows read and 6 `status: stranded` (`idle::repro_a_commit_judges_one_stranding`); no duty judgement (`life:`) per thing.
- **A reader's restart while connected**: 373 B per sync ID (measured before the idle fixes; recount).
- **First sync of a closure** (a root with n independent members, the built model): per member 4.0 deliveries, 47 KB (23 KB of it sent by the new reader back to the maker, unexplained), 7.6 signs, 42 transactions, 16 step verifications and 16 stamp verifications. Kept unread under the root's one sync ID: 1.9 deliveries, 17 KB, 2 entries per member.
- **Held per sync ID** with one small value and two grants: a node keeping it unread 37 store rows (4.3 KB) and 6.2 blobs (35.9 KB); a reader 48 rows (5.2 KB), 8.2 blobs (43 KB) and 29.7 KB of engine rows. Six rows of about 500 B exist per sync ID whatever it holds. About half of a sync ID's entries name blobs also held under other sync IDs (certificate copies).

## To fix (each grows with the wrong thing: notes/principles.md, Fast by construction)
- **Caught up per connection.** Streams keeps a source caught up per connection (`caught: StampedSet<ConnId>` and `caught_at` in core/sync/src/streams/mod.rs `track`), as spec/sync-status.md §1 defines it over the whole stream; every S's stranding (core/sync/src/status/mod.rs `judge_strandings`), status and heard out read it. A stream crossing a connection for one S (a push in hand, a message served and not yet Applied) flips the connection, and each S shared there is judged again. The design: caught up per (connection, S): S is busy on a connection while an event of S is in hand there (a pending batch, its bodies owed), served and not yet reported Applied, or logged and not yet pushed; what is per connection (a Pull out, a gap, no reply yet) stays per connection. spec/sync-status.md §1 changes to say it per S; passes (`caught_since`) and waits follow.
- **A reconnect re-judges every member.** A connection taking a record re-adds each member one by one (opens `take`, then a `Moved::Joined` per member), and each member's status sources (left, then joined), register plans, standing (spec/sync-opens.md §6: re-judged when a connection takes a record), stranding and certificate-blob checks are judged again: O(shared set) per reconnect, as spec/sync.md §2 allows ("the connections whose shared set it changes"). Flat needs the shared set held by the record: a connection takes the record's membership whole, per-member state (sources, register plans, stream places already) keyed by the record, and the record's being connected one fact that the per-S judgements read only where they depend on it.
- The deliveries per unit at a first sync: opens found in one round should batch (spec/sync-streams.md §4 Joining).

## Still to count
- **Making n at once** (sharing a tag of n notes): one keys commit and a sealed secret per holder each (a seal to a KEM key is over 1 KB), a genesis step each.
- **Removing one reader from a thing that holds roles on n others**: each of the n changes its keys (spec/permissions.md §3 Required rotation). Commits, bytes, steps registered per store, and what each remaining holder fetches.
- **A first sync through a node keeping the closure unread only**, and a first sync by a newly paired node without the pairing's own cost (measured together: 102 deliveries and 148 KB per sync ID world-wide, the account's rotation reaching every sync ID).
- **Start-up and the closure walk** with n units.

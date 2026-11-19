# What a node pays for holding many things with their own sync ID
> Summary: Central since a closure is many sync IDs (notes/sync-unit-scope.md). Partly counted (notes/sync-unit-design.md §8): an idle reconnect's round trips and bytes do not grow, but it reads about 370 store rows per shared sync ID, a small commit reads 230-440 more store rows per sync ID held, and a first sync costs about 4 deliveries and 47 KB per unit. Left: fix those by design, and count making many at once, a removal's cascade and start-up.
> Priority: normal
> Tags: sync, engine, perf

Nothing bounds how many sync IDs one commit is carried under today; with a unit being one independent thing and its dependents a commit is under one per unit it writes.

No kept test counts an idle reconnect, a commit or a first sync at n and 10n shared sync IDs (`opens::a_reconnect_costs_the_same_at_n_and_10n` varies unshared ones): §8's growth came from a throwaway test; each fix lands with its count.

## Counted (debug, at n and 10n; tables and method in notes/sync-unit-design.md §8)
- **Idle reconnect** (nothing out of date): deliveries and bytes flat (core/sync/tests/it/idle.rs). Local work grows: about 370 store rows read, 7 `status: stranded`, 3 `inbox: register judged`, 3 `opens standing`, 10 `perm: roles walked` per shared sync ID.
- **The first reconnect after first contact** proves only the account where the record names the cards' key actors too, so it re-tests every credential and sends whole filters (spec/sync-opens.md §3: other actors than the record names): O(shared sync IDs) once per contact.
- **One small commit**: deliveries and bytes flat (29; 3926 B over three nodes). Local work grows with the sync IDs held: 234 store rows read per sync ID (437 in a closure of nested things), 7 `status: stranded`, 1 each of `life: lost access` and `life: role duty owed`.
- **A reader's restart while connected**: 373 B and about 1280 store rows read per sync ID.
- **First sync of a closure** (a root with n independent members, the built model): per member 4.0 deliveries, 47 KB (23 KB of it sent by the new reader back to the maker, unexplained), 7.6 signs, 42 transactions, 16 step verifications and 16 stamp verifications. Kept unread under the root's one sync ID: 1.9 deliveries, 17 KB, 2 entries per member.
- **Held per sync ID** with one small value and two grants: a node keeping it unread 37 store rows (4.3 KB) and 6.2 blobs (35.9 KB); a reader 48 rows (5.2 KB), 8.2 blobs (43 KB) and 29.7 KB of engine rows. Six rows of about 500 B exist per sync ID whatever it holds. About half of a sync ID's entries name blobs also held under other sync IDs (certificate copies).

## To fix (each grows with the wrong thing: notes/principles.md, Fast by construction)
- Per-sync-ID work at a reconnect with nothing out of date and at a commit on one sync ID (`status: stranded`, `inbox: register`, `opens standing`, the store rows behind them).
- The deliveries per unit at a first sync: opens found in one round should batch (spec/sync-streams.md §4 Joining).

## Still to count
- **Making n at once** (sharing a tag of n notes): one keys commit and a sealed secret per holder each (a seal to a KEM key is over 1 KB), a genesis step each.
- **Removing one reader from a thing that holds roles on n others**: each of the n changes its keys (spec/permissions.md §3 Required rotation). Commits, bytes, steps registered per store, and what each remaining holder fetches.
- **A first sync through a node keeping the closure unread only**, and a first sync by a newly paired node without the pairing's own cost (measured together: 102 deliveries and 148 KB per sync ID world-wide, the account's rotation reaching every sync ID).
- **Start-up and the closure walk** with n units.

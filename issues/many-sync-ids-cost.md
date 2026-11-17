# What a node pays for holding many things with their own sync ID
> Summary: Perf investigation, not started. Under the reference graph (spec/sync-set.md §2) sharing a tag of notes gives every note its own keys and sync ID, so a node holding tens of thousands of sync IDs is ordinary use. The protocol's idle cost is stated not to grow with them (spec/sync-streams.md §4 Costs); a node's local work, the cost of making them and key changes cascading through them are unmeasured. Count each at n and 10n.
> Priority: normal
> Tags: sync, engine, perf

Nothing bounds how many sync IDs one commit is carried under (nothing limits the sync units a thing is in): measure that too.

To count (work, in a debug test, at n and 10n sync IDs; no timing runs: notes/principles.md, Check scaling):
- **A node's local work per connection** with nothing out of date: the agreement digest over the shared set and the filter (spec/sync-opens.md §3, §5), what is read per member at a reconnect, what a pass's end does per sync ID.
- **Making n of them at once** (sharing a tag of n notes): one keys commit and a sealed secret per holder each (a seal to a KEM key is over 1 KB), a genesis step each, a ticket each for a holder that is not carried them.
- **Removing one reader from a thing that holds roles on n others**: each of the n changes its keys (spec/permissions.md §3, the rotations required through a holder actor). Commits, bytes and what each remaining holder fetches.
- **Storage held per sync ID with no content**: steps, claim sets, store rows, record members per peer.
- **Start-up and the closure walk** with n pieces.

Each count that grows faster than n, or that is paid while nothing changes, gets its own issue and a fix by design (notes/principles.md, Fast by construction).

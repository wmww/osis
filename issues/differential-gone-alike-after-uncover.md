# Sync differential: writes gone alike under a cover that turned invalid
> Summary: Every node reads an older value than the reference when all of them dropped a write's body under a snapshot whose author's write role a concurrent role change overrode; the rule accepts that (gone alike, notes/revocation.md), the differential's oracle has no excuse for it.
> Priority: normal
> Tags: sync, tests

Shape (a shrunk script; it pairs nodes, so it replays only after accounts piece 3): node 3 grants node 1's account Writes while node 2 grants it Reads, the roster settling at Read. Node 1, holding Writes for a while, snapshots thing 0, carrying v7. Nodes 0 and 3 drop v7's body and their own later snapshot's as covered by it, then judge node 1's snapshot invalid. No valid body carrying v7 is left; every node reads v4, the reference (handed every commit whole) reads v7.

A body dropped under a cover that later turns invalid comes back from any copy and with none left is gone at every node alike (notes/revocation.md; issues/drop-rejoin-robust.md). Open: an excuse computed from the history (a value write some node snapshotted while a concurrent role change was undoing its write right, held by no node at the check, as `lost_writes` does for releases), or a reason the drop should not happen (a cover from a writer whose role is contested not yet trusted).

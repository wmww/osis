# Sync differential: writes gone alike under a cover that turned invalid
> Summary: every node reads an older value than the reference when all of them dropped a write's body under a snapshot whose author's write role a concurrent grant overrode; notes/revocation.md accepts that (gone alike), the differential's oracle has no excuse for it. Seen on one world of 50 for a shrunk script, not on 120 property seeds.
> Priority: normal
> Tags: sync, tests

Replay in a scratch test (notes/sync-test-harness.md, Replaying a script) on world 32 (`OSIS_SYNC_START=32 OSIS_SYNC_SEEDS=1`; it moves with commit bytes); 1 failing world of 0..50:
`New(0), Pair(0), Write(3, 0), Run, Lossy(Loss { drop: 0, dup: 0, delay: 200, delay_ms: 5000 }), Give(2, 0, Holder::Node(1), Syncs), Partition(0, 2), Strong(1, None, 0), Give(0, 0, Holder::Node(1), Reads), Revoke(0, 0, Holder::Node(1)), Write(3, 0), Run, Run, Give(2, 0, Holder::Node(1), Syncs), Write(3, 0), Run, Write(3, 0), Write(0, 0), Give(2, 0, Holder::Node(1), Syncs), Give(2, 0, Holder::Node(1), Reads), Give(3, 0, Holder::Node(1), Writes), Write(3, 0)`

What happens (probed with `Engine::body_page` per node and on the reference):
- Node 3 grants node 1's account Writes while node 2 grants it Reads; the roster settles at Read.
- Node 1, holding Writes for a while, compacts thing 0: its snapshot carries v7. Nodes 0 and 3 drop v7's body and their own later snapshot's as covered by it (`covered by a held snapshot`), then judge node 1's snapshot invalid. No valid body carrying v7 is left anywhere; node 1 holds v7 only inside its invalid snapshot.
- Every node reads v4 (an older snapshot by account 0 dated after v7). The reference, handed every commit whole, never dropped v7 and reads it: `node 0 reads thing 0 unlike the reference`.

notes/revocation.md (accepted) and issues/drop-rejoin-robust.md say a body dropped under a cover that later turns invalid comes back from any copy and with none left is gone at every node alike: the nodes follow the rule, the oracle does not know it. Open: an excuse computed from the history (a value write some node's account snapshotted while a concurrent role change was undoing its write right, held by no node at the check, as `lost_writes` does for releases), or a reason the drop should not happen (a cover from a writer whose role is contested not yet trusted).

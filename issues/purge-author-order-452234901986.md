# A body dropped while invalid, valid again and purged before its refetch has no leftover
> Summary: Design question. A node that drops a delta as invalid, then sees it turn valid and purged in one step, holds it "missing when purged" (never received, not fetched), so it reads the older value; a node that held the body holds its leftover, whose value-less write wins, and reads absent. Found by `order::arrival_order_purge_author_large_spec_perm_6` seed 452234901986.
> Priority: normal
> Tags: engine, retention, tests

Replay: `OSIS_ORDER_SEED=452234901986 OSIS_ORDER_LEN=50 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_purge_author_large_spec_perm_6`.

Minimal case (thing G, register under permanent retention):
- 0 lowers 2 to read (frontier lists none of 2's writes), then grants 2 write again.
- 2 writes `m1` (D), then purges its own deltas by author (P).
- A fresh node gets G and the identities, D, the lowering, P, then the re-grant. D arrives invalid (2 holds read) and is dropped (spec/permissions.md §6 Invalid). The re-grant makes D and P valid in one re-judgment: `valid_again` makes D missing, then `rejudge_purges` purges it, and `make_leftover` drops a missing part (`DropFor::Other`: "a part missing when purged", spec/commits.md §5 Never received: not fetched on its own).
- The fresh node reads G's `"g"`. A node that held D when P applied, in any order, holds D's leftover: its value-less write beats `"g"` and the register reads absent (spec/crdt.md §4.7).

Both follow the spec as written, so the oracle (keep-everything node, same commits) and the fresh node disagree for good: a leftover is never uploaded and the purger's hosts delete D, so only a writer's later compaction (its snapshot carries D's write value-less) brings them together. The subtle property: a purged delta still shapes reads through its leftover, but whether a node has that leftover depends on whether it held the body when the purge took it.

Options:
1. Count a part missing when purged as missing (fetched where present; a copy is held as its leftover, as `takes_late` already allows). One state instead of two for "a copy would join". Converges in the harness (its host keeps every pack); in the network it converges only where a host still has the body.
2. Accept it (spec/permissions.md §6: a body no node holds stays gone) and have the order harness spare such aspects, computed from the history. A carve-out in the oracle; needs a validity model of the arrival order.
3. A purged delta's own writes leave the state at every node (no value-less write of its own, unlike expiry), so holding the body changes nothing. Changes spec/crdt.md §4.7 for purges; a purge that does not reset (the API's purge by author writes `purge.0` only) then shows the older value everywhere.

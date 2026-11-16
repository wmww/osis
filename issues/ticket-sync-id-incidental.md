# Two things' ticket sync ID test holds only at one rng stream
> Summary: engine `tickets::a_sync_id_two_things_tickets_name_is_judged_for_each_spec_sync_inbox_5` passes on main only as its history is: one extra commit by peer 0 before it makes A and B (any content, so only tids and commit IDs move) and A's entries never open under B's sync ID; incidental dependence on tids or commit order, cause not found.
> Priority: normal
> Tags: engine, sync, tests

Reproducer (main): in that test, after `people(2)`, have peer 0 commit a weak in its account root's `holds.0` (once, or several times): `assert!(... "A's entries open under B's sync ID")` fails; opening each of A's entries under `sb` gives `Opened::NotOpen` however many rounds are tried. With the history as written it passes. The rule it checks (spec/sync-inbox.md §5 Ticket sync IDs: an entry arriving under a sync ID several things' tickets name is judged for each) must not depend on tids or commit IDs, so either the test reaches its case by accident or the engine judges by an incidental order.

KNOWN in tools/known_failures.txt meanwhile (the needed-by-reference harness's introductions are such a commit).

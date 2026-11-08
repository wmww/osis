# Gap snapshots: `t:gonemap.0` states differ between nodes
> Summary: `waits::gap_snapshots_converge_large_spec_crdt_8` fails 8 of 300 seeds at its own default range (1056, 1084, 1127, 1154, 1165, 1218, 1273, 1286) and 8 of 300 from 200958076497, plus 144758 at plain size from 144731, all on `t:gonemap.0` (a map entry's key and value present on one node, a key-less, value-less entry on the other). Per-branch size (1000..1030) misses them. Fails on e3cdd005f and 8f3cd8d05; 144758 also on 0c75228bc.
> Priority: normal
> Tags: engine, retention, tests

Expected fixed by notes/expiry-creation-design.md step 3 (no whole-dot key move); these seeds are its acceptance check.

Replay (under 1 s): `OSIS_ORDER_START=1056 OSIS_ORDER_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact waits::gap_snapshots_converge_large_spec_crdt_8`. `t:gonemap.0` is the aspect whose entries are removed (purge on replace); likely the same family as issues/swept-hidden-write-uncoverable.md (an edit into a removed entry recreating it in a snapshot), which a fixer should rule in or out first.

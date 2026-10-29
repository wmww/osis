# Ephemeral data: one state system for an app
> Summary: Tracking issue for ephemeral data (in-memory things and schema-declared aspects; synced as ordinary signed commits marked ephemeral and kept in memory at nodes and servers; a `presence` lifetime tied to the author's connection; signals folded in as `signal` aspects). The design is notes/ephemeral.md, revised after two owner reviews, with a four-step plan; steps 1-3 built, step 4 (presence) left.
> Tags: api, node, sync

Design and plan: notes/ephemeral.md (owner direction and reviews recorded there).

## Owner reviews applied
- Round 1: flags kept; ephemeral placements approved; state held by every holder, outlives its author, merges on reconnect; `presence` opt-in; `MAX_LEASE` 20 min, keep-alive 15 min as a backstop; no convergence exemption.
- Round 2: `signal`, not `event`; ephemeral data like ordinary data, history "don't care"; simplification pass done: synced ephemeral data reuses commits, validity, sync and the server path (14 synced-only mechanisms down to 5; no new message types).
- Round 3: no signal window: a signal is an ephemeral commit marked relay-only, pushed to current subscribers and held by nobody; late joiners see only ephemeral state.

## Decisions to glance at (no answer needed unless one is wrong)
- Presence crosses servers and member peers that serve the label, but not a client node bridging two servers (relaying would keep a departed author's values up).
- Per-label caps on ephemeral bytes at servers and nodes: past them, that label's ephemeral data stops syncing or converging there (a defined outcome against a hostile writer); compaction frees the server cap.

## Status
- Steps 1 (local ephemeral things and aspects), 2 (ephemeral placements, undo) and 3 (ephemeral commits, relay-only signals, the old signal path deleted) built (notes/ephemeral.md Step 1/2/3 as built); step 4 (presence) not started. Step 3's open items (unsync and lost access keep state until restart, unpaged deltas only, no coalescing or relay delay) are listed there.

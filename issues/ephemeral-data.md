# Ephemeral data: one state system for an app
> Summary: Tracking issue for ephemeral data (in-memory things and schema-declared aspects; synced as ordinary signed commits marked ephemeral and kept in memory at nodes and servers; a `presence` lifetime tied to the author's connection; signals folded in as `signal` aspects). The design is notes/ephemeral.md, revised after two owner reviews, with a four-step plan; step 1 (local) is being built.
> Tags: api, node, sync

Design and plan: notes/ephemeral.md (owner direction and reviews recorded there).

## Owner reviews applied
- Round 1: flags kept; ephemeral placements approved; state held by every holder, outlives its author, merges on reconnect; `presence` opt-in; `MAX_LEASE` 20 min, keep-alive 15 min as a backstop; no convergence exemption.
- Round 2: `signal`, not `event`; ephemeral data like ordinary data, history "don't care"; simplification pass done: synced ephemeral data reuses commits, validity, sync and the server path (14 synced-only mechanisms down to 5; no new message types).

## Decisions to glance at (no answer needed unless one is wrong)
- Presence crosses servers and member peers that serve the label, but not a client node bridging two servers (relaying would keep a departed author's values up).
- `SIGNAL_WINDOW` 60 s default (per aspect by `expires`): a joiner within it still gets a recent signal; a node restarting within it may deliver one twice.
- Per-label caps on ephemeral bytes at servers and nodes: past them, that label's ephemeral data stops syncing or converging there (a defined outcome against a hostile writer); compaction frees the server cap.

## Status
- Step 1 of notes/ephemeral.md: in progress. Steps 2-4: not started.

# Ephemeral data: one state system for an app
> Summary: Tracking issue for ephemeral data (in-memory things and schema-declared aspects; synced as ordinary signed commits marked ephemeral and kept in memory at nodes and hosts; values that live while their author is there are expiring writes the author renews (`osis::KeepAlive`, no lifetime of their own); signals folded in as `signal` aspects). The design is notes/ephemeral.md, revised after two reviews by Tess, with a four-step plan, all built.
> Tags: api, node, sync

Design and plan: notes/ephemeral.md (Tess's direction and reviews recorded there).

## Tess's reviews applied
- Round 1: flags kept; ephemeral placements approved; state held by every holder, outlives its author, merges on reconnect; `presence` opt-in (since replaced: an expiring ephemeral write its author renews, notes/ephemeral.md Values that live while their author is there); no convergence exemption.
- Round 2: `signal`, not `event`; ephemeral data like ordinary data, history "don't care"; simplification pass done: synced ephemeral data reuses commits, validity, sync and the host path (14 synced-only mechanisms down to 5; no new message types).
- Round 3: no signal window: a signal is an ephemeral commit marked relay-only, pushed to current subscribers and held by nobody; late joiners see only ephemeral state.

## Decisions to glance at (no answer needed unless one is wrong)
- Per-label caps on ephemeral bytes at hosts and nodes: past them, that label's ephemeral data stops syncing or converging there (a defined outcome against a hostile writer). Only an author compacts, its own commits (own covers), keeping them within about twice its state: a host cap of twice the sum of the authors' states holds everything; past it, the entries that arrived when it was full stay out there (first come, first served) with a diagnostic.

## Status
- Steps 1 (local ephemeral things and aspects), 2 (ephemeral placements, undo) and 3 (ephemeral commits, relay-only signals, the old signal path deleted) and 4 (presence, since replaced by renewed expiring writes) built (notes/ephemeral.md Step 1-4 as built). Step 3's open items (unsync and lost access keep state until restart, unpaged deltas only, no coalescing or relay delay) are listed there.

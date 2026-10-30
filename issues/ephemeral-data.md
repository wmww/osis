# Ephemeral data: one state system for an app
> Summary: Tracking issue for ephemeral data (in-memory things and schema-declared aspects; synced as ordinary signed commits marked ephemeral and kept in memory at nodes and servers; a `presence` lifetime tied to the author's connection; signals folded in as `signal` aspects). The design is notes/ephemeral.md, revised after two owner reviews, with a four-step plan, all built.
> Tags: api, node, sync

Design and plan: notes/ephemeral.md (owner direction and reviews recorded there).

## Owner reviews applied
- Round 1: flags kept; ephemeral placements approved; state held by every holder, outlives its author, merges on reconnect; `presence` opt-in; `MAX_LEASE` 20 min, keep-alive 15 min as a backstop; no convergence exemption.
- Round 2: `signal`, not `event`; ephemeral data like ordinary data, history "don't care"; simplification pass done: synced ephemeral data reuses commits, validity, sync and the server path (14 synced-only mechanisms down to 5; no new message types).
- Round 3: no signal window: a signal is an ephemeral commit marked relay-only, pushed to current subscribers and held by nobody; late joiners see only ephemeral state.

## Decisions to glance at (no answer needed unless one is wrong)
- Presence crosses servers and member peers that serve the label, but not a client node bridging two servers (relaying would keep a departed author's values up). A member peer serves presence to its sessions but uploads none of theirs to its servers (it could not delete it there when the session leaves), so a device reachable only through a member peer is not seen by the server's devices. Owner call: the protocol now has the untie primitive (an upload's tie-only replacement, spec/sync.md §5 Replace); what is missing is a standalone release (untie without a new entry) and the policy of a peer uploading its sessions' presence.
- Per-label caps on ephemeral bytes at servers and nodes: past them, that label's ephemeral data stops syncing or converging there (a defined outcome against a hostile writer). Only an author compacts, its own commits (own covers), keeping them within about twice its state: a server cap of twice the sum of the authors' states holds everything; past it, the entries that arrived when it was full stay out there (first come, first served) with a diagnostic.

## Status
- Steps 1 (local ephemeral things and aspects), 2 (ephemeral placements, undo) and 3 (ephemeral commits, relay-only signals, the old signal path deleted) and 4 (presence) built (notes/ephemeral.md Step 1-4 as built). Step 3's open items (unsync and lost access keep state until restart, unpaged deltas only, no coalescing or relay delay) are listed there.

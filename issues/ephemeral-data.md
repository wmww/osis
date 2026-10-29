# Ephemeral data: one state system for an app
> Summary: Tracking issue for ephemeral data (in-memory things and schema-declared aspects held by every node syncing them, merging on reconnect; a `presence` lifetime tied to the author; signals folded in as `event` aspects). The design is notes/ephemeral.md, revised after owner review, with a five-step plan; nothing built yet. Waits on the commit-query API work.
> Tags: api, node, sync

Design and plan: notes/ephemeral.md (owner direction and review recorded there).

## Owner review applied
Flags `ephemeral`/`event` kept; ephemeral placements approved (side effects listed in the note's Model); ephemeral state is ordinary CRDT state held by every holder, outlives its author, merges on reconnect, served to joiners by any holder; dying with the author is the `presence` flag; `MAX_LEASE` 20 min and keep-alive 15 min as a presence-only backstop; no convergence exemption.

## Decisions to glance at (no answer needed unless one is wrong)
- Holders answer a joiner with merged state judged by their own rights (as compaction snapshots): only writers answer; a reader can still bridge by forwarding authors' bodies verbatim. A writer can forge others' ephemeral writes, the same class as snapshots.
- The per-label growth cap (default 16 MiB, config): past it a node stops taking that label's ephemeral data until restart or unsync, so that label stops converging there (a defined outcome against a hostile writer).
- Third flag name `presence` for the author-tied lifetime.

## Status
- Steps 1-5 of notes/ephemeral.md: not started.

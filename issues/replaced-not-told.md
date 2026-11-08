# A part replaced with no history kept is not told leaving the listing
> Summary: A commit listener hears a commit when its parts' meta changes (applied, validity, dropped, purged, fetched), not when a later write replaces a part that keeps no history and so drops it from the listing: a page read shows it, a listener showing a list keeps it until the body is compacted. Telling it exactly needs the commits whose liveness a transaction flipped, which no index gives cheaply.
> Priority: normal
> Tags: engine, api

notes/listener-design.md asks for one call per commit whose listed form reads otherwise. Built: `Core::commit_changes` journals `(valid, dropped, stripped, missing)` per part, so a listing change by replacement (`body_live` turning false on a part past its keep bound) is told only when the body later drops (compaction). Same for a keep bound passing without a drop.

Options: at a transaction's end, for each aspect whose state changed under a commit listener, re-judge the held unkept parts there and tell those that left (O(held unkept parts) per write, bounded by compaction; a cache of last-told liveness per part); or have the apply path report the writes a join killed (deaths) and map them to bodies. Either needs the engine to know which aspects have listeners, or pays for every write while any listener exists.

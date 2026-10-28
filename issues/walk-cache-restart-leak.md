# A saved walk under a non-root thing survives a restart
> Summary: When a component's root moves (a thing with a smaller tid joins), the walk saved under the old root is retired in memory only; if the node restarts before the next `to_save`, `Timelines::restore` stops at the first saved walk it finds (the new root's, or uses the old one with j > 0 only when the root has none) and never retires the old key, so it stays in the walk cache for good. Disk only, results unaffected.
> Tags: perm, node

Repro: `incremental::creation_fast_equals_general_large` with `save_checked`'s `stale` exemption removed (fails e.g. at shard seed 0x9005eed0a02 sample 38).

Fix ideas: persist retirements with the root change (write the delete in the same batch as the next commit), or have `restore` (or a startup pass) delete saved walks under things that are not their component's root.

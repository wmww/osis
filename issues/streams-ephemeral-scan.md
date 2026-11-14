# Any ephemeral change reads every listed member's memory part on every connection
> Summary: serving pushes the ephemeral listing when the store's memory mark moves; `Streams::ephemeral` then calls `read_memory` for each member listed on that connection, so one ephemeral write costs O(connections × members) instead of the members it touched.
> Priority: normal
> Tags: sync, performance

core/sync/src/streams/serve.rs `push` → `ephemeral`. The memory part is ordered by one counter per sync ID; a node-wide memory read after a mark (like `read_log` over the durable log, filtered by the shared set per event) would cost the events since the mark. Needs a store call reading the memory part across sync IDs after a node-wide counter.

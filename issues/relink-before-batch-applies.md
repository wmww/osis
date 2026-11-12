# Chunk repair judges before its batch applies

> Summary: `log_events_from` runs `relink_lost` on a batch's chunk deletions before the batch's own commit blobs are stored and opened, so a role commit or purge arriving in the same batch as the deletes it justifies does not stop a repair that rewrites purged content.
> Priority: normal
> Tags: node-sync

Repair (spec/sync.md §1) rewrites a value whose chunks every host deleted, judged by this node's view: a purge it holds invalid leaves the value live, and the rewrite is a new write the purge does not cover. A writer's pass sends no delete while a role commit it holds waits for its relay at the host (notes/sync-convergence.md, Deletes wait for the role view), so the host's log holds the role commit before the deletes. But a reader of that log can get both in one batch (a fill from an older position): the loop collects `lost` and calls `relink_lost` before `flush_storing`/`open_entries` apply the batch's blobs, and a body announced without bytes is fetched later still. The repair then runs on the old role view and revives the purged value.

Candidate rule: repair runs once the label's stream is applied to its end (no fetch of a commit blob outstanding), e.g. at the pass end the batch schedules, not inside the batch. Needs a test: one batch carrying the promotion and the chunk deletes.

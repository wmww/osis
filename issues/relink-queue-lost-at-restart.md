# Chunk repair queue lost at a restart

> Summary: `relink_pending` (chunks deleted from every host, waiting for the label's settled pass or an aspect's back-off) is memory only; a restart drops it, and the Deleted events that queued it are not read again, so a live value's lost chunk stays lost.
> Priority: low
> Tags: node-sync

- Window: from the batch that deleted the chunks to the pass that repairs them. Usually one event; longer while a commit on the aspect is pending (`unsettled`), an entry of the label is unopened, or the per-aspect back-off holds the repair (1 h to 7 days).
- Needs a purger that had not seen the reuse (spec/sync-ids.md §1 repair) plus a restart in that window.
- Options: persist the queue per label in the sync store (bounded: only held blobs stay queued, `relink_lost`); or rebuild at start by asking which held blobs live states link that no host of the label holds (a scan of every label's closure).

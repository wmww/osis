# Stores keep every record and list blob ever logged
> Summary: A store keeping S unread keeps every record and list blob any node logged under S while S lives: no delete key covers one, so blobs whose records are no longer needed, and the losers among readers' concurrent blobs of the same records, stay there. Own stores settle on one; stores do not.
> Priority: low
> Tags: sync

Own stores are settled: a record or list blob in a node's own store counts whoever logged it, and of two of one kind the one carrying all the other carries (and more, or the same under a lower ID) wins (spec/permissions.md §4 Logging certificates; osis-sync `keep::readers_logging_the_same_records_settle_on_one_record_blob_spec_permissions_4`).

Left: a record or list blob carries no commitments (spec/wire.md §3, §4), so no Delete can name it at a store keeping S unread (spec/sync-judgement.md §2: "never must-not-hold: no delete key covers it"). Every record blob logged there stays until S stops there: each reader that sealed one before seeing another's, every increment a writer sealed as records came, and every blob whose records S no longer needs. Grows with changes to the record set and with readers logging at once, bounded by S's caps.

Fix shape: give certificate blobs a delete authorization a writer of S holds (a commitment under S's step delete key, or a Delete of a blob with no commitments by S's head delete key), and delete at a store what lost or is unneeded in the writer's own store, once the winner is shown there. Wire change (free); check against spec/sync-ids.md §6 Delete and the hostile cases (a writer deleting a needed record blob: readers log their own again).

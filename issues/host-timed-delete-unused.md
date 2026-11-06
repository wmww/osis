# Hosts still take timed deletes no node sends
> Summary: With keep at most D > 0 gone, no node sends a timed delete (a Delete item's `at`), but hosts still accept, schedule and log them (spec/sync.md §5 "Optionally timed", spec/wire.md §11 `at`, the Pending event 2, bundle record 5; osis-label `DeleteItem::at`, osis-host sweep, osis-proto `Event::Pending`, engine `labeling::delete_item`'s `at`). Remove them end to end.
> Tags: host, node-sync, spec

Unblocked (whole commits step 2b, which reworked delete items in the same files, is built). Drop `at` from the Delete item and its signed digest, the host's pending-delete index and sweep step, `LogRecord::Pending`/`Event::Pending`/the bundle's timed-delete record, the sim's `check.rs` arm, and the spec lines; regenerate vectors.

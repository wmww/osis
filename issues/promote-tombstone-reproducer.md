# A minimal reproducer for promoting a tombstoned entry
> Summary: `would_promote` refuses an entry the node removed within its tombstone and recorded again from a host's announcement (spec/sync.md §5 Promotion); only sim `evil_host_drops` (setup 899326633465, seed 899326633475) shows the case, no fast node test does.
> Priority: low
> Tags: tests, sync

- The case: a writer's own commit body it removed (deleted at every host it knew) while it keeps the bytes and does not upload a fresh encryption, then a host (here a dishonest one, its deletes dropped) shows the body again. Recorded again unstamped (`log_events_from`, tombstone path), it read as a deposit, and promotion stamped it and placed its author's chain as fresh record blobs at the honest host each time (ping-pong at quiescence).
- Tried in `core/node/tests/it/promotion.rs` without success: a reader's deposit (its bytes go with the entry, `forget_blob`), the writer's own body deleted by an injected host Deleted (it uploads a fresh encryption at once, which holds the parts stamped, so nothing is promoted), a Deleted plus replayed Added in one Stream (same). The sim case needs the bytes kept with a part that no other stamped entry holds and that the node does not upload again.

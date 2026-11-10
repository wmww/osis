# Inbox copy cache goes stale over peer links
> Summary: `inbox_certificates` caches "all there" per inbox blob (`InboxCopied`), but what counts as held depends on which connections carry the label (`held_parts`), and nothing drops the cache when those change: a debug assertion fires in a three-node, peers-only group. In release the pass skips a copy it wants.
> Priority: normal
> Tags: node, sync, tests

Repro: core/test/sim/tests/it/no_server.rs `repro_a_write_then_a_reply_over_a_reader_keeps_the_inbox_copy_cache_true`: A and C apart, B between (an admin that made C's link); A writes, then C does. Panics at core/node/src/sync/pass/inbox.rs `debug_assert!(!copied, ...)`. The other order passes (`writes_cross_a_reader_both_ways_row_24`).

Cause read, not traced: `InboxCopied::moved`/`lost` drop entries on role, record, label and host-loss changes; `held_parts` also reads the conns holding the label.

Also seen in tier 1, timing-dependent: osis `port::rows_that_wait_through_the_socket` failed once (of four runs) with the same assertion on the `osis-sync` thread ("inbox_certificates skipped blob ... that wants a copy"), so the test's reply never came.

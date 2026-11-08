# An invalid text body leaves an empty element record in the state
> Summary: a held invalid text delta leaves a record with no write (no creation, char, position or flag; span 1) in the aspect's state, which a rebuild without the body lacks. Reads agree, states and live writes do not: the body's own record counts as a live write (spec/commits.md §5), so the author's own refused text body (kept, spec/permissions.md §6) keeps a live write and its host delete waits for a carrier. Found when dropping invalid bodies skipped the rebuild (`order::undeleted_char_after_reopen_reads_alike_*`, debug `check_rebuilt`); the drop rebuilds, so only bodies kept invalid (own, memory) show it.
> Priority: low
> Tags: crdt, engine

Un-merge takes the invalid delta's creation (spec/crdt.md §4.6, §6.1) but a record left with nothing is not removed from the state. Expected by the valid-order rule (notes/crdt.md: an invalid body leaves nothing): holding an invalid body or not gives the same state. Repro: make `retention::drop_part_for` skip its rebuild for `DropFor::Invalid` and run the test above.

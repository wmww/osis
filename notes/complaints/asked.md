# asked
- The sim's `advance` ticks every node whatever its wake, and a label's resync (60 s) divides `STALL_TIMEOUT_MS` (2 min): a test of a wake at the stall time passed with the wake removed. The new stream test sets `resync_ms` 50 s and steps time to the node's own wakes to see it.
- Review: the old `a_trickling_co_reader_holds_a_body_for_the_stall_time_only` passes with the new stall wake removed (sim ticks every node); only the new test, stepping to the node's own wakes, catches it.

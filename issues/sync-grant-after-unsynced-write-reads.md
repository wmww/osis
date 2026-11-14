# A read grant after an unsynced write is not read
> Summary: node 1 writes a thing, a durable write of its store fails unsynced, then its read grant to node 0 is refused ("storage sync failed"); once healed node 0 holds the Read role but reads no value, the reference reads the last write. Deterministic reproducer `flows::a_reader_granted_through_an_unsynced_write_reads` (ignored); full-size faulty seed 188669321416, shrunk.
> Priority: normal
> Tags: sync, tests

- Not investigated. Close to `flows::sync_follows_an_engine_that_read_its_store_again_spec_sync_ids_5` (passes), where the unsynced fault comes before the grantee's thing is made.

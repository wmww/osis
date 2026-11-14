# sync-records
- `record_put_row` silently writes nothing for a record that is not in the store: the streams test harness used a made-up record ID, so every durable row it "wrote" went nowhere and tests still passed. Harnesses must create real records.
- A full `Node` cannot carry data yet (the engine facade answers NotBuilt), so the end-to-end restart tests run in the opens and streams harnesses separately and the 1 KB reconnect cost adds the two.
- `sid(0)` in tests is `SyncId([0; 16])`, the record-wide label `NO_LABEL`: a test sync ID leaving the node would wipe record-wide rows. The new tests use sync IDs from 1.

# sync-records
- `record_put_row` silently writes nothing for a record that is not in the store: the streams test harness used a made-up record ID, so every durable row it "wrote" went nowhere and tests still passed. Harnesses must create real records.
- A full `Node` cannot carry data yet (the engine facade answers NotBuilt), so the end-to-end restart tests run in the opens and streams harnesses separately and the 1 KB reconnect cost adds the two.
- `sid(0)` in tests is `SyncId([0; 16])`, the record-wide label `NO_LABEL`: a test sync ID leaving the node would wipe record-wide rows. The new tests use sync IDs from 1.
- (review) The reconnect cost summed opens' and streams' message bodies only: no frame headers, no Hello, no Prove/Proved (about 840 B alone). Measure every byte a connection carries, or state the property without a number.
- (review) The pull crash test planned only `Fault::Crash`, which fails every later write too, so a swallowed store error (a body take treated as declined, its cursor then stored) passed. Plan `Fault::Fail` beside it.
- (review) A whole listing reaches paging only past `MAX_MESSAGE` (9 MiB): a paged-listing test needs about 650 inline bodies; a smaller reply budget knob in the Pair harness would make such tests cheaper.

# crash-restart
> Summary: Workflow mishaps met fixing the crash_restart oracle.

- `NetSim::quiet` clears partitions (`blocked.clear()`), so a partition set before it is gone: a test of "one host away" must use `advance` + `settle`. Took two wrong test runs to see.
- Sim trace is capped at 40 lines and `OSIS_SIM_TRACE` only affects phase B: phase A probes need a code edit.
- A harness change to delivery order (a BTreeMap by ID against `commit_ids`' ts order) silently re-rolls every seed, so a regression seed tests nothing while still passing. A handmade test beside a seed test catches it.

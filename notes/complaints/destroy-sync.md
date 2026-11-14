# destroy-sync
- The reproducers' setup broke silently on rebase onto sync-rebuild: holder-trust made grants offers the harness accepts after each step, so a script ending in `Run` leaves the last accept unsynced; `three()` needs a second `Run`. A setup assert caught it, but only because the reproducers were un-ignored.
- `World::partition` of a node from both peers over a long `advance` hits the storm cap with redials; `power_off` does too (ticks count as deliveries): raise `w.cap` for long waits.
- Emptying a destroyed thing's sync ID was never run end to end before: three independent gaps (sync ID not read while it keeps, no delete key once record-less, own record blobs never dropped) each blocked it; only the facade-level and fake-ground tests existed.

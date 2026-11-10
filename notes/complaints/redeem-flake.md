# redeem-flake
- The heavy lock was held by another run for about 10 minutes before the first flake loop could start.
- No sync trace in osis's runtime tests: catching the stall took a throwaway `SyncEngine::handle` tracer (frames decoded per connection, `OSIS_SYNC_TRACE`) and eprintln in the redeem waits; libtest swallows it without `--nocapture`. A kept, env-gated tracer in the driver would have saved most of the time.
- `World` had peer links and a reach model but no way to add a relay (`add_relay`), so no osis test used direct links in the manual world.
- Review: the first gate failed on a rotation_holds_large seed main fails too (its random offset); a second whole gate (7 min) was the only way to a pass.

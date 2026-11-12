# rotation-excuse-tight
- Each by-hand property sweep waited up to 25 min on the heavy lock behind other branches' gates, for runs of 45-120 s.
- libtest captures `eprintln!` from the seed threads: instrumenting a property run needs `--nocapture`, else counters read zero (cost one locked run).
- Two `claudewait` calls chained in one Bash call exceed the tool's default timeout and get moved to the background: one per call.
- The obvious plant (drop the `Walk::Seal` stale check in `blocked_epoch`) leaves `co_writer_seals_no_keyset_with_a_stale_box_spec_crypto_4` passing (the left-out record alone keeps W out there) and rotation_holds passing (issues/rotation-holds-skips-departures-below.md).
